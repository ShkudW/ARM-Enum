 
function WebAppEnum {
	param(
		[switch]$Check
	)


    function Show-ClientLoginGui {
    param([switch]$Topmost)

    if ($Host.Runspace.ApartmentState -ne 'STA') {
        Write-Warning "Run with pwsh -STA"
    }

    Add-Type -AssemblyName PresentationFramework,PresentationCore,WindowsBase

    $xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="ARM-Enum and Abuse" Height="560" Width="720"
        WindowStartupLocation="CenterScreen" ResizeMode="NoResize"
        Background="#0B1220" FontFamily="Segoe UI" SnapsToDevicePixels="True">
  <Window.Resources>
    <DropShadowEffect x:Key="CardShadow" BlurRadius="22" ShadowDepth="0" Color="#99000000"/>
    <Style TargetType="TextBox">
      <Setter Property="Background" Value="#0F1626"/>
      <Setter Property="Foreground" Value="#E5E7EB"/>
      <Setter Property="BorderBrush" Value="#334155"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="8,4"/>
      <Setter Property="Height" Value="34"/>
    </Style>
    <Style TargetType="PasswordBox">
      <Setter Property="Background" Value="#0F1626"/>
      <Setter Property="Foreground" Value="#E5E7EB"/>
      <Setter Property="BorderBrush" Value="#334155"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="8,4"/>
      <Setter Property="Height" Value="34"/>
    </Style>
    <Style TargetType="Button">
      <Setter Property="Padding" Value="18,10"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Cursor" Value="Hand"/>
    </Style>
  </Window.Resources>

  <Grid Margin="22">
    <Grid.RowDefinitions>
      <RowDefinition Height="140"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <!-- Header (animated gradient) -->
    <Border Grid.Row="0" CornerRadius="18" Margin="0,0,0,14">
      <Border.Background>
        <LinearGradientBrush StartPoint="0,0" EndPoint="1,1">
          <GradientStop x:Name="gs1" Color="#3B82F6" Offset="0"/>
          <GradientStop x:Name="gs2" Color="#8B5CF6" Offset="1"/>
        </LinearGradientBrush>
      </Border.Background>
      <Grid Margin="18">
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="*"/>
        </Grid.ColumnDefinitions>

        <StackPanel Grid.Column="1" Margin="14,0,0,0" VerticalAlignment="Center">
          <TextBlock Text="WebApp Enumeration" Foreground="#f8fafc" FontSize="22" FontWeight="Bold"/>
          <TextBlock Text="By @ShkudW - https://github.com/ShkudW/ARM-Enum " Foreground="#E0E7FF" FontSize="13"/>
        </StackPanel>
      </Grid>
    </Border>

    <!-- Card -->
    <Border Grid.Row="1" CornerRadius="18" Background="#101828" Padding="22" Effect="{StaticResource CardShadow}">
      <Grid>
        <Grid.RowDefinitions>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="Auto"/>
          <RowDefinition Height="12"/>
          <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="170"/>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>

        <!-- Client ID -->
        <TextBlock Grid.Row="0" Grid.Column="0" Margin="0,6,10,6" Foreground="#CBD5E1" FontSize="13" Text="Client ID"/>
        <TextBox   x:Name="ClientIdBox" Grid.Row="0" Grid.Column="1" Margin="0,4,0,4" ToolTip="GUID of the App Registration"/>

        <!-- Secret -->
        <TextBlock Grid.Row="1" Grid.Column="0" Margin="0,6,10,6" Foreground="#CBD5E1" FontSize="13" Text="Client Secret"/>
        <PasswordBox x:Name="SecretBox" Grid.Row="1" Grid.Column="1" Margin="0,4,0,4" ToolTip="App client secret"/>
        <TextBox   x:Name="SecretPlainBox" Grid.Row="1" Grid.Column="1" Margin="0,4,0,4" Visibility="Collapsed" ToolTip="App client secret (visible)"/>
        <CheckBox  x:Name="ShowSecretChk" Content="Show" Grid.Row="1" Grid.Column="2" Margin="10,6,0,4"
                   Foreground="#B4C6FC" VerticalAlignment="Center"/>

        <!-- Domain -->
        <TextBlock Grid.Row="2" Grid.Column="0" Margin="0,6,10,6" Foreground="#CBD5E1" FontSize="13" Text="Domain"/>
        <TextBox   x:Name="DomainBox" Grid.Row="2" Grid.Column="1" Margin="0,4,0,4" ToolTip="Tenant domain, e.g. contoso.com"/>

        <!-- Inline error -->
        <TextBlock x:Name="ErrorText" Grid.Row="4" Grid.ColumnSpan="3"
                   Foreground="#FCA5A5" FontSize="12" Visibility="Collapsed"/>
      </Grid>
    </Border>

    <!-- Buttons -->
    <DockPanel Grid.Row="2" Margin="0,16,0,0" LastChildFill="False">
      <StackPanel Orientation="Horizontal" DockPanel.Dock="Right">
        <Button x:Name="CancelBtn" Content="Cancel" Margin="0,0,8,0"
                Background="#0E1726" Foreground="#CBD5E1" BorderBrush="#334155" IsCancel="True"/>
        <Button x:Name="OkBtn" Content="Continue"
                Background="#3B82F6" Foreground="White" BorderBrush="#2563EB" IsDefault="True"/>
      </StackPanel>
    </DockPanel>
  </Grid>
</Window>
"@

    $xdoc = New-Object System.Xml.XmlDocument
    $xdoc.LoadXml($xaml)
    $reader  = New-Object System.Xml.XmlNodeReader $xdoc
    $window  = [Windows.Markup.XamlReader]::Load($reader)

    $ClientIdBox    = $window.FindName("ClientIdBox")
    $SecretBox      = $window.FindName("SecretBox")
    $SecretPlainBox = $window.FindName("SecretPlainBox")
    $ShowSecretChk  = $window.FindName("ShowSecretChk")
    $DomainBox      = $window.FindName("DomainBox")
    $OkBtn          = $window.FindName("OkBtn")
    $CancelBtn      = $window.FindName("CancelBtn")
    $ErrorText      = $window.FindName("ErrorText")
    $gs1            = $window.FindName("gs1")
    $gs2            = $window.FindName("gs2")

    if ($Topmost) { $window.Topmost = $true }

    $window.Add_Loaded({
        $c1 = [Windows.Media.ColorConverter]::ConvertFromString("#3B82F6")
        $c2 = [Windows.Media.ColorConverter]::ConvertFromString("#8B5CF6")
        $c3 = [Windows.Media.ColorConverter]::ConvertFromString("#06B6D4")
        $c4 = [Windows.Media.ColorConverter]::ConvertFromString("#22D3EE")

        $a1 = New-Object Windows.Media.Animation.ColorAnimation($c1, $c3, (New-Object Windows.Duration([TimeSpan]::FromSeconds(6))))
        $a1.AutoReverse = $true; $a1.RepeatBehavior = [Windows.Media.Animation.RepeatBehavior]::Forever
        $a2 = New-Object Windows.Media.Animation.ColorAnimation($c2, $c4, (New-Object Windows.Duration([TimeSpan]::FromSeconds(6))))
        $a2.AutoReverse = $true; $a2.RepeatBehavior = [Windows.Media.Animation.RepeatBehavior]::Forever

        $gs1.BeginAnimation([Windows.Media.GradientStop]::ColorProperty, $a1)
        $gs2.BeginAnimation([Windows.Media.GradientStop]::ColorProperty, $a2)

        $ClientIdBox.Focus() | Out-Null
    })

  
    $ShowSecretChk.Add_Checked({
        $SecretPlainBox.Text       = $SecretBox.Password
        $SecretPlainBox.Visibility = "Visible"
        $SecretBox.Visibility      = "Collapsed"
    })
    $ShowSecretChk.Add_Unchecked({
        $SecretBox.Password        = $SecretPlainBox.Text
        $SecretPlainBox.Visibility = "Collapsed"
        $SecretBox.Visibility      = "Visible"
    })

  
    $handler = {
        $OkBtn.RaiseEvent((New-Object Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent)))
    }
    $ClientIdBox.Add_KeyDown({ if ($_.Key -eq 'Return') { & $handler } })
    $SecretBox.Add_KeyDown({ if ($_.Key -eq 'Return') { & $handler } })
    $SecretPlainBox.Add_KeyDown({ if ($_.Key -eq 'Return') { & $handler } })
    $DomainBox.Add_KeyDown({ if ($_.Key -eq 'Return') { & $handler } })


    $OkBtn.Add_Click({
        $ErrorText.Visibility = "Collapsed"
        $cid = $ClientIdBox.Text.Trim()
        $dom = $DomainBox.Text.Trim()
        $sec = if ($ShowSecretChk.IsChecked) { $SecretPlainBox.Text } else { $SecretBox.Password }

        if ([string]::IsNullOrWhiteSpace($cid) -or [string]::IsNullOrWhiteSpace($sec) -or [string]::IsNullOrWhiteSpace($dom)) {
            $ErrorText.Text = "Please fill all fields."
            $ErrorText.Visibility = "Visible"
            return
        }

        $tmpGuid = [Guid]::Empty
        if (-not [Guid]::TryParse($cid, [ref]$tmpGuid)) {
            $ErrorText.Text = "Client ID must be a valid GUID."
            $ErrorText.Visibility = "Visible"
            return
        }

        $result = [PSCustomObject]@{
            ClientId     = $cid
            ClientSecret = $sec
            Domain       = $dom
        }
        $window.Tag = $result
        $window.DialogResult = $true
        $window.Close()
    })

    $CancelBtn.Add_Click({ $window.DialogResult = $false; $window.Close() })

    $null = $window.ShowDialog()
    if ($window.DialogResult -eq $true) { return $window.Tag }
}


    function GetTenantID{param([string]$TenantName)
            try {
                $resp = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantName/.well-known/openid-configuration" -ErrorAction Stop
                    $TenantID = ($resp.issuer -split '/')[3]
                } catch {
                    Write-Host "[!] The specified domain is invalid or not reachable." -ForegroundColor Red
                }
            return $TenantID

    }
	function GetAzureARMToken {param ([string]$RefreshToken,[string]$ClientID,[string]$ClientSecret,[string]$TenantID)
				$Url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
				$Headers = @{"User-Agent"= "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"}
				
				if($RefreshToken -and -not $ClientID -and -not $ClientSecret){
					$body = @{
							"client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
							"scope" = "https://management.azure.com/.default"
							"grant_type" = "refresh_token"
							"Refresh_token" = $RefreshToken
					}
				}
				elseif($ClientID -and $ClientSecret -and -not $RefreshToken){
					
					$body = @{
							"grant_type" = "client_credentials"
							"scope" = "https://management.azure.com/.default"
							"client_id" = $ClientID
							"client_secret" = $ClientSecret
					}
				}
				else {
					return $null
				}
				
				try {
					$RequestUrl =  Invoke-RestMethod -Method Post -Uri $Url -Body $Body -Headers $Headers
					return $RequestUrl.access_token
				}
				catch{
					return $_
				}
		}

	function GetSubscriptions {param ([string]$AzureARMToken,[int]$MaxRetries = 8)
				$Headers = @{
					'Authorization' = "Bearer $AzureARMToken"
					'User-Agent'	= "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
					'Accept'        = 'application/json'
				}
				$results1 = @()
				$url = "https://management.azure.com/subscriptions?api-version=2021-01-01"
				while ($url) {
					$attempt = 0
					while ($true) {
						try {
							$resp = Invoke-RestMethod -Method GET -Uri $url -Headers $Headers -ErrorAction Stop
							break
						}
						catch {
							$attempt++
							$httpResp = $_.Exception.Response
							if ($httpResp -and [int]$httpResp.StatusCode -eq 429 -and $attempt -le $MaxRetries) {
								$retryAfter = $httpResp.Headers['Retry-After']
								if (-not $retryAfter) { $retryAfter = 60 }
								Start-Sleep -Seconds ([int]$retryAfter)
								continue
							}	
							throw
						}
					}

					if ($resp.value) {
						$batch = $resp.value | ForEach-Object {
							[pscustomobject]@{
								DisplayName    = $_.displayName
								SubscriptionId = $_.subscriptionId
								State          = $_.state
							}
					}
					$results1 += $batch
				}
				$url = $resp.nextLink
			}
			return $results1
		}

		function CheckSubscriptionPrivileges {param ([string]$AzureARMToken,[string]$Subid)
				function Test-OpAllowed {param([string[]]$Allowed,[string[]]$Denied,[string]$Operation)
					$matches = $false
					foreach ($pat in $Allowed) {
						if ($Operation -like $pat) { $matches = $true; break }
					}
					if (-not $matches) { return $false }
					foreach ($pat in $Denied) {
						if ($Operation -like $pat) { return $false }
					}
					return $true
				}

				$Headers = @{
					'Authorization' = "Bearer $AzureARMToken"
					'User-Agent'	= "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
					'Accept'        = 'application/json'
				}

				$Detectors = @(
					
					@{ Name='CanManageRBAC'; 			Ops=@('Microsoft.Authorization/roleAssignments/write') },
					@{ Name='OwnerLike';     			Ops=@('*'); ExcludeOps=@('Microsoft.Authorization/roleAssignments/write') },
					@{ Name='CanListStorageKeys'; 		Ops=@('Microsoft.Storage/storageAccounts/listKeys/action') },
					@{ Name='CanGrantDiskSAS';    		Ops=@('Microsoft.Compute/disks/grantAccess/action') },
					@{ Name='CanListCosmosKeys';  		Ops=@('Microsoft.DocumentDB/databaseAccounts/listKeys/action') },
					@{ Name='KV_ReadSecrets';     		Ops=@('Microsoft.KeyVault/vaults/secrets/read') },
					@{ Name='KV_AccessPolicyWrite'; 	Ops=@('Microsoft.KeyVault/vaults/accessPolicies/write') },
					@{ Name='KV_VaultWrite';        	Ops=@('Microsoft.KeyVault/vaults/write') },
					@{ Name='CanInstallVMExt';   		Ops=@('Microsoft.Compute/virtualMachines/extensions/*') },
					@{ Name='CanRunAutomation';  		Ops=@('Microsoft.Automation/automationAccounts/*') },
					@{ Name='CanTriggerLogic';   		Ops=@('Microsoft.Logic/workflows/*') },
					@{ Name='GlobalRead';        		Ops=@('*/read') }
				)
				$hi = @()
				$lo = @()

				$url = "https://management.azure.com/subscriptions/$($Subid)/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"
				try {
					$resp = Invoke-RestMethod -Method GET -Uri $url -Headers $Headers -ErrorAction Stop
				} catch {
					$lo += [pscustomobject]@{ DisplayName=$sub.DisplayName; SubscriptionId=$sub.SubscriptionId; Summary="ERROR: $($_.Exception.Message)" }
					continue
				}

				$allow = @()
				$deny  = @()
				$allowData = @()
				$denyData  = @()

				foreach ($p in $resp.value) {
					if ($p.actions)         { $allow  += $p.actions }
					if ($p.notActions)      { $deny   += $p.notActions }
					if ($p.dataActions)     { $allowD += $p.dataActions }
					if ($p.notDataActions)  { $denyD  += $p.notDataActions }
				}

					$allow     = $allow     | Select-Object -Unique
					$deny      = $deny      | Select-Object -Unique
					$allowData = $allowData | Select-Object -Unique
					$denyData  = $denyData  | Select-Object -Unique
					
					$denyAll = ($deny -contains '*') -or ($denyD -contains '*')
					
					$hasStar          =  (Test-OpAllowed -Allowed $allow  -Denied $deny  -Operation '*') -or (Test-OpAllowed -Allowed $allowD -Denied $denyD -Operation '*')
					$canManageRBAC    =  Test-OpAllowed -Allowed $allow -Denied $deny -Operation 'Microsoft.Authorization/roleAssignments/write'
					$hasGlobalRead    =  Test-OpAllowed -Allowed $allow  -Denied $deny  -Operation '*/read'
					$hasGlobalWrite   =  Test-OpAllowed -Allowed $allow  -Denied $deny  -Operation '*/write'
					
					$summary = $null
						if ($denyAll) {
							$summary = '* in NotActions'
						}
						elseif ($canManageRBAC -and $hasStar) {
							$summary = 'Owner'
						}
						elseif ($hasStar) {
							$summary = 'Owner-like (no RBAC manage)'
						}
						elseif ($hasGlobalRead -and -not $hasGlobalWrite -and -not $hasStar) {
							$summary = 'allowed only read'
						}
						else {
							$summary = 'no effective high-level permissions'
						}

						$row = [pscustomobject]@{
							DisplayName    = $sub.DisplayName
							SubscriptionId = $sub.SubscriptionId
							Summary        = $summary
						}

				return  $row
		}
		
function Test-WebAppSurface {
    param(
        [Parameter(Mandatory)][string]$HostName,
        [Parameter(Mandatory)][bool]$HttpsOnly,
        [int]$TimeoutSec = 10,
        [int]$MaxRedirects = 5,
        [switch]$SaveFindingsToJson
    )

    $scheme = if ($HttpsOnly) { 'https' } else { 'http' }
    $base   = "{0}://{1}" -f $scheme, $HostName
    $ua     = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36'
    $hdrs   = @{ 'Accept'='*/*'; 'User-Agent'=$ua }

    $findings = New-Object System.Collections.Generic.List[object]

    function Add-Finding {
        param([string]$Type,[string]$Path,[int]$Status,[string]$Evidence,[hashtable]$Extra)
        $find = [pscustomobject]@{
            HostName = $HostName
            Scheme   = $scheme
            Type     = $Type
            Path     = $Path
            Status   = $Status
            Evidence = $Evidence
            Extra    = $Extra
        }
        $findings.Add($find) | Out-Null
    }

    
    try {
        $headRoot = Invoke-WebRequest -Uri $base'/' -Method Head -Headers $hdrs -TimeoutSec $TimeoutSec -MaximumRedirection $MaxRedirects -ErrorAction Stop
        $h = $headRoot.Headers
        $server  = $h['Server']
        $xpb     = $h['X-Powered-By']
        $aspver  = $h['X-AspNet-Version']
        $mvcver  = $h['X-AspNetMvc-Version']
        $hsts    = $h['Strict-Transport-Security']
        $setc    = $h['Set-Cookie']
        $acao    = $h['Access-Control-Allow-Origin']
        $acac    = $h['Access-Control-Allow-Credentials']

       
        if ($server -or $xpb -or $aspver -or $mvcver) {
            Add-Finding -Type 'Fingerprint' -Path '/' -Status $headRoot.StatusCode -Evidence "Server=$server; X-Powered-By=$xpb; ASP.NET=$aspver; ASP.NET MVC=$mvcver" -Extra @{}
        }

        
        if ($HttpsOnly -and [string]::IsNullOrWhiteSpace($hsts)) {
            Add-Finding -Type 'MissingHSTS' -Path '/' -Status $headRoot.StatusCode -Evidence 'Strict-Transport-Security header is missing' -Extra @{}
        }

        
        if ($setc) {
            $cookieIssues = @()
            foreach ($c in (@($setc))) {
                if ($c -notmatch '(?i)\bSecure\b')   { $cookieIssues += "No Secure: $c" }
                if ($c -notmatch '(?i)\bHttpOnly\b') { $cookieIssues += "No HttpOnly: $c" }
                if ($c -notmatch '(?i)\bSameSite=')  { $cookieIssues += "No SameSite: $c" }
            }
            if ($cookieIssues.Count -gt 0) {
                Add-Finding -Type 'CookieFlags' -Path '/' -Status $headRoot.StatusCode -Evidence (($cookieIssues -join '; ') -replace "`r?`n",' ') -Extra @{}
            }
        }

       
        if ($acao -and $acao -eq '*') {
            if ($acac -and $acac.ToString().ToLower() -eq 'true') {
                Add-Finding -Type 'CORS' -Path '/' -Status $headRoot.StatusCode -Evidence 'ACAO=* with Credentials=true (invalid & risky)' -Extra @{}
            } else {
                Add-Finding -Type 'CORS' -Path '/' -Status $headRoot.StatusCode -Evidence 'ACAO=* (public)' -Extra @{}
            }
        }

        
        try {
            $opt = Invoke-WebRequest -Uri $base'/' -Method Options -Headers $hdrs -TimeoutSec $TimeoutSec -MaximumRedirection $MaxRedirects -ErrorAction Stop
            $allowMethods = $opt.Headers['Allow']
            $acaMethods   = $opt.Headers['Access-Control-Allow-Methods']
            $acaHeaders   = $opt.Headers['Access-Control-Allow-Headers']
            if ($allowMethods -or $acaMethods -or $acaHeaders) {
                Add-Finding -Type 'CORS-Preflight' -Path '/' -Status $opt.StatusCode -Evidence "Allow=$allowMethods; ACA-Methods=$acaMethods; ACA-Headers=$acaHeaders" -Extra @{}
            }
        } catch {}

       
        try {
            $trace = Invoke-WebRequest -Uri $base'/' -Method Trace -Headers $hdrs -TimeoutSec $TimeoutSec -MaximumRedirection 0 -ErrorAction Stop
            Add-Finding -Type 'TRACE-Enabled' -Path '/' -Status $trace.StatusCode -Evidence 'TRACE responded' -Extra @{}
        } catch {
           
        }

    } catch {
       
    }

   
    $paths = @(
        '/robots.txt','/sitemap.xml',
        '/swagger','/swagger/index.html','/swagger/v1/swagger.json','/openapi.json','/api/docs',
        '/graphql',
        '/health','/healthz','/ready','/status','/metrics',
        '/actuator','/actuator/health','/actuator/env','/actuator/prometheus',
        '/elmah.axd','/trace.axd',
        '/.well-known/security.txt','/.well-known/openid-configuration','/.well-known/assetlinks.json','/.well-known/apple-app-site-association',
        '/.git/HEAD','/.git/config','/.gitignore','/.svn/entries','/.DS_Store','.htaccess','/web.config','/appsettings.json','/appsettings.Production.json',
        '/_next/static/'
    )

    foreach ($p in $paths) {
        $u = $base + $p
        try {
            $r = Invoke-WebRequest -Uri $u -Method Get -Headers $hdrs -TimeoutSec $TimeoutSec -MaximumRedirection $MaxRedirects -ErrorAction Stop
            $ct = $r.Headers['Content-Type']
            $ev = if ($ct) { "Content-Type=$ct" } else { "Status=$($r.StatusCode)" }

            Add-Finding -Type 'ExposedPath' -Path $p -Status $r.StatusCode -Evidence $ev -Extra @{}
        } catch {
            $resp = $_.Exception.Response
            $code = $null; if ($resp) { try { $code = [int]$resp.StatusCode } catch {} }
            if ($code -in 200,401,403) {
              
                Add-Finding -Type 'InterestingPath' -Path $p -Status $code -Evidence 'Exists but not directly accessible' -Extra @{}
            }
        }
    }

  
    try {
        $scm = "https://$HostName".Replace('.azurewebsites.net','.scm.azurewebsites.net')
        $ku  = Invoke-WebRequest -Uri ($scm + '/') -Method Get -Headers $hdrs -TimeoutSec $TimeoutSec -MaximumRedirection 0 -ErrorAction Stop
        Add-Finding -Type 'SCM-Endpoint' -Path $scm -Status $ku.StatusCode -Evidence 'SCM root responded (likely requires auth)' -Extra @{}
    } catch {
        $resp = $_.Exception.Response
        $code = $null; if ($resp) { try { $code = [int]$resp.StatusCode } catch {} }
        if ($code -in 200,301,302,401,403) {
            Add-Finding -Type 'SCM-Endpoint' -Path $scm -Status $code -Evidence 'SCM indicates presence' -Extra @{}
        }
    }

    if ($SaveFindingsToJson) {
        $out = Join-Path $PWD ("{0}__surface.json" -f ($HostName -replace '[^\w\.-]+','_'))
        $findings | ConvertTo-Json -Depth 6 | Out-File -FilePath $out -Encoding utf8
        Write-Host "[*] Findings saved to: $out" -ForegroundColor Yellow
    }

    return ,$findings
}


	function Get-EnvIfExposed {
		param(
			[Parameter(Mandatory)][string]$HostName,
			[Parameter(Mandatory)][bool]$HttpsOnly,
			[int]$TimeoutSec = 10,
			[int]$MaxRedirects = 5,
			[switch]$SaveToFile,
			[switch]$TryCommonVariants
		)

		$schemes = @()
		$scheme = if ($HttpsOnly) { 'https' } else { 'http' }
		$schemes += $scheme

		$envCandidates = @('.env')
		if ($TryCommonVariants) {
			$envCandidates += '.env.local','.env.production','.env.prod','.env.dev','.env.stage','.env.staging'
		}

		$ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
		$headers = @{ 'Accept'='*/*'; 'User-Agent'=$ua }

    
		$envLine = '^[A-Za-z_][A-Za-z0-9_]*\s*=\s*.+$'
		$htmlMarkers = @('<!DOCTYPE html','<html','<head','<title')
		$suspectedKeys = @('SECRET','CLIENT','KEY','TOKEN','PASSWORD','DATABASE','CONNECTION','AZURE','AWS','GCP','API','APPSETTING','CONNECTIONSTRING')

		foreach ($path in $envCandidates) {
			$uri = '{0}://{1}/{2}' -f $scheme, $HostName, $path.TrimStart('/')
			Write-Host "[*] Probing $uri" -ForegroundColor Cyan

			try {
				$head = Invoke-WebRequest -Uri $uri -Method Head -Headers $headers -TimeoutSec $TimeoutSec -MaximumRedirection $MaxRedirects -ErrorAction Stop

				$ct = $head.Headers.'Content-Type'
				if ($ct -and $ct -match 'text/html|application/xhtml\+xml') {
					Write-Host "[-] Content-Type looks like HTML ($ct) → skipping." -ForegroundColor DarkYellow
					continue
				}

				$resp = Invoke-WebRequest -Uri $uri -Method Get -Headers $headers -TimeoutSec $TimeoutSec -MaximumRedirection $MaxRedirects -ErrorAction Stop
				$content = [string]$resp.Content

				if ([string]::IsNullOrWhiteSpace($content)) {
					Write-Host "[-] Empty body." -ForegroundColor DarkYellow
					continue
				}

				$lowerHead = $content.Substring(0, [Math]::Min(4096, $content.Length)).ToLowerInvariant()
				if ($htmlMarkers | ForEach-Object { $lowerHead.Contains($_) } | Where-Object { $_ } ) {
					Write-Host "[-] Looks like HTML/login page → skipping." -ForegroundColor DarkYellow
					continue
				}

				$lines = $content -split "`r?`n"
				$envLikeCount = ($lines | Where-Object { $_ -match $envLine }).Count

				if ($envLikeCount -lt 3) {
					Write-Host "[-] Not enough env-like lines ($envLikeCount) → skipping." -ForegroundColor DarkYellow
					continue
				}
          
				$joined = $content.ToUpperInvariant()
				$hasSensitiveHint = $false
				foreach ($k in $suspectedKeys) {
					if ($joined.Contains($k)) { $hasSensitiveHint = $true; break }
				}

				if (-not $hasSensitiveHint) {
					Write-Host "[±] Env-like but no obvious sensitive keys → still reporting." -ForegroundColor Yellow
				}
				Write-Host "[+] FOUND $path on $HostName" -ForegroundColor Green

				$previewLines = $lines | Where-Object { $_ -match $envLine } | Select-Object -First 50
				Write-Host "----- BEGIN $path ($HostName) -----" -ForegroundColor DarkGreen
				$previewLines | ForEach-Object { Write-Host $_ }
				if ($lines.Count -gt 50) { Write-Host "[...] (truncated)" }
				Write-Host "----- END $path -----" -ForegroundColor DarkGreen

				if ($SaveToFile) {
					$safe = $HostName -replace '[^\w\.-]+','_'
					$out  = Join-Path -Path $PWD -ChildPath ("{0}__{1}.txt" -f $safe, $path.TrimStart('/').Replace('/','_'))
					$content | Out-File -FilePath $out -Encoding utf8
					Write-Host "[*] Saved to: $out" -ForegroundColor Yellow
				}

				return [pscustomobject]@{
					HostName  = $HostName
					Path      = $path
					Scheme    = $scheme
					Exposed   = $true
					Status    = $resp.StatusCode
					Length    = $content.Length
					ContentType = ($resp.Headers.'Content-Type')
					FileSaved = ($SaveToFile.IsPresent)
				}
			}
			catch {
				$code = $null
				if ($_.Exception.PSObject.Properties.Name -contains 'Response' -and $_.Exception.Response) {
					try { $code = [int]$_.Exception.Response.StatusCode } catch {}
				}
				if ($code -eq 404) {
					Write-Host "[-] 404 Not Found: $uri" -ForegroundColor DarkYellow
				} elseif ($code) {
					Write-Host "[-] HTTP $code " -ForegroundColor DarkYellow
				} else {
					Write-Host "[-] Error: $($_.Exception.Message)" -ForegroundColor DarkYellow
				}
			}
		}
		return [pscustomobject]@{
			HostName = $HostName; Path = $null; Scheme = $scheme; Exposed = $false; Status = $null
		}
	}

	function Get-AllWebApps {
		
		param(  
			[array]$Subscriptions,
			[string]$AzureARMToken,
			[string]$TenantID,
			[string]$ClientID,
			[string]$ClientSecret,
			[string]$RefreshToken,
			[int]$MaxRetries = 5
		)

		foreach ($sub in $Subscriptions) {

			$subpermission = (CheckSubscriptionPrivileges -AzureARMToken $AzureARMToken -Subid $sub.SubscriptionId).Summary

			Write-Host ""
			Write-Host "==============================================================================="
			Write-Host ("Subscription: {0} - {1} | Permission: {2}" -f $sub.DisplayName, $sub.SubscriptionId, $subpermission) -ForegroundColor Cyan
			Write-Host "-------------------------------------------------------------------------------" -ForegroundColor Cyan


			$listUrl = "https://management.azure.com/subscriptions/$($sub.SubscriptionId)/providers/Microsoft.Web/sites?api-version=2024-11-01"

			$HeadersARM = @{
				'Authorization' = "Bearer $AzureARMToken"
				'Accept'        = 'application/json'
				'User-Agent'    = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36'
			}

			while ($listUrl) {
				$attempt = 0
				while ($true) {
					try {
						$resp = Invoke-RestMethod -Method GET -Uri $listUrl -Headers $HeadersARM -ErrorAction Stop
						break
					}
					catch {
						$attempt++
						$httpResp = $_.Exception.Response
						$code = if ($httpResp) { [int]$httpResp.StatusCode } else { $null }

						if ($code -eq 429 -and $attempt -le $MaxRetries) {
							
							$retryAfter = $httpResp.Headers['Retry-After']
							if (-not $retryAfter) { $retryAfter = 60 }
							Write-Host "[X] 429 throttling. Sleeping $retryAfter seconds..." -ForegroundColor Yellow
							Start-Sleep -Seconds ([int]$retryAfter)
							continue
						}
						elseif ($code -eq 401 -and $attempt -le $MaxRetries) {
							Write-Host "[!] 401 Unauthorized. Trying to refresh ARM token..." -ForegroundColor Yellow
							if ($ClientID -and $ClientSecret -and $TenantID) {
								$AzureARMToken = GetAzureARMToken -ClientID $ClientID -ClientSecret $ClientSecret -TenantID $TenantID
							}
							elseif ($RefreshToken -and $TenantID) {
								$AzureARMToken = GetAzureARMToken -RefreshToken $RefreshToken -TenantID $TenantID
							}
							else {
								throw
							}
							$HeadersARM['Authorization'] = "Bearer $AzureARMToken"
							continue
						}
						elseif ($attempt -le $MaxRetries) {
						 
							Start-Sleep -Seconds ([int][Math]::Min(30, 2 * $attempt))
							continue
						}
						else {
							throw
						}
					}
				}
		   
				foreach ($site in ($resp.value | Where-Object { $_.type -eq 'Microsoft.Web/sites' })) {
					$obj = [pscustomobject]@{
						SubscriptionName = $sub.DisplayName
						HttpsOnly        = [bool]$site.properties.httpsOnly
						DefaultHostName  = [string]$site.properties.defaultHostName
					}
					if($check){
						
					if ([string]::IsNullOrWhiteSpace($obj.DefaultHostName)) { continue }
						$probe = Get-EnvIfExposed -HostName $obj.DefaultHostName -HttpsOnly $obj.HttpsOnly -TimeoutSec 10 -MaxRedirects 5 -SaveToFile -TryCommonVariants
						$surf  = Test-WebAppSurface -HostName $obj.DefaultHostName -HttpsOnly $obj.HttpsOnly -TimeoutSec 10 -MaxRedirects 5 -SaveFindingsToJson

						Write-Host ("Sub: {0} | Host: {1} | HTTPS: {2} | Env: {3} | Paths: {4}" -f $obj.SubscriptionName, $obj.DefaultHostName, $obj.HttpsOnly, $probe.Exposed, ($surf | Where-Object {$_.Type -in 'ExposedPath','InterestingPath'}).Count)
					}
					write-host "$($obj.DefaultHostName) , HTTP: $($obj.HttpsOnly)"
					
				}
				 
				if ($resp.nextLink) {
					$listUrl = $resp.nextLink
				} else {
					$listUrl = $null
				}
			}
		}

		
	}

	function main{

        $creds = Show-ClientLoginGui -Topmost
        if (-not $creds) { Write-Host "Canceled." -ForegroundColor Yellow; return }

        $script:ClientId     = $creds.ClientId
        $script:ClientSecret = $creds.ClientSecret
        $DomainName          = $creds.Domain


        $script:TenantId = GetTenantID -TenantName $DomainName
		$ARM = GetAzureARMToken -ClientID $script:ClientId -ClientSecret $script:ClientSecret -TenantID $script:TenantId
        $script:ArmToken = $ARM
        $subs = GetSubscriptions -AzureARMToken $ARM
        Get-AllWebApps -AzureARMToken $ARM -Subscriptions $subs -ClientID $script:ClientId -ClientSecret $script:ClientSecret -TenantID $script:TenantId 

	}
	
	main

}
