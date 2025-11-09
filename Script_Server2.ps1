# ============================
# Script: Windows Server 2025 DC Deployment
# Purpose: Automated deployment of Primary Domain Controller
# Author:Benjamin BACLE
# Date: 11/2025
#Credits David Rdriguez
# ============================

$ethipaddress = '10.75.0.11' 
$ethprefixlength = '16' # subnet mask - 16 = 255.255.0.0
$ethdefaultgw = '10.75.0.1' # default gateway
$ethdns = '10.75.0.10' # DNS: first DC
$globalsubnet = '10.75.0.0/16'

# Active Directory Variables
$domainname = 'adatum.fr'

# Disable IE Enhanced Security Configuration Variable
$disableiesecconfig = 'yes'

# Hostname
$computername = 'SERVERDC2'

# NTP 
$ntpserver1 = '0.au.pool.ntp.org'
$ntpserver2 = '1.au.pool.ntp.org'

# Log setup
Function Timestamp { $Global:timestamp = Get-Date -Format "dd-MM-yyy_hh:mm:ss" }
$logfile = "C:\Windows-2025-AD-Replica-log.txt"

Write-Host "-= Get timestamp =-" -ForegroundColor Green
Timestamp
IF (!(Test-Path $logfile)) { New-Item -ItemType File -Path $logfile | Out-Null }

# ============================
# Phase 1 - Network, IE, Hostname
# ============================
$firstcheck = Select-String -Path $logfile -Pattern "1-Basic-Server-Config-Complete"
IF (!$firstcheck) {
    Timestamp
    Add-Content $logfile "$($Timestamp) - Starting SRV2 configuration"

    Try {
        New-NetIPAddress -IPAddress $ethipaddress -PrefixLength $ethprefixlength -DefaultGateway $ethdefaultgw -InterfaceIndex (Get-NetAdapter).InterfaceIndex -ErrorAction Stop | Out-Null
        Set-DnsClientServerAddress -ServerAddresses $ethdns -InterfaceIndex (Get-NetAdapter).InterfaceIndex -ErrorAction Stop
        Write-Host "-= IP Address set to $($ethipaddress), DNS to $($ethdns) =-" -ForegroundColor Green
        Add-Content $logfile "$($Timestamp) - Network configuration complete"
    } Catch {
        Write-Warning "Failed to apply network settings: $($_.Exception.Message)"
        Break
    }

    Try {
        IF ($disableiesecconfig -eq "yes") {
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}' -name IsInstalled -Value 0
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}' -name IsInstalled -Value 0
            Write-Host "-= IE ESC disabled =-" -ForegroundColor Green
            Add-Content $logfile "$($Timestamp) - IE ESC disabled"
        }
    } Catch {
        Write-Warning "Failed to disable IE ESC: $($_.Exception.Message)"
    }

    Try {
        Rename-Computer -ComputerName $env:COMPUTERNAME -NewName $computername -ErrorAction Stop
        Write-Host "-= Hostname set to $computername =-" -ForegroundColor Green
        Add-Content $logfile "$($Timestamp) - Hostname set to $computername"
    } Catch {
        Write-Warning "Failed to rename computer: $($_.Exception.Message)"
        Break
    }

    Add-Content $logfile "$($Timestamp) - 1-Basic-Server-Config-Complete"
    Write-Host "-= Rebooting in 30s to apply config... =-" -ForegroundColor White -BackgroundColor Red
    Start-Sleep 30
    Restart-Computer -Force
    Break
}

# ============================
# Phase 2 - Join Domain
# ============================
$secondcheck = Select-String -Path $logfile -Pattern "2-Domain-Join-Complete"
IF (!$secondcheck) {
    Timestamp
    Write-Host "-= Phase 2: Joining domain $domainname =-" -ForegroundColor Cyan
    
    $domaincred = Get-Credential -Message "Enter domain admin credentials (e.g. adatum\Administrateur)"

    Try {
        Write-Host "-= Joining domain $domainname... =-" -ForegroundColor Yellow
        Add-Computer -DomainName $domainname -Credential $domaincred -ErrorAction Stop
        Write-Host "-= Joined domain successfully =-" -ForegroundColor Green
        Add-Content $logfile "$($Timestamp) - Joined domain $domainname successfully"
    } Catch {
        Write-Warning "Failed to join domain: $($_.Exception.Message)"
        Add-Content $logfile "$($Timestamp) - Domain join failed: $($_.Exception.Message)"
        Break
    }

    Add-Content $logfile "$($Timestamp) - 2-Domain-Join-Complete"
    Write-Host "-= Rebooting in 30s after domain join... =-" -ForegroundColor White -BackgroundColor Red
    Start-Sleep 30
    Restart-Computer -Force
    Break
}

# ============================
# Phase 3 - Promote to DC Replica
# ============================
$thirdcheck = Select-String -Path $logfile -Pattern "3-DC-Promotion-Complete"
IF (!$thirdcheck) {
    Timestamp
    Write-Host "-= Phase 3: Promoting to Domain Controller =-" -ForegroundColor Cyan
    
    # Checking domain membership
    Write-Host "-= Checking domain membership... =-" -ForegroundColor Yellow
    $CurrentDomain = (Get-ComputerInfo).CsDomain
    IF ($CurrentDomain -ne $domainname) {
        Write-Warning "Server not yet joined to domain $domainname (current: $CurrentDomain)."
        Add-Content $logfile "$($Timestamp) - Domain join not detected. Aborting promotion."
        Break
    } ELSE {
        Write-Host "-= Domain membership confirmed ($CurrentDomain) =-" -ForegroundColor Green
        Add-Content $logfile "$($Timestamp) - Domain membership confirmed"
    }

    # Installation AD-DS
    Try {
        Write-Host "-= Installing AD-Domain-Services role =-" -ForegroundColor Yellow
        Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -ErrorAction Stop
        Write-Host "-= AD-DS role installed successfully =-" -ForegroundColor Green
        Add-Content $logfile "$($Timestamp) - AD-DS role installed"
    } Catch {
        Write-Warning "Failed to install AD-DS: $($_.Exception.Message)"
        Break
    }

    # Promotion DC
    $dsrmpassword = Read-Host "Enter Directory Services Restore Mode (DSRM) Password" -AsSecureString
    $domaincred = Get-Credential -Message "Enter domain admin credentials (e.g. adatum\Administrateur)"
    
    Try {
        Write-Host "-= Promoting server as additional Domain Controller (Global Catalog + DNS) =-" -ForegroundColor Yellow
        Install-ADDSDomainController `
            -DomainName $domainname `
            -InstallDns `
            -Credential $domaincred `
            -SafeModeAdministratorPassword $dsrmpassword `
            -NoGlobalCatalog:$false `
            -NoRebootOnCompletion:$false `
            -Force `
            -Confirm:$false `
            -ErrorAction Stop
        
        Write-Host "-= Domain Controller promotion completed successfully =-" -ForegroundColor Green
        Add-Content $logfile "$($Timestamp) - DC promotion complete (GC + DNS)"
    } Catch {
        Write-Warning "Failed to promote to DC: $($_.Exception.Message)"
        Add-Content $logfile "$($Timestamp) - DC promotion failed: $($_.Exception.Message)"
        Break
    }

    Add-Content $logfile "$($Timestamp) - 3-DC-Promotion-Complete"
    Write-Host "-= Server will reboot automatically after promotion =-" -ForegroundColor White -BackgroundColor Red
    Break
}

# ============================
# Phase 4 - Post-Promo Config
# ============================
$fourthcheck = Select-String -Path $logfile -Pattern "4-Post-Config-Complete"
IF (!$fourthcheck) {
    Timestamp
    Write-Host "-= Phase 4: Post-promotion configuration =-" -ForegroundColor Cyan

    # DNS Scavenging
    Try {
        Write-Host "-= Enabling DNS Scavenging... =-" -ForegroundColor Yellow
        Set-DnsServerScavenging -ScavengingState $true -ScavengingInterval 7.00:00:00 -ErrorAction Stop
        Set-DnsServerZoneAging $domainname -Aging $true -RefreshInterval 7.00:00:00 -NoRefreshInterval 7.00:00:00 -ErrorAction Stop
        
        # Reverse zone (if trouble)
        $reversezone = '0.75.10.in-addr.arpa'
        Try {
            Set-DnsServerZoneAging $reversezone -Aging $true -RefreshInterval 7.00:00:00 -NoRefreshInterval 7.00:00:00 -ErrorAction Stop
        } Catch {
            Write-Host "-= Reverse zone not found, skipping aging config =-" -ForegroundColor Yellow
        }
        
        Write-Host "-= DNS Scavenging enabled =-" -ForegroundColor Green
        Add-Content $logfile "$($Timestamp) - DNS Scavenging enabled"
    } Catch {
        Write-Warning "Failed to configure DNS scavenging: $($_.Exception.Message)"
    }

    # NTP ( Replica will sync with PDC automatically, but we never know)
    Write-Host "-= NTP: Replica will sync with PDC automatically =-" -ForegroundColor Green
    Add-Content $logfile "$($Timestamp) - NTP syncs with PDC (no manual config needed)"

    Add-Content $logfile "$($Timestamp) - 4-Post-Config-Complete"
    Write-Host "-= Post-promotion configuration complete =-" -ForegroundColor Green
}

# ============================
# Phase 5 - Zone DNS woodgrovebank.com
# ============================
$dnscheck = Select-String -Path $logfile -Pattern "5-DNS-Zone-Woodgrove-Complete"
IF (!$dnscheck) {
    Timestamp
    Write-Host "-= Phase 5: Creating DNS zone woodgrovebank.com =-" -ForegroundColor Cyan
    
    Try {
        Write-Host "-= Creating primary DNS zone woodgrovebank.com... =-" -ForegroundColor Yellow
        Add-DnsServerPrimaryZone -Name "woodgrovebank.com" -ReplicationScope "Forest" -ErrorAction Stop
        Write-Host "-= Zone woodgrovebank.com created successfully =-" -ForegroundColor Green
        Add-Content $logfile "$($Timestamp) - DNS zone woodgrovebank.com created"
        
        # Ajout d'une entrée A de test
        Add-DnsServerResourceRecordA -Name "www" -ZoneName "woodgrovebank.com" -IPv4Address "10.75.0.11" -ErrorAction Stop
        Write-Host "-= Added test record: www.woodgrovebank.com -> 10.75.0.11 =-" -ForegroundColor Green
        Add-Content $logfile "$($Timestamp) - Added www.woodgrovebank.com A record"
        
    } Catch {
        Write-Warning "Failed to create DNS zone: $($_.Exception.Message)"
        Add-Content $logfile "$($Timestamp) - DNS zone creation failed"
    }

    Add-Content $logfile "$($Timestamp) - 5-DNS-Zone-Woodgrove-Complete"
    Write-Host "-= DNS zone woodgrovebank.com configuration complete =-" -ForegroundColor Green
}

# ============================
# Script Complete
# ============================
Timestamp
Write-Host "`n================================================" -ForegroundColor Cyan
Write-Host "   SRV2 Configuration Complete!" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Server: $computername.$domainname" -ForegroundColor White
Write-Host "IP: $ethipaddress" -ForegroundColor White
Write-Host "Roles: DC Replica + DNS" -ForegroundColor White
Write-Host "DNS Zone: woodgrovebank.com" -ForegroundColor White
Write-Host "================================================`n" -ForegroundColor Cyan
Add-Content $logfile "$($Timestamp) - All SRV2 configuration complete"
