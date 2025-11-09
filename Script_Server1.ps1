# ============================
# Script: Windows Server 2025 DC Deployment
# Purpose: Automated deployment of Primary Domain Controller
# Author:Benjamin BACLE
# Date: 11/2025
#Credits David Rdriguez
# ============================


$ethipaddress = '10.75.0.10' # static IP Address of the server
$ethprefixlength = '16' # subnet mask - 16 = 255.255.0.0
$ethdefaultgw = '10.75.0.1' # default gateway
$ethdnsprimary = '127.0.0.1' # DNS Primary (localhost)
$ethdnssecondary = '10.75.0.11' # DNS Secondary (SRV2)
$globalsubnet = '10.75.0.0/16' # Global Subnet will be used in DNS Reverse Record and AD Sites and Services Subnet
$subnetlocation = 'Paris'
$sitename = 'ParisHQ' # Renames Default-First-Site within AD Sites and Services

# Active Directory Variables
$domainname = 'adatum.fr' # enter in your active directory domain
$passwordforusers = ConvertTo-SecureString "P@ssw0rd123456!" -AsPlainText -Force # Default password for imported users

# Disable IE Enhanced Security Configuration Variable
$disableiesecconfig = 'yes' # to disable IE Enhanced Security Configuration, set this variable to yes. to leave enabled, set this variable to no

# Hostname Variables
$computername = 'SERVERDC1' # enter in your server name

# NTP Variables
$ntpserver1 = '0.au.pool.ntp.org'
$ntpserver2 = '1.au.pool.ntp.org'

# DNS Variables
$reversezone = '75.10.in-addr.arpa'

# DHCP Variables
$ScopeStart = "10.75.0.1"
$ScopeEnd = "10.75.0.200"
$ScopeMask = "255.255.0.0"
$ScopeGateway = "10.75.0.1"
$ScopeName = "Scope_TESTDOMAIN"

# Timestamp
Function Timestamp {
    $Global:timestamp = Get-Date -Format "dd-MM-yyy_hh:mm:ss"
}

# Log File Location
$logfile = "C:\Windows-2025-AD-Deployment-log.txt"

# Create Log File
Write-Host "-= Get timestamp =-" -ForegroundColor Green
Timestamp

IF (Test-Path $logfile) {
    Write-Host "-= Logfile Exists =-" -ForegroundColor Yellow
}
ELSE {
    Write-Host "-= Creating Logfile =-" -ForegroundColor Green
    Try {
        New-Item -ItemType File -Path $logfile -ErrorAction Stop | Out-Null
        Write-Host "-= The file $($logfile) has been created =-" -ForegroundColor Green
    }
    Catch {
        Write-Warning -Message $("Could not create logfile. Error: "+ $_.Exception.Message)
        Break;
    }
}

# Check Script Progress via Logfile
$firstcheck = Select-String -Path $logfile -Pattern "1-Basic-Server-Config-Complete"

IF (!$firstcheck) {

    # Add starting date and time
    Write-Host "-= 1-Basic-Server-Config-Complete, does not exist =-" -ForegroundColor Yellow
    Timestamp
    Add-Content $logfile "$($Timestamp) - Starting Active Directory Script"

    ## 1-Basic-Server-Config ##
    #------------ SETTINGS ------------
    # Set Network
    Timestamp
    Try {
        New-NetIPAddress -IPAddress $ethipaddress -PrefixLength $ethprefixlength -DefaultGateway $ethdefaultgw -InterfaceIndex (Get-NetAdapter).InterfaceIndex -ErrorAction Stop | Out-Null
        Set-DNSClientServerAddress -ServerAddresses $ethdnsprimary,$ethdnssecondary -InterfaceIndex (Get-NetAdapter).InterfaceIndex -ErrorAction Stop
        Write-Host "-= IP Address successfully set to $($ethipaddress), subnet $($ethprefixlength), default gateway $($ethdefaultgw) and DNS Servers $($ethdnsprimary), $($ethdnssecondary) =-" -ForegroundColor Green
        Add-Content $logfile "$($Timestamp) - IP Address successfully set to $($ethipaddress), subnet $($ethprefixlength), default gateway $($ethdefaultgw) and DNS Servers $($ethdnsprimary), $($ethdnssecondary)"
    }
    Catch {
        Write-Warning -Message $("Failed to apply network settings. Error: "+ $_.Exception.Message)
        Break;
    }

    # Disable IE Enhanced Security Configuration
    Timestamp 
    Try {
        IF ($disableiesecconfig -eq "yes") {
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}' -name IsInstalled -Value 0 -ErrorAction Stop
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}' -name IsInstalled -Value 0 -ErrorAction Stop
            Write-Host "-= IE Enhanced Security Configuration successfully disabled for Admin and User =-" -ForegroundColor Green
            Add-Content $logfile "$($Timestamp) - IE Enhanced Security Configuration successfully disabled for Admin and User"
        }
    }
    Catch {
        Write-Warning -Message $("Failed to disable Ie Security Configuration. Error: "+ $_.Exception.Message)
        Break;
    }

    If ($disableiesecconfig -ne "yes") {
        Write-Host "-= IE Enhanced Security Configuration remains enabled =-" -ForegroundColor Green
        Add-Content $logfile "$($Timestamp) - IE Enhanced Security Configuration remains enabled"
    }

    # Set Hostname
    Timestamp
    Try {
        Rename-Computer -ComputerName $env:computername -NewName $computername -ErrorAction Stop | Out-Null
        Write-Host "-= Computer name set to $($computername) =-" -ForegroundColor Green
        Add-Content $logfile "$($Timestamp) - Computer name set to $($computername)"
    }
    Catch {
        Write-Warning -Message $("Failed to set new computer name. Error: "+ $_.Exception.Message)
        Break;
    }

    # Add first script complete to logfile
    Timestamp
    Add-Content $logfile "$($Timestamp) - 1-Basic-Server-Config-Complete"

    # Reboot Computer to apply settings
    Timestamp
    Write-Host "-= Save all your work, computer rebooting in 30 seconds =-"  -ForegroundColor White -BackgroundColor Red
    Sleep 30

    Try {
        Restart-Computer -ComputerName $env:computername -ErrorAction Stop
        Write-Host "-= Rebooting Now!! =-" -ForegroundColor Green
        Add-Content $logfile "$($Timestamp) - Rebooting Now!!"
        Break;
    }
    Catch {
        Write-Warning -Message $("Failed to restart computer $($env:computername). Error: "+ $_.Exception.Message)
        Break;
    }
}

# Check Script Progress via Logfile
$secondcheck = Get-Content $logfile | Where-Object { $_.Contains("1-Basic-Server-Config-Complete") }

IF ($secondcheck) {
    $thirdcheck = Get-Content $logfile | Where-Object { $_.Contains("2-Build-Active-Directory-Complete") }

    IF (!$thirdcheck) {

        ## 2-Build-Active-Directory ##
        Timestamp
        
        #------------- VARIABLES -------------
        $dsrmpassword = Read-Host "Enter Directory Services Restore Password" -AsSecureString

        #------------ SETTINGS ------------
        # Install Active Directory Services
        Timestamp
        Try {
            Write-Host "-= Active Directory Domain Services installing =-" -ForegroundColor Yellow
            Install-WindowsFeature -name AD-Domain-Services -IncludeManagementTools
            Write-Host "-= Active Directory Domain Services installed successfully =-" -ForegroundColor Green
            Add-Content $logfile "$($Timestamp) - Active Directory Domain Services installed successfully"
        }
        Catch {
            Write-Warning -Message $("Failed to install Active Directory Domain Services. Error: "+ $_.Exception.Message)
            Break;
        }

        # Configure Active Directory
        Timestamp
        Try {
            Write-Host "-= Configuring Active Directory Domain Services =-" -ForegroundColor Yellow
            Install-ADDSForest -DomainName $domainname -InstallDNS -ErrorAction Stop -NoRebootOnCompletion -SafeModeAdministratorPassword $dsrmpassword -Confirm:$false | Out-Null
            Write-Host "-= Active Directory Domain Services configured successfully =-" -ForegroundColor Green
            Add-Content $logfile "$($Timestamp) - Active Directory Domain Services configured successfully"
        }
        Catch {
            Write-Warning -Message $("Failed to configure Active Directory Domain Services. Error: "+ $_.Exception.Message)
            Break;
        }

        # Add second script complete to logfile
        Timestamp
        Add-Content $logfile "$($Timestamp) - 2-Build-Active-Directory-Complete"

        # Reboot Computer to apply settings
        Write-Host "-= Save all your work, computer rebooting in 30 seconds =-" -ForegroundColor White -BackgroundColor Red
        Sleep 30

        Try {
            Restart-Computer -ComputerName $env:computername -ErrorAction Stop
            Write-Host "Rebooting Now!!" -ForegroundColor Green
            Add-Content $logfile "$($Timestamp) - Rebooting Now!!"
            Break;
        }
        Catch {
            Write-Warning -Message $("Failed to restart computer $($env:computername). Error: "+ $_.Exception.Message)
            Break;
        }
    }
}

# Check Script Progress via Logfile
$fourthcheck = Get-Content $logfile | Where-Object { $_.Contains("2-Build-Active-Directory-Complete") }

IF ($fourthcheck) {
    $fifthcheck = Get-Content $logfile | Where-Object { $_.Contains("3-Finalize-AD-Config-Complete") }

    IF (!$fifthcheck) {
        ## 3-Finalize-AD-Config ##
        Timestamp

        # Add DNS Reverse Record
        Try {
            Add-DnsServerPrimaryZone -NetworkId $globalsubnet -DynamicUpdate Secure -ReplicationScope Domain -ErrorAction Stop
            Write-Host "-= Successfully added in $($globalsubnet) as a reverse lookup within DNS =-" -ForegroundColor Green
            Add-Content $logfile "$($Timestamp) - Successfully added $($globalsubnet) as a reverse lookup within DNS"
        }
        Catch {
            Write-Warning -Message $("Failed to create reverse DNS lookups zone for network $($globalsubnet). Error: "+ $_.Exception.Message)
            Break;
        }

        # --- DNS Scavenging ---
        Write-Host "-= Set DNS Scavenging =-" -ForegroundColor Yellow
        Timestamp
        Try {
            Set-DnsServerScavenging -ScavengingState $true -ScavengingInterval 7.00:00:00 -Verbose -ErrorAction Stop
            Set-DnsServerZoneAging $domainname -Aging $true -RefreshInterval 7.00:00:00 -NoRefreshInterval 7.00:00:00 -Verbose -ErrorAction Stop
            Set-DnsServerZoneAging $reversezone -Aging $true -RefreshInterval 7.00:00:00 -NoRefreshInterval 7.00:00:00 -Verbose -ErrorAction Stop
            Add-Content $logfile "$($Timestamp) - DNS Scavenging Complete"
        }
        Catch {
            Write-Warning -Message $("Failed to DNS Scavenging. Error: "+ $_.Exception.Message)
            Break;
        }

        Get-DnsServerScavenging
        Write-Host "-= DNS Scavenging Complete =-" -ForegroundColor Green

        # --- DNS Forwarders (Cloudflare for Families) ---
        Timestamp
        Try {
            Set-DnsServerForwarder -IPAddress "1.1.1.3","1.0.0.3" -ErrorAction Stop
            Write-Host "-= DNS Forwarders set to Cloudflare for Families (1.1.1.3, 1.0.0.3) =-" -ForegroundColor Green
            Add-Content $logfile "$($Timestamp) - DNS Forwarders configured"
        }
        Catch {
            Write-Warning -Message $("Failed to set DNS forwarders. Error: "+ $_.Exception.Message)
        }

        # --- DNS Zone fabrikam.fr ---
        Timestamp
        Try {
            Add-DnsServerPrimaryZone -Name "fabrikam.fr" -ReplicationScope "Domain" -DynamicUpdate Secure -ErrorAction Stop
            Add-DnsServerResourceRecordA -Name "web" -ZoneName "fabrikam.fr" -IPv4Address "10.75.0.50" -ErrorAction Stop
            Add-DnsServerResourceRecordAAAA -Name "web" -ZoneName "fabrikam.fr" -IPv6Address "2001:db8::50" -ErrorAction Stop
            Add-DnsServerResourceRecordCName -Name "www" -ZoneName "fabrikam.fr" -HostNameAlias "web.liteware.fr" -ErrorAction Stop
            Write-Host "-= Zone fabrikam.fr created with A, AAAA, CNAME records =-" -ForegroundColor Green
            Add-Content $logfile "$($Timestamp) - Zone fabrikam.fr configured"
        }
        Catch {
            Write-Warning -Message $("Failed to configure fabrikam.fr. Error: "+ $_.Exception.Message)
        }

        # --- DNS Zone liteware.fr with MX records ---
        Timestamp
        Try {
            Add-DnsServerPrimaryZone -Name "liteware.fr" -ReplicationScope "Domain" -DynamicUpdate Secure -ErrorAction Stop
            Add-DnsServerResourceRecordA -Name "web" -ZoneName "liteware.fr" -IPv4Address "10.75.0.51" -ErrorAction Stop
            Add-DnsServerResourceRecordMX -Name "." -ZoneName "liteware.fr" -MailExchange "web.liteware.fr" -Preference 10 -ErrorAction Stop
            Add-DnsServerResourceRecordMX -Name "." -ZoneName "liteware.fr" -MailExchange "srv2.adatum.fr" -Preference 20 -ErrorAction Stop
            Write-Host "-= Zone liteware.fr created with MX records =-" -ForegroundColor Green
            Add-Content $logfile "$($Timestamp) - Zone liteware.fr configured with MX"
        }
        Catch {
            Write-Warning -Message $("Failed to configure liteware.fr. Error: "+ $_.Exception.Message)
        }

        # --- DNS Conditional Forwarder for woodgrovebank.com ---
        Timestamp
        Try {
            Add-DnsServerConditionalForwarderZone -Name "woodgrovebank.com" -MasterServers "10.75.0.11" -ReplicationScope "Domain" -ErrorAction Stop
            Write-Host "-= Conditional Forwarder created: woodgrovebank.com -> 10.75.0.11 =-" -ForegroundColor Green
            Add-Content $logfile "$($Timestamp) - Conditional forwarder woodgrovebank.com created"
        }
        Catch {
            Write-Warning -Message $("Failed to create conditional forwarder. Error: "+ $_.Exception.Message)
        }

        # --- DHCP Integration ---
        Timestamp
        Try {
            Write-Host "-= Installing and configuring DHCP Server =-" -ForegroundColor Yellow
            Install-WindowsFeature -Name DHCP -IncludeManagementTools -ErrorAction Stop
            Add-DhcpServerv4Scope -Name $ScopeName -StartRange $ScopeStart -EndRange $ScopeEnd -SubnetMask $ScopeMask -State Active -ErrorAction Stop
            Set-DhcpServerv4OptionValue -DnsServer $ethipaddress -Router $ScopeGateway -DnsDomain $domainname -ErrorAction Stop
            Write-Host "-= DHCP Server installed and scope configured successfully =-" -ForegroundColor Green
            Add-Content $logfile "$($Timestamp) - DHCP Server installed and configured successfully"
        }
        Catch {
            Write-Warning -Message $("Failed to install or configure DHCP Server. Error: "+ $_.Exception.Message)
            Break;
        }

        # --- DHCP Authorization in Active Directory ---
        Timestamp
        Try {
            Write-Host "-= Authorizing DHCP Server in Active Directory =-" -ForegroundColor Yellow
            Add-DhcpServerInDC -DnsName "$env:COMPUTERNAME.$domainname" -IPAddress $ethipaddress -ErrorAction Stop
            Write-Host "-= DHCP server successfully authorized in Active Directory =-" -ForegroundColor Green
            Add-Content $logfile "$($Timestamp) - DHCP server successfully authorized in Active Directory"
        } Catch {
            Write-Warning -Message $("Failed to authorize DHCP server in Active Directory. Error: " + $_.Exception.Message)
            Add-Content $logfile "$($Timestamp) - DHCP server authorization failed"
        }

        # --- DHCP Post-Deployment Configuration ---
        Timestamp
        Try {
            Write-Host "-= Running DHCP post-deployment configuration... =-" -ForegroundColor Yellow
            netsh dhcp add securitygroups | Out-Null
            Restart-Service DHCPServer -ErrorAction Stop
            Write-Host "-= DHCP post-deployment configuration completed successfully =-" -ForegroundColor Green
            Add-Content $logfile "$($Timestamp) - DHCP post-deployment configuration completed successfully"
        } Catch {
            Write-Warning -Message $("Failed to complete DHCP post-deployment configuration. Error: " + $_.Exception.Message)
            Add-Content $logfile "$($Timestamp) - DHCP post-deployment configuration failed"
        }

        # --- DHCP Conflict Detection ---
        Timestamp
        Try {
            Set-DhcpServerv4DnsSetting -ComputerName $env:COMPUTERNAME -DynamicUpdates "Always" -DeleteDnsRROnLeaseExpiry $True -ErrorAction Stop
            Set-DhcpServerSetting -ConflictDetectionAttempts 3 -ErrorAction Stop
            Write-Host "-= DHCP Conflict Detection enabled (3 attempts) =-" -ForegroundColor Green
            Add-Content $logfile "$($Timestamp) - DHCP Conflict Detection configured"
        }
        Catch {
            Write-Warning -Message $("Failed to configure DHCP conflict detection. Error: "+ $_.Exception.Message)
        }

        # --- DHCP Static Route (Option 121) ---
        Timestamp
        Try {
            $routeValue = [byte[]](24, 192, 168, 21, 10, 75, 255, 254)
            Set-DhcpServerv4OptionValue -ScopeId "10.75.0.0" -OptionId 121 -Value $routeValue -ErrorAction Stop
            Write-Host "-= DHCP Static Route: 192.168.21.0/24 via 10.75.255.254 (Option 121) =-" -ForegroundColor Green
            Add-Content $logfile "$($Timestamp) - DHCP static route configured"
        }
        Catch {
            Write-Warning -Message $("Failed to add DHCP static route. Error: "+ $_.Exception.Message)
        }

        Add-Content $logfile "$($Timestamp) - 3-DHCP-Install-Complete"
        Write-Host "-= DHCP Server installation and authorization complete on primary DC =-" -ForegroundColor Green

        # Create Active Directory Sites and Services
        Timestamp
        Try {
            New-ADReplicationSubnet -Name $globalsubnet -Site "Default-First-Site-Name" -Location $subnetlocation -ErrorAction Stop
            Write-Host "-= Successfully added Subnet $($globalsubnet) with location $($subnetlocation) in AD Sites and Services =-" -ForegroundColor Green
            Add-Content $logfile "$($Timestamp) - Successfully added Subnet $($globalsubnet) with location $($subnetlocation) in AD Sites and Services"
        }
        Catch {
            Write-Warning -Message $("Failed to create Subnet $($globalsubnet) in AD Sites and Services. Error: "+ $_.Exception.Message)
            Break;
        }

        # Rename Active Directory Site
        Timestamp
        Try {
            Get-ADReplicationSite Default-First-Site-Name | Rename-ADObject -NewName $sitename -ErrorAction Stop
            Write-Host "-= Successfully renamed Default-First-Site-Name to $sitename in AD Sites and Services =-" -ForegroundColor Green
            Add-Content $logfile "$($Timestamp) - Successfully renamed Default-First-Site-Name to $sitename in AD Sites and Services"
        }
        Catch {
            Write-Warning -Message $("Failed to rename site in AD Sites and Services. Error: "+ $_.Exception.Message)
            Break;
        }

        # Add NTP settings to PDC
        Timestamp
        $serverpdc = Get-AdDomainController -Filter * | Where {$_.OperationMasterRoles -contains "PDCEmulator"}

        IF ($serverpdc) {
            Try {
                Start-Process -FilePath "C:\Windows\System32\w32tm.exe" -ArgumentList "/config /manualpeerlist:$($ntpserver1),$($ntpserver2) /syncfromflags:MANUAL /reliable:yes /update" -ErrorAction Stop
                Stop-Service w32time -ErrorAction Stop
                sleep 2
                Start-Service w32time -ErrorAction Stop
                Write-Host "-= Successfully set NTP Servers: $($ntpserver1) and $($ntpserver2) =-" -ForegroundColor Green
                Add-Content $logfile "$($Timestamp) - Successfully set NTP Servers: $($ntpserver1) and $($ntpserver2)"
            }
            Catch {
                Write-Warning -Message $("Failed to set NTP Servers. Error: "+ $_.Exception.Message)
                Break;
            }
        }

        # Script Finished
        Timestamp
        Write-Host "-= 3-Finalize-AD-Config Complete =-" -ForegroundColor Green
        Add-Content $logfile "$($Timestamp) - 3-Finalize-AD-Config-Complete"
    }
}

# Check Script Progress via Logfile
$sixthcheck = Get-Content $logfile | Where-Object { $_.Contains("3-Finalize-AD-Config-Complete") }

IF ($sixthcheck) {
    $seventhcheck = Get-Content $logfile | Where-Object { $_.Contains("4-OU-Users-GPO-Complete") }

    IF (!$seventhcheck) {
        ## 4-Create-OU-Import-Users-GPO ##
        Timestamp
        Write-Host "-= Starting OU Creation, User Import and Password Policy =-" -ForegroundColor Yellow

        # --- Create Organizational Units ---
        Timestamp
        Try {
            # OU principale Managed Objects
            New-ADOrganizationalUnit -Name "Managed Objects" -Path "DC=adatum,DC=fr" -ProtectedFromAccidentalDeletion $true -ErrorAction Stop
            Write-Host "-= OU 'Managed Objects' created =-" -ForegroundColor Green
            Add-Content $logfile "$($Timestamp) - OU Managed Objects created"

            # OU Users sous Managed Objects
            New-ADOrganizationalUnit -Name "Users" -Path "OU=Managed Objects,DC=adatum,DC=fr" -ProtectedFromAccidentalDeletion $true -ErrorAction Stop
            Write-Host "-= OU 'Users' created under Managed Objects =-" -ForegroundColor Green
            Add-Content $logfile "$($Timestamp) - OU Users created"

            # OU Contractors sous Managed Objects
            New-ADOrganizationalUnit -Name "Contractors" -Path "OU=Managed Objects,DC=adatum,DC=fr" -ProtectedFromAccidentalDeletion $true -ErrorAction Stop
            Write-Host "-= OU 'Contractors' created under Managed Objects =-" -ForegroundColor Green
            Add-Content $logfile "$($Timestamp) - OU Contractors created"
        }
        Catch {
            Write-Warning -Message $("Failed to create OUs. Error: "+ $_.Exception.Message)
            Add-Content $logfile "$($Timestamp) - OU creation failed"
        }

        # --- Import Users from CSV using CSVDE ---
        Timestamp
        $csvPath = "C:\usersadatum.csv"
        
        IF (Test-Path $csvPath) {
            Try {
                Write-Host "-= Importing users from $csvPath using CSVDE =-" -ForegroundColor Yellow
                
                # Utilisation de csvde pour importer les utilisateurs
                $csvdeResult = csvde -i -f $csvPath
                
                IF ($LASTEXITCODE -eq 0) {
                    Write-Host "-= Users successfully imported via CSVDE =-" -ForegroundColor Green
                    Add-Content $logfile "$($Timestamp) - Users imported from CSV via CSVDE"
                }
                ELSE {
                    Write-Warning "CSVDE import completed with errors. Check output above."
                    Add-Content $logfile "$($Timestamp) - CSVDE import completed with warnings"
                }
            }
            Catch {
                Write-Warning -Message $("Failed to import users via CSVDE. Error: "+ $_.Exception.Message)
                Add-Content $logfile "$($Timestamp) - CSVDE import failed"
            }
        }
        ELSE {
            Write-Host "-= CSV file not found at $csvPath, skipping user import =-" -ForegroundColor Yellow
            Write-Host "-= Place your CSV file at C:\usersadatum.csv and run: csvde -i -f C:\usersadatum.csv =-" -ForegroundColor Yellow
            Add-Content $logfile "$($Timestamp) - CSV file not found, user import skipped"
        }

        # --- Set Password for Users and Enable Accounts ---
        Timestamp
        Try {
            Write-Host "-= Setting password for all users in Users OU =-" -ForegroundColor Yellow
            Get-ADUser -Filter * -SearchBase "OU=Users,OU=Managed Objects,DC=adatum,DC=fr" | Set-ADAccountPassword -NewPassword $passwordforusers -Reset -ErrorAction Stop
            Get-ADUser -Filter * -SearchBase "OU=Users,OU=Managed Objects,DC=adatum,DC=fr" | Enable-ADAccount -ErrorAction Stop
            Write-Host "-= Password set and accounts enabled for Users OU =-" -ForegroundColor Green
            Add-Content $logfile "$($Timestamp) - Password set for Users OU"
        }
        Catch {
            Write-Warning -Message $("Failed to set password for Users OU. Error: "+ $_.Exception.Message)
        }

        Timestamp
        Try {
            Write-Host "-= Setting password for all users in Contractors OU =-" -ForegroundColor Yellow
            Get-ADUser -Filter * -SearchBase "OU=Contractors,OU=Managed Objects,DC=adatum,DC=fr" | Set-ADAccountPassword -NewPassword $passwordforusers -Reset -ErrorAction Stop
            Get-ADUser -Filter * -SearchBase "OU=Contractors,OU=Managed Objects,DC=adatum,DC=fr" | Enable-ADAccount -ErrorAction Stop
            Write-Host "-= Password set and accounts enabled for Contractors OU =-" -ForegroundColor Green
            Add-Content $logfile "$($Timestamp) - Password set for Contractors OU"
        }
        Catch {
            Write-Warning -Message $("Failed to set password for Contractors OU. Error: "+ $_.Exception.Message)
        }

        # --- Configure Default Domain Password Policy ---
        Timestamp
        Try {
            Write-Host "-= Configuring Default Domain Password Policy =-" -ForegroundColor Yellow
            
            Set-ADDefaultDomainPasswordPolicy -Identity $domainname `
                -MaxPasswordAge "180.00:00:00" `
                -MinPasswordAge "0.00:00:00" `
                -MinPasswordLength 8 `
                -ComplexityEnabled $true `
                -LockoutDuration "00:10:00" `
                -LockoutObservationWindow "00:10:00" `
                -LockoutThreshold 5 `
                -ErrorAction Stop
            
            Write-Host "-= Password Policy configured: Max 180 days, Min 0 days, Length 8, Complexity ON =-" -ForegroundColor Green
            Write-Host "-= Account Lockout: 5 attempts, 10 min lockout duration =-" -ForegroundColor Green
            Add-Content $logfile "$($Timestamp) - Default Domain Password Policy configured"
        }
        Catch {
            Write-Warning -Message $("Failed to configure password policy. Error: "+ $_.Exception.Message)
            Add-Content $logfile "$($Timestamp) - Password policy configuration failed"
        }

        # --- Display Password Policy ---
        Timestamp
        Try {
            Write-Host "`n-= Current Password Policy =-" -ForegroundColor Cyan
            Get-ADDefaultDomainPasswordPolicy -Identity $domainname | Format-List
        }
        Catch {
            Write-Warning -Message $("Failed to display password policy. Error: "+ $_.Exception.Message)
        }

        # Mark completion
        Timestamp
        Add-Content $logfile "$($Timestamp) - 4-OU-Users-GPO-Complete"
        Write-Host "-= OU Creation, User Import and Password Policy Complete =-" -ForegroundColor Green
        Write-Host "-= Active Directory Script Complete =-" -ForegroundColor Green
        Add-Content $logfile "$($Timestamp) - Active Directory Script Complete"
    }
}