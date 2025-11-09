# Windows Server 2025 - Active Directory Deployment Scripts

Automated PowerShell scripts for complete Active Directory infrastructure deployment on Windows Server 2025.

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Architecture](#architecture)
- [Available Scripts](#available-scripts)
- [Installation Guide](#installation-guide)
- [Detailed Features](#detailed-features)
- [Domain Structure](#domain-structure)
- [Author](#author)

---

## Overview

This project provides two PowerShell scripts to automatically deploy:
- A **primary domain controller** (SRV1) for the `adatum.fr` domain
- A **replica domain controller** (SRV2) for high availability

The scripts handle the entire process: network configuration, AD-DS installation, advanced DNS configuration, DHCP deployment, OU creation, user import, and security policies.

---

## Prerequisites

### Hardware / Virtualization
- **2 Windows Server 2025 VMs** (Standard or Datacenter)
- **RAM**: 4 GB minimum per server (8 GB recommended)
- **Disk**: 60 GB minimum per server
- **CPU**: 2 vCPU minimum

### Network
- Isolated network with `10.75.0.0/16` subnet
- No existing DHCP/DNS server on the network
- Internet connectivity for updates (optional)

### Required Files
- `Script_Server1.ps1` - Script for primary DC server (SRV1)
- `Script_Server2.ps1` - Script for replica DC server (SRV2)
- `usersadatum.csv` - CSV file containing users to import (optional)

---

## Architecture

```
+-----------------------------------------------------+
|                  Domain adatum.fr                   |
+-----------------------------------------------------+
|                                                     |
|  +------------------+      +------------------+     |
|  |   SERVERDC1      |      |   SERVERDC2      |     |
|  |  10.75.0.10      |<---->|  10.75.0.11      |     |
|  |                  |      |                  |     |
|  | - Primary DC     |      | - Replica DC     |     |
|  | - Global Catalog |      | - Global Catalog |     |
|  | - DNS Server     |      | - DNS Server     |     |
|  | - DHCP Server    |      |                  |     |
|  +------------------+      +------------------+     |
|                                                     |
|  DNS Zones:                                         |
|  - adatum.fr                                        |
|  - fabrikam.fr                                      |
|  - liteware.fr                                      |
|  - woodgrovebank.com (on SRV2)                      |
|                                                     |
|  DHCP Scope: 10.75.0.0/16 -                         |
+-----------------------------------------------------+
```

---

## Available Scripts

### 1. `Script_Server1.ps1` - Primary Server (SRV1)

Deployment script for the primary domain controller with full configuration.

**Automatic configuration:**
- Server name: `SERVERDC1`
- IP address: `10.75.0.10/16`
- Roles: DC, DNS, DHCP, Global Catalog

### 2. `Script_Server2.ps1` - Replica Server (SRV2)

Deployment script for the secondary domain controller for high availability.

**Automatic configuration:**
- Server name: `SERVERDC2`
- IP address: `10.75.0.11/16`
- Roles: DC Replica, DNS, Global Catalog

---

## Installation Guide

### Step 1: Preparation

1. **Install Windows Server 2025** on both VMs
2. **Download the scripts** to each server
3. **Prepare CSV file** (optional): `C:\usersadatum.csv`

### Step 2: Deploy SRV1 (Primary Server)

```powershell
# Allow script execution
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force

# Run the script
.\Script_Server1.ps1
```

**Required interaction:**
- DSRM password (Directory Services Restore Mode) at first reboot
- Script automatically restarts 2 times
- Rerun the script after each reboot

**Total duration: ~15-20 minutes**

### Step 3: Deploy SRV2 (Replica Server)

**Warning:** Wait until SRV1 is fully configured before starting SRV2

```powershell
# Allow script execution
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force

# Run the script
.\Script_Server2.ps1
```

**Required interaction:**
- Domain credentials during domain join (Phase 2)
- Domain credentials + DSRM password during promotion (Phase 3)
- Script automatically restarts 3 times
- Rerun the script after each reboot

**Total duration: ~20-25 minutes**

---

## Detailed Features

### Network Configuration

#### SRV1 - Primary Server
```
IP Address    : 10.75.0.10/16
Gateway       : 10.75.0.1
DNS Primary   : 127.0.0.1 (localhost)
DNS Secondary : 10.75.0.11 (SRV2)
```

#### SRV2 - Replica Server
```
IP Address    : 10.75.0.11/16
Gateway       : 10.75.0.1
DNS Primary   : 10.75.0.10 (SRV1)
```

---

### DNS Configuration

#### DNS Zones Created

**On SRV1:**
- `adatum.fr` - Primary domain zone
- `10.75.0.0/16` - Reverse lookup zone
- `fabrikam.fr` - Secondary zone with records:
  - A record: `web.fabrikam.fr` → `10.75.0.50`
  - AAAA record: `web.fabrikam.fr` → `2001:db8::50`
  - CNAME record: `www.fabrikam.fr` → `web.liteware.fr`
- `liteware.fr` - Zone with MX records:
  - MX (priority 10): `liteware.fr` → `web.liteware.fr`
  - MX (priority 20): `liteware.fr` → `srv2.adatum.fr`

**On SRV2:**
- `woodgrovebank.com` - Standalone zone with:
  - A record: `www.woodgrovebank.com` → `10.75.0.11`

#### DNS Forwarders

**Cloudflare for Families** (malware + adult content filtering):
- Primary: `1.1.1.3`
- Secondary: `1.0.0.3`

#### Conditional Forwarder

SRV1 automatically redirects queries for `woodgrovebank.com` to SRV2 (`10.75.0.11`)

#### DNS Scavenging

Automatic configuration to clean obsolete records:
- Scavenging interval: 7 days
- No-refresh period: 7 days
- Refresh period: 7 days

---

### DHCP Configuration

**DHCP Server:** SRV1 only

#### DHCP Scope
```
Name          : Scope_TESTDOMAIN
Network       : 10.75.0.0/16
IP Range      : 10.75.0.1 - 10.75.0.200
Subnet Mask   : 255.255.0.0
Gateway       : 10.75.0.1
DNS Server    : 10.75.0.10
DNS Domain    : adatum.fr
```

#### Advanced Options

**IP Conflict Detection:**
- Number of attempts: **3 pings** before IP assignment
- Prevents conflicts with static IP machines

**Static Route (Option 121):**
- Network: `192.168.21.0/24`
- Gateway: `10.75.255.254`
- Allows DHCP clients to access remote network

---

### Active Directory Configuration

#### Organizational Units (OU)

Automatically created structure:

```
adatum.fr
└── Managed Objects
    ├── Users         (Permanent users)
    └── Contractors   (Contractors/Interns)
```

Protection against accidental deletion enabled on all OUs.

#### User Import

**Method:** CSVDE (CSV Directory Exchange)

**File location:** `C:\usersadatum.csv`

**Expected CSV format:**
```csv
dn,objectClass,sAMAccountName,givenName,sn,userPrincipalName,description
"CN=John Doe,OU=Users,OU=Managed Objects,DC=adatum,DC=fr",user,jdoe,John,Doe,jdoe@adatum.fr,Sales Representative
"CN=Jane Smith,OU=Users,OU=Managed Objects,DC=adatum,DC=fr",user,jsmith,Jane,Smith,jsmith@adatum.fr,Accounting Personnel
```

**User configuration:**
- Initial password: `P@ssw0rd123456!`
- Accounts automatically enabled
- Password change not forced at first logon

---

### Password Policy

Domain-level configuration:

| Parameter | Value |
|-----------|-------|
| Maximum password age | **180 days** |
| Minimum password age | **0 days** |
| Minimum password length | **8 characters** |
| Complexity required | **Enabled** |
| Password history | Default (24) |

#### Account Lockout Policy

| Parameter | Value |
|-----------|-------|
| Lockout threshold | **5 attempts** |
| Lockout duration | **10 minutes** |
| Reset counter after | **10 minutes** |

---

### NTP Configuration

**Primary server (SRV1) only:**
- NTP Server 1: `0.au.pool.ntp.org`
- NTP Server 2: `1.au.pool.ntp.org`
- Mode: MANUAL (reliable time source)

SRV2 automatically synchronizes its clock with SRV1.

---

### AD Sites and Services

| Parameter | Value |
|-----------|-------|
| Site name | `ParisHQ` |
| Subnet | `10.75.0.0/16` |
| Location | `Paris` |

The default site `Default-First-Site-Name` is automatically renamed to `ParisHQ`.

---

## Domain Structure

### General Information

```
Domain name    : adatum.fr
Global Catalog : SRV1 + SRV2
```

---

## Logs and Tracking

### Log Files

**SRV1:**
```
C:\Windows-2025-AD-Deployment-log.txt
```

**SRV2:**
```
C:\Windows-2025-AD-Replica-log.txt
```

### Execution Phases

#### SRV1 - 4 Phases
1. `1-Basic-Server-Config-Complete` - Network and hostname configuration
2. `2-Build-Active-Directory-Complete` - AD-DS installation
3. `3-Finalize-AD-Config-Complete` - DNS, DHCP, Sites
4. `4-OU-Users-GPO-Complete` - OUs, users, policies

#### SRV2 - 5 Phases
1. `1-Basic-Server-Config-Complete` - Network and hostname configuration
2. `2-Domain-Join-Complete` - Domain join
3. `3-DC-Promotion-Complete` - DC promotion
4. `4-Post-Config-Complete` - DNS configuration
5. `5-DNS-Zone-Woodgrove-Complete` - woodgrovebank.com zone

---

## Author

**Project developed as part of Windows Server 2025 practical work**

Contact: benjamin@voyager3.fr
School: IPSSI
Date: November 2025

---

## License

This project is provided for educational purposes only.

---

## Warnings

- **Do not use in production** without additional adaptation and security hardening
- Default passwords must be changed
- Test in an isolated environment before any deployment
- Backup your data before execution

---

**If this project was helpful, feel free to star it!**
