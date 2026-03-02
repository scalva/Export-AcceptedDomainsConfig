# AcceptedDomainsAnalyzer

Exports Exchange Online **Accepted Domains** configuration and (optionally) runs **domain DNS health checks** (MX/SPF/DKIM/DMARC/MTA) and exports everything to CSV.

- PowerShell 7 compatible
- Designed for Microsoft 365 consulting / auditing
- Best-effort approach: continues when some checks/cmdlets/modules are not available

![PowerShell](https://img.shields.io/badge/PowerShell-7+-blue)
![Exchange Online](https://img.shields.io/badge/Exchange-Online-green)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Release](https://img.shields.io/github/v/release/scalva/Export-AcceptedDomainsConfig)
![Last Commit](https://img.shields.io/github/last-commit/scalva/Export-AcceptedDomainsConfig)

## Credits

This project is based on the original work by **Ernesto Cobos Roqueñí**.

Original script inspiration and implementation:

https://github.com/ernestocrmsft/guacamole/blob/main/Scripts/GetAcceptedDomains-HealthChecker.ps1

The original script was adapted and significantly extended to support:

- Exchange Online consulting and audit scenarios
- PowerShell 7 compatibility
- Execution logging and structured output
- PASS / FAIL authentication posture analysis (SPF, DKIM, DMARC)
- Multi-tenant friendly execution

Many thanks for the original idea and implementation.

## What it does

- Retrieves `Get-AcceptedDomain` from Exchange Online
- Optionally performs DNS checks per accepted domain:
  - MX lookup (via `Resolve-DnsName` when available)
  - SPF / DKIM / DMARC / MTA (via `DomainHealthChecker` module)
- Exports a single CSV with both configuration and analysis fields

## Requirements

- PowerShell 7+
- ExchangeOnlineManagement module (script imports it; can optionally install it)
- Permissions to connect to Exchange Online and run `Get-AcceptedDomain`
- Optional (for DNS checks): `DomainHealthChecker` module

## Usage

### Basic export (no DNS checks)
```powershell
.\Export-AcceptedDomainsConfig.ps1 -OutputPath .\AcceptedDomains.csv