# AcceptedDomainsAnalyzer

Exports Exchange Online **Accepted Domains** configuration and (optionally) runs **domain DNS health checks** (MX/SPF/DKIM/DMARC/MTA) and exports everything to CSV.

- PowerShell 7 compatible
- Designed for Microsoft 365 consulting / auditing
- Best-effort approach: continues when some checks/cmdlets/modules are not available

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