# RoleCrawl
<p align="center"><img src="https://github.com/sleeptok3n/RoleCrawl/assets/38359072/304a5dad-add1-4f75-9091-27afb2f20551" alt="RoleCrawl"/></p>
RoleCrawl is a PowerShell module for auditing Azure role assignments across subscriptions, resource groups, and individual resources. The refreshed cmdlets are automation-friendly, emit structured objects, and can export CSV or JSON reports without requiring any interactive prompts.

## Features
- Enumerates role assignments for Azure AD users and groups across one or many subscriptions.
- Works non-interactively for CI/CD or scheduled runs while still supporting verbose progress.
- Enriches each assignment with scope metadata (subscription, resource group, resource type/name).
- Optional CSV/JSON export per principal, with sensible defaults for batch reporting.
- Summaries surface in verbose output to highlight top roles encountered per principal.

## Prerequisites
- PowerShell 5.1 or newer (PowerShell 7 recommended for cross-platform automation).
- Az PowerShell modules with access to `Connect-AzAccount`, `Get-AzSubscription`, `Get-AzRoleAssignment`, and Azure AD cmdlets (`Get-AzADUser`, `Get-AzADGroup`).
- Azure credentials with read access to the target subscriptions and Microsoft Graph directory objects.

## Installation
Import the RoleCrawl module into your session:

```powershell
Import-Module ./RoleCrawl.psm1
```

## Quick Start
Audit the currently signed-in account across every accessible subscription and write a CSV to `./reports`:

```powershell
Get-AzUserRoleAssignments -AllSubscriptions -ExportPath ./reports -Verbose
```

## Targeted Scenarios
### Scan a specific user
```powershell
Get-AzUserRoleAssignments -UserPrincipalName alice@contoso.com -SubscriptionId 11111111-1111-1111-1111-111111111111
```

### Include classic administrators
```powershell
Get-AzUserRoleAssignments -CurrentUser -IncludeClassicAdministrators -AllSubscriptions
```

### Scan multiple groups from a file
```powershell
Get-AzGroupRoleAssignments -InputFile ./group-ids.txt -AllSubscriptions -ExportPath ./reports
```

### Export JSON instead of CSV
```powershell
Get-AzGroupRoleAssignments -GroupDisplayName 'Incident Responders' -ExportPath ./reports/groups.json
```

## Command Reference
- `Get-AzUserRoleAssignments`
  - Identify principals via `-CurrentUser`, `-UserPrincipalName`, or `-UserObjectId`.
  - Scope scans with `-SubscriptionId`, `-SubscriptionName`, or `-AllSubscriptions` (default when unspecified).
  - Use `-TenantId` to force authentication within a specific tenant.
- `Get-AzGroupRoleAssignments`
  - Accepts object IDs (`-GroupObjectId`), display names (`-GroupDisplayName`), or a newline-delimited list (`-InputFile`).
  - Shares the same subscription, export, and tenant parameters as the user cmdlet.

Set `-ExportPath` to a directory for multi-principal exports (files are auto-named). Supplying a `.csv` or `.json` file path is supported when scanning a single principal.

## Output
Both cmdlets return `PSCustomObject` records with the principal metadata, subscription identifiers, scope type (Subscription, ResourceGroup, Resource), resource details, role definition IDs/names, and any conditional access clauses. Verbose output surfaces top role counts, while informational messages confirm export locations when `-ExportPath` is used.

## Use Cases
RoleCrawl was originally built to map permissions within an Azure tenant for offensive security, but the streamlined automation flows also support blue-team investigations, least-privilege reviews, and scheduled compliance checks. Pair RoleCrawl with tools such as [GraphRunner](https://github.com/dafthack/GraphRunner) to pivot from discovered groups to concrete subscription/resource access without manual lookups.
