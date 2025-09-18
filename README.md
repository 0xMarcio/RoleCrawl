# RoleCrawl
<p align="center"><img src="rolecrawl.webp" alt="RoleCrawl" width="50%" /></p>
RoleCrawl is a PowerShell module for auditing Azure role assignments across subscriptions, resource groups, and individual resources. The refreshed cmdlets are automation-friendly, emit structured objects, and can export CSV or JSON reports without requiring any interactive prompts.

## Features
- Enumerates role assignments for Azure AD users and groups across one or many subscriptions.
- Works non-interactively for CI/CD or scheduled runs while still supporting verbose progress.
- Enriches each assignment with scope metadata (subscription, resource group, resource type/name).
- Optional CSV/JSON export per principal, with sensible defaults for batch reporting.
- Summaries surface in verbose output to highlight top roles encountered per principal.
- Augments each assignment with role definition metadata (custom/built-in flag, description, assignable scopes) and emits scope breakdowns for quick triage.
- Automatically logs every Azure cmdlet executed so you can review successes, failures, and messages without enabling debug output.

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
  - Automatically captures subscription, resource-group, and resource-level assignments without additional prompts.
  - Streams structured command and summary sections for autonomous runs (no additional switches required).
- `Get-AzGroupRoleAssignments`
  - Accepts object IDs (`-GroupObjectId`), display names (`-GroupDisplayName`), or a newline-delimited list (`-InputFile`).
  - Shares the same subscription, export, and tenant parameters as the user cmdlet.
  - Outputs enriched role metadata identical to the user cmdlet and renders the same per-principal summaries.

Set `-ExportPath` to a directory for multi-principal exports (files are auto-named). Supplying a `.csv` or `.json` file path is supported when scanning a single principal. Every invocation already uses `-All` internally, so the full dataset is gathered without extra flags.

## Output
Both cmdlets return `PSCustomObject` records with principal metadata, subscription identifiers, scope type (Subscription, ResourceGroup, Resource), resource details, role definition context (name, ID, type, description, assignable scopes), and any conditional access clauses. Console output is also organized into:
- **Initialization** — authentication, principal lookups, and subscription discovery with success/failure state and messages.
- **Principal summaries** — per user/group sections highlighting assignment counts, scope breakdowns, top roles, export paths, and the exact Azure cmdlets executed (with correlated outcomes).
- **Run summary** — totals for principals processed and assignments discovered.

Verbose output continues to surface additional detail, but the structured log ensures failures are visible even with default preferences.

## Use Cases
RoleCrawl was originally built to map permissions within an Azure tenant for offensive security, but the streamlined automation flows also support blue-team investigations, least-privilege reviews, and scheduled compliance checks. Pair RoleCrawl with tools such as [GraphRunner](https://github.com/dafthack/GraphRunner) to pivot from discovered groups to concrete subscription/resource access without manual lookups.
