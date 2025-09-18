# Repository Guidelines

## Project Structure & Module Organization
RoleCrawl is a single-module project (`RoleCrawl.psm1`) that exposes `Get-AzUserRoleAssignments` and `Get-AzGroupRoleAssignments`. Support code lives beside those cmdlets (e.g., `Ensure-RoleCrawlConnection`, `Resolve-RoleCrawlSubscriptions`, `Invoke-RoleCrawlPrincipalScan`). Keep shared helpers internal to the module and prefer composing new capabilities through those utilities. If you add tooling, isolate it in clearly named folders such as `scripts/` or `docs/` and reference them in `README.md`.

## Build, Test, and Development Commands
Load the module with `pwsh -NoProfile -Command "Import-Module ./RoleCrawl.psm1"`. Smoke-test the main flows using non-production tenants:
- `Get-AzUserRoleAssignments -AllSubscriptions -Verbose`
- `Get-AzGroupRoleAssignments -GroupObjectId <guid> -ExportPath ./reports`
Run linting before commits: `pwsh -NoProfile -Command "Invoke-ScriptAnalyzer -Path RoleCrawl.psm1"`. If you introduce automated tests, place them under `tests/` and wire them into CI scripts.

## Coding Style & Naming Conventions
Follow PowerShell advanced-function conventions: `[CmdletBinding()]`, declarative parameters, and verbose-friendly messaging. Use 4-space indentation, PascalCase for functions/parameters, and camelCase for locals. Keep `Write-Host` out of runtime paths—favor `Write-Verbose`, `Write-Warning`, or `Write-Information`. Export only public cmdlets via `Export-ModuleMember` and preserve `Set-StrictMode -Version Latest` unless you have a strong reason to relax it.

## Testing Guidelines
Manual validation remains primary. Cover both user and group scans, exercising subscription filters, JSON/CSV exports, and the `-IncludeClassicAdministrators` switch. Confirm output objects contain the expected fields (scope metadata, role definition IDs) and that exports choose sensible filenames for multi-principal runs. When you add automation, use Pester v5+, mirror the module structure, and provide sample fixtures for role assignment responses.

## Commit & Pull Request Guidelines
Write focused, imperative commit subjects (e.g., "Add JSON export support"). In pull requests, summarize behavioural changes, list validation commands (`Invoke-ScriptAnalyzer`, key cmdlet invocations), and document any tenant, subscription, or module prerequisites for reviewers. Include sanitized snippets of generated output or export paths when UX changes are involved.

## Security & Configuration Tips
Never commit credentials, tenant IDs, or generated CSV/JSON artifacts. Use least-privilege accounts with `Connect-AzAccount`, and call out required Azure RBAC roles in PRs. When sharing repro steps, strip principal identifiers or replace them with placeholders. For automation, prefer managed identities or service principals with read-only scopes and validate that `-TenantId` is honoured in new code paths.
