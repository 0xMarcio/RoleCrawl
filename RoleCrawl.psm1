# Author: Eli Ainhorn (sleeptok3n)
# License: BSD 3-Clause

Set-StrictMode -Version Latest

function ConvertFrom-RoleCrawlJwtPayload {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Token
    )

    $segments = $Token.Split('.')
    if ($segments.Count -lt 2) {
        throw "The access token is not a valid JWT"
    }

    $payload = $segments[1].Replace('-', '+').Replace('_', '/')
    $padding = (4 - ($payload.Length % 4)) % 4
    if ($padding) {
        $payload += '=' * $padding
    }

    $bytes = [System.Convert]::FromBase64String($payload)
    $jsonPayload = [System.Text.Encoding]::UTF8.GetString($bytes)
    return $jsonPayload | ConvertFrom-Json
}

function Get-RoleCrawlSafeFileName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Value
    )

    $invalid = [System.IO.Path]::GetInvalidFileNameChars()
    $builder = New-Object System.Text.StringBuilder
    foreach ($character in $Value.ToCharArray()) {
        if ($invalid -contains $character) {
            [void]$builder.Append('_')
        } else {
            [void]$builder.Append($character)
        }
    }

    $result = $builder.ToString().Trim('_')
    if (-not $result) {
        $result = 'rolecrawldata'
    }
    return $result
}

function Ensure-RoleCrawlConnection {
    [CmdletBinding()]
    param(
        [string]$TenantId
    )

    $context = Get-AzContext -ErrorAction SilentlyContinue
    $needsLogin = $false

    if (-not $context -or -not $context.Account) {
        $needsLogin = $true
    } elseif ($TenantId -and $context.Tenant -and $context.Tenant.Id -ne $TenantId) {
        $needsLogin = $true
    }

    if ($needsLogin) {
        $connectParams = @{}
        if ($TenantId) {
            $connectParams['Tenant'] = $TenantId
        }
        $context = Connect-AzAccount @connectParams
    }

    return $context
}

function Get-RoleCrawlCurrentUser {
    [CmdletBinding()]
    param()

    $token = Get-AzAccessToken -ResourceUrl 'https://graph.microsoft.com/' -ErrorAction Stop
    $payload = ConvertFrom-RoleCrawlJwtPayload -Token $token.Token

    $objectId = $payload.oid
    $principalName = $payload.preferred_username
    $displayName = $payload.name

    try {
        $user = Get-AzADUser -ObjectId $objectId -ErrorAction Stop
        if ($user.DisplayName) {
            $displayName = $user.DisplayName
        }
        if ($user.UserPrincipalName) {
            $principalName = $user.UserPrincipalName
        }
    } catch {
        Write-Verbose "Unable to resolve additional metadata for the current user: $($_.Exception.Message)"
    }

    return [pscustomobject]@{
        ObjectId      = $objectId
        PrincipalName = $principalName
        DisplayName   = $displayName
    }
}

function Resolve-RoleCrawlPrincipal {
    [CmdletBinding(DefaultParameterSetName = 'ObjectId')]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('User', 'Group')]
        [string]$Type,

        [Parameter(ParameterSetName = 'ObjectId')]
        [string]$ObjectId,

        [Parameter(ParameterSetName = 'PrincipalName')]
        [string]$PrincipalName
    )

    if (-not $ObjectId -and -not $PrincipalName) {
        throw "Either ObjectId or PrincipalName must be provided"
    }

    $lookupParams = @{}
    $lookupCommand = $null

    if ($Type -eq 'User') {
        $lookupCommand = 'Get-AzADUser'
        if ($ObjectId) {
            $lookupParams['ObjectId'] = $ObjectId
        } else {
            $lookupParams['UserPrincipalName'] = $PrincipalName
        }
    } else {
        $lookupCommand = 'Get-AzADGroup'
        if ($ObjectId) {
            $lookupParams['ObjectId'] = $ObjectId
        } else {
            $lookupParams['DisplayName'] = $PrincipalName
        }
    }

    try {
        $principal = & $lookupCommand @lookupParams -ErrorAction Stop
    } catch {
        Write-Warning "Unable to resolve $Type '$($ObjectId ?? $PrincipalName)': $($_.Exception.Message)"
        return $null
    }

    if ($principal -is [System.Array] -and $principal.Count -gt 1) {
        Write-Warning "$Type lookup for '$($PrincipalName ?? $ObjectId)' returned multiple matches. Using the first entry ($($principal[0].Id))."
        $principal = $principal[0]
    }

    $metadata = [ordered]@{
        ObjectId      = $principal.Id
        DisplayName   = $principal.DisplayName
        PrincipalName = $null
    }

    if ($Type -eq 'User') {
        $metadata.PrincipalName = $principal.UserPrincipalName
    } else {
        $metadata.PrincipalName = $principal.Mail
        if (-not $metadata.PrincipalName) {
            $metadata.PrincipalName = $principal.DisplayName
        }
    }

    return [pscustomobject]$metadata
}

function Resolve-RoleCrawlSubscriptions {
    [CmdletBinding()]
    param(
        [string[]]$SubscriptionId,
        [string[]]$SubscriptionName,
        [switch]$All
    )

    $subscriptions = New-Object System.Collections.Generic.List[object]

    if ($SubscriptionId) {
        foreach ($id in $SubscriptionId) {
            if ([string]::IsNullOrWhiteSpace($id)) {
                continue
            }
            try {
                $subscription = Get-AzSubscription -SubscriptionId $id -ErrorAction Stop
                $subscriptions.Add($subscription) | Out-Null
            } catch {
                Write-Warning "Unable to resolve subscription '$id': $($_.Exception.Message)"
            }
        }
    }

    if ($SubscriptionName) {
        foreach ($name in $SubscriptionName) {
            if ([string]::IsNullOrWhiteSpace($name)) {
                continue
            }
            try {
                $subscription = Get-AzSubscription -SubscriptionName $name -ErrorAction Stop
                $subscriptions.Add($subscription) | Out-Null
            } catch {
                Write-Warning "Unable to resolve subscription '$name': $($_.Exception.Message)"
            }
        }
    }

    if (-not $subscriptions.Count -and ($All.IsPresent -or (-not $SubscriptionId -and -not $SubscriptionName))) {
        try {
            $allSubscriptions = Get-AzSubscription -ErrorAction Stop
            foreach ($subscription in $allSubscriptions) {
                $subscriptions.Add($subscription) | Out-Null
            }
        } catch {
            throw "Unable to enumerate subscriptions: $($_.Exception.Message)"
        }
    }

    $unique = $subscriptions | Sort-Object -Property Id -Unique
    if (-not $unique) {
        throw "No subscriptions resolved. Provide -SubscriptionId/-SubscriptionName or ensure the connected account has access."
    }
    return $unique
}

function Get-RoleCrawlScopeInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Scope,
        [Parameter(Mandatory)]
        [string]$SubscriptionId
    )

    $info = [ordered]@{
        ScopeType    = 'Subscription'
        ResourceGroup = $null
        ResourceName  = $null
        ResourceType  = $null
    }

    $normalizedScope = $Scope.TrimEnd('/')

    if ($normalizedScope -match "/subscriptions/$SubscriptionId/resourceGroups/([^/]+)$") {
        $info.ScopeType = 'ResourceGroup'
        $info.ResourceGroup = $matches[1]
        return [pscustomobject]$info
    }

    if ($normalizedScope -match "/subscriptions/$SubscriptionId/resourceGroups/([^/]+)/providers/(.+)$") {
        $info.ScopeType = 'Resource'
        $info.ResourceGroup = $matches[1]
        $providerSegment = $matches[2]
        $segments = $providerSegment.Split('/')
        if ($segments.Length -ge 2) {
            $info.ResourceType = "$($segments[0])/$($segments[1])"
            $info.ResourceName = $segments[-1]
        }

        try {
            $resource = Get-AzResource -ResourceId $normalizedScope -ErrorAction Stop
            if ($resource.ResourceGroupName) {
                $info.ResourceGroup = $resource.ResourceGroupName
            }
            if ($resource.Name) {
                $info.ResourceName = $resource.Name
            }
            if ($resource.ResourceType) {
                $info.ResourceType = $resource.ResourceType
            }
        } catch {
            Write-Verbose "Unable to resolve metadata for resource scope '$normalizedScope': $($_.Exception.Message)"
        }
    }

    return [pscustomobject]$info
}

function Export-RoleCrawlData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IEnumerable]$Data,
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$PrincipalIdentifier
    )

    $dataArray = @($Data)
    if (-not $dataArray.Count) {
        return $null
    }

    $targetPath = $Path
    $format = 'csv'

    if (Test-Path $targetPath) {
        $item = Get-Item $targetPath
        if ($item.PSIsContainer) {
            $safeName = Get-RoleCrawlSafeFileName -Value $PrincipalIdentifier
            $targetPath = Join-Path -Path $item.FullName -ChildPath ("{0}-role-assignments.csv" -f $safeName)
        } else {
            $extension = [System.IO.Path]::GetExtension($targetPath)
            if ($extension) {
                $format = $extension.TrimStart('.').ToLowerInvariant()
            }
        }
    } else {
        $extension = [System.IO.Path]::GetExtension($targetPath)
        if (-not $extension -and [System.IO.Directory]::Exists($targetPath)) {
            $safeName = Get-RoleCrawlSafeFileName -Value $PrincipalIdentifier
            $targetPath = Join-Path -Path $targetPath -ChildPath ("{0}-role-assignments.csv" -f $safeName)
        } elseif (-not $extension) {
            $targetPath = $targetPath + '.csv'
        } else {
            $format = $extension.TrimStart('.').ToLowerInvariant()
        }
    }

    if ($format -notin @('csv', 'json')) {
        Write-Warning "Unsupported export format '$format'. Defaulting to CSV."
        $format = 'csv'
        $targetPath = [System.IO.Path]::ChangeExtension($targetPath, '.csv')
    }

    $directory = Split-Path -Parent $targetPath
    if (-not $directory) {
        $directory = (Get-Location).Path
    }
    if (-not (Test-Path $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }

    switch ($format) {
        'json' {
            $json = $dataArray | ConvertTo-Json -Depth 6
            Set-Content -Path $targetPath -Value $json -Encoding utf8
        }
        default {
            $dataArray | Export-Csv -Path $targetPath -NoTypeInformation -Encoding UTF8
        }
    }

    return $targetPath
}

function Invoke-RoleCrawlPrincipalScan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('User', 'Group')]
        [string]$PrincipalType,
        [Parameter(Mandatory)]
        [string]$PrincipalObjectId,
        [string]$PrincipalName,
        [string]$PrincipalDisplayName,
        [Parameter(Mandatory)]
        [object[]]$Subscriptions,
        [string]$ExportPath,
        [switch]$IncludeClassicAdministrators
    )

    $results = New-Object System.Collections.Generic.List[pscustomobject]
    $subscriptionCount = $Subscriptions.Count

    for ($index = 0; $index -lt $subscriptionCount; $index++) {
        $subscription = $Subscriptions[$index]
        $progress = if ($subscriptionCount) { (($index + 1) / $subscriptionCount) * 100 } else { 100 }
        Write-Progress -Activity "Scanning $PrincipalType role assignments" -Status $subscription.Name -PercentComplete $progress

        try {
            Set-AzContext -SubscriptionId $subscription.Id -ErrorAction Stop | Out-Null
        } catch {
            Write-Warning "Unable to set context for subscription $($subscription.Name) ($($subscription.Id)): $($_.Exception.Message)"
            continue
        }

        try {
            $assignments = Get-AzRoleAssignment -ObjectId $PrincipalObjectId -Scope "/subscriptions/$($subscription.Id)" -IncludeClassicAdministrators:$IncludeClassicAdministrators.IsPresent -ErrorAction Stop
        } catch {
            Write-Warning "Failed to retrieve assignments for subscription $($subscription.Name): $($_.Exception.Message)"
            continue
        }

        foreach ($assignment in $assignments) {
            $scopeInfo = Get-RoleCrawlScopeInfo -Scope $assignment.Scope -SubscriptionId $subscription.Id
            $results.Add([pscustomobject]@{
                PrincipalType        = $PrincipalType
                PrincipalObjectId    = $PrincipalObjectId
                PrincipalName        = $PrincipalName
                PrincipalDisplayName = $PrincipalDisplayName
                SubscriptionId       = $subscription.Id
                SubscriptionName     = $subscription.Name
                Scope                = $assignment.Scope
                ScopeType            = $scopeInfo.ScopeType
                ResourceGroup        = $scopeInfo.ResourceGroup
                ResourceName         = $scopeInfo.ResourceName
                ResourceType         = $scopeInfo.ResourceType
                RoleDefinitionName   = $assignment.RoleDefinitionName
                RoleDefinitionId     = $assignment.RoleDefinitionId
                CanDelegate          = $assignment.CanDelegate
                Condition            = $assignment.Condition
                ConditionVersion     = $assignment.ConditionVersion
            }) | Out-Null
        }
    }

    Write-Progress -Activity "Scanning $PrincipalType role assignments" -Completed

    if ($results.Count) {
        $subscriptionSummary = ($results | Select-Object -ExpandProperty SubscriptionId -Unique).Count
        $roleSummary = ($results | Group-Object RoleDefinitionName | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object { "{0}({1})" -f $_.Name, $_.Count }) -join ', '
        if (-not $roleSummary) {
            $roleSummary = 'n/a'
        }
        Write-Verbose ("Found {0} assignments across {1} subscriptions for {2}" -f $results.Count, $subscriptionSummary, ($PrincipalDisplayName ?? $PrincipalObjectId))
        Write-Verbose ("Top role assignments: {0}" -f $roleSummary)
    } else {
        Write-Verbose ("No role assignments found for {0}" -f ($PrincipalDisplayName ?? $PrincipalObjectId))
    }

    if ($ExportPath) {
        $identifier = $PrincipalDisplayName
        if (-not $identifier) {
            $identifier = $PrincipalName
        }
        if (-not $identifier) {
            $identifier = $PrincipalObjectId
        }

        $exportedPath = Export-RoleCrawlData -Data $results -Path $ExportPath -PrincipalIdentifier $identifier
        if ($exportedPath) {
            Write-Information "Exported assignments for $identifier to $exportedPath" -InformationAction Continue
        }
    }

    return $results
}

function Get-AzUserRoleAssignments {
    [CmdletBinding()]
    param(
        [string[]]$UserObjectId,
        [string[]]$UserPrincipalName,
        [switch]$CurrentUser,
        [string[]]$SubscriptionId,
        [string[]]$SubscriptionName,
        [switch]$AllSubscriptions,
        [string]$ExportPath,
        [switch]$IncludeClassicAdministrators,
        [string]$TenantId
    )

    Ensure-RoleCrawlConnection -TenantId $TenantId | Out-Null

    if (-not $UserObjectId -and -not $UserPrincipalName -and -not $CurrentUser.IsPresent) {
        $CurrentUser = $true
    }

    $principalBuffer = New-Object System.Collections.Generic.List[pscustomobject]

    if ($CurrentUser.IsPresent) {
        try {
            $current = Get-RoleCrawlCurrentUser
            $principalBuffer.Add($current) | Out-Null
        } catch {
            throw "Unable to resolve the currently signed-in user. Specify -UserObjectId or -UserPrincipalName. Details: $($_.Exception.Message)"
        }
    }

    if ($UserObjectId) {
        foreach ($id in $UserObjectId) {
            if ([string]::IsNullOrWhiteSpace($id)) { continue }
            $principal = Resolve-RoleCrawlPrincipal -Type 'User' -ObjectId $id
            if ($principal) {
                $principalBuffer.Add($principal) | Out-Null
            }
        }
    }

    if ($UserPrincipalName) {
        foreach ($upn in $UserPrincipalName) {
            if ([string]::IsNullOrWhiteSpace($upn)) { continue }
            $principal = Resolve-RoleCrawlPrincipal -Type 'User' -PrincipalName $upn
            if ($principal) {
                $principalBuffer.Add($principal) | Out-Null
            }
        }
    }

    if (-not $principalBuffer.Count) {
        throw "No users resolved. Provide -UserObjectId, -UserPrincipalName, or use -CurrentUser."
    }

    $principals = $principalBuffer | Sort-Object ObjectId -Unique

    if ($principals.Count -gt 1 -and $ExportPath) {
        if (Test-Path $ExportPath -PathType Leaf) {
            throw "When exporting multiple users, specify -ExportPath as a directory."
        }
        $extension = [System.IO.Path]::GetExtension($ExportPath)
        if ($extension -and -not (Test-Path $ExportPath) -and $principals.Count -gt 1) {
            throw "When exporting multiple users, provide -ExportPath as an existing directory or one without a file extension."
        }
    }

    $subscriptions = Resolve-RoleCrawlSubscriptions -SubscriptionId $SubscriptionId -SubscriptionName $SubscriptionName -All:($AllSubscriptions.IsPresent)

    $results = New-Object System.Collections.Generic.List[pscustomobject]
    foreach ($principal in $principals) {
        $principalResults = Invoke-RoleCrawlPrincipalScan -PrincipalType 'User' -PrincipalObjectId $principal.ObjectId -PrincipalName $principal.PrincipalName -PrincipalDisplayName $principal.DisplayName -Subscriptions $subscriptions -ExportPath $ExportPath -IncludeClassicAdministrators:$IncludeClassicAdministrators
        foreach ($item in $principalResults) {
            $results.Add($item) | Out-Null
        }
    }

    return $results
}

function Get-AzGroupRoleAssignments {
    [CmdletBinding()]
    param(
        [string[]]$GroupObjectId,
        [string[]]$GroupDisplayName,
        [string]$InputFile,
        [string[]]$SubscriptionId,
        [string[]]$SubscriptionName,
        [switch]$AllSubscriptions,
        [string]$ExportPath,
        [switch]$IncludeClassicAdministrators,
        [string]$TenantId
    )

    Ensure-RoleCrawlConnection -TenantId $TenantId | Out-Null

    $principalBuffer = New-Object System.Collections.Generic.List[pscustomobject]
    $groupIds = New-Object System.Collections.Generic.List[string]

    if ($GroupObjectId) {
        foreach ($id in $GroupObjectId) {
            if ([string]::IsNullOrWhiteSpace($id)) { continue }
            $groupIds.Add($id.Trim()) | Out-Null
        }
    }

    if ($InputFile) {
        if (-not (Test-Path $InputFile -PathType Leaf)) {
            throw "Group input file '$InputFile' not found."
        }
        $fileIds = Get-Content -Path $InputFile | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        foreach ($id in $fileIds) {
            $groupIds.Add($id.Trim()) | Out-Null
        }
    }

    foreach ($id in ($groupIds | Sort-Object -Unique)) {
        $principal = Resolve-RoleCrawlPrincipal -Type 'Group' -ObjectId $id
        if ($principal) {
            $principalBuffer.Add($principal) | Out-Null
        }
    }

    if ($GroupDisplayName) {
        foreach ($name in $GroupDisplayName) {
            if ([string]::IsNullOrWhiteSpace($name)) { continue }
            $principal = Resolve-RoleCrawlPrincipal -Type 'Group' -PrincipalName $name
            if ($principal) {
                $principalBuffer.Add($principal) | Out-Null
            }
        }
    }

    if (-not $principalBuffer.Count) {
        throw "No groups resolved. Provide -GroupObjectId, -GroupDisplayName, or -InputFile."
    }

    $principals = $principalBuffer | Sort-Object ObjectId -Unique

    if ($principals.Count -gt 1 -and $ExportPath) {
        if (Test-Path $ExportPath -PathType Leaf) {
            throw "When exporting multiple groups, specify -ExportPath as a directory."
        }
        $extension = [System.IO.Path]::GetExtension($ExportPath)
        if ($extension -and -not (Test-Path $ExportPath) -and $principals.Count -gt 1) {
            throw "When exporting multiple groups, provide -ExportPath as an existing directory or one without a file extension."
        }
    }

    $subscriptions = Resolve-RoleCrawlSubscriptions -SubscriptionId $SubscriptionId -SubscriptionName $SubscriptionName -All:($AllSubscriptions.IsPresent)

    $results = New-Object System.Collections.Generic.List[pscustomobject]
    foreach ($principal in $principals) {
        $principalResults = Invoke-RoleCrawlPrincipalScan -PrincipalType 'Group' -PrincipalObjectId $principal.ObjectId -PrincipalName $principal.PrincipalName -PrincipalDisplayName $principal.DisplayName -Subscriptions $subscriptions -ExportPath $ExportPath -IncludeClassicAdministrators:$IncludeClassicAdministrators
        foreach ($item in $principalResults) {
            $results.Add($item) | Out-Null
        }
    }

    return $results
}

Export-ModuleMember -Function 'Get-AzUserRoleAssignments', 'Get-AzGroupRoleAssignments'
