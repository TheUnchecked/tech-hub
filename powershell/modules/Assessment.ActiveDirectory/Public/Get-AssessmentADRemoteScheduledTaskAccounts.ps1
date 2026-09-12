#Requires -Version 5.1

Set-StrictMode -Version Latest

function Get-AssessmentADRemoteScheduledTaskAccounts {
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName
        )]
        [Alias('CN','Name','Computer')]
        [string]$ComputerName
    )

    begin {

        function Convert-AssessmentTaskIdentity {
            param(
                [Parameter(Mandatory)]
                [string]$Identity
            )

            switch -Regex ($Identity) {
                '^(?i)SYSTEM$' {
                    return 'NT AUTHORITY\SYSTEM'
                }

                '^(?i)LOCAL SERVICE$' {
                    return 'NT AUTHORITY\LOCAL SERVICE'
                }

                '^(?i)NETWORK SERVICE$' {
                    return 'NT AUTHORITY\NETWORK SERVICE'
                }
            }

            if ($Identity -match '^[^\\]+\\[^\\]+$') {
                return $Identity
            }

            if ($Identity -match '^S-\d-(\d+-){1,}\d+$') {
                try {
                    $sid = New-Object System.Security.Principal.SecurityIdentifier($Identity)

                    return $sid.Translate(
                        [System.Security.Principal.NTAccount]
                    ).Value
                }
                catch {
                    return $Identity
                }
            }

            try {
                $nt = New-Object System.Security.Principal.NTAccount($Identity)
                $sid = $nt.Translate(
                    [System.Security.Principal.SecurityIdentifier]
                )

                return $sid.Translate(
                    [System.Security.Principal.NTAccount]
                ).Value
            }
            catch {
                return $Identity
            }
        }

        function Get-AssessmentTasksViaCim {
            param(
                [Parameter(Mandatory)]
                [string]$Target
            )

            $session = $null

            try {
                $session = New-CimSession `
                    -ComputerName $Target `
                    -ErrorAction Stop

                $tasks = Get-ScheduledTask `
                    -CimSession $session `
                    -ErrorAction Stop

                foreach ($task in @($tasks)) {

                    $rawAccount = $task.Principal.UserId

                    if ([string]::IsNullOrWhiteSpace($rawAccount)) {
                        $rawAccount = $task.Principal.GroupId
                    }

                    $account = $null

                    if ($rawAccount) {
                        $account = Convert-AssessmentTaskIdentity `
                            -Identity $rawAccount
                    }

                    [PSCustomObject][ordered]@{
                        ComputerName = $Target
                        TaskName     = $task.TaskPath + $task.TaskName
                        AccountName  = $account
                        IsReadOnly   = $true
                    }
                }
            }
            finally {
                if ($session) {
                    Remove-CimSession `
                        -CimSession $session `
                        -ErrorAction SilentlyContinue
                }
            }
        }

        function Get-AssessmentTasksViaCom {
            param(
                [Parameter(Mandatory)]
                [string]$Target
            )

            $service = $null

            try {
                $service = New-Object -ComObject 'Schedule.Service'

                $service.Connect($Target)

                $root = $service.GetFolder('\')

                $stack = New-Object System.Collections.Stack
                $stack.Push($root)

                while ($stack.Count -gt 0) {

                    $folder = $stack.Pop()

                    foreach ($subFolder in @($folder.GetFolders(0))) {
                        $stack.Push($subFolder)
                    }

                    foreach ($task in @($folder.GetTasks(0))) {

                        $rawAccount = $null

                        try {
                            $rawAccount =
                                $task.Definition.Principal.UserId
                        }
                        catch {}

                        if ([string]::IsNullOrWhiteSpace($rawAccount)) {
                            try {
                                $rawAccount =
                                    $task.Definition.Principal.GroupId
                            }
                            catch {}
                        }

                        $account = $null

                        if ($rawAccount) {
                            $account = Convert-AssessmentTaskIdentity `
                                -Identity $rawAccount
                        }

                        [PSCustomObject][ordered]@{
                            ComputerName = $Target
                            TaskName     = $task.Path
                            AccountName  = $account
                            IsReadOnly   = $true
                        }
                    }
                }
            }
            finally {
                if ($service) {
                    [System.Runtime.InteropServices.Marshal]::ReleaseComObject(
                        $service
                    ) | Out-Null
                }
            }
        }
    }

    process {

        try {
            Get-AssessmentTasksViaCim -Target $ComputerName
        }
        catch {

            Write-Verbose `
                "[$ComputerName] CIM path failed. Falling back to Task Scheduler COM API."

            try {
                Get-AssessmentTasksViaCom -Target $ComputerName
            }
            catch {
                Write-Error `
                    -Message "[$ComputerName] Remote query failed: $($_.Exception.Message)"
            }
        }
    }
}