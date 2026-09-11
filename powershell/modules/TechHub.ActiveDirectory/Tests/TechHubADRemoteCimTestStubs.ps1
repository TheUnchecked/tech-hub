#requires -Version 5.1

Set-StrictMode -Version Latest

# ============================================================
# SHARED CIM CMDLET FALLBACKS FOR REMOTE COLLECTOR TESTS
# ============================================================
#
# The CimCmdlets module (New-CimSession, Get-CimInstance, ...) is not
# available on every test host (for example Linux/pwsh CI runners).
# Several Pester files for remote collectors define a fallback global
# function so `Mock <CmdletName>` has a real command to attach to.
#
# Pester loads every test file into the same PowerShell session, so a
# `global:` function defined by one file's BeforeAll stays in scope
# for every file that runs afterwards. Each fallback previously kept
# its own, inconsistent parameter set; whichever test file happened to
# run first "won" and silently left its (sometimes parameterless)
# stub in place for every other file, breaking `-ParameterFilter`
# matching in a way that only reproduced when the full suite ran.
#
# Dot-source this single, fully-parameterized definition from every
# remote collector test file instead of declaring local copies, so
# execution order can no longer change test behavior.

if (-not (Get-Command New-CimSession -ErrorAction SilentlyContinue)) {
    function global:New-CimSession {
        param(
            $ComputerName,
            $Credential,
            $SessionOption,
            $ErrorAction
        )
        throw 'Synthetic CIM session'
    }
}

if (-not (Get-Command New-CimSessionOption -ErrorAction SilentlyContinue)) {
    function global:New-CimSessionOption {
        param(
            [switch]$UseSsl,
            $Protocol
        )
        throw 'Synthetic CIM option'
    }
}

if (-not (Get-Command Get-CimInstance -ErrorAction SilentlyContinue)) {
    function global:Get-CimInstance {
        param(
            $CimSession,
            $ClassName,
            $Filter,
            $ErrorAction
        )
        throw 'Synthetic CIM query'
    }
}

if (-not (Get-Command Get-CimAssociatedInstance -ErrorAction SilentlyContinue)) {
    function global:Get-CimAssociatedInstance {
        param(
            $CimSession,
            $InputObject,
            $Association,
            $ResultClassName,
            $ErrorAction
        )
        throw 'Synthetic CIM association query'
    }
}

if (-not (Get-Command Remove-CimSession -ErrorAction SilentlyContinue)) {
    function global:Remove-CimSession {
        param(
            [Parameter(ValueFromPipeline)]
            [object]$CimSession,
            $ErrorAction
        )
    }
}
