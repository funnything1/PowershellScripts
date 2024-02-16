
# Ensure admin privileges
If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Output "Administrator privileges are required."
    Start-Process PowerShell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# Initialize environment
$ErrorActionPreference = 'Stop'

# Function to add or remove privilege
function Adjust-Privilege {
    param(
        [string]$Privilege,
        [bool]$DisableAllPrivileges = $false,
        [bool]$RemovePrivilege = $false
    )

    $definition = @'
    using System;
    using System.Runtime.InteropServices;

    public class Privileges {
        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct TokPriv1Luid {
            public int Count;
            public long Luid;
            public int Attr;
        }

        internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
        internal const int TOKEN_QUERY = 0x00000008;
        internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
    }
'@

    Add-Type -TypeDefinition $definition -Name "Privileges" -Namespace "PInvoke"

    $tokenPrivileges = New-Object PInvoke.Privileges+TokPriv1Luid
    $tokenPrivileges.Count = 1
    $tokenPrivileges.Luid = 0
    $tokenPrivileges.Attr = [PInvoke.Privileges]::SE_PRIVILEGE_ENABLED

    $htok = [IntPtr]::Zero
    $hproc = [PInvoke.Privileges]::GetCurrentProcess()

    [PInvoke.Privileges]::OpenProcessToken($hproc, [PInvoke.Privileges]::TOKEN_ADJUST_PRIVILEGES -bor [PInvoke.Privileges]::TOKEN_QUERY, [ref]$htok)

    $tp = New-Object PInvoke.Privileges+TokPriv1Luid
    $tp.Count = 1
    $tp.Luid = 0
    $tp.Attr = if ($RemovePrivilege) { 0 } else { [PInvoke.Privileges]::SE_PRIVILEGE_ENABLED }

    [PInvoke.Privileges]::LookupPrivilegeValue($null, $Privilege, [ref]$tp.Luid)
    [PInvoke.Privileges]::AdjustTokenPrivileges($htok, $DisableAllPrivileges, [ref]$tp, 0, [IntPtr]::Zero, [IntPtr]::Zero)
}

# Function to remove "Windows Security" app and related operations
function Remove-WindowsSecurityApp {
    param(
        [string]$PathPattern
    )
    
    $expandedPath = [Environment]::ExpandEnvironmentVariables($PathPattern)
    Write-Host "Searching for items matching pattern: '$expandedPath'."
    
    $adminSid = New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-544'
    $adminAccount = $adminSid.Translate([System.Security.Principal.NTAccount])
    $adminFullControlAccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($adminAccount, [System.Security.AccessControl.FileSystemRights]::FullControl, [System.Security.AccessControl.AccessControlType]::Allow)
    
    $foundAbsolutePaths = @(Get-ChildItem -Path $expandedPath -Force -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
    if (!$foundAbsolutePaths) {
        Write-Host 'Skipping, no items available.'
        return
    }

    
foreach ($path in $foundAbsolutePaths) {
    Write-Host "Processing file: '$path'."
    
    try {
        $acl = Get-Acl -Path $path
        $acl.SetOwner($adminAccount)
        $acl.AddAccessRule($adminFullControlAccessRule)
        Set-Acl -Path $path -AclObject $acl
        Remove-Item -Recurse -LiteralPath $path -Force

        Write-Host "Successfully removed '$path'."
    } catch {
        Write-Host "Error processing '$path': $_"

        # Continue with the next iteration
        continue
    }
}

}

# Remove "Windows Security" app (breaks Windows Security user interface)
Write-Host "--- Remove 'Windows Security' app (SecHealthUI) (breaks Windows Security user interface)"

# Soft delete files matching pattern
Remove-WindowsSecurityApp -PathPattern "$env:WINDIR\SystemApps\Microsoft.Windows.SecHealthUI_cw5n1h2txyewy\*"
Remove-WindowsSecurityApp -PathPattern "$env:SYSTEMDRIVE\Program Files\WindowsApps\Microsoft.Windows.SecHealthUI_*_cw5n1h2txyewy\*"
Remove-WindowsSecurityApp -PathPattern "$env:PROGRAMDATA\Microsoft\Windows\AppRepository\Packages\Microsoft.Windows.SecHealthUI_*_cw5n1h2txyewy\*"
Remove-WindowsSecurityApp -PathPattern "$env:LOCALAPPDATA\Packages\Microsoft.Windows.SecHealthUI_cw5n1h2txyewy\*"

# Enable removal of system app 'Microsoft.Windows.SecHealthUI' by marking it as "EndOfLife"
$currentUserSid = (New-Object System.Security.Principal.NTAccount($env:USERNAME)).Translate([Security.Principal.SecurityIdentifier]).Value
$keyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\EndOfLife\$currentUserSid\Microsoft.Windows.SecHealthUI_cw5n1h2txyewy"
if (-not (Test-Path $keyPath)) {
    New-Item -Path $keyPath -Force | Out-Null
    Write-Host "Successfully created the registry key at path '$keyPath'."
}

# Uninstall 'Microsoft.Windows.SecHealthUI' Microsoft Store app
Get-AppxPackage 'Microsoft.Windows.SecHealthUI' | Remove-AppxPackage

# Mark 'Microsoft.Windows.SecHealthUI' as deprovisioned to block reinstall during Windows updates
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.Windows.SecHealthUI_cw5n1h2txyewy" /f

#Cleanup files with admin permissions 
rm -r $env:WINDIR\SystemApps\Microsoft.Windows.SecHealthUI_cw5n1h2txyewy\ -Force -ErrorAction SilentlyContinue

# Revert 'Microsoft.Windows.SecHealthUI' to its default, non-removable state
Remove-Item -Path $keyPath -Force | Out-Null
Write-Host "Successfully removed the registry key at path '$keyPath'." -ForegroundColor Green

# Pause the script to view the final state
Read-Host -Prompt "Press Enter to continue"

# Exit the script successfully
exit 0