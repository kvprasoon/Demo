Clear-History
#region Negative Splits

    $String = 'a b c d,e,d'

    #Existing options for splitting
    # normal split
        $String -split ' '

    # conditional split with scriptblock
        $String -split {$_ -eq' ' -or $_ -eq ','}

    # max substrings split
        $String -split ' ', 3

    # max substrings -ive split
        $String -split ' ', -3


#endregion

#region History duration
    Get-History

    Get-History | Select-Object -First 1 | Format-List *
#endregion

#region Line continuation
    # Wrapping with a pipe at the end of a line
    Get-Process | Where Path |
        Get-Item | Where FullName -match "AppData" |
        Sort FullName -Unique

    # Wrapping with a backtick at the end of a line and a pipe at the beginning of a line
    Get-Process | Where Path `
        | Get-Item | Where FullName -match "AppData" `
        | Sort FullName -Unique

    # Wrapping with a pipe at the beginning of a line (no backtick required)
    Get-Process | Where Path
        | Get-Item | Where FullName -match "AppData"
        | Sort FullName -Unique
#endregion

#region Foreach parallel
    Measure-Command -Expression {1..10 | ForEach-Object -Process {Write-Host  "number $_" ; Start-Sleep -Seconds 1}}

    Measure-Command -Expression {1..10 | ForEach-Object -Parallel {Write-Host  "number $_" ; Start-Sleep -Seconds 1}}

    Measure-Command -Expression {1..10 | ForEach-Object -Parallel  {Write-Host  "number $_" ; Start-Sleep -Seconds 1}} -ThrottleLimit 2

    # Very detailed blog post: https://devblogs.microsoft.com/powershell/powershell-foreach-object-parallel-feature/
#endregion

#region as login shell

#endregion

#region Ternary operator

#endregion

#region Erroraction Break

#endregion

#region Pipeline chain operators

#endregion

#region Null conditional, coaelcing and assignment operator

#endregion

#region Tab completion for variable assignments

#endregion

#region Error view and Get-Error cmdlet

#endregion

#region Null conditional member and method accessing

#endregion

#region Unix filesystem info

#endregion

#region Import windows modules with WinComp

#endregion