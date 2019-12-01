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


#region Ternary operator
    $a = 5
    $b = 10

    # The old way
    if($a -gt $b){
        'a is greater than b'
    }
    else{
        'b is greater than a'
    }

    #or

    if($a -lt $b){
        'b is greater than a'
    }
    else{
        'a is greater than b'
    }

    # Using Ternary operator
    # condition ? iftrue : else
    $a -gt $b ? 'a is greater than b' : 'b is greater than a'

    $a -lt $b ? 'b is greater than a' : 'a is greater than b'
#endregion


#region Erroraction Break
    C:\Users\kvprasoon\Documents\GitHub\Demo\PS7Highlights\script1.ps1 -Path c:\Temp

    C:\Users\kvprasoon\Documents\GitHub\Demo\PS7Highlights\script1.ps1 -Path c:\Temp -ErrorAction Break
#endregion


#region Pipeline chain operators
    # Last execeution status
    $?

    # Existing approach
    if($?){
        'if previous execution is successful, then do something'
    }
    else{
        'do nothing'
    }

    # Chain operators && and ||
    ($Output = Get-Process -Name pwsh) && "$($Output.Count) pwsh found" # execute if previsous exec is success

    ($Output = Get-Service -Name pwsh) || "No pwsh found" # execute if previsous exec is failure

    ($Output = Get-Service -Name pwsh) && "$($Output.Count) pwsh found" || "No pwsh found"

    ($Output = Get-Process -Name pwsh) && "$($Output.Count) pwsh found" || "No pwsh found"
#endregion


#region Null conditional and assignment operator
    $Value = $null

    # Existing appraoch for Null condition check
    if($null -eq $Value){
        'Value is null'
    }

    $Value ?? 'Value is null'

    # Existing appraoch for Null condition check and assignment
    "Value is before check is $Value"
    if($null -eq $Value){
        $Value = 1
        "Value is now $Value"
    }

    $Value = $null

    "Value is before check is $Value"
    $Value ??= 1

    "Value is now $Value"
#endregion

#region Tab completion for variable assignments
    $ErrorActionPreference = 'Stop'
#endregion

#region New version notification
    start-Process -FilePath 'C:\Users\kvprasoon\Downloads\PowerShell-7.0.0-preview.5-win-x64\pwsh.exe'
#endregion

#region Error view and Get-Error cmdlet
    $ErrorView # new error view variable
    Get-Process foo

    $ErrorView = 'CategoryView'
    Get-Process foo

    $ErrorView = 'NormalView'
    Get-Process foo

    Get-Error -Newest
#endregion

#region Null conditional member accessing and indexing
    $NoValue = $null

    # Member access on a null value
        $NoValue.Open()
        if($null -ne $NoValue){
            $NoValue.Open()
        }
        # Null conditional Member access
        ${NoValue}?.Open()

    # Indexing on a null value
        $NoValue = $null
        $NoValue[1]
        if($null -ne $NoValue){
            $NoValue[2]
        }

        # Null conditional indexing
        ${NoValue}?[1]

        $NoValue = 1,2,3
        ${NoValue}?[1]
#endregion

#region -SecurityDescriptorSddl parameter for Set and New Service cmdlets

#endregion
