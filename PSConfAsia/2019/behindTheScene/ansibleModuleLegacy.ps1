
Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

Function Set-Attr($obj, $name, $value) {
    <#
    .SYNOPSIS
    Helper function to set an "attribute" on a psobject instance in PowerShell.
    This is a convenience to make adding Members to the object easier and
    slightly more pythonic
    .EXAMPLE
    Set-Attr $result "changed" $true
#>

    # If the provided $obj is undefined, define one to be nice
    If (-not $obj.GetType) {
        $obj = @{ }
    }

    Try {
        $obj.$name = $value
    }
    Catch {
        $obj | Add-Member -Force -MemberType NoteProperty -Name $name -Value $value
    }
}

Function Exit-Json($obj) {
    <#
    .SYNOPSIS
    Helper function to convert a PowerShell object to JSON and output it, exiting
    the script
    .EXAMPLE
    Exit-Json $result
#>

    # If the provided $obj is undefined, define one to be nice
    If (-not $obj.GetType) {
        $obj = @{ }
    }

    if (-not $obj.ContainsKey('changed')) {
        Set-Attr $obj "changed" $false
    }

    Write-Output $obj | ConvertTo-Json -Compress -Depth 99
    Exit
}

Function Fail-Json($obj, $message = $null) {
    <#
    .SYNOPSIS
    Helper function to add the "msg" property and "failed" property, convert the
    PowerShell Hashtable to JSON and output it, exiting the script
    .EXAMPLE
    Fail-Json $result "This is the failure message"
#>

    if ($obj -is [hashtable] -or $obj -is [psobject]) {
        # Nothing to do
    }
    elseif ($obj -is [string] -and $null -eq $message) {
        # If we weren't given 2 args, and the only arg was a string,
        # create a new Hashtable and use the arg as the failure message
        $message = $obj
        $obj = @{ }
    }
    else {
        # If the first argument is undefined or a different type,
        # make it a Hashtable
        $obj = @{ }
    }

    # Still using Set-Attr for PSObject compatibility
    Set-Attr $obj "msg" $message
    Set-Attr $obj "failed" $true

    if (-not $obj.ContainsKey('changed')) {
        Set-Attr $obj "changed" $false
    }

    Write-Output $obj | ConvertTo-Json -Compress -Depth 99
    Exit 1
}

Function Add-Warning($obj, $message) {
    <#
    .SYNOPSIS
    Helper function to add warnings, even if the warnings attribute was
    not already set up. This is a convenience for the module developer
    so they do not have to check for the attribute prior to adding.
#>

    if (-not $obj.ContainsKey("warnings")) {
        $obj.warnings = @()
    }
    elseif ($obj.warnings -isnot [array]) {
        throw "Add-Warning: warnings attribute is not an array"
    }

    $obj.warnings += $message
}

Function Add-DeprecationWarning($obj, $message, $version = $null) {
    <#
    .SYNOPSIS
    Helper function to add deprecations, even if the deprecations attribute was
    not already set up. This is a convenience for the module developer
    so they do not have to check for the attribute prior to adding.
#>
    if (-not $obj.ContainsKey("deprecations")) {
        $obj.deprecations = @()
    }
    elseif ($obj.deprecations -isnot [array]) {
        throw "Add-DeprecationWarning: deprecations attribute is not a list"
    }

    $obj.deprecations += @{
        msg     = $message
        version = $version
    }
}

Function Expand-Environment($value) {
    <#
    .SYNOPSIS
    Helper function to expand environment variables in values. By default
    it turns any type to a string, but we ensure $null remains $null.
#>
    if ($null -ne $value) {
        [System.Environment]::ExpandEnvironmentVariables($value)
    }
    else {
        $value
    }
}

Function Get-AnsibleParam($obj, $name, $default = $null, $resultobj = @{ }, $failifempty = $false, $emptyattributefailmessage, $ValidateSet, $ValidateSetErrorMessage, $type = $null, $aliases = @()) {
    <#
    .SYNOPSIS
    Helper function to get an "attribute" from a psobject instance in PowerShell.
    This is a convenience to make getting Members from an object easier and
    slightly more pythonic
    .EXAMPLE
    $attr = Get-AnsibleParam $response "code" -default "1"
    .EXAMPLE
    Get-AnsibleParam -obj $params -name "State" -default "Present" -ValidateSet "Present","Absent" -resultobj $resultobj -failifempty $true
    Get-AnsibleParam also supports Parameter validation to save you from coding that manually
    Note that if you use the failifempty option, you do need to specify resultobject as well.
#>
    # Check if the provided Member $name or aliases exist in $obj and return it or the default.
    try {

        $found = $null
        # First try to find preferred parameter $name
        $aliases = @($name) + $aliases

        # Iterate over aliases to find acceptable Member $name
        foreach ($alias in $aliases) {
            if ($obj.ContainsKey($alias)) {
                $found = $alias
                break
            }
        }

        if ($null -eq $found) {
            throw
        }
        $name = $found

        if ($ValidateSet) {

            if ($ValidateSet -contains ($obj.$name)) {
                $value = $obj.$name
            }
            else {
                if ($null -eq $ValidateSetErrorMessage) {
                    #Auto-generated error should be sufficient in most use cases
                    $ValidateSetErrorMessage = "Get-AnsibleParam: Argument $name needs to be one of $($ValidateSet -join ",") but was $($obj.$name)."
                }
                Fail-Json -obj $resultobj -message $ValidateSetErrorMessage
            }
        }
        else {
            $value = $obj.$name
        }
    }
    catch {
        if ($failifempty -eq $false) {
            $value = $default
        }
        else {
            if (-not $emptyattributefailmessage) {
                $emptyattributefailmessage = "Get-AnsibleParam: Missing required argument: $name"
            }
            Fail-Json -obj $resultobj -message $emptyattributefailmessage
        }
    }

    # If $null -eq $value, the parameter was unspecified by the user (deliberately or not)
    # Please leave $null-values intact, modules need to know if a parameter was specified
    if ($null -eq $value) {
        return $null
    }

    if ($type -eq "path") {
        # Expand environment variables on path-type
        $value = Expand-Environment($value)
        # Test if a valid path is provided
        if (-not (Test-Path -IsValid $value)) {
            $path_invalid = $true
            # could still be a valid-shaped path with a nonexistent drive letter
            if ($value -match "^\w:") {
                # rewrite path with a valid drive letter and recheck the shape- this might still fail, eg, a nonexistent non-filesystem PS path
                if (Test-Path -IsValid $(@(Get-PSDrive -PSProvider Filesystem)[0].Name + $value.Substring(1))) {
                    $path_invalid = $false
                }
            }
            if ($path_invalid) {
                Fail-Json -obj $resultobj -message "Get-AnsibleParam: Parameter '$name' has an invalid path '$value' specified."
            }
        }
    }
    elseif ($type -eq "str") {
        # Convert str types to real Powershell strings
        $value = $value.ToString()
    }
    elseif ($type -eq "bool") {
        # Convert boolean types to real Powershell booleans
        $value = $value | ConvertTo-Bool
    }
    elseif ($type -eq "int") {
        # Convert int types to real Powershell integers
        $value = $value -as [int]
    }
    elseif ($type -eq "float") {
        # Convert float types to real Powershell floats
        $value = $value -as [float]
    }
    elseif ($type -eq "list") {
        if ($value -is [array]) {
            # Nothing to do
        }
        elseif ($value -is [string]) {
            # Convert string type to real Powershell array
            $value = $value.Split(",").Trim()
        }
        elseif ($value -is [int]) {
            $value = @($value)
        }
        else {
            Fail-Json -obj $resultobj -message "Get-AnsibleParam: Parameter '$name' is not a YAML list."
        }
        # , is not a typo, forces it to return as a list when it is empty or only has 1 entry
        return , $value
    }

    return $value
}

#Alias Get-attr-->Get-AnsibleParam for backwards compat. Only add when needed to ease debugging of scripts
If (-not(Get-Alias -Name "Get-attr" -ErrorAction SilentlyContinue)) {
    New-Alias -Name Get-attr -Value Get-AnsibleParam
}

Function ConvertTo-Bool {
    <#
    .SYNOPSIS
    Helper filter/pipeline function to convert a value to boolean following current
    Ansible practices
    .EXAMPLE
    $is_true = "true" | ConvertTo-Bool
#>
    param(
        [parameter(valuefrompipeline = $true)]
        $obj
    )

    $boolean_strings = "yes", "on", "1", "true", 1
    $obj_string = [string]$obj

    if (($obj -is [boolean] -and $obj) -or $boolean_strings -contains $obj_string.ToLower()) {
        return $true
    }
    else {
        return $false
    }
}

Function Parse-Args($arguments, $supports_check_mode = $false) {
    <#
    .SYNOPSIS
    Helper function to parse Ansible JSON arguments from a "file" passed as
    the single argument to the module.
    .EXAMPLE
    $params = Parse-Args $args
#>
    $params = New-Object psobject
    If ($arguments.Length -gt 0) {
        $params = Get-Content $arguments[0] | ConvertFrom-Json
    }
    Else {
        $params = $complex_args
    }
    $check_mode = Get-AnsibleParam -obj $params -name "_ansible_check_mode" -type "bool" -default $false
    If ($check_mode -and -not $supports_check_mode) {
        Exit-Json @{
            skipped = $true
            changed = $false
            msg     = "remote module does not support check mode"
        }
    }
    return $params
}


Function Get-FileChecksum($path, $algorithm = 'sha1') {
    <#
    .SYNOPSIS
    Helper function to calculate a hash of a file in a way which PowerShell 3
    and above can handle
#>
    If (Test-Path -LiteralPath $path -PathType Leaf) {
        switch ($algorithm) {
            'md5' { $sp = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider }
            'sha1' { $sp = New-Object -TypeName System.Security.Cryptography.SHA1CryptoServiceProvider }
            'sha256' { $sp = New-Object -TypeName System.Security.Cryptography.SHA256CryptoServiceProvider }
            'sha384' { $sp = New-Object -TypeName System.Security.Cryptography.SHA384CryptoServiceProvider }
            'sha512' { $sp = New-Object -TypeName System.Security.Cryptography.SHA512CryptoServiceProvider }
            default { Fail-Json @{ } "Unsupported hash algorithm supplied '$algorithm'"
            }
        }

        If ($PSVersionTable.PSVersion.Major -ge 4) {
            $raw_hash = Get-FileHash -LiteralPath $path -Algorithm $algorithm
            $hash = $raw_hash.Hash.ToLower()
        }
        Else {
            $fp = [System.IO.File]::Open($path, [System.IO.Filemode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite);
            $hash = [System.BitConverter]::ToString($sp.ComputeHash($fp)).Replace("-", "").ToLower();
            $fp.Dispose();
        }
    }
    ElseIf (Test-Path -LiteralPath $path -PathType Container) {
        $hash = "3";
    }
    Else {
        $hash = "1";
    }
    return $hash
}

Function Get-PendingRebootStatus {
    <#
    .SYNOPSIS
    Check if reboot is required, if so notify CA.
    Function returns true if computer has a pending reboot
#>
    $featureData = Invoke-WmiMethod -EA Ignore -Name GetServerFeature -Namespace root\microsoft\windows\servermanager -Class MSFT_ServerManagerTasks
    $regData = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" "PendingFileRenameOperations" -EA Ignore
    $CBSRebootStatus = Get-ChildItem "HKLM:\\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing"  -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -eq "RebootPending" }
    if (($featureData -and $featureData.RequiresReboot) -or $regData -or $CBSRebootStatus) {
        return $True
    }
    else {
        return $False
    }
}

# this line must stay at the bottom to ensure all defined module parts are exported
Export-ModuleMember -Alias * -Function * -Cmdlet *

ț(v^Rإ]O*^# Copyright (c) 2018 Ansible Project
    # Simplified BSD License (see licenses/simplified_bsd.txt or https://opensource.org/licenses/BSD-2-Clause)

    Function Add-CSharpType {
        <#
    .SYNOPSIS
    Compiles one or more C# scripts similar to Add-Type. This exposes
    more configuration options that are useable within Ansible and it
    also allows multiple C# sources to be compiled together.

    .PARAMETER References
    [String[]] A collection of C# scripts to compile together.

    .PARAMETER IgnoreWarnings
    [Switch] Whether to compile code that contains compiler warnings, by
    default warnings will cause a compiler error.

    .PARAMETER PassThru
    [Switch] Whether to return the loaded Assembly

    .PARAMETER AnsibleModule
    [Ansible.Basic.AnsibleModule] used to derive the TempPath and Debug values.
        TempPath is set to the Tmpdir property of the class
        IncludeDebugInfo is set when the Ansible verbosity is >= 3

    .PARAMETER TempPath
    [String] The temporary directory in which the dynamic assembly is
    compiled to. This file is deleted once compilation is complete.
    Cannot be used when AnsibleModule is set. This is a no-op when
    running on PSCore.

    .PARAMETER IncludeDebugInfo
    [Switch] Whether to include debug information in the compiled
    assembly. Cannot be used when AnsibleModule is set. This is a no-op
    when running on PSCore.

    .PARAMETER CompileSymbols
    [String[]] A list of symbols to be defined during compile time. These are
    added to the existing symbols, 'CORECLR', 'WINDOWS', 'UNIX' that are set
    conditionalls in this cmdlet.
    #>
        param(
            [Parameter(Mandatory = $true)][AllowEmptyCollection()][String[]]$References,
            [Switch]$IgnoreWarnings,
            [Switch]$PassThru,
            [Parameter(Mandatory = $true, ParameterSetName = "Module")][Object]$AnsibleModule,
            [Parameter(ParameterSetName = "Manual")][String]$TempPath = $env:TMP,
            [Parameter(ParameterSetName = "Manual")][Switch]$IncludeDebugInfo,
            [String[]]$CompileSymbols = @()
        )
        if ($null -eq $References -or $References.Length -eq 0) {
            return
        }

        # define special symbols CORECLR, WINDOWS, UNIX if required
        # the Is* variables are defined on PSCore, if absent we assume an
        # older version of PowerShell under .NET Framework and Windows
        $defined_symbols = [System.Collections.ArrayList]$CompileSymbols
        $is_coreclr = Get-Variable -Name IsCoreCLR -ErrorAction SilentlyContinue
        if ($null -ne $is_coreclr) {
            if ($is_coreclr.Value) {
                $defined_symbols.Add("CORECLR") > $null
            }
        }
        $is_windows = Get-Variable -Name IsWindows -ErrorAction SilentlyContinue
        if ($null -ne $is_windows) {
            if ($is_windows.Value) {
                $defined_symbols.Add("WINDOWS") > $null
            }
            else {
                $defined_symbols.Add("UNIX") > $null
            }
        }
        else {
            $defined_symbols.Add("WINDOWS") > $null
        }

        # pattern used to find referenced assemblies in the code
        $assembly_pattern = [Regex]"//\s*AssemblyReference\s+-Name\s+(?<Name>[\w.]*)(\s+-CLR\s+(?<CLR>Core|Framework))?"
        $no_warn_pattern = [Regex]"//\s*NoWarn\s+-Name\s+(?<Name>[\w\d]*)(\s+-CLR\s+(?<CLR>Core|Framework))?"

        # PSCore vs PSDesktop use different methods to compile the code,
        # PSCore uses Roslyn and can compile the code purely in memory
        # without touching the disk while PSDesktop uses CodeDom and csc.exe
        # to compile the code. We branch out here and run each
        # distribution's method to add our C# code.
        if ($is_coreclr) {
            # compile the code using Roslyn on PSCore

            # Include the default assemblies using the logic in Add-Type
            # https://github.com/PowerShell/PowerShell/blob/master/src/Microsoft.PowerShell.Commands.Utility/commands/utility/AddType.cs
            $assemblies = [System.Collections.Generic.HashSet`1[Microsoft.CodeAnalysis.MetadataReference]]@(
                [Microsoft.CodeAnalysis.CompilationReference]::CreateFromFile(([System.Reflection.Assembly]::GetAssembly([PSObject])).Location)
            )
            $netcore_app_ref_folder = [System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName([PSObject].Assembly.Location), "ref")
            $lib_assembly_location = [System.IO.Path]::GetDirectoryName([object].Assembly.Location)
            foreach ($file in [System.IO.Directory]::EnumerateFiles($netcore_app_ref_folder, "*.dll", [System.IO.SearchOption]::TopDirectoryOnly)) {
                $assemblies.Add([Microsoft.CodeAnalysis.MetadataReference]::CreateFromFile($file)) > $null
            }

            # loop through the references, parse as a SyntaxTree and get
            # referenced assemblies
            $ignore_warnings = New-Object -TypeName 'System.Collections.Generic.Dictionary`2[[String], [Microsoft.CodeAnalysis.ReportDiagnostic]]'
            $parse_options = ([Microsoft.CodeAnalysis.CSharp.CSharpParseOptions]::Default).WithPreprocessorSymbols($defined_symbols)
            $syntax_trees = [System.Collections.Generic.List`1[Microsoft.CodeAnalysis.SyntaxTree]]@()
            foreach ($reference in $References) {
                # scan through code and add any assemblies that match
                # //AssemblyReference -Name ... [-CLR Core]
                # //NoWarn -Name ... [-CLR Core]
                $assembly_matches = $assembly_pattern.Matches($reference)
                foreach ($match in $assembly_matches) {
                    $clr = $match.Groups["CLR"].Value
                    if ($clr -and $clr -ne "Core") {
                        continue
                    }
                    $assembly_path = $match.Groups["Name"]
                    if (-not ([System.IO.Path]::IsPathRooted($assembly_path))) {
                        $assembly_path = Join-Path -Path $lib_assembly_location -ChildPath $assembly_path
                    }
                    $assemblies.Add([Microsoft.CodeAnalysis.MetadataReference]::CreateFromFile($assembly_path)) > $null
                }
                $warn_matches = $no_warn_pattern.Matches($reference)
                foreach ($match in $warn_matches) {
                    $clr = $match.Groups["CLR"].Value
                    if ($clr -and $clr -ne "Core") {
                        continue
                    }
                    $ignore_warnings.Add($match.Groups["Name"], [Microsoft.CodeAnalysis.ReportDiagnostic]::Suppress)
                }
                $syntax_trees.Add([Microsoft.CodeAnalysis.CSharp.CSharpSyntaxTree]::ParseText($reference, $parse_options)) > $null
            }

            # Release seems to contain the correct line numbers compared to
            # debug,may need to keep a closer eye on this in the future
            $compiler_options = (New-Object -TypeName Microsoft.CodeAnalysis.CSharp.CSharpCompilationOptions -ArgumentList @(
                    [Microsoft.CodeAnalysis.OutputKind]::DynamicallyLinkedLibrary
                )).WithOptimizationLevel([Microsoft.CodeAnalysis.OptimizationLevel]::Release)

            # set warnings to error out if IgnoreWarnings is not set
            if (-not $IgnoreWarnings.IsPresent) {
                $compiler_options = $compiler_options.WithGeneralDiagnosticOption([Microsoft.CodeAnalysis.ReportDiagnostic]::Error)
                $compiler_options = $compiler_options.WithSpecificDiagnosticOptions($ignore_warnings)
            }

            # create compilation object
            $compilation = [Microsoft.CodeAnalysis.CSharp.CSharpCompilation]::Create(
                [System.Guid]::NewGuid().ToString(),
                $syntax_trees,
                $assemblies,
                $compiler_options
            )

            # Load the compiled code and pdb info, we do this so we can
            # include line number in a stracktrace
            $code_ms = New-Object -TypeName System.IO.MemoryStream
            $pdb_ms = New-Object -TypeName System.IO.MemoryStream
            try {
                $emit_result = $compilation.Emit($code_ms, $pdb_ms)
                if (-not $emit_result.Success) {
                    $errors = [System.Collections.ArrayList]@()

                    foreach ($e in $emit_result.Diagnostics) {
                        # builds the error msg, based on logic in Add-Type
                        # https://github.com/PowerShell/PowerShell/blob/master/src/Microsoft.PowerShell.Commands.Utility/commands/utility/AddType.cs#L1239
                        if ($null -eq $e.Location.SourceTree) {
                            $errors.Add($e.ToString()) > $null
                            continue
                        }

                        $cancel_token = New-Object -TypeName System.Threading.CancellationToken -ArgumentList $false
                        $text_lines = $e.Location.SourceTree.GetText($cancel_token).Lines
                        $line_span = $e.Location.GetLineSpan()

                        $diagnostic_message = $e.ToString()
                        $error_line_string = $text_lines[$line_span.StartLinePosition.Line].ToString()
                        $error_position = $line_span.StartLinePosition.Character

                        $sb = New-Object -TypeName System.Text.StringBuilder -ArgumentList ($diagnostic_message.Length + $error_line_string.Length * 2 + 4)
                        $sb.AppendLine($diagnostic_message)
                        $sb.AppendLine($error_line_string)

                        for ($i = 0; $i -lt $error_line_string.Length; $i++) {
                            if ([System.Char]::IsWhiteSpace($error_line_string[$i])) {
                                continue
                            }
                            $sb.Append($error_line_string, 0, $i)
                            $sb.Append(' ', [Math]::Max(0, $error_position - $i))
                            $sb.Append("^")
                            break
                        }

                        $errors.Add($sb.ToString()) > $null
                    }

                    throw [InvalidOperationException]"Failed to compile C# code:`r`n$($errors -join "`r`n")"
                }

                $code_ms.Seek(0, [System.IO.SeekOrigin]::Begin) > $null
                $pdb_ms.Seek(0, [System.IO.SeekOrigin]::Begin) > $null
                $compiled_assembly = [System.Runtime.Loader.AssemblyLoadContext]::Default.LoadFromStream($code_ms, $pdb_ms)
            }
            finally {
                $code_ms.Close()
                $pdb_ms.Close()
            }
        }
        else {
            # compile the code using CodeDom on PSDesktop

            # configure compile options based on input
            if ($PSCmdlet.ParameterSetName -eq "Module") {
                $temp_path = $AnsibleModule.Tmpdir
                $include_debug = $AnsibleModule.Verbosity -ge 3
            }
            else {
                $temp_path = $TempPath
                $include_debug = $IncludeDebugInfo.IsPresent
            }
            $compiler_options = [System.Collections.ArrayList]@("/optimize")
            if ($defined_symbols.Count -gt 0) {
                $compiler_options.Add("/define:" + ([String]::Join(";", $defined_symbols.ToArray()))) > $null
            }

            $compile_parameters = New-Object -TypeName System.CodeDom.Compiler.CompilerParameters
            $compile_parameters.GenerateExecutable = $false
            $compile_parameters.GenerateInMemory = $true
            $compile_parameters.TreatWarningsAsErrors = (-not $IgnoreWarnings.IsPresent)
            $compile_parameters.IncludeDebugInformation = $include_debug
            $compile_parameters.TempFiles = (New-Object -TypeName System.CodeDom.Compiler.TempFileCollection -ArgumentList $temp_path, $false)

            # Add-Type automatically references System.dll, System.Core.dll,
            # and System.Management.Automation.dll which we replicate here
            $assemblies = [System.Collections.Generic.HashSet`1[String]]@(
                "System.dll",
                "System.Core.dll",
                ([System.Reflection.Assembly]::GetAssembly([PSObject])).Location
            )

            # create a code snippet for each reference and check if we need
            # to reference any extra assemblies
            $ignore_warnings = [System.Collections.ArrayList]@()
            $compile_units = [System.Collections.Generic.List`1[System.CodeDom.CodeSnippetCompileUnit]]@()
            foreach ($reference in $References) {
                # scan through code and add any assemblies that match
                # //AssemblyReference -Name ... [-CLR Framework]
                # //NoWarn -Name ... [-CLR Framework]
                $assembly_matches = $assembly_pattern.Matches($reference)
                foreach ($match in $assembly_matches) {
                    $clr = $match.Groups["CLR"].Value
                    if ($clr -and $clr -ne "Framework") {
                        continue
                    }
                    $assemblies.Add($match.Groups["Name"].Value) > $null
                }
                $warn_matches = $no_warn_pattern.Matches($reference)
                foreach ($match in $warn_matches) {
                    $clr = $match.Groups["CLR"].Value
                    if ($clr -and $clr -ne "Framework") {
                        continue
                    }
                    $warning_id = $match.Groups["Name"].Value
                    # /nowarn should only contain the numeric part
                    if ($warning_id.StartsWith("CS")) {
                        $warning_id = $warning_id.Substring(2)
                    }
                    $ignore_warnings.Add($warning_id) > $null
                }
                $compile_units.Add((New-Object -TypeName System.CodeDom.CodeSnippetCompileUnit -ArgumentList $reference)) > $null
            }
            if ($ignore_warnings.Count -gt 0) {
                $compiler_options.Add("/nowarn:" + ([String]::Join(",", $ignore_warnings.ToArray()))) > $null
            }
            $compile_parameters.ReferencedAssemblies.AddRange($assemblies)
            $compile_parameters.CompilerOptions = [String]::Join(" ", $compiler_options.ToArray())

            # compile the code together and check for errors
            $provider = New-Object -TypeName Microsoft.CSharp.CSharpCodeProvider
            $compile = $provider.CompileAssemblyFromDom($compile_parameters, $compile_units)
            if ($compile.Errors.HasErrors) {
                $msg = "Failed to compile C# code: "
                foreach ($e in $compile.Errors) {
                    $msg += "`r`n" + $e.ToString()
                }
                throw [InvalidOperationException]$msg
            }
            $compiled_assembly = $compile.CompiledAssembly
        }

        # return the compiled assembly if PassThru is set.
        if ($PassThru) {
            return $compiled_assembly
        }
    }

    Export-ModuleMember -Function Add-CSharpType
