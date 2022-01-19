$code={
    param($global:remediation = 'Search Only')
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    # Config
    $filetypes = @('*.JAR','*.WAR','*.EAR','*.JPI','*.HPI')

    #Init
    $global:Errors = @()
    $global:vulnerabilityresults = @()
    $global:debuglog = @()
    $global:csv = @()

    # CVEs Scanned for
    # CVE-2021-44228 Apache Log4j2 2.0-beta9 through 2.12.1 and 2.13.0 through 2.15.0 JNDI Score: 10.0 CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
    # CVE-2021-45046 Apache Log4j 2.15.0 Score: 9.0 (AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H)
    # CVE-2021-45105 Apache Log4j2 versions 2.0-alpha1 through 2.16.0 Score: 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)

    function Check-Version{
        param($version,$hasJNDI)
        
        if($version -ne $null){
            $parsedVer = $version.replace('version=','').split('.')
        }else{
            $parsedVer = (0,0,0)
        }
        $CVE = 'CVE-2021-44228'
        $CVSSScore = '10.0'
        $FixedVersion = $false
        if($hasJNDI -eq $false){$CVE = $null; $CVSSScore = $null; $FixedVersion = $false}
        if($version -eq 'version=2.15.0'){$CVE = 'CVE-2021-45046'; $CVSSScore = '9.0'; $FixedVersion = $false}
        if($version -eq 'version=2.16.0'){$CVE = 'CVE-2021-45105'; $CVSSScore = '7.5'; $FixedVersion = $false}
        
        if($parsedVer[0] -gt '2'){$CVE = $null; $CVSSScore = $null; $FixedVersion = $true}
        if($parsedVer[0] -eq '2' -and $parsedVer[1] -gt '16'){$CVE = $null; $CVSSScore = $null; $FixedVersion = $true}

        #if($version -eq 'version=2.17.0'){$CVE = $null; $CVSSScore = $null; $FixedVersion = $true}


        if($version -eq 'version=2.12.2'){$CVE = 'CVE-2021-45105'; $CVSSScore = '7.5'; $FixedVersion = $false}
        $return = @{CVE = $CVE; CVSSScore = $CVSSScore; fixedversion = $fixedversion} 
        return $return
    }

    function write-console{
        param($CVE,$path,$version)
        $color = 'magenta'
        write-host "┌[$CVE] Version: $version" -ForegroundColor $color
        write-host "└─[" -ForegroundColor $color -NoNewline
        write-host " Located: $path"
        $global:vulnerabilityresults += "┌[$CVE] Version: $version`r`n└─[ Located: $path"
    }
    function remove-file{
        
        if($global:remediation -eq 'Search Only'){return 'Search Only mode: not remediated'}
        if($global:remediation -eq 'Remove JNDILookup.class'){return 'JNDILookup.class removed'}
        if($global:remediation -eq 'Remove Java file'){return 'Java file removed'}
        return $remresult

    }
    function Scan-File{
        param($path)
        $path = $path.fullname
        $hasJNDI = $false
        try{
            $nestedfiles = ([System.IO.Compression.ZipArchive]([System.IO.Compression.ZipFile]::OpenRead($path))).Entries | where {$_.name -eq 'jndiLookup.class'}
        }catch{
            $global:Errors += @{Error=$_.exception.Message;path=$path}
        }
        foreach($nestedfile in $nestedfiles) {
            if ($nestedfile.name -eq 'JndiLookup.class'){
                $hasJNDI = $true
                $JNDIfile = $nestedfile.fullname
            }
        }
        try{
            $zip = [io.compression.zipfile]::OpenRead($path)
        }catch{
            $global:Errors += @{Error=$_.exception.Message;path=$path}
        }
        $file = $zip.Entries | where-object { $_.Name -eq "pom.properties" -and $_.FullName -match 'log4j'}
        if($file -ne $null){
            $stream = $file.Open()
            $reader = New-Object IO.StreamReader($stream)
            $text = $reader.ReadToEnd()
            $version = -split $text | select-string -Pattern "Version"
            $reader.Close()
            $stream.Close()
            $zip.Dispose()
        }
        $versionCVE = (Check-Version -version $version.line -hasJNDI $hasJNDI)
    
        if ($hasJNDI -and !($versionCVE.fixedversion)){
            $vuln = $true
            write-console -CVE $versionCVE.CVE -path $path -version $version
            $remresult = remove-file 

        }else{$vuln = $false}
        $return = @{
            path = $path;
                version = $version.line;
                text=$text;
                pomLocation=$file.FullName;
                hasJNDI=$hasJNDI;
                JNDILocation=$JNDIfile
                CVE = $versionCVE.CVE
                CVSSScore = $versionCVE.CVSSScore
                FixedVersion = $versionCVE.fixedversion
                Vulnerable = $vuln
                ComputerName = $env:COMPUTERNAME
                Remediated = $remresult 
        }
        return $return
    }

    function Scan-System{
        param($filetypes)
        $scannedfiles =@()
        $DriveErrors = @()
        $drives = (Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType ='3'").DeviceID
        #$Drives = (Get-PSDrive -PSProvider FileSystem | Select-Object Root, DisplayRoot | Where-Object {$_.DisplayRoot -eq $null}).root
        $drives = @('c:\test','g:\test\')
        
        foreach ($Drive in $Drives) {
            $drive = "$drive\"
            $searchingmessage = "Searching Drive $drive on host $env:ComputerName..."
            write-host $searchingmessage -ForegroundColor Cyan
            $global:vulnerabilityresults += $searchingmessage
            $javaFiles = Get-ChildItem $Drive -Recurse -ErrorVariable DriveError -include $filetypes -ErrorAction SilentlyContinue #| out-null
            foreach ($javaFile in $javaFiles){
                $scannedfiles += [pscustomobject](Scan-File $javaFile)
            }
        }
        $global:csv = $Scannedfiles
        $global:Errors += @{Error=$DriveError.exception.message}
        $scannedfiles += $global:Errors
        $scannedfiles = convertto-json $scannedfiles
        return $scannedfiles
    }


    Function Main{


    
        If(!(Test-Path "$env:SystemDrive\Log4jSherlock")) { New-Item -ItemType Directory "$env:SystemDrive\Log4jSherlock" -Force }
        $date = get-date -Format "yyyy-MM-dd_HH-mm-ss"
        $results = Scan-System -filetypes $filetypes

        write-host "`r`nErrors:`r`n"

        $global:vulnerabilityresults += "`r`nErrors:`r`n"

        $global:Errors | foreach {
            $errorMessage = "┌[$($_.Error)`r`n└─[$($_.path)"
            write-host $errorMessage -ForegroundColor red
            $global:vulnerabilityresults += $errorMessage
        }


        $jsonpath = "$env:SystemDrive\Log4jSherlock\log4jsherlock $date.json"
        $resultpath = "$env:SystemDrive\Log4jSherlock\log4jsherlock $date.txt"
        $csvpath = "$env:SystemDrive\Log4jSherlock\log4jsherlock $date.csv"
        write-host "`r`nWriting Log Files to $env:SystemDrive\Log4jSherlock\..."
        set-content -path $jsonpath -value $results
        Set-Content -path $resultpath -Value $global:vulnerabilityresults
        $global:csv | export-csv $csvpath -NoTypeInformation
        return @{json=$results;txt=$global:vulnerabilityresults;csv=($global:csv | convertto-csv);comp = $env:COMPUTERNAME}

    }
    main
}


function get-menu{
    $user = $env:username
    $continue = $true
    $creds = $null
    $remediation = 'Search Only'
    $remmessage = 'Log4jSherlock will only scan and report but will not remediate.'
    
    do{
        cls
        $logo = " ██▓     ▒█████    ▄████       ▄▄▄  ▄▄▄██▀▀▀██████  ██░ ██ ▓█████  ██▀███   ██▓     ▒█████   ▄████▄   ██ ▄█▀`r`n▓██▒    ▒██▒  ██▒ ██▒ ▀█▒    ▄████▒   ▒██ ▒██    ▒ ▓██░ ██▒▓█   ▀ ▓██ ▒ ██▒▓██▒    ▒██▒  ██▒▒██▀ ▀█   ██▄█▒ `r`n▒██░    ▒██░  ██▒▒██░▄▄▄░  ▄█▀  ██▒   ░██ ░ ▓██▄   ▒██▀▀██░▒███   ▓██ ░▄█ ▒▒██░    ▒██░  ██▒▒▓█    ▄ ▓███▄░ `r`n▒██░    ▒██   ██░░▓█  ██▓ ██▄▄▄▄██░▓██▄██▓  ▒   ██▒░▓█ ░██ ▒▓█  ▄ ▒██▀▀█▄  ▒██░    ▒██   ██░▒▓▓▄ ▄██▒▓██ █▄ `r`n░██████▒░ ████▓▒░░▒▓███▀▒▒▓▓▓   ██  ▓███▒ ▒██████▒▒░▓█▒░██▓░▒████▒░██▓ ▒██▒░██████▒░ ████▓▒░▒ ▓███▀ ░▒██▒ █▄`r`n░ ▒░▓  ░░ ▒░▒░▒░  ░▒   ▒ ░░▒▓   █▓  ▒▓▒▒░ ▒ ▒▓▒ ▒ ░ ▒ ░░▒░▒░░ ▒░ ░░ ▒▓ ░▒▓░░ ▒░▓  ░░ ▒░▒░▒░ ░ ░▒ ▒  ░▒ ▒▒ ▓▒`r`n░ ░ ▒  ░  ░ ▒ ▒░   ░   ░ ░ ▒▒   ▒   ▒ ░▒░ ░ ░▒  ░ ░ ▒ ░▒░ ░ ░ ░  ░  ░▒ ░ ▒░░ ░ ▒  ░  ░ ▒ ▒░   ░  ▒   ░ ░▒ ▒░`r`n  ░ ░   ░ ░ ░ ▒  ░ ░   ░    ▒   ░   ░ ░ ░ ░  ░  ░   ░  ░░ ░   ░     ░░   ░   ░ ░   ░ ░ ░ ▒  ░        ░ ░░ ░ `r`n    ░  ░    ░ ░        ░ ░  ░       ░   ░       ░   ░  ░  ░   ░  ░   ░         ░  ░    ░ ░  ░ ░      ░  ░   `r`n                                                                                  ░               `r`n"
        write-host $logo -foreground 'magenta'
        write-host "Version: 1.1.2022.1.12"
        write-host "Written by Harley Schaeffer"
        write-host "https://github.com/Maelstromage/Log4jSherlock`r`n"
        write-host '[*]==================== Menu ====================[*]'
        write-host ""
        write-host "[U] - Run as a different user. Current user: [" -nonewline 
        write-host $user -nonewline -foreground magenta
        write-host "]"
        <#
        write-host "[V] - Remediate Vulnerability type: [" -nonewline
        write-host "$remediation" -nonewline -foreground magenta
        write-host "]"
        write-host "    ($remmessage)" -ForegroundColor red
        #>
        write-host "[R] - Run with above parameters"
        write-host "Enter a Letter to continue"
        $readhost = Read-Host
        switch ($readhost){
            'U' {
                $creds = Get-Credential
                $user = $creds.username
            }
            <#
            'V' {
                write-host "`r`nSelect a remediation type"
                write-host "1. Search Only (Log4jSherlock will only scan and report but will not remediate.)"
                write-host "2. Remove JNDILookup.class (Remediates the vulnerability and has the best chance to not break functinality. Other scanners might read as false positive.)"
                write-host "3. Remove Java file (Removes the entire JAR, WAR, EAR, JPI, or HPI file. Will break Log4j functionality. )"
                write-host "Warning: removing JNDILookup.class or the Java file itself can break the functionality of the machine in question, do so at your own risk." -ForegroundColor red
                $remediationselection = read-host
                switch ($remediationselection){
                    1 {
                        $remediation = 'Search Only'
                        $remmessage = "Log4jSherlock will only scan and report but will not remediate."
                    }
                    2 {
                        $remediation = 'Remove JNDILookup.class'
                        $remmessage = "Warning: removing JNDILookup.class or the Java file itself can break the functionality of the machine in question, do so at your own risk. `r`n    Remediates the vulnerability and has the best chance to not break functinality. Other scanners might read as false positive."
                    }
                    3 {
                        $remediation = 'Remove Java file'
                        $remmessage = "Warning: removing JNDILookup.class or the Java file itself can break the functionality of the machine in question, do so at your own risk. `r`n    Removes the entire JAR, WAR, EAR, JPI, or HPI file. Will break Log4j functionality."
                    }
                    default {
                        write-host "Incorrect input. Press any key to continue"
                        Read-Host
                    }


                }
            }
            #>
            'R' {
                $continue = $false
                Scan-MultipleSystems -creds $creds

            }
            default {
                write-host "Please enter one of the values above. example: 1, 2, 3. Press any key to continue."
                read-host
            }

        }
    }while($continue -eq $true)    
    
}

function Scan-MultipleSystems{
    param($creds=$null)
    get-job | stop-job
    get-job | remove-job
    $date = get-date -Format "yyyy-MM-dd_HH-mm-ss"
    $comps = get-content "$PSScriptRoot\Computers.txt"
    #$creds = Get-Credential -Message "Caution: Script will run even if you do not type your password correctly probably locking you out:"
    foreach ($comp in $comps){
        Get-Service -Name WinRM -ComputerName $comp -ErrorAction silentlycontinue | out-null |  Set-Service -Status Running
        if ($creds -ne $null){
            Invoke-Command -credential $creds -computername $comp -ScriptBlock $code -AsJob
        }else{
            Invoke-Command -computername $comp -ScriptBlock $code -AsJob
        }
    }
    #$exit = $false
    $combinedresults = @()
    $continue = $true
    do{
        if ((Get-Job -state running) -eq $null){$continue = $false}
        foreach($job in get-job){
            if ($job.state -eq 'Completed'){
                $Received = $job | Receive-Job
                $csv=$Received.csv
                $txt=$Received.txt
                $json=$Received.json
                write-logs -csv $csv -txt $txt -json $json -date $date -comp $received.comp
                $job | remove-job
                get-job
            }
        }        foreach($job in get-job){
        if ($job.state -eq 'Failed'){
                $Received = $job | Receive-Job
                $txt=$Received
                write-logs -csv $null -txt $txt -json $null -date $date -comp $received.comp
                $job | remove-job
            }
        }
        
    }while($continue -ne $false)
    get-job
}
function write-logs{
    param($csv,$txt,$json,$date,$comp)
    if(!(test-path "$PSScriptRoot\Logs $date")){New-Item -ItemType Directory -Path $PSScriptRoot -Name "Logs $date" | out-null}

    $path = "$PSScriptRoot\Logs $date\$comp $date"
    write-host "`r`nWriting logs to $PSScriptRoot\Logs $date\$comp $date "
    if($json -ne $null){set-content -path "$path.json" -value $json}
    if($txt -ne $null){Set-Content -path "$path.txt" -Value $txt}
    if($csv -ne $null){Set-Content -path "$path.csv" -Value $csv}

}



get-menu

