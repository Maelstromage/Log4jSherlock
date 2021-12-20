$code={
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    # Config
    $filetypes = @('*.JAR','*.WAR','*.EAR','*.JPI','*.HPI')
    $global:color = 'Magenta'

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
    
        $CVE = 'CVE-2021-44228'
        $CVSSScore = '10.0'
        $FixedVersion = $false
        if($hasJNDI -eq $false){$CVE = $null; $CVSSScore = $null; $FixedVersion = $false}
        if($version -eq 'version=2.15.0'){$CVE = 'CVE-2021-45046'; $CVSSScore = '9.0'; $FixedVersion = $false}
        if($version -eq 'version=2.16.0'){$CVE = 'CVE-2021-45105'; $CVSSScore = '7.5'; $FixedVersion = $false}
        if($version -eq 'version=2.17.0'){$CVE = $null; $CVSSScore = $null; $FixedVersion = $true}
        if($version -eq 'version=2.12.2'){$CVE = 'CVE-2021-45105'; $CVSSScore = '7.5'; $FixedVersion = $false}
        $return = @{CVE = $CVE; CVSSScore = $CVSSScore; fixedversion = $fixedversion} 
    
        return $return
    }

    function write-console{
        param($CVE,$path,$version)
        $color = $global:color
        write-host "┌[$CVE] Version: $version" -ForegroundColor $color
        write-host "└─[" -ForegroundColor $color -NoNewline
        write-host " Located: $path"
        $global:vulnerabilityresults += "┌[$CVE] Version: $version`r`n└─[ Located: $path"
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
        }
        return $return
    }

    function Scan-System{
        param($filetypes)
        $scannedfiles =@()
        $DriveErrors = @()
        $Drives = (Get-PSDrive -PSProvider FileSystem | Select-Object Root, DisplayRoot | Where-Object {$_.DisplayRoot -eq $null}).root
        #$drives = @('c:\test','g:\test\')
        foreach ($Drive in $Drives) {
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
        $date = get-date -Format "yyyy-MM-dd_hh-mm-ss"
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
        write-host "`r`nWriting Json to $jsonpath on $env:Computername ..."
        set-content -path $jsonpath -value $results
        write-host "`r`nWriting log to $resultpath on $env:Computername..."
        Set-Content -path $resultpath -Value $global:vulnerabilityresults
        write-host "`r`nWriting CSV to $csvpath on $env:Computername..."
        $global:csv | export-csv $csvpath -NoTypeInformation
        return @{json=$results;txt=$global:vulnerabilityresults;csv=($global:csv | convertto-csv);comp = $env:COMPUTERNAME}

    }
    main
}
function display-logo{
    $logo = " ██▓     ▒█████    ▄████       ▄▄▄  ▄▄▄██▀▀▀██████  ██░ ██ ▓█████  ██▀███   ██▓     ▒█████   ▄████▄   ██ ▄█▀`r`n▓██▒    ▒██▒  ██▒ ██▒ ▀█▒    ▄████▒   ▒██ ▒██    ▒ ▓██░ ██▒▓█   ▀ ▓██ ▒ ██▒▓██▒    ▒██▒  ██▒▒██▀ ▀█   ██▄█▒ `r`n▒██░    ▒██░  ██▒▒██░▄▄▄░  ▄█▀  ██▒   ░██ ░ ▓██▄   ▒██▀▀██░▒███   ▓██ ░▄█ ▒▒██░    ▒██░  ██▒▒▓█    ▄ ▓███▄░ `r`n▒██░    ▒██   ██░░▓█  ██▓ ██▄▄▄▄██░▓██▄██▓  ▒   ██▒░▓█ ░██ ▒▓█  ▄ ▒██▀▀█▄  ▒██░    ▒██   ██░▒▓▓▄ ▄██▒▓██ █▄ `r`n░██████▒░ ████▓▒░░▒▓███▀▒▒▓▓▓   ██  ▓███▒ ▒██████▒▒░▓█▒░██▓░▒████▒░██▓ ▒██▒░██████▒░ ████▓▒░▒ ▓███▀ ░▒██▒ █▄`r`n░ ▒░▓  ░░ ▒░▒░▒░  ░▒   ▒ ░░▒▓   █▓  ▒▓▒▒░ ▒ ▒▓▒ ▒ ░ ▒ ░░▒░▒░░ ▒░ ░░ ▒▓ ░▒▓░░ ▒░▓  ░░ ▒░▒░▒░ ░ ░▒ ▒  ░▒ ▒▒ ▓▒`r`n░ ░ ▒  ░  ░ ▒ ▒░   ░   ░ ░ ▒▒   ▒   ▒ ░▒░ ░ ░▒  ░ ░ ▒ ░▒░ ░ ░ ░  ░  ░▒ ░ ▒░░ ░ ▒  ░  ░ ▒ ▒░   ░  ▒   ░ ░▒ ▒░`r`n  ░ ░   ░ ░ ░ ▒  ░ ░   ░    ▒   ░   ░ ░ ░ ░  ░  ░   ░  ░░ ░   ░     ░░   ░   ░ ░   ░ ░ ░ ▒  ░        ░ ░░ ░ `r`n    ░  ░    ░ ░        ░ ░  ░       ░   ░       ░   ░  ░  ░   ░  ░   ░         ░  ░    ░ ░  ░ ░      ░  ░   `r`n                                                                                  ░               `r`n"
    write-host $logo -foreground $global:color
    write-host "Version: 1.0.2021.12.19"
    write-host "Written by Harley Schaeffer"
    write-host "https://github.com/Maelstromage/Log4jSherlock`r`n"

}
function Scan-MultipleSystems{
    get-job | stop-job
    get-job | remove-job
    $date = get-date -Format "yyyy-MM-dd_hh-mm-ss"
    $comps = get-content "$PSScriptRoot\Computers.txt"
    $creds = Get-Credential -Message "Caution: Script will run even if you do not type your password correctly:"
    foreach ($comp in $comps){
        Invoke-Command -credential $creds -computername $comp -ScriptBlock $code -AsJob
    }
    $exit = $false
    $combinedresults = @()
    
    do{
        
        foreach($job in get-job){
            if ($job.state -eq 'Completed'){
                $Received = $job | Receive-Job
                $csv=$Received.csv
                $txt=$Received.txt
                $json=$Received.json
                write-logs -csv $csv -txt $txt -json $json -date $date -comp $received.comp
                $job | remove-job
            }

        }
        if ((get-date -Format 'ss')[1] -eq '0'){
            Get-Job -State Running
            write-host "CTRL+C to Quit" -NoNewline
        }
        
    }while($continue -ne $false)
}
function write-logs{
    param($csv,$txt,$json,$date,$comp)
    if(!(test-path "$PSScriptRoot\Logs $date")){New-Item -ItemType Directory -Path $PSScriptRoot -Name "Logs $date"}

    $path = "$PSScriptRoot\Logs $date\$comp $date"
    write-host "`r`nWriting Json to $path.json..."
    set-content -path "$path.json" -value $json
    write-host "`r`nWriting log to $path.txt..."
    Set-Content -path "$path.txt" -Value $txt
    write-host "`r`nWriting CSV to $path.csv..."
    Set-Content -path "$path.csv" -Value $csv

}

display-logo
Scan-MultipleSystems
