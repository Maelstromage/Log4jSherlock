# Log4jSherlock
Version 0.85.2021.12.18


---------------------
# Overview

Log4j Scanner coded in Powershell, so you can run it in windows! This tool scans for JAR, WAR, EAR, JPI, HPI that contain the effected JndiLookup.class even in nested files.
Scans nested files searches for the effected JNDI class. pulls version and reports in CSV, JSON, and txt log. reports error i.e. access issues to folders where files could be missed.

# CVE Detection

Scans for the following CVEs
- CVE-2021-44228 Apache Log4j2 2.0-beta9 through 2.12.1 and 2.13.0 through 2.15.0 JNDI 
- CVE-2021-45046 Apache Log4j 2.15.0 
- CVE-2021-45105 Apache Log4j2 versions 2.0-alpha1 through 2.16.0


# Usage
1. Download the ps1 file https://raw.githubusercontent.com/Maelstromage/Log4jSherlock/main/Log4Sherlock.ps1
2. Run as an admin on windows

# How this Script works

1. Scans all local drives on a system it is run on
2. Grabs pom.properties inside one of the above filetypes even in nested files (to obtain the version number)
3. Searches within the jar file for JndiLookup.class even in nested files
4. Files containing JndiLookup.class with vulnerable versions are marked with appropriate CVE
5. Saves logs to C:\Log4jSherlock on the SystemDrive

# Summary
This script starts scanning drives, once it comes upon one of the above file types it checks for file names inside the file. The first file it looks for is jndiLookup.class. This file is inside every version of log4j starting from 2.0-beta9. It reads the pom.properties file to get the file version so that it may exclude version 2.16.0, 2.17.0, and 2.12.2. It collects any Errors so that you know what has not been scanned i.e. access issues to files or folders. Creates a CSV file so you can open it up in excel and filter it. For greater detail a json file is created.

# Comments
Nearing Completion. Need to clean up a few bugs and do some more testing.

# Author
- Harley Schaeffer



