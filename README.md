THIS SCRIPT IS PROVIDED TO YOU "AS IS." TO THE EXTENT PERMITTED BY LAW, QUALYS HEREBY DISCLAIMS ALL WARRANTIES AND LIABILITY FOR THE PROVISION OR USE OF THIS SCRIPT. IN NO EVENT SHALL THESE SCRIPTS BE DEEMED TO BE CLOUD SERVICES AS PROVIDED BY QUALYS

# Description
The Log4jScanner.exe utility helps to detect CVE-2021-44228 and CVE-2021-45046 vulnerabilities.
The utility will scan the entire hard drive(s) including archives (and nested JARs) for the Java class that indicates the Java application contains a vulnerable log4j library. The utility will output its results to a console.

Qualys has added a new QID (376160) that is designed to look for the results of this scan and mark the asset as vulnerable if the vulnerable log4j library was found.

Qualys customers should use the following to run the tool on any asset they want to scan:
> Log4jScanner.exe /scan /report_sig

# Direct Download Link
https://github.com/Qualys/log4jscanwin/releases/download/1.2.18/Log4jScanner-1.2.18.zip

# Usage
```
/scan
  Scan local drives for vulnerable JAR, WAR, EAR, ZIP files used by various Java applications.
/scan_directory "C:\Some\Path"
  Scan a specific directory for vulnerable JAR, WAR, EAR, ZIP files used by various Java applications.
/scan_file "C:\Some\Path\Some.jar"
  Scan a specific file for supported CVE(s).
/report
  Generate a JSON report of possible detections of supported CVE(s).
/report_pretty
  Generate a human readable JSON report of possible detections of supported CVE(s).
/report_sig
  Generate a signature report of possible detections of supported CVE(s).
```

Sample Usage - The following command helps you scan local drives for vulnerable JAR, WAR, EAR, and ZIP.
> Log4jScanner.exe /scan

Sample Usage - The following command helps you scan local drives for vulnerable files and writes a signature report to C:\ProgramData\Qualys
> Log4jScanner.exe /scan /report_sig

# Output - The following output shows detection
```
Qualys Log4j Vulnerability Scanner 1.2.18.0
https://www.qualys.com/
Supported CVE(s): CVE-2021-4104, CVE-2021-44228, CVE-2021-45046, CVE-2021-45105

Scanning Local Drives...
Log4j Found: 'D:\Temp\log4j-1.1.3.zip!jakarta-log4j-1.1.3/dist/lib/log4j-core.jar' ( Manifest Vendor: Apache Software Foundation, Manifest Version: 1.1.3, JNDI Class: NOT Found, Log4j Vendor: log4j, Log4j Version: 1.1.3, CVE Status: N/A )
Log4j Found: 'D:\Temp\log4j-1.1.3.zip!jakarta-log4j-1.1.3/dist/lib/log4j.jar' ( Manifest Vendor: Apache Software Foundation, Manifest Version: 1.1.3, JNDI Class: NOT Found, Log4j Vendor: log4j, Log4j Version: 1.1.3, CVE Status: N/A )
Log4j Found: 'D:\Temp\log4j-1.1.3.zip' ( Manifest Vendor: , Manifest Version: , JNDI Class: NOT Found, Log4j Vendor: Unknown, Log4j Version: Unknown, CVE Status: N/A )
Log4j Found: 'D:\Temp\log4j-1.2.17.jar' ( Manifest Vendor: Apache Software Foundation, Manifest Version: 1.2.17, JNDI Class: NOT Found, Log4j Vendor: log4j, Log4j Version: 1.2.17, CVE Status: Potentially Vulnerable ( CVE-2021-4104: Found ) )
Log4j Found: 'D:\Temp\log4j-1.2.17.zip!apache-log4j-1.2.17/log4j-1.2.17.jar' ( Manifest Vendor: Apache Software Foundation, Manifest Version: 1.2.17, JNDI Class: NOT Found, Log4j Vendor: log4j, Log4j Version: 1.2.17, CVE Status: Potentially Vulnerable ( CVE-2021-4104: Found ) )
Log4j Found: 'D:\Temp\log4j-1.2.17.zip' ( Manifest Vendor: , Manifest Version: , JNDI Class: NOT Found, Log4j Vendor: Unknown, Log4j Version: Unknown, CVE Status: N/A )
Log4j Found: 'D:\Temp\log4j-1.2.9.jar' ( Manifest Vendor: Apache Software Foundation, Manifest Version: 1.2.9, JNDI Class: NOT Found, Log4j Vendor: log4j, Log4j Version: 1.2.9, CVE Status: Potentially Vulnerable ( CVE-2021-4104: Found ) )
Log4j Found: 'D:\Temp\log4j-1.2.9.zip!logging-log4j-1.2.9/dist/lib/log4j-1.2.9.jar' ( Manifest Vendor: Apache Software Foundation, Manifest Version: 1.2.9, JNDI Class: NOT Found, Log4j Vendor: log4j, Log4j Version: 1.2.9, CVE Status: Potentially Vulnerable ( CVE-2021-4104: Found ) )
Log4j Found: 'D:\Temp\log4j-1.2.9.zip' ( Manifest Vendor: , Manifest Version: , JNDI Class: NOT Found, Log4j Vendor: Unknown, Log4j Version: Unknown, CVE Status: N/A )
Log4j Found: 'D:\Temp\log4j-api-2.16.0.jar' ( Manifest Vendor: log4j, Manifest Version: 2.16.0, JNDI Class: NOT Found, Log4j Vendor: log4j-api, Log4j Version: 2.16.0, CVE Status: Mitigated )
Log4j Found: 'D:\Temp\log4j-core-2.11.1.jar' ( Manifest Vendor: log4j, Manifest Version: 2.11.1, JNDI Class: Found, Log4j Vendor: log4j-core, Log4j Version: 2.11.1, CVE Status: Potentially Vulnerable ( CVE-2021-44228: Found CVE-2021-45046: Found CVE-2021-45105: Found ) )
Log4j Found: 'D:\Temp\log4j-core-2.14.0.jar' ( Manifest Vendor: log4j, Manifest Version: 2.14.0, JNDI Class: Found, Log4j Vendor: log4j-core, Log4j Version: 2.14.0, CVE Status: Potentially Vulnerable ( CVE-2021-44228: Found CVE-2021-45046: Found CVE-2021-45105: Found ) )
Log4j Found: 'D:\Temp\log4j-core-2.15.0.jar' ( Manifest Vendor: log4j, Manifest Version: 2.15.0, JNDI Class: Found, Log4j Vendor: log4j-core, Log4j Version: 2.15.0, CVE Status: Potentially Vulnerable ( CVE-2021-44228: NOT Found CVE-2021-45046: Found CVE-2021-45105: Found ) )
Log4j Found: 'D:\Temp\log4j-core-2.16.0.jar' ( Manifest Vendor: log4j, Manifest Version: 2.16.0, JNDI Class: Found, Log4j Vendor: log4j-core, Log4j Version: 2.16.0, CVE Status: Potentially Vulnerable ( CVE-2021-44228: NOT Found CVE-2021-45046: NOT Found CVE-2021-45105: Found ) )
Log4j Found: 'D:\Temp\log4j-core-2.17.0.jar' ( Manifest Vendor: log4j, Manifest Version: 2.17.0, JNDI Class: Found, Log4j Vendor: log4j-core, Log4j Version: 2.17.0, CVE Status: Mitigated )
Log4j Found: 'D:\Temp\log4j-core.jar' ( Manifest Vendor: Apache Software Foundation, Manifest Version: 1.1.3, JNDI Class: NOT Found, Log4j Vendor: log4j, Log4j Version: 1.1.3, CVE Status: N/A )
Log4j Found: 'D:\Temp\log4j-iostreams-2.15.0.jar' ( Manifest Vendor: log4j, Manifest Version: 2.15.0, JNDI Class: NOT Found, Log4j Vendor: log4j-iostreams, Log4j Version: 2.15.0, CVE Status: Mitigated )
Log4j Found: 'D:\Temp\log4j.jar' ( Manifest Vendor: Apache Software Foundation, Manifest Version: 1.1.3, JNDI Class: NOT Found, Log4j Vendor: log4j, Log4j Version: 1.1.3, CVE Status: N/A )
Log4j Found: 'D:\Temp\org.apache.log4j_1.2.15.v201012070815.jar' ( Manifest Vendor: %PLUGIN_PROVIDER, Manifest Version: 1.2.15.v201012070815, JNDI Class: NOT Found, Log4j Vendor: Unknown, Log4j Version: Unknown, CVE Status: N/A )
Log4j Found: 'D:\Temp\昆虫\log4j-core-2.11.1.jar' ( Manifest Vendor: log4j, Manifest Version: 2.11.1, JNDI Class: Found, Log4j Vendor: log4j-core, Log4j Version: 2.11.1, CVE Status: Potentially Vulnerable ( CVE-2021-44228: Found CVE-2021-45046: Found CVE-2021-45105: Found ) )
Log4j Found: 'D:\Temp\昆虫\log4j-core-2.14.0.jar' ( Manifest Vendor: log4j, Manifest Version: 2.14.0, JNDI Class: Found, Log4j Vendor: log4j-core, Log4j Version: 2.14.0, CVE Status: Potentially Vulnerable ( CVE-2021-44228: Found CVE-2021-45046: Found CVE-2021-45105: Found ) )

Scan Summary:
        Scan Date:               2021-12-21T13:27:49-0800
        Scan Duration:           66 Seconds
        Files Scanned:           919154
        Directories Scanned:     268121
        JAR(s) Scanned:          617
        WAR(s) Scanned:          0
        EAR(s) Scanned:          0
        ZIP(s) Scanned:          110
        Vulnerabilities Found:   12
```
