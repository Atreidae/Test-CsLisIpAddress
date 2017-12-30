# Test-CsLisIpAddress
Checks to see if a user IP Address/Subnet mask combo is present in the Skype4B / Lync LIS database. 
If the Subnet is present it's details will be returned. 
If not the script will provide feedback suggesting the IP isn't present or warn you of multiple matches.


## DESCRIPTION  
Created by James Arber. [www.skype4badmin.com](http://www.skype4badmin.com)
Borrows code heavily from [MrAutomation's Powershell version of IpCalc](https://gallery.technet.microsoft.com/scriptcenter/ipcalc-PowerShell-Script-01b7bd23) to locate the NetworkID of the entered details

    
	
## NOTES 
    Version      	   	: 1.01
	Date			    : 30/12/2017
	Lync Version		: Tested against Skype4B 2015
    Author    			: James Arber
	Header stolen from  : Greig Sheridan who stole it from Pat Richard's amazing "Get-CsConnections.ps1"
							
	:v1.01:	Minor Bug Fix Release
			-	Fixed Synopsis
			-	Fixed Auto Update URL
			-	Various Typos
			-	Logging Improvements
			-	GitHub Improvements

	:v1.00:	Initial Release

	:v0.10:	Internal Build
	
## LINK  
    https://www.skype4badmin.com

## KNOWN ISSUES
   None at this stage, this is however in development code and bugs are expected

## Script Specifics
**EXAMPLE** Locates and returns the expected LIS entry for the user at 192.168.150.128 with a 24bit subnet mask (255.255.255.0)
'PS C:\> .\Test-CsLisIpAddress.ps1 192.168.150.128/24'

**EXAMPLE** Locates and returns the expected LIS entry for the user at 192.168.150.128 with a subnet mask of 255.255.255.0
'PS C:\> .\Test-CsLisIpAddress.ps1 192.168.150.128 255.255.255.0'

**PARAMETER IpAddress**
IP address of example user in "192.168.0.1" format or with CIDR notation ie "192.168.0.1/24"

**PARAMETER SubnetMask**
Subnet mask of example user in mask format ie "255.255.255.0" (no wildcards for you cisco types out there)

**PARAMETER -DisableScriptUpdate**
Stops the script from checking online for an update and prompting the user to download. Ideal for scheduled tasks

**INPUT**
Test-CsLisIpAddress accepts pipeline input of single objects with named properties matching parameters.

**Output**
Custom.PsObject. Test-CsLisIpAddress returns a the results of a migration as a custom object on the pipeline.
