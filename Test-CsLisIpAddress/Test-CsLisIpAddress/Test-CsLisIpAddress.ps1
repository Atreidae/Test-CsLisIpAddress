<#  
.SYNOPSIS  
	Checks to see if a user IP Address/Subnet mask combo is present in the Skype4B / Lync LIS database. 
	If the Subnet is present it's details will be returned. 
	If not the script will provide feedback suggesting the IP isn't present or warn you of multiple matches.



.DESCRIPTION  
	Created by James Arber. www.skype4badmin.com
	Borrows code heavily from MrAutomation's Powershell version of IpCalc to locate the NetworkID of the entered details
		https://gallery.technet.microsoft.com/scriptcenter/ipcalc-PowerShell-Script-01b7bd23
    
	
.NOTES  
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
	
.LINK  
    https://www.skype4badmin.com

.KNOWN ISSUES
   None at this stage, this is however in development code and bugs are expected

.EXAMPLE Migrates a single user, configures their voice routing and sets up exchange UM
    PS C:\> .\Test-CsLisIpAddress.ps1 192.168.150.128/24

.EXAMPLE Migrates all the users in Example.Csv, configures their voice routing and sets up exchange UM
	PS C:\> .\Test-CsLisIpAddress.ps1 192.168.150.128 255.255.255.0

.PARAMETER IpAddress
	IP address of example user in "192.168.0.1" format or with CIDR notation ie "192.168.0.1/24"

.PARAMETER SubnetMask
	Subnet mask of example user in mask format ie "255.255.255.0" (no wildcards for you cisco types out there)

.PARAMETER -DisableScriptUpdate
    Stops the script from checking online for an update and prompting the user to download. Ideal for scheduled tasks

.INPUT
Test-CsLisIpAddress accepts pipeline input of single objects with named properties matching parameters.

.Output
Custom.PsObject. Test-CsLisIpAddress returns a the results of a migration as a custom object on the pipeline.

#>

#region variables
# Script Config
###############################
# Edit Variables Further Down #
###############################


[CmdletBinding(DefaultParametersetName="Common")]
param(
	[Parameter(ValueFromPipelineByPropertyName, Mandatory=$true, Position=1)] $IPAddress,
	[Parameter(ValueFromPipelineByPropertyName, Mandatory=$false, Position=2)] $SubnetMask,
	[Parameter(Mandatory=$false)] [switch]$DisableScriptUpdate
	)



#### Variable Block


#############################
# Script Specific Variables #
#############################

	$ScriptVersion = 1.01
	$StartTime = Get-Date
	Write-Host "Info: Test-CsLisIpAddress Version $ScriptVersion started at $StartTime" -ForegroundColor Green
	$LogFileLocation = $PSCommandPath -replace ".ps1",".log" #Where do we store the log files? (In the same folder by default)
	$DefaultLogComponent = "Unknown" 
	Write-Host "Info: Importing Base Variables" -ForegroundColor Green


#endregion variables


#region Functions
  ##################
  # Function Block #
  ##################
Function Write-Log {
    PARAM(
         [String]$Message,
         [String]$Path = $LogFileLocation,
         [int]$severity = 1,
         [string]$component = "Default"
         )

         $TimeZoneBias = Get-WmiObject -Query "Select Bias from Win32_TimeZone"
         $Date= Get-Date -Format "HH:mm:ss"
         $Date2= Get-Date -Format "MM-dd-yyyy"

         $MaxLogFileSizeMB = 10
         If(Test-Path $Path)
         {
            if(((gci $Path).length/1MB) -gt $MaxLogFileSizeMB) # Check the size of the log file and archive if over the limit.
            {
                $ArchLogfile = $Path.replace(".log", "_$(Get-Date -Format dd-MM-yyy_hh-mm-ss).lo_")
                ren $Path $ArchLogfile
            }
         }
         
		 "$env:ComputerName date=$([char]34)$date2$([char]34) time=$([char]34)$date$([char]34) component=$([char]34)$component$([char]34) type=$([char]34)$severity$([char]34) Message=$([char]34)$Message$([char]34)"| Out-File -FilePath $Path -Append -NoClobber -Encoding default
         #If the log entry is just informational (less than 2), output it to write verbose
		 if ($severity -le 2) {"Info: $date $Message"| Write-Host -ForegroundColor Green}
		 #If the log entry has a severity of 3 assume its a warning and write it to write-warning
		 if ($severity -eq 3) {"$date $Message"| Write-Warning}
		 #If the log entry has a severity of 4 or higher, assume its an error and display an error message (Note, critical errors are caught by throw statements so may not appear here)
		 if ($severity -ge 4) {"$date $Message"| Write-Error}
} 

Function Get-IEProxy {
	Write-Host "Info: Checking for proxy settings" -ForegroundColor Green
        If ( (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').ProxyEnable -ne 0) {
            $proxies = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').proxyServer
            if ($proxies) {
                if ($proxies -ilike "*=*") {
                    return $proxies -replace "=", "://" -split (';') | Select-Object -First 1
                }
                Else {
                    return ('http://{0}' -f $proxies)
                }
            }
            Else {
                return $null
            }
        }
        Else {
            return $null
        }
    }

#endregion functions

## Mr Automations Code starts here to find the network ID

#region HelperFunctions 
 
# Function to convert IP address string to binary 
function toBinary ($dottedDecimal){ 
 $dottedDecimal.split(".") | ForEach-Object {$binary=$binary + $([convert]::toString($_,2).padleft(8,"0"))} 
 return $binary 
} 
 
# Function to binary IP address to dotted decimal string 
function toDottedDecimal ($binary){ 
 do {$dottedDecimal += "." + [string]$([convert]::toInt32($binary.substring($i,8),2)); $i+=8 } while ($i -le 24) 
 return $dottedDecimal.substring(1) 
} 
 
# Function to convert CIDR format to binary 
function CidrToBin ($cidr){ 
    if($cidr -le 32){ 
        [Int[]]$array = (1..32) 
        for($i=0;$i -lt $array.length;$i++){ 
            if($array[$i] -gt $cidr){$array[$i]="0"}else{$array[$i]="1"} 
        } 
        $cidr =$array -join "" 
    } 
    return $cidr 
} 
 
# Function to convert network mask to wildcard format 
function NetMasktoWildcard ($wildcard) { 
    foreach ($bit in [char[]]$wildcard) { 
        if ($bit -eq "1") { 
            $wildcardmask += "0" 
            } 
        elseif ($bit -eq "0") { 
            $wildcardmask += "1" 
            } 
        } 
    return $wildcardmask 
    } 
#endregion 
 

#region scriptblock
#Get Proxy Details
Write-Log -component "Script Block" -Message "Started Logging" -severity 1
if ($DisableScriptUpdate -eq $false) {
	Write-Log -component "Self Update" -Message "Checking for Script Update" -severity 1
	Write-Log -component "Self Update" -Message "Checking for Proxy" -severity 1
	    $ProxyURL = Get-IEProxy
    If ( $ProxyURL) {
		Write-Log -component "Self Update" -Message "Using proxy address $ProxyURL" -severity 1
       }
    Else {
		Write-Log -component "Self Update" -Message "No proxy setting detected, using direct connection" -severity 1
		    }
	
	$GitHubScriptVersion = Invoke-WebRequest https://raw.githubusercontent.com/atreidae/Test-CsLisIpAddress/master/version -TimeoutSec 10 -Proxy $ProxyURL
        If ($GitHubScriptVersion.Content.length -eq 0) {
			Write-Log -component "Self Update" -Message "Error checking for new version. You can check manualy here" -severity 3
			Write-Log -component "Self Update" -Message "http://www.skype4badmin.com/find-and-test-user-ip-addresses-in-the-skype-location-database" -severity 1
			Write-Log -component "Self Update" -Message "Pausing for 5 seconds" -severity 1
            start-sleep 5
            }
        else { 
                if ([single]$GitHubScriptVersion.Content -gt [single]$ScriptVersion) {
				Write-Log -component "Self Update" -Message "New Version Available" -severity 3
                   #New Version available

                    #Prompt user to download
				$title = "Update Available"
				$message = "an update to this script is available, did you want to download it?"

				$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", `
					"Launches a browser window with the update"

				$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", `
					"No thanks."

				$options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)

				$result = $host.ui.PromptForChoice($title, $message, $options, 0) 

				switch ($result)
					{
						0 {
							Write-Log -component "Self Update" -Message "User opted to download update" -severity 1
							start "http://www.skype4badmin.com/find-and-test-user-ip-addresses-in-the-skype-location-database"
							Write-Log -component "Self Update" -Message "Exiting Script" -severity 3
							Exit
						}
						1 {Write-Log -component "Self Update" -Message "User opted to skip update" -severity 1
									
							}
							
					}
                 }   
                 Else{
                 Write-Log -component "Self Update" -Message "Script is up to date" -severity 1
                 }
        
	       }

	}

 	#Import the Skype for Business / Lync Modules and error if not found
	Write-Log -component "Script Block" -Message "Checking for Lync/Skype management tools" -severity 1
	$ManagementTools = $false
	if(!(Get-Module "SkypeForBusiness")) {Import-Module SkypeForBusiness -Verbose:$false}
	if(!(Get-Module "Lync")) {Import-Module Lync -Verbose:$false}
	if(Get-Module "SkypeForBusiness") {$ManagementTools = $true}
	if(Get-Module "Lync") {$ManagementTools = $true}
	if(!$ManagementTools) {
		Write-Log 
		Write-Log -component "Script Block" -Message "Could not locate Lync/Skype4B Management tools. Script Exiting" -severity 3
		Exit
		}

# Check to see if the IP Address was entered in CIDR format. 
Write-log "Checking input IP Address" -component "ipCalc" -severity 1
Write-log "Entered IP $IPAddress" -component "ipCalc" -severity 1

if ($IPAddress -like "*/*") { 
	$CIDRIPAddress = $IPAddress 
    $IPAddress = $CIDRIPAddress.Split("/")[0] 
    $cidr = [convert]::ToInt32($CIDRIPAddress.Split("/")[1]) 
    if ($cidr -le 32 -and $cidr -ne 0) { 
		Write-log "CIDR Notation found" -component "ipCalc" -severity 1
        $ipBinary = toBinary $IPAddress 
        Write-Verbose $ipBinary 
        $smBinary = CidrToBin($cidr) 
        Write-Verbose $smBinary 
        $Netmask = toDottedDecimal($smBinary) 
        $wildcardbinary = NetMasktoWildcard ($smBinary) 
        } 
    else { 
		Write-log "Subnet Mask is invalid!" -component "ipCalc" -severity 3
		Exit 
        } 
    } 
 
# Address was not entered in CIDR format. 
else { 
	Write-log "Entered Mask $SubnetMask" -component "ipCalc" -severity 1
	$Netmask = $SubnetMask
    if (!$Netmask) { 
		Write-log "Subnet mask not found, requesting from user" -component "ipCalc" -severity 1
        $Netmask = Read-Host "Subnet Mask" 
        } 
    $ipBinary = toBinary $IPAddress 
    if ($Netmask -eq "0.0.0.0") { 
		Write-log "Subnet Mask is invalid!" -component "ipCalc" -severity 3
        Exit 
        } 
    else { 
        $smBinary = toBinary $Netmask 
        $wildcardbinary = NetMasktoWildcard ($smBinary) 
        } 
    } 
 
 
# First determine the location of the first zero in the subnet mask in binary (if any) 
$netBits=$smBinary.indexOf("0") 
 
# If there is a 0 found then the subnet mask is less than 32 (CIDR). 
if ($netBits -ne -1) { 
    $cidr = $netBits 
	Write-log "Found a netmask of /$cidr" -component "ipCalc" -severity 1
    #validate the subnet mask 
    if(($smBinary.length -ne 32) -or ($smBinary.substring($netBits).contains("1") -eq $true)) { 
        Write-log "Subnet Mask is invalid!" -component "ipCalc" -severity 3
        Exit 
        } 
    # Validate the IP address 
    if($ipBinary.length -ne 32) { 
        Write-log "IP Address is invalid!" -component "ipCalc" -severity 3
        Exit 
        } 
    #identify subnet boundaries 
    $networkID = toDottedDecimal $($ipBinary.substring(0,$netBits).padright(32,"0")) 
    $networkIDbinary = $ipBinary.substring(0,$netBits).padright(32,"0") 
    $firstAddress = toDottedDecimal $($ipBinary.substring(0,$netBits).padright(31,"0") + "1") 
    $firstAddressBinary = $($ipBinary.substring(0,$netBits).padright(31,"0") + "1") 
    $lastAddress = toDottedDecimal $($ipBinary.substring(0,$netBits).padright(31,"1") + "0") 
    $lastAddressBinary = $($ipBinary.substring(0,$netBits).padright(31,"1") + "0") 
    $broadCast = toDottedDecimal $($ipBinary.substring(0,$netBits).padright(32,"1")) 
    $broadCastbinary = $ipBinary.substring(0,$netBits).padright(32,"1") 
    $wildcard = toDottedDecimal ($wildcardbinary) 
    $Hostspernet = ([convert]::ToInt32($broadCastbinary,2) - [convert]::ToInt32($networkIDbinary,2)) - 1 
   } 
 
# Subnet mask is 32 (CIDR) 
else { 
     
    # Validate the IP address 
    if($ipBinary.length -ne 32) { 
        Write-log "IP Address is invalid!" -component "ipCalc" -severity 3
        Exit 
        } 
 
    #identify subnet boundaries 
    $networkID = toDottedDecimal $($ipBinary) 
    $networkIDbinary = $ipBinary 
    $firstAddress = toDottedDecimal $($ipBinary) 
    $firstAddressBinary = $ipBinary 
    $lastAddress = toDottedDecimal $($ipBinary) 
    $lastAddressBinary = $ipBinary 
    $broadCast = toDottedDecimal $($ipBinary) 
    $broadCastbinary = $ipBinary 
    $wildcard = toDottedDecimal ($wildcardbinary) 
    $Hostspernet = 1 
    $cidr = 32 
    } 
 
#region Lis Lookup
 Write-log "Network ID Found $networkID" -component "LIS" -severity 1

 #Get-CSLisSubnet doesnt support filtering, so we use where object instead
 $output = $null
 $output = (Get-CsLisSubnet | Where-object {$_.Subnet -eq $networkID})
if (!$output) {
		Write-log "No results returned from Location DB" -component "LIS" -severity 3
		Write-log "Sorry, We couldnt find a match for that IP / Subnet mask in the LIS database" -component "LIS" -severity 1
		Write-log "Remember, You cant use SuperNets like a /22 to cover users in seperate /24's as the network ID's are different" -component "LIS" -severity 1
		Write-log "Consult TechNet for more info on configuring LIS https://technet.microsoft.com/en-us/library/gg413069.aspx" -component "LIS" -severity 1
		Write-log "Did you remember to run Publish-CsLisConfiguration after importing your subnets?" -component "LIS" -severity 1
	}
	Else {
			#Results returned. need to make sure only 1 subnet is returned
			if ($output[1] -ne $null) {
			Write-log "Multiple results returned from Location DB" -component "LIS" -severity 3
			Write-log "This indicates duplicate entries in the LIS DB" -component "LIS" -severity 1
			Write-log "Export your LIS DB into a CSV file. Update it as appropriate and re-import" -component "LIS" -severity 1
			Write-log "Consult TechNet for more info https://technet.microsoft.com/en-us/library/gg413069.aspx" -component "LIS" -severity 1

				
			$output
			Exit
			}
		#results look good
		Write-log "LIS Entry found" -component "LIS" -severity 1
		$output
		Write-log "Script terminated normally" -component "LIS" -severity 1
		}
#endregion

#endregion scriptblock