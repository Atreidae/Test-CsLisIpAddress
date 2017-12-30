# Test-CsLisIpAddress
Provide this script with the IP Address and Subnet Mask of a users computer and see what Skype4B's LIS would report for them

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
