##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Cisco IOS XR Router NDM
# Version:  V3R6
# Class:    UNCLASSIFIED
# Updated:  4/21/2026
# Author:   Naval Sea Systems Command (NAVSEA)
##########################################################################
$ErrorActionPreference = "Stop"

Function Get-V216522 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216522
        STIG ID    : CISC-ND-000010
        Rule ID    : SV-216522r960735_rule
        CCI ID     : CCI-000054
        Rule Name  : SRG-APP-000001-NDM-000200
        Rule Title : The Cisco router must be configured to limit the number of concurrent management sessions to an organization-defined number.
        DiscussMD5 : F1519029437488F84FA9ED3FCE4716F8
        CheckMD5   : 3904816B1A49E3FED585F8D3AC469A78
        FixMD5     : 8D43B56FA8FBD3FB5FD4B6BBB2FA1D58
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $OpenFinding = $False
    $Exception = $False

    # Get server session limit.
    $ServerSession = $ShowRunningConfig | Select-String -Pattern "^ssh server session-limit"

    if ($ServerSession) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "The router has been configured to limit the number of concurrent management sessions." | Out-String
        $FindingDetails += "--------------------------" | Out-String
        $FindingDetails += "'$ServerSession'" | Out-String
        $FindingDetails += "" | Out-String
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "The router has not been configured to limit the number of concurrent management sessions. This is a finding." | Out-String
        $OpenFinding = $True
    }
    if ($OpenFinding) {
        $Status = "Open"
    }
    else {
        If (-Not($Exception) -and $FindingDetails.Trim().Length -gt 0) {
            $Status = "NotAFinding"
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails.Trim() -Algorithm SHA1
    }
    else {
        if  ($Status -ne "Not_Reviewed") {
            throw "Attempt to set Status without providing Finding Details."
        }
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status.Trim()
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails.Trim()
            ShowRun      = $ShowRunningConfig
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $SendAnswerData = $AnswerData
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status.Trim()
        FindingDetails   = $FindingDetails.Trim()
        AnswerData       = $SendAnswerData
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V216523 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216523
        STIG ID    : CISC-ND-000140
        Rule ID    : SV-216523r1137875_rule
        CCI ID     : CCI-001368, CCI-004192
        Rule Name  : SRG-APP-000038-NDM-000213
        Rule Title : The Cisco router must be configured to enforce approved authorizations for controlling the flow of management information within the device based on control policies.
        DiscussMD5 : 61B3FF6909A1F8732EFBB220FB482128
        CheckMD5   : 696431D257D9B9967A9ECA9087976E22
        FixMD5     : B6100D9A703DA4A2309FF47B43FE548D
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $OpenFinding = $False
    $Exception = $False
    $VtyPoolNoLineDefault = @()
    $VtyACLNameNotInDevice = @()
    $VtyACLMissingConfig = @()
    $VtyACLs = @()
    $NoVtyPoolName = @()
    $VtyNoAccessClass = @()

    # Get vty pools.
    $VtyPools = $ShowRunningConfig | Select-String -Pattern "^vty"
    IF ($VtyPools) {
        ForEach ($VtyPool in $VtyPools) {
            $VtyPoolName = $VtyPool.ToString().Split([char[]]"") | Select-Object -Index 1
            IF ($VtyPoolName) {
                # Get line vty
                $LineDefault = $ShowRunningConfig | Select-String -Pattern "line $VtyPoolName"
                IF ($LineDefault) {
                    $LineDefaultConfig = Get-Section $ShowRunningConfig $LineDefault | Out-String
                    IF ($LineDefaultConfig) {
                        # Get line vty ACL
                        $VtyACL = $LineDefaultConfig | Select-String -Pattern "^access-class"
                        IF ($VtyACL) {
                            $VtyACLName = $VtyACL.ToString().Split([char[]]"") | Select-Object -Index 2
                            # Verify ACL is configured in device
                            $AccessList = ($ShowRunningConfig | Select-String -Pattern "ipv4 access-list $VtyACLName")
                            $AccessListConfig = Get-Section $ShowRunningConfig $AccessList
                            IF ($AccessList) {
                                $Pattern1 = " permit ipv4 .* any"
                                $Pattern2 = "deny ipv4 any any log-input"
                                IF (($AccessListConfig | Select-String -Pattern $Pattern1) -and ($AccessListConfig | Select-String -Pattern $Pattern2)) {
                                    $VtyACLs += "$VtyPool"+"`n "+"$VtyACL"+"`n`n"
                                } ELSE {
                                    $VtyACLMissingConfig += "$VtyPool"+"`n "+"$VtyACL"+"`n`n"
                                }
                            } ELSE {
                                $VtyACLNameNotInDevice += "$VtyPool"+"`n "+"$VtyACL"+"`n`n"
                            }
                        } ELSE {
                            $VtyNoAccessClass += "$LineDefault"+"`n"+ "$LineDefaultConfig"+"`n"
                        }
                    }
                } ELSE {
                    $VtyPoolNoLineDefault += "$VtyPool"+"`n"
                }
            } ELSE {
                $NoVtyPoolName += "$VtyPool"+"`n"
            }
        }
    } ELSE {
        $FindingDetails += "" | Out-String
        $FindingDetails += "The router has no vty configured." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "--------------------------" | Out-String
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    IF ($NoVtyPoolName.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following vty has no name defined. This is a finding." | Out-String
        $FindingDetails += "--------------------------" | Out-String
        $FindingDetails += $NoVtyPoolName
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }
    IF($VtyNoAccessClass.Count -gt 0){
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following line vty has no access-list defined. This is a finding." | Out-String
        $FindingDetails += "--------------------------" | Out-String
        $FindingDetails += $VtyNoAccessClass
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }
    IF ($VtyPoolNoLineDefault.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Line for following vty pool has not been configured. This is a finding." | Out-String
        $FindingDetails += "--------------------------" | Out-String
        $FindingDetails += $VtyPoolNoLineDefault
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }
    IF ($VtyACLNameNotInDevice.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following ACLs associated to vty pool has not been configured in device. This is a finding." | Out-String
        $FindingDetails += "--------------------------" | Out-String
        $FindingDetails += $VtyACLNameNotInDevice
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }
    IF ($VtyACLMissingConfig.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following ACLs associated to vty pools is not configured properly. This is a finding." | Out-String
        $FindingDetails += "--------------------------" | Out-String
        $FindingDetails += $VtyACLMissingConfig
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }
    IF ($VtyACLs.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following ACLs and associated vty pools are configured in device." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "--------------------------" | Out-String
        $FindingDetails += $VtyACLs
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    IF ($OpenFinding) {
        $Status = "Open"
    }
    else {
        If (-Not($Exception) -and $FindingDetails.Trim().Length -gt 0) {
            $Status = "NotAFinding"
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails.Trim() -Algorithm SHA1
    }
    else {
        if  ($Status -ne "Not_Reviewed") {
            throw "Attempt to set Status without providing Finding Details."
        }
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status.Trim()
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails.Trim()
            ShowRun      = $ShowRunningConfig
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $SendAnswerData = $AnswerData
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status.Trim()
        FindingDetails   = $FindingDetails.Trim()
        AnswerData       = $SendAnswerData
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V216524 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216524
        STIG ID    : CISC-ND-000150
        Rule ID    : SV-216524r960840_rule
        CCI ID     : CCI-000044
        Rule Name  : SRG-APP-000065-NDM-000214
        Rule Title : The Cisco router must be configured to enforce the limit of three consecutive invalid logon attempts after which time lock out the user account from accessing the device for 15 minutes.
        DiscussMD5 : 6EA24F5018AA9E110FB8B7C1C1DCF238
        CheckMD5   : 7ABD63AB59AFDA8E28CCD7CEE3020964
        FixMD5     : 0840B96AFFA4F59721907EB3EF1549F7
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $OpenFinding = $False
    $Exception = $False
    $NoOfHosts = 0

    # Get authentication server
    $RadiusServerHosts = $ShowRunningConfig | Select-String -Pattern "^radius-server host "
    if ($RadiusServerHosts) {
        foreach ($RadiusServerHost in $RadiusServerHosts) {
            $NoOfHosts += 1
            $RadiusServerHostConfig = Get-Section $ShowRunningConfig $RadiusServerHost
            # Verify authentication key is set
            $RadiusServerKey = $RadiusServerHostConfig | Select-String -Pattern "^key .*"
            if ($RadiusServerKey) {
                # Get authentication login details
                $RadiusLocalAuthentication = $ShowRunningConfig | Select-String -Pattern "^aaa authentication login .*"
                if ($RadiusLocalAuthentication) {
                    $RadiusServerAuthenticationName = ($RadiusLocalAuthentication.ToString().Split([char[]]"") | Select-Object -Index 3)
                    # Verify authentication is set for line default and line console
                    $LineDefault = $ShowRunningConfig | Select-String -Pattern "^line default"
                    if ($LineDefault) {
                        $LineDefaultConfig = Get-Section $ShowRunningConfig $LineDefault
                        $LineDefaultAuth = $LineDefaultConfig | Select-String -Pattern "login authentication $RadiusServerAuthenticationName"
                        if ($LineDefaultAuth) {
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "Authentication login '$RadiusLocalAuthentication' is set for '$RadiusServerHost'." | Out-String
                            $FindingDetails += "Login authentication '$RadiusServerAuthenticationName' is set for line default." | Out-String
                            $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
                            $FindingDetails += "" | Out-String
                            $Exception = $True
                        }
                        else {
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "Authentication login '$RadiusLocalAuthentication' is set for '$RadiusServerHost'." | Out-String
                            $FindingDetails += "Login authentication '$RadiusServerAuthenticationName' is not set for line default. This is a finding." | Out-String
                            $FindingDetails += "" | Out-String
                            $OpenFinding = $True
                        }
                    }
                    else {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Line default is not set for device." | Out-String
                        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
                        $FindingDetails += "--------------------------" | Out-String
                        $FindingDetails += "" | Out-String
                        $Exception = $True
                    }
                    $LineConsole = $ShowRunningConfig | Select-String -Pattern "^line console"
                    if ($LineConsole) {
                        $LineConsoleConfig = Get-Section $ShowRunningConfig $LineConsole
                        $LineConsoleAuth = $LineConsoleConfig | Select-String -Pattern "login authentication $RadiusServerAuthenticationName"
                        if ($LineConsoleAuth) {
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "Authentication login '$RadiusLocalAuthentication' is set for '$RadiusServerHost'." | Out-String
                            $FindingDetails += "Login authentication '$RadiusServerAuthenticationName' is set for line console." | Out-String
                            $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
                            $FindingDetails += "" | Out-String
                            $Exception = $True
                        }
                        else {
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "Authentication login '$RadiusLocalAuthentication' is set for '$RadiusServerHost'." | Out-String
                            $FindingDetails += "Login authentication '$RadiusServerAuthenticationName' is not set for line console. This is a finding." | Out-String
                            $FindingDetails += "" | Out-String
                            $OpenFinding = $True
                        }
                    }
                    else {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Line console is not set for device." | Out-String
                        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
                        $FindingDetails += "" | Out-String
                        $Exception = $True
                    }
                }
                else {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Authentication login is not set for '$RadiusServerHost'." | Out-String
                    $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
                    $FindingDetails += "" | Out-String
                    $Exception = $True
                }
            }
            else {
                $FindingDetails += "" | Out-String
                $FindingDetails += "Key is not configured for radius server '$RadiusServerHost'. This is a finding." | Out-String
                $FindingDetails += "" | Out-String
                $OpenFinding = $True
            }
        }
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Authentication server is not configured for the device. This is a finding." | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }
    if ($OpenFinding) {
        $Status = "Open"
    }
    else {
        If (-Not($Exception) -and $FindingDetails.Trim().Length -gt 0) {
            $Status = "NotAFinding"
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails.Trim() -Algorithm SHA1
    }
    else {
        if  ($Status -ne "Not_Reviewed") {
            throw "Attempt to set Status without providing Finding Details."
        }
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status.Trim()
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails.Trim()
            ShowRun      = $ShowRunningConfig
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $SendAnswerData = $AnswerData
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status.Trim()
        FindingDetails   = $FindingDetails.Trim()
        AnswerData       = $SendAnswerData
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V216525 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216525
        STIG ID    : CISC-ND-000160
        Rule ID    : SV-216525r960843_rule
        CCI ID     : CCI-000048
        Rule Name  : SRG-APP-000068-NDM-000215
        Rule Title : The Cisco router must be configured to display the Standard Mandatory DoD Notice and Consent Banner before granting access to the device.
        DiscussMD5 : CF61FAB7486D38C6A0974CBBE13DBBB4
        CheckMD5   : 9E07FC09CE6871C88E82F08CEFBB78E2
        FixMD5     : 129A7B59400E6DD308BEE16CD0DC843D
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $OpenFinding = $False
    $Exception = $False

    # Get authentication server
    $BannerLogin = $ShowRunningConfig | Select-String -Pattern "^banner login"
    if ($BannerLogin) {
        $BannerLoginDelimiter = ($BannerLogin.ToString().Split([char[]]"") | Select-Object -Index 2)
        $startIndex = ($ShowRunningConfig | Select-String -Pattern "^banner login" | Select-Object -First 1).LineNumber[0]
        $endSTR = $BannerLoginDelimiter
        $endIndex = 0
        for ($i = $startIndex; $i -le $ShowRunningConfig.Count; $i++) {
            $endIndex = $i + 1
            if ($ShowRunningConfig[$i] -eq $endSTR) {
                # If the $endSTR line is found
                break
            }
        }
        $BannerLoginConfig = $ShowRunningConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))

        $FindingDetails += "" | Out-String
        $FindingDetails += "Following DOD Notice and Consent Banner is set for the device." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "--------------------------" | Out-String
        $FindingDetails += $BannerLoginConfig | Out-String
        $FindingDetails += "" | Out-String
        $Exception = $True

    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Standard Mandatory DoD Notice and Consent Banner is not configured for the device. This is a finding." | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }
    if ($OpenFinding) {
        $Status = "Open"
    }
    else {
        If (-Not($Exception) -and $FindingDetails.Trim().Length -gt 0) {
            $Status = "NotAFinding"
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails.Trim() -Algorithm SHA1
    }
    else {
        if  ($Status -ne "Not_Reviewed") {
            throw "Attempt to set Status without providing Finding Details."
        }
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status.Trim()
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails.Trim()
            ShowRun      = $ShowRunningConfig
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $SendAnswerData = $AnswerData
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status.Trim()
        FindingDetails   = $FindingDetails.Trim()
        AnswerData       = $SendAnswerData
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V216526 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216526
        STIG ID    : CISC-ND-000250
        Rule ID    : SV-216526r960885_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000091-NDM-000223
        Rule Title : The Cisco router must be configured to generate audit records when successful/unsuccessful attempts to logon with access privileges occur.
        DiscussMD5 : E108C657E0F9750757FD9F90E4407295
        CheckMD5   : A571E82947DF6167E187B79B6BBD93B1
        FixMD5     : ACE7376F057233E0EED4BD9FAE615A56
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $OpenFinding = $False
    $Exception = $False

    # Get logging buffer info
    $LogBuffer = $ShowRunningConfig | Select-String -Pattern "^logging buffered informational"
    # Get logging buffer security info
    $LogSeverityInfo = $ShowRunningConfig | Select-String -Pattern "^logging .* severity info"
    if (($LogBuffer -and $LogSeverityInfo)) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Logging buffer and severity info is set for device." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "--------------------------" | Out-String
        $FindingDetails += $LogBuffer | Out-String
        $FindingDetails += $LogSeverityInfo | Out-String
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    elseif ($LogBuffer) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Logging buffer '$LogBuffer' is configured in device, but logging severity info is not set. This is a finding." | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }
    elseif ($LogSeverityInfo) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Logging buffer '$LogSeverityInfo' is configured in device, but logging buffer is not set. This is a finding." | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Logging buffer and severity info are not configured for the device. This is a finding." | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }
    if ($OpenFinding) {
        $Status = "Open"
    }
    else {
        If (-Not($Exception) -and $FindingDetails.Trim().Length -gt 0) {
            $Status = "NotAFinding"
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails.Trim() -Algorithm SHA1
    }
    else {
        if  ($Status -ne "Not_Reviewed") {
            throw "Attempt to set Status without providing Finding Details."
        }
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status.Trim()
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails.Trim()
            ShowRun      = $ShowRunningConfig
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $SendAnswerData = $AnswerData
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status.Trim()
        FindingDetails   = $FindingDetails.Trim()
        AnswerData       = $SendAnswerData
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V216527 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216527
        STIG ID    : CISC-ND-000280
        Rule ID    : SV-216527r960894_rule
        CCI ID     : CCI-000131
        Rule Name  : SRG-APP-000096-NDM-000226
        Rule Title : The Cisco router must produce audit records containing information to establish when (date and time) the events occurred.
        DiscussMD5 : D3221577E453F1B93CE67F6D72965A55
        CheckMD5   : 163ACA06A8AC649C7E24C5B26512AF45
        FixMD5     : D1E94ACCBF6A335BA8E87EB3B8163048
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $OpenFinding = $False
    $Exception = $False
    $TimeStamps = @()

    # Get service timestamps
    $ServiceTimeStamps = $ShowRunningConfig | Select-String -Pattern "^service timestamps .*"
    if ($ServiceTimeStamps) {
        foreach ($ServiceTimeStamp in $ServiceTimeStamps) {
            $TimeStamps += "$ServiceTimeStamp`n"
        }
        $FindingDetails += "" | Out-String
        $FindingDetails += "Service timestamps are set for device." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "--------------------------" | Out-String
        $FindingDetails += $TimeStamps
        $FindingDetails += "" | Out-String
        $Exception = $True

    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Service timestamps are not configured for the device. This is a finding." | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }
    if ($OpenFinding) {
        $Status = "Open"
    }
    else {
        If (-Not($Exception) -and $FindingDetails.Trim().Length -gt 0) {
            $Status = "NotAFinding"
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails.Trim() -Algorithm SHA1
    }
    else {
        if  ($Status -ne "Not_Reviewed") {
            throw "Attempt to set Status without providing Finding Details."
        }
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status.Trim()
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails.Trim()
            ShowRun      = $ShowRunningConfig
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $SendAnswerData = $AnswerData
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status.Trim()
        FindingDetails   = $FindingDetails.Trim()
        AnswerData       = $SendAnswerData
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V216528 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216528
        STIG ID    : CISC-ND-000290
        Rule ID    : SV-216528r960897_rule
        CCI ID     : CCI-000132
        Rule Name  : SRG-APP-000097-NDM-000227
        Rule Title : The Cisco router must produce audit records containing information to establish where the events occurred.
        DiscussMD5 : AFF39330BBAA35F46273890D1E49DA4A
        CheckMD5   : 6E0B8A4C37346ED8231176045A3BC32A
        FixMD5     : 6537803AAC4F1EE5471D8F52E4C89CB2
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $OpenFinding = $False
    $Exception = $False
    $NoDenyACL = @()
    $NoDenyLogInputACL = @()
    $DenyLogInputACL = @()

    # Get service ACLs
    $ACLList = $ShowRunningConfig | Select-String -Pattern "^ipv4 access-list .*"
    if ($ACLList) {
        foreach ($ACL in $ACLList) {
            $ACLConfig = Get-Section $ShowRunningConfig $ACL
            $ACLDenyStatements = $ACLConfig | Select-String -Pattern " deny .*"
            if ($ACLDenyStatements) {
                foreach ($ACLDenyStatement in $ACLDenyStatements) {
                    $ACLDenyLogInput = $ACLDenyStatement | Select-String -Pattern " log-input$"
                    if ($ACLDenyLogInput) {
                        $DenyLogInputACL += "$ACL`n " + "$ACLDenyStatement`n`n"
                    }
                    else {
                        $NoDenyLogInputACL += "$ACL`n " + "$ACLDenyStatement`n`n"
                    }
                }
            }
            else {
                $NoDenyACL += "$ACL`n"
            }
        }

        if ($NoDenyLogInputACL.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Following ACLs' deny statement missing log-input parameter. If these are interface bound ACLs, then this is a finding." | Out-String
            $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "--------------------------" | Out-String
            $FindingDetails += $NoDenyLogInputACL
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
        if ($NoDenyACL.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Following ACLs have no deny statement configured." | Out-String
            $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "--------------------------" | Out-String
            $FindingDetails += $NoDenyACL
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
        if ($DenyLogInputACL.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Following ACLs have deny statements configured with log-input." | Out-String
            $FindingDetails += "Verify these are interface bound ACLs." | Out-String
            $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "--------------------------" | Out-String
            $FindingDetails += $DenyLogInputACL
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "ACLs are not configured for the device." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    if ($OpenFinding) {
        $Status = "Open"
    }
    else {
        If (-Not($Exception) -and $FindingDetails.Trim().Length -gt 0) {
            $Status = "NotAFinding"
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails.Trim() -Algorithm SHA1
    }
    else {
        if  ($Status -ne "Not_Reviewed") {
            throw "Attempt to set Status without providing Finding Details."
        }
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status.Trim()
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails.Trim()
            ShowRun      = $ShowRunningConfig
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $SendAnswerData = $AnswerData
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status.Trim()
        FindingDetails   = $FindingDetails.Trim()
        AnswerData       = $SendAnswerData
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V216529 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216529
        STIG ID    : CISC-ND-000470
        Rule ID    : SV-216529r1043177_rule
        CCI ID     : CCI-000382
        Rule Name  : SRG-APP-000142-NDM-000245
        Rule Title : The Cisco router must be configured to be configured to prohibit the use of all unnecessary and nonsecure functions and services.
        DiscussMD5 : 3E6CD5ADF99942F100B05BEF828F3687
        CheckMD5   : 01E3BC7C48443B4B90D92FF53EE429A3
        FixMD5     : 643F4FEF083D6BDBCB375CB1AE11D314
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $OpenFinding = $False
    $Exception = $False
    $AllSet = $True

    # Define patterns for checking
    $Check_Patterns = @(
        'service ipv4 tcp-small-servers max-servers .*',
        'service ipv4 udp-small-servers max-servers .*',
        'http client vrf .*',
        'telnet vrf default ipv4 server max-servers .*',
        'service call-home')

    foreach ($Check_Pattern in $Check_Patterns) {
        $ForbiddenService = $ShowRunningConfig | Select-String -Pattern $Check_Pattern
        if ($ForbiddenService) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Router has '$ForbiddenService' configured. This is a finding." | Out-String
            $FindingDetails += "" | Out-String
            $AllSet = $False
            $OpenFinding = $True
        }
    }
    if ($AllSet) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "This device does not have any unnecessary or nonsecure ports, protocols, and services enabled." | Out-String
        $FindingDetails += "--------------------------" | Out-String
        $FindingDetails += "" | Out-String
    }
    if ($OpenFinding) {
        $Status = "Open"
    }
    else {
        If (-Not($Exception) -and $FindingDetails.Trim().Length -gt 0) {
            $Status = "NotAFinding"
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails.Trim() -Algorithm SHA1
    }
    else {
        if  ($Status -ne "Not_Reviewed") {
            throw "Attempt to set Status without providing Finding Details."
        }
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status.Trim()
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails.Trim()
            ShowRun      = $ShowRunningConfig
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $SendAnswerData = $AnswerData
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status.Trim()
        FindingDetails   = $FindingDetails.Trim()
        AnswerData       = $SendAnswerData
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V216530 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216530
        STIG ID    : CISC-ND-000490
        Rule ID    : SV-216530r1051115_rule
        CCI ID     : CCI-001358, CCI-002111
        Rule Name  : SRG-APP-000148-NDM-000346
        Rule Title : The Cisco router must be configured with only one local account to be used as the account of last resort in the event the authentication server is unavailable.
        DiscussMD5 : 770661E395811E143543EDE334AC2B0C
        CheckMD5   : EB9CC438407E90A91E06AA91956A384E
        FixMD5     : F25F4FFC610F508B5586E05111FFBE1B
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $OpenFinding = $False
    $Exception = $False
    $NoGroupUsername = @()
    $NoSecretUsername = @()
    $NoGroupSecretUsername = @()

    # Get authentication server
    $Usernames = $ShowRunningConfig | Select-String -Pattern "^username "
    if ($Usernames) {
        foreach ($Username in $Usernames) {
            $UsernameConfig = Get-Section $ShowRunningConfig $Username
            # Verify group and secret is configured
            $Group = $UsernameConfig | Select-String -Pattern "^group .*"
            $Secret = $UsernameConfig | Select-String -Pattern "^secret .*"
            if (!$Group) {
                $NoGroupUsername += "$Username`n"
            }
            if (!$Secret) {
                $NoSecretUsername += "$Username`n"
            }
            if (($Group -and $Secret)) {
                $NoGroupSecretUsername += "$Username`n"
            }
        }
        if ($NoGroupUsername.count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Group is not set for following users." | Out-String
            $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "--------------------------" | Out-String
            $FindingDetails += $NoGroupUsername
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
        if ($NoSecretUsername.count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Secret password is not set for following users." | Out-String
            $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "--------------------------" | Out-String
            $FindingDetails += $NoSecretUsername
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
        if ($NoGroupSecretUsername.count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Group and password are not set for following users." | Out-String
            $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "--------------------------" | Out-String
            $FindingDetails += $NoGroupSecretUsername
            $FindingDetails += "" | Out-String
            $Exception = $True
        }

    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Local username is not set for device." | Out-String
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    # Get authentication login details
    $RadiusLocalAuthentication = $ShowRunningConfig | Select-String -Pattern "^aaa authentication login .* local"
    if ($RadiusLocalAuthentication) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Authentication login '$RadiusLocalAuthentication' is set for device." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "AAA Authentication login local is not set on this device. This is a finding." | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }

    if ($OpenFinding) {
        $Status = "Open"
    }
    else {
        If (-Not($Exception) -and $FindingDetails.Trim().Length -gt 0) {
            $Status = "NotAFinding"
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails.Trim() -Algorithm SHA1
    }
    else {
        if  ($Status -ne "Not_Reviewed") {
            throw "Attempt to set Status without providing Finding Details."
        }
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status.Trim()
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails.Trim()
            ShowRun      = $ShowRunningConfig
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $SendAnswerData = $AnswerData
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status.Trim()
        FindingDetails   = $FindingDetails.Trim()
        AnswerData       = $SendAnswerData
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V216531 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216531
        STIG ID    : CISC-ND-000530
        Rule ID    : SV-216531r960993_rule
        CCI ID     : CCI-001941
        Rule Name  : SRG-APP-000156-NDM-000250
        Rule Title : The Cisco router must be configured to implement replay-resistant authentication mechanisms for network access to privileged accounts.
        DiscussMD5 : 580A8A11C54DF570B552663B9E4F2B01
        CheckMD5   : 900B0D694D3A6B22A0D669CCDEF7E1D4
        FixMD5     : 25DCE1562AC52EE97119EC6CEE317FF9
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $OpenFinding = $False
    $Exception = $False

    # Get server session v2.
    $ServerSession = $ShowRunningConfig | Select-String -Pattern "^ssh server v2"

    if ($ServerSession) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "The router has been configured to implement replay-resistant authentication mechanisms for network access to privileged accounts." | Out-String
        $FindingDetails += "--------------------------" | Out-String
        $FindingDetails += $ServerSession | Out-String
        $FindingDetails += "" | Out-String
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "The router has not been configured to implement replay-resistant authentication mechanisms for network access to privileged accounts. This is a finding." | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }
    if ($OpenFinding) {
        $Status = "Open"
    }
    else {
        If (-Not($Exception) -and $FindingDetails.Trim().Length -gt 0) {
            $Status = "NotAFinding"
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails.Trim() -Algorithm SHA1
    }
    else {
        if  ($Status -ne "Not_Reviewed") {
            throw "Attempt to set Status without providing Finding Details."
        }
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status.Trim()
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails.Trim()
            ShowRun      = $ShowRunningConfig
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $SendAnswerData = $AnswerData
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status.Trim()
        FindingDetails   = $FindingDetails.Trim()
        AnswerData       = $SendAnswerData
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V216532 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216532
        STIG ID    : CISC-ND-000720
        Rule ID    : SV-216532r961068_rule
        CCI ID     : CCI-001133
        Rule Name  : SRG-APP-000190-NDM-000267
        Rule Title : The Cisco router must be configured to terminate all network connections associated with device management after five minutes of inactivity.
        DiscussMD5 : C55855B1F7DC3A2BCA7DC4A4B7EA8027
        CheckMD5   : DCE01910D77FF99EDAD685A6084AAAFD
        FixMD5     : 52AEC45D754CA5EF6FC7C777F7471397
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $OpenFinding = $False
    $Exception = $False

    $Check_Patterns = @(
        'console',
        'default')

    foreach ($Check_Pattern in $Check_Patterns) {
        # Get line console and line default configuration
        $LineDefault = $ShowRunningConfig | Select-String -Pattern "line $Check_Pattern"
        if ($LineDefault) {
            $LineDefaultConfig = Get-Section $ShowRunningConfig $LineDefault
            if ($LineDefaultConfig) {
                # Verify timeout is configured
                $ExecTimeout = $LineDefaultConfig | Select-String -Pattern "^exec-timeout "
                if ($ExecTimeout) {
                    $ExecTime = $ExecTimeout.ToString().Split([char[]]"") | Select-Object -Index 1
                    if ($ExecTime -and $ExecTime -le 5) {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "'$ExecTimeout' has been configured for '$LineDefault'." | Out-String
                        $FindingDetails += "" | Out-String
                    }
                    else {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "'$ExecTimeout' has been configured for '$LineDefault'." | Out-String
                        $FindingDetails += "Exec timeout time should be 5 minutes or less. This is a finding."
                        $FindingDetails += "" | Out-String
                        $OpenFinding = $True
                    }
                }
                else {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Timeout has not been configured for '$LineDefault'. This is a finding." | Out-String
                    $FindingDetails += "" | Out-String
                    $OpenFinding = $True
                }
            }
        }
        else {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Line '$Check_Pattern' has not been configured for device." | Out-String
            $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
    }

    if ($OpenFinding) {
        $Status = "Open"
    }
    else {
        If (-Not($Exception) -and $FindingDetails.Trim().Length -gt 0) {
            $Status = "NotAFinding"
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails.Trim() -Algorithm SHA1
    }
    else {
        if  ($Status -ne "Not_Reviewed") {
            throw "Attempt to set Status without providing Finding Details."
        }
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status.Trim()
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails.Trim()
            ShowRun      = $ShowRunningConfig
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $SendAnswerData = $AnswerData
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status.Trim()
        FindingDetails   = $FindingDetails.Trim()
        AnswerData       = $SendAnswerData
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V216533 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216533
        STIG ID    : CISC-ND-000980
        Rule ID    : SV-216533r1193106_rule
        CCI ID     : CCI-001849
        Rule Name  : SRG-APP-000357-NDM-000293
        Rule Title : The Cisco router must be configured to allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.
        DiscussMD5 : 3796374344336078FA1BEEE6A23D7D08
        CheckMD5   : A40FBB9AA37EA868DBED0289FAED4FD5
        FixMD5     : A50DD334C7350E9B6510D3B81910F53A
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $OpenFinding = $False
    $Exception = $False

    # Get log buffer
    $LogBuffers = $ShowRunningConfig | Select-String -Pattern "^logging buffered \d"
    If ($LogBuffers) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Logging buffer has been configured for device." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "--------------------------" | Out-String
        $FindingDetails += $LogBuffer
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    Else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Logging buffer has not been configured for device. This is a finding." | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }

    # Get logging syslog server
    $LogSyslog = $ShowRunningConfig | Select-String -Pattern "^logging \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    If ($LogSyslog) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Logging to a syslog server has been configured on this device." | Out-String
        $FindingDetails += $LogSyslog
        $FindingDetails += "" | Out-String
    }
    Else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Logging to a syslog server has not been configured on this device. This is a finding." | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }

    # Get log archive
    $LogArchive = $ShowRunningConfig | Select-String -Pattern "^logging archive"
    If ($LogArchive) {
        $Check_Patterns = @(
        'device harddisk',
        'severity notifications',
        'file-size',
        'archive-size')
        $LogArchiveConfig = Get-Section $ShowRunningConfig $LogArchive
        $LogArchiveParameter = @()
        $LogArchiveParameterMissing = @()
        ForEach ($Check_Pattern in $Check_Patterns) {
            $CheckArchiveFormat = $LogArchiveConfig | Select-String -Pattern $Check_Pattern
            If ($CheckArchiveFormat) {
                $LogArchiveParameter += "$CheckArchiveFormat`n"
            } Else {
                $LogArchiveParameterMissing += "$Check_Pattern`n"
            }
        }
        If ($LogArchiveParameter.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "'$LogArchive' has been configured with following parameters." | Out-String
            $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "--------------------------" | Out-String
            $FindingDetails += $LogArchiveParameter
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
        If ($LogArchiveParameterMissing.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "'$LogArchive' missing following parameters." | Out-String
            $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "--------------------------" | Out-String
            $FindingDetails += $LogArchiveParameterMissing
            $FindingDetails += "" | Out-String
            $Exception = $True
        }

    }
    Else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Logging archive has not been configured for device. This is a finding." | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }

    If ($OpenFinding) {
        $Status = "Open"
    }
    else {
        If (-Not($Exception) -and $FindingDetails.Trim().Length -gt 0) {
            $Status = "NotAFinding"
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails.Trim() -Algorithm SHA1
    }
    else {
        if  ($Status -ne "Not_Reviewed") {
            throw "Attempt to set Status without providing Finding Details."
        }
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status.Trim()
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails.Trim()
            ShowRun      = $ShowRunningConfig
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $SendAnswerData = $AnswerData
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status.Trim()
        FindingDetails   = $FindingDetails.Trim()
        AnswerData       = $SendAnswerData
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V216534 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216534
        STIG ID    : CISC-ND-001000
        Rule ID    : SV-216534r991930_rule
        CCI ID     : CCI-001858, CCI-003831
        Rule Name  : SRG-APP-000360-NDM-000295
        Rule Title : The Cisco router must be configured to generate an alert for all audit failure events.
        DiscussMD5 : 5A2FE043544D5FA66D313940CA473FE4
        CheckMD5   : 93C38AEF5FBC831A215112E3A79408FA
        FixMD5     : 61EA7F6B7A933039A32F6158B3747849
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ShowRunningConfig = $(Get-CiscoShowTechData -ShowTech $ShowTech -DataType XR-RunningConfig)
    $OpenFinding = $False
    $Exception = $False

    # Get logging severity
    $LogSeverityInfo = $ShowRunningConfig | Select-String -Pattern "^logging .* severity"

    if ($LogSeverityInfo) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Router is configured to generate an alert for all audit failure events." | Out-String
        $FindingDetails += "--------------------------" | Out-String
        $FindingDetails += $LogSeverityInfo | Out-String
        $FindingDetails += "" | Out-String
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Router is not configured to generate an alert for all audit failure events. This is a finding." | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }

    if ($OpenFinding) {
        $Status = "Open"
    }
    else {
        If (-Not($Exception) -and $FindingDetails.Trim().Length -gt 0) {
            $Status = "NotAFinding"
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails.Trim() -Algorithm SHA1
    }
    else {
        if  ($Status -ne "Not_Reviewed") {
            throw "Attempt to set Status without providing Finding Details."
        }
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status.Trim()
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails.Trim()
            ShowRun      = $ShowRunningConfig
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $SendAnswerData = $AnswerData
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status.Trim()
        FindingDetails   = $FindingDetails.Trim()
        AnswerData       = $SendAnswerData
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V216535 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216535
        STIG ID    : CISC-ND-001030
        Rule ID    : SV-216535r1015296_rule
        CCI ID     : CCI-001893, CCI-004922, CCI-004923, CCI-004928
        Rule Name  : SRG-APP-000373-NDM-000298
        Rule Title : The Cisco router must be configured to synchronize its clock with the primary and secondary time sources using redundant authoritative time sources.
        DiscussMD5 : DDCB7B99A9C111819BBFC1DE39E2919A
        CheckMD5   : 7954F4FBCE62EBBD9F576405340E481F
        FixMD5     : A6ABD07D6107CF2D190F14DBE6CE5F74
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $OpenFinding = $False
    $Exception = $False

    # Get ntp servers
    $Count = 0
    $NtpServers = $ShowRunningConfig | Select-String -Pattern "^ntp server .*"
    if ($NtpServers) {
        foreach ($NtpServer in $NtpServers) {
            $Count += 1
        }
        if ($Count -gt 1) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Router is configured to synchronize its clock with redundant authoritative time sources." | Out-String
            $FindingDetails += "--------------------------" | Out-String
            $FindingDetails += $NtpServers | Out-String
            $FindingDetails += "" | Out-String
        }
        else {
            $FindingDetails += "" | Out-String
            $FindingDetails += "More than one authoritative time source is required to be synchronized with router, only one is configured here." | Out-String
            $FindingDetails += "This is a finding." | Out-String
            $FindingDetails += "--------------------------" | Out-String
            $FindingDetails += $NtpServers | Out-String
            $FindingDetails += "" | Out-String
            $OpenFinding = $True
        }
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Router is not configured to synchronize its clock with redundant authoritative time sources. This is a finding." | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }

    if ($OpenFinding) {
        $Status = "Open"
    }
    else {
        If (-Not($Exception) -and $FindingDetails.Trim().Length -gt 0) {
            $Status = "NotAFinding"
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails.Trim() -Algorithm SHA1
    }
    else {
        if  ($Status -ne "Not_Reviewed") {
            throw "Attempt to set Status without providing Finding Details."
        }
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status.Trim()
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails.Trim()
            ShowRun      = $ShowRunningConfig
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $SendAnswerData = $AnswerData
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status.Trim()
        FindingDetails   = $FindingDetails.Trim()
        AnswerData       = $SendAnswerData
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V216536 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216536
        STIG ID    : CISC-ND-001040
        Rule ID    : SV-216536r961446_rule
        CCI ID     : CCI-001889
        Rule Name  : SRG-APP-000375-NDM-000300
        Rule Title : The Cisco router must record time stamps for audit records that meet a granularity of one second for a minimum degree of precision.
        DiscussMD5 : 2974D00B49AD6EF5BED63C9D62352117
        CheckMD5   : FA3B668EE2D1987FFB3676F19E0F8A12
        FixMD5     : E508859880688E2B10FD43D2B78A4C54
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $OpenFinding = $False
    $Exception = $False

    # Get logging severity
    $ServiceTimestamps = $ShowRunningConfig | Select-String -Pattern "^service timestamps log .*"
    if ($ServiceTimestamps) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Router is configured to record time stamps that meet a granularity of one second." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "--------------------------" | Out-String
        $FindingDetails += $ServiceTimestamp
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Router is not configured to record time stamps that meet a granularity of one second. This is a finding." | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }

    if ($OpenFinding) {
        $Status = "Open"
    }
    else {
        If (-Not($Exception) -and $FindingDetails.Trim().Length -gt 0) {
            $Status = "NotAFinding"
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails.Trim() -Algorithm SHA1
    }
    else {
        if  ($Status -ne "Not_Reviewed") {
            throw "Attempt to set Status without providing Finding Details."
        }
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status.Trim()
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails.Trim()
            ShowRun      = $ShowRunningConfig
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $SendAnswerData = $AnswerData
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status.Trim()
        FindingDetails   = $FindingDetails.Trim()
        AnswerData       = $SendAnswerData
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V216537 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216537
        STIG ID    : CISC-ND-001050
        Rule ID    : SV-216537r961443_rule
        CCI ID     : CCI-001890
        Rule Name  : SRG-APP-000374-NDM-000299
        Rule Title : The Cisco router must be configured to record time stamps for log records that can be mapped to Coordinated Universal Time (UTC) or Greenwich Mean Time (GMT).
        DiscussMD5 : 0DB319F1C50C4B706E240B90B0BB86AF
        CheckMD5   : 53E2DEB7E535DD9B90594406E5E5434A
        FixMD5     : B5B0BC0309A316A3EF9F5D5DAB94E55D
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $OpenFinding = $False
    $Exception = $False

    # Get logging severity
    $ClockTimezone = $ShowRunningConfig | Select-String -Pattern "^clock timezone .*"
    $ServiceTimestamps = $ShowRunningConfig | Select-String -Pattern "^service timestamps .*"
    if (($ServiceTimestamps -and $ClockTimezone)) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Router is configured to record time stamps for mapping audit records to UTC or GMT." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "--------------------------" | Out-String
        $FindingDetails += $ClockTimezone | Out-String
        $FindingDetails += $ServiceTimestamps | Out-String
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    elseif ($ServiceTimestamps) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "'$ServiceTimestamps' is configured but the router is not configured with clock time zone, for mapping audit records to UTC or GMT." | Out-String
        $FindingDetails += "This is a finding." | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }
    elseif ($ClockTimezone) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "$ClockTimezone' is configured but the router is not configured with service time stamps, for audit records that can be mapped to UTC or GMT." | Out-String
        $FindingDetails += "This is a finding." | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Router is not configured to record time stamps for mapping audit records to UTC or GMT." | Out-String
        $FindingDetails += "This is a finding." | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }

    if ($OpenFinding) {
        $Status = "Open"
    }
    else {
        If (-Not($Exception) -and $FindingDetails.Trim().Length -gt 0) {
            $Status = "NotAFinding"
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails.Trim() -Algorithm SHA1
    }
    else {
        if  ($Status -ne "Not_Reviewed") {
            throw "Attempt to set Status without providing Finding Details."
        }
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status.Trim()
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails.Trim()
            ShowRun      = $ShowRunningConfig
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $SendAnswerData = $AnswerData
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status.Trim()
        FindingDetails   = $FindingDetails.Trim()
        AnswerData       = $SendAnswerData
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V216538 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216538
        STIG ID    : CISC-ND-001130
        Rule ID    : SV-216538r961506_rule
        CCI ID     : CCI-001967
        Rule Name  : SRG-APP-000395-NDM-000310
        Rule Title : The Cisco router must be configured to authenticate SNMP messages using a FIPS-validated Keyed-Hash Message Authentication Code (HMAC).
        DiscussMD5 : D496EF6E2854AA9218CFE0EDD0C58874
        CheckMD5   : C92916DB882FADEB4EDE5A2DA0F09688
        FixMD5     : C83164445682EB3FCE4460C8B5EB33D1
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $OpenFinding = $False
    $Exception = $False
    $SnmpServerGroupNames = @()
    $SnmpServerReadAuthNames = @()
    $SnmpServerWriteAuthNames = @()
    $IsoIncludeSet = $False
    $IsoIncludeVerified = @()
    $IsoIncludeNotVerified = @()

    # Get snmp-server groups
    $SnmpServerGroups = $ShowRunningConfig | Select-String -Pattern "^snmp-server group .* v3 (auth|priv) (read|write) .*"
    $SnmpServerHosts = $ShowRunningConfig | Select-String -Pattern "^snmp-server host .* version 3 (auth|priv).*"
    if (($SnmpServerGroups)) {
        foreach ($SnmpServerGroup in $SnmpServerGroups) {
            $SnmpServerGroupSplit = $SnmpServerGroup.ToString().Split([char[]]"")
            $SnmpServerGroupNames += $SnmpServerGroupSplit | Select-Object -Index 2
            if ($SnmpServerGroupSplit.Count -ge 6) {
                $SnmpServerReadAuthNames += $SnmpServerGroupSplit | Select-Object -Index 6
            }
            if ($SnmpServerGroupSplit.Count -ge 8) {
                $SnmpServerWriteAuthNames += $SnmpServerGroupSplit | Select-Object -Index 8
            }
        }
        $SnmpIsoIncludes = $ShowRunningConfig | Select-String -Pattern "^snmp-server view .* iso included"
        foreach ($SnmpIsoInclude in $SnmpIsoIncludes) {
            $SnmpIsoIncludeName = $SnmpIsoInclude.ToString().Split([char[]]"") | Select-Object -Index 2
            if ($SnmpServerReadAuthNames) {
                foreach ($SnmpServerReadAuthName in $SnmpServerReadAuthNames) {
                    if ($SnmpIsoIncludeName -eq $SnmpServerReadAuthName) {
                        $IsoIncludeSet = $True
                    }
                }
            }
            if (($SnmpServerWriteAuthNames -and !$IsoIncludeSet)) {
                foreach ($SnmpServerWriteAuthName in $SnmpServerWriteAuthNames) {
                    if ($SnmpIsoIncludeName -eq $SnmpServerWriteAuthName) {
                        $IsoIncludeSet = $True
                    }
                }
            }
            if (!$IsoIncludeSet) {
                $IsoIncludeNotVerified += "$SnmpIsoInclude`n"
            }
            else {
                $IsoIncludeVerified += "$SnmpIsoInclude`n"
            }
            $IsoIncludeSet = $False
        }
        $FindingDetails += "" | Out-String
        $FindingDetails += "SNMP Server Group Configuration:" | Out-String
        $FindingDetails += "--------------------------" | Out-String
        $FindingDetails += $SnmpServerGroups | Out-String
        $FindingDetails += "" | Out-String
        $Exception = $True
        if ($IsoIncludeVerified.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "SNMP Server View Configuration:" | Out-String
            $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "--------------------------" | Out-String
            $FindingDetails += $IsoIncludeVerified | Out-String
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
        if ($IsoIncludeNotVerified.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Following are snmp-server iso included views which do not have user group defined read or write authentication." | Out-String
            $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "--------------------------" | Out-String
            $FindingDetails += $IsoIncludeNotVerified
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "snmp-server group is not set for the device. This is a finding." | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }
    $FindingDetails += "" | Out-String
    $FindingDetails += "Verify snmp server users configuration with 'show snmp users' command." | Out-String
    $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
    $FindingDetails += "" | Out-String
    $Exception = $True
    if ($SnmpServerHosts) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Verify following snmp server host configurations are in accordance with snmp users." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "--------------------------" | Out-String
        $FindingDetails += $SnmpServerHosts | Out-String
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "snmp server host configuration is missing." | Out-String
        $FindingDetails += "This is a finding." | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }

    if ($OpenFinding) {
        $Status = "Open"
    }
    else {
        If (-Not($Exception) -and $FindingDetails.Trim().Length -gt 0) {
            $Status = "NotAFinding"
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails.Trim() -Algorithm SHA1
    }
    else {
        if  ($Status -ne "Not_Reviewed") {
            throw "Attempt to set Status without providing Finding Details."
        }
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status.Trim()
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails.Trim()
            ShowRun      = $ShowRunningConfig
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $SendAnswerData = $AnswerData
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status.Trim()
        FindingDetails   = $FindingDetails.Trim()
        AnswerData       = $SendAnswerData
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V216539 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216539
        STIG ID    : CISC-ND-001140
        Rule ID    : SV-216539r961506_rule
        CCI ID     : CCI-000068
        Rule Name  : SRG-APP-000395-NDM-000310
        Rule Title : The Cisco router must be configured to encrypt SNMP messages using a FIPS 140-2 approved algorithm.
        DiscussMD5 : EC38084E1A006FA7ADEE0533040CE597
        CheckMD5   : 795B1599970CFC450A63E1E2E1F9ED38
        FixMD5     : AC1C817F75E9FFD9313E62CA25C3B111
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $OpenFinding = $False
    $Exception = $False
    $SnmpServerGroupNames = @()
    $SnmpServerReadAuthNames = @()
    $SnmpServerWriteAuthNames = @()
    $IsoIncludeSet = $False
    $IsoIncludeVerified = @()
    $IsoIncludeNotVerified = @()

    # Get snmp-server groups
    $SnmpServerGroups = $ShowRunningConfig | Select-String -Pattern "^snmp-server group .* v3 (auth|priv) (read|write) .*"
    $SnmpServerHosts = $ShowRunningConfig | Select-String -Pattern "^snmp-server host .* version 3 (auth|priv).*"
    if (($SnmpServerGroups)) {
        foreach ($SnmpServerGroup in $SnmpServerGroups) {
            $SnmpServerGroupSplit = $SnmpServerGroup.ToString().Split([char[]]"")
            $SnmpServerGroupNames += $SnmpServerGroupSplit | Select-Object -Index 2
            if ($SnmpServerGroupSplit.Count -ge 6) {
                $SnmpServerReadAuthNames += $SnmpServerGroupSplit | Select-Object -Index 6
            }
            if ($SnmpServerGroupSplit.Count -ge 8) {
                $SnmpServerWriteAuthNames += $SnmpServerGroupSplit | Select-Object -Index 8
            }
        }
        $SnmpIsoIncludes = $ShowRunningConfig | Select-String -Pattern "^snmp-server view .* iso included"
        foreach ($SnmpIsoInclude in $SnmpIsoIncludes) {
            $SnmpIsoIncludeName = $SnmpIsoInclude.ToString().Split([char[]]"") | Select-Object -Index 2
            if ($SnmpServerReadAuthNames) {
                foreach ($SnmpServerReadAuthName in $SnmpServerReadAuthNames) {
                    if ($SnmpIsoIncludeName -eq $SnmpServerReadAuthName) {
                        $IsoIncludeSet = $True
                    }
                }
            }
            if (($SnmpServerWriteAuthNames -and !$IsoIncludeSet)) {
                foreach ($SnmpServerWriteAuthName in $SnmpServerWriteAuthNames) {
                    if ($SnmpIsoIncludeName -eq $SnmpServerWriteAuthName) {
                        $IsoIncludeSet = $True
                    }
                }
            }
            if (!$IsoIncludeSet) {
                $IsoIncludeNotVerified += "$SnmpIsoInclude`n"
            }
            else {
                $IsoIncludeVerified += "$SnmpIsoInclude`n"
            }
            $IsoIncludeSet = $False
        }
        $FindingDetails += "" | Out-String
        $FindingDetails += "SNMP Server Group Configuration:" | Out-String
        $FindingDetails += "--------------------------" | Out-String
        $FindingDetails += $SnmpServerGroups | Out-String
        $FindingDetails += "" | Out-String
        $Exception = $True
        if ($IsoIncludeVerified.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "SNMP Server View Configuration:" | Out-String
            $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "--------------------------" | Out-String
            $FindingDetails += $IsoIncludeVerified | Out-String
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
        if ($IsoIncludeNotVerified.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Following are snmp-server iso included views which do not have user group defined read or write authentication." | Out-String
            $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "--------------------------" | Out-String
            $FindingDetails += $IsoIncludeNotVerified
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "snmp-server group is not set for the device. This is a finding." | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }
    $FindingDetails += "" | Out-String
    $FindingDetails += "Verify snmp server users configuration with 'show snmp users' command." | Out-String
    $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
    $FindingDetails += "" | Out-String
    $Exception = $True
    if ($SnmpServerHosts) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Verify following snmp server host configurations are in accordance with snmp users." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "--------------------------" | Out-String
        $FindingDetails += $SnmpServerHosts | Out-String
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "snmp server host configuration is missing." | Out-String
        $FindingDetails += "This is a finding." | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }

    if ($OpenFinding) {
        $Status = "Open"
    }
    else {
        If (-Not($Exception) -and $FindingDetails.Trim().Length -gt 0) {
            $Status = "NotAFinding"
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails.Trim() -Algorithm SHA1
    }
    else {
        if  ($Status -ne "Not_Reviewed") {
            throw "Attempt to set Status without providing Finding Details."
        }
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status.Trim()
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails.Trim()
            ShowRun      = $ShowRunningConfig
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $SendAnswerData = $AnswerData
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status.Trim()
        FindingDetails   = $FindingDetails.Trim()
        AnswerData       = $SendAnswerData
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V216540 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216540
        STIG ID    : CISC-ND-001150
        Rule ID    : SV-216540r1156820_rule
        CCI ID     : CCI-001967
        Rule Name  : SRG-APP-000395-NDM-000347
        Rule Title : The Cisco router must be configured to authenticate Network Time Protocol (NTP) sources using authentication with FIPS-compliant algorithms.
        DiscussMD5 : B0056CA5AB21016C8ACE3BB62DB5F56B
        CheckMD5   : 9EAA3776726821E9CC78B70CA4A65A50
        FixMD5     : A086403A8EB953968F56C085F39EAC8F
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $OpenFinding = $False
    $Exception = $False
    # Get NTP details
    $Ntp = $ShowRunningConfig | Select-String -Pattern "^ntp"
    IF ($Ntp) {
        $NtpConfig = Get-Section $ShowRunningConfig $Ntp
        IF ($NtpConfig) {
            $NtpAuthenticationKey = $NtpConfig | Select-String -Pattern "authentication-key \d+ hmac-sha2 encrypted .*"
            $NtpTrustedKey = $NtpConfig | Select-String -Pattern "trusted-key"
            $NtpServers = $NtpConfig | Select-String -Pattern "server .* key .*"
        }
        ELSE {
            $NtpAuthenticationKey = $Ntp | Select-String -Pattern "authentication-key \d+ hmac-sha2 encrypted .*"
            $NtpTrustedKey = $Ntp | Select-String -Pattern "trusted-key"
            $NtpServers = $Ntp | Select-String -Pattern "server .* key .*"
        }
        IF ($NtpAuthenticationKey -and $NtpTrustedKey -and $NtpServers) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "The following Network Time Protocol has been configured on this router:" | Out-String
            $FindingDetails += "-----------------------------------------------------------------------" | Out-String
            $FindingDetails += $Ntp | Out-String
            $FindingDetails += $NtpConfig | Out-String
            $FindingDetails += "" | Out-String
        }
        ELSE {
            IF (!$NtpAuthenticationKey) {
                $FindingDetails += "" | Out-String
                $FindingDetails += "Network Time Protocol authentication-key is missing or is not properly configured." | Out-String
                $OpenFinding = $True
            }
            IF (!$NtpTrustedKey) {
                $FindingDetails += "" | Out-String
                $FindingDetails += "Network Time Protocol trusted-key is missing or is not properly configured." | Out-String
                $OpenFinding = $True
            }
            IF ((!$NtpServers)) {
                $FindingDetails += "" | Out-String
                $FindingDetails += "Network Time Protocol is missing server configurations." | Out-String
                $OpenFinding = $True
            }
            IF ($OpenFinding) {
                $FindingDetails += "" | Out-String
                $FindingDetails += "This is a finding." | Out-String
                $FindingDetails += "------------------" | Out-String
                $FindingDetails += $Ntp | Out-String
                $FindingDetails += $NtpConfig | Out-String
                $FindingDetails += "" | Out-String
            }
        }
    }
    ELSE {
        $FindingDetails += "" | Out-String
        $FindingDetails += "This router has not been configured with Network Time Protocol. This is a finding." | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }
    IF ($OpenFinding) {
        $Status = "Open"
    }
    ELSE {
        If (-Not($Exception) -and $FindingDetails.Trim().Length -gt 0) {
            $Status = "NotAFinding"
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails.Trim() -Algorithm SHA1
    }
    else {
        if  ($Status -ne "Not_Reviewed") {
            throw "Attempt to set Status without providing Finding Details."
        }
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status.Trim()
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails.Trim()
            ShowRun      = $ShowRunningConfig
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $SendAnswerData = $AnswerData
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status.Trim()
        FindingDetails   = $FindingDetails.Trim()
        AnswerData       = $SendAnswerData
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V216541 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216541
        STIG ID    : CISC-ND-001200
        Rule ID    : SV-216541r961554_rule
        CCI ID     : CCI-002890
        Rule Name  : SRG-APP-000411-NDM-000330
        Rule Title : The Cisco router must be configured to use FIPS-validated Keyed-Hash Message Authentication Code (HMAC) to protect the integrity of remote maintenance sessions.
        DiscussMD5 : C97B40F468F941854C8AB2653A5314BC
        CheckMD5   : 11B7A21B2FF39420A06618CD9CDDAB03
        FixMD5     : 25DCE1562AC52EE97119EC6CEE317FF9
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $OpenFinding = $False
    $Exception = $False

    # Get server session v2.
    $ServerSession = $ShowRunningConfig | Select-String -Pattern "^ssh server v2"

    if ($ServerSession) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "The router has been configured to use FIPS-validated HMAC to protect the integrity of remote maintenance sessions." | Out-String
        $FindingDetails += "--------------------------" | Out-String
        $FindingDetails += $ServerSession | Out-String
        $FindingDetails += "" | Out-String
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "The router has not been configured to use FIPS-validated HMAC to protect the integrity of remote maintenance sessions. This is a finding." | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }
    if ($OpenFinding) {
        $Status = "Open"
    }
    else {
        If (-Not($Exception) -and $FindingDetails.Trim().Length -gt 0) {
            $Status = "NotAFinding"
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails.Trim() -Algorithm SHA1
    }
    else {
        if  ($Status -ne "Not_Reviewed") {
            throw "Attempt to set Status without providing Finding Details."
        }
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status.Trim()
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails.Trim()
            ShowRun      = $ShowRunningConfig
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $SendAnswerData = $AnswerData
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status.Trim()
        FindingDetails   = $FindingDetails.Trim()
        AnswerData       = $SendAnswerData
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V216542 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216542
        STIG ID    : CISC-ND-001210
        Rule ID    : SV-216542r961557_rule
        CCI ID     : CCI-003123
        Rule Name  : SRG-APP-000412-NDM-000331
        Rule Title : The Cisco router must be configured to implement cryptographic mechanisms to protect the confidentiality of remote maintenance sessions.
        DiscussMD5 : 451042AAB21D5513C191D553EC3B6ADF
        CheckMD5   : 896F8C624A8064CF0F5F6166831636D8
        FixMD5     : 25DCE1562AC52EE97119EC6CEE317FF9
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $OpenFinding = $False
    $Exception = $False

    # Get server session v2.
    $ServerSession = $ShowRunningConfig | Select-String -Pattern "^ssh server v2"

    if ($ServerSession) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "The router has been configured to implement SSH version 2." | Out-String
        $FindingDetails += "--------------------------" | Out-String
        $FindingDetails += $ServerSession | Out-String
        $FindingDetails += "" | Out-String
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "The router has not been configured to implement SSH version 2. This is a finding." | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }
    if ($OpenFinding) {
        $Status = "Open"
    }
    else {
        If (-Not($Exception) -and $FindingDetails.Trim().Length -gt 0) {
            $Status = "NotAFinding"
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails.Trim() -Algorithm SHA1
    }
    else {
        if  ($Status -ne "Not_Reviewed") {
            throw "Attempt to set Status without providing Finding Details."
        }
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status.Trim()
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails.Trim()
            ShowRun      = $ShowRunningConfig
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $SendAnswerData = $AnswerData
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status.Trim()
        FindingDetails   = $FindingDetails.Trim()
        AnswerData       = $SendAnswerData
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V216543 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216543
        STIG ID    : CISC-ND-001310
        Rule ID    : SV-216543r961860_rule
        CCI ID     : CCI-001851
        Rule Name  : SRG-APP-000515-NDM-000325
        Rule Title : The Cisco router must be configured to off-load log records onto a different system than the system being audited.
        DiscussMD5 : 12FFD3C03701BE9B47C761E0CCB72458
        CheckMD5   : 42389F7816D50DEA056D74AA3AE2A4B0
        FixMD5     : 5B48EB05EFE3623A8BDB7933C9AFB27C
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $OpenFinding = $False
    $Exception = $False

    # Get server session v2.
    $SeverityLog = $ShowRunningConfig | Select-String -Pattern "^logging .* severity info"

    if ($SeverityLog) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "The router has been configured to send log records to a syslog server." | Out-String
        $FindingDetails += "--------------------------" | Out-String
        $FindingDetails += $SeverityLog | Out-String
        $FindingDetails += "" | Out-String
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "The router has not been configured to send log records to a syslog server. This is a finding." | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }
    if ($OpenFinding) {
        $Status = "Open"
    }
    else {
        If (-Not($Exception) -and $FindingDetails.Trim().Length -gt 0) {
            $Status = "NotAFinding"
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails.Trim() -Algorithm SHA1
    }
    else {
        if  ($Status -ne "Not_Reviewed") {
            throw "Attempt to set Status without providing Finding Details."
        }
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status.Trim()
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails.Trim()
            ShowRun      = $ShowRunningConfig
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $SendAnswerData = $AnswerData
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status.Trim()
        FindingDetails   = $FindingDetails.Trim()
        AnswerData       = $SendAnswerData
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V216544 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216544
        STIG ID    : CISC-ND-001370
        Rule ID    : SV-216544r1137887_rule
        CCI ID     : CCI-000370
        Rule Name  : SRG-APP-000516-NDM-000336
        Rule Title : The Cisco router must be configured to use at least two authentication servers for the purpose of authenticating users prior to granting administrative access.
        DiscussMD5 : 499C4BC76E102C66C756732859C51091
        CheckMD5   : 6123BDA7CB402FE8B81A50E6F8CA57E4
        FixMD5     : 2BDE95E59A9DBB765FB04D7ECA47CF9C
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $OpenFinding = $False
    $Exception = $False
    $NoOfHosts = 0

    # Get authentication server
    $RadiusServerHosts = $ShowRunningConfig | Select-String -Pattern "^radius-server host "
    IF ($RadiusServerHosts){
        ForEach ($RadiusServerHost in $RadiusServerHosts) {
            $NoOfHosts += 1
            $RadiusServerHostConfig = Get-Section $ShowRunningConfig $RadiusServerHost
            # Verify authentication key is set
            $RadiusServerKey = $RadiusServerHostConfig | Select-String -Pattern "^key .*"
            IF ($RadiusServerKey) {
                # Get authentication login details
                $RadiusLocalAuthentication = $ShowRunningConfig | Select-String -Pattern "^aaa authentication login .*"
                IF ($RadiusLocalAuthentication) {
                    $RadiusServerAuthenticationName = ($RadiusLocalAuthentication.ToString().Split([char[]]"") | Select-Object -Index 3)
                    # Verify authentication is set for line default and line console
                    $LineDefault = $ShowRunningConfig | Select-String -Pattern "^line default"
                    IF ($LineDefault){
                        $LineDefaultConfig = Get-Section $ShowRunningConfig $LineDefault
                        $LineDefaultAuth = $LineDefaultConfig | Select-String -Pattern "login authentication $RadiusServerAuthenticationName"
                        IF ($LineDefaultAuth) {
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "Authentication login is set for '$RadiusServerHost'." | Out-String
                            $FindingDetails += "--------------------------" | Out-String
                            $FindingDetails += $RadiusLocalAuthentication | Out-String
                            $FindingDetails += "Login authentication is set for line default." | Out-String
                            $FindingDetails += "--------------------------" | Out-String
                            $FindingDetails += $RadiusServerAuthenticationName | Out-String
                            $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
                            $FindingDetails += "" | Out-String
                            $Exception = $True
                        } ELSE {
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "Authentication login is set for '$RadiusServerHost'." | Out-String
                            $FindingDetails += "--------------------------" | Out-String
                            $FindingDetails += $RadiusLocalAuthentication | Out-String
                            $FindingDetails += "Login authentication '$RadiusServerAuthenticationName' is not set for line default. This is a finding." | Out-String
                            $FindingDetails += "" | Out-String
                            $OpenFinding = $True
                        }
                    } ELSE {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Line default is not set for device." | Out-String
                        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
                        $FindingDetails += "" | Out-String
                        $Exception = $True
                    }
                    $LineConsole = $ShowRunningConfig | Select-String -Pattern "^line console"
                    IF ($LineConsole){
                        $LineConsoleConfig = Get-Section $ShowRunningConfig $LineConsole
                        $LineConsoleAuth = $LineConsoleConfig | Select-String -Pattern "login authentication $RadiusServerAuthenticationName"
                        IF ($LineConsoleAuth) {
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "Authentication login is set for '$RadiusServerHost'." | Out-String
                            $FindingDetails += "--------------------------" | Out-String
                            $FindingDetails += $RadiusLocalAuthentication | Out-String
                            $FindingDetails += "Login authentication is set for line console." | Out-String
                            $FindingDetails += "--------------------------" | Out-String
                            $FindingDetails += $RadiusServerAuthenticationName | Out-String
                            $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
                            $FindingDetails += "" | Out-String
                            $Exception = $True
                        } ELSE {
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "Authentication login is set for '$RadiusServerHost'." | Out-String
                            $FindingDetails += "--------------------------" | Out-String
                            $FindingDetails += $RadiusLocalAuthentication | Out-String
                            $FindingDetails += "Login authentication '$RadiusServerAuthenticationName' is not set for line console. This is a finding." | Out-String
                            $FindingDetails += "" | Out-String
                            $OpenFinding = $True
                        }
                    } ELSE {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Line console is not set for device." | Out-String
                        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
                        $FindingDetails += "" | Out-String
                        $Exception = $True
                    }
                } ELSE {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Authentication login is not set for '$RadiusServerHost'." | Out-String
                    $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
                    $FindingDetails += "" | Out-String
                    $Exception = $True
                }
            } ELSE {
                $FindingDetails += "" | Out-String
                $FindingDetails += "Key is not configured for radius server '$RadiusServerHost'. This is a finding." | Out-String
                $FindingDetails += "" | Out-String
                $OpenFinding = $True
            }
        }
        IF($NoOfHosts -le 1) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "The device should be configured to use at least two authentication servers as primary source for authentication, only one has been configured. This is a finding." | Out-String
            $FindingDetails += "--------------------------" | Out-String
            $FindingDetails += $RadiusServerHosts | Out-String
            $FindingDetails += "" | Out-String
            $OpenFinding = $True
        } ELSE {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Following are the authentication servers, primary source for authentication." | Out-String
            $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "--------------------------" | Out-String
            $FindingDetails += $RadiusServerHosts | Out-String
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
    } ELSE {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Authentication server is not configured for the device. This is a finding." | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }
    IF ($OpenFinding) {
        $Status = "Open"
    }
    ELSE {
        If (-Not($Exception) -and $FindingDetails.Trim().Length -gt 0) {
            $Status = "NotAFinding"
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails.Trim() -Algorithm SHA1
    }
    else {
        if  ($Status -ne "Not_Reviewed") {
            throw "Attempt to set Status without providing Finding Details."
        }
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status.Trim()
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails.Trim()
            ShowRun      = $ShowRunningConfig
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $SendAnswerData = $AnswerData
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status.Trim()
        FindingDetails   = $FindingDetails.Trim()
        AnswerData       = $SendAnswerData
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V216545 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216545
        STIG ID    : CISC-ND-001410
        Rule ID    : SV-216545r1069525_rule
        CCI ID     : CCI-000366, CCI-000537
        Rule Name  : SRG-APP-000516-NDM-000340
        Rule Title : The Cisco router must be configured to back up the configuration when changes occur.
        DiscussMD5 : 6D8F1725F65C6027E6A4DB4EE39E1B5D
        CheckMD5   : A52C117BA7B65989C1BEBC2867F2B61F
        FixMD5     : 04E45D7B22B1758C9B8EB8E9903A5A09
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $OpenFinding = $False
    $Exception = $False

    # Get server session limit.
    $BackupServer = $ShowRunningConfig | Select-String -Pattern "^configuration commit auto-save filename"

    if ($BackupServer) {
        if ($BackupServer | Select-String -Pattern " scp") {
            $FindingDetails += "" | Out-String
            $FindingDetails += "The router has been configured to conduct backups of the configuration when changes occur." | Out-String
            $FindingDetails += "--------------------------" | Out-String
            $FindingDetails += $BackupServer | Out-String
            $FindingDetails += "" | Out-String
        }
        else {
            $FindingDetails += "" | Out-String
            $FindingDetails += "The router has not been configured properly to conduct backups of the configuration as per STIG check guidance. This is a finding." | Out-String
            $FindingDetails += "" | Out-String
            $OpenFinding = $True
        }
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Centralized backup has been implemented. Please review and make determination based on STIG check guidance." | Out-String
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    if ($OpenFinding) {
        $Status = "Open"
    }
    else {
        If (-Not($Exception) -and $FindingDetails.Trim().Length -gt 0) {
            $Status = "NotAFinding"
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails.Trim() -Algorithm SHA1
    }
    else {
        if  ($Status -ne "Not_Reviewed") {
            throw "Attempt to set Status without providing Finding Details."
        }
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status.Trim()
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails.Trim()
            ShowRun      = $ShowRunningConfig
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $SendAnswerData = $AnswerData
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status.Trim()
        FindingDetails   = $FindingDetails.Trim()
        AnswerData       = $SendAnswerData
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V216546 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216546
        STIG ID    : CISC-ND-001440
        Rule ID    : SV-216546r961863_rule
        CCI ID     : CCI-000366, CCI-001159
        Rule Name  : SRG-APP-000516-NDM-000344
        Rule Title : The Cisco router must be configured to obtain its public key certificates from an appropriate certificate policy through an approved service provider.
        DiscussMD5 : 04007CC7FF3BCC803D7E52B0C1A37BE1
        CheckMD5   : A5F532227CB9384C418A7E1F4697721C
        FixMD5     : B35A92464F405C1EA45CE0A2A1C33D04
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $OpenFinding = $False
    $Exception = $False

    # Get server session limit.
    $CATrustPoint = ($ShowRunningConfig | Select-String -Pattern "^crypto ca trustpoint" -Context 0, 2) -replace '>', ''

    if ($CATrustPoint) {
        $EnrollmentUrl = $CATrustPoint | Select-String -Pattern "enrollment url"
        if ($EnrollmentUrl) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "The router has been configured to obtain its public key certificates from an appropriate certificate policy through an approved service provider." | Out-String
            $FindingDetails += "--------------------------" | Out-String
            $FindingDetails += $CATrustPoint | Out-String
            $FindingDetails += "" | Out-String
        }
        else {
            $FindingDetails += "" | Out-String
            $FindingDetails += "CATrustPoint has been configured for the router but not enrollment url." | Out-String
            $FindingDetails += "This is a finding." | Out-String
            $FindingDetails += "--------------------------" | Out-String
            $FindingDetails += $CATrustPoint | Out-String
            $FindingDetails += "" | Out-String
            $OpenFinding = $True
        }
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "The router has not been configured to obtain its public key certificates from an " | Out-String
        $FindingDetails += "appropriate certificate policy through an approved service provider. This is a finding." | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }
    if ($OpenFinding) {
        $Status = "Open"
    }
    else {
        If (-Not($Exception) -and $FindingDetails.Trim().Length -gt 0) {
            $Status = "NotAFinding"
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails.Trim() -Algorithm SHA1
    }
    else {
        if  ($Status -ne "Not_Reviewed") {
            throw "Attempt to set Status without providing Finding Details."
        }
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status.Trim()
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails.Trim()
            ShowRun      = $ShowRunningConfig
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $SendAnswerData = $AnswerData
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status.Trim()
        FindingDetails   = $FindingDetails.Trim()
        AnswerData       = $SendAnswerData
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V216547 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216547
        STIG ID    : CISC-ND-001450
        Rule ID    : SV-216547r961863_rule
        CCI ID     : CCI-001851
        Rule Name  : SRG-APP-000516-NDM-000317
        Rule Title : The Cisco router must be configured to send log data to at least two syslog servers for the purpose of forwarding alerts to the administrators and the information system security officer (ISSO).
        DiscussMD5 : 2B60B499490110C0A7C4C1920395BB82
        CheckMD5   : FEE6521495C2FF58ED360DDB7D4A8EEB
        FixMD5     : 2E4E09F104B469787C933023A1F5BF6D
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $OpenFinding = $False
    $Exception = $False

    # Get server session v2.
    $SeverityLogs = $ShowRunningConfig | Select-String -Pattern "^logging .* severity info"
    if ($SeverityLogs) {
        if ($SeverityLogs.Count -ge 2) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "The router has been configured to send log records to more than one syslog servers." | Out-String
            $FindingDetails += "--------------------------" | Out-String
            $FindingDetails += $SeverityLogs | Out-String
            $FindingDetails += "" | Out-String
        }
        else {
            $FindingDetails += "" | Out-String
            $FindingDetails += "The router has been configured to send log records to one syslog server. It should be configured to send logs to at least two syslog servers." | Out-String
            $FindingDetails += "This is finding." | Out-String
            $FindingDetails += "--------------------------" | Out-String
            $FindingDetails += $SeverityLogs | Out-String
            $FindingDetails += "" | Out-String
            $OpenFinding = $True
        }
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "The router has not been configured to send log records to one syslog server. It should be configured to send syslogs to at least two syslog servers." | Out-String
        $FindingDetails += "This is a finding." | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }
    if ($OpenFinding) {
        $Status = "Open"
    }
    else {
        If (-Not($Exception) -and $FindingDetails.Trim().Length -gt 0) {
            $Status = "NotAFinding"
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails.Trim() -Algorithm SHA1
    }
    else {
        if  ($Status -ne "Not_Reviewed") {
            throw "Attempt to set Status without providing Finding Details."
        }
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status.Trim()
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails.Trim()
            ShowRun      = $ShowRunningConfig
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $SendAnswerData = $AnswerData
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status.Trim()
        FindingDetails   = $FindingDetails.Trim()
        AnswerData       = $SendAnswerData
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

Function Get-V216549 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216549
        STIG ID    : CISC-ND-001470
        Rule ID    : SV-216549r961863_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-NDM-000317
        Rule Title : The Cisco router must be running an IOS release that is currently supported by Cisco Systems.
        DiscussMD5 : 48C9EDC8AEA8EE82D3771483542AB7DB
        CheckMD5   : 9F47D0473276BCBD682E9F3C56B5322C
        FixMD5     : 6B4D73D26C5614740F02021AADF6ED58
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$SiteName
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $FuncDescription = ($MyInvocation.MyCommand.ScriptBlock -split "#>")[0].split("`r`n")
    $VulnID = ($FuncDescription | Select-String -Pattern "V-\d{4,6}$").Matches[0].Value
    $RuleID = ($FuncDescription | Select-String -Pattern "SV-\d{4,6}r\d{1,}_rule$").Matches[0].Value
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ShowVersion = $(Get-CiscoShowTechData -ShowTech $ShowTech -DataType XR-Version)
    $OpenFinding = $False
    $Exception = $False
    $ShowVersionPretty = @()

    # Get server version.
    if ($ShowVersion) {
        foreach ($Line in $ShowVersion) {
            if ($Line -eq "") {
                $ShowVersionPretty += "`n"
            }
            else {
                $ShowVersionPretty += "$Line`n"
            }
        }
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following is the details of router version. Verify that the release is still supported by Cisco." | Out-String
        $FindingDetails += " All releases supported by Cisco can be found on the following URL:" | Out-String
        $FindingDetails += "www.cisco.com/c/en/us/support/ios-nx-os-software" | Out-String
        $FindingDetails += "--------------------------" | Out-String
        $FindingDetails += $ShowVersionPretty
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Show version missing in Showtech file. This is a finding." | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }
    if ($OpenFinding) {
        $Status = "Open"
    }
    else {
        If (-Not($Exception) -and $FindingDetails.Trim().Length -gt 0) {
            $Status = "NotAFinding"
        }
    }
    #---=== End Custom Code ===---#

    if ($FindingDetails.Trim().Length -gt 0) {
        $ResultHash = Get-TextHash -Text $FindingDetails.Trim() -Algorithm SHA1
    }
    else {
        if  ($Status -ne "Not_Reviewed") {
            throw "Attempt to set Status without providing Finding Details."
        }
        $ResultHash = ""
    }

    if ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            RuleID       = $RuleID
            AnswerKey    = $PSBoundParameters.AnswerKey
            Status       = $Status.Trim()
            Hostname     = $Hostname
            Username     = $Username
            UserSID      = $UserSID
            Instance     = $Instance
            Database     = $Database
            Site         = $Site
            ResultHash   = $ResultHash
            ResultData   = $FindingDetails.Trim()
            ShowRun      = $ShowRunningConfig
            ESPath       = $ESPath
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }

        $AnswerData = (Get-CorporateComment @GetCorpParams)
        if ($Status -eq $AnswerData.ExpectedStatus) {
            $SendAnswerData = $AnswerData
        }
    }

    $SendCheckParams = @{
        Module           = $ModuleName
        Status           = $Status.Trim()
        FindingDetails   = $FindingDetails.Trim()
        AnswerData       = $SendAnswerData
        SeverityOverride = $SeverityOverride
        Justification    = $Justification
        HeadInstance     = $Instance
        HeadDatabase     = $Database
        HeadSite         = $Site
        HeadHash         = $ResultHash
    }
    if ($AF_UserHeader) {
        $SendCheckParams.Add("HeadUsername", $Username)
        $SendCheckParams.Add("HeadUserSID", $UserSID)
    }

    return Send-CheckResult @SendCheckParams
}

# SIG # Begin signature block
# MIIkCwYJKoZIhvcNAQcCoIIj/DCCI/gCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBYrClRFlGrpJg8
# A4sObVoj3dnt6rL0JAijM5qWqROHjaCCHiQwggUqMIIEEqADAgECAgMTYdUwDQYJ
# KoZIhvcNAQELBQAwWjELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1UuUy4gR292ZXJu
# bWVudDEMMAoGA1UECxMDRG9EMQwwCgYDVQQLEwNQS0kxFTATBgNVBAMTDERPRCBJ
# RCBDQS03MjAeFw0yNTAzMjUwMDAwMDBaFw0yODAzMjMyMzU5NTlaMIGOMQswCQYD
# VQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0Qx
# DDAKBgNVBAsTA1BLSTEMMAoGA1UECxMDVVNOMTswOQYDVQQDEzJDUy5OQVZBTCBT
# VVJGQUNFIFdBUkZBUkUgQ0VOVEVSIENSQU5FIERJVklTSU9OLjAwMTCCASIwDQYJ
# KoZIhvcNAQEBBQADggEPADCCAQoCggEBALl8XR1aeL1ARA9c9RE46+zVmtnbYcsc
# D6WG/eVPobPKhzYePfW3HZS2FxQQ0yHXRPH6AS/+tjCqpGtpr+MA5J+r5X9XkqYb
# 1+nwfMlXHCQZDLAsmRN4bNDLAtADzEOp9YojDTTIE61H58sRSw6f4uJwmicVkYXq
# Z0xrPO2xC1/B0D7hzBVKmxeVEcWF81rB3Qf9rKOwiWz9icMZ1FkYZAynaScN5UIv
# V+PuLgH0m9ilY54JY4PWEnNByxM/2A34IV5xG3Avk5WiGFMGm1lKCx0BwsKn0PfX
# Kd0RIcu/fkOEcCz7Lm7NfsQQqtaTKRuBAE5mLiD9cmmbt2WcnfAQvPcCAwEAAaOC
# AcIwggG+MB8GA1UdIwQYMBaAFIP0XzXrzNpde5lPwlNEGEBave9ZMDcGA1UdHwQw
# MC4wLKAqoCiGJmh0dHA6Ly9jcmwuZGlzYS5taWwvY3JsL0RPRElEQ0FfNzIuY3Js
# MA4GA1UdDwEB/wQEAwIGwDAWBgNVHSAEDzANMAsGCWCGSAFlAgELKjAdBgNVHQ4E
# FgQUmWLtMKC6vsuXOz9nYQtTtn1sApcwZQYIKwYBBQUHAQEEWTBXMDMGCCsGAQUF
# BzAChidodHRwOi8vY3JsLmRpc2EubWlsL3NpZ24vRE9ESURDQV83Mi5jZXIwIAYI
# KwYBBQUHMAGGFGh0dHA6Ly9vY3NwLmRpc2EubWlsMIGSBgNVHREEgYowgYekgYQw
# gYExCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNV
# BAsTA0RvRDEMMAoGA1UECxMDUEtJMQwwCgYDVQQLEwNVU04xLjAsBgNVBAMTJUlS
# RUxBTkQuREFOSUVMLkNIUklTVE9QSEVSLjEzODcxNTAzMzgwHwYDVR0lBBgwFgYK
# KwYBBAGCNwoDDQYIKwYBBQUHAwMwDQYJKoZIhvcNAQELBQADggEBAI7+Xt5NkiSp
# YYEaISRpmsKDnEpuoKzvHjEKl41gmTMLnj7mVTLQFm0IULnaLu8FHelUkI+RmFFW
# gHwaGTujbe0H9S6ySzKQGGSt7jrZijYGAWCG/BtRUVgOSLlWZsLxiVCU07femEGT
# 2JQTEhx5/6ADAE/ZT6FZieiDYa7CZ14+1yKZ07x+t5k+hKAHEqdI6+gkInxqwunZ
# 8VFUoPyTJDsiifDXj5LG7+vUr6YNWZfVh2QJJeQ3kmheKLXRIqNAX2Ova3gFUzme
# 05Wp9gAT4vM7Zk86cHAqVFtwOnK/IGRKBWyEW1btJGWM4yk98TxGKh5JSPN4EAln
# 3i2bAfl2BLAwggWNMIIEdaADAgECAhAOmxiO+dAt5+/bUOIIQBhaMA0GCSqGSIb3
# DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAX
# BgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0IEFzc3Vy
# ZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBaFw0zMTExMDkyMzU5NTlaMGIx
# CzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3
# dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBH
# NDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAL/mkHNo3rvkXUo8MCIw
# aTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3EMB/zG6Q4FutWxpdtHauyefLK
# EdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKyunWZanMylNEQRBAu34LzB4Tm
# dDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsFxl7sWxq868nPzaw0QF+xembu
# d8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU15zHL2pNe3I6PgNq2kZhAkHnD
# eMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJBMtfbBHMqbpEBfCFM1LyuGwN1
# XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObURWBf3JFxGj2T3wWmIdph2PVld
# QnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6nj3cAORFJYm2mkQZK37AlLTS
# YW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxBYKqxYxhElRp2Yn72gLD76GSm
# M9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5SUUd0viastkF13nqsX40/ybzT
# QRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+xq4aLT8LWRV+dIPyhHsXAj6Kx
# fgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIBNjAPBgNVHRMBAf8EBTADAQH/
# MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwPTzAfBgNVHSMEGDAWgBRF66Kv
# 9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMCAYYweQYIKwYBBQUHAQEEbTBr
# MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQwYIKwYBBQUH
# MAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJ
# RFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNl
# cnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDARBgNVHSAECjAIMAYG
# BFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0NcVec4X6CjdBs9thbX979XB72a
# rKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnovLbc47/T/gLn4offyct4kvFID
# yE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65ZyoUi0mcudT6cGAxN3J0TU53/o
# Wajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFWjuyk1T3osdz9HNj0d1pcVIxv
# 76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPFmCLBsln1VWvPJ6tsds5vIy30
# fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9ztwGpn1eqXijiuZQwggW4MIID
# oKADAgECAgFIMA0GCSqGSIb3DQEBDAUAMFsxCzAJBgNVBAYTAlVTMRgwFgYDVQQK
# Ew9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsTA0RvRDEMMAoGA1UECxMDUEtJMRYw
# FAYDVQQDEw1Eb0QgUm9vdCBDQSA2MB4XDTIzMDUxNjE2MDIyNloXDTI5MDUxNTE2
# MDIyNlowWjELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDEM
# MAoGA1UECxMDRG9EMQwwCgYDVQQLEwNQS0kxFTATBgNVBAMTDERPRCBJRCBDQS03
# MjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALi+DvkbsJrZ8W6Dbflh
# Bv6ONtCSv5QQ+HAE/TlN3/9qITfxmlSWc9S702/NjzgTxJv36Jj5xD0+shC9k+5X
# IQNEZHeCU0C6STdJJwoJt2ulrK5bY919JGa3B+/ctujJ6ZAFMROBwo0b18uzeykH
# +bRhuvNGrpYMJljoMRsqcdWbls+I78qz3YZQQuq5f3LziE03wD5eFRsmXt9PrCaR
# FiftqjezlmoiMOdGbr/DFaLDHkrf/fvtQmreIPKQuQFwmw190LvhdUa4yjshnTV9
# nv1Wo22Yc8US2N3vEOwr5oQPLt/bQyhPHvPt6WNJMqjr7grwSrScJNb2Yr7Fz3I/
# 1fECAwEAAaOCAYYwggGCMB8GA1UdIwQYMBaAFBNPPLvbXUUppZRwttqsnkziL8EL
# MB0GA1UdDgQWBBSD9F8168zaXXuZT8JTRBhAWr3vWTAOBgNVHQ8BAf8EBAMCAYYw
# ZwYDVR0gBGAwXjALBglghkgBZQIBCyQwCwYJYIZIAWUCAQsnMAsGCWCGSAFlAgEL
# KjALBglghkgBZQIBCzswDAYKYIZIAWUDAgEDDTAMBgpghkgBZQMCAQMRMAwGCmCG
# SAFlAwIBAycwEgYDVR0TAQH/BAgwBgEB/wIBADAMBgNVHSQEBTADgAEAMDcGA1Ud
# HwQwMC4wLKAqoCiGJmh0dHA6Ly9jcmwuZGlzYS5taWwvY3JsL0RPRFJPT1RDQTYu
# Y3JsMGwGCCsGAQUFBwEBBGAwXjA6BggrBgEFBQcwAoYuaHR0cDovL2NybC5kaXNh
# Lm1pbC9pc3N1ZWR0by9ET0RST09UQ0E2X0lULnA3YzAgBggrBgEFBQcwAYYUaHR0
# cDovL29jc3AuZGlzYS5taWwwDQYJKoZIhvcNAQEMBQADggIBALAs2CLSvmi9+W/r
# cF0rh09yoqQphPSu6lKv5uyc/3pz3mFL+lFUeIdAVihDbP4XKB+wr+Yz34LeeL82
# 79u3MBAEk4xrJOH29uiRBJFTtMdt8GvOecd2pZSGFbDMTt10Bh9N+IvGYclwMkvt
# 26Q+VlZysQr3fQQ8QdO6z4e9jTFR92QmoW4eLyx8CmgZT2CESRl60Ey0A6Gf87Hh
# ntetRp9k0VkFOk7hWfCSUFBhTrmuJBgNB9HP7e5DuPwKUZLICziVxVrZydoyUmyX
# Aki9q6VrUAsm/1/i/YeUInqtXJZ2vs3foMsNa/tVSQ1BG1Wn/1ZfVzWLd+sAA/nk
# CnbsMc61UG8Yec0jC4WMCsmsQKLEfPrt9/U+tEuX9mqeD3dtpR+vq18av8FNd1mY
# zRgFdNc2+P09daj70PslCCb64XAJh1RY4zHPsOA9o+OXdHAX0kpTackvueXyuLb6
# BM0FCaTpq83Y2oH55kM/pPN3brNHUcIkBzqTj48X3WgQbrrwvGTWh4PSGoitnvsB
# nxsBfAFbqugOUEnnIk0an2Vdl3zGXBooAiODnd/n87Ht7psLp7koapfXTGJBClZU
# mSFpdwtI15hvdw9KThK41bC0cLu8lZ4TEFAxSJyuGjxkhBKXeq7LrRSjO8T+bHte
# u6ud36J9k9xg5brIqTW2ripCBEEtMIIGtDCCBJygAwIBAgIQDcesVwX/IZkuQEMi
# DDpJhjANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGln
# aUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhE
# aWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwHhcNMjUwNTA3MDAwMDAwWhcNMzgwMTE0
# MjM1OTU5WjBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4x
# QTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQw
# OTYgU0hBMjU2IDIwMjUgQ0ExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKC
# AgEAtHgx0wqYQXK+PEbAHKx126NGaHS0URedTa2NDZS1mZaDLFTtQ2oRjzUXMmxC
# qvkbsDpz4aH+qbxeLho8I6jY3xL1IusLopuW2qftJYJaDNs1+JH7Z+QdSKWM06qc
# hUP+AbdJgMQB3h2DZ0Mal5kYp77jYMVQXSZH++0trj6Ao+xh/AS7sQRuQL37QXbD
# hAktVJMQbzIBHYJBYgzWIjk8eDrYhXDEpKk7RdoX0M980EpLtlrNyHw0Xm+nt5pn
# YJU3Gmq6bNMI1I7Gb5IBZK4ivbVCiZv7PNBYqHEpNVWC2ZQ8BbfnFRQVESYOszFI
# 2Wv82wnJRfN20VRS3hpLgIR4hjzL0hpoYGk81coWJ+KdPvMvaB0WkE/2qHxJ0ucS
# 638ZxqU14lDnki7CcoKCz6eum5A19WZQHkqUJfdkDjHkccpL6uoG8pbF0LJAQQZx
# st7VvwDDjAmSFTUms+wV/FbWBqi7fTJnjq3hj0XbQcd8hjj/q8d6ylgxCZSKi17y
# Vp2NL+cnT6Toy+rN+nM8M7LnLqCrO2JP3oW//1sfuZDKiDEb1AQ8es9Xr/u6bDTn
# YCTKIsDq1BtmXUqEG1NqzJKS4kOmxkYp2WyODi7vQTCBZtVFJfVZ3j7OgWmnhFr4
# yUozZtqgPrHRVHhGNKlYzyjlroPxul+bgIspzOwbtmsgY1MCAwEAAaOCAV0wggFZ
# MBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFO9vU0rp5AZ8esrikFb2L9RJ
# 7MtOMB8GA1UdIwQYMBaAFOzX44LScV1kTN8uZz/nupiuHA9PMA4GA1UdDwEB/wQE
# AwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDB3BggrBgEFBQcBAQRrMGkwJAYIKwYB
# BQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0
# cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5j
# cnQwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0Rp
# Z2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJ
# YIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQAXzvsWgBz+Bz0RdnEwvb4LyLU0
# pn/N0IfFiBowf0/Dm1wGc/Do7oVMY2mhXZXjDNJQa8j00DNqhCT3t+s8G0iP5kvN
# 2n7Jd2E4/iEIUBO41P5F448rSYJ59Ib61eoalhnd6ywFLerycvZTAz40y8S4F3/a
# +Z1jEMK/DMm/axFSgoR8n6c3nuZB9BfBwAQYK9FHaoq2e26MHvVY9gCDA/JYsq7p
# GdogP8HRtrYfctSLANEBfHU16r3J05qX3kId+ZOczgj5kjatVB+NdADVZKON/gnZ
# ruMvNYY2o1f4MXRJDMdTSlOLh0HCn2cQLwQCqjFbqrXuvTPSegOOzr4EWj7PtspI
# HBldNE2K9i697cvaiIo2p61Ed2p8xMJb82Yosn0z4y25xUbI7GIN/TpVfHIqQ6Ku
# /qjTY6hc3hsXMrS+U0yy+GWqAXam4ToWd2UQ1KYT70kZjE4YtL8Pbzg0c1ugMZyZ
# Zd/BdHLiRu7hAWE6bTEm4XYRkA6Tl4KSFLFk43esaUeqGkH/wyW4N7OigizwJWeu
# kcyIPbAvjSabnf7+Pu0VrFgoiovRDiyx3zEdmcif/sYQsfch28bZeUz2rtY/9TCA
# 6TD8dC3JE3rYkrhLULy7Dc90G6e8BlqmyIjlgp2+VqsS9/wQD7yFylIz0scmbKvF
# oW2jNrbM1pD2T7m3XDCCBu0wggTVoAMCAQICEAqA7xhLjfEFgtHEdqeVdGgwDQYJ
# KoZIhvcNAQELBQAwaTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJ
# bmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBS
# U0E0MDk2IFNIQTI1NiAyMDI1IENBMTAeFw0yNTA2MDQwMDAwMDBaFw0zNjA5MDMy
# MzU5NTlaMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7
# MDkGA1UEAxMyRGlnaUNlcnQgU0hBMjU2IFJTQTQwOTYgVGltZXN0YW1wIFJlc3Bv
# bmRlciAyMDI1IDEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDQRqwt
# Esae0OquYFazK1e6b1H/hnAKAd/KN8wZQjBjMqiZ3xTWcfsLwOvRxUwXcGx8AUjn
# i6bz52fGTfr6PHRNv6T7zsf1Y/E3IU8kgNkeECqVQ+3bzWYesFtkepErvUSbf+EI
# YLkrLKd6qJnuzK8Vcn0DvbDMemQFoxQ2Dsw4vEjoT1FpS54dNApZfKY61HAldytx
# NM89PZXUP/5wWWURK+IfxiOg8W9lKMqzdIo7VA1R0V3Zp3DjjANwqAf4lEkTlCDQ
# 0/fKJLKLkzGBTpx6EYevvOi7XOc4zyh1uSqgr6UnbksIcFJqLbkIXIPbcNmA98Os
# kkkrvt6lPAw/p4oDSRZreiwB7x9ykrjS6GS3NR39iTTFS+ENTqW8m6THuOmHHjQN
# C3zbJ6nJ6SXiLSvw4Smz8U07hqF+8CTXaETkVWz0dVVZw7knh1WZXOLHgDvundrA
# tuvz0D3T+dYaNcwafsVCGZKUhQPL1naFKBy1p6llN3QgshRta6Eq4B40h5avMcpi
# 54wm0i2ePZD5pPIssoszQyF4//3DoK2O65Uck5Wggn8O2klETsJ7u8xEehGifgJY
# i+6I03UuT1j7FnrqVrOzaQoVJOeeStPeldYRNMmSF3voIgMFtNGh86w3ISHNm0Ia
# adCKCkUe2LnwJKa8TIlwCUNVwppwn4D3/Pt5pwIDAQABo4IBlTCCAZEwDAYDVR0T
# AQH/BAIwADAdBgNVHQ4EFgQU5Dv88jHt/f3X85FxYxlQQ89hjOgwHwYDVR0jBBgw
# FoAU729TSunkBnx6yuKQVvYv1Ensy04wDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB
# /wQMMAoGCCsGAQUFBwMIMIGVBggrBgEFBQcBAQSBiDCBhTAkBggrBgEFBQcwAYYY
# aHR0cDovL29jc3AuZGlnaWNlcnQuY29tMF0GCCsGAQUFBzAChlFodHRwOi8vY2Fj
# ZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdS
# U0E0MDk2U0hBMjU2MjAyNUNBMS5jcnQwXwYDVR0fBFgwVjBUoFKgUIZOaHR0cDov
# L2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0VGltZVN0YW1waW5n
# UlNBNDA5NlNIQTI1NjIwMjVDQTEuY3JsMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsG
# CWCGSAGG/WwHATANBgkqhkiG9w0BAQsFAAOCAgEAZSqt8RwnBLmuYEHs0QhEnmNA
# ciH45PYiT9s1i6UKtW+FERp8FgXRGQ/YAavXzWjZhY+hIfP2JkQ38U+wtJPBVBaj
# YfrbIYG+Dui4I4PCvHpQuPqFgqp1PzC/ZRX4pvP/ciZmUnthfAEP1HShTrY+2DE5
# qjzvZs7JIIgt0GCFD9ktx0LxxtRQ7vllKluHWiKk6FxRPyUPxAAYH2Vy1lNM4kze
# kd8oEARzFAWgeW3az2xejEWLNN4eKGxDJ8WDl/FQUSntbjZ80FU3i54tpx5F/0Kr
# 15zW/mJAxZMVBrTE2oi0fcI8VMbtoRAmaaslNXdCG1+lqvP4FbrQ6IwSBXkZagHL
# hFU9HCrG/syTRLLhAezu/3Lr00GrJzPQFnCEH1Y58678IgmfORBPC1JKkYaEt2Od
# Dh4GmO0/5cHelAK2/gTlQJINqDr6JfwyYHXSd+V08X1JUPvB4ILfJdmL+66Gp3CS
# BXG6IwXMZUXBhtCyIaehr0XkBoDIGMUG1dUtwq1qmcwbdUfcSYCn+OwncVUXf53V
# JUNOaMWMts0VlRYxe5nK+At+DI96HAlXHAL5SlfYxJ7La54i71McVWRP66bW+yER
# NpbJCjyCYG2j+bdpxo/1Cy4uPcU3AWVPGrbn5PhDBf3Froguzzhk++ami+r3Qrx5
# bIbY3TVzgiFI7Gq3zWcxggU9MIIFOQIBATBhMFoxCzAJBgNVBAYTAlVTMRgwFgYD
# VQQKEw9VLlMuIEdvdmVybm1lbnQxDDAKBgNVBAsTA0RvRDEMMAoGA1UECxMDUEtJ
# MRUwEwYDVQQDEwxET0QgSUQgQ0EtNzICAxNh1TANBglghkgBZQMEAgEFAKCBhDAY
# BgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3
# AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEi
# BCByvD985Rf094KME8+Ks+PG7ZHvRW42fkIFOOFw+aKi0TANBgkqhkiG9w0BAQEF
# AASCAQCuMNzzK0NRBlOwNTFG5xIK2CIQEn6LvI+SfZ/bEjYqE5TkkX6cXHnm8ibP
# GV9L46UejegLnC0c8dAyUtnEzrMJMdVPVUCJQsGXB1Z938/u7HSLWtuw01F94y3A
# WSCDbzFwehxmEK3RWYiVYcy2agzqcdOHrqOJiCOiPWBnadjD25U2Cy6xmrsp8uiv
# wG+byYeqCkVExuY75obFEewwz5JQ2l42N6I6XS6cWLDnmTi/hncv6+k36p6bKSgS
# s/W1d+Bm1hrPmKh/1+xSQHceUPErsYCRNNv9j5nLHRMuX14B1cMix7KZ2gKT2PV3
# DGZKoHLd/61Mqvjna06kpZokTgQCoYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMP
# AgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEw
# PwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2
# IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0aDANBglghkgBZQMEAgEF
# AKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI2
# MDQyMjE2MTcxNlowLwYJKoZIhvcNAQkEMSIEIEhbpmioQ37hmAmM44C0ObuWpiSZ
# 9stp+lSbPO28K3fzMA0GCSqGSIb3DQEBAQUABIICAK+TGDXZkgSPFGwJcX4Gi9S3
# uHvCX3EmnX64lYXGsjFJEG6v3LU3iNioLjJbUHDrNMdlNQOQwuL4QEOD/kUJU70l
# dpQA5F8GrWdW9JQP3b/jswWF5hcy3ZxDu+uDK3ysgt+/FlrLw+BRBUV+IVkRJkON
# +Fcks0IBoxpoXaRWv0iZa/9yR/DY6ZJxJe2unN6EdxqkXFDjY0b1Wpg3x4/QNYvV
# zXBaQwTxWIln3iR7ZuM1zSGsUGtFX7wQutEfw6AeJazX3YfA78euiU2iD5E2YVTv
# nWJqvdQ7pXeF4PVl8ER5cI5F61hxWaHAIu/hkwKEQNDtWoRk6V9RxdEA1BQ5bRhi
# 89acGi4xwYIocc6Oiym6jtvXrUljsbHTNpCy+Hx9kybnrV7DOtbIuwTHdXWAgwhp
# kJiL5P/hboJiheKFLzU5UDnm9vi+bNoGPKctdrQnMJ2xxWAzSlpGI1fb4MK2UPh+
# bR2ChdY+32QFPneUqlWfl5IxwKhMMWkOURJ1Z3zWftLS4wCiMfiha1OB8QtLWd6O
# 0y2Rf8EiZajAyZ0ewWJlGdQIA5Tn6NewgTOJDI5bVmHdE6/PJcBmTBzrKJkw5SiI
# I+fJxI5w5/3Ac3VB9kTtX8JPsvtmAVw+GoE3NJJpo99hJSb/ioDn/z974gRpt1oD
# wL1c3XhtyNO1fDTQUTKx
# SIG # End signature block
