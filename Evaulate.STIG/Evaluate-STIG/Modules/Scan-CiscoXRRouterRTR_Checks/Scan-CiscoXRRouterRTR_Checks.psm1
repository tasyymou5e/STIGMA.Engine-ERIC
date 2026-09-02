##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Cisco IOS XR Router RTR
# Version:  V3R3
# Class:    UNCLASSIFIED
# Updated:  3/31/2026
# Author:   Naval Sea Systems Command (NAVSEA)
##########################################################################
$ErrorActionPreference = "Stop"

Function Get-V216735 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216735
        STIG ID    : CISC-RT-000010
        Rule ID    : SV-216735r1117236_rule
        CCI ID     : CCI-001368
        Rule Name  : SRG-NET-000018-RTR-000001
        Rule Title : The Cisco router must be configured to enforce approved authorizations for controlling the flow of information within the network based on organization-defined information flow control policies.
        DiscussMD5 : 2F00D27AF1DDECB8F99F4CAFFF230C18
        CheckMD5   : 2145B8AC85E99CCA27C254599743410F
        FixMD5     : 04A5D292DDCFFCB92274D92AB41BD4D3
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
    #Interfaces with inbound ACLs
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
    $Ipv4InterfaceList = @()
    foreach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        $IngressACLs = ($InterfaceConfig | Select-String -Pattern "ipv4 access-group .* ingress")
        if ($IngressACLs) {
            foreach ($IngressACL in $IngressACLs) {
                $ACLName = $IngressACL.ToString().Split([char[]]"") | Select-Object -Index 2
                $ACLExtended = $ShowRunningConfig | Select-String -Pattern "^ipv4 access-list $ACLName"
                if ($ACLExtended) {
                    $Ipv4InterfaceList += "$Interface" + "`n " + "$IngressACL" + "`n`n"
                }
                else {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Ingress ACL '$ACLName' associated to '$Interface' is not configured in the device. This is a finding" | Out-String
                    $FindingDetails += "" | Out-String
                    $OpenFinding = $True
                }
            }
        }
    }
    if ($Ipv4InterfaceList.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following interface and associated IPv4 ingress ACLs are configured in device." | Out-String
        $FindingDetails += "Verify that ACLs are configured to allow or deny traffic for specific source and destination addresses as well as ports and protocols." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $Ipv4InterfaceList
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

Function Get-V216739 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216739
        STIG ID    : CISC-RT-000050
        Rule ID    : SV-216739r1007834_rule
        CCI ID     : CCI-000803, CCI-002205
        Rule Name  : SRG-NET-000168-RTR-000078
        Rule Title : The Cisco router must be configured to enable routing protocol authentication using FIPS 198-1 algorithms with keys not exceeding 180 days of lifetime.
        DiscussMD5 : 87FE0A00E795631BFE3EE27302A89E07
        CheckMD5   : 9AA46BB026440366903677DF586E9F4A
        FixMD5     : 42B9473BA199BF9CBA7ECD6A3B6F29BB
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
    $BgpKeyChains = @()
    $OspfKeyChains = @()
    $TcpBgpKeys = @()
    $TcpBgpKeyCheck = @()
    $BgpAoNeighborList = @()
    $NoBgpAoNeighborList = @()
    $KeyStrings = @()
    $KeyStringPwdList = @()
    $DupTcpBgpKeychain = $False
    $DupPasswd = $False
    $KeyChainListWDuration = @()
    $HashBgpKeyChains = @{}
    $TcpBgpKeyNames = @()
    # Verify key chain strings are unique
    $KeyChainList = ($ShowRunningConfig | Select-String -Pattern "^key chain .*")
    if ($KeyChainList) {
        foreach ($KeyChain in $KeyChainList) {
            $startIndex = ($ShowRunningConfig | Select-String -Pattern $KeyChain | Select-Object -First 1).LineNumber[0]
            $endSTR = "!"
            $endIndex = 0
            for ($i = $startIndex; $i -le $ShowRunningConfig.Count; $i++) {
                $endIndex = $i + 1
                if ($ShowRunningConfig[$i] -eq $endSTR) {
                    # If the $endSTR line is found
                    break
                }
            }
            $KeyChainConfig = $ShowRunningConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
            $KeyStrings = $KeyChainConfig | Select-String -Pattern "key-string .*"
            if ($KeyStrings) {
                $DupPasswd = $False
                foreach ($KeyString in $KeyStrings) {
                    $KeyStringPwd = $KeyString.ToString().Split([char[]]"") | Select-Object -Last 1
                    if ($KeyStringPwdList -contains $KeyStringPwd) {
                        $DupPasswd = $True
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Password set for '$KeyChain' is not unique. This is a finding." | Out-String
                        $OpenFinding = $True
                    }
                    else {
                        $KeyStringPwdList += $KeyStringPwd
                    }
                }
            }
            else {
                $FindingDetails += "" | Out-String
                $FindingDetails += "No Password set for '$KeyChain'. This is a finding." | Out-String
                $OpenFinding = $True
            }
        }
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "No key chain set for device." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $Exception = $True
    }
    if (!$DupPasswd) {
        $KeyChains = $ShowRunningConfig | Select-String -Pattern "^key chain .*"
        if ($KeyChains) {
            foreach ($KeyChain in $KeyChains) {
                $KeyChainName = $KeyChain.ToString().Trim().Split([char[]]"") | Select-Object -Index 2
                $KeyChainConfig = Get-Section $ShowRunningConfig $KeyChain.ToString()
                $Keys = $KeyChainConfig | Select-String -Pattern "^key .*"
                $Send = $KeyChainConfig | Select-String -Pattern "^send-id .*"
                $Recv = $KeyChainConfig | Select-String -Pattern "^recv-id .*"
                $KeyString = $KeyChainConfig | Select-String -Pattern "^key-string .*"
                # Keys for bgp router
                if (($Keys) -and ($Send) -and ($Recv)) {
                    $KeyId = $Keys.ToString().Trim().Split([char[]]"") | Select-Object -Index 1
                    $SendId = $Send.ToString().Trim().Split([char[]]"") | Select-Object -Index 1
                    $RecvId = $Recv.ToString().Trim().Split([char[]]"") | Select-Object -Index 1
                    $BgpKeyChains += "key $KeyId SendID $SendId ReceiveID $RecvId"
                    $HashBgpKeyChains[$KeyChainName] = "key $KeyId SendID $SendId ReceiveID $RecvId"
                    $AcceptLIfeTime = $KeyChainConfig | Select-String -Pattern "^accept-lIfetime .*"
                    $SendLIfeTime = $KeyChainConfig | Select-String -Pattern "^send-lIfetime .*"
                    if (($KeyChainName) -and ($AcceptLIfeTime) -and ($SendLIfeTime)) {
                        $KeyChainListWDuration += "BGP keychain:`n $KeyChain`n  $AcceptLIfeTime`n  $SendLIfeTime`n`n"
                    }
                }
                else {
                    # Keys for ospf router
                    foreach ($Key in $Keys) {
                        $startIndex = ($KeyChainConfig | Select-String -Pattern $Key | Select-Object -First 1).LineNumber[0]
                        $endSTR = "!"
                        $endIndex = 0
                        for ($i = $startIndex; $i -le $KeyChainConfig.Count; $i++) {
                            $endIndex = $i + 1
                            if ($KeyChainConfig[$i] -eq $endSTR) {
                                # If the $endSTR line is found
                                break
                            }
                        }
                        $KeyConfig = $KeyChainConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
                        $KeyId = $Key.ToString().Trim().Split([char[]]"") | Select-Object -Index 1
                        $AcceptLIfeTime = $KeyConfig | Select-String -Pattern "^accept-lIfetime .*"
                        $SendLIfeTime = $KeyConfig | Select-String -Pattern "^send-lIfetime .*"
                        $KeyChainListWDuration += "OSPF keychain:`n $KeyChainName`n  $Key`n  $AcceptLIfeTime`n  $SendLIfeTime`n`n"
                    }
                    $OspfKeyChains += $KeyChainName
                }
            }
            # List key chains with duration for review
            $FindingDetails += "" | Out-String
            $FindingDetails += "Following are the list of key chains set in device and their duration." | Out-String
            $FindingDetails += "Verify that the protocol key lifetime is configured to not exceed 180 days." | Out-String
            $FindingDetails += "Review and make finding determination based on STIG check guidance. ." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += $KeyChainListWDuration
            $FindingDetails += "" | Out-String
            $Exception = $True
            ########### BGP Checks ###################
            $TcpAo = ($ShowRunningConfig | Select-String -Pattern "^tcp ao")
            if ($TcpAo) {
                $TcpAoConfig = Get-Section $ShowRunningConfig $TcpAo
                #Check all bgp key chains are defined in tcp ao
                foreach ($BgpKeyChain in $BgpKeyChains) {
                    $BgpKeyChainDefinedInTcpAo = $TcpAoConfig | Select-String -Pattern $BgpKeyChain
                    if (!$BgpKeyChainDefinedInTcpAo) {
                        $FindingDetails += "" | Out-String
                        $HashKey = $HashBgpKeyChains.Keys | Where-Object { $HashBgpKeyChains[$_] -eq $BgpKeyChain  }
                        $FindingDetails += "'$HashKey' is not defined in TCP AO. This is a finding." | Out-String
                        $FindingDetails += "" | Out-String
                        $OpenFinding = $True
                    }
                }
                $TcpBgpKeyChains = ($TcpAoonfig | Select-String -Pattern "^ keychain")
                # Check there is no duplicate keychain
                foreach ($TcpBgpKeyChain in $TcpBgpKeyChains) {
                    if ($TcpBgpKeyCheck -contains $TcpBgpKeyChain) {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "TCP AO has duplicate keyring '$TcpBgpKeyChain'. This is a finding." | Out-String
                        $FindingDetails += "" | Out-String
                        $OpenFinding = $True
                        $DupTcpBgpKeychain = $True
                        break
                    }
                    else {
                        $TcpBgpKeyCheck += $TcpBgpKeyChain
                    }
                }
                if (($BgpKeyChains.count -gt 0) -and (!$DupTcpBgpKeychain)) {
                    $TcpBgpKeyChains = ($TcpAoConfig | Select-String -Pattern "^keychain" -Context 0, 1) -replace '>', ''
                    foreach ($TcpBgpKeyChain in $TcpBgpKeyChains) {
                        $BgpKeySet = $False
                        foreach ($BgpKeyChain in $BgpKeyChains) {
                            if ($TcpBgpKeyChain | Select-String -Pattern $BgpKeyChain) {
                                $TcpBgpKeyName = ($TcpBgpKeyChain | Select-String -Pattern "keychain .*").ToString().Trim().Split([char[]]"") | Select-Object -Index 1
                                $TcpBgpKeyNames += $TcpBgpKeyName
                                $TcpBgpKeys += $BgpKeyChain
                                $BgpKeySet = $True
                            }
                        }
                        if (!$BgpKeySet) {
                            $TcpBgpKeyChain = $TcpBgpKeyChain.ToString().Trim()
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "Following TCP AO keychain is not configured as a key chain in device. This is a finding." | Out-String
                            $FindingDetails += "$TcpBgpKeyChain"
                            $FindingDetails += "" | Out-String
                            $OpenFinding = $True
                        }
                    }
                    if ($TcpBgpKeys.Count -gt 0) {
                        $RouteBgp = ($ShowRunningConfig | Select-String -Pattern "^router bgp")
                        $RouteBgpConfig = Get-Section $ShowRunningConfig $RouteBgp.ToString()
                        if ($RouteBgpConfig) {
                            # Get bgp neighbors
                            $bgpNeighbors = ($RouteBgpConfig | Select-String -Pattern "^neighbor .*")
                            foreach ($bgpNeighbor in $bgpNeighbors) {
                                $startIndex = ($RouteBgpConfig | Select-String -Pattern $bgpNeighbor | Select-Object -First 1).LineNumber[0]
                                $endSTR = "!"
                                $endIndex = 0
                                for ($i = $startIndex; $i -le $RouteBgpConfig.Count; $i++) {
                                    $endIndex = $i + 1
                                    if ($RouteBgpConfig[$i] -eq $endSTR) {
                                        # If the $endSTR line is found
                                        break
                                    }
                                }
                                $BgpNeighborConfig = ""
                                $BgpNeighborConfig = $RouteBgpConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
                                $BgpAoKeyChainSet = $False
                                foreach ($TcpBgpKeyName in $TcpBgpKeyNames) {
                                    if ($BgpNeighborConfig | Select-String -Pattern "ao $TcpBgpKeyName") {
                                        $BgpAoNeighborList += "$BgpNeighbor`n $TcpBgpKeyName`n"
                                        $BgpAoKeyChainSet = $True
                                    }
                                }
                                if (!$BgpAoKeyChainSet) {
                                    $NoBgpAoNeighborList += "$BgpNeighbor`n"
                                }
                            }
                            # Get bgp neighbor groups
                            $BgpNeighborGroups = ($RouteBgpConfig | Select-String -Pattern "^neighbor-group .*")
                            foreach ($BgpNeighborGroup in $BgpNeighborGroups) {
                                $BgpNeighborGroupName = ($BgpNeighborGroup).ToString().Split([char[]]"") | Select-Object -Index 1
                                $startIndex = ($RouteBgpConfig | Select-String -Pattern $BgpNeighborGroup | Select-Object -First 1).LineNumber[0]
                                $endSTR = "!"
                                $endIndex = 0
                                for ($i = $startIndex; $i -le $RouteBgpConfig.Count; $i++) {
                                    $endIndex = $i + 1
                                    if ($RouteBgpConfig[$i] -eq $endSTR) {
                                        # If the $endSTR line is found
                                        break
                                    }
                                }
                                $BgpNeighborGroupConfig = ""
                                $BgpNeighborGroupConfig = $RouteBgpConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
                                $BgpAoKeyChainSet = $False
                                foreach ($TcpBgpKeyName in $TcpBgpKeyNames) {
                                    if ($BgpNeighborGroupConfig | Select-String -Pattern "ao $TcpBgpKeyName") {
                                        $BgpAoNeighborList += "$BgpNeighborGroup`n $TcpBgpKeyName`n"
                                        $BgpAoKeyChainSet = $True
                                    }
                                }
                                if (!$BgpAoKeyChainSet) {
                                    $NoBgpAoNeighborList += "$BgpNeighborGroup`n"
                                }
                            }
                            # Get bgp vrf neighbors
                            $BgpVrfs = ($RouteBgpConfig | Select-String -Pattern "^vrf .*")
                            foreach ($BgpVrf in $BgpVrfs) {
                                $BgpVrfName = ($BgpVrf).ToString().Split([char[]]"") | Select-Object -Index 1
                                $startIndex = ($RouteBgpConfig | Select-String -Pattern $BgpVrf | Select-Object -First 1).LineNumber[0]
                                $endSTR = "!"
                                $endIndex = 0
                                for ($i = $startIndex; $i -le $RouteBgpConfig.Count; $i++) {
                                    $endIndex = $i + 1
                                    if ($RouteBgpConfig[$i] -eq $endSTR) {
                                        # If the $endSTR line is found
                                        break
                                    }
                                }
                                $BgpVrfConfig = ""
                                $BgpVrfConfig = $RouteBgpConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
                                $BgpVrfNeighbors = $BgpVrfConfig | Select-String -Pattern "^neighbor .*"
                                foreach ($BgpVrfNeighbor in $BgpVrfNeighbors) {
                                    $BgpVrfNeighborName = ($BgpVrfNeighbor).ToString().Split([char[]]"") | Select-Object -Index 1
                                    $startIndex = ($BgpVrfConfig | Select-String -Pattern $BgpVrfNeighbor | Select-Object -First 1).LineNumber[0]
                                    $endSTR = "!"
                                    $endIndex = 0
                                    for ($i = $startIndex; $i -le $BgpVrfConfig.Count; $i++) {
                                        $endIndex = $i + 1
                                        if ($BgpVrfConfig[$i] -eq $endSTR) {
                                            # If the $endSTR line is found
                                            break
                                        }
                                    }
                                    $BgpVrfNeighborConfig = ""
                                    $BgpVrfNeighborConfig = $BgpVrfConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
                                    $BgpAoKeyChainSet = $False
                                    foreach ($TcpBgpKeyName in $TcpBgpKeyNames) {
                                        if ($BgpVrfNeighborConfig | Select-String -Pattern "ao $TcpBgpKeyName") {
                                            $BgpAoNeighborList += "$BgpVrfNeighbor" + " `n" + "$TcpBgpKeyName" + "`n`n"
                                            $BgpAoKeyChainSet = $True
                                        }
                                    }
                                    if (!$BgpAoKeyChainSet) {
                                        $NoBgpAoNeighborList += "$BgpVrfNeighbor" + "`n"
                                    }
                                }
                            }
                            if ($BgpAoNeighborList -gt 0) {
                                $FindingDetails += "" | Out-String
                                $FindingDetails += "Followig BGP neighbors are set with neighbor routing authentication." | Out-String
                                $FindingDetails += "-------------------------------------------" | Out-String
                                $FindingDetails += $BgpAoNeighborList
                                $FindingDetails += "" | Out-String
                            }
                            if ($NoBgpAoNeighborList -gt 0) {
                                $FindingDetails += "" | Out-String
                                $FindingDetails += "Followig BGP neighbors are not set with neighbor routing authentication. This is a finding." | Out-String
                                $FindingDetails += "-------------------------------------------" | Out-String
                                $FindingDetails += $NoBgpAoNeighborList
                                $FindingDetails += "" | Out-String
                                $OpenFinding = $True
                            }
                        }
                        else {
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "Router BGP is not set for the device." | Out-String
                        }
                    }
                    else {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Following BGP keys are not set for TCP AO." | Out-String
                        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
                        $FindingDetails += "-------------------------------------------" | Out-String
                        $FindingDetails += $HashBgpKeyChains.Keys | Out-String
                        $FindingDetails += "" | Out-String
                        $Exception = $True
                    }
                }
                else {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Key chains are not configured in device." | Out-String
                    $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
                    $FindingDetails += "" | Out-String
                    $Exception = $True
                }
            }
            else {
                $FindingDetails += "" | Out-String
                $FindingDetails += "TCP AO is not set for device." | Out-String
                $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
                $FindingDetails += "" | Out-String
                $Exception = $True
            }
            ########### IGP Checks ###################
            $IGProtocols = @(
                'ospf',
                'isis',
                'eigrp')
            foreach ($IGProtocol in $IGProtocols) {
                $IGProtocolPretty = $IGProtocol.ToString().ToUpper()
                $OspfList = $ShowRunningConfig | Select-String -Pattern "^router $IGProtocol"
                if ($OSPFList) {
                    foreach ($Ospf in $OspfList) {
                        $OspfConfig = Get-Section $ShowRunningConfig $Ospf.ToString()
                        $RouterOspfKeyChain = $OspfConfig | Select-String -Pattern "^authentication message-digest keychain .*"
                        if ($RouterOspfKeyChain) {
                            $RouterOspfKeyChainName = $RouterOspfKeyChain.ToString().Trim().Split([char[]]"") | Select-Object -Index 3
                            if ($OspfKeyChains -contains $RouterOspfKeyChainName) {
                                $FindingDetails += "" | Out-String
                                $FindingDetails += "Following $IGProtocolPretty routers are set with neighbor routing authentication." | Out-String
                                $FindingDetails += "-------------------------------------------" | Out-String
                                $FindingDetails += "$Ospf`n $RouterOspfKeyChain`n"
                                $FindingDetails += "" | Out-String
                            }
                            else {
                                $FindingDetails += "" | Out-String
                                $FindingDetails += "'$RouterOspfKeyChainName' OSPF keychain is not configured in the device as a key chain. This is a finding." | Out-String
                                $FindingDetails += "" | Out-String
                                $OpenFinding = $True
                            }
                        }
                        else {
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "No keychain is configured for $IGProtocolPretty. This is a finding." | Out-String
                            $FindingDetails += "$Ospf" | Out-String
                            $FindingDetails += $OspfConfig | Out-String
                            $FindingDetails += "" | Out-String
                            $OpenFinding = $True
                        }
                    }
                }
                else {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Router $IGProtocolPretty is not set for the device." | Out-String
                }
            }
        }
    }
    if (!($ShowRunningConfig | Select-String -Pattern "^router eigrp")) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "EIGRP is not configured on this device." | Out-String
        $FindingDetails += "" | Out-String
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "EIGRP is configured on this device which does not support authentication using FIPS 198-1 algorithms." | Out-String
        $FindingDetails += "This is a finding." | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }
    # Check if IS-IS is configured
    if (!($ShowRunningConfig | Select-String -Pattern "^router isis")) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "IS-IS is not configured on this device." | Out-String
        $FindingDetails += "" | Out-String
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "IS-IS is configured on this device which doesnot support authentication using FIPS 198-1 algorithms." | Out-String
        $FindingDetails += "This is a finding." | Out-String
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

Function Get-V216740 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216740
        STIG ID    : CISC-RT-000060
        Rule ID    : SV-216740r1117237_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-NET-000019-RTR-000007
        Rule Title : The Cisco router must be configured to have all inactive interfaces disabled.
        DiscussMD5 : CF11435C63FA613CCB396A7EA6AE337D
        CheckMD5   : E0C2480092C54A08A11D026F9006488E
        FixMD5     : 46B9F38416FABAB85922B0D3B4B125FD
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
    $InterfaceEnabled = @()
    $InterfaceNotEnabled = @()
    # Check If inactive interfaces are disabled
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface "
    if ($Interfaces) {
        foreach ($Interface in $Interfaces) {
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            if (!($InterfaceConfig -like "shutdown")) {
                # Add enabled (no shutdown) interface to FindingDetails
                $InterfaceEnabled += "$Interface" + "`n"
            }
            else {
                # Add not enabled (shutdown) interface to FindingDetails
                $InterfaceNotEnabled += "$Interface" + "`n"
            }
        }
        if ($InterfaceEnabled.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Below are list of enabled interfaces." | Out-String
            $FindingDetails += "Review and verify following list of interfaces are inactive." | Out-String
            $FindingDetails += "Make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += $InterfaceEnabled
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
        if ($InterfaceNotEnabled.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Below are list of disabled interfaces." | Out-String
            $FindingDetails += "Review and confirm these are inactive interfaces." | Out-String
            $FindingDetails += "Make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += $InterfaceNotEnabled
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

Function Get-V216741 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216741
        STIG ID    : CISC-RT-000070
        Rule ID    : SV-216741r531087_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-NET-000131-RTR-000035
        Rule Title : The Cisco router must be configured to have all non-essential capabilities disabled.
        DiscussMD5 : DE5C8B6D4BBC37E5D1B0099B8BBF9615
        CheckMD5   : DB85DBDC381905478D1ED9DFB446DD52
        FixMD5     : 05DA43BF32869B2D328F18F0292D2725
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
    $NonEssentialCap = @()
    # Check for unnecessary or non-secure services
    $Services = $ShowRunningConfig | Select-String -Pattern "^service ipv4 tcp-small-servers|^service ipv4 udp-small-servers|^http client vrf|^telnet vrf default ipv4 server"
    if (!$Services) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Router does not have any unnecessary or non-secure services enabled." | Out-String
        $FindingDetails += "" | Out-String
    }
    else {
        foreach ($Service in $Services) {
            # Add enabled (no shutdown) services to FindingDetails
            $NonEssentialCap += "$Service`n"
        }
    }
    if ($NonEssentialCap.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Below are the services that should be disabled. This is a finding." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $NonEssentialCap
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

Function Get-V216743 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216743
        STIG ID    : CISC-RT-000130
        Rule ID    : SV-216743r531087_rule
        CCI ID     : CCI-001097
        Rule Name  : SRG-NET-000205-RTR-000001
        Rule Title : The Cisco router must be configured to restrict traffic destined to itself.
        DiscussMD5 : 47D3B51E0DAC1BB1AE06F12D9B6524D6
        CheckMD5   : 0A4D21DB1AEE0B9675A09B011B8E59E8
        FixMD5     : 755FAD3BA6E25014F72F68E87C10F2CD
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
    $IngressACLList = @()
    $IngressInterfaceList = @()
    $NotIngressInterfaceList = @()
    # Check for ingress interfaces
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface "
    if ($Interfaces) {
        foreach ($Interface in $Interfaces) {
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            $IngressACLs = ($InterfaceConfig | Select-String -Pattern "ipv4 access-group .* ingress")
            if ($IngressACLs) {
                foreach ($IngressACL in $IngressACLs) {
                    $ACLName = $IngressACL.ToString().Split([char[]]"") | Select-Object -Index 2
                    $AccessList = ($ShowRunningConfig | Select-String -Pattern "ipv4 access-list $ACLName")
                    if ($AccessList) {
                        $IngressACLList += "$ACLName`n"
                        $IngressInterfaceList += "$Interface`n $IngressACL`n"
                    }
                    else {
                        #Access list not defined in device. This is a finding
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Ingress ACL '$ACLName' associated to '$Interface' is not configured in the system. This is a finding" | Out-String
                        $FindingDetails += "" | Out-String
                        $OpenFinding = $True
                    }
                }
            }
            else {
                #Not ingress interface
                $NotIngressInterfaceList += "$Interface`n"
            }
        }
        if ($IngressInterfaceList.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Following are interfaces with ingress ACLs configured. " | Out-String
            $FindingDetails += "Verify that the ACL has been applied to the appropriate interface, " | Out-String
            $FindingDetails += "to only allow specIfic management and control plane traffic from specIfic sources destined to itself." | Out-String
            $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += $IngressInterfaceList
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
        if ($NotIngressInterfaceList.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Ingress ACLs are not configured for following interfaces. " | Out-String
            $FindingDetails += "Verify that all internal and external ACLs has been applied to the appropriate interfaces, " | Out-String
            $FindingDetails += "to only allow specIfic management and control plane traffic from specIfic sources destined to itself." | Out-String
            $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += $NotIngressInterfaceList
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
    }
    else {
        #No interfaces configured
        $FindingDetails += "" | Out-String
        $FindingDetails += "No interfaces configured for the device." | Out-String
        $FindingDetails += "Make finding determination based on STIG check guidance." | Out-String
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

Function Get-V216744 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216744
        STIG ID    : CISC-RT-000140
        Rule ID    : SV-216744r531087_rule
        CCI ID     : CCI-001097
        Rule Name  : SRG-NET-000205-RTR-000002
        Rule Title : The Cisco router must be configured to drop all fragmented Internet Control Message Protocol (ICMP) packets destined to itself.
        DiscussMD5 : 4CA6B5E1FCA08B57F2B6B4DAC427269E
        CheckMD5   : 49485D3781F287F3146BC0B5F80ADCEA
        FixMD5     : 44C5865F3987730837F2AADEBFDC1F9E
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
    $IcmpFragmentDenied = @()
    $IcmpFragmentNotDenied = @()
    $NoIcmpFragment = @()
    # Get Access List
    $AccessLists = ($ShowRunningConfig | Select-String -Pattern "ipv4 access-list ")
    if (!$AccessLists) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Router does not have any ipv4 access list defined." | Out-String
        $FindingDetails += "Make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    else {
        foreach ($AccessList in $AccessLists) {
            $AccessListConfig = Get-Section $ShowRunningConfig $AccessList.ToString()
            $IcmpPackets = ($AccessListConfig | Select-String -Pattern " icmp " | Select-String -Pattern " fragments ")
            if (!$IcmpPackets) {
                $NoIcmpFragment += "$AccessList`n"
            }
            else {
                foreach ($IcmpPacket in $IcmpPackets) {
                    if ($IcmpPacket | Select-String -Pattern "deny") {
                        $IcmpFragmentDenied += "$AccessList`n $IcmpPacket`n"
                    }
                    else {
                        $IcmpFragmentNotDenied += "$AccessList`n $IcmpPacket`n"
                    }
                }
            }
        }
        if ($NoIcmpFragment.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "No Fragmented ICMP packet in following ACLs." | Out-String
            $FindingDetails += "Make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += $NoIcmpFragment
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
        if ($IcmpFragmentDenied.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Following ACLs have fragmented ICMP packet dropped." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += $IcmpFragmentDenied
            $FindingDetails += "" | Out-String
        }
        if ($IcmpFragmentNotDenied.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Following ACLs do not have fragmented ICMP packet dropped. This is a finding." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += $IcmpFragmentNotDenied
            $FindingDetails += "" | Out-String
            $OpenFinding = $True
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

Function Get-V216745 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216745
        STIG ID    : CISC-RT-000160
        Rule ID    : SV-216745r856436_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-RTR-000112
        Rule Title : The Cisco router must be configured to have IP directed broadcast disabled on all interfaces.
        DiscussMD5 : C7C9EC64928AFE84A2285002F4337BE9
        CheckMD5   : 843B6201E5B7AB3AF75C351930F90D08
        FixMD5     : 4FE399250D69D7F4FDB1393D24F2DAE4
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
    $BroadcastInterface = @()
    $NoBroadcastInterface = @()
    # Check If IP directed broadcast is disabled
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
    foreach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        $directedBroadcast = ($InterfaceConfig | Select-String -Pattern "^ipv4 directed-broadcast")
        if ($directedBroadcast) {
            $BroadcastInterface += "$Interface`n"
        }
        else {
            $NoBroadcastInterface += "$Interface`n"
        }
    }
    if ($BroadcastInterface.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following interfaces have IPV4 directed-broadcast configured. This is a finding." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $BroadcastInterface
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }
    if ($NoBroadcastInterface.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following interfaces do not have IPV4 directed-broadcast configured." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $NoBroadcastInterface
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

Function Get-V216746 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216746
        STIG ID    : CISC-RT-000170
        Rule ID    : SV-216746r856437_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-RTR-000113
        Rule Title : The Cisco router must be configured to have Internet Control Message Protocol (ICMP) unreachable messages disabled on all external interfaces.
        DiscussMD5 : B158847153C15A3DCED3E37EC4308D48
        CheckMD5   : F0C1200BF85B63BF5B1F037BC0BDB7DF
        FixMD5     : 0437061ED344E60506B8D714B17DAFEF
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
    $InterfaceUnrEachableDisabled = @()
    $InterfaceNotUnrEachableDisabled = @()
    #Check If 'ipv4 unrEachables disable' is configured on all external interfaces
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
    foreach ($Interface in $Interfaces) {
        $InterfaceConfig = (Get-Section $ShowRunningConfig $Interface.ToString() | Select-String -Pattern "ipv4 unreachables disable")
        if ($InterfaceConfig) {
            $InterfaceUnrEachableDisabled += "$Interface" + "`n"
        }
        else {
            $InterfaceNotUnrEachableDisabled += "$Interface" + "`n"
        }
    }
    if ($InterfaceUnrEachableDisabled.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following interfaces have ipv4 unreachables disable command configured." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $InterfaceUnrEachableDisabled
        $FindingDetails += "" | Out-String
    }
    if ($InterfaceNotUnrEachableDisabled.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following interfaces do not have ipv4 unreachables disable command configured." | Out-String
        $FindingDetails += "Review following interfaces. For external interfaces, ipv4 unreachables disable should be configured." | Out-String
        $FindingDetails += "Make finding determination based on STIG check guidance. " | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $InterfaceNotUnrEachableDisabled
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    # Check If ICMP PE router is configured to rate limit
    $IcmpRouter = $ShowRunningConfig | Select-String -Pattern "icmp ipv4 rate-limit unreachable"
    if (!$IcmpRouter) {
        $FindingDetails += "ICMP rate-limit unreachable is not configured in PE router. This is a finding." | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }
    else {
        $FindingDetails += "ICMP rate-limit unreachable is configured in PE router." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $IcmpRouter | Out-String
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

Function Get-V216747 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216747
        STIG ID    : CISC-RT-000180
        Rule ID    : SV-216747r856438_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-RTR-000114
        Rule Title : The Cisco router must be configured to have Internet Control Message Protocol (ICMP) mask reply messages disabled on all external interfaces.
        DiscussMD5 : 584565EC957CFC2E39988E08985844B8
        CheckMD5   : 2CA271BCC7BB8BDE12138586A65087BF
        FixMD5     : 76F982E5878E0ABAF699B5A468D0C5AB
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
    $InterfaceMaskReply = @()
    $InterfaceNoMaskReply = @()
    # Check If IPV4 mask-reply is disabled
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
    foreach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        if ($InterfaceConfig | Select-String -Pattern "^ipv4 mask-reply") {
            $InterfaceMaskReply += "$Interface" + "`n"
        }
        else {
            $InterfaceNoMaskReply += "$Interface" + "`n"
        }
    }
    if ($InterfaceMaskReply.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Interfaces below have ipv4 mask-reply enabled. This should not be configured on an external interface." | Out-String
        $FindingDetails += "Verify these are not external interfaces" | Out-String
        $FindingDetails += "Make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $InterfaceMaskReply
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "No Interfaces have ipv4 mask-reply enabled." | Out-String
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

Function Get-V216748 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216748
        STIG ID    : CISC-RT-000190
        Rule ID    : SV-216748r856439_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-RTR-000115
        Rule Title : The Cisco router must be configured to have Internet Control Message Protocol (ICMP) redirect messages disabled on all external interfaces.
        DiscussMD5 : 28F4F11F66A3AE986F120CD52D1CD226
        CheckMD5   : 0F2352105DB8AFBA145A906490BF46FB
        FixMD5     : C520D03E2B001DB671D8CD82850EFE16
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
    $InterfaceRedirects = @()
    $InterfaceNoRedirects = @()
    # Get Interfaces
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
    foreach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        if ($InterfaceConfig | Select-String -Pattern "^ipv4 redirects") {
            $InterfaceRedirects += "$Interface" + "`n"
        }
        else {
            $InterfaceNoRedirects += "$Interface" + "`n"
        }
    }
    if ($InterfaceRedirects.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Interfaces below have ipv4 redirects enabled. This should not be configured on an external interface." | Out-String
        $FindingDetails += "Verify these are not external interfaces" | Out-String
        $FindingDetails += "Make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $InterfaceRedirects
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "No Interfaces have ipv4 redirects enabled." | Out-String
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

Function Get-V216749 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216749
        STIG ID    : CISC-RT-000200
        Rule ID    : SV-216749r531087_rule
        CCI ID     : CCI-000134
        Rule Name  : SRG-NET-000078-RTR-000001
        Rule Title : The Cisco router must be configured to log all packets that have been dropped at interfaces via ACL.
        DiscussMD5 : FE94D3A3F2DBEE19BA50B5E322FE11F4
        CheckMD5   : FB62DBE8A364B8DDEAA71BE6D3835261
        FixMD5     : 2CBE9DFFBBAA5F7643A8614D1AB65255
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
    $DenyLogAclList = @()
    $NoDenyLogAclList = @()
    # Check If dropped packets are logged
    $AccessLists = ($ShowRunningConfig | Select-String -Pattern "ipv4 access-list ")
    if (!$AccessLists) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Router does not have any ipv4 access list defined." | Out-String
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    else {
        foreach ($AccessList in $AccessLists) {
            $AccessListConfig = Get-Section $ShowRunningConfig $AccessList.ToString()
            $DenyStatements = ($AccessListConfig | Select-String -Pattern "deny ")
            $LogCounter = 0
            $NoLogCounter = 0
            if ($DenyStatements) {
                foreach ($DenyStatement in $DenyStatements) {
                    if ($DenyStatement | Select-String -Pattern " log") {
                        if ($LogCounter -eq 0) {
                            $DenyLogAclList += "`n$AccessList`n  $DenyStatement`n"
                            $LogCounter += 1
                        }
                        else {
                            $DenyLogAclList += " $DenyStatement`n"
                        }
                    }
                    else {
                        if ($NoLogCounter -eq 0) {
                            $NoDenyLogAclList += "`n$AccessList`n  $DenyStatement`n"
                            $NoLogCounter += 1
                        }
                        else {
                            $NoDenyLogAclList += " $DenyStatement`n"
                        }
                    }
                }
            }
        }
        if ($DenyLogAclList.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Dropped packets are logged for following ACLs." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += $DenyLogAclList
            $FindingDetails += "" | Out-String
        }
        if ($NoDenyLogAclList.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Following ACLs do not have deny statements configured. This is a finding." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += $NoDenyLogAclList
            $FindingDetails += "" | Out-String
            $OpenFinding = $True
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

Function Get-V216750 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216750
        STIG ID    : CISC-RT-000210
        Rule ID    : SV-216750r531087_rule
        CCI ID     : CCI-000132
        Rule Name  : SRG-NET-000076-RTR-000001
        Rule Title : The Cisco router must be configured to produce audit records containing information to establish where the events occurred.
        DiscussMD5 : E4D5EFD2C2CF773BC40DD1A0B70AC385
        CheckMD5   : 5EC8890D423F031DE19BE2F875AB2416
        FixMD5     : 8BF29DE5F54C89C5D7394C342F8B23D0
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
    $DenyLogAclList = @()
    $NoDenyLogAclList = @()
    # Check If dropped packets are logged
    $AccessLists = ($ShowRunningConfig | Select-String -Pattern "ipv4 access-list ")
    if (!$AccessLists) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Router does not have any ipv4 access list defined." | Out-String
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    else {
        foreach ($AccessList in $AccessLists) {
            $AccessListConfig = Get-Section $ShowRunningConfig $AccessList.ToString()
            $DenyStatements = ($AccessListConfig | Select-String -Pattern "deny ")
            $LogCounter = 0
            $NoLogCounter = 0
            if ($DenyStatements) {
                foreach ($DenyStatement in $DenyStatements) {
                    if ($DenyStatement | Select-String -Pattern " log-input") {
                        if ($LogCounter -eq 0) {
                            $DenyLogAclList += "`n$AccessList`n  $DenyStatement`n"
                            $LogCounter += 1
                        }
                        else {
                            $DenyLogAclList += " $DenyStatement`n"
                        }
                    }
                    else {
                        if ($NoLogCounter -eq 0) {
                            $NoDenyLogAclList += "`n$AccessList`n  $DenyStatement`n"
                            $NoLogCounter += 1
                        }
                        else {
                            $NoDenyLogAclList += " $DenyStatement`n"
                        }
                    }
                }
            }
        }
        if ($DenyLogAclList.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Log-input parameter is configured on deny statements, for following ACLs." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += $DenyLogAclList
            $FindingDetails += "" | Out-String
        }
        if ($NoDenyLogAclList.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Following ACLs do not have Log-input parameter is configured on deny statements." | Out-String
            $FindingDetails += "If the router is not configured to produce audit records containing information to establish to establish where the events occurred." | Out-String
            $FindingDetails += "This is a finding." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += $NoDenyLogAclList
            $FindingDetails += "" | Out-String
            $OpenFinding = $True
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

Function Get-V216751 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216751
        STIG ID    : CISC-RT-000220
        Rule ID    : SV-216751r531087_rule
        CCI ID     : CCI-000133
        Rule Name  : SRG-NET-000077-RTR-000001
        Rule Title : The Cisco router must be configured to produce audit records containing information to establish the source of the events.
        DiscussMD5 : 43B48607F27628D3CE3E18F07250F3B8
        CheckMD5   : 508EF57AB945A6D01B4F09D54D0C6695
        FixMD5     : 8BF29DE5F54C89C5D7394C342F8B23D0
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
    $ACLWithDenyLogInput = @()
    $ACLWithNoDenyLogInput = @()
    # Check If dropped packets are logged
    $AccessLists = ($ShowRunningConfig | Select-String -Pattern "ipv4 access-list ")
    if (!$AccessLists) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Router does not have any ipv4 access list defined." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    else {
        foreach ($AccessList in $AccessLists) {
            $AccessListConfig = Get-Section $ShowRunningConfig $AccessList.ToString()
            $DenyStatements = ($AccessListConfig | Select-String -Pattern "deny ")
            $LogCounter = 0
            $NoLogCounter = 0
            if ($DenyStatements) {
                foreach ($DenyStatement in $DenyStatements) {
                    if ($DenyStatement | Select-String -Pattern "log-input") {
                        if ($LogCounter -eq 0) {
                            $ACLWithDenyLogInput += "`n$AccessList`n  $DenyStatement`n"
                            $LogCounter += 1
                        }
                        else {
                            $ACLWithDenyLogInput += " $DenyStatement`n"
                        }
                    }
                    else {
                        if ($NoLogCounter -eq 0) {
                            $ACLWithNoDenyLogInput += "`n$AccessList`n  $DenyStatement`n"
                            $NoLogCounter += 1
                        }
                        else {
                            $ACLWithNoDenyLogInput += " $DenyStatement`n"
                        }
                    }
                }
            }
        }
        if ($ACLWithDenyLogInput.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += " log-input parameter is configured on deny statements, for following ACLs." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += $ACLWithDenyLogInput
            $FindingDetails += "" | Out-String
        }
        if ($ACLWithNoDenyLogInput.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Review following ACLs where deny statements do not have log-input parameter. This is a finding." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += $ACLWithNoDenyLogInput
            $FindingDetails += "" | Out-String
            $OpenFinding = $True
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

Function Get-V216752 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216752
        STIG ID    : CISC-RT-000240
        Rule ID    : SV-216752r1117241_rule
        CCI ID     : CCI-001109
        Rule Name  : SRG-NET-000202-RTR-000001
        Rule Title : The Cisco perimeter router must be configured to deny network traffic by default and allow network traffic by exception.
        DiscussMD5 : A7866C6F77EDE7578FAA64386238B650
        CheckMD5   : D4DC970C73D4B01B9C5CAF15D47BDC5E
        FixMD5     : 47127D4DBF8046C5EADEBF1C1CBBA197
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
    $NoIngressACLInterfaceList = @()
    $IngressACLInterfaceList = @()
    $IngressACLInterfaceListNotConfigured = @()
    $DenyLogInputACLList = @()
    # Get interface configuration.
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
    foreach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        $InterfaceAccessGr = ($InterfaceConfig | Select-String -Pattern "ipv4 access-group .* in")
        if (!($InterfaceAccessGr)) {
            # Add interface without an inbound ACL to FindingDetails
            $NoIngressACLInterfaceList += "$Interface" + "`n"
        }
        else {
            $ACLName = ($InterfaceConfig | Select-String -Pattern "ipv4 access-group .* ingress").ToString().Split([char[]]"") | Select-Object -Index 2
            $ACLExtended = $ShowRunningConfig | Select-String -Pattern "^ipv4 access-list $ACLName`$"
            if (!$ACLExtended) {
                $FindingDetails += "" | Out-String
                $FindingDetails += "Inbound ACL '$ACLName' associated to '$Interface' is not configured in device. This is a finding." | Out-String
                $FindingDetails += "" | Out-String
                $OpenFinding = $True
            }
            else {
                # Add ACL entries to FindingDetails
                $ACLConfig = Get-Section $ShowRunningConfig $ACLExtended.ToString()
                if (!($ACLConfig | Select-String -Pattern "deny[ ]*ipv4 any any log-input")) {
                    $FindingDetails += "" | Out-String
                    $IngressACLInterfaceListNotConfigured += "$Interface" + "`n " + "$InterfaceAccessGr" + "`n`n"
                }
                else {
                    $IngressACLInterfaceList += "$Interface" + "`n " + "$InterfaceAccessGr" + "`n`n"
                }
            }
        }
    }
    if ($IngressACLInterfaceListNotConfigured) {
        $FindingDetails += "Following are interfaces associated with inbound ACLs." | Out-String
        $FindingDetails += "ACLs are missing deny ipv4 any any log-input entry. This is a finding" | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $IngressACLInterfaceListNotConfigured
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }
    if ($IngressACLInterfaceList) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following are interfaces with inbound ACLs." | Out-String
        $FindingDetails += "These ACLs are configured to deny all other traffic that is not explicitly allowed." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $IngressACLInterfaceList
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    if ($NoIngressACLInterfaceList) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following are interfaces without inbound ACLs. inbound ACL should be applied to all external interfaces" | Out-String
        $FindingDetails += "Verify these are not external interfaces. " | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $NoIngressACLInterfaceList
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

Function Get-V216753 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216753
        STIG ID    : CISC-RT-000250
        Rule ID    : SV-216753r1117237_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-NET-000019-RTR-000002
        Rule Title : The Cisco perimeter router must be configured to enforce approved authorizations for controlling the flow of information between interconnected networks in accordance with applicable policy.
        DiscussMD5 : 44F0EAA765E18A783388CFE0F0607DD8
        CheckMD5   : B40912F6B2DD5CE22EF73CE7008FAD8B
        FixMD5     : F08FEECDA1E952E63EAE1257269D01BD
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
    $InterfaceInboundACL = @()
    $InterfaceNoInbountACL = @()
    $ACLList = @()
    #Get Access list
    $ACLs = $ShowRunningConfig | Select-String -Pattern "^ipv4 access-list .*"
    if ($ACLs) {
        foreach ($ACL in $ACLs) {
            $ACLList += "$ACL`n"
        }
        # Get interface configuration.
        $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
        foreach ($Interface in $Interfaces) {
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            if (($InterfaceConfig | Select-String -Pattern "^ipv4 access-group .* ingress")) {
                # Add interface without an inbound ACL to FindingDetails
                $ACLIn = ($InterfaceConfig | Select-String -Pattern "ipv4 access-group .* in")
                $ACLInName = $ACLIn.ToString().Split([char[]]"") | Select-Object -Index 2
                $IPACL = $ShowRunningConfig | Select-String -Pattern "^ipv4 access-list $ACLInName`$"
                if (!$IPACL) {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Inbound ACL '$ACLInName' associated to '$Interface' is not configured in device. This is a finding." | Out-String
                    $FindingDetails += "" | Out-String
                    $OpenFinding = $True
                }
                else {
                    # Add ACL entries to FindingDetails
                    $InterfaceInboundACL += "$Interface" + "`n " + "$ACLIn" + "`n`n"
                }
            }
            else {
                $InterfaceNoInbountACL += "$Interface" + "`n"
            }
        }
        if ($ACLList.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Review the router configuration to verify that following ACLs are configured to allow or deny traffic" | Out-String
            $FindingDetails += " for specIfic source and destination addresses as well as ports and protocols. Apply ACL inbound on all external interfaces." | Out-String
            $FindingDetails += "Make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += $ACLList
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
        if ($InterfaceInboundACL.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Following interfaces and inbound ACLs are configured in device." | Out-String
            $FindingDetails += "Verify that ACLs are configured to allow or deny traffic for specIfic source and destination addresses as well as ports and protocols." | Out-String
            $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += $InterfaceInboundACL
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "This device does not have an extended ACL configured, make finding determination based on STIG check guidance." | Out-String
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

Function Get-V216754 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216754
        STIG ID    : CISC-RT-000260
        Rule ID    : SV-216754r856440_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000364-RTR-000109
        Rule Title : The Cisco perimeter router must be configured to only allow incoming communications from authorized sources to be routed to authorized destinations.
        DiscussMD5 : B7A8ABE4E87430A07316D294D66EA58D
        CheckMD5   : A15AB75D1C98A681A0C7AD39C6268ACD
        FixMD5     : 46376918C853E66C4E58587A3AC9CF0E
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
    # Get ACL configuration
    if ($ShowRunningConfig | Select-String -Pattern "^ipv4 access-list ") {
        $AccessLists = $ShowRunningConfig | Select-String -Pattern "^ipv4 access-list "
        $ACLNameList = @()
        foreach ($AccessList in $AccessLists) {
            $ACLList += "$AccessList`n"
        }
        if ($ACLList.Count -gt 0) {
            # Add Access List to FindingDetails
            $FindingDetails += "" | Out-String
            $FindingDetails += "Review the below ACL configurations to verify that it allows only incoming communications from authorized sources to be routed to authorized destinations." | Out-String
            $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += $ACLList
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "This device does not have an ACL configured, make finding determination based on STIG check guidance." | Out-String
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

Function Get-V216755 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216755
        STIG ID    : CISC-RT-000270
        Rule ID    : SV-216755r856441_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000364-RTR-000110
        Rule Title : The Cisco perimeter router must be configured to block inbound packets with source Bogon IP address prefixes.
        DiscussMD5 : FF2A4B7629939398BC463DF86378208A
        CheckMD5   : D59D48B36F8D998F48F6F456B712EA8C
        FixMD5     : B7CD5B42A4E2D310334D0F335B8CF883
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
    $bogons = @(
        'deny ipv4 0.0.0.0 0.255.255.255 any log-input',
        'deny ipv4 10.0.0.0 0.255.255.255 any log-input',
        'deny ipv4 100.64.0.0 0.63.255.255 any log-input',
        'deny ipv4 127.0.0.0 0.255.255.255 any log-input',
        'deny ipv4 169.254.0.0 0.0.255.255 any log-input',
        'deny ipv4 172.16.0.0 0.15.255.255 any log-input',
        'deny ipv4 192.0.0.0 0.0.0.255 any log-input',
        'deny ipv4 192.0.2.0 0.0.0.255 any log-input',
        'deny ipv4 192.168.0.0 0.0.255.255 any log-input',
        'deny ipv4 198.18.0.0 0.1.255.255 any log-input',
        'deny ipv4 198.51.100.0 0.0.0.255 any log-input',
        'deny ipv4 203.0.113.0 0.0.0.255 any log-input',
        'deny ipv4 224.0.0.0 31.255.255.255 any log-input',
        'permit tcp any any established',
        'permit tcp host \d+.12.1.9 host \d+.12.1.10 eq bgp',
        'permit tcp host \d+.12.1.9 eq bgp host \d+.12.1.10',
        'permit icmp host \d+.12.1.9 host \d+.12.1.10 echo',
        'permit icmp host \d+.12.1.9 host \d+.12.1.10 echo-reply',
        'deny ipv4 any any log-input')
    $AccessLists = $ShowRunningConfig | Select-String -Pattern "^ipv4 access-list "
    $ACLList = @()
    $BogonACLPresent = $False
    $ACLBogonActive = @()
    $InterfaceWithBogonACL = @()
    $BogonACLMissingInterface = @()
    #Check all access lists for configuration and compile list for those with configuration present
    foreach ($AccessList in $AccessLists) {
        $ConfigActive = $False
        $AccessListName = $AccessList.ToString().Split([char[]]"") | Select-Object -Index 2
        $AccessListConfig = Get-Section $ShowRunningConfig $AccessList.ToString()
        # Compare bogon configurations against ACL configurations
        foreach ($config in $bogons) {
            if ($AccessListConfig | Select-String -Pattern $config) {
                $ACLList += $config
                $ConfigActive = $True
                $BogonACLPresent = $True
            }
            else {
                $ConfigActive = $False
                break
            }
        }
        # Check If this ACL blocks all bogon prefixes
        if ($ConfigActive -eq $True) {
            $ACLBogonActive += $AccessList
            #Verify ACL is properly configured in interface
            $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
            $InterfaceBogonSet = $False
            foreach ($Interface in $Interfaces) {
                $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
                if ($InterfaceConfig | Select-String -Pattern "ipv4 access-group $AccessListName in") {
                    $InterfaceWithBogonACL += "$Interface" + " `n" + "$AccessList" + "`n`n"
                    $InterfaceBogonSet = $True
                }
            }
            if (!$InterfaceBogonSet) {
                # ACL blocking bogon sourced traffic is not configured properly
                $BogonACLMissingInterface += "$AccessList" + "`n"
            }
        }
        else {
            if ($ACLList.count -gt 0) {
                $FindingDetails += "" | Out-String
                $FindingDetails += "Following ACL configured to block bogon sourced traffic, is missing entries. This is a finding." | Out-String
                $FindingDetails += ($AccessList.ToString() | Out-String)
                $FindingDetails += "" | Out-String
                $OpenFinding = $True
            }
        }
        #Initializing variables
        $ConfigActive = $False
        $ACLList = @()
    }
    if ($InterfaceWithBogonACL.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following Interface and associated ACLs are configured to block bogon sourced traffic." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $InterfaceWithBogonACL
        $FindingDetails += "" | Out-String
    }
    if ($BogonACLMissingInterface.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following ACLs are configured to block bogon sourced traffic, but not associated to any interface." | Out-String
        $FindingDetails += "Make finding determination based on STIG check guidance. " | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $BogonACLMissingInterface
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    if (!$BogonACLPresent) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "There are no ACL configured to block bogon sourced traffic." | Out-String
        $FindingDetails += "Make finding determination based on STIG check guidance. " | Out-String
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

Function Get-V216756 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216756
        STIG ID    : CISC-RT-000280
        Rule ID    : SV-216756r1117237_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-NET-000019-RTR-000008
        Rule Title : The Cisco perimeter router must be configured to protect an enclave connected to an alternate gateway by using an inbound filter that only permits packets with destination addresses within the sites address space.
        DiscussMD5 : 57F43B052D32972D7A564E0EA289A250
        CheckMD5   : EE26D998419471BA310F9FC8EB8E9F21
        FixMD5     : 4CA016EF65E9B85B87F352B1267F6F6E
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
    $InterfaceNoACLInbound = @()
    $InterfaceWithACLInbound = @()
    # Get interface configuration.
    $Interfaces = ($ShowRunningConfig | Select-String -Pattern "^interface")
    foreach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        if (!($InterfaceConfig | Select-String -Pattern "ipv4 access-group .* in")) {
            # Add interface without an inbound ACL
            $InterfaceNoACLInbound += "$Interface" + "`n"
        }
        else {
            $ACLIn = ($InterfaceConfig | Select-String -Pattern "ipv4 access-group .* in")
            $ACLInName = $ACLIn.ToString().Split([char[]]"") | Select-Object -Index 2
            $IPACL = $ShowRunningConfig | Select-String -Pattern "^ipv4 access-list $ACLInName`$"
            if (!$IPACL) {
                $FindingDetails += "" | Out-String
                $FindingDetails += "Inbound ACL '$ACLInName' associated to '$Interface' is not configured in device. This is a finding." | Out-String
                $FindingDetails += "" | Out-String
                $OpenFinding = $True
            }
            else {
                # Add ACL entries to FindingDetails
                $InterfaceWithACLInbound = "$Interface" + "`n " + "$ACLIn" + "`n`n"
            }
        }
    }
    if ($InterfaceNoACLInbound.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following interfaces do not have inbound ACL configured." | Out-String
        $FindingDetails += "If an interface connects to an ISP, it should have an associated inbound ACL. Verify if any of following interfaces connect to ISP." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $InterfaceNoACLInbound
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    if ($InterfaceWithACLInbound.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following interfaces are associated to inbound ACL. Verify if the interface connects to ISP and corresponding ACL is configured correctly." | Out-String
        $FindingDetails += "Verify these ACLs only allow traffic to specIfic destination addresses (i.e. enclave's NIPRNet address space)."
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "--------------------------" | Out-String
        $FindingDetails += $InterfaceWithACLInbound
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

Function Get-V216757 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216757
        STIG ID    : CISC-RT-000290
        Rule ID    : SV-216757r1117237_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-NET-000019-RTR-000009
        Rule Title : The Cisco perimeter router must be configured to not be a Border Gateway Protocol (BGP) peer to an alternate gateway service provider.
        DiscussMD5 : A195F6394BF1A3854AD59D69D0A36EEC
        CheckMD5   : 1A5A9D629B7888C2A08E5FD0C18A6BC4
        FixMD5     : 6FAED61D3FF1C185E826A38B8D9B5265
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
    $InterfaceNoACLInbound = @()
    $InterfaceWithACLInbound = @()
    # Get interface configuration.
    $Interfaces = ($ShowRunningConfig | Select-String -Pattern "^interface")
    foreach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        if (!($InterfaceConfig | Select-String -Pattern "ipv4 access-group .* in")) {
            # Add interface without an inbound ACL
            $InterfaceNoACLInbound += "$Interface" + "`n"
        }
        else {
            $ACLIn = ($InterfaceConfig | Select-String -Pattern "ipv4 access-group .* in")
            $ACLInName = $ACLIn.ToString().Split([char[]]"") | Select-Object -Index 2
            $IPACL = $ShowRunningConfig | Select-String -Pattern "^ipv4 access-list $ACLInName`$"
            if (!$IPACL) {
                $FindingDetails += "" | Out-String
                $FindingDetails += "Inbound ACL '$ACLInName' associated to '$Interface' is not configured in device. This is a finding." | Out-String
                $FindingDetails += "" | Out-String
                $OpenFinding = $True
            }
            else {
                # Add ACL entries to FindingDetails
                $InterfaceWithACLInbound = "$Interface" + "`n " + "$ACLIn" + "`n`n"
            }
        }
    }
    if ($InterfaceNoACLInbound.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following interfaces do not have inbound ACL configured." | Out-String
        $FindingDetails += "If an interface connects to an ISP, it should have an associated inbound ACL. Verify if any of following interfaces connect to ISP." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $InterfaceNoACLInbound
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    if ($InterfaceWithACLInbound.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following interfaces are associated to inbound ACL. Verify if the interface connects to ISP, corresponding ACL is configured correctly." | Out-String
        $FindingDetails += "Verify these ACLs only allow traffic to specIfic destination addresses (i.e. enclave's NIPRNet address space)."
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "--------------------------" | Out-String
        $FindingDetails += $InterfaceWithACLInbound
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

Function Get-V216758 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216758
        STIG ID    : CISC-RT-000300
        Rule ID    : SV-216758r1117237_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-NET-000019-RTR-000010
        Rule Title : The Cisco perimeter router must be configured to not redistribute static routes to an alternate gateway service provider into BGP or an IGP peering with the NIPRNet or to other autonomous systems.
        DiscussMD5 : 34181932F5C081FABD8322F6FB8C4588
        CheckMD5   : E7C67C5C4B5C79FB36FC6E04B9F0904E
        FixMD5     : 3EED5DD44F65CFD24B8518E6B101394B
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
    # Check If OSPF is configured
    if (!($ShowRunningConfig | Select-String -Pattern "^router ospf")) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "OSPF is not configured on this device." | Out-String
        $FindingDetails += "" | Out-String
    }
    else {
        $PolicyResult = @()
        $OspfRouters = $ShowRunningConfig | Select-String -Pattern "^router ospf"
        foreach ($OspfRouter in $OspfRouters) {
            $PolicyResult = Get-RouterPolicy $ShowRunningConfig $OspfRouter
            $FindingDetails += $PolicyResult[0]
            $OpenFinding = $PolicyResult[1]
            $Exception = $PolicyResult[2]
        }
    }
    # Check If EIGRP is configured
    if (!($ShowRunningConfig | Select-String -Pattern "^router eigrp")) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "EIGRP is not configured on this device." | Out-String
        $FindingDetails += "" | Out-String
    }
    else {
        $PolicyResult = @()
        $EigrpRouters = $ShowRunningConfig | Select-String -Pattern "^router eigrp"
        foreach ($EigrpRouter in $EigrpRouters) {
            $PolicyResult = Get-RouterPolicy $ShowRunningConfig $EigrpRouter
            $FindingDetails += $PolicyResult[0]
            $OpenFinding = $PolicyResult[1]
            $Exception = $PolicyResult[2]
        }
    }
    # Check If RIP is configured
    if (!($ShowRunningConfig | Select-String -Pattern "^router rip")) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "RIP is not configured on this device." | Out-String
        $FindingDetails += "" | Out-String
    }
    else {
        $PolicyResult = @()
        $RipRouters = $ShowRunningConfig | Select-String -Pattern "^router rip"
        foreach ($RipRouter in $RipRouters) {
            $PolicyResult = Get-RouterPolicy $ShowRunningConfig $RipRouter
            $FindingDetails += $PolicyResult[0]
            $OpenFinding = $PolicyResult[1]
            $Exception = $PolicyResult[2]
        }
    }
    # Check If BGP is configured
    if (!($ShowRunningConfig | Select-String -Pattern "^router bgp")) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "BGP is not configured on this device." | Out-String
        $FindingDetails += "" | Out-String
    }
    else {
        $PolicyResult = @()
        $BgpRouters = $ShowRunningConfig | Select-String -Pattern "^router bgp"
        foreach ($BgpRouter in $BgpRouters) {
            $PolicyResult = Get-RouterPolicy $ShowRunningConfig $BgpRouter
            $FindingDetails += $PolicyResult[0]
            $OpenFinding = $PolicyResult[1]
            $Exception = $PolicyResult[2]
        }
    }
    #>
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

Function Get-V216760 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216760
        STIG ID    : CISC-RT-000320
        Rule ID    : SV-216760r1007832_rule
        CCI ID     : CCI-001097
        Rule Name  : SRG-NET-000205-RTR-000003
        Rule Title : The Cisco perimeter router must be configured to filter traffic destined to the enclave in accordance with the guidelines contained in DoD Instruction 8551.1.
        DiscussMD5 : 5427F5419DAACF78B385DB328483654D
        CheckMD5   : 0C4BD513AB8A06E0D1B15C8487B0F4A9
        FixMD5     : 132067DF6E6961B32BAC2D4CC0643F13
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
    $InterfaceNoACLInbound = @()
    $InterfaceWithACLInbound = @()
    # Get interface configuration.
    $Interfaces = ($ShowRunningConfig | Select-String -Pattern "^interface")
    foreach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        if (!($InterfaceConfig | Select-String -Pattern "ipv4 access-group .* in")) {
            # Add interface without an inbound ACL
            $InterfaceNoACLInbound += "$Interface" + "`n"
        }
        else {
            $ACLIn = ($InterfaceConfig | Select-String -Pattern "ipv4 access-group .* in")
            $ACLInName = $ACLIn.ToString().Split([char[]]"") | Select-Object -Index 2
            $IPACL = $ShowRunningConfig | Select-String -Pattern "^ipv4 access-list $ACLInName`$"
            if (!$IPACL) {
                $FindingDetails += "" | Out-String
                $FindingDetails += "Inbound ACL '$ACLInName' associated to '$Interface' is not configured in device. This is a finding." | Out-String
                $FindingDetails += "" | Out-String
                $OpenFinding = $True
            }
            else {
                # Add ACL entries to FindingDetails
                $InterfaceWithACLInbound = "$Interface" + "`n " + "$ACLIn" + "`n`n"
            }
        }
    }
    if ($InterfaceNoACLInbound.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following interfaces do not have inbound ACL configured." | Out-String
        $FindingDetails += "If these are external interfaces, it should have an associated inbound ACL." | Out-String
        $FindingDetails += "The inbound ACL should be configured correctly in accordance with the guidelines contained in DoD 8551.1 ."
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $InterfaceNoACLInbound
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    if ($InterfaceWithACLInbound.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following interfaces are associated to inbound ACL." | Out-String
        $FindingDetails += "Verify corresponding ACL is configured correctly in accordance with the guidelines contained in DoD 8551.1 ."
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "--------------------------" | Out-String
        $FindingDetails += $InterfaceWithACLInbound
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

Function Get-V216761 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216761
        STIG ID    : CISC-RT-000330
        Rule ID    : SV-216761r531087_rule
        CCI ID     : CCI-001097
        Rule Name  : SRG-NET-000205-RTR-000004
        Rule Title : The Cisco perimeter router must be configured to filter ingress traffic at the external interface on an inbound direction.
        DiscussMD5 : 93C32F6B01898831FA9D0ECC5D9AC835
        CheckMD5   : 2F83C498F849260B95F490BD3168DE39
        FixMD5     : 4CC4DBBB288393F35EF3F75663F6CF70
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
    $InterfaceNoACLInbound = @()
    $InterfaceWithACLInbound = @()
    # Get interface configuration.
    $Interfaces = ($ShowRunningConfig | Select-String -Pattern "^interface")
    foreach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        if (!($InterfaceConfig | Select-String -Pattern "ipv4 access-group .* in")) {
            # Add interface without an inbound ACL
            $InterfaceNoACLInbound += "$Interface" + "`n"
        }
        else {
            $ACLIn = ($InterfaceConfig | Select-String -Pattern "ipv4 access-group .* in")
            $ACLInName = $ACLIn.ToString().Split([char[]]"") | Select-Object -Index 2
            $IPACL = $ShowRunningConfig | Select-String -Pattern "^ipv4 access-list $ACLInName`$"
            if (!$IPACL) {
                $FindingDetails += "" | Out-String
                $FindingDetails += "Inbound ACL '$ACLInName' associated to '$Interface' is not configured in device. This is a finding." | Out-String
                $FindingDetails += "" | Out-String
                $OpenFinding = $True
            }
            else {
                # Add ACL entries to FindingDetails
                $InterfaceWithACLInbound = "$Interface" + "`n " + "$ACLIn" + "`n`n"
            }
        }
    }
    if ($InterfaceNoACLInbound.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following interfaces do not have inbound ACL configured." | Out-String
        $FindingDetails += "If these are external interfaces, it should have an associated inbound ACL." | Out-String
        $FindingDetails += "If ACL is not configured then this is a finding."
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $InterfaceNoACLInbound
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    if ($InterfaceWithACLInbound.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following interfaces are associated to inbound ACL." | Out-String
        $FindingDetails += "--------------------------" | Out-String
        $FindingDetails += $InterfaceWithACLInbound
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

Function Get-V216762 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216762
        STIG ID    : CISC-RT-000340
        Rule ID    : SV-216762r531087_rule
        CCI ID     : CCI-001097
        Rule Name  : SRG-NET-000205-RTR-000005
        Rule Title : The Cisco perimeter router must be configured to filter egress traffic at the internal interface on an inbound direction.
        DiscussMD5 : 242B7359B47A49AC1A5518D08E3218C0
        CheckMD5   : 579995D1D79BE531F974219514CAC6AD
        FixMD5     : 9092AC23E36F3C0644FF36F7F17BB674
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
    $InterfaceNoACLInbound = @()
    $InterfaceWithACLInbound = @()
    # Get interface configuration.
    $Interfaces = ($ShowRunningConfig | Select-String -Pattern "^interface")
    foreach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        if (!($InterfaceConfig | Select-String -Pattern "ipv4 access-group .* ingress")) {
            # Add interface without an inbound ACL
            $InterfaceNoACLInbound += "$Interface" + "`n"
        }
        else {
            $ACLIn = ($InterfaceConfig | Select-String -Pattern "ipv4 access-group .* ingress")
            $ACLInName = $ACLIn.ToString().Split([char[]]"") | Select-Object -Index 2
            $IPACL = $ShowRunningConfig | Select-String -Pattern "^ipv4 access-list $ACLInName`$"
            if (!$IPACL) {
                $FindingDetails += "" | Out-String
                $FindingDetails += "ACL '$ACLInName' associated to '$Interface' is not configured in device. This is a finding." | Out-String
                $FindingDetails += "" | Out-String
                $OpenFinding = $True
            }
            else {
                # Add ACL entries to FindingDetails
                $InterfaceWithACLInbound = "$Interface" + "`n " + "$ACLIn" + "`n`n"
            }
        }
    }
    if ($InterfaceNoACLInbound.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following interfaces do not have egress ACL configured." | Out-String
        $FindingDetails += "If these are internal interfaces, it should have an associated egress ACL." | Out-String
        $FindingDetails += "If ACL is not configured then this is a finding."
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $InterfaceNoACLInbound
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    if ($InterfaceWithACLInbound.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following interfaces are associated to egress ACL." | Out-String
        $FindingDetails += "--------------------------" | Out-String
        $FindingDetails += $InterfaceWithACLInbound
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

Function Get-V216764 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216764
        STIG ID    : CISC-RT-000360
        Rule ID    : SV-216764r856442_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000364-RTR-000111
        Rule Title : The Cisco perimeter router must be configured to have Link Layer Discovery Protocol (LLDP) disabled on all external interfaces.
        DiscussMD5 : 9270173D7E9AA5C805DF67936581541B
        CheckMD5   : 804AEB3F379CE30B0429E4CD7D15E3BF
        FixMD5     : 13A7F0008E201DDFE8185A6269D70D8D
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
    # Check If cdp enabled globally
    $CheckGLobalCdp = ($ShowRunningConfig | Select-String -Pattern "^lldp")
    if (!$CheckGlobalCdp) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "LLDP is not enabled globally." | Out-String
        $FindingDetails += "" | Out-String
    }
    else {
        # Get interface configuration.
        $Interfaces = ($ShowRunningConfig | Select-String -Pattern "^interface")
        $InterfaceLdpDisabled = @()
        $InterfaceLdpEnabled = @()
        foreach ($Interface in $Interfaces) {
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            $InterfaceConfigLine = ""
            foreach ($line in $InterfaceConfig) {
                $InterfaceConfigLine += $line + " "
            }
            if (($InterfaceConfigLine | Select-String -Pattern "lldp transmit disable ") -or (($InterfaceConfig | Select-String -Pattern "^lldp") -and ($InterfaceConfig | Select-String -Pattern "^ transmit disable"))) {
                $InterfaceLdpDisabled += "$Interface" + "`n"
                $Exception = $True
            }
            else {
                $InterfaceLdpEnabled += "$Interface" + "`n"
                $Exception = $True
            }
        }
        if ($InterfaceLdpEnabled.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "LLDP is enabled globally. Following interaces do not have LLDP disabled. For an external interface LLDP transmit should be disabled." | Out-String
            $FindingDetails += "Review if these are external interfaces and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += "$InterfaceLdpEnabled"
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
        if ($InterfaceLdpDisabled.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "LLDP is enabled globally. Following interaces have LLDP disabled. For an external interface LLDP transmit should be disabled." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += "$InterfaceLdpDisabled"
            $FindingDetails += "" | Out-String
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

Function Get-V216765 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216765
        STIG ID    : CISC-RT-000370
        Rule ID    : SV-216765r856443_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000364-RTR-000111
        Rule Title : The Cisco perimeter router must be configured to have Cisco Discovery Protocol (CDP) disabled on all external interfaces.
        DiscussMD5 : 5D66B0E62DE6E36DD2641D3152AE00CF
        CheckMD5   : 6BDD2AB0556DE83A877450822B729C9B
        FixMD5     : 1B528B79B7982CB9338132B7BA869773
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
    $CdpEnabledGlobally = $True
    # Check If cdp enabled globally
    $CheckGLobalcdp = $ShowRunningConfig | Select-String -Pattern "^cdp"
    if (!$CheckGlobalcdp) {
        $CdpEnabledGlobally = $False
    }
    else {
        # Get interface configuration.
        $CdpEnabledGlobally = $True
    }
    $Interfaces = ($ShowRunningConfig | Select-String -Pattern "^interface")
    $InterfaceCdpDisabled = @()
    $InterfaceCdpEnabled = @()
    foreach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        $InterfaceConfigLine = ""
        foreach ($line in $InterfaceConfig) {
            $InterfaceConfigLine += $line + " "
        }
        if (($InterfaceConfigLine | Select-String -Pattern " cdp ") -or ($InterfaceConfigLine | Select-String -Pattern "^cdp ")) {
            $InterfaceCdpEnabled += "$Interface" + "`n"
        }
        else {
            $InterfaceCdpDisabled += "$Interface" + "`n"
        }
    }
    if (($CdpEnabledGlobally -and ($InterfaceCdpEnabled.Count -gt 0))) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "CDP is enabled globally." | Out-String
        $FindingDetails += "Following interaces also have CDP enabled. For an external interface CDP should not be enabled."
        $FindingDetails += "Review if these are external interfaces and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $InterfaceCdpEnabled
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    else {
        if ((!$CdpEnabledGlobally -and ($InterfaceCdpEnabled.Count -gt 0))) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "CDP is not enabled globally." | Out-String
            $FindingDetails += "Following interaces have CDP enabled. For an external interface in this case CDP should not be enabled."
            $FindingDetails += "Review if these are external interfaces and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += $InterfaceCdpEnabled
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
        else {
            if ((!$CdpEnabledGlobally -and ($InterfaceCdpEnabled.Count -eq 0))) {
                $FindingDetails += "" | Out-String
                $FindingDetails += "CDP is not enabled globally or on any interfaces." | Out-String
                $FindingDetails += "" | Out-String
            }
            else {
                $FindingDetails += "" | Out-String
                $FindingDetails += "CDP is enabled globally, but is not on any interfaces." | Out-String
                $FindingDetails += "" | Out-String
            }
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

Function Get-V216766 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216766
        STIG ID    : CISC-RT-000380
        Rule ID    : SV-216766r856444_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000364-RTR-000112
        Rule Title : The Cisco perimeter router must be configured to have Proxy ARP disabled on all external interfaces.
        DiscussMD5 : C698836D6831E473338364E5CD0F025A
        CheckMD5   : 70C06950EF64A54463058B1669064B15
        FixMD5     : 16CB3139F6C541F0965F162C0E6EB5B2
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
    # Get interface configuration.
    $Interfaces = ($ShowRunningConfig | Select-String -Pattern "^interface")
    $InterfaceArpEnabled = @()
    foreach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        $InterfaceConfigLine = ""
        foreach ($line in $InterfaceConfig) {
            $InterfaceConfigLine += $line + " "
        }
        $ProxyArpCheck = ($InterfaceConfigLine | Select-String -Pattern " proxy-arp ")
        # check if proxy-arp is enabled
        if ($ProxyArpCheck) {
            $InterfaceArpEnabled += "$Interface" + "`n"
            $OpenFinding = $True
        }
    }
    if ($InterfaceArpEnabled -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "IP Proxy ARP is enabled for below interfaces. This check for external interfaces should be disabled. Review if these are external interfaces and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $InterfaceArpEnabled
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

Function Get-V216767 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216767
        STIG ID    : CISC-RT-000390
        Rule ID    : SV-216767r945857_rule
        CCI ID     : CCI-001097
        Rule Name  : SRG-NET-000364-RTR-000113
        Rule Title : The Cisco perimeter router must be configured to block all outbound management traffic.
        DiscussMD5 : C47C470B04B9AD60043EAB341E8417A1
        CheckMD5   : C3321A631C412BA378051E50E1B46D40
        FixMD5     : 934B8743272D258AD71DD044CDB98CA3
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
    # Get interface list.
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
    $OutboundInterfaceList = @()
    $OutboundAclList = @()
    $OutboundACLEntries = @(
        'deny tcp any any eq tacacs log-input',
        'deny tcp any any eq ssh log-input',
        'deny udp any any eq snmp log-input',
        'deny udp any any eq snmptrap log-input',
        'deny udp any any eq syslog log-input',
        'deny ipv4 any any log-input')
    foreach ($Interface in $Interfaces) {
        # Verify interface has outbound ACL
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        $OutboundACL = ($InterfaceConfig | Select-String -Pattern "ipv4 access-group .* egress")
        if ($OutboundACL) {
            $OutboundInterfaceList += "$Interface" + "`n"
            # Verify outbound ACL is configured to block all management traffic
            $ACLBlckMgmntTr = $False
            $ACLName = $OutboundACL.ToString().Split([char[]]"") | Select-Object -Index 2
            $ACLExtended = $ShowRunningConfig | Select-String -Pattern "^ipv4 access-list $ACLName"
            if ($ACLExtended) {
                # Add ACL entries to FindingDetails
                $ACLConfig = Get-Section $ShowRunningConfig $ACLExtended.ToString()
                foreach ($config in $OutboundACLEntries) {
                    $ACLDetails = ($ACLConfig | Select-String -Pattern $config)
                    if ($ACLDetails) {
                        $ACLBlckMgmntTr = $True
                    }
                    else {
                        $ACLBlckMgmntTr = $False
                        break
                    }
                }
                if ($ACLBlckMgmntTr) {
                    $OutboundAclList += "$ACLName" + "`n"
                }
            }
        }
    }
    if ($OutboundInterfaceList.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following interfaces are configured with outbound ACLs. For an external interface, outbound ACLs should discard management traffic."
        $FindingDetails += "Review if these are external interfaces and the egress ACL blocks management traffic and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $OutboundInterfaceList
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "None of the interfaces for the device are configured with outbound ACLs."
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    if ($OutboundAclList.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following are outbound ACLs that discard management traffic."
        $FindingDetails += "Review all external interfaces have been configured with an outbound ACL that discards management traffic."
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $OutboundAclList
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "There are no outbound ACLs configured to block management traffic."
        $FindingDetails += "Review and make finding determination based on STIG check guidance."
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

Function Get-V216768 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216768
        STIG ID    : CISC-RT-000400
        Rule ID    : SV-216768r991934_rule
        CCI ID     : CCI-001097, CCI-004891
        Rule Name  : SRG-NET-000205-RTR-000009
        Rule Title : The Cisco out-of-band management (OOBM) gateway router must be configured to transport management traffic to the Network Operations Center (NOC) via dedicated circuit, MPLS/VPN service, or IPsec tunnel.
        DiscussMD5 : 406AB996463C887DB43FA08F3B651F94
        CheckMD5   : 38810E964DA2FAD8CD3F8AAE35DCBADC
        FixMD5     : 2F252A53420C725E8A7727B011E2F373
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
    $TunnelIpsecSet = $False
    # Get interface configuration.
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
    foreach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        # Verify If tunnel profile is configured
        $TunnelIpsec = ($Interface | Select-String -Pattern "^interface tunnel-ipsec .*")
        if ($TunnelIpsec) {
            $TunnelIpsecSet = $True
            if (($InterfaceConfig | Select-String -Pattern "^profile .*")) {
                # Get the profile name
                $ProfileName = (($InterfaceConfig | Select-String -Pattern "^profile .*").ToString().Split([char[]]"") | Select-Object -Index 1)
                # Get crypto ipsec of profile
                $IPsecProfile = ($ShowRunningConfig | Select-String -Pattern "^crypto ipsec profile $ProfileName")
                if ($IPsecProfile) {
                    $IPsecProfileConfig = Get-Section $ShowRunningConfig $IPsecProfile.ToString()
                    if ($IPsecProfileConfig) {
                        # Get ACL and transform set of ipsec profile
                        $IPsecACLTrset = ($IPsecProfileConfig | Select-String -Pattern "match .* transform-set .*")
                        if ($IPsecACLTrset) {
                            $IPsecACL = ($IPsecACLTrset.ToString().Split([char[]]"") | Select-Object -Index 1)
                            $IPsecTrset = ($IPsecACLTrset.ToString().Split([char[]]"") | Select-Object -Index 3)
                            # Verify ACL is configured
                            $ACLSet = ($ShowRunningConfig | Select-String -Pattern "ipv4 access-list $IPsecACL")
                            if (!$ACLSet) {
                                $FindingDetails += "" | Out-String
                                $FindingDetails += " ACL '$IPsecACL' for interface '$TunnelIpsec' is not configured. Make finding determination based on STIG check guidance." | Out-String
                                $FindingDetails += "" | Out-String
                                $Exception = $True
                            }
                            # Get transform set details
                            $IPsecTrsetConfig = ($ShowRunningConfig | Select-String -Pattern "^crypto ipsec transform-set $IPsecTrset esp-aes 256 esp-sha256-hmac")
                            if ($IPsecTrsetConfig) {
                                # Verify isakmp keyring has been configured
                                $IsakmpKeyring = ($ShowRunningConfig | Select-String -Pattern "^crypto isakmp keyring .*")
                                if ($IsakmpKeyring) {
                                    $IsakmpKeyringConfig = Get-Section $ShowRunningConfig $IsakmpKeyring.ToString()
                                    $PresharedKey = ($IsakmpKeyringConfig | Select-String -Pattern "^pre-shared-key address .*")
                                    if (!$PresharedKey) {
                                        $FindingDetails += "" | Out-String
                                        $FindingDetails += " '$IsakmpKeyRing' is not configured properly. Make finding determination based on STIG check guidance." | Out-String
                                        $FindingDetails += "" | Out-String
                                        $OpenFinding = $True
                                        break
                                    }
                                }
                                else {
                                    $FindingDetails += "" | Out-String
                                    $FindingDetails += " crypto isakmp keyring, not configured. make finding determination based on STIG check guidance." | Out-String
                                    $FindingDetails += "" | Out-String
                                    $OpenFinding = $True
                                    break
                                }
                                $IsakmpKeyPolicy = ($ShowRunningConfig | Select-String -Pattern "^crypto isakmp policy .*")
                                if ($IsakmpKeyPolicy) {
                                    $IsakmpKeyPolicyConfig = Get-Section $ShowRunningConfig $IsakmpKeyPolicy.ToString()
                                    # Verify following is set in isakmp policy
                                    $IsakmpPolicy = (($IsakmpKeyPolicyConfig | Select-String -Pattern "aes 256") -and ($IsakmpKeyPolicyConfig | Select-String -Pattern "hash sha256"))
                                    if (!$IsakmpPolicy) {
                                        $FindingDetails += "" | Out-String
                                        $FindingDetails += " '$IsakmpKeyPolicy' is not configured properly. This is a finding." | Out-String
                                        $FindingDetails += "" | Out-String
                                        $OpenFinding = $True
                                    }
                                }
                                else {
                                    $FindingDetails += "" | Out-String
                                    $FindingDetails += " '$IsakmpKeyPolicy' is not configured. This is a finding." | Out-String
                                    $FindingDetails += "" | Out-String
                                    $OpenFinding = $True
                                }
                            }
                            else {
                                $FindingDetails += "" | Out-String
                                $FindingDetails += "Transform-set '$IPsecTrset' for '$IPsecProfile' is not configured properly. This is a finding." | Out-String
                                $FindingDetails += "" | Out-String
                                $OpenFinding = $True
                            }
                        }
                        else {
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "Transform-set '$IPsecTrset' for '$IPsecProfile' is not configured. This is a finding." | Out-String
                            $FindingDetails += "" | Out-String
                            $OpenFinding = $True
                        }
                    }
                    else {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "crypto ipsec profile '$IPsecProfile' is not configured properly. This is a finding." | Out-String
                        $FindingDetails += "" | Out-String
                        $OpenFinding = $True
                    }
                }
                else {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "crypto ipsec profile for '$ProfileName' is not configured properly. This is a finding." | Out-String
                    $FindingDetails += "" | Out-String
                    $OpenFinding = $True
                }
                if (!$OpenFinding) {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Profile '$ProfileName' for '$TunnelIpsec' has been configured." | Out-String
                    $FindingDetails += "" | Out-String
                }
            }
            else {
                $FindingDetails += "" | Out-String
                $FindingDetails += "No profile configured for '$TunnelIpsec'. This is a finding." | Out-String
                $FindingDetails += "" | Out-String
                $OpenFinding = $True
            }
        }
    }
    if (!$TunnelIpsecSet) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "No tunnel-ipsec configured." | Out-String
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

Function Get-V216769 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216769
        STIG ID    : CISC-RT-000410
        Rule ID    : SV-216769r531087_rule
        CCI ID     : CCI-001097
        Rule Name  : SRG-NET-000205-RTR-000010
        Rule Title : The Cisco out-of-band management (OOBM) gateway router must be configured to forward only authorized management traffic to the Network Operations Center (NOC).
        DiscussMD5 : 9629B6535AD16F18F566C074229188BB
        CheckMD5   : 78BD92908A6B8B06C5E1703BE20FB5EA
        FixMD5     : FB53E10CE5A8F71AB9B34DA3374FDEC3
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
    $TunnelIpsecSet = $False
    # Get interface configuration.
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
    foreach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        # Verify If tunnel profile is configured
        $TunnelIpsec = ($Interface | Select-String -Pattern "^interface tunnel-ipsec .*")
        if ($TunnelIpsec) {
            $TunnelIpsecSet = $True
            if (($InterfaceConfig | Select-String -Pattern "^profile .*")) {
                # Get the profile name
                $ProfileName = (($InterfaceConfig | Select-String -Pattern "^profile .*").ToString().Split([char[]]"") | Select-Object -Index 1)
                # Get crypto ipsec of profile
                $IPsecProfile = ($ShowRunningConfig | Select-String -Pattern "^crypto ipsec profile $ProfileName")
                if ($IPsecProfile) {
                    $IPsecProfileConfig = Get-Section $ShowRunningConfig $IPsecProfile.ToString()
                    if ($IPsecProfileConfig) {
                        # Get ACL and transform set of ipsec profile
                        $IPsecACLTrset = ($IPsecProfileConfig | Select-String -Pattern "match .* transform-set .*")
                        if ($IPsecACLTrset) {
                            $IPsecACL = ($IPsecACLTrset.ToString().Split([char[]]"") | Select-Object -Index 1)
                            $IPsecTrset = ($IPsecACLTrset.ToString().Split([char[]]"") | Select-Object -Index 3)
                            # Verify ACL is configured
                            $ACLSet = ($ShowRunningConfig | Select-String -Pattern "ipv4 access-list $IPsecACL")
                            if (!$ACLSet) {
                                $FindingDetails += "" | Out-String
                                $FindingDetails += " ACL '$IPsecACL' for interface '$TunnelIpsec', not configured. Make finding determination based on STIG check guidance." | Out-String
                                $FindingDetails += "" | Out-String
                                $Exception = $True
                            }
                            # Get transform set details
                            $IPsecTrsetConfig = ($ShowRunningConfig | Select-String -Pattern "^crypto ipsec transform-set $IPsecTrset esp-aes 256 esp-sha256-hmac")
                            if ($IPsecTrsetConfig) {
                                # Verify isakmp keyring has been configured
                                $IsakmpKeyring = ($ShowRunningConfig | Select-String -Pattern "^crypto isakmp keyring .*")
                                if ($IsakmpKeyring) {
                                    $IsakmpKeyringConfig = Get-Section $ShowRunningConfig $IsakmpKeyring.ToString()
                                    $PresharedKey = ($IsakmpKeyringConfig | Select-String -Pattern "^pre-shared-key address .*")
                                    if (!$PresharedKey) {
                                        $FindingDetails += "" | Out-String
                                        $FindingDetails += " '$IsakmpKeyRing', not configured properly. This is a finding." | Out-String
                                        $FindingDetails += "" | Out-String
                                        $OpenFinding = $True
                                        break
                                    }
                                }
                                else {
                                    $FindingDetails += "" | Out-String
                                    $FindingDetails += " crypto isakmp keyring, not configured. This is a finding." | Out-String
                                    $FindingDetails += "" | Out-String
                                    $OpenFinding = $True
                                    break
                                }
                                $IsakmpKeyPolicy = ($ShowRunningConfig | Select-String -Pattern "^crypto isakmp policy .*")
                                if ($IsakmpKeyPolicy) {
                                    $IsakmpKeyPolicyConfig = Get-Section $ShowRunningConfig $IsakmpKeyPolicy.ToString()
                                    # Verify following is set in isakmp policy
                                    $IsakmpPolicy = (($IsakmpKeyPolicyConfig | Select-String -Pattern "aes 256") -and ($IsakmpKeyPolicyConfig | Select-String -Pattern "hash sha256"))
                                    if (!$IsakmpPolicy) {
                                        $FindingDetails += "" | Out-String
                                        $FindingDetails += " '$IsakmpKeyPolicy', not configured properly. This is a finding." | Out-String
                                        $FindingDetails += "" | Out-String
                                        $OpenFinding = $True
                                    }
                                }
                                else {
                                    $FindingDetails += "" | Out-String
                                    $FindingDetails += " '$IsakmpKeyPolicy', not configured. This is a finding." | Out-String
                                    $FindingDetails += "" | Out-String
                                    $OpenFinding = $True
                                }
                            }
                            else {
                                $FindingDetails += "" | Out-String
                                $FindingDetails += "Transform-set '$IPsecTrset' for '$IPsecProfile', not configured properly. This is a finding." | Out-String
                                $FindingDetails += "" | Out-String
                                $OpenFinding = $True
                            }
                        }
                        else {
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "Transform-set '$IPsecTrset' for '$IPsecProfile', not configured. This is a finding." | Out-String
                            $FindingDetails += "" | Out-String
                            $OpenFinding = $True
                        }
                    }
                    else {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "crypto ipsec profile '$IPsecProfile', not configured properly. This is a finding." | Out-String
                        $FindingDetails += "" | Out-String
                        $OpenFinding = $True
                    }
                }
                else {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "crypto ipsec profile for '$ProfileName', not configured properly. This is a finding." | Out-String
                    $FindingDetails += "" | Out-String
                    $OpenFinding = $True
                }
                if (!$OpenFinding) {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Profile '$ProfileName' for '$TunnelIpsec' has been configured."
                    $FindingDetails += "If this is an OOBM interface review that '$IPsecACL' is configured to only permit management traffic to NOC." | Out-String
                    $FindingDetails += "Make finding determination based on STIG check guidance." | Out-String
                    $FindingDetails += "" | Out-String
                    $Exception = $True
                }
            }
            else {
                $FindingDetails += "" | Out-String
                $FindingDetails += "No profile configured for '$TunnelIpsec'. This is a finding." | Out-String
                $FindingDetails += "" | Out-String
                $OpenFinding = $True
            }
        }
        if ($InterfaceConfig | Select-String -Pattern "^ipv4 access-group .* egress") {
            # Get the ACL name
            $ACLName = (($InterfaceConfig | Select-String -Pattern "^ipv4 access-group .* egress").ToString().Split([char[]]"") | Select-Object -Index 2)
            $ACLExtended = $ShowRunningConfig | Select-String -Pattern "^ipv4 access-list $ACLName`$"
            if (!$ACLExtended) {
                $FindingDetails += "" | Out-String
                $FindingDetails += "Inbound ACL '$ACLName' under '$Interface' is not configured." | Out-String
                $FindingDetails += "" | Out-String
                $OpenFinding = $True
            }
            else {
                # Add ACL entries to FindingDetails
                $ACLConfig = Get-Section $ShowRunningConfig $ACLExtended.ToString()
                $FindingDetails += "" | Out-String
                $FindingDetails += "If '$Interface' is an OOBM interface, review that outbound ACL '$ACLName' configured only to forward management traffic to NOC and make finding determination based on STIG check guidance." | Out-String
                $FindingDetails += "" | Out-String
                $Exception = $True
            }
        }
    }
    if (!$TunnelIpsecSet) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "No tunnel-ipsec configured." | Out-String
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

Function Get-V216770 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216770
        STIG ID    : CISC-RT-000420
        Rule ID    : SV-216770r1117237_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-NET-000019-RTR-000011
        Rule Title : The Cisco out-of-band management (OOBM) gateway router must be configured to have separate IGP instances for the managed network and management network.
        DiscussMD5 : CF022CD5F75841E20CC261A9AFE489E8
        CheckMD5   : F6CA25D87A44AFE4342B017064A364B9
        FixMD5     : 77A510E3863EAC5BC92A031D4427CF44
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
    $IGPs = @(
        'ospf',
        'isis',
        'eigrp')
    foreach ($Igp in $Igps) {
        $IgpPretty = $Igp.ToString().ToUpper()
        $IgpList = $ShowRunningConfig | Select-String -Pattern "^router $Igp"
        if ($IgpList.count -eq 0) {
            $FindingDetails += "Router $IgpPretty is not configured." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += "" | Out-String
        }
        else {
            $IgpDetails = @()
            foreach ($This_Igp in $IgpList) {
                $IgpConfig = Get-Section $ShowRunningConfig $This_Igp
                $startIndex = ($ShowRunningConfig | Select-String -Pattern "^router $Igp" | Select-Object -First 1).LineNumber[0]
                $endSTR = "^!"
                $endIndex = 0
                for ($i = $startIndex; $i -le $ShowRunningConfig.Count; $i++) {
                    $endIndex = $i + 1
                    if ($ShowRunningConfig[$i] | Select-String -Pattern $endSTR) {
                        # If the $endSTR line is found
                        break
                    }
                }
                $IgpConfig = $ShowRunningConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1)) | Out-String
                $IgpDetails += "`n$IgpConfig"
            }
            if ($IgpList.count -gt 1) {
                $FindingDetails += "This device has a single router $IgpPretty configuration. " | Out-String
                $FindingDetails += "The Cisco out-of-band management (OOBM) gateway router must be configured to have separate IGP instances for the managed network and management network." | Out-String
                $FindingDetails += "If applicable here, make finding determination based on STIG check guidance." | Out-String
                $FindingDetails += "-------------------------------------------" | Out-String
                $FindingDetails += $IgpDetails
                $FindingDetails += "" | Out-String
                $Exception = $True
            }
            else {
                $FindingDetails += '' | Out-String
                $FindingDetails += "Following $IgpPretty protocols are configured for the device."
                $FindingDetails += "VerIfy that the OOBM interface is configured to have separate IGP instances for the managed network and management network." | Out-String
                $FindingDetails += "Make finding determination based on STIG check guidance." | Out-String
                $FindingDetails += "-------------------------------------------" | Out-String
                $FindingDetails += $IgpDetails
                $FindingDetails += "" | Out-String
            }
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

Function Get-V216771 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216771
        STIG ID    : CISC-RT-000430
        Rule ID    : SV-216771r1117237_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-NET-000019-RTR-000012
        Rule Title : The Cisco out-of-band management (OOBM) gateway router must be configured to not redistribute routes between the management network routing domain and the managed network routing domain.
        DiscussMD5 : B36D2655D72BDDA49C669E1A1737E380
        CheckMD5   : 3F1C8FDA7D119BD240BA5E5836BB1512
        FixMD5     : 813547234187FBC029092B30C4E9F7CF
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
    # Get vrfs from router bgp
    $RouteBgp = ($ShowRunningConfig | Select-String -Pattern "^router bgp")
    if ($RouteBgp) {
        $startIndex = ($ShowRunningConfig | Select-String -Pattern "^router bgp" | Select-Object -First 1).LineNumber[0]
        $endSTR = "^!"
        $endIndex = 0
        for ($i = $startIndex; $i -le $ShowRunningConfig.Count; $i++) {
            $endIndex = $i + 1
            if ($ShowRunningConfig[$i] | Select-String -Pattern $endSTR) {
                # If the $endSTR line is found
                break
            }
        }
        $RouteBgpConfig = $ShowRunningConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
        $BgpVrfs = ($RouteBgpConfig | Select-String "^ vrf ")
        $VrfConfigList = @()
        $VrfNoConfigList = @()
        $BgpDetails = @()
        if ($BgpVrfs) {
            $BgpVrfConfigList = @()
            $BgpRedistributeIgps = @()
            $BgpDetails += "$RouteBgp`n"
            foreach ($BgpVrf in $BgpVrfs) {
                $BgpVrfName = ($bgpVrf).ToString().Split([char[]]"") | Select-Object -Index 2
                $startIndex = ($RouteBgpConfig | Select-String -Pattern "^ vrf $BgpVrfName" | Select-Object -First 1).LineNumber[0]
                $endSTR = "!"
                $endIndex = 0
                for ($i = $startIndex; $i -le $RouteBgpConfig.Count; $i++) {
                    $endIndex = $i + 1
                    if ($RouteBgpConfig[$i] | Select-String -Pattern $endSTR) {
                        # If the $endSTR line is found
                        break
                    }
                }
                $BgpVrfConfig = $RouteBgpConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
                $BgpVrfConfigPretty = $BgpVrfConfig | Out-String
                $BgpDetails += "$BgpVrfConfigPretty`n"
                $BgpRedistributes = $BgpVrfConfig | Select-String -Pattern "redistribute"
                if ($BgpRedistributes) {
                    foreach ($BgpRedistribute in $BgpRedistributes) {
                        $BgpIgpName = ($BgpRedistribute -replace "redistribute", "").Trim()
                        $BgpRedistributeIgps += "$BgpIgpName"
                    }
                }
                $NoBgpRedistributeIgpConfig = @()
                $RouteIgpConfigList = @()
                #Get IGP config deatils
                foreach ($BgpRedistributeIgp in $BgpRedistributeIgps) {
                    $RouteIgps = ($ShowRunningConfig | Select-String -Pattern "^router $BgpRedistributeIgp")
                    if ($RouteIgps) {
                        foreach ($RouteIgp in $RouteIgps) {
                            $startIndex = ($ShowRunningConfig | Select-String -Pattern "^router $BgpRedistributeIgp" | Select-Object -First 1).LineNumber[0]
                            $endSTR = "^!"
                            $endIndex = 0
                            for ($i = $startIndex; $i -le $ShowRunningConfig.Count; $i++) {
                                $endIndex = $i + 1
                                if ($ShowRunningConfig[$i] | Select-String -Pattern $endSTR) {
                                    # If the $endSTR line is found
                                    break
                                }
                            }
                            $RouteIgpConfig = $ShowRunningConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1)) | Out-String
                            $RouteIgpConfigList += "$RouteIgpConfig`n"
                        }
                    }
                    else {
                        $NoBgpRedistributeIgpConfig += "$BgpRedistributeIgp`n"
                    }
                }
                # Get vrf configs
                $Vrf = ($ShowRunningConfig | Select-String -Pattern "^vrf $BgpVrfName")
                if ($Vrf) {
                    $startIndex = ($ShowRunningConfig | Select-String -Pattern "^vrf $BgpVrfName" | Select-Object -First 1).LineNumber[0]
                    $endSTR = "^!"
                    $endIndex = 0
                    for ($i = $startIndex; $i -le $ShowRunningConfig.Count; $i++) {
                        $endIndex = $i + 1
                        if ($ShowRunningConfig[$i] | Select-String -Pattern $endSTR) {
                            # If the $endSTR line is found
                            break
                        }
                    }
                    $VrfConfig = $ShowRunningConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1)) | Out-String
                    #$VrfConfig = Get-Section $ShowRunningConfig $Vrf
                    $VrfConfigList += "$VrfConfig`n"
                }
                else {
                    $VrfNoConfigList += "$BgpVrfName`n"
                }
            }
        }
        else {
            $FindingDetails += "" | Out-String
            $FindingDetails += "VRFs are not configured for BGP router." | Out-String
            $Exception = $True
        }
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "BGP router is not configured for this router." | Out-String
        $Exception = $True
    }
    if ($BgpDetails) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "BGP router configured in device with VRF details." | Out-String
        $FindingDetails += "------------------------------" | Out-String
        $FindingDetails += $BgpDetails
        $Exception = $True
    }
    if ($RouteIgpConfigList.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "IGP configs" | Out-String
        $FindingDetails += "------------------------------" | Out-String
        $FindingDetails += $RouteIgpConfigList
        $Exception = $True
    }
    if ($NoBgpRedistributeIgpConfig.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following IGPs redistributed into BGP are not configured in the device. This is a finding." | Out-String
        $FindingDetails += "------------------------------" | Out-String
        $FindingDetails += $NoBgpRedistributeIgpConfig
        $OpenFinding = $True
    }
    if ($VrfConfigList.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following are the VRF configurations." | Out-String
        $FindingDetails += "------------------------------" | Out-String
        $FindingDetails += $VrfConfigList
        $Exception = $True
    }
    if ($VrfNoConfigList.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following BGP VRFs are not configured in the device. This is a finding." | Out-String
        $FindingDetails += "------------------------------" | Out-String
        $FindingDetails += $VrfNoConfigList
        $OpenFinding = $True
    }
    if ($OpenFinding) {
        $Status = "Open"
    }
    else {
        If (-Not($Exception) -and $FindingDetails.Trim().Length -gt 0) {
            $Status = "NotAFinding"
        }
        else {
            $FindingDetails += "This STIG check is to verify that Interior Gateway Protocol (IGP) instance used for the managed network does not redistribute routes " | Out-String
            $FindingDetails += "into the IGP instance used for the management network, and vice versa." | Out-String
            $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
            $Status = "Not_Reviewed"
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

Function Get-V216772 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216772
        STIG ID    : CISC-RT-000440
        Rule ID    : SV-216772r531087_rule
        CCI ID     : CCI-001097
        Rule Name  : SRG-NET-000205-RTR-000011
        Rule Title : The Cisco out-of-band management (OOBM) gateway router must be configured to block any traffic destined to itself that is not sourced from the OOBM network or the Network Operations Center (NOC).
        DiscussMD5 : 08122C1E2289ABFB8268F25E81B1AE11
        CheckMD5   : 627F87A424EEEB9DE239A1AEEB7B073D
        FixMD5     : E4F004762ECC49E2F43856D9CFD5F00F
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
    # Get interface configuration.
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
    $OOBMInterfaceList = @()
    $OtherInterfaceList = @()
    $OOBMACLList = @()
    foreach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        $InterfaceConfig = ($InterfaceConfig -split "[\r\n]+")
        $InterfaceOOBM = ($InterfaceConfig | Select-String -Pattern "ipv4 access-group .* ingress")
        if (!$InterfaceOOBM) {
            # Add interface without an inbound ACL to FindingDetails
            $OtherInterfaceList += "$Interface" + "`n"
            $Exception = $True
        }
        else {
            $OOBMInterfaceList += "$Interface" + "`n"
            $OOBMACLList += "$InterfaceOOBM" + "`n"
        }
    }
    if ($OtherInterfaceList.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Verify if the below are Out of Band Management interfaces and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "Interfaces without an inbound ACL configured:" | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += "$OtherInterfaceList"
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    if ($OOBMInterfaceList.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Review if the inbound ACLs are bound to OOB interface connecting to the OOBM backbone. Verify traffic destined to itself is only from the OOBM or NOC address space." | Out-String
        $FindingDetails += "Make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += "$OOBMACLList"
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

Function Get-V216773 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216773
        STIG ID    : CISC-RT-000450
        Rule ID    : SV-216773r531087_rule
        CCI ID     : CCI-001097
        Rule Name  : SRG-NET-000205-RTR-000012
        Rule Title : The Cisco router must be configured to only permit management traffic that ingresses and egresses the out-of-band management (OOBM) interface.
        DiscussMD5 : E19B70837C37C18058E6A6F2087AE72E
        CheckMD5   : 3EC6C6EB44779C9C8A9FD5AA29762B6C
        FixMD5     : 21A192360BDD4264D348B9F3983BE42E
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
    $OOBMInterface = $False
    # Get interface configuration.
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
    $InterfaceList = @()
    $OOBMInterface = $False
    foreach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        if (($InterfaceConfig -like "ipv4 access-group * ingress") -and ($InterfaceConfig -like "ipv4 access-group * egress")) {
            $OOBMInterface = $True
            $InterfaceList += "$Interface" + "`n"
            $ACLInName = $InterfaceConfig | Select-String -Pattern "ipv4 access-group .* ingress"
            $ACLOutName = $InterfaceConfig | Select-String -Pattern "ipv4 access-group .* egress"
            $InterfaceList += " $ACLInName`n  $ACLOutName`n`n"
        }
    }
    if ($InterfaceList -gt 0) {
        # Add ACL entries to FindingDetails
        $FindingDetails += "" | Out-String
        $FindingDetails += "Interfaces with both an ingress and egress ACL." | Out-String
        $FindingDetails += "If these are OOBM (non-dedicated) interface used for management access, verIfy that the associated ingress ACL only allows management and ICMP traffic and that the egress ACL blocks any transit traffic." | Out-String
        $FindingDetails += "This requirement is only applicable where management access to the router is via an OOBM interface which is not a true OOBM interface." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $InterfaceList
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    if (!$OOBMInterface) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "None of the interfaces has both ingress and egress ACLs configured." | Out-String
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

Function Get-V216774 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216774
        STIG ID    : CISC-RT-000460
        Rule ID    : SV-216774r531087_rule
        CCI ID     : CCI-001097
        Rule Name  : SRG-NET-000205-RTR-000013
        Rule Title : The Cisco router providing connectivity to the Network Operations Center (NOC) must be configured to forward all in-band management traffic via an IPsec tunnel.
        DiscussMD5 : 70392E55F4B80776EAC729835EA873B8
        CheckMD5   : 0BA1DED6F4CE1495C68C96E4EF7F8393
        FixMD5     : A8419C52F10047B780FFFB83A89E164E
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
    # Get interface configuration.
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
    $IPsecACLTrset = @()
    $IpsecTnlInterfaceList = @()
    $IpsecACLList = @()
    $NoIpsecInterfaceList = @()
    $NoIPsecProfile = @()
    $NoIPsecACLTrset = @()
    $NoIpsecACLList = @()
    foreach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        # Verify If tunnel profile is configured
        $TunnelIpsec = ($Interface | Select-String -Pattern "^interface tunnel-ipsec .*")
        if ($TunnelIpsec) {
            if (($InterfaceConfig | Select-String -Pattern "^profile .*")) {
                $InterfaceConfigPretty = $InterfaceConfig | Out-String
                $IpsecTnlInterfaceList += "$Interface`n$InterfaceConfigPretty`n"
                # Get the profile name
                $ProfileName = (($InterfaceConfig | Select-String -Pattern "^profile .*").ToString().Split([char[]]"") | Select-Object -Index 1)
                # Get crypto ipsec of profile
                $IPsecProfile = ($ShowRunningConfig | Select-String -Pattern "^crypto ipsec profile $ProfileName")
                if ($IPsecProfile) {
                    $IPsecProfileConfig = Get-Section $ShowRunningConfig $IPsecProfile.ToString()
                    if ($IPsecProfileConfig) {
                        # Get ACL and transform set of ipsec profile
                        $IPsecProfileConfigPretty = $IPsecProfileConfig | Out-String
                        $IPsecACLTransformset = ($IPsecProfileConfig | Select-String -Pattern "match .* transform-set .*")
                        if ($IPsecACLTransformset) {
                            $IPsecACLName = ($IPsecACLTransformset.ToString().Split([char[]]"") | Select-Object -Index 1)
                            $IPsecTrsetName = ($IPsecACLTransformset.ToString().Split([char[]]"") | Select-Object -Index 3)
                            $IPsecACL = $ShowRunningConfig | Select-String -Pattern "ipv4 access-list $IPsecACLName"
                            $IPsecTrset = $ShowRunningConfig | Select-String -Pattern "crypto ipsec transform-set $IPsecTrsetName esp-aes 256 esp-sha256-hmac"
                            if ($IPsecACL) {
                                # Add configured ACL to ACL list
                                $IpsecACLList += "$IPsecACL`n"
                            }
                            else {
                                $NoIpsecACLList += "$IPsecACLName`n"
                            }
                            # Get transform set details
                            if ($IPsecTrset) {
                                $IPsecTrsetConfig = Get-Section $ShowRunningConfig $IPsecTrset | Out-String
                                #Verify isakmp keyring and crypto isakmp policy are set
                                $IsakmpPolicy = $ShowRunningConfig | Select-String -Pattern "^crypto isakmp policy .*"
                                if ($IsakmpPolicy) {
                                    $IsakmpPolicyConfig = Get-Section $ShowRunningConfig $IsakmpPolicy | Out-String
                                    $IsakmpKeyring = $ShowRunningConfig | Select-String -Pattern "^crypto isakmp keyring .*"
                                    if ($IsakmpKeyring) {
                                        $IsakmpKeyringConfig = Get-Section $ShowRunningConfig $IsakmpKeyring | Out-String
                                        $IPsecACLTrset += "$IPsecProfile`n $IPsecProfileConfigPretty`n$IPsecTrset`n $IPsecTrsetConfig`n$IsakmpPolicy`n  $IsakmpPolicy`n$IsakmpKeyring`n  $IsakmpKeyringConfig`n`n"
                                    }
                                    else {
                                        $FindingDetails += "" | Out-String
                                        $FindingDetails += "ISAKMP KEYRING is not configured in profile. This is a finding" | Out-String
                                        $FindingDetails += "" | Out-String
                                        $OpenFinding = $True
                                    }
                                }
                                else {
                                    $FindingDetails += "" | Out-String
                                    $FindingDetails += "ISAKMP POLICY is not configured in profile. This is a finding" | Out-String
                                    $FindingDetails += "" | Out-String
                                    $OpenFinding = $True
                                }
                            }
                        }
                        else {
                            $NoIPsecACLTrset += "$IPsecProfileName`n"
                        }
                    }
                }
                else {
                    $NoIPsecProfile += "$ProfileName`n"
                }
            }
        }
        else {
            $NoIpsecInterfaceList += "$Interface`n"
        }
    }
    if ($IpsecTnlInterfaceList.Count -gt 0) {
        # Add ACL entries to FindingDetails
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following are IPSec tunnel interfaces." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $IpsecTnlInterfaceList
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "No IPSec tunnel interface set for device." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    if ($IpsecACLList.Count -gt 0) {
        # Add inbound ACL entries to FindingDetails
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following ACLs are configured for IPSec tunnel via crypto map. Review the crypto ipsec profile and review that the destinations for these ACLs are in management network." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $IpsecACLList | Out-String
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    if ($IPsecACLTrset.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following are crypto transform set, policy, keyring configured in device." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $IPsecACLTrset | Out-String
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    if ($NoIpsecInterfaceList.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "No IPSec tunnel interfaces set for following interfaces." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $NoIpsecInterfaceList
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    if ($NoIPsecProfile.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "No crypto ipsec profile was set for following. This is a finding" | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $NoIPsecProfile
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }
    if ($NoIPsecACLTrset.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "No transform-set configured for following ipsec profile. This is a finding" | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $NoIPsecACLTrset
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }
    if ($NoIpsecACLList.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following IPSec ACLs sre not configured in device. This is a finding" | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $NoIpsecACLList
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

Function Get-V216777 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216777
        STIG ID    : CISC-RT-000490
        Rule ID    : SV-216777r1117236_rule
        CCI ID     : CCI-001368
        Rule Name  : SRG-NET-000018-RTR-000002
        Rule Title : The Cisco BGP router must be configured to reject inbound route advertisements for any Bogon prefixes.
        DiscussMD5 : FE9D220A578DA4091F65B58176564E96
        CheckMD5   : 8BEA7263E1451BF4363970A2F3A75EA6
        FixMD5     : A5767B132AAD82FF2993C3789648AE6A
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
    $BogonPrefixSet = $False
    $BogonList = @()
    $BogonPolicySet = $False
    $BogonRoutePolicyList = @()
    $BogonNeighborList = @()
    $bogon_prefixes = @(
        '0.0.0.0/8 le 32',
        '10.0.0.0/8 le 32',
        '100.64.0.0/10 le 32',
        '127.0.0.0/8 le 32',
        '169.254.0.0/16 le 32',
        '172.16.0.0/12 le 32',
        '192.0.2.0/24 le 32',
        '192.88.99.0/24 le 32',
        '192.168.0.0/16 le 32',
        '198.18.0.0/15 le 32',
        '198.51.100.0/24 le 32',
        '203.0.113.0/24 le 32',
        '240.0.0.0/4 le 32',
        '224.0.0.0/4 le 32')
    $PrefixLists = $ShowRunningConfig | Select-String -Pattern "^prefix-set "
    if ($PrefixLists) {
        foreach ($PrefixList in $PrefixLists) {
            $PrefixListConfig = Get-Section $ShowRunningConfig $PrefixList
            foreach ($config in $bogon_prefixes) {
                $PrefixBogon = ($PrefixListConfig | Select-String -Pattern $config)
                if ($PrefixBogon) {
                    $BogonList += $config
                    $BogonPrefixSet = $True
                }
                else {
                    $BogonPrefixSet = $False
                    break
                }
            }
            if ($BogonPrefixSet) {
                $PrefixListName = $PrefixList.ToString().Split([char[]]"") | Select-Object -Index 1
                $RoutePolicyName = ""
                # VerIfy route-policy to verIfy filtering of BOGON prefixes
                $RoutePolicies = ($ShowRunningConfig | Select-String -Pattern "^route-policy .*")
                $BogonRoutePolicyList = @()
                foreach ($RoutePolicy in $RoutePolicies) {
                    $RoutePolicyConfig = Get-Section $ShowRunningConfig $RoutePolicy
                    $RoutePolicyConfigLine = ""
                    foreach ($line in $RoutePolicyConfig) {
                        $RoutePolicyConfigLine += $line + " "
                    }
                    if ($RoutePolicyConfigLine | Select-String -Pattern "If destination in $PrefixListName then drop Else pass endIf") {
                        $RoutePolicyName = $RoutePolicy.ToString().Split([char[]]"") | Select-Object -Index 1
                        $BogonPolicySet = $True
                        $BogonRoutePolicyList += "$RoutePolicyName`n"
                    }
                }
                if ($BogonPolicySet) {
                    # Get neighbors from router bgp
                    $RouteBgp = ($ShowRunningConfig | Select-String -Pattern "^router bgp")
                    $RouteBgpConfig = Get-Section $ShowRunningConfig $RouteBgp.ToString()
                    if ($RouteBgpConfig) {
                        $bgpNeighbors = ($RouteBgpConfig | Select-String -Pattern "^neighbor .*")
                        $BogonNeighborList = @()
                        foreach ($bgpNeighbor in $bgpNeighbors) {
                            $BgpNeighborName = ($bgpNeighbor).ToString().Split([char[]]"") | Select-Object -Index 1
                            $startIndex = ($RouteBgpConfig | Select-String -Pattern "^neighbor $BgpNeighborName" | Select-Object -First 1).LineNumber[0]
                            $endSTR = "!"
                            $endIndex = 0
                            for ($i = $startIndex; $i -le $RouteBgpConfig.Count; $i++) {
                                $endIndex = $i + 1
                                if ($RouteBgpConfig[$i] -eq $endSTR) {
                                    # If the $endSTR line is found
                                    break
                                }
                            }
                            $BgpNeighborConfig = ""
                            $BgpNeighborConfig = $RouteBgpConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
                            $BgpNeighborConfigRemote = ($BgpNeighborConfig | Select-String -Pattern "^remote-as ")
                            if ($BgpNeighborConfigRemote) {
                                foreach ($BogonRoutePolicy in $BogonRoutePolicyList) {
                                    $ThisRoutePolicy = $BogonRoutePolicy.ToString().Split([char[]]"'") | Select-Object -Index 1
                                    if ($BgpNeighborConfig | Select-String -Pattern "^route-policy $ThisRoutePolicy in") {
                                        $BogonNeighborList += "$bgpNeighbor`n"
                                    }
                                }
                            }
                        }
                    }
                }
            }
            else {
                $FindingDetails += "" | Out-String
                $FindingDetails += "BOGON prefix is not set for $PrefixList"
                $FindingDetails += "Make finding determination based on STIG check guidance." | Out-String
                $FindingDetails += "-------------------------------------------" | Out-String
                $FindingDetails += "" | Out-String
                $Exception = $True
            }
        }
        if ($BogonNeighborList.Count -gt 0 ) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Review BGP neighbors with BOGON route policy set. VerIfy that it will reject BGP routes for any Bogon prefixes."
            $FindingDetails += "Make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += $BogonNeighborList
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
        if ($BogonRoutePolicyList.Count -gt 0 ) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Following route policies are configured to reject BOGON prefixes. VerIfy they are configured for external neighbors."
            $FindingDetails += "Make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += $BogonRoutePolicyList
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "No BOGON prefix set for '$PrefixList'. Make finding determination based on STIG check guidance." | Out-String
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

Function Get-V216778 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216778
        STIG ID    : CISC-RT-000500
        Rule ID    : SV-216778r1117236_rule
        CCI ID     : CCI-001368
        Rule Name  : SRG-NET-000018-RTR-000003
        Rule Title : The Cisco BGP router must be configured to reject inbound route advertisements for any prefixes belonging to the local autonomous system (AS).
        DiscussMD5 : 15604E7A38DC562D1796E7ED9B97D40D
        CheckMD5   : 1BCADE9A5F77865479992A17FCB5B3B4
        FixMD5     : CA904B0A9DCD185C9DF070CE34BA4A0A
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
    $BgpRoutePolicyList = @()
    # Get neighbors from router bgp
    $RouteBgp = ($ShowRunningConfig | Select-String -Pattern "^router bgp")
    if ($RouteBgp) {
        $RouteBgpConfig = Get-Section $ShowRunningConfig $RouteBgp.ToString()
        $bgpNeighbors = ($RouteBgpConfig | Select-String -Pattern "^neighbor .*")
        $LocalNeighborList = @()
        $LocalNeighborList += "$RouteBgp`n"
        $BgpRoutePolicyList = @()
        foreach ($bgpNeighbor in $bgpNeighbors) {
            $BgpNeighborName = ($bgpNeighbor).ToString().Split([char[]]"") | Select-Object -Index 1
            $startIndex = ($RouteBgpConfig | Select-String -Pattern "^neighbor $BgpNeighborName" | Select-Object -First 1).LineNumber[0]
            $endSTR = "!"
            $endIndex = 0
            for ($i = $startIndex; $i -le $RouteBgpConfig.Count; $i++) {
                $endIndex = $i + 1
                if ($RouteBgpConfig[$i] -eq $endSTR) {
                    # If the $endSTR line is found
                    break
                }
            }
            $BgpNeighborConfig = $RouteBgpConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
            $BgpNeighborConfigPretty = $RouteBgpConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1)) | Out-String
            $BgpRoutePolicy = $BgpNeighborConfig | Select-String -Pattern "^route-policy .* in"
            if ($BgpRoutePolicy) {
                $BgpRoutePolicyList += $BgpRoutePolicy.ToString().Split([char[]]"") | Select-Object -Index 1
                $LocalNeighborList += "$BgpNeighborConfigPretty`n"
            }
        }
        $LocalRoutePolicyList = @()
        $NoLocalRoutePolicyList = @()
        $LocalPolicyPrefixLists = @()
        $NoLocalPolicyPrefixLists = @()
        if ($BgpRoutePolicyList.Count -gt 0) {
            foreach ($BgpRoutePolicy in $BgpRoutePolicyList) {
                $RoutePolicy = $ShowRunningConfig | Select-String -Pattern "^route-policy $BgpRoutePolicy$"
                $startIndex = ($ShowRunningConfig | Select-String -Pattern $RoutePolicy | Select-Object -First 1).LineNumber[0]
                $endSTR = "^!"
                $endIndex = 0
                for ($i = $startIndex; $i -le $ShowRunningConfig.Count; $i++) {
                    $endIndex = $i + 1
                    if ($ShowRunningConfig[$i] | Select-String -Pattern $endSTR) {
                        # If the $endSTR line is found
                        break
                    }
                }
                $RoutePolicyConfig = $ShowRunningConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1)) | Out-String
                $RoutePolicyConfigSection = Get-Section $ShowRunningConfig $RoutePolicy
                $RoutePolicyConfigLine = ""
                foreach ($line in $RoutePolicyConfigSection) {
                    $RoutePolicyConfigLine += $line + " "
                }
                $PolicyPattern1 = "If destination in .* then drop else pass endIf"
                $PolicyPattern2 = "If destination in .* then drop elseif destination in .* then drop else pass endIf"
                if (($RoutePolicyConfigLine | Select-String -Pattern $PolicyPattern1 ) -or ($RoutePolicyConfigLine | Select-String -Pattern $PolicyPattern2 )) {
                    $LocalRoutePolicyList += "$RoutePolicyConfig`n"
                    $LocalPolicyPrefixList = (($RoutePolicyConfig | Select-String -Pattern "If destination in .* then" -AllMatches) | ForEach-Object {$_.matches.value})
                    foreach ($LocalPolicyPrefix in $LocalPolicyPrefixList) {
                        $LocalPolicyPrefixName = $LocalPolicyPrefix.ToString().Split([char[]]"") | Select-Object -Index 3
                        $PolicyPrefix = $ShowRunningConfig | Select-String -Pattern "^prefix-set $LocalPolicyPrefixName"
                        if ($PolicyPrefix) {
                            $startIndex = ($ShowRunningConfig | Select-String -Pattern "^prefix-set $LocalPolicyPrefixName" | Select-Object -First 1).LineNumber[0]
                            $endSTR = "^!"
                            $endIndex = 0
                            for ($i = $startIndex; $i -le $ShowRunningConfig.Count; $i++) {
                                $endIndex = $i + 1
                                if ($ShowRunningConfig[$i] | Select-String -Pattern $endSTR) {
                                    # If the $endSTR line is found
                                    break
                                }
                            }
                            $LocalPolicyPrefixConfig = $ShowRunningConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1)) | Out-String
                            $LocalPolicyPrefixLists += "$LocalPolicyPrefixConfig`n"
                        }
                        else {
                            $NoLocalPolicyPrefixLists += "$LocalPolicyPrefixName'n"
                        }
                    }
                }
                else {
                    $NoLocalRoutePolicyList += "$RoutePolicyConfig`n"
                }
            }
        }
        if ($LocalNeighborList.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Review BGP neighbors with BOGON/LOCAL route policy set. Verify that it will reject routes belonging to the local AS." | Out-String
            $FindingDetails += "Make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += $LocalNeighborList
            $Exception = $True
        }
        if ($LocalRoutePolicyList.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Following route policies are configured in BGP neighbors to reject BOGON/LOCAL prefixes. Verify they are configured for external neighbors." | Out-String
            $FindingDetails += "Make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += $LocalRoutePolicyList
            $Exception = $True
        }
        if ($NoLocalRoutePolicyList.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Following route policies are configured in BGP neighbors. But they are not configured to reject BOGON/LOCAL prefixes." | Out-String
            $FindingDetails += "Make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += $NoLocalRoutePolicyList
            $Exception = $True
        }
        if ($LocalPolicyPrefixLists.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Following are route policy prefixes configured in BGP neighbor route policies." | Out-String
            $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += $LocalPolicyPrefixLists
            $Exception = $True
        }
        if ($NoLocalPolicyPrefixLists.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Following BGP neighbor route policy prefixes are not configured in device." | Out-String
            $FindingDetails += "This is a finding." | Out-String
            $FindingDetails += "-------------------------------------------"
            $FindingDetails += $NoLocalPolicyPrefixLists
            $Exception = $True
        }
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "No BGP router set in device."
        $FindingDetails += "Make finding determination based on STIG check guidance." | Out-String
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

Function Get-V216779 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216779
        STIG ID    : CISC-RT-000510
        Rule ID    : SV-216779r1117236_rule
        CCI ID     : CCI-001368
        Rule Name  : SRG-NET-000018-RTR-000004
        Rule Title : The Cisco BGP router must be configured to reject inbound route advertisements from a customer edge (CE) router for prefixes that are not allocated to that customer.
        DiscussMD5 : 1E452C1DD618D5C1A5EC12900C5D6A13
        CheckMD5   : D0F55DB31313FECA9EAD45448EC67E77
        FixMD5     : E3976903F37A9D029CBA9FA6764D4177
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
    $BgpRoutePolicyList = @()
    # Get neighbors from router bgp
    $RouteBgp = ($ShowRunningConfig | Select-String -Pattern "^router bgp")
    if ($RouteBgp) {
        $RouteBgpConfig = Get-Section $ShowRunningConfig $RouteBgp.ToString()
        $bgpNeighbors = ($RouteBgpConfig | Select-String -Pattern "^neighbor .*")
        $LocalNeighborList = @()
        $LocalNeighborList += "$RouteBgp`n"
        $BgpRoutePolicyList = @()
        foreach ($bgpNeighbor in $bgpNeighbors) {
            $BgpNeighborName = ($bgpNeighbor).ToString().Split([char[]]"") | Select-Object -Index 1
            $startIndex = ($RouteBgpConfig | Select-String -Pattern "^neighbor $BgpNeighborName" | Select-Object -First 1).LineNumber[0]
            $endSTR = "!"
            $endIndex = 0
            for ($i = $startIndex; $i -le $RouteBgpConfig.Count; $i++) {
                $endIndex = $i + 1
                if ($RouteBgpConfig[$i] -eq $endSTR) {
                    # If the $endSTR line is found
                    break
                }
            }
            $BgpNeighborConfig = $RouteBgpConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
            $BgpNeighborConfigPretty = $RouteBgpConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1)) | Out-String
            $BgpRoutePolicy = $BgpNeighborConfig | Select-String -Pattern "^route-policy .* in"
            if ($BgpRoutePolicy) {
                $BgpRoutePolicyList += $BgpRoutePolicy.ToString().Split([char[]]"") | Select-Object -Index 1
                $LocalNeighborList += "$BgpNeighborConfigPretty`n"
            }
        }
        $LocalRoutePolicyList = @()
        $NoLocalRoutePolicyList = @()
        $LocalPolicyPrefixLists = @()
        $NoLocalPolicyPrefixLists = @()
        if ($BgpRoutePolicyList.Count -gt 0) {
            foreach ($BgpRoutePolicy in $BgpRoutePolicyList) {
                $RoutePolicy = $ShowRunningConfig | Select-String -Pattern "^route-policy $BgpRoutePolicy$"
                $startIndex = ($ShowRunningConfig | Select-String -Pattern $RoutePolicy | Select-Object -First 1).LineNumber[0]
                $endSTR = "^!"
                $endIndex = 0
                for ($i = $startIndex; $i -le $ShowRunningConfig.Count; $i++) {
                    $endIndex = $i + 1
                    if ($ShowRunningConfig[$i] | Select-String -Pattern $endSTR) {
                        # If the $endSTR line is found
                        break
                    }
                }
                $RoutePolicyConfig = $ShowRunningConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1)) | Out-String
                $RoutePolicyConfigSection = Get-Section $ShowRunningConfig $RoutePolicy
                $RoutePolicyConfigLine = ""
                foreach ($line in $RoutePolicyConfigSection) {
                    $RoutePolicyConfigLine += $line + " "
                }
                $PolicyPattern1 = "If destination in .* then pass else drop endif"
                if ( $RoutePolicyConfigLine | Select-String -Pattern $PolicyPattern1 ) {
                    $LocalRoutePolicyList += "$RoutePolicyConfig`n"
                    $LocalPolicyPrefixList = (($RoutePolicyConfig | Select-String -Pattern "If destination in .* then" -AllMatches) | ForEach-Object {$_.matches.value})
                    foreach ($LocalPolicyPrefix in $LocalPolicyPrefixList) {
                        $LocalPolicyPrefixName = $LocalPolicyPrefix.ToString().Split([char[]]"") | Select-Object -Index 3
                        $PolicyPrefix = $ShowRunningConfig | Select-String -Pattern "^prefix-set $LocalPolicyPrefixName"
                        if ($PolicyPrefix) {
                            $startIndex = ($ShowRunningConfig | Select-String -Pattern "^prefix-set $LocalPolicyPrefixName" | Select-Object -First 1).LineNumber[0]
                            $endSTR = "^!"
                            $endIndex = 0
                            for ($i = $startIndex; $i -le $ShowRunningConfig.Count; $i++) {
                                $endIndex = $i + 1
                                if ($ShowRunningConfig[$i] | Select-String -Pattern $endSTR) {
                                    # If the $endSTR line is found
                                    break
                                }
                            }
                            $LocalPolicyPrefixConfig = $ShowRunningConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1)) | Out-String
                            $LocalPolicyPrefixLists += "$LocalPolicyPrefixConfig`n"
                        }
                        else {
                            $NoLocalPolicyPrefixLists += "$LocalPolicyPrefixName'n"
                        }
                    }
                }
                else {
                    $NoLocalRoutePolicyList += "$RoutePolicyConfig`n"
                }
            }
        }
        if ($LocalNeighborList.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Review BGP neighbors with route policy set. " | Out-String
            $FindingDetails += "Verify that it will reject reject inbound route advertisements from each CE router for prefixes that are not allocated to that customer." | Out-String
            $FindingDetails += "Make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += $LocalNeighborList
            $Exception = $True
        }
        if ($LocalRoutePolicyList.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Following route policies are configured in BGP neighbors to reject " | Out-String
            $FindingDetails += "inbound route advertisements from each CE router for prefixes that are not allocated to that customer. " | Out-String
            $FindingDetails += "Make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += $LocalRoutePolicyList
            $Exception = $True
        }
        if ($NoLocalRoutePolicyList.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Following route policies are configured in BGP neighbors." | Out-String
            $FindingDetails += "But they are not configured to reject inbound route advertisements from each CE router for prefixes that are not allocated to that customer. " | Out-String
            $FindingDetails += "Make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += $NoLocalRoutePolicyList
            $Exception = $True
        }
        if ($LocalPolicyPrefixLists.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Following are route policy prefixes configured in BGP neighbor route policies." | Out-String
            $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += $LocalPolicyPrefixLists
            $Exception = $True
        }
        if ($NoLocalPolicyPrefixLists.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Following BGP neighbor route policy prefixes are not configured in device." | Out-String
            $FindingDetails += "This is a finding." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += $NoLocalPolicyPrefixLists
            $Exception = $True
        }
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "No BGP router set in device." | Out-String
        $FindingDetails += "Make finding determination based on STIG check guidance." | Out-String
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

Function Get-V216780 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216780
        STIG ID    : CISC-RT-000520
        Rule ID    : SV-216780r1117236_rule
        CCI ID     : CCI-001368
        Rule Name  : SRG-NET-000018-RTR-000005
        Rule Title : The Cisco BGP router must be configured to reject outbound route advertisements for any prefixes that do not belong to any customers or the local autonomous system (AS).
        DiscussMD5 : 7241C6965424850C42BB97B5150E2364
        CheckMD5   : 9478CC64898BD8C3A28C7DF0C6772CA3
        FixMD5     : CAF28387B4EF1161ACC80C33905A8543
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
    $BgpRoutePolicyList = @()
    # Get neighbors from router bgp
    $RouteBgp = ($ShowRunningConfig | Select-String -Pattern "^router bgp")
    if ($RouteBgp) {
        $RouteBgpConfig = Get-Section $ShowRunningConfig $RouteBgp.ToString()
        $bgpNeighbors = ($RouteBgpConfig | Select-String -Pattern "^neighbor .*")
        $LocalNeighborList = @()
        $LocalNeighborList += "$RouteBgp`n"
        $BgpRoutePolicyList = @()
        foreach ($bgpNeighbor in $bgpNeighbors) {
            $BgpNeighborName = ($bgpNeighbor).ToString().Split([char[]]"") | Select-Object -Index 1
            $startIndex = ($RouteBgpConfig | Select-String -Pattern "^neighbor $BgpNeighborName" | Select-Object -First 1).LineNumber[0]
            $endSTR = "!"
            $endIndex = 0
            for ($i = $startIndex; $i -le $RouteBgpConfig.Count; $i++) {
                $endIndex = $i + 1
                if ($RouteBgpConfig[$i] -eq $endSTR) {
                    # If the $endSTR line is found
                    break
                }
            }
            $BgpNeighborConfig = $RouteBgpConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
            $BgpNeighborConfigPretty = $RouteBgpConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1)) | Out-String
            $BgpRoutePolicy = $BgpNeighborConfig | Select-String -Pattern "^route-policy .* out"
            if ($BgpRoutePolicy) {
                $BgpRoutePolicyList += $BgpRoutePolicy.ToString().Split([char[]]"") | Select-Object -Index 1
                $LocalNeighborList += "$BgpNeighborConfigPretty`n"
            }
        }
        $LocalRoutePolicyList = @()
        $NoLocalRoutePolicyList = @()
        $LocalPolicyPrefixLists = @()
        $NoLocalPolicyPrefixLists = @()
        if ($BgpRoutePolicyList.Count -gt 0) {
            foreach ($BgpRoutePolicy in $BgpRoutePolicyList) {
                $RoutePolicy = $ShowRunningConfig | Select-String -Pattern "^route-policy $BgpRoutePolicy$"
                $startIndex = ($ShowRunningConfig | Select-String -Pattern $RoutePolicy | Select-Object -First 1).LineNumber[0]
                $endSTR = "^!"
                $endIndex = 0
                for ($i = $startIndex; $i -le $ShowRunningConfig.Count; $i++) {
                    $endIndex = $i + 1
                    if ($ShowRunningConfig[$i] | Select-String -Pattern $endSTR) {
                        # If the $endSTR line is found
                        break
                    }
                }
                $RoutePolicyConfig = $ShowRunningConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1)) | Out-String
                $RoutePolicyConfigSection = Get-Section $ShowRunningConfig $RoutePolicy
                $RoutePolicyConfigLine = ""
                foreach ($line in $RoutePolicyConfigSection) {
                    $RoutePolicyConfigLine += $line + " "
                }
                $PolicyPattern1 = "If destination in .* then pass else drop endif"
                if ( $RoutePolicyConfigLine | Select-String -Pattern $PolicyPattern1 ) {
                    $LocalRoutePolicyList += "$RoutePolicyConfig`n"
                    $LocalPolicyPrefixList = (($RoutePolicyConfig | Select-String -Pattern "If destination in .* then" -AllMatches) | ForEach-Object {$_.matches.value})
                    foreach ($LocalPolicyPrefix in $LocalPolicyPrefixList) {
                        $LocalPolicyPrefixName = $LocalPolicyPrefix.ToString().Split([char[]]"") | Select-Object -Index 3
                        $PolicyPrefix = $ShowRunningConfig | Select-String -Pattern "^prefix-set $LocalPolicyPrefixName"
                        if ($PolicyPrefix) {
                            $startIndex = ($ShowRunningConfig | Select-String -Pattern "^prefix-set $LocalPolicyPrefixName" | Select-Object -First 1).LineNumber[0]
                            $endSTR = "^!"
                            $endIndex = 0
                            for ($i = $startIndex; $i -le $ShowRunningConfig.Count; $i++) {
                                $endIndex = $i + 1
                                if ($ShowRunningConfig[$i] | Select-String -Pattern $endSTR) {
                                    # If the $endSTR line is found
                                    break
                                }
                            }
                            $LocalPolicyPrefixConfig = $ShowRunningConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1)) | Out-String
                            $LocalPolicyPrefixLists += "$LocalPolicyPrefixConfig`n"
                        }
                        else {
                            $NoLocalPolicyPrefixLists += "$LocalPolicyPrefixName'n"
                        }
                    }
                }
                else {
                    $NoLocalRoutePolicyList += "$RoutePolicyConfig`n"
                }
            }
        }
        if ($LocalNeighborList.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Review BGP neighbors with outbound route policy set. " | Out-String
            $FindingDetails += "Verify it is accepting prefixes belonging to customers or the local autonomous system." | Out-String
            $FindingDetails += "Make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += $LocalNeighborList
            $Exception = $True
        }
        if ($LocalRoutePolicyList.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Following outbound route policies are configured in BGP neighbors." | Out-String
            $FindingDetails += "Review the route policy to determine if it is accepting prefixes belonging to customers or the local autonomous system." | Out-String
            $FindingDetails += "Make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += $LocalRoutePolicyList
            $Exception = $True
        }
        if ($NoLocalRoutePolicyList.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Following outbound route policies are configured in BGP neighbors." | Out-String
            $FindingDetails += "But they are not configured to accept prefixes belonging to customers or the local autonomous system." | Out-String
            $FindingDetails += "Make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += $NoLocalRoutePolicyList
            $Exception = $True
        }
        if ($LocalPolicyPrefixLists.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Following are route policy prefixes configured in BGP neighbor route policies." | Out-String
            $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += $LocalPolicyPrefixLists
            $Exception = $True
        }
        if ($NoLocalPolicyPrefixLists.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Following BGP neighbor route policy prefixes are not configured in device." | Out-String
            $FindingDetails += "This is a finding." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += $NoLocalPolicyPrefixLists
            $Exception = $True
        }
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "No BGP router set in device." | Out-String
        $FindingDetails += "Make finding determination based on STIG check guidance." | Out-String
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

Function Get-V216781 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216781
        STIG ID    : CISC-RT-000530
        Rule ID    : SV-216781r531087_rule
        CCI ID     : CCI-001097
        Rule Name  : SRG-NET-000205-RTR-000006
        Rule Title : The Cisco BGP router must be configured to reject outbound route advertisements for any prefixes belonging to the IP core.
        DiscussMD5 : CDC06478CEBD6B4107D41097C2DF244B
        CheckMD5   : 228C2EF3BD848F47F2910A0EC49FE17E
        FixMD5     : FCFE6921D0E1BA4A91DDE9DDC3ECB1B8
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
    $BgpRoutePolicyList = @()
    # Get neighbors from router bgp
    $RouteBgp = ($ShowRunningConfig | Select-String -Pattern "^router bgp")
    if ($RouteBgp) {
        $RouteBgpConfig = Get-Section $ShowRunningConfig $RouteBgp.ToString()
        $bgpNeighbors = ($RouteBgpConfig | Select-String -Pattern "^neighbor .*")
        $LocalNeighborList = @()
        $LocalNeighborList += "$RouteBgp`n"
        $BgpRoutePolicyList = @()
        foreach ($bgpNeighbor in $bgpNeighbors) {
            $BgpNeighborName = ($bgpNeighbor).ToString().Split([char[]]"") | Select-Object -Index 1
            $startIndex = ($RouteBgpConfig | Select-String -Pattern "^neighbor $BgpNeighborName" | Select-Object -First 1).LineNumber[0]
            $endSTR = "!"
            $endIndex = 0
            for ($i = $startIndex; $i -le $RouteBgpConfig.Count; $i++) {
                $endIndex = $i + 1
                if ($RouteBgpConfig[$i] -eq $endSTR) {
                    # If the $endSTR line is found
                    break
                }
            }
            $BgpNeighborConfig = $RouteBgpConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
            $BgpNeighborConfigPretty = $RouteBgpConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1)) | Out-String
            $BgpRoutePolicy = $BgpNeighborConfig | Select-String -Pattern "^route-policy .* out"
            if ($BgpRoutePolicy) {
                $BgpRoutePolicyList += $BgpRoutePolicy.ToString().Split([char[]]"") | Select-Object -Index 1
                $LocalNeighborList += "$BgpNeighborConfigPretty`n"
            }
        }
        $LocalRoutePolicyList = @()
        $NoLocalRoutePolicyList = @()
        $LocalPolicyPrefixLists = @()
        $NoLocalPolicyPrefixLists = @()
        if ($BgpRoutePolicyList.Count -gt 0) {
            foreach ($BgpRoutePolicy in $BgpRoutePolicyList) {
                $RoutePolicy = $ShowRunningConfig | Select-String -Pattern "^route-policy $BgpRoutePolicy$"
                $startIndex = ($ShowRunningConfig | Select-String -Pattern $RoutePolicy | Select-Object -First 1).LineNumber[0]
                $endSTR = "^!"
                $endIndex = 0
                for ($i = $startIndex; $i -le $ShowRunningConfig.Count; $i++) {
                    $endIndex = $i + 1
                    if ($ShowRunningConfig[$i] | Select-String -Pattern $endSTR) {
                        # If the $endSTR line is found
                        break
                    }
                }
                $RoutePolicyConfig = $ShowRunningConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1)) | Out-String
                $RoutePolicyConfigSection = Get-Section $ShowRunningConfig $RoutePolicy
                $RoutePolicyConfigLine = ""
                foreach ($line in $RoutePolicyConfigSection) {
                    $RoutePolicyConfigLine += $line + " "
                }
                $PolicyPattern1 = "If destination in .* then drop else pass endif"
                if ( $RoutePolicyConfigLine | Select-String -Pattern $PolicyPattern1 ) {
                    $LocalRoutePolicyList += "$RoutePolicyConfig`n"
                    $LocalPolicyPrefixList = (($RoutePolicyConfig | Select-String -Pattern "If destination in .* then" -AllMatches) | ForEach-Object {$_.matches.value})
                    foreach ($LocalPolicyPrefix in $LocalPolicyPrefixList) {
                        $LocalPolicyPrefixName = $LocalPolicyPrefix.ToString().Split([char[]]"") | Select-Object -Index 3
                        $PolicyPrefix = $ShowRunningConfig | Select-String -Pattern "^prefix-set $LocalPolicyPrefixName"
                        if ($PolicyPrefix) {
                            $startIndex = ($ShowRunningConfig | Select-String -Pattern "^prefix-set $LocalPolicyPrefixName" | Select-Object -First 1).LineNumber[0]
                            $endSTR = "^!"
                            $endIndex = 0
                            for ($i = $startIndex; $i -le $ShowRunningConfig.Count; $i++) {
                                $endIndex = $i + 1
                                if ($ShowRunningConfig[$i] | Select-String -Pattern $endSTR) {
                                    # If the $endSTR line is found
                                    break
                                }
                            }
                            $LocalPolicyPrefixConfig = $ShowRunningConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1)) | Out-String
                            $LocalPolicyPrefixLists += "$LocalPolicyPrefixConfig`n"
                        }
                        else {
                            $NoLocalPolicyPrefixLists += "$LocalPolicyPrefixName'n"
                        }
                    }
                }
                else {
                    $NoLocalRoutePolicyList += "$RoutePolicyConfig`n"
                }
            }
        }
        if ($LocalNeighborList.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Review BGP neighbors with outbound route policy set. " | Out-String
            $FindingDetails += "Verify if the router is not configured to reject outbound route advertisements for prefixes belonging to the IP core." | Out-String
            $FindingDetails += "Make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += $LocalNeighborList
            $Exception = $True
        }
        if ($LocalRoutePolicyList.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Following outbound route policies are configured in BGP neighbors." | Out-String
            $FindingDetails += "Review the route policy to determine if it is rejecting outbound route advertisements for prefixes belonging to the IP core." | Out-String
            $FindingDetails += "Make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += $LocalRoutePolicyList
            $Exception = $True
        }
        if ($NoLocalRoutePolicyList.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Following outbound route policies are configured in BGP neighbors." | Out-String
            $FindingDetails += "But they are not configured to reject outbound route advertisements for prefixes belonging to the IP core." | Out-String
            $FindingDetails += "Make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += $NoLocalRoutePolicyList
            $Exception = $True
        }
        if ($LocalPolicyPrefixLists.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Following are route policy prefixes configured in BGP neighbor route policies." | Out-String
            $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += $LocalPolicyPrefixLists
            $Exception = $True
        }
        if ($NoLocalPolicyPrefixLists.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Following BGP neighbor route policy prefixes are not configured in device." | Out-String
            $FindingDetails += "This is a finding."
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += $NoLocalPolicyPrefixLists
            $Exception = $True
        }
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "No BGP router set in device." | Out-String
        $FindingDetails += "Make finding determination based on STIG check guidance." | Out-String
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

Function Get-V216782 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216782
        STIG ID    : CISC-RT-000540
        Rule ID    : SV-216782r1117236_rule
        CCI ID     : CCI-000032
        Rule Name  : SRG-NET-000018-RTR-000006
        Rule Title : The Cisco BGP router must be configured to reject route advertisements from BGP peers that do not list their autonomous system (AS) number as the first AS in the AS_PATH attribute.
        DiscussMD5 : 99CE7EAD7813099EF08081FAAE051BCA
        CheckMD5   : BC5D535EB2B373B2CD4B768F4EFEB72F
        FixMD5     : DAF0D6C8E7C16291A4E63F2C7DF8936F
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
    # Get neighbors from router bgp
    $RouteBgp = ($ShowRunningConfig | Select-String -Pattern "^router bgp")
    if ($RouteBgp) {
        $RouteBgpConfig = Get-Section $ShowRunningConfig $RouteBgp.ToString()
        if ($RouteBgpConfig) {
            $bgpEnforceFirst = ($RouteBgpConfig | Select-String -Pattern "enforce-first-as disable")
            if ($bgpEnforceFirst) {
                $FindingDetails += "" | Out-String
                $FindingDetails += "BGP router has enforce-first-as disable." | Out-String
                $FindingDetails += "This is a finding." | Out-String
                $FindingDetails += "" | Out-String
                $OpenFinding = $True
            }
            else {
                $FindingDetails += "" | Out-String
                $FindingDetails += "Enforce-first-as disable not configured for BGP router." | Out-String
                $FindingDetails += "" | Out-String
            }
        }
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "BGP router not set for the device." | Out-String
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

Function Get-V216783 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216783
        STIG ID    : CISC-RT-000550
        Rule ID    : SV-216783r1117236_rule
        CCI ID     : CCI-000032
        Rule Name  : SRG-NET-000018-RTR-000010
        Rule Title : The Cisco BGP router must be configured to reject route advertisements from CE routers with an originating AS in the AS_PATH attribute that does not belong to that customer.
        DiscussMD5 : F925954F4D552EEAF4C06F9150AD2118
        CheckMD5   : DA8D5E75D1091769528AA2AC9FD4C800
        FixMD5     : C686C4AD2BD7CAA70EC1ACB8F54230BB
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
    $LocalPolicySet = $False
    # Verify route-policy to verify filtering of BOGON prefixes
    $RoutePolicies = ($ShowRunningConfig | Select-String -Pattern "^route-policy .*")
    $LocalRoutePolicyList = @()
    foreach ($RoutePolicy in $RoutePolicies) {
        $RoutePolicyConfig = Get-Section $ShowRunningConfig $RoutePolicy
        $RoutePolicyConfigLine = ""
        foreach ($line in $RoutePolicyConfig) {
            $RoutePolicyConfigLine += $line + " "
        }
        $PolicyPattern1 = "If as-path originates-from .* then pass Else drop endIf"
        if ($RoutePolicyConfigLine | Select-String -Pattern $PolicyPattern1) {
            $RoutePolicyName = $RoutePolicy.ToString().Split([char[]]"") | Select-Object -Index 1
            $LocalPolicySet = $True
            $LocalRoutePolicyList += "$RoutePolicyName`n"
        }
    }
    foreach ($RoutePolicy in $RoutePolicies) {
        # Get nested route policies
        $RoutePolicyConfig = Get-Section $ShowRunningConfig $RoutePolicy
        $RoutePolicyConfigLine = ""
        foreach ($line in $RoutePolicyConfig) {
            $RoutePolicyConfigLine += $line + " "
        }
        foreach ($LocalRoutePolicy in $LocalRoutePolicyList) {
            $LocalRoutePolicy = $LocalRoutePolicy.Trim()
            if ($RoutePolicyConfigLine | Select-String -Pattern "apply $LocalRoutePolicy") {
                $RoutePolicyName = $RoutePolicy.ToString().Split([char[]]"") | Select-Object -Index 1
                $LocalRoutePolicyList += "$RoutePolicyName`n"
            }
        }
    }
    if ($LocalPolicySet) {
        # Get neighbors from router bgp
        $BgpNeighborPolicyConfigList = @()
        $RouteBgp = ($ShowRunningConfig | Select-String -Pattern "^router bgp")
        if ($RouteBgp) {
            $RouteBgpConfig = Get-Section $ShowRunningConfig $RouteBgp.ToString()
            $bgpNeighbors = ($RouteBgpConfig | Select-String -Pattern "^neighbor .*")
            $LocalNeighborList = @()
            $LocalNeighborList += "$RouteBgp`n"
            foreach ($bgpNeighbor in $bgpNeighbors) {
                $BgpNeighborName = ($bgpNeighbor).ToString().Split([char[]]"") | Select-Object -Index 1
                $startIndex = ($RouteBgpConfig | Select-String -Pattern "^neighbor $BgpNeighborName" | Select-Object -First 1).LineNumber[0]
                $endSTR = "!"
                $endIndex = 0
                for ($i = $startIndex; $i -le $RouteBgpConfig.Count; $i++) {
                    $endIndex = $i + 1
                    if ($RouteBgpConfig[$i] -eq $endSTR) {
                        # If the $endSTR line is found
                        break
                    }
                }
                $BgpNeighborConfig = $RouteBgpConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
                $BgpNeighborConfigPretty = $RouteBgpConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1)) | Out-String
                foreach ($LocalRoutePolicy in $LocalRoutePolicyList) {
                    $LocalRoutePolicy = $LocalRoutePolicy.Trim()
                    if ($BgpNeighborConfig | Select-String -Pattern "^route-policy $LocalRoutePolicy in") {
                        $LocalNeighborList += "$bgpNeighborConfigPretty`n"
                        $BgpNeighborPolicy = ($ShowRunningConfig | Select-String -Pattern "^route-policy $LocalRoutePolicy")
                        if ($BgpNeighborPolicy) {
                            $startIndex = ($ShowRunningConfig | Select-String -Pattern $BgpNeighborPolicy | Select-Object -First 1).LineNumber[0]
                            $endSTR = "!"
                            $endIndex = 0
                            for ($i = $startIndex; $i -le $ShowRunningConfig.Count; $i++) {
                                $endIndex = $i + 1
                                if ($ShowRunningConfig[$i] -eq $endSTR) {
                                    # If the $endSTR line is found
                                    break
                                }
                            }
                            $BgpNeighborPolicyConfig = $ShowRunningConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1)) | Out-String
                            $BgpNeighborPolicyConfigList += "$BgpNeighborPolicyConfig`n"
                        }
                    }
                }
            }
        }
        else {
            $FindingDetails += "" | Out-String
            $FindingDetails += "BGP router not set for the device." | Out-String
        }
    }
    if ($LocalNeighborList.Count -gt 1 ) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following are the BGP neighbors. " | Out-String
        $FindingDetails += "Verify if the router is configured to reject updates from CE routers with an originating AS in the AS_PATH attribute. " | Out-String
        $FindingDetails += "Make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $LocalNeighborList
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "None of the BGP neighbors are configured to reject updates from CE routers with an originating AS in the AS_PATH attribute that does not belong to that customer. " | Out-String
    }
    if ($BgpNeighborPolicyConfigList.Count -gt 0 ) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Verify following BGP route policies permit only routes from each CE router with an originating AS in the AS_PATH attribute that does not belong to that customer." | Out-String
        $FindingDetails += "Make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $BgpNeighborPolicyConfigList
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

Function Get-V216784 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216784
        STIG ID    : CISC-RT-000560
        Rule ID    : SV-216784r856445_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-RTR-000117
        Rule Title : The Cisco BGP router must be configured to use the maximum prefixes feature to protect against route table flooding and prefix de-aggregation attacks.
        DiscussMD5 : DCD144516D9A2A6F0A3433654C5448FA
        CheckMD5   : 33F640B36E0A9F92600E75C92B758E36
        FixMD5     : 36D92DEB6FB1AF1E77DE4C256CDCB867
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
    # Get neighbors from router bgp
    $RouteBgp = ($ShowRunningConfig | Select-String -Pattern "^router bgp")
    if ($RouteBgp) {
        $BgpTokens = $RouteBgp -split '\s+'
        if ($BgpTokens.Count -ge 3) {
            $RouteBgpAsn = $RouteBgp.ToString().Split([char[]]"") | Select-Object -Index 2
            $RouteBgpConfig = Get-Section $ShowRunningConfig $RouteBgp.ToString()
            if ($RouteBgpConfig) {
                $BgpNeighbors = ($RouteBgpConfig | Select-String -Pattern "^neighbor .*")
                $MaxPrefixNeighborList = @()
                $NoDiscardMaxPrefixNeighborList = @()
                $MaxPrefixNeighborList += "$RouteBgp`n"
                $NoDiscardMaxPrefixNeighborList += "$RouteBgp`n"
                foreach ($BgpNeighbor in $BgpNeighbors) {
                    $BgpNeighborName = ($BgpNeighbor).ToString().Split([char[]]"") | Select-Object -Index 1
                    $startIndex = ($RouteBgpConfig | Select-String -Pattern "^neighbor $BgpNeighborName" | Select-Object -First 1).LineNumber[0]
                    $endSTR = "!"
                    $endIndex = 0
                    for ($i = $startIndex; $i -le $RouteBgpConfig.Count; $i++) {
                        $endIndex = $i + 1
                        if ($RouteBgpConfig[$i] -eq $endSTR) {
                            # If the $endSTR line is found
                            break
                        }
                    }
                    $BgpNeighborConfig = $RouteBgpConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
                    $BgpNeighborConfigPretty = $RouteBgpConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1)) | Out-String
                    # Continue If the neighbor is remote
                    $BgpNeighborConfigRemote = ($BgpNeighborConfig | Select-String -Pattern "^remote-as ")
                    if ($BgpNeighborConfigRemote) {
                        $NeighborTokens = $BgpNeighborConfigRemote -split '\s+'
                        if ($NeighborTokens.Count -ge 2) {
                            $NeighborAsn = $BgpNeighborConfigRemote.ToString().Split([char[]]"") | Select-Object -Index 1
                            # eBGP neighbor when ASN is different
                            if ($RouteBgpAsn -ne $NeighborAsn) {
                                $MaxPrefix = ($BgpNeighborConfig | Select-String -Pattern "maximum-prefix .*")
                                if ($MaxPrefix) {
                                    if ($MaxPrefix | Select-String -Pattern " discard-extra-paths") {
                                        $MaxPrefixNeighborList += "$BgpNeighborConfigPretty`n"
                                    }
                                    else {
                                        $NoDiscardMaxPrefixNeighborList += "$BgpNeighborConfigPretty`n"
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if ($MaxPrefixNeighborList.Count -gt 1 ) {
                $FindingDetails += "" | Out-String
                $FindingDetails += "Following eBGP neighbors have maximum-prefix configued to discard extra-path." | Out-String
                $FindingDetails += "Make finding determination based on STIG check guidance." | Out-String
                $FindingDetails += "-------------------------------------------" | Out-String
                $FindingDetails += $MaxPrefixNeighborList
                $FindingDetails += "" | Out-String
                $Exception = $True
            }
            elseif ($NoDiscardMaxPrefixNeighborList.Count -gt 1) {
                $FindingDetails += "" | Out-String
                $FindingDetails += "Following eBGP neighbors do not have maximum-prefix configued to discard extra-path." | Out-String
                $FindingDetails += "This is a finding." | Out-String
                $FindingDetails += "-------------------------------------------" | Out-String
                $FindingDetails += $NoDiscardMaxPrefixNeighborList
                $FindingDetails += "" | Out-String
                $OpenFinding = $True
            }
            else {
                $FindingDetails += "" | Out-String
                $FindingDetails += "None of the BGP neighbors has maximum-prefix configued." | Out-String
                $FindingDetails += "Make finding determination based on STIG check guidance." | Out-String
                $Exception = $True
            }
        }
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "BGP router not set for the device." | Out-String
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

Function Get-V216785 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216785
        STIG ID    : CISC-RT-000570
        Rule ID    : SV-216785r856446_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-RTR-000118
        Rule Title : The Cisco BGP router must be configured to limit the prefix size on any inbound route advertisement to /24 or the least significant prefixes issued to the customer.
        DiscussMD5 : 187F252F4E8735A2919EE37717DAF21E
        CheckMD5   : 18232DA6A386C05FC1FE45E3893E679A
        FixMD5     : E2364FA6ABB722816B769977DD01F7B0
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
    $LocalPolicySet = $False
    # Verify route-policy to verify filtering of BOGON prefixes
    $RoutePolicies = ($ShowRunningConfig | Select-String -Pattern "^route-policy .*")
    $LocalRoutePolicyList = @()
    foreach ($RoutePolicy in $RoutePolicies) {
        $RoutePolicyConfig = Get-Section $ShowRunningConfig $RoutePolicy
        $RoutePolicyConfigLine = ""
        foreach ($line in $RoutePolicyConfig) {
            $RoutePolicyConfigLine += $line + " "
        }
        $PolicyPattern1 = "if destination in .* then pass else drop endIf"
        if ($RoutePolicyConfigLine | Select-String -Pattern $PolicyPattern1) {
            $RoutePolicyName = $RoutePolicy.ToString().Split([char[]]"") | Select-Object -Index 1
            $LocalPolicySet = $True
            $LocalRoutePolicyList += "$RoutePolicyName`n"
        }
    }
    foreach ($RoutePolicy in $RoutePolicies) {
        # Get nested route policies
        $RoutePolicyConfig = Get-Section $ShowRunningConfig $RoutePolicy
        $RoutePolicyConfigLine = ""
        foreach ($line in $RoutePolicyConfig) {
            $RoutePolicyConfigLine += $line + " "
        }
        foreach ($LocalRoutePolicy in $LocalRoutePolicyList) {
            $LocalRoutePolicy = $LocalRoutePolicy.Trim()
            if ($RoutePolicyConfigLine | Select-String -Pattern "apply $LocalRoutePolicy") {
                $RoutePolicyName = $RoutePolicy.ToString().Split([char[]]"") | Select-Object -Index 1
                $LocalRoutePolicyList += "$RoutePolicyName`n"
            }
        }
    }
    if ($LocalPolicySet) {
        # Get neighbors from router bgp
        $BgpNeighborPolicyConfigList = @()
        $RouteBgp = ($ShowRunningConfig | Select-String -Pattern "^router bgp")
        if ($RouteBgp) {
            $RouteBgpConfig = Get-Section $ShowRunningConfig $RouteBgp.ToString()
            $bgpNeighbors = ($RouteBgpConfig | Select-String -Pattern "^neighbor .*")
            $LocalNeighborList = @()
            $LocalPolicyPrefixLists = @()
            $NoLocalPolicyPrefixLists = @()
            $LocalNeighborList += "$RouteBgp`n"
            foreach ($bgpNeighbor in $bgpNeighbors) {
                $BgpNeighborName = ($bgpNeighbor).ToString().Split([char[]]"") | Select-Object -Index 1
                $startIndex = ($RouteBgpConfig | Select-String -Pattern "^neighbor $BgpNeighborName" | Select-Object -First 1).LineNumber[0]
                $endSTR = "!"
                $endIndex = 0
                for ($i = $startIndex; $i -le $RouteBgpConfig.Count; $i++) {
                    $endIndex = $i + 1
                    if ($RouteBgpConfig[$i] -eq $endSTR) {
                        # If the $endSTR line is found
                        break
                    }
                }
                $BgpNeighborConfig = $RouteBgpConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
                $BgpNeighborConfigPretty = $RouteBgpConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1)) | Out-String
                foreach ($LocalRoutePolicy in $LocalRoutePolicyList) {
                    $LocalRoutePolicy = $LocalRoutePolicy.Trim()
                    if ($BgpNeighborConfig | Select-String -Pattern "^route-policy $LocalRoutePolicy in") {
                        $LocalNeighborList += "$bgpNeighborConfigPretty`n"
                        $BgpNeighborPolicy = ($ShowRunningConfig | Select-String -Pattern "^route-policy $LocalRoutePolicy")
                        if ($BgpNeighborPolicy) {
                            $startIndex = ($ShowRunningConfig | Select-String -Pattern $BgpNeighborPolicy | Select-Object -First 1).LineNumber[0]
                            $endSTR = "!"
                            $endIndex = 0
                            for ($i = $startIndex; $i -le $ShowRunningConfig.Count; $i++) {
                                $endIndex = $i + 1
                                if ($ShowRunningConfig[$i] -eq $endSTR) {
                                    # If the $endSTR line is found
                                    break
                                }
                            }
                            $BgpNeighborPolicyConfigPretty = $ShowRunningConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1)) | Out-String
                            $BgpNeighborPolicyConfigList += "$BgpNeighborPolicyConfigPretty`n"
                            $BgpNeighborPolicyConfig = $ShowRunningConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1)) | Out-String
                            $LocalPolicyPrefixList = (($BgpNeighborPolicyConfig | Select-String -Pattern "If destination in .* then" -AllMatches) | ForEach-Object {$_.matches.value})
                            foreach ($LocalPolicyPrefix in $LocalPolicyPrefixList) {
                                $LocalPolicyPrefixName = $LocalPolicyPrefix.ToString().Split([char[]]"") | Select-Object -Index 3
                                $PolicyPrefix = $ShowRunningConfig | Select-String -Pattern "^prefix-set $LocalPolicyPrefixName"
                                if ($PolicyPrefix) {
                                    $startIndex = ($ShowRunningConfig | Select-String -Pattern "^prefix-set $LocalPolicyPrefixName" | Select-Object -First 1).LineNumber[0]
                                    $endSTR = "^!"
                                    $endIndex = 0
                                    for ($i = $startIndex; $i -le $ShowRunningConfig.Count; $i++) {
                                        $endIndex = $i + 1
                                        if ($ShowRunningConfig[$i] | Select-String -Pattern $endSTR) {
                                            # If the $endSTR line is found
                                            break
                                        }
                                    }
                                    $LocalPolicyPrefixConfig = $ShowRunningConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1)) | Out-String
                                    $LocalPolicyPrefixLists += "$LocalPolicyPrefixConfig`n"
                                }
                                else {
                                    $NoLocalPolicyPrefixLists += "$LocalPolicyPrefixName'n"
                                }
                            }
                        }
                    }
                }
            }
        }
        else {
            $FindingDetails += "" | Out-String
            $FindingDetails += "BGP router not set for the device." | Out-String
        }
    }
    if ($LocalNeighborList.Count -gt 1 ) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following are the BGP neighbors. " | Out-String
        $FindingDetails += "Verify if the router is configured to reject updates from CE routers with an originating AS in the AS_PATH attribute. " | Out-String
        $FindingDetails += "Make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $LocalNeighborList
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "None of the BGP neighbors are configured to reject updates from CE routers with an originating AS in the AS_PATH attribute that does not belong to that customer. " | Out-String
    }
    if ($BgpNeighborPolicyConfigList.Count -gt 0 ) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Verify following BGP route policies permit only routes from each CE router with an originating AS in the AS_PATH attribute that does not belong to that customer." | Out-String
        $FindingDetails += "Make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $BgpNeighborPolicyConfigList
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    if ($LocalPolicyPrefixLists.Count -gt 0 ) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following are route policy prefixes configured in BGP neighbor route policies." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $LocalPolicyPrefixLists
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    if ($NoLocalPolicyPrefixLists.Count -gt 0 ) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following BGP neighbor route policy prefixes are not configured in device."
        $FindingDetails += "This is a finding."
        $FindingDetails += "-------------------------------------------"
        $FindingDetails += $NoLocalPolicyPrefixLists
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

Function Get-V216786 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216786
        STIG ID    : CISC-RT-000580
        Rule ID    : SV-216786r991935_rule
        CCI ID     : CCI-004931
        Rule Name  : SRG-NET-000512-RTR-000001
        Rule Title : The Cisco BGP router must be configured to use its loopback address as the source address for iBGP peering sessions.
        DiscussMD5 : 44D94C6E786622A798070AF093C5DD41
        CheckMD5   : 47CFEBCDB18CBD1F66ACAD2EF2F9C467
        FixMD5     : C4BE87A6FCD93FD24926076C9EFB66D6
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
    $PolicySet = $False
    $NoCustomerPolicySet = $True
    #Verify Loopback address has been configured
    # Get interface configuration.
    $LoopbackInterfaces = @()
    $LoopbackNeighbors = @()
    $LoopbackGroupNeighbors = @()
    $Interfaces = ($ShowRunningConfig | Select-String -Pattern "^interface Loopback")
    if ($Interfaces) {
        foreach ($Interface in $Interfaces) {
            $InterfaceName = $Interface.ToString().Split([char[]]"") | Select-Object -Index 1
            $LoopbackInterfaces += "$Interface" + "`n"            # Verify loopback interface is configured for bgp neighbor
            # Get neighbors from router bgp
            $RouteBgp = ($ShowRunningConfig | Select-String -Pattern "^router bgp")
            $RouteBgpConfig = Get-Section $ShowRunningConfig $RouteBgp.ToString()
            $RouteBgpSource = $RouteBgp.ToString().Split([char[]]"") | Select-Object -Index 2
            if ($RouteBgpConfig) {
                # Check neighbor groups are set for loopback interfaces
                $bgpNeighborGroups = ($RouteBgpConfig | Select-String -Pattern "^neighbor-group .*")
                $LoopbackNeighborGroupList = @()
                foreach ($bgpNeighborGroup in $bgpNeighborGroups) {
                    $BgpNeighborGroupName = ($bgpNeighborGroup).ToString().Split([char[]]"") | Select-Object -Index 1
                    $startIndex = ($RouteBgpConfig | Select-String -Pattern "^neighbor-group $BgpNeighborGroupName" | Select-Object -First 1).LineNumber[0]
                    $endSTR = "!"
                    $endIndex = 0
                    for ($i = $startIndex; $i -le $RouteBgpConfig.Count; $i++) {
                        $endIndex = $i + 1
                        if ($RouteBgpConfig[$i] -eq $endSTR) {
                            # If the $endSTR line is found
                            break
                        }
                    }
                    $BgpNeighborGroupConfig = ""
                    $BgpNeighborGroupConfig = $RouteBgpConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
                    $NeighborGroupRemoteSource = ($BgpNeighborGroupConfig | Select-String -Pattern "^remote-as $RouteBgpSource" )
                    if ($NeighborGroupRemoteSource) {
                        $BgpNeighborConfigGroupLoopbacks = ($BgpNeighborGroupConfig | Select-String -Pattern "^update-source $InterfaceName")
                        if ($BgpNeighborConfigGroupLoopbacks) {
                            $LoopbackGroupNeighbors += $bgpNeighborGroupName
                        }
                    }
                }
                # Check neighbors are set for loopback interfaces
                $bgpNeighbors = ($RouteBgpConfig | Select-String -Pattern "^neighbor .*")
                foreach ($bgpNeighbor in $bgpNeighbors) {
                    $BgpNeighborName = ($bgpNeighbor).ToString().Split([char[]]"") | Select-Object -Index 1
                    $startIndex = ($RouteBgpConfig | Select-String -Pattern "^neighbor $BgpNeighborName" | Select-Object -First 1).LineNumber[0]
                    $endSTR = "!"
                    $endIndex = 0
                    for ($i = $startIndex; $i -le $RouteBgpConfig.Count; $i++) {
                        $endIndex = $i + 1
                        if ($RouteBgpConfig[$i] -eq $endSTR) {
                            # If the $endSTR line is found
                            break
                        }
                    }
                    $BgpNeighborConfig = ""
                    $BgpNeighborConfig = $RouteBgpConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
                    $NeighborRemoteSource = ($BgpNeighborConfig | Select-String -Pattern "^remote-as $RouteBgpSource" )
                    if ($NeighborRemoteSource) {
                        $BgpNeighborConfigLoopbacks = ($BgpNeighborConfig | Select-String -Pattern "^update-source $InterfaceName")
                        if ($BgpNeighborConfigLoopbacks) {
                            foreach ($BgpNeighborConfigLoopback in $BgpNeighborConfigLoopbacks) {
                                $LoopbackNeighbors += "$BgpNeighbor`n"
                            }
                        }
                    }
                    if ($LoopbackGroupNeighbors -gt 0) {
                        foreach ($LoopbackGroupNeighbor in $LoopbackGroupNeighbors) {
                            if ($BgpNeighborConfig | Select-String -Pattern "use neighbor-group $LoopbackGroupNeighbor") {
                                $LoopbackNeighbors += "$bgpNeighbor`n"
                            }
                        }
                    }
                }
            }
        }
        if ($LoopbackInterfaces.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Loopback addresses configured for following router interfaces." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += "$LoopbackInterfaces"
            $FindingDetails += "" | Out-String
        }
        if ($LoopbackNeighbors.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Bgp neighbors configured to use its loopback address as the source address for all iBGP peering." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += "$LoopbackNeighbors"
            $FindingDetails += "" | Out-String
        }
        else {
            $FindingDetails += "" | Out-String
            $FindingDetails += "No Bgp neighbor configured to use its loopback address as the source address for all iBGP peering." | Out-String
            $FindingDetails += "This is a finding." | Out-String
            $OpenFinding = $True
        }
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Loopback addresses not configured for Router." | Out-String
        $FindingDetails += "If the router does not use its loopback address as the source address for all iBGP sessions, this is a finding." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
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

Function Get-V216787 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216787
        STIG ID    : CISC-RT-000590
        Rule ID    : SV-216787r991936_rule
        CCI ID     : CCI-004931
        Rule Name  : SRG-NET-000512-RTR-000002
        Rule Title : The Cisco MPLS router must be configured to use its loopback address as the source address for LDP peering sessions.
        DiscussMD5 : 07840DA21E9B8D28F87FBD673D88E6BC
        CheckMD5   : 459F6BF7365EBC0D49B4E18737D041DA
        FixMD5     : 1DA6E5814AAEB7826B1D332FE212B470
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
    #Verify Loopback address has been configured
    # Get interface configuration.
    $LoopbackInterfaces = @()
    $LdpPeerSet = @()
    $Interfaces = ($ShowRunningConfig | Select-String -Pattern "^interface Loopback")
    if ($Interfaces) {
        foreach ($Interface in $Interfaces) {
            $LoopbackInterfaces += "$Interface" + "`n"
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            $InterfaceIp = ($InterfaceConfig | Select-String -Pattern "^ipv4 address").ToString().Split([char[]]"") | Select-Object -Index 2
            if ($InterfaceIp) {
                # Verify loopback interface ip is configured for mpls ldp
                # Get mpls ldp
                $LdpPeer = ($ShowRunningConfig | Select-String -Pattern "^mpls ldp")
                if ($LdpPeer) {
                    $LdpPeerConfig = Get-Section $ShowRunningConfig $LdpPeer.ToString()
                    $LdpPeerIp = ($LdpPeerConfig | Select-String -Pattern "router-id $InterfaceIp")
                    if ($LdpPeerIp) {
                        $LdpPeerSet += "$LdpPeerIp`n"
                    }
                }
            }
        }
        if ($LoopbackInterfaces.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Loopback addresses configured for Router." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += "$LoopbackInterfaces"
            $FindingDetails += "" | Out-String
        }
        if ($LdpPeerSet.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Router is configured to use its loopback address for LDP peering." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += "$LdpPeerSet"
            $FindingDetails += "" | Out-String
        }
        else {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Router is not configured to use its loopback address for LDP peering." | Out-String
            $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Loopback address not configured for Router." | Out-String
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

Function Get-V216788 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216788
        STIG ID    : CISC-RT-000600
        Rule ID    : SV-216788r531087_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-RTR-000003
        Rule Title : The Cisco MPLS router must be configured to synchronize IGP and LDP to minimize packet loss when an IGP adjacency is established prior to LDP peers completing label exchange.
        DiscussMD5 : A51F8F66B369CDC74584CED06C2515B2
        CheckMD5   : A9334A3FF1723035D3DBFFEB29F1A623
        FixMD5     : AB5779D7954D283D39FB21B4F509FFDB
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
    $OspfSync = @()
    $NoOspfSync = @()
    $IsisSync = @()
    $NoIsisSync = @()
    $LdpPeer = ($ShowRunningConfig | Select-String -Pattern "^mpls ldp")
    if ($LdpPeer) {
        $OspfList = $ShowRunningConfig | Select-String -Pattern "^router ospf"
        $IsisList = $ShowRunningConfig | Select-String -Pattern "^router isis"
        if ($OspfList.count -eq 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "This device has no router ospf configurations." | Out-String
            $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
        else {
            foreach ($ospf in $OspfList) {
                $OspfConfigLine = ""
                $OspfConfig = Get-Section $ShowRunningConfig $ospf
                foreach ($line in $OspfConfig) {
                    $OspfConfigLine += $line + " "
                }
                if ($OspfConfigLine | Select-String -Pattern " mpls ldp sync") {
                    $OspfSync += "$ospf`n"
                }
                else {
                    $NoOspfSync += "$ospf`n"
                }
            }
        }
        if ($IsisList.count -eq 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "This device has no router isis configurations." | Out-String
            $FindingDetails += "" | Out-String
        }
        else {
            foreach ($isis in $IsisList) {
                $IsisConfigLine = ""
                $IsisConfig = Get-Section $ShowRunningConfig $isis
                foreach ($line in $IsisConfig) {
                    $IsisConfigLine += $line + " "
                }
                if ($IsisConfigLine | Select-String -Pattern " mpls ldp sync") {
                    $IsisSync = "$isis`n"
                }
                else {
                    $NoIsisSync = "$isis`n"
                }
            }
        }
        if ($OspfSync.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "OSPF Routers synchronized to IGP and LDP." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += "$OspfSync"
            $FindingDetails += "" | Out-String
        }
        if ($NoOspfSync.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Following OSPF Routers are not synchronized to IGP and LDP." | Out-String
            $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += "$NoOspfSync"
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
        if ($IsisSync.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "ISIS Routers synchronized to IGP and LDP." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += "$IsisSync"
            $FindingDetails += "" | Out-String
        }
        if ($NoIsisSync.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Following ISIS Routers are not synchronized to IGP and LDP." | Out-String
            $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += "$NoIsisSync"
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "MPLS LDP not configured for Router. Further checks were not done for MPLS LDP sync" | Out-String
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

Function Get-V216789 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216789
        STIG ID    : CISC-RT-000610
        Rule ID    : SV-216789r531087_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-NET-000193-RTR-000001
        Rule Title : The MPLS router with RSVP-TE enabled must be configured with message pacing to adjust maximum burst and maximum number of RSVP messages to an output queue based on the link speed and input queue size of adjacent core routers.
        DiscussMD5 : 5EA4FD82B976C564529CCF9052A1C952
        CheckMD5   : C4F4C3398DE2FEFBBA09F2A6ADF900C8
        FixMD5     : 8A8D7664CB0F464C70642C0DB056F835
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
    #Verify Loopback address has been configured
    # Get interface configuration.
    $RsvpRateLimitInterfaces = @()
    $MplsTraffic = ($ShowRunningConfig | Select-String -Pattern "^mpls traffic-eng")
    if ($MplsTraffic) {
        $MplsTrafficConfig = Get-Section $ShowRunningConfig $MplsTraffic.ToString()
        $Interface = ($MplsTrafficConfig | Select-String "^interface .*").ToString().Split([char[]]"") | Select-Object -Index 1
        if ($Interface) {
            # Verify loopback interface ip is configured for mpls ldp
            # Get mpls ld
            $RsvpCheck = ($ShowRunningConfig | Select-String -Pattern "^rsvp")
            if ($RsvpCheck) {
                $RsvpCheckConfig = Get-Section $ShowRunningConfig $RsvpCheck
                foreach ($line in $RsvpCheckConfig) {
                    $RsvpCheckConfigLine += $line + " "
                }
                $RsvpInterface = ($RsvpCheckConfig | Select-String -Pattern "^interface $Interface")
                if ($RsvpInterface) {
                    $RsvpRateLimit = ($RsvpCheckConfig | Select-String -Pattern "^signaling rate-limit rate .*")
                    if ($RsvpRateLimit) {
                        $RsvpRateLimitInterfaces = "$Interface" + "`n"
                    }
                }
                else {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "RSVP interface is not same as MPLS traffic engineering '$Interface'." | Out-String
                    $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
                    $FindingDetails += "" | Out-String
                    $Exception = $True
                }
            }
            else {
                $FindingDetails += "" | Out-String
                $FindingDetails += "RSVP is not set in device for MPLS traffic engineering '$Interface'." | Out-String
                $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
                $FindingDetails += "" | Out-String
                $Exception = $True
            }
        }
        else {
            $FindingDetails += "" | Out-String
            $FindingDetails += "No interface set for MPLS traffic engineering." | Out-String
            $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "No MPLS traffic engineering set for device." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    if ($RsvpRateLimitInterfaces.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "RSVP messages rate limit is set for following interface." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += "$RsvpRateLimitInterfaces"
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

Function Get-V216790 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216790
        STIG ID    : CISC-RT-000620
        Rule ID    : SV-216790r531087_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-RTR-000004
        Rule Title : The Cisco MPLS router must be configured to have TTL Propagation disabled.
        DiscussMD5 : DE8361C65A485067FE918DB7BC708BE1
        CheckMD5   : 6532F7C64631B9D05F086320C479A3F2
        FixMD5     : 36C900883170071A51F44D1FF35FCF96
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
    #Verify Loopback address has been configured
    # Get interface configuration.
    $MplsIpTtlProp = ($ShowRunningConfig | Select-String -Pattern "^mpls ip-ttl-propagate disable")
    if ($MplsIpTtlProp) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "MPLS IP TTL propagation is disabled for the router." | Out-String
        $FindingDetails += "" | Out-String
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "MPLS IP TTL propagation is not disabled for the router." | Out-String
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

Function Get-V216791 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216791
        STIG ID    : CISC-RT-000630
        Rule ID    : SV-216791r991937_rule
        CCI ID     : CCI-004931
        Rule Name  : SRG-NET-000512-RTR-000005
        Rule Title : The Cisco PE router must be configured to have each Virtual Routing and Forwarding (VRF) instance bound to the appropriate physical or logical interfaces to maintain traffic separation between all MPLS L3VPNs.
        DiscussMD5 : DC0F4C0B031776948852D1FAAA3328A8
        CheckMD5   : 12770C48365415A3C760DE85D3EA4DE1
        FixMD5     : D023BE7CC188BC9DDF91F3B733A098DC
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
    # Get interface configuration.
    $Interfaces = ($ShowRunningConfig | Select-String -Pattern "^interface")
    $InterfaceVrfL3Vpn = @()
    $InterfaceNoVrfL3Vpn = @()
    foreach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        if (!($InterfaceConfig | Select-String -Pattern "^shutdown")) {
            $VrfL3VpnCheck = (($InterfaceConfig | Select-String -Pattern "^vrf .*") -and ($InterfaceConfig | Select-String -Pattern "^ipv4 address .*"))
            # check If proxy-arp is enabled
            if ($VrfL3VpnCheck) {
                $InterfaceVrfL3Vpn += "$Interface" + "`n"
            }
            else {
                $InterfaceNoVrfL3Vpn += "$Interface" + "`n"
            }
        }
    }
    if ($InterfaceVrfL3Vpn -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following interfaces have VRFs configured. Review all are CE-facing interfaces and verify that the proper VRF is defined via the ip vrf forwarding command." | Out-String
        $FindingDetails += " Make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += "$InterfaceVrfL3Vpn"
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    if ($InterfaceNoVrfL3Vpn -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following interfaces do not have VRFs configured. Review all CE-facing interfaces and verify that the proper VRF is defined via the ip vrf forwarding command." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += "$InterfaceNoVrfL3Vpn"
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

Function Get-V216792 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216792
        STIG ID    : CISC-RT-000640
        Rule ID    : SV-216792r991939_rule
        CCI ID     : CCI-004931
        Rule Name  : SRG-NET-000512-RTR-000006
        Rule Title : The Cisco PE router must be configured to have each Virtual Routing and Forwarding (VRF) instance with the appropriate Route Target (RT).
        DiscussMD5 : 09644BAFE76C8F8C9E3877598D74478B
        CheckMD5   : 9ACB098824F58DED8DD9700FEBAF6A07
        FixMD5     : 1F000D9CE6A7AB63339243207511772A
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
    $Vrfs = ($ShowRunningConfig | Select-String -Pattern "^vrf ")
    $VrfWithRTList = @()
    $VrfWithNoRTList = @()
    if ($vrfs) {
        foreach ($Vrf in $Vrfs) {
            $VrfConfig = Get-Section $ShowRunningConfig $Vrf
            $VrfExportRT = ($VrfConfig | Select-String -Pattern "^export route-target" -Context 0, 1 ) -replace '>', ''
            $VrfImportRT = ($VrfConfig | Select-String -Pattern "^import route-target" -Context 0, 1 ) -replace '>', ''
            $VrfAddressFamily = ($VrfConfig | Select-String -Pattern "^address-family ipv4 .*")
            if (($VrfExportRT) -and ($VrfImportRT)) {
                $VrfWithRTList += "$Vrf`n"
                $VrfWithRTList += "$VrfAddressFamily`n"
                $VrfWithRTList += "$VrfExportRT`n"
                $VrfWithRTList += "$VrfImportRT`n"
            }
            else {
                if ((($VrfExportRT) -and (!$VrfImportRT))) {
                    $VrfWithRTList += "$Vrf`n"
                    $VrfWithRTList += "$VrfAddressFamily`n"
                    $VrfWithRTList += "$VrfExportRT`n"
                }
                else {
                    if (((!$VrfExportRT) -and ($VrfImportRT))) {
                        $VrfWithRTList += "$Vrf`n"
                        $VrfWithRTList += "$VrfAddressFamily`n"
                        $VrfWithRTList += "$VrfImportRT`n"
                    }
                    else {
                        $VrfWithNoRTList += "$Vrf`n"
                    }
                }
            }
        }
    }
    if ($VrfWithRTList -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Review following VRFs and verify that the correct RT is configured for each VRF." | Out-String
        $FindingDetails += " Make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += "$VrfWithRTList"
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    else {
        if ($VrfWithNoRTList -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Following VRFs has no RTs defined." | Out-String
            $FindingDetails += " Review and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += "$VrfWithNoRTList"
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
        else {
            $FindingDetails += "" | Out-String
            $FindingDetails += "No VRF has been configured for the router." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += "" | Out-String
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

Function Get-V216793 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216793
        STIG ID    : CISC-RT-000650
        Rule ID    : SV-216793r991940_rule
        CCI ID     : CCI-004931
        Rule Name  : SRG-NET-000512-RTR-000007
        Rule Title : The Cisco PE router must be configured to have each VRF with the appropriate Route Distinguisher (RD).
        DiscussMD5 : 691CD8FFB8F4E196E4CA5C0E909C9BBE
        CheckMD5   : E0441D9F1A9FF5254B3B92B25A52CB09
        FixMD5     : 6C2687F7468DD479E205ECD4D348EAA1
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
    # Get vrf rds from router bgp
    $RouteBgp = ($ShowRunningConfig | Select-String -Pattern "^router bgp")
    $RouteBgpConfig = Get-Section $ShowRunningConfig $RouteBgp
    $bgpVrfs = ($RouteBgpConfig | Select-String "^vrf ")
    $BgpVrfRdList = @()
    $BgpVrfNoRdList = @()
    if ($bgpVrfs) {
        foreach ($bgpVrf in $bgpVrfs) {
            $BgpVrfName = ($bgpVrf).ToString().Split([char[]]"") | Select-Object -Index 1
            $startIndex = ($RouteBgpConfig | Select-String -Pattern "^vrf $bgpVrfName" | Select-Object -First 1).LineNumber[0]
            $endSTR = "!"
            $endIndex = 0
            for ($i = $startIndex; $i -le $RouteBgpConfig.Count; $i++) {
                $endIndex = $i + 1
                if ($RouteBgpConfig[$i] -eq $endSTR) {
                    # If the $endSTR line is found
                    break
                }
            }
            $BgpVrfConfig = $RouteBgpConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
            $BgpVrfRd = ($BgpVrfConfig | Select-String -Pattern "^rd .*")
            if ($BgpVrfRd) {
                # Add vrf, rd to list
                $BgpVrfRdList += "$bgpVrf`n"
                $BgpVrfRdList += "$BgpVrfRd`n"
            }
            else {
                # Add vrf to list
                $BgpVrfNoRdList += "+$bgpVrf`n"
            }
        }
        if ($BgpVrfRdList -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Review following router VRFs and verify that the correct RD is configured for each VRF." | Out-String
            $FindingDetails += " Make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += "$BgpVrfRdList"
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
        if ($BgpVrfNoRdList -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Following router VRFs have no RD configured." | Out-String
            $FindingDetails += " Make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += "$BgpVrfNoRdList"
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "No VRFs configured for router bgp." | Out-String
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

Function Get-V216794 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216794
        STIG ID    : CISC-RT-000660
        Rule ID    : SV-216794r878124_rule
        CCI ID     : CCI-001958
        Rule Name  : SRG-NET-000343-RTR-000001
        Rule Title : The Cisco PE router providing MPLS Layer 2 Virtual Private Network (L2VPN) services must be configured to authenticate targeted Label Distribution Protocol (LDP) sessions used to exchange virtual circuit (VC) information using a FIPS-approved message authentication code algorithm.
        DiscussMD5 : 303FC40EBD15DC55D90C7E06C9924903
        CheckMD5   : 8D3C199B44F79C127EA1FE5FC185ABB8
        FixMD5     : A27F0D066812A788C62900938377C576
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
    $LdpNeighborPWList = @()
    $LdpNeighborNoPWList = @()
    # Get mpls ldp
    $LdpPeer = ($ShowRunningConfig | Select-String -Pattern "^mpls ldp")
    if ($LdpPeer) {
        $LdpPeerConfig = Get-Section $ShowRunningConfig $LdpPeer.ToString()
        $LdpNeighbors = ($LdpPeerConfig | Select-String -Pattern "^neighbor .*")
        if ($LdpNeighbors) {
            foreach ($LdpNeighbor in $LdpNeighbors) {
                $startIndex = ($LdpPeerConfig | Select-String $LdpNeighbor | Select-Object -First 1).LineNumber[0]
                $LdpNeighborPassword = $LdpPeerConfig | Select-Object -Index (($startIndex - 1)..($startIndex))
                if ($LdpNeighborPassword | Select-String -Pattern "password encrypted .*") {
                    $LdpNeighborPWList += "$LdpNeighbor`n"
                }
                else {
                    $LdpNeighborNoPWList += "$LdpNeighbor`n"
                }
            }
            if ($LdpNeighborPWList.Count -gt 0) {
                $FindingDetails += "" | Out-String
                $FindingDetails += "Following are ldp neighbor list with password encryption. The Cisco PE router providing " | Out-String
                $FindingDetails += "MPLS Layer 2 Virtual Private Network (L2VPN) services must be configured to authenticate" | Out-String
                $FindingDetails += "targeted Label Distribution Protocol (LDP) sessions used to exchange virtual circuit (VC) information " | Out-String
                $FindingDetails += "using a FIPS-approved message authentication code algorithm.." | Out-String
                $FindingDetails += "-------------------------------------------" | Out-String
                $FindingDetails += "$LdpNeighborPWList"
                $FindingDetails += "" | Out-String
            }
            if ($LdpNeighborNoPWList.Count -gt 0) {
                $FindingDetails += "" | Out-String
                $FindingDetails += "Following are ldp neighbor list without password encryption.. The Cisco PE router providing " | Out-String
                $FindingDetails += "MPLS Layer 2 Virtual Private Network (L2VPN) services must be configured to authenticate" | Out-String
                $FindingDetails += "targeted Label Distribution Protocol (LDP) sessions used to exchange virtual circuit (VC) information " | Out-String
                $FindingDetails += "using a FIPS-approved message authentication code algorithm. This is a finding" | Out-String
                $FindingDetails += "-------------------------------------------" | Out-String
                $FindingDetails += "$LdpNeighborNoPWList"
                $FindingDetails += "" | Out-String
                $OpenFinding = $True
            }
        }
        else {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Neighbors are not configured for MPLS LDP for this device." | Out-String
            $FindingDetails += "" | Out-String
        }
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "No MPLS LDP set for device." | Out-String
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

Function Get-V216795 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216795
        STIG ID    : CISC-RT-000670
        Rule ID    : SV-216795r991942_rule
        CCI ID     : CCI-004931
        Rule Name  : SRG-NET-000512-RTR-000008
        Rule Title : The Cisco PE router providing MPLS Virtual Private Wire Service (VPWS) must be configured to have the appropriate pseudowire ID for each attachment circuit.
        DiscussMD5 : E3C639A9C000F8942ADF7264DF269D39
        CheckMD5   : 49922B20818CD30DAB616DD4CD511F38
        FixMD5     : 2367292C54D3C7A9F57FA3D82556F61A
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
    $PWIdList = @()
    $XconnectGrList = @()
    $UniquePWId = $False
    # Get mpls ldp
    $L2Vpn = ($ShowRunningConfig | Select-String -Pattern "^l2vpn")
    if ($L2Vpn) {
        $L2VpnConfig = Get-Section $ShowRunningConfig $L2Vpn.ToString()
        $XConnectGrps = ($L2VpnConfig | Select-String -Pattern "^xconnect group ")
        if ($XConnectGrps) {
            $UniquePWId = $True
            foreach ($XConnectGrp in $XConnectGrps) {
                $startIndex = ($L2VpnConfig | Select-String -Pattern $XConnectGrp | Select-Object -First 1).LineNumber[0]
                $endSTR = "!"
                $endIndex = 0
                for ($i = $startIndex; $i -le $L2VpnConfig.Count; $i++) {
                    $endIndex = $i + 1
                    if ($L2VpnConfig[$i] -eq $endSTR) {
                        # If the $endSTR line is found
                        break
                    }
                }
                $XConnectGrpConfig = $L2VpnConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
                $XConnectGrpConfigPretty = $L2VpnConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1)) | Out-String
                if ($XConnectGrpConfig) {
                    $PWIdSet = ( $XConnectGrpConfig | Select-String -Pattern "neighbor ipv4 .* pw-id .*")
                    if ($PWIdSet) {
                        $PWId = ( $XConnectGrpConfig | Select-String -Pattern "neighbor ipv4 .* pw-id .*").ToString().Split([char[]]"") | Select-Object -Index 4
                        if ($PWIdList -contains $PWId) {
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "Pseudowire ID $PWId for $XConnectGrp appears to be in conflict." | Out-String
                            $FindingDetails += "Globally unique pseudowire ID should be configured. This is a finding." | Out-String
                            $FindingDetails += "-------------------------------------------" | Out-String
                            $FindingDetails += $XConnectGrpConfig | Out-String
                            $FindingDetails += "" | Out-String
                            $OpenFinding = $True
                            $UniquePWId = $False
                        }
                        else {
                            $PWIdList += $PWId
                            $XconnectGrList += "$XConnectGrpConfigPretty" + "`n"
                        }
                    }
                }
            }
            if ($UniquePWId) {
                $FindingDetails += "" | Out-String
                $FindingDetails += "Globally unique pseudowire ID has been configured for following." | Out-String
                $FindingDetails += "-------------------------------------------" | Out-String
                $FindingDetails += $XconnectGrList | Out-String
                $FindingDetails += "" | Out-String
            }
        }
        else {
            $FindingDetails += "" | Out-String
            $FindingDetails += "No L2Vpn xconnect group configured for the device." | Out-String
            $FindingDetails += "" | Out-String
        }
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "No L2Vpn configured for the device." | Out-String
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

Function Get-V216796 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216796
        STIG ID    : CISC-RT-000680
        Rule ID    : SV-216796r531087_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-RTR-000009
        Rule Title : The Cisco PE router providing Virtual Private LAN Services (VPLS) must be configured to have all attachment circuits defined to the virtual forwarding instance (VFI) with the globally unique VPN ID assigned for each customer VLAN.
        DiscussMD5 : F6BC6B30EB9BF6EDE71ADF174401E45B
        CheckMD5   : D75D79B4F6A75B55BE5B920302D82F9F
        FixMD5     : 58BAFBDF75ACD896630D1592AA392E60
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
    $InterfaceList = @()
    $VpnIdList = @()
    $L2VpnInterface = @()
    # Get interface configuration.
    $Interfaces = ($ShowRunningConfig | Select-String -Pattern "^interface .*")
    foreach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        $L2TransportCheck = (($InterfaceConfig | Select-String -Pattern "^l2transport") -or ($Interface | Select-String -Pattern " l2transport"))
        $InterfaceName = $Interface.ToString().Split([char[]]"") | Select-Object -Index 1
        # check If proxy-arp is enabled
        if ($L2TransportCheck) {
            $InterfaceList += $InterfaceName
        }
    }
    if (!$InterfaceList -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "l2transport has not been configured on any interfaces." | Out-String
        $FindingDetails += "" | Out-String
    }
    else {
        $L2Vpn = ($ShowRunningConfig | Select-String -Pattern "^l2vpn").ToString().Trim()
        if ($L2Vpn) {
            #$L2VpnConfig = Get-Section $ShowRunningConfig $L2Vpn.ToString()
            $startIndex = ($ShowRunningConfig | Select-String -Pattern $L2Vpn | Select-Object -First 1).LineNumber[0]
            $endSTR = "^!"
            $endIndex = 0
            for ($i = $startIndex; $i -le $ShowRunningConfig.Count; $i++) {
                $endIndex = $i + 1
                if ($ShowRunningConfig[$i] | Select-String -Pattern $endSTR) {
                    # If the $endSTR line is found
                    break
                }
            }
            $L2VpnConfig = $ShowRunningConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
            $L2VpnBridgeGrps = ($L2VpnConfig | Select-String -Pattern "bridge group .*")
            $AnyVpnIdSet = $False
            foreach ( $L2VpnBridgeGrp in $L2VpnBridgeGrps) {
                $startIndex = ($L2VpnConfig | Select-String -Pattern "$L2VpnBridgeGrp$" | Select-Object -First 1).LineNumber[0]
                $endSTR = "^ !"
                $endIndex = $L2VpnBridgeGrp0
                for ($i = $startIndex; $i -le $L2VpnConfig.Count; $i++) {
                    $endIndex = $i + 1
                    if ($L2VpnConfig[$i] | Select-String -Pattern $endSTR) {
                        # If the $endSTR line is found
                        break
                    }
                }
                $L2VpnBridgeGrp = $L2VpnBridgeGrp.ToString().Trim()
                $L2VpnBridgeGrpConfig = $L2VpnConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
                $L2VpnBridgeGrpConfigPretty = $L2VpnConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1)) | Out-String
                $ThisVpnId = ($L2VpnBridgeGrpConfig | Select-String -Pattern "vpn-id")
                $VpnIDSet = $False
                $L2TransportInterfaceSet = $False
                if ($ThisVpnId) {
                    $ThisVpnId = $ThisVpnId.ToString().Trim()
                    $VpnIDSet = $True
                    $AnyVpnIdSet = $True
                    #Verify bridge domain, interface is set
                    $ThisDomain = ($L2VpnBridgeGrpConfig | Select-String -Pattern "bridge-domain")
                    if ($ThisDomain) {
                        $ThisInterface = ($L2VpnBridgeGrpConfig | Select-String -Pattern "  interface .*")
                        if ($ThisInterface) {
                            if ($VpnIdList -contains $ThisVpnId) {
                                $FindingDetails += "" | Out-String
                                $FindingDetails += "VPN ID '$ThisVpnId' for '$L2VpnBridgeGrp' appears to be in conflict." | Out-String
                                $FindingDetails += "Globally unique VPN IDs for each customer using VPLS for carrier Ethernet services between multiple sites needs to be configured."
                                $FindingDetails += "This is a finding." | Out-String
                                $FindingDetails += "-------------------------------------------" | Out-String
                                $FindingDetails += $L2VpnBridgeGrpConfigPretty | Out-String
                                $FindingDetails += "" | Out-String
                                $OpenFinding = $True
                            }
                            else {
                                $VpnIdList += $ThisVpnId
                                foreach ($L2TransportInterface in $InterfaceList) {
                                    if ($L2VpnBridgeGrpConfig | Select-String -Pattern "interface $L2TransportInterface") {
                                        $L2VpnInterface += "$L2VpnBridgeGrpConfigPretty`n"
                                        $L2TransportInterfaceSet = $True
                                    }
                                }
                            }
                            if (!$L2TransportInterfaceSet) {
                                $FindingDetails += "" | Out-String
                                $FindingDetails += "Interface for '$L2VpnBridgeGrp' with '$ThisVpnId' is not set as l2transport interface." | Out-String
                                $FindingDetails += "This is a finding." | Out-String
                                $FindingDetails += "-------------------------------------------" | Out-String
                                $FindingDetails += $L2VpnBridgeGrpConfig | Out-String
                                $FindingDetails += "" | Out-String
                                $OpenFinding = $True
                            }
                        }
                        else {
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "No interface is set for '$L2VpnBridgeGrp'." | Out-String
                            $FindingDetails += "This is a finding." | Out-String
                            $FindingDetails += "-------------------------------------------" | Out-String
                            $FindingDetails += $L2VpnBridgeGrpConfig | Out-String
                            $FindingDetails += "" | Out-String
                            $OpenFinding = $True
                        }
                    }
                    else {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "No bridge-domain set for '$L2VpnBridgeGrp'." | Out-String
                        $FindingDetails += "This is a finding." | Out-String
                        $FindingDetails += "-------------------------------------------" | Out-String
                        $FindingDetails += $L2VpnBridgeGrpConfig | Out-String
                        $FindingDetails += "" | Out-String
                        $OpenFinding = $True
                    }
                }
                if ((!$AnyVpnIdSet) -and ($InterfaceList.Count -gt 0)) {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "l2transport interface has been set but no vpn-id has been set in device." | Out-String
                    $FindingDetails += "This is a finding." | Out-String
                    $FindingDetails += "-------------------------------------------" | Out-String
                    $FindingDetails += $InterfaceList | Out-String
                    $FindingDetails += "" | Out-String
                    $OpenFinding = $True
                }
            }
            if ($L2VpnInterface.Count -gt 0) {
                $FindingDetails += "" | Out-String
                $FindingDetails += "Following interfaces are set as l2transport interface with unique vpn id." | Out-String
                $FindingDetails += "-------------------------------------------" | Out-String
                $FindingDetails += $L2VpnInterface
                $FindingDetails += "" | Out-String
            }
        }
        else {
            $FindingDetails += "" | Out-String
            $FindingDetails += "L2transport interface configured butL2Vpn is not configured for the device. This is a finding" | Out-String
            $FindingDetails += "" | Out-String
            $OpenFinding = $True
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

Function Get-V216797 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216797
        STIG ID    : CISC-RT-000690
        Rule ID    : SV-216797r531087_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-RTR-000010
        Rule Title : The Cisco PE router must be configured to enforce the split-horizon rule for all pseudowires within a Virtual Private LAN Services (VPLS) bridge domain.
        DiscussMD5 : E35A10F3C7891A0D873085BA7AB0DD26
        CheckMD5   : A62541C1376826F077D35E2994FB27C0
        FixMD5     : A22FAAF68FEBE8ECFA240EF91CF0FB20
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
    $InterfaceList = @()
    $SplitHorizonSet = @()
    $NoSplitHorizonSet = @()
    # Get l2vpn
    $L2Vpn = ($ShowRunningConfig | Select-String -Pattern "^l2vpn")
    if ($L2Vpn) {
        $startIndex = ($ShowRunningConfig | Select-String -Pattern $L2Vpn | Select-Object -First 1).LineNumber[0]
        $endSTR = "^!"
        $endIndex = 0
        for ($i = $startIndex; $i -le $ShowRunningConfig.Count; $i++) {
            $endIndex = $i + 1
            if ($ShowRunningConfig[$i] | Select-String -Pattern $endSTR) {
                # If the $endSTR line is found
                break
            }
        }
        $L2VpnConfig = $ShowRunningConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
        $L2VpnBridgeGrps = ($L2VpnConfig | Select-String -Pattern "bridge group .*")
        if ($L2VpnBridgeGrps) {
            foreach ( $L2VpnBridgeGrp in $L2VpnBridgeGrps) {
                $startIndex = ($L2VpnConfig | Select-String -Pattern "$L2VpnBridgeGrp$" | Select-Object -First 1).LineNumber[0]
                $endSTR = "^ !"
                $endIndex = 0
                for ($i = $startIndex; $i -le $L2VpnConfig.Count; $i++) {
                    $endIndex = $i + 1
                    if ($L2VpnConfig[$i] | Select-String -Pattern $endSTR) {
                        # If the $endSTR line is found
                        break
                    }
                }
                $L2VpnBridgeGrp = $L2VpnBridgeGrp.ToString().Trim()
                $L2VpnBridgeGrpConfig = $L2VpnConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
                #Verify bridge domain, interface is set
                $L2VpnBridgeDomains = ($L2VpnBridgeGrpConfig | Select-String -Pattern "bridge-domain")
                if ($L2VpnBridgeDomains) {
                    foreach ($L2VpnBridgeDomain in $L2VpnBridgeDomains) {
                        $startIndex = ($L2VpnBridgeGrpConfig | Select-String -Pattern "$L2VpnBridgeDomain$" | Select-Object -First 1).LineNumber[0]
                        $endSTR = "^  !"
                        $endIndex = 0
                        for ($i = $startIndex; $i -le $L2VpnConfig.Count; $i++) {
                            $endIndex = $i + 1
                            if ($L2VpnBridgeGrpConfig[$i] | Select-String -Pattern $endSTR) {
                                # If the $endSTR line is found
                                break
                            }
                        }
                        $L2VpnBridgeDomain = $L2VpnBridgeDomain.ToString().Trim()
                        $L2VpnBridgeDomainConfig = $L2VpnBridgeGrpConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
                        $ThisInterface = ($L2VpnBridgeDomainConfig | Select-String -Pattern " interface .*")
                        if ($ThisInterface) {
                            if ($L2VpnBridgeDomainConfig | Select-String -Pattern "split-horizon group") {
                                $SplitHorizonSet += "$L2VpnBridgeGrp`n"
                                $SplitHorizonSet += "$L2VpnBridgeDomain`n`n"
                            }
                            else {
                                $NoSplitHorizonSet += "$L2VpnBridgeGrp`n"
                                $NoSplitHorizonSet += "$L2VpnBridgeDomain`n`n"
                            }
                        }
                        else {
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "No interface is set for bridge group '$L2VpnBridgeGrp' '$L2VpnBridgeDomain'." | Out-String
                            $FindingDetails += "This is a finding." | Out-String
                            $FindingDetails += "-------------------------------------------" | Out-String
                            $FindingDetails += $L2VpnBridgeGrpConfig | Out-String
                            $FindingDetails += "" | Out-String
                            $OpenFinding = $True
                        }
                    }
                }
                else {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "No bridge-domain set for '$L2VpnBridgeGrp'." | Out-String
                    $FindingDetails += "This is a finding." | Out-String
                    $FindingDetails += "-------------------------------------------" | Out-String
                    $FindingDetails += $L2VpnBridgeGrpConfig | Out-String
                    $FindingDetails += "" | Out-String
                    $OpenFinding = $True
                }
            }
        }
        else {
            $FindingDetails += "" | Out-String
            $FindingDetails += "No bridge group set for '$L2Vpn'." | Out-String
            $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += $L2VpnConfig | Out-String
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "L2Vpn is not configured for the device." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    if ($SplitHorizonSet.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Split horizon is configured on router for following bridge domains. This requirement is only applicable to a mesh VPLS topology. " | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $SplitHorizonSet | Out-String
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    if ($NoSplitHorizonSet.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Split horizon is not configured on router for following bridge domains. This requirement is only applicable to a mesh VPLS topology. " | Out-String
        $FindingDetails += "This is a finding for mesh VPLS topology."
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $NoSplitHorizonSet | Out-String
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

Function Get-V216798 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216798
        STIG ID    : CISC-RT-000700
        Rule ID    : SV-216798r531087_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-NET-000193-RTR-000002
        Rule Title : The Cisco PE router providing Virtual Private LAN Services (VPLS) must be configured to have traffic storm control thresholds on CE-facing interfaces.
        DiscussMD5 : 90BB27F85C57CD268FDA0B7D9EEFF566
        CheckMD5   : 509B84461ED16E48E7FF2AB62365FCD4
        FixMD5     : 5D990117911236608445AF644FAF4329
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
    $StormContrlSet = @()
    $NoStormContrlSet = @()
    # Get l2vpn
    $L2Vpn = ($ShowRunningConfig | Select-String -Pattern "^l2vpn")
    if ($L2Vpn) {
        $startIndex = ($ShowRunningConfig | Select-String -Pattern $L2Vpn | Select-Object -First 1).LineNumber[0]
        $endSTR = "^!"
        $endIndex = 0
        for ($i = $startIndex; $i -le $ShowRunningConfig.Count; $i++) {
            $endIndex = $i + 1
            if ($ShowRunningConfig[$i] | Select-String -Pattern $endSTR) {
                # If the $endSTR line is found
                break
            }
        }
        $L2VpnConfig = $ShowRunningConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
        $L2VpnBridgeGrps = ($L2VpnConfig | Select-String -Pattern "bridge group .*")
        if ($L2VpnBridgeGrps) {
            foreach ( $L2VpnBridgeGrp in $L2VpnBridgeGrps) {
                $L2VpnBridgeGrp = $L2VpnBridgeGrp.ToString().Trim()
                $startIndex = ($L2VpnConfig | Select-String -Pattern "$L2VpnBridgeGrp$" | Select-Object -First 1).LineNumber[0]
                $endSTR = "^ !"
                $endIndex = 0
                for ($i = $startIndex; $i -le $L2VpnConfig.Count; $i++) {
                    $endIndex = $i + 1
                    if ($L2VpnConfig[$i] | Select-String -Pattern $endSTR) {
                        # If the $endSTR line is found
                        break
                    }
                }
                $L2VpnBridgeGrp = $L2VpnBridgeGrp.ToString().Trim()
                $L2VpnBridgeGrpConfig = $L2VpnConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
                #Verify bridge domain, interface is set
                $L2VpnBridgeDomains = ($L2VpnBridgeGrpConfig | Select-String -Pattern "bridge-domain")
                if ($L2VpnBridgeDomains) {
                    foreach ($L2VpnBridgeDomain in $L2VpnBridgeDomains) {
                        $startIndex = ($L2VpnBridgeGrpConfig | Select-String -Pattern "$L2VpnBridgeDomain$" | Select-Object -First 1).LineNumber[0]
                        $endSTR = "^  !"
                        $endIndex = 0
                        for ($i = $startIndex; $i -le $L2VpnConfig.Count; $i++) {
                            $endIndex = $i + 1
                            if ($L2VpnBridgeGrpConfig[$i] | Select-String -Pattern $endSTR) {
                                # If the $endSTR line is found
                                break
                            }
                        }
                        $L2VpnBridgeDomain = $L2VpnBridgeDomain.ToString().Trim()
                        $L2VpnBridgeDomainConfig = $L2VpnBridgeGrpConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
                        $ThisInterface = ($L2VpnBridgeDomainConfig | Select-String -Pattern " interface .*")
                        if ($ThisInterface) {
                            $InterfaceString = ""
                            foreach ($Interface in $ThisInterface) {
                                $InterfaceString += $Interface.ToString().Trim() + "`n "
                            }
                            $OutputString = "$L2VpnBridgeGrp`n $L2VpnBridgeDomain`n $InterfaceString`n"
                            $L2VpnStormControl = ($L2VpnBridgeGrpConfig | Select-String -Pattern "storm-control unknown-unicast") -and ($L2VpnBridgeGrpConfig | Select-String -Pattern "storm-control multicast") -and ($L2VpnBridgeGrpConfig | Select-String -Pattern "storm-control broadcast")
                            if ($L2VpnStormControl) {
                                $StormContrlSet += $L2VpnBridgeGrpConfig
                            }
                            else {
                                $NoStormContrlSet += $OutputString
                            }
                        }
                        else {
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "No interface is set for bridge group '$L2VpnBridgeGrp' '$L2VpnBridgeDomain'." | Out-String
                            $FindingDetails += "This is a finding." | Out-String
                            $FindingDetails += "-------------------------------------------" | Out-String
                            $FindingDetails += $L2VpnBridgeGrpConfig | Out-String
                            $FindingDetails += "" | Out-String
                            $OpenFinding = $True
                        }
                    }
                }
                else {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "No bridge-domain set for '$L2VpnBridgeGrp'." | Out-String
                    $FindingDetails += "This is a finding." | Out-String
                    $FindingDetails += "-------------------------------------------" | Out-String
                    $FindingDetails += $L2VpnBridgeGrpConfig | Out-String
                    $FindingDetails += "" | Out-String
                    $OpenFinding = $True
                }
            }
        }
        else {
            $FindingDetails += "" | Out-String
            $FindingDetails += "No bridge group set for '$L2Vpn'." | Out-String
            $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += $L2VpnConfig | Out-String
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "L2Vpn is not configured for the device." | Out-String
        $FindingDetails += "" | Out-String
    }
    if ($StormContrlSet.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Storm control is enabled in l2vpn for following bridge groups. Verify the interfaces are CE-facing interfaces. " | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $StormContrlSet | Out-String
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    if ($NoStormContrlSet.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Storm control is not enabled in l2vpn for following bridge groups. If interfaces are CE-facing interfaces, storm control should be enabled. " | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $NoStormContrlSet | Out-String
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

Function Get-V216799 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216799
        STIG ID    : CISC-RT-000710
        Rule ID    : SV-216799r856448_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-RTR-000119
        Rule Title : The Cisco PE router must be configured to implement Internet Group Management Protocol (IGMP) or Multicast Listener Discovery (MLD) snooping for each Virtual Private LAN Services (VPLS) bridge domain.
        DiscussMD5 : 6D93EE9D6B47AEE77CB69F2BE0DC346B
        CheckMD5   : 2D69A3C205FF0D5D8FCAD3A4562B2E72
        FixMD5     : B7FEA912729A22CC48E8463D265E8E87
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
    $IGMPSnoopingList = @()
    $NoIGMPSnoopingList = @()
    # Get l2vpn
    $L2Vpn = ($ShowRunningConfig | Select-String -Pattern "^l2vpn")
    if ($L2Vpn) {
        $startIndex = ($ShowRunningConfig | Select-String -Pattern $L2Vpn | Select-Object -First 1).LineNumber[0]
        $endSTR = "^!"
        $endIndex = 0
        for ($i = $startIndex; $i -le $ShowRunningConfig.Count; $i++) {
            $endIndex = $i + 1
            if ($ShowRunningConfig[$i] | Select-String -Pattern $endSTR) {
                # If the $endSTR line is found
                break
            }
        }
        $L2VpnConfig = $ShowRunningConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
        $L2VpnBridgeGrps = ($L2VpnConfig | Select-String -Pattern "bridge group .*")
        if ($L2VpnBridgeGrps) {
            foreach ( $L2VpnBridgeGrp in $L2VpnBridgeGrps) {
                $L2VpnBridgeGrp = $L2VpnBridgeGrp.ToString().Trim()
                $startIndex = ($L2VpnConfig | Select-String -Pattern "$L2VpnBridgeGrp$" | Select-Object -First 1).LineNumber[0]
                $endSTR = "^ !"
                $endIndex = 0
                for ($i = $startIndex; $i -le $L2VpnConfig.Count; $i++) {
                    $endIndex = $i + 1
                    if ($L2VpnConfig[$i] | Select-String -Pattern $endSTR) {
                        # If the $endSTR line is found
                        break
                    }
                }
                $L2VpnBridgeGrp = $L2VpnBridgeGrp.ToString().Trim()
                $L2VpnBridgeGrpConfig = $L2VpnConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
                #Verify bridge domain, interface is set
                $L2VpnBridgeDomains = ($L2VpnBridgeGrpConfig | Select-String -Pattern "bridge-domain")
                if ($L2VpnBridgeDomains) {
                    foreach ($L2VpnBridgeDomain in $L2VpnBridgeDomains) {
                        $startIndex = ($L2VpnBridgeGrpConfig | Select-String -Pattern "$L2VpnBridgeDomain$" | Select-Object -First 1).LineNumber[0]
                        $endSTR = "^  !"
                        $endIndex = 0
                        for ($i = $startIndex; $i -le $L2VpnConfig.Count; $i++) {
                            $endIndex = $i + 1
                            if ($L2VpnBridgeGrpConfig[$i] | Select-String -Pattern $endSTR) {
                                # If the $endSTR line is found
                                break
                            }
                        }
                        $L2VpnBridgeDomain = $L2VpnBridgeDomain.ToString().Trim()
                        $L2VpnBridgeDomainConfig = $L2VpnBridgeGrpConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
                        $ThisInterface = ($L2VpnBridgeDomainConfig | Select-String -Pattern " interface .*")
                        if ($ThisInterface) {
                            $InterfaceString = ""
                            foreach ($Interface in $ThisInterface) {
                                $InterfaceString += $Interface.ToString().Trim() + "`n "
                            }
                            $OutputString = "$L2VpnBridgeGrp`n $L2VpnBridgeDomain`n $InterfaceString`n"
                            $L2VpnIGMPSnooping = ($L2VpnBridgeGrpConfig | Select-String -Pattern "igmp snooping profile default")
                            if ($L2VpnIGMPSnooping) {
                                $IGMPSnoopingList += $OutputString
                            }
                            else {
                                $NoIGMPSnoopingList += $OutputString
                            }
                        }
                        else {
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "No interface is set for bridge group '$L2VpnBridgeGrp' '$L2VpnBridgeDomain'." | Out-String
                            $FindingDetails += "This is a finding." | Out-String
                            $FindingDetails += "-------------------------------------------" | Out-String
                            $FindingDetails += $L2VpnBridgeGrpConfig | Out-String
                            $FindingDetails += "" | Out-String
                            $OpenFinding = $True
                        }
                    }
                }
                else {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "No bridge-domain set for '$L2VpnBridgeGrp'." | Out-String
                    $FindingDetails += "This is a finding." | Out-String
                    $FindingDetails += "-------------------------------------------" | Out-String
                    $FindingDetails += $L2VpnBridgeGrpConfig | Out-String
                    $FindingDetails += "" | Out-String
                    $OpenFinding = $True
                }
            }
        }
        else {
            $FindingDetails += "" | Out-String
            $FindingDetails += "No bridge group set for '$L2Vpn'." | Out-String
            $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += $L2VpnConfig | Out-String
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "L2Vpn is not configured for the device." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    if ($IGMPSnoopingList.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "IGMP or MLD snooping has been configured for following" | Out-String
        $FindingDetails += "Snooping should be configured for IPv4 and IPv6 multicast traffic respectively for each VPLS bridge domain. " | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $IGMPSnoopingList | Out-String
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    if ($NoIGMPSnoopingList.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "IGMP or MLD snooping has not been configured for following in l2vpn. " | Out-String
        $FindingDetails += "IGMP or MLD snooping should be configured for IPv4 and IPv6 multicast traffic respectively for each VPLS bridge domain." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $NoIGMPSnoopingList | Out-String
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

Function Get-V216800 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216800
        STIG ID    : CISC-RT-000720
        Rule ID    : SV-216800r531087_rule
        CCI ID     : CCI-001094
        Rule Name  : SRG-NET-000192-RTR-000002
        Rule Title : The Cisco PE router must be configured to limit the number of MAC addresses it can learn for each Virtual Private LAN Services (VPLS) bridge domain.
        DiscussMD5 : 6AB86FD5C6467F69B158A88BAFB9951D
        CheckMD5   : 3585596F3F11F296E3B153F6E12EE17F
        FixMD5     : 9A539089CA2A6E2BB7A02DD734AB1CDA
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
    $MaxMacSet = @()
    $NoMaxMacSet = @()
    # Get l2vpn
    $L2Vpn = ($ShowRunningConfig | Select-String -Pattern "^l2vpn")
    if ($L2Vpn) {
        $startIndex = ($ShowRunningConfig | Select-String -Pattern $L2Vpn | Select-Object -First 1).LineNumber[0]
        $endSTR = "^!"
        $endIndex = 0
        for ($i = $startIndex; $i -le $ShowRunningConfig.Count; $i++) {
            $endIndex = $i + 1
            if ($ShowRunningConfig[$i] | Select-String -Pattern $endSTR) {
                # If the $endSTR line is found
                break
            }
        }
        $L2VpnConfig = $ShowRunningConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
        $L2VpnBridgeGrps = ($L2VpnConfig | Select-String -Pattern "bridge group .*")
        if ($L2VpnBridgeGrps) {
            foreach ( $L2VpnBridgeGrp in $L2VpnBridgeGrps) {
                $L2VpnBridgeGrp = $L2VpnBridgeGrp.ToString().Trim()
                $startIndex = ($L2VpnConfig | Select-String -Pattern "$L2VpnBridgeGrp$" | Select-Object -First 1).LineNumber[0]
                $endSTR = "^ !"
                $endIndex = 0
                for ($i = $startIndex; $i -le $L2VpnConfig.Count; $i++) {
                    $endIndex = $i + 1
                    if ($L2VpnConfig[$i] | Select-String -Pattern $endSTR) {
                        # If the $endSTR line is found
                        break
                    }
                }
                $L2VpnBridgeGrp = $L2VpnBridgeGrp.ToString().Trim()
                $L2VpnBridgeGrpConfig = $L2VpnConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
                $L2VpnBridgeGrpConfigPretty = $L2VpnConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1)) | Out-String
                #Verify bridge domain, interface is set
                $L2VpnBridgeDomains = ($L2VpnBridgeGrpConfig | Select-String -Pattern "bridge-domain")
                if ($L2VpnBridgeDomains) {
                    foreach ($L2VpnBridgeDomain in $L2VpnBridgeDomains) {
                        $startIndex = ($L2VpnBridgeGrpConfig | Select-String -Pattern "$L2VpnBridgeDomain$" | Select-Object -First 1).LineNumber[0]
                        $endSTR = "^  !"
                        $endIndex = 0
                        for ($i = $startIndex; $i -le $L2VpnConfig.Count; $i++) {
                            $endIndex = $i + 1
                            if ($L2VpnBridgeGrpConfig[$i] | Select-String -Pattern $endSTR) {
                                # If the $endSTR line is found
                                break
                            }
                        }
                        $L2VpnBridgeDomain = $L2VpnBridgeDomain.ToString().Trim()
                        $L2VpnBridgeDomainConfig = $L2VpnBridgeGrpConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
                        $L2VpnBridgeDomainConfigPretty = $L2VpnBridgeGrpConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1)) | Out-String
                        $ThisInterface = ($L2VpnBridgeDomainConfig | Select-String -Pattern " interface .*")
                        if ($ThisInterface) {
                            $InterfaceString = ""
                            foreach ($Interface in $ThisInterface) {
                                $InterfaceString += $Interface.ToString().Trim() + "`n "
                            }
                            $OutputString = "$L2VpnBridgeGrp`n $L2VpnBridgeDomain`n $InterfaceString`n"
                            $L2VpnMaxLimit = ($L2VpnBridgeDomainConfig | Select-String -Pattern "mac") -and ($L2VpnBridgeDomainConfig | Select-String -Pattern "limit") -and ($L2VpnBridgeDomainConfig | Select-String -Pattern "maximum .*")
                            if ($L2VpnMaxLimit) {
                                $MaxMacSet += $L2VpnBridgeGrpConfigPretty + "`n"
                            }
                            else {
                                $NoMaxMacSet += $L2VpnBridgeGrpConfigPretty + "`n"
                            }
                        }
                        else {
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "No interface is set for bridge group '$L2VpnBridgeGrp' '$L2VpnBridgeDomain'." | Out-String
                            $FindingDetails += "This is a finding." | Out-String
                            $FindingDetails += "-------------------------------------------" | Out-String
                            $FindingDetails += $L2VpnBridgeGrpConfig | Out-String
                            $FindingDetails += "" | Out-String
                            $OpenFinding = $True
                        }
                    }
                }
                else {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "No bridge-domain set for '$L2VpnBridgeGrp'." | Out-String
                    $FindingDetails += "This is a finding." | Out-String
                    $FindingDetails += "-------------------------------------------" | Out-String
                    $FindingDetails += $L2VpnBridgeGrpConfig | Out-String
                    $FindingDetails += "" | Out-String
                    $OpenFinding = $True
                }
            }
        }
        else {
            $FindingDetails += "" | Out-String
            $FindingDetails += "No bridge group set for '$L2Vpn'." | Out-String
            $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += $L2VpnConfig | Out-String
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "L2Vpn is not configured for the device." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    if ($MaxMacSet.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "MAC address learning limit is configured for following bridge domain in l2vpn. Verify following are VPLS bridge domain. " | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $MaxMacSet | Out-String
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    if ($NoMaxMacSet.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "MAC address learning limit is not configured for following bridge domain in l2vpn." | Out-String
        $FindingDetails += "If following are VPLS bridge domain, MAC address learning limit should be configured. " | Out-String
        $FindingDetails += "Review and make finding determination not based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $NoMaxMacSet | Out-String
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

Function Get-V216801 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216801
        STIG ID    : CISC-RT-000730
        Rule ID    : SV-216801r531087_rule
        CCI ID     : CCI-001097
        Rule Name  : SRG-NET-000205-RTR-000007
        Rule Title : The Cisco PE router must be configured to block any traffic that is destined to IP core infrastructure.
        DiscussMD5 : 0DAA9B297DEBEBE165DF969AD8F2374E
        CheckMD5   : C4D01B8F3A68244A53B46C1C3FF6BF31
        FixMD5     : 55C3B68C05E61D55ED82B00166829E93
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
    # Get interface configuration.
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
    $IngressInterfaceList = @()
    $OtherInterfaceList = @()
    $IngressACLList = @()
    $IngressInterfaceSet = $False
    foreach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        $IngressInterface = ($InterfaceConfig | Select-String -Pattern "ipv4 access-group .* ingress")
        if ($IngressInterface) {
            $ACLName = $IngressInterface.ToString().Split([char[]]"") | Select-Object -Index 2
            $ACLExtended = $ShowRunningConfig | Select-String -Pattern "^ipv4 access-list $ACLName"
            if ($ACLExtended) {
                $IngressInterfaceList += "$Interface" + "`n"
                $ACLInName = $IngressInterface.ToString().Split([char[]]"") | Select-Object -Index 2
                $IngressACLList += "$ACLInName" + "`n"
                $IngressInterfaceSet = $True
            }
            else {
                $FindingDetails += "" | Out-String
                $FindingDetails += "Ingress ACL '$ACLName' for '$Interface' is not configured in the system. This is a finding" | Out-String
                $FindingDetails += "" | Out-String
                $OpenFinding = $True
            }
        }
        else {
            # Add interface without an inbound ACL to FindingDetails
            $OtherInterfaceList += "$Interface" + "`n"
        }
    }
    if ($IngressInterfaceList.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Interfaces below has ingress ACL configured. Verify they are external or CE-facing interfaces." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += "$IngressInterfaceList"
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    if ($OtherInterfaceList.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Interfaces below are not configured with ingress ACL. If they are external or CE-facing interfaces, ingress ACL should be configured for them." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "Interfaces without an inbound ACL configured:" | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += "$OtherInterfaceList"
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    if (!$IngressInterfaceSet) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "No ingress ACL has been configured in the device for any interface." | Out-String
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

Function Get-V216802 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216802
        STIG ID    : CISC-RT-000740
        Rule ID    : SV-216802r531087_rule
        CCI ID     : CCI-001097
        Rule Name  : SRG-NET-000205-RTR-000008
        Rule Title : The Cisco PE router must be configured with Unicast Reverse Path Forwarding (uRPF) loose mode enabled on all CE-facing interfaces.
        DiscussMD5 : AFC3F12538B130296907DCA02F0CB5C3
        CheckMD5   : FD2091E2033BBD2FBF8172C5D47003C8
        FixMD5     : A7B1D120766C42D066B9F2CE341CF56E
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
    # Get interface configuration.
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
    $UrpfInterfaceList = @()
    $OtherInterfaceList = @()
    foreach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        if (!($InterfaceConfig | Select-String -Pattern "^shutdown")) {
            $UrpfInterface = ($InterfaceConfig | Select-String -Pattern "ipv4 verify unicast source reachable-via any")
            if (!$UrpfInterface) {
                # Add interface without an inbound ACL to FindingDetails
                $OtherInterfaceList += "$Interface" + "`n"
                $Exception = $True
            }
            else {
                $UrpfInterfaceList += "$Interface" + "`n"
            }
        }
    }
    if ($OtherInterfaceList.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Interfaces below do not have uRPF loose mode enabled.Verify they are not CE facing interfaces and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += "$OtherInterfaceList"
        $FindingDetails += "" | Out-String
    }
    if ($UrpfInterfaceList.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Interfaces below have uRPF loose mode enabled. Verify they are CE-facing interfaces and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += "$UrpfInterfaceList"
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

Function Get-V216804 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216804
        STIG ID    : CISC-RT-000760
        Rule ID    : SV-216804r917439_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-NET-000193-RTR-000113
        Rule Title : The Cisco PE router must be configured to enforce a Quality-of-Service (QoS) policy to provide preferred treatment for mission-critical applications.
        DiscussMD5 : 3ED253A8C7E48F6B7785F67864C65759
        CheckMD5   : 957201828247C45CF755D7D242904E90
        FixMD5     : 11F5236A7CE403A3FF859B13D9D00E95
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
    $ClassMapList = @()
    $PolicyMapSet = $False
    $PolicyInterface = @()
    $InterfaceNoPolicy = @()
    #Get map policy
    $MapPolicy = $ShowRunningConfig | Select-String -Pattern "^policy-map "
    if ($MapPolicy) {
        $MapPolicyConfig = Get-Section $ShowRunningConfig $MapPolicy
        $MapPolicyConfigPretty = $MapPolicyConfig | Out-String
        $MapPolicyName = $MapPolicy.ToString().Split([char[]]"") | Select-Object -Index 1
        # Get Interfaces
        $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface "
        if ($Interfaces) {
            foreach ($Interface in $Interfaces) {
                $InterfaceName = $Interface.ToString().Split([char[]]"") | Select-Object -Index 1
                $InterfaceConfig = Get-Section $ShowRunningConfig $Interface
                $InterfaceConfigPretty = $InterfaceConfig | Out-String
                if ($InterfaceConfig | Select-String -Pattern "service-policy output $MapPolicyName") {
                    $PolicyInterface += "$InterfaceConfigPretty" + "`n"
                    $PolicyMapSet = $True
                }
                else {
                    $InterfaceNoPolicy += "$Interface" + "`n"
                }
            }
        }
        else {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Policy map for class maps $MapPolicyName exists. But no interfaces set for device. This is a finding."
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += "$MapPolicy"
            $FindingDetails += "" | Out-String
            $OpenFinding = $True
        }
        # Get class maps
        if ($PolicyMapSet) {
            $ClassMaps = $ShowRunningConfig | Select-String -Pattern "^class-map match-all "
            if ($ClassMaps) {
                foreach ($ClassMap in $ClassMaps) {
                    $ClassMapConfig = Get-Section $ShowRunningConfig $ClassMap | Out-String
                    $ClassMapList += "$ClassMap`n$ClassMapConfig`n"
                }
            }
        }
        if ($MapPolicyConfig) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Following is the policy map configured in device. Verify that the policy map reserves the bandwidth for each traffic type. " | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += "$MapPolicy" | Out-String
            $FindingDetails += "$MapPolicyConfigPretty" | Out-String
            $FindingDetails += "" | Out-String
        }
        if ($ClassMapList.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Class maps below are configured in device. Verify that the class-maps are configured to match on DSCP values. " | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += "$ClassMapList" | Out-String
            $FindingDetails += "" | Out-String
        }
        if ($PolicyInterface -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "$MapPolicy for class maps is set for following interfaces." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += "$PolicyInterface" | Out-String
            $FindingDetails += "" | Out-String
        }
        else {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Policy map $MapPolicy for class maps is not bound to any interface. This is a finding."
            $FindingDetails += "" | Out-String
            $OpenFinding = $True
        }
        if ($InterfaceNoPolicy.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Following interfaces has no output service $MapPolicy set."
            $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += "$InterfaceNoPolicy" | Out-String
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "No policy map set in router. Review and make finding determination based on STIG check guidance." | Out-String
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

Function Get-V216805 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216805
        STIG ID    : CISC-RT-000770
        Rule ID    : SV-216805r917442_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-NET-000193-RTR-000114
        Rule Title : The Cisco P router must be configured to enforce a Quality-of-Service (QoS) policy to provide preferred treatment for mission-critical applications.
        DiscussMD5 : 3ED253A8C7E48F6B7785F67864C65759
        CheckMD5   : F784C74BEF0697D3C8398715E7C031C8
        FixMD5     : 11F5236A7CE403A3FF859B13D9D00E95
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
    $ClassMapList = @()
    $PolicyMapSet = $False
    $PolicyInterface = @()
    $InterfaceNoPolicy = @()
    #Get map policy
    $MapPolicy = $ShowRunningConfig | Select-String -Pattern "^policy-map "
    if ($MapPolicy) {
        $MapPolicyConfig = Get-Section $ShowRunningConfig $MapPolicy
        $MapPolicyConfigPretty = $MapPolicyConfig | Out-String
        $MapPolicyName = $MapPolicy.ToString().Split([char[]]"") | Select-Object -Index 1
        # Get Interfaces
        $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface "
        if ($Interfaces) {
            foreach ($Interface in $Interfaces) {
                $InterfaceName = $Interface.ToString().Split([char[]]"") | Select-Object -Index 1
                $InterfaceConfig = Get-Section $ShowRunningConfig $Interface
                $InterfaceConfigPretty = $InterfaceConfig | Out-String
                if ($InterfaceConfig | Select-String -Pattern "service-policy output $MapPolicyName") {
                    $PolicyInterface += "$InterfaceConfigPretty" + "`n"
                    $PolicyMapSet = $True
                }
                else {
                    $InterfaceNoPolicy += "$Interface" + "`n"
                }
            }
        }
        else {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Policy map for class maps $MapPolicyName exists. But no interfaces set for device. This is a finding."
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += "$MapPolicy"
            $FindingDetails += "" | Out-String
            $OpenFinding = $True
        }
        # Get class maps
        if ($PolicyMapSet) {
            $ClassMaps = $ShowRunningConfig | Select-String -Pattern "^class-map match-all "
            if ($ClassMaps) {
                foreach ($ClassMap in $ClassMaps) {
                    $ClassMapConfig = Get-Section $ShowRunningConfig $ClassMap | Out-String
                    $ClassMapList += "$ClassMap`n$ClassMapConfig`n"
                }
            }
        }
        if ($MapPolicyConfig) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Following is the policy map configured in device. Verify that the policy map reserves the bandwidth for each traffic type. " | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += "$MapPolicy" | Out-String
            $FindingDetails += "$MapPolicyConfigPretty" | Out-String
            $FindingDetails += "" | Out-String
        }
        if ($ClassMapList.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Class maps below are configured in device. Verify that the class-maps are configured to match on DSCP values. " | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += "$ClassMapList" | Out-String
            $FindingDetails += "" | Out-String
        }
        if ($PolicyInterface -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "$MapPolicy for class maps is set for following interfaces." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += "$PolicyInterface" | Out-String
            $FindingDetails += "" | Out-String
        }
        else {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Policy map $MapPolicy for class maps is not bound to any interface. This is a finding."
            $FindingDetails += "" | Out-String
            $OpenFinding = $True
        }
        if ($InterfaceNoPolicy.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Following interfaces has no output service $MapPolicy set."
            $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += "$InterfaceNoPolicy" | Out-String
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "No policy map set in router. Review and make finding determination based on STIG check guidance." | Out-String
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

Function Get-V216806 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216806
        STIG ID    : CISC-RT-000780
        Rule ID    : SV-216806r531087_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-NET-000193-RTR-000112
        Rule Title : The Cisco PE router must be configured to enforce a Quality-of-Service (QoS) policy to limit the effects of packet flooding denial-of-service (DoS) attacks.
        DiscussMD5 : F5E8F727DE225728A2565FF8E60E3B0A
        CheckMD5   : F181D9A957E72D4483767CEE89A5C6D8
        FixMD5     : 7AD69945C281E8096CF1E521DB0A2461
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
    $PolicyMapSet = $False
    $PolicyInterface = @()
    $ScavengerClasses = @()
    $ScavengerPolicies = @()
    $NoScavengerPolicies = @()
    #Determine If SCAVENGER class-map is set
    $ClassMaps = $ShowRunningConfig | Select-String -Pattern "^class-map match-all .*"
    if ($ClassMaps) {
        foreach ($ClassMap in $ClassMaps) {
            $ClassMapConfig = Get-Section $ShowRunningConfig $ClassMap
            $ClassMapConfigPretty = $ClassMapConfig | Out-String
            $ClassMapConfigDscp = ($ClassMapConfig | Select-String -Pattern "^match dscp cs1")
            if ($ClassMapConfigDscp) {
                $ScavengerClasses += "$ClassMap`n $ClassMapConfig`n`n"
            }
        }
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "No class-map set in router. " | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    #Get map policy
    if ($ScavengerClasses.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "SCAVENGER class map set in device. " | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "--------------------------------------" | Out-String
        $FindingDetails += $ScavengerClasses
        $FindingDetails += "" | Out-String
        $Exception = $True
        $MapPolicies = $ShowRunningConfig | Select-String -Pattern "^policy-map "
        if ($MapPolicies) {
            $MapPolicyConfig = Get-Section $ShowRunningConfig $MapPolicies
            $MapPolicyConfigPretty = $MapPolicyConfig | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "POLICY MAP set in device. " | Out-String
            $FindingDetails += "Verify that the POLICY MAP includes the SCAVENGER class with low priority, otherwise this will be a finding. " | Out-String
            $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "--------------------------------------" | Out-String
            $FindingDetails += "$MapPolicies`n$MapPolicyConfigPretty`n`n"
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
        else {
            $FindingDetails += "" | Out-String
            $FindingDetails += "No POLICY MAP set in router." | Out-String
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

Function Get-V216807 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216807
        STIG ID    : CISC-RT-000790
        Rule ID    : SV-216807r1117237_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-NET-000019-RTR-000003
        Rule Title : The Cisco multicast router must be configured to disable Protocol Independent Multicast (PIM) on all interfaces that are not required to support multicast routing.
        DiscussMD5 : 637B11CAC2BBABB823BBE2FFE7C8D75E
        CheckMD5   : 45A9B4CD25C7E90771FEA9F15E563F70
        FixMD5     : BBD590769603B450E02FBB80E441F787
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
    # Get interface rds from router pim
    $RoutePim = ($ShowRunningConfig | Select-String -Pattern "^router pim")
    $RoutePimConfig = Get-Section $ShowRunningConfig $RoutePim
    # Verify address-family ipv4 set for router pim
    $pimInterfaces = ($RoutePimConfig | Select-String "^interface ")
    if ($pimInterfaces) {
        foreach ($pimInterface in $pimInterfaces) {
            $PimInterfaceName = ($pimInterface).ToString().Split([char[]]"") | Select-Object -Index 1
            $startIndex = ($RoutePimConfig | Select-String -Pattern "^interface $pimInterfaceName" | Select-Object -First 1).LineNumber[0]
            $endSTR = "!"
            $endIndex = 0
            for ($i = $startIndex; $i -le $RoutePimConfig.Count; $i++) {
                $endIndex = $i + 1
                if ($RoutePimConfig[$i] -eq $endSTR) {
                    # If the $endSTR line is found
                    break
                }
            }
            $PimInterfaceConfig = $RoutePimConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
            $PimInterfaceEnable = ($PimInterfaceConfig | Select-String -Pattern "^enable$")
            if ($PimInterfaceEnable) {
                # Add interface, rd to list
                $PimInterfaceEnableList += "$pimInterface`n"
            }
            else {
                # Add interface to list
                $PimInterfaceNotEnableList += "$pimInterface`n"
            }
        }
        if ($PimInterfaceEnableList -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "The following interfaces are configured for PIM." | Out-String
            $FindingDetails += "Verify these are required interfaces to support multicast topology." | Out-String
            $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += "$PimInterfaceEnableList"
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
        if ($PimInterfaceNotEnableList -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "The following interfaces are not configured for PIM." | Out-String
            $FindingDetails += "Verify these are not required interfaces to support multicast topology." | Out-String
            $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += "$PimInterfaceNotEnableList"
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "The are no interfaces configured for PIM. This is a finding." | Out-String
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

Function Get-V216808 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216808
        STIG ID    : CISC-RT-000800
        Rule ID    : SV-216808r1117237_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-NET-000019-RTR-000004
        Rule Title : The Cisco multicast router must be configured to bind a Protocol Independent Multicast (PIM) neighbor filter to interfaces that have PIM enabled.
        DiscussMD5 : 0C4685D5F08C52AB2BE35627C7874D11
        CheckMD5   : 3E2D30BA70721D27568175630425D6CA
        FixMD5     : 8741CDBF7994B7C13630C57DFE70DB36
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
    # Get interface rds from router pim
    $RoutePim = ($ShowRunningConfig | Select-String -Pattern "^router pim")
    if ($RoutePim) {
        $startIndex = ($ShowRunningConfig | Select-String -Pattern $RoutePim | Select-Object -First 1).LineNumber[0]
        $endSTR = "^!"
        $endIndex = 0
        for ($i = $startIndex; $i -le $ShowRunningConfig.Count; $i++) {
            $endIndex = $i + 1
            if ($ShowRunningConfig[$i] -eq $endSTR) {
                # If the $endSTR line is found
                break
            }
        }
        $RoutePimConfig = $ShowRunningConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
        #$RoutePimConfig = Get-Section $ShowRunningConfig $RoutePim
        # Verify address-family ipv4 set for router pim
        $DefaultACL = $RoutePimConfig | Select-String -Pattern "^  neighbor-filter .*"
        $PimInterfaces = ($RoutePimConfig | Select-String "^  interface ")
        $PimInterfaceEnableNoACLList = @()
        $PimInterfaceEnableList = @()
        $PimInterfaceNotEnableList = @()
        $PimInterfaceEnableListACLNotDefined = @()
        if ($PimInterfaces) {
            foreach ($PimInterface in $PimInterfaces) {
                $PimInterfaceName = ($PimInterface).ToString().Split([char[]]"") | Select-Object -Index 1
                $startIndex = ($RoutePimConfig | Select-String -Pattern $PimInterface | Select-Object -First 1).LineNumber[0]
                $endSTR = "^  !"
                $endIndex = 0
                for ($i = $startIndex; $i -le $RoutePimConfig.Count; $i++) {
                    $endIndex = $i + 1
                    if ($RoutePimConfig[$i] | Select-String -Pattern $endSTR) {
                        # If the $endSTR line is found
                        break
                    }
                }
                $PimInterfaceConfig = $RoutePimConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
                $PimInterfaceEnable = ($PimInterfaceConfig | Select-String -Pattern "^   enable$")
                if ($PimInterfaceEnable) {
                    # Get interface ACL
                    $PimInterfaceACL = ($PimInterfaceConfig | Select-String -Pattern "^   neighbor-filter .*")
                    if ($PimInterfaceACL) {
                        #Verify ACL is configured in device
                        $PimInterfaceACLName = ($PimInterfaceACL).ToString().Trim().Split([char[]]"") | Select-Object -Index 1
                        $PimInterfaceACLPretty = $ShowRunningConfig | Select-String -Pattern "^ipv4 access-list $PimInterfaceACLName"
                        if ($PimInterfaceACLPretty) {
                            $PimInterfaceEnableList += "$PimInterface`n $PimInterfaceACLPretty`n`n"
                        }
                        else {
                            $PimInterfaceEnableListACLNotDefined += "$PimInterface`n $PimInterfaceACL`n`n"
                        }
                    }
                    else {
                        if ($DefaultACL) {
                            $DefaultACLName = ($DefaultACL).ToString().Trim().Split([char[]]"") | Select-Object -Index 1
                            $DefaultACLPretty = $ShowRunningConfig | Select-String -Pattern "^ipv4 access-list $DefaultACLName"
                            if ($DefaultACLPretty) {
                                $PimInterfaceEnableList += "$PimInterface`n $DefaultACLPretty`n`n"
                            }
                            else {
                                $FindingDetails += "" | Out-String
                                $FindingDetails += "ACL '$DefaultACLName' for router pim interface '$PimInterface' is not configured." | Out-String
                                $FindingDetails += "This is a finding." | Out-String
                                $FindingDetails += "" | Out-String
                                $OpenFinding = $True
                            }
                        }
                        else {
                            $PimInterfaceEnableNoACLList += "$PimInterface`n"
                        }
                    }
                }
                else {
                    # Add interface to list
                    $PimInterfaceNotEnableList += "$PimInterface`n"
                }
            }
            if ($PimInterfaceEnableList.Count -gt 0) {
                $FindingDetails += "" | Out-String
                $FindingDetails += "Following are enabled interfaces and ACLs associated to PIM." | Out-String
                $FindingDetails += "Verify these are required interfaces to support multicast topology." | Out-String
                $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
                $FindingDetails += "-------------------------------------------" | Out-String
                $FindingDetails += "$PimInterfaceEnableList"
                $FindingDetails += "" | Out-String
                $Exception = $True
            }
            if ($PimInterfaceEnableNoACLList.Count -gt 0) {
                $FindingDetails += "" | Out-String
                $FindingDetails += "Following are enabled interfaces associated to PIM has no ACL configured." | Out-String
                $FindingDetails += "If these are required interfaces to support multicast topology, then ACL should be configured." | Out-String
                $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
                $FindingDetails += "-------------------------------------------" | Out-String
                $FindingDetails += "$PimInterfaceEnableNoACLList"
                $FindingDetails += "" | Out-String
                $Exception = $True
            }
            if ($PimInterfaceNotEnableList.Count -gt 0) {
                $FindingDetails += "" | Out-String
                $FindingDetails += "Following are interfaces associated to PIM that are not enabled." | Out-String
                $FindingDetails += "Verify these are not required interfaces to support multicast topology." | Out-String
                $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
                $FindingDetails += "-------------------------------------------" | Out-String
                $FindingDetails += "$PimInterfaceNotEnableList"
                $FindingDetails += "" | Out-String
                $Exception = $True
            }
            if ($PimInterfaceEnableListACLNotDefined.Count -gt 0) {
                $FindingDetails += "" | Out-String
                $FindingDetails += "Following ACLs associated to PIM interfaces are not configured in device." | Out-String
                $FindingDetails += "This is a finding." | Out-String
                $FindingDetails += "-------------------------------------------" | Out-String
                $FindingDetails += $PimInterfaceEnableListACLNotDefined
                $FindingDetails += "" | Out-String
                $OpenFinding = $True
            }
        }
        else {
            $FindingDetails += "" | Out-String
            $FindingDetails += "No interface configured for PIM. This is a finding" | Out-String
            $FindingDetails += "" | Out-String
            $OpenFinding = $True
        }
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "PIM is not configured for the device." | Out-String
        $FindingDetails += " Make finding determination based on STIG check guidance." | Out-String
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

Function Get-V216809 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216809
        STIG ID    : CISC-RT-000810
        Rule ID    : SV-216809r1117237_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-NET-000019-RTR-000005
        Rule Title : The Cisco multicast edge router must be configured to establish boundaries for administratively scoped multicast traffic.
        DiscussMD5 : 62F442656F21941DAB2FF8599EB32308
        CheckMD5   : 6BB6EB1C8CAA78B9A241C44EAFA12606
        FixMD5     : DB97E03E6FCBE47E45E76E8242148090
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
    $MulticastInterfaceACLs = @()
    $NoMulticastInterfaceACLs = @()
    $MulticastInterfaceNoACLs = @()
    # Get interface configuration.
    $MulticastRouting = $ShowRunningConfig | Select-String -Pattern "^MULTICAST-routing"
    if ($MulticastRouting) {
        $startIndex = ($ShowRunningConfig | Select-String -Pattern $MulticastRouting | Select-Object -First 1).LineNumber[0]
        $endSTR = "^!"
        $endIndex = 0
        for ($i = $startIndex; $i -le $ShowRunningConfig.Count; $i++) {
            $endIndex = $i + 1
            if ($ShowRunningConfig[$i] | Select-String -Pattern $endSTR) {
                # If the $endSTR line is found
                break
            }
        }
        $MulticastRoutingConfig = $ShowRunningConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
        # Verify MULTICAST config
        $MulticastAddress = $MulticastRoutingConfig | Select-String -Pattern "^ address-family ipv4"
        if ($MulticastAddress) {
            $MulticastInterfaces = $MulticastRoutingConfig | Select-String -Pattern "^  interface "
            if ($MulticastInterfaces) {
                foreach ($MulticastInterface in $MulticastInterfaces) {
                    $startIndex = ($MulticastRoutingConfig | Select-String -Pattern $MulticastInterface | Select-Object -First 1).LineNumber[0]
                    $endSTR = "^  !"
                    $endIndex = 0
                    for ($i = $startIndex; $i -le $MulticastRoutingConfig.Count; $i++) {
                        $endIndex = $i + 1
                        if ($MulticastRoutingConfig[$i] | Select-String -Pattern $endSTR) {
                            # If the $endSTR line is found
                            break
                        }
                    }
                    $MulticastInterfaceConfig = $MulticastRoutingConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
                    $MulticastInterface = $MulticastInterface.ToString().Trim()
                    $MulticastInterfaceACL = $MulticastInterfaceConfig | Select-String -Pattern "^   boundary .*"
                    $MulticastInterfaceACL = $MulticastInterfaceACL.ToString().Trim()
                    if ($MulticastInterfaceACL) {
                        $MulticastInterfaceACLName = $MulticastInterfaceACL.ToString().Trim().Split([char[]]"") | Select-Object -Index 1
                        if ( $ShowRunningConfig | Select-String -Pattern "^ipv4 access-list $MulticastInterfaceACLName") {
                            $MulticastInterfaceACLs += "$MulticastInterface`n $MulticastInterfaceACL`n"
                        }
                        else {
                            $NoMulticastInterfaceACLs += "$MulticastInterface`n $MulticastInterfaceACL`n"
                        }
                    }
                    else {
                        $MulticastInterfaceNoACLs += "$MulticastInterface`n"
                    }
                }
            }
            else {
                $FindingDetails += "" | Out-String
                $FindingDetails += "No MULTICAST interface is configured in device." | Out-String
                $FindingDetails += "This is a finding." | Out-String
                $FindingDetails += "" | Out-String
                $OpenFinding = $True
            }
        }
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following is the MULTICAST routing configured in device." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $MulticastRoutingConfig | Out-String
        $FindingDetails += "" | Out-String
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "MULTICAST routing is not configured in device." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    if ($MulticastInterfaceACLs.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following MULTICAST interfaces and ACLs are configured in device." | Out-String
        $FindingDetails += "Verify that admin-scope MULTICAST traffic is blocked at the external edge." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += "$MulticastInterfaceACLs"
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    if ($NoMulticastInterfaceACLs.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following MULTICAST ACLs are not configured in device." | Out-String
        $FindingDetails += "This is a finding." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += "$NoMulticastInterfaceACLs"
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }
    if ($MulticastInterfaceNoACLs.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following MULTICAST interfaces have no boundary ACLs configured in device. This is a finding" | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += "$MulticastInterfaceNoACLs"
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

Function Get-V216810 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216810
        STIG ID    : CISC-RT-000820
        Rule ID    : SV-216810r856449_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-RTR-000120
        Rule Title : The Cisco multicast Rendezvous Point (RP) router must be configured to filter Protocol Independent Multicast (PIM) Join messages received from the Designated Router (DR) for any undesirable multicast groups.
        DiscussMD5 : 1D8226EC842478B7C18033811A1C94E1
        CheckMD5   : 23AE9D1FEBFA4F13391A14D30FAA3B6E
        FixMD5     : D4503F29EAF8057C52CE47A942DF504A
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
    # Checks for router pim
    $RoutePim = ($ShowRunningConfig | Select-String -Pattern "^router pim")
    if ($RoutePim) {
        $startIndex = ($ShowRunningConfig | Select-String -Pattern $RoutePim | Select-Object -First 1).LineNumber[0]
        $endSTR = "^!"
        $endIndex = 0
        for ($i = $startIndex; $i -le $ShowRunningConfig.Count; $i++) {
            $endIndex = $i + 1
            if ($ShowRunningConfig[$i] | Select-String -Pattern $endSTR) {
                # If the $endSTR line is found
                break
            }
        }
        $RoutePimConfig = $ShowRunningConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
        $FindingDetails += "" | Out-String
        $FindingDetails += "Router PIM config" | Out-String
        $FindingDetails += "--------------------------------" | Out-String
        $FindingDetails += $RoutePimConfig | Out-String
        $FindingDetails += "" | Out-String
        # Verify address-family ipv4 set for router pim
        $AddressFamily = $RoutePimConfig | Select-String -Pattern "^ address-family ipv4"
        if ($AddressFamily) {
            $PimRegister = ($RoutePimConfig | Select-String -Pattern "^  accept-register ")
            if ($PimRegister) {
                #Verify ACL is configured in device
                $PimRegister = $PimRegister.ToString().Trim()
                $PimRegisterACLName = ($PimRegister).Split([char[]]"") | Select-Object -Index 1
                $PimRegisterACL = $ShowRunningConfig | Select-String -Pattern "^ipv4 access-list $PimRegisterACLName"
                if ($PimRegisterACL) {
                    # Verify maximum register-states defined for router pim
                    $PimRegisterACLConfig = Get-Section $ShowRunningConfig $PimRegisterACL | Out-String
                    $FindingDetails += "Following ACL associated to router PIM '$PimRegister' is configured in device." | Out-String
                    $FindingDetails += "-----------------------------------------" | Out-String
                    $FindingDetails += "$PimRegisterACL`n$PimRegisterACLConfig" | Out-String
                    $PimRouterMaxVerify = ($RoutePimConfig | Select-String "^  maximum register-states .*")
                    if ($PimRouterMaxVerify) {
                        $PimRouterMaxVerify = $PimRouterMaxVerify.ToString().Trim()
                        $FindingDetails += "Following configured to rate limit the number of multicast register messages." | Out-String
                        $FindingDetails += "-------------------------------------------" | Out-String
                        $FindingDetails += $PimRouterMaxVerify | Out-String
                        $FindingDetails += "" | Out-String
                    }
                    else {
                        $FindingDetails += "Rate limit the number of multicast register messages is not configured for the router." | Out-String
                    }
                    $FindingDetails += "From above verify that the RP router is configured to filter PIM register messages" | Out-String
                    $FindingDetails += "received from a multicast DR for any undesirable multicast groups and sources." | Out-String
                    $FindingDetails += "Review above and make finding determination based on STIG check guidance." | Out-String
                    $FindingDetails += "----------------------------------------------" | Out-String
                    $Exception = $True
                }
                else {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "ACL '$PimRegisterACLName' associated to router PIM '$PimRegister' is not configured." | Out-String
                    $FindingDetails += "This is a finding." | Out-String
                    $FindingDetails += "" | Out-String
                    $OpenFinding = $True
                }
            }
        }
        else {
            $FindingDetails += "" | Out-String
            $FindingDetails += "No address-family configured for router PIM. This is a finding." | Out-String
            $FindingDetails += "" | Out-String
            $OpenFinding = $True
        }
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Router PIM not configured for the device." | Out-String
        $FindingDetails += " Make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    #Checks for router msdp peers
    $RouteMsdp = $ShowRunningConfig | Select-String -Pattern "router msdp"
    $MsdpPeerList = @()
    $IngressInterface = $False
    if ($RouteMsdp) {
        $startIndex = ($ShowRunningConfig | Select-String -Pattern $RouteMsdp | Select-Object -First 1).LineNumber[0]
        $endSTR = "^!"
        $endIndex = 0
        for ($i = $startIndex; $i -le $ShowRunningConfig.Count; $i++) {
            $endIndex = $i + 1
            if ($ShowRunningConfig[$i] | Select-String -Pattern $endSTR) {
                # If the $endSTR line is found
                break
            }
        }
        $RouteMsdpConfig = $ShowRunningConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
        $FindingDetails += "Router MSDP config" | Out-String
        $FindingDetails += "--------------------------------" | Out-String
        $FindingDetails += $RouteMsdpConfig | Out-String
        $FindingDetails += "" | Out-String
        $RouteMsdpPeers = $RouteMsdpConfig | Select-String -Pattern "^ peer .*"
        if ($RouteMsdpPeers) {
            foreach ($RouteMsdpPeer in $RouteMsdpPeers) {
                $RouteMsdpPeer = $RouteMsdpPeer.ToString().Trim()
                $MsdpPeerList += "$RouteMsdpPeer`n"
            }
            #Interfaces with inbound ACLs
            $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
            $IngressInterfaceList = @()
            foreach ($Interface in $Interfaces) {
                $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
                $IngressACLs = ($InterfaceConfig | Select-String -Pattern "ipv4 access-group .* ingress")
                if ($IngressACLs) {
                    $IngressInterface = $True
                    $InterfaceIpv4Address = ($InterfaceConfig | Select-String -Pattern "ipv4 address .*")
                    if ($InterfaceIpv4Address) {
                        foreach ($IngressACL in $IngressACLs) {
                            $ACLName = $IngressACL.ToString().Split([char[]]"") | Select-Object -Index 2
                            $ACLExtended = $ShowRunningConfig | Select-String -Pattern "^ipv4 access-list $ACLName"
                            if ($ACLExtended) {
                                $IngressInterfaceList += "$Interface`n $IngressACL`n`n"
                            }
                            else {
                                $FindingDetails += "" | Out-String
                                $FindingDetails += "Ingress ACL '$ACLName' associated to '$Interface' is not configured in the system. This is a finding" | Out-String
                                $FindingDetails += "" | Out-String
                                $OpenFinding = $True
                            }
                        }
                    }
                    else {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "ipv4 address not configured for $Interface with ingress ACL $ACLName. This is a finding" | Out-String
                        $FindingDetails += "" | Out-String
                        $OpenFinding = $True
                    }
                }
            }
        }
        else {
            $FindingDetails += "" | Out-String
            $FindingDetails += "MSDP router is set but no MSDP peers are set up for the device " | Out-String
            $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
        if ($MsdpPeerList.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Following are MSDP router peer list" | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += $MsdpPeerList
            if ($IngressInterfaceList.Count -gt 0) {
                $FindingDetails += "" | Out-String
                $FindingDetails += "Following are interfaces with INGRESS ACL." | Out-String
                $FindingDetails += "Verify following are configured to only accept MSDP packets from known MSDP peers." | Out-String
                $FindingDetails += "Review above and make finding determination based on STIG check guidance." | Out-String
                $FindingDetails += "-------------------------------------------" | Out-String
                $FindingDetails += $IngressInterfaceList
                $FindingDetails += "" | Out-String
                $Exception = $True
            }
            else {
                if (!$IngressInterface) {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "No INGRESS interface and ACL list are configured in device for MSDP peers." | Out-String
                    $FindingDetails += "" | Out-String
                }
            }
        }
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "No MSDP router and MSDP peers set up for the device " | Out-String
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

Function Get-V216811 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216811
        STIG ID    : CISC-RT-000830
        Rule ID    : SV-216811r1117237_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-NET-000019-RTR-000013
        Rule Title : The Cisco multicast Rendezvous Point (RP) router must be configured to filter Protocol Independent Multicast (PIM) Register messages received from the Designated Router (DR) for any undesirable multicast groups and sources.
        DiscussMD5 : AFBA9F976485DD6E345D358C87F4D9A7
        CheckMD5   : E140F3EB820960468C47A1D7F5059889
        FixMD5     : 91F4ACF4008A9185B17CC0FAED4ADC88
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
    # Get interface rds from router pim
    $RoutePim = ($ShowRunningConfig | Select-String -Pattern "^router pim")
    if ($RoutePim) {
        $startIndex = ($ShowRunningConfig | Select-String -Pattern $RoutePim | Select-Object -First 1).LineNumber[0]
        $endSTR = "^!"
        $endIndex = 0
        for ($i = $startIndex; $i -le $ShowRunningConfig.Count; $i++) {
            $endIndex = $i + 1
            if ($ShowRunningConfig[$i] -eq $endSTR) {
                # If the $endSTR line is found
                break
            }
        }
        $RoutePimConfig = $ShowRunningConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
        $FindingDetails += "" | Out-String
        $FindingDetails += "Router PIM config" | Out-String
        $FindingDetails += "--------------------------------" | Out-String
        $FindingDetails += $RoutePimConfig | Out-String
        $FindingDetails += "" | Out-String
        # Verify address-family ipv4 set for router pim
        $AddressFamily = $RoutePimConfig | Select-String -Pattern "^ address-family ipv4"
        if ($AddressFamily) {
            $PimRegister = ($RoutePimConfig | Select-String -Pattern "^  accept-register ")
            if ($PimRegister) {
                #Verify ACL is configured in device
                $PimRegister = $PimRegister.ToString().Trim()
                $PimRegisterACLName = ($PimRegister).Split([char[]]"") | Select-Object -Index 1
                $PimRegisterACL = $ShowRunningConfig | Select-String -Pattern "^ipv4 access-list $PimRegisterACLName"
                if ($PimRegisterACL) {
                    $FindingDetails += "" | Out-String
                    $PimRegisterACLConfig = Get-Section $ShowRunningConfig $PimRegisterACL | Out-String
                    $FindingDetails += "Following ACL associated to router PIM '$PimRegister' is configured in device." | Out-String
                    $FindingDetails += "-----------------------------------------" | Out-String
                    $FindingDetails += "$PimRegisterACL`n$PimRegisterACLConfig" | Out-String
                    $FindingDetails += "From above verify that the RP router is configured to filter PIM register messages" | Out-String
                    $FindingDetails += "received from a multicast DR for any undesirable multicast groups and sources." | Out-String
                    $FindingDetails += "Review above and make finding determination based on STIG check guidance." | Out-String
                    $Exception = $True
                }
                else {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "ACL '$PimRegisterACLName' for router PIM '$PimRegister' is not configured." | Out-String
                    $FindingDetails += "This is a finding." | Out-String
                    $FindingDetails += "" | Out-String
                    $OpenFinding = $True
                }
            }
        }
        else {
            $FindingDetails += "" | Out-String
            $FindingDetails += "No address-family configured for router PIM. This is a finding." | Out-String
            $FindingDetails += "" | Out-String
            $OpenFinding = $True
        }
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Router PIM not configured for the device." | Out-String
        $FindingDetails += " Make finding determination based on STIG check guidance." | Out-String
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

Function Get-V216812 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216812
        STIG ID    : CISC-RT-000840
        Rule ID    : SV-216812r1117237_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-NET-000019-RTR-000014
        Rule Title : The Cisco multicast Rendezvous Point (RP) router must be configured to filter Protocol Independent Multicast (PIM) Join messages received from the Designated Router (DR) for any undesirable multicast groups.
        DiscussMD5 : 886093DB12B8C178DBD7B6AB20443EE9
        CheckMD5   : 2ECC0EA6087B6C07F9018768F333BC5B
        FixMD5     : 1B23AF9DCC87F9C4273D5A901190AC05
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
    # Get interface rds from router pim
    $RoutePim = ($ShowRunningConfig | Select-String -Pattern "^router pim")
    if ($RoutePim) {
        $startIndex = ($ShowRunningConfig | Select-String -Pattern $RoutePim | Select-Object -First 1).LineNumber[0]
        $endSTR = "^!"
        $endIndex = 0
        for ($i = $startIndex; $i -le $ShowRunningConfig.Count; $i++) {
            $endIndex = $i + 1
            if ($ShowRunningConfig[$i] -eq $endSTR) {
                # If the $endSTR line is found
                break
            }
        }
        $RoutePimConfig = $ShowRunningConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
        $FindingDetails += "" | Out-String
        $FindingDetails += "Router PIM config" | Out-String
        $FindingDetails += "--------------------------------" | Out-String
        $FindingDetails += $RoutePimConfig | Out-String
        $FindingDetails += "" | Out-String
        # Verify address-family ipv4 set for router pim
        $AddressFamily = $RoutePimConfig | Select-String -Pattern "^ address-family ipv4"
        if ($AddressFamily) {
            $PimAllowRp = ($RoutePimConfig | Select-String -Pattern "^  allow-rp group-list .*")
            if ($PimAllowRp) {
                #Verify ACL is configured in device
                $PimAllowRp = $PimAllowRp.ToString().Trim()
                $PimAllowRpACLName = ($PimAllowRp).Split([char[]]"") | Select-Object -Index 2
                $PimAllowRpACL = $ShowRunningConfig | Select-String -Pattern "^ipv4 access-list $PimAllowRpACLName"
                $PimAllowRpACLConfig = Get-Section $ShowRunningConfig $PimAllowRpACL | Out-String
                if ($PimAllowRpACL) {
                    $FindingDetails += "Following ACL associated to router PIM '$PimAllowRp' is configured in device." | Out-String
                    $FindingDetails += "-----------------------------------------" | Out-String
                    $FindingDetails += "$PimAllowRpACL`n$PimAllowRpACLConfig" | Out-String
                    $FindingDetails += "From above verify that the RP router is configured to filter PIM join messages " | Out-String
                    $FindingDetails += "for any undesirable multicast groups." | Out-String
                    $FindingDetails += "Review above and make finding determination based on STIG check guidance." | Out-String
                    $Exception = $True
                }
                else {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "ACL '$PimAllowRpACLName' for router pim '$PimAllowRp' is not configured." | Out-String
                    $FindingDetails += "This is a finding." | Out-String
                    $FindingDetails += "" | Out-String
                    $OpenFinding = $True
                }
            }
            else {
                $FindingDetails += "" | Out-String
                $FindingDetails += "allow-rp group-list for router pim is not configured." | Out-String
                $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
                $FindingDetails += "" | Out-String
                $Exception = $True
            }
        }
        else {
            $FindingDetails += "" | Out-String
            $FindingDetails += "No address-family configured for router pim. This is a finding." | Out-String
            $FindingDetails += "" | Out-String
            $OpenFinding = $True
        }
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Router pim not configured for the device." | Out-String
        $FindingDetails += " Make finding determination based on STIG check guidance." | Out-String
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

Function Get-V216813 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216813
        STIG ID    : CISC-RT-000850
        Rule ID    : SV-216813r856450_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-RTR-000121
        Rule Title : The Cisco multicast Rendezvous Point (RP) must be configured to rate limit the number of Protocol Independent Multicast (PIM) Register messages.
        DiscussMD5 : FF23FC590BF4FB011186597BAE16CA93
        CheckMD5   : 13BB9D6EC6B4286E137E28C767D7CB5F
        FixMD5     : C2C362E287706D605D128249C515E1B9
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
    # Get interface rds from router pim
    $RoutePim = ($ShowRunningConfig | Select-String -Pattern "^router pim")
    if ($RoutePim) {
        $startIndex = ($ShowRunningConfig | Select-String -Pattern $RoutePim | Select-Object -First 1).LineNumber[0]
        $endSTR = "^!"
        $endIndex = 0
        for ($i = $startIndex; $i -le $ShowRunningConfig.Count; $i++) {
            $endIndex = $i + 1
            if ($ShowRunningConfig[$i] -eq $endSTR) {
                # If the $endSTR line is found
                break
            }
        }
        $RoutePimConfig = $ShowRunningConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
        $FindingDetails += "" | Out-String
        $FindingDetails += "Router PIM config" | Out-String
        $FindingDetails += "--------------------------------" | Out-String
        $FindingDetails += $RoutePimConfig | Out-String
        $FindingDetails += "" | Out-String
        # Verify address-family ipv4 set for router pim
        $AddressFamily = $RoutePimConfig | Select-String -Pattern "^ address-family ipv4"
        if ($AddressFamily) {
            $PimRegister = ($RoutePimConfig | Select-String -Pattern "^  accept-register ")
            if ($PimRegister) {
                #Verify ACL is configured in device
                $PimRegister = $PimRegister.ToString().Trim()
                $PimRegisterACLName = ($PimRegister).Split([char[]]"") | Select-Object -Index 1
                $PimRegisterACL = $ShowRunningConfig | Select-String -Pattern "^ipv4 access-list $PimRegisterACLName"
                if ($PimRegisterACL) {
                    $PimRegisterACLConfig = Get-Section $ShowRunningConfig $PimRegisterACL | Out-String
                    $FindingDetails += "Following ACL associated to router PIM '$PimRegister' is configured in device." | Out-String
                    $FindingDetails += "-----------------------------------------" | Out-String
                    $FindingDetails += "$PimRegisterACL`n$PimRegisterACLConfig" | Out-String
                    $PimMaxRegister = ($RoutePimConfig | Select-String -Pattern "^  maximum register-states .*").ToString().Trim()
                    if ($PimMaxRegister) {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Maximum register '$PimMaxRegister' is configured for router PIM '$PimRegister' to limit the number of PIM register states." | Out-String
                        $FindingDetails += "Review above and make finding determination based on STIG check guidance." | Out-String
                        $FindingDetails += "" | Out-String
                        $Exception = $True
                    }
                    else {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Maximum register is not configured for router pim '$PimRegister' to limit the number of PIM register states." | Out-String
                        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
                        $FindingDetails += "" | Out-String
                        $Exception = $True
                    }
                }
                else {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "ACL '$PimRegisterACLName' for router pim '$PimRegister' is not configured." | Out-String
                    $FindingDetails += "This is a finding." | Out-String
                    $FindingDetails += "" | Out-String
                    $OpenFinding = $True
                }
            }
        }
        else {
            $FindingDetails += "" | Out-String
            $FindingDetails += "No address-family configured for router pim. This is a finding." | Out-String
            $FindingDetails += "" | Out-String
            $OpenFinding = $True
        }
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Router pim not configured for the device." | Out-String
        $FindingDetails += " Make finding determination based on STIG check guidance." | Out-String
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

Function Get-V216814 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216814
        STIG ID    : CISC-RT-000860
        Rule ID    : SV-216814r878125_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000364-RTR-000114
        Rule Title : The Cisco multicast Designated Router (DR) must be configured to filter the Internet Group Management Protocol (IGMP) and Multicast Listener Discovery (MLD) Report messages to allow hosts to join only multicast groups that have been approved by the organization.
        DiscussMD5 : BC62F6A539A6B3CDB8D915307F15609E
        CheckMD5   : 988EC506091D831A89BD367DCA657C1B
        FixMD5     : 22E294CAE6A6276AE69E0C83D65336F0
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
    # Checks for router igmp
    $RouteIgmp = ($ShowRunningConfig | Select-String -Pattern "^router igmp")
    if ($RouteIgmp) {
        $startIndex = ($ShowRunningConfig | Select-String -Pattern $RouteIgmp | Select-Object -First 1).LineNumber[0]
        $endSTR = "^!"
        $endIndex = 0
        for ($i = $startIndex; $i -le $ShowRunningConfig.Count; $i++) {
            $endIndex = $i + 1
            if ($ShowRunningConfig[$i] | Select-String -Pattern $endSTR) {
                # If the $endSTR line is found
                break
            }
        }
        $RouteIgmpConfig = $ShowRunningConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
        $FindingDetails += "" | Out-String
        $FindingDetails += "Router IGMP config" | Out-String
        $FindingDetails += "--------------------------------" | Out-String
        $FindingDetails += $RouteIgmpConfig | Out-String
        $FindingDetails += "" | Out-String
        #Igmp Interfaces
        $Interfaces = $RouteIgmpConfig | Select-String -Pattern "^ interface"
        $IgmpInterfaceList = @()
        if ($Interfaces) {
            foreach ($Interface in $Interfaces) {
                $startIndex = ($RouteIgmpConfig | Select-String -Pattern $Interface | Select-Object -First 1).LineNumber[0]
                $endSTR = "^ !"
                $endIndex = 0
                for ($i = $startIndex; $i -le $RouteIgmpConfig.Count; $i++) {
                    $endIndex = $i + 1
                    if ($RouteIgmpConfig[$i] | Select-String -Pattern $endSTR) {
                        # If the $endSTR line is found
                        break
                    }
                }
                $IgmpInterfaceConfig = $RouteIgmpConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
                $IgmpInterfaceConfigPretty = $RouteIgmpConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1)) | Out-String
                $Interface = $Interface.ToString().Trim()
                $IgmpInterfaceACLs = $IgmpInterfaceConfig | Select-String -Pattern "^  access-group .*"
                if ($IgmpInterfaceACLs) {
                    foreach ($IgmpInterfaceACL in $IgmpInterfaceACLs) {
                        #Verify ACLs are set
                        $ACLName = $IgmpInterfaceACL.ToString().Split([char[]]"") | Select-Object -Index 3
                        $ACLExtended = $ShowRunningConfig | Select-String -Pattern "^ipv4 access-list $ACLName"
                        if ($ACLExtended) {
                            $ACLExtendedConfig = Get-Section $ShowRunningConfig $ACLExtended | Out-String
                            $IgmpInterfaceList += "$IgmpInterfaceConfigPretty`n`n $ACLExtended`n$ACLExtendedConfig`n`n"
                        }
                        else {
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "IGMP ACL '$ACLName' associated to '$Interface' is not configured in the system. This is a finding" | Out-String
                            $FindingDetails += "" | Out-String
                            $OpenFinding = $True
                        }
                    }
                }
                else {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "No IGMP ACL configured for '$Interface'. This is a finding" | Out-String
                    $FindingDetails += "" | Out-String
                    $OpenFinding = $True
                }
            }
            if ($IgmpInterfaceList.Count -gt 0) {
                $FindingDetails += "" | Out-String
                $FindingDetails += "Following are IGMP router interface and ACL list" | Out-String
                $FindingDetails += "Verify that all host facing interfaces are configured to filter IGMP Membership Report messages (IGMP joins)" | Out-String
                $FindingDetails += "Verify that the ACL denies unauthorized groups or permits only authorized groups.." | Out-String
                $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
                $FindingDetails += "-------------------------------------------" | Out-String
                $FindingDetails += $IgmpInterfaceList
                $FindingDetails += "" | Out-String
                $Exception = $True
            }
        }
        else {
            $FindingDetails += "" | Out-String
            $FindingDetails += "IGMP router is set but no IGMP interfaces are set up for the device " | Out-String
            $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "No IGMP router set up for the device " | Out-String
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

Function Get-V216815 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216815
        STIG ID    : CISC-RT-000870
        Rule ID    : SV-216815r878126_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000364-RTR-000115
        Rule Title : The Cisco multicast Designated Router (DR) must be configured to filter the Internet Group Management Protocol (IGMP) and Multicast Listener Discovery (MLD) Report messages to allow hosts to join a multicast group only from sources that have been approved by the organization.
        DiscussMD5 : BC62F6A539A6B3CDB8D915307F15609E
        CheckMD5   : 6F89408162CABB537EF7B04FD4F99D0F
        FixMD5     : 6D0D583CC5A2D463F1132A43FF6492BD
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
    # Checks for router igmp
    $RouteIgmp = ($ShowRunningConfig | Select-String -Pattern "^router igmp")
    if ($RouteIgmp) {
        $startIndex = ($ShowRunningConfig | Select-String -Pattern $RouteIgmp | Select-Object -First 1).LineNumber[0]
        $endSTR = "^!"
        $endIndex = 0
        for ($i = $startIndex; $i -le $ShowRunningConfig.Count; $i++) {
            $endIndex = $i + 1
            if ($ShowRunningConfig[$i] | Select-String -Pattern $endSTR) {
                # If the $endSTR line is found
                break
            }
        }
        $RouteIgmpConfig = $ShowRunningConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
        $FindingDetails += "" | Out-String
        $FindingDetails += "Router IGMP config" | Out-String
        $FindingDetails += "--------------------------------" | Out-String
        $FindingDetails += $RouteIgmpConfig | Out-String
        $FindingDetails += "" | Out-String
        #Igmp Interfaces
        $Interfaces = $RouteIgmpConfig | Select-String -Pattern "^ interface"
        $IgmpInterfaceList = @()
        if ($Interfaces) {
            foreach ($Interface in $Interfaces) {
                $startIndex = ($RouteIgmpConfig | Select-String -Pattern $Interface | Select-Object -First 1).LineNumber[0]
                $endSTR = "^ !"
                $endIndex = 0
                for ($i = $startIndex; $i -le $RouteIgmpConfig.Count; $i++) {
                    $endIndex = $i + 1
                    if ($RouteIgmpConfig[$i] | Select-String -Pattern $endSTR) {
                        # If the $endSTR line is found
                        break
                    }
                }
                $IgmpInterfaceConfig = $RouteIgmpConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
                $Interface = $Interface.ToString().Trim()
                $IgmpInterfaceACLs = $IgmpInterfaceConfig | Select-String -Pattern "^  access-group .*"
                if ($IgmpInterfaceACLs) {
                    foreach ($IgmpInterfaceACL in $IgmpInterfaceACLs) {
                        #Verify ACLs are set
                        $ACLName = $IgmpInterfaceACL.ToString().Split([char[]]"") | Select-Object -Index 3
                        $ACLExtended = $ShowRunningConfig | Select-String -Pattern "^ipv4 access-list $ACLName"
                        if ($ACLExtended) {
                            $ACLExtendedConfig = Get-Section $ShowRunningConfig $ACLExtended | Out-String
                            $IgmpInterfaceList += "$IgmpInterfaceConfigPretty`n`n $ACLExtended`n$ACLExtendedConfig`n`n"
                        }
                        else {
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "IGMP ACL '$ACLName' for '$Interface' is not configured in the system. This is a finding" | Out-String
                            $FindingDetails += "" | Out-String
                            $OpenFinding = $True
                        }
                    }
                }
                else {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "No IGMP ACL configured for '$Interface'. This is a finding" | Out-String
                    $FindingDetails += "" | Out-String
                    $OpenFinding = $True
                }
            }
            if ($IgmpInterfaceList.Count -gt 0) {
                $FindingDetails += "" | Out-String
                $FindingDetails += "Following are IGMP router interface and ACL list" | Out-String
                $FindingDetails += "Verify that all host facing interfaces are configured to filter IGMP Membership Report messages (IGMP joins)" | Out-String
                $FindingDetails += "Verify that the ACL denies unauthorized sources or allows only authorized sources." | Out-String
                $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
                $FindingDetails += "-------------------------------------------" | Out-String
                $FindingDetails += $IgmpInterfaceList
                $FindingDetails += "" | Out-String
                $Exception = $True
            }
        }
        else {
            $FindingDetails += "" | Out-String
            $FindingDetails += "igmp router is set but no igmp interfaces are set up for the device " | Out-String
            $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "No igmp router set up for the device " | Out-String
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

Function Get-V216816 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216816
        STIG ID    : CISC-RT-000880
        Rule ID    : SV-216816r856453_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-RTR-000122
        Rule Title : The Cisco multicast Designated Router (DR) must be configured to limit the number of mroute states resulting from Internet Group Management Protocol (IGMP) and Multicast Listener Discovery (MLD) Host Membership Reports.
        DiscussMD5 : 34D08C377A292763DA68ECD672B8219E
        CheckMD5   : 29820832AB921A49C3C2AAD92C9FE81E
        FixMD5     : B923D46DD7ACD3824C8375F95A74C542
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
    # Checks for router igmp
    $RouteIgmp = ($ShowRunningConfig | Select-String -Pattern "^router igmp")
    if ($RouteIgmp) {
        $startIndex = ($ShowRunningConfig | Select-String -Pattern $RouteIgmp | Select-Object -First 1).LineNumber[0]
        $endSTR = "^!"
        $endIndex = 0
        for ($i = $startIndex; $i -le $ShowRunningConfig.Count; $i++) {
            $endIndex = $i + 1
            if ($ShowRunningConfig[$i] | Select-String -Pattern $endSTR) {
                # If the $endSTR line is found
                break
            }
        }
        $RouteIgmpConfig = $ShowRunningConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
        $FindingDetails += "" | Out-String
        $FindingDetails += "Router IGMP config" | Out-String
        $FindingDetails += "--------------------------------" | Out-String
        $FindingDetails += $RouteIgmpConfig | Out-String
        $FindingDetails += "" | Out-String
        # Verify maximum groups configured
        $MaxGroups = $RouteIgmpConfig | Select-String -Pattern "^ maximum groups .*"
        if ($MaxGroups) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Maximum group is configured globally for IGMP." | Out-String
            $FindingDetails += "Verify IGMP limits have been configured globally or on each host-facing interface via the ip igmp limit command." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += "$MaxGroups"
            $FindingDetails += "" | Out-String
        }
        else {
            #Igmp Interfaces
            $Interfaces = $RouteIgmpConfig | Select-String -Pattern "^ interface"
            $IgmpInterfaceMaxGrpList = @()
            $NoIgmpInterfaceMaxGrpList = @()
            $IgmpInterfaceList = @()
            if ($Interfaces) {
                foreach ($Interface in $Interfaces) {
                    $startIndex = ($RouteIgmpConfig | Select-String -Pattern $Interface | Select-Object -First 1).LineNumber[0]
                    $endSTR = "^ !"
                    $endIndex = 0
                    for ($i = $startIndex; $i -le $RouteIgmpConfig.Count; $i++) {
                        $endIndex = $i + 1
                        if ($RouteIgmpConfig[$i] | Select-String -Pattern $endSTR) {
                            # If the $endSTR line is found
                            break
                        }
                    }
                    $IgmpInterfaceConfig = $RouteIgmpConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
                    $Interface = $Interface.ToString().Trim()
                    $IgmpInterfaceMaxGrp = $IgmpInterfaceConfig | Select-String -Pattern "^  maximum groups"
                    if ($IgmpInterfaceMaxGrp) {
                        $IgmpInterfaceMaxGrp = $IgmpInterfaceMaxGrp.ToString().Trim()
                        $IgmpInterfaceMaxGrpList += "$Interface" + "`n " + "$IgmpInterfaceMaxGrpL" + "`n`n"
                    }
                    else {
                        $NoIgmpInterfaceMaxGrpList += "$Interface" + "`n"
                    }
                }
                if ($IgmpInterfaceMaxGrpList.Count -gt 0) {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Maximum group configured for following interfaces" | Out-String
                    $FindingDetails += "Verify IGMP limits have been configured globally or on each host-facing interface via the ip igmp limit command." | Out-String
                    $FindingDetails += "Make finding determination based on STIG check guidance." | Out-String
                    $FindingDetails += "-------------------------------------------" | Out-String
                    $FindingDetails += $IgmpInterfaceMaxGrpList
                    $FindingDetails += "" | Out-String
                    $Exception = $True
                }
                else {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Maximum group is not configured for IGMP" | Out-String
                    $FindingDetails += "Verify IGMP limits have been configured globally or on each host-facing interface via the ip igmp limit command." | Out-String
                    $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
                    $FindingDetails += "" | Out-String
                    $Exception = $True
                }
                if ($NoIgmpInterfaceMaxGrpList.Count -gt 0) {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Maximum group is not configured for following IGMP interfaces." | Out-String
                    $FindingDetails += "This is a finding." | Out-String
                    $FindingDetails += $NoIgmpInterfaceMaxGrpList
                    $FindingDetails += "" | Out-String
                    $OpenFinding = $True
                }
            }
            else {
                $FindingDetails += "" | Out-String
                $FindingDetails += "IGMP is set but no igmp interfaces are set up for the device " | Out-String
                $FindingDetails += "Maximum group is not configured for igmp router" | Out-String
                $FindingDetails += "Verify IGMP limits have been configured globally or on each host-facing interface via the ip igmp limit command." | Out-String
                $FindingDetails += "This is a finding." | Out-String
                $FindingDetails += "" | Out-String
                $OpenFinding = $True
            }
        }
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "No IGMP set up for the device " | Out-String
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

Function Get-V216817 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216817
        STIG ID    : CISC-RT-000890
        Rule ID    : SV-216817r945856_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-RTR-000123
        Rule Title : The Cisco multicast Designated Router (DR) must be configured to set the shortest-path tree (SPT) threshold to infinity to minimalize source-group (S, G) state within the multicast topology where Any Source Multicast (ASM) is deployed.
        DiscussMD5 : 55812D10AD50D0E624DA5A8FBDC8289E
        CheckMD5   : 1B6139C0A91198274EE345D377C868E2
        FixMD5     : 028FB2206FB9FAD9CB3FDF35242E6D73
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
    # Get interface rds from router pim
    $RoutePim = ($ShowRunningConfig | Select-String -Pattern "^router pim")
    if ($RoutePim) {
        $startIndex = ($ShowRunningConfig | Select-String -Pattern $RoutePim | Select-Object -First 1).LineNumber[0]
        $endSTR = "^!"
        $endIndex = 0
        for ($i = $startIndex; $i -le $ShowRunningConfig.Count; $i++) {
            $endIndex = $i + 1
            if ($ShowRunningConfig[$i] -eq $endSTR) {
                # If the $endSTR line is found
                break
            }
        }
        $RoutePimConfig = $ShowRunningConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
        $FindingDetails += "" | Out-String
        $FindingDetails += "Router PIM config" | Out-String
        $FindingDetails += "--------------------------------" | Out-String
        $FindingDetails += $RoutePimConfig | Out-String
        $FindingDetails += "" | Out-String
        #Verify spt-threshold is configured in device
        $PimSptThrshld = ($RoutePimConfig | Select-String -Pattern "^  spt-threshold ")
        if ($PimSptThrshld) {
            $PimSptThrshld = $PimSptThrshld.ToString().Trim()
            $PimSptThrshld = $PimSptThrshld.ToString().Trim()
            $FindingDetails += "" | Out-String
            $FindingDetails += "SPT-THRESHOLD INFINITY has been configured for PIM." | Out-String
            $FindingDetails += " Review and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += "$PimSptThrshld"
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
        else {
            $FindingDetails += "" | Out-String
            $FindingDetails += "SPT-THRESHOLD has not been configured PIM. This is a finding" | Out-String
            $FindingDetails += "" | Out-String
            $OpenFinding = $True
        }
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "No route PIM set up for device." | Out-String
        $FindingDetails += " Make finding determination based on STIG check guidance." | Out-String
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

Function Get-V216818 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216818
        STIG ID    : CISC-RT-000900
        Rule ID    : SV-216818r856455_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000364-RTR-000116
        Rule Title : The Cisco Multicast Source Discovery Protocol (MSDP) router must be configured to only accept MSDP packets from known MSDP peers.
        DiscussMD5 : 0713B0911CF3C45830027829DA2F65D1
        CheckMD5   : A44BB195986C182BBDF696906F6272C8
        FixMD5     : 700ADD66355C231D2CAB5AD8148FEAB8
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
    $RoutePeerOctets = @()
    #Checks for router msdp peers
    $RouteMsdp = $ShowRunningConfig | Select-String -Pattern "router msdp"
    $MsdpPeerList = @()
    $IngressInterface = $False
    if ($RouteMsdp) {
        $startIndex = ($ShowRunningConfig | Select-String -Pattern $RouteMsdp | Select-Object -First 1).LineNumber[0]
        $endSTR = "^!"
        $endIndex = 0
        for ($i = $startIndex; $i -le $ShowRunningConfig.Count; $i++) {
            $endIndex = $i + 1
            if ($ShowRunningConfig[$i] | Select-String -Pattern $endSTR) {
                # If the $endSTR line is found
                break
            }
        }
        $RouteMsdpConfig = $ShowRunningConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
        $FindingDetails += "Router MSDP config" | Out-String
        $FindingDetails += "--------------------------------" | Out-String
        $FindingDetails += $RouteMsdpConfig | Out-String
        $FindingDetails += "" | Out-String
        $RouteMsdpPeers = $RouteMsdpConfig | Select-String -Pattern "^ peer .*"
        if ($RouteMsdpPeers) {
            foreach ($RouteMsdpPeer in $RouteMsdpPeers) {
                $RouteMsdpPeer = $RouteMsdpPeer.ToString().Trim()
                $MsdpPeerIp = ($RouteMsdpPeer.ToString().Split([char[]]"") | Select-Object -Index 1)
                if ($MsdpPeerIp -match "^(\d{1,3}\.\d{1,3}).*$") {
                    $firstTwoOctets = $matches[1]
                    $RoutePeerOctets += $firstTwoOctets
                }
                $MsdpPeerList += "$RouteMsdpPeer`n"
            }
            #Interfaces with inbound ACLs
            $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
            $IngressInterfaceList = @()
            foreach ($Interface in $Interfaces) {
                $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
                if (($InterfaceConfig | Select-String -Pattern "^ipv4 address .*")) {
                    $InterfaceIp = ($InterfaceConfig | Select-String -Pattern "^ipv4 address").ToString().Split([char[]]"") | Select-Object -Index 2
                    if ($InterfaceIp -match "^(\d{1,3}\.\d{1,3}).*$") {
                        $InterfaceOctet = $matches[1]
                        foreach ($RoutePeerOctet in $RoutePeerOctets) {
                            if ($InterfaceOctet -eq $RoutePeerOctet) {
                                $IngressACLs = ($InterfaceConfig | Select-String -Pattern "ipv4 access-group .* ingress")
                                if ($IngressACLs) {
                                    $IngressInterface = $True
                                    $InterfaceIpv4Address = ($InterfaceConfig | Select-String -Pattern "ipv4 address .*")
                                    if ($InterfaceIpv4Address) {
                                        foreach ($IngressACL in $IngressACLs) {
                                            $ACLName = $IngressACL.ToString().Split([char[]]"") | Select-Object -Index 2
                                            $ACLExtended = $ShowRunningConfig | Select-String -Pattern "^ipv4 access-list $ACLName"
                                            if ($ACLExtended) {
                                                $IngressInterfaceList += "$Interface`n $InterfaceIpv4Address`n $IngressACL`n`n"
                                            }
                                            else {
                                                $FindingDetails += "" | Out-String
                                                $FindingDetails += "Ingress ACL '$ACLName' associated to '$Interface' is not configured in the system. This is a finding" | Out-String
                                                $FindingDetails += "" | Out-String
                                                $OpenFinding = $True
                                            }
                                        }
                                    }
                                    else {
                                        $FindingDetails += "" | Out-String
                                        $FindingDetails += "ipv4 address not configured for '$Interface' with ingress ACL '$ACLName'. This is a finding" | Out-String
                                        $FindingDetails += "" | Out-String
                                        $OpenFinding = $True
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        else {
            $FindingDetails += "" | Out-String
            $FindingDetails += "MSDP is set but no msdp peers are set up for the device " | Out-String
            $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
        if ($MsdpPeerList.Count -gt 0) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Following are MSDP peer list" | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += $MsdpPeerList
            if ($IngressInterfaceList.Count -gt 0) {
                $FindingDetails += "" | Out-String
                $FindingDetails += "Following are ingress interface and ACL list." | Out-String
                $FindingDetails += "Verify following interfaces are configured to only accept MSDP packets from known MSDP peers." | Out-String
                $FindingDetails += "Review above and make finding determination based on STIG check guidance." | Out-String
                $FindingDetails += "-------------------------------------------" | Out-String
                $FindingDetails += $IngressInterfaceList
                $FindingDetails += "" | Out-String
                $Exception = $True
            }
            else {
                if (!$IngressInterface) {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "No ingress interface and ACL list are configured in device for MSDP peers." | Out-String
                    $FindingDetails += "" | Out-String
                }
            }
        }
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "No MSDP router and MSDP peers set up for the device " | Out-String
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

Function Get-V216819 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216819
        STIG ID    : CISC-RT-000910
        Rule ID    : SV-216819r856456_rule
        CCI ID     : CCI-001958
        Rule Name  : SRG-NET-000343-RTR-000002
        Rule Title : The Cisco Multicast Source Discovery Protocol (MSDP) router must be configured to authenticate all received MSDP packets.
        DiscussMD5 : AF197D413EEFD172CECCE8D40B0C70B2
        CheckMD5   : 9ED1321394D8C88ADFE346CAF2D57EA8
        FixMD5     : 5383D156EA588F59392A7D9CE53D851B
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
    #Checks for router msdp peers
    $RouteMsdp = $ShowRunningConfig | Select-String -Pattern "router msdp"
    if ($RouteMsdp) {
        $startIndex = ($ShowRunningConfig | Select-String -Pattern $RouteMsdp | Select-Object -First 1).LineNumber[0]
        $endSTR = "^!"
        $endIndex = 0
        for ($i = $startIndex; $i -le $ShowRunningConfig.Count; $i++) {
            $endIndex = $i + 1
            if ($ShowRunningConfig[$i] | Select-String -Pattern $endSTR) {
                # If the $endSTR line is found
                break
            }
        }
        $RouteMsdpConfig = $ShowRunningConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
        $FindingDetails += "Router MSDP config" | Out-String
        $FindingDetails += "--------------------------------" | Out-String
        $FindingDetails += $RouteMsdpConfig | Out-String
        $FindingDetails += "" | Out-String
        $RouteMsdpPeers = $RouteMsdpConfig | Select-String -Pattern "^ peer .*"
        $RouteMsdpPeerWPasswd = @()
        $RouteMsdpPeerNoPasswd = @()
        if ($RouteMsdpPeers) {
            foreach ($RouteMsdpPeer in $RouteMsdpPeers) {
                $startIndex = ($RouteMsdpConfig | Select-String -Pattern $RouteMsdpPeer | Select-Object -First 1).LineNumber[0]
                $endSTR = "^ !"
                $endIndex = 0
                for ($i = $startIndex; $i -le $RouteMsdpConfig.Count; $i++) {
                    $endIndex = $i + 1
                    if ($RouteMsdpConfig[$i] | Select-String -Pattern $endSTR) {
                        # If the $endSTR line is found
                        break
                    }
                }
                $RouteMsdpPeerConfig = $RouteMsdpConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
                $RouteMsdpPeer = $RouteMsdpPeer.ToString().Trim()
                $RouteMsdpPeerPasswd = $RouteMsdpPeerConfig | Select-String -Pattern "^  password .*"
                if ($RouteMsdpPeerPasswd) {
                    $RouteMsdpPeerWPasswd += "$RouteMsdpPeer`n"
                }
                else {
                    $RouteMsdpPeerNoPasswd += "$RouteMsdpPeer`n"
                }
            }
        }
        else {
            $FindingDetails += "" | Out-String
            $FindingDetails += "MSDP is set but no MSDP peers are set up for the device " | Out-String
            $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "No MSDP set for the device " | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    if ($RouteMsdpPeerWPasswd.Count -gt 0 ) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following MSDP peers are set with password authentication." | Out-String
        $FindingDetails += "------------------------------" | Out-String
        $FindingDetails += $RouteMsdpPeerWPasswd
        $FindingDetails += "" | Out-String
    }
    if ($RouteMsdpPeerNoPasswd.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following MSDP peers are not set with password authentication." | Out-String
        $FindingDetails += "This is a finding." | Out-String
        $FindingDetails += "------------------------------" | Out-String
        $FindingDetails += $RouteMsdpPeerNoPasswd
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

Function Get-V216820 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216820
        STIG ID    : CISC-RT-000920
        Rule ID    : SV-216820r1117236_rule
        CCI ID     : CCI-001368
        Rule Name  : SRG-NET-000018-RTR-000007
        Rule Title : The Cisco Multicast Source Discovery Protocol (MSDP) router must be configured to filter received source-active multicast advertisements for any undesirable multicast groups and sources.
        DiscussMD5 : CE5FE6D1ABAF16B3AB97ED1B614B2C6F
        CheckMD5   : 96C1BD3E2CC4C1B18C79B1106B6A7F10
        FixMD5     : A593FAB751ECE1C8497393FB182CA172
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
    #Checks for router msdp peers
    $RouteMsdp = $ShowRunningConfig | Select-String -Pattern "router msdp"
    if ($RouteMsdp) {
        $startIndex = ($ShowRunningConfig | Select-String -Pattern $RouteMsdp | Select-Object -First 1).LineNumber[0]
        $endSTR = "^!"
        $endIndex = 0
        for ($i = $startIndex; $i -le $ShowRunningConfig.Count; $i++) {
            $endIndex = $i + 1
            if ($ShowRunningConfig[$i] | Select-String -Pattern $endSTR) {
                # If the $endSTR line is found
                break
            }
        }
        $RouteMsdpConfig = $ShowRunningConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
        $FindingDetails += "Router MSDP config" | Out-String
        $FindingDetails += "--------------------------------" | Out-String
        $FindingDetails += $RouteMsdpConfig | Out-String
        $FindingDetails += "" | Out-String
        $RouteMsdpSaFilter = $RouteMsdpConfig | Select-String -Pattern "^ sa-filter in list .*"
        if ($RouteMsdpSaFilter) {
            if ($RouteMsdpSaFilter.ToString().Split([char[]]"").Count -gt 0) {
                $ACLName = $RouteMsdpSaFilter.ToString().Split([char[]]"") | Select-Object -Index 4
                $ACLExtended = $ShowRunningConfig | Select-String -Pattern "^ipv4 access-list $ACLName"
                if ($ACLExtended) {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Inbound sa filter ACL for MSDP is configured in the system." | Out-String
                    $FindingDetails += "Please verify  ACL is configured to filter received source-active multicast advertisements " | Out-String
                    $FindingDetails += "for any undesirable multicast groups and sources." | Out-String
                    $FindingDetails += "Make finding determination based on STIG check guidance." | Out-String
                    $FindingDetails += "---------------------------------" | Out-String
                    $FindingDetails += "$RouteMsdpSaFilter`n`n$ACLExtended`n"
                    $Exception = $True
                }
                else {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "'Following ACL for MSPD sa filter is not configured in the system. This is a finding." | Out-String
                    $FindingDetails += "---------------------------------" | Out-String
                    $FindingDetails += "$RouteMsdpSaFilter`n$ACLExtended`n"
                    $FindingDetails += "" | Out-String
                    $OpenFinding = $True
                }
            }
            else {
                $FindingDetails += "" | Out-String
                $FindingDetails += "'$RouteMsdpSaFilter' missing ACL name. This is a finding" | Out-String
                $FindingDetails += "" | Out-String
                $OpenFinding = $True
            }
        }
        else {
            $FindingDetails += "" | Out-String
            $FindingDetails += "MSDP is set but no inbound sa filter set for the device " | Out-String
            $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "No MSDP set up for the device " | Out-String
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

Function Get-V216821 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216821
        STIG ID    : CISC-RT-000930
        Rule ID    : SV-216821r1117236_rule
        CCI ID     : CCI-001368
        Rule Name  : SRG-NET-000018-RTR-000008
        Rule Title : The Cisco Multicast Source Discovery Protocol (MSDP) router must be configured to filter source-active multicast advertisements to external MSDP peers to avoid global visibility of local-only multicast sources and groups.
        DiscussMD5 : 4941DAD27354E7533595B49B65260840
        CheckMD5   : 5851DA623575A12106CB246059A09DB6
        FixMD5     : 2FE63A0F53185355ED84E97143F28E31
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
    #Checks for router msdp peers
    $RouteMsdp = $ShowRunningConfig | Select-String -Pattern "router msdp"
    $MsdpPeerList = @()
    $IngressInterface = $False
    if ($RouteMsdp) {
        $startIndex = ($ShowRunningConfig | Select-String -Pattern $RouteMsdp | Select-Object -First 1).LineNumber[0]
        $endSTR = "^!"
        $endIndex = 0
        for ($i = $startIndex; $i -le $ShowRunningConfig.Count; $i++) {
            $endIndex = $i + 1
            if ($ShowRunningConfig[$i] -eq $endSTR) {
                # If the $endSTR line is found
                break
            }
        }
        $RouteMsdpConfig = $ShowRunningConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
        $FindingDetails += "Router MSDP config" | Out-String
        $FindingDetails += "--------------------------------" | Out-String
        $FindingDetails += $RouteMsdpConfig | Out-String
        $FindingDetails += "" | Out-String
        $RouteMsdpSaFilter = $RouteMsdpConfig | Select-String -Pattern "^ sa-filter out list .*"
        if ($RouteMsdpSaFilter) {
            if ($RouteMsdpSaFilter.ToString().Split([char[]]"").Count -gt 0) {
                $ACLName = $RouteMsdpSaFilter.ToString().Split([char[]]"") | Select-Object -Index 4
                $ACLExtended = $ShowRunningConfig | Select-String -Pattern "^ipv4 access-list $ACLName"
                if ($ACLExtended) {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "MSDP outbound sa filter ACL is configured in the system." | Out-String
                    $FindingDetails += "Verify  ACL is configured to prevent exporting multicast active sources belonging to the private network." | Out-String
                    $FindingDetails += "Make finding determination based on STIG check guidance." | Out-String
                    $FindingDetails += "---------------------------------" | Out-String
                    $FindingDetails += "$RouteMsdpSaFilter`n`n$ACLExtended`n"
                    $FindingDetails += "" | Out-String
                    $Exception = $True
                }
                else {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "MSDP outbound sa filter ACL is configured in the system." | Out-String
                    $FindingDetails += "This is a finding" | Out-String
                    $FindingDetails += "---------------------------------" | Out-String
                    $FindingDetails += "$RouteMsdpSaFilter`n`n$ACLExtended`n"
                    $FindingDetails += "" | Out-String
                    $OpenFinding = $True
                }
            }
            else {
                $FindingDetails += "" | Out-String
                $FindingDetails += "'$RouteMsdpSaFilter' for MSDP missing ACL name. This is a finding" | Out-String
                $FindingDetails += "" | Out-String
                $OpenFinding = $True
            }
        }
        else {
            $FindingDetails += "" | Out-String
            $FindingDetails += "MSDP is set but no outbound sa filter set for the device " | Out-String
            $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "No MSDP is set for the device " | Out-String
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

Function Get-V216822 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216822
        STIG ID    : CISC-RT-000940
        Rule ID    : SV-216822r1117236_rule
        CCI ID     : CCI-001368
        Rule Name  : SRG-NET-000018-RTR-000009
        Rule Title : The Cisco Multicast Source Discovery Protocol (MSDP) router must be configured to limit the amount of source-active messages it accepts on a per-peer basis.
        DiscussMD5 : 3EBC6EDA406C0475A1BF74355C6C4A53
        CheckMD5   : FC7E08A7FA08FC416316A54900405A20
        FixMD5     : 92AB92B3B0E659765E367FADB3621AB5
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
    #Checks for router msdp
    $RouteMsdp = $ShowRunningConfig | Select-String -Pattern "router msdp"
    if ($RouteMsdp) {
        $startIndex = ($ShowRunningConfig | Select-String -Pattern $RouteMsdp | Select-Object -First 1).LineNumber[0]
        $endSTR = "^!"
        $endIndex = 0
        for ($i = $startIndex; $i -le $ShowRunningConfig.Count; $i++) {
            $endIndex = $i + 1
            if ($ShowRunningConfig[$i] | Select-String -Pattern $endSTR) {
                # If the $endSTR line is found
                break
            }
        }
        $RouteMsdpConfig = $ShowRunningConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
        $FindingDetails += "Router MSDP config" | Out-String
        $FindingDetails += "--------------------------------" | Out-String
        $FindingDetails += $RouteMsdpConfig | Out-String
        $FindingDetails += "" | Out-String
        $MsdpPeerNoMaxExt = @()
        $MsdpPeerWMaxExt = @()
        $RouteMsdpPeers = $RouteMsdpConfig | Select-String -Pattern "^ peer .*"
        if ($RouteMsdpPeers) {
            foreach ($RouteMsdpPeer in $RouteMsdpPeers) {
                $startIndex = ($RouteMsdpConfig | Select-String -Pattern $RouteMsdpPeer | Select-Object -First 1).LineNumber[0]
                $endSTR = "^ !"
                $endIndex = 0
                for ($i = $startIndex; $i -le $RouteMsdpConfig.Count; $i++) {
                    $endIndex = $i + 1
                    if ($RouteMsdpConfig[$i] | Select-String -Pattern $endSTR) {
                        # If the $endSTR line is found
                        break
                    }
                }
                $RouteMsdpPeerConfig = $RouteMsdpConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
                $RouteMsdpPeer = $RouteMsdpPeer.ToString().Trim()
                $RouteMsdpPeerMaxExt = $RouteMsdpPeerConfig | Select-String -Pattern "^  maximum external-sa .*"
                if ($RouteMsdpPeerMaxExt) {
                    $RouteMsdpPeerMaxExt = $RouteMsdpPeerMaxExt.ToString().Trim()
                    $MsdpPeerWMaxExt += "$RouteMsdpPeer`n$RouteMsdpPeerMaxExt`n"
                }
                else {
                    $MsdpPeerNoMaxExt += "$RouteMsdpPeer`n$RouteMsdpPeerMaxExt`n"
                }
            }
        }
        else {
            $FindingDetails += "" | Out-String
            $FindingDetails += "MSDP is set but no MSDP peers are set up for the device " | Out-String
            $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "" | Out-String
            $Exception = $True
        }
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "MSDP is not set for the device " | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    if ($MsdpPeerWMaxExt.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following MSDP peers are set with maximum external-sa" | Out-String
        $FindingDetails += "MSDP maximum external-sa is configured to limit the amount of source-active messages it accepts on a per-peer basis." | Out-String
        $FindingDetails += "---------------------------------" | Out-String
        $FindingDetails += $MsdpPeerWMaxExt
        $FindingDetails += "" | Out-String
    }
    if ($MsdpPeerNoMaxExt.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following MSDP peers are not set with maximum external-sa" | Out-String
        $FindingDetails += "MSDP maximum external-sa is configured to limit the amount of source-active messages it accepts on a per-peer basis." | Out-String
        $FindingDetails += "This is a finding." | Out-String
        $FindingDetails += "---------------------------------" | Out-String
        $FindingDetails += $MsdpPeerNoMaxExt
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

Function Get-V216823 {
    <#
    .DESCRIPTION
        Vuln ID    : V-216823
        STIG ID    : CISC-RT-000950
        Rule ID    : SV-216823r991943_rule
        CCI ID     : CCI-004931
        Rule Name  : SRG-NET-000512-RTR-000011
        Rule Title : The Cisco Multicast Source Discovery Protocol (MSDP) router must be configured to use a loopback address as the source address when originating MSDP traffic.
        DiscussMD5 : 7499E19C7D868B586E00063AE75C164C
        CheckMD5   : C57E881A0420F8942894477164D47AAE
        FixMD5     : 9BFC11ADABCE967322878976D6D434C3
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
    #Checks for router msdp peers
    $RouteMsdp = $ShowRunningConfig | Select-String -Pattern "router msdp"
    if ($RouteMsdp) {
        $startIndex = ($ShowRunningConfig | Select-String -Pattern $RouteMsdp | Select-Object -First 1).LineNumber[0]
        $endSTR = "^!"
        $endIndex = 0
        for ($i = $startIndex; $i -le $ShowRunningConfig.Count; $i++) {
            $endIndex = $i + 1
            if ($ShowRunningConfig[$i] | Select-String -Pattern $endSTR) {
                # If the $endSTR line is found
                break
            }
        }
        $RouteMsdpConfig = $ShowRunningConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
        $RouteMsdpLoopback = $RouteMsdpConfig | Select-String -Pattern "^ connect-source Loopback.*"
        if ($RouteMsdpLoopback) {
            $RouteMsdpLoopback = $RouteMsdpLoopback.ToString().Trim()
            $FindingDetails += "" | Out-String
            $FindingDetails += "MSDP is set with loopback address '$RouteMsdpLoopback'." | Out-String
            $FindingDetails += "Router should use its loopback address as the source address when originating MSDP traffic." | Out-String
            $FindingDetails += "" | Out-String
        }
        else {
            $FindingDetails += "" | Out-String
            $FindingDetails += "MSDP is not set with loopback address." | Out-String
            $FindingDetails += "Router should use its loopback address as the source address when originating MSDP traffic. This is a finding" | Out-String
            $FindingDetails += "" | Out-String
            $OpenFinding = $True
        }
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "No MSDP router set up for the device " | Out-String
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

Function Get-V217005 {
    <#
    .DESCRIPTION
        Vuln ID    : V-217005
        STIG ID    : CISC-RT-000310
        Rule ID    : SV-217005r945858_rule
        CCI ID     : CCI-001094
        Rule Name  : SRG-NET-000205-RTR-000014
        Rule Title : The Cisco perimeter router must be configured to restrict it from accepting outbound IP packets that contain an illegitimate address in the source address field via egress filter or by enabling Unicast Reverse Path Forwarding (uRPF).
        DiscussMD5 : B9595D2DAE58AB9CE7582BBAE4615A92
        CheckMD5   : AD235026798431D6ECF8FC6D99F78075
        FixMD5     : EE94CA807AC3FEFF88503B10FB02D8FF
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
    #Interfaces with inbound ACLs
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
    $IngressInterfaceList = @()
    $UprfInterfaceList = @()
    if ($Interfaces) {
        foreach ($Interface in $Interfaces) {
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            # Get ingress interface list
            $IngressACLs = ($InterfaceConfig | Select-String -Pattern "ipv4 access-group .* ingress")
            if ($IngressACLs) {
                $IngressInterface = $True
                foreach ($IngressACL in $IngressACLs) {
                    $ACLName = $IngressACL.ToString().Split([char[]]"") | Select-Object -Index 2
                    $ACLExtended = $ShowRunningConfig | Select-String -Pattern "^ipv4 access-list $ACLName"
                    if ($ACLExtended) {
                        $IngressInterfaceList += "$Interface`n $InterfaceIpv4Address`n $IgressACL`n`n"
                    }
                    else {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Ingress ACL '$ACLName' associated to '$Interface' is not configured in the system. This is a finding" | Out-String
                        $FindingDetails += "" | Out-String
                        $OpenFinding = $True
                    }
                }
            }
            # Get uPRF interfaces
            $UprfInterface = ($InterfaceConfig | Select-String -Pattern "ipv4 verify unicast source reachable-via rx")
            if ($UprfInterface) {
                $UprfInterfaceList += "$Interface" + "`n"
            }
        }
    }
    if ($UprfInterfaceList.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following interfaces are configured with uRPF." | Out-String
        $FindingDetails += "uRPF or an ingress ACL should be configured on all internal interfaces to restrict the router " | Out-String
        $FindingDetails += "from accepting outbound IP packets that contain an illegitimate address in the source address field ." | Out-String
        $FindingDetails += "Make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $UprfInterfaceList
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    if ($EgressInterfaceList.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following are interfaces with ingress ACLs." | Out-String
        $FindingDetails += "uRPF or an ingress ACL should be configured on all internal interfaces to restrict the router from accepting outbound IP packets that contain an illegitimate address in the source address field." | Out-String
        $FindingDetails += "Make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $EgressInterfaceList
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

Function Get-V217006 {
    <#
    .DESCRIPTION
        Vuln ID    : V-217006
        STIG ID    : CISC-RT-000350
        Rule ID    : SV-217006r945859_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000205-RTR-000015
        Rule Title : The Cisco perimeter router must be configured to block all packets with any IP options.
        DiscussMD5 : 580BCA4BBB7649843D17285D715164E5
        CheckMD5   : CC155E5FFFCC2D1BF446A70698779F85
        FixMD5     : 385E3C4692F1F328E309486BDA14899B
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
    #Checks for ipv4 soure route
    $SourceRoute = $ShowRunningConfig | Select-String -Pattern "^ipv4 source-route"
    if ($SourceRoute) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "ipv4 source-route is configured for the router. This is a finding. " | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "ipv4 source-route is not configured for the router. " | Out-String
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

Function Get-V217007 {
    <#
    .DESCRIPTION
        Vuln ID    : V-217007
        STIG ID    : CISC-RT-000470
        Rule ID    : SV-217007r856462_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-RTR-000124
        Rule Title : The Cisco BGP router must be configured to enable the Generalized TTL Security Mechanism (GTSM).
        DiscussMD5 : 017D1AB32C3CBD0DB696871C1A2408F6
        CheckMD5   : B48EDC6CC4778ED7C2CD4F21CF39EF0D
        FixMD5     : E8892473CD495E5DBE89776A38C96F09
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
    $TtlSecurityInternalNeighborList = @()
    $TtlSecurityNeighborList = @()
    $NoTtlSecurityNeighborList = @()
    # Verify bgp router has route policy set for neighbor
    # Get neighbors from router bgp
    $RouteBgp = ($ShowRunningConfig | Select-String -Pattern "^router bgp")
    if ($RouteBgp) {
        $RouterBgpAddress = $RouteBgp.ToString().Split([char[]]"") | Select-Object -Index 2
        $RouteBgpConfig = Get-Section $ShowRunningConfig $RouteBgp.ToString()
        $InternalNeighborGroupList = @()
        if ($RouteBgpConfig) {
            #Get neighbor groups
            # Get neighbor groups from router bgp with route policy
            $bgpNeighborGroups = ($RouteBgpConfig | Select-String -Pattern "^neighbor-group .*")
            foreach ($bgpNeighborGroup in $bgpNeighborGroups) {
                $BgpNeighborGroupName = ($bgpNeighborGroup).ToString().Split([char[]]"") | Select-Object -Index 1
                $startIndex = ($RouteBgpConfig | Select-String -Pattern "^neighbor-group $BgpNeighborGroupName" | Select-Object -First 1).LineNumber[0]
                $endSTR = "!"
                $endIndex = 0
                for ($i = $startIndex; $i -le $RouteBgpConfig.Count; $i++) {
                    $endIndex = $i + 1
                    if ($RouteBgpConfig[$i] -eq $endSTR) {
                        # If the $endSTR line is found
                        break
                    }
                }
                $BgpNeighborGroupConfig = ""
                $BgpNeighborGroupConfig = $RouteBgpConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
                $BgpNeighborGroupConfigRemote = ($BgpNeighborGroupConfig | Select-String -Pattern "^remote-as $RouterBgpAddress")
                if ($BgpNeighborGroupConfigRemote) {
                    $InternalNeighborGroupList += $BgpNeighborGroupName
                }
            }
            # Get neighbors
            $BgpNeighbors = ($RouteBgpConfig | Select-String -Pattern "^neighbor .*")
            $InternalNeighbor = $False
            foreach ($BgpNeighbor in $BgpNeighbors) {
                $BgpNeighborName = ($BgpNeighbor).ToString().Split([char[]]"") | Select-Object -Index 1
                $startIndex = ($RouteBgpConfig | Select-String -Pattern "^neighbor $BgpNeighborName" | Select-Object -First 1).LineNumber[0]
                $endSTR = "!"
                $endIndex = 0
                for ($i = $startIndex; $i -le $RouteBgpConfig.Count; $i++) {
                    $endIndex = $i + 1
                    if ($RouteBgpConfig[$i] -eq $endSTR) {
                        # If the $endSTR line is found
                        break
                    }
                }
                $BgpNeighborConfig = $RouteBgpConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
                if ($BgpNeighborConfig | Select-String -Pattern "use neighbor-group .*") {
                    foreach ($InternalNeighborGroup in $InternalNeighborGroupList) {
                        if ($BgpNeighborConfig | Select-String -Pattern "use neighbor-group $InternalNeighborGroup") {
                            $TtlSecurityInternalNeighborList += "$bgpNeighbor" + "`n"
                            $InternalNeighbor = $True
                        }
                    }
                }
                $BgpNeighborTtlSecurity = $BgpNeighborConfig | Select-String -Pattern "ttl-security"
                if ($BgpNeighborTtlSecurity) {
                    if ($BgpNeighborConfig | Select-String -Pattern "remote-as $RouterBgpAddress") {
                        # Check for ttl-security in neighbor config
                        $TtlSecurityInternalNeighborList += "$bgpNeighbor" + "`n"
                        $InternalNeighbor = $True
                    }
                    else {
                        $TtlSecurityNeighborList += "$bgpNeighbor" + "`n"
                    }
                }
                else {
                    $NoTtlSecurityNeighborList += "$bgpNeighbor" + "`n"
                }
            }
            if ($TtlSecurityNeighborList.Count -gt 0 ) {
                $FindingDetails += "" | Out-String
                $FindingDetails += "Following bgp neigbors have TTL security configured." | Out-String
                $FindingDetails += "Review these are external neighbors." | Out-String
                $FindingDetails += "Make finding determination based on STIG check guidance. ." | Out-String
                $FindingDetails += "-------------------------------------------" | Out-String
                $FindingDetails += $TtlSecurityNeighborList
                $FindingDetails += "" | Out-String
                $Exception = $True
            }
            if ($NoTtlSecurityNeighborList.Count -gt 0) {
                $FindingDetails += "" | Out-String
                $FindingDetails += "Following BGP neighbors do not have TTL security configured." | Out-String
                $FindingDetails += "If these are external neighbors, then  TTL security should be configured." | Out-String
                $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
                $FindingDetails += "-------------------------------------------" | Out-String
                $FindingDetails += $NoTtlSecurityNeighborList
                $Exception = $True
            }
        }
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "BGP router not set for the device." | Out-String
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

Function Get-V217008 {
    <#
    .DESCRIPTION
        Vuln ID    : V-217008
        STIG ID    : CISC-RT-000480
        Rule ID    : SV-217008r945862_rule
        CCI ID     : CCI-000366, CCI-002205
        Rule Name  : SRG-NET-000230-RTR-000002
        Rule Title : The Cisco BGP router must be configured to use a unique key for each autonomous system (AS) that it peers with.
        DiscussMD5 : 61A61BCDF3CC1AF638D5627970244406
        CheckMD5   : E7B995ADF4679DDB888CF5C829E4D0FA
        FixMD5     : 5D409D09303443CCA87D930ACD72B194
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
    $KeyChains = @()
    $ExternalNeighborList = @()
    $ExternalNeighborKeyChainList = @()
    $NotExternalNeighborList = @()
    $RouteBgp = ($ShowRunningConfig | Select-String -Pattern "^router bgp")
    if ($RouteBgp) {
        $RouteBgpSource = $RouteBgp.ToString().Split([char[]]"") | Select-Object -Index 2
        $RouteBgpConfig = Get-Section $ShowRunningConfig $RouteBgp.ToString()
        # Get bgp neighbors
        $bgpNeighbors = ($RouteBgpConfig | Select-String -Pattern "^neighbor .*")
        foreach ($bgpNeighbor in $bgpNeighbors) {
            $startIndex = ($RouteBgpConfig | Select-String -Pattern $bgpNeighbor | Select-Object -First 1).LineNumber[0]
            $endSTR = "!"
            $endIndex = 0
            for ($i = $startIndex; $i -le $RouteBgpConfig.Count; $i++) {
                $endIndex = $i + 1
                if ($RouteBgpConfig[$i] -eq $endSTR) {
                    # If the $endSTR line is found
                    break
                }
            }
            $BgpNeighborConfig = ""
            $BgpNeighborConfig = $RouteBgpConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
            $BgpNeighborRemoteAs = $BgpNeighborConfig | Select-String -Pattern "remote-as .*"
            if ($BgpNeighborConfig | Select-String -Pattern "remote-as .*") {
                $BgpNeighborRemoteAs = $BgpNeighborConfig | Select-String -Pattern "remote-as $RouteBgpSource"
                if (!$BgpNeighborRemoteAs) {
                    $BgpNeighborKeyChain = $BgpNeighborConfig | Select-String -Pattern "keychain .*"
                    if ($BgpNeighborKeyChain) {
                        $BgpNeighborKeyChainName = $BgpNeighborKeyChain.ToString().Split([char[]]"") | Select-Object -Index 1
                        if ($KeyChains -contains $BgpNeighborKeyChainName) {
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "'$BgpNeighborKeyChainName' associated to '$BgpNeighbor' is a duplicate. The ISSM and router administrator should have unique keys This is a finding." | Out-String
                            $FindingDetails += "" | Out-String
                            $OpenFinding = $True
                        }
                        else {
                            $KeyChains += $BgpNeighborKeyChainName
                            $ExternalNeighborKeyChainList += "$BgpNeighbor`n $BgpNeighborKeyChain`n`n"
                        }
                    }
                    else {
                        $ExternalNeighborList += "$BgpNeighbor`n"
                    }
                }
                else {
                    $NotExternalNeighborList += "$BgpNeighbor`n"
                }
            }
            else {
                $FindingDetails += "" | Out-String
                $FindingDetails += "No remote-as configured for BGP neighbor '$BgpNeighbor'." | Out-String
                $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
                $FindingDetails += "" | Out-String
                $Exception = $True
            }
        }
        # Get bgp neighbor groups
        $BgpNeighborGroups = ($RouteBgpConfig | Select-String -Pattern "^neighbor-group .*")
        foreach ($BgpNeighborGroup in $BgpNeighborGroups) {
            $BgpNeighborGroupName = ($BgpNeighborGroup).ToString().Split([char[]]"") | Select-Object -Index 1
            $startIndex = ($RouteBgpConfig | Select-String -Pattern $BgpNeighborGroup | Select-Object -First 1).LineNumber[0]
            $endSTR = "!"
            $endIndex = 0
            for ($i = $startIndex; $i -le $RouteBgpConfig.Count; $i++) {
                $endIndex = $i + 1
                if ($RouteBgpConfig[$i] -eq $endSTR) {
                    # If the $endSTR line is found
                    break
                }
            }
            $BgpNeighborGroupConfig = ""
            $BgpNeighborGroupConfig = $RouteBgpConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
            $BgpNeighborGroupRemoteAs = $BgpNeighborGroupConfig | Select-String -Pattern "remote-as .*"
            if ($BgpNeighborGroupConfig | Select-String -Pattern "remote-as .*") {
                $BgpNeighborGroupRemoteAs = $BgpNeighborGroupConfig | Select-String -Pattern "remote-as $RouteBgpSource"
                if (!$BgpNeighborGroupRemoteAs) {
                    $BgpNeighborGroupKeyChain = $BgpNeighborGroupConfig | Select-String -Pattern "keychain .*"
                    if ($BgpNeighborGroupKeyChain) {
                        $BgpNeighborGroupKeyChainName = $BgpNeighborGroupKeyChain.ToString().Split([char[]]"") | Select-Object -Index 1
                        if ($KeyChains -contains $BgpNeighborGroupKeyChainName) {
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "'$BgpNeighborGroupKeyChainName' associated to '$BgpNeighborGroup' is a duplicate. The ISSM and router administrator should have unique keys This is a finding." | Out-String
                            $FindingDetails += "" | Out-String
                            $OpenFinding = $True
                        }
                        else {
                            $KeyChains += $BgpNeighborGroupKeyChainName
                            $ExternalNeighborKeyChainList += "$BgpNeighborGroup" + "`n " + "$BgpNeighborGroupKeyChain" + "`n`n"
                        }
                    }
                    else {
                        $ExternalNeighborList += "$BgpNeighborGroup" + "`n"
                    }
                }
                else {
                    $NotExternalNeighborList += "$BgpNeighborGroup" + "`n"
                }
            }
            else {
                $FindingDetails += "" | Out-String
                $FindingDetails += "No remote-as configured for BGP neighbor '$BgpNeighborGroup'." | Out-String
                $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
                $FindingDetails += "" | Out-String
                $Exception = $True
            }
        }
        # Get bgp vrf neighbors
        $BgpVrfs = ($RouteBgpConfig | Select-String -Pattern "^vrf .*")
        foreach ($BgpVrf in $BgpVrfs) {
            $BgpVrfName = ($BgpVrf).ToString().Split([char[]]"") | Select-Object -Index 1
            $startIndex = ($RouteBgpConfig | Select-String -Pattern $BgpVrf | Select-Object -First 1).LineNumber[0]
            $endSTR = "!"
            $endIndex = 0
            for ($i = $startIndex; $i -le $RouteBgpConfig.Count; $i++) {
                $endIndex = $i + 1
                if ($RouteBgpConfig[$i] -eq $endSTR) {
                    # If the $endSTR line is found
                    break
                }
            }
            $BgpVrfConfig = ""
            $BgpVrfConfig = $RouteBgpConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
            $BgpVrfNeighbors = $BgpVrfConfig | Select-String -Pattern "^neighbor .*"
            foreach ($BgpVrfNeighbor in $BgpVrfNeighbors) {
                $BgpVrfNeighborName = ($BgpVrfNeighbor).ToString().Split([char[]]"") | Select-Object -Index 1
                $startIndex = ($BgpVrfConfig | Select-String -Pattern $BgpVrfNeighbor | Select-Object -First 1).LineNumber[0]
                $endSTR = "!"
                $endIndex = 0
                for ($i = $startIndex; $i -le $BgpVrfConfig.Count; $i++) {
                    $endIndex = $i + 1
                    if ($BgpVrfConfig[$i] -eq $endSTR) {
                        # If the $endSTR line is found
                        break
                    }
                }
                $BgpVrfNeighborConfig = ""
                $BgpVrfNeighborConfig = $BgpVrfConfig | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
                $BgpVrfNeighborRemoteAs = $BgpVrfNeighborConfig | Select-String -Pattern "remote-as .*"
                if ($BgpVrfNeighborConfig | Select-String -Pattern "remote-as .*") {
                    $BgpVrfNeighborRemoteAs = $BgpVrfNeighborConfig | Select-String -Pattern "remote-as $RouteBgpSource"
                    if (!$BgpVrfNeighborRemoteAs) {
                        $BgpVrfNeighborKeyChain = $BgpVrfNeighborConfig | Select-String -Pattern "keychain .*"
                        if ($BgpVrfNeighborKeyChain) {
                            $BgpVrfNeighborKeyChainName = $BgpVrfNeighborKeyChain.ToString().Split([char[]]"") | Select-Object -Index 1
                            if ($KeyChains -contains $BgpVrfNeighborKeyChainName) {
                                $FindingDetails += "" | Out-String
                                $FindingDetails += "'$BgpVrfNeighborKeyChainName' associated to '$BgpVrfNeighbor' is a duplicate. The ISSM and router administrator should have unique keys This is a finding." | Out-String
                                $FindingDetails += "" | Out-String
                                $OpenFinding = $True
                            }
                            else {
                                $KeyChains += $BgpVrfNeighborKeyChainName
                                $ExternalNeighborKeyChainList += $BgpVrfNeighbor + "`n " + $BgpVrfNeighborKeyChain + "`n`n"
                            }
                        }
                        else {
                            $ExternalNeighborList += "$BgpVrfNeighbor" + "`n"
                        }
                    }
                    else {
                        $NotExternalNeighborList += "$BgpVrfNeighbor" + "`n"
                    }
                }
                else {
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "No remote-as configured for BGP neighbor '$BgpVrfNeighbor'." | Out-String
                    $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
                    $FindingDetails += "" | Out-String
                    $Exception = $True
                }
            }
        }
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Router BGP not configured in device." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    if ($ExternalNeighborKeyChainList -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following external BGP neighbors are configured with unique keychains." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $ExternalNeighborKeyChainList
        $FindingDetails += "" | Out-String
    }
    if ($ExternalNeighborKeyChainList -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following external BGP neighbors are not associated keychains." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $ExternalNeighborList
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

Function Get-V217009 {
    <#
    .DESCRIPTION
        Vuln ID    : V-217009
        STIG ID    : CISC-RT-000750
        Rule ID    : SV-217009r945860_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000205-RTR-000016
        Rule Title : The Cisco PE router must be configured to ignore or block all packets with any IP options.
        DiscussMD5 : AF758A1A25F785C9D837E4606B47A8B6
        CheckMD5   : 38741C1E42AA422A25D69A925C64BD4C
        FixMD5     : 71683CE2D992E152B077FF81E128208B
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
    #Checks for router msdp peers
    $SourceRoute = $ShowRunningConfig | Select-String -Pattern "^ipv4 source-route"
    if ($SourceRoute) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "ipv4 source-route is configured for the router. This is a finding. " | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "ipv4 source-route is not configured for the router. " | Out-String
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

Function Get-V230037 {
    <#
    .DESCRIPTION
        Vuln ID    : V-230037
        STIG ID    : CISC-RT-000235
        Rule ID    : SV-230037r878128_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-RTR-000100
        Rule Title : The Cisco router must be configured to have Cisco Express Forwarding enabled.
        DiscussMD5 : A1D0C6AD10599F8CA9AE95313508FB3C
        CheckMD5   : 52F8F5525C31AF71C6BAB7F4F837F315
        FixMD5     : 0985BF68A2EE61C3B2FFCCDFE4124BFC
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
    $ShowCef = $(Get-CiscoShowTechData -ShowTech $ShowTech -DataType XR-Cef)
    $OpenFinding = $False
    $Exception = $False
    #Checks for router msdp peers
    $IpCef = (($ShowCef | Select-String -Pattern "^ip cef") -or ($ShowRunningConfig | Select-String -Pattern "^ipv6 cef"))
    if (!$IpCef) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "CEF is not enabled on the router. This is a finding. " | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "CEF is enabled for the router. " | Out-String
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

Function Get-V230040 {
    <#
    .DESCRIPTION
        Vuln ID    : V-230040
        STIG ID    : CISC-RT-000236
        Rule ID    : SV-230040r532994_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-RTR-000012
        Rule Title : The Cisco router must be configured to advertise a hop limit of at least 32 in Router Advertisement messages for IPv6 stateless auto-configuration deployments.
        DiscussMD5 : 58951D134DA33AFAB85953208EA404A6
        CheckMD5   : 7ADEB7B4E3D9123EC62E341328677709
        FixMD5     : 945587ACD4773B3B4ABE1A6AF37DC171
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
    #Checks for router msdp peers
    $HopLimit = $ShowRunningConfig | Select-String -Pattern "^ipv6 hop-limit .*"
    if (!$HopLimit) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "ipv6 hop-limit is not configured for the router." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    else {
        $HopLimitNo = $HopLimit.ToString().Split([char[]]"") | Select-Object -Last 1
        $HopLimitNo = [int]$HopLimitNo
        if ($HopLimitNo -lt 32) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "ipv6 hop-limit is configured for the router. But less than 32. This is a finding.  " | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += "'$HopLimit'"
            $FindingDetails += "" | Out-String
            $OpenFinding = $True
        }
        else {
            $FindingDetails += "" | Out-String
            $FindingDetails += "ipv6 hop-limit is configured for the router and id greater than 32.  " | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += "'$HopLimit'"
            $FindingDetails += "" | Out-String
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

Function Get-V230043 {
    <#
    .DESCRIPTION
        Vuln ID    : V-230043
        STIG ID    : CISC-RT-000237
        Rule ID    : SV-230043r533001_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-RTR-000013
        Rule Title : The Cisco router must not be configured to use IPv6 Site Local Unicast addresses.
        DiscussMD5 : 5905FE5CC4A0A6775A24A1662EC96B2A
        CheckMD5   : B4CD914D70E318420F481682924A89CF
        FixMD5     : 09258164C3BE526391F7F061323EF3ED
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
    #Checks for FEC0
    $FecoConf = $ShowRunningConfig | Select-String -Pattern "FEC0"
    if ($FecoConf) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "FEC0::/10 IPv6 should not be configured for the router. This is a finding. " | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += "$FecoConf"
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "FEC0::/10 IPv6 addresses is not configured for the router. " | Out-String
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

Function Get-V230046 {
    <#
    .DESCRIPTION
        Vuln ID    : V-230046
        STIG ID    : CISC-RT-000391
        Rule ID    : SV-230046r533007_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-RTR-000014
        Rule Title : The Cisco perimeter router must be configured to suppress Router Advertisements on all external IPv6-enabled interfaces.
        DiscussMD5 : 38D1C8FFBC0B7B3BB01BC9B0E6A2D5A1
        CheckMD5   : AD27B90E97037E6DBEF8AC3F9749AB0F
        FixMD5     : 697936D913C8B682DBF2BF42E9570247
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
    $IntNdRaSuppress = @()
    $NotIntNdRaSuppress = @()
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
    foreach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        $Ipv6Addresses = ($InterfaceConfig | Select-String -Pattern "ipv6 address .*")
        if ($Ipv6Addresses) {
            $Ipv6NdRaSuppress = ($InterfaceConfig | Select-String -Pattern "ipv6 nd ra suppress")
            if ($Ipv6NdRaSuppress) {
                $IntNdRaSuppress += "$Interface" + "`n"
            }
            else {
                $NotIntNdRaSuppress += "$Interface" + "`n"
            }
        }
    }
    if ($IntNdRaSuppress.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following ipv6 interfaces are configured with nd ra suppress." | Out-String
        $FindingDetails += "Router should be configured to suppress Router Advertisements on all external IPv6-enabled interfaces." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $IntNdRaSuppress
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    if ($NotIntNdRaSuppress.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following ipv6 interfaces are not configured with nd ra suppress." | Out-String
        $FindingDetails += "Router should be configured to suppress Router Advertisements on all external IPv6-enabled interfaces." | Out-String
        $FindingDetails += " Verify following are not external IPv6-enabled interfaces." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $NotIntNdRaSuppress
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    else {
        $FindingDetails += "" | Out-String
        $FindingDetails += "No ipv6 interfaces are configured with nd ra suppress in the device." | Out-String
        $FindingDetails += "Router should be configured to suppress Router Advertisements on all external IPv6-enabled interfaces." | Out-String
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

Function Get-V230049 {
    <#
    .DESCRIPTION
        Vuln ID    : V-230049
        STIG ID    : CISC-RT-000392
        Rule ID    : SV-230049r950991_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000364-RTR-000200
        Rule Title : The Cisco perimeter router must be configured to drop IPv6 undetermined transport packets.
        DiscussMD5 : 6F5EC21E86DCCDD4BDAC9197F76B8722
        CheckMD5   : B275F98FFD60A95C446167C4A92ECFE0
        FixMD5     : 486446CACBAFE56A748357E9632849E1
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
    #Interfaces
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
    $IngressInterfaceList = @()
    $NoTransportPkgList = @()
    foreach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        $InterfaceConfigPretty = $InterfaceConfig | Out-String
        $IngressACLs = ($InterfaceConfig | Select-String -Pattern "ipv6 access-group .* ingress")
        if ($IngressACLs) {
            $InterfaceIpv6Address = ($InterfaceConfig | Select-String -Pattern "ipv6 address .*")
            if ($InterfaceIpv6Address) {
                foreach ($IngressACL in $IngressACLs) {
                    $ACLName = $IngressACL.ToString().Split([char[]]"") | Select-Object -Index 2
                    $ACLExtended = $ShowRunningConfig | Select-String -Pattern "^ipv6 access-list $ACLName"
                    if ($ACLExtended) {
                        $ACLConfig = Get-Section $ShowRunningConfig $ACLExtended.ToString()
                        $ACLDenyIpTransport = "deny ipv6 any any log undetermined-transport"
                        $ACLDenyAny = "deny ipv6 any any log"
                        if (($ACLConfig | Select-String -Pattern $ACLDenyIpTransport) -and ($ACLConfig | Select-String -Pattern $ACLDenyAny)) {
                            $IngressInterfaceList += "$Interface`n$InterfaceConfigPretty`n`n$ACLExtended`n$ACLDenyIpTransport`n$ACLDenyAny`n`n"
                        }
                        else {
                            $NoTransportPkgList += "$Interface`n$InterfaceConfigPretty`n`n$ACLExtended`n`n"
                        }
                    }
                    else {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Ingress ACL '$ACLName' for '$Interface' is not configured in the system. This is a finding" | Out-String
                        $FindingDetails += "" | Out-String
                        $OpenFinding = $True
                    }
                }
            }
            else {
                $FindingDetails += "" | Out-String
                $FindingDetails += "ipv6 address not configured for '$Interface' with ingress ACL '$ACLName'. This is a finding" | Out-String
                $FindingDetails += "" | Out-String
                $OpenFinding = $True
            }
        }
    }
    if ($IngressInterfaceList.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following interface and associated ipv6 ingress ACLs are configured to drop IPv6 undetermined transport packets." | Out-String
        $FindingDetails += "Verify inbound IPv6 ACL has been configured on the external interface." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $IngressInterfaceList
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    if ($NoTransportPkgList.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following interface and associated ipv6 ingress ACLs are not configured to drop undetermined transport packets." | Out-String
        $FindingDetails += "If inbound IPv6 ACL has been configured on the external interface, this will be a finding." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $NoTransportPkgList
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

Function Get-V230052 {
    <#
    .DESCRIPTION
        Vuln ID    : V-230052
        STIG ID    : CISC-RT-000393
        Rule ID    : SV-230052r856665_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000364-RTR-000201
        Rule Title : The Cisco perimeter router must be configured drop IPv6 packets with a Routing Header type 0, 1, or 3–255.
        DiscussMD5 : BFAE3EE23704B264822D9E59DBA7C85E
        CheckMD5   : 02A1F0DD016C34BA12E72C69F4F4AF16
        FixMD5     : A8F164CC72F4EB34E705E685EFD158A0
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
    #Interfaces
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
    $RoutingTypeSetList = @()
    $RoutingTypeNotSetList = @()
    $NoDenyRoutingLogList = @()
    foreach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        $InterfaceConfigPretty = $InterfaceConfig | Out-String
        $IngressACLs = ($InterfaceConfig | Select-String -Pattern "ipv6 access-group .* ingress")
        if ($IngressACLs) {
            $InterfaceIpv6Address = ($InterfaceConfig | Select-String -Pattern "ipv6 address .*")
            if ($InterfaceIpv6Address) {
                foreach ($IngressACL in $IngressACLs) {
                    $ACLName = $IngressACL.ToString().Split([char[]]"") | Select-Object -Index 2
                    $ACLExtended = $ShowRunningConfig | Select-String -Pattern "^ipv6 access-list $ACLName"
                    if ($ACLExtended) {
                        $ACLConfig = Get-Section $ShowRunningConfig $ACLExtended.ToString()
                        $ACLConfigRoutingTypes = $ACLConfig | Select-String -Pattern "permit .* routing-type"
                        if ($ACLConfigRoutingTypes) {
                            foreach ($ACLConfigRoutingType in $ACLConfigRoutingTypes) {
                                $RoutingType = $ACLConfigRoutingType.ToString().Split([char[]]"") | Select-Object -Index 7
                                $RoutingType = [int] $RoutingType
                                if (($RoutingType -lt 2) -or ($RoutingType -gt 2)) {
                                    $RoutingTypeNotSetList += "$Interface`n $ACLName`n`n"
                                }
                                else {
                                    $ACLDenyIpTransport = "deny ipv6 any any routing log"
                                    $ACLDenyAny = "deny ipv6 any any log"
                                    if (($ACLConfig | Select-String -Pattern $ACLDenyIpTransport) -and ($ACLConfig | Select-String -Pattern $ACLDenyAny)) {
                                        $RoutingTypeSetList += "$Interface`n$InterfaceConfigPretty`n`n$ACLExtended`n$ACLDenyIpTransport`n$ACLDenyAny`n`n"
                                    }
                                    else {
                                        $NoDenyRoutingLogList += "$Interface`n $ACLExtended`n`n"
                                    }
                                }
                            }
                        }
                    }
                    else {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Ingress ACL '$ACLName' for '$Interface' is not configured in the system. This is a finding" | Out-String
                        $FindingDetails += "" | Out-String
                        $OpenFinding = $True
                    }
                }
            }
            else {
                $FindingDetails += "" | Out-String
                $FindingDetails += "ipv6 address not configured for '$Interface' with ingress ACL '$ACLName'. This is a finding" | Out-String
                $FindingDetails += "" | Out-String
                $OpenFinding = $True
            }
        }
    }
    if ($RoutingTypeSetList.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following interface and associated ipv6 ingress ACLs are configured to drop IPv6 packets containing a Routing Header of type 0, 1, or 3-255." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $RoutingTypeSetList
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    if ($RoutingTypeNotSetList.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following interface and associated ipv6 ingress ACLs are not configured to drop IPv6 packets containing a Routing Header of type 0, 1, or 3-255.." | Out-String
        $FindingDetails += "This is a finding" | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $RoutingTypeNotSetList
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }
    if ($NoDenyRoutingLogList.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "Following interface and associated ipv6 ingress ACLs are configured to drop IPv6 packets containing a Routing Header of type 0, 1, or 3-255." | Out-String
        $FindingDetails += "But deny ipv6 any any routing log or deny ipv6 any any log is not configured." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $NoDenyRoutingLogList
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

Function Get-V230147 {
    <#
    .DESCRIPTION
        Vuln ID    : V-230147
        STIG ID    : CISC-RT-000394
        Rule ID    : SV-230147r1132531_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000364-RTR-000202
        Rule Title : The Cisco perimeter router must be configured to drop IPv6 packets containing a Hop-by-Hop header with invalid option type values.
        DiscussMD5 : 656C5FF07F8F3226F2834A62F85EF5D8
        CheckMD5   : 517A05DA5B0CB354A9F7AB069959C426
        FixMD5     : DB3F0B4A76CD92BD2FEDBD4F5097C1A8
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
    #Interfaces with inbound ACLs
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
    $Ipv6InterfaceList = @()
    $NoHbhIpv6InterfaceList = @()
    foreach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        $IngressACLs = ($InterfaceConfig | Select-String -Pattern "ipv6 access-group .* ingress")
        if ($IngressACLs) {
            $InterfaceIpv6Address = ($InterfaceConfig | Select-String -Pattern "ipv6 address .*")
            if ($InterfaceIpv6Address) {
                foreach ($IngressACL in $IngressACLs) {
                    $ACLName = $IngressACL.ToString().Split([char[]]"") | Select-Object -Index 2
                    $ACLExtended = $ShowRunningConfig | Select-String -Pattern "^ipv6 access-list $ACLName"
                    if ($ACLExtended) {
                        $hbhString1 = "deny hbh any any dest-option log"
                        $ACLConfig = Get-Section $ShowRunningConfig $ACLExtended.ToString()
                        if ($ACLConfig | Select-String -Pattern $hbhString1) {
                            $Ipv6InterfaceList += "$Interface" + "`n " + "$IngressACL" + "`n`n"
                        }
                        else {
                            $NoHbhIpv6InterfaceList += "$Interface" + "`n " + "$IngressACL" + "`n`n"
                        }
                    }
                    else {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Ingress ACL '$ACLName' for '$Interface' is not configured in this router. This is a finding." | Out-String
                        $FindingDetails += "" | Out-String
                        $OpenFinding = $True
                    }
                }
            }
            else {
                $FindingDetails += "" | Out-String
                $FindingDetails += "IPv6 address not configured for '$Interface' with ingress ACL '$ACLName'. This is a finding." | Out-String
                $FindingDetails += "" | Out-String
                $OpenFinding = $True
            }
        }
    }
    if ($Ipv6InterfaceList.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "The following interfaces and associated IPv6 ingress ACLs are configured in this device to drop IPv6 packets containing a Hop-by-Hop header with destination option." | Out-String
        $FindingDetails += "Verify if an inbound IPv6 ACL has been configured on all external interfaces." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $Ipv6InterfaceList
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    if ($NoHbhIpv6InterfaceList.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "The following interfaces and associated IPv6 ingress ACLs are not configured in this device to drop IPv6 packets containing a Hop-by-Hop header with destination option." | Out-String
        $FindingDetails += "Verify if an inbound IPv6 ACL has been configured on all external interfaces." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $NoHbhIpv6InterfaceList
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

Function Get-V230151 {
    <#
    .DESCRIPTION
        Vuln ID    : V-230151
        STIG ID    : CISC-RT-000395
        Rule ID    : SV-230151r1132534_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000364-RTR-000203
        Rule Title : The Cisco perimeter router must be configured to drop IPv6 packets containing a Destination Option header with invalid option type values.
        DiscussMD5 : BCE33EA8AC14AE74CC7A1B48701EC393
        CheckMD5   : 7714005D7C918D5FBC081C53D87FBCBD
        FixMD5     : 626D2EAC0E35789161E625FF8CB6690E
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
    #Interfaces with inbound ACLs
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
    $Ipv6InterfaceList = @()
    $NoHbhIpv6InterfaceList = @()
    foreach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        $IngressACLs = ($InterfaceConfig | Select-String -Pattern "ipv6 access-group .* ingress")
        if ($IngressACLs) {
            $InterfaceIpv6Address = ($InterfaceConfig | Select-String -Pattern "ipv6 address .*")
            if ($InterfaceIpv6Address) {
                foreach ($IngressACL in $IngressACLs) {
                    $ACLName = $IngressACL.ToString().Split([char[]]"") | Select-Object -Index 2
                    $ACLExtended = $ShowRunningConfig | Select-String -Pattern "^ipv6 access-list $ACLName"
                    if ($ACLExtended) {
                        $hbhString1 = "deny 60 any any dest-option log"
                        $ACLConfig = Get-Section $ShowRunningConfig $ACLExtended.ToString()
                        if ($ACLConfig | Select-String -Pattern $hbhString1) {
                            $Ipv6InterfaceList += "$Interface" + "`n " + "$IngressACL" + "`n`n"
                        }
                        else {
                            $NoHbhIpv6InterfaceList += "$Interface" + "`n " + "$IngressACL" + "`n`n"
                        }
                    }
                    else {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Ingress ACL '$ACLName' for '$Interface' is not configured in this router. This is a finding." | Out-String
                        $FindingDetails += "" | Out-String
                        $OpenFinding = $True
                    }
                }
            }
            else {
                $FindingDetails += "" | Out-String
                $FindingDetails += "IPv6 address not configured for '$Interface' with ingress ACL '$ACLName'. This is a finding." | Out-String
                $FindingDetails += "" | Out-String
                $OpenFinding = $True
            }
        }
    }
    if ($Ipv6InterfaceList.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "The following interfaces and associated IPv6 ingress ACLs are configured in this device to drop IPv6 packets containing a destination option header." | Out-String
        $FindingDetails += "Verify if an inbound IPv6 ACL has been configured on all external interfaces." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $Ipv6InterfaceList
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    if ($NoHbhIpv6InterfaceList.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "The following interfaces and associated IPv6 ingress ACLs are not configured in this device to drop IPv6 packets containing a destination option header." | Out-String
        $FindingDetails += "Verify if an inbound IPv6 ACL has been configured on all external interfaces." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $NoHbhIpv6InterfaceList
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

Function Get-V230154 {
    <#
    .DESCRIPTION
        Vuln ID    : V-230154
        STIG ID    : CISC-RT-000396
        Rule ID    : SV-230154r1132537_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000364-RTR-000204
        Rule Title : The Cisco perimeter router must be configured to drop IPv6 packets containing an extension header with the Endpoint Identification option.
        DiscussMD5 : E5C7A9AE4D14F4BD2F188D81435C985F
        CheckMD5   : CFD009E63766F21765F073DB86B99129
        FixMD5     : A92001DFB8E7EEF34B7C1D32886AFA6B
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
    #Interfaces with inbound ACLs
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
    $Ipv6InterfaceList = @()
    $NoHbhIpv6InterfaceList = @()
    foreach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        $IngressACLs = ($InterfaceConfig | Select-String -Pattern "ipv6 access-group .* ingress")
        if ($IngressACLs) {
            $InterfaceIpv6Address = ($InterfaceConfig | Select-String -Pattern "ipv6 address .*")
            if ($InterfaceIpv6Address) {
                foreach ($IngressACL in $IngressACLs) {
                    $ACLName = $IngressACL.ToString().Split([char[]]"") | Select-Object -Index 2
                    $ACLExtended = $ShowRunningConfig | Select-String -Pattern "^ipv6 access-list $ACLName"
                    if ($ACLExtended) {
                        $hbhString1 = "deny 60 any any dest-option log"
                        $hbhString2 = "deny hbh any any dest-option log"
                        $ACLConfig = Get-Section $ShowRunningConfig $ACLExtended.ToString()
                        if (($ACLConfig | Select-String -Pattern $hbhString1) -and ($ACLConfig | Select-String -Pattern $hbhString2)) {
                            $Ipv6InterfaceList += "$Interface" + "`n " + "$IngressACL" + "`n`n"
                        }
                        else {
                            $NoHbhIpv6InterfaceList += "$Interface" + "`n " + "$IngressACL" + "`n`n"
                        }
                    }
                    else {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Ingress ACL '$ACLName' for '$Interface' is not configured in this router. This is a finding." | Out-String
                        $FindingDetails += "" | Out-String
                        $OpenFinding = $True
                    }
                }
            }
            else {
                $FindingDetails += "" | Out-String
                $FindingDetails += "IPv6 address not configured for '$Interface' with ingress ACL '$ACLName'. This is a finding." | Out-String
                $FindingDetails += "" | Out-String
                $OpenFinding = $True
            }
        }
    }
    if ($Ipv6InterfaceList.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "The following interfaces and associated IPv6 ingress ACLs are configured in this device to drop IPv6 packets containing a destination option header." | Out-String
        $FindingDetails += "Verify if an inbound IPv6 ACL has been configured on all external interfaces." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $Ipv6InterfaceList
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    if ($NoHbhIpv6InterfaceList.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "The following interfaces and associated IPv6 ingress ACLs are not configured in this device to drop IPv6 packets containing a destination option header." | Out-String
        $FindingDetails += "Verify if an inbound IPv6 ACL has been configured on all external interfaces." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $NoHbhIpv6InterfaceList
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

Function Get-V230157 {
    <#
    .DESCRIPTION
        Vuln ID    : V-230157
        STIG ID    : CISC-RT-000397
        Rule ID    : SV-230157r1132540_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000364-RTR-000205
        Rule Title : The Cisco perimeter router must be configured to drop IPv6 packets containing the NSAP address option within Destination Option header.
        DiscussMD5 : D9C7467C245639452E2AB647D504F034
        CheckMD5   : FBAEF4D9DE4BAB2600E9462C97F78702
        FixMD5     : 626D2EAC0E35789161E625FF8CB6690E
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
    #Interfaces with inbound ACLs
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
    $Ipv6InterfaceList = @()
    $NoHbhIpv6InterfaceList = @()
    foreach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        $IngressACLs = ($InterfaceConfig | Select-String -Pattern "ipv6 access-group .* ingress")
        if ($IngressACLs) {
            $InterfaceIpv6Address = ($InterfaceConfig | Select-String -Pattern "ipv6 address .*")
            if ($InterfaceIpv6Address) {
                foreach ($IngressACL in $IngressACLs) {
                    $ACLName = $IngressACL.ToString().Split([char[]]"") | Select-Object -Index 2
                    $ACLExtended = $ShowRunningConfig | Select-String -Pattern "^ipv6 access-list $ACLName"
                    if ($ACLExtended) {
                        $hbhString1 = "deny 60 any any dest-option log"
                        $ACLConfig = Get-Section $ShowRunningConfig $ACLExtended.ToString()
                        if ($ACLConfig | Select-String -Pattern $hbhString1) {
                            $Ipv6InterfaceList += "$Interface" + "`n " + "$IngressACL" + "`n`n"
                        }
                        else {
                            $NoHbhIpv6InterfaceList += "$Interface" + "`n " + "$IngressACL" + "`n`n"
                        }
                    }
                    else {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Ingress ACL '$ACLName' for '$Interface' is not configured in this router. This is a finding." | Out-String
                        $FindingDetails += "" | Out-String
                        $OpenFinding = $True
                    }
                }
            }
            else {
                $FindingDetails += "" | Out-String
                $FindingDetails += "IPv6 address not configured for '$Interface' with ingress ACL '$ACLName'. This is a finding." | Out-String
                $FindingDetails += "" | Out-String
                $OpenFinding = $True
            }
        }
    }
    if ($Ipv6InterfaceList.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "The following interfaces and associated IPv6 ingress ACLs are configured in this device to drop IPv6 packets containing a destination option header." | Out-String
        $FindingDetails += "Verify if an inbound IPv6 ACL has been configured on all external interfaces." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $Ipv6InterfaceList
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    if ($NoHbhIpv6InterfaceList.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "The following interfaces and associated IPv6 ingress ACLs are not configured in this device to drop IPv6 packets containing a destination option header." | Out-String
        $FindingDetails += "Verify if an inbound IPv6 ACL has been configured on all external interfaces." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $NoHbhIpv6InterfaceList
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

Function Get-V230160 {
    <#
    .DESCRIPTION
        Vuln ID    : V-230160
        STIG ID    : CISC-RT-000398
        Rule ID    : SV-230160r1132543_rule
        CCI ID     : CCI-002403
        Rule Name  : SRG-NET-000364-RTR-000206
        Rule Title : The Cisco perimeter router must be configured to drop IPv6 packets containing a Hop-by-Hop or Destination Option extension header with an undefined option type.
        DiscussMD5 : 82357BC78DDDA9AABDDF330E2B960775
        CheckMD5   : D51A1EA0553F3B6465AF61C9468EC3B3
        FixMD5     : EAF36508A879EB1C4884A0295B0A02AF
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
    #Interfaces with inbound ACLs
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
    $Ipv6InterfaceList = @()
    $NoHbhIpv6InterfaceList = @()
    foreach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        $IngressACLs = ($InterfaceConfig | Select-String -Pattern "ipv6 access-group .* ingress")
        if ($IngressACLs) {
            $InterfaceIpv6Address = ($InterfaceConfig | Select-String -Pattern "ipv6 address .*")
            if ($InterfaceIpv6Address) {
                foreach ($IngressACL in $IngressACLs) {
                    $ACLName = $IngressACL.ToString().Split([char[]]"") | Select-Object -Index 2
                    $ACLExtended = $ShowRunningConfig | Select-String -Pattern "^ipv6 access-list $ACLName"
                    if ($ACLExtended) {
                        $hbhString1 = "deny 60 any any dest-option log"
                        $hbhString2 = "deny hbh any any dest-option log"
                        $ACLConfig = Get-Section $ShowRunningConfig $ACLExtended.ToString()
                        if (($ACLConfig | Select-String -Pattern $hbhString1) -and ($ACLConfig | Select-String -Pattern $hbhString2)) {
                            $Ipv6InterfaceList += "$Interface" + "`n " + "$IngressACL" + "`n`n"
                        }
                        else {
                            $NoHbhIpv6InterfaceList += "$Interface" + "`n " + "$IngressACL" + "`n`n"
                        }
                    }
                    else {
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "Ingress ACL '$ACLName' for '$Interface' is not configured in this router. This is a finding." | Out-String
                        $FindingDetails += "" | Out-String
                        $OpenFinding = $True
                    }
                }
            }
            else {
                $FindingDetails += "" | Out-String
                $FindingDetails += "IPv6 address not configured for '$Interface' with ingress ACL '$ACLName'. This is a finding." | Out-String
                $FindingDetails += "" | Out-String
                $OpenFinding = $True
            }
        }
    }
    if ($Ipv6InterfaceList.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "The following interfaces and associated IPv6 ingress ACLs are configured in this device to drop IPv6 packets containing a destination option header." | Out-String
        $FindingDetails += "Verify if an inbound IPv6 ACL has been configured on all external interfaces." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $Ipv6InterfaceList
        $FindingDetails += "" | Out-String
        $Exception = $True
    }
    if ($NoHbhIpv6InterfaceList.Count -gt 0) {
        $FindingDetails += "" | Out-String
        $FindingDetails += "The following interfaces and associated IPv6 ingress ACLs are not configured in this device to drop IPv6 packets containing a destination option header." | Out-String
        $FindingDetails += "Verify if an inbound IPv6 ACL has been configured on all external interfaces." | Out-String
        $FindingDetails += "Review and make finding determination based on STIG check guidance." | Out-String
        $FindingDetails += "-------------------------------------------" | Out-String
        $FindingDetails += $NoHbhIpv6InterfaceList
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCANIpDFnrYbzSBT
# Zh56YApoQLh7EqmOe/EPzmf0CCzzaaCCHiQwggUqMIIEEqADAgECAgMTYdUwDQYJ
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
# BCAnFG1BJxCnKycApID5Cjaz3W8xWwtZg0aPfdhyATCRLDANBgkqhkiG9w0BAQEF
# AASCAQCkW+AayKETFqluSnMU1BG/yaUyf50yMWgDO+0MWFryM6Wrfary8v+UODBe
# /rPCfNHBfIhqQe3UcVUtNMtDWJmlDkCuvu4Ft9ahKAa9GfzbX5S9T8vFVs33hIS+
# xgHm6gahkIccWrSas6+0+GpZBb6VygaQ3qyMNTLsmL+hWzOAk3FGGIhzFHO86XS7
# GDHly5O8uHbbyGFvde4l4EAyaUbgQ7oLkR2GLmm5cLPywtddjfGS3w5Txx6CVuGg
# mBbv8v5a7jfhvGEziVhzDUjdIYICRSOnu2ZLExZ9WS7lQSlm+rSmdOTgvROv6OBW
# 2ffDtVwJe4tPF0FmbGKKTpNQCusDoYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMP
# AgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEw
# PwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2
# IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0aDANBglghkgBZQMEAgEF
# AKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI2
# MDQyMjE2MTcxN1owLwYJKoZIhvcNAQkEMSIEIGyE75zp1C1BJYPWpUdU1h+xWMgM
# YikREKNKK5CBctwTMA0GCSqGSIb3DQEBAQUABIICAGcvo/UoY4yQKgRSjtO7qolY
# PohIRfOOFYqGm+hR8VZ3XasnpNtP0ia59O0ds/z0u2iXqwWVcf6FkSM/DeR1TJfo
# 3ifI3BjJZsJOVMuwJZGOF1YxLhw5JXEPMqqr1X8vThQuTbRDt7ifTrfB9h9uEyNH
# lzQurQ9frdLq6L9E3x/nLNrSuCoW3ebvSahgrkctR/xDj900sQpFDZmZS/xE8YdD
# ktUiftv20yNIbFQ8iyno+9PzfnNQPpqrx/A2qlEJSLf61thAGNX+PbLjhlJZ4Uwg
# gU/3nSdxKCyx0F3ePnCoMC0iaoB8VRn/n9u+uVc49qed6XbTQVfIkLiaHOV79tdY
# om1IAIx0L+pbD1B+RuX9pHkZVIpntQvePDYh6KgEwxImyQ/LRVA/GK5VA/89bnEj
# yPLeKTMTQqcPSvx92CJXeTzXCQTqUMUuScNS9p9+V9B2SVKCCuG2ND3Pb5qC/c7U
# Zk+sCNlH/4Shsr4GilgHyNRGcPdtLigaG4YPMaBBcM0DSKuuxaSU7ibnutQX6o7n
# hYW/w7dkVRRnBxsV3zbjVpdCWhTaw/DPTG2zmq8wDIx8YSezDQ/h9V1nkMcQAzSG
# F0Jobr2k/oINCpl4OzW1Ygwz8G3ucceJtnC52fK1YyANpvLl+nDoiRH0HGWmsSZa
# PHkUhYnfINfyyRIH/P4h
# SIG # End signature block
