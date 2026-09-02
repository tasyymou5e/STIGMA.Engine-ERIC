############################################
# File Output functions for Evaluate-STIG #
############################################

Function Get-TruncatedOutput {
    param (
        [Parameter(Mandatory = $true)]
        [string]$InputText,

        [Parameter(Mandatory = $true)]
        [Int32]$TruncateOutput
    )

    # Calculate buffer for newline character to help prevent additional truncation in external tools.
    $Buffer = [regex]::Matches($InputText, "(\r\n|\r|\n)").Count
    $EffectiveTruncate = $TruncateOutput - $Buffer

    if ($InputText.Trim().Length -gt $EffectiveTruncate) {
        $OutputSplit = $InputText -split "~~~~~", 2
        $HeaderText = $OutputSplit[0].Trim()
        $BarText = "`r`n~~~~~`r`n"
        $DetailText = $OutputSplit[1].Trim()
        $MsgText = "`r`n`r`n---truncated results. met character limit of $($TruncateOutput)---"

        if ($HeaderText.Length + $BarText.Length + $MsgText.Length -ge $EffectiveTruncate) {
            # Preserve full header and bar text
            $OutputText = $HeaderText + $BarText + $MsgText
        }
        else {
            # Set truncation point to retain header/bar text and maximize detail, while appending
            # truncation message and keeping output within the character constraints.
            $TruncateAt = $EffectiveTruncate - $MsgText.Length
            $OutputText = $(($HeaderText + $BarText + $DetailText).Substring(0, $TruncateAt)) + $MsgText
        }
    }
    else {
        $OutputText = $InputText
    }

    return $OutputText.Trim()
}

Function Format-Object {
    Param (
        [Parameter(Mandatory = $true)]
        [array]$OutputPayload,

        [Parameter(Mandatory = $true)]
        [psobject]$ScanObject,

        [Parameter(Mandatory = $true)]
        [Int32]$TruncateOutput
    )

    $FileObjects = New-Object System.Collections.Generic.List[System.Object]

    Foreach ($Scan_Object in $ScanObject) {
        Foreach ($Vuln in $Scan_Object.VulnResults) {
            # Set TruncatedFindingDetails and TruncatedComments variables
            if ($null -ne $Vuln.FindingDetails -and $Vuln.FindingDetails.Trim().Length -gt 0) {
                $TruncatedFindingDetails = Get-TruncatedOutput -InputText $Vuln.FindingDetails -TruncateOutput $TruncateOutput
            }
            else {
                $TruncatedFindingDetails = ""
            }
            if ($null -ne $Vuln.Comments -and $Vuln.Comments.Trim().Length -gt 0) {
                $TruncatedComments = Get-TruncatedOutput -InputText $Vuln.Comments -TruncateOutput $TruncateOutput
            }
            else {
                $TruncatedComments = ""
            }

            $Object = [PSCustomObject]@{}
            Switch ($OutputPayload) {
                "Title"            {$Object | Add-Member -MemberType NoteProperty -Name "Title" -Value $Scan_Object.STIGInfo.Title}
                "Version"          {$Object | Add-Member -MemberType NoteProperty -Name "Version" -Value "V$($Scan_Object.STIGInfo.Version)R$($Scan_Object.STIGInfo.Release)"}
                "ReleaseDate"      {$Object | Add-Member -MemberType NoteProperty -Name "ReleaseDate" -Value $Scan_Object.STIGInfo.ReleaseDate}
                "Classification"   {$Object | Add-Member -MemberType NoteProperty -Name "Classification" -Value $Scan_Object.STIGInfo.Classification}
                "HostName"         {$Object | Add-Member -MemberType NoteProperty -Name "HostName" -Value $Scan_Object.TargetData.HostName}
                "Site"             {$Object | Add-Member -MemberType NoteProperty -Name "Site" -Value $Scan_Object.TargetData.Site}
                "Instance"         {$Object | Add-Member -MemberType NoteProperty -Name "Instance" -Value $Scan_Object.TargetData.Instance}
                "IP"               {$Object | Add-Member -MemberType NoteProperty -Name "IP" -Value $Scan_Object.TargetData.IPAddress}
                "MAC"              {$Object | Add-Member -MemberType NoteProperty -Name "MAC" -Value $Scan_Object.TargetData.MacAddress}
                "FQDN"             {$Object | Add-Member -MemberType NoteProperty -Name "FQDN" -Value $Scan_Object.TargetData.FQDN}
                "Role"             {$Object | Add-Member -MemberType NoteProperty -Name "Role" -Value $Scan_Object.TargetData.Role}
                "GroupID"          {$Object | Add-Member -MemberType NoteProperty -Name "GroupID" -Value $Vuln.GroupID}
                "GroupTitle"       {$Object | Add-Member -MemberType NoteProperty -Name "GroupTitle" -Value $Vuln.GroupTitle}
                "RuleID"           {$Object | Add-Member -MemberType NoteProperty -Name "RuleID" -Value $Vuln.RuleID}
                "STIGID"           {$Object | Add-Member -MemberType NoteProperty -Name "STIGID" -Value $Vuln.STIGID}
                "Severity"         {$Object | Add-Member -MemberType NoteProperty -Name "Severity" -Value $Vuln.Severity}
                "SeverityOverride" {$Object | Add-Member -MemberType NoteProperty -Name "SeverityOverride" -Value $Vuln.SeverityOverride}
                "Justification"    {$Object | Add-Member -MemberType NoteProperty -Name "Justification" -Value $Vuln.Justification}
                "LegacyIDs"        {$Object | Add-Member -MemberType NoteProperty -Name "LegacyIDs" -Value $($Vuln.LegacyIDs -join '; ')}
                "RuleTitle"        {$Object | Add-Member -MemberType NoteProperty -Name "RuleTitle" -Value $Vuln.RuleTitle}
                "Discussion"       {$Object | Add-Member -MemberType NoteProperty -Name "Discussion" -Value $Vuln.Discussion}
                "CheckText"        {$Object | Add-Member -MemberType NoteProperty -Name "CheckText" -Value $Vuln.CheckText}
                "FixText"          {$Object | Add-Member -MemberType NoteProperty -Name "FixText" -Value $Vuln.FixText}
                "CCI"              {$Object | Add-Member -MemberType NoteProperty -Name "CCI" -Value $($Vuln.CCI -join '; ')}
                "Status"           {$Object | Add-Member -MemberType NoteProperty -Name "Status" -Value $Vuln.Status}
                "FindingDetails"   {$Object | Add-Member -MemberType NoteProperty -Name "FindingDetails" -Value $TruncatedFindingDetails}
                "Comments"         {$Object | Add-Member -MemberType NoteProperty -Name "Comments" -Value $TruncatedComments}
                "ESVersion"        {$Object | Add-Member -MemberType NoteProperty -Name "ESVersion" -Value $Scan_Object.ESData.ESVersion}
                "StartTime"        {$Object | Add-Member -MemberType NoteProperty -Name "StartTime" -Value $Scan_Object.ESData.StartTime}
            }
            $FileObjects.Add($Object)
        }
    }

    Return $FileObjects
}

Function Format-BaseFileName {
    Param (
        [Parameter(Mandatory = $true)]
        [String]$Hostname,

        [Parameter(Mandatory = $true)]
        [String]$STIGShortName,

        [Parameter(Mandatory = $false)]
        [String]$SiteOrInstance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $true)]
        [String]$STIGVersion
    )

    # Create list of invalid characters
    $InvalidChars = [System.IO.Path]::GetInvalidFileNameChars() # Get system identified invalid characters - varies by OS
    $InvalidChars += @('<', '>', ':', '"', '/', '\', '|', '?', '*')     # Add known invalid characters for Windows OS
    $InvalidChars = $InvalidChars | Select-Object -Unique       # Remove any duplicates

    # Build BaseFileName variable from inputs
    $BaseFileName = "$($Hostname)_$($STIGShortName)"
    If ($SiteOrInstance) {
        $BaseFileName += "_$($SiteOrInstance)"
    }
    If ($Database) {
        $BaseFileName += "_$($Database)"
    }
    $BaseFileName += "_$($StigVersion)"

    # Replace whitespace with "_"
    $BaseFileName = $BaseFileName -replace "\s+", "_"

    # Replace "\" and "/" with "-"
    $BaseFileName = ($BaseFileName -replace "(\\+|\/+)", "-") -replace ("-{2,}", "-")

    # Replace any invalid characters
    $ValidChar = '+'
    ForEach ($InvalidChar in $InvalidChars) {
        $BaseFileName = $BaseFileName.Replace($InvalidChar, $ValidChar)
    }
    $BaseFileName = $BaseFileName -replace "\+{2,}", "+"

    # Return formatted file name
    Return $BaseFileName
}

Function Format-CKL {
    param
    (
        [Parameter(Mandatory)]
        [string]$SchemaPath,

        [Parameter(Mandatory)]
        [psobject]$ScanObject,

        [Parameter(Mandatory)]
        [Int32]$TruncateOutput,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [Parameter()]
        [string]$Marking = "",

        [Parameter(Mandatory = $true)]
        [String]$WorkingDir,

        [Parameter(Mandatory = $true)]
        [String]$ESPath,

        [Parameter(Mandatory = $true)]
        [String]$LogComponent,

        [Parameter(Mandatory = $true)]
        [String]$OSPlatform
    )

    # Read the schema
    [xml]$Schema = Get-Content $SchemaPath

    # Get Target Data
    If (($ScanObject | Measure-Object).Count -gt 1) {
        If ($ScanObject | Where-Object {($_.ESData.CanCombine -eq $true)}) {
            $TargetData = ($ScanObject | Where-Object {($_.ESData.CanCombine -eq $true)})[0].TargetData
            $TargetKey = ($ScanObject | Where-Object {($_.ESData.CanCombine -eq $true)})[0].TargetData.TargetKey
            $ScanObject = ($ScanObject | Where-Object {($_.ESData.CanCombine -eq $true)})
        }
        Else {
            Throw "None of the scanned STIGs can be combined."
        }
    }
    Else {
        $TargetData = $ScanObject.TargetData
        $TargetKey = $ScanObject.TargetData.TargetKey
    }

    # Build the XML data
    $Encoding = [System.Text.UTF8Encoding]::new($false)
    $xmlSettings = New-Object System.Xml.XmlWriterSettings
    $xmlSettings.Encoding = $Encoding
    $xmlSettings.Indent = $true
    $xmlSettings.IndentChars = "`t"
    $xmlSettings.NewLineHandling = "None"

    $xmlWriter = [System.Xml.XmlWriter]::Create($($OutputPath), $xmlSettings)

    $rootnode = $Schema.SelectSingleNode("//*")

    $xpath = "*[local-name()='element' or local-name()='complexType' or local-name()='sequence' or local-name()='attribute']"
    $nodes = $rootnode.SelectNodes($xpath)

    # Create Evaluate-STIG comment
    $xmlWriter.WriteComment("<Evaluate-STIG><version>$($ScanObject[0].ESData.ESVersion)</version></Evaluate-STIG>")

    #We know Checklist is the root node and has "ASSET" and "STIGS" as sub nodes
    $xmlWriter.WriteStartElement("CHECKLIST")

    $xmlWriter.WriteStartElement("ASSET")
    # Specify elements and order from STIG Viewer saved CKL.  May differ from STIG Viewer schema.
    $SortOrder = @("ROLE", "ASSET_TYPE", "MARKING", "HOST_NAME", "HOST_IP", "HOST_MAC", "HOST_FQDN", "TARGET_COMMENT", "TECH_AREA", "TARGET_KEY", "WEB_OR_DATABASE", "WEB_DB_SITE", "WEB_DB_INSTANCE")
    Foreach ($node in $(($nodes | Where-Object {$_.Name -eq "ASSET"}).complexType.sequence.element) | Sort-Object {$SortOrder.IndexOf($_.ref)}) {
        If ($node.ref -in $SortOrder) {
            Switch ($Node.ref) {
                "ROLE" {
                    $ValidValues = @("None", "Workstation", "Member Server", "Domain Controller")
                    If ($TargetData.Role -and $TargetData.Role -notin $ValidValues) {
                        Throw "Invalid value for property [$($_)]: '$($TargetData.Role)'"
                    }
                    Else {
                        $xmlWriter.WriteElementString($Node.ref, $($TargetData.Role))
                    }
                }
                "ASSET_TYPE" {
                    $xmlWriter.WriteElementString($Node.ref, "Computing")
                }
                "MARKING" {
                    $xmlWriter.WriteElementString($Node.ref, $($Marking))
                }
                "HOST_NAME" {
                    $xmlWriter.WriteElementString($Node.ref, $($TargetData.Hostname))
                }
                "HOST_IP" {
                    $xmlWriter.WriteElementString($Node.ref, $($TargetData.IpAddress))
                }
                "HOST_MAC" {
                    $xmlWriter.WriteElementString($Node.ref, $($TargetData.MacAddress))
                }
                "HOST_FQDN" {
                    $xmlWriter.WriteElementString($Node.ref, $($TargetData.FQDN))
                }
                "TARGET_COMMENT" {
                    $xmlWriter.WriteElementString($Node.ref, $($TargetData.TargetComments))
                }
                "TECH_AREA" {
                    If (($ScanObject | Measure-Object).Count -gt 1) {
                        $xmlWriter.WriteElementString($Node.ref, "")
                    }
                    Else {
                        $xmlWriter.WriteElementString($Node.ref, $TargetData.CklTechArea)
                    }
                }
                "TARGET_KEY" {
                    $xmlWriter.WriteElementString($Node.ref, $TargetKey)
                }
                "WEB_OR_DATABASE" {
                    If ($TargetData.WebOrDatabase -notin @("true", "false")) {
                        Throw "Invalid value for property [$($_)]: '$($TargetData.WebOrDatabase )'"
                    }
                    Else {
                        $xmlWriter.WriteElementString($Node.ref, $(([String]($Targetdata.WebOrDatabase)).ToLower()))
                    }
                }
                "WEB_DB_SITE" {
                    $xmlWriter.WriteElementString($Node.ref, $($TargetData.Site))
                }
                "WEB_DB_INSTANCE" {
                    $xmlWriter.WriteElementString($Node.ref, $($TargetData.Instance))
                }
                default {
                    $xmlWriter.WriteStartElement($Node.ref)
                    $xmlWriter.WriteFullEndElement()
                }
            }
        }
    }
    $xmlWriter.WriteEndElement() #ASSET

    $xmlWriter.WriteStartElement("STIGS")

    ForEach ($Scan in $ScanObject) {
        # Read the STIG content
        If (-not($Scan.ESData.IsManualSTIG)) {
            $STIGXMLPath = $(Join-Path -Path $ESPath -ChildPath StigContent | Join-Path -ChildPath $Scan.ESData.STIGXMLName)
        }
        Else {
            $STIGXMLPath = $(Join-Path -Path $ESPath -ChildPath StigContent | Join-Path -ChildPath Manual | Join-Path -ChildPath $Scan.ESData.STIGXMLName)
        }
        # https://stackoverflow.com/questions/71847945/strange-characters-found-in-xml-file-and-powershell-output-after-exporting-from
        ($Content = [xml]::new()).Load($STIGXMLPath)

        # Set STIG Classification
        Switch -Regex ($Content.'xml-stylesheet') {
            'STIG_unclass.xsl' {
                $Classification = "UNCLASSIFIED"
            }
            'STIG_cui.xsl' {
                $Classification = "CUI"
            }
            DEFAULT {
                Throw "Unable to determine STIG classification."
            }
        }

        $xmlWriter.WriteStartElement("iSTIG")

        # Create Evaluate-STIG comment
        $xmlWriter.WriteComment("<Evaluate-STIG><time>$($Scan.ESData.StartTime)</time><module><name>$($Scan.ESData.ModuleName)</name><version>$([String]$Scan.ESData.ModuleVersion)</version></module></Evaluate-STIG>")

        $xmlWriter.WriteStartElement("STIG_INFO")
        # Specify elements and order from STIG Viewer saved CKL.  May differ from STIG Viewer schema.
        $SortOrder = @("version", "classification", "customname", "stigid", "description", "filename", "releaseinfo", "title", "uuid", "notice", "source")
        Foreach ($node in $(($nodes | Where-Object { $_.Name -eq "SID_NAME"}).simpleType.restriction.enumeration) | Sort-Object {$SortOrder.IndexOf($_.value)}) {
            If ($node.value -in $SortOrder) {
                $xmlWriter.WriteStartElement("SI_DATA")
                $xmlWriter.WriteElementString("SID_NAME", $Node.value)
                Switch ($Node.value) {
                    "version" {
                        $xmlWriter.WriteElementString("SID_DATA", $Content.Benchmark.version)
                    }
                    "classification" {
                        $xmlWriter.WriteElementString("SID_DATA", $Classification)
                    }
                    "customname" {
                        # Do Nothing
                    }
                    "stigid" {
                        $xmlWriter.WriteElementString("SID_DATA", $Content.Benchmark.id)
                    }
                    "description" {
                        $xmlWriter.WriteElementString("SID_DATA", $Content.Benchmark.description)
                    }
                    "filename" {
                        $xmlWriter.WriteElementString("SID_DATA", $(Split-Path $STIGXMLPath -Leaf))
                    }
                    "releaseinfo" {
                        $xmlWriter.WriteElementString("SID_DATA", ($Content.Benchmark.'plain-text' | Where-Object { $_.id -eq "release-info" }).'#text')
                    }
                    "title" {
                        $xmlWriter.WriteElementString("SID_DATA", $Content.Benchmark.title)
                    }
                    "uuid" {
                        $xmlWriter.WriteElementString("SID_DATA", $([guid]::NewGuid()))
                    }
                    "notice" {
                        $xmlWriter.WriteElementString("SID_DATA", $Content.Benchmark.notice.id)
                    }
                    "source" {
                        $xmlWriter.WriteElementString("SID_DATA", $Content.Benchmark.reference.source)
                    }
                }
                $xmlWriter.WriteEndElement() #SI_DATA
            }
        }
        $xmlWriter.WriteEndElement() #STIG_INFO
        # Specify elements and order from STIG Viewer saved CKL.  May differ from STIG Viewer schema.
        $SortOrder = @("STIG_DATA", "STATUS", "FINDING_DETAILS", "COMMENTS", "SEVERITY_OVERRIDE", "SEVERITY_JUSTIFICATION")
        $AttribSortOrder = @("Vuln_Num", "Severity", "Group_Title", "Rule_ID", "Rule_Ver", "Rule_Title", "Vuln_Discuss", "IA_Controls", "Check_Content", "Fix_Text", "False_Positives", "False_Negatives", "Documentable", "Mitigations", "Potential_Impact", "Third_Party_Tools", "Mitigation_Control", "Responsibility", "Security_Override_Guidance", "Check_Content_Ref", "Weight", "Class", "STIGRef", "TargetKey", "STIG_UUID", "LEGACY_ID", "CCI_REF")
        Foreach ($Vuln in $Content.Benchmark.Group) {
            # Get results from scan object
            $ScanResult = $Scan.VulnResults | Where-Object GroupID -EQ $Vuln.id
            # Set TruncatedFindingDetails and TruncatedComments variables
            if ($null -ne $ScanResult.FindingDetails -and$ScanResult.FindingDetails.Trim().Length -gt 0) {
                $TruncatedFindingDetails = Get-TruncatedOutput -InputText $ScanResult.FindingDetails -TruncateOutput $TruncateOutput
            }
            else {
                $TruncatedFindingDetails = ""
            }
            if ($null -ne $ScanResult.Comments -and $ScanResult.Comments.Trim().Length -gt 0) {
                $TruncatedComments = Get-TruncatedOutput -InputText $ScanResult.Comments -TruncateOutput $TruncateOutput
            }
            else {
                $TruncatedComments = ""
            }

            # Create VULN element
            $xmlWriter.WriteStartElement("VULN")

            If ($ScanResult.STIGMan.AFMod -eq $true) {
                # Create Evaluate-STIG comment
                $xmlWriter.WriteComment("<Evaluate-STIG><AnswerFile>$($ScanResult.STIGMan.AnswerFile)</AnswerFile><LastWrite>$($ScanResult.STIGMan.LastWrite)</LastWrite><AFMod>$(([String]$ScanResult.STIGMan.AFMod).ToLower())</AFMod><OldStatus>$($ScanResult.STIGMan.OldStatus)</OldStatus><NewStatus>$($ScanResult.STIGMan.NewStatus)</NewStatus></Evaluate-STIG>")
            }

            Foreach ($node in $(($nodes | Where-Object { $_.Name -eq "VULN"}).complexType.sequence.element) | Sort-Object {$SortOrder.IndexOf($_.ref)}) {
                If ($node.ref -in $SortOrder) {
                    Switch ($Node.ref) {
                        "STIG_DATA" {
                            Foreach ($subnode in $(($nodes | Where-Object {$_.Name -eq "VULN_ATTRIBUTE"}).simpleType.restriction.enumeration) | Sort-Object {$AttribSortOrder.IndexOf($_.value)}) {
                                If ($subnode.value -in $AttribSortOrder) {
                                    Switch ($subnode.value) {
                                        "Vuln_Num" {
                                            $xmlWriter.WriteStartElement("STIG_DATA")
                                            $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                            $xmlWriter.WriteElementString("ATTRIBUTE_DATA", $Vuln.id)
                                            $xmlWriter.WriteEndElement() #STIG_DATA
                                        }
                                        "Severity" {
                                            $xmlWriter.WriteStartElement("STIG_DATA")
                                            $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                            $xmlWriter.WriteElementString("ATTRIBUTE_DATA", $Vuln.Rule.severity)
                                            $xmlWriter.WriteEndElement() #STIG_DATA
                                        }
                                        "Group_Title" {
                                            $xmlWriter.WriteStartElement("STIG_DATA")
                                            $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                            $xmlWriter.WriteElementString("ATTRIBUTE_DATA", $Vuln.title)
                                            $xmlWriter.WriteEndElement() #STIG_DATA
                                        }
                                        "Rule_ID" {
                                            $xmlWriter.WriteStartElement("STIG_DATA")
                                            $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                            $xmlWriter.WriteElementString("ATTRIBUTE_DATA", $Vuln.Rule.id)
                                            $xmlWriter.WriteEndElement() #STIG_DATA
                                        }
                                        "Rule_Ver" {
                                            $xmlWriter.WriteStartElement("STIG_DATA")
                                            $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                            $xmlWriter.WriteElementString("ATTRIBUTE_DATA", $Vuln.Rule.version)
                                            $xmlWriter.WriteEndElement() #STIG_DATA
                                        }
                                        "Rule_Title" {
                                            $xmlWriter.WriteStartElement("STIG_DATA")
                                            $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                            $xmlWriter.WriteElementString("ATTRIBUTE_DATA", $Vuln.Rule.title)
                                            $xmlWriter.WriteEndElement() #STIG_DATA
                                        }
                                        "Vuln_Discuss" {
                                            $Tag = "VulnDiscussion"
                                            $Value = [String](Get-InnerXml -InnerXml $Vuln.rule.description -Tag $Tag)
                                            $xmlWriter.WriteStartElement("STIG_DATA")
                                            $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                            If ($Value) {
                                                $xmlWriter.WriteElementString("ATTRIBUTE_DATA", $Value)
                                            }
                                            Else {
                                                $xmlWriter.WriteStartElement("ATTRIBUTE_DATA")
                                                $xmlWriter.WriteFullEndElement() #ATTRIBUTE_DATA
                                            }
                                            $xmlWriter.WriteEndElement() #STIG_DATA
                                        }
                                        "IA_Controls" {
                                            $Tag = "IAControls"
                                            $Value = [String](Get-InnerXml -InnerXml $Vuln.rule.description -Tag $Tag)
                                            $xmlWriter.WriteStartElement("STIG_DATA")
                                            $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                            If ($Value) {
                                                $xmlWriter.WriteElementString("ATTRIBUTE_DATA", $Value)
                                            }
                                            Else {
                                                $xmlWriter.WriteStartElement("ATTRIBUTE_DATA")
                                                $xmlWriter.WriteFullEndElement() #ATTRIBUTE_DATA
                                            }
                                            $xmlWriter.WriteEndElement() #STIG_DATA
                                        }
                                        "Check_Content" {
                                            $xmlWriter.WriteStartElement("STIG_DATA")
                                            $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                            $xmlWriter.WriteElementString("ATTRIBUTE_DATA", $Vuln.Rule.check.'check-content')
                                            $xmlWriter.WriteEndElement() #STIG_DATA
                                        }
                                        "Fix_Text" {
                                            $xmlWriter.WriteStartElement("STIG_DATA")
                                            $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                            $xmlWriter.WriteElementString("ATTRIBUTE_DATA", $Vuln.Rule.fixtext.'#text')
                                            $xmlWriter.WriteEndElement() #STIG_DATA
                                        }
                                        "False_Positives" {
                                            $Tag = "FalsePositives"
                                            $Value = [String](Get-InnerXml -InnerXml $Vuln.rule.description -Tag $Tag)
                                            $xmlWriter.WriteStartElement("STIG_DATA")
                                            $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                            If ($Value) {
                                                $xmlWriter.WriteElementString("ATTRIBUTE_DATA", $Value)
                                            }
                                            Else {
                                                $xmlWriter.WriteStartElement("ATTRIBUTE_DATA")
                                                $xmlWriter.WriteFullEndElement() #ATTRIBUTE_DATA
                                            }
                                            $xmlWriter.WriteEndElement() #STIG_DATA
                                        }
                                        "False_Negatives" {
                                            $Tag = "FalseNegatives"
                                            $Value = [String](Get-InnerXml -InnerXml $Vuln.rule.description -Tag $Tag)
                                            $xmlWriter.WriteStartElement("STIG_DATA")
                                            $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                            If ($Value) {
                                                $xmlWriter.WriteElementString("ATTRIBUTE_DATA", $Value)
                                            }
                                            Else {
                                                $xmlWriter.WriteStartElement("ATTRIBUTE_DATA")
                                                $xmlWriter.WriteFullEndElement() #ATTRIBUTE_DATA
                                            }
                                            $xmlWriter.WriteEndElement() #STIG_DATA
                                        }
                                        "Documentable" {
                                            $Tag = "Documentable"
                                            $Value = [String](Get-InnerXml -InnerXml $Vuln.rule.description -Tag $Tag)
                                            $xmlWriter.WriteStartElement("STIG_DATA")
                                            $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                            If ($Value) {
                                                $xmlWriter.WriteElementString("ATTRIBUTE_DATA", $Value)
                                            }
                                            Else {
                                                $xmlWriter.WriteStartElement("ATTRIBUTE_DATA")
                                                $xmlWriter.WriteFullEndElement() #ATTRIBUTE_DATA
                                            }
                                            $xmlWriter.WriteEndElement() #STIG_DATA
                                        }
                                        "Mitigations" {
                                            $Tag = "Mitigations"
                                            $Value = [String](Get-InnerXml -InnerXml $Vuln.rule.description -Tag $Tag)
                                            $xmlWriter.WriteStartElement("STIG_DATA")
                                            $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                            If ($Value) {
                                                $xmlWriter.WriteElementString("ATTRIBUTE_DATA", $Value)
                                            }
                                            Else {
                                                $xmlWriter.WriteStartElement("ATTRIBUTE_DATA")
                                                $xmlWriter.WriteFullEndElement() #ATTRIBUTE_DATA
                                            }
                                            $xmlWriter.WriteEndElement() #STIG_DATA
                                        }
                                        "Potential_Impact" {
                                            $Tag = "PotentialImpacts"
                                            $Value = [String](Get-InnerXml -InnerXml $Vuln.rule.description -Tag $Tag)
                                            $xmlWriter.WriteStartElement("STIG_DATA")
                                            $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                            If ($Value) {
                                                $xmlWriter.WriteElementString("ATTRIBUTE_DATA", $Value)
                                            }
                                            Else {
                                                $xmlWriter.WriteStartElement("ATTRIBUTE_DATA")
                                                $xmlWriter.WriteFullEndElement() #ATTRIBUTE_DATA
                                            }
                                            $xmlWriter.WriteEndElement() #STIG_DATA
                                        }
                                        "Third_Party_Tools" {
                                            $Tag = "ThirdPartyTools"
                                            $Value = [String](Get-InnerXml -InnerXml $Vuln.rule.description -Tag $Tag)
                                            $xmlWriter.WriteStartElement("STIG_DATA")
                                            $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                            If ($Value) {
                                                $xmlWriter.WriteElementString("ATTRIBUTE_DATA", $Value)
                                            }
                                            Else {
                                                $xmlWriter.WriteStartElement("ATTRIBUTE_DATA")
                                                $xmlWriter.WriteFullEndElement() #ATTRIBUTE_DATA
                                            }
                                            $xmlWriter.WriteEndElement() #STIG_DATA
                                        }
                                        "Mitigation_Control" {
                                            $Tag = "MitigationControl"
                                            $Value = [String](Get-InnerXml -InnerXml $Vuln.rule.description -Tag $Tag)
                                            $xmlWriter.WriteStartElement("STIG_DATA")
                                            $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                            If ($Value) {
                                                $xmlWriter.WriteElementString("ATTRIBUTE_DATA", $Value)
                                            }
                                            Else {
                                                $xmlWriter.WriteStartElement("ATTRIBUTE_DATA")
                                                $xmlWriter.WriteFullEndElement() #ATTRIBUTE_DATA
                                            }
                                            $xmlWriter.WriteEndElement() #STIG_DATA
                                        }
                                        "Responsibility" {
                                            $Tag = "Responsibility"
                                            $Value = [String](Get-InnerXml -InnerXml $Vuln.rule.description -Tag $Tag)
                                            $xmlWriter.WriteStartElement("STIG_DATA")
                                            $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                            If ($Value) {
                                                $xmlWriter.WriteElementString("ATTRIBUTE_DATA", $Value)
                                            }
                                            Else {
                                                $xmlWriter.WriteStartElement("ATTRIBUTE_DATA")
                                                $xmlWriter.WriteFullEndElement() #ATTRIBUTE_DATA
                                            }
                                            $xmlWriter.WriteEndElement() #STIG_DATA
                                        }
                                        "Security_Override_Guidance" {
                                            $Tag = "SeverityOverrideGuidance"
                                            $Value = [String](Get-InnerXml -InnerXml $Vuln.rule.description -Tag $Tag)
                                            $xmlWriter.WriteStartElement("STIG_DATA")
                                            $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                            If ($Value) {
                                                $xmlWriter.WriteElementString("ATTRIBUTE_DATA", $Value)
                                            }
                                            Else {
                                                $xmlWriter.WriteStartElement("ATTRIBUTE_DATA")
                                                $xmlWriter.WriteFullEndElement() #ATTRIBUTE_DATA
                                            }
                                            $xmlWriter.WriteEndElement() #STIG_DATA
                                        }
                                        "Check_Content_Ref" {
                                            $xmlWriter.WriteStartElement("STIG_DATA")
                                            $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                            $xmlWriter.WriteElementString("ATTRIBUTE_DATA", $Vuln.Rule.check.'check-content-ref'.name)
                                            $xmlWriter.WriteEndElement() #STIG_DATA
                                        }
                                        "Weight" {
                                            $xmlWriter.WriteStartElement("STIG_DATA")
                                            $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                            $xmlWriter.WriteElementString("ATTRIBUTE_DATA", $Vuln.rule.weight)
                                            $xmlWriter.WriteEndElement() #STIG_DATA
                                        }
                                        "Class" {
                                            $xmlWriter.WriteStartElement("STIG_DATA")
                                            $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                            Switch ($Classification) {
                                                "CUI" {
                                                    $xmlWriter.WriteElementString("ATTRIBUTE_DATA", "CUI")
                                                }
                                                default {
                                                    $xmlWriter.WriteElementString("ATTRIBUTE_DATA", "Unclass")
                                                }
                                            }
                                            $xmlWriter.WriteEndElement() #STIG_DATA
                                        }
                                        "STIGRef" {
                                            $xmlWriter.WriteStartElement("STIG_DATA")
                                            $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                            $xmlWriter.WriteElementString("ATTRIBUTE_DATA", "$($Content.Benchmark.title) :: Version $($Content.Benchmark.version), $(($Content.Benchmark.'plain-text' | Where-Object { $_.id -eq 'release-info' }).'#text')")
                                            $xmlWriter.WriteEndElement() #STIG_DATA
                                        }
                                        "TargetKey" {
                                            $xmlWriter.WriteStartElement("STIG_DATA")
                                            $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                            $xmlWriter.WriteElementString("ATTRIBUTE_DATA", $Vuln.rule.reference.identifier)
                                            $xmlWriter.WriteEndElement() #STIG_DATA
                                        }
                                        "STIG_UUID" {
                                            $xmlWriter.WriteStartElement("STIG_DATA")
                                            $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                            $xmlWriter.WriteElementString("ATTRIBUTE_DATA", $([guid]::NewGuid()))
                                            $xmlWriter.WriteEndElement() #STIG_DATA
                                        }
                                        "LEGACY_ID" {
                                            If ($Vuln.Rule.ident | Where-Object {$_.system -eq "http://cyber.mil/legacy"}) {
                                                Foreach ($legacy in ($Vuln.Rule.ident | Where-Object {$_.system -eq "http://cyber.mil/legacy"} | Sort-Object '#text' -Descending)) {
                                                    $xmlWriter.WriteStartElement("STIG_DATA")
                                                    $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                                    $xmlWriter.WriteElementString("ATTRIBUTE_DATA", "$($legacy.'#text')")
                                                    $xmlWriter.WriteEndElement() #STIG_DATA
                                                }
                                            }
                                        }
                                        "CCI_REF" {
                                            Foreach ($CCI in ($Vuln.Rule.ident | Where-Object {$_.system -like "http://*.mil/cci"} | Sort-Object '#text')) {
                                                $xmlWriter.WriteStartElement("STIG_DATA")
                                                $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                                $xmlWriter.WriteElementString("ATTRIBUTE_DATA", "$($CCI.'#text')")
                                                $xmlWriter.WriteEndElement() #STIG_DATA
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        "STATUS" {
                            $ValidValues = @("NR", "NF", "NA", "O", "Not_Reviewed", "NotAFinding", "Not_Applicable", "Open", "not_a_finding", "notchecked", "pass", "notapplicable", "fail")
                            If (-Not($ScanResult.Status)) {
                                $Status = "Not_Reviewed"
                            }
                            ElseIf ($ScanResult.Status -and $ScanResult.Status -notin $ValidValues) {
                                Throw "Invalid value for property [$($_)]: '$($ScanResult.Status)'"
                            }
                            Else {
                                $Status = $(Convert-Status -InputObject $ScanResult.Status -Output CKL)
                            }
                            $xmlWriter.WriteElementString("STATUS", $Status)
                        }
                        "FINDING_DETAILS" {
                            $xmlWriter.WriteElementString("FINDING_DETAILS", $TruncatedFindingDetails)
                        }
                        "COMMENTS" {
                            $xmlWriter.WriteElementString("COMMENTS", $TruncatedComments)
                        }
                        "SEVERITY_OVERRIDE" {
                            If ($ScanResult.SeverityOverride) {
                                $ValidValues = @("low", "medium", "high")
                                If ($ScanResult.SeverityOverride -notin $ValidValues) {
                                    Throw "Invalid value for property [$($_)]: '$($ScanResult.SeverityOverride)'"
                                }
                                Else {
                                    $xmlWriter.WriteElementString("SEVERITY_OVERRIDE", $($ScanResult.SeverityOverride))
                                }
                            }
                            Else {
                                $xmlWriter.WriteElementString("SEVERITY_OVERRIDE", "")
                            }
                        }
                        "SEVERITY_JUSTIFICATION" {
                            If ($ScanResult.Justification) {
                                $xmlWriter.WriteElementString("SEVERITY_JUSTIFICATION", $($ScanResult.Justification))
                            }
                            Else {
                                $xmlWriter.WriteElementString("SEVERITY_JUSTIFICATION", "")
                            }
                        }
                        default {
                            $xmlWriter.WriteStartElement($Node.ref)
                            $xmlWriter.WriteFullEndElement()
                        }
                    }
                }
            }
            $xmlWriter.WriteEndElement() #VULN
        }

        $xmlWriter.WriteEndElement() #iSTIG
    }

    $xmlWriter.WriteEndElement() #STIGS

    $xmlWriter.WriteEndElement() #CHECKLIST
    $xmlWriter.WriteEndDocument()
    $xmlWriter.Flush()
    $xmlWriter.Close()

    Write-Log -Path $STIGLog -Message "Validating CKL File" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
    $ChecklistValid = Test-XmlValidation -XmlFile $OutputPath -SchemaFile $SchemaPath

    # Action for validation result
    If ($ChecklistValid) {
        Write-Log -Path $STIGLog -Message "'$(Split-Path $OutputPath -Leaf)' : Passed." -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
    }
    Else {
        $BadFileDestination = Join-Path -Path $WorkingDir -ChildPath "Bad_CKL"
        Write-Log -Path $STIGLog -Message "ERROR: '$(Split-Path $OutputPath -Leaf)' : failed schema validation. Moving to $BadFileDestination." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
        ForEach ($Item in $ChecklistValid.Message) {
            Write-Log -Path $STIGLog -Message $Item -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
        }
        If (-Not(Test-Path $BadFileDestination)) {
            $null = New-Item -Path $BadFileDestination -ItemType Directory
        }
        Copy-Item -Path $OutputPath -Destination $BadFileDestination -Force
        Remove-Item $OutputPath -Force
    }

    Return $ChecklistValid
}

Function Format-CKLB {
    # https://mattou07.net/posts/creating-complex-json-with-powershell/
    param
    (
        [Parameter(Mandatory)]
        [string]$SchemaPath,

        [Parameter(Mandatory)]
        [psobject]$ScanObject,

        [Parameter(Mandatory)]
        [Int32]$TruncateOutput,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [Parameter()]
        [string]$Marking = "",

        [Parameter(Mandatory = $true)]
        [String]$WorkingDir,

        [Parameter(Mandatory = $true)]
        [String]$ESPath,

        [Parameter(Mandatory = $true)]
        [String]$LogComponent,

        [Parameter(Mandatory = $true)]
        [String]$OSPlatform
    )

    $Schema = Get-Content $SchemaPath -Raw | ConvertFrom-Json

    # Get Target Data
    If (($ScanObject | Measure-Object).Count -gt 1) {
        If ($ScanObject | Where-Object {($_.ESData.CanCombine -eq $true)}) {
            $TargetData = ($ScanObject | Where-Object {($_.ESData.CanCombine -eq $true)})[0].TargetData
            $ScanObject = ($ScanObject | Where-Object {($_.ESData.CanCombine -eq $true)})
        }
        Else {
            Throw "None of the scanned STIGs can be combined."
        }
    }
    Else {
        $TargetData = $ScanObject.TargetData
    }

    $objCKLB = [ordered]@{}
    $RootProps = ($Schema.properties.PsObject.Members | Where-Object MemberType -EQ "NoteProperty").Name
    ForEach ($P1 in $RootProps) {
        Switch ($P1) {
            "evaluate-stig" {
                $objES = [ordered]@{}
                $ESProps = ($Schema.properties.$P1.properties.psobject.members | Where-Object MemberType -EQ "NoteProperty").Name
                ForEach ($P2 in $ESProps) {
                    Switch ($P2) {
                        "version" {
                            $objES.Add($_, $($ScanObject[0].ESData.ESVersion))
                        }
                        Default {
                            $Message = "Unexpected CKLB schema property: '$_'"
                            Throw $Message
                        }
                    }
                }
                $objCKLB.Add("evaluate-stig", $objES)
            }
            "title" {
                If (($ScanObject | Measure-Object).Count -gt 1) {
                    $objCKLB.Add($_, "Evaluate-STIG_COMBINED")
                }
                Else {
                    $objCKLB.Add($_, "Evaluate-STIG_$($ScanObject.ESData.STIGShortName)")
                }
            }
            "id" {
                $objCKLB.Add($_, $([guid]::NewGuid()))
            }
            "stigs" {
                $arrSTIGs = New-Object System.Collections.ArrayList
                ForEach ($Scan in $ScanObject) {
                    # Read the STIG content
                    If (-not($Scan.ESData.IsManualSTIG)) {
                        $STIGXMLPath = $(Join-Path -Path $ESPath -ChildPath StigContent | Join-Path -ChildPath $Scan.ESData.STIGXMLName)
                    }
                    Else {
                        $STIGXMLPath = $(Join-Path -Path $ESPath -ChildPath StigContent | Join-Path -ChildPath Manual | Join-Path -ChildPath $Scan.ESData.STIGXMLName)
                    }
                    # https://stackoverflow.com/questions/71847945/strange-characters-found-in-xml-file-and-powershell-output-after-exporting-from
                    ($Content = [xml]::new()).Load($STIGXMLPath)

                    # Set STIG Classification
                    Switch -Regex ($Content.'xml-stylesheet') {
                        'STIG_unclass.xsl' {
                            $Classification = "UNCLASSIFIED"
                        }
                        'STIG_cui.xsl' {
                            $Classification = "CUI"
                        }
                        DEFAULT {
                            Throw "Unable to determine STIG classification."
                        }
                    }

                    $objSTIG = [ordered]@{}
                    $STIGUUID = [guid]::NewGuid()
                    $StigProps = ($Schema.properties.$P1.items.properties.psobject.members | Where-Object MemberType -EQ "NoteProperty").Name
                    ForEach ($P2 in $StigProps) {
                        Switch ($P2) {
                            "evaluate-stig" {
                                $objES = [ordered]@{}
                                $ESProps = ($Schema.properties.$P1.items.properties.$P2.properties.psobject.members | Where-Object MemberType -EQ "NoteProperty").Name
                                ForEach ($P3 in $ESProps) {
                                    Switch ($P3) {
                                        "time" {
                                            $objES.Add($_, $($Scan.ESData.StartTime))
                                        }
                                        "module" {
                                            $objModule = [ordered]@{}
                                            $ModuleProps = ($Schema.properties.$P1.items.properties.$P2.properties.$P3.properties.psobject.members | Where-Object MemberType -EQ "NoteProperty").Name
                                            ForEach ($P4 in $ModuleProps) {
                                                Switch ($P4) {
                                                    "name" {
                                                        $objModule.Add($_, $($Scan.ESData.ModuleName))
                                                    }
                                                    "version" {
                                                        $objModule.Add($_, $([String]$Scan.ESData.ModuleVersion))
                                                    }
                                                    Default {
                                                        $Message = "Unexpected CKLB schema property: '$_'"
                                                        Throw $Message
                                                    }
                                                }
                                            }
                                            $objES.Add($_, $($objModule))
                                        }
                                        Default {
                                            $Message = "Unexpected CKLB schema property: '$_'"
                                            Throw $Message
                                        }
                                    }
                                }
                                $objSTIG.Add("evaluate-stig", $objES)
                            }
                            "stig_name" {
                                $objSTIG.Add($_, $Content.Benchmark.title)
                            }
                            "display_name" {
                                $objSTIG.Add($_, $(($Content.Benchmark.title).Replace(" Security Technical Implementation Guide", "")))
                            }
                            "stig_id" {
                                $objSTIG.Add($_, $Content.Benchmark.id)
                            }
                            "release_info" {
                                $objSTIG.Add($_, $($Content.Benchmark.'plain-text' | Where-Object { $_.id -eq "release-info" }).'#text')
                            }
                            "version" {
                                $objSTIG.Add($_, $Content.Benchmark.version)
                            }
                            "uuid" {
                                $objSTIG.Add($_, $STIGUUID)
                            }
                            "reference_identifier" {
                                $objSTIG.Add($_, $($Content.Benchmark.Group)[0].Rule.reference.identifier)
                            }
                            "size" {
                                $objSTIG.Add($_, ($Content.Benchmark.Group | Measure-Object).Count)
                            }
                            "rules" {
                                $arrRules = New-Object System.Collections.ArrayList
                                $RuleProps = ($Schema.properties.$P1.items.properties.$P2.items.properties.psobject.members | Where-Object MemberType -EQ "NoteProperty").Name
                                ForEach ($Vuln in $Content.Benchmark.Group) {
                                    # Get results from scan object
                                    $ScanResult = $Scan.VulnResults | Where-Object GroupID -EQ $Vuln.id
                                    # Set TruncatedFindingDetails and TruncatedComments variables
                                    if ($null -ne $ScanResult.FindingDetails -and $ScanResult.FindingDetails.Trim().Length -gt 0) {
                                        $TruncatedFindingDetails = Get-TruncatedOutput -InputText $ScanResult.FindingDetails -TruncateOutput $TruncateOutput
                                    }
                                    else {
                                        $TruncatedFindingDetails = ""
                                    }
                                    if ($null -ne $ScanResult.Comments -and $ScanResult.Comments.Trim().Length -gt 0) {
                                        $TruncatedComments = Get-TruncatedOutput -InputText $ScanResult.Comments -TruncateOutput $TruncateOutput
                                    }
                                    else {
                                        $TruncatedComments = ""
                                    }

                                    $objRule = [ordered]@{}
                                    ForEach ($P3 in $RuleProps) {
                                        Switch ($P3) {
                                            "evaluate-stig" {
                                                If ($ScanResult.STIGMan.AFMod -eq $true) {
                                                    $objES = [ordered]@{}
                                                    $ESProps = ($Schema.properties.$P1.items.properties.$P2.items.properties.$P3.properties.psobject.members | Where-Object MemberType -EQ "NoteProperty").Name
                                                    ForEach ($P4 in $ESProps) {
                                                        Switch ($P4) {
                                                            "answer_file" {
                                                                $objES.Add($_, $($ScanResult.STIGMan.AnswerFile))
                                                            }
                                                            "last_write" {
                                                                $objES.Add($_, $($ScanResult.STIGMan.LastWrite))
                                                            }
                                                            "afmod" {
                                                                $objES.Add($_, $ScanResult.STIGMan.AFMod)
                                                            }
                                                            "old_status" {
                                                                $objES.Add($_, $($ScanResult.STIGMan.OldStatus))
                                                            }
                                                            "new_status" {
                                                                $objES.Add($_, $($ScanResult.STIGMan.NewStatus))
                                                            }
                                                            Default {
                                                                $Message = "Unexpected CKLB schema property: '$_'"
                                                                Throw $Message
                                                            }
                                                        }
                                                    }
                                                    $objRule.Add("evaluate-stig", $objES)
                                                }
                                            }
                                            "group_id_src" {
                                                $objRule.Add($_, $($Vuln.id))
                                            }
                                            "group_tree" {
                                                $objGroupTree = [ordered]@{}
                                                $arrGroupTree = New-Object System.Collections.ArrayList
                                                $GroupTreeProps = ($Schema.properties.$P1.items.properties.$P2.items.properties.$P3.items.properties.psobject.members | Where-Object MemberType -EQ "NoteProperty").Name
                                                ForEach ($P4 in $GroupTreeProps) {
                                                    Switch ($P4) {
                                                        "id" {
                                                            $objGroupTree.Add($_, $($Vuln.id))
                                                        }
                                                        "title" {
                                                            $objGroupTree.Add($_, $($Vuln.title))
                                                        }
                                                        "description" {
                                                            $objGroupTree.add($_, $($Vuln.description))
                                                        }
                                                        Default {
                                                            $Message = "Unexpected CKLB schema property: '$_'"
                                                            Throw $Message
                                                        }
                                                    }
                                                }
                                                $null = $arrGroupTree.Add($objGroupTree)
                                                $objRule.Add("group_tree", $arrGroupTree)
                                            }
                                            "group_id" {
                                                $objRule.Add($_, $($Vuln.id))
                                            }
                                            "severity" {
                                                $objRule.Add($_, $($Vuln.rule.severity))
                                            }
                                            "group_title" {
                                                $objRule.Add($_, $($Vuln.rule.title))
                                            }
                                            "rule_id_src" {
                                                $objRule.Add($_, $($Vuln.rule.id))
                                            }
                                            "rule_id" {
                                                $objRule.Add($_, $($Vuln.rule.id -replace "_rule", ""))
                                            }
                                            "rule_version" {
                                                $objRule.Add($_, $($Vuln.rule.version))
                                            }
                                            "rule_title" {
                                                $objRule.Add($_, $($Vuln.rule.title))
                                            }
                                            "fix_text" {
                                                $objRule.Add($_, $($Vuln.rule.fixtext.'#text'))
                                            }
                                            "weight" {
                                                $objRule.Add($_, $($Vuln.rule.weight))
                                            }
                                            "check_content" {
                                                $objRule.Add($_, $($Vuln.Rule.check.'check-content'))
                                            }
                                            "check_content_ref" {
                                                $objCCRef = [ordered]@{}
                                                $CCRefProps = ($Schema.properties.$P1.items.properties.$P2.items.properties.$P3.properties.psobject.members | Where-Object MemberType -EQ "NoteProperty").Name
                                                ForEach ($P4 in $CCRefProps) {
                                                    Switch ($P4) {
                                                        "href" {
                                                            $objCCRef.Add($_, $($Vuln.rule.check.'check-content-ref'.href))
                                                        }
                                                        "name" {
                                                            $objCCRef.Add($_, $($Vuln.rule.check.'check-content-ref'.name))
                                                        }
                                                        Default {
                                                            $Message = "Unexpected CKLB schema property: '$_'"
                                                            Throw $Message
                                                        }
                                                    }
                                                }
                                                $objRule.Add($_, $objCCRef)
                                            }
                                            "classification" {
                                                $objRule.Add($_, $Classification)
                                            }
                                            "discussion" {
                                                $Tag = "VulnDiscussion"
                                                $objRule.Add($_, [String](Get-InnerXml -InnerXml $Vuln.rule.description -Tag $Tag))
                                            }
                                            "false_positives" {
                                                $Tag = "FalsePositives"
                                                $objRule.Add($_, [String](Get-InnerXml -InnerXml $Vuln.rule.description -Tag $Tag))
                                            }
                                            "false_negatives" {
                                                $Tag = "FalseNegatives"
                                                $objRule.Add($_, [String](Get-InnerXml -InnerXml $Vuln.rule.description -Tag $Tag))
                                            }
                                            "documentable" {
                                                $Tag = "Documentable"
                                                $objRule.Add($_, [String](Get-InnerXml -InnerXml $Vuln.rule.description -Tag $Tag))
                                            }
                                            "security_override_guidance" {
                                                $Tag = "SeverityOverrideGuidance"
                                                $objRule.Add($_, [String](Get-InnerXml -InnerXml $Vuln.rule.description -Tag $Tag))
                                            }
                                            "potential_impacts" {
                                                $Tag = "PotentialImpacts"
                                                $objRule.Add($_, [String](Get-InnerXml -InnerXml $Vuln.rule.description -Tag $Tag))
                                            }
                                            "third_party_tools" {
                                                $Tag = "ThirdPartyTools"
                                                $objRule.Add($_, [String](Get-InnerXml -InnerXml $Vuln.rule.description -Tag $Tag))
                                            }
                                            "ia_controls" {
                                                $Tag = "IAControls"
                                                $objRule.Add($_, [String](Get-InnerXml -InnerXml $Vuln.rule.description -Tag $Tag))
                                            }
                                            "responsibility" {
                                                $Tag = "Responsibility"
                                                $objRule.Add($_, [String](Get-InnerXml -InnerXml $Vuln.rule.description -Tag $Tag))
                                            }
                                            "mitigations" {
                                                $Tag = "Mitigations"
                                                $objRule.Add($_, [String](Get-InnerXml -InnerXml $Vuln.rule.description -Tag $Tag))
                                            }
                                            "mitigation_control" {
                                                $Tag = "MitigationControl"
                                                $objRule.Add($_, [String](Get-InnerXml -InnerXml $Vuln.rule.description -Tag $Tag))
                                            }
                                            "legacy_ids" {
                                                If ($Vuln.Rule.ident | Where-Object {$_.system -eq "http://cyber.mil/legacy"}) {
                                                    $arrLegacy = New-Object System.Collections.ArrayList
                                                    Foreach ($legacy in ($Vuln.Rule.ident | Where-Object {$_.system -eq "http://cyber.mil/legacy"} | Sort-Object '#text')) {
                                                        $null = $arrLegacy.Add($($legacy.'#text'))
                                                    }
                                                    $objRule.Add($_, $arrLegacy)
                                                }
                                            }
                                            "ccis" {
                                                $arrCCIs = New-Object System.Collections.ArrayList
                                                Foreach ($CCI in ($Vuln.Rule.ident | Where-Object {$_.system -like "http://*.mil/cci"} | Sort-Object '#text')) {
                                                    $null = $arrCCIs.Add($($CCI.'#text'))
                                                }
                                                $objRule.Add($_, $arrCCIs)
                                            }
                                            "reference_identifier" {
                                                $objRule.Add($_, $($Vuln.Rule.reference.identifier))
                                            }
                                            "uuid" {
                                                $objRule.Add($_, $([guid]::NewGuid()))
                                            }
                                            "stig_uuid" {
                                                $objRule.Add($_, $STIGUUID)
                                            }
                                            "status" {
                                                $ValidValues = @("NR", "NF", "NA", "O", "Not_Reviewed", "NotAFinding", "Not_Applicable", "Open", "not_a_finding", "notchecked", "pass", "notapplicable", "fail")
                                                If (-Not($ScanResult.Status)) {
                                                    $Status = "not_reviewed"
                                                }
                                                ElseIf ($ScanResult.Status -and $ScanResult.Status -notin $ValidValues) {
                                                    Throw "Invalid value for property [$($_)]: '$($ScanResult.Status)'"
                                                }
                                                Else {
                                                    $Status = $(Convert-Status -InputObject $ScanResult.Status -Output CKLB)
                                                }
                                                $objRule.Add($_, $Status.ToLower())
                                            }
                                            "overrides" {
                                                $objOverrides = @{}
                                                If ($ScanResult.SeverityOverride) {
                                                    $ValidValues = @("low", "medium", "high")
                                                    $dataObject = [ordered]@{}
                                                    If ($ScanResult.SeverityOverride -notin $ValidValues) {
                                                        Throw "Invalid value for property [$($_)]: '$($ScanResult.SeverityOverride)'"
                                                    }
                                                    Else {
                                                        $dataObject.Add("severity", $($ScanResult.SeverityOverride).ToLower())
                                                    }
                                                    If ($ScanResult.Justification) {
                                                        $dataObject.Add("reason", $($ScanResult.Justification))
                                                    }
                                                    Else {
                                                        $dataObject.Add("reason", "No reason provided")
                                                    }
                                                    $objOverrides.Add("severity", $dataObject)
                                                }
                                                $objRule.Add($_, $objOverrides)
                                            }
                                            "comments" {
                                                $objRule.Add($_, $TruncatedComments)
                                            }
                                            "finding_details" {
                                                $objRule.Add($_, $TruncatedFindingDetails)
                                            }
                                            Default {
                                                $Message = "Unexpected CKLB schema property: '$_'"
                                                Throw $Message
                                            }
                                        }
                                    }
                                    $null = $arrRules.Add($objRule)
                                }
                                $objSTIG.Add("rules", $arrRules)
                            }
                        }
                    }
                    $null = $arrSTIGs.Add($objSTIG)
                }
                $objCKLB.Add("stigs", $arrSTIGs)
            }
            "active" {
                $objCKLB.Add($_, $false)
            }
            "mode" {
                $objCKLB.Add($_, 1)
            }
            "has_path" {
                $objCKLB.Add($_, $true)
            }
            "target_data" {
                $objTargetData = [ordered]@{}
                $TargetDataProps = ($Schema.properties.$P1.properties.psobject.members | Where-Object MemberType -EQ "NoteProperty").Name
                ForEach ($P2 in $TargetDataProps) {
                    Switch ($P2) {
                        "target_type" {
                            $objTargetData.Add($_, "Computing")
                        }
                        "host_name" {
                            $objTargetData.Add($_, $($TargetData.Hostname))
                        }
                        "ip_address" {
                            $objTargetData.Add($_, $($TargetData.IpAddress))
                        }
                        "mac_address" {
                            $objTargetData.Add($_, $($TargetData.MacAddress))
                        }
                        "fqdn" {
                            $objTargetData.Add($_, $($TargetData.FQDN))
                        }
                        "comments" {
                            $objTargetData.Add($_, $($TargetData.TargetComments))
                        }
                        "role" {
                            $ValidValues = @("None", "Workstation", "Member Server", "Domain Controller")
                            If ($TargetData.Role -and $TargetData.Role -notin $ValidValues) {
                                Throw "Invalid value for property [$($_)]: '$($TargetData.Role)'"
                            }
                            Else {
                                $objTargetData.Add($_, $($TargetData.Role))
                            }
                        }
                        "is_web_database" {
                            If ($TargetData.WebOrDatabase.GetType().Name -ne "Boolean") {
                                Throw "Invalid value type for property [$($_)]: '$($TargetData.WebOrDatabase.GetType().Name)'"
                            }
                            Else {
                                $objTargetData.Add($_, $($TargetData.WebOrDatabase))
                            }
                        }
                        "technology_area" {
                            If (($ScanObject | Measure-Object).Count -gt 1) {
                                $objTargetData.Add($_, "None")
                            }
                            Else {
                                $objTargetData.Add($_, $TargetData.CklTechArea)
                            }
                        }
                        "web_db_site" {
                            $objTargetData.Add($_, $($TargetData.Site))
                        }
                        "web_db_instance" {
                            $objTargetData.Add($_, $($TargetData.Instance))
                        }
                        "classification" {
                            $objTargetData.Add($_, $($Marking))
                        }
                        Default {
                            $Message = "Unexpected CKLB schema property: '$_'"
                            Throw $Message
                        }
                    }
                }
                $objCKLB.Add($_, $objTargetData)
            }
            "cklb_version" {
                $objCKLB.Add($_, "1.0")
            }
            Default {
                $Message = "Unexpected CKLB schema property: '$_'"
                Throw $Message
            }
        }
    }

    # Convert to JSON and preserve some characters - https://stackoverflow.com/a/53644601/45375
    $CKLB = [regex]::replace($($objCKLB | ConvertTo-Json -Depth 10 -Compress), '\\u[0-9a-fA-F]{4}', {param($match) [char] [int] ('0x' + $match.Value.Substring(2))})

    # CKLB file must be 'UTF-8' and no BOM
    [System.IO.File]::WriteAllLines($OutputPath, $CKLB)

    Write-Log -Path $STIGLog -Message "Validating CKLB File" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
    $ChecklistValid = $true
    If ([Version]$PSVersionTable.PSVersion -lt [Version]"7.0") {
        Write-Log -Path $STIGLog -Message "PowerShell $($PSVersionTable.PSVersion -join ".") not supported for Json validation" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
    }
    Else {
        $ChecklistValid = Test-JsonValidation -JsonFile $OutputPath -SchemaFile $SchemaPath

        # Action for validation result
        If ($ChecklistValid) {
            Write-Log -Path $STIGLog -Message "'$(Split-Path $OutputPath -Leaf)' : Passed." -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        }
        Else {
            $BadFileDestination = Join-Path -Path $WorkingDir -ChildPath "Bad_CKL"
            Write-Log -Path $STIGLog -Message "ERROR: '$(Split-Path $OutputPath -Leaf)' : failed schema validation. Moving to $BadFileDestination." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
            ForEach ($Item in $ChecklistValid.Message) {
                Write-Log -Path $STIGLog -Message $Item -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
            }
            If (-Not(Test-Path $BadFileDestination)) {
                New-Item -Path $BadFileDestination -ItemType Directory | Out-Null
            }
            Copy-Item -Path $OutputPath -Destination $BadFileDestination -Force
            Remove-Item $OutputPath -Force
        }
    }

    Return $ChecklistValid
}

Function Format-XCCDF {
    param
    (
        [Parameter(Mandatory)]
        [psobject]$ScanObject,

        [Parameter(Mandatory = $true)]
        [Int32]$TruncateOutput,

        [Parameter(Mandatory)]
        [psobject]$SchemaPath,

        [Parameter(Mandatory)]
        [psobject]$AssetData,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [Parameter()]
        [string]$Marking = "",

        [Parameter(Mandatory = $true)]
        [String]$ESPath
    )

    Try {
        # Get Target Data
        If (($ScanObject | Measure-Object).Count -gt 1) {
            Throw "Only single STIG results supported for XCCDF output."
        }

        # Read the STIG content
        If (-not($ScanObject.ESData.IsManualSTIG)) {
            $STIGXMLPath = $(Join-Path -Path $ESPath -ChildPath StigContent | Join-Path -ChildPath $ScanObject.ESData.STIGXMLName)
        }
        Else {
            $STIGXMLPath = $(Join-Path -Path $ESPath -ChildPath StigContent | Join-Path -ChildPath Manual | Join-Path -ChildPath $Scan.ESData.STIGXMLName)
        }
        # https://stackoverflow.com/questions/71847945/strange-characters-found-in-xml-file-and-powershell-output-after-exporting-from
        ($Content = [xml]::new()).Load($STIGXMLPath)

        # Build the XML data
        $Encoding = [System.Text.UTF8Encoding]::new($false)
        $xmlSettings = New-Object System.Xml.XmlWriterSettings
        $xmlSettings.Encoding = $Encoding
        $xmlSettings.Indent = $true
        $xmlSettings.IndentChars = "    "
        $xmlSettings.NewLineHandling = "None"

        $xmlWriter = [System.Xml.XmlWriter]::Create($($OutputPath), $xmlSettings)

        # Set XCCDF namespaces
        $Namespace = "http://checklists.nist.gov/xccdf/1.2"
        $SMNamespace = "http://github.com/nuwcdivnpt/stig-manager"

        # Create Marking comment
        If ($Marking) {
            $xmlWriter.WriteComment("                                                                                          $Marking                                                                                          ")
        }

        # Create 'Benchmark' node
        $xmlWriter.WriteStartElement("cdf", "Benchmark", $Namespace)
        $xmlWriter.WriteAttributeString("xmlns", "cdf", "http://www.w3.org/2000/xmlns/", $Namespace)
        $xmlWriter.WriteAttributeString("xmlns", "xsi", "http://www.w3.org/2000/xmlns/", $Content.Benchmark.xsi)
        $xmlWriter.WriteAttributeString("xmlns", "dc", "http://www.w3.org/2000/xmlns/", $Content.Benchmark.dc)
        $xmlWriter.WriteAttributeString("xmlns", "sm", "http://www.w3.org/2000/xmlns/", $SMNamespace)
        $xmlWriter.WriteAttributeString("id", "xccdf_mil.disa.stig_benchmark_$($Content.Benchmark.id)")

        # Create 'status' element
        $xmlWriter.WriteStartElement("cdf", "status", $Namespace)
        $xmlWriter.WriteAttributeString("date", $(Get-Date $ScanObject.STIGInfo.ReleaseDate -Format "yyyy-MM-dd"))
        $xmlWriter.WriteString("accepted")
        $xmlWriter.WriteEndElement() # Close 'status'

        # Create 'Title' element
        $xmlWriter.WriteElementString("title", $Namespace, $ScanObject.STIGInfo.Title)

        # Create 'Description' element
        $xmlWriter.WriteElementString("description", $Namespace, $Content.Benchmark.description)

        # Create 'reference' node
        $xmlWriter.WriteStartElement("cdf", "reference", $Namespace)
        $xmlWriter.WriteAttributeString("href", $Content.Benchmark.reference.href)
        ForEach ($Item in @("publisher", "source")) {
            # Create sub-element
            $xmlWriter.WriteElementString($Item, $Content.Benchmark.dc, $Content.Benchmark.reference.$Item)
        }
        $xmlWriter.WriteEndElement() # Close 'reference'

        # Create 'plain-text' elements
        ForEach ($Item in $Content.Benchmark.'plain-text') {
            $xmlWriter.WriteStartElement("cdf", "plain-text", $Namespace)
            $xmlWriter.WriteAttributeString("id", $Item.id)
            $xmlWriter.WriteString($Item.'#text')
            $xmlWriter.WriteEndElement() # Close $Item
        }

        # Create 'platform' element
        $xmlWriter.WriteStartElement("cdf", "platform", $Namespace)
        $xmlWriter.WriteAttributeString("idref", "cpe:2.3:a:disa:stig")
        $xmlWriter.WriteEndElement() # Close 'platform'

        # Create 'Version' element (non-XCCDF standard)
        $xmlWriter.WriteElementString("version", $Namespace, "V$($ScanObject.STIGInfo.Version)R$($ScanObject.STIGInfo.Release)")

        # Create 'metadata' node
        $xmlWriter.WriteStartElement("cdf", "metadata", $Namespace)
        ForEach ($Item in @("creator", "publisher", "source")) {
            Switch ($Item) {
                "creator" {
                    $xmlWriter.WriteElementString($Item, $Content.Benchmark.dc, "Evaluate-STIG $($ScanObject.ESData.ESVersion)")
                }
                "publisher" {
                    $xmlWriter.WriteElementString($Item, $Content.Benchmark.dc, $Content.Benchmark.reference.publisher)
                }
                "source" {
                    $xmlWriter.WriteElementString($Item, $Content.Benchmark.dc, $Content.Benchmark.reference.source)
                }
            }
        }
        $xmlWriter.WriteEndElement() # Close 'metadata'

        # Create 'Group' nodes
        ForEach ($Item in $ScanObject.VulnResults) {
            $STIGGroup = $Content.Benchmark.Group | Where-Object id -EQ $Item.GroupID
            $xmlWriter.WriteStartElement("cdf", "Group", $Namespace)
            $xmlWriter.WriteAttributeString("id", "xccdf_mil.disa.stig_group_$($STIGGroup.id)")

            # Create 'tltle' element
            $xmlWriter.WriteElementString("title", $Namespace, $Item.GroupTitle)

            # Create 'rule' node
            $xmlWriter.WriteStartElement("cdf", "Rule", $Namespace)
            $xmlWriter.WriteAttributeString("id", "xccdf_mil.disa.stig_rule_$($STIGGroup.Rule.id)")
            $xmlWriter.WriteAttributeString("severity", $STIGGroup.Rule.severity)
            $xmlWriter.WriteAttributeString("weight", $STIGGroup.Rule.weight)
            ForEach ($Sub1 in @("version", "title", "description", "reference", "ident", "fixtext")) {
                # Create sub-element
                Switch ($Sub1) {
                    "reference" {
                        # Create 'reference' elements
                        $xmlWriter.WriteStartElement("cdf", $Sub1, $Namespace)
                        $xmlWriter.WriteElementString("publisher", $Content.Benchmark.dc, $STIGGroup.Rule.reference.publisher)
                        $xmlWriter.WriteElementString("identifier", $Content.Benchmark.dc, $STIGGroup.Rule.reference.identifier)
                        $xmlWriter.WriteElementString("type", $Content.Benchmark.dc, $STIGGroup.Rule.reference.type)
                        $xmlWriter.WriteEndElement() # Close 'reference'
                    }
                    "ident" {
                        # Create 'ident' elements
                        ForEach ($ident in $STIGGroup.Rule.ident) {
                            $xmlWriter.WriteStartElement("cdf", $Sub1, $Namespace)
                            $xmlWriter.WriteAttributeString("system", $ident.system)
                            $xmlWriter.WriteString($ident.'#text')
                            $xmlWriter.WriteEndElement() # Close 'ident'
                        }
                    }
                    "fixtext" {
                        $xmlWriter.WriteStartElement("cdf", $Sub1, $Namespace)
                        $xmlWriter.WriteAttributeString("fixref", $STIGGroup.Rule.$Sub1.fixref)
                        $xmlWriter.WriteString($STIGGroup.Rule.$Sub1.'#text')
                        $xmlWriter.WriteEndElement() # Close 'fixtext'
                    }
                    DEFAULT {
                        $xmlWriter.WriteElementString($Sub1, $Namespace, $STIGGroup.Rule.$Sub1)
                    }
                }
            }

            # Create 'check' node
            $xmlWriter.WriteStartElement("cdf", "check", $Namespace)
            $xmlWriter.WriteAttributeString("system", "Evaluate-STIG")
            # Create 'check-content-ref' node
            $xmlWriter.WriteStartElement("cdf", "check-content-ref", $Namespace)
            $xmlWriter.WriteAttributeString("name", "Get-$(($Item.GroupID).Replace('-',''))")
            $xmlWriter.WriteAttributeString("href", $ScanObject.ESData.ModuleName)
            $xmlWriter.WriteEndElement() # Close 'check-content-ref'
            $xmlWriter.WriteEndElement() # Close 'check'

            $xmlWriter.WriteEndElement() # Close 'rule'
            $xmlWriter.WriteEndElement() # Close 'Group'
        }

        # Create 'TestResult' node
        $xmlWriter.WriteStartElement("cdf", "TestResult", $Namespace)
        $xmlWriter.WriteAttributeString("id", "xccdf_mil.navy.navsea.Evaluate-STIG_testresult_$($ScanObject.ESData.ModuleName)-$($ScanObject.ESData.ModuleVersion)")
        $xmlWriter.WriteAttributeString("test-system", "cpe:2.3:a:navsea:evaluate-stig:$($ScanObject.ESData.ESVersion)")
        $xmlWriter.WriteAttributeString("start-time", $(Get-Date $ScanObject.ESData.StartTime -Format 'yyyy-MM-ddTHH:mm:ssK'))
        $xmlWriter.WriteAttributeString("end-time", $(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssK'))

        # Create 'organization' element
        $xmlWriter.WriteElementString("organization", $Namespace, "Naval Sea Systems Command (NAVSEA)")

        # Create 'target' element
        $xmlWriter.WriteElementString("target", $Namespace, $ScanObject.TargetData.HostName)

        # Create 'target-address' element(s)
        If ($ScanObject.TargetData.IpAddress) {
            ForEach ($IP in ($ScanObject.TargetData.IpAddress).Split(",").Trim()) {
                $xmlWriter.WriteElementString("target-address", $Namespace, $IP)
            }
        }
        Else {
            $xmlWriter.WriteElementString("target-address", $Namespace, "0.0.0.0")
        }

        # Create 'target-facts' node
        $xmlWriter.WriteStartElement("cdf", "target-facts", $Namespace)
        # Create 'fact' elements
        ForEach ($Item in @("HostName", "FQDN", "Manufacturer", "Model", "SerialNumber", "OSName", "OSVersion", "CPUName", "Role", "Instance", "WebOrDatabase", "Site")) {
            if ($AssetData.$Item){
                $xmlWriter.WriteStartElement("cdf", "fact", $Namespace)
                $xmlWriter.WriteAttributeString("type", $AssetData.$Item.GetType().Name.ToLower())
                $xmlWriter.WriteAttributeString("name", "fact:asset:identifier:$($Item.ToLower())")
                If ($AssetData.$Item.GetType().Name -eq "Boolean") {
                    $xmlWriter.WriteString(([string]$AssetData.$Item).ToLower())
                }
                Else {
                    $xmlWriter.WriteString($AssetData.$Item)
                }
                $xmlWriter.WriteEndElement() # Close 'fact'
            }
        }

        ForEach ($Item in $AssetData.ActiveAdapters){
            Foreach ($ItemDetail in @("Caption", "IPv4Address", "MACAddress")){
                if ($ItemDetail -eq "IPv4Address"){
                    ForEach ($IP in ($Item.IPv4Address).Split(",").Trim()) {
                        $xmlWriter.WriteStartElement("cdf", "fact", $Namespace)
                        $xmlWriter.WriteAttributeString("type", $IP.GetType().Name.ToLower())
                        $xmlWriter.WriteAttributeString("name", "fact:asset:identifier:$($ItemDetail.ToLower())")
                        $xmlWriter.WriteString($IP)
                        $xmlWriter.WriteEndElement() # Close 'fact'
                    }
                }
                else {
                    $xmlWriter.WriteStartElement("cdf", "fact", $Namespace)
                    $xmlWriter.WriteAttributeString("type", $($Item.$ItemDetail).GetType().Name.ToLower())
                    $xmlWriter.WriteAttributeString("name", "fact:asset:identifier:$($ItemDetail.ToLower())")
                    $xmlWriter.WriteString($Item.$ItemDetail)
                    $xmlWriter.WriteEndElement() # Close 'fact'
                }
            }
            if ($Item.IPv6Address){
                Foreach ($IP in ($Item.IPv6Address).Split(",").Trim()) {
                    $xmlWriter.WriteStartElement("cdf", "fact", $Namespace)
                    $xmlWriter.WriteAttributeString("type", $IP.GetType().Name.ToLower())
                    $xmlWriter.WriteAttributeString("name", "fact:asset:identifier:ipv6address")
                    $xmlWriter.WriteString($IP)
                    $xmlWriter.WriteEndElement() # Close 'fact'
                }
            }
        }
        $xmlWriter.WriteEndElement() # Close 'target-fact'

        # Create 'rule-result' nodes
        ForEach ($Item in $ScanObject.VulnResults) {
            # Set TruncatedFindingDetails and TruncatedComments variables
            if ($null -ne $Item.FindingDetails -and $Item.FindingDetails.Trim().Length -gt 0) {
                $TruncatedFindingDetails = Get-TruncatedOutput -InputText $Item.FindingDetails -TruncateOutput $TruncateOutput
            }
            else {
                $TruncatedFindingDetails = ""
            }
            if ($null -ne $Item.Comments -and $Item.Comments.Trim().Length -gt 0) {
                $TruncatedComments = Get-TruncatedOutput -InputText $Item.Comments -TruncateOutput $TruncateOutput
            }
            else {
                $TruncatedComments = ""
            }

            # Set XML attributes
            $STIGGroup = $Content.Benchmark.Group | Where-Object id -EQ $Item.GroupID
            $xmlWriter.WriteStartElement("cdf", "rule-result", $Namespace)
            $xmlWriter.WriteAttributeString("idref", "xccdf_mil.disa.stig_rule_$($STIGGroup.Rule.id)")
            $xmlWriter.WriteAttributeString("weight", $($STIGGroup.Rule.weight))
            $xmlWriter.WriteAttributeString("severity", $($STIGGroup.Rule.severity))
            $xmlWriter.WriteAttributeString("time", $(Get-Date $ScanObject.ESData.StartTime -Format 'yyyy-MM-ddTHH:mm:ssK'))
            $xmlWriter.WriteAttributeString("version", $($STIGGroup.Rule.version))

            # Create 'result' element
            $xmlWriter.WriteElementString("result", $Namespace, $(Convert-Status -InputObject $Item.Status -Output XCCDF))

            # Create 'ident' elements
            ForEach ($ident in $STIGGroup.Rule.ident) {
                $xmlWriter.WriteStartElement("cdf", "ident", $Namespace)
                $xmlWriter.WriteAttributeString("system", $ident.system)
                $xmlWriter.WriteString($ident.'#text')
                $xmlWriter.WriteEndElement() # Close 'ident'
            }

            # Create 'message' element
            $xmlWriter.WriteStartElement("cdf", "message", $Namespace)
            $xmlWriter.WriteAttributeString("severity", "info")
            $xmlWriter.WriteString("$($TruncatedFindingDetails)`r`n`r`n$($TruncatedComments)")
            $xmlWriter.WriteEndElement() # Close 'message'

            # Create 'fix' element
            $xmlWriter.WriteStartElement("cdf", "fix", $Namespace)
            $xmlWriter.WriteAttributeString("id", $STIGGroup.Rule.fixtext.fixref)
            $xmlWriter.WriteEndElement() # Close 'fix'

            # Create 'check' node
            $xmlWriter.WriteStartElement("cdf", "check", $Namespace)
            $xmlWriter.WriteAttributeString("system", "Evaluate-STIG")
            # Create 'check-content-ref' node
            $xmlWriter.WriteStartElement("cdf", "check-content-ref", $Namespace)
            $xmlWriter.WriteAttributeString("name", "Get-$(($Item.GroupID).Replace('-',''))")
            $xmlWriter.WriteAttributeString("href", $ScanObject.ESData.ModuleName)
            $xmlWriter.WriteEndElement() # Close 'check-content-ref'
            # Create 'check-content' node
            $xmlWriter.WriteStartElement("cdf", "check-content", $Namespace)
            # Create 'sm:resultEngine' node
            $xmlWriter.WriteStartElement("sm", "resultEngine", $SMNamespace)
            # Create 'sm:time' element
            $xmlWriter.WriteElementString("time", $SMNamespace, $(Get-Date $ScanObject.ESData.StartTime -Format 'yyyy-MM-ddTHH:mm:ssK'))
            # Create 'sm:type' element
            $xmlWriter.WriteElementString("type", $SMNamespace, "script")
            # Create 'sm:product' element
            $xmlWriter.WriteElementString("product", $SMNamespace, "Evaluate-STIG")
            # Create 'sm:version' element
            $xmlWriter.WriteElementString("version", $SMNamespace, $($ScanObject.ESData.ESVersion))
            # Create 'sm:overrides' node if Comment exists
            If ($Item.Comments.Trim().Length -gt 0) {
                $xmlWriter.WriteStartElement("sm", "overrides", $SMNamespace)
                # Create 'sm:remark; element
                $xmlWriter.WriteElementString("remark", $SMNamespace, $TruncatedComments)
                # Create 'sm:authority' element
                $xmlWriter.WriteElementString("authority", $SMNamespace, $(Split-Path -Path $ScanObject.ESData.AnswerFile -Leaf))
                # Create 'sm:newResult' and 'sm:oldResult' elements
                If ($Item.STIGMan.AFMod) {
                    $xmlWriter.WriteElementString("newResult", $SMNamespace, $Item.STIGMan.NewStatus)
                    $xmlWriter.WriteElementString("oldResult", $SMNamespace, $Item.STIGMan.OldStatus)
                }
                Else {
                    $xmlWriter.WriteElementString("newResult", $SMNamespace, $(Convert-Status -InputObject $Item.Status -Output XCCDF))
                    $xmlWriter.WriteElementString("oldResult", $SMNamespace, $(Convert-Status -InputObject $Item.Status -Output XCCDF))
                }
                $xmlWriter.WriteEndElement() # Close 'overrides'
            }
            # Create 'sm:checkContent' node
            $xmlWriter.WriteStartElement("sm", "checkContent", $SMNamespace)
            # Create 'sm:location' node
            $xmlWriter.WriteElementString("location", $SMNamespace, "$($ScanObject.ESData.ModuleName):$($ScanObject.ESData.ModuleVersion)")
            $xmlWriter.WriteEndElement() # Close 'checkContent'
            $xmlWriter.WriteEndElement() # Close 'resultEngine'
            $xmlWriter.WriteEndElement() # Close 'check-content'
            $xmlWriter.WriteEndElement() # Close 'check'

            $xmlWriter.WriteEndElement() # Close 'rule-result'
        }

        # Create 'score' element
        $xmlWriter.WriteStartElement("cdf", "score", $Namespace)
        $xmlWriter.WriteAttributeString("maximum", "100")
        $xmlWriter.WriteString([Math]::Round((($ScanObject.VulnResults | Where-Object Status -In @('NotAFinding', 'Not_Applicable') | Measure-Object).Count / ($ScanObject.VulnResults | Measure-Object).Count * 100), 2))
        $xmlWriter.WriteEndElement() # Close 'score'

        $xmlWriter.WriteEndElement() # Close 'TestResult'

        $xmlWriter.WriteEndElement() # Close 'Benchmark'

        # Create Marking comment
        If ($Marking) {
            $xmlWriter.WriteComment("                                                                                          $Marking                                                                                          ")
        }

        $xmlWriter.WriteEndDocument()
        $xmlWriter.Flush()
        $xmlWriter.Close()

        Write-Log -Path $STIGLog -Message "Validating XCCDF File" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        $ChecklistValid = $true

        $ChecklistValid = Test-ARFXCCDFXMLValidation -XmlFile $OutputPath -SchemaPath $SchemaPath

        # Action for validation result
        If ($ChecklistValid) {
            Write-Log -Path $STIGLog -Message "'$(Split-Path $OutputPath -Leaf)' : Passed." -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        }
        Else {
            $BadFileDestination = Join-Path -Path $WorkingDir -ChildPath "Bad_CKL"
            Write-Log -Path $STIGLog -Message "ERROR: '$(Split-Path $OutputPath -Leaf)' : failed schema validation. Moving to $BadFileDestination." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
            ForEach ($Item in $ChecklistValid.Message) {
                Write-Log -Path $STIGLog -Message $Item -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
            }
            If (-Not(Test-Path $BadFileDestination)) {
                New-Item -Path $BadFileDestination -ItemType Directory | Out-Null
            }
            Copy-Item -Path $OutputPath -Destination $BadFileDestination -Force
            Remove-Item $OutputPath -Force
        }

        Return $ChecklistValid
    }
    Catch {
        Return $False
    }
}

Function Format-ARF {
    param
    (
        [Parameter(Mandatory)]
        [psobject]$ScanObject,

        [Parameter(Mandatory = $true)]
        [Int32]$TruncateOutput,

        [Parameter(Mandatory)]
        [psobject]$AssetData,

        [Parameter(Mandatory)]
        [psobject]$SchemaPath,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [Parameter()]
        [string]$Marking = "",

        [Parameter(Mandatory = $true)]
        [String]$ESPath
    )

    Try {
        # Get Target Data
        If (($ScanObject | Measure-Object).Count -gt 1) {
            Throw "Only single STIG results supported for ARF output."
        }

        # Read the STIG content
        If (-not($ScanObject.ESData.IsManualSTIG)) {
            $STIGXMLPath = $(Join-Path -Path $ESPath -ChildPath StigContent | Join-Path -ChildPath $ScanObject.ESData.STIGXMLName)
        }
        Else {
            $STIGXMLPath = $(Join-Path -Path $ESPath -ChildPath StigContent | Join-Path -ChildPath Manual | Join-Path -ChildPath $Scan.ESData.STIGXMLName)
        }
        # https://stackoverflow.com/questions/71847945/strange-characters-found-in-xml-file-and-powershell-output-after-exporting-from
        ($Content = [xml]::new()).Load($STIGXMLPath)

        # Build the XML data
        $Encoding = [System.Text.UTF8Encoding]::new($false)
        $xmlSettings = New-Object System.Xml.XmlWriterSettings
        $xmlSettings.Encoding = $Encoding
        $xmlSettings.Indent = $true
        $xmlSettings.IndentChars = "    "
        $xmlSettings.NewLineHandling = "None"

        $xmlWriter = [System.Xml.XmlWriter]::Create($($OutputPath), $xmlSettings)

        # Set ARF namespaces
        $arfNamespace = "http://scap.nist.gov/schema/asset-reporting-format/1.1"
        $coreNamespace = "http://scap.nist.gov/schema/reporting-core/1.1"
        $xccdfNamespace = "http://checklists.nist.gov/xccdf/1.2"
        $aiNamespace = "http://scap.nist.gov/schema/asset-identification/1.1"
        $schemaLocation = "http://scap.nist.gov/schema/reporting-core/1.1 https://csrc.nist.gov/schema/reporting-core/1.1/reporting-core_1.1.0.xsd http://scap.nist.gov/schema/asset-reporting-format/1.1 https://csrc.nist.gov/schema/asset-reporting-format/1.1/asset-reporting-format_1.1.0.xsd http://scap.nist.gov/schema/asset-identification/1.1 https://csrc.nist.gov/schema/asset-identification/1.1/asset-identification_1.1.0.xsd"

        # Create Marking comment
        If ($Marking) {
            $xmlWriter.WriteComment("                                                                                          $Marking                                                                                          ")
        }

        # Create 'asset-report-collection' node
        $xmlWriter.WriteStartElement("arf", "asset-report-collection", $arfNamespace)
        $xmlWriter.WriteAttributeString("xsi", "schemaLocation", "http://www.w3.org/2001/XMLSchema-instance", $schemaLocation)
        $xmlWriter.WriteAttributeString("xmlns", "arf", "http://www.w3.org/2000/xmlns/", "http://scap.nist.gov/schema/asset-reporting-format/1.1")
        $xmlWriter.WriteAttributeString("xmlns", "core", "http://www.w3.org/2000/xmlns/", "http://scap.nist.gov/schema/reporting-core/1.1")
        $xmlWriter.WriteAttributeString("xmlns", "xsi", "http://www.w3.org/2000/xmlns/", $Content.Benchmark.xsi)
        $xmlWriter.WriteAttributeString("xmlns", "xlink", "http://www.w3.org/2000/xmlns/", "http://www.w3.org/1999/xlink")
        $xmlWriter.WriteAttributeString("xmlns", "ai", "http://www.w3.org/2000/xmlns/","http://scap.nist.gov/schema/asset-identification/1.1")
        $xmlWriter.WriteAttributeString("xmlns", "dc", "http://www.w3.org/2000/xmlns/", $Content.Benchmark.dc)
        $xmlWriter.WriteAttributeString("xmlns", "xccdf", "http://www.w3.org/2000/xmlns/", "http://checklists.nist.gov/xccdf/1.2")

        # Create 'core:relationships' element
        $xmlWriter.WriteStartElement("core", "relationship", $coreNamespace)
        $xmlWriter.WriteAttributeString("type", "arf-rel:isAbout")
        $xmlWriter.WriteAttributeString("subject", "xccdf_mil.disa.stig_benchmark_$($ScanObject.ESData.STIGXMLName)")
        $xmlWriter.WriteAttributeString("object",  $ScanObject.TargetData.HostName)
        $xmlWriter.WriteEndElement() # close 'core:relationship'
        $xmlWriter.WriteStartElement("core", "relationship", $coreNamespace)
        $xmlWriter.WriteAttributeString("type", "stig-rel:checkContext")
        $xmlWriter.WriteAttributeString("subject", "xccdf_mil.disa.stig_benchmark_$($ScanObject.ESData.STIGXMLName)")
        $xmlWriter.WriteAttributeString("object", "xccdf_mil.disa.stig_benchmark_$($ScanObject.ESData.STIGXMLName)")
        $xmlWriter.WriteEndElement() # close 'core:relationship'
        $xmlWriter.WriteStartElement("core", "relationship", $coreNamespace)
        $xmlWriter.WriteAttributeString("type", "stig-rel:fromSource")
        $xmlWriter.WriteAttributeString("subject", $ScanObject.ESData.STIGXMLName)
        $xmlWriter.WriteAttributeString("object", $ScanObject.ESData.ModuleName)
        $xmlWriter.WriteEndElement() # close 'core:relationship'

        # Create 'report-requests' node
        $xmlWriter.WriteStartElement("arf", "report-requests", $arfNamespace)
        # Create 'report-request' node
        $xmlWriter.WriteStartElement("arf", "report-request", $arfNamespace)
        $xmlWriter.WriteAttributeString("id", "xccdf_mil.disa.stig_benchmark_$($ScanObject.ESData.STIGXMLName)")
        $xmlWriter.WriteStartElement("arf", "content", $arfNamespace)
        $xmlWriter.WriteStartElement("xccdf", "Benchmark", $xccdfNamespace)
        $xmlWriter.WriteAttributeString("id", "xccdf_mil.disa.stig_benchmark_$($ScanObject.ESData.STIGXMLName)")
        # Create 'status' node
        $xmlWriter.WriteStartElement("xccdf", "status", $xccdfNamespace)
        $xmlwriter.WriteAttributeString("date", $Content.Benchmark.status.date)
        $xmlwriter.WriteString($Content.Benchmark.status.'#text')
        $xmlwriter.WriteEndElement() # Close 'status'
        $xmlWriter.WriteElementString("title", $xccdfNamespace, $Content.Benchmark.title)
        $xmlWriter.WriteElementString("description", $xccdfNamespace, $Content.Benchmark.description)
        # Create 'platform' element
        $xmlWriter.WriteStartElement("xccdf", "platform", $xccdfNamespace)
        $xmlWriter.WriteAttributeString("idref", "cpe:2.3:a:disa:stig")
        $xmlWriter.WriteString("")
        $xmlWriter.WriteEndElement() # Close 'platform'
        # Create 'version' element
        $xmlWriter.WriteElementString("version", $xccdfNamespace, "V$($ScanObject.STIGInfo.Version)R$($ScanObject.STIGInfo.Release)")
        # Create 'metadata' node
        $xmlWriter.WriteStartElement("xccdf", "metadata", $xccdfNamespace)
        ForEach ($Item in @("creator", "publisher", "source")) {
            Switch ($Item) {
                "creator" {
                    $xmlWriter.WriteElementString($Item, $Content.Benchmark.dc, "Evaluate-STIG $($ScanObject.ESData.ESVersion)")
                }
                "publisher" {
                    $xmlWriter.WriteElementString($Item, $Content.Benchmark.dc, $Content.Benchmark.reference.publisher)
                }
                "source" {
                    $xmlWriter.WriteElementString($Item, $Content.Benchmark.dc, $Content.Benchmark.reference.source)
                }
            }
        }
        $xmlWriter.WriteEndElement() # Close 'metadata'
        # Create 'Group' elements
        ForEach ($Item in $Content.Benchmark.'Group') {
            $xmlWriter.WriteStartElement("xccdf", "Group", $xccdfNamespace)
            $xmlWriter.WriteAttributeString("id", "xccdf_mil.disa.stig_group_$($Item.id)")
            $xmlWriter.WriteElementString("title", $xccdfNamespace, $Item.title)
            $xmlWriter.WriteElementString("description", $xccdfNamespace, $Item.description)
            #Create Rule element
            $xmlWriter.WriteStartElement("xccdf", "Rule", $xccdfNamespace)
            $xmlWriter.WriteAttributeString("id", "xccdf_mil.disa.stig_rule_$($Item.Rule.id)")
            $xmlWriter.WriteAttributeString("severity", $Item.Rule.severity)
            $xmlWriter.WriteAttributeString("weight", $Item.Rule.weight)
            ForEach ($Sub1 in @("ident", "fix")) {
                # Create sub-element
                Switch ($Sub1) {
                    "ident" {
                        # Create 'ident' elements
                        ForEach ($ident in $Item.Rule.ident) {
                            $xmlWriter.WriteStartElement("xccdf", $Sub1, $xccdfNamespace)
                            $xmlWriter.WriteAttributeString("system", $ident.system)
                            $xmlWriter.WriteString($ident.'#text')
                            $xmlWriter.WriteEndElement() # Close 'ident'
                        }
                    }
                    "fix" {
                        $xmlWriter.WriteStartElement("xccdf", $Sub1, $xccdfNamespace)
                        $xmlWriter.WriteAttributeString("id", $Item.Rule.$Sub1.id)
                        $xmlWriter.WriteString("")
                        $xmlWriter.WriteEndElement() # Close 'fix'
                    }
                    DEFAULT {
                        $xmlWriter.WriteElementString($Sub1, $xccdfNamespace, $Item.Rule.$Sub1)
                    }
                }
            }

            # Create 'check' node
            $xmlWriter.WriteStartElement("xccdf", "check", $xccdfNamespace)
            $xmlWriter.WriteAttributeString("system", "Evaluate-STIG")
            # Create 'check-content-ref' node
            $xmlWriter.WriteStartElement("xccdf", "check-content-ref", $xccdfNamespace)
            $xmlWriter.WriteAttributeString("href", $ScanObject.ESData.ModuleName)
            $xmlWriter.WriteAttributeString("name", "Get-$(($Item.id).Replace('-',''))")
            $xmlWriter.WriteEndElement() # Close 'check-content-ref'
            $xmlWriter.WriteEndElement() # Close 'check'
            $xmlWriter.WriteEndElement() # Close 'Rule'
            $xmlWriter.WriteEndElement() # Close 'Group'
        }
        $xmlWriter.WriteEndElement() # close 'Benchmark'
        $xmlWriter.WriteEndElement() # close 'content'
        $xmlWriter.WriteEndElement() # Close 'report-request'
        $xmlWriter.WriteEndElement() # Close 'report-requests'

        # Create 'assets' element
        $xmlWriter.WriteStartElement("arf", "assets", $arfNamespace)
        $xmlWriter.WriteStartElement("arf", "asset", $arfNamespace)
        $xmlWriter.WriteAttributeString("id", $ScanObject.TargetData.HostName)
        $xmlWriter.WriteStartElement("ai", "asset", $aiNamespace)
        $xmlWriter.WriteEndElement() # close 'asset'
        $xmlWriter.WriteEndElement() # Close 'asset'
        $xmlWriter.WriteEndElement() # Close 'assets'

        # Create 'reports' element
        $xmlWriter.WriteStartElement("arf", "reports", $arfNamespace)
        $xmlWriter.WriteStartElement("arf", "report", $arfNamespace)
        $xmlWriter.WriteAttributeString("id", "xccdf_mil.disa.stig_benchmark_$($ScanObject.ESData.STIGXMLName)_$($ScanObject.TargetData.HostName)")
        # Create 'content' element
        $xmlWriter.WriteStartElement("arf", "content", $arfNamespace)
        $xmlWriter.WriteStartElement("xccdf", "Benchmark", $xccdfNamespace)
        $xmlWriter.WriteAttributeString("id", "xccdf_mil.disa.stig_benchmark_$($ScanObject.ESData.STIGXMLName)")
        # Create 'status' node
        $xmlWriter.WriteStartElement("xccdf", "status", $xccdfNamespace)
        $xmlwriter.WriteAttributeString("date", $Content.Benchmark.status.date)
        $xmlwriter.WriteString($Content.Benchmark.status.'#text')
        $xmlwriter.WriteEndElement() # Close 'status'
        $xmlWriter.WriteElementString("title", $xccdfNamespace, $Content.Benchmark.title)
        $xmlWriter.WriteElementString("description", $xccdfNamespace, $Content.Benchmark.description)
        # Create 'platform' element
        $xmlWriter.WriteStartElement("xccdf", "platform", $xccdfNamespace)
        $xmlWriter.WriteAttributeString("idref", "cpe:2.3:a:disa:stig")
        $xmlWriter.WriteString("")
        $xmlWriter.WriteEndElement() # Close 'platform'
        # Create 'version' element
        $xmlWriter.WriteElementString("version", $xccdfNamespace, "V$($ScanObject.STIGInfo.Version)R$($ScanObject.STIGInfo.Release)")
        # Create 'metadata' node
        $xmlWriter.WriteStartElement("xccdf", "metadata", $xccdfNamespace)
        ForEach ($Item in @("creator", "publisher", "source")) {
            Switch ($Item) {
                "creator" {
                    $xmlWriter.WriteElementString($Item, $Content.Benchmark.dc, "Evaluate-STIG $($ScanObject.ESData.ESVersion)")
                }
                "publisher" {
                    $xmlWriter.WriteElementString($Item, $Content.Benchmark.dc, $Content.Benchmark.reference.publisher)
                }
                "source" {
                    $xmlWriter.WriteElementString($Item, $Content.Benchmark.dc, $Content.Benchmark.reference.source)
                }
            }
        }
        $xmlWriter.WriteEndElement() # Close 'metadata'
        # Create 'Group' elements
        ForEach ($Item in $Content.Benchmark.'Group') {
            $xmlWriter.WriteStartElement("xccdf", "Group", $xccdfNamespace)
            $xmlWriter.WriteAttributeString("id", "xccdf_mil.disa.stig_group_$($Item.id)")
            $xmlWriter.WriteElementString("title", $xccdfNamespace, $Item.title)
            $xmlWriter.WriteElementString("description", $xccdfNamespace, $Item.description)
            #Create Rule element
            $xmlWriter.WriteStartElement("xccdf", "Rule", $xccdfNamespace)
            $xmlWriter.WriteAttributeString("id", "xccdf_mil.disa.stig_rule_$($Item.Rule.id)")
            $xmlWriter.WriteAttributeString("severity", $Item.Rule.severity)
            $xmlWriter.WriteAttributeString("weight", $Item.Rule.weight)
            ForEach ($Sub1 in @("ident", "fix")) {
                # Create sub-element
                Switch ($Sub1) {
                    "ident" {
                        # Create 'ident' elements
                        ForEach ($ident in $Item.Rule.ident) {
                            $xmlWriter.WriteStartElement("xccdf", $Sub1, $xccdfNamespace)
                            $xmlWriter.WriteAttributeString("system", $ident.system)
                            $xmlWriter.WriteString($ident.'#text')
                            $xmlWriter.WriteEndElement() # Close 'ident'
                        }
                    }
                    "fix" {
                        $xmlWriter.WriteStartElement("xccdf", $Sub1, $xccdfNamespace)
                        $xmlWriter.WriteAttributeString("id", $Item.Rule.$Sub1.id)
                        $xmlWriter.WriteString("")
                        $xmlWriter.WriteEndElement() # Close 'fix'
                    }
                    DEFAULT {
                        $xmlWriter.WriteElementString($Sub1, $xccdfNamespace, $Item.Rule.$Sub1)
                    }
                }
            }

            # Create 'check' node
            $xmlWriter.WriteStartElement("xccdf", "check", $xccdfNamespace)
            $xmlWriter.WriteAttributeString("system", "Evaluate-STIG")
            # Create 'check-content-ref' node
            $xmlWriter.WriteStartElement("xccdf", "check-content-ref", $xccdfNamespace)
            $xmlWriter.WriteAttributeString("href", $ScanObject.ESData.ModuleName)
            $xmlWriter.WriteAttributeString("name", "Get-$(($Item.id).Replace('-',''))")
            $xmlWriter.WriteEndElement() # Close 'check-content-ref'
            $xmlWriter.WriteEndElement() # Close 'check'
            $xmlWriter.WriteEndElement() # Close 'Rule'
            $xmlWriter.WriteEndElement() # Close 'Group'
        }
        # Create 'TestResult' node
        $xmlWriter.WriteStartElement("xccdf", "TestResult", $xccdfNamespace)
        $xmlWriter.WriteAttributeString("id", "xccdf_mil.navy.navsea.Evaluate-STIG_testresult_$($ScanObject.ESData.ModuleName)-$($ScanObject.ESData.ModuleVersion)")
        $xmlWriter.WriteAttributeString("test-system", "cpe:2.3:a:navsea:evaluate-stig")
        $xmlWriter.WriteAttributeString("version", $ScanObject.ESData.ESVersion)
        $xmlWriter.WriteAttributeString("start-time", $(Get-Date $ScanObject.ESData.StartTime -Format 'yyyy-MM-ddTHH:mm:ssK'))
        $xmlWriter.WriteAttributeString("end-time", $(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssK'))
        $xmlWriter.WriteElementString("xccdf", "target", $xccdfNamespace, $ScanObject.TargetData.HostName)
        # Create 'target-facts' node
        $xmlWriter.WriteStartElement("xccdf", "target-facts", $xccdfNamespace)
        # Create 'fact' elements

        ForEach ($Item in @("HostName", "FQDN", "Manufacturer", "Model", "SerialNumber", "OSName", "OSVersion", "CPUName", "Role", "Instance", "WebOrDatabase", "Site")) {
            if ($AssetData.$Item){
                $xmlWriter.WriteStartElement("xccdf", "fact", $xccdfNamespace)
                $xmlWriter.WriteAttributeString("name", "fact:asset:identifier:$($Item.ToLower())")
                If ($AssetData.$Item.GetType().Name -eq "Boolean") {
                    $xmlWriter.WriteString(([string]$AssetData.$Item).ToLower())
                }
                Else {
                    $xmlWriter.WriteString($AssetData.$Item)
                }
                $xmlWriter.WriteEndElement() # Close 'fact'
            }
        }

        ForEach ($Item in $AssetData.ActiveAdapters){
            Foreach ($ItemDetail in @("Caption", "IPv4Address", "MACAddress")){
                if ($ItemDetail -eq "IPv4Address"){
                    ForEach ($IP in ($Item.IPv4Address).Split(",").Trim()) {
                        $xmlWriter.WriteStartElement("xccdf", "fact", $xccdfNamespace)
                        $xmlWriter.WriteAttributeString("name", "fact:asset:identifier:$($ItemDetail.ToLower())")
                        $xmlWriter.WriteString($IP)
                        $xmlWriter.WriteEndElement() # Close 'fact'
                    }
                }
                else {
                    $xmlWriter.WriteStartElement("xccdf", "fact", $xccdfNamespace)
                    $xmlWriter.WriteAttributeString("name", "fact:asset:identifier:$($ItemDetail.ToLower())")
                    $xmlWriter.WriteString($Item.$ItemDetail)
                    $xmlWriter.WriteEndElement() # Close 'fact'
                }
            }
            if ($Item.IPv6Address){
                Foreach ($IP in ($Item.IPv6Address).Split(",").Trim()) {
                    $xmlWriter.WriteStartElement("xccdf", "fact", $xccdfNamespace)
                    $xmlWriter.WriteAttributeString("name", "fact:asset:identifier:ipv6address")
                    $xmlWriter.WriteString($IP)
                    $xmlWriter.WriteEndElement() # Close 'fact'
                }
            }
        }
        $xmlWriter.WriteEndElement() # Close 'target-facts'

        # Create 'rule-result' nodes
        ForEach ($Item in $ScanObject.VulnResults) {
            # Set TruncatedFindingDetails and TruncatedComments variables
            if ($null -ne $Item.FindingDetails -and $Item.FindingDetails.Trim().Length -gt 0) {
                $TruncatedFindingDetails = Get-TruncatedOutput -InputText $Item.FindingDetails -TruncateOutput $TruncateOutput
            }
            else {
                $TruncatedFindingDetails = ""
            }
            if ($null -ne $Item.Comments -and $Item.Comments.Trim().Length -gt 0) {
                $TruncatedComments = Get-TruncatedOutput -InputText $Item.Comments -TruncateOutput $TruncateOutput
            }
            else {
                $TruncatedComments = ""
            }

            # Set XML attributes
            $STIGGroup = $Content.Benchmark.Group | Where-Object id -EQ $Item.GroupID
            $xmlWriter.WriteStartElement("xccdf", "rule-result", $xccdfNamespace)
            $xmlWriter.WriteAttributeString("idref", "xccdf_mil.disa.stig_rule_$($STIGGroup.Rule.id)")
            $xmlWriter.WriteAttributeString("weight", $($STIGGroup.Rule.weight))
            $xmlWriter.WriteAttributeString("severity", $($STIGGroup.Rule.severity))
            $xmlWriter.WriteAttributeString("time", $(Get-Date $ScanObject.ESData.StartTime -Format 'yyyy-MM-ddTHH:mm:ssK'))
            $xmlWriter.WriteAttributeString("version", $($STIGGroup.Rule.version))

            # Create 'result' element
            $xmlWriter.WriteElementString("result", $xccdfNamespace, $(Convert-Status -InputObject $Item.Status -Output ARF))

            # Create 'ident' elements
            ForEach ($ident in $STIGGroup.Rule.ident) {
                $xmlWriter.WriteStartElement("xccdf", "ident", $xccdfNamespace)
                $xmlWriter.WriteAttributeString("system", $ident.system)
                $xmlWriter.WriteString($ident.'#text')
                $xmlWriter.WriteEndElement() # Close 'ident'
            }

            # Create 'message' element
            $xmlWriter.WriteStartElement("xccdf", "message", $xccdfNamespace)
            $xmlWriter.WriteAttributeString("severity", "info")
            $xmlWriter.WriteString("$($TruncatedFindingDetails)`r`n`r`n$($TruncatedComments)")
            $xmlWriter.WriteEndElement() # Close 'message'

            # Create 'fix' element
            $xmlWriter.WriteStartElement("xccdf", "fix", $xccdfNamespace)
            $xmlWriter.WriteAttributeString("id", $STIGGroup.Rule.fix.id)
            $xmlWriter.WriteEndElement() # Close 'fix'

            # Create 'check' node
            $xmlWriter.WriteStartElement("xccdf", "check", $xccdfNamespace)
            $xmlWriter.WriteAttributeString("system", "Evaluate-STIG")
            # Create 'check-content-ref' node
            $xmlWriter.WriteStartElement("xccdf", "check-content-ref", $xccdfNamespace)
            $xmlWriter.WriteAttributeString("name", "Get-$(($Item.GroupID).Replace('-',''))")
            $xmlWriter.WriteAttributeString("href", $ScanObject.ESData.ModuleName)
            $xmlWriter.WriteEndElement() # Close 'check-content-ref'
            $xmlWriter.WriteEndElement() # Close 'check'

            $xmlWriter.WriteEndElement() # Close 'rule-result'
        }

        # Create 'score' element
        $xmlWriter.WriteStartElement("xccdf", "score", $xccdfNamespace)
        $xmlWriter.WriteAttributeString("maximum", "100")
        $xmlWriter.WriteString([Math]::Round((($ScanObject.VulnResults | Where-Object Status -In @('NotAFinding', 'Not_Applicable') | Measure-Object).Count / ($ScanObject.VulnResults | Measure-Object).Count * 100), 2))
        $xmlWriter.WriteEndElement() # Close 'score'

        $xmlWriter.WriteEndElement() # Close 'TestResult'
        $xmlWriter.WriteEndElement() # Close 'benchmark'
        $xmlWriter.WriteEndElement() # Close 'content'
        $xmlWriter.WriteEndElement() # Close 'report'
        $xmlWriter.WriteEndElement() # Close 'reports'

        $xmlWriter.WriteEndElement() # Close 'asset-report-collection'

        # Create Marking comment
        If ($Marking) {
            $xmlWriter.WriteComment("                                                                                          $Marking                                                                                          ")
        }

        $xmlWriter.WriteEndDocument()
        $xmlWriter.Flush()
        $xmlWriter.Close()

        Write-Log -Path $STIGLog -Message "Validating ARF File" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        $ChecklistValid = $true

        $ChecklistValid = Test-ARFXCCDFXMLValidation -XmlFile $OutputPath -SchemaPath $SchemaPath

        # Action for validation result
        If ($ChecklistValid) {
            Write-Log -Path $STIGLog -Message "'$(Split-Path $OutputPath -Leaf)' : Passed." -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        }
        Else {
            $BadFileDestination = Join-Path -Path $WorkingDir -ChildPath "Bad_CKL"
            Write-Log -Path $STIGLog -Message "ERROR: '$(Split-Path $OutputPath -Leaf)' : failed schema validation. Moving to $BadFileDestination." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
            ForEach ($Item in $ChecklistValid.Message) {
                Write-Log -Path $STIGLog -Message $Item -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
            }
            If (-Not(Test-Path $BadFileDestination)) {
                New-Item -Path $BadFileDestination -ItemType Directory | Out-Null
            }
            Copy-Item -Path $OutputPath -Destination $BadFileDestination -Force
            Remove-Item $OutputPath -Force
        }

        Return $ChecklistValid
    }
    Catch {
        Return $False
    }
}

# SIG # Begin signature block
# MIIkCwYJKoZIhvcNAQcCoIIj/DCCI/gCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA5IzGkN1zkz9tT
# 96vDAu6Z2TA+4B6VCA8zkbumQNsaDqCCHiQwggUqMIIEEqADAgECAgMTYdUwDQYJ
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
# BCCOYAdXH30cT3A0GjmnjaTyZc5PYYhdYOaR6CzM0Q7gOzANBgkqhkiG9w0BAQEF
# AASCAQB0TjPcKKdCLpRGaqYyFGhJwrs/KGABTG+GzujQ1xCq1Im47fURkuduKLpe
# cvUs/uV0xGNVEg3Em24oP5oXXk4yQy2f4WdQj3+Za1XeMqOoAzkVRHgbo5S+obVu
# QtXCX9qWWSDbi4EvTj8nzs4tqpeeO83Bc+Bl9TECFgvPkn2HGvsR4sypGk8sjm4B
# xoEedWz70jx7jCNrn2S8ER4+mhpx31A+blHatzMBilmW4o/1QPzOl2/hLPg4h/rp
# XYQp3IwBLxulFHO9giozzc4gMDsOnICDIBXMsivGT/Pa4KHgs5Vld3+OzNGyZy8T
# nku2XvoXjEaVr0rQ5hTTJ2XQTK+QoYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMP
# AgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEw
# PwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2
# IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0aDANBglghkgBZQMEAgEF
# AKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI2
# MDQyMjE2MTY1OFowLwYJKoZIhvcNAQkEMSIEIOqTS9XFfrzAh/Rgcl1bIGm82U/o
# zcVDb8j7MmuRDHANMA0GCSqGSIb3DQEBAQUABIICAMT5OKOY27qnNGhToPhfnrrA
# zHsnt17KuCt+KFhZITwqx41FeNeaEYH8UsnHyEf457HRIKiHBeij/E5tVhhLJhCr
# o1CC4i1WHxuxZHHN+ifZfjGiGinmuLTiVNs6miPi/W7jL3KNm/uV+70rGcLDyHg9
# 8QsQjriX3mWJ1oF9+xjRsDP9pEd6oQWtbr1nzyP9gnQbfBqUie1bMSWkTPBRVxpq
# 9HASURYWZdI9pQxmT58Vhp2zRkuWxaoHgUyfuSUjFvhUPE1oER7rrNOhPzeFt+4R
# oAI3TGzuqie+ZrO8UtaWwyUIyoCwNJs/HxodgABYbx1zA01Bn2BLezDC5dcanEaZ
# NWZpq09UTvqGlpuW76052DKzmPDdP+pkZJOL+A0+dBtZN7ftGnaTf+kzHXaA3Fvw
# gcqDUklD0qSzT15HVbJBAD+3UaDwxIMohSos8r1oYRrdZIMp9qyf1U8004QZuxqt
# DLzvqimB0XDdwBDJcRGzcz3Vgf+ewvVLO8hFohCDPhQ/b3vkFnnCqKlBrG9d5oYX
# 2+OR8aVW2FDsuleJ1FudAt1QHQmSm8F3S688JP4aIUkbD6RaLrxNwhAmrLoDjVef
# 8R4MO3XQxWCyQh8oC3sI+QRa/3Su7pJ5MdypzKG2ULYFzBWHQfBYTFMhvQCztbyR
# X+sxmTPDIjwBxW+qOw2G
# SIG # End signature block
