' Copyright (c) 2011 Palo Alto Networks, Inc. <info@paloaltonetworks.com>
'
' Permission to use, copy, modify, and distribute this software for any
' purpose with or without fee is hereby granted, provided that the above
' copyright notice and this permission notice appear in all copies.

' Alterations to use RADIUS accounting logs/DHCP leases over Kiwi/syslog 
' v5.1
' Gareth Hill


' Changelog:

' v5.1 
'	* Agentless support

' v5.0
'	* DHCP stuff added

' v4.7
'	* Now passes username from Windows Event to script to allow for more precision - requires the scheduled task to be created with further criteria.
'	* Added a flag that allows script to be recursively called to account for possible latency between the log write and windows event; this is experimental and should NOT be enabled by default.

' v4.5
'	* Here there be dragons
'	* Added optimisation to attempt to reduce runtime, at the cost of more system resources; may seperate into flag, likely will be scrapped

' v4.0
'	* Added support for configuration XML File
'	* IAS log compatibility improved; variable set in configuration file
'	* Seperated DTS/IAS into seperate functions
'	* Possible debug flag in config file for future release?

' v3.0
'	* Added IAS log compatibility

' v2.2
'	* Fixed issue with mm/dd/yyyy date format in nps logs; only captures time now

' V2.1
'	* Added support for ignore-user-list

' v2.0
'	* Optimised to process last 500 events only
'	* Removed timestamp-based logic - if only reading last 500 events, not required, simplifies regex, improves efficiency
'	* Removed tail functionality - inefficent

' Known Issues:
'	* RESOLVED 08/08/12 (bug in UID Agent, not present in v4.15-1) Timeouts: Not "refreshing" user-sessions, will timeout in x mins (needs to re-auth to refresh), need to observe event information that will allow refresh (or modify timeout on WLC)
'	* Sanitisation of users in format user@FQDN currently not supported; to be implemented in next stable release

'
' Script to read a log upon Microsoft's RADIUS service authenticating against a site's AD, and pass the username/IP to the Palo-Alto User-Agent
' Requires: * NPS accounting set to create new logs daily, in DTS Compliant format (this affects log naming convention)
'           * Ensure RADIUS accounting information is being sent from the WLC to the school's RADIUS server
'           * The server running the User-Agent must have IP connectivity
'           * The User-Agent must have the User-ID XML API enabled
'	    * As a convention, this script should be stored in %domainname%\scripts\
'	    * The script needs to be configured to trigger on Windows Event ID 6272
'	    * The User-ID timeout in the Agent needs to be less than the Session timeout on the WLC
'	    * Trigger task must be run as the cesanetcf_sync account to prevent functionality breaking 
' 

'//
'//Declaring site-agnostic variables
'//
set xmlHttp = CreateObject("MSXML2.ServerXMLHTTP")
Set objFSO = CreateObject("Scripting.FileSystemObject")
Const SXH_SERVER_CERT_IGNORE_ALL_SERVER_ERRORS = 13056
ptrn = "<Timestamp data_type=\S4\S>.+(\d\d:\d\d:\d\d)\.\d+</Timestamp>.*<User-Name data_type=\S1\S>(.+)</User-Name>.*<Framed-IP-Address data_type=\S3\S>(\d+\.\d+\.\d+\.\d+)</Framed-IP-Address>.*<Acct-Authentic data_type=\S0\S>[^3]</Acct-Authentic>.*<Client-IP-Address data_type=\S3\S>(\d+\.\d+\.\d+\.\d+)" '//Regex Pattern to match in the logs, for NPS
ptrnDHCP= "<Timestamp data_type=\S4\S>.+(\d\d:\d\d:\d\d)\.\d+</Timestamp>.*<User-Name data_type=\S1\S>(.+)</User-Name>.*<Calling-Station-Id data_type=\S1\S>(.+)</Calling-Station-Id>"
strFileName = "IN" & right(year(date()),2) & right("0" & month(date()),2) & right("0" & day(date()),2) & ".log" '//The log name for the date in question
Dim arrExclusions(), aClientIPS()
Dim strDomain, strLogPath, strLogFormat, strAgentServer, strAgentPort, strDHCPServer, strVsys, blnAgent, strAPIKey, strTimeout
Set xmlDoc = CreateObject("Microsoft.XMLDOM")
xmlDoc.Async = "False"
xmlDoc.Load("C:\Program Files (x86)\Palo Alto Networks\User-ID Agent\UIDConfig.xml")
strEventUser = wscript.arguments.item(0)
strCallingStation = wscript.arguments.item(1)

'//
'//Site specific variables
'//
LoadConfig

'//
'//Load the exclusions
'//
LoadExclusions("C:\Program Files (x86)\Palo Alto Networks\User-ID Agent\ignore_user_list.txt")

If strLogFormat="DTS" Then
	'//
	'//Variables used to narrow the range of lines processed
	'//
	intLength = LogLength(strLogPath & strFileName) '//The current length of the log file.
	intLineCounter = 0

	Set objFile = objFSO.OpenTextFile(strLogPath & strFileName) '//Open the log
	ProcessDTSLog
	objFile.Close '//close off the file
ElseIf strLogFormat="IAS" Then
	'//
	'//Variables used to narrow the range of lines processed
	'//
	intLength = LogLength(strLogPath & strFileName) '//The current length of the log file.
	intLineCounter = 0

	Set objFile = objFSO.OpenTextFile(strLogPath & strFileName) '//Open the log
	ProcessIASLog
	objFile.Close '//close off the file
ElseIf strLogFormat="DHCP" Then
	ProcessDHCPClients
End If

'//
'//Takes an XML string, opens a connection to User-Agent, sends XML, closes connection
'//
Function PostToAgent(strUserAgentData)
	On Error Resume Next
	If blnAgent = 1 Then
		sUrl = "https://" & strAgentServer & ":" & strAgentPort & "/"
		xmlHttp.open "put", sUrl, False
	Else
		sUrl = "https://filter.cesa.catholic.edu.au/api/?key=" & strAPIKey & "&type=user-id&action=set&vsys=" & strVsys & "&client=wget&file-name=UID.xml"
		xmlHttp.open "post", sUrl, False
	End If
	xmlHttp.setRequestHeader "Content-type", "text/xml"
	xmlHttp.setOption 2, 13056
	xmlHttp.send(strUserAgentData)
	xmlHttp.close
End Function

'//
'//Reads in a file, returns the number of lines within it
'//
Function LogLength(strPath)
	LogLength = 0
	Set objLog = objFSO.OpenTextFile(strPath)
	Do Until objLog.AtEndofStream 
		objLog.SkipLine
		LogLength = LogLength + 1
	Loop
	objLog.Close
End Function

Function LoadExclusions(strExcPath)
	ExcLength = 0
	Set objExc = objFSO.OpenTextFile(strExcPath)
	Do Until objExc.AtEndofStream 
		Redim Preserve arrExclusions(ExcLength)
		arrExclusions(ExcLength) = Trim(objExc.readLine)
		ExcLength = ExcLength + 1
	Loop
	objExc.Close
End Function

Function ProcessDTSLog
	'//
	'// Create the regular expression.
	'//
	Set re = New RegExp
	re.Pattern = ptrn
	re.IgnoreCase = False
	re.Global = True

	On Error Resume Next

	'//
	'//Parses the log, inspects the data associated with each event, validates, generates XML string, passes to UID
	'// 
	Do Until objFile.AtEndofStream 

		If intLineCounter >= (intLength - 500) Then '//only deal with the last 500 lines (this number can be tweaked to needs)
			strLog = objFile.ReadLine() '//read a line from the file

			Set Matches = re.Execute(strLog) '//Perform the search

			If Matches.Count > 0 Then '//Tests the pattern is matched.
				set oMatch = Matches(0)
				strTimestamp = oMatch.subMatches(0)
				strUser = oMatch.subMatches(1)
				strAddress = oMatch.subMatches(2)
				strClientIP = oMatch.subMatches(3)

				If InStr(strUser, "\") > 0 Then '//Check if domain is appended to User-Name, if so, remove for consistentcy
					strUser = Right(strUser, ((Len(strUser))-(InStr(strUser, "\"))))
				End If

				If InStr(strEventUser, "\") > 0 Then
					strEventUser = Right(strEventUser, ((Len(strEventUser))-(InStr(strEventUser, "\"))))
				End If

				If strUser = strEventUser Then

					If UBound(Filter(arrExclusions, strUser, True, 1)) <= -1 Then
						'//If DateDiff("n",FormatDateTime(strTimestamp),Time) <= 2 Then '//In case the radius accounting doesn't see many events, only load within 5 mins of the trigger.
							If UBound(Filter(aClientIPs, strClientIP, True, 0)) > -1 Then '//Only deal with events from WLCs defined above

								If InStr(strUser, "host/") = 0 Then '//Filter these events as they aren't required.

									'// Build the XML message
									strXMLLine = "<uid-message><version>1.0</version><type>update</type><payload><login>"
									If blnAgent = 1 Then
										strXMLLine = strXMLLine & "<entry name=""" & strDomain & "\" & strUser & """ ip=""" & strAddress & """/>"
									Else
										strXMLLine = strXMLLine & "<entry name=""" & strDomain & "\" & strUser & """ ip=""" & strAddress & """ timeout=""20""/>"
									End If
									strXMLLine = strXMLLine & "</login></payload></uid-message>"

									PostToAgent(strXMLLine) '//Send the relevant UID details to User-Agent
								End If
							End If
						'//End If
					End If
				End If
			End If
		Else '//If the line being processed is not one of the last 500, skip it
			objFile.SkipLine
			intLineCounter = intLineCounter + 1 '//increment the counter
		End If
	Loop
End Function

Function ProcessIASLog
	'//
	'//Parses the log, inspects the data associated with each event, validates, generates XML string, passes to UID
	'// 

	On Error Resume Next

	Do Until objFile.AtEndofStream 

		If intLineCounter >= (intLength - 500) Then '//only deal with the last 500 lines (this number can be tweaked to needs)
			strLog = objFile.ReadLine() '//read a line from the file

			arrIASAttributes = Split(strLog, ",")

			strNotSureWhatThisIs = arrIASAttributes(6)
			strAcctAuth = arrIASAttributes(19)

			If strNotSureWhatThisIs = "5" Then
				If strAcctAuth<>"3" Then
					strTimestamp = arrIASAttributes(3)
					strUser = arrIASAttributes(1)
					strAddress = arrIASAttributes(11)
					strClientIP = arrIASAttributes(9)

					If InStr(strUser, "\") > 0 Then '//Check if domain is appended to User-Name, if so, remove for consistentcy
						strUser = Right(strUser, ((Len(strUser))-(InStr(strUser, "\"))))
					End If

					If InStr(strEventUser, "\") > 0 Then
						strEventUser = Right(strEventUser, ((Len(strEventUser))-(InStr(strEventUser, "\"))))
					End If

					If strUser = strEventUser Then

						If UBound(Filter(arrExclusions, strUser, True, 1)) <= -1 Then
							'//If DateDiff("n",FormatDateTime(strTimestamp),Time) <= 2 Then '//In case the radius accounting doesn't see many events, only load within 5 mins of the trigger.
								If UBound(Filter(aClientIPs, strClientIP, True, 0)) > -1 Then '//Only deal with events from WLCs defined above

									If InStr(strUser, "host/") = 0 Then '//Filter these events as they aren't required.

										'// Build the XML message
										strXMLLine = "<uid-message><version>1.0</version><type>update</type><payload><login>"
										If blnAgent = 1 Then
											strXMLLine = strXMLLine & "<entry name=""" & strDomain & "\" & strUser & """ ip=""" & strAddress & """/>"
										Else
											strXMLLine = strXMLLine & "<entry name=""" & strDomain & "\" & strUser & """ ip=""" & strAddress & """ timeout=""20""/>"
										End If
										strXMLLine = strXMLLine & "</login></payload></uid-message>"

										PostToAgent(strXMLLine) '//Send the relevant UID details to User-Agent
									End If
								End If
							'//End If
						End If
					End If
				End If
			End If
		Else '//If the line being processed is not one of the last 500, skip it
			objFile.SkipLine
			intLineCounter = intLineCounter + 1 '//increment the counter
		End If
	Loop
End Function

Function ProcessDHCPClients
	On Error Resume Next

	If InStr(strEventUser, "\") > 0 Then
		strEventUser = Right(strEventUser, ((Len(strEventUser))-(InStr(strEventUser, "\"))))
	End If

	If InStr(strEventUser, "$") = 0 Then

		If InStr(strEventUser, "host/") = 0 Then '//Filter these events as they aren't required.

			Set oRe=New RegExp
			oRe.Global=True
			oRe.Pattern= "\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
			Set o=oRe.Execute(strCallingStation)

			If o.count=1 Then
				strAddress = strCallingStation
			Else

				Set oRe=New RegExp 
				Set oShell = CreateObject("WScript.Shell") 
  
				oRe.Global=True

				oRe.Pattern= "\s(\d+\.\d+\.\d+\.\d+)\s*-\s\d+\.\d+\.\d+\.\d+\s*-Active"
				Set oScriptExec = oShell.Exec("netsh dhcp server \\" & strDHCPServer & " show scope") 
				Set o=oRe.Execute(oScriptExec.StdOut.ReadAll) 
				For i=0 To o.Count-1
 					Redim Preserve arrScopes(i)
 					arrScopes(i) = o(i).SubMatches(0)
				Next
				CleanMac strCallingStation

				strAddress = "Fail"

				For Each scope in arrScopes

					If strAddress = "Fail" Then
    						strAddress = FindMac(scope, strCallingStation)
					End If
				Next
			End If

			If strAddress <> "Fail" Then

				'// Build the XML message
				strXMLLine = "<uid-message><version>1.0</version><type>update</type><payload><login>"
				If blnAgent = 1 Then
					strXMLLine = strXMLLine & "<entry name=""" & strDomain & "\" & strEventUser & """ ip=""" & strAddress & """/>"
				Else
					strXMLLine = strXMLLine & "<entry name=""" & strDomain & "\" & strEventUser & """ ip=""" & strAddress & """ timeout=""20""/>"
				End If
				strXMLLine = strXMLLine & "</login></payload></uid-message>"

				PostToAgent(strXMLLine) '//Send the relevant UID details to User-Agent

			End If
		End If
	End If
End Function

Function LoadConfig
	strQuery = "/user-id-script-config/wireless-lan-controllers/wlc"
	Set colItem = xmlDoc.selectNodes(strQuery)
	count = 0
	For Each objItem in colItem
		Redim Preserve aClientIPs(count)
		aClientIPs(count) = objItem.text
		count = count + 1
	Next
	strQuery = "/user-id-script-config/domain"
	Set objItem = xmlDoc.selectSingleNode(strQuery)
	strDomain = objItem.text
	strQuery = "/user-id-script-config/LogPath"
	Set objItem = xmlDoc.selectSingleNode(strQuery)
	strLogPath = objItem.text
	strQuery = "/user-id-script-config/AgentServer"
	Set objItem = xmlDoc.selectSingleNode(strQuery)
	strAgentServer = objItem.text
	strQuery = "/user-id-script-config/AgentPort"
	Set objItem = xmlDoc.selectSingleNode(strQuery)
	strAgentPort = objItem.text
	strQuery = "/user-id-script-config/LogFormat"
	Set objItem = xmlDoc.selectSingleNode(strQuery)
	strLogFormat = objItem.text
	strQuery = "/user-id-script-config/DHCPServer"
	Set objItem = xmlDoc.selectSingleNode(strQuery)
	strDHCPServer = objItem.text
	strQuery = "/user-id-script-config/VSYS"
	Set objItem = xmlDoc.selectSingleNode(strQuery)
	strVsys = objItem.text
	strQuery = "/user-id-script-config/Key"
	Set objItem = xmlDoc.selectSingleNode(strQuery)
	strAPIKey = objItem.text
	strQuery = "/user-id-script-config/Agent"
	Set objItem = xmlDoc.selectSingleNode(strQuery)
	blnAgent = objItem.text
	strQuery = "/user-id-script-config/Timeout"
	Set objItem = xmlDoc.selectSingleNode(strQuery)
	strTimeout = objItem.text
	count = 0
End Function

Function FindMac(strScope, strMac)
	strIP = ""
	Set oShell = CreateObject("WScript.Shell") 
	Set oRe2=New RegExp
	oRe2.Global=True
	oRe2.Pattern= "(\d+\.\d+\.\d+\.\d+)\s*-\s\d+\.\d+\.\d+\.\d+\s*-\s*(([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}))"
	Set oScriptExec = oShell.Exec("netsh dhcp server \\" & strDHCPServer & " scope " & strScope & " show clients")
      	Do Until oScriptExec.StdOut.AtEndOfStream  
    		strTemp = oScriptExec.StdOut.ReadLine 
		set p = oRe2.Execute(strTemp)
		If p.Count > 0 Then
			strMacComp = p(0).SubMatches(1)
			CleanMac strMacComp
			If strMac = strMacComp Then
                        	strIP = p(0).SubMatches(0)
				Exit Do
			End If
		End If
      	Loop
	If strIP <> "" Then
		FindMac=strIP
	Else 
		FindMac="Fail"
	End If
End Function

Function CleanMac(strMac)
	strMac = Replace(strMac, "-", "")
	strMac = Replace(strMac, ".", "")
	strMac = Replace(strMac, ":", "")
	strMac = LCase(strMac)
End Function
