'Version: 1.2.1
'Date Modified: 08-11-2010
' 
' changelog;
' 1.2 removed the domain section much easier to just obfuscate the entire domain\user evertime
' 1.2 removed the subfolder the sophos log is added into (not required)
' 1.2.1 objFSO and wshShell set before CheckOSBit function. Fixed logging to root of c:.
' 1.3 now outputs event details to Windows Event Log.
'Developed By:
'
'Adin Sabic
'Tim Heldna
'Simon Sigré
'Gareth Hill
' Catholic Education Office South Australia
'
'Thout Shall Always Use Option Explicit!
Option Explicit
'On Error Resume Next
'
Dim objFSO, WshShell
Dim strFileSophos9AV, strFileSophos9AU, strFileSophos9RMS
Dim blnFileSophos9AV, blnFileSophos9AU, blnFileSophos9RMS, blnEventLog
Dim strFileSophos9SetupPath, strFileSophos9Flags, strFileSophosInstall
Dim strSophosServer, strSophosDomain, strSophosUser, strSophosPassword, strSophosGroup
Dim strClientString, strServerString, strOSBit
Dim blnReInstall
Dim strCID
Dim strVersion

Set objFSO = CreateObject("Scripting.FileSystemObject")
Set WshShell = WScript.CreateObject("WScript.Shell")

strVersion = "1.3"

'
' Start School Unique Settings Here
'
'Set this to true if you have changed your username and password with the Obfuscation tool
'See http://www.sophos.com/support/knowledgebase/article/13094.html for setup
'
'
'Sophos server name only (no backslashes)
strSophosServer = "sophosserver.test.domain"
'
'
strSophosUser = "BwjbCTR4tjvoTnhvs2bdQa2GzHEoTIXbViq33795BJscuQRg9xAlTSDQnBSWdW2x9cc="
strSophosPassword = "BwjRxEKGwl/yRiGGkmIKmICg/fLqDaly9bENXngxFD7gVaWvBMACATRn"
'
strSophosGroup = "Workstations"
'
'
' End School Unique Settings
'
blnReInstall = FALSE
strOSBit = CheckOSBit

strSophosGroup = "\" & strSophosServer & "\" & strSophosGroup

strFileSophos9SetupPath = "\\" & strSophosServer & "\SophosUpdate\CIDs\S000\SAVSCFXP\"

strFileSophos9Flags = "-mng yes -crt R -ouser " & strSophosUser & " -opwd " & strSophosPassword & " -G " & strSophosGroup

'Check exe exist on client
strFileSophos9AV = "C:\Program Files" & strOSBit & "\Sophos\Sophos Anti-Virus\SavMain.exe"
strFileSophos9AU = "C:\Program Files" & strOSBit & "\Sophos\AutoUpdate\ALUpdate.exe"
strFileSophos9RMS = "C:\Program Files" & strOSBit & "\Sophos\Remote Management System\AutoUpdateAgentNT.exe"
blnFileSophos9AV = objFSO.FileExists(strFileSophos9AV)
blnFileSophos9AU = objFSO.FileExists(strFileSophos9AU)
blnFileSophos9RMS = objFSO.FileExists(strFileSophos9RMS)

'Compare the mrinit.conf files on client and server for consistency 
strClientString = CheckFile("C:\Program Files" & strOSBit & "\Sophos\Remote Management System\mrinit.conf", "ParentRouterAddress")
strServerString = CheckFile("\\" & strSophosServer & "\SophosUpdate\CIDs\S000\SAVSCFXP\mrinit.conf", "ParentRouterAddress")

'Not used ATM, would be useful if there is a version that cant be upgraded via server.
'Would also be useful if we could remember why we initially started coding this too.
'If arrVersion(0) & "." & arrVersion(1) = strCID Then
'	WshShell.LogEvent 0, "Sophos Version Comparison Success."
'Else
'	blnReInstall = TRUE
'	WshShell.LogEvent 0, "Sophos Version Comparison Failure."
'End If 


'If the server String  returns empty then the file is not found on the server and do not deploy to client

If strServerString <> "" Then
	If strClientString <> strServerString  Then
		blnReInstall = TRUE
		Call WriteToLog("mrinit File Comparison Failure", 1)
	End If
Else
	Call WriteToLog ("Could not find mrinit.exe on server", 1)
End If

If blnFileSophos9AV = FALSE Then
	blnReInstall = TRUE
	Call WriteToLog ("SavMain.exe File not Found.", 1)
End If

If blnFileSophos9AU = FALSE Then
	blnReInstall = TRUE
	Call WriteToLog ("ALUpdate.exe File not Found.", 1)
End If

If blnFileSophos9RMS = FALSE Then
	blnReInstall = TRUE
	Call WriteToLog ("AutoUpdateAgentNT.exe File not Found.", 1)
End If

If blnReInstall = TRUE Then
	strFileSophosInstall = strFileSophos9SetupPath & "setup.exe " & strFileSophos9Flags

	Call WriteToLog ("Sophos Install v" + strVersion + " Started", 0)
	WshShell.Run strFileSophosInstall, 1, True
End If

Function CheckFile(strPath, strCheck)
	Dim strFileName,strLine
	Dim objFile
	Dim arrFileLines()
	Dim i

	i = 0
	If objFSO.FileExists(strPath) Then
		Set objFile = objFSO.OpenTextFile(strPath, 1)
	
		Do Until objFile.AtEndOfStream
			Redim Preserve arrFileLines(i)
     			arrFileLines(i) = objFile.ReadLine
			
			'Check for needed text passed as param
			If InStr(arrFileLines(i), strCheck) Then
				CheckFile = arrFileLines(i)
				Exit Do
			End If
     			i = i + 1
		Loop

		objFile.Close
	End If
End Function 

Sub WriteToLog(strOutput, intType)

	If blnEventLog Then
		WshShell.LogEvent intType, strOutput
	Else
		Call AddLog (strOutput, intType)
	End If

End Sub
		


Function CheckOSBit()

	blnEventLog = WshShell.LogEvent(0, "Writing to EventLog..")
	Dim OsType
	OsType = WshShell.RegRead("HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment\PROCESSOR_ARCHITECTURE")

	If (OsType = "x86") Then
		CheckOSBit = ""
		Call WriteToLog ("Sophos Install Script Initiated for X86", 0)
	Else
		CheckOSBit = " (x86)"
		Call WriteToLog ("Sophos Install Script Initiated for x64 bit Windows.", 0)
	End if
End Function

Sub CheckSophosVersion
	Dim strVersion
	strVersion =  objFSO.GetFileVersion("C:\Program Files" & CheckOSBit & "\Sophos\Sophos Anti-Virus\SavMain.exe")

	Dim arrVersion
	Dim tempStr

	arrVersion = Split(strVersion, ".",3)

	Dim i

	wscript.echo arrVersion(0) & "." & arrVersion(1)

End Sub

Sub AddLog(strTextToAdd, intType)
	Dim objFolder, objFile, objFileOpen
	Dim strFolder, strFile, strErrType
	Dim strComputerName, strComputerIP
	Const ForAppending = 8

	strFolder="c:"
	strFile = "sophosscriptedinstall.log"

	If NOT objFSO.FileExists(strFolder & "\" & strFile) Then
		Set objFile = objFSO.CreateTextFile(strFolder & "\" & strFile)
		objFIle.Close
	End If


	strComputerName = wshShell.ExpandEnvironmentStrings( "%COMPUTERNAME%" )


	Set objFileOpen = objFSO.OpenTextFile(strFolder & "\" & strFile, ForAppending, True)

	If intType=1 Then
		strErrType = "Error: "
	Else
		strErrType = "Message: "
	End If

	objFileOpen.WriteLine(strErrType & strTextToAdd & " " & " : " & strComputerName & " : " & NOW() )
	objFileOpen.Close

	set objFolder = nothing
	set objFile = nothing
	set objFileOpen = nothing
End Sub

