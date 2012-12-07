'//Quick and dirty script to archive/delete old RADIUS accounting logs to prevent server space issues. Designed to be run as scheduled task daily.
'//Functions WindowsZip, NewZip provided under the Creative Commons license located http://creativecommons.org/licenses/by-nc/2.5/ by NateRice.com.

Dim arrLogFiles()
strTodaysLog = "IN" & right(year(date()),2) & right("0" & month(date()),2) & right("0" & day(date()),2) & ".log"

Set objFSO = CreateObject("Scripting.FileSystemObject")
objLogFolder = "C:\Windows\System32\LogFiles\npsaccounting" '//set this to where RADIUS accounting logs are stored

Set objFolder = objFSO.GetFolder(objLogFolder)

Set colFiles = objFolder.Files

i = 0

For Each objFile in colFiles
	If UCase(objFSO.GetExtensionName(objFile.name)) = "LOG" Then
		If Not objFile.Name = strTodaysLog Then
        		Redim Preserve arrLogFiles(i)
			arrLogFiles(i) = objStartFolder & "\" & objFile.Name
			i = i + 1
		End If
    	End If
Next

For Each logFile in arrLogFiles
	WindowsZip logFile, "C:\Windows\System32\LogFiles\npsaccounting\logarchive.zip"
	objFSO.DeleteFile logFile
Next


Function WindowsZip(sFile, sZipFile)

	Set oZipShell = CreateObject("WScript.Shell")  
  	Set oZipFSO = CreateObject("Scripting.FileSystemObject")
  
  	If Not oZipFSO.FileExists(sZipFile) Then
    		NewZip(sZipFile)
  	End If

  	Set oZipApp = CreateObject("Shell.Application")
  
  	sZipFileCount = oZipApp.NameSpace(sZipFile).items.Count

  	aFileName = Split(sFile, "\")
  	sFileName = (aFileName(Ubound(aFileName)))
  
  	'listfiles
  	sDupe = False
  	For Each sFileNameInZip In oZipApp.NameSpace(sZipFile).items
    		If LCase(sFileName) = LCase(sFileNameInZip) Then
      			sDupe = True
      			Exit For
    		End If
  	Next
  
  	If Not sDupe Then
    		oZipApp.NameSpace(sZipFile).Copyhere sFile

    		'Keep script waiting until Compressing is done
    		On Error Resume Next
    		sLoop = 0
    		Do Until sZipFileCount < oZipApp.NameSpace(sZipFile).Items.Count
      			Wscript.Sleep(100)
      			sLoop = sLoop + 1
    		Loop
    		On Error GoTo 0
  	End If
End Function

Sub NewZip(sNewZip)

  	Set oNewZipFSO = CreateObject("Scripting.FileSystemObject")
  	Set oNewZipFile = oNewZipFSO.CreateTextFile(sNewZip)
    
  	oNewZipFile.Write Chr(80) & Chr(75) & Chr(5) & Chr(6) & String(18, 0)
  
  	oNewZipFile.Close
  	Set oNewZipFSO = Nothing

  	Wscript.Sleep(500)
End Sub
