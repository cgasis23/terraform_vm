' LogHelloWorld.vbs
' Logs a Hello World message with timestamp, username, and password to C:\logs\hello_world.log

Option Explicit

Dim fso, logDir, logFile, logMessage, ts, shell, dateTime
Dim username, password

Set fso = CreateObject("Scripting.FileSystemObject")
Set shell = CreateObject("WScript.Shell")

logDir = "C:\\logs"
logFile = logDir & "\\hello_world.log"

' Get username and password from arguments
If WScript.Arguments.Count > 1 Then
    username = WScript.Arguments(0)
    password = WScript.Arguments(1)
Else
    username = "(no username)"
    password = "(no password)"
End If

' Ensure log directory exists
If Not fso.FolderExists(logDir) Then
    fso.CreateFolder logDir
End If

' Get current timestamp in ISO format
Dim dt, isoDate
dt = Now
isoDate = Year(dt) & "-" & Right("0" & Month(dt),2) & "-" & Right("0" & Day(dt),2) & _
    "T" & Right("0" & Hour(dt),2) & ":" & Right("0" & Minute(dt),2) & ":" & Right("0" & Second(dt),2)

logMessage = "VBS: " & isoDate & ": Hello World! Username: " & username & ", Password: " & password & vbCrLf

' Append log message to file
Set ts = fso.OpenTextFile(logFile, 8, True) ' 8 = ForAppending, True = create if not exists
ts.Write logMessage
ts.Close

WScript.Echo "Log entry written successfully to " & logFile 