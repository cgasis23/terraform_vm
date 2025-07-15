' Log.vbs - Fetch AWS credentials at runtime using Node.js

Set objShell = CreateObject("WScript.Shell")
Set objExec = objShell.Exec("""C:\Program Files\nodejs\node.exe"" ""C:\DSC\scripts\getCredentials.js"" win_srv_2022-user-credentials-test")

secretJson = ""
Do While Not objExec.StdOut.AtEndOfStream
    secretJson = secretJson & objExec.StdOut.ReadLine()
Loop

' Parse username and password from Node.js output: Retrieved credentials: { username: 'cgasis', password: 'Test123$' }
Set re = New RegExp
re.Pattern = "username: '([^']+)'"
re.Global = True
Set matches = re.Execute(secretJson)

If matches.Count > 0 Then
    username = matches(0).SubMatches(0)
Else
    username = ""
End If

re.Pattern = "password: '([^']+)'"
Set matches = re.Execute(secretJson)
If matches.Count > 0 Then
    password = matches(0).SubMatches(0)
Else
    password = ""
End If

' Example: Write credentials to a log file (for demonstration only, do not log real credentials in production!)
Set fso = CreateObject("Scripting.FileSystemObject")
Set logFile = fso.OpenTextFile("C:\logs\hello_world_vb.log", 8, True)
logFile.WriteLine "Username: " & username
logFile.WriteLine "Password: " & password
logFile.Close

' Now you can use the username and password variables in your VBS logic
