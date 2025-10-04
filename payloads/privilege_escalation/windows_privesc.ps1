# Windows Privilege Escalation Script
# Safe privilege escalation enumeration for authorized testing

Write-Host "=== Windows Privilege Escalation Enumeration ===" -ForegroundColor Green
Write-Host "Date: $(Get-Date)" -ForegroundColor Yellow
Write-Host "User: $env:USERNAME" -ForegroundColor Yellow
Write-Host "Domain: $env:USERDOMAIN" -ForegroundColor Yellow
Write-Host "Computer: $env:COMPUTERNAME" -ForegroundColor Yellow
Write-Host ""

Write-Host "=== System Information ===" -ForegroundColor Green
Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, TotalPhysicalMemory
Write-Host ""

Write-Host "=== User Information ===" -ForegroundColor Green
whoami /all
Write-Host ""

Write-Host "=== Local Users ===" -ForegroundColor Green
Get-LocalUser | Select-Object Name, Enabled, LastLogon
Write-Host ""

Write-Host "=== Local Groups ===" -ForegroundColor Green
Get-LocalGroup | Select-Object Name, Description
Write-Host ""

Write-Host "=== Group Memberships ===" -ForegroundColor Green
Get-LocalGroupMember -Group "Administrators" | Select-Object Name, ObjectClass
Write-Host ""

Write-Host "=== Running Processes ===" -ForegroundColor Green
Get-Process | Select-Object Name, Id, CPU, WorkingSet | Sort-Object CPU -Descending | Select-Object -First 20
Write-Host ""

Write-Host "=== Services ===" -ForegroundColor Green
Get-Service | Where-Object {$_.Status -eq "Running"} | Select-Object Name, Status, StartType | Select-Object -First 20
Write-Host ""

Write-Host "=== Network Connections ===" -ForegroundColor Green
Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State | Select-Object -First 20
Write-Host ""

Write-Host "=== Installed Software ===" -ForegroundColor Green
Get-WmiObject -Class Win32_Product | Select-Object Name, Version | Select-Object -First 20
Write-Host ""

Write-Host "=== Hotfixes ===" -ForegroundColor Green
Get-HotFix | Select-Object HotFixID, InstalledOn | Select-Object -First 20
Write-Host ""

Write-Host "=== Environment Variables ===" -ForegroundColor Green
Get-ChildItem Env: | Select-Object Name, Value | Where-Object {$_.Name -match "(PATH|TEMP|TMP|USERPROFILE)"}
Write-Host ""

Write-Host "=== Registry Information ===" -ForegroundColor Green
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" | Select-Object *
Write-Host ""

Write-Host "=== Scheduled Tasks ===" -ForegroundColor Green
Get-ScheduledTask | Where-Object {$_.State -eq "Running"} | Select-Object TaskName, State
Write-Host ""

Write-Host "=== WMI Information ===" -ForegroundColor Green
Get-WmiObject -Class Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber
Write-Host ""

Write-Host "=== Disk Information ===" -ForegroundColor Green
Get-WmiObject -Class Win32_LogicalDisk | Select-Object DeviceID, Size, FreeSpace
Write-Host ""

Write-Host "=== Network Adapters ===" -ForegroundColor Green
Get-NetAdapter | Select-Object Name, InterfaceDescription, Status
Write-Host ""

Write-Host "=== Firewall Rules ===" -ForegroundColor Green
Get-NetFirewallRule | Select-Object DisplayName, Direction, Action | Select-Object -First 20
Write-Host ""

Write-Host "=== Event Logs ===" -ForegroundColor Green
Get-EventLog -LogName Security -Newest 10 | Select-Object TimeGenerated, EntryType, Message
Write-Host ""

Write-Host "=== Privilege Escalation Check Complete ===" -ForegroundColor Green
