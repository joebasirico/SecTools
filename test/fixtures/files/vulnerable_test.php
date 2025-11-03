<?php
// Test file with intentional security vulnerabilities
// This file is used to test the Code Security Scanner tool

// SQL Injection vulnerabilities
function searchUsers($userId) {
    // VULN: Variable interpolation in mysql_query
    $query = "SELECT * FROM users WHERE id = $userId";
    mysql_query($query);

    // VULN: Variable interpolation in mysqli_query
    mysqli_query($conn, "SELECT * FROM users WHERE name = $username");
}

// XSS vulnerabilities
function displayContent() {
    // VULN: Echo user input without escaping
    echo $_GET["content"];

    // VULN: Print user input without escaping
    print $_POST["html"];

    // VULN: Echo from cookie
    echo $_COOKIE["data"];
}

// Command Injection vulnerabilities
function executeCommand($directory) {
    // VULN: Variable in exec()
    exec("ls " . $directory);

    // VULN: Variable in shell_exec()
    shell_exec("cat " . $filename);

    // VULN: Variable in system()
    system("rm " . $file);
}

// Path Traversal
function readFile() {
    // VULN: Opening file from user input
    $handle = fopen($_GET["file"], "r");

    // VULN: Include file from user input
    include($_GET["page"]);

    // VULN: Require file from POST
    require($_POST["template"]);
}

// Hardcoded Secrets
// VULN: Hardcoded credentials
$api_key = "sk_live_1234567890";
$password = "admin123";
$db_password = "secretpass";

// Weak Cryptography
function hashPassword($password) {
    // VULN: Using MD5
    $hash = md5($password);

    // VULN: Using SHA1
    $digest = sha1($data);

    // VULN: Using deprecated mcrypt
    $encrypted = mcrypt_encrypt(MCRYPT_DES, $key, $data, MCRYPT_MODE_ECB);
}

// Insecure Deserialization
function loadData() {
    // VULN: Unsafe unserialize with user input
    $data = unserialize($_GET["data"]);

    // VULN: unserialize from POST
    $obj = unserialize($_POST["object"]);
}

// Open Redirect
function redirectUser() {
    // VULN: Redirect to user input
    header("Location: " . $_GET["url"]);
}
?>
