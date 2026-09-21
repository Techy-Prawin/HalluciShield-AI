<?php
// ============================================================
// EDUCATIONAL DEMO ONLY — DO NOT USE IN PRODUCTION
// This file deliberately contains a SQL injection vulnerability
// so it can be studied, tested against, and used to learn how
// to write the SAFE version instead.
// ============================================================

$conn = new mysqli("localhost", "demo_user", "demo_pass", "demo_db");

$username = $_POST['username'];
$password = $_POST['password'];

// --- VULNERABLE: user input concatenated directly into SQL ---
$query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
$result = $conn->query($query);

// Because the input isn't escaped or parameterized, an attacker can
// submit a username like:
//     admin' -- 
// which turns the query into:
//     SELECT * FROM users WHERE username = 'admin' -- ' AND password = '...'
// The "--" comments out the password check, logging in as admin
// without knowing the password. Other payloads (UNION SELECT, etc.)
// can extract arbitrary data from the database.

if ($result && $result->num_rows > 0) {
    echo "Login successful!";
} else {
    echo "Invalid credentials.";
}

// ============================================================
// THE FIX: use a parameterized query / prepared statement.
// Uncomment and use this instead of the code above:
// ============================================================
/*
$stmt = $conn->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->bind_param("ss", $username, $password);
$stmt->execute();
$result = $stmt->get_result();

if ($result && $result->num_rows > 0) {
    echo "Login successful!";
} else {
    echo "Invalid credentials.";
}
*/

// Additional hardening for real systems:
// - Never store plaintext passwords — use password_hash()/password_verify()
// - Apply least-privilege DB accounts
// - Add input validation and rate limiting on login attempts
?>
