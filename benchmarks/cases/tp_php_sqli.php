<?php
// BENCHMARK CASE: True Positive — PHP SQLi via direct $_GET interpolation
// CWE-89 | Source: $_GET | Sink: mysqli_query
$conn = mysqli_connect("localhost", "root", "", "mydb");

function get_user() {
    global $conn;
    $id = $_GET['id'];
    // Unsanitized user input directly interpolated into SQL query
    $result = mysqli_query($conn, "SELECT * FROM users WHERE id = $id");
    return mysqli_fetch_assoc($result);
}

$user = get_user();
echo $user['name'];
