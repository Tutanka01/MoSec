<?php
// BENCHMARK CASE: False Positive — PHP SQLi prevented by PDO prepared statement
// CWE-89 | Source: $_GET | Sink: PDO::query — SAFE (parameterized)
$pdo = new PDO("mysql:host=localhost;dbname=mydb", "root", "");
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

function get_user_safe(PDO $pdo): array {
    $id = $_GET['id'] ?? '0';
    // Properly parameterized — NOT injectable
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->execute([$id]);
    return $stmt->fetch(PDO::FETCH_ASSOC) ?: [];
}

$user = get_user_safe($pdo);
echo htmlspecialchars($user['name'] ?? '');
