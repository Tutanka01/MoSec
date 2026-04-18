<?php
// BENCHMARK CASE: True Positive — PHP XSS via unescaped echo
// CWE-79 | Source: $_GET | Sink: echo
function greet() {
    $name = $_GET['name'] ?? 'World';
    // Unsanitized user input echoed directly into HTML response — XSS
    echo "<h1>Hello, $name!</h1>";
}

greet();
