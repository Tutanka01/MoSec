<?php
// BENCHMARK CASE: True Positive — PHP Command Injection via shell_exec
// CWE-78 | Source: $_GET | Sink: shell_exec
function ping_host() {
    $host = $_GET['host'];
    // Unsanitized user input passed directly to shell command
    $output = shell_exec("ping -c 4 " . $host);
    echo "<pre>$output</pre>";
}

ping_host();
