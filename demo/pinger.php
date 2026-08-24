<?php
// Demo data for PHP Shell Injection Companion — used with
// `./gradlew runIde` to capture the real Marketplace screenshot. Open
// this file, the warning should appear on the exec() line inside
// ping_host.

function ping_host($host) {
    // Interpolated command string -- FLAGGED.
    exec("ping -c 1 $host");
}

function ping_host_safely($host) {
    // Escaped via escapeshellarg -- NOT flagged (no raw interpolation
    // in the outer string, the concatenation right operand is the
    // sanitized value, still a real improvement worth doing).
    exec("ping -c 1 " . escapeshellarg($host));
}
