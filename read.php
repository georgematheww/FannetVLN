<?php
// read.php - intentionally vulnerable for lab ONLY
if (!isset($_GET['file'])) {
    echo "Usage: read.php?file=<path>";
    exit;
}

$file = $_GET['file'];             // <--- user-controlled, no validation

$content = @file_get_contents($file);  // <--- direct filesystem read

if ($content === false) {
    echo "Could not open file: " . htmlspecialchars($file);
} else {
    echo "<pre>" . htmlspecialchars($content) . "</pre>";
}
?>
