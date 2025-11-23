<?php
// secure_read.php - example safe approach
$allowed = [
    'about' => __DIR__ . '/about.html',
    'config' => __DIR__ . '/config.php', // probably you wouldn't serve config but example only
];

if (!isset($_GET['file']) || !array_key_exists($_GET['file'], $allowed)) {
    echo "Invalid file.";
    exit;
}
$path = $allowed[$_GET['file']];
echo "<pre>" . htmlspecialchars(file_get_contents($path)) . "</pre>";
?>
