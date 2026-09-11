<?php

declare(strict_types=1);

$capturesDir = realpath(__DIR__ . '/../captures');
$requested = basename((string) ($_GET['file'] ?? ''));

if ($capturesDir === false || $requested === '' || !str_ends_with($requested, '.pcap')) {
    http_response_code(400);
    exit('Invalid request');
}

$fullPath = realpath($capturesDir . '/' . $requested);

if ($fullPath === false || dirname($fullPath) !== $capturesDir) {
    http_response_code(404);
    exit('File not found');
}

header('Content-Type: application/vnd.tcpdump.pcap');
header('Content-Disposition: attachment; filename="' . $requested . '"');
header('Content-Length: ' . filesize($fullPath));
readfile($fullPath);
