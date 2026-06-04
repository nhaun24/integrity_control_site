<?php
declare(strict_types=1);

session_start();

const DATA_DIR = __DIR__ . '/../var/data';
const AUTH_FILE = DATA_DIR . '/auth.json';

function load_config(): array
{
    $defaults = require __DIR__ . '/config.example.php';
    $localPath = __DIR__ . '/config.php';
    if (is_file($localPath)) {
        $local = require $localPath;
        if (is_array($local)) {
            $defaults = array_replace($defaults, $local);
        }
    }
    return $defaults;
}

function configured_password_hash(array $config): ?string
{
    $fromEnv = getenv((string)($config['password_hash_env'] ?? 'CONTROL_SITE_PASSWORD_HASH'));
    if (is_string($fromEnv) && $fromEnv !== '') {
        return $fromEnv;
    }
    if (is_file(AUTH_FILE)) {
        $payload = json_decode((string)file_get_contents(AUTH_FILE), true);
        return is_array($payload) && is_string($payload['password_hash'] ?? null) ? $payload['password_hash'] : null;
    }
    return null;
}

function deny(): never
{
    http_response_code(403);
    echo 'Forbidden';
    exit;
}

function detected_mime_type(string $path): string
{
    $extensionMime = match (strtolower(pathinfo($path, PATHINFO_EXTENSION))) {
        'jpg', 'jpeg' => 'image/jpeg',
        'png' => 'image/png',
        'gif' => 'image/gif',
        'webp' => 'image/webp',
        'svg' => 'image/svg+xml',
        default => null,
    };

    if ($extensionMime === 'image/svg+xml') {
        return $extensionMime;
    }

    if (function_exists('mime_content_type')) {
        $mime = mime_content_type($path);
        if (is_string($mime) && $mime !== '') {
            return $mime;
        }
    }

    return $extensionMime ?? 'application/octet-stream';
}

$config = load_config();
if (configured_password_hash($config) !== null && empty($_SESSION['authenticated'])) {
    deny();
}

$root = realpath((string)$config['target_site_path']);
$file = (string)($_GET['file'] ?? '');
$path = $root ? realpath($root . DIRECTORY_SEPARATOR . ltrim($file, DIRECTORY_SEPARATOR)) : false;
$allowedExt = array_map('strtolower', (array)$config['image_extensions']);
$ext = strtolower(pathinfo($path ?: '', PATHINFO_EXTENSION));
if (!$root || !$path || !is_file($path) || !str_starts_with($path, rtrim($root, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR) || !in_array($ext, $allowedExt, true)) {
    deny();
}

$mime = detected_mime_type($path);
header('Content-Type: ' . $mime);
header('Content-Length: ' . filesize($path));
readfile($path);
