<?php
declare(strict_types=1);

session_start();

const APP_NAME = 'Integrity Site Control';
const DATA_DIR = __DIR__ . '/../var/data';
const AUTH_FILE = DATA_DIR . '/auth.json';
const BACKUP_DIR = __DIR__ . '/../var/backups';

$config = load_config();
$messages = [];
$errors = [];

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

function e(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function ensure_private_dirs(): void
{
    foreach ([DATA_DIR, BACKUP_DIR] as $dir) {
        if (!is_dir($dir)) {
            mkdir($dir, 0750, true);
        }
    }
}

function csrf_token(): string
{
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

function require_csrf(): void
{
    if (($_POST['csrf'] ?? '') !== ($_SESSION['csrf'] ?? null)) {
        throw new RuntimeException('Security check failed. Please refresh and try again.');
    }
}

function configured_password_hash(array $config): ?string
{
    $envName = (string)($config['password_hash_env'] ?? 'CONTROL_SITE_PASSWORD_HASH');
    $fromEnv = getenv($envName);
    if (is_string($fromEnv) && $fromEnv !== '') {
        return $fromEnv;
    }
    if (is_file(AUTH_FILE)) {
        $payload = json_decode((string)file_get_contents(AUTH_FILE), true);
        if (is_array($payload) && isset($payload['password_hash']) && is_string($payload['password_hash'])) {
            return $payload['password_hash'];
        }
    }
    return null;
}

function is_authenticated(): bool
{
    return !empty($_SESSION['authenticated']);
}

function target_root(array $config): string
{
    $root = realpath((string)$config['target_site_path']);
    if ($root === false || !is_dir($root)) {
        throw new RuntimeException('Target site path does not exist or is not a directory: ' . (string)$config['target_site_path']);
    }
    return rtrim($root, DIRECTORY_SEPARATOR);
}

function relative_path(string $root, string $fullPath): string
{
    $root = rtrim($root, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
    return ltrim(str_replace($root, '', $fullPath), DIRECTORY_SEPARATOR);
}

function resolve_target_file(array $config, string $relative): string
{
    $root = target_root($config);
    $full = realpath($root . DIRECTORY_SEPARATOR . ltrim($relative, DIRECTORY_SEPARATOR));
    if ($full === false || !is_file($full) || !str_starts_with($full, $root . DIRECTORY_SEPARATOR)) {
        throw new RuntimeException('Invalid target file.');
    }
    return $full;
}

function scan_files(array $config, array $extensions): array
{
    $root = target_root($config);
    $files = [];
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS)
    );
    foreach ($iterator as $file) {
        if (!$file instanceof SplFileInfo || !$file->isFile()) {
            continue;
        }
        $ext = strtolower($file->getExtension());
        if (in_array($ext, $extensions, true)) {
            $files[] = relative_path($root, $file->getPathname());
        }
    }
    natcasesort($files);
    return array_values($files);
}

function backup_file(string $fullPath, string $relative): string
{
    ensure_private_dirs();
    $stamp = gmdate('Ymd-His');
    $safeRelative = preg_replace('/[^A-Za-z0-9._-]+/', '_', $relative) ?: basename($fullPath);
    $backup = BACKUP_DIR . DIRECTORY_SEPARATOR . $stamp . '-' . $safeRelative;
    if (!copy($fullPath, $backup)) {
        throw new RuntimeException('Could not create backup before saving changes.');
    }
    return $backup;
}

function dom_for_file(string $fullPath): DOMDocument
{
    $content = (string)file_get_contents($fullPath);
    $dom = new DOMDocument('1.0', 'UTF-8');
    libxml_use_internal_errors(true);
    $dom->preserveWhiteSpace = true;
    $dom->formatOutput = false;
    $dom->loadHTML('<?xml encoding="UTF-8">' . $content, LIBXML_HTML_NOIMPLIED | LIBXML_HTML_NODEFDTD);
    libxml_clear_errors();
    return $dom;
}

function node_key(DOMElement $node): string
{
    $parts = [];
    while ($node->parentNode instanceof DOMNode) {
        $index = 1;
        $sibling = $node->previousSibling;
        while ($sibling !== null) {
            if ($sibling instanceof DOMElement && $sibling->tagName === $node->tagName) {
                $index++;
            }
            $sibling = $sibling->previousSibling;
        }
        array_unshift($parts, strtolower($node->tagName) . ':' . $index);
        if (!$node->parentNode instanceof DOMElement) {
            break;
        }
        $node = $node->parentNode;
    }
    return implode('/', $parts);
}

function element_by_key(DOMDocument $dom, string $key): ?DOMElement
{
    $current = $dom;
    foreach (explode('/', $key) as $part) {
        if (!preg_match('/^([a-z0-9]+):(\d+)$/i', $part, $matches)) {
            return null;
        }
        $tag = strtolower($matches[1]);
        $wanted = (int)$matches[2];
        $seen = 0;
        $found = null;
        foreach ($current->childNodes as $child) {
            if ($child instanceof DOMElement && strtolower($child->tagName) === $tag) {
                $seen++;
                if ($seen === $wanted) {
                    $found = $child;
                    break;
                }
            }
        }
        if (!$found instanceof DOMElement) {
            return null;
        }
        $current = $found;
    }
    return $current instanceof DOMElement ? $current : null;
}

function editable_text_items(string $fullPath): array
{
    $dom = dom_for_file($fullPath);
    $xpath = new DOMXPath($dom);
    $query = '//*[not(self::script) and not(self::style) and not(self::noscript) and not(self::svg)]';
    $items = [];
    foreach ($xpath->query($query) ?: [] as $node) {
        if (!$node instanceof DOMElement) {
            continue;
        }
        $hasElementChild = false;
        foreach ($node->childNodes as $child) {
            if ($child instanceof DOMElement) {
                $hasElementChild = true;
                break;
            }
        }
        if ($hasElementChild) {
            continue;
        }
        $text = trim(preg_replace('/\s+/', ' ', $node->textContent));
        if ($text === '') {
            continue;
        }
        $items[] = [
            'key' => node_key($node),
            'tag' => strtolower($node->tagName),
            'text' => $text,
        ];
    }
    return $items;
}

function save_text_items(string $fullPath, string $relative, array $updates): int
{
    $dom = dom_for_file($fullPath);
    $changed = 0;
    foreach ($updates as $key => $value) {
        if (!is_string($key) || !is_string($value)) {
            continue;
        }
        $node = element_by_key($dom, $key);
        if (!$node instanceof DOMElement) {
            continue;
        }
        $newValue = trim($value);
        if ($node->textContent !== $newValue) {
            while ($node->firstChild) {
                $node->removeChild($node->firstChild);
            }
            $node->appendChild($dom->createTextNode($newValue));
            $changed++;
        }
    }
    if ($changed > 0) {
        backup_file($fullPath, $relative);
        $html = $dom->saveHTML();
        $html = preg_replace('/^<\?xml encoding="UTF-8"\?>\s*/', '', $html ?? '');
        file_put_contents($fullPath, $html, LOCK_EX);
    }
    return $changed;
}

function replace_image(array $config, string $relative, array $upload): void
{
    $target = resolve_target_file($config, $relative);
    $allowedExt = array_map('strtolower', (array)$config['image_extensions']);
    $ext = strtolower(pathinfo($target, PATHINFO_EXTENSION));
    if (!in_array($ext, $allowedExt, true)) {
        throw new RuntimeException('The selected target is not a supported image type.');
    }
    if (($upload['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
        throw new RuntimeException('Upload failed. Please choose a replacement image.');
    }
    if (($upload['size'] ?? 0) > (int)$config['max_upload_bytes']) {
        throw new RuntimeException('The uploaded file is larger than the configured size limit.');
    }
    $tmp = (string)$upload['tmp_name'];
    $nameExt = strtolower(pathinfo((string)$upload['name'], PATHINFO_EXTENSION));
    if (!in_array($nameExt, $allowedExt, true)) {
        throw new RuntimeException('Unsupported replacement image extension.');
    }
    $mime = mime_content_type($tmp) ?: '';
    if ($ext !== 'svg' && !str_starts_with($mime, 'image/')) {
        throw new RuntimeException('The replacement file does not look like an image.');
    }
    backup_file($target, $relative);
    if (!move_uploaded_file($tmp, $target)) {
        if (!rename($tmp, $target)) {
            throw new RuntimeException('Could not replace the selected image. Check filesystem permissions.');
        }
    }
}

ensure_private_dirs();
$action = $_POST['action'] ?? $_GET['action'] ?? 'dashboard';

try {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if ($action === 'setup') {
            require_csrf();
            $password = (string)($_POST['password'] ?? '');
            if (strlen($password) < 12) {
                throw new RuntimeException('Use a password of at least 12 characters.');
            }
            file_put_contents(AUTH_FILE, json_encode([
                'password_hash' => password_hash($password, PASSWORD_DEFAULT),
                'created_at' => gmdate('c'),
            ], JSON_PRETTY_PRINT), LOCK_EX);
            $_SESSION['authenticated'] = true;
            $messages[] = 'Admin password created.';
        } elseif ($action === 'login') {
            require_csrf();
            $hash = configured_password_hash($config);
            if ($hash && password_verify((string)($_POST['password'] ?? ''), $hash)) {
                $_SESSION['authenticated'] = true;
                $messages[] = 'Signed in.';
            } else {
                $errors[] = 'Invalid password.';
            }
        } elseif ($action === 'logout') {
            require_csrf();
            session_destroy();
            session_start();
            $messages[] = 'Signed out.';
        } elseif (!is_authenticated()) {
            throw new RuntimeException('Please sign in first.');
        } elseif ($action === 'save_text') {
            require_csrf();
            $relative = (string)($_POST['page'] ?? '');
            $fullPath = resolve_target_file($config, $relative);
            $changed = save_text_items($fullPath, $relative, (array)($_POST['text'] ?? []));
            $messages[] = $changed > 0 ? "Saved {$changed} text change(s)." : 'No text changes were needed.';
            $_GET['page'] = $relative;
        } elseif ($action === 'replace_image') {
            require_csrf();
            replace_image($config, (string)($_POST['image'] ?? ''), $_FILES['replacement'] ?? []);
            $messages[] = 'Photo replaced and the previous file was backed up.';
        }
    }
} catch (Throwable $exception) {
    $errors[] = $exception->getMessage();
}

$hash = configured_password_hash($config);
$needsSetup = $hash === null;
$authenticated = is_authenticated();

?><!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?= e(APP_NAME) ?></title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
<header class="topbar">
    <div>
        <p class="eyebrow">Apache Control Panel</p>
        <h1><?= e(APP_NAME) ?></h1>
    </div>
    <?php if ($authenticated): ?>
        <form method="post">
            <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
            <input type="hidden" name="action" value="logout">
            <button class="secondary" type="submit">Sign out</button>
        </form>
    <?php endif; ?>
</header>
<main>
    <?php foreach ($messages as $message): ?><div class="notice success"><?= e($message) ?></div><?php endforeach; ?>
    <?php foreach ($errors as $error): ?><div class="notice error"><?= e($error) ?></div><?php endforeach; ?>

    <?php if ($needsSetup): ?>
        <section class="card narrow">
            <h2>Create the admin password</h2>
            <p>No password has been configured yet. Create one now, then restrict this control site with HTTPS and server access rules.</p>
            <form method="post" class="stack">
                <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
                <input type="hidden" name="action" value="setup">
                <label>Password <input type="password" name="password" minlength="12" required autocomplete="new-password"></label>
                <button type="submit">Create password</button>
            </form>
        </section>
    <?php elseif (!$authenticated): ?>
        <section class="card narrow">
            <h2>Sign in</h2>
            <form method="post" class="stack">
                <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
                <input type="hidden" name="action" value="login">
                <label>Password <input type="password" name="password" required autocomplete="current-password"></label>
                <button type="submit">Open control site</button>
            </form>
        </section>
    <?php else: ?>
        <?php
        $pageFiles = [];
        $imageFiles = [];
        try {
            $pageFiles = scan_files($config, (array)$config['page_extensions']);
            $imageFiles = scan_files($config, (array)$config['image_extensions']);
        } catch (Throwable $exception) {
            echo '<div class="notice error">' . e($exception->getMessage()) . '</div>';
        }
        $selectedPage = (string)($_GET['page'] ?? ($pageFiles[0] ?? ''));
        ?>
        <section class="grid">
            <article class="card">
                <h2>Edit text descriptions</h2>
                <p>Select a page, edit headings, descriptions, buttons, or short text blocks, then save. The original file is backed up first.</p>
                <form method="get" class="inline-form">
                    <label>Page
                        <select name="page" onchange="this.form.submit()">
                            <?php foreach ($pageFiles as $page): ?>
                                <option value="<?= e($page) ?>" <?= $page === $selectedPage ? 'selected' : '' ?>><?= e($page) ?></option>
                            <?php endforeach; ?>
                        </select>
                    </label>
                    <button class="secondary" type="submit">Load</button>
                </form>
                <?php if ($selectedPage !== ''): ?>
                    <?php
                    $items = [];
                    try {
                        $items = editable_text_items(resolve_target_file($config, $selectedPage));
                    } catch (Throwable $exception) {
                        echo '<div class="notice error">' . e($exception->getMessage()) . '</div>';
                    }
                    ?>
                    <form method="post" class="stack editor">
                        <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
                        <input type="hidden" name="action" value="save_text">
                        <input type="hidden" name="page" value="<?= e($selectedPage) ?>">
                        <?php if ($items === []): ?>
                            <p class="muted">No simple editable text blocks were found on this page.</p>
                        <?php endif; ?>
                        <?php foreach ($items as $item): ?>
                            <label>
                                <span class="label-title">&lt;<?= e($item['tag']) ?>&gt;</span>
                                <textarea name="text[<?= e($item['key']) ?>]" rows="3"><?= e($item['text']) ?></textarea>
                            </label>
                        <?php endforeach; ?>
                        <button type="submit" <?= $items === [] ? 'disabled' : '' ?>>Save text changes</button>
                    </form>
                <?php endif; ?>
            </article>
            <article class="card">
                <h2>Change photos</h2>
                <p>Replace an existing site image with a new upload while keeping the same filename, so current page references keep working.</p>
                <form method="post" enctype="multipart/form-data" class="stack">
                    <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
                    <input type="hidden" name="action" value="replace_image">
                    <label>Current photo
                        <select name="image" required>
                            <?php foreach ($imageFiles as $image): ?>
                                <option value="<?= e($image) ?>"><?= e($image) ?></option>
                            <?php endforeach; ?>
                        </select>
                    </label>
                    <label>Replacement file
                        <input type="file" name="replacement" accept="image/*,.svg" required>
                    </label>
                    <button type="submit">Replace selected photo</button>
                </form>
                <div class="gallery">
                    <?php foreach (array_slice($imageFiles, 0, 24) as $image): ?>
                        <figure>
                            <img src="preview.php?file=<?= rawurlencode($image) ?>" alt="">
                            <figcaption><?= e($image) ?></figcaption>
                        </figure>
                    <?php endforeach; ?>
                </div>
            </article>
        </section>
    <?php endif; ?>
</main>
</body>
</html>
