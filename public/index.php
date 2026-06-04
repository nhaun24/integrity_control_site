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

function dom_extension_available(): bool
{
    return class_exists('DOMDocument') && class_exists('DOMXPath');
}

function dom_for_file(string $fullPath): DOMDocument
{
    if (!dom_extension_available()) {
        throw new RuntimeException('PHP DOM/XML extension is not installed. Using the built-in HTML fallback editor instead.');
    }

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

function protected_html_ranges(string $content): array
{
    preg_match_all('/<(script|style|noscript|svg)\b[^>]*>.*?<\/\1>/is', $content, $matches, PREG_OFFSET_CAPTURE);
    $ranges = [];
    foreach ($matches[0] as $match) {
        $ranges[] = [$match[1], $match[1] + strlen($match[0])];
    }
    return $ranges;
}

function offset_in_ranges(int $offset, array $ranges): bool
{
    foreach ($ranges as [$start, $end]) {
        if ($offset >= $start && $offset < $end) {
            return true;
        }
    }
    return false;
}

function fallback_text_matches(string $content): array
{
    $tags = 'h[1-6]|p|a|button|span|li|figcaption|small|strong|em|label|option|title';
    $pattern = '/<(' . $tags . ')\b([^>]*)>([^<>]+)<\/\1>/iu';
    preg_match_all($pattern, $content, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER);
    $protectedRanges = protected_html_ranges($content);
    $items = [];
    $index = 0;

    foreach ($matches as $match) {
        $offset = $match[0][1];
        if (offset_in_ranges($offset, $protectedRanges)) {
            continue;
        }

        $rawText = $match[3][0];
        $text = trim(preg_replace('/\s+/', ' ', html_entity_decode($rawText, ENT_QUOTES | ENT_HTML5, 'UTF-8')) ?? '');
        if ($text === '') {
            continue;
        }

        $items[] = [
            'key' => 'fallback:' . $index,
            'tag' => strtolower($match[1][0]),
            'text' => $text,
            'full' => $match[0][0],
            'offset' => $offset,
            'text_offset' => $match[3][1],
            'text_length' => strlen($rawText),
        ];
        $index++;
    }

    return $items;
}

function editable_text_items(string $fullPath): array
{
    if (!dom_extension_available()) {
        return fallback_text_matches((string)file_get_contents($fullPath));
    }

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

function save_text_items_with_fallback(string $fullPath, string $relative, array $updates): int
{
    $content = (string)file_get_contents($fullPath);
    $items = fallback_text_matches($content);
    $replacements = [];
    $changed = 0;

    foreach ($items as $item) {
        $key = $item['key'];
        if (!isset($updates[$key]) || !is_string($updates[$key])) {
            continue;
        }

        $newValue = trim($updates[$key]);
        if ($item['text'] === $newValue) {
            continue;
        }

        $replacements[] = [
            'offset' => $item['text_offset'],
            'length' => $item['text_length'],
            'value' => htmlspecialchars($newValue, ENT_NOQUOTES | ENT_SUBSTITUTE, 'UTF-8'),
        ];
        $changed++;
    }

    if ($changed > 0) {
        backup_file($fullPath, $relative);
        usort($replacements, static fn(array $a, array $b): int => $b['offset'] <=> $a['offset']);
        foreach ($replacements as $replacement) {
            $content = substr_replace($content, $replacement['value'], $replacement['offset'], $replacement['length']);
        }
        file_put_contents($fullPath, $content, LOCK_EX);
    }

    return $changed;
}

function save_text_items(string $fullPath, string $relative, array $updates): int
{
    if (!dom_extension_available()) {
        return save_text_items_with_fallback($fullPath, $relative, $updates);
    }

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

function uploaded_file_looks_like_svg(string $tmp): bool
{
    $handle = fopen($tmp, 'rb');
    if ($handle === false) {
        return false;
    }
    $sample = fread($handle, 4096);
    fclose($handle);
    if (!is_string($sample) || $sample === '') {
        return false;
    }

    return stripos($sample, '<svg') !== false;
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
    $mime = detected_mime_type($tmp);
    if ($nameExt === 'svg') {
        if ($mime !== 'image/svg+xml' && !uploaded_file_looks_like_svg($tmp)) {
            throw new RuntimeException('The replacement file does not look like an SVG image.');
        }
    } elseif (!str_starts_with($mime, 'image/')) {
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
    if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
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
                <?php if (!dom_extension_available()): ?>
                    <div class="notice info">Limited text editor mode is active. Simple HTML text can still be edited here; install the PHP DOM/XML extension on the server to enable full DOM-based editing.</div>
                <?php endif; ?>
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
                <?php $selectedImage = $imageFiles[0] ?? ''; ?>
                <?php if ($imageFiles === []): ?>
                    <p class="muted">No supported image files were found in the configured site folder.</p>
                <?php else: ?>
                    <div class="photo-preview">
                        <img id="selected-photo-preview" src="preview.php?file=<?= rawurlencode($selectedImage) ?>" alt="Selected existing photo preview">
                        <a id="selected-photo-link" href="preview.php?file=<?= rawurlencode($selectedImage) ?>" target="_blank" rel="noopener">Open selected photo full size</a>
                    </div>
                <?php endif; ?>
                <form method="post" enctype="multipart/form-data" class="stack">
                    <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
                    <input type="hidden" name="action" value="replace_image">
                    <label>Current photo
                        <select name="image" required id="image-select">
                            <?php foreach ($imageFiles as $image): ?>
                                <option value="<?= e($image) ?>"><?= e($image) ?></option>
                            <?php endforeach; ?>
                        </select>
                    </label>
                    <label>Replacement file
                        <input type="file" name="replacement" accept="image/*,image/svg+xml,.svg" required>
                    </label>
                    <button type="submit" <?= $imageFiles === [] ? 'disabled' : '' ?>>Replace selected photo</button>
                </form>
                <?php if ($imageFiles !== []): ?>
                    <p class="muted">Showing <?= count($imageFiles) ?> existing photo(s). Click a thumbnail to select it for replacement.</p>
                <?php endif; ?>
                <div class="gallery">
                    <?php foreach ($imageFiles as $image): ?>
                        <button class="photo-card" type="button" data-image="<?= e($image) ?>">
                            <img src="preview.php?file=<?= rawurlencode($image) ?>" alt="Preview of <?= e($image) ?>" loading="lazy">
                            <span><?= e($image) ?></span>
                        </button>
                    <?php endforeach; ?>
                </div>
            </article>
        </section>
    <?php endif; ?>
</main>
<script>
const imageSelect = document.getElementById('image-select');
const selectedPhotoPreview = document.getElementById('selected-photo-preview');
const selectedPhotoLink = document.getElementById('selected-photo-link');
const photoCards = document.querySelectorAll('.photo-card');

function previewUrl(file) {
    return 'preview.php?file=' + encodeURIComponent(file);
}

function selectImage(file) {
    if (imageSelect) {
        imageSelect.value = file;
    }
    if (selectedPhotoPreview && selectedPhotoLink) {
        const url = previewUrl(file);
        selectedPhotoPreview.src = url;
        selectedPhotoLink.href = url;
    }
    photoCards.forEach((card) => {
        card.classList.toggle('is-selected', card.dataset.image === file);
    });
}

if (imageSelect) {
    imageSelect.addEventListener('change', () => selectImage(imageSelect.value));
    selectImage(imageSelect.value);
}

photoCards.forEach((card) => {
    card.addEventListener('click', () => selectImage(card.dataset.image));
});
</script>
</body>
</html>
