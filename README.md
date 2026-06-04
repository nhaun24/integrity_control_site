# Integrity Control Site

A small PHP control panel for the Integrity website. It is designed to run on the same Apache server as the main public site and edit files in `/var/www/integrity_site`.

## What it does

- Creates a password-protected control panel on first launch.
- Scans the main site for editable page files (`.html`, `.htm` by default).
- Lets an authenticated admin update simple text blocks such as headings, paragraphs, buttons, and short descriptions.
- Scans the main site for photos/images (`.jpg`, `.jpeg`, `.png`, `.gif`, `.webp`, `.svg` by default).
- Replaces an existing photo while keeping the same filename so the live site keeps pointing at it.
- Creates a backup in `var/backups/` before every text save or image replacement.

## Files

- `public/index.php` — main control panel UI and edit logic.
- `public/preview.php` — authenticated image preview endpoint.
- `public/styles.css` — dashboard styling.
- `public/config.example.php` — defaults and deployment settings.

## Apache setup

Point an Apache virtual host or protected location at this repository's `public/` directory. Example:

```apache
<VirtualHost *:80>
    ServerName control.example.com
    DocumentRoot /path/to/integrity_control_site/public

    <Directory /path/to/integrity_control_site/public>
        AllowOverride None
        Require all granted
    </Directory>

    # Optional: store the admin password hash in Apache instead of var/data/auth.json.
    # Generate with: php -r "echo password_hash('your-password', PASSWORD_DEFAULT), PHP_EOL;"
    SetEnv CONTROL_SITE_PASSWORD_HASH "$2y$..."
</VirtualHost>
```

Use HTTPS for the control domain. The Apache/PHP user must have read/write permission to `/var/www/integrity_site` and write permission to this app's `var/` directory.

## Configuration

Defaults live in `public/config.example.php`. To override them without editing tracked files, create `public/config.php`:

```php
<?php
return [
    'target_site_path' => '/var/www/integrity_site',
    'max_upload_bytes' => 10 * 1024 * 1024,
    // Add 'php' only if those files are mostly HTML and safe for DOM-based editing.
    'page_extensions' => ['html', 'htm'],
];
```

For local testing, you can point the app at another directory with:

```bash
INTEGRITY_TARGET_SITE_PATH=/tmp/my-test-site php -S 127.0.0.1:8080 -t public
```

## First login

If `CONTROL_SITE_PASSWORD_HASH` is not configured and `var/data/auth.json` does not exist, the control panel shows a setup form. Create a password of at least 12 characters. After that, the setup screen is disabled and the normal sign-in screen is shown.

## Safety notes

- The app backs up changed files, but it is still best to keep the main site in Git or another backup system.
- Text editing intentionally targets simple text-only elements. Complex sections with nested markup may need direct code edits.
- Replacing photos preserves the original target filename. Upload a replacement with the correct visual dimensions for the existing design.
