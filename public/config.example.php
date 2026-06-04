<?php
return [
    // Absolute path to the public web root of the site being controlled.
    'target_site_path' => getenv('INTEGRITY_TARGET_SITE_PATH') ?: '/var/www/integrity_site',

    // Optional: set CONTROL_SITE_PASSWORD_HASH in Apache/env instead of storing a hash file.
    // Generate a hash with: php -r "echo password_hash('your-password', PASSWORD_DEFAULT), PHP_EOL;"
    'password_hash_env' => 'CONTROL_SITE_PASSWORD_HASH',

    // File extensions treated as editable page templates/content files.
    'page_extensions' => ['html', 'htm'],

    // File extensions treated as replaceable site photos/images.
    'image_extensions' => ['jpg', 'jpeg', 'png', 'gif', 'webp'],

    // Safety limit for uploaded replacement photos.
    'max_upload_bytes' => 10 * 1024 * 1024,
];
