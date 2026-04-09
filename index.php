<?php

declare(strict_types=1);

$requestPath = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';

if (!function_exists('str_starts_with')) {
    function str_starts_with(string $haystack, string $needle): bool
    {
        if ($needle === '') {
            return true;
        }
        return substr($haystack, 0, strlen($needle)) === $needle;
    }
}

if (!function_exists('str_contains')) {
    function str_contains(string $haystack, string $needle): bool
    {
        if ($needle === '') {
            return true;
        }
        return strpos($haystack, $needle) !== false;
    }
}

if (PHP_SAPI === 'cli-server') {
    $fullPath = __DIR__ . $requestPath;
    if (is_file($fullPath)) {
        return false;
    }
}

session_set_cookie_params([
    'httponly' => true,
    'samesite' => 'Lax'
]);
session_start();

const MAX_UPLOAD_BYTES = 104857600;
const CATEGORIES = ['oferty', 'grafiki', 'pdf', 'wskazowki', 'poradniki', 'umowy', 'inne'];

function panelPassword(): string
{
    $pw = (string) (getenv('PANEL_PASSWORD') ?: '');
    if ($pw !== '') {
        return $pw;
    }
    if (PHP_SAPI === 'cli-server') {
        return 'admin123';
    }
    return '';
}

function sharePasswordKey(): string
{
    $key = (string) (getenv('SHARE_PASSWORD_KEY') ?: '');
    if ($key !== '') {
        return $key;
    }
    return panelPassword();
}

function encryptShareSecret(string $plaintext): string
{
    if ($plaintext === '') {
        return '';
    }
    if (!function_exists('openssl_encrypt')) {
        return '';
    }
    $key = hash('sha256', sharePasswordKey(), true);
    $iv = random_bytes(12);
    $tag = '';
    $cipher = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
    if ($cipher === false || $tag === '') {
        return '';
    }
    return base64_encode($iv . $tag . $cipher);
}

function decryptShareSecret(string $encoded): string
{
    if ($encoded === '') {
        return '';
    }
    if (!function_exists('openssl_decrypt')) {
        return '';
    }
    $raw = base64_decode($encoded, true);
    if (!is_string($raw) || strlen($raw) < 12 + 16 + 1) {
        return '';
    }
    $iv = substr($raw, 0, 12);
    $tag = substr($raw, 12, 16);
    $cipher = substr($raw, 28);
    $key = hash('sha256', sharePasswordKey(), true);
    $plain = openssl_decrypt($cipher, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
    return $plain === false ? '' : (string) $plain;
}

function ensureDirs(): void
{
    $dataDir = __DIR__ . '/data';
    $uploadsDir = __DIR__ . '/uploads';
    if (!is_dir($dataDir)) {
        mkdir($dataDir, 0775, true);
    }
    if (!is_dir($uploadsDir)) {
        mkdir($uploadsDir, 0775, true);
    }
}

function filesDbPath(): string
{
    return __DIR__ . '/data/files.json';
}

function readFilesDb(): array
{
    $path = filesDbPath();
    if (!is_file($path)) {
        return ['files' => []];
    }
    $raw = file_get_contents($path);
    if ($raw === false) {
        return ['files' => []];
    }
    $decoded = json_decode($raw, true);
    if (!is_array($decoded) || !isset($decoded['files']) || !is_array($decoded['files'])) {
        return ['files' => []];
    }
    return $decoded;
}

function writeFilesDb(array $db): void
{
    $path = filesDbPath();
    $json = json_encode($db, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    if ($json === false) {
        return;
    }
    file_put_contents($path, $json, LOCK_EX);
}

function csrfToken(): string
{
    $token = $_SESSION['csrf'] ?? null;
    if (!is_string($token) || $token === '') {
        $token = bin2hex(random_bytes(16));
        $_SESSION['csrf'] = $token;
    }
    return $token;
}

function requireCsrf(): void
{
    $token = (string) ($_POST['csrf'] ?? '');
    $expected = (string) ($_SESSION['csrf'] ?? '');
    if ($token === '' || $expected === '' || !hash_equals($expected, $token)) {
        renderError('Błąd', 'Nieprawidłowy token bezpieczeństwa. Odśwież stronę i spróbuj ponownie.', 400);
        exit;
    }
}

function isAuthed(): bool
{
    return isset($_SESSION['auth']) && $_SESSION['auth'] === true;
}

function requireAuth(): void
{
    if (!isAuthed()) {
        header('Location: /login', true, 302);
        exit;
    }
}

function h(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function formatBytes(int $bytes): string
{
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $value = (float) $bytes;
    $idx = 0;
    while ($value >= 1024 && $idx < count($units) - 1) {
        $value /= 1024;
        $idx += 1;
    }
    $precision = $idx === 0 ? 0 : 1;
    return number_format($value, $precision, '.', '') . ' ' . $units[$idx];
}

function baseUrl(): string
{
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    return $scheme . '://' . $host;
}

function normalizeCategory(string $value): string
{
    $v = strtolower(trim($value));
    $v = str_replace(['ą', 'ć', 'ę', 'ł', 'ń', 'ó', 'ś', 'ż', 'ź'], ['a', 'c', 'e', 'l', 'n', 'o', 's', 'z', 'z'], $v);
    return in_array($v, CATEGORIES, true) ? $v : 'inne';
}

function categoryLabel(string $value): string
{
    $v = normalizeCategory($value);
    switch ($v) {
        case 'oferty':
            return 'Oferty';
        case 'grafiki':
            return 'Grafiki';
        case 'pdf':
            return 'PDF';
        case 'wskazowki':
            return 'Wskazówki';
        case 'poradniki':
            return 'Poradniki';
        case 'umowy':
            return 'Umowy';
        default:
            return 'Inne';
    }
}

function isShareUnlocked(string $token): bool
{
    return isset($_SESSION['shareUnlocked']) && is_array($_SESSION['shareUnlocked']) && ($_SESSION['shareUnlocked'][$token] ?? null) === true;
}

function setShareUnlocked(string $token): void
{
    if (!isset($_SESSION['shareUnlocked']) || !is_array($_SESSION['shareUnlocked'])) {
        $_SESSION['shareUnlocked'] = [];
    }
    $_SESSION['shareUnlocked'][$token] = true;
}

function isShareProtected(array $file): bool
{
    $hash = (string) ($file['sharePasswordHash'] ?? '');
    return $hash !== '';
}

function sharePasswordPlain(array $file): string
{
    $enc = (string) ($file['sharePasswordEnc'] ?? '');
    return $enc !== '' ? decryptShareSecret($enc) : '';
}

function requireShareUnlockedFor(array $file, string $token): void
{
    if (!isShareProtected($file)) {
        return;
    }
    if (isAuthed()) {
        return;
    }
    if (isShareUnlocked($token)) {
        return;
    }
    header('Location: /s/' . rawurlencode($token), true, 302);
    exit;
}

function oneTimePasswordStore(string $id, string $password): void
{
    if (!isset($_SESSION['oneTimePasswords']) || !is_array($_SESSION['oneTimePasswords'])) {
        $_SESSION['oneTimePasswords'] = [];
    }
    $_SESSION['oneTimePasswords'][$id] = $password;
}

function oneTimePasswordConsume(string $id): string
{
    if (!isset($_SESSION['oneTimePasswords']) || !is_array($_SESSION['oneTimePasswords'])) {
        return '';
    }
    $pw = (string) ($_SESSION['oneTimePasswords'][$id] ?? '');
    unset($_SESSION['oneTimePasswords'][$id]);
    return $pw;
}

function displayNameFor(array $file): string
{
    $display = (string) ($file['displayName'] ?? '');
    $original = (string) ($file['originalName'] ?? '');
    return $display !== '' ? $display : $original;
}

function findById(array $db, string $id): ?array
{
    foreach (($db['files'] ?? []) as $idx => $f) {
        if (($f['id'] ?? null) === $id) {
            return ['index' => $idx, 'file' => $f];
        }
    }
    return null;
}

function findByToken(array $db, string $token): ?array
{
    foreach (($db['files'] ?? []) as $idx => $f) {
        $t = (string) ($f['token'] ?? $f['id'] ?? '');
        if ($t === $token) {
            return ['index' => $idx, 'file' => $f];
        }
    }
    return null;
}

function findByIdOrToken(array $db, string $value): ?array
{
    $byId = findById($db, $value);
    if ($byId !== null) {
        return $byId;
    }
    return findByToken($db, $value);
}

function iniSizeToBytes(string $value): int
{
    $v = trim($value);
    if ($v === '') {
        return 0;
    }
    $last = strtolower(substr($v, -1));
    $num = (float) $v;
    switch ($last) {
        case 'g':
            return (int) round($num * 1024 * 1024 * 1024);
        case 'm':
            return (int) round($num * 1024 * 1024);
        case 'k':
            return (int) round($num * 1024);
        default:
            return (int) round($num);
    }
}

function inferMimeFromExtension(string $filename): string
{
    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION) ?: '');
    switch ($ext) {
        case 'jpg':
        case 'jpeg':
            return 'image/jpeg';
        case 'png':
            return 'image/png';
        case 'gif':
            return 'image/gif';
        case 'webp':
            return 'image/webp';
        case 'pdf':
            return 'application/pdf';
        case 'txt':
        case 'log':
            return 'text/plain';
        case 'json':
            return 'application/json';
        default:
            return '';
    }
}

function detectMimeType(string $absolutePath, string $fallback): string
{
    $type = $fallback !== '' ? $fallback : 'application/octet-stream';
    if (function_exists('finfo_open')) {
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        if ($finfo !== false) {
            $detected = finfo_file($finfo, $absolutePath);
            finfo_close($finfo);
            if (is_string($detected) && $detected !== '') {
                $type = $detected;
            }
        }
    }
    $type = strtolower(trim((string) $type));
    if ($type === '' || $type === 'application/octet-stream') {
        $guess = inferMimeFromExtension($absolutePath);
        if ($guess !== '') {
            $type = $guess;
        }
    }
    return $type !== '' ? $type : 'application/octet-stream';
}

function isPreviewSafeMime(string $mime): bool
{
    if (str_starts_with($mime, 'image/')) {
        return $mime !== 'image/svg+xml';
    }
    if (str_starts_with($mime, 'audio/')) {
        return true;
    }
    if (str_starts_with($mime, 'video/')) {
        return true;
    }
    return $mime === 'application/pdf';
}

function isInlineSafeMime(string $mime): bool
{
    if ($mime === 'text/html' || $mime === 'application/xhtml+xml' || $mime === 'image/svg+xml') {
        return false;
    }
    return true;
}

function readTextPreview(string $absolutePath, int $maxBytes = 65536): string
{
    $fh = fopen($absolutePath, 'rb');
    if ($fh === false) {
        return '';
    }
    $data = fread($fh, $maxBytes);
    fclose($fh);
    if ($data === false) {
        return '';
    }
    $text = (string) $data;
    if (strlen($text) === $maxBytes) {
        $text .= "\n\n…(ucięto podgląd)";
    }
    return $text;
}

function renderPage(string $title, string $content, string $extraHead = ''): void
{
    header('Content-Type: text/html; charset=utf-8');
    echo '<!doctype html>';
    echo '<html lang="pl">';
    echo '<head>';
    echo '<meta charset="utf-8" />';
    echo '<meta name="viewport" content="width=device-width, initial-scale=1" />';
    echo '<title>' . h($title) . '</title>';
    echo '<link rel="stylesheet" href="/assets/styles.css" />';
    echo $extraHead;
    echo '</head>';
    echo '<body>';
    echo $content;
    echo '</body>';
    echo '</html>';
}

function renderShell(string $headline, string $subline, string $mainHtml): string
{
    $logo = '<img class="logo" src="/logo.png" alt="Logo" />';
    $footer = renderFooter();
    $sub = $subline !== '' ? '<p>' . h($subline) . '</p>' : '';
    return '<div class="page">'
        . '<header class="header">' . $logo
        . '<div class="headerText"><h1>' . h($headline) . '</h1>' . $sub . '</div>'
        . '</header>'
        . $mainHtml
        . $footer
        . '</div>';
}

function renderFooter(): string
{
    $email = 'hello@commeriongroup.com';
    $phoneLabel = '+48 733 622 108';
    $phoneHref = '+48733622108';
    return '<footer class="footer">'
        . '<div class="footerContact">'
        . '<a class="footerLink" href="mailto:' . h($email) . '">' . h($email) . '</a>'
        . '<span class="footerSep">•</span>'
        . '<a class="footerLink" href="tel:' . h($phoneHref) . '">' . h($phoneLabel) . '</a>'
        . '</div>'
        . '</footer>';
}

function renderError(string $title, string $message, int $status = 404): void
{
    http_response_code($status);
    renderPage($title, renderShell($title, $message, '<main class="card"><a class="button buttonPrimary" href="/admin">Wróć do panelu</a></main>'));
}

function parseIdFromPath(string $path, string $prefix): ?string
{
    if (!str_starts_with($path, $prefix)) {
        return null;
    }
    $id = substr($path, strlen($prefix));
    $id = trim($id, '/');
    if ($id === '') {
        return null;
    }
    if (!preg_match('/^[a-f0-9]{16,64}$/', $id)) {
        return null;
    }
    return $id;
}

function safeExt(string $originalName): string
{
    $ext = strtolower(pathinfo($originalName, PATHINFO_EXTENSION) ?: '');
    if ($ext === '' || strlen($ext) > 16) {
        return '';
    }
    if (!preg_match('/^[a-z0-9]+$/', $ext)) {
        return '';
    }
    return '.' . $ext;
}

function contentDisposition(string $filename): string
{
    $fallback = preg_replace('/[^A-Za-z0-9._ -]/', '_', $filename);
    $fallback = $fallback === '' ? 'download' : $fallback;
    $utf8 = rawurlencode($filename);
    return "attachment; filename=\"{$fallback}\"; filename*=UTF-8''{$utf8}";
}

ensureDirs();

$method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');

if ($requestPath === '/') {
    header('Location: /admin', true, 302);
    exit;
}

if ($requestPath === '/login' && $method === 'GET') {
    $error = (string) ($_GET['error'] ?? '');
    $logo = '<img class="logo" src="/logo.png" alt="Logo" />';
    $footer = renderFooter();
    $main = '<main class="authMain"><div class="card cardNarrow">'
        . '<form class="form" method="post" action="/login">'
        . '<label class="label" for="password">Hasło</label>'
        . '<input class="input" id="password" name="password" type="password" autocomplete="current-password" autofocus required />'
        . ($error === '1' ? '<div class="alert">Nieprawidłowe hasło.</div>' : '')
        . ($error === 'config' ? '<div class="alert">Panel nie jest skonfigurowany. Ustaw zmienną środowiskową PANEL_PASSWORD.</div>' : '')
        . '<button class="button buttonPrimary" type="submit">Zaloguj</button>'
        . '</form>'
        . '</div></main>';
    $body = '<div class="page"><header class="header headerPublic">' . $logo . '</header>' . $main . $footer . '</div>';
    renderPage('Panel', $body);
    exit;
}

if ($requestPath === '/login' && $method === 'POST') {
    $password = (string) ($_POST['password'] ?? '');
    $expected = panelPassword();
    if ($expected === '') {
        header('Location: /login?error=config', true, 302);
        exit;
    }
    if (!hash_equals($expected, $password)) {
        header('Location: /login?error=1', true, 302);
        exit;
    }
    $_SESSION['auth'] = true;
    header('Location: /admin', true, 302);
    exit;
}

if ($requestPath === '/logout' && $method === 'POST') {
    requireCsrf();
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], (bool) $params['secure'], (bool) $params['httponly']);
    }
    session_destroy();
    header('Location: /login', true, 302);
    exit;
}

if ($requestPath === '/admin' && $method === 'GET') {
    requireAuth();
    $db = readFilesDb();
    $files = $db['files'];
    usort($files, fn($a, $b) => (int) ($b['uploadedAt'] ?? 0) <=> (int) ($a['uploadedAt'] ?? 0));

    $q = strtolower(trim((string) ($_GET['q'] ?? '')));
    $filterCat = normalizeCategory((string) ($_GET['cat'] ?? 'inne'));
    $filterCatEnabled = isset($_GET['cat']) && (string) $_GET['cat'] !== '';

    $filtered = array_values(array_filter($files, function ($f) use ($q, $filterCatEnabled, $filterCat) {
        $category = normalizeCategory((string) ($f['category'] ?? 'inne'));
        if ($filterCatEnabled && $category !== $filterCat) {
            return false;
        }
        if ($q === '') {
            return true;
        }
        $hay = strtolower(displayNameFor($f) . ' ' . (string) ($f['originalName'] ?? ''));
        return str_contains($hay, $q);
    }));

    $groups = [];
    foreach ($filtered as $f) {
        $cat = normalizeCategory((string) ($f['category'] ?? 'inne'));
        if (!isset($groups[$cat])) {
            $groups[$cat] = [];
        }
        $groups[$cat][] = $f;
    }
    foreach (CATEGORIES as $cat) {
        if (!isset($groups[$cat])) {
            $groups[$cat] = [];
        }
    }

    $rows = '';
    $csrf = csrfToken();

    $renderRows = function (array $list) use ($csrf): string {
        $rowsHtml = '';
        foreach ($list as $f) {
            $id = (string) ($f['id'] ?? '');
            $token = (string) ($f['token'] ?? $id);
            $originalName = (string) ($f['originalName'] ?? '');
            $displayName = displayNameFor($f);
            $size = (int) ($f['size'] ?? 0);
            $uploadedAt = (int) ($f['uploadedAt'] ?? 0);
            $storedName = (string) ($f['storedName'] ?? '');
            $absolutePath = __DIR__ . '/uploads/' . $storedName;
            $mime = is_file($absolutePath) ? detectMimeType($absolutePath, (string) ($f['mime'] ?? '')) : strtolower((string) ($f['mime'] ?? ''));
            $locked = isShareProtected($f);
            $pw = $locked ? sharePasswordPlain($f) : '';
            $pwOneTime = oneTimePasswordConsume($id);
            if ($pwOneTime !== '') {
                $pw = $pwOneTime;
            }
            if ($id === '' || $originalName === '') {
                continue;
            }
            $shareUrl = baseUrl() . '/s/' . rawurlencode($token);
            $downloadUrl = '/download/' . rawurlencode($id);
            $editUrl = '/edit/' . rawurlencode($id);
            $thumb = '';
            if ($mime !== '' && str_starts_with($mime, 'image/') && $mime !== 'image/svg+xml') {
                $thumb = '<img class="thumb" src="/view/' . h(rawurlencode($token)) . '" alt="" loading="lazy" />';
            }
            $pwRow = '';
            if ($locked) {
                if ($pw !== '') {
                    $label = $pwOneTime !== '' ? 'Nowe hasło' : 'Hasło';
                    $pwRow = '<div class="muted small">' . h($label) . ': <span class="mono">' . h($pw) . '</span> <button class="button buttonSecondary buttonXs" type="button" data-copy="' . h($pw) . '">Kopiuj hasło</button></div>';
                } else {
                    $pwRow = '<div class="muted small">Hasło: ustawione, ale nie do odczytania</div>'
                        . '<div class="actionsBar">'
                        . '<form method="post" action="/genpass" class="inlineForm">'
                        . '<input type="hidden" name="csrf" value="' . h($csrf) . '" />'
                        . '<input type="hidden" name="id" value="' . h($id) . '" />'
                        . '<button class="button buttonSecondary buttonXs" type="submit">Generuj hasło</button>'
                        . '</form>'
                        . '<a class="button buttonGhost buttonXs" href="' . h($editUrl) . '">Ustaw hasło</a>'
                        . '</div>';
                }
            } else {
                $pwRow = '<div class="muted small">Hasło: brak</div>'
                    . '<div class="actionsBar">'
                    . '<form method="post" action="/genpass" class="inlineForm">'
                    . '<input type="hidden" name="csrf" value="' . h($csrf) . '" />'
                    . '<input type="hidden" name="id" value="' . h($id) . '" />'
                    . '<button class="button buttonSecondary buttonXs" type="submit">Generuj hasło</button>'
                    . '</form>'
                    . '<a class="button buttonGhost buttonXs" href="' . h($editUrl) . '">Ustaw hasło</a>'
                    . '</div>';
            }
            $rowsHtml .= '<tr>'
                . '<td>'
                . ($thumb !== '' ? '<div class="fileCell">' . $thumb . '<div class="fileMeta">' : '<div class="fileMeta">')
                . '<div class="mono">' . h($originalName) . '</div>'
                . ($displayName !== $originalName ? '<div class="muted small">Publicznie: ' . h($displayName) . '</div>' : '')
                . '<div class="muted small"><a class="mono link" href="' . h($shareUrl) . '" target="_blank" rel="noreferrer">' . h($shareUrl) . '</a></div>'
                . $pwRow
                . '<div class="actionsBar">'
                . '<a class="button buttonGhost buttonXs" href="' . h($downloadUrl) . '">Pobierz</a>'
                . '<button class="button buttonSecondary buttonXs" type="button" data-copy="' . h($shareUrl) . '">Kopiuj link</button>'
                . '<a class="button buttonPrimary buttonXs" href="' . h($shareUrl) . '" target="_blank" rel="noreferrer">Podgląd</a>'
                . '<a class="button buttonGhost buttonXs" href="' . h($editUrl) . '">Edytuj</a>'
                . '<form method="post" action="/delete" class="inlineForm">'
                . '<input type="hidden" name="csrf" value="' . h($csrf) . '" />'
                . '<input type="hidden" name="id" value="' . h($id) . '" />'
                . '<button class="button buttonDanger buttonXs" type="submit" data-confirm="Usunąć plik?">Usuń</button>'
                . '</form>'
                . '</div>'
                . '</div>'
                . ($thumb !== '' ? '</div>' : '')
                . '</td>'
                . '<td class="muted">' . h(formatBytes($size)) . '</td>'
                . '<td class="muted">' . h(date('Y-m-d H:i', (int) round($uploadedAt / 1000))) . '</td>'
                . '</tr>';
        }
        return $rowsHtml;
    };

    $tables = '';
    foreach (CATEGORIES as $cat) {
        $list = $groups[$cat] ?? [];
        $rowsHtml = $renderRows($list);
        $tables .= '<section class="card">'
            . '<div class="cardHeader"><h2>Kategoria: ' . h(categoryLabel($cat)) . '</h2><div class="muted">' . h((string) count($list)) . ' szt.</div></div>'
            . '<div class="tableWrap">'
            . '<table class="table">'
            . '<thead><tr><th>Plik</th><th>Rozmiar</th><th>Dodano</th></tr></thead>'
            . '<tbody>' . ($rowsHtml !== '' ? $rowsHtml : '<tr><td class="muted" colspan="3">Brak plików w tej kategorii.</td></tr>') . '</tbody>'
            . '</table>'
            . '</div>'
            . '</section>';
    }

    $uploadMax = iniSizeToBytes((string) ini_get('upload_max_filesize'));
    $postMax = iniSizeToBytes((string) ini_get('post_max_size'));
    $effectiveMax = MAX_UPLOAD_BYTES;
    if ($uploadMax > 0) {
        $effectiveMax = min($effectiveMax, $uploadMax);
    }
    if ($postMax > 0) {
        $effectiveMax = min($effectiveMax, $postMax);
    }
    $writableUploads = is_writable(__DIR__ . '/uploads');
    $writableData = is_writable(__DIR__ . '/data');

    $warnings = '';
    if (!$writableUploads || !$writableData) {
        $warnings .= '<div class="alert">Brak uprawnień zapisu do '
            . (!$writableUploads ? '<span class="mono">uploads/</span>' : '')
            . (!$writableUploads && !$writableData ? ' i ' : '')
            . (!$writableData ? '<span class="mono">data/</span>' : '')
            . '. Ustaw prawa zapisu na serwerze.</div>';
    }
    if ($effectiveMax < MAX_UPLOAD_BYTES) {
        $warnings .= '<div class="alert">PHP ogranicza upload do ' . h(formatBytes($effectiveMax)) . ' (post_max_size / upload_max_filesize). Jeśli upload “nie dodaje pliku”, to zwykle ten limit.</div>';
    }
    if (!function_exists('openssl_encrypt') || !function_exists('openssl_decrypt')) {
        $warnings .= '<div class="alert">Na serwerze nie ma OpenSSL w PHP — nie da się wyświetlać i kopiować haseł (da się tylko weryfikować). Włącz rozszerzenie OpenSSL albo generuj hasło i od razu je przepisuj.</div>';
    }

    $catOptions = '';
    foreach (CATEGORIES as $cat) {
        $selected = $cat === 'inne' ? ' selected' : '';
        $catOptions .= '<option value="' . h($cat) . '"' . $selected . '>' . h(categoryLabel($cat)) . '</option>';
    }

    $filterOptions = '<option value=""' . (!$filterCatEnabled ? ' selected' : '') . '>Wszystkie</option>';
    foreach (CATEGORIES as $cat) {
        $selected = ($filterCatEnabled && $filterCat === $cat) ? ' selected' : '';
        $filterOptions .= '<option value="' . h($cat) . '"' . $selected . '>' . h(categoryLabel($cat)) . '</option>';
    }

    $main = '<main class="grid">'
        . '<section class="card sticky">'
        . '<div class="cardHeader"><h2>Dodaj plik</h2>'
        . '<form method="post" action="/logout"><input type="hidden" name="csrf" value="' . h($csrf) . '" /><button class="button buttonGhost" type="submit">Wyloguj</button></form>'
        . '</div>'
        . $warnings
        . '<form class="form" method="post" action="/upload" enctype="multipart/form-data">'
        . '<input type="hidden" name="csrf" value="' . h($csrf) . '" />'
        . '<input class="input" type="file" name="file" required />'
        . '<label class="label" for="category">Kategoria</label>'
        . '<select class="input" id="category" name="category">' . $catOptions . '</select>'
        . '<label class="label" for="displayName">Nazwa publiczna (opcjonalnie)</label>'
        . '<input class="input" id="displayName" name="displayName" type="text" placeholder="np. Oferta — kwiecień 2026" />'
        . '<div class="row">'
        . '<button class="button buttonPrimary" type="submit">Upload</button>'
        . '<div class="hint">Limit aplikacji: ' . h(formatBytes(MAX_UPLOAD_BYTES)) . '</div>'
        . '</div>'
        . '</form>'
        . '<div class="muted small">Udostępnianie zawsze działa przez link firmowy z logo: <span class="mono">/s/...</span></div>'
        . '</section>'
        . '<section class="card rightScroll">'
        . '<div class="cardHeader"><h2>Twoje pliki</h2><div class="muted">' . h((string) count($filtered)) . ' szt.</div></div>'
        . '<form class="toolbar" method="get" action="/admin">'
        . '<input class="input" type="text" name="q" value="' . h((string) ($_GET['q'] ?? '')) . '" placeholder="Szukaj po nazwie…" />'
        . '<select class="input" name="cat">' . $filterOptions . '</select>'
        . '<button class="button buttonGhost" type="submit">Filtruj</button>'
        . '</form>'
        . '<div class="stack">' . $tables . '</div>'
        . '</section>'
        . '</main>';

    $body = renderShell('Panel plików', 'Uploaduj pliki i udostępniaj je firmowym linkiem.', $main);
    renderPage('Panel — Pliki', $body, '<script defer src="/assets/app.js"></script>');
    exit;
}

if ($requestPath === '/genpass' && $method === 'POST') {
    requireAuth();
    requireCsrf();
    $id = (string) ($_POST['id'] ?? '');
    if (!preg_match('/^[a-f0-9]{16,64}$/', $id)) {
        header('Location: /admin', true, 302);
        exit;
    }
    $db = readFilesDb();
    $found = findById($db, $id);
    if ($found === null) {
        header('Location: /admin', true, 302);
        exit;
    }
    $idx = (int) $found['index'];
    $newPassword = bin2hex(random_bytes(4));
    $db['files'][$idx]['sharePasswordHash'] = password_hash($newPassword, PASSWORD_DEFAULT);
    $db['files'][$idx]['sharePasswordEnc'] = encryptShareSecret($newPassword);
    writeFilesDb($db);
    oneTimePasswordStore($id, $newPassword);
    header('Location: /admin', true, 302);
    exit;
}

if ($requestPath === '/upload' && $method === 'POST') {
    requireAuth();
    requireCsrf();
    if (!isset($_FILES['file']) || !is_array($_FILES['file'])) {
        $contentLength = (int) ($_SERVER['CONTENT_LENGTH'] ?? 0);
        $uploadMax = iniSizeToBytes((string) ini_get('upload_max_filesize'));
        $postMax = iniSizeToBytes((string) ini_get('post_max_size'));
        $msg = 'Brak pliku w żądaniu.';
        if ($contentLength > 0 && empty($_POST) && empty($_FILES)) {
            $msg = 'PHP odrzuciło żądanie (zwykle limit post_max_size / upload_max_filesize).';
        }
        $msg .= ' Limity PHP: upload_max_filesize=' . (string) ini_get('upload_max_filesize') . ', post_max_size=' . (string) ini_get('post_max_size') . '.';
        renderError('Błąd uploadu', $msg, 400);
        exit;
    }

    $file = $_FILES['file'];
    $error = (int) ($file['error'] ?? UPLOAD_ERR_NO_FILE);
    if ($error !== UPLOAD_ERR_OK) {
        $map = [
            UPLOAD_ERR_INI_SIZE => 'Plik przekracza upload_max_filesize.',
            UPLOAD_ERR_FORM_SIZE => 'Plik przekracza limit formularza.',
            UPLOAD_ERR_PARTIAL => 'Plik został przesłany tylko częściowo.',
            UPLOAD_ERR_NO_FILE => 'Nie wybrano pliku.',
            UPLOAD_ERR_NO_TMP_DIR => 'Brak katalogu tymczasowego na serwerze.',
            UPLOAD_ERR_CANT_WRITE => 'Nie można zapisać pliku na dysku.',
            UPLOAD_ERR_EXTENSION => 'Upload zablokowany przez rozszerzenie PHP.'
        ];
        $reason = $map[$error] ?? ('Nieznany błąd uploadu: ' . (string) $error);
        renderError('Błąd uploadu', $reason, 400);
        exit;
    }

    $tmpName = (string) ($file['tmp_name'] ?? '');
    $originalName = (string) ($file['name'] ?? 'plik');
    $size = (int) ($file['size'] ?? 0);
    $mime = (string) ($file['type'] ?? 'application/octet-stream');
    $category = normalizeCategory((string) ($_POST['category'] ?? 'inne'));
    $displayName = trim((string) ($_POST['displayName'] ?? ''));
    if ($displayName !== '' && mb_strlen($displayName) > 140) {
        $displayName = mb_substr($displayName, 0, 140);
    }

    if ($size <= 0 || $size > MAX_UPLOAD_BYTES) {
        renderError('Błąd uploadu', 'Plik jest za duży lub pusty.', 400);
        exit;
    }

    $id = bin2hex(random_bytes(16));
    $token = bin2hex(random_bytes(16));
    $ext = safeExt($originalName);
    $storedName = $id . $ext;
    $dest = __DIR__ . '/uploads/' . $storedName;

    if (!move_uploaded_file($tmpName, $dest)) {
        renderError('Błąd uploadu', 'Nie udało się zapisać pliku na dysku.', 500);
        exit;
    }

    $mime = detectMimeType($dest, $mime);

    $db = readFilesDb();
    $db['files'][] = [
        'id' => $id,
        'token' => $token,
        'originalName' => $originalName,
        'displayName' => $displayName,
        'category' => $category,
        'storedName' => $storedName,
        'size' => $size,
        'mime' => $mime,
        'uploadedAt' => (int) round(microtime(true) * 1000)
    ];
    writeFilesDb($db);

    header('Location: /admin', true, 302);
    exit;
}

$editId = parseIdFromPath($requestPath, '/edit/');
if ($editId !== null && $method === 'GET') {
    requireAuth();
    $db = readFilesDb();
    $found = findById($db, $editId);
    if ($found === null) {
        renderError('Nie znaleziono', 'Taki plik nie istnieje.');
        exit;
    }
    $file = $found['file'];
    $csrf = csrfToken();
    $originalName = (string) ($file['originalName'] ?? '');
    $displayName = (string) ($file['displayName'] ?? '');
    $category = normalizeCategory((string) ($file['category'] ?? 'inne'));
    $token = (string) ($file['token'] ?? $editId);
    $shareUrl = baseUrl() . '/s/' . rawurlencode($token);
    $passwordSet = isShareProtected($file);
    $currentPassword = $passwordSet ? sharePasswordPlain($file) : '';
    $oneTimePassword = oneTimePasswordConsume($editId);
    $mailStatus = (string) ($_GET['mail'] ?? '');
    $mailAlert = '';
    if ($mailStatus === '1') {
        $mailAlert = '<div class="alert">Wysłano e-mail.</div>';
    } elseif ($mailStatus === '0') {
        $mailAlert = '<div class="alert">Nie udało się wysłać e-maila. Sprawdź adres i konfigurację serwera.</div>';
    }
    $pwStatus = (string) ($_GET['pw'] ?? '');
    $pwAlert = '';
    if ($pwStatus === '1') {
        $pwAlert = '<div class="alert">Hasło zapisane — możesz je teraz kopiować.</div>';
    } elseif ($pwStatus === '0') {
        $pwAlert = '<div class="alert">Podane hasło nie pasuje do aktualnego.</div>';
    }

    $catOptions = '';
    foreach (CATEGORIES as $cat) {
        $selected = $cat === $category ? ' selected' : '';
        $catOptions .= '<option value="' . h($cat) . '"' . $selected . '>' . h(categoryLabel($cat)) . '</option>';
    }

    $defaultSubject = 'Udostępniony plik — Commerion Group';
    $defaultMessage = "Link: {$shareUrl}\n";

    $main = '<main class="card">'
        . '<h2>Edytuj</h2>'
        . '<div class="fileBox">'
        . '<div class="fileName">' . h($originalName) . '</div>'
        . '<div class="muted small">Link udostępniania: <span class="mono">' . h($shareUrl) . '</span></div>'
        . '</div>'
        . $mailAlert
        . $pwAlert
        . ($oneTimePassword !== '' ? '<div class="alert">Nowe hasło: <span class="mono">' . h($oneTimePassword) . '</span></div>' : '')
        . '<form class="form" method="post" action="/edit">'
        . '<input type="hidden" name="csrf" value="' . h($csrf) . '" />'
        . '<input type="hidden" name="id" value="' . h($editId) . '" />'
        . '<label class="label" for="displayName">Nazwa publiczna</label>'
        . '<input class="input" id="displayName" name="displayName" type="text" value="' . h($displayName) . '" placeholder="Jeśli puste — będzie nazwa pliku" />'
        . '<label class="label" for="category">Kategoria</label>'
        . '<select class="input" id="category" name="category">' . $catOptions . '</select>'
        . '<div class="row"><div class="muted small">Hasło do linku: ' . ($passwordSet ? 'ustawione' : 'brak') . '</div></div>'
        . ($passwordSet
            ? ($currentPassword !== ''
                ? '<div class="row"><div class="muted small">Aktualne hasło: <span class="mono">' . h($currentPassword) . '</span> <button class="button buttonSecondary buttonXs" type="button" data-copy="' . h($currentPassword) . '">Kopiuj hasło</button></div></div>'
                : '<div class="row"><div class="muted small">Aktualne hasło: (nie do odczytania)</div></div>'
                . '<label class="label" for="existingSharePassword">Jeśli znasz aktualne hasło, wpisz je tu (żeby dało się je kopiować)</label>'
                . '<input class="input" id="existingSharePassword" name="existingSharePassword" type="password" autocomplete="current-password" />'
                . '<div class="row"><button class="button buttonSecondary" type="submit" name="action" value="remember">Zapisz do kopiowania</button></div>')
            : '')
        . '<label class="label" for="sharePassword">Ustaw / zmień hasło linku (opcjonalnie)</label>'
        . '<input class="input" id="sharePassword" name="sharePassword" type="password" autocomplete="new-password" placeholder="Wpisz nowe hasło, aby ustawić lub zmienić" />'
        . '<label class="row"><input type="checkbox" name="removePassword" value="1" /> <span class="muted small">Usuń hasło</span></label>'
        . '<div class="row">'
        . '<button class="button buttonPrimary" type="submit" name="action" value="save">Zapisz</button>'
        . '<button class="button buttonSecondary" type="submit" name="action" value="regen">Regeneruj link</button>'
        . '<button class="button buttonGhost" type="submit" name="action" value="genpass">Generuj hasło</button>'
        . '<a class="button buttonGhost" href="/admin">Wróć</a>'
        . '</div>'
        . '</form>'
        . '<div class="fileBox">'
        . '<div class="fileName">Wyślij link mailem</div>'
        . '<div class="muted small">Wysyłka działa przez funkcję <span class="mono">mail()</span> (bez PHPMailer). Na niektórych hostingach wymaga konfiguracji.</div>'
        . '</div>'
        . '<form class="form" method="post" action="/send-email">'
        . '<input type="hidden" name="csrf" value="' . h($csrf) . '" />'
        . '<input type="hidden" name="id" value="' . h($editId) . '" />'
        . '<label class="label" for="to">Adres e-mail</label>'
        . '<input class="input" id="to" name="to" type="email" placeholder="np. klient@firma.pl" required />'
        . '<label class="label" for="subject">Temat</label>'
        . '<input class="input" id="subject" name="subject" type="text" value="' . h($defaultSubject) . '" />'
        . '<label class="label" for="pw">Hasło (jeśli ustawione)</label>'
        . '<input class="input" id="pw" name="pw" type="text" value="' . h($currentPassword) . '" placeholder="Wpisz hasło, które chcesz wysłać" />'
        . '<label class="label" for="message">Wiadomość</label>'
        . '<textarea class="input" id="message" name="message" rows="6">' . h($defaultMessage) . '</textarea>'
        . '<div class="row">'
        . '<button class="button buttonPrimary" type="submit">Wyślij</button>'
        . '</div>'
        . '</form>'
        . '</main>';

    $body = renderShell('Panel plików', 'Edycja danych i linku udostępniania.', $main);
    renderPage('Panel — Edycja', $body);
    exit;
}

if ($requestPath === '/edit' && $method === 'POST') {
    requireAuth();
    requireCsrf();
    $id = (string) ($_POST['id'] ?? '');
    if (!preg_match('/^[a-f0-9]{16,64}$/', $id)) {
        renderError('Błąd', 'Nieprawidłowe ID.', 400);
        exit;
    }
    $db = readFilesDb();
    $found = findById($db, $id);
    if ($found === null) {
        renderError('Nie znaleziono', 'Taki plik nie istnieje.');
        exit;
    }
    $idx = (int) $found['index'];
    $action = (string) ($_POST['action'] ?? 'save');
    if ($action === 'regen') {
        $db['files'][$idx]['token'] = bin2hex(random_bytes(16));
        writeFilesDb($db);
        header('Location: /edit/' . rawurlencode($id), true, 302);
        exit;
    }
    if ($action === 'remember') {
        $existing = (string) ($_POST['existingSharePassword'] ?? '');
        $hash = (string) ($db['files'][$idx]['sharePasswordHash'] ?? '');
        if ($existing === '' || $hash === '' || !password_verify($existing, $hash)) {
            header('Location: /edit/' . rawurlencode($id) . '?pw=0', true, 302);
            exit;
        }
        $enc = encryptShareSecret($existing);
        if ($enc !== '') {
            $db['files'][$idx]['sharePasswordEnc'] = $enc;
        }
        writeFilesDb($db);
        oneTimePasswordStore($id, $existing);
        header('Location: /edit/' . rawurlencode($id) . '?pw=1', true, 302);
        exit;
    }
    if ($action === 'genpass') {
        $newPassword = bin2hex(random_bytes(4));
        $db['files'][$idx]['sharePasswordHash'] = password_hash($newPassword, PASSWORD_DEFAULT);
        $db['files'][$idx]['sharePasswordEnc'] = encryptShareSecret($newPassword);
        writeFilesDb($db);
        oneTimePasswordStore($id, $newPassword);
        header('Location: /edit/' . rawurlencode($id), true, 302);
        exit;
    }
    $displayName = trim((string) ($_POST['displayName'] ?? ''));
    if ($displayName !== '' && mb_strlen($displayName) > 140) {
        $displayName = mb_substr($displayName, 0, 140);
    }
    $category = normalizeCategory((string) ($_POST['category'] ?? 'inne'));
    $db['files'][$idx]['displayName'] = $displayName;
    $db['files'][$idx]['category'] = $category;
    $removePassword = ((string) ($_POST['removePassword'] ?? '')) === '1';
    $sharePassword = trim((string) ($_POST['sharePassword'] ?? ''));
    if ($sharePassword !== '' && mb_strlen($sharePassword) > 80) {
        $sharePassword = mb_substr($sharePassword, 0, 80);
    }
    if ($removePassword) {
        unset($db['files'][$idx]['sharePasswordHash']);
        unset($db['files'][$idx]['sharePasswordEnc']);
    } elseif ($sharePassword !== '') {
        $db['files'][$idx]['sharePasswordHash'] = password_hash($sharePassword, PASSWORD_DEFAULT);
        $db['files'][$idx]['sharePasswordEnc'] = encryptShareSecret($sharePassword);
        oneTimePasswordStore($id, $sharePassword);
    }
    writeFilesDb($db);
    header('Location: /admin', true, 302);
    exit;
}

if ($requestPath === '/send-email' && $method === 'POST') {
    requireAuth();
    requireCsrf();
    $id = (string) ($_POST['id'] ?? '');
    if (!preg_match('/^[a-f0-9]{16,64}$/', $id)) {
        renderError('Błąd', 'Nieprawidłowe ID.', 400);
        exit;
    }
    $to = trim((string) ($_POST['to'] ?? ''));
    if ($to === '' || filter_var($to, FILTER_VALIDATE_EMAIL) === false) {
        header('Location: /edit/' . rawurlencode($id) . '?mail=0', true, 302);
        exit;
    }
    $subject = trim((string) ($_POST['subject'] ?? 'Udostępniony plik'));
    if ($subject === '') {
        $subject = 'Udostępniony plik';
    }
    $message = (string) ($_POST['message'] ?? '');
    $pw = trim((string) ($_POST['pw'] ?? ''));

    $db = readFilesDb();
    $found = findById($db, $id);
    if ($found === null) {
        header('Location: /admin', true, 302);
        exit;
    }
    $file = $found['file'];
    $token = (string) ($file['token'] ?? $id);
    $shareUrl = baseUrl() . '/s/' . rawurlencode($token);
    $name = displayNameFor($file);

    $final = "Udostępniony plik: {$name}\n";
    $final .= "Link: {$shareUrl}\n";
    if ($pw !== '') {
        $final .= "Hasło: {$pw}\n";
    }
    $final .= "\n";
    $final .= $message;

    $headers = [];
    $headers[] = 'MIME-Version: 1.0';
    $headers[] = 'Content-type: text/plain; charset=UTF-8';
    $headers[] = 'From: Commerion Group <hello@commeriongroup.com>';
    $headers[] = 'Reply-To: hello@commeriongroup.com';

    $ok = @mail($to, $subject, $final, implode("\r\n", $headers));
    header('Location: /edit/' . rawurlencode($id) . '?mail=' . ($ok ? '1' : '0'), true, 302);
    exit;
}

if ($requestPath === '/delete' && $method === 'POST') {
    requireAuth();
    requireCsrf();
    $id = (string) ($_POST['id'] ?? '');
    if (!preg_match('/^[a-f0-9]{16,64}$/', $id)) {
        renderError('Błąd', 'Nieprawidłowe ID.', 400);
        exit;
    }
    $db = readFilesDb();
    $found = findById($db, $id);
    if ($found === null) {
        header('Location: /admin', true, 302);
        exit;
    }
    $file = $found['file'];
    $storedName = (string) ($file['storedName'] ?? '');
    $absolutePath = __DIR__ . '/uploads/' . $storedName;
    if ($storedName !== '' && is_file($absolutePath)) {
        @unlink($absolutePath);
    }
    array_splice($db['files'], (int) $found['index'], 1);
    writeFilesDb($db);
    header('Location: /admin', true, 302);
    exit;
}

$downloadId = parseIdFromPath($requestPath, '/download/');
if ($downloadId !== null && $method === 'GET') {
    requireAuth();
    $db = readFilesDb();
    $found = findByIdOrToken($db, $downloadId);
    if ($found === null) {
        renderError('Nie znaleziono', 'Taki plik nie istnieje.');
        exit;
    }
    $file = $found['file'];

    $storedName = (string) ($file['storedName'] ?? '');
    $originalName = (string) ($file['originalName'] ?? 'download');
    $absolutePath = __DIR__ . '/uploads/' . $storedName;
    if (!is_file($absolutePath)) {
        renderError('Brak pliku', 'Plik został usunięty z dysku.');
        exit;
    }

    header('Content-Type: application/octet-stream');
    header('Content-Length: ' . (string) filesize($absolutePath));
    header('Content-Disposition: ' . contentDisposition($originalName));
    header('X-Content-Type-Options: nosniff');
    readfile($absolutePath);
    exit;
}

$dlToken = parseIdFromPath($requestPath, '/dl/');
if ($dlToken !== null && $method === 'GET') {
    $db = readFilesDb();
    $found = findByToken($db, $dlToken);
    if ($found === null) {
        renderError('Nie znaleziono', 'Taki plik nie istnieje.');
        exit;
    }
    $file = $found['file'];
    requireShareUnlockedFor($file, $dlToken);
    $storedName = (string) ($file['storedName'] ?? '');
    $originalName = (string) ($file['originalName'] ?? 'download');
    $absolutePath = __DIR__ . '/uploads/' . $storedName;
    if (!is_file($absolutePath)) {
        renderError('Brak pliku', 'Plik został usunięty z dysku.');
        exit;
    }
    header('Content-Type: application/octet-stream');
    header('Content-Length: ' . (string) filesize($absolutePath));
    header('Content-Disposition: ' . contentDisposition($originalName));
    header('X-Content-Type-Options: nosniff');
    readfile($absolutePath);
    exit;
}

$viewToken = parseIdFromPath($requestPath, '/view/');
if ($viewToken !== null && $method === 'GET') {
    $db = readFilesDb();
    $found = findByToken($db, $viewToken);
    if ($found === null) {
        http_response_code(404);
        exit;
    }
    $file = $found['file'];
    requireShareUnlockedFor($file, $viewToken);
    $storedName = (string) ($file['storedName'] ?? '');
    $originalName = (string) ($file['originalName'] ?? 'file');
    $absolutePath = __DIR__ . '/uploads/' . $storedName;
    if (!is_file($absolutePath)) {
        http_response_code(404);
        exit;
    }

    $mime = detectMimeType($absolutePath, (string) ($file['mime'] ?? 'application/octet-stream'));
    $inlineOk = isInlineSafeMime($mime);
    if (!$inlineOk) {
        $mime = 'application/octet-stream';
    }

    header('Content-Type: ' . $mime);
    header('Content-Length: ' . (string) filesize($absolutePath));
    header('Content-Disposition: ' . ($inlineOk ? 'inline' : contentDisposition($originalName)));
    header('X-Content-Type-Options: nosniff');
    readfile($absolutePath);
    exit;
}

$shareId = parseIdFromPath($requestPath, '/s/');
if ($shareId !== null && $method === 'POST') {
    requireCsrf();
    $db = readFilesDb();
    $found = findByToken($db, $shareId);
    if ($found === null) {
        renderError('Nie znaleziono', 'Taki link nie jest aktywny.');
        exit;
    }
    $file = $found['file'];
    if (!isShareProtected($file)) {
        setShareUnlocked($shareId);
        header('Location: /s/' . rawurlencode($shareId), true, 302);
        exit;
    }
    $password = (string) ($_POST['password'] ?? '');
    $hash = (string) ($file['sharePasswordHash'] ?? '');
    if ($hash !== '' && $password !== '' && password_verify($password, $hash)) {
        setShareUnlocked($shareId);
        header('Location: /s/' . rawurlencode($shareId), true, 302);
        exit;
    }
    header('Location: /s/' . rawurlencode($shareId) . '?error=1', true, 302);
    exit;
}

if ($shareId !== null && $method === 'GET') {
    $db = readFilesDb();
    $found = findByToken($db, $shareId);
    if ($found === null) {
        renderError('Nie znaleziono', 'Taki link nie jest aktywny.');
        exit;
    }
    $file = $found['file'];

    if (isShareProtected($file) && !isShareUnlocked($shareId)) {
        $error = ((string) ($_GET['error'] ?? '')) === '1';
        $csrf = csrfToken();
        $name = displayNameFor($file);
        $content = '<div class="page">'
            . '<header class="header headerPublic"><img class="logo" src="/logo.png" alt="Logo" /></header>'
            . '<main class="card cardPublic">'
            . '<h1 class="title">Zabezpieczony link</h1>'
            . '<div class="fileBox"><div class="fileName">' . h($name) . '</div><div class="muted">Wymagane hasło do otwarcia pliku.</div></div>'
            . '<form class="form" method="post" action="/s/' . h(rawurlencode($shareId)) . '">'
            . '<input type="hidden" name="csrf" value="' . h($csrf) . '" />'
            . '<label class="label" for="password">Hasło</label>'
            . '<input class="input" id="password" name="password" type="password" autocomplete="current-password" required />'
            . ($error ? '<div class="alert">Nieprawidłowe hasło.</div>' : '')
            . '<button class="button buttonPrimary" type="submit">Otwórz</button>'
            . '</form>'
            . '</main>'
            . renderFooter()
            . '</div>';
        renderPage('Zabezpieczony link', $content);
        exit;
    }

    $originalName = displayNameFor($file);
    $size = (int) ($file['size'] ?? 0);
    $direct = baseUrl() . '/dl/' . rawurlencode($shareId);
    $absolutePath = __DIR__ . '/uploads/' . (string) ($file['storedName'] ?? '');
    $mime = is_file($absolutePath) ? detectMimeType($absolutePath, (string) ($file['mime'] ?? 'application/octet-stream')) : (string) ($file['mime'] ?? 'application/octet-stream');

    $preview = '';
    if (isPreviewSafeMime($mime)) {
        $src = '/view/' . h(rawurlencode($shareId));
        if (str_starts_with($mime, 'image/')) {
            $preview = '<div class="preview"><img class="previewImg" src="' . $src . '" alt="' . h($originalName) . '" /></div>';
        } elseif ($mime === 'application/pdf') {
            $preview = '<div class="preview"><iframe class="previewFrame" src="' . $src . '" title="Podgląd pliku"></iframe></div>';
        } elseif (str_starts_with($mime, 'audio/')) {
            $preview = '<div class="preview"><audio class="previewAudio" controls src="' . $src . '"></audio></div>';
        } elseif (str_starts_with($mime, 'video/')) {
            $preview = '<div class="preview"><video class="previewVideo" controls src="' . $src . '"></video></div>';
        }
    } elseif (str_starts_with($mime, 'text/plain') && is_file($absolutePath)) {
        $text = readTextPreview($absolutePath);
        if ($text !== '') {
            $preview = '<div class="preview"><pre class="previewText">' . h($text) . '</pre></div>';
        }
    }

    $content = '<div class="page">'
        . '<header class="header headerPublic"><img class="logo" src="/logo.png" alt="Logo" /></header>'
        . '<main class="card cardPublic">'
        . '<h1 class="title">Udostępniony plik</h1>'
        . '<div class="fileBox">'
        . '<div class="fileName">' . h($originalName) . '</div>'
        . '<div class="muted">' . h(formatBytes($size)) . '</div>'
        . '</div>'
        . $preview
        . '<div class="row">'
        . '<a class="button buttonPrimary" href="/dl/' . h(rawurlencode($shareId)) . '">Pobierz</a>'
        . '<a class="button buttonSecondary" href="/view/' . h(rawurlencode($shareId)) . '" target="_blank" rel="noreferrer">Otwórz</a>'
        . '<a class="button buttonGhost" href="' . h($direct) . '">Link bezpośredni</a>'
        . '</div>'
        . '<div class="footerNote muted">Link firmowy — bez rejestracji, bez reklam.</div>'
        . '</main>'
        . renderFooter()
        . '</div>';

    renderPage('Udostępniony plik', $content);
    exit;
}

renderError('Nie znaleziono', 'Ta strona nie istnieje.');
