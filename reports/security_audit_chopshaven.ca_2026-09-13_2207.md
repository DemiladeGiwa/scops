# 🔒 Security Audit: chopshaven.ca

**Date:** September 13, 2026 22:07  
**Target:** https://chopshaven.ca  
**Platform:** WordPress 6.8.6 — server: hcdn  

---

## 🚨 Critical Vulnerabilities

### 1. User Enumeration via REST API — Usernames Fully Exposed

> [!CAUTION]
> The WordPress REST API publicly exposes registered usernames, giving an attacker half the credentials needed for a brute-force login attempt.

**What's exposed:** `https://chopshaven.ca/wp-json/wp/v2/users`

The WordPress REST API publicly exposes registered usernames, giving an attacker half the credentials needed for a brute-force login attempt.

| User ID | Display Name | Username (slug) |
|---|---|---|
| 2 | Himani Panwar | himanipanwar |
| 1 | spidersdevadmin | spidersdevadmin |
| 3 | Stephen Isiuwe | ekene_super_admin |

**Fix:**
```php
// Add to functions.php — block REST user enumeration for logged-out visitors
add_filter('rest_endpoints', function($endpoints) {
    if (!is_user_logged_in()) {
        unset($endpoints['/wp/v2/users']);
        unset($endpoints['/wp/v2/users/(?P<id>[\d]+)']);
    }
    return $endpoints;
});
```

---

### 2. User Enumeration via Author Archives

> [!CAUTION]
> Author archive pages leak usernames through the page `<title>` tag / canonical author URL, without needing the REST API.

**What's exposed:** `https://chopshaven.ca/?author=1`

Author archive pages leak usernames through the page `<title>` tag / canonical author URL, without needing the REST API.

- `?author=4` → page title `Chopshaven` (https://chopshaven.ca/?author=4)
- `?author=5` → page title `Chopshaven` (https://chopshaven.ca/?author=5)

**Fix:**
```php
// Add to functions.php — redirect author archive queries
add_action('template_redirect', function() {
    if (is_author()) {
        wp_redirect(home_url(), 301);
        exit;
    }
});
```

---

## ⚠️ High-Severity Issues

### 3. wp-login.php Publicly Accessible — No Rate Limiting Detected

> [!WARNING]
> The default WordPress login page is reachable with no visible CAPTCHA, 2FA, or rate-limiting markers in the page source. This is a **best-effort heuristic** — some protections (server-side rate limiting, IP-based lockouts) don't show up in the HTML and may still be active. Treat this as 'worth confirming,' not conclusive.

**What's exposed:** `https://chopshaven.ca/wp-login.php`

The default WordPress login page is reachable with no visible CAPTCHA, 2FA, or rate-limiting markers in the page source. This is a **best-effort heuristic** — some protections (server-side rate limiting, IP-based lockouts) don't show up in the HTML and may still be active. Treat this as 'worth confirming,' not conclusive.

**Fix:**
```
1. Install Wordfence or Limit Login Attempts Reloaded
2. Add two-factor authentication (e.g. WP 2FA plugin)
3. Consider a custom login URL (WPS Hide Login)
4. Add CAPTCHA to the login form
```

---

### 4. WordPress readme.html Exposed

> [!WARNING]
> The default WordPress `readme.html` is publicly reachable, confirming the CMS and often the version.

**What's exposed:** `https://chopshaven.ca/readme.html`

The default WordPress `readme.html` is publicly reachable, confirming the CMS and often the version.

**Fix:**
```apache
# In .htaccess
<Files readme.html>
  Order Deny,Allow
  Deny from all
</Files>
```

---

### 5. WordPress Version Number Exposed in HTML Source

> [!WARNING]
> The exact WordPress/asset version is visible in the page source.

**What's exposed:** `https://chopshaven.ca`

The exact WordPress/asset version is visible in the page source.

`<meta name="generator" content="WordPress 6.8.6">`
Asset query strings: `?ver=06758`, `?ver=1.9`, `?ver=1789336136`, `?ver=2.19.3`, `?ver=4`, `?ver=5`, `?ver=6.0.6`, `?ver=6.8.6`

**Fix:**
```php
// Add to functions.php
remove_action('wp_head', 'wp_generator');

add_filter('style_loader_src', function($src) { return remove_query_arg('ver', $src); });
add_filter('script_loader_src', function($src) { return remove_query_arg('ver', $src); });
```

---

## 🔶 Medium-Severity Issues

### 6. Missing Security Headers

> [!IMPORTANT]
> Missing/leaking HTTP response headers:

**What's exposed:** `https://chopshaven.ca`

Missing/leaking HTTP response headers:

| Header | Status |
|---|---|
| `X-Frame-Options` | ✅ Present |
| `X-Content-Type-Options` | ✅ Present |
| `Strict-Transport-Security` | ✅ Present |
| `Referrer-Policy` | ✅ Present |
| `Permissions-Policy` | ✅ Present |
| `Content-Security-Policy` | ✅ Present |

Also exposed: `X-Powered-By: PHP/8.3.33`, `Platform: hostinger`

**Fix:**
```apache
<IfModule mod_headers.c>
  Header always set X-Frame-Options "SAMEORIGIN"
  Header always set X-Content-Type-Options "nosniff"
  Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
  Header always set Referrer-Policy "strict-origin-when-cross-origin"
  Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"
  Header always unset X-Powered-By
</IfModule>
```

---

### 7. Plugin & Theme Version Numbers Exposed

> [!IMPORTANT]
> Plugin/theme names and versions visible in page source (usable to look up known CVEs):

**What's exposed:** `https://chopshaven.ca`

Plugin/theme names and versions visible in page source (usable to look up known CVEs):

| Plugin/Theme | Version |
|---|---|
| `astra-sites` | 06758 |
| `chopshaven-wp-theme` | 1.9 |
| `contact-form-7` | 6.0.6 |
| `ultimate-addons-for-gutenberg` | 2.19.3 |

**Fix:**
```
Strip `?ver=` query strings from enqueued assets, and keep all plugins/themes updated regardless.
```

---

### 8. WP-JSON / REST API Fully Exposed

> [!IMPORTANT]
> The full WordPress REST API root is publicly reachable, exposing site structure, content types, and routes.

**What's exposed:** `https://chopshaven.ca/wp-json/`

The full WordPress REST API root is publicly reachable, exposing site structure, content types, and routes.

**Fix:**
```
Restrict with a plugin (e.g. Disable REST API) if the API isn't needed by the front end, or limit exposed routes via `rest_endpoints`.
```

---

## 📊 Attack Chain Summary

```
Step 1: User Enumeration via REST API — Usernames Fully Exposed
Step 2: User Enumeration via Author Archives
Step 3: wp-login.php Publicly Accessible — No Rate Limiting Detected
Step 4: WordPress readme.html Exposed
Step 5: WordPress Version Number Exposed in HTML Source
```

> [!CAUTION]
> The findings above can plausibly be chained together into a realistic path toward account or site compromise. Treat critical items as top priority.

---

## ✅ Recommended Fixes — Priority Order

| Priority | Fix | Difficulty | Time |
|---|---|---|---|
| 🔴 **P0** | User Enumeration via REST API — Usernames Fully Exposed | Easy–Medium | 5–20 min |
| 🔴 **P0** | User Enumeration via Author Archives | Easy–Medium | 5–20 min |
| 🟠 **P1** | wp-login.php Publicly Accessible — No Rate Limiting Detected | Easy–Medium | 5–20 min |
| 🟠 **P1** | WordPress readme.html Exposed | Easy–Medium | 5–20 min |
| 🟠 **P1** | WordPress Version Number Exposed in HTML Source | Easy–Medium | 5–20 min |
| 🟡 **P2** | Missing Security Headers | Easy–Medium | 5–20 min |
| 🟡 **P2** | Plugin & Theme Version Numbers Exposed | Easy–Medium | 5–20 min |
| 🟡 **P2** | WP-JSON / REST API Fully Exposed | Easy–Medium | 5–20 min |

---

## ✔️ Passed Checks

- XML-RPC exposure — no issue found
