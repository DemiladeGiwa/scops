# 🔒 Security Audit: chopshaven.ca

**Date:** September 13, 2026 23:15  
**Target:** https://chopshaven.ca  
**Platform:** WordPress 7.1 — server: hcdn  

---

## 🚨 Critical Vulnerabilities

### 1. User Enumeration via Author Archives

> [!CAUTION]
> Author archive pages leak usernames through the page `<title>` tag / canonical author URL, without needing the REST API.

**What's exposed:** `https://chopshaven.ca/?author=1`

Author archive pages leak usernames through the page `<title>` tag / canonical author URL, without needing the REST API.

- `?author=1` → page title `403 Forbidden` (https://chopshaven.ca/?author=1)
- `?author=2` → page title `403 Forbidden` (https://chopshaven.ca/?author=2)
- `?author=4` → page title `403 Forbidden` (https://chopshaven.ca/?author=4)
- `?author=5` → page title `403 Forbidden` (https://chopshaven.ca/?author=5)

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

### 2. WordPress Version Number Exposed in HTML Source

> [!WARNING]
> The exact WordPress/asset version is visible in the page source.

**What's exposed:** `https://chopshaven.ca`

The exact WordPress/asset version is visible in the page source.

`<meta name="generator" content="WordPress 7.1">`
Asset query strings: `?ver=089983451`, `?ver=1`, `?ver=1.9`, `?ver=1789336136`, `?ver=2.20.3`, `?ver=3`, `?ver=6.0.6`, `?ver=7.1`

**Fix:**
```php
// Add to functions.php
remove_action('wp_head', 'wp_generator');

add_filter('style_loader_src', function($src) { return remove_query_arg('ver', $src); });
add_filter('script_loader_src', function($src) { return remove_query_arg('ver', $src); });
```

---

## 🔶 Medium-Severity Issues

### 3. Missing Security Headers

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

### 4. WP-JSON / REST API Fully Exposed

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
Step 1: User Enumeration via Author Archives
Step 2: WordPress Version Number Exposed in HTML Source
```

> [!CAUTION]
> The findings above can plausibly be chained together into a realistic path toward account or site compromise. Treat critical items as top priority.

---

## ✅ Recommended Fixes — Priority Order

| Priority | Fix | Difficulty | Time |
|---|---|---|---|
| 🔴 **P0** | User Enumeration via Author Archives | Easy–Medium | 5–20 min |
| 🟠 **P1** | WordPress Version Number Exposed in HTML Source | Easy–Medium | 5–20 min |
| 🟡 **P2** | Missing Security Headers | Easy–Medium | 5–20 min |
| 🟡 **P2** | WP-JSON / REST API Fully Exposed | Easy–Medium | 5–20 min |

---

## ✔️ Passed Checks

- XML-RPC exposure — no issue found
- User enumeration via REST API — no issue found
- Login hardening (wp-login.php) — no issue found
- readme.html exposure — no issue found
- Plugin/theme version exposure — no issue found
