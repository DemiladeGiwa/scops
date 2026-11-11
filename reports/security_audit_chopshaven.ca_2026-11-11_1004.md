# 🔒 Security Audit: chopshaven.ca

**Date:** November 11, 2026 10:04  
**Target:** https://chopshaven.ca  
**Platform:** WordPress (version not disclosed) — server: hcdn  

---

## 🚨 Critical Vulnerabilities

### 1. User Enumeration via Author Archives

> [!CAUTION]
> Author archive pages leak usernames through the page `<title>` tag / canonical author URL, without needing the REST API.

**What's exposed:** `https://chopshaven.ca/?author=1`

Author archive pages leak usernames through the page `<title>` tag / canonical author URL, without needing the REST API.

- `?author=1` → page title `WordPress &rsaquo; Error` (https://chopshaven.ca/?author=1)
- `?author=2` → page title `WordPress &rsaquo; Error` (https://chopshaven.ca/?author=2)
- `?author=3` → page title `WordPress &rsaquo; Error` (https://chopshaven.ca/?author=3)
- `?author=4` → page title `WordPress &rsaquo; Error` (https://chopshaven.ca/?author=4)
- `?author=5` → page title `WordPress &rsaquo; Error` (https://chopshaven.ca/?author=5)

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

### 2. WordPress readme.html Exposed

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

## 🔶 Medium-Severity Issues

### 3. Missing Security Headers

> [!IMPORTANT]
> Missing/leaking HTTP response headers:

**What's exposed:** `https://chopshaven.ca`

Missing/leaking HTTP response headers:

| Header | Status |
|---|---|
| `X-Frame-Options` | ❌ Missing |
| `X-Content-Type-Options` | ❌ Missing |
| `Strict-Transport-Security` | ❌ Missing |
| `Referrer-Policy` | ❌ Missing |
| `Permissions-Policy` | ❌ Missing |
| `Content-Security-Policy` | ✅ Present |

Also exposed: `X-Powered-By: PHP/8.3.36`, `Platform: hostinger`

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

## 📊 Attack Chain Summary

```
Step 1: User Enumeration via Author Archives
Step 2: WordPress readme.html Exposed
```

> [!CAUTION]
> The findings above can plausibly be chained together into a realistic path toward account or site compromise. Treat critical items as top priority.

---

## ✅ Recommended Fixes — Priority Order

| Priority | Fix | Difficulty | Time |
|---|---|---|---|
| 🔴 **P0** | User Enumeration via Author Archives | Easy–Medium | 5–20 min |
| 🟠 **P1** | WordPress readme.html Exposed | Easy–Medium | 5–20 min |
| 🟡 **P2** | Missing Security Headers | Easy–Medium | 5–20 min |

---

## ✔️ Passed Checks

- XML-RPC exposure — no issue found
- User enumeration via REST API — no issue found
- Login hardening (wp-login.php) — no issue found
- Version disclosure — no issue found
- Plugin/theme version exposure — no issue found
- REST API root exposure — no issue found
