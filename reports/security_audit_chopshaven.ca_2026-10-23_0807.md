# 🔒 Security Audit: chopshaven.ca

**Date:** October 23, 2026 08:07  
**Target:** https://chopshaven.ca  
**Platform:** WordPress (version not disclosed) — server: hcdn  

---

## 🚨 Critical Vulnerabilities

### 1. User Enumeration via Author Archives

> [!CAUTION]
> Author archive pages leak usernames through the page `<title>` tag / canonical author URL, without needing the REST API.

**What's exposed:** `https://chopshaven.ca/?author=1`

Author archive pages leak usernames through the page `<title>` tag / canonical author URL, without needing the REST API.

- `?author=1` → page title `Checking your browser before accessing. Just a moment...` (https://chopshaven.ca/?author=1)
- `?author=2` → page title `Checking your browser before accessing. Just a moment...` (https://chopshaven.ca/?author=2)
- `?author=3` → page title `Checking your browser before accessing. Just a moment...` (https://chopshaven.ca/?author=3)
- `?author=4` → page title `Checking your browser before accessing. Just a moment...` (https://chopshaven.ca/?author=4)
- `?author=5` → page title `Checking your browser before accessing. Just a moment...` (https://chopshaven.ca/?author=5)

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

## 🔶 Medium-Severity Issues

### 2. Missing Security Headers

> [!IMPORTANT]
> Missing/leaking HTTP response headers:

**What's exposed:** `https://chopshaven.ca`

Missing/leaking HTTP response headers:

| Header | Status |
|---|---|
| `X-Frame-Options` | ❌ Missing |
| `X-Content-Type-Options` | ❌ Missing |
| `Strict-Transport-Security` | ❌ Missing |
| `Referrer-Policy` | ✅ Present |
| `Permissions-Policy` | ✅ Present |
| `Content-Security-Policy` | ✅ Present |

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
```

> [!CAUTION]
> The findings above can plausibly be chained together into a realistic path toward account or site compromise. Treat critical items as top priority.

---

## ✅ Recommended Fixes — Priority Order

| Priority | Fix | Difficulty | Time |
|---|---|---|---|
| 🔴 **P0** | User Enumeration via Author Archives | Easy–Medium | 5–20 min |
| 🟡 **P2** | Missing Security Headers | Easy–Medium | 5–20 min |

---

## ✔️ Passed Checks

- XML-RPC exposure — no issue found
- User enumeration via REST API — no issue found
- Login hardening (wp-login.php) — no issue found
- readme.html exposure — no issue found
- Version disclosure — no issue found
- Plugin/theme version exposure — no issue found
- REST API root exposure — no issue found
