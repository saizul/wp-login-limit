# Security policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | yes       |

## Reporting a vulnerability

Please do **not** open a public issue. Use GitHub's private vulnerability
reporting ("Security" tab, "Report a vulnerability") on
<https://github.com/saizul/wp-login-limit>.

Include the affected version, a description and steps to reproduce. You can
expect an acknowledgement within 7 days. Please give us reasonable time to
release a fix before disclosing the issue.

Bypasses are security bugs too: a way to make more attempts than the limits
allow, to spoof the client IP without a trusted proxy, to tell a right
password from a wrong one during a lockout, or to forge fail2ban lines.

## How the plugin protects your site

- **Client IP**: only `REMOTE_ADDR` is trusted unless it is a configured
  trusted proxy or (when enabled) one of Cloudflare's published ranges.
  `X-Forwarded-For` is walked from the right, skipping trusted proxies, so a
  client cannot inject an address; invalid entries stop the walk; header
  length and hop count are bounded.
- **Counting**: failures are stored in a custom table (an object cache cannot
  evict them). Attempts during a lockout are refused before the password
  result is used and get the same error either way. Email addresses of
  existing users count as their login.
- **Coverage**: wp-login.php and `wp_signon()` forms, XML-RPC (or XML-RPC
  authentication switched off with `xmlrpc_enabled`), and REST API
  application passwords (`429`/`403` error for locked or denied clients).
- **Messages**: unknown usernames and wrong passwords get the same message
  (setting on by default).
- **Admin**: Settings > Login Limit requires `manage_options` (filterable
  with `login_limit_capability`). Settings use the Settings API; unlocking
  (one nonce per record), unlocking everyone and clearing the log each check
  the capability and a nonce.
- **Input**: IP lists keep only valid addresses and CIDR ranges (at most
  500), numbers are clamped, choices are allowlisted, the email address is
  validated.
- **Output**: everything on the settings screen is escaped. fail2ban lines
  reduce usernames to safe characters, so a crafted username cannot forge a
  line or an address.
- **SQL**: every query uses `$wpdb->prepare()`; table names use `%i`.
- **No remote requests**, no tracking, no external assets.
- **Uninstall** drops both tables, deletes the options and the cron event on
  every site, and removes the per-user known networks.

Login Limit slows down password guessing; it does not replace strong
passwords or two-factor authentication.
