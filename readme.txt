=== Login Limit ===
Contributors: saizul
Tags: brute force, login, security, lockout, fail2ban
Requires at least: 6.2
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 0.1.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Brute-force protection: failed login limits per IP and username with escalating lockouts on wp-login.php, XML-RPC and application passwords.

== Description ==

Login Limit slows down password guessing without captchas, external services or upsells, and it gets the client IP right behind proxies and CDNs.

**Limits**

* Failed logins per IP (IPv6 counted per /64 network) and per username.
* Escalating lockouts: 15 minutes, 1 hour, 4 hours, 16 hours, then 24 hours (all configurable).
* A username lockout does not block networks the user logged in from before.
* Works on wp-login.php and login forms that use wp_signon(), XML-RPC and REST API application passwords.
* Option to disable XML-RPC authentication entirely.

**Client IP**

* Proxy headers are read only from trusted proxies you list (CIDR ranges allowed).
* X-Forwarded-For, X-Real-IP or CF-Connecting-IP; one switch for Cloudflare's published ranges.

**More**

* Allowlist and denylist with IPv4/IPv6 addresses and CIDR ranges.
* Generic error messages that do not reveal usernames.
* Active lockouts with one-click unlock, and a lockout log.
* Throttled admin email alerts.
* Optional fail2ban-friendly lines in the PHP error log.
* WP-CLI: wp login-limit unlock, list, log, check.

== Installation ==

1. Upload the plugin folder to /wp-content/plugins/ or install the zip from Plugins > Add New > Upload Plugin.
2. Activate Login Limit. The defaults protect the site right away.
3. Open Settings > Login Limit and check "Your IP address as this plugin sees it". Behind a proxy or CDN, add the proxy to Trusted proxies or tick Cloudflare.

== Frequently Asked Questions ==

= I locked myself out. =

Wait for the lockout to end, run wp login-limit unlock with your IP address, or rename the plugin folder over SFTP. Then add your IP to the allowlist.

= Everyone gets locked out at once. =

The site is behind a proxy that is not trusted yet, so every visitor shares the proxy's address. Add the proxy under Trusted proxies.

= Does it work with WooCommerce and other login forms? =

Yes, with every form that logs in through wp_signon() or wp_authenticate().

= What data is stored? =

Failure counters per IP and username, a lockout log, and per user the last 10 networks they logged in from. Everything is removed on uninstall.

== Changelog ==

= 0.1.0 =
* First release.
