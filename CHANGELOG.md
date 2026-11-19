# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-11-19

### Added

- Failed login limits per IP (IPv6 counted per configurable network, /64 by
  default) and per username, in a fixed counting window.
- Escalating lockouts: first lockout, multiplier, maximum and reset period
  (defaults 15 min, x4, 24 h, 24 h).
- Known networks per user: a username lockout does not block networks the
  user logged in from before.
- Coverage of wp-login.php and `wp_signon()` forms, XML-RPC and REST API
  application passwords, with identical answers for right and wrong
  passwords during a lockout.
- Option to disable XML-RPC authentication entirely.
- Trusted proxies with `X-Forwarded-For` (walked from the right), `X-Real-IP`
  or `CF-Connecting-IP`, and a Cloudflare switch with the published ranges.
- Allowlist and denylist with IPv4/IPv6 addresses and CIDR ranges;
  "lock out at once" usernames.
- Generic login error messages.
- Settings > Login Limit: client IP check with proxy hint, active lockouts
  with unlock, settings, lockout log.
- Throttled admin email with a count of suppressed lockouts.
- fail2ban-friendly lines in the PHP error log, with example filter and jail.
- WP-CLI: `wp login-limit unlock|list|log|check`.
- Hooks: `login_limit_lockout`, `login_limit_refused`,
  `login_limit_client_ip`, `login_limit_send_notification`,
  `login_limit_fail2ban_write`, `login_limit_capability`.
- Translation template, multisite-aware uninstall.
- PHPUnit tests on WordPress stubs, phpcs (WordPress Coding Standards), CI on
  PHP 7.4 to 8.4, POT check and a release workflow that builds the plugin zip.

[Unreleased]: https://github.com/saizul/wp-login-limit/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/saizul/wp-login-limit/releases/tag/v0.1.0
