# Login Limit

[![CI](https://github.com/saizul/wp-login-limit/actions/workflows/ci.yml/badge.svg)](https://github.com/saizul/wp-login-limit/actions/workflows/ci.yml)
[![Release zip](https://github.com/saizul/wp-login-limit/actions/workflows/release-zip.yml/badge.svg)](https://github.com/saizul/wp-login-limit/actions/workflows/release-zip.yml)
[![Latest release](https://img.shields.io/github/v/release/saizul/wp-login-limit?sort=semver)](https://github.com/saizul/wp-login-limit/releases)
![PHP](https://img.shields.io/badge/PHP-7.4%20to%208.4-777bb4)
![WordPress](https://img.shields.io/badge/WordPress-6.2%2B-21759b)
[![License: GPL v2+](https://img.shields.io/badge/license-GPL--2.0--or--later-blue.svg)](LICENSE)
[![Good first issues](https://img.shields.io/github/issues/saizul/wp-login-limit/good%20first%20issue?label=good%20first%20issues)](https://github.com/saizul/wp-login-limit/labels/good%20first%20issue)

**Brute-force protection for WordPress that gets the client IP right.**
Limits failed logins per IP and per username with escalating lockouts, on
wp-login.php, XML-RPC and REST API application passwords. Proxy headers are
only trusted from proxies you name (or Cloudflare's ranges), so attackers
cannot dodge the counter with a fake `X-Forwarded-For`.

Plugin slug: `wp-login-limit` - display name: *Login Limit*.

- No tracking, no remote requests, no upsells, no captcha service.
- Counters live in a small custom table, not in transients that an object
  cache can evict.
- Writes fail2ban-ready log lines if you want bans at the firewall.

## Contents

- [Features](#features)
- [Quick start](#quick-start)
- [How lockouts work](#how-lockouts-work)
- [Client IP and proxies](#client-ip-and-proxies)
- [XML-RPC and application passwords](#xml-rpc-and-application-passwords)
- [Email alerts](#email-alerts)
- [fail2ban](#fail2ban)
- [WP-CLI](#wp-cli)
- [Hooks for developers](#hooks-for-developers)
- [FAQ](#faq)
- [Development and testing](#development-and-testing)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [Security and license](#security-and-license)

## Features

- **Per-IP limit** (5 failures in 15 minutes by default). IPv6 clients are
  counted per /64 network (configurable), because one customer usually owns
  a whole /64.
- **Per-username limit** (10 failures from all IPs together) against
  distributed attacks. Networks a user logged in from before are not
  affected, so an attacker cannot lock you out of your own account from your
  usual connection.
- **Escalating lockouts**: 15 min, 1 h, 4 h, 16 h, then 24 h (base,
  multiplier, maximum and reset period are settings).
- **All login paths**: wp-login.php and every `wp_signon()` form (WooCommerce
  and friends), XML-RPC, and REST API / basic-auth application passwords.
  Locked-out clients get the same answer whether the password was right or
  wrong.
- **Option to disable XML-RPC authentication** entirely (pingbacks keep
  working).
- **Trusted proxies**: `X-Forwarded-For` (walked from the right),
  `X-Real-IP` or `CF-Connecting-IP`, only from addresses or CIDR ranges you
  trust; one tick for Cloudflare's published ranges.
- **Allowlist and denylist** with IPv4/IPv6 addresses and CIDR ranges, plus
  "lock out at once" usernames such as `admin`.
- **Generic error messages**: "The username or password is incorrect." for
  both unknown users and wrong passwords.
- **Lockout log** and **active lockouts** with one-click unlock under
  Settings > Login Limit.
- **Admin email** on lockouts, throttled (one email per hour by default,
  with a count of what happened in between).
- **fail2ban-friendly** log lines to the PHP error log (optional).
- **WP-CLI**: `wp login-limit unlock | list | log | check`.
- Nonces and capability checks everywhere, sanitised input, escaped output,
  translation ready, multisite-aware uninstall.

## Quick start

Requirements: WordPress 6.2 or newer (tested up to 7.1), PHP 7.4 or newer.

1. Download `wp-login-limit.zip` from the
   [latest release](https://github.com/saizul/wp-login-limit/releases) and
   install it from **Plugins > Add New > Upload Plugin**, or clone this
   repository into `wp-content/plugins/wp-login-limit`.
2. Activate **Login Limit**. The defaults protect the site right away.
3. Open **Settings > Login Limit** and check the line "Your IP address as
   this plugin sees it". If the site is behind a proxy or CDN, set
   [trusted proxies](#client-ip-and-proxies) first.
4. Optional: add your office IP to the allowlist, tick "Disable all XML-RPC
   methods that need a login" if you do not use the mobile apps or Jetpack,
   and enable fail2ban lines.

Try it from a private window: five wrong passwords and the sixth attempt
says "Too many failed login attempts. Please try again in 15 mins.", even
with the right password. Unlock yourself with:

```sh
wp login-limit unlock 203.0.113.5
```

## How lockouts work

| Setting | Default | Meaning |
| --- | --- | --- |
| Failed logins per IP | 5 | Failures from one IP (IPv6: one /64) within the window. |
| Failed logins per username | 10 | Failures for one username from all IPs together. 0 switches it off. |
| Counting window | 900 s | Counting starts at the first failure; after the window, it starts over. |
| First lockout | 900 s | Length of the first lockout. |
| Multiplier | 4 | Each further lockout lasts this many times longer. 1 = no escalation. |
| Longest lockout | 86400 s | Cap. |
| Escalation resets after | 86400 s | Without a new lockout for this long, the next one is a first lockout again. |
| IPv6 network size | 64 | Prefix counted as one client (128 = single addresses). |

The n-th lockout lasts `min(max, first * multiplier^(n-1))`. With the
defaults: 15 min, 1 h, 4 h, 16 h, 24 h, 24 h, ...

Other rules:

- Attempts during a lockout are refused **before** the result is shown and
  are not counted again, so a locked-out bot cannot extend its own lockout
  forever, and cannot tell whether a password was right.
- A successful login clears the failure counter of that IP and username (the
  escalation level stays until the reset period passes).
- An email address of an existing user counts as that user's login, so
  `admin` and `admin@example.org` share one counter.
- **Allowlisted** IPs are never counted or locked. **Denylisted** IPs can
  never log in. Trying a **"lock out at once" username** (list only names
  that do not exist on your site) locks the IP immediately.
- A daily cron job removes stale counters and log entries older than the
  retention period (30 days).

## Client IP and proxies

Getting the IP wrong is the most common failure of login limiters: behind a
proxy every visitor shares the proxy's address (one attacker locks out
everyone), and trusting `X-Forwarded-For` blindly lets an attacker pick a
new "IP" for every attempt.

Login Limit uses `REMOTE_ADDR`, unless `REMOTE_ADDR` is a **trusted proxy**:

| Setting | Use it for |
| --- | --- |
| Trusted proxies | Your load balancer or reverse proxy: addresses or CIDR ranges, one per line (`127.0.0.1`, `10.0.0.0/16`). |
| Client IP header | `X-Forwarded-For` (default), `X-Real-IP` or `CF-Connecting-IP`, read only from trusted proxies. |
| Cloudflare | Trusts Cloudflare's published ranges and reads `CF-Connecting-IP` from them. |

`X-Forwarded-For` is walked **from the right**: trusted proxies are skipped
and the first address that is not a trusted proxy is the client. Entries a
client adds on the left are ignored; garbage stops the walk; ports and
`[IPv6]` brackets are stripped; IPv4-mapped IPv6 addresses become IPv4.

The settings screen shows the address the plugin sees for you and warns when
a proxy header is present but no proxy is trusted. Setups for nginx,
Cloudflare and cloud load balancers are in
[`examples/reverse-proxy.md`](examples/reverse-proxy.md). Anything else can
use the `login_limit_client_ip` filter.

Cloudflare publishes its ranges at <https://www.cloudflare.com/ips/>; the
plugin ships the current list (`IpResolver::CLOUDFLARE_RANGES`). Add new
ranges as trusted proxies until the plugin is updated.

## XML-RPC and application passwords

- **XML-RPC** logins (`xmlrpc.php`, including `system.multicall`) go
  through the same limits. Choose "Disable all XML-RPC methods that need a
  login" to switch them off completely with core's `xmlrpc_enabled` filter;
  pingbacks and other public methods keep working.
- **Application passwords** (REST API and other basic-auth requests) are
  counted too. A locked-out client gets a `429` (denylist: `403`) REST error
  with the same message whether the application password was right or
  wrong.

Log entries and fail2ban lines show the gateway: `login`, `xmlrpc` or `rest`.

## Email alerts

| Setting | Default |
| --- | --- |
| Email the administrator | On repeated lockouts of the same IP or username (other options: never, every lockout) |
| Send emails to | The site's admin email |
| At most one email every | 3600 s |

Lockouts during the quiet period are counted and mentioned in the next email
("3 more lockouts happened since the last email"), so a large attack does not
flood the inbox.

## fail2ban

Tick **fail2ban** in the settings. Every failure, lockout and refused attempt
then writes one line to the PHP error log:

```
wp-login-limit: authentication failure from 203.0.113.5 user="admin" gateway=login
wp-login-limit: lockout from 203.0.113.5 user="admin" gateway=xmlrpc
wp-login-limit: blocked from 203.0.113.5 user="admin" gateway=rest
```

The IP is the resolved client IP. Usernames are reduced to
`A-Z a-z 0-9 . _ @ + -` (anything else becomes `?`), so a crafted username
cannot forge a second line or another address.

Filter (`/etc/fail2ban/filter.d/wp-login-limit.conf`):

```ini
[Definition]
failregex = wp-login-limit: (?:authentication failure|lockout|blocked) from <HOST> user=
ignoreregex =
```

A jail example is in
[`examples/fail2ban/`](examples/fail2ban/). Point `logpath` at your PHP error
log (php.ini `error_log` or the PHP-FPM pool setting), or send the lines
elsewhere with the `login_limit_fail2ban_write` filter. Behind a CDN,
banning at this server's firewall does not help: use the CDN's firewall.

## WP-CLI

```sh
# Unlock an IP, an IPv6 network or a username (or everyone).
wp login-limit unlock 203.0.113.5
wp login-limit unlock 2001:db8:1:2::/64 admin
wp login-limit unlock --all

# Active lockouts and the log.
wp login-limit list
wp login-limit list --format=json
wp login-limit log --limit=20

# Can this IP (and user) log in right now?
wp login-limit check 203.0.113.5 --user=admin
# Not locked. 3 failed attempts left for 203.0.113.5.
```

The settings are one option: `wp option get wp_login_limit_settings
--format=json` shows them (after they were saved once).

## Hooks for developers

| Hook | Type | Arguments | Use it to |
| --- | --- | --- | --- |
| `login_limit_lockout` | action | `Lockout $lockout` | React to a new lockout (monitoring, chat alerts). |
| `login_limit_refused` | action | `Lockout $lockout` | Runs for every refused attempt (locked or denylisted). |
| `login_limit_client_ip` | filter | `string $ip` | Read the IP from a proxy the settings do not cover. |
| `login_limit_send_notification` | filter | `bool $send`, `Lockout $lockout` | Skip some emails. |
| `login_limit_fail2ban_write` | filter | `bool $write`, `string $line` | Write fail2ban lines somewhere else (return false). |
| `login_limit_capability` | filter | `string $capability` | Who can change settings and unlock (`manage_options`). |

`Lockout` has `reason` (`ip`, `user`, `denylist`), `ip`, `username`,
`gateway`, `duration`, `level` and `until`. Examples are in
[`examples/mu-plugin-hooks.php`](examples/mu-plugin-hooks.php).

## FAQ

**I locked myself out.**
Wait for the lockout to end, run `wp login-limit unlock <your IP>` (or
`--all`), or rename the plugin folder over SFTP. Add your IP to the
allowlist afterwards.

**Everyone gets locked out at once.**
Your site is behind a proxy that is not trusted yet, so all visitors share
the proxy's address. See [Client IP and proxies](#client-ip-and-proxies).

**Can an attacker lock out my admin account?**
The per-username limit locks a username for clients that have not logged in
as that user before. Your own connections stay usable. If you prefer, set
"Failed logins per username" to 0 and rely on the per-IP limit.

**Does it work with WooCommerce, membership and custom login forms?**
Yes, if they log in with `wp_signon()` or `wp_authenticate()`, as almost all
do. Their error messages come from the same `authenticate` filter.

**Does it work with a custom login URL plugin, 2FA or SSO?**
Yes. The limits apply wherever WordPress checks a password. Logins through
SSO providers that do not use passwords are not counted.

**Why not transients?**
With a persistent object cache, transients can be evicted at any time, which
silently resets the counters. A small table is reliable and indexed.

**What data is stored?**
Counters per IP (or IPv6 network) and per attempted username, a lockout log
with IP, username and gateway, and per user the last 10 networks they logged
in from (user meta). Everything is deleted on uninstall; the log is pruned
after the retention period.

**Does it work on multisite?**
Yes. Each site has its own tables and settings; known networks are per user.
Uninstall cleans up every site.

## Development and testing

```sh
composer install
composer test           # PHPUnit on light WordPress stubs, no database needed
composer phpcs          # WordPress Coding Standards and PHP 7.4+ compatibility
composer lint           # php -l on every file
composer make-pot       # regenerate languages/wp-login-limit.pot
```

Project layout:

```
wp-login-limit.php          Plugin header, autoloader, activation hooks
uninstall.php               Drops the tables, options and user meta
src/Plugin.php              Wiring, cron, fail2ban output, capability
src/Auth.php                authenticate, wp_login_failed, wp_login, XML-RPC, application passwords
src/Limiter.php             Allow/deny lists, per-IP and per-username limits, unlock
src/Policy.php              Lockout math (window, escalation, cap, reset)
src/Record.php              Counter state of one IP or username
src/Lockout.php             Why an attempt is blocked
src/Ip.php                  IPv4/IPv6, CIDR, IPv6 networks
src/IpResolver.php          Client IP behind trusted proxies and Cloudflare
src/Notifier.php            Throttled admin email
src/Fail2ban.php            Log line format
src/Settings.php            The settings option
src/Schema.php              Custom tables (dbDelta)
src/Store/                  Storage contracts and database implementations
src/Admin/SettingsPage.php  Settings > Login Limit
src/Cli/Command.php         wp login-limit
tests/                      PHPUnit tests, WordPress and WP-CLI stubs
bin/make-pot.php            POT generator
examples/                   fail2ban, proxy setups, developer snippets
```

CI runs on PHP 7.4, 8.0, 8.1, 8.2, 8.3 and 8.4: `composer validate`,
`php -l`, phpcs, PHPUnit and the POT check. Publishing a GitHub release
builds `wp-login-limit.zip`, smoke-tests it and attaches it to the release.

The unit tests run against stubs and in-memory stores: they cover IP
resolution, CIDR matching, the lockout math, the limiter, the WordPress
hooks (including XML-RPC and application password paths), email throttling,
fail2ban lines, settings, the admin screen and WP-CLI. The SQL in
`src/Store/` is not exercised by CI; test on a staging site before relying
on it.

## Roadmap

Ideas, roughly in order. Items marked **good first issue** are small and
well scoped; see [CONTRIBUTING.md](CONTRIBUTING.md#good-first-issues).

- "Add my IP to the allowlist" button - **good first issue**
- Show remaining attempts on the login form (optional) - **good first issue**
- `wp login-limit log --event=lockout_ip` filter - **good first issue**
- Generic messages on the lost-password form - **good first issue**
- Export the lockout log as CSV - **good first issue**
- Dashboard widget with lockouts in the last 24 hours - **good first issue**
- RFC 7239 `Forwarded` header support
- Network-wide settings for multisite
- Integration tests against a real WordPress and MySQL (wp-env) in CI
- WordPress.org release with screenshots

## Contributing

Contributions of every size are welcome: bug reports, tests, docs,
translations and code. Start with [CONTRIBUTING.md](CONTRIBUTING.md), which
has the setup, the coding standards and a list of beginner tasks, and please
follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Security and license

- [SECURITY.md](SECURITY.md): please report vulnerabilities privately.
- [CHANGELOG.md](CHANGELOG.md).

Login Limit is free software under the [GPL-2.0-or-later](LICENSE).
Copyright (c) 2026 Saizul Amin ([saizul.com](https://saizul.com)).
