# Contributing

Thanks for helping improve Login Limit. Bug reports, fixes, tests,
documentation and translations are all welcome, and first-time contributors
are especially welcome: the security logic is a handful of small, pure
classes and every part has tests.

By taking part you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Ways to help

- **Pick a beginner task** from the list below or from issues labelled
  [`good first issue`](https://github.com/saizul/wp-login-limit/labels/good%20first%20issue).
  Comment on the issue first so two people do not work on the same thing.
- **Report a bug** with the "Bug report" template. For IP problems include
  your proxy/CDN setup and what the settings screen shows as "Your IP
  address as this plugin sees it" (mask the last part of the address).
- **Share a proxy setup** (hosting, load balancer, CDN) and the settings that
  worked. Those notes go into `examples/reverse-proxy.md`.
- **Translate** the plugin: `languages/wp-login-limit.pot` is the template.

Security problems go to the private channel in [SECURITY.md](SECURITY.md),
not to public issues.

## Good first issues

Each task is small, has a clear "done" and touches one or two files. Tests go
in `tests/Unit/`.

1. **"Add my IP to the allowlist" button.** In
   `SettingsPage::render_ip_check()`, add a small admin-post form (nonce and
   capability, like `handle_unlock_all()`) that appends the resolved IP to
   the `allowlist` setting through `Settings::sanitize()`. Test it in
   `tests/Unit/AdminTest.php`.
2. **Optional "attempts left" hint on the login form.** Add a setting
   (default off) and use `Policy::remaining()` in `Auth::generic()` to append
   "N attempts left". Keep it off by default and explain the trade-off in the
   README.
3. **`--event` filter for `wp login-limit log`.** Accept `lockout_ip`,
   `lockout_user`, `denied`, `unlock`, `unlock_all`; filter in
   `src/Cli/Command.php` and add tests to `tests/Unit/CliTest.php`.
4. **Generic messages on the lost-password form.** Hook
   `lostpassword_errors` (WordPress 5.5+) so "There is no account with that
   username or email address" becomes a neutral "If the account exists, an
   email was sent". Respect the `generic_errors` setting.
5. **Export the lockout log as CSV.** A button on the settings screen
   (nonce + capability) with columns `time,event,ip,username,gateway,duration,level`.
   Prefix cells starting with `=`, `+`, `-` or `@` with `'`.
6. **Dashboard widget.** "Lockouts in the last 24 hours" with the top three
   IPs, using `LogStore::recent()`. Only for users with
   `Plugin::capability()`.
7. **Settings link to the Cloudflare IP list.** Next to the Cloudflare
   checkbox, show how many ranges are built in and link to
   <https://www.cloudflare.com/ips/>. Escape everything.
8. **Translate the plugin into your language** with Poedit or Loco Translate
   from `languages/wp-login-limit.pot`, and open a PR with the `.po` file.

## Development setup

```bash
git clone https://github.com/saizul/wp-login-limit.git
cd wp-login-limit
composer install
composer test           # PHPUnit on WordPress stubs and in-memory stores
composer phpcs          # WordPress Coding Standards + PHPCompatibilityWP
composer phpcbf         # fix what phpcs can fix automatically
composer lint           # php -l
composer make-pot       # regenerate the translations template
```

PHP 7.4 or newer is required. Dependencies are resolved for PHP 7.4
(`config.platform`), so the same lock file works across the CI matrix. There
is no JavaScript build.

To try the plugin in a real site, symlink or copy the folder into
`wp-content/plugins/` of a local WordPress install (wp-env, LocalWP, DDEV or
similar) and activate it. Test the XML-RPC path with:

```sh
curl -s http://localhost:8888/xmlrpc.php -d '<?xml version="1.0"?><methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>admin</value></param><param><value>wrong</value></param></params></methodCall>'  # gitleaks:allow (deliberately wrong password)
```

and application passwords with `curl -u admin:wrong http://localhost:8888/wp-json/wp/v2/users/me`.

## Where things go

- `src/Ip.php`, `src/IpResolver.php` - **all** IP logic. Pure functions;
  keep them free of WordPress calls (`IpTest.php`, `IpResolverTest.php`).
- `src/Policy.php` - the lockout math (`PolicyTest.php`). Any change here
  needs a test that spells out the new durations.
- `src/Limiter.php` - lists and limits, built on Policy and the stores
  (`LimiterTest.php`).
- `src/Auth.php` - the WordPress hooks (`AuthTest.php`). Keep it thin.
- `src/Notifier.php`, `src/Fail2ban.php` - email and log lines. If you change
  the log line format, update `examples/fail2ban/` and the README; the test
  checks the example filter against real lines.
- `src/Store/` - storage contracts and the `$wpdb` implementations. Tests use
  `tests/Support/Memory*Store.php`; keep both in sync.
- `src/Admin/`, `src/Cli/` - settings screen and WP-CLI.
- `tests/Stubs/` - light WordPress and WP-CLI stubs. Add a stub when you use
  a new WordPress function; keep it minimal and record calls in `WpStubs` so
  tests can assert them.

## Coding standards

- WordPress Coding Standards (`composer phpcs` must pass) and PHP 7.4
  compatibility: no union types, no `match`, no named arguments, no
  constructor promotion, no `str_contains()`.
- Never trust a request header for the client IP outside `IpResolver`.
- Escape all output, sanitise all input, check capabilities and nonces.
- Every SQL query uses `$wpdb->prepare()` with `%i` for table names.
- No remote requests, no tracking, no upsells, no new runtime dependencies.
- Translatable strings use the `wp-login-limit` text domain.
- Keep pull requests focused. Update `CHANGELOG.md` under "Unreleased".

## Pull requests

1. Fork the repository and create a branch (`feature/allowlist-my-ip`,
   `fix/xff-ipv6-port`).
2. Make your change with tests.
3. Run `composer test`, `composer phpcs` and, if strings changed,
   `composer make-pot`, and commit the regenerated file.
4. Open the pull request and fill in the checklist.

CI must pass before a pull request is merged.

## Releases

Maintainers bump the version in `wp-login-limit.php` (header and
`WP_LOGIN_LIMIT_VERSION`), `src/Plugin.php` (`VERSION`), `readme.txt`
(`Stable tag`) and `CHANGELOG.md`, then publish a GitHub release tagged
`vX.Y.Z`. The release workflow checks that the versions match, builds
`wp-login-limit.zip` and attaches it to the release.
