## What does this change?

<!-- One or two sentences. Link the issue: "Closes #123". -->

## Type

- [ ] Bug fix
- [ ] Limits, lockout math or IP resolution
- [ ] Login paths (wp-login.php, XML-RPC, application passwords)
- [ ] Settings screen, alerts, fail2ban, WP-CLI or hooks
- [ ] Documentation or translations
- [ ] Tests or tooling

## Checklist

- [ ] IP logic stays in `src/Ip.php` / `src/IpResolver.php`, lockout math in `src/Policy.php`, both with tests.
- [ ] No request header is trusted for the client IP outside `IpResolver`.
- [ ] New settings are sanitised in `src/Settings.php` and tested.
- [ ] SQL uses `$wpdb->prepare()`; output is escaped; forms check a capability and a nonce.
- [ ] The in-memory stores in `tests/Support/` match any change to `src/Store/`.
- [ ] No remote requests, no tracking, no new runtime dependencies.
- [ ] `composer test` and `composer phpcs` pass.
- [ ] `composer make-pot` run and `languages/wp-login-limit.pot` committed (if strings changed).
- [ ] `CHANGELOG.md` updated under "Unreleased".

## How did you test it on a real site?

<!-- WordPress and PHP versions, proxy setup, which login paths you tried. -->
