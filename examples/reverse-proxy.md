# Real client IP behind a proxy

Login Limit only reads proxy headers for requests whose `REMOTE_ADDR` is a
**trusted proxy**. Pick the setup that matches your hosting.

## Cloudflare

Settings > Login Limit: tick **Cloudflare**. Requests from Cloudflare's
published ranges use `CF-Connecting-IP`; anything else uses `REMOTE_ADDR`.

If an own load balancer sits between Cloudflare and WordPress, also add the
load balancer to **Trusted proxies**. The plugin then walks
`X-Forwarded-For` from the right, skipping the load balancer and Cloudflare.

## nginx in front of PHP-FPM or Apache on the same server

```nginx
location / {
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Real-IP       $remote_addr;
    proxy_pass http://127.0.0.1:8080;
}
```

Trusted proxies: `127.0.0.1` (and `::1`). Client IP header:
`X-Forwarded-For` or `X-Real-IP`.

## Cloud load balancer (AWS ALB, Google Cloud, DigitalOcean, ...)

Trusted proxies: the private subnet of the load balancer, for example
`10.0.0.0/16`. Client IP header: `X-Forwarded-For`.

## Checking

The top of Settings > Login Limit shows "Your IP address as this plugin
sees it". Compare it with what <https://ifconfig.me> shows in the same
browser. If every visitor shows the same address, a proxy is not trusted yet
and all visitors share one counter, so one attacker locks out everyone.

## Why not just trust X-Forwarded-For?

Anyone can send `X-Forwarded-For: 1.2.3.4`. Trusting it without checking
`REMOTE_ADDR` lets attackers pick a new "IP" for every attempt (no lockout
ever) or lock out someone else's address.
