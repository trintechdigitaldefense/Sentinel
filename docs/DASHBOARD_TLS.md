# SENTINEL dashboard remote-access TLS

## Security boundary

The Sentinel dashboard HTTP server is an application backend, not a public TLS endpoint. It now binds only to a loopback address (`127.0.0.1`, `::1`, or `localhost`). Any configured non-loopback bind—including `0.0.0.0`, a LAN address, or `dashboard.allow_public_bind=true`—is refused and replaced with `127.0.0.1`.

For remote browser access, terminate HTTPS on a reverse proxy running on the **same host** and proxy to the loopback-only Sentinel listener. Do not expose port 8792 directly to a LAN or the Internet.

## Sentinel configuration

In `~/.sentinel/config.json`, configure the dashboard section:

```json
{
  "dashboard": {
    "bind": "127.0.0.1",
    "port": 8792,
    "remote_access": true,
    "cookie_secure": true
  }
}
```

- `remote_access=true` declares that remote browser access is intended. Sentinel refuses to start in this mode unless `cookie_secure=true`.
- `cookie_secure=true` causes the HttpOnly session cookie to include the `Secure` attribute. Use it only when the browser-facing connection is HTTPS through the trusted local reverse proxy.
- Sentinel does not trust `X-Forwarded-Proto` or other client-supplied forwarding headers to decide whether a connection is secure.
- `SameSite=Strict` and HttpOnly remain enabled. The dashboard's Origin/Host check expects HTTPS when `cookie_secure=true`.

The configuration flag is an operator assertion, not cryptographic proof that the reverse proxy is correctly configured. Complete the verification below before enabling remote access.

## Example Nginx reverse proxy

Replace `sentinel.example.com` and certificate paths with values provisioned for the host. Keep the default server block so unknown Host names are not routed to Sentinel.

```nginx
server {
    listen 80 default_server;
    server_name _;
    return 444;
}

server {
    listen 443 ssl http2;
    server_name sentinel.example.com;

    ssl_certificate     /etc/letsencrypt/live/sentinel.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/sentinel.example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    add_header Strict-Transport-Security "max-age=31536000" always;

    location / {
        proxy_pass http://127.0.0.1:8792;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

Provision a separate HTTP-to-HTTPS redirect only for the intended hostname, and ensure the TLS virtual host is the only route to the backend. The reverse proxy and Sentinel must run on the same trusted host; do not configure a proxy on another machine to reach an exposed plain-HTTP Sentinel listener.

## Verification checklist

Before approving remote access:

- [ ] Sentinel listens only on loopback; verify with `ss -ltnp` or an equivalent socket inspection.
- [ ] Port 8792 is not reachable from another host.
- [ ] The reverse proxy listens on the intended HTTPS port and presents a valid, hostname-matching certificate.
- [ ] TLS 1.2 or TLS 1.3 is negotiated; plain HTTP is redirected or rejected for the intended hostname.
- [ ] Unknown Host values are rejected by the proxy.
- [ ] `dashboard.remote_access=true` and `dashboard.cookie_secure=true` are set in the protected local config.
- [ ] After login, inspect the `sentinel_token` cookie: it must be HttpOnly, Secure, and SameSite=Strict.
- [ ] A same-origin HTTPS POST succeeds; a cross-origin or Host-mismatched POST is rejected.
- [ ] The proxy does not log credentials, session cookies, or request bodies containing secrets.
- [ ] Record the proxy configuration, certificate renewal owner, verification date, and rollback procedure.

Do not treat this document or the presence of `cookie_secure=true` as evidence that a customer's reverse proxy is already deployed correctly. Remote access remains unapproved until the target host is checked.
