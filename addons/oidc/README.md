# oidc-okena

OpenID Connect login in front of okena's routes, as an addon: internal tools
(Grafana, admin pages, dashboards) behind "sign in with Google, Okta, Entra,
Keycloak..." and an e-mail or domain allow list. Only Go's standard library
and okena's SDK.

```sh
cd addons/oidc && go build -o /usr/local/bin/oidc-okena .
openssl rand -hex 32 > /etc/okena/oidc-key       # seals the cookies
```

```nginx
addon oidc {
    run /usr/local/bin/oidc-okena -issuer https://accounts.google.com -client-id ID \
        -client-secret-file /etc/okena/oidc-secret -cookie-key-file /etc/okena/oidc-key \
        -allow-domain example.com
    timeout 5s                     # the code's exchange is a call to the provider
}
route /* { addon oidc; to pool grafana }
```

* A page load without a session (GET or HEAD asking for HTML) is sent to the
  provider: the authorization code flow with PKCE (S256), a state and a
  nonce, kept in a sealed cookie for 10 minutes. Any other request without
  a session gets 401.
* At the callback (`-callback`, `/oauth2/callback`) the code is exchanged,
  the ID token's signature (RS, PS, ES, EdDSA from the provider's JWKS,
  fetched again when a key is new to it; HS256 with the client secret),
  issuer, audience, expiry and nonce are checked, and the e-mail is held to
  `-allow-email` and `-allow-domain` (an `email_verified: false` is no
  e-mail). Then a session cookie, sealed with AES-256-GCM, for `-session`
  (12h): nothing is kept on this side, so any number of okena instances
  share sessions when they share `-cookie-key-file`.
* With a session the request goes on with `x-user-email`, `x-user-sub` and
  `x-user-name` (`-header`, `-sub-header`, `-name-header`), a client's own
  fields of those names replaced, and without the session cookie.
* `-logout` (`/oauth2/logout`) ends the session.
* The callback's URL is `https://HOST/oauth2/callback` unless
  `-redirect-url` says it; register it with the provider. `-ca-file` for a
  provider under a private CA; `-insecure-cookie` drops `Secure` (plain HTTP
  tests only).

`tests/gateway/oidc.py` runs it against a provider of its own.
