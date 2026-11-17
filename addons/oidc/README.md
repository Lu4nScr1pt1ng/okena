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
    phases request_headers response_headers   # (a renewed session's cookie on the response)
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
* `-logout` (`/oauth2/logout`) ends the session: its cookies cleared, its
  refresh token revoked at the provider's `revocation_endpoint` (RFC 7009),
  and, when the provider has an `end_session_endpoint`, the browser sent
  there (OpenID Connect RP-Initiated Logout) with `id_token_hint`,
  `client_id` and `post_logout_redirect_uri` (`-post-logout-url`, else
  `https://HOST/`; register it with the provider).
* `-refresh-every 5m`: a session whose provider gave a refresh token (ask
  for one with `-scopes "openid email profile offline_access"` where the
  provider wants that) is checked with the provider that often. A refresh
  the provider refuses ends the session (a user disabled there is out
  within that time); one the provider doesn't answer leaves it as it was.
  The ID token it may return is checked as at sign-in, for the same
  subject, and the e-mail again against the allow lists. Requests that come
  at once with one stale cookie make one refresh (a provider that rotates
  refresh tokens takes a second use of one as theft).
* The renewed cookie goes out on the response when the addon has the
  `response_headers` phase (`phases request_headers response_headers`).
  Without it a page load is sent to itself with the new cookie, and other
  requests use the renewed session the addon keeps until then.
* `-access-token-header x-access-token` passes the provider's access token
  to the backend (renewed with the session), a client's own field of that
  name replaced.
* A session too long for one cookie (refresh, access and ID tokens) is cut
  into up to three (`okena_session`, `okena_session_1`, `_2`); past that the
  ID token is left out, then the access token.
* The callback's URL is `https://HOST/oauth2/callback` unless
  `-redirect-url` says it; register it with the provider. `-ca-file` for a
  provider under a private CA; `-insecure-cookie` drops `Secure` (plain HTTP
  tests only).

`tests/gateway/oidc.py` runs it against a provider of its own.
