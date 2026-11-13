# coraza-okena

A web application firewall addon for okena: [Coraza](https://coraza.io) with
the [OWASP Core Rule Set](https://coreruleset.org) built in.

```sh
cd addons/coraza && go build -o /usr/local/bin/coraza-okena .
```

```nginx
addon waf {
    run /usr/local/bin/coraza-okena -paranoia 1
    phases request_body     # the body's arguments too (form fields, JSON)
    body 16KiB              # its first 16 KiB, the most a call carries
    timeout 50ms
    on_error allow          # a WAF that cannot answer lets traffic through; deny to fail closed
}
route /* { addon waf; to pool app }
```

Each request's line, query arguments and fields go through the rules (CRS
phases 1 and 2). A request the
rules refuse gets their status, 403 unless a rule says otherwise; the matched
rules are logged to okena's log:

```
coraza-okena: GET /item?id=1'%20OR%20'1'='1 from 203.0.113.9: deny (rules 942100,949110)
```

| Flag | |
|---|---|
| `-paranoia N` | the CRS paranoia level, 1 (default) to 4 |
| `-detect` | log only, block nothing; the backend gets the matched rules' ids in `x-waf-rules` |
| `-rules FILE` | SecLang directives of your own, after the CRS's (exclusions, custom rules) |
| `-crs=false` | your rules only |
| `-workers N` | requests judged at once (default: the CPUs) |

With `phases request_body` the body goes through the rules too (URL-encoded
forms, JSON, multipart, by the CRS's body processors); a body longer than
`body` is judged on its first bytes, as with `SecRequestBodyLimitAction
ProcessPartial`.

With `response_headers` or `response_body` among its phases, the request's
transaction goes on into the response: its status and fields (phase 3) and,
with `response_body`, a counted body up to `body` (phase 4: the CRS's data
leakage rules, for the MIME types `SecResponseBodyMimeType` names). A
response the rules refuse is replaced by the rules' status and a short body;
the backend's never reaches the client.
