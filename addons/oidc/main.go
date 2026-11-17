// oidc-okena: OpenID Connect login in front of okena's routes, as an addon.
//
// A request without a session is sent to the provider (authorization code
// flow with PKCE); the provider sends the browser back to the callback path,
// where the code is exchanged for an ID token, the token's signature, issuer,
// audience, expiry and nonce are checked against the provider's published
// keys, the e-mail is held to the allow lists, and a session cookie (AES-GCM
// sealed, nothing kept on this side) is set. A request with a valid session
// goes on with the user's identity in fields the backend can trust (a
// client's own are replaced) and without the session cookie. Requests that
// are not a page load (not GET/HEAD, or not asking for HTML) get 401 instead
// of a redirect.
//
// With -refresh-every, a session whose provider gave a refresh token is
// checked with the provider again that often (the refresh grant): a refused
// refresh ends it, so a user disabled at the provider is out within that
// time, and the session's tokens are renewed. The new cookie goes out on the
// response when the addon has the response_headers phase; without it a page
// load is sent to itself with it, and other requests use the renewed session
// kept here until then. Logout revokes the refresh token (RFC 7009) and, when
// the provider has an end_session_endpoint, ends the session there too
// (OpenID Connect RP-Initiated Logout).
//
//	addon oidc {
//	    run /usr/local/bin/oidc-okena -issuer https://accounts.google.com -client-id ID \
//	        -client-secret-file /etc/okena/oidc-secret -cookie-key-file /etc/okena/oidc-key \
//	        -allow-domain example.com
//	    timeout 5s                 # the code's exchange is a call to the provider
//	}
//	route /* { addon oidc; to pool internal }
//
// Only the standard library and okena's SDK.
package main

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	addon "github.com/Lu4nScr1pt1ng/okena/sdk/go"
)

type config struct {
	issuer, clientID, clientSecret string
	redirectURL, callback, logout  string
	postLogout                     string
	scopes                         string
	cookie                         string
	ttl, refreshEvery              time.Duration
	allowEmails, allowDomains      map[string]bool
	header, subHeader, nameHeader  string
	atHeader                       string
	secure                         bool
	aead                           cipher.AEAD
}

type provider struct {
	AuthEndpoint  string `json:"authorization_endpoint"`
	TokenEndpoint string `json:"token_endpoint"`
	JWKSURI       string `json:"jwks_uri"`
	Issuer        string `json:"issuer"`
	EndSession    string `json:"end_session_endpoint"`
	Revocation    string `json:"revocation_endpoint"`
}

var (
	cfg    config
	prov   provider
	client *http.Client
	keysMu sync.RWMutex
	keys   = map[string]crypto.PublicKey{}
	keysAt time.Time
)

func main() {
	var secretFile, keyFile, caFile, emails, domains string
	flag.StringVar(&cfg.issuer, "issuer", "", "the provider's issuer URL (its discovery document is ISSUER/.well-known/openid-configuration)")
	flag.StringVar(&cfg.clientID, "client-id", "", "the client ID")
	flag.StringVar(&secretFile, "client-secret-file", "", "a file holding the client secret")
	flag.StringVar(&keyFile, "cookie-key-file", "", "a file holding 32 bytes (64 hex digits) that seal the cookies; without it a key made at start (sessions end with the process)")
	flag.StringVar(&cfg.redirectURL, "redirect-url", "", "the callback's full URL (default: https://HOST + -callback)")
	flag.StringVar(&cfg.callback, "callback", "/oauth2/callback", "the callback's path")
	flag.StringVar(&cfg.logout, "logout", "/oauth2/logout", "the path that ends a session")
	flag.StringVar(&cfg.postLogout, "post-logout-url", "", "where the provider sends the browser after its logout (default: https://HOST/)")
	flag.DurationVar(&cfg.refreshEvery, "refresh-every", 0, "check a session with the provider this often, by its refresh token (0: never)")
	flag.StringVar(&cfg.atHeader, "access-token-header", "", "a field that carries the access token to the backend (none: it is not kept)")
	flag.StringVar(&cfg.scopes, "scopes", "openid email profile", "the scopes asked for")
	flag.StringVar(&cfg.cookie, "cookie", "okena_session", "the session cookie's name")
	flag.DurationVar(&cfg.ttl, "session", 12*time.Hour, "how long a session lasts")
	flag.StringVar(&emails, "allow-email", "", "e-mail addresses let in, comma-separated")
	flag.StringVar(&domains, "allow-domain", "", "e-mail domains let in, comma-separated (no lists: any verified user of the provider)")
	flag.StringVar(&cfg.header, "header", "x-user-email", "the field that carries the e-mail")
	flag.StringVar(&cfg.subHeader, "sub-header", "x-user-sub", "the field that carries the subject")
	flag.StringVar(&cfg.nameHeader, "name-header", "x-user-name", "the field that carries the name")
	flag.StringVar(&caFile, "ca-file", "", "CA certificates for the provider (default: the system's)")
	insecureCookie := flag.Bool("insecure-cookie", false, "cookies without Secure (plain HTTP, for testing)")
	flag.Parse()
	if cfg.issuer == "" || cfg.clientID == "" || secretFile == "" {
		log.Fatal("oidc-okena: -issuer, -client-id and -client-secret-file are needed")
	}
	cfg.secure = !*insecureCookie
	cfg.allowEmails, cfg.allowDomains = set(emails), set(domains)
	s, err := os.ReadFile(secretFile)
	if err != nil {
		log.Fatal(err)
	}
	cfg.clientSecret = strings.TrimSpace(string(s))
	key := make([]byte, 32)
	if keyFile != "" {
		k, err := os.ReadFile(keyFile)
		if err != nil {
			log.Fatal(err)
		}
		if key, err = hex.DecodeString(strings.TrimSpace(string(k))); err != nil || len(key) != 32 {
			log.Fatal("oidc-okena: the cookie key is 64 hex digits")
		}
	} else if _, err := rand.Read(key); err != nil {
		log.Fatal(err)
	}
	block, _ := aes.NewCipher(key)
	cfg.aead, _ = cipher.NewGCM(block)
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			log.Fatal(err)
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(pem)
		tr.TLSClientConfig = &tls.Config{RootCAs: pool}
	}
	client = &http.Client{Transport: tr, Timeout: 4 * time.Second}
	if err := discover(); err != nil {
		log.Fatal("oidc-okena: ", err)
	}
	go sweep()
	log.Fatal(addon.Run(handle, addon.Options{Workers: 16}))
}

func set(list string) map[string]bool {
	m := map[string]bool{}
	for _, s := range strings.Split(list, ",") {
		if s = strings.ToLower(strings.TrimSpace(s)); s != "" {
			m[s] = true
		}
	}
	return m
}

func discover() error {
	if err := getJSON(strings.TrimSuffix(cfg.issuer, "/")+"/.well-known/openid-configuration", &prov); err != nil {
		return err
	}
	if prov.Issuer != cfg.issuer || prov.AuthEndpoint == "" || prov.TokenEndpoint == "" || prov.JWKSURI == "" {
		return errors.New("the discovery document does not match the issuer, or lacks an endpoint")
	}
	return loadKeys()
}

func getJSON(u string, v any) error {
	r, err := client.Get(u)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return fmt.Errorf("%s: %s", u, r.Status)
	}
	return json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(v)
}

// ---------------------------------------------------------------- requests

func handle(r *addon.Request, a *addon.Answer) {
	if r.IsResponse() {
		// a renewed session's cookies, on its response
		if v, ok := pending.LoadAndDelete(r.Stream); ok {
			for _, c := range v.(*waiting).cookies {
				a.Add("set-cookie", c)
			}
		}
		return
	}
	path := r.Path()
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	switch path {
	case cfg.callback:
		callback(r, a)
		return
	case cfg.logout:
		logout(r, a)
		return
	}
	s, raw, ok := session(r)
	if ok && cfg.refreshEvery > 0 && s.RT != "" && time.Now().UnixMilli() >= s.Chk {
		ns, err := renew(raw, s)
		switch {
		case err == errRefused:
			ok = false // the provider says no more: signed out
			for _, c := range clearSession(r) {
				a.Add("set-cookie", c)
			}
		case err != nil:
			log.Print("oidc-okena: a session's refresh: ", err, " (it goes on as it was)")
		default:
			cs := setSession(r, ns)
			switch {
			case !r.Last:
				pending.Store(r.Stream, &waiting{cookies: cs, at: time.Now()})
			case pageLoad(r):
				a.Respond(302) // to itself, with the renewed cookie
				a.Add("location", r.Target)
				for _, c := range cs {
					a.Add("set-cookie", c)
				}
				a.Add("cache-control", "no-store")
				return
			}
			s = ns
		}
	}
	if ok {
		// whatever the client says of itself goes: ours in its place
		a.Set(cfg.header, s.Email)
		a.Set(cfg.subHeader, s.Sub)
		if s.Name != "" {
			a.Set(cfg.nameHeader, s.Name)
		} else {
			a.Remove(cfg.nameHeader)
		}
		if cfg.atHeader != "" {
			if s.AT != "" {
				a.Set(cfg.atHeader, s.AT)
			} else {
				a.Remove(cfg.atHeader)
			}
		}
		if c := cookiesWithout(r, cfg.cookie); c == "" {
			a.Remove("cookie")
		} else {
			a.Set("cookie", c)
		}
		return
	}
	if !pageLoad(r) {
		a.Respond(401)
		a.Add("content-type", "text/plain")
		a.Add("www-authenticate", `Bearer realm="oidc"`)
		a.Body([]byte("sign in first\n"))
		return
	}
	login(r, a)
}

func pageLoad(r *addon.Request) bool {
	accept, _ := r.Header("accept")
	return (r.Method == "GET" || r.Method == "HEAD") && strings.Contains(accept, "text/html")
}

// ---------------------------------------------------------------- sessions renewed

var (
	errRefused = errors.New("the provider refused the refresh")
	// cookies for a request's response (its response_headers call)
	pending sync.Map // addon.StreamID -> *waiting
	// sessions renewed, by their old cookie: requests that still carry it
	// (before the new one reached the browser, or many at once) use the
	// renewal, and one refresh is asked for at a time: a provider that
	// rotates refresh tokens takes an old one as a theft
	renewMu sync.Mutex
	renewed = map[[32]byte]*flight{}
)

type waiting struct {
	cookies []string
	at      time.Time
}

type flight struct {
	done chan struct{}
	s    sess
	err  error
	at   time.Time
}

func renew(raw string, s sess) (sess, error) {
	k := sha256.Sum256([]byte(raw))
	renewMu.Lock()
	f := renewed[k]
	if f != nil {
		select {
		case <-f.done:
			if f.err == nil && time.Now().UnixMilli() >= f.s.Chk {
				s, f = f.s, nil // (that renewal is due again: from it)
			}
		default:
		}
	}
	if f == nil {
		f = &flight{done: make(chan struct{}), at: time.Now()}
		renewed[k] = f
		renewMu.Unlock()
		f.s, f.err = refresh(s)
		if f.err != nil && f.err != errRefused {
			renewMu.Lock()
			delete(renewed, k) // (the provider unreachable: asked again by the next one)
			renewMu.Unlock()
		}
		close(f.done)
	} else {
		renewMu.Unlock()
		<-f.done
	}
	return f.s, f.err
}

// sweep: what was kept for requests that are long gone
func sweep() {
	for range time.Tick(30 * time.Second) {
		now := time.Now()
		pending.Range(func(k, v any) bool {
			if now.Sub(v.(*waiting).at) > time.Minute {
				pending.Delete(k)
			}
			return true
		})
		renewMu.Lock()
		for k, f := range renewed {
			if now.Sub(f.at) > cfg.refreshEvery+time.Minute {
				delete(renewed, k)
			}
		}
		renewMu.Unlock()
	}
}

// refresh: the refresh grant, its ID token checked as at sign-in (but its
// nonce: none comes), the same subject, the e-mail still let in
func refresh(s sess) (sess, error) {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {s.RT},
		"client_id":     {cfg.clientID},
		"client_secret": {cfg.clientSecret},
	}
	t, status, err := tokenCall(form)
	if err != nil {
		return s, err
	}
	if status == 400 || status == 401 {
		return s, errRefused
	}
	if status != 200 {
		return s, fmt.Errorf("the token endpoint: %d %s", status, t.Error)
	}
	ns := s
	if t.IDToken != "" {
		claims, err := verify(t.IDToken, "")
		if err != nil {
			log.Print("oidc-okena: a refreshed ID token: ", err)
			return s, errRefused
		}
		if sub, _ := claims["sub"].(string); sub != s.Sub {
			return s, errRefused
		}
		email, _ := claims["email"].(string)
		if v, ok := claims["email_verified"].(bool); ok && !v {
			email = ""
		}
		if email != "" {
			ns.Email = email
		}
		if name, _ := claims["name"].(string); name != "" {
			ns.Name = strings.Map(printable, name)
		}
		ns.IDT = t.IDToken
	}
	if !allowed(ns.Email) {
		return s, errRefused
	}
	if t.RefreshToken != "" {
		ns.RT = t.RefreshToken
	}
	if cfg.atHeader != "" {
		ns.AT = t.AccessToken
	}
	ns.Chk = time.Now().Add(cfg.refreshEvery).UnixMilli()
	return ns, nil
}

// logout: the session's refresh token revoked, its cookies cleared, and the
// browser to the provider's end_session_endpoint (else to /)
func logout(r *addon.Request, a *addon.Answer) {
	s, _, ok := session(r)
	if ok && s.RT != "" && prov.Revocation != "" {
		go revoke(s.RT)
	}
	loc := "/"
	if prov.EndSession != "" {
		q := url.Values{"client_id": {cfg.clientID}, "post_logout_redirect_uri": {postLogoutURL(r)}}
		if ok && s.IDT != "" {
			q.Set("id_token_hint", s.IDT)
		}
		sep := "?"
		if strings.Contains(prov.EndSession, "?") {
			sep = "&"
		}
		loc = prov.EndSession + sep + q.Encode()
	}
	a.Respond(302)
	a.Add("location", loc)
	for _, c := range clearSession(r) {
		a.Add("set-cookie", c)
	}
	a.Add("cache-control", "no-store")
}

func postLogoutURL(r *addon.Request) string {
	if cfg.postLogout != "" {
		return cfg.postLogout
	}
	if cfg.redirectURL != "" {
		if u, err := url.Parse(cfg.redirectURL); err == nil {
			return u.Scheme + "://" + u.Host + "/"
		}
	}
	host, _ := r.Header("host")
	return "https://" + host + "/"
}

func revoke(rt string) {
	r, err := client.PostForm(prov.Revocation, url.Values{"token": {rt}, "token_type_hint": {"refresh_token"},
		"client_id": {cfg.clientID}, "client_secret": {cfg.clientSecret}})
	if err != nil {
		log.Print("oidc-okena: revoking a refresh token: ", err)
		return
	}
	r.Body.Close()
}

type state struct {
	State, Verifier, Nonce, Return string
	Exp                            int64
}

type sess struct {
	Sub, Email, Name string
	Exp              int64  // the session's end (unix seconds)
	Chk              int64  `json:",omitempty"` // when to ask the provider again (unix ms)
	RT               string `json:",omitempty"` // its refresh token
	AT               string `json:",omitempty"` // its access token (-access-token-header)
	IDT              string `json:",omitempty"` // its ID token (logout's id_token_hint)
}

func redirectURL(r *addon.Request) string {
	if cfg.redirectURL != "" {
		return cfg.redirectURL
	}
	host, _ := r.Header("host")
	return "https://" + host + cfg.callback
}

func login(r *addon.Request, a *addon.Answer) {
	st := state{State: token(16), Verifier: token(32), Nonce: token(16), Return: r.Target, Exp: time.Now().Add(10 * time.Minute).Unix()}
	ch := sha256.Sum256([]byte(st.Verifier))
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {cfg.clientID},
		"redirect_uri":          {redirectURL(r)},
		"scope":                 {cfg.scopes},
		"state":                 {st.State},
		"nonce":                 {st.Nonce},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(ch[:])},
		"code_challenge_method": {"S256"},
	}
	sep := "?"
	if strings.Contains(prov.AuthEndpoint, "?") {
		sep = "&"
	}
	a.Respond(302)
	a.Add("location", prov.AuthEndpoint+sep+q.Encode())
	a.Add("set-cookie", cookie(cfg.cookie+"_state", seal(st), 600))
	a.Add("cache-control", "no-store")
}

func callback(r *addon.Request, a *addon.Answer) {
	fail := func(code int, why string) {
		a.Respond(code)
		a.Add("content-type", "text/plain")
		a.Add("set-cookie", clearCookie(cfg.cookie+"_state"))
		a.Add("cache-control", "no-store")
		a.Body([]byte(why + "\n"))
	}
	u, err := url.Parse(r.Target)
	if err != nil {
		fail(400, "a bad callback")
		return
	}
	q := u.Query()
	var st state
	if c, ok := cookieValue(r, cfg.cookie+"_state"); !ok || !open(c, &st) || st.Exp < time.Now().Unix() {
		fail(400, "no sign-in under way (or it took too long): start again")
		return
	}
	if q.Get("state") == "" || !hmac.Equal([]byte(q.Get("state")), []byte(st.State)) {
		fail(400, "the state does not match")
		return
	}
	if e := q.Get("error"); e != "" {
		fail(403, "the provider said: "+e)
		return
	}
	tok, err := exchange(q.Get("code"), st.Verifier, redirectURL(r))
	if err != nil {
		log.Print("oidc-okena: the code's exchange: ", err)
		fail(502, "the provider did not give a token")
		return
	}
	idt := tok.IDToken
	claims, err := verify(idt, st.Nonce)
	if err != nil {
		log.Print("oidc-okena: the ID token: ", err)
		fail(401, "the ID token does not hold")
		return
	}
	email, _ := claims["email"].(string)
	if v, ok := claims["email_verified"].(bool); ok && !v {
		email = ""
	}
	if !allowed(email) {
		fail(403, "not let in")
		return
	}
	sub, _ := claims["sub"].(string)
	name, _ := claims["name"].(string)
	s := sess{Sub: sub, Email: email, Name: strings.Map(printable, name), Exp: time.Now().Add(cfg.ttl).Unix(), IDT: idt}
	if cfg.refreshEvery > 0 && tok.RefreshToken != "" {
		s.RT = tok.RefreshToken
		s.Chk = time.Now().Add(cfg.refreshEvery).UnixMilli()
	} else if prov.Revocation != "" && tok.RefreshToken != "" {
		s.RT = tok.RefreshToken // (only for logout to revoke it)
	}
	if cfg.atHeader != "" {
		s.AT = tok.AccessToken
	}
	ret := st.Return
	if !strings.HasPrefix(ret, "/") || strings.HasPrefix(ret, "//") || strings.HasPrefix(ret, cfg.callback) {
		ret = "/"
	}
	a.Respond(302)
	a.Add("location", ret)
	for _, c := range setSession(r, s) {
		a.Add("set-cookie", c)
	}
	a.Add("set-cookie", clearCookie(cfg.cookie+"_state"))
	a.Add("cache-control", "no-store")
}

func printable(r rune) rune {
	if r < 0x20 || r == 0x7f {
		return -1
	}
	return r
}

func allowed(email string) bool {
	if email == "" {
		return false
	}
	email = strings.ToLower(email)
	if len(cfg.allowEmails) == 0 && len(cfg.allowDomains) == 0 {
		return true
	}
	if cfg.allowEmails[email] {
		return true
	}
	if i := strings.LastIndexByte(email, '@'); i >= 0 && cfg.allowDomains[email[i+1:]] {
		return true
	}
	return false
}

// session: the request's session (its cookies, joined), and that text
func session(r *addon.Request) (sess, string, bool) {
	var s sess
	c, ok := cookieValue(r, cfg.cookie)
	if !ok {
		return s, "", false
	}
	for i := 1; i < chunks; i++ {
		more, ok := cookieValue(r, fmt.Sprintf("%s_%d", cfg.cookie, i))
		if !ok {
			break
		}
		c += more
	}
	// renewed already, its new cookie not there yet: the renewal
	renewMu.Lock()
	f := renewed[sha256.Sum256([]byte(c))]
	renewMu.Unlock()
	if f != nil {
		select {
		case <-f.done:
			if f.err == nil {
				return f.s, c, f.s.Exp >= time.Now().Unix() && allowed(f.s.Email)
			}
			if f.err == errRefused {
				return s, c, false
			}
		default:
		}
	}
	if !open(c, &s) || s.Exp < time.Now().Unix() || !allowed(s.Email) {
		return s, c, false
	}
	return s, c, true
}

// a sealed session is cut into cookies of this size, at most this many (a
// request head is 16 KiB at most in okena, and browsers take 4 KiB a cookie)
const chunk, chunks = 3800, 3

// setSession: the session's cookies (and those of a longer one before it
// cleared). What makes it too long goes first: the ID token (logout then
// names the client alone), then the access token.
func setSession(r *addon.Request, s sess) []string {
	v := seal(s)
	if len(v) > chunk*chunks {
		s.IDT = ""
		v = seal(s)
	}
	if len(v) > chunk*chunks {
		log.Print("oidc-okena: the access token makes the session too long for its cookies: not kept")
		s.AT = ""
		v = seal(s)
	}
	age := int(s.Exp - time.Now().Unix())
	var out []string
	for i := 0; i < chunks; i++ {
		name := cfg.cookie
		if i > 0 {
			name = fmt.Sprintf("%s_%d", cfg.cookie, i)
		}
		switch {
		case len(v) > 0:
			n := min(len(v), chunk)
			out = append(out, cookie(name, v[:n], age))
			v = v[n:]
		case i > 0:
			if _, had := cookieValue(r, name); had {
				out = append(out, clearCookie(name))
			}
		}
	}
	return out
}

func clearSession(r *addon.Request) []string {
	out := []string{clearCookie(cfg.cookie)}
	for i := 1; i < chunks; i++ {
		if _, had := cookieValue(r, fmt.Sprintf("%s_%d", cfg.cookie, i)); had {
			out = append(out, clearCookie(fmt.Sprintf("%s_%d", cfg.cookie, i)))
		}
	}
	return out
}

// ---------------------------------------------------------------- the provider

type tokens struct {
	IDToken      string `json:"id_token"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Error        string `json:"error"`
}

func tokenCall(form url.Values) (tokens, int, error) {
	var t tokens
	r, err := client.PostForm(prov.TokenEndpoint, form)
	if err != nil {
		return t, 0, err
	}
	defer r.Body.Close()
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&t); err != nil && r.StatusCode == 200 {
		return t, 0, err
	}
	return t, r.StatusCode, nil
}

func exchange(code, verifier, redirect string) (tokens, error) {
	t, status, err := tokenCall(url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirect},
		"client_id":     {cfg.clientID},
		"client_secret": {cfg.clientSecret},
		"code_verifier": {verifier},
	})
	if err != nil {
		return t, err
	}
	if status != 200 || t.IDToken == "" {
		return t, fmt.Errorf("%d %s", status, t.Error)
	}
	return t, nil
}

func verify(tok, nonce string) (map[string]any, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, errors.New("not a JWT")
	}
	var h struct{ Alg, Kid string }
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || json.Unmarshal(hb, &h) != nil {
		return nil, errors.New("its header")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("its signature")
	}
	if err := checkSig(h.Alg, h.Kid, []byte(parts[0]+"."+parts[1]), sig); err != nil {
		return nil, err
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("its claims")
	}
	var c map[string]any
	d := json.NewDecoder(bytes.NewReader(pb))
	d.UseNumber()
	if err := d.Decode(&c); err != nil {
		return nil, errors.New("its claims")
	}
	now := time.Now().Unix()
	if iss, _ := c["iss"].(string); iss != cfg.issuer {
		return nil, errors.New("another issuer")
	}
	if !audience(c["aud"]) {
		return nil, errors.New("another audience")
	}
	if exp, err := num(c["exp"]); err != nil || exp+60 < now {
		return nil, errors.New("expired")
	}
	if n, _ := c["nonce"].(string); nonce != "" && !hmac.Equal([]byte(n), []byte(nonce)) {
		return nil, errors.New("another nonce") // ("": a refresh's token, which has none to match)
	}
	return c, nil
}

func num(v any) (int64, error) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, errors.New("not a number")
	}
	f, err := n.Float64()
	return int64(f), err
}

func audience(v any) bool {
	switch a := v.(type) {
	case string:
		return a == cfg.clientID
	case []any:
		for _, x := range a {
			if s, _ := x.(string); s == cfg.clientID {
				return true
			}
		}
	}
	return false
}

func checkSig(alg, kid string, data, sig []byte) error {
	if strings.HasPrefix(alg, "HS") {
		var mac []byte
		switch alg {
		case "HS256":
			m := hmac.New(sha256.New, []byte(cfg.clientSecret))
			m.Write(data)
			mac = m.Sum(nil)
		default:
			return errors.New("an algorithm not taken: " + alg)
		}
		if !hmac.Equal(mac, sig) {
			return errors.New("a bad signature")
		}
		return nil
	}
	if len(alg) < 5 {
		return errors.New("an algorithm not taken: " + alg)
	}
	k := key(kid)
	if k == nil {
		return errors.New("no key " + kid)
	}
	var hf crypto.Hash
	switch alg[2:] {
	case "256":
		hf = crypto.SHA256
	case "384":
		hf = crypto.SHA384
	case "512":
		hf = crypto.SHA512
	}
	if alg == "EdDSA" {
		if pk, ok := k.(ed25519.PublicKey); ok && ed25519.Verify(pk, data, sig) {
			return nil
		}
		return errors.New("a bad signature")
	}
	if hf == 0 {
		return errors.New("an algorithm not taken: " + alg)
	}
	var digest []byte
	switch hf {
	case crypto.SHA256:
		d := sha256.Sum256(data)
		digest = d[:]
	case crypto.SHA384:
		d := sha512.Sum384(data)
		digest = d[:]
	default:
		d := sha512.Sum512(data)
		digest = d[:]
	}
	switch pk := k.(type) {
	case *rsa.PublicKey:
		switch alg[:2] {
		case "RS":
			if rsa.VerifyPKCS1v15(pk, hf, digest, sig) == nil {
				return nil
			}
		case "PS":
			if rsa.VerifyPSS(pk, hf, digest, sig, nil) == nil {
				return nil
			}
		}
	case *ecdsa.PublicKey:
		n := (pk.Curve.Params().BitSize + 7) / 8
		if alg[:2] == "ES" && len(sig) == 2*n {
			r := new(big.Int).SetBytes(sig[:n])
			s := new(big.Int).SetBytes(sig[n:])
			if ecdsa.Verify(pk, digest, r, s) {
				return nil
			}
		}
	}
	return errors.New("a bad signature")
}

// key: the provider's key of that id, its set fetched again (once a minute
// at most) when it is not known: providers rotate them
func key(kid string) crypto.PublicKey {
	keysMu.RLock()
	k := keys[kid]
	at := keysAt
	keysMu.RUnlock()
	if k == nil && time.Since(at) > time.Minute {
		if err := loadKeys(); err != nil {
			log.Print("oidc-okena: the provider's keys: ", err)
		}
		keysMu.RLock()
		k = keys[kid]
		keysMu.RUnlock()
	}
	return k
}

func loadKeys() error {
	var set struct {
		Keys []struct {
			Kty, Kid, Crv, N, E, X, Y string
		} `json:"keys"`
	}
	if err := getJSON(prov.JWKSURI, &set); err != nil {
		return err
	}
	m := map[string]crypto.PublicKey{}
	b := func(s string) *big.Int {
		d, _ := base64.RawURLEncoding.DecodeString(s)
		return new(big.Int).SetBytes(d)
	}
	for _, k := range set.Keys {
		switch k.Kty {
		case "RSA":
			m[k.Kid] = &rsa.PublicKey{N: b(k.N), E: int(b(k.E).Int64())}
		case "EC":
			var c elliptic.Curve
			switch k.Crv {
			case "P-256":
				c = elliptic.P256()
			case "P-384":
				c = elliptic.P384()
			case "P-521":
				c = elliptic.P521()
			default:
				continue
			}
			pk := &ecdsa.PublicKey{Curve: c, X: b(k.X), Y: b(k.Y)}
			if !c.IsOnCurve(pk.X, pk.Y) {
				continue
			}
			m[k.Kid] = pk
		case "OKP":
			if k.Crv == "Ed25519" {
				d, _ := base64.RawURLEncoding.DecodeString(k.X)
				if len(d) == ed25519.PublicKeySize {
					m[k.Kid] = ed25519.PublicKey(d)
				}
			}
		}
	}
	keysMu.Lock()
	keys, keysAt = m, time.Now()
	keysMu.Unlock()
	return nil
}

// ---------------------------------------------------------------- cookies

func token(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func seal(v any) string {
	p, _ := json.Marshal(v)
	nonce := make([]byte, cfg.aead.NonceSize())
	rand.Read(nonce)
	return base64.RawURLEncoding.EncodeToString(cfg.aead.Seal(nonce, nonce, p, []byte(cfg.cookie)))
}

func open(s string, v any) bool {
	b, err := base64.RawURLEncoding.DecodeString(s)
	ns := cfg.aead.NonceSize()
	if err != nil || len(b) < ns {
		return false
	}
	p, err := cfg.aead.Open(nil, b[:ns], b[ns:], []byte(cfg.cookie))
	return err == nil && json.Unmarshal(p, v) == nil
}

func cookie(name, value string, maxAge int) string {
	c := fmt.Sprintf("%s=%s; Path=/; Max-Age=%d; HttpOnly; SameSite=Lax", name, value, maxAge)
	if cfg.secure {
		c += "; Secure"
	}
	return c
}

func clearCookie(name string) string { return cookie(name, "", 0) }

func cookies(r *addon.Request) []string {
	var out []string
	for _, f := range r.Headers {
		if strings.EqualFold(f.Name, "cookie") {
			for _, c := range strings.Split(f.Value, ";") {
				if c = strings.TrimSpace(c); c != "" {
					out = append(out, c)
				}
			}
		}
	}
	return out
}

func cookieValue(r *addon.Request, name string) (string, bool) {
	for _, c := range cookies(r) {
		if v, ok := strings.CutPrefix(c, name+"="); ok {
			return v, true
		}
	}
	return "", false
}

func cookiesWithout(r *addon.Request, name string) string {
	var keep []string
	for _, c := range cookies(r) {
		n, _, _ := strings.Cut(c, "=")
		if n == name || n == name+"_state" || (strings.HasPrefix(n, name+"_") && len(n) == len(name)+2 && n[len(name)+1] >= '1' && n[len(name)+1] <= '9') {
			continue
		}
		keep = append(keep, c)
	}
	return strings.Join(keep, "; ")
}
