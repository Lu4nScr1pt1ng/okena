// ext-okena: Envoy's external authorization (ext_authz) and external
// processing (ext_proc) gRPC services, for okena: services written for Envoy
// decide okena's requests unchanged.
//
//	addon authz {
//	    run /usr/local/bin/ext-okena -authz 10.0.0.7:9001
//	    timeout 200ms
//	    on_error deny          # Envoy's failure_mode_allow: false
//	}
//	route /api/* { addon authz; to pool api }
//
// -authz: each request is a CheckRequest (envoy.service.auth.v3): its method,
// path, host, scheme, protocol, headers (lowercase, with :method, :path,
// :authority, :scheme as Envoy sends them) and the client's address. OK lets
// it on with ok_response's headers set, added or removed and its query
// parameters set or removed; a denial is okena's answer with denied_response's
// status (403 unless given), headers and body.
//
// -proc: each request opens an ext_proc stream (envoy.service.ext_proc.v3),
// sends request_headers, and applies the answer: a header mutation (a
// :path is the new target, :authority the Host) or an immediate response.
//
// With both, ext_authz is asked first. An error, or no answer within -timeout
// or the addon's own timeout, leaves the request to okena's on_error.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	procv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"

	addon "github.com/Lu4nScr1pt1ng/okena/sdk/go"
)

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

var (
	authz   authv3.AuthorizationClient
	proc    procv3.ExternalProcessorClient
	timeout time.Duration
	extras  = map[string]string{}
)

func dial(addr string, useTLS bool, ca string) *grpc.ClientConn {
	creds := insecure.NewCredentials()
	if useTLS {
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if ca != "" {
			pem, err := os.ReadFile(ca)
			if err != nil {
				log.Fatal(err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				log.Fatalf("%s: no certificate", ca)
			}
			cfg.RootCAs = pool
		}
		creds = credentials.NewTLS(cfg)
	}
	c, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Fatal(err)
	}
	return c
}

func main() {
	a := flag.String("authz", "", "an ext_authz service, HOST:PORT")
	p := flag.String("proc", "", "an ext_proc service, HOST:PORT")
	useTLS := flag.Bool("tls", false, "speak TLS to them")
	ca := flag.String("ca", "", "the CA that signs their certificates (with -tls; default: the system's)")
	flag.DurationVar(&timeout, "timeout", 5*time.Second, "a call's time")
	workers := flag.Int("workers", 256, "requests asked about at once")
	var ctxext multi
	flag.Var(&ctxext, "context", "KEY=VALUE, sent in ext_authz's context_extensions (repeatable)")
	flag.Parse()
	log.SetFlags(0)
	log.SetPrefix("ext-okena: ")
	if *a == "" && *p == "" {
		log.Fatal("-authz HOST:PORT, -proc HOST:PORT, or both")
	}
	for _, kv := range ctxext {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			log.Fatalf("-context %q: KEY=VALUE", kv)
		}
		extras[k] = v
	}
	if *a != "" {
		authz = authv3.NewAuthorizationClient(dial(*a, *useTLS, *ca))
	}
	if *p != "" {
		proc = procv3.NewExternalProcessorClient(dial(*p, *useTLS, *ca))
	}
	log.Printf("ready: ext_authz %q, ext_proc %q", *a, *p)
	log.Fatal(addon.Run(handle, addon.Options{Workers: *workers}))
}

type view struct {
	method, target, host, scheme, protocol string
	headers                                []field // lowercase, pseudo-headers first
}

type field struct{ k, v string }

func (v *view) get(k string) (string, bool) {
	for _, f := range v.headers {
		if f.k == k {
			return f.v, true
		}
	}
	return "", false
}

func handle(r *addon.Request, a *addon.Answer) {
	v := &view{method: r.Method, target: r.Target, scheme: "http", protocol: "HTTP/1.1"}
	v.host, _ = r.Header("host")
	if r.Flags&addon.FlagTLS != 0 {
		v.scheme = "https"
	}
	if r.Flags&addon.FlagH2 != 0 {
		v.protocol = "HTTP/2"
	} else if r.Flags&addon.FlagH3 != 0 {
		v.protocol = "HTTP/3"
	}
	v.headers = []field{{":authority", v.host}, {":path", v.target}, {":method", v.method}, {":scheme", v.scheme}}
	for _, f := range r.Headers {
		if k := strings.ToLower(f.Name); k != "host" {
			v.headers = append(v.headers, field{k, f.Value})
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if authz != nil {
		done, err := check(ctx, r, v, a)
		if err != nil {
			log.Printf("ext_authz: %v", err)
			a.Fail()
			return
		}
		if done {
			return
		}
	}
	if proc != nil {
		if err := process(ctx, v, a); err != nil {
			log.Printf("ext_proc: %v", err)
			a.Fail()
		}
	}
}

// ext_authz: true when it answered the request (denied)
func check(ctx context.Context, r *addon.Request, v *view, a *addon.Answer) (bool, error) {
	hs := map[string]string{}
	for _, f := range v.headers {
		if old, ok := hs[f.k]; ok {
			hs[f.k] = old + "," + f.v
		} else {
			hs[f.k] = f.v
		}
	}
	path, query, _ := strings.Cut(v.target, "?")
	_ = path
	client := ""
	if ip := r.ClientIP(); ip != nil {
		client = ip.String()
	}
	req := &authv3.CheckRequest{Attributes: &authv3.AttributeContext{
		Source: &authv3.AttributeContext_Peer{Address: &corev3.Address{Address: &corev3.Address_SocketAddress{
			SocketAddress: &corev3.SocketAddress{Address: client, PortSpecifier: &corev3.SocketAddress_PortValue{PortValue: 0}}}}},
		Request: &authv3.AttributeContext_Request{Time: timestamppb.Now(), Http: &authv3.AttributeContext_HttpRequest{
			Method: v.method, Headers: hs, Path: v.target, Host: v.host, Scheme: v.scheme, Protocol: v.protocol, Query: query,
		}},
		ContextExtensions: extras,
	}}
	resp, err := authz.Check(ctx, req)
	if err != nil {
		return false, err
	}
	if resp.GetStatus().GetCode() == 0 {
		ok := resp.GetOkResponse()
		for _, h := range ok.GetHeaders() {
			option(v, h, a)
		}
		for _, k := range ok.GetHeadersToRemove() {
			a.Remove(k)
		}
		if len(ok.GetQueryParametersToSet()) > 0 || len(ok.GetQueryParametersToRemove()) > 0 {
			u, err := url.ParseRequestURI(v.target)
			if err == nil {
				q := u.Query()
				for _, k := range ok.GetQueryParametersToRemove() {
					q.Del(k)
				}
				for _, p := range ok.GetQueryParametersToSet() {
					q.Set(p.GetKey(), p.GetValue())
				}
				u.RawQuery = q.Encode()
				a.Target(u.RequestURI())
			}
		}
		return false, nil
	}
	d := resp.GetDeniedResponse()
	status := int(d.GetStatus().GetCode())
	if status < 200 || status > 599 {
		status = 403
	}
	a.Respond(status)
	for _, h := range d.GetHeaders() {
		a.Add(h.GetHeader().GetKey(), value(h.GetHeader()))
	}
	a.Body([]byte(d.GetBody()))
	return true, nil
}

func value(h *corev3.HeaderValue) string {
	if len(h.GetRawValue()) > 0 {
		return string(h.GetRawValue())
	}
	return h.GetValue()
}

// a header option onto the request: overwrite unless it says to append
func option(v *view, h *corev3.HeaderValueOption, a *addon.Answer) {
	k := strings.ToLower(h.GetHeader().GetKey())
	val := value(h.GetHeader())
	_, present := v.get(k)
	switch {
	case k == ":path":
		if strings.HasPrefix(val, "/") {
			a.Target(val)
		}
		return
	case k == ":authority":
		k = "host"
	case strings.HasPrefix(k, ":"):
		return
	}
	if h.GetAppend() != nil {
		if h.GetAppend().GetValue() {
			a.Add(k, val)
		} else {
			a.Set(k, val)
		}
		return
	}
	switch h.GetAppendAction() {
	case corev3.HeaderValueOption_ADD_IF_ABSENT:
		if !present {
			a.Set(k, val)
		}
	case corev3.HeaderValueOption_OVERWRITE_IF_EXISTS:
		if present {
			a.Set(k, val)
		}
	default:
		a.Set(k, val)
	}
}

// ext_proc: the request headers on a stream of their own, one answer
func process(ctx context.Context, v *view, a *addon.Answer) error {
	s, err := proc.Process(ctx)
	if err != nil {
		return err
	}
	defer s.CloseSend()
	hm := &corev3.HeaderMap{}
	for _, f := range v.headers {
		hm.Headers = append(hm.Headers, &corev3.HeaderValue{Key: f.k, RawValue: []byte(f.v)})
	}
	_, hasBody := v.get("content-length")
	if cl, _ := v.get("content-length"); cl == "0" {
		hasBody = false
	}
	if _, te := v.get("transfer-encoding"); te {
		hasBody = true
	}
	if err := s.Send(&procv3.ProcessingRequest{Request: &procv3.ProcessingRequest_RequestHeaders{
		RequestHeaders: &procv3.HttpHeaders{Headers: hm, EndOfStream: !hasBody}}}); err != nil {
		return err
	}
	resp, err := s.Recv()
	if err != nil {
		return err
	}
	if im := resp.GetImmediateResponse(); im != nil {
		status := int(im.GetStatus().GetCode())
		if status < 200 || status > 599 {
			status = 200
		}
		a.Respond(status)
		for _, h := range im.GetHeaders().GetSetHeaders() {
			a.Add(h.GetHeader().GetKey(), value(h.GetHeader()))
		}
		a.Body(im.GetBody())
		return nil
	}
	rh := resp.GetRequestHeaders()
	if rh == nil {
		return fmt.Errorf("an answer to request_headers was expected, not %T", resp.GetResponse())
	}
	m := rh.GetResponse().GetHeaderMutation()
	for _, k := range m.GetRemoveHeaders() {
		if !strings.HasPrefix(k, ":") {
			a.Remove(k)
		}
	}
	for _, h := range m.GetSetHeaders() {
		option(v, h, a)
	}
	return nil
}
