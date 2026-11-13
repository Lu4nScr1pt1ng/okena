// wasm-okena: proxy-wasm plugins (the ABI Envoy, nginx and Traefik run) as an
// okena addon, on wazero (no cgo). The plugin runs in this process, apart
// from okena's workers, like every addon.
//
//	addon auth {
//	    run /usr/local/bin/wasm-okena -plugin /etc/okena/auth.wasm -config '{"realm":"x"}' -cluster authz=10.0.0.5:8080
//	    timeout 50ms
//	}
//	route /api/* { addon auth; to pool api }
//
// For each request the plugin's HTTP context sees the request headers as
// Envoy gives them (lowercase names, with :method, :path, :authority and
// :scheme) in proxy_on_request_headers; what it changes goes back to okena (a
// changed :path is the new target, :authority the Host), and a
// proxy_send_local_response is okena's answer to the client. A plugin that
// pauses for proxy_http_call gets the answer (the call is made here, to
// -cluster's address) and continues or answers then.
//
//	-plugin FILE      the .wasm
//	-config TEXT      the plugin's configuration (@FILE reads it from a file)
//	-vm-config TEXT   the VM's (proxy_on_vm_start)
//	-root-id NAME     the root context's id (plugin_root_id)
//	-name NAME        the plugin's name (plugin_name, logs)
//	-cluster N=H:P    an upstream for proxy_http_call (repeatable); a cluster
//	                  named HOST:PORT needs none
//	-instances N      plugin instances (requests at once; default: the CPUs)
//	-cache DIR        compiled plugins kept there (default ~/.cache/okena-wasm; "": none)
//	-compile          compile the plugin into the cache and exit (before deploying)
//	-log-level N      0 trace ... 5 critical (default 2, info)
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	addon "github.com/Lu4nScr1pt1ng/okena/sdk/go"
)

func defaultCache() string {
	if d, err := os.UserCacheDir(); err == nil {
		return d + "/okena-wasm"
	}
	return ""
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func text(v string) []byte {
	if strings.HasPrefix(v, "@") {
		b, err := os.ReadFile(v[1:])
		if err != nil {
			log.Fatal(err)
		}
		return b
	}
	return []byte(v)
}

func main() {
	plugin := flag.String("plugin", "", "the proxy-wasm plugin (.wasm)")
	config := flag.String("config", "", "its configuration (@FILE: from a file)")
	vmConfig := flag.String("vm-config", "", "the VM's configuration (@FILE: from a file)")
	rootID := flag.String("root-id", "", "the root context's id")
	name := flag.String("name", "", "the plugin's name (default: the addon's)")
	instances := flag.Int("instances", runtime.NumCPU(), "plugin instances: requests at once")
	cache := flag.String("cache", defaultCache(), "compiled plugins kept here, so a restart does not compile again (\"\": none)")
	compileOnly := flag.Bool("compile", false, "compile the plugin into the cache, then exit")
	logLevel := flag.Int("log-level", 2, "the least level logged, 0 trace to 5 critical")
	var clusters multi
	flag.Var(&clusters, "cluster", "NAME=HOST:PORT, an upstream for proxy_http_call (repeatable)")
	flag.Parse()
	log.SetFlags(0)
	log.SetPrefix("wasm-okena: ")
	if *plugin == "" {
		log.Fatal("-plugin FILE is needed")
	}
	wasm, err := os.ReadFile(*plugin)
	if err != nil {
		log.Fatal(err)
	}
	if *name == "" {
		*name = os.Getenv("OKENA_ADDON_NAME")
	}
	h := &host{
		vmConfig: text(*vmConfig), config: text(*config), name: *name, rootID: *rootID,
		clusters: map[string]string{}, logLevel: *logLevel,
		shared: &shared{data: map[string][]byte{}, cas: map[string]uint32{}, mvals: map[uint32]uint64{}},
		client: &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 64, IdleConnTimeout: 90 * time.Second}},
	}
	for _, c := range clusters {
		k, v, ok := strings.Cut(c, "=")
		if !ok {
			log.Fatalf("-cluster %q: NAME=HOST:PORT", c)
		}
		h.clusters[k] = v
	}
	ctx := context.Background()
	if err := newHost(ctx, wasm, h, *cache); err != nil {
		log.Fatal(err)
	}
	if *compileOnly {
		return
	}
	if *instances < 1 {
		*instances = 1
	}
	pool := make(chan *instance, *instances)
	for i := 0; i < *instances; i++ {
		in, err := h.instantiate(ctx, i)
		if err != nil {
			log.Fatal(err)
		}
		pool <- in
	}
	log.Printf("%s ready: %s, %d instances", h.name, *plugin, *instances)
	log.Fatal(addon.Run(func(r *addon.Request, a *addon.Answer) {
		in := <-pool
		defer func() { pool <- in }()
		in.mu.Lock()
		defer in.mu.Unlock()
		if err := in.request(ctx, r, a); err != nil {
			log.Printf("%s: %v", h.name, err)
			a.Fail()
		}
	}, addon.Options{Workers: *instances}))
}

// a request through the plugin's HTTP context: what it decides into a
func (in *instance) request(ctx context.Context, r *addon.Request, a *addon.Answer) error {
	host, _ := r.Header("host")
	scheme := "http"
	if r.Flags&addon.FlagTLS != 0 {
		scheme = "https"
	}
	proto := "HTTP/1.1"
	if r.Flags&addon.FlagH2 != 0 {
		proto = "HTTP/2"
	} else if r.Flags&addon.FlagH3 != 0 {
		proto = "HTTP/3"
	}
	client := ""
	if ip := r.ClientIP(); ip != nil {
		client = ip.String()
	}
	st := &stream{id: in.next, req: &requestInfo{method: r.Method, path: r.Target, host: host, scheme: scheme, protocol: proto, client: client}}
	in.next++
	st.headers = []pair{{":authority", host}, {":path", r.Target}, {":method", r.Method}, {":scheme", scheme}}
	eos := true
	for _, f := range r.Headers {
		n := strings.ToLower(f.Name)
		if n == "host" {
			continue
		}
		if n == "content-length" && f.Value != "0" || n == "transfer-encoding" {
			eos = false
		}
		st.headers = append(st.headers, pair{n, f.Value})
	}
	orig := append([]pair(nil), st.headers...)
	in.cur = st
	in.effective = st.id
	defer func() {
		in.effective = st.id
		in.call(ctx, "proxy_on_log", uint64(st.id))
		in.call(ctx, "proxy_on_done", uint64(st.id))
		in.call(ctx, "proxy_on_delete", uint64(st.id))
		in.cur = nil
		in.pending = nil
	}()
	if _, err := in.call(ctx, "proxy_on_context_create", uint64(st.id), uint64(in.root)); err != nil {
		return err
	}
	var res []uint64
	var err error
	if in.abi01 {
		res, err = in.call(ctx, "proxy_on_request_headers", uint64(st.id), uint64(len(st.headers)))
	} else {
		e := uint64(0)
		if eos {
			e = 1
		}
		res, err = in.call(ctx, "proxy_on_request_headers", uint64(st.id), uint64(len(st.headers)), e)
	}
	if err != nil {
		return err
	}
	action := uint64(actionContinue)
	if res != nil {
		action = res[0]
	}
	// paused for callouts: their answers, until it continues or answers
	if action == actionPause && st.local == nil {
		in.runCallouts(ctx, in.root)
		if st.local == nil && !st.continued && !st.closed {
			return fmt.Errorf("the plugin paused the request and neither continued nor answered it")
		}
	}
	// the body, when the addon's call carries one (phases request_body)
	if st.local == nil && !st.closed && !eos && (len(r.Body) > 0 || !r.BodyUnread) && in.fn["proxy_on_request_body"] != nil {
		st.body = r.Body
		st.continued = false
		e := uint64(1)
		if r.BodyTruncated {
			e = 0
		}
		res, err := in.call(ctx, "proxy_on_request_body", uint64(st.id), uint64(len(r.Body)), e)
		if err != nil {
			return err
		}
		if res != nil && res[0] == actionPause && st.local == nil {
			in.runCallouts(ctx, in.root)
		}
	}
	if st.closed && st.local == nil {
		st.local = &localResponse{status: 403}
	}
	if l := st.local; l != nil {
		status := l.status
		if status < 200 || status > 599 {
			status = 403
		}
		a.Respond(status)
		for _, p := range l.headers {
			a.Add(p[0], p[1])
		}
		a.Body(l.body)
		return nil
	}
	diff(orig, st.headers, a)
	return nil
}

// what the plugin changed in the request's headers, as okena's ops
func diff(orig, now []pair, a *addon.Answer) {
	pseudo := func(ps []pair, k string) string {
		for _, p := range ps {
			if p[0] == k {
				return p[1]
			}
		}
		return ""
	}
	if p := pseudo(now, ":path"); p != pseudo(orig, ":path") && strings.HasPrefix(p, "/") {
		a.Target(p)
	}
	if h := pseudo(now, ":authority"); h != pseudo(orig, ":authority") && h != "" {
		a.Set("host", h)
	}
	values := func(ps []pair) (map[string][]string, []string) {
		m := map[string][]string{}
		var order []string
		for _, p := range ps {
			if strings.HasPrefix(p[0], ":") {
				continue
			}
			if _, ok := m[p[0]]; !ok {
				order = append(order, p[0])
			}
			m[p[0]] = append(m[p[0]], p[1])
		}
		return m, order
	}
	om, oorder := values(orig)
	nm, norder := values(now)
	for _, k := range oorder {
		if _, ok := nm[k]; !ok {
			a.Remove(k)
		}
	}
	for _, k := range norder {
		nv, ov := nm[k], om[k]
		if strings.Join(nv, "\x00") == strings.Join(ov, "\x00") && len(nv) == len(ov) {
			continue
		}
		a.Set(k, nv[0])
		for _, v := range nv[1:] {
			a.Add(k, v)
		}
	}
}
