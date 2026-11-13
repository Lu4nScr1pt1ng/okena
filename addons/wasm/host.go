package main

// The proxy-wasm host: the ABI (0.2.1, and 0.1.0's names) that Envoy, nginx
// and Traefik give plugins, on wazero. Each instance of the plugin runs one
// request at a time (as on one Envoy worker); the addon runs several
// instances at once. Imports a plugin wants that are not here are given as
// stubs answering Unimplemented, so any plugin instantiates.

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// WasmResult
const (
	rOK               = 0
	rNotFound         = 1
	rBadArgument      = 2
	rInvalidMemory    = 6
	rEmpty            = 7
	rCasMismatch      = 8
	rUnimplemented    = 12
	actionContinue    = 0
	actionPause       = 1
	mapRequestHeaders = 0
	mapResponseHeaders = 2
	bufResponseBody   = 1
	mapCallHeaders    = 6
	mapCallTrailers   = 7
	bufRequestBody    = 0
	bufCallBody       = 4
	bufVMConfig       = 6
	bufPluginConfig   = 7
)

type pair [2]string

type localResponse struct {
	status  int
	headers []pair
	body    []byte
}

type callout struct {
	token   uint32
	cluster string
	headers []pair
	body    []byte
	timeout time.Duration
}

type calloutAnswer struct {
	headers []pair
	body    []byte
}

// a request in an instance
type stream struct {
	id        uint32
	headers   []pair
	local     *localResponse
	continued bool
	closed    bool
	props     map[string][]byte
	req       *requestInfo
	body      []byte
	resp      []pair // the response's headers (:status first)
	respBody  []byte
	at        time.Time
}

type requestInfo struct {
	method, path, host, scheme, protocol, client string
}

type shared struct {
	mu    sync.Mutex
	data  map[string][]byte
	cas   map[string]uint32
	next  uint32
	mmu   sync.Mutex
	mvals map[uint32]uint64
	mnext uint32
}

type host struct {
	rt        wazero.Runtime
	compiled  wazero.CompiledModule
	vmConfig  []byte
	config    []byte
	name      string
	rootID    string
	clusters  map[string]string
	logLevel  int
	shared    *shared
	instances sync.Map // module name -> *instance
	client    *http.Client
}

type instance struct {
	mu        sync.Mutex
	h         *host
	mod       api.Module
	fn        map[string]api.Function
	abi01     bool
	root      uint32
	next      uint32
	cur       *stream
	effective uint32
	tick      time.Duration
	tickSet   chan struct{}
	pending   []*callout
	answer    *calloutAnswer
	token     uint32
}

// cacheDir: where compiled plugins are kept (wazero's compilation cache), so
// that a restart does not compile again; "" none
func newHost(ctx context.Context, wasm []byte, h *host, cacheDir string) error {
	rc := wazero.NewRuntimeConfig()
	if cacheDir != "" {
		if c, err := wazero.NewCompilationCacheWithDir(cacheDir); err == nil {
			rc = rc.WithCompilationCache(c)
		} else {
			log.Printf("%s: no compilation cache in %s: %v", h.name, cacheDir, err)
		}
	}
	h.rt = wazero.NewRuntimeWithConfig(ctx, rc)
	wasi_snapshot_preview1.MustInstantiate(ctx, h.rt)
	c, err := h.rt.CompileModule(ctx, wasm)
	if err != nil {
		return fmt.Errorf("compiling the plugin: %w", err)
	}
	h.compiled = c
	b := h.rt.NewHostModuleBuilder("env")
	done := map[string]bool{}
	for name, f := range h.functions() {
		b.NewFunctionBuilder().WithGoModuleFunction(f.fn, f.params, f.results).Export(name)
		done[name] = true
	}
	// what the plugin imports and the host does not give: Unimplemented
	for _, d := range c.ImportedFunctions() {
		mod, name, _ := d.Import()
		if mod != "env" || done[name] {
			continue
		}
		results := d.ResultTypes()
		b.NewFunctionBuilder().WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
			if len(results) > 0 {
				stack[0] = rUnimplemented
			}
		}), d.ParamTypes(), results).Export(name)
		done[name] = true
	}
	if _, err := b.Instantiate(ctx); err != nil {
		return fmt.Errorf("the host functions: %w", err)
	}
	return nil
}

// an instance of the plugin, started and configured
func (h *host) instantiate(ctx context.Context, n int) (*instance, error) {
	name := fmt.Sprintf("plugin-%d", n)
	start := []string{}
	exports := h.compiled.ExportedFunctions()
	if _, ok := exports["_initialize"]; ok {
		start = []string{"_initialize"}
	} else if _, ok := exports["_start"]; ok {
		start = []string{"_start"}
	}
	cfg := wazero.NewModuleConfig().WithName(name).WithStartFunctions().WithStdout(os.Stderr).WithStderr(os.Stderr).
		WithSysNanotime().WithSysWalltime().WithSysNanosleep().WithRandSource(randReader{})
	in := &instance{h: h, fn: map[string]api.Function{}, root: 1, next: 2, tickSet: make(chan struct{}, 1)}
	h.instances.Store(name, in)
	m, err := h.rt.InstantiateModule(ctx, h.compiled, cfg)
	if err != nil {
		return nil, fmt.Errorf("instantiating the plugin: %w", err)
	}
	in.mod = m
	for _, s := range start {
		if _, err := m.ExportedFunction(s).Call(ctx); err != nil {
			return nil, fmt.Errorf("%s: %w", s, err)
		}
	}
	for _, f := range []string{"proxy_on_memory_allocate", "malloc", "proxy_on_context_create", "proxy_on_vm_start",
		"proxy_on_configure", "proxy_on_request_headers", "proxy_on_request_body", "proxy_on_response_headers",
		"proxy_on_response_body", "proxy_on_done", "proxy_on_log", "proxy_on_delete",
		"proxy_on_tick", "proxy_on_http_call_response"} {
		if fn := m.ExportedFunction(f); fn != nil {
			in.fn[f] = fn
		}
	}
	if in.fn["proxy_on_memory_allocate"] == nil {
		in.fn["proxy_on_memory_allocate"] = in.fn["malloc"]
	}
	if in.fn["proxy_on_memory_allocate"] == nil || in.fn["proxy_on_context_create"] == nil {
		return nil, fmt.Errorf("not a proxy-wasm plugin (no proxy_on_memory_allocate or proxy_on_context_create)")
	}
	if f := in.fn["proxy_on_request_headers"]; f != nil && len(f.Definition().ParamTypes()) == 2 {
		in.abi01 = true
	}
	in.effective = in.root
	if _, err := in.call(ctx, "proxy_on_context_create", uint64(in.root), 0); err != nil {
		return nil, err
	}
	if r, err := in.call(ctx, "proxy_on_vm_start", uint64(in.root), uint64(len(h.vmConfig))); err != nil || (r != nil && r[0] == 0) {
		return nil, fmt.Errorf("the plugin refused to start (proxy_on_vm_start): %v", err)
	}
	if r, err := in.call(ctx, "proxy_on_configure", uint64(in.root), uint64(len(h.config))); err != nil || (r != nil && r[0] == 0) {
		return nil, fmt.Errorf("the plugin refused its configuration (proxy_on_configure): %v", err)
	}
	in.runCallouts(ctx, in.root)
	go in.ticker()
	return in, nil
}

func (in *instance) call(ctx context.Context, name string, args ...uint64) ([]uint64, error) {
	f := in.fn[name]
	if f == nil {
		return nil, nil
	}
	r, err := f.Call(ctx, args...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return r, nil
}

func (in *instance) ticker() {
	var t *time.Ticker
	var c <-chan time.Time
	for {
		select {
		case <-in.tickSet:
			if t != nil {
				t.Stop()
				t, c = nil, nil
			}
			if in.tick > 0 {
				t = time.NewTicker(in.tick)
				c = t.C
			}
		case <-c:
			in.mu.Lock()
			ctx := context.Background()
			in.effective = in.root
			if _, err := in.call(ctx, "proxy_on_tick", uint64(in.root)); err != nil {
				log.Printf("%s: %v", in.h.name, err)
			}
			in.runCallouts(ctx, in.root)
			in.mu.Unlock()
		}
	}
}

// the callouts the plugin dispatched: made one after the other, each answer
// handed to the plugin (with its root context, as Envoy does)
func (in *instance) runCallouts(ctx context.Context, from uint32) {
	for len(in.pending) > 0 {
		c := in.pending[0]
		in.pending = in.pending[1:]
		in.answer = in.h.dispatch(c)
		in.effective = from
		nb := 0
		if in.answer != nil {
			nb = len(in.answer.body)
		}
		nh := 0
		if in.answer != nil {
			nh = len(in.answer.headers)
		}
		if _, err := in.call(ctx, "proxy_on_http_call_response", uint64(in.root), uint64(c.token), uint64(nh), uint64(nb), 0); err != nil {
			log.Printf("%s: %v", in.h.name, err)
		}
		in.answer = nil
	}
}

func (h *host) dispatch(c *callout) *calloutAnswer {
	addr := c.cluster
	if a, ok := h.clusters[c.cluster]; ok {
		addr = a
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		log.Printf("%s: http_call to %q: no such cluster (-cluster NAME=HOST:PORT)", h.name, c.cluster)
		return nil
	}
	method, path, authority := "GET", "/", addr
	var hs http.Header = http.Header{}
	for _, p := range c.headers {
		switch p[0] {
		case ":method":
			method = p[1]
		case ":path":
			path = p[1]
		case ":authority":
			authority = p[1]
		default:
			if !strings.HasPrefix(p[0], ":") {
				hs.Add(p[0], p[1])
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, "http://"+addr+path, bytes.NewReader(c.body))
	if err != nil {
		return nil
	}
	req.Header = hs
	req.Host = authority
	resp, err := h.client.Do(req)
	if err != nil {
		log.Printf("%s: http_call to %s: %v", h.name, addr, err)
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	a := &calloutAnswer{body: body, headers: []pair{{":status", fmt.Sprint(resp.StatusCode)}}}
	for k, vs := range resp.Header {
		for _, v := range vs {
			a.headers = append(a.headers, pair{strings.ToLower(k), v})
		}
	}
	return a
}

// --------------------------------------------------------------- memory

func readBytes(m api.Module, ptr, size uint32) ([]byte, bool) {
	b, ok := m.Memory().Read(ptr, size)
	if !ok {
		return nil, false
	}
	return append([]byte(nil), b...), true
}

func (in *instance) give(ctx context.Context, m api.Module, data []byte, retPtr, retSize uint32) uint64 {
	var ptr uint32
	if len(data) > 0 {
		r, err := in.fn["proxy_on_memory_allocate"].Call(ctx, uint64(len(data)))
		if err != nil || r[0] == 0 {
			return rInvalidMemory
		}
		ptr = uint32(r[0])
		if !m.Memory().Write(ptr, data) {
			return rInvalidMemory
		}
	}
	if !m.Memory().WriteUint32Le(retPtr, ptr) || !m.Memory().WriteUint32Le(retSize, uint32(len(data))) {
		return rInvalidMemory
	}
	return rOK
}

func encodePairs(ps []pair) []byte {
	n := 4 + 8*len(ps)
	for _, p := range ps {
		n += len(p[0]) + len(p[1]) + 2
	}
	b := make([]byte, 4, n)
	binary.LittleEndian.PutUint32(b, uint32(len(ps)))
	for _, p := range ps {
		b = binary.LittleEndian.AppendUint32(b, uint32(len(p[0])))
		b = binary.LittleEndian.AppendUint32(b, uint32(len(p[1])))
	}
	for _, p := range ps {
		b = append(b, p[0]...)
		b = append(b, 0)
		b = append(b, p[1]...)
		b = append(b, 0)
	}
	return b
}

func decodePairs(b []byte) ([]pair, bool) {
	if len(b) < 4 {
		return nil, len(b) == 0
	}
	n := int(binary.LittleEndian.Uint32(b))
	if 4+8*n > len(b) {
		return nil, false
	}
	at := 4 + 8*n
	ps := make([]pair, n)
	for i := 0; i < n; i++ {
		kl := int(binary.LittleEndian.Uint32(b[4+8*i:]))
		vl := int(binary.LittleEndian.Uint32(b[8+8*i:]))
		if at+kl+vl+2 > len(b) {
			return nil, false
		}
		ps[i] = pair{string(b[at : at+kl]), string(b[at+kl+1 : at+kl+1+vl])}
		at += kl + vl + 2
	}
	return ps, true
}

type randReader struct{}

func (randReader) Read(p []byte) (int, error) {
	f, err := os.Open("/dev/urandom")
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return io.ReadFull(f, p)
}
