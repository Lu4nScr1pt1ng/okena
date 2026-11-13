package main

// The host functions of the proxy-wasm ABI (module "env").

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/tetratelabs/wazero/api"
)

type hostFn struct {
	fn      api.GoModuleFunction
	params  []api.ValueType
	results []api.ValueType
}

var (
	i32 = api.ValueTypeI32
	i64 = api.ValueTypeI64
)

func sig(n int, extra ...api.ValueType) []api.ValueType {
	t := make([]api.ValueType, n)
	for i := range t {
		t[i] = i32
	}
	return append(t, extra...)
}

func (h *host) inst(m api.Module) *instance {
	v, _ := h.instances.Load(m.Name())
	in, _ := v.(*instance)
	return in
}

func u32(s []uint64, i int) uint32 { return uint32(s[i]) }

func mutable(t uint32) bool { return t == mapRequestHeaders || t == mapResponseHeaders }

func (h *host) functions() map[string]hostFn {
	f := map[string]hostFn{}
	add := func(name string, params int, fn func(ctx context.Context, in *instance, m api.Module, s []uint64) uint64) {
		f[name] = hostFn{api.GoModuleFunc(func(ctx context.Context, m api.Module, s []uint64) {
			in := h.inst(m)
			if in == nil {
				s[0] = rBadArgument
				return
			}
			s[0] = fn(ctx, in, m, s)
		}), sig(params), []api.ValueType{i32}}
	}

	add("proxy_log", 3, func(ctx context.Context, in *instance, m api.Module, s []uint64) uint64 {
		msg, ok := readBytes(m, u32(s, 1), u32(s, 2))
		if !ok {
			return rInvalidMemory
		}
		if int(u32(s, 0)) >= h.logLevel {
			log.Printf("%s: %s", h.name, msg)
		}
		return rOK
	})
	add("proxy_get_log_level", 1, func(ctx context.Context, in *instance, m api.Module, s []uint64) uint64 {
		m.Memory().WriteUint32Le(u32(s, 0), uint32(h.logLevel))
		return rOK
	})
	add("proxy_get_current_time_nanoseconds", 1, func(ctx context.Context, in *instance, m api.Module, s []uint64) uint64 {
		m.Memory().WriteUint64Le(u32(s, 0), uint64(time.Now().UnixNano()))
		return rOK
	})
	add("proxy_set_tick_period_milliseconds", 1, func(ctx context.Context, in *instance, m api.Module, s []uint64) uint64 {
		in.tick = time.Duration(u32(s, 0)) * time.Millisecond
		select {
		case in.tickSet <- struct{}{}:
		default:
		}
		return rOK
	})
	add("proxy_set_effective_context", 1, func(ctx context.Context, in *instance, m api.Module, s []uint64) uint64 {
		in.effective = u32(s, 0)
		return rOK
	})
	add("proxy_done", 0, func(ctx context.Context, in *instance, m api.Module, s []uint64) uint64 { return rOK })

	// buffers
	buffer := func(in *instance, t uint32) ([]byte, bool) {
		switch t {
		case bufVMConfig:
			return h.vmConfig, true
		case bufPluginConfig:
			return h.config, true
		case bufCallBody:
			if in.answer != nil {
				return in.answer.body, true
			}
		case bufRequestBody:
			if in.cur != nil {
				return in.cur.body, true
			}
			return nil, true
		case bufResponseBody:
			if in.cur != nil {
				return in.cur.respBody, true
			}
			return nil, true
		}
		return nil, false
	}
	add("proxy_get_buffer_bytes", 5, func(ctx context.Context, in *instance, m api.Module, s []uint64) uint64 {
		b, ok := buffer(in, u32(s, 0))
		if !ok {
			return rNotFound
		}
		start, max := int(u32(s, 1)), int(u32(s, 2))
		if start > len(b) {
			return rBadArgument
		}
		b = b[start:]
		if max < len(b) {
			b = b[:max]
		}
		return in.give(ctx, m, b, u32(s, 3), u32(s, 4))
	})
	add("proxy_get_buffer_status", 3, func(ctx context.Context, in *instance, m api.Module, s []uint64) uint64 {
		b, ok := buffer(in, u32(s, 0))
		if !ok {
			return rNotFound
		}
		m.Memory().WriteUint32Le(u32(s, 1), uint32(len(b)))
		m.Memory().WriteUint32Le(u32(s, 2), 1)
		return rOK
	})
	add("proxy_set_buffer_bytes", 5, func(ctx context.Context, in *instance, m api.Module, s []uint64) uint64 { return rUnimplemented })

	// header maps
	headers := func(in *instance, t uint32) *[]pair {
		switch t {
		case mapRequestHeaders:
			if in.cur != nil {
				return &in.cur.headers
			}
		case mapResponseHeaders:
			if in.cur != nil && in.cur.resp != nil {
				return &in.cur.resp
			}
		case mapCallHeaders:
			if in.answer != nil {
				return &in.answer.headers
			}
		case mapCallTrailers:
			empty := []pair{}
			return &empty
		}
		return nil
	}
	add("proxy_get_header_map_pairs", 3, func(ctx context.Context, in *instance, m api.Module, s []uint64) uint64 {
		hs := headers(in, u32(s, 0))
		if hs == nil {
			return rNotFound
		}
		return in.give(ctx, m, encodePairs(*hs), u32(s, 1), u32(s, 2))
	})
	add("proxy_set_header_map_pairs", 3, func(ctx context.Context, in *instance, m api.Module, s []uint64) uint64 {
		hs := headers(in, u32(s, 0))
		if hs == nil || !mutable(u32(s, 0)) {
			return rNotFound
		}
		b, ok := readBytes(m, u32(s, 1), u32(s, 2))
		if !ok {
			return rInvalidMemory
		}
		ps, ok := decodePairs(b)
		if !ok {
			return rBadArgument
		}
		for i := range ps {
			ps[i][0] = strings.ToLower(ps[i][0])
		}
		*hs = ps
		return rOK
	})
	add("proxy_get_header_map_size", 2, func(ctx context.Context, in *instance, m api.Module, s []uint64) uint64 {
		hs := headers(in, u32(s, 0))
		if hs == nil {
			return rNotFound
		}
		m.Memory().WriteUint32Le(u32(s, 1), uint32(len(encodePairs(*hs))))
		return rOK
	})
	key := func(m api.Module, s []uint64, i int) (string, bool) {
		b, ok := readBytes(m, u32(s, i), u32(s, i+1))
		return strings.ToLower(string(b)), ok
	}
	add("proxy_get_header_map_value", 5, func(ctx context.Context, in *instance, m api.Module, s []uint64) uint64 {
		hs := headers(in, u32(s, 0))
		k, ok := key(m, s, 1)
		if hs == nil || !ok {
			return rNotFound
		}
		for _, p := range *hs {
			if p[0] == k {
				return in.give(ctx, m, []byte(p[1]), u32(s, 3), u32(s, 4))
			}
		}
		return rNotFound
	})
	edit := func(name string, fn func(hs *[]pair, k, v string)) {
		add(name, 5, func(ctx context.Context, in *instance, m api.Module, s []uint64) uint64 {
			hs := headers(in, u32(s, 0))
			if hs == nil || !mutable(u32(s, 0)) {
				return rNotFound
			}
			k, ok := key(m, s, 1)
			v, ok2 := readBytes(m, u32(s, 3), u32(s, 4))
			if !ok || !ok2 {
				return rInvalidMemory
			}
			fn(hs, k, string(v))
			return rOK
		})
	}
	edit("proxy_replace_header_map_value", func(hs *[]pair, k, v string) {
		out := (*hs)[:0]
		done := false
		for _, p := range *hs {
			if p[0] == k {
				if done {
					continue
				}
				p[1], done = v, true
			}
			out = append(out, p)
		}
		if !done {
			out = append(out, pair{k, v})
		}
		*hs = out
	})
	edit("proxy_add_header_map_value", func(hs *[]pair, k, v string) { *hs = append(*hs, pair{k, v}) })
	add("proxy_remove_header_map_value", 3, func(ctx context.Context, in *instance, m api.Module, s []uint64) uint64 {
		hs := headers(in, u32(s, 0))
		if hs == nil || !mutable(u32(s, 0)) {
			return rNotFound
		}
		k, ok := key(m, s, 1)
		if !ok {
			return rInvalidMemory
		}
		out := (*hs)[:0]
		for _, p := range *hs {
			if p[0] != k {
				out = append(out, p)
			}
		}
		*hs = out
		return rOK
	})

	// properties: what Envoy calls attributes, those a request has here
	add("proxy_get_property", 4, func(ctx context.Context, in *instance, m api.Module, s []uint64) uint64 {
		b, ok := readBytes(m, u32(s, 0), u32(s, 1))
		if !ok {
			return rInvalidMemory
		}
		path := strings.TrimRight(string(b), "\x00")
		v, ok := in.property(path)
		if !ok {
			return rNotFound
		}
		return in.give(ctx, m, v, u32(s, 2), u32(s, 3))
	})
	add("proxy_set_property", 4, func(ctx context.Context, in *instance, m api.Module, s []uint64) uint64 {
		k, ok := readBytes(m, u32(s, 0), u32(s, 1))
		v, ok2 := readBytes(m, u32(s, 2), u32(s, 3))
		if !ok || !ok2 {
			return rInvalidMemory
		}
		if in.cur == nil {
			return rNotFound
		}
		if in.cur.props == nil {
			in.cur.props = map[string][]byte{}
		}
		in.cur.props[strings.TrimRight(string(k), "\x00")] = v
		return rOK
	})

	// the request
	add("proxy_send_local_response", 8, func(ctx context.Context, in *instance, m api.Module, s []uint64) uint64 {
		if in.cur == nil {
			return rNotFound
		}
		body, ok := readBytes(m, u32(s, 3), u32(s, 4))
		hb, ok2 := readBytes(m, u32(s, 5), u32(s, 6))
		if !ok || !ok2 {
			return rInvalidMemory
		}
		hs, ok := decodePairs(hb)
		if !ok {
			return rBadArgument
		}
		in.cur.local = &localResponse{status: int(u32(s, 0)), headers: hs, body: body}
		return rOK
	})
	cont := func(ctx context.Context, in *instance, m api.Module, s []uint64) uint64 {
		if in.cur != nil {
			in.cur.continued = true
		}
		return rOK
	}
	add("proxy_continue_stream", 1, cont)
	add("proxy_continue_request", 0, cont)
	add("proxy_close_stream", 1, func(ctx context.Context, in *instance, m api.Module, s []uint64) uint64 {
		if in.cur != nil {
			in.cur.closed = true
		}
		return rOK
	})
	add("proxy_clear_route_cache", 0, func(ctx context.Context, in *instance, m api.Module, s []uint64) uint64 { return rOK })

	// callouts
	add("proxy_http_call", 10, func(ctx context.Context, in *instance, m api.Module, s []uint64) uint64 {
		up, ok := readBytes(m, u32(s, 0), u32(s, 1))
		hb, ok2 := readBytes(m, u32(s, 2), u32(s, 3))
		body, ok3 := readBytes(m, u32(s, 4), u32(s, 5))
		if !ok || !ok2 || !ok3 {
			return rInvalidMemory
		}
		hs, ok := decodePairs(hb)
		if !ok {
			return rBadArgument
		}
		in.token++
		c := &callout{token: in.token, cluster: string(up), headers: hs, body: body,
			timeout: time.Duration(u32(s, 8)) * time.Millisecond}
		if c.timeout <= 0 || c.timeout > 30*time.Second {
			c.timeout = 30 * time.Second
		}
		in.pending = append(in.pending, c)
		m.Memory().WriteUint32Le(u32(s, 9), c.token)
		return rOK
	})

	// shared data, across the instances
	add("proxy_get_shared_data", 5, func(ctx context.Context, in *instance, m api.Module, s []uint64) uint64 {
		k, ok := readBytes(m, u32(s, 0), u32(s, 1))
		if !ok {
			return rInvalidMemory
		}
		h.shared.mu.Lock()
		v, found := h.shared.data[string(k)]
		cas := h.shared.cas[string(k)]
		h.shared.mu.Unlock()
		if !found {
			return rNotFound
		}
		if r := in.give(ctx, m, v, u32(s, 2), u32(s, 3)); r != rOK {
			return r
		}
		m.Memory().WriteUint32Le(u32(s, 4), cas)
		return rOK
	})
	add("proxy_set_shared_data", 5, func(ctx context.Context, in *instance, m api.Module, s []uint64) uint64 {
		k, ok := readBytes(m, u32(s, 0), u32(s, 1))
		v, ok2 := readBytes(m, u32(s, 2), u32(s, 3))
		if !ok || !ok2 {
			return rInvalidMemory
		}
		h.shared.mu.Lock()
		defer h.shared.mu.Unlock()
		if cas := u32(s, 4); cas != 0 && cas != h.shared.cas[string(k)] {
			return rCasMismatch
		}
		h.shared.next++
		h.shared.data[string(k)] = v
		h.shared.cas[string(k)] = h.shared.next
		return rOK
	})

	// metrics: kept, so that plugins that count work (they are not exported)
	add("proxy_define_metric", 4, func(ctx context.Context, in *instance, m api.Module, s []uint64) uint64 {
		h.shared.mmu.Lock()
		h.shared.mnext++
		id := h.shared.mnext
		h.shared.mmu.Unlock()
		m.Memory().WriteUint32Le(u32(s, 3), id)
		return rOK
	})
	f["proxy_increment_metric"] = hostFn{api.GoModuleFunc(func(ctx context.Context, m api.Module, s []uint64) {
		h.shared.mmu.Lock()
		h.shared.mvals[u32(s, 0)] += s[1]
		h.shared.mmu.Unlock()
		s[0] = rOK
	}), []api.ValueType{i32, i64}, []api.ValueType{i32}}
	f["proxy_record_metric"] = hostFn{api.GoModuleFunc(func(ctx context.Context, m api.Module, s []uint64) {
		h.shared.mmu.Lock()
		h.shared.mvals[u32(s, 0)] = s[1]
		h.shared.mmu.Unlock()
		s[0] = rOK
	}), []api.ValueType{i32, i64}, []api.ValueType{i32}}
	add("proxy_get_metric", 2, func(ctx context.Context, in *instance, m api.Module, s []uint64) uint64 {
		h.shared.mmu.Lock()
		v := h.shared.mvals[u32(s, 0)]
		h.shared.mmu.Unlock()
		m.Memory().WriteUint64Le(u32(s, 1), v)
		return rOK
	})
	return f
}

// the attributes of the request in this instance, Envoy's names
func (in *instance) property(path string) ([]byte, bool) {
	p := strings.ReplaceAll(path, "\x00", ".")
	if in.cur != nil {
		if v, ok := in.cur.props[path]; ok {
			return v, true
		}
		if v, ok := in.cur.props[p]; ok {
			return v, true
		}
	}
	switch p {
	case "plugin_name":
		return []byte(in.h.name), true
	case "plugin_root_id":
		return []byte(in.h.rootID), true
	case "plugin_vm_id":
		return []byte(""), true
	}
	if in.cur == nil || in.cur.req == nil {
		return nil, false
	}
	r := in.cur.req
	switch p {
	case "request.path":
		return []byte(r.path), true
	case "request.url_path":
		return []byte(strings.SplitN(r.path, "?", 2)[0]), true
	case "request.query":
		if i := strings.IndexByte(r.path, '?'); i >= 0 {
			return []byte(r.path[i+1:]), true
		}
		return []byte(""), true
	case "request.host":
		return []byte(r.host), true
	case "request.scheme":
		return []byte(r.scheme), true
	case "request.method":
		return []byte(r.method), true
	case "request.protocol":
		return []byte(r.protocol), true
	case "source.address":
		return []byte(r.client + ":0"), true
	case "source.port":
		return []byte{0, 0, 0, 0, 0, 0, 0, 0}, true
	case "connection.mtls":
		return []byte{0}, true
	}
	return nil, false
}
