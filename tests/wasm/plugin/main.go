// A proxy-wasm plugin for tests/gateway/wasm.py, on the proxy-wasm Go SDK
// (GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared): what it does
// depends on the path.
package main

import (
	"strconv"
	"strings"

	"github.com/proxy-wasm/proxy-wasm-go-sdk/proxywasm"
	"github.com/proxy-wasm/proxy-wasm-go-sdk/proxywasm/types"
)

func main() {}

func init() {
	proxywasm.SetPluginContext(func(uint32) types.PluginContext { return &plugin{} })
}

type plugin struct {
	types.DefaultPluginContext
	config string
}

func (p *plugin) OnPluginStart(int) types.OnPluginStartStatus {
	b, err := proxywasm.GetPluginConfiguration()
	if err != nil && err != types.ErrorStatusNotFound {
		proxywasm.LogCriticalf("configuration: %v", err)
		return false
	}
	p.config = string(b)
	proxywasm.LogInfof("started with %q", p.config)
	return types.OnPluginStartStatusOK
}

func (p *plugin) NewHttpContext(uint32) types.HttpContext { return &stream{p: p} }

type stream struct {
	types.DefaultHttpContext
	p *plugin
}

func (s *stream) OnHttpRequestHeaders(int, bool) types.Action {
	path, _ := proxywasm.GetHttpRequestHeader(":path")
	switch {
	case strings.HasSuffix(path, "/deny"):
		proxywasm.SendHttpResponse(403, [][2]string{{"x-plugin", "test"}, {"content-type", "text/plain"}}, []byte("denied by wasm\n"), -1)
		return types.ActionPause
	case strings.HasSuffix(path, "/rewrite"):
		proxywasm.ReplaceHttpRequestHeader(":path", "/rewritten?by=wasm")
	case strings.HasSuffix(path, "/auth"):
		// asks a service, and goes on or refuses with what it says
		token, _ := proxywasm.GetHttpRequestHeader("authorization")
		_, err := proxywasm.DispatchHttpCall("authsvc", [][2]string{{":method", "GET"}, {":path", "/check"},
			{":authority", "auth"}, {"authorization", token}}, nil, nil, 2000, func(int, int, int) {
			hs, _ := proxywasm.GetHttpCallResponseHeaders()
			status := ""
			for _, h := range hs {
				if h[0] == ":status" {
					status = h[1]
				}
			}
			body, _ := proxywasm.GetHttpCallResponseBody(0, 1024)
			if status == "200" {
				proxywasm.AddHttpRequestHeader("x-user", string(body))
				proxywasm.ResumeHttpRequest()
				return
			}
			proxywasm.SendHttpResponse(401, [][2]string{{"x-auth", "refused"}}, []byte("no\n"), -1)
		})
		if err != nil {
			proxywasm.SendHttpResponse(500, nil, []byte("callout: "+err.Error()), -1)
		}
		return types.ActionPause
	}
	// every other request: fields set and removed, what the host says
	proxywasm.AddHttpRequestHeader("x-wasm", "yes")
	proxywasm.AddHttpRequestHeader("x-config", s.p.config)
	proxywasm.RemoveHttpRequestHeader("x-drop")
	if a, err := proxywasm.GetProperty([]string{"source", "address"}); err == nil {
		proxywasm.AddHttpRequestHeader("x-source", string(a))
	}
	if m, err := proxywasm.GetProperty([]string{"request", "method"}); err == nil {
		proxywasm.AddHttpRequestHeader("x-method", string(m))
	}
	// a counter shared by every instance
	for {
		v, cas, err := proxywasm.GetSharedData("count")
		n := 0
		if err == nil {
			n, _ = strconv.Atoi(string(v))
		}
		n++
		if err := proxywasm.SetSharedData("count", []byte(strconv.Itoa(n)), cas); err == nil {
			proxywasm.AddHttpRequestHeader("x-count", strconv.Itoa(n))
			break
		}
	}
	return types.ActionContinue
}
