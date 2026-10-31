// grpcbench: a gRPC backend and an open-loop load generator for the
// proxy comparison in tests/bench/grpc.sh. No protoc: messages are raw
// bytes (a codec that passes them through) and the service is described
// by hand, so the bytes on the wire are what any gRPC client sends.
//
//	grpcbench server -addr 127.0.0.1:28500
//	grpcbench load -addr 127.0.0.1:28501 -mode unary|stream -rate 10000 -conns 8 -dur 10s
//
// unary: one call per tick, latency from when the call was due (the
// schedule, so a stall is not hidden). stream: -conns server-streaming
// calls, each asking the backend for a message every conns/rate seconds;
// the backend stamps each with the wall-clock time it sent it and the
// latency is until it arrives (same host, same clock). bidi: -conns
// bidirectional streams, a message each tick on the next one, latency
// until its echo. Output: one line, the rate achieved and the latency
// percentiles in microseconds.
package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/status"
)

type raw struct{}

func (raw) Marshal(v any) ([]byte, error) { return *v.(*[]byte), nil }
func (raw) Unmarshal(b []byte, v any) error {
	*v.(*[]byte) = append([]byte(nil), b...)
	return nil
}
func (raw) Name() string { return "proto" }

var _ encoding.Codec = raw{}

type svc interface{}

func unaryHandler(_ any, ctx context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
	var b []byte
	if err := dec(&b); err != nil {
		return nil, err
	}
	return &b, nil
}

func bidiHandler(_ any, st grpc.ServerStream) error {
	for {
		var b []byte
		if err := st.RecvMsg(&b); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if err := st.SendMsg(&b); err != nil {
			return err
		}
	}
}

// pace waits until t: a sleep, then a spin for the last stretch (Go's
// timers wake at millisecond granularity: a sleep alone is up to 1 ms late)
func pace(t time.Time) {
	if w := time.Until(t) - 2*time.Millisecond; w > 0 {
		time.Sleep(w)
	}
	for time.Now().Before(t) {
	}
}

// the request: interval (ns), count, size; then count messages on that
// schedule, the first 8 bytes of each the UnixNano it was sent (a stream
// sleeps rather than spins: a late wake-up delays the send, not the
// latency measured)
func feedHandler(_ any, st grpc.ServerStream) error {
	var req []byte
	if err := st.RecvMsg(&req); err != nil {
		return err
	}
	if len(req) < 24 {
		return io.ErrUnexpectedEOF
	}
	iv := time.Duration(binary.LittleEndian.Uint64(req))
	n := int(binary.LittleEndian.Uint64(req[8:]))
	msg := make([]byte, max(8, int(binary.LittleEndian.Uint64(req[16:]))))
	start := time.Now()
	for i := 0; i < n; i++ {
		if w := time.Until(start.Add(time.Duration(i) * iv)); w > 0 {
			time.Sleep(w)
		}
		binary.LittleEndian.PutUint64(msg, uint64(time.Now().UnixNano()))
		if err := st.SendMsg(&msg); err != nil {
			return err
		}
	}
	return nil
}

var desc = grpc.ServiceDesc{
	ServiceName: "bench.B",
	HandlerType: (*svc)(nil),
	Methods:     []grpc.MethodDesc{{MethodName: "Unary", Handler: unaryHandler}},
	Streams: []grpc.StreamDesc{{StreamName: "Bidi", Handler: bidiHandler,
		ServerStreams: true, ClientStreams: true},
		{StreamName: "Feed", Handler: feedHandler, ServerStreams: true}},
}

// grpc.health.v1.Health/Check in raw bytes (for okena's `health grpc`):
// "" and bench.B are SERVING, bench.Down NOT_SERVING, others NOT_FOUND
func healthCheck(_ any, ctx context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
	var b []byte
	if err := dec(&b); err != nil {
		return nil, err
	}
	name := ""
	if len(b) >= 2 && b[0] == 0x0A && int(b[1]) <= len(b)-2 {
		name = string(b[2 : 2+int(b[1])])
	}
	var st byte
	switch name {
	case "", "bench.B":
		st = 1
	case "bench.Down":
		st = 2
	default:
		return nil, status.Error(codes.NotFound, "unknown service")
	}
	out := []byte{0x08, st}
	return &out, nil
}

var healthDesc = grpc.ServiceDesc{
	ServiceName: "grpc.health.v1.Health",
	HandlerType: (*svc)(nil),
	Methods:     []grpc.MethodDesc{{MethodName: "Check", Handler: healthCheck}},
}

func server(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:28500", "listen")
	fs.Parse(args)
	l, err := net.Listen("tcp", *addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	s := grpc.NewServer(grpc.ForceServerCodec(raw{}), grpc.MaxConcurrentStreams(1000))
	s.RegisterService(&desc, nil)
	s.RegisterService(&healthDesc, nil)
	s.Serve(l)
}

func load(args []string) {
	fs := flag.NewFlagSet("load", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:28500", "target")
	mode := fs.String("mode", "unary", "unary | stream | bidi")
	rate := fs.Int("rate", 1000, "calls (unary) or messages (stream) a second")
	conns := fs.Int("conns", 8, "connections (unary) / streams (stream)")
	dur := fs.Duration("dur", 10*time.Second, "measured duration")
	warm := fs.Duration("warmup", 2*time.Second, "unmeasured lead-in")
	size := fs.Int("size", 64, "message bytes")
	fs.Parse(args)

	payload := make([]byte, *size)
	ccs := make([]*grpc.ClientConn, *conns)
	for i := range ccs {
		cc, err := grpc.NewClient(*addr, grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithDefaultCallOptions(grpc.ForceCodec(raw{})))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		ccs[i] = cc
	}
	ctx := context.Background()

	var mu sync.Mutex
	var lat []time.Duration
	var errs, done atomic.Int64
	var measuring atomic.Bool
	record := func(d time.Duration, err error) {
		if !measuring.Load() {
			return
		}
		if err != nil {
			if errs.Add(1) <= 3 {
				fmt.Fprintln(os.Stderr, "error:", err)
			}
			return
		}
		done.Add(1)
		mu.Lock()
		lat = append(lat, d)
		mu.Unlock()
	}

	var send func(i int, due time.Time)
	switch *mode {
	case "unary":
		send = func(i int, due time.Time) {
			go func() {
				var out []byte
				err := ccs[i%len(ccs)].Invoke(ctx, "/bench.B/Unary", &payload, &out)
				record(time.Since(due), err)
			}()
		}
	case "stream":
		iv := time.Duration(*conns) * time.Second / time.Duration(*rate)
		n := int((*warm + *dur) / iv)
		req := make([]byte, 24)
		binary.LittleEndian.PutUint64(req, uint64(iv))
		binary.LittleEndian.PutUint64(req[8:], uint64(n))
		binary.LittleEndian.PutUint64(req[16:], uint64(*size))
		var wg sync.WaitGroup
		t0 := time.Now()
		for i := 0; i < *conns; i++ {
			st, err := ccs[i].NewStream(ctx, &desc.Streams[1], "/bench.B/Feed")
			if err == nil {
				err = st.SendMsg(&req)
			}
			if err == nil {
				err = st.CloseSend()
			}
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					var b []byte
					if err := st.RecvMsg(&b); err != nil {
						if err != io.EOF {
							record(0, err)
						}
						return
					}
					now := time.Now()
					due := time.Unix(0, int64(binary.LittleEndian.Uint64(b)))
					if now.Sub(t0) >= *warm && now.Before(t0.Add(*warm+*dur)) {
						record(now.Sub(due), nil)
					}
				}
			}()
		}
		measuring.Store(true)
		wg.Wait()
		measuring.Store(false)
		report(lat, done.Load(), errs.Load(), *dur)
		return
	case "bidi":
		type strm struct {
			mu  sync.Mutex
			st  grpc.ClientStream
			due chan time.Time
		}
		ss := make([]*strm, *conns)
		for i := range ss {
			st, err := ccs[i].NewStream(ctx, &desc.Streams[0], "/bench.B/Bidi")
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			s := &strm{st: st, due: make(chan time.Time, 1<<16)}
			ss[i] = s
			go func() {
				for {
					var b []byte
					err := s.st.RecvMsg(&b)
					if err != nil {
						if measuring.Load() {
							fmt.Fprintln(os.Stderr, "stream:", err)
						}
						return
					}
					record(time.Since(<-s.due), nil)
				}
			}()
		}
		send = func(i int, due time.Time) {
			s := ss[i%len(ss)]
			s.mu.Lock()
			s.due <- due
			err := s.st.SendMsg(&payload)
			s.mu.Unlock()
			if err != nil {
				record(0, err)
			}
		}
	default:
		fmt.Fprintln(os.Stderr, "mode: unary | stream")
		os.Exit(2)
	}

	interval := time.Second / time.Duration(*rate)
	start := time.Now()
	measureAt := start.Add(*warm)
	end := measureAt.Add(*dur)
	for n := 0; ; n++ {
		due := start.Add(time.Duration(n) * interval)
		if due.After(end) {
			break
		}
		if !measuring.Load() && !due.Before(measureAt) {
			measuring.Store(true)
		}
		pace(due)
		send(n, due)
	}
	time.Sleep(500 * time.Millisecond) // the last answers
	measuring.Store(false)
	mu.Lock()
	defer mu.Unlock()
	report(lat, done.Load(), errs.Load(), *dur)
}

func report(lat []time.Duration, done, errs int64, dur time.Duration) {
	sort.Slice(lat, func(a, b int) bool { return lat[a] < lat[b] })
	pct := func(p float64) float64 {
		if len(lat) == 0 {
			return 0
		}
		i := int(p * float64(len(lat)-1))
		return float64(lat[i].Nanoseconds()) / 1000
	}
	fmt.Printf("rate %.0f/s  p50 %.0f  p90 %.0f  p99 %.0f  p99.9 %.0f  max %.0f us  errors %d\n",
		float64(done)/dur.Seconds(), pct(.5), pct(.9), pct(.99), pct(.999), pct(1), errs)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "grpcbench server|load ...")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "server":
		server(os.Args[2:])
	case "load":
		load(os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, "grpcbench server|load ...")
		os.Exit(2)
	}
}
