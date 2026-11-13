// Package addon is the okena addon SDK for Go (protocol version 1,
// docs/ADDONS.md in the okena repository).
//
// An addon is a program okena starts (`addon NAME { run ... }`) and calls at
// phases of a request through shared memory:
//
//	func main() {
//		addon.Run(func(r *addon.Request, a *addon.Answer) {
//			if _, ok := r.Header("x-block"); ok {
//				a.Respond(403)
//				a.Add("content-type", "text/plain")
//				a.Body([]byte("blocked\n"))
//				return
//			}
//			a.Set("x-checked", "yes") // the default answer: continue
//		}, addon.Options{})
//	}
//
// With Options.Workers above 1 the handler runs on that many goroutines at
// once (a call that takes long does not hold the others); answers to one
// worker slot are written one at a time. After a call the addon polls the
// rings for Options.SpinMicros (default: the addon's `poll`, 50 us unless
// set; OKENA_ADDON_SPIN_US overrides it) before it sleeps on the bell.
package addon

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

const (
	magic   = 0x314E4F4444414B4F
	version = 1

	PhaseRequestHeaders = 1
	PhaseRequestBody    = 2
	PhaseResponseHeaders = 4
	PhaseResponseBody   = 8
	PhaseLog            = 16
	phasesResponse      = PhaseResponseHeaders | PhaseResponseBody
	FlagTLS             = 1
	FlagH2              = 2
	FlagH3              = 4
	FlagBodyTruncated   = 8
	FlagBodyChunked     = 16
	FlagBodyUnread      = 32

	opSet    = 1
	opAdd    = 2
	opRemove = 3
	opTarget = 4
	opPool   = 5

	answerMax = 1 << 16
)

// Field is one field of the request head.
type Field struct{ Name, Value string }

// Request is a call: the request's head as okena forwards it (HTTP/1.1 form,
// also for HTTP/2 and HTTP/3 clients) and what okena knows of the client.
// Its strings are copies: they stay valid after the handler returns.
type Request struct {
	ID      uint32
	Phase   uint16
	Flags   uint32
	Route   uint32
	Head    []byte
	Method  string
	Target  string
	Headers []Field
	Family  uint16
	Client  [16]byte
	// Body is the request's body (phases request_body), decoded when it came
	// chunked: all of it, or its first `body` bytes (BodyTruncated).
	Body          []byte
	BodyTruncated bool
	BodyUnread    bool // the client waits for 100 Continue: not read
	// Stream is the same in every call about one request (its phases, its log).
	Stream StreamID
	// Status is the backend's status in the response phases (Headers and Body
	// are then the response's; Method and Target stay the request's).
	Status int
}

// StreamID identifies a request across its calls: a map key.
type StreamID struct {
	Slot uint32
	Key  uint64
}

// IsResponse says the call is about the backend's response.
func (r *Request) IsResponse() bool { return r.Phase&phasesResponse != 0 }

// Header returns the first field of that name (any case).
func (r *Request) Header(name string) (string, bool) {
	for _, f := range r.Headers {
		if strings.EqualFold(f.Name, name) {
			return f.Value, true
		}
	}
	return "", false
}

// Path is the target without its query.
func (r *Request) Path() string {
	if i := strings.IndexByte(r.Target, '?'); i >= 0 {
		return r.Target[:i]
	}
	return r.Target
}

// ClientIP is the client's address (the one trusted proxies name, if any).
func (r *Request) ClientIP() net.IP {
	switch r.Family {
	case 4:
		return net.IP(append([]byte(nil), r.Client[:4]...))
	case 6:
		return net.IP(append([]byte(nil), r.Client[:]...))
	}
	return nil
}

// Answer is what the handler decides: continue (the default), with changes
// to the request, or respond. okena's own fields (Content-Length,
// Transfer-Encoding, Connection...) are not changed.
type Answer struct {
	buf      []byte
	nops     uint16
	action   uint16
	status   uint16
	body     []byte
	none     bool
	overflow bool
}

func (a *Answer) op(code byte, name, value string) {
	if len(name) > 0xFFFF || len(value) > 0xFFFF || len(a.buf)+6+len(name)+len(value) > answerMax {
		a.overflow = true
		return
	}
	a.buf = append(a.buf, code, 0, byte(len(name)), byte(len(name)>>8), byte(len(value)), byte(len(value)>>8))
	a.buf = append(a.buf, name...)
	a.buf = append(a.buf, value...)
	a.nops++
}

// Set replaces every request field of that name (respond: a response field).
func (a *Answer) Set(name, value string) { a.op(opSet, name, value) }

// Add adds a field (respond: a response field).
func (a *Answer) Add(name, value string) { a.op(opAdd, name, value) }

// Remove takes away every request field of that name.
func (a *Answer) Remove(name string) { a.op(opRemove, name, "") }

// Target replaces the request target (path and query).
func (a *Answer) Target(target string) { a.op(opTarget, "", target) }

// Pool sends the request to another pool (its name in okena's configuration).
func (a *Answer) Pool(name string) { a.op(opPool, "", name) }

// Respond answers the client here with this status; Add gives its fields.
func (a *Answer) Respond(status int) { a.action, a.status = 1, uint16(status) }

// Body is the body of a Respond.
func (a *Answer) Body(b []byte) { a.body = b }

// NoAnswer leaves the call unanswered: okena's on_error, at its time.
func (a *Answer) NoAnswer() { a.none = true }

// Fail says the addon could not decide (its own service is down, say):
// okena's on_error at once, and a failure for the circuit.
func (a *Answer) Fail() { a.action = 2 }

func (a *Answer) reset() {
	a.buf = a.buf[:24]
	a.nops, a.action, a.status, a.body, a.none, a.overflow = 0, 0, 0, nil, false, false
}

// Handler decides about a request.
type Handler func(*Request, *Answer)

// Options of Run.
type Options struct {
	Workers    int // goroutines running the handler (default 1)
	SpinMicros int // polling after a call before sleeping (default: the configuration's `poll`)
}

// Addon is the memory okena shares with this addon.
type Addon struct {
	m      []byte
	nrings uint32
	rbytes uint64
	hbytes uint64
	stride uint64
	bell   int
	wake0  int
	Name   string
	locks  []sync.Mutex
}

// Open maps the memory OKENA_ADDON_FD names.
func Open() (*Addon, error) {
	fd := 3
	if s := os.Getenv("OKENA_ADDON_FD"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil {
			return nil, fmt.Errorf("okena addon: OKENA_ADDON_FD: %w", err)
		}
		fd = n
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return nil, fmt.Errorf("okena addon: %w", err)
	}
	m, err := syscall.Mmap(fd, 0, int(st.Size), syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("okena addon: %w", err)
	}
	le := binary.LittleEndian
	if le.Uint64(m) != magic || le.Uint32(m[8:]) != version {
		return nil, errors.New("okena addon: not okena's memory, or another protocol version")
	}
	a := &Addon{
		m:      m,
		nrings: le.Uint32(m[12:]),
		rbytes: uint64(le.Uint32(m[16:])),
		hbytes: uint64(le.Uint32(m[20:])),
		stride: le.Uint64(m[24:]),
		bell:   int(le.Uint32(m[32:])),
		wake0:  int(le.Uint32(m[36:])),
	}
	a.Name = strings.TrimRight(string(m[64:128]), "\x00")
	if i := strings.IndexByte(a.Name, 0); i >= 0 {
		a.Name = a.Name[:i]
	}
	a.locks = make([]sync.Mutex, a.nrings)
	return a, nil
}

func (a *Addon) u32(off uint64) *uint32 { return (*uint32)(unsafe.Pointer(&a.m[off])) }
func (a *Addon) u64(off uint64) *uint64 { return (*uint64)(unsafe.Pointer(&a.m[off])) }
func (a *Addon) pair(r uint32) uint64  { return a.hbytes + uint64(r)*a.stride }

type call struct {
	ring uint32
	req  Request
}

// Run serves calls with h until an error (it does not return otherwise).
func Run(h Handler, o Options) error {
	a, err := Open()
	if err != nil {
		return err
	}
	return a.Run(h, o)
}

// Run serves calls with h.
func (a *Addon) Run(h Handler, o Options) error {
	spin := o.SpinMicros
	if spin == 0 {
		spin = int(atomic.LoadUint32(a.u32(140))) // the addon's `poll`
		if s := os.Getenv("OKENA_ADDON_SPIN_US"); s != "" {
			if n, err := strconv.Atoi(s); err == nil {
				spin = n
			}
		}
	}
	workers := o.Workers
	if workers < 1 {
		workers = 1
	}
	var queue chan call
	if workers > 1 {
		queue = make(chan call, 4096)
		for i := 0; i < workers; i++ {
			go func() {
				ans := &Answer{buf: make([]byte, 24, 1024)}
				for c := range queue {
					ans.reset()
					h(&c.req, ans)
					a.answer(c.ring, c.req.ID, ans, true)
				}
			}()
		}
	}
	runtime.LockOSThread()
	sleep, ready := a.u32(60), a.u32(48)
	atomic.StoreUint32(sleep, 1)
	atomic.StoreUint32(ready, 1)
	ans := &Answer{buf: make([]byte, 24, 1024)}
	spinFor := time.Duration(spin) * time.Microsecond
	var last time.Time
	polling := false
	buf := make([]byte, 8)
	for {
		if a.poll(h, ans, queue) > 0 {
			if !polling && spinFor > 0 {
				atomic.StoreUint32(sleep, 0)
				polling = true
			}
			last = time.Now()
			continue
		}
		if polling && time.Since(last) < spinFor {
			continue
		}
		atomic.SwapUint32(sleep, 1)
		polling = false
		if a.poll(h, ans, queue) > 0 {
			last = time.Now()
			continue
		}
		if _, err := syscall.Read(a.bell, buf); err != nil && err != syscall.EINTR {
			return fmt.Errorf("okena addon: the bell: %w", err)
		}
	}
}

// poll takes every call waiting, once.
func (a *Addon) poll(h Handler, ans *Answer, queue chan call) int {
	n := 0
	le := binary.LittleEndian
	mask := a.rbytes - 1
	for r := uint32(0); r < a.nrings; r++ {
		p := a.pair(r)
		head := atomic.LoadUint64(a.u64(p))
		tail := atomic.LoadUint64(a.u64(p + 64))
		if head == tail {
			continue
		}
		d := p + a.hbytes
		answered := false
		for tail != head {
			at := d + (tail & mask)
			ln := uint64(le.Uint32(a.m[at:]))
			kind := le.Uint16(a.m[at+4:])
			if ln < 8 || ln&7 != 0 || ln > head-tail {
				tail = head
				break
			}
			if kind == 1 {
				var c call
				c.ring = r
				a.parse(at, &c.req)
				c.req.Stream = StreamID{r, le.Uint64(a.m[at+56:])}
				if c.req.Phase == PhaseLog {
					ans.reset()
					h(&c.req, ans) // (never answered)
				} else if queue != nil {
					queue <- c
				} else {
					ans.reset()
					h(&c.req, ans)
					answered = a.answer(r, c.req.ID, ans, false) || answered
				}
				n++
			}
			tail += ln
		}
		atomic.StoreUint64(a.u64(p+64), tail)
		if answered {
			a.wake(r)
		}
	}
	return n
}

func (a *Addon) parse(at uint64, q *Request) {
	le := binary.LittleEndian
	m := a.m
	q.Phase = le.Uint16(m[at+6:])
	q.ID = le.Uint32(m[at+8:])
	q.Flags = le.Uint32(m[at+12:])
	hl := uint64(le.Uint32(m[at+16:]))
	nh := uint64(le.Uint16(m[at+20:]))
	q.Family = le.Uint16(m[at+22:])
	copy(q.Client[:], m[at+24:at+40])
	q.Route = le.Uint32(m[at+48:])
	hat := at + 64 + 8*nh
	bl := uint64(le.Uint32(m[at+52:]))
	all := string(m[hat : hat+hl+bl]) // the head, then what follows it
	q.Head = []byte(all[:hl])
	q.Body = []byte(all[hl:])
	q.BodyTruncated = q.Flags&FlagBodyTruncated != 0
	q.BodyUnread = q.Flags&FlagBodyUnread != 0
	if q.Flags&FlagBodyChunked != 0 {
		var whole bool
		q.Body, whole = Dechunk(q.Body)
		q.BodyTruncated = !whole
	}
	sub := func(o, l uint16) string {
		if int(o)+int(l) > len(all) {
			return ""
		}
		return all[o : o+l]
	}
	q.Method = sub(le.Uint16(m[at+40:]), le.Uint16(m[at+42:]))
	to, tl := le.Uint16(m[at+44:]), le.Uint16(m[at+46:])
	q.Target = sub(to, tl)
	if q.Phase&phasesResponse != 0 {
		// after the head: the request's method and target, then the body
		if e := int(to) + int(tl); e <= len(all) {
			q.Body = []byte(all[e:])
		}
		if f := strings.Fields(all[:hl]); len(f) > 1 {
			q.Status, _ = strconv.Atoi(f[1])
		}
	}
	q.Headers = make([]Field, nh)
	for i := uint64(0); i < nh; i++ {
		x := at + 64 + 8*i
		q.Headers[i] = Field{sub(le.Uint16(m[x:]), le.Uint16(m[x+2:])), sub(le.Uint16(m[x+4:]), le.Uint16(m[x+6:]))}
	}
}

// Dechunk decodes a chunk-framed body: its bytes, and whether its last chunk
// was there.
func Dechunk(raw []byte) ([]byte, bool) {
	var out []byte
	for {
		i := strings.Index(string(raw), "\r\n")
		if i < 0 {
			return out, false
		}
		size := string(raw[:i])
		if j := strings.IndexByte(size, ';'); j >= 0 {
			size = size[:j]
		}
		n, err := strconv.ParseUint(strings.TrimSpace(size), 16, 31)
		if err != nil {
			return out, false
		}
		if n == 0 {
			return out, true
		}
		raw = raw[i+2:]
		if uint64(len(raw)) < n {
			return append(out, raw...), false
		}
		out = append(out, raw[:n]...)
		if uint64(len(raw)) < n+2 {
			return out, false
		}
		raw = raw[n+2:]
	}
}

// answer writes an answer into ring r's answers; false when there is no room
// (okena ends that call at its time). From the handler goroutines (locked),
// it wakes the worker itself.
func (a *Addon) answer(r uint32, id uint32, ans *Answer, alone bool) bool {
	if ans.none || ans.overflow {
		return false
	}
	if alone {
		a.locks[r].Lock()
		defer a.locks[r].Unlock()
	}
	le := binary.LittleEndian
	h := a.pair(r) + a.hbytes + a.rbytes
	d := h + a.hbytes
	size := (uint64(len(ans.buf)+len(ans.body)) + 7) &^ 7
	head := atomic.LoadUint64(a.u64(h))
	tail := atomic.LoadUint64(a.u64(h + 64))
	pos := head & (a.rbytes - 1)
	var pad uint64
	if a.rbytes-pos < size {
		pad = a.rbytes - pos
	}
	if pad+size > a.rbytes-(head-tail) {
		return false
	}
	if pad > 0 {
		le.PutUint32(a.m[d+pos:], uint32(pad))
		le.PutUint32(a.m[d+pos+4:], 0)
		head += pad
		pos = 0
	}
	b := ans.buf
	le.PutUint32(b[0:], uint32(size))
	le.PutUint16(b[4:], 1)
	le.PutUint16(b[6:], ans.action)
	le.PutUint32(b[8:], id)
	le.PutUint16(b[12:], ans.status)
	le.PutUint16(b[14:], ans.nops)
	le.PutUint32(b[16:], uint32(len(ans.body)))
	le.PutUint32(b[20:], 0)
	at := d + pos
	copy(a.m[at:], b)
	copy(a.m[at+uint64(len(b)):], ans.body)
	atomic.StoreUint64(a.u64(h), head+size)
	if alone {
		a.wake(r)
	}
	return true
}

// wake writes worker slot r's eventfd, unless its worker polls for answers.
func (a *Addon) wake(r uint32) {
	h := a.pair(r) + a.hbytes + a.rbytes
	if atomic.LoadUint32(a.u32(h+128)) != 0 {
		return
	}
	one := []byte{1, 0, 0, 0, 0, 0, 0, 0}
	syscall.Write(a.wake0+int(r), one)
}
