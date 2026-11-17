// grpcjson-okena: gRPC-JSON transcoding as an okena addon. A JSON request
// to a path a gRPC method answers (its google.api.http rule, or
// POST /package.Service/Method for any method) is made into the method's
// message, the gRPC service is called, and its answer goes back as JSON (an
// error: the HTTP status google.rpc's mapping gives, and a JSON body of code
// and message). Other paths go on to the route as they came.
//
//	addon grpcjson {
//	    run /usr/local/bin/grpcjson-okena -descriptors /etc/okena/api.pb -backend 10.0.0.7:9000
//	    phases request_body
//	    body 1MiB
//	    timeout 5s
//	}
//	route /v1/* { addon grpcjson; to pool rest }
//
// The descriptors are a FileDescriptorSet with its imports
// (protoc --include_imports --descriptor_set_out=api.pb ...).
//
// Streaming methods too. A server stream is gathered (within the call's
// time) and answered as newline-delimited JSON, a {"result": message} line
// for each, as grpc-gateway writes them (-stream array: one JSON array
// instead); a stream that fails after its first message ends with an
// {"error": status} line, and one that fails before any is an error answer.
// A client stream takes its messages from the body: a JSON array, or one
// JSON object a line. An answer is at most -max-answer bytes (what an
// addon's answer ring holds): a longer stream is cut there and ends with a
// RESOURCE_EXHAUSTED error line.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	addon "github.com/Lu4nScr1pt1ng/okena/sdk/go"
	"google.golang.org/genproto/googleapis/api/annotations"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

// a rule: a verb and a path template that call a method
type rule struct {
	verb    string
	segs    []seg
	body    string // "*", a field's name, or "" (the query fills the message)
	method  protoreflect.MethodDescriptor
	fullRPC string // /package.Service/Method
}

// the most an answer may be: an addon's answer ring is 256 KiB, shared by
// the answers a worker has not taken yet
const answerCap = 224 << 10

type seg struct {
	lit   string   // a literal, or ""
	field string   // a variable's field path (a.b)
	pat   []string // its pattern's segments: "*" one, "**" the rest, literals
}

var (
	rules   []rule
	conn    *grpc.ClientConn
	timeout time.Duration
	asArray bool
	maxAns  int
	unmarsh = protojson.UnmarshalOptions{DiscardUnknown: false}
	marsh   = protojson.MarshalOptions{}
)

func main() {
	desc := flag.String("descriptors", "", "a FileDescriptorSet, with its imports")
	backend := flag.String("backend", "", "the gRPC service: host:port")
	useTLS := flag.Bool("tls", false, "TLS to the service")
	caFile := flag.String("ca-file", "", "CA certificates for its TLS (default: the system's)")
	flag.DurationVar(&timeout, "timeout", 4*time.Second, "a call's time")
	protoNames := flag.Bool("proto-names", false, "JSON field names as in the .proto (default: lowerCamelCase)")
	emit := flag.Bool("emit-defaults", false, "fields at their default value written too")
	stream := flag.String("stream", "ndjson", "a server stream's answer: ndjson ({\"result\": ...} a line) or array")
	flag.IntVar(&maxAns, "max-answer", 192<<10, "the most bytes of an answer (a stream is cut there)")
	flag.Parse()
	switch *stream {
	case "ndjson":
	case "array":
		asArray = true
	default:
		log.Fatal("grpcjson-okena: -stream is ndjson or array")
	}
	if maxAns < 1024 || maxAns > answerCap {
		log.Fatalf("grpcjson-okena: -max-answer is 1024 to %d", answerCap)
	}
	if *desc == "" || *backend == "" {
		log.Fatal("grpcjson-okena: -descriptors and -backend are needed")
	}
	marsh = protojson.MarshalOptions{UseProtoNames: *protoNames, EmitUnpopulated: *emit}
	if err := load(*desc); err != nil {
		log.Fatal("grpcjson-okena: ", err)
	}
	creds := insecure.NewCredentials()
	if *useTLS {
		c := &tls.Config{}
		if *caFile != "" {
			pem, err := os.ReadFile(*caFile)
			if err != nil {
				log.Fatal(err)
			}
			c.RootCAs = x509.NewCertPool()
			c.RootCAs.AppendCertsFromPEM(pem)
		}
		creds = credentials.NewTLS(c)
	}
	var err error
	if conn, err = grpc.NewClient(*backend, grpc.WithTransportCredentials(creds)); err != nil {
		log.Fatal(err)
	}
	log.Fatal(addon.Run(handle, addon.Options{Workers: 32}))
}

func load(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var set descriptorpb.FileDescriptorSet
	if err := (proto.UnmarshalOptions{Resolver: protoregistry.GlobalTypes}).Unmarshal(b, &set); err != nil {
		return err
	}
	files, err := protodesc.NewFiles(&set)
	if err != nil {
		return err
	}
	files.RangeFiles(func(f protoreflect.FileDescriptor) bool {
		svcs := f.Services()
		for i := 0; i < svcs.Len(); i++ {
			ms := svcs.Get(i).Methods()
			for j := 0; j < ms.Len(); j++ {
				m := ms.Get(j)
				full := "/" + string(svcs.Get(i).FullName()) + "/" + string(m.Name())
				rules = append(rules, rule{verb: "POST", segs: literal(full), body: "*", method: m, fullRPC: full})
				opts, _ := m.Options().(*descriptorpb.MethodOptions)
				if opts == nil || !proto.HasExtension(opts, annotations.E_Http) {
					continue
				}
				hr := proto.GetExtension(opts, annotations.E_Http).(*annotations.HttpRule)
				for _, h := range append([]*annotations.HttpRule{hr}, hr.GetAdditionalBindings()...) {
					if r, err := fromHTTP(h, m, full); err != nil {
						log.Printf("grpcjson-okena: %s: %v (that rule left out)", full, err)
					} else {
						rules = append(rules, r)
					}
				}
			}
		}
		return true
	})
	if len(rules) == 0 {
		return errors.New("no method in the descriptors")
	}
	return nil
}

func literal(p string) []seg {
	var out []seg
	for _, s := range strings.Split(strings.Trim(p, "/"), "/") {
		out = append(out, seg{lit: s})
	}
	return out
}

func fromHTTP(h *annotations.HttpRule, m protoreflect.MethodDescriptor, full string) (rule, error) {
	r := rule{method: m, fullRPC: full, body: h.GetBody()}
	var tpl string
	switch p := h.GetPattern().(type) {
	case *annotations.HttpRule_Get:
		r.verb, tpl = "GET", p.Get
	case *annotations.HttpRule_Put:
		r.verb, tpl = "PUT", p.Put
	case *annotations.HttpRule_Post:
		r.verb, tpl = "POST", p.Post
	case *annotations.HttpRule_Delete:
		r.verb, tpl = "DELETE", p.Delete
	case *annotations.HttpRule_Patch:
		r.verb, tpl = "PATCH", p.Patch
	case *annotations.HttpRule_Custom:
		r.verb, tpl = p.Custom.GetKind(), p.Custom.GetPath()
	default:
		return r, errors.New("a rule without a pattern")
	}
	if i := strings.LastIndex(tpl, ":"); i > strings.LastIndex(tpl, "}") {
		tpl = tpl[:i] + "/" + tpl[i:] // a verb (":cancel"): a last segment of its own
	}
	tpl = strings.Trim(tpl, "/")
	for len(tpl) > 0 {
		var part string
		if tpl[0] == '{' {
			end := strings.IndexByte(tpl, '}')
			if end < 0 {
				return r, errors.New("an unclosed variable in " + tpl)
			}
			part, tpl = tpl[1:end], strings.TrimPrefix(tpl[end+1:], "/")
			field, pat, _ := strings.Cut(part, "=")
			s := seg{field: field, pat: []string{"*"}}
			if pat != "" {
				s.pat = strings.Split(pat, "/")
			}
			r.segs = append(r.segs, s)
			continue
		}
		part, tpl, _ = strings.Cut(tpl, "/")
		r.segs = append(r.segs, seg{lit: part})
	}
	if r.body != "" && r.body != "*" && m.Input().Fields().ByName(protoreflect.Name(r.body)) == nil {
		return r, errors.New("its body field is not in " + string(m.Input().FullName()))
	}
	return r, nil
}

// match: the path's variables, when it is the rule's
func (r *rule) match(path []string) (map[string]string, bool) {
	vars := map[string]string{}
	i := 0
	for k, s := range r.segs {
		if s.field == "" {
			if s.lit == "**" {
				return vars, true
			}
			if i >= len(path) || (s.lit != "*" && path[i] != s.lit) {
				return nil, false
			}
			i++
			continue
		}
		var took []string
		for pi, p := range s.pat {
			if p == "**" {
				rest := len(path) - i - (len(r.segs) - k - 1) - (len(s.pat) - pi - 1)
				if rest < 1 {
					return nil, false
				}
				took = append(took, path[i:i+rest]...)
				i += rest
				continue
			}
			if i >= len(path) || (p != "*" && path[i] != p) {
				return nil, false
			}
			took = append(took, path[i])
			i++
		}
		vars[s.field] = strings.Join(took, "/")
	}
	return vars, i == len(path)
}

// ---------------------------------------------------------------- requests

func handle(r *addon.Request, a *addon.Answer) {
	if r.IsResponse() {
		return
	}
	target := r.Target
	rawPath, rawQuery, _ := strings.Cut(target, "?")
	var parts []string
	for _, p := range strings.Split(strings.Trim(rawPath, "/"), "/") {
		u, err := url.PathUnescape(p)
		if err != nil {
			return
		}
		parts = append(parts, u)
	}
	if tryRules(r, a, parts, rawQuery) {
		return
	}
	// a custom verb (/v1/items:watch): its last segment of its own, as the
	// templates have it
	if n := len(parts); n > 0 {
		if i := strings.LastIndexByte(parts[n-1], ':'); i > 0 {
			split := append(append([]string{}, parts[:n-1]...), parts[n-1][:i], parts[n-1][i:])
			if tryRules(r, a, split, rawQuery) {
				return
			}
		}
	}
	// not a method's: on to the route, as it came
}

func tryRules(r *addon.Request, a *addon.Answer, parts []string, rawQuery string) bool {
	for i := range rules {
		ru := &rules[i]
		if ru.verb != r.Method {
			continue
		}
		vars, ok := ru.match(parts)
		if !ok {
			continue
		}
		transcode(r, a, ru, vars, rawQuery)
		return true
	}
	return false
}

// message: one request message, from a body (its JSON) and the path's and
// the query's fields
func message(ru *rule, body []byte, vars map[string]string, rawQuery string) (*dynamicpb.Message, error) {
	in := dynamicpb.NewMessage(ru.method.Input())
	switch {
	case ru.body == "*":
		if len(body) > 0 {
			if err := unmarsh.Unmarshal(body, in); err != nil {
				return nil, errors.New("the body: " + err.Error())
			}
		}
	case ru.body != "":
		fd := ru.method.Input().Fields().ByName(protoreflect.Name(ru.body))
		if len(body) > 0 {
			if fd.Kind() == protoreflect.MessageKind && !fd.IsList() && !fd.IsMap() {
				sub := in.Mutable(fd).Message().Interface()
				if err := unmarsh.Unmarshal(body, sub); err != nil {
					return nil, errors.New("the body: " + err.Error())
				}
			} else {
				// a scalar or a list as the body: through a message that holds just it
				wrap := []byte(`{"` + fd.JSONName() + `":` + string(body) + `}`)
				if err := unmarsh.Unmarshal(wrap, in); err != nil {
					return nil, errors.New("the body: " + err.Error())
				}
			}
		}
	}
	for k, v := range vars {
		if err := setPath(in, k, []string{v}); err != nil {
			return nil, errors.New("the path's " + k + ": " + err.Error())
		}
	}
	if ru.body != "*" {
		q, err := url.ParseQuery(rawQuery)
		if err != nil {
			return nil, errors.New("the query: " + err.Error())
		}
		for k, vs := range q {
			if _, isVar := vars[k]; isVar || k == ru.body {
				continue
			}
			if err := setPath(in, k, vs); err != nil {
				return nil, errors.New("the query's " + k + ": " + err.Error())
			}
		}
	}
	return in, nil
}

// bodies: a client stream's messages, from a JSON array or one JSON value a
// line (none: no message)
func bodies(b []byte) ([][]byte, error) {
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return nil, nil
	}
	var out [][]byte
	if b[0] == '[' {
		var raw []json.RawMessage
		if err := json.Unmarshal(b, &raw); err != nil {
			return nil, errors.New("the body: " + err.Error())
		}
		for _, x := range raw {
			out = append(out, x)
		}
		return out, nil
	}
	d := json.NewDecoder(bytes.NewReader(b))
	for {
		var x json.RawMessage
		if err := d.Decode(&x); err == io.EOF {
			return out, nil
		} else if err != nil {
			return nil, errors.New("the body: " + err.Error())
		}
		out = append(out, x)
	}
}

func transcode(r *addon.Request, a *addon.Answer, ru *rule, vars map[string]string, rawQuery string) {
	if r.BodyTruncated || r.BodyUnread {
		fail(a, codes.InvalidArgument, "the body is larger than the addon takes (its `body`)")
		return
	}
	var ins []*dynamicpb.Message
	if ru.method.IsStreamingClient() {
		bs, err := bodies(r.Body)
		if err != nil {
			fail(a, codes.InvalidArgument, err.Error())
			return
		}
		for _, b := range bs {
			in, err := message(ru, b, vars, rawQuery)
			if err != nil {
				fail(a, codes.InvalidArgument, err.Error())
				return
			}
			ins = append(ins, in)
		}
	} else {
		in, err := message(ru, r.Body, vars, rawQuery)
		if err != nil {
			fail(a, codes.InvalidArgument, err.Error())
			return
		}
		ins = append(ins, in)
	}
	md := metadata.MD{}
	for _, f := range r.Headers {
		n := strings.ToLower(f.Name)
		if n == "authorization" || strings.HasPrefix(n, "x-") {
			md.Append(n, f.Value)
		}
	}
	ctx, cancel := context.WithTimeout(metadata.NewOutgoingContext(context.Background(), md), timeout)
	defer cancel()
	if !ru.method.IsStreamingClient() && !ru.method.IsStreamingServer() {
		out := dynamicpb.NewMessage(ru.method.Output())
		if err := conn.Invoke(ctx, ru.fullRPC, ins[0], out); err != nil {
			st, _ := status.FromError(err)
			fail(a, st.Code(), st.Message())
			return
		}
		one(a, out)
		return
	}
	st, err := conn.NewStream(ctx, &grpc.StreamDesc{ServerStreams: ru.method.IsStreamingServer(),
		ClientStreams: ru.method.IsStreamingClient()}, ru.fullRPC)
	if err != nil {
		s, _ := status.FromError(err)
		fail(a, s.Code(), s.Message())
		return
	}
	for _, in := range ins {
		if err := st.SendMsg(in); err != nil {
			break // (the service ended it: RecvMsg says why)
		}
	}
	st.CloseSend()
	if !ru.method.IsStreamingServer() {
		out := dynamicpb.NewMessage(ru.method.Output())
		if err := st.RecvMsg(out); err != nil {
			s, _ := status.FromError(err)
			fail(a, s.Code(), s.Message())
			return
		}
		one(a, out)
		return
	}
	// a server stream, gathered
	var buf bytes.Buffer
	n := 0
	end := func(c codes.Code, msg string) {
		e, _ := protojson.Marshal(status.New(c, msg).Proto())
		if asArray {
			// (an array can't carry an error after its elements: its last element is it)
			if n > 0 {
				buf.WriteByte(',')
			}
			buf.WriteString(`{"error":`)
			buf.Write(e)
			buf.WriteByte('}')
			return
		}
		buf.WriteString(`{"error":`)
		buf.Write(e)
		buf.WriteString("}\n")
	}
	if asArray {
		buf.WriteByte('[')
	}
	for {
		out := dynamicpb.NewMessage(ru.method.Output())
		err := st.RecvMsg(out)
		if err == io.EOF {
			break
		}
		if err != nil {
			s, _ := status.FromError(err)
			if n == 0 {
				fail(a, s.Code(), s.Message())
				return
			}
			end(s.Code(), s.Message())
			break
		}
		b, err := marsh.Marshal(out)
		if err != nil {
			fail(a, codes.Internal, err.Error())
			return
		}
		// room for this line, and for an error line after it
		if buf.Len()+len(b)+16+256 > maxAns {
			cancel()
			end(codes.ResourceExhausted, "the stream is longer than an answer holds (-max-answer)")
			break
		}
		if asArray {
			if n > 0 {
				buf.WriteByte(',')
			}
			buf.Write(b)
		} else {
			buf.WriteString(`{"result":`)
			buf.Write(b)
			buf.WriteString("}\n")
		}
		n++
	}
	if asArray {
		buf.WriteByte(']')
	}
	a.Respond(200)
	if asArray {
		a.Add("content-type", "application/json")
	} else {
		a.Add("content-type", "application/x-ndjson")
	}
	a.Body(buf.Bytes())
}

// one: a message as the answer
func one(a *addon.Answer, out proto.Message) {
	b, err := marsh.Marshal(out)
	if err != nil {
		fail(a, codes.Internal, err.Error())
		return
	}
	if len(b) > maxAns {
		fail(a, codes.ResourceExhausted, "the answer is larger than an answer holds (-max-answer)")
		return
	}
	a.Respond(200)
	a.Add("content-type", "application/json")
	a.Body(b)
}

// setPath: a field (a.b.c) of the message set from text, as a path or a query
// gives it; a repeated field takes every value
func setPath(m protoreflect.Message, path string, vals []string) error {
	names := strings.Split(path, ".")
	for i, n := range names {
		fd := m.Descriptor().Fields().ByJSONName(n)
		if fd == nil {
			fd = m.Descriptor().Fields().ByName(protoreflect.Name(n))
		}
		if fd == nil {
			return errors.New("no such field")
		}
		if i < len(names)-1 {
			if fd.Kind() != protoreflect.MessageKind || fd.IsList() || fd.IsMap() {
				return errors.New("not a message")
			}
			m = m.Mutable(fd).Message()
			continue
		}
		if fd.IsMap() {
			return errors.New("a map is not set this way")
		}
		if fd.IsList() {
			l := m.Mutable(fd).List()
			for _, v := range vals {
				pv, err := scalar(fd, v)
				if err != nil {
					return err
				}
				l.Append(pv)
			}
			return nil
		}
		pv, err := scalar(fd, vals[len(vals)-1])
		if err != nil {
			return err
		}
		m.Set(fd, pv)
	}
	return nil
}

func scalar(fd protoreflect.FieldDescriptor, v string) (protoreflect.Value, error) {
	switch fd.Kind() {
	case protoreflect.StringKind:
		return protoreflect.ValueOfString(v), nil
	case protoreflect.BytesKind:
		return protoreflect.ValueOfBytes([]byte(v)), nil
	case protoreflect.BoolKind:
		b, err := strconv.ParseBool(v)
		return protoreflect.ValueOfBool(b), err
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		n, err := strconv.ParseInt(v, 10, 32)
		return protoreflect.ValueOfInt32(int32(n)), err
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		n, err := strconv.ParseInt(v, 10, 64)
		return protoreflect.ValueOfInt64(n), err
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		n, err := strconv.ParseUint(v, 10, 32)
		return protoreflect.ValueOfUint32(uint32(n)), err
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		n, err := strconv.ParseUint(v, 10, 64)
		return protoreflect.ValueOfUint64(n), err
	case protoreflect.FloatKind:
		f, err := strconv.ParseFloat(v, 32)
		return protoreflect.ValueOfFloat32(float32(f)), err
	case protoreflect.DoubleKind:
		f, err := strconv.ParseFloat(v, 64)
		return protoreflect.ValueOfFloat64(f), err
	case protoreflect.EnumKind:
		if ev := fd.Enum().Values().ByName(protoreflect.Name(v)); ev != nil {
			return protoreflect.ValueOfEnum(ev.Number()), nil
		}
		n, err := strconv.ParseInt(v, 10, 32)
		if err != nil {
			return protoreflect.Value{}, errors.New("not one of the enum's values")
		}
		return protoreflect.ValueOfEnum(protoreflect.EnumNumber(n)), nil
	}
	return protoreflect.Value{}, errors.New("a message is not set from text")
}

// fail: the HTTP status for a gRPC code (google.rpc.Code's mapping) and the
// error as JSON
func fail(a *addon.Answer, c codes.Code, msg string) {
	httpOf := map[codes.Code]int{
		codes.OK: 200, codes.Canceled: 499, codes.Unknown: 500, codes.InvalidArgument: 400,
		codes.DeadlineExceeded: 504, codes.NotFound: 404, codes.AlreadyExists: 409,
		codes.PermissionDenied: 403, codes.ResourceExhausted: 429, codes.FailedPrecondition: 400,
		codes.Aborted: 409, codes.OutOfRange: 400, codes.Unimplemented: 501, codes.Internal: 500,
		codes.Unavailable: 503, codes.DataLoss: 500, codes.Unauthenticated: 401,
	}
	code, ok := httpOf[c]
	if !ok {
		code = 500
	}
	b, _ := protojson.Marshal(status.New(c, msg).Proto())
	a.Respond(code)
	a.Add("content-type", "application/json")
	a.Body(b)
}
