// The gRPC service tests/gateway/grpcjson.py transcodes to: shop.v1.Shop,
// its descriptors made here (there is no protoc in the tests) with
// google.api.http rules, and served without generated code.
//
//	grpcjson-test-server -write FILE     the descriptor set, with its imports
//	grpcjson-test-server -listen ADDR    the service
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"

	"google.golang.org/genproto/googleapis/api/annotations"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

func field(name string, n int32, t descriptorpb.FieldDescriptorProto_Type, typ string, repeated bool) *descriptorpb.FieldDescriptorProto {
	l := descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL
	if repeated {
		l = descriptorpb.FieldDescriptorProto_LABEL_REPEATED
	}
	f := &descriptorpb.FieldDescriptorProto{Name: proto.String(name), Number: proto.Int32(n), Type: t.Enum(), Label: l.Enum(),
		JsonName: proto.String(jsonName(name))}
	if typ != "" {
		f.TypeName = proto.String(typ)
	}
	return f
}

func jsonName(s string) string {
	parts := strings.Split(s, "_")
	for i := 1; i < len(parts); i++ {
		parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
	}
	return strings.Join(parts, "")
}

func method(name, in, out string, rule *annotations.HttpRule) *descriptorpb.MethodDescriptorProto {
	o := &descriptorpb.MethodOptions{}
	if rule != nil {
		proto.SetExtension(o, annotations.E_Http, rule)
	}
	return &descriptorpb.MethodDescriptorProto{Name: proto.String(name), InputType: proto.String(in), OutputType: proto.String(out), Options: o}
}

func streaming(m *descriptorpb.MethodDescriptorProto, client, server bool) *descriptorpb.MethodDescriptorProto {
	m.ClientStreaming, m.ServerStreaming = proto.Bool(client), proto.Bool(server)
	return m
}

func fileProto() *descriptorpb.FileDescriptorProto {
	S, I64, I32, B, E, M := descriptorpb.FieldDescriptorProto_TYPE_STRING, descriptorpb.FieldDescriptorProto_TYPE_INT64,
		descriptorpb.FieldDescriptorProto_TYPE_INT32, descriptorpb.FieldDescriptorProto_TYPE_BOOL,
		descriptorpb.FieldDescriptorProto_TYPE_ENUM, descriptorpb.FieldDescriptorProto_TYPE_MESSAGE
	return &descriptorpb.FileDescriptorProto{
		Name: proto.String("shop/v1/shop.proto"), Package: proto.String("shop.v1"), Syntax: proto.String("proto3"),
		Dependency: []string{"google/api/annotations.proto"},
		EnumType: []*descriptorpb.EnumDescriptorProto{{Name: proto.String("Color"), Value: []*descriptorpb.EnumValueDescriptorProto{
			{Name: proto.String("COLOR_UNSPECIFIED"), Number: proto.Int32(0)}, {Name: proto.String("RED"), Number: proto.Int32(1)},
			{Name: proto.String("BLUE"), Number: proto.Int32(2)}}}},
		MessageType: []*descriptorpb.DescriptorProto{
			{Name: proto.String("Item"), Field: []*descriptorpb.FieldDescriptorProto{
				field("id", 1, S, "", false), field("name", 2, S, "", false), field("price_cents", 3, I64, "", false),
				field("tags", 4, S, "", true), field("color", 5, E, ".shop.v1.Color", false), field("in_stock", 6, B, "", false),
				field("seen_by", 7, S, "", false)}},
			{Name: proto.String("GetItemRequest"), Field: []*descriptorpb.FieldDescriptorProto{field("id", 1, S, "", false)}},
			{Name: proto.String("CreateItemRequest"), Field: []*descriptorpb.FieldDescriptorProto{
				field("parent", 1, S, "", false), field("item", 2, M, ".shop.v1.Item", false)}},
			{Name: proto.String("ListItemsRequest"), Field: []*descriptorpb.FieldDescriptorProto{
				field("parent", 1, S, "", false), field("page_size", 2, I32, "", false), field("color", 3, E, ".shop.v1.Color", false),
				field("tags", 4, S, "", true)}},
			{Name: proto.String("ListItemsResponse"), Field: []*descriptorpb.FieldDescriptorProto{
				field("items", 1, M, ".shop.v1.Item", true), field("echo", 2, S, "", false)}},
		},
		Service: []*descriptorpb.ServiceDescriptorProto{{Name: proto.String("Shop"), Method: []*descriptorpb.MethodDescriptorProto{
			method("GetItem", ".shop.v1.GetItemRequest", ".shop.v1.Item",
				&annotations.HttpRule{Pattern: &annotations.HttpRule_Get{Get: "/v1/items/{id}"}}),
			method("CreateItem", ".shop.v1.CreateItemRequest", ".shop.v1.Item",
				&annotations.HttpRule{Pattern: &annotations.HttpRule_Post{Post: "/v1/{parent=shops/*}/items"}, Body: "item"}),
			method("ListItems", ".shop.v1.ListItemsRequest", ".shop.v1.ListItemsResponse",
				&annotations.HttpRule{Pattern: &annotations.HttpRule_Get{Get: "/v1/{parent=shops/*}/items"},
					AdditionalBindings: []*annotations.HttpRule{{Pattern: &annotations.HttpRule_Get{Get: "/v1/all-items"}}}}),
			method("DeleteItem", ".shop.v1.GetItemRequest", ".shop.v1.Item",
				&annotations.HttpRule{Pattern: &annotations.HttpRule_Delete{Delete: "/v1/items/{id}"}}),
			method("Ping", ".shop.v1.GetItemRequest", ".shop.v1.Item", nil),
			streaming(method("WatchItems", ".shop.v1.ListItemsRequest", ".shop.v1.Item",
				&annotations.HttpRule{Pattern: &annotations.HttpRule_Get{Get: "/v1/{parent=shops/*}/items:watch"}}), false, true),
			streaming(method("BulkCreate", ".shop.v1.CreateItemRequest", ".shop.v1.ListItemsResponse",
				&annotations.HttpRule{Pattern: &annotations.HttpRule_Post{Post: "/v1/items:bulk"}, Body: "*"}), true, false),
			streaming(method("Chat", ".shop.v1.GetItemRequest", ".shop.v1.Item", nil), true, true),
		}}},
	}
}

var (
	files = []*descriptorpb.FileDescriptorProto{}
	mu    sync.Mutex
	items = map[string]*dynamicpb.Message{}
	owner = map[string]string{}
	order []string
	seq   int
)

func main() {
	write := flag.String("write", "", "the descriptor set's file")
	listen := flag.String("listen", "", "the address to serve on")
	flag.Parse()
	for _, d := range []protoreflect.FileDescriptor{descriptorpb.File_google_protobuf_descriptor_proto,
		annotations.File_google_api_http_proto, annotations.File_google_api_annotations_proto} {
		files = append(files, protodesc.ToFileDescriptorProto(d))
	}
	files = append(files, fileProto())
	set := &descriptorpb.FileDescriptorSet{File: files}
	reg, err := protodesc.NewFiles(set)
	if err != nil {
		log.Fatal(err)
	}
	if *write != "" {
		b, _ := proto.Marshal(set)
		if err := os.WriteFile(*write, b, 0o644); err != nil {
			log.Fatal(err)
		}
		return
	}
	d, _ := reg.FindDescriptorByName("shop.v1.Shop")
	svc := d.(protoreflect.ServiceDescriptor)
	l, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	s := grpc.NewServer(grpc.UnknownServiceHandler(func(_ any, st grpc.ServerStream) error {
		full, _ := grpc.MethodFromServerStream(st)
		m := svc.Methods().ByName(protoreflect.Name(full[strings.LastIndexByte(full, '/')+1:]))
		if m == nil {
			return status.Error(codes.Unimplemented, full)
		}
		if m.IsStreamingClient() || m.IsStreamingServer() {
			return stream(m, st)
		}
		in := dynamicpb.NewMessage(m.Input())
		if err := st.RecvMsg(in); err != nil {
			return err
		}
		md, _ := metadata.FromIncomingContext(st.Context())
		out, err := serve(st.Context(), m, in, md)
		if err != nil {
			return err
		}
		return st.SendMsg(out)
	}))
	log.Fatal(s.Serve(l))
}

func set(m protoreflect.Message, name string, v protoreflect.Value) {
	m.Set(m.Descriptor().Fields().ByName(protoreflect.Name(name)), v)
}

// the streaming methods: WatchItems (a parent's items, one a message;
// shops/fail breaks after the first, shops/fail-first before any,
// shops/big sends more than an answer holds), BulkCreate (every item sent,
// then them all), Chat (each id back as "echo:ID")
func stream(m protoreflect.MethodDescriptor, st grpc.ServerStream) error {
	switch m.Name() {
	case "WatchItems":
		in := dynamicpb.NewMessage(m.Input())
		if err := st.RecvMsg(in); err != nil {
			return err
		}
		parent := get(in, "parent").String()
		switch parent {
		case "shops/fail-first":
			return status.Error(codes.FailedPrecondition, "nothing to watch")
		case "shops/big":
			for i := 0; i < 5000; i++ {
				it := dynamicpb.NewMessage(m.Output())
				set(it, "id", protoreflect.ValueOfString(fmt.Sprintf("b%d", i)))
				set(it, "name", protoreflect.ValueOfString(strings.Repeat("x", 100)))
				if err := st.SendMsg(it); err != nil {
					return nil // (the client went: fine)
				}
			}
			return nil
		}
		mu.Lock()
		var send []proto.Message
		for _, id := range order {
			if it, ok := items[id]; ok && owner[id] == parent {
				send = append(send, proto.Clone(it))
			}
		}
		mu.Unlock()
		for i, it := range send {
			if err := st.SendMsg(it); err != nil {
				return err
			}
			if i == 0 && parent == "shops/fail" {
				return status.Error(codes.Aborted, "the watch broke")
			}
		}
		if parent == "shops/fail" {
			it := dynamicpb.NewMessage(m.Output())
			set(it, "id", protoreflect.ValueOfString("f1"))
			st.SendMsg(it)
			return status.Error(codes.Aborted, "the watch broke")
		}
		return nil
	case "BulkCreate":
		out := dynamicpb.NewMessage(m.Output())
		l := out.Mutable(out.Descriptor().Fields().ByName("items")).List()
		for {
			in := dynamicpb.NewMessage(m.Input())
			if err := st.RecvMsg(in); err == io.EOF {
				break
			} else if err != nil {
				return err
			}
			got, err := serve(st.Context(), m.Parent().(protoreflect.ServiceDescriptor).Methods().ByName("CreateItem"), in, nil)
			if err != nil {
				return err
			}
			l.Append(protoreflect.ValueOfMessage(got.(*dynamicpb.Message)))
		}
		return st.SendMsg(out)
	case "Chat":
		for {
			in := dynamicpb.NewMessage(m.Input())
			if err := st.RecvMsg(in); err == io.EOF {
				return nil
			} else if err != nil {
				return err
			}
			it := dynamicpb.NewMessage(m.Output())
			set(it, "id", protoreflect.ValueOfString("echo:"+get(in, "id").String()))
			if err := st.SendMsg(it); err != nil {
				return err
			}
		}
	}
	return status.Error(codes.Unimplemented, string(m.Name()))
}

func get(m protoreflect.Message, name string) protoreflect.Value {
	return m.Get(m.Descriptor().Fields().ByName(protoreflect.Name(name)))
}

func serve(_ context.Context, m protoreflect.MethodDescriptor, in *dynamicpb.Message, md metadata.MD) (proto.Message, error) {
	mu.Lock()
	defer mu.Unlock()
	switch m.Name() {
	case "GetItem", "DeleteItem", "Ping":
		id := get(in, "id").String()
		it, ok := items[id]
		if m.Name() == "Ping" {
			out := dynamicpb.NewMessage(m.Output())
			out.Set(out.Descriptor().Fields().ByName("id"), protoreflect.ValueOfString("pong:"+id))
			if a := md.Get("authorization"); len(a) > 0 {
				out.Set(out.Descriptor().Fields().ByName("seen_by"), protoreflect.ValueOfString(a[0]))
			}
			return out, nil
		}
		if !ok {
			return nil, status.Errorf(codes.NotFound, "no item %q", id)
		}
		if m.Name() == "DeleteItem" {
			delete(items, id)
		}
		return it, nil
	case "CreateItem":
		it := get(in, "item").Message().Interface().(*dynamicpb.Message)
		if get(it, "name").String() == "" {
			return nil, status.Error(codes.InvalidArgument, "an item needs a name")
		}
		seq++
		id := fmt.Sprintf("i%d", seq)
		owner[id] = get(in, "parent").String()
		it = proto.Clone(it).(*dynamicpb.Message)
		it.Set(it.Descriptor().Fields().ByName("id"), protoreflect.ValueOfString(id))
		items[id] = it
		order = append(order, id)
		return it, nil
	case "ListItems":
		out := dynamicpb.NewMessage(m.Output())
		l := out.Mutable(out.Descriptor().Fields().ByName("items")).List()
		parent, color := get(in, "parent").String(), get(in, "color").Enum()
		for _, id := range order {
			it, ok := items[id]
			if !ok || (parent != "" && owner[id] != parent) || (color != 0 && get(it, "color").Enum() != color) {
				continue
			}
			l.Append(protoreflect.ValueOfMessage(it))
			if n := get(in, "page_size").Int(); n > 0 && int64(l.Len()) >= n {
				break
			}
		}
		var tags []string
		tl := get(in, "tags").List()
		for i := 0; i < tl.Len(); i++ {
			tags = append(tags, tl.Get(i).String())
		}
		out.Set(out.Descriptor().Fields().ByName("echo"), protoreflect.ValueOfString(parent+"|"+strings.Join(tags, ",")))
		return out, nil
	}
	return nil, status.Error(codes.Unimplemented, string(m.Name()))
}
