// An ext_authz and ext_proc service for tests/gateway/envoyext.py, the way a
// service written for Envoy would answer.
//
//	ext_authz: "Bearer good" is let on, told x-user: alice, its query given
//	  via=authz and its x-drop taken away; anything else is 401 with a
//	  www-authenticate field and a body.
//	ext_proc: x-proc: seen set, x-drop removed; a path ending in /move moves
//	  to /moved; one ending in /immediate is answered 418 here.
package main

import (
	"context"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	procv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type authz struct{ authv3.UnimplementedAuthorizationServer }

func hv(k, v string) *corev3.HeaderValueOption {
	return &corev3.HeaderValueOption{Header: &corev3.HeaderValue{Key: k, Value: v}, Append: wrapperspb.Bool(false)}
}

func (authz) Check(ctx context.Context, r *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	h := r.GetAttributes().GetRequest().GetHttp()
	if strings.Contains(string(h.GetRawBody()), "deny me") {
		return &authv3.CheckResponse{Status: &rpcstatus.Status{Code: int32(codes.PermissionDenied)},
			HttpResponse: &authv3.CheckResponse_DeniedResponse{DeniedResponse: &authv3.DeniedHttpResponse{
				Status: &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden}, Body: "its body says no\n"}}}, nil
	}
	if h.GetHeaders()["authorization"] == "Bearer good" && h.GetHeaders()[":method"] == h.GetMethod() {
		return &authv3.CheckResponse{Status: &rpcstatus.Status{Code: int32(codes.OK)},
			HttpResponse: &authv3.CheckResponse_OkResponse{OkResponse: &authv3.OkHttpResponse{
				Headers:              []*corev3.HeaderValueOption{hv("x-user", "alice"), hv("x-client", r.GetAttributes().GetSource().GetAddress().GetSocketAddress().GetAddress())},
				HeadersToRemove:      []string{"x-drop"},
				QueryParametersToSet: []*corev3.QueryParameter{{Key: "via", Value: "authz"}},
			}}}, nil
	}
	return &authv3.CheckResponse{Status: &rpcstatus.Status{Code: int32(codes.PermissionDenied)},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{DeniedResponse: &authv3.DeniedHttpResponse{
			Status:  &typev3.HttpStatus{Code: typev3.StatusCode_Unauthorized},
			Headers: []*corev3.HeaderValueOption{hv("www-authenticate", "Bearer")},
			Body:    "authz says no\n",
		}}}, nil
}

type proc struct{ procv3.UnimplementedExternalProcessorServer }

func (proc) Process(s procv3.ExternalProcessor_ProcessServer) error {
	seen := "" // the request's path, kept on this stream for its response
	for {
		req, err := s.Recv()
		if err != nil {
			return nil
		}
		if rh := req.GetResponseHeaders(); rh != nil {
			s.Send(&procv3.ProcessingResponse{Response: &procv3.ProcessingResponse_ResponseHeaders{ResponseHeaders: &procv3.HeadersResponse{
				Response: &procv3.CommonResponse{HeaderMutation: &procv3.HeaderMutation{
					SetHeaders: []*corev3.HeaderValueOption{hv("x-proc-resp", "seen "+seen)}, RemoveHeaders: []string{"server"}}},
			}}})
			continue
		}
		if rb := req.GetResponseBody(); rb != nil {
			if strings.Contains(string(rb.GetBody()), "secret") {
				s.Send(&procv3.ProcessingResponse{Response: &procv3.ProcessingResponse_ImmediateResponse{ImmediateResponse: &procv3.ImmediateResponse{
					Status: &typev3.HttpStatus{Code: typev3.StatusCode(500)}, Body: []byte("withheld\n")}}})
			} else if strings.Contains(string(rb.GetBody()), "mutate-resp") {
				s.Send(&procv3.ProcessingResponse{Response: &procv3.ProcessingResponse_ResponseBody{ResponseBody: &procv3.BodyResponse{
					Response: &procv3.CommonResponse{BodyMutation: &procv3.BodyMutation{Mutation: &procv3.BodyMutation_Body{Body: []byte("mutated response\n")}}}}}})
			} else {
				s.Send(&procv3.ProcessingResponse{Response: &procv3.ProcessingResponse_ResponseBody{ResponseBody: &procv3.BodyResponse{}}})
			}
			continue
		}
		if b := req.GetRequestBody(); b != nil {
			var bm *procv3.BodyMutation
			if strings.Contains(string(b.GetBody()), "mutate-me") {
				bm = &procv3.BodyMutation{Mutation: &procv3.BodyMutation_Body{Body: []byte("mutated by ext_proc")}}
			}
			s.Send(&procv3.ProcessingResponse{Response: &procv3.ProcessingResponse_RequestBody{RequestBody: &procv3.BodyResponse{
				Response: &procv3.CommonResponse{HeaderMutation: &procv3.HeaderMutation{
					SetHeaders: []*corev3.HeaderValueOption{hv("x-proc-body", strconv.Itoa(len(b.GetBody())))}}, BodyMutation: bm},
			}}})
			continue
		}
		hs := req.GetRequestHeaders()
		if hs == nil {
			continue
		}
		path := ""
		for _, h := range hs.GetHeaders().GetHeaders() {
			if h.GetKey() == ":path" {
				path = string(h.GetRawValue())
			}
		}
		seen = path
		if strings.HasSuffix(path, "/immediate") {
			s.Send(&procv3.ProcessingResponse{Response: &procv3.ProcessingResponse_ImmediateResponse{ImmediateResponse: &procv3.ImmediateResponse{
				Status:  &typev3.HttpStatus{Code: typev3.StatusCode(418)},
				Headers: &procv3.HeaderMutation{SetHeaders: []*corev3.HeaderValueOption{hv("x-proc", "immediate")}},
				Body:    []byte("short and stout\n"),
			}}})
			continue
		}
		set := []*corev3.HeaderValueOption{hv("x-proc", "seen")}
		if strings.HasSuffix(path, "/move") {
			set = append(set, hv(":path", "/moved"))
		}
		s.Send(&procv3.ProcessingResponse{Response: &procv3.ProcessingResponse_RequestHeaders{RequestHeaders: &procv3.HeadersResponse{
			Response: &procv3.CommonResponse{HeaderMutation: &procv3.HeaderMutation{SetHeaders: set, RemoveHeaders: []string{"x-drop"}}},
		}}})
	}
}

func main() {
	l, err := net.Listen("tcp", os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	g := grpc.NewServer()
	authv3.RegisterAuthorizationServer(g, authz{})
	procv3.RegisterExternalProcessorServer(g, proc{})
	log.Fatal(g.Serve(l))
}
