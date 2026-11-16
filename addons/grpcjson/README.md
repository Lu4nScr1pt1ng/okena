# grpcjson-okena

gRPC-JSON transcoding as an okena addon: REST clients call a gRPC service
in JSON, by the paths its `google.api.http` rules give (as Envoy's
transcoder and grpc-gateway read them), or by `POST /package.Service/Method`.

```sh
cd addons/grpcjson && go build -o /usr/local/bin/grpcjson-okena .
protoc --include_imports --descriptor_set_out=/etc/okena/api.pb -I. api.proto
```

```nginx
addon grpcjson {
    run /usr/local/bin/grpcjson-okena -descriptors /etc/okena/api.pb -backend 10.0.0.7:9000
    phases request_body            # the JSON body comes with the call
    body 1MiB
    timeout 5s
}
route /v1/* { addon grpcjson; to pool rest }
```

* Rules: GET, PUT, POST, DELETE, PATCH and custom verbs, with their
  `additional_bindings`; path variables `{name}`, `{name=pattern/*}`,
  `{name=**}`, nested fields (`{book.id}`); `body: "*"`, `body: "field"`,
  or no body, the query then filling the other fields (scalars, enums by
  name or number, repeated fields from repeated parameters). Every unary
  method also answers `POST /package.Service/Method` with its whole message
  as the body.
* The answer is the reply as JSON (lowerCamelCase names; `-proto-names` for
  the .proto's, `-emit-defaults` for fields at their default). A gRPC error
  is the HTTP status google.rpc's mapping gives (NotFound 404,
  InvalidArgument 400, Unauthenticated 401, ...) with
  `{"code": ..., "message": ...}`.
* `Authorization` and `x-*` fields go to the service as metadata.
* A path no rule matches goes on to the route unchanged, so one route can
  serve a REST API and its gRPC methods.
* `-tls` and `-ca-file` for a service behind TLS. Unary methods only.

`tests/gateway/grpcjson.py` runs it against a service without generated
code (`tests/grpcjson`).
