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
  name or number, repeated fields from repeated parameters). Every method
  also answers `POST /package.Service/Method` with its whole message as the
  body. A custom verb (`/v1/items:watch`) is matched as the template has it.
* The answer is the reply as JSON (lowerCamelCase names; `-proto-names` for
  the .proto's, `-emit-defaults` for fields at their default). A gRPC error
  is the HTTP status google.rpc's mapping gives (NotFound 404,
  InvalidArgument 400, Unauthenticated 401, ...) with
  `{"code": ..., "message": ...}`.
* `Authorization` and `x-*` fields go to the service as metadata.
* A path no rule matches goes on to the route unchanged, so one route can
  serve a REST API and its gRPC methods.
* `-tls` and `-ca-file` for a service behind TLS.

**Streaming methods.**

* A server stream is gathered within the call's time (`-timeout`) and
  answered as newline-delimited JSON (`application/x-ndjson`), one
  `{"result": ...}` line a message, as grpc-gateway writes them (`-stream
  array` for one JSON array instead). A stream that fails after its first
  message ends with an `{"error": {"code": ..., "message": ...}}` line (the
  status is 200 by then); one that fails before any is an error answer.
* A client stream (and a bidirectional one) takes its messages from the
  body: a JSON array of them, or one JSON object a line. The path's and the
  query's fields go into each.
* An answer is at most `-max-answer` bytes (192 KiB by default, 224 KiB at
  most: what an addon's answer ring holds). A longer stream is cut there and
  ends with a `RESOURCE_EXHAUSTED` error line. A stream meant to stay open
  (a watch that never ends) is no fit for an addon's single answer: call
  the service over gRPC, or gRPC-Web, for that.

`tests/gateway/grpcjson.py` runs it against a service without generated
code (`tests/grpcjson`).
