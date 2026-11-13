//! A proxy-wasm plugin on the Rust SDK (the proxy-wasm crate), for
//! tests/gateway/wasm.py: x-rust on every request, /rust-deny answered here.
use proxy_wasm::traits::{Context, HttpContext, RootContext};
use proxy_wasm::types::{Action, ContextType, LogLevel};

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Info);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> { Box::new(Root) });
}}

struct Root;
impl Context for Root {}
impl RootContext for Root {
    fn create_http_context(&self, _: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(Stream))
    }
    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }
}

struct Stream;
impl Context for Stream {}
impl HttpContext for Stream {
    fn on_http_request_headers(&mut self, _: usize, _: bool) -> Action {
        let path = self.get_http_request_header(":path").unwrap_or_default();
        if path.ends_with("/rust-deny") {
            self.send_http_response(451, vec![("x-plugin", "rust")], Some(b"unavailable\n"));
            return Action::Pause;
        }
        self.add_http_request_header("x-rust", "yes");
        self.set_http_request_header("x-drop", None);
        Action::Continue
    }
}
