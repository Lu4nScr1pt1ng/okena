//! An addon in Rust: lets requests go on with x-checked: yes, answers
//! /blocked itself, and takes x-debug away.
//!
//!     cargo build --release --example hello
//!     addon hello { run /path/to/target/release/examples/hello }
use okena_addon::{run, Answer, Request};

fn main() {
    run(|req: &Request, ans: &mut Answer| {
        let path = req.path();
        if path.ends_with(b"/blocked") {
            ans.respond(403);
            ans.add("content-type", "text/plain");
            ans.body(b"blocked by the addon\n");
        } else if !path.ends_with(b"/pass") {
            ans.set("x-checked", "yes");
            ans.remove("x-debug");
        }
    })
    .expect("okena addon");
}
