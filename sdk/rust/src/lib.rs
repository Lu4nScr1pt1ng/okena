//! okena addon SDK for Rust (protocol version 1, docs/ADDONS.md in the okena
//! repository). No dependency beyond `std`.
//!
//! ```no_run
//! use okena_addon::{run, Answer, Request};
//!
//! fn main() {
//!     run(|req: &Request, ans: &mut Answer| {
//!         if req.header("x-block").is_some() {
//!             ans.respond(403);
//!             ans.add("content-type", "text/plain");
//!             ans.body(b"blocked\n");
//!             return;
//!         }
//!         ans.set("x-checked", "yes"); // the default answer: continue
//!     })
//!     .expect("okena addon");
//! }
//! ```
//!
//! The handler runs on one thread. After a call the addon polls the rings for
//! the addon's `poll` (default 50 us; `OKENA_ADDON_SPIN_US` overrides it)
//! before it sleeps on the bell.

use std::fs::File;
use std::io::{self, Read, Write};
use std::mem::ManuallyDrop;
use std::os::fd::FromRawFd;
use std::sync::atomic::{fence, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

const MAGIC: u64 = 0x314E_4F44_4441_4B4F;
const VERSION: u32 = 1;
const ANSWER_MAX: usize = 1 << 16;

pub const PHASE_REQUEST_HEADERS: u16 = 1;
pub const FLAG_TLS: u32 = 1;
pub const FLAG_H2: u32 = 2;
pub const FLAG_H3: u32 = 4;
pub const PHASE_REQUEST_BODY: u16 = 2;
pub const PHASE_RESPONSE_HEADERS: u16 = 4;
pub const PHASE_RESPONSE_BODY: u16 = 8;
pub const PHASE_LOG: u16 = 16;
pub const FLAG_BODY_TRUNCATED: u32 = 8;
pub const FLAG_BODY_CHUNKED: u32 = 16;
pub const FLAG_BODY_UNREAD: u32 = 32;

extern "C" {
    fn mmap(addr: *mut u8, len: usize, prot: i32, flags: i32, fd: i32, off: i64) -> *mut u8;
}
const PROT_READ: i32 = 1;
const PROT_WRITE: i32 = 2;
const MAP_SHARED: i32 = 1;

/// A call: the request's head as okena forwards it (HTTP/1.1 form, also for
/// HTTP/2 and HTTP/3 clients). It borrows okena's memory: valid while the
/// handler runs.
pub struct Request<'a> {
    pub id: u32,
    pub phase: u16,
    pub flags: u32,
    pub route: u32,
    pub head: &'a [u8],
    pub family: u16,
    pub client: [u8; 16],
    /// The body as it came (phases request_body): `dechunk` it when
    /// `flags & FLAG_BODY_CHUNKED`.
    pub body: &'a [u8],
    /// The same in every call about one request (its phases, its log).
    pub stream: (u32, u64),
    all: &'a [u8],
    method: (usize, usize),
    target: (usize, usize),
    index: &'a [u8],
}

impl<'a> Request<'a> {
    fn slice(&self, o: usize, l: usize) -> &'a [u8] {
        self.all.get(o..o + l).unwrap_or(&[])
    }
    /// A call about the backend's response: fields and body are the
    /// response's, method and target the request's.
    pub fn is_response(&self) -> bool {
        self.phase & (PHASE_RESPONSE_HEADERS | PHASE_RESPONSE_BODY) != 0
    }
    /// The backend's status (the response phases).
    pub fn status(&self) -> u16 {
        std::str::from_utf8(self.head).ok().and_then(|h| h.split(' ').nth(1)).and_then(|s| s.parse().ok()).unwrap_or(0)
    }
    pub fn method(&self) -> &'a [u8] {
        self.slice(self.method.0, self.method.1)
    }
    pub fn target(&self) -> &'a [u8] {
        self.slice(self.target.0, self.target.1)
    }
    /// The target without its query.
    pub fn path(&self) -> &'a [u8] {
        let t = self.target();
        t.split(|&c| c == b'?').next().unwrap_or(t)
    }
    pub fn fields(&self) -> impl Iterator<Item = (&'a [u8], &'a [u8])> + '_ {
        self.index.chunks_exact(8).map(move |x| {
            let u = |i: usize| u16::from_le_bytes([x[i], x[i + 1]]) as usize;
            (self.slice(u(0), u(2)), self.slice(u(4), u(6)))
        })
    }
    /// The first field of that name (any case).
    pub fn header(&self, name: &str) -> Option<&'a [u8]> {
        self.fields().find(|(n, _)| n.eq_ignore_ascii_case(name.as_bytes())).map(|(_, v)| v)
    }
    pub fn client_ip(&self) -> Option<std::net::IpAddr> {
        match self.family {
            4 => Some(std::net::Ipv4Addr::new(self.client[0], self.client[1], self.client[2], self.client[3]).into()),
            6 => Some(std::net::Ipv6Addr::from(self.client).into()),
            _ => None,
        }
    }
}

/// What the handler decides: continue (the default), with changes to the
/// request, or respond. okena's own fields (Content-Length, Connection...)
/// are not changed.
pub struct Answer {
    buf: Vec<u8>,
    nops: u16,
    action: u16,
    status: u16,
    body: Vec<u8>,
    body_set: bool,
    none: bool,
    overflow: bool,
}

impl Answer {
    fn new() -> Self {
        Answer { buf: vec![0; 24], nops: 0, action: 0, status: 0, body: Vec::new(), body_set: false, none: false, overflow: false }
    }
    fn reset(&mut self) {
        self.buf.truncate(24);
        self.body.clear();
        (self.nops, self.action, self.status, self.none, self.overflow, self.body_set) = (0, 0, 0, false, false, false);
    }
    fn op(&mut self, code: u8, name: &[u8], value: &[u8]) {
        if name.len() > 0xFFFF || value.len() > 0xFFFF || self.buf.len() + 6 + name.len() + value.len() > ANSWER_MAX {
            self.overflow = true;
            return;
        }
        self.buf.extend_from_slice(&[code, 0]);
        self.buf.extend_from_slice(&(name.len() as u16).to_le_bytes());
        self.buf.extend_from_slice(&(value.len() as u16).to_le_bytes());
        self.buf.extend_from_slice(name);
        self.buf.extend_from_slice(value);
        self.nops += 1;
    }
    /// Replaces every request field of that name (respond: a response field).
    pub fn set(&mut self, name: &str, value: &str) {
        self.op(1, name.as_bytes(), value.as_bytes())
    }
    /// Adds a field (respond: a response field).
    pub fn add(&mut self, name: &str, value: &str) {
        self.op(2, name.as_bytes(), value.as_bytes())
    }
    /// Takes away every request field of that name.
    pub fn remove(&mut self, name: &str) {
        self.op(3, name.as_bytes(), b"")
    }
    /// Sends the request to another pool (its name in okena's configuration).
    pub fn pool(&mut self, name: &str) {
        self.op(5, b"", name.as_bytes())
    }
    /// Replaces the request target (path and query).
    pub fn target(&mut self, target: &str) {
        self.op(4, b"", target.as_bytes())
    }
    /// Answers the client here with this status; `add` gives its fields.
    pub fn respond(&mut self, status: u16) {
        (self.action, self.status) = (1, status)
    }
    /// The body of a respond; with continue, a body in place of the one that
    /// came (one the call carried whole; okena sets its Content-Length).
    pub fn body(&mut self, body: &[u8]) {
        self.body.clear();
        self.body.extend_from_slice(body);
        self.body_set = true;
    }
    /// Leaves the call unanswered: okena's on_error, at its time.
    pub fn no_answer(&mut self) {
        self.none = true
    }
    /// Says the addon could not decide: okena's on_error at once, and a
    /// failure for the circuit.
    pub fn fail(&mut self) {
        self.action = 2
    }
}

/// The memory okena shares with this addon.
pub struct Addon {
    m: *mut u8,
    nrings: u32,
    rbytes: u64,
    hbytes: u64,
    stride: u64,
    bell: ManuallyDrop<File>,
    wake0: i32,
    pub name: String,
    spin: Duration,
}

impl Addon {
    /// Maps the memory OKENA_ADDON_FD names.
    pub fn open() -> io::Result<Addon> {
        let fd: i32 = std::env::var("OKENA_ADDON_FD").ok().and_then(|s| s.parse().ok()).unwrap_or(3);
        let f = ManuallyDrop::new(unsafe { File::from_raw_fd(fd) });
        let size = f.metadata()?.len() as usize;
        let m = unsafe { mmap(std::ptr::null_mut(), size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0) };
        if m as isize == -1 {
            return Err(io::Error::last_os_error());
        }
        let rd32 = |o: usize| unsafe { (m.add(o) as *const u32).read_unaligned() };
        let rd64 = |o: usize| unsafe { (m.add(o) as *const u64).read_unaligned() };
        if rd64(0) != MAGIC || rd32(8) != VERSION {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "not okena's memory, or another protocol version"));
        }
        let name = unsafe { std::slice::from_raw_parts(m.add(64), 64) };
        let name = String::from_utf8_lossy(name.split(|&c| c == 0).next().unwrap_or(&[])).into_owned();
        let spin = std::env::var("OKENA_ADDON_SPIN_US").ok().and_then(|s| s.parse().ok()).unwrap_or(rd32(140) as u64);
        Ok(Addon {
            m,
            nrings: rd32(12),
            rbytes: rd32(16) as u64,
            hbytes: rd32(20) as u64,
            stride: rd64(24),
            bell: ManuallyDrop::new(unsafe { File::from_raw_fd(rd32(32) as i32) }),
            wake0: rd32(36) as i32,
            name,
            spin: Duration::from_micros(spin),
        })
    }

    fn a32(&self, off: u64) -> &AtomicU32 {
        unsafe { &*(self.m.add(off as usize) as *const AtomicU32) }
    }
    fn a64(&self, off: u64) -> &AtomicU64 {
        unsafe { &*(self.m.add(off as usize) as *const AtomicU64) }
    }
    fn bytes(&self, off: u64, len: usize) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.m.add(off as usize), len) }
    }
    fn pair(&self, r: u32) -> u64 {
        self.hbytes + r as u64 * self.stride
    }
    fn u16at(&self, off: u64) -> u16 {
        let b = self.bytes(off, 2);
        u16::from_le_bytes([b[0], b[1]])
    }
    fn u32at(&self, off: u64) -> u32 {
        let b = self.bytes(off, 4);
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    }

    /// Serves calls with the handler, forever (returns on an error).
    pub fn run<F: FnMut(&Request, &mut Answer)>(&mut self, mut f: F) -> io::Result<()> {
        let mut ans = Answer::new();
        self.a32(60).store(1, Ordering::SeqCst);
        self.a32(48).store(1, Ordering::SeqCst);
        let mut last = Instant::now();
        let mut polling = false;
        loop {
            if self.poll(&mut f, &mut ans) > 0 {
                if !polling && !self.spin.is_zero() {
                    self.a32(60).store(0, Ordering::SeqCst);
                    polling = true;
                }
                last = Instant::now();
                continue;
            }
            if polling && last.elapsed() < self.spin {
                std::hint::spin_loop();
                continue;
            }
            self.a32(60).swap(1, Ordering::SeqCst);
            polling = false;
            if self.poll(&mut f, &mut ans) > 0 {
                last = Instant::now();
                continue;
            }
            let mut v = [0u8; 8];
            match (&*self.bell).read(&mut v) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }

    fn poll<F: FnMut(&Request, &mut Answer)>(&self, f: &mut F, ans: &mut Answer) -> usize {
        let mut n = 0;
        let mask = self.rbytes - 1;
        for r in 0..self.nrings {
            let p = self.pair(r);
            let head = self.a64(p).load(Ordering::Acquire);
            let mut tail = self.a64(p + 64).load(Ordering::Relaxed);
            if head == tail {
                continue;
            }
            let d = p + self.hbytes;
            let mut answered = false;
            while tail != head {
                let at = d + (tail & mask);
                let len = self.u32at(at) as u64;
                let kind = self.u16at(at + 4);
                if len < 8 || len & 7 != 0 || len > head - tail {
                    tail = head;
                    break;
                }
                if kind == 1 {
                    let hl = self.u32at(at + 16) as usize;
                    let nh = self.u16at(at + 20) as usize;
                    let mut client = [0u8; 16];
                    client.copy_from_slice(self.bytes(at + 24, 16));
                    let req = Request {
                        id: self.u32at(at + 8),
                        phase: self.u16at(at + 6),
                        flags: self.u32at(at + 12),
                        route: self.u32at(at + 48),
                        family: self.u16at(at + 22),
                        client,
                        method: (self.u16at(at + 40) as usize, self.u16at(at + 42) as usize),
                        target: (self.u16at(at + 44) as usize, self.u16at(at + 46) as usize),
                        index: self.bytes(at + 64, 8 * nh),
                        head: self.bytes(at + 64 + 8 * nh as u64, hl),
                        body: self.bytes(at + 64 + 8 * nh as u64 + hl as u64, self.u32at(at + 52) as usize),
                        all: self.bytes(at + 64 + 8 * nh as u64, hl + self.u32at(at + 52) as usize),
                        stream: (r, self.u32at(at + 56) as u64 | (self.u32at(at + 60) as u64) << 32),
                    };
                    let mut req = req;
                    if req.is_response() {
                        let e = (req.target.0 + req.target.1).min(req.all.len());
                        req.body = &req.all[e..];
                    }
                    ans.reset();
                    f(&req, ans);
                    if req.phase != PHASE_LOG {
                        answered |= self.answer(r, req.id, ans);
                    }
                    n += 1;
                }
                tail += len;
            }
            self.a64(p + 64).store(tail, Ordering::Release);
            if answered {
                fence(Ordering::SeqCst);
                let h = p + self.hbytes + self.rbytes;
                if self.a32(h + 128).load(Ordering::Relaxed) == 0 {
                    let mut w = ManuallyDrop::new(unsafe { File::from_raw_fd(self.wake0 + r as i32) });
                    let _ = w.write(&1u64.to_le_bytes());
                }
            }
        }
        n
    }

    fn answer(&self, r: u32, id: u32, ans: &mut Answer) -> bool {
        if ans.none || ans.overflow {
            return false;
        }
        let h = self.pair(r) + self.hbytes + self.rbytes;
        let d = h + self.hbytes;
        let size = ((ans.buf.len() + ans.body.len() + 7) & !7) as u64;
        let mut head = self.a64(h).load(Ordering::Relaxed);
        let tail = self.a64(h + 64).load(Ordering::Acquire);
        let mut pos = head & (self.rbytes - 1);
        let pad = if self.rbytes - pos < size { self.rbytes - pos } else { 0 };
        if pad + size > self.rbytes - (head - tail) {
            return false;
        }
        unsafe {
            if pad > 0 {
                let p = self.m.add((d + pos) as usize);
                (p as *mut u32).write_unaligned(pad as u32);
                (p.add(4) as *mut u32).write_unaligned(0);
                head += pad;
                pos = 0;
            }
            let b = &mut ans.buf;
            b[0..4].copy_from_slice(&(size as u32).to_le_bytes());
            b[4..6].copy_from_slice(&1u16.to_le_bytes());
            b[6..8].copy_from_slice(&ans.action.to_le_bytes());
            b[8..12].copy_from_slice(&id.to_le_bytes());
            b[12..14].copy_from_slice(&ans.status.to_le_bytes());
            b[14..16].copy_from_slice(&ans.nops.to_le_bytes());
            b[16..20].copy_from_slice(&(ans.body.len() as u32).to_le_bytes());
            b[20..24].copy_from_slice(&u32::from(ans.action == 0 && ans.body_set).to_le_bytes());
            let p = self.m.add((d + pos) as usize);
            std::ptr::copy_nonoverlapping(b.as_ptr(), p, b.len());
            std::ptr::copy_nonoverlapping(ans.body.as_ptr(), p.add(b.len()), ans.body.len());
        }
        self.a64(h).store(head + size, Ordering::Release);
        true
    }
}

/// Decodes a chunk-framed body: its bytes, and whether its last chunk was there.
pub fn dechunk(mut raw: &[u8]) -> (Vec<u8>, bool) {
    let mut out = Vec::new();
    loop {
        let Some(i) = raw.windows(2).position(|w| w == b"\r\n") else { return (out, false) };
        let size = std::str::from_utf8(&raw[..i]).unwrap_or("").split(';').next().unwrap_or("").trim();
        let Ok(n) = usize::from_str_radix(size, 16) else { return (out, false) };
        if n == 0 {
            return (out, true);
        }
        raw = &raw[i + 2..];
        if raw.len() < n {
            out.extend_from_slice(raw);
            return (out, false);
        }
        out.extend_from_slice(&raw[..n]);
        if raw.len() < n + 2 {
            return (out, false);
        }
        raw = &raw[n + 2..];
    }
}

/// Opens okena's memory and serves calls with the handler, forever.
pub fn run<F: FnMut(&Request, &mut Answer)>(f: F) -> io::Result<()> {
    Addon::open()?.run(f)
}
