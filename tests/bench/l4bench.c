// Test harness only (not part of okena): an epoll echo backend, a tiny
// keep-alive HTTP backend, and a closed-loop ping-pong client that
// reports latency percentiles.
//
//   l4bench echo PORT THREADS
//   l4bench http PORT THREADS     answers every request with 200 and "ok"
//   l4bench ping HOST PORT CONNS THREADS SECONDS SIZE
//   l4bench pingep HOST PORT CONNS THREADS SECONDS SIZE
//                                  every connection with a message in flight
//                                  at all times (epoll): the most a second
//   l4bench sink PORT THREADS      reads and drops
//   l4bench blast HOST PORT CONNS THREADS SECONDS
//                                  writes 64 KiB at a time: Gbit/s
//   l4bench cps HOST PORT THREADS SECONDS
//                                  a new connection per 64-byte exchange (the
//                                  client closes with a reset: no TIME_WAIT)
//   l4bench httpbig PORT SIZE      HTTP/1.1, keep-alive: every request answered
//                                  with a body of SIZE bytes, or of N for GET /N
//                                  (N at most SIZE; a thread a connection;
//                                  cacheable: Cache-Control: max-age=3600)
//   l4bench hold HOST PORT N SECONDS
//                                  N keep-alive HTTP connections, each one GET
//                                  and its answer, then idle for SECONDS (from
//                                  127.0.0.2.. as sources, 20000 a source)
//   l4bench uecho PORT THREADS     UDP echo
//   l4bench uping HOST PORT CONNS THREADS SECONDS SIZE
//                                  UDP, a datagram in flight on each socket
//                                  (epoll); one not back in 200 ms is lost
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int port_g, http_g;
static void *echo_thread(void *arg) {
    (void)arg;
    int ls = socket(AF_INET, SOCK_STREAM, 0), one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port_g),
                            .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    if (bind(ls, (void *)&a, sizeof a) || listen(ls, 4096)) { perror("bind"); exit(1); }
    int ep = epoll_create1(0);
    struct epoll_event ev = {.events = EPOLLIN, .data.fd = ls}, evs[256];
    epoll_ctl(ep, EPOLL_CTL_ADD, ls, &ev);
    char buf[65536];
    for (;;) {
        int n = epoll_wait(ep, evs, 256, -1);
        for (int i = 0; i < n; i++) {
            int fd = evs[i].data.fd;
            if (fd == ls) {
                int c = accept4(ls, 0, 0, SOCK_NONBLOCK);
                if (c < 0) continue;
                setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
                ev.events = EPOLLIN; ev.data.fd = c;
                epoll_ctl(ep, EPOLL_CTL_ADD, c, &ev);
                continue;
            }
            ssize_t r = read(fd, buf, sizeof buf);
            if (r <= 0) { close(fd); continue; }
            if (http_g) {
                // one response per request head in what was read (no bodies)
                static const char resp[] = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
                int n = 0;
                for (ssize_t k = 3; k < r; k++)
                    if (buf[k] == '\n' && buf[k - 1] == '\r' && buf[k - 2] == '\n' && buf[k - 3] == '\r') n++;
                for (int k = 0; k < n; k++)
                    if (write(fd, resp, sizeof resp - 1) < 0) break;
                continue;
            }
            ssize_t off = 0;
            while (off < r) { ssize_t w = write(fd, buf + off, r - off); if (w <= 0) break; off += w; }
        }
    }
    return 0;
}

static const char *host_g; static int conns_g, secs_g, size_g, threads_g;
static long *lat_g; static long nlat_g; static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static long now_ns(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec * 1000000000L + t.tv_nsec; }

static void *ping_thread(void *arg) {
    long per = conns_g / threads_g; (void)arg;
    int *fds = calloc(per, sizeof(int)), one = 1;
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port_g)};
    inet_pton(AF_INET, host_g, &a.sin_addr);
    for (long i = 0; i < per; i++) {
        fds[i] = socket(AF_INET, SOCK_STREAM, 0);
        setsockopt(fds[i], IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        if (connect(fds[i], (void *)&a, sizeof a)) { perror("connect"); exit(1); }
    }
    char *msg = malloc(size_g), *in = malloc(size_g); memset(msg, 'x', size_g);
    long cap = 1 << 22, n = 0, *lat = malloc(cap * sizeof(long));
    long end = now_ns() + secs_g * 1000000000L, warm = now_ns() + 1000000000L;
    // each connection in turn: send, wait for the echo (closed loop)
    while (now_ns() < end) {
        for (long i = 0; i < per; i++) {
            long t0 = now_ns();
            if (write(fds[i], msg, size_g) != size_g) { perror("write"); exit(1); }
            long got = 0;
            while (got < size_g) { ssize_t r = read(fds[i], in + got, size_g - got); if (r <= 0) { perror("read"); exit(1); } got += r; }
            long t1 = now_ns();
            if (t0 > warm && n < cap) lat[n++] = t1 - t0;
        }
    }
    pthread_mutex_lock(&mu);
    memcpy(lat_g + nlat_g, lat, n * sizeof(long)); nlat_g += n;
    pthread_mutex_unlock(&mu);
    return 0;
}
static int cmp(const void *a, const void *b) { long x = *(long *)a, y = *(long *)b; return (x > y) - (x < y); }

static int more_modes(int argc, char **argv);
int main(int argc, char **argv) {
    if (argc >= 2) { int r = more_modes(argc, argv); if (r >= 0) return r; }
    if (argc >= 4 && (!strcmp(argv[1], "echo") || !strcmp(argv[1], "http"))) {
        http_g = !strcmp(argv[1], "http");
        port_g = atoi(argv[2]); int t = atoi(argv[3]);
        pthread_t th; for (int i = 0; i < t; i++) pthread_create(&th, 0, echo_thread, 0);
        pause(); return 0;
    }
    if (argc < 8) { fprintf(stderr, "usage: see source\n"); return 2; }
    host_g = argv[2]; port_g = atoi(argv[3]); conns_g = atoi(argv[4]); threads_g = atoi(argv[5]);
    secs_g = atoi(argv[6]); size_g = atoi(argv[7]);
    lat_g = malloc((long)threads_g * (1 << 22) * sizeof(long));
    pthread_t th[256];
    for (int i = 0; i < threads_g; i++) pthread_create(&th[i], 0, ping_thread, 0);
    for (int i = 0; i < threads_g; i++) pthread_join(th[i], 0);
    qsort(lat_g, nlat_g, sizeof(long), cmp);
    double rate = nlat_g / (double)(secs_g - 1);
    printf("%.0f req/s  p50 %.1f us  p99 %.1f us  p99.9 %.1f us  max %.1f us\n", rate,
           lat_g[nlat_g / 2] / 1e3, lat_g[nlat_g * 99 / 100] / 1e3, lat_g[nlat_g * 999 / 1000] / 1e3,
           lat_g[nlat_g - 1] / 1e3);
    return 0;
}


static char *big_resp; static long big_size;
static void *big_conn(void *arg) {
    int c = (int)(long)arg; char buf[65536]; long have = 0;
    for (;;) {
        ssize_t r = read(c, buf + have, sizeof buf - have);
        if (r <= 0) break;
        have += r;
        for (;;) {   // each request head in what was read
            char *e = memmem(buf, have, "\r\n\r\n", 4);
            if (!e) break;
            long used = e + 4 - buf, size = big_size;
            if (have > 6 && buf[5] >= '1' && buf[5] <= '9') size = atol(buf + 5);   // GET /SIZE
            if (size > big_size) size = big_size;
            char head[128];
            int hl = snprintf(head, sizeof head, "HTTP/1.1 200 OK\r\nCache-Control: max-age=3600\r\nContent-Length: %ld\r\n\r\n", size);
            if (write(c, head, hl) != hl) goto out;
            for (long off = 0; off < size;) { ssize_t w = write(c, big_resp + off, size - off); if (w <= 0) goto out; off += w; }
            memmove(buf, buf + used, have - used); have -= used;
        }
        if (have == sizeof buf) break;
    }
out:
    close(c);
    return 0;
}
static int httpbig(int port, long size) {
    signal(SIGPIPE, SIG_IGN);              // a client gone mid-body: that connection, not the server
    big_size = size; big_resp = malloc(size); memset(big_resp, 'x', size);
    int ls = socket(AF_INET, SOCK_STREAM, 0), one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    if (bind(ls, (void *)&a, sizeof a) || listen(ls, 4096)) { perror("bind"); return 1; }
    for (;;) {
        int c = accept(ls, 0, 0);
        if (c < 0) continue;
        setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        pthread_t t;
        if (pthread_create(&t, 0, big_conn, (void *)(long)c)) { perror("thread"); close(c); continue; }
        pthread_detach(t);
    }
}


static int hold(const char *host, int port, long n, int secs) {
    signal(SIGPIPE, SIG_IGN);
    int *fds = calloc(n, sizeof(int)), ep = epoll_create1(0), one = 1;
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port)};
    inet_pton(AF_INET, host, &a.sin_addr);
    static const char req[] = "GET / HTTP/1.1\r\nHost: a\r\n\r\n";
    long ok = 0, failed = 0, i = 0;
    while (i < n) {
        long batch = i + 2000 < n ? i + 2000 : n, started = i;
        for (; i < batch; i++) {
            int fd = socket(AF_INET, SOCK_STREAM, 0);
            struct sockaddr_in src = {.sin_family = AF_INET,
                                      .sin_addr.s_addr = htonl(0x7F000002 + (uint32_t)(i / 20000))};
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
            if (bind(fd, (void *)&src, sizeof src) || connect(fd, (void *)&a, sizeof a) ||
                write(fd, req, sizeof req - 1) != (ssize_t)sizeof req - 1) { close(fd); fds[i] = -1; failed++; continue; }
            fds[i] = fd;
        }
        for (long k = started; k < batch; k++) {   // each its answer, whole
            if (fds[k] < 0) continue;
            char buf[4096]; long got = 0, want = -1;
            struct pollfd pf = {.fd = fds[k], .events = POLLIN};
            while (want < 0 || got < want) {
                if (poll(&pf, 1, 5000) <= 0) break;
                ssize_t r = read(fds[k], buf + got, sizeof buf - got);
                if (r <= 0) break;
                got += r;
                char *e = memmem(buf, got, "\r\n\r\n", 4);
                if (e && want < 0) {
                    char *cl = memmem(buf, e - buf, "Content-Length:", 15);
                    want = (e + 4 - buf) + (cl ? atol(cl + 15) : 0);
                }
            }
            if (want >= 0 && got >= want) ok++; else { close(fds[k]); fds[k] = -1; failed++; }
        }
    }
    (void)ep;
    printf("held %ld, failed %ld\n", ok, failed);
    fflush(stdout);
    sleep(secs);
    return 0;
}

// ---- more modes ----
static void *sink_thread(void *arg) {
    (void)arg;
    int ls = socket(AF_INET, SOCK_STREAM, 0), one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port_g),
                            .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    if (bind(ls, (void *)&a, sizeof a) || listen(ls, 4096)) { perror("bind"); exit(1); }
    int ep = epoll_create1(0);
    struct epoll_event ev = {.events = EPOLLIN, .data.fd = ls}, evs[256];
    epoll_ctl(ep, EPOLL_CTL_ADD, ls, &ev);
    static __thread char buf[1 << 18];
    for (;;) {
        int n = epoll_wait(ep, evs, 256, -1);
        for (int i = 0; i < n; i++) {
            int fd = evs[i].data.fd;
            if (fd == ls) {
                int c = accept4(ls, 0, 0, SOCK_NONBLOCK);
                if (c < 0) continue;
                ev.events = EPOLLIN; ev.data.fd = c;
                epoll_ctl(ep, EPOLL_CTL_ADD, c, &ev);
                continue;
            }
            ssize_t r;
            while ((r = read(fd, buf, sizeof buf)) > 0) ;
            if (r == 0 || (r < 0 && errno != EAGAIN)) close(fd);
        }
    }
    return 0;
}
static void *uecho_thread(void *arg) {
    (void)arg;
    int s = socket(AF_INET, SOCK_DGRAM, 0), one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port_g),
                            .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    if (bind(s, (void *)&a, sizeof a)) { perror("bind"); exit(1); }
    char buf[65536];
    for (;;) {
        struct sockaddr_in from; socklen_t fl = sizeof from;
        ssize_t r = recvfrom(s, buf, sizeof buf, 0, (void *)&from, &fl);
        if (r >= 0) sendto(s, buf, r, 0, (void *)&from, fl);
    }
    return 0;
}

static volatile long total_g, lost_g;
static int udp_g;
// epoll over this thread's sockets, each with one message in flight
static void *pingep_thread(void *arg) {
    (void)arg;
    long per = conns_g / threads_g;
    int one = 1, ep = epoll_create1(0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port_g)};
    inet_pton(AF_INET, host_g, &a.sin_addr);
    int *fds = calloc(per, sizeof(int)); long *t0 = calloc(per, sizeof(long)), *got = calloc(per, sizeof(long));
    char *msg = malloc(size_g), *in = malloc(65536); memset(msg, 'x', size_g);
    for (long i = 0; i < per; i++) {
        fds[i] = socket(AF_INET, udp_g ? SOCK_DGRAM : SOCK_STREAM, 0);
        if (!udp_g) setsockopt(fds[i], IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        if (connect(fds[i], (void *)&a, sizeof a)) { perror("connect"); exit(1); }
        struct epoll_event ev = {.events = EPOLLIN, .data.u64 = i};
        epoll_ctl(ep, EPOLL_CTL_ADD, fds[i], &ev);
    }
    long cap = 1 << 22, n = 0, *lat = malloc(cap * sizeof(long)), lost = 0;
    long end = now_ns() + secs_g * 1000000000L, warm = now_ns() + 1000000000L;
    for (long i = 0; i < per; i++) { t0[i] = now_ns(); if (write(fds[i], msg, size_g) != size_g) { perror("write"); exit(1); } }
    struct epoll_event evs[256];
    long last_sweep = now_ns();
    while (now_ns() < end) {
        int k = epoll_wait(ep, evs, 256, 50);
        long now = now_ns();
        for (int j = 0; j < k; j++) {
            long i = evs[j].data.u64;
            ssize_t r = read(fds[i], in, udp_g ? 65536 : size_g - got[i]);
            if (r <= 0) { if (r < 0 && errno == EAGAIN) continue; perror("read"); exit(1); }
            if (!udp_g) { got[i] += r; if (got[i] < size_g) continue; got[i] = 0; }
            if (t0[i] > warm && n < cap) lat[n++] = now - t0[i];
            t0[i] = now;
            if (write(fds[i], msg, size_g) != size_g && !udp_g) { perror("write"); exit(1); }
        }
        if (udp_g && now - last_sweep > 50000000L) {     // lost datagrams: send again
            last_sweep = now;
            for (long i = 0; i < per; i++)
                if (now - t0[i] > 200000000L) { if (t0[i] > warm) lost++; t0[i] = now; (void)!write(fds[i], msg, size_g); }
        }
    }
    pthread_mutex_lock(&mu);
    memcpy(lat_g + nlat_g, lat, n * sizeof(long)); nlat_g += n; lost_g += lost;
    pthread_mutex_unlock(&mu);
    return 0;
}
static void *blast_thread(void *arg) {
    (void)arg;
    long per = conns_g / threads_g, sent = 0;
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port_g)};
    inet_pton(AF_INET, host_g, &a.sin_addr);
    struct pollfd *p = calloc(per, sizeof *p);
    for (long i = 0; i < per; i++) {
        p[i].fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0); p[i].events = POLLOUT;
        connect(p[i].fd, (void *)&a, sizeof a);
    }
    static __thread char buf[65536];
    long start = now_ns(), warm = start + 1000000000L, end = start + secs_g * 1000000000L;
    while (now_ns() < end) {
        if (poll(p, per, 100) <= 0) continue;
        for (long i = 0; i < per; i++) if (p[i].revents & POLLOUT) {
            ssize_t w = write(p[i].fd, buf, sizeof buf);
            if (w > 0 && now_ns() > warm) sent += w;
        }
    }
    __sync_fetch_and_add(&total_g, sent);
    return 0;
}
static void *cps_thread(void *arg) {
    (void)arg;
    long n = 0, cap = 1 << 22, *lat = malloc(cap * sizeof(long));
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port_g)};
    inet_pton(AF_INET, host_g, &a.sin_addr);
    char msg[64], in[64]; memset(msg, 'x', 64);
    struct linger lg = {1, 0}; int one = 1;
    long end = now_ns() + secs_g * 1000000000L, warm = now_ns() + 1000000000L;
    while (now_ns() < end) {
        long t0 = now_ns();
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        if (connect(fd, (void *)&a, sizeof a)) { close(fd); continue; }
        long got = 0;
        if (write(fd, msg, 64) == 64)
            while (got < 64) { ssize_t r = read(fd, in + got, 64 - got); if (r <= 0) break; got += r; }
        setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
        close(fd);
        if (got == 64 && t0 > warm) { if (n < cap) lat[n++] = now_ns() - t0; }
    }
    pthread_mutex_lock(&mu);
    memcpy(lat_g + nlat_g, lat, n * sizeof(long)); nlat_g += n;
    pthread_mutex_unlock(&mu);
    return 0;
}
static void report(void) {
    qsort(lat_g, nlat_g, sizeof(long), cmp);
    if (!nlat_g) { printf("0 req/s\n"); return; }
    double rate = nlat_g / (double)(secs_g - 1);
    printf("%.0f req/s  p50 %.1f us  p99 %.1f us  p99.9 %.1f us  max %.1f us  lost %ld\n", rate,
           lat_g[nlat_g / 2] / 1e3, lat_g[nlat_g * 99 / 100] / 1e3, lat_g[nlat_g * 999 / 1000] / 1e3,
           lat_g[nlat_g - 1] / 1e3, lost_g);
}
static int more_modes(int argc, char **argv) {
    const char *m = argv[1];
    if (!strcmp(m, "httpbig") && argc >= 4) return httpbig(atoi(argv[2]), atol(argv[3]));
    if (!strcmp(m, "hold") && argc >= 6) return hold(argv[2], atoi(argv[3]), atol(argv[4]), atoi(argv[5]));
    pthread_t th[256];
    if ((!strcmp(m, "sink") || !strcmp(m, "uecho")) && argc >= 4) {
        port_g = atoi(argv[2]); int t = atoi(argv[3]);
        for (int i = 0; i < t; i++) pthread_create(&th[0], 0, !strcmp(m, "sink") ? sink_thread : uecho_thread, 0);
        pause(); return 0;
    }
    if (!strcmp(m, "cps") && argc >= 6) {
        host_g = argv[2]; port_g = atoi(argv[3]); threads_g = atoi(argv[4]); secs_g = atoi(argv[5]);
        lat_g = malloc((long)threads_g * (1 << 22) * sizeof(long));
        for (int i = 0; i < threads_g; i++) pthread_create(&th[i], 0, cps_thread, 0);
        for (int i = 0; i < threads_g; i++) pthread_join(th[i], 0);
        report(); return 0;
    }
    if (!strcmp(m, "blast") && argc >= 7) {
        host_g = argv[2]; port_g = atoi(argv[3]); conns_g = atoi(argv[4]); threads_g = atoi(argv[5]); secs_g = atoi(argv[6]);
        for (int i = 0; i < threads_g; i++) pthread_create(&th[i], 0, blast_thread, 0);
        for (int i = 0; i < threads_g; i++) pthread_join(th[i], 0);
        printf("%.2f Gbit/s\n", total_g * 8.0 / (secs_g - 1) / 1e9); return 0;
    }
    if ((!strcmp(m, "pingep") || !strcmp(m, "uping")) && argc >= 8) {
        udp_g = !strcmp(m, "uping");
        host_g = argv[2]; port_g = atoi(argv[3]); conns_g = atoi(argv[4]); threads_g = atoi(argv[5]);
        secs_g = atoi(argv[6]); size_g = atoi(argv[7]);
        lat_g = malloc((long)threads_g * (1 << 22) * sizeof(long));
        for (int i = 0; i < threads_g; i++) pthread_create(&th[i], 0, pingep_thread, 0);
        for (int i = 0; i < threads_g; i++) pthread_join(th[i], 0);
        report(); return 0;
    }
    return -1;
}
