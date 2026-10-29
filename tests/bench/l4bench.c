// Test harness only (not part of okena): an epoll echo backend, a tiny
// keep-alive HTTP backend, and a closed-loop ping-pong client that
// reports latency percentiles.
//
//   l4bench echo PORT THREADS
//   l4bench http PORT THREADS     answers every request with 200 and "ok"
//   l4bench ping HOST PORT CONNS THREADS SECONDS SIZE
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

int main(int argc, char **argv) {
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
