// The XDP bench's baselines: the path alone, and the far end.
#include <linux/bpf.h>
#define SEC(n) __attribute__((section(n), used))
// the frame straight back out (the path's cost, no balancing)
SEC("xdp") int xdp_tx(struct xdp_md *ctx) { return XDP_TX; }
// the far end: what the balancer sent, dropped (counted by the veth)
SEC("xdp") int xdp_drop(struct xdp_md *ctx) { return XDP_DROP; }
char _license[] SEC("license") = "GPL";
