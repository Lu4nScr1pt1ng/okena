// The XDP bench's loader (libbpf), for what okena does not load itself:
//   kload attach OBJ PROG IFACE      a program of OBJ on IFACE (in the driver, else generic)
//   kload katran OBJ IFACE GWMAC VIP PORT PROTO LRU REAL...
//                                    Katran's balancer.bpf.o on IFACE, its maps filled the
//                                    way its control plane fills them: the default router's
//                                    MAC, one VIP, the reals (1..n), the ring (RING_SIZE
//                                    slots in turn) and an LRU a CPU (LRU flows in all)
//   kload stats IFACE                the program on IFACE: runs, and ns in it (needs
//                                    kernel.bpf_stats_enabled=1)
// The programs stay attached after it exits (`ip link set IFACE xdp off`).
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RING_SIZE 65537		// katran/lib/bpf/balancer_consts.h

static void die(const char *what) { fprintf(stderr, "kload: %s\n", what); exit(1); }

static const char *attach(int fd, const char *name) {
	int ifx = if_nametoindex(name);
	if (!ifx) die("no such interface");
	if (bpf_xdp_attach(ifx, fd, XDP_FLAGS_DRV_MODE, NULL) == 0) return "driver";
	if (bpf_xdp_attach(ifx, fd, XDP_FLAGS_SKB_MODE, NULL) == 0) return "generic";
	die("attach");
	return 0;
}

static int mapfd(struct bpf_object *obj, const char *name) {
	int fd = bpf_object__find_map_fd_by_name(obj, name);
	if (fd < 0) { fprintf(stderr, "kload: no map %s\n", name); exit(1); }
	return fd;
}

// katran/lib/bpf/balancer_structs.h
struct vip_definition { uint32_t vip[4]; uint16_t port; uint8_t proto; uint8_t pad; };
struct vip_meta { uint32_t flags, vip_num; };
struct real_definition { uint32_t dst[4]; uint8_t flags; uint8_t pad[3]; };
struct flow_key { uint32_t src[4], dst[4]; uint32_t ports; uint8_t proto; uint8_t pad[3]; };
struct real_pos_lru { uint32_t pos; uint32_t pad; uint64_t atime; };

int main(int argc, char **argv) {
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	if (argc == 5 && !strcmp(argv[1], "attach")) {
		struct bpf_object *obj = bpf_object__open_file(argv[2], NULL);
		if (!obj || bpf_object__load(obj)) die("load");
		struct bpf_program *p = bpf_object__find_program_by_name(obj, argv[3]);
		if (!p) die("no such program");
		printf("%s on %s (%s)\n", argv[3], argv[4], attach(bpf_program__fd(p), argv[4]));
		return 0;
	}
	if (argc >= 10 && !strcmp(argv[1], "katran")) {
		int ncpu = libbpf_num_possible_cpus(), lru = atoi(argv[8]) / ncpu;
		struct bpf_object *obj = bpf_object__open_file(argv[2], NULL);
		if (!obj) die("open");
		// the LRU a CPU (lru_mapping, a map of maps): its template made here
		// (libbpf 1.3 cannot resize the one it would make)
		struct bpf_map *outer = bpf_object__find_map_by_name(obj, "lru_mapping");
		int tmpl = bpf_map_create(BPF_MAP_TYPE_LRU_HASH, NULL, sizeof(struct flow_key),
			sizeof(struct real_pos_lru), lru, NULL);
		if (!outer || tmpl < 0 || bpf_map__set_inner_map_fd(outer, tmpl)) die("lru_mapping");
		if (bpf_object__load(obj)) die("load");
		int lm = bpf_map__fd(outer);
		for (uint32_t c = 0; c < (uint32_t)ncpu; c++) {
			int fd = bpf_map_create(BPF_MAP_TYPE_LRU_HASH, NULL, sizeof(struct flow_key),
				sizeof(struct real_pos_lru), lru, NULL);
			if (fd < 0 || bpf_map_update_elem(lm, &c, &fd, 0)) die("a CPU's LRU");
		}
		uint32_t k = 0;
		uint64_t mac = 0;		// ctl_array[0]: the default router's MAC
		unsigned m[6];
		if (sscanf(argv[4], "%x:%x:%x:%x:%x:%x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) != 6) die("mac");
		for (int i = 0; i < 6; i++) ((uint8_t *)&mac)[i] = m[i];
		if (bpf_map_update_elem(mapfd(obj, "ctl_array"), &k, &mac, 0)) die("ctl_array");
		struct vip_definition vd = {0};
		if (inet_pton(AF_INET, argv[5], &vd.vip[0]) != 1) die("VIP");
		vd.port = htons(atoi(argv[6]));
		vd.proto = atoi(argv[7]);
		struct vip_meta vm = {0, 0};
		if (bpf_map_update_elem(mapfd(obj, "vip_map"), &vd, &vm, 0)) die("vip_map");
		int nreal = argc - 9, rf = mapfd(obj, "reals"), cf = mapfd(obj, "ch_rings");
		for (int i = 0; i < nreal; i++) {
			struct real_definition rd = {0};
			if (inet_pton(AF_INET, argv[9 + i], &rd.dst[0]) != 1) die("real");
			k = i + 1;
			if (bpf_map_update_elem(rf, &k, &rd, 0)) die("reals");
		}
		for (k = 0; k < RING_SIZE; k++) {
			uint32_t r = 1 + k % nreal;
			if (bpf_map_update_elem(cf, &k, &r, 0)) die("ch_rings");
		}
		struct bpf_program *p = bpf_object__find_program_by_name(obj, "balancer_ingress");
		if (!p) die("no balancer_ingress");
		printf("katran on %s (%s), %d reals, LRU %d a CPU\n", argv[3],
			attach(bpf_program__fd(p), argv[3]), nreal, lru);
		return 0;
	}
	if (argc == 3 && !strcmp(argv[1], "stats")) {
		int ifx = if_nametoindex(argv[2]);
		uint32_t id = 0;
		if (!ifx || bpf_xdp_query_id(ifx, 0, &id) || !id) die("no program on the interface");
		int fd = bpf_prog_get_fd_by_id(id);
		struct bpf_prog_info info = {0};
		uint32_t len = sizeof info;
		if (fd < 0 || bpf_prog_get_info_by_fd(fd, &info, &len)) die("prog info");
		printf("%llu %llu\n", (unsigned long long)info.run_cnt, (unsigned long long)info.run_time_ns);
		return 0;
	}
	fprintf(stderr, "usage: kload attach OBJ PROG IFACE\n"
		"       kload katran OBJ IFACE GWMAC VIP PORT PROTO LRU REAL...\n"
		"       kload stats IFACE\n");
	return 2;
}
