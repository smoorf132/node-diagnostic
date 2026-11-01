/* nd-guard.h — ABI карт guard, общий для XDP (nd-guard-xdp.bpf.c) и tc (nd-guard-tc.bpf.c).
 * Карты пинятся в GUARD_PIN/maps/<имя>; tc-объект переиспользует их по имени
 * (`bpftool prog loadall … map name guard_cfg_map pinned …`).
 * Python-сторона — modules/guard_ctrl.py: структуры ниже меняются только вместе с ней.
 * Порядок байт: host-order поля пишутся native (x86/arm64 — LE), адреса в lpm* — network. */
#ifndef ND_GUARD_H
#define ND_GUARD_H

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define GUARD_P_TCP 0x1
#define GUARD_P_UDP 0x2
#define GUARD_P_GEO 0x4

enum { COOKIE_OFF = 0, COOKIE_AUTO = 1, COOKIE_ALWAYS = 2 };

struct guard_cfg {               /* guard_cfg_map[0], 40 байт; python: "<IIIIIHH2Q" (native) */
	__u32 geo_on, cookie_mode, syn_threshold, hold_sec, rcv_wscale;
	__u16 mss4, mss6;            /* наш MSS в SYN-ACK: MTU-40 / MTU-60 */
	__u64 key[2];                /* ключ SipHash: 16 байт key-file как есть */
};

/* guard_state_map[0]; часы — bpf_ktime_get_ns() (CLOCK_MONOTONIC) */
struct guard_state { __u64 win_start_ns, win_syn, attack_until_ns; };

struct lpm4 { __u32 prefixlen; __u8 addr[4]; };    /* prefixlen — host order */
struct lpm6 { __u32 prefixlen; __u8 addr[16]; };

/* guard_stats_map: PERCPU, guard_ctrl.py stats суммирует по CPU */
enum { ST_PASS, ST_GEO_DROP, ST_ALLOW, ST_SYN, ST_COOKIE_SENT, ST_COOKIE_OK, ST_COOKIE_BAD,
       ST_ASSIGN_ERR, ST__MAX };

_Static_assert(sizeof(struct guard_cfg) == 40, "guard_cfg: 40 байт (guard_ctrl.py)");
_Static_assert(sizeof(struct guard_state) == 24, "guard_state: 3×u64");

#define GUARD_NSEC 1000000000ULL

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct guard_cfg);
} guard_cfg_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct guard_state);
} guard_state_map SEC(".maps");

/* ключ — порт в host order, значение — GUARD_P_* */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 65536);
	__type(key, __u32);
	__type(value, __u8);
} guard_ports_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, ST__MAX);
	__type(key, __u32);
	__type(value, __u64);
} guard_stats_map SEC(".maps");

static __always_inline void guard_stat(__u32 idx)
{
	__u64 *c = bpf_map_lookup_elem(&guard_stats_map, &idx);

	if (c)
		*c += 1;
}

#endif /* ND_GUARD_H */
