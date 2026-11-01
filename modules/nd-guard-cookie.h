/* SYN-cookie guard: SipHash-2-4 + кодирование опций (MSS/WS/SACK).
 * Чистые функции без BPF-хелперов: компилируется и под clang -target bpf, и на host.
 * Порядок байт: адреса/порты — как в пакете (network order), cli_isn/slot/cookie — host order.
 * cookie = hash24 << 8 | mss_idx(3) << 5 | sack << 4 | wscale(4; 15 = клиент не прислал WS). */
#ifndef ND_GUARD_COOKIE_H
#define ND_GUARD_COOKIE_H

#include <linux/types.h>

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#ifdef __clang__
#define ND_UNROLL _Pragma("unroll")
#else
#define ND_UNROLL
#endif

#define ND_COOKIE_WS_NONE 15
#define ND_COOKIE_SLOT(ns) ((__u32)((ns) >> 36)) /* ~68,7 с */

struct nd_cookie_opts {
	__u16 mss;
	__u8 wscale_ok, snd_wscale, sack_ok;
};

static const __u16 nd_msstab4[8] = {536, 1220, 1300, 1360, 1400, 1440, 1452, 1460};
static const __u16 nd_msstab6[8] = {1220, 1280, 1340, 1380, 1400, 1420, 1432, 1440};

#define ND_ROTL64(x, b) (((x) << (b)) | ((x) >> (64 - (b))))

#define ND_SIPROUND(v0, v1, v2, v3)                                        \
	do {                                                               \
		v0 += v1; v1 = ND_ROTL64(v1, 13); v1 ^= v0; v0 = ND_ROTL64(v0, 32); \
		v2 += v3; v3 = ND_ROTL64(v3, 16); v3 ^= v2;                \
		v0 += v3; v3 = ND_ROTL64(v3, 21); v3 ^= v0;                \
		v2 += v1; v1 = ND_ROTL64(v1, 17); v1 ^= v2; v2 = ND_ROTL64(v2, 32); \
	} while (0)

/* SipHash-2-4 ровно над 6 словами (48 байт) */
static __always_inline __u64 nd_siphash24(const __u64 key[2], const __u64 m[6])
{
	__u64 v0 = key[0] ^ 0x736f6d6570736575ULL;
	__u64 v1 = key[1] ^ 0x646f72616e646f6dULL;
	__u64 v2 = key[0] ^ 0x6c7967656e657261ULL;
	__u64 v3 = key[1] ^ 0x7465646279746573ULL;
	__u64 b = 48ULL << 56;
	int i;

	ND_UNROLL
	for (i = 0; i < 6; i++) {
		v3 ^= m[i];
		ND_SIPROUND(v0, v1, v2, v3);
		ND_SIPROUND(v0, v1, v2, v3);
		v0 ^= m[i];
	}
	v3 ^= b;
	ND_SIPROUND(v0, v1, v2, v3);
	ND_SIPROUND(v0, v1, v2, v3);
	v0 ^= b;
	v2 ^= 0xff;
	ND_SIPROUND(v0, v1, v2, v3);
	ND_SIPROUND(v0, v1, v2, v3);
	ND_SIPROUND(v0, v1, v2, v3);
	ND_SIPROUND(v0, v1, v2, v3);
	return v0 ^ v1 ^ v2 ^ v3;
}

/* max i: tab[i] <= client_mss, иначе 0 */
static __always_inline __u8 nd_mss_idx(__u16 client_mss, int v6)
{
	__u8 idx = 0;
	int i;

	ND_UNROLL
	for (i = 1; i < 8; i++) {
		__u16 t = v6 ? nd_msstab6[i] : nd_msstab4[i];

		if (t <= client_mss)
			idx = (__u8)i;
	}
	return idx;
}

static __always_inline __u8 nd_cookie_optbyte(__u8 mss_idx, __u8 sack, __u8 wscale)
{
	return (__u8)(((mss_idx & 7) << 5) | ((sack & 1) << 4) | (wscale & 15));
}

static __always_inline __u64 nd_cookie_hash(const __u64 key[2], const __u32 saddr[4],
					    const __u32 daddr[4], __u16 sport, __u16 dport,
					    __u32 cli_isn, __u32 slot, __u8 optbyte)
{
	__u64 m[6];

	m[0] = (__u64)saddr[0] << 32 | saddr[1];
	m[1] = (__u64)saddr[2] << 32 | saddr[3];
	m[2] = (__u64)daddr[0] << 32 | daddr[1];
	m[3] = (__u64)daddr[2] << 32 | daddr[3];
	m[4] = (__u64)sport << 48 | (__u64)dport << 32 | cli_isn;
	m[5] = (__u64)slot << 8 | optbyte;
	return nd_siphash24(key, m);
}

static __always_inline __u32 nd_cookie_make(const __u64 key[2], const __u32 saddr[4],
					    const __u32 daddr[4], __u16 sport, __u16 dport,
					    __u32 cli_isn, __u32 slot, __u8 optbyte)
{
	__u64 h = nd_cookie_hash(key, saddr, daddr, sport, dport, cli_isn, slot, optbyte);

	return (__u32)(h >> 40) << 8 | optbyte;
}

/* 0 — валиден, -1 — нет */
static __always_inline int nd_cookie_check(const __u64 key[2], const __u32 saddr[4],
					   const __u32 daddr[4], __u16 sport, __u16 dport,
					   __u32 cli_isn, __u32 cookie, __u32 now_slot, int v6,
					   struct nd_cookie_opts *out)
{
	__u8 ob = cookie & 0xff;
	__u8 ws = ob & 15;
	__u8 idx = ob >> 5;
	__u32 want = cookie >> 8;
	int i;

	if (ws > 14 && ws != ND_COOKIE_WS_NONE)
		return -1;

	ND_UNROLL
	for (i = 0; i < 2; i++) {
		__u32 slot = now_slot - i;
		__u64 h = nd_cookie_hash(key, saddr, daddr, sport, dport, cli_isn, slot, ob);

		if ((__u32)(h >> 40) == want) {
			out->mss = v6 ? nd_msstab6[idx & 7] : nd_msstab4[idx & 7];
			out->wscale_ok = ws != ND_COOKIE_WS_NONE;
			out->snd_wscale = out->wscale_ok ? ws : 0;
			out->sack_ok = (ob >> 4) & 1;
			return 0;
		}
	}
	return -1;
}

#endif /* ND_GUARD_COOKIE_H */
