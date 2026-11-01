/*
 * nd-guard-xdp.bpf.c — XDP-часть guard: гео-фильтр по LPM и SYN-ACK с SYN-cookie.
 *
 * На каждый пакет (порт из guard_ports_map, иначе PASS без статистики):
 *   allowlist → гео (единственный DROP) → SYN: окно 1 с, auto/always → SYN-ACK (XDP_TX) → PASS.
 * Любая ошибка — PASS (fail-open, D9). ACK с cookie проверяет tc (nd-guard-tc.bpf.c).
 *
 * Совместимость: ядро ≥ 5.10, clang без -mcpu=v3 — без atomic fetch, bpf_loop и доступа
 * к стеку по переменному смещению. Разбор опций и сборка SYN-ACK — глобальные функции
 * (BTF, ядро ≥ 5.6): верификатор проверяет каждую один раз с непрозрачными аргументами,
 * поэтому комбинации опций SYN не размножают состояния (иначе — E2BIG).
 * Порядок байт cookie (R3): адреса/порты — как в пакете, ISN/cookie — host order.
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "nd-guard.h"
#include "nd-guard-cookie.h"

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 65536);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm4);
	__type(value, __u8);
} geo4_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 65536);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm6);
	__type(value, __u8);
} geo6_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 1024);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm4);
	__type(value, __u8);
} allow4_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 1024);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm6);
	__type(value, __u8);
} allow6_map SEC(".maps");

#define ND_IP_MF      0x2000
#define ND_IP_OFFSET  0x1fff
#define ND_OPT_EOL    0
#define ND_OPT_NOP    1
#define ND_OPT_MSS    2
#define ND_OPT_WS     3
#define ND_OPT_SACKOK 4
#define ND_OPT_TS     8
#define ND_OPT_SPACE  40   /* максимум опций TCP */
#define ND_MAX_WS     14
#define ND_TCP_SYNACK 0x12
#define ND_L4_OFF4    (sizeof(struct ethhdr) + sizeof(struct iphdr))
#define ND_L4_OFF6    (sizeof(struct ethhdr) + sizeof(struct ipv6hdr))

/* Опции SYN, упакованные в u64 (результат nd_syn_opts):
 * [0:16) MSS клиента (0 — не прислал), [16:20) WS (≤ 14; 15 — не прислал),
 * [20] SACKOK, [21] TS, [32:64) TSval клиента как в пакете (→ наш TSecr) */
#define ND_SO_WS_SHIFT   16
#define ND_SO_SACK       (1ULL << 20)
#define ND_SO_TS         (1ULL << 21)
#define ND_SO_TSVAL_SHIFT 32

/* TCP-заголовок SYN-ACK + до 5 слов опций; хвост за doff — нули (в чексумму не входят) */
struct synack_tcp {
	struct tcphdr th;
	__be32 opt[5];
};

static __always_inline __u16 csum_fold(__s64 sum)
{
	__u32 s = (__u32)sum;

	s = (s & 0xffff) + (s >> 16);
	s = (s & 0xffff) + (s >> 16);
	return (__u16)~s;
}

static __always_inline int lpm_hit(void *m4, void *m6, int v6, const __u32 saddr[4])
{
	if (v6) {
		struct lpm6 k = { .prefixlen = 128 };

		__builtin_memcpy(k.addr, saddr, 16);
		return bpf_map_lookup_elem(m6, &k) != 0;
	} else {
		struct lpm4 k = { .prefixlen = 32 };

		__builtin_memcpy(k.addr, saddr, 4);
		return bpf_map_lookup_elem(m4, &k) != 0;
	}
}

/*
 * Опции SYN → u64 (ND_SO_*). Глобальная функция: значения флагов ни на что не ветвятся,
 * остаются «неточными» для верификатора, и пути с разными опциями сливаются.
 * Ограниченный цикл по байтам (≤ 40), next — смещение следующей опции. Чтобы состояние
 * в начале итерации не зависело от истории:
 *  - указатели на пакет берутся из ctx заново на каждой итерации (volatile — clang их
 *    не выносит из цикла): диапазоны проверок прошлых итераций не живут в состоянии;
 *  - конец опций по doff (lim) — отдельно загруженный указатель: сравнение указателей
 *    ничего не уточняет;
 *  - next = i + len ≤ 40, а длина для разбора смысла перечитывается volatile-чтением:
 *    сравнения «len == 4» не сужают next до константы.
 */
__noinline __u64 nd_syn_opts(struct xdp_md *ctx, __u32 v6, __u32 optlen)
{
	__u64 next = 0;   /* u64: на ядрах < 5.16 spill u32 теряет границы */
	__u64 mss = 0, ws = ND_COOKIE_WS_NONE, sack = 0, ts = 0, tsval = 0;
	__u32 optoff = (v6 ? ND_L4_OFF6 : ND_L4_OFF4) + sizeof(struct tcphdr);
	__u32 i;

	if (optlen > ND_OPT_SPACE)
		optlen = 0;
	for (i = 0; i < ND_OPT_SPACE; i++) {
		__u8 *opt = (__u8 *)(long)*(volatile __u32 *)&ctx->data + optoff;
		__u8 *lim = (__u8 *)(long)*(volatile __u32 *)&ctx->data + optoff + optlen;
		void *end = (void *)(long)*(volatile __u32 *)&ctx->data_end;
		__u8 kind, len;

		if (i != next)
			continue;               /* внутри опции */
		if (opt + i + 1 > lim || (void *)(opt + i + 1) > end)
			break;
		kind = opt[i];
		if (kind == ND_OPT_EOL)
			break;
		if (kind == ND_OPT_NOP) {
			next = i + 1;
			continue;
		}
		if (opt + i + 2 > lim || (void *)(opt + i + 2) > end)
			break;
		len = opt[i + 1];
		if (len < 2 || i + len > ND_OPT_SPACE || opt + i + len > lim)
			break;                  /* битая опция — дальше не разбираем, как ядро */
		next = i + len;
		len = *(volatile __u8 *)(opt + i + 1);

		if (kind == ND_OPT_MSS && len == 4) {
			if ((void *)(opt + i + 4) <= end)
				mss = (__u16)opt[i + 2] << 8 | opt[i + 3];
		} else if (kind == ND_OPT_WS && len == 3) {
			if ((void *)(opt + i + 3) <= end)
				ws = opt[i + 2] > ND_MAX_WS ? ND_MAX_WS : opt[i + 2];
		} else if (kind == ND_OPT_SACKOK && len == 2) {
			sack = ND_SO_SACK;
		} else if (kind == ND_OPT_TS && len == 10) {
			if ((void *)(opt + i + 10) <= end) {
				tsval = (__u64)*(__u32 *)(opt + i + 2) << ND_SO_TSVAL_SHIFT;
				ts = ND_SO_TS;
			}
		}
	}
	return tsval | ts | sack | ws << ND_SO_WS_SHIFT | mss;
}

/* Окно SYN 1 с + режим cookies. XADD без fetch (ядро < 5.12, -mcpu=v1): счётчик читается
 * после инкремента — то же n = fetch_add + 1, при гонке CPU — не меньше. */
static __always_inline int syn_wants_cookie(const struct guard_cfg *cfg, __u64 now)
{
	__u32 zero = 0;
	struct guard_state *st = bpf_map_lookup_elem(&guard_state_map, &zero);
	__u64 n;

	if (!st)
		return cfg->cookie_mode == COOKIE_ALWAYS;
	if (now - st->win_start_ns > GUARD_NSEC) {
		st->win_start_ns = now;
		st->win_syn = 0;
	}
	__sync_fetch_and_add(&st->win_syn, 1);
	n = st->win_syn;
	if (cfg->cookie_mode == COOKIE_AUTO && n > cfg->syn_threshold)
		st->attack_until_ns = now + (__u64)cfg->hold_sec * GUARD_NSEC;
	if (cfg->cookie_mode == COOKIE_ALWAYS)
		return 1;
	return cfg->cookie_mode == COOKIE_AUTO && now < st->attack_until_ns;
}

/* Пакет вмещает TCP-заголовок + nw слов опций с начала w */
#define ND_FITS(w, nw, end)                                                     \
	((void *)((w) + 6) <= (end) && ((nw) < 2 || (void *)((w) + 7) <= (end)) && \
	 ((nw) < 3 || (void *)((w) + 8) <= (end)) &&                              \
	 ((nw) < 4 || (void *)((w) + 9) <= (end)) &&                              \
	 ((nw) < 5 || (void *)((w) + 10) <= (end)))

/*
 * SYN → SYN-ACK с cookie на месте (opts — из nd_syn_opts). Глобальная функция: заголовки
 * перечитывает из пакета сама. 0 — пакет готов к XDP_TX, <0 — отдать ядру.
 */
__noinline int nd_synack(struct xdp_md *ctx, __u64 opts, __u64 now)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct tcphdr *tcp;
	struct guard_cfg *cfg;
	struct synack_tcp s;
	__u32 saddr[4] = {}, daddr[4] = {};
	__u8 cli_mac[ETH_ALEN], srv_mac[ETH_ALEN];
	__u32 zero = 0, isn, tcplen, newlen, sum;
	__u16 cli_mss, our_mss;
	__u8 ws = (opts >> ND_SO_WS_SHIFT) & 0xf, ws_rcv;
	__be16 sport, dport;
	__u64 nw;      /* слов опций; u64 — границы переживают spill на ядрах < 5.16 */
	__be32 *w;
	int v6, delta;

	cfg = bpf_map_lookup_elem(&guard_cfg_map, &zero);
	if (!cfg || (void *)(eth + 1) > data_end)
		return -1;
	if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = (void *)(eth + 1);

		if ((void *)(ip6 + 1) > data_end || ip6->nexthdr != IPPROTO_TCP)
			return -1;
		__builtin_memcpy(saddr, &ip6->saddr, 16);
		__builtin_memcpy(daddr, &ip6->daddr, 16);
		tcp = (void *)(ip6 + 1);
		v6 = 1;
	} else if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *ip = (void *)(eth + 1);

		if ((void *)(ip + 1) > data_end || ip->ihl != 5 || ip->protocol != IPPROTO_TCP)
			return -1;
		saddr[0] = ip->saddr;
		daddr[0] = ip->daddr;
		tcp = (void *)(ip + 1);
		v6 = 0;
	} else {
		return -1;
	}
	if ((void *)(tcp + 1) > data_end)
		return -1;
	sport = tcp->source;
	dport = tcp->dest;
	isn = bpf_ntohl(tcp->seq);
	__builtin_memcpy(cli_mac, eth->h_source, ETH_ALEN);
	__builtin_memcpy(srv_mac, eth->h_dest, ETH_ALEN);

	cli_mss = opts & 0xffff;
	if (!cli_mss)
		cli_mss = v6 ? 1220 : 536;
	__builtin_memset(&s, 0, sizeof(s));
	s.th.source = dport;
	s.th.dest = sport;
	s.th.seq = bpf_htonl(nd_cookie_make(cfg->key, saddr, daddr, sport, dport, isn,
					    ND_COOKIE_SLOT(now),
					    nd_cookie_optbyte(nd_mss_idx(cli_mss, v6),
							      !!(opts & ND_SO_SACK), ws)));
	s.th.ack_seq = bpf_htonl(isn + 1);
	s.th.window = bpf_htons(65535);

	our_mss = v6 ? cfg->mss6 : cfg->mss4;
	if (!our_mss)
		our_mss = v6 ? 1440 : 1460;
	ws_rcv = cfg->rcv_wscale > ND_MAX_WS ? ND_MAX_WS : cfg->rcv_wscale;
	s.opt[0] = bpf_htonl(0x02040000 | our_mss);
	nw = 1;
	if (opts & ND_SO_TS) {
		/* SACKOK,TS | NOP,NOP,TS */
		s.opt[1] = bpf_htonl(opts & ND_SO_SACK ? 0x0402080a : 0x0101080a);
		s.opt[2] = bpf_htonl((__u32)(now / 1000000));
		s.opt[3] = (__u32)(opts >> ND_SO_TSVAL_SHIFT);
		nw = 4;
	} else if (opts & ND_SO_SACK) {
		s.opt[1] = bpf_htonl(0x01010402);                       /* NOP,NOP,SACKOK */
		nw = 2;
	}
	if (ws != ND_COOKIE_WS_NONE) {
		__be32 wsopt = bpf_htonl(0x01030300 | ws_rcv);          /* NOP,WS */

		if (nw == 4)
			s.opt[4] = wsopt;
		else if (nw == 2)
			s.opt[2] = wsopt;
		else
			s.opt[1] = wsopt;
		nw++;
	}
	tcplen = sizeof(struct tcphdr) + nw * 4;
	((__u8 *)&s.th)[12] = (tcplen / 4) << 4;
	((__u8 *)&s.th)[13] = ND_TCP_SYNACK;

	if (v6) {
		struct ipv6hdr ip6;
		struct { __u32 s[4], d[4]; __be32 len; __u8 zero[3], nh; } ph;

		__builtin_memset(&ip6, 0, sizeof(ip6));
		((__u8 *)&ip6)[0] = 0x60;
		ip6.payload_len = bpf_htons(tcplen);
		ip6.nexthdr = IPPROTO_TCP;
		ip6.hop_limit = 64;
		__builtin_memcpy(&ip6.saddr, daddr, 16);
		__builtin_memcpy(&ip6.daddr, saddr, 16);

		__builtin_memset(&ph, 0, sizeof(ph));
		__builtin_memcpy(ph.s, daddr, 16);
		__builtin_memcpy(ph.d, saddr, 16);
		ph.len = bpf_htonl(tcplen);
		ph.nh = IPPROTO_TCP;
		sum = bpf_csum_diff(0, 0, (__be32 *)&ph, sizeof(ph), 0);
		s.th.check = csum_fold(bpf_csum_diff(0, 0, (__be32 *)&s, sizeof(s), sum));

		newlen = ND_L4_OFF6 + tcplen;
		delta = (int)newlen - (int)(data_end - data);
		if (delta && bpf_xdp_adjust_tail(ctx, delta))
			return -1;
		data = (void *)(long)ctx->data;
		data_end = (void *)(long)ctx->data_end;
		eth = data;
		w = (void *)((struct ipv6hdr *)(eth + 1) + 1);
		if (!ND_FITS(w, nw, data_end))
			return -1;
		*(struct ipv6hdr *)(eth + 1) = ip6;
	} else {
		struct iphdr ip4;
		struct { __be32 s, d; __u8 zero, proto; __be16 len; } ph;

		__builtin_memset(&ip4, 0, sizeof(ip4));
		((__u8 *)&ip4)[0] = 0x45;
		ip4.tot_len = bpf_htons(sizeof(struct iphdr) + tcplen);
		ip4.frag_off = bpf_htons(0x4000);  /* DF, id 0 */
		ip4.ttl = 64;
		ip4.protocol = IPPROTO_TCP;
		ip4.saddr = daddr[0];
		ip4.daddr = saddr[0];
		ip4.check = csum_fold(bpf_csum_diff(0, 0, (__be32 *)&ip4, sizeof(ip4), 0));

		ph.s = daddr[0];
		ph.d = saddr[0];
		ph.zero = 0;
		ph.proto = IPPROTO_TCP;
		ph.len = bpf_htons(tcplen);
		sum = bpf_csum_diff(0, 0, (__be32 *)&ph, sizeof(ph), 0);
		s.th.check = csum_fold(bpf_csum_diff(0, 0, (__be32 *)&s, sizeof(s), sum));

		newlen = ND_L4_OFF4 + tcplen;
		delta = (int)newlen - (int)(data_end - data);
		if (delta && bpf_xdp_adjust_tail(ctx, delta))
			return -1;
		data = (void *)(long)ctx->data;
		data_end = (void *)(long)ctx->data_end;
		eth = data;
		w = (void *)((struct iphdr *)(eth + 1) + 1);
		if (!ND_FITS(w, nw, data_end))
			return -1;
		*(struct iphdr *)(eth + 1) = ip4;
	}

	/* все проверки границ позади — пишем остальное */
	__builtin_memcpy(eth->h_dest, cli_mac, ETH_ALEN);
	__builtin_memcpy(eth->h_source, srv_mac, ETH_ALEN);
	__builtin_memcpy(w, &s, 24);   /* заголовок + MSS */
	if (nw > 1)
		w[6] = s.opt[1];
	if (nw > 2)
		w[7] = s.opt[2];
	if (nw > 3)
		w[8] = s.opt[3];
	if (nw > 4)
		w[9] = s.opt[4];
	return 0;
}

SEC("xdp")
int nd_guard_xdp(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct tcphdr *tcp = 0;
	struct guard_cfg *cfg;
	__u32 saddr[4] = {};
	__u32 zero = 0, port;
	__u8 *pflags, need, proto;
	void *l4;
	int v6;

	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;
	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *ip = (void *)(eth + 1);

		if ((void *)(ip + 1) > data_end)
			return XDP_PASS;
		if (ip->version != 4 || ip->ihl != 5 ||
		    (ip->frag_off & bpf_htons(ND_IP_MF | ND_IP_OFFSET)))
			return XDP_PASS;
		saddr[0] = ip->saddr;
		proto = ip->protocol;
		l4 = ip + 1;
		v6 = 0;
	} else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = (void *)(eth + 1);

		if ((void *)(ip6 + 1) > data_end)
			return XDP_PASS;
		__builtin_memcpy(saddr, &ip6->saddr, 16);
		proto = ip6->nexthdr;
		l4 = ip6 + 1;
		v6 = 1;
	} else {
		return XDP_PASS;  /* VLAN, ARP и прочее */
	}

	if (proto == IPPROTO_TCP) {
		tcp = l4;
		if ((void *)(tcp + 1) > data_end)
			return XDP_PASS;
		port = bpf_ntohs(tcp->dest);
		need = GUARD_P_TCP;
	} else if (proto == IPPROTO_UDP) {
		struct udphdr *udp = l4;

		if ((void *)(udp + 1) > data_end)
			return XDP_PASS;
		port = bpf_ntohs(udp->dest);
		need = GUARD_P_UDP;
	} else {
		return XDP_PASS;
	}

	pflags = bpf_map_lookup_elem(&guard_ports_map, &port);
	if (!pflags || !(*pflags & need))
		return XDP_PASS;  /* не наш порт — без статистики */

	if (lpm_hit(&allow4_map, &allow6_map, v6, saddr)) {
		guard_stat(ST_ALLOW);
		return XDP_PASS;
	}

	cfg = bpf_map_lookup_elem(&guard_cfg_map, &zero);
	if (!cfg) {
		guard_stat(ST_PASS);
		return XDP_PASS;
	}

	if (cfg->geo_on && (*pflags & GUARD_P_GEO) && !lpm_hit(&geo4_map, &geo6_map, v6, saddr)) {
		guard_stat(ST_GEO_DROP);
		return XDP_DROP;
	}

	if (tcp && tcp->syn && !(tcp->ack || tcp->rst || tcp->fin)) {
		__u64 now = bpf_ktime_get_ns();
		__u32 doff = tcp->doff;

		guard_stat(ST_SYN);
		if (doff >= 5 && syn_wants_cookie(cfg, now) &&
		    nd_synack(ctx, nd_syn_opts(ctx, v6, doff * 4 - sizeof(struct tcphdr)), now) == 0) {
			guard_stat(ST_COOKIE_SENT);
			return XDP_TX;
		}
	}

	guard_stat(ST_PASS);
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
