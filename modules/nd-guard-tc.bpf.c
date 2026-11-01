/*
 * nd-guard-tc.bpf.c — tc ingress-часть guard: ACK с SYN-cookie → bpf_sk_assign_tcp_reqsk.
 *
 * SYN-ACK с cookie отправил XDP (nd-guard-xdp.bpf.c), ядро этого SYN не видело. Здесь — ACK
 * клиента: cookie сошёлся → kfunc bpf_sk_assign_tcp_reqsk (ядро ≥ 6.9) вешает на skb
 * request sock с опциями из cookie, и ядро создаёт соединение в cookie_v4/v6_check —
 * без conntrack и без SYN (D1).
 *
 *   cookies off / auto вне атаки (+ 2 слота жизни cookie) → выход
 *   TCP на порт с GUARD_P_TCP, ACK без SYN/RST → bpf_skc_lookup_tcp → только LISTEN
 *   nd_cookie_check(ack_seq - 1, seq - 1) → ST_COOKIE_BAD | атрибуты → kfunc →
 *   ST_ASSIGN_ERR | ST_COOKIE_OK
 *
 * Всегда TC_ACT_UNSPEC (D11): фильтры clsact с большим pref (шейпер, 49200) тоже отработают.
 * Fail-open (D9): любая ошибка — пакет уходит в ядро как есть; невалидный cookie не дропается
 * (ядро само ответит RST или примет собственный syncookie).
 * Карты — общие с XDP (nd-guard.h); при загрузке переиспользуются по pin'ам:
 *   bpftool prog loadall nd-guard-tc.bpf.o PROGS type classifier map name guard_cfg_map pinned … .
 * kfunc объявлен __weak (R5): на ядре без него объект грузится, вызов вырезает верификатор.
 * Порядок байт cookie (R3) — как в XDP: адреса/порты как в пакете, ISN/cookie — host order.
 * Заголовки читаются bpf_skb_load_bytes в стек: нелинейный skb не мешает, а у верификатора
 * нет диапазонов пакетных указателей. Опции ACK разбирает глобальная функция (верифицируется
 * один раз, как разбор SYN в XDP).
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "nd-guard.h"
#include "nd-guard-cookie.h"

#ifndef __ksym
#define __ksym __attribute__((section(".ksyms")))
#endif
#ifndef __weak
#define __weak __attribute__((weak))
#endif
#ifndef bpf_ksym_exists
#define bpf_ksym_exists(sym) ({                                                          \
	_Static_assert(!__builtin_constant_p(!!sym), #sym " should be marked as __weak"); \
	!!sym;                                                                            \
})
#endif

/* Без vmlinux.h: поля — как в include/linux/bpf.h ядра.
 * struct sock — полный (пустой) тип, а не `struct sock;`: libbpf сверяет прототип kfunc с BTF
 * ядра, и FWD против STRUCT для него несовместимы — __weak kfunc молча не разрешился бы. */
struct sock {};
struct bpf_tcp_req_attrs {
	__u32 rcv_tsval, rcv_tsecr;
	__u16 mss;
	__u8 rcv_wscale, snd_wscale, ecn_ok, wscale_ok, sack_ok, tstamp_ok, usec_ts_ok, reserved[3];
};
_Static_assert(sizeof(struct bpf_tcp_req_attrs) == 20, "bpf_tcp_req_attrs: 20 байт, как в ядре");

extern int bpf_sk_assign_tcp_reqsk(struct __sk_buff *skb, struct sock *sk,
				   struct bpf_tcp_req_attrs *attrs, int attrs__sz) __ksym __weak;

#define ND_IP_MF      0x2000
#define ND_IP_OFFSET  0x1fff
#define ND_OPT_EOL    0
#define ND_OPT_NOP    1
#define ND_OPT_TS     8
#define ND_OPT_TS_LEN 10
#define ND_OPT_SPACE  40   /* максимум опций TCP */
#define ND_MAX_WS     14
/* cookie принимается в текущем и прошлом слоте: выданный в момент t живёт до t + 2·2^36 нс */
#define ND_COOKIE_TTL_NS (2ULL << 36)

/*
 * TS-опция ACK: смещение от начала опций (0..30) или -1, если её нет. Глобальная функция:
 * верифицируется один раз с непрозрачными аргументами. Каждая опция читается хелпером
 * (смещение — обычный скаляр, без доступа к стеку/пакету по переменному смещению);
 * off ≤ optlen ≤ 40, поэтому состояния итераций сходятся. Битая опция — разбор
 * прекращается, как в tcp_parse_options.
 */
__noinline int nd_ack_ts(struct __sk_buff *skb, __u64 optoff, __u64 optlen)
{
	__u64 off = 0, next;   /* u64: на ядрах < 5.16 spill u32 теряет границы */
	__u8 kl[2];
	int n;

	if (optlen > ND_OPT_SPACE)
		return -1;
	for (n = 0; n < ND_OPT_SPACE; n++) {
		if (off >= optlen)
			break;
		if (bpf_skb_load_bytes(skb, optoff + off, kl, 1) || kl[0] == ND_OPT_EOL)
			break;
		if (kl[0] == ND_OPT_NOP) {
			off++;
			continue;
		}
		if (off + 2 > optlen || bpf_skb_load_bytes(skb, optoff + off, kl, 2))
			break;
		next = off + kl[1];
		if (kl[1] < 2 || next > optlen)
			break;
		if (kl[0] == ND_OPT_TS && kl[1] == ND_OPT_TS_LEN)
			return off;
		off = next;
	}
	return -1;
}

SEC("tc")
int nd_guard_tc(struct __sk_buff *skb)
{
	struct bpf_tcp_req_attrs attrs;
	struct bpf_sock_tuple tuple;
	struct nd_cookie_opts opts;
	struct guard_cfg *cfg;
	struct bpf_sock *skc;
	struct sock *sk;
	struct tcphdr tcp;
	__u32 saddr[4] = {}, daddr[4] = {};
	__u32 zero = 0, port, tlen, l4off;
	__u8 *pflags;
	__u64 now;
	int v6, ts, err;

	cfg = bpf_map_lookup_elem(&guard_cfg_map, &zero);
	if (!cfg)
		return TC_ACT_UNSPEC;
	now = bpf_ktime_get_ns();
	if (cfg->cookie_mode == COOKIE_AUTO) {
		struct guard_state *st = bpf_map_lookup_elem(&guard_state_map, &zero);

		/* XDP выдаёт cookie до attack_until; позже 2 слотов после него они протухли */
		if (!st || now > st->attack_until_ns + ND_COOKIE_TTL_NS)
			return TC_ACT_UNSPEC;
	} else if (cfg->cookie_mode != COOKIE_ALWAYS) {
		return TC_ACT_UNSPEC;   /* off */
	}

	/* как в XDP: L2 — Ethernet (на tc ingress данные начинаются с MAC-заголовка) */
	if (skb->protocol == bpf_htons(ETH_P_IP)) {
		struct iphdr ip;

		if (bpf_skb_load_bytes(skb, ETH_HLEN, &ip, sizeof(ip)) ||
		    ip.version != 4 || ip.ihl != 5 || ip.protocol != IPPROTO_TCP ||
		    (ip.frag_off & bpf_htons(ND_IP_MF | ND_IP_OFFSET)))
			return TC_ACT_UNSPEC;
		saddr[0] = ip.saddr;
		daddr[0] = ip.daddr;
		l4off = ETH_HLEN + sizeof(ip);
		v6 = 0;
	} else if (skb->protocol == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr ip6;

		if (bpf_skb_load_bytes(skb, ETH_HLEN, &ip6, sizeof(ip6)) ||
		    ip6.nexthdr != IPPROTO_TCP)
			return TC_ACT_UNSPEC;
		__builtin_memcpy(saddr, &ip6.saddr, 16);
		__builtin_memcpy(daddr, &ip6.daddr, 16);
		l4off = ETH_HLEN + sizeof(ip6);
		v6 = 1;
	} else {
		return TC_ACT_UNSPEC;
	}

	if (bpf_skb_load_bytes(skb, l4off, &tcp, sizeof(tcp)) ||
	    !tcp.ack || tcp.syn || tcp.rst || tcp.doff < 5)
		return TC_ACT_UNSPEC;
	port = bpf_ntohs(tcp.dest);
	pflags = bpf_map_lookup_elem(&guard_ports_map, &port);
	if (!pflags || !(*pflags & GUARD_P_TCP))
		return TC_ACT_UNSPEC;

	/* сокет по 4-tuple: established/request/timewait — ядро разберётся само; нужен listener */
	__builtin_memset(&tuple, 0, sizeof(tuple));
	if (v6) {
		__builtin_memcpy(tuple.ipv6.saddr, saddr, 16);
		__builtin_memcpy(tuple.ipv6.daddr, daddr, 16);
		tuple.ipv6.sport = tcp.source;
		tuple.ipv6.dport = tcp.dest;
		tlen = sizeof(tuple.ipv6);
	} else {
		tuple.ipv4.saddr = saddr[0];
		tuple.ipv4.daddr = daddr[0];
		tuple.ipv4.sport = tcp.source;
		tuple.ipv4.dport = tcp.dest;
		tlen = sizeof(tuple.ipv4);
	}
	skc = bpf_skc_lookup_tcp(skb, &tuple, tlen, BPF_F_CURRENT_NETNS, 0);
	if (!skc)
		return TC_ACT_UNSPEC;
	if (skc->state != BPF_TCP_LISTEN)
		goto release;

	/* R3: те же входы, что у nd_cookie_make в XDP: клиент — источник ACK, мы — получатель */
	if (nd_cookie_check(cfg->key, saddr, daddr, tcp.source, tcp.dest,
			    bpf_ntohl(tcp.seq) - 1, bpf_ntohl(tcp.ack_seq) - 1,
			    ND_COOKIE_SLOT(now), v6, &opts)) {
		guard_stat(ST_COOKIE_BAD);
		goto release;
	}

	__builtin_memset(&attrs, 0, sizeof(attrs));   /* ecn_ok, usec_ts_ok, reserved — 0 */
	ts = nd_ack_ts(skb, l4off + sizeof(tcp), tcp.doff * 4 - sizeof(tcp));
	if (ts >= 0) {
		__be32 tsv[2];

		if (bpf_skb_load_bytes(skb, l4off + sizeof(tcp) + ts + 2, tsv, sizeof(tsv)) == 0) {
			attrs.tstamp_ok = 1;
			attrs.rcv_tsval = bpf_ntohl(tsv[0]);
			attrs.rcv_tsecr = bpf_ntohl(tsv[1]);
		}
	}
	attrs.mss = opts.mss;
	attrs.wscale_ok = opts.wscale_ok;
	attrs.snd_wscale = opts.snd_wscale;
	/* наш WS — тот, что XDP объявил в SYN-ACK (там же ограничен 14) */
	if (opts.wscale_ok)
		attrs.rcv_wscale = cfg->rcv_wscale > ND_MAX_WS ? ND_MAX_WS : cfg->rcv_wscale;
	attrs.sack_ok = opts.sack_ok;

	/* cookie верный, но назначить нечем (нет kfunc, не tcp_sock) — тоже ST_ASSIGN_ERR */
	sk = (struct sock *)bpf_skc_to_tcp_sock(skc);
	err = -1;
	if (sk && bpf_ksym_exists(bpf_sk_assign_tcp_reqsk))
		err = bpf_sk_assign_tcp_reqsk(skb, sk, &attrs, sizeof(attrs));
	guard_stat(err < 0 ? ST_ASSIGN_ERR : ST_COOKIE_OK);
release:
	bpf_sk_release(skc);
	return TC_ACT_UNSPEC;
}

char _license[] SEC("license") = "GPL";
