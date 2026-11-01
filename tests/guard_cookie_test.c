/* host-тест ядра SYN-cookie: cc -O2 -Wall -Werror -I modules tests/guard_cookie_test.c */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "nd-guard-cookie.h"

static void test_siphash_vector48(void)
{
	/* vectors_sip64[48] из github.com/veorq/SipHash/vectors.h */
	static const unsigned char exp[8] = {0x51, 0xa9, 0xcb, 0x9e, 0xcb, 0xa3, 0x12, 0xe6};
	unsigned char kb[16], mb[48];
	__u64 key[2], m[6], want = 0;
	int i, j;

	for (i = 0; i < 16; i++) kb[i] = (unsigned char)i;
	for (i = 0; i < 48; i++) mb[i] = (unsigned char)i;
	for (i = 0; i < 2; i++) {
		key[i] = 0;
		for (j = 7; j >= 0; j--) key[i] = key[i] << 8 | kb[i * 8 + j];
	}
	for (i = 0; i < 6; i++) {
		m[i] = 0;
		for (j = 7; j >= 0; j--) m[i] = m[i] << 8 | mb[i * 8 + j];
	}
	for (j = 7; j >= 0; j--) want = want << 8 | exp[j];
	assert(nd_siphash24(key, m) == want);
}

static const __u64 KEY[2] = {0x0123456789abcdefULL, 0xfedcba9876543210ULL};
static __u32 S4[4] = {0x0100a8c0, 0, 0, 0}, D4[4] = {0x0200a8c0, 0, 0, 0};
static __u32 S6[4], D6[4];
#define SP 0x5000 /* сырые __be16, как в пакете */
#define DP 0xbb01
#define ISN 0xdeadbeefu
#define SLOT 1000u

static void roundtrip(const __u32 *s, const __u32 *d, int v6)
{
	struct nd_cookie_opts o;
	__u8 ob = nd_cookie_optbyte(7, 1, 7);
	__u32 c = nd_cookie_make(KEY, s, d, SP, DP, ISN, SLOT, ob);

	memset(&o, 0, sizeof(o));
	assert(nd_cookie_check(KEY, s, d, SP, DP, ISN, c, SLOT, v6, &o) == 0);
	assert(o.mss == (v6 ? 1440 : 1460));
	assert(o.snd_wscale == 7 && o.wscale_ok == 1 && o.sack_ok == 1);
}

static void test_roundtrip_v4(void) { roundtrip(S4, D4, 0); }

static void test_roundtrip_v6(void)
{
	/* fd00::1 / fd00::2, сырые сетевые байты в __u32 */
	unsigned char a[16] = {0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
	unsigned char b[16] = {0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
	memcpy(S6, a, 16);
	memcpy(D6, b, 16);
	roundtrip(S6, D6, 1);
}

static void test_slots(void)
{
	struct nd_cookie_opts o;
	__u32 c = nd_cookie_make(KEY, S4, D4, SP, DP, ISN, SLOT, nd_cookie_optbyte(7, 1, 7));

	assert(nd_cookie_check(KEY, S4, D4, SP, DP, ISN, c, SLOT + 1, 0, &o) == 0);
	assert(nd_cookie_check(KEY, S4, D4, SP, DP, ISN, c, SLOT + 2, 0, &o) == -1);
}

static void test_tamper(void)
{
	struct nd_cookie_opts o;
	__u32 c = nd_cookie_make(KEY, S4, D4, SP, DP, ISN, SLOT, nd_cookie_optbyte(7, 1, 7));
	int i;

	for (i = 0; i < 8; i++)
		assert(nd_cookie_check(KEY, S4, D4, SP, DP, ISN, c ^ (1u << i), SLOT, 0, &o) == -1);
	assert(nd_cookie_check(KEY, S4, D4, SP, DP, ISN + 1, c, SLOT, 0, &o) == -1);
	assert(nd_cookie_check(KEY, S4, D4, SP + 1, DP, ISN, c, SLOT, 0, &o) == -1);
}

static void test_ws_none(void)
{
	struct nd_cookie_opts o;
	__u32 c = nd_cookie_make(KEY, S4, D4, SP, DP, ISN, SLOT,
				 nd_cookie_optbyte(3, 0, ND_COOKIE_WS_NONE));

	assert(nd_cookie_check(KEY, S4, D4, SP, DP, ISN, c, SLOT, 0, &o) == 0);
	assert(o.wscale_ok == 0 && o.sack_ok == 0 && o.mss == 1360);
}

static void test_mss_idx(void)
{
	assert(nd_mss_idx(1452, 0) == 6);
	assert(nd_mss_idx(1400, 0) == 4);
	assert(nd_mss_idx(500, 0) == 0);
	assert(nd_mss_idx(1440, 1) == 7);
	assert(nd_mss_idx(1300, 1) == 1);
}

/* таблицы MSS упакованы в константы (без .rodata — clang 14): значения как в D4 */
static void test_mss_tab(void)
{
	static const __u16 v4[8] = {536, 1220, 1300, 1360, 1400, 1440, 1452, 1460};
	static const __u16 v6[8] = {1220, 1280, 1340, 1380, 1400, 1420, 1432, 1440};
	__u32 i;

	for (i = 0; i < 8; i++) {
		assert(nd_mss_tab(i, 0) == v4[i]);
		assert(nd_mss_tab(i, 1) == v6[i]);
		assert(nd_mss_tab(i + 8, 0) == v4[i]);   /* индекс по модулю 8 */
	}
}

int main(void)
{
	test_siphash_vector48();
	test_roundtrip_v4();
	test_roundtrip_v6();
	test_slots();
	test_tamper();
	test_ws_none();
	test_mss_idx();
	test_mss_tab();
	puts("COOKIE OK");
	return 0;
}
