// SPDX-License-Identifier: GPL-2.0
//
// rsi_policy_json.c (v2: POLY binary format + aggressive debug)
//
// This version adds debug prints at the points where failures typically occur:
//   - JSON tokenization/parse progress (key-level)
//   - staging context summary (counts + per-object summaries)
//   - index resolution (Self, ANY, CF owner)
//   - binary sizing + exact write offsets
//   - binary parse (round-trip) with bounds checks that print *where* it failed
//
// Keep pr_info() volume in mind; you can gate with DEBUG_VERBOSE below.

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#include <asm/page.h>
#include <linux/rmm_payload.h>
#include <linux/miscdevice.h>

static char *path = "/etc/policy.json";
module_param(path, charp, 0644);
MODULE_PARM_DESC(path, "Policy JSON file path");

static unsigned long rsi_fid = 0xC40002F0;
module_param(rsi_fid, ulong, 0644);
MODULE_PARM_DESC(rsi_fid, "RSI SMC function ID for rsi_parse_config");

/* -------------------- Debug controls -------------------- */
#define DEBUG_VERBOSE 1
#define DBG(fmt, ...) do { if (DEBUG_VERBOSE) pr_info("POLYDBG: " fmt, ##__VA_ARGS__); } while (0)
#define ERR(fmt, ...) pr_info("POLYERR: " fmt, ##__VA_ARGS__)

/* -------------------- Caps -------------------- */
#ifndef PARSER_MAX_VMS
#define PARSER_MAX_VMS  8
#endif
#ifndef PARSER_MAX_MEMS
#define PARSER_MAX_MEMS 8
#endif
#ifndef PARSER_MAX_MAPS
#define PARSER_MAX_MAPS 8
#endif
#ifndef PARSER_MAX_CFS
#define PARSER_MAX_CFS  8
#endif
#ifndef PARSER_MAX_CF_RANGE
#define PARSER_MAX_CF_RANGE 8
#endif

/* -------------------- New wire format (POLY) -------------------- */
#define PAYLOAD_MAGIC 0x504f4c59U /* 'POLY' */
#define BIN_PAGE_SIZE PAGE_SIZE
#define VM_IDX_ANY    0xFFFFu
#define JSON_MAX_SIZE (1ULL << 20)

/*
 * Raw cfg layout streamed by group attestation currently comes from
 * RMM's in-memory parsed_payload object (no PAYLOAD_MAGIC header).
 * This decoder matches that fixed layout so we can render JSON back.
 */
#define RAW_CFG_VMS          8U
#define RAW_CFG_MEMS         8U
#define RAW_CFG_MAPS         8U
#define RAW_CFG_CFS          8U
#define RAW_CFG_CF_RANGE     8U
#define RAW_CFG_VM_SIZE      12U
#define RAW_CFG_MAP_SIZE     24U
#define RAW_CFG_MEM_SIZE     (24U + RAW_CFG_MAPS * RAW_CFG_MAP_SIZE)
#define RAW_CFG_CF_SIZE      (12U + RAW_CFG_CF_RANGE * 4U)
#define RAW_CFG_SIZE         (8U + RAW_CFG_VMS * RAW_CFG_VM_SIZE + \
			      RAW_CFG_MEMS * RAW_CFG_MEM_SIZE + \
			      RAW_CFG_CFS * RAW_CFG_CF_SIZE)

enum { PROT_R = 1, PROT_W = 2, PROT_RW = 3 };
enum { MEM_PROTECTED = 1, MEM_UNPROTECTED = 2, MEM_OTHER = 3 };
enum { CF_TYPE_CALL = 1, CF_TYPE_EXCEPTION = 2, CF_TYPE_OTHER = 3 };
enum { CF_POLICY_BLOCK = 1, CF_POLICY_ALLOW = 2, CF_POLICY_OTHER = 3 };

/* -------------------- Small helpers -------------------- */

static inline size_t k_strscpy(char *dst, const char *src, size_t dstsz)
{
	size_t n;
	if (!dst || !dstsz) return 0;
	n = strnlen(src, dstsz - 1);
	memcpy(dst, src, n);
	dst[n] = '\0';
	return n;
}

static void copy_name4(char out[4], const char *src)
{
	size_t n = strlen(src);
	memset(out, 0, 4);
	if (n > 4) n = 4;
	memcpy(out, src, n);
}

static void name4_to_cstr(const char name4[4], char out[5])
{
	int i, p = 0;
	for (i = 0; i < 4; i++) {
		if (!name4[i]) break;
		out[p++] = name4[i];
	}
	out[p] = '\0';
}

static int looks_vm(const char *k)  { return (k[0] == 'V' && k[1] == 'M'); }
static int looks_mem(const char *k) { return (k[0] == 'M' && k[1] == 'e' && k[2] == 'm'); }
static int looks_cf(const char *k)  { return (k[0] == 'C' && k[1] == 'F'); }

/* -------------------- Minimal JSON tokenizer -------------------- */

struct js { const char *s; size_t n; size_t i; };

static void js_skip(struct js *j)
{
	while (j->i < j->n) {
		char c = j->s[j->i];
		if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
			j->i++;
		else
			break;
	}
}

static int js_expect(struct js *j, char ch)
{
	js_skip(j);
	if (j->i >= j->n || j->s[j->i] != ch) {
		ERR("js_expect('%c') failed at i=%zu (got '%c')\n",
		    ch, j->i, (j->i < j->n ? j->s[j->i] : '?'));
		return -EINVAL;
	}
	j->i++;
	return 0;
}

static int js_maybe(struct js *j, char ch)
{
	js_skip(j);
	if (j->i < j->n && j->s[j->i] == ch) { j->i++; return 1; }
	return 0;
}

static int js_peek(struct js *j, char *out)
{
	js_skip(j);
	if (j->i >= j->n) return -EINVAL;
	*out = j->s[j->i];
	return 0;
}

static int js_string(struct js *j, char *out, size_t outsz)
{
	size_t p = 0;

	if (js_expect(j, '"'))
		return -EINVAL;

	while (j->i < j->n) {
		char c = j->s[j->i++];
		if (c == '"')
			break;
		if (c == '\\') {
			if (j->i >= j->n) return -EINVAL;
			c = j->s[j->i++];
			if (c != '"' && c != '\\') return -EINVAL;
		}
		if (p + 1 < outsz)
			out[p++] = c;
	}
	if (outsz)
		out[p < outsz ? p : (outsz - 1)] = '\0';
	return 0;
}

static int js_bool(struct js *j, int *val)
{
	js_skip(j);
	if (j->i + 3 < j->n && !strncmp(&j->s[j->i], "true", 4)) {
		*val = 1; j->i += 4; return 0;
	}
	if (j->i + 4 < j->n && !strncmp(&j->s[j->i], "false", 5)) {
		*val = 0; j->i += 5; return 0;
	}
	ERR("js_bool failed at i=%zu\n", j->i);
	return -EINVAL;
}

static int js_number_u64(struct js *j, unsigned long long *out)
{
	unsigned long long x = 0;
	int base = 10, have = 0;

	js_skip(j);
	if (j->i >= j->n) return -EINVAL;

	if (j->s[j->i] == '0' && j->i + 1 < j->n &&
	    (j->s[j->i + 1] == 'x' || j->s[j->i + 1] == 'X')) {
		base = 16; j->i += 2;
	}

	if (base == 16) {
		while (j->i < j->n) {
			char c = j->s[j->i];
			int v = -1;
			if (c >= '0' && c <= '9') v = c - '0';
			else if (c >= 'a' && c <= 'f') v = 10 + (c - 'a');
			else if (c >= 'A' && c <= 'F') v = 10 + (c - 'A');
			else break;
			x = (x << 4) + (unsigned long long)v;
			have = 1; j->i++;
		}
	} else {
		while (j->i < j->n) {
			char c = j->s[j->i];
			if (c < '0' || c > '9') break;
			x = x * 10ull + (unsigned long long)(c - '0');
			have = 1; j->i++;
		}
	}

	if (!have) {
		ERR("js_number_u64 no digits at i=%zu\n", j->i);
		return -EINVAL;
	}
	*out = x;
	return 0;
}

static int js_number_u32(struct js *j, unsigned int *out)
{
	unsigned long long v;
	if (js_number_u64(j, &v)) return -EINVAL;
	*out = (unsigned int)v;
	return 0;
}

/* -------------------- String->enum helpers -------------------- */

static unsigned short prot_from_str(const char *s)
{
	int r = (strchr(s, 'R') != NULL);
	int w = (strchr(s, 'W') != NULL);
	if (r && w) return PROT_RW;
	if (r)      return PROT_R;
	if (w)      return PROT_W;
	return 0;
}

static unsigned short mem_type_from_str(const char *s)
{
	if (!strcmp(s, "PROTECTED"))   return MEM_PROTECTED;
	if (!strcmp(s, "UNPROTECTED")) return MEM_UNPROTECTED;
	if (!strcmp(s, "OTHER"))       return MEM_OTHER;
	return 0;
}

static unsigned short cf_type_from_str(const char *s)
{
	if (!strcmp(s, "CALL"))       return CF_TYPE_CALL;
	if (!strcmp(s, "EXCEPTION")) return CF_TYPE_EXCEPTION;
	if (!strcmp(s, "OTHER"))      return CF_TYPE_OTHER;
	return 0;
}

static unsigned short cf_policy_from_str(const char *s)
{
	if (!strcmp(s, "BLOCK")) return CF_POLICY_BLOCK;
	if (!strcmp(s, "ALLOW")) return CF_POLICY_ALLOW;
	if (!strcmp(s, "OTHER")) return CF_POLICY_OTHER;
	return 0;
}

static const char *prot_to_str(unsigned short prot)
{
	switch (prot) {
	case PROT_RW: return "RW";
	case PROT_R:  return "R";
	case PROT_W:  return "W";
	default:      return "";
	}
}

static const char *mem_type_to_str(unsigned short t)
{
	switch (t) {
	case MEM_PROTECTED:   return "PROTECTED";
	case MEM_UNPROTECTED: return "UNPROTECTED";
	case MEM_OTHER:       return "OTHER";
	default:              return "OTHER";
	}
}

static const char *cf_type_to_str(unsigned short t)
{
	switch (t) {
	case CF_TYPE_CALL:       return "CALL";
	case CF_TYPE_EXCEPTION: return "EXCEPTION";
	case CF_TYPE_OTHER:      return "OTHER";
	default:                 return "OTHER";
	}
}

static const char *cf_policy_to_str(unsigned short p)
{
	switch (p) {
	case CF_POLICY_BLOCK: return "BLOCK";
	case CF_POLICY_ALLOW: return "ALLOW";
	case CF_POLICY_OTHER: return "OTHER";
	default:              return "OTHER";
	}
}

/* Parse array of u32 numbers: [ 0x10, 32, ... ] */
static int parse_u32_array(struct js *j, unsigned short *out_len, unsigned int *out, unsigned short out_cap)
{
	unsigned short n = 0;

	if (js_expect(j, '['))
		return -EINVAL;

	while (1) {
		char c;
		js_skip(j);
		if (js_peek(j, &c)) return -EINVAL;

		if (c == ']') { j->i++; break; }

		if (n >= out_cap) {
			ERR("range array too long (cap=%u) at i=%zu\n", out_cap, j->i);
			return -EINVAL;
		}

		{
			unsigned int v;
			if (js_number_u32(j, &v)) return -EINVAL;
			out[n++] = v;
		}

		if (!js_maybe(j, ',')) {
			if (js_expect(j, ']')) return -EINVAL;
			break;
		}
	}

	*out_len = n;
	return 0;
}

/* -------------------- Staging structs -------------------- */

struct st_vm {
	char name4[4];
	unsigned int hash;
	unsigned char is_gateway;
	unsigned char strict;
};

struct st_map {
	unsigned short vm_index;
	unsigned short prot;
	unsigned long long gpa;
	int any_count;
	char vm_name_tmp[8];
};

struct st_mem {
	char name4[4];
	unsigned long long size;
	unsigned short type;
	unsigned short num_maps;
	struct st_map maps[PARSER_MAX_MAPS];
};

struct st_cf {
	char name4[4];
	unsigned short owner_vm_index;
	char owner_name_tmp[8];
	unsigned short type;
	unsigned short policy;
	unsigned short range_len;
	unsigned int range[PARSER_MAX_CF_RANGE];
};

struct st_ctx {
	char self_name4[4];
	unsigned short self_vm_index;
	struct st_vm  vms[PARSER_MAX_VMS];
	struct st_mem mems[PARSER_MAX_MEMS];
	struct st_cf  cfs[PARSER_MAX_CFS];
	unsigned short num_vms, num_mems, num_cfs;
};

/* -------------------- Parsers -------------------- */

static int parse_vm_obj(struct js *j, struct st_vm *vm)
{
	char vn[5]; name4_to_cstr(vm->name4, vn);
	DBG("parse_vm_obj %s at i=%zu\n", vn, j->i);

	if (js_expect(j, '{')) return -EINVAL;

	while (1) {
		if (js_maybe(j, '}')) break;

		{
			char key[32];
			if (js_string(j, key, sizeof(key))) return -EINVAL;
			if (js_expect(j, ':')) return -EINVAL;

			if (!strcmp(key, "hash")) {
				unsigned int v;
				if (js_number_u32(j, &v)) return -EINVAL;
				vm->hash = v;
				DBG("  VM %s hash=0x%x\n", vn, vm->hash);
			} else if (!strcmp(key, "is-gateway")) {
				int b;
				if (js_bool(j, &b)) return -EINVAL;
				vm->is_gateway = (unsigned char)b;
				DBG("  VM %s is-gateway=%u\n", vn, (unsigned)vm->is_gateway);
			} else if (!strcmp(key, "strict")) {
				int b;
				if (js_bool(j, &b)) return -EINVAL;
				vm->strict = (unsigned char)b;
				DBG("  VM %s strict=%u\n", vn, (unsigned)vm->strict);
			} else {
				ERR("unknown VM key '%s'\n", key);
				return -EINVAL;
			}
		}

		if (!js_maybe(j, ',')) {
			if (js_expect(j, '}')) return -EINVAL;
			break;
		}
	}
	return 0;
}

static int parse_map_obj(struct js *j, struct st_map *m)
{
	DBG("parse_map_obj vm='%s' at i=%zu\n", m->vm_name_tmp, j->i);

	if (js_expect(j, '{')) return -EINVAL;

	while (1) {
		if (js_maybe(j, '}')) break;

		{
			char key[32];
			if (js_string(j, key, sizeof(key))) return -EINVAL;
			if (js_expect(j, ':')) return -EINVAL;

			if (!strcmp(key, "gpa")) {
				unsigned long long v;
				if (js_number_u64(j, &v)) return -EINVAL;
				m->gpa = v;
				DBG("  map gpa=0x%llx\n", m->gpa);
			} else if (!strcmp(key, "prot")) {
				char prot[8];
				if (js_string(j, prot, sizeof(prot))) return -EINVAL;
				m->prot = prot_from_str(prot);
				if (!m->prot) {
					ERR("bad prot '%s'\n", prot);
					return -EINVAL;
				}
				DBG("  map prot=%s(%u)\n", prot, (unsigned)m->prot);
			} else if (!strcmp(key, "any-count")) {
				unsigned int v;
				if (js_number_u32(j, &v)) return -EINVAL;
				m->any_count = (int)v;
				DBG("  map any-count=%d\n", m->any_count);
			} else {
				ERR("unknown MAP key '%s'\n", key);
				return -EINVAL;
			}
		}

		if (!js_maybe(j, ',')) {
			if (js_expect(j, '}')) return -EINVAL;
			break;
		}
	}

	return 0;
}

static int parse_mappings_dict(struct js *j, struct st_mem *mem)
{
	char mn[5]; name4_to_cstr(mem->name4, mn);
	DBG("parse_mappings_dict Mem %s at i=%zu\n", mn, j->i);

	if (js_expect(j, '{')) return -EINVAL;

	while (1) {
		char c;
		if (js_peek(j, &c)) return -EINVAL;
		if (c == '}') { j->i++; break; }

		{
			char vmname[8];
			if (js_string(j, vmname, sizeof(vmname))) return -EINVAL;
			if (js_expect(j, ':')) return -EINVAL;

			if (mem->num_maps >= PARSER_MAX_MAPS) {
				ERR("Mem %s too many mappings (cap=%u)\n", mn, PARSER_MAX_MAPS);
				return -EINVAL;
			}

			{
				struct st_map *m = &mem->maps[mem->num_maps];
				memset(m, 0, sizeof(*m));
				k_strscpy(m->vm_name_tmp, vmname, sizeof(m->vm_name_tmp));
				if (parse_map_obj(j, m)) return -EINVAL;
				mem->num_maps++;
				DBG("  added mapping[%u] vm='%s'\n", (unsigned)(mem->num_maps - 1), vmname);
			}
		}

		if (!js_maybe(j, ',')) {
			if (js_expect(j, '}')) return -EINVAL;
			break;
		}
	}

	return 0;
}

static int parse_mem_obj(struct js *j, struct st_mem *mem)
{
	char mn[5]; name4_to_cstr(mem->name4, mn);
	DBG("parse_mem_obj %s at i=%zu\n", mn, j->i);

	if (js_expect(j, '{')) return -EINVAL;

	while (1) {
		if (js_maybe(j, '}')) break;

		{
			char key[32];
			if (js_string(j, key, sizeof(key))) return -EINVAL;
			if (js_expect(j, ':')) return -EINVAL;

			if (!strcmp(key, "size")) {
				unsigned long long v;
				if (js_number_u64(j, &v)) return -EINVAL;
				mem->size = v;
				DBG("  Mem %s size=0x%llx\n", mn, mem->size);
			} else if (!strcmp(key, "type")) {
				char ts[32];
				unsigned short tv;
				if (js_string(j, ts, sizeof(ts))) return -EINVAL;
				tv = mem_type_from_str(ts);
				if (!tv) {
					ERR("Mem %s bad type '%s'\n", mn, ts);
					return -EINVAL;
				}
				mem->type = tv;
				DBG("  Mem %s type=%s(%u)\n", mn, ts, (unsigned)mem->type);
			} else if (!strcmp(key, "mappings")) {
				if (parse_mappings_dict(j, mem)) return -EINVAL;
				DBG("  Mem %s num_maps=%u\n", mn, (unsigned)mem->num_maps);
			} else {
				ERR("unknown MEM key '%s'\n", key);
				return -EINVAL;
			}
		}

		if (!js_maybe(j, ',')) {
			if (js_expect(j, '}')) return -EINVAL;
			break;
		}
	}

	return 0;
}

static int parse_cf_obj(struct js *j, struct st_cf *cf)
{
	char cn[5]; name4_to_cstr(cf->name4, cn);
	DBG("parse_cf_obj %s at i=%zu\n", cn, j->i);

	if (js_expect(j, '{')) return -EINVAL;

	while (1) {
		if (js_maybe(j, '}')) break;

		{
			char key[32];
			if (js_string(j, key, sizeof(key))) return -EINVAL;
			if (js_expect(j, ':')) return -EINVAL;

			if (!strcmp(key, "owner")) {
				char owner[16];
				if (js_string(j, owner, sizeof(owner))) return -EINVAL;
				k_strscpy(cf->owner_name_tmp, owner, sizeof(cf->owner_name_tmp));
				DBG("  CF %s owner='%s'\n", cn, cf->owner_name_tmp);
			} else if (!strcmp(key, "type")) {
				char ts[16];
				unsigned short tv;
				if (js_string(j, ts, sizeof(ts))) return -EINVAL;
				tv = cf_type_from_str(ts);
				if (!tv) {
					ERR("CF %s bad type '%s'\n", cn, ts);
					return -EINVAL;
				}
				cf->type = tv;
				DBG("  CF %s type=%s(%u)\n", cn, ts, (unsigned)cf->type);
			} else if (!strcmp(key, "policy")) {
				char ps[16];
				unsigned short pv;
				if (js_string(j, ps, sizeof(ps))) return -EINVAL;
				pv = cf_policy_from_str(ps);
				if (!pv) {
					ERR("CF %s bad policy '%s'\n", cn, ps);
					return -EINVAL;
				}
				cf->policy = pv;
				DBG("  CF %s policy=%s(%u)\n", cn, ps, (unsigned)cf->policy);
			} else if (!strcmp(key, "range")) {
				unsigned short rl;
				if (parse_u32_array(j, &rl, cf->range, PARSER_MAX_CF_RANGE)) return -EINVAL;
				cf->range_len = rl;
				DBG("  CF %s range_len=%u\n", cn, (unsigned)cf->range_len);
			} else {
				ERR("unknown CF key '%s'\n", key);
				return -EINVAL;
			}
		}

		if (!js_maybe(j, ',')) {
			if (js_expect(j, '}')) return -EINVAL;
			break;
		}
	}

	return 0;
}

static int parse_root(const char *json, size_t len, struct st_ctx *ctx)
{
	struct js j;
	j.s = json; j.n = len; j.i = 0;

	DBG("parse_root: len=%zu\n", len);

	if (js_expect(&j, '{')) return -EINVAL;

	while (1) {
		if (js_maybe(&j, '}')) break;

		{
			char key[64];
			if (js_string(&j, key, sizeof(key))) return -EINVAL;
			if (js_expect(&j, ':')) return -EINVAL;

			DBG("root key='%s' at i=%zu\n", key, j.i);

			if (!strcmp(key, "Self")) {
				char sname[32];
				if (js_string(&j, sname, sizeof(sname))) return -EINVAL;
				copy_name4(ctx->self_name4, sname);
				{
					char sn[5]; name4_to_cstr(ctx->self_name4, sn);
					DBG("Self='%s'\n", sn);
				}
			} else if (looks_vm(key)) {
				if (ctx->num_vms >= PARSER_MAX_VMS) return -ENOMEM;
				{
					struct st_vm *vm = &ctx->vms[ctx->num_vms];
					memset(vm, 0, sizeof(*vm));
					copy_name4(vm->name4, key);
					if (parse_vm_obj(&j, vm)) return -EINVAL;
					DBG("Added VM[%u]\n", (unsigned)ctx->num_vms);
					ctx->num_vms++;
				}
			} else if (looks_mem(key)) {
				if (ctx->num_mems >= PARSER_MAX_MEMS) return -ENOMEM;
				{
					struct st_mem *mem = &ctx->mems[ctx->num_mems];
					memset(mem, 0, sizeof(*mem));
					copy_name4(mem->name4, key);
					if (parse_mem_obj(&j, mem)) return -EINVAL;
					DBG("Added Mem[%u]\n", (unsigned)ctx->num_mems);
					ctx->num_mems++;
				}
			} else if (looks_cf(key)) {
				if (ctx->num_cfs >= PARSER_MAX_CFS) return -ENOMEM;
				{
					struct st_cf *cf = &ctx->cfs[ctx->num_cfs];
					memset(cf, 0, sizeof(*cf));
					copy_name4(cf->name4, key);
					if (parse_cf_obj(&j, cf)) return -EINVAL;
					DBG("Added CF[%u]\n", (unsigned)ctx->num_cfs);
					ctx->num_cfs++;
				}
			} else {
				ERR("unknown root key '%s'\n", key);
				return -EINVAL;
			}
		}

		if (!js_maybe(&j, ',')) {
			if (js_expect(&j, '}')) return -EINVAL;
			break;
		}
	}

	DBG("parse_root done: vms=%u mems=%u cfs=%u\n",
	    (unsigned)ctx->num_vms, (unsigned)ctx->num_mems, (unsigned)ctx->num_cfs);
	return 0;
}

/* -------------------- Resolve indices -------------------- */

static int find_vm_index(const struct st_ctx *ctx, const char name4[4], unsigned short *idx_out)
{
	unsigned short i;
	for (i = 0; i < ctx->num_vms; i++) {
		if (!memcmp(ctx->vms[i].name4, name4, 4)) { *idx_out = i; return 0; }
	}
	return -ENOENT;
}

static int find_vm_index_by_cstr(const struct st_ctx *ctx, const char *name, unsigned short *idx_out)
{
	char n4[4];
	copy_name4(n4, name);
	return find_vm_index(ctx, n4, idx_out);
}

static void dump_ctx_summary(const struct st_ctx *ctx)
{
	unsigned short i, mi;
	char sn[5];

	name4_to_cstr(ctx->self_name4, sn);
	DBG("CTX: Self='%s' vms=%u mems=%u cfs=%u\n",
	    sn, (unsigned)ctx->num_vms, (unsigned)ctx->num_mems, (unsigned)ctx->num_cfs);

	for (i = 0; i < ctx->num_vms; i++) {
		char vn[5]; name4_to_cstr(ctx->vms[i].name4, vn);
		DBG("  VM[%u] %s hash=0x%x gw=%u strict=%u\n",
		    (unsigned)i, vn, ctx->vms[i].hash, (unsigned)ctx->vms[i].is_gateway, (unsigned)ctx->vms[i].strict);
	}

	for (i = 0; i < ctx->num_mems; i++) {
		char mn[5]; name4_to_cstr(ctx->mems[i].name4, mn);
		DBG("  Mem[%u] %s size=0x%llx type=%u maps=%u\n",
		    (unsigned)i, mn, ctx->mems[i].size, (unsigned)ctx->mems[i].type, (unsigned)ctx->mems[i].num_maps);
		for (mi = 0; mi < ctx->mems[i].num_maps; mi++) {
			DBG("    map[%u] vm='%s' gpa=0x%llx prot=%u any=%d\n",
			    (unsigned)mi,
			    ctx->mems[i].maps[mi].vm_name_tmp,
			    ctx->mems[i].maps[mi].gpa,
			    (unsigned)ctx->mems[i].maps[mi].prot,
			    ctx->mems[i].maps[mi].any_count);
		}
	}

	for (i = 0; i < ctx->num_cfs; i++) {
		char cn[5]; name4_to_cstr(ctx->cfs[i].name4, cn);
		DBG("  CF[%u] %s owner='%s' type=%u pol=%u range_len=%u\n",
		    (unsigned)i, cn, ctx->cfs[i].owner_name_tmp,
		    (unsigned)ctx->cfs[i].type, (unsigned)ctx->cfs[i].policy, (unsigned)ctx->cfs[i].range_len);
	}
}

static int resolve_indices(struct st_ctx *ctx)
{
	unsigned short i, mi;

	if (find_vm_index(ctx, ctx->self_name4, &ctx->self_vm_index)) {
		ERR("resolve: 'Self' VM not found.\n");
		return -EINVAL;
	}
	DBG("resolve: Self idx=%u\n", (unsigned)ctx->self_vm_index);

	/* Resolve MEM mappings */
	for (i = 0; i < ctx->num_mems; i++) {
		struct st_mem *mem = &ctx->mems[i];
		char mn[5]; name4_to_cstr(mem->name4, mn);

		for (mi = 0; mi < mem->num_maps; mi++) {
			struct st_map *m = &mem->maps[mi];

			if (!strcmp(m->vm_name_tmp, "ANY")) {
				m->vm_index = VM_IDX_ANY;
				DBG("resolve: Mem %s map[%u] -> ANY\n", mn, (unsigned)mi);
				if (m->any_count <= 0) {
					ERR("resolve: Mem %s map[%u] ANY missing/invalid any-count\n", mn, (unsigned)mi);
					return -EINVAL;
				}
				continue;
			}

			if (find_vm_index_by_cstr(ctx, m->vm_name_tmp, &m->vm_index)) {
				ERR("resolve: Mem %s map[%u] VM '%s' not found\n", mn, (unsigned)mi, m->vm_name_tmp);
				return -EINVAL;
			}
			m->any_count = 0;
			DBG("resolve: Mem %s map[%u] -> vm_index=%u\n", mn, (unsigned)mi, (unsigned)m->vm_index);
		}
	}

	/* Resolve CF owners */
	for (i = 0; i < ctx->num_cfs; i++) {
		struct st_cf *cf = &ctx->cfs[i];
		char cn[5]; name4_to_cstr(cf->name4, cn);

		if (cf->owner_name_tmp[0]) {
			if (find_vm_index_by_cstr(ctx, cf->owner_name_tmp, &cf->owner_vm_index)) {
				ERR("resolve: CF %s owner '%s' not found\n", cn, cf->owner_name_tmp);
				return -EINVAL;
			}
			DBG("resolve: CF %s owner_idx=%u\n", cn, (unsigned)cf->owner_vm_index);
		} else {
			cf->owner_vm_index = 0xFFFF;
			DBG("resolve: CF %s owner=<none>\n", cn);
		}
	}

	return 0;
}

/* -------------------- LE write/read -------------------- */

static void wr_u16(unsigned char *p, unsigned short v)
{
	p[0] = (unsigned char)(v & 0xFF);
	p[1] = (unsigned char)((v >> 8) & 0xFF);
}
static void wr_u32(unsigned char *p, unsigned int v)
{
	p[0] = (unsigned char)(v & 0xFF);
	p[1] = (unsigned char)((v >> 8) & 0xFF);
	p[2] = (unsigned char)((v >> 16) & 0xFF);
	p[3] = (unsigned char)((v >> 24) & 0xFF);
}
static void wr_u64(unsigned char *p, unsigned long long v)
{
	p[0] = (unsigned char)(v & 0xFF);
	p[1] = (unsigned char)((v >> 8) & 0xFF);
	p[2] = (unsigned char)((v >> 16) & 0xFF);
	p[3] = (unsigned char)((v >> 24) & 0xFF);
	p[4] = (unsigned char)((v >> 32) & 0xFF);
	p[5] = (unsigned char)((v >> 40) & 0xFF);
	p[6] = (unsigned char)((v >> 48) & 0xFF);
	p[7] = (unsigned char)((v >> 56) & 0xFF);
}
static void wr_i32(unsigned char *p, int v) { wr_u32(p, (unsigned int)v); }

static unsigned short rd_u16(const unsigned char *p)
{
	return (unsigned short)p[0] | ((unsigned short)p[1] << 8);
}
static unsigned int rd_u32(const unsigned char *p)
{
	return (unsigned int)p[0]
	     | ((unsigned int)p[1] << 8)
	     | ((unsigned int)p[2] << 16)
	     | ((unsigned int)p[3] << 24);
}
static unsigned long long rd_u64(const unsigned char *p)
{
	unsigned long long v = 0;
	v |= (unsigned long long)p[0];
	v |= (unsigned long long)p[1] << 8;
	v |= (unsigned long long)p[2] << 16;
	v |= (unsigned long long)p[3] << 24;
	v |= (unsigned long long)p[4] << 32;
	v |= (unsigned long long)p[5] << 40;
	v |= (unsigned long long)p[6] << 48;
	v |= (unsigned long long)p[7] << 56;
	return v;
}
static int rd_i32(const unsigned char *p) { return (int)rd_u32(p); }

/* -------------------- Size calc -------------------- */

static size_t size_of_payload(const struct st_ctx *c)
{
	size_t sz = 16;
	unsigned short i;

	sz += (size_t)c->num_vms * 12;

	for (i = 0; i < c->num_mems; i++) {
		const struct st_mem *m = &c->mems[i];
		sz += 16;
		sz += (size_t)m->num_maps * 20;
	}

	for (i = 0; i < c->num_cfs; i++) {
		const struct st_cf *cf = &c->cfs[i];
		sz += 12;
		sz += (size_t)cf->range_len * 4;
	}

	return sz;
}

/* -------------------- JSON -> binary with offset debug -------------------- */

static int json_to_rmm_payload(const char *json, size_t json_len,
			      unsigned char *out_buf, size_t out_cap,
			      size_t *out_len)
{
	struct st_ctx *ctx;
	unsigned char *p, *base;
	size_t need;
	unsigned short i, mi;

	if (!json || !out_buf || !out_len)
		return -EINVAL;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	DBG("json_to_rmm_payload: json_len=%zu out_cap=%zu\n", json_len, out_cap);

	if (parse_root(json, json_len, ctx)) {
		ERR("JSON parse failed.\n");
		kfree(ctx);
		return -EINVAL;
	}

	dump_ctx_summary(ctx);

	if (resolve_indices(ctx)) {
		ERR("resolve_indices failed.\n");
		kfree(ctx);
		return -EINVAL;
	}

	need = size_of_payload(ctx);
	*out_len = need;

	DBG("payload size need=%zu bytes\n", need);

	if (need > out_cap) {
		ERR("need=%zu > cap=%zu\n", need, out_cap);
		kfree(ctx);
		return -ENOSPC;
	}

	base = out_buf;
	p = out_buf;

	/* Header */
	DBG("write: HDR @off=%zu\n", (size_t)(p - base));
	wr_u32(p + 0, PAYLOAD_MAGIC);
	wr_u16(p + 4, 1);
	wr_u16(p + 6, ctx->self_vm_index);
	wr_u16(p + 8, ctx->num_vms);
	wr_u16(p + 10, ctx->num_mems);
	wr_u16(p + 12, ctx->num_cfs);
	wr_u16(p + 14, 0);
	p += 16;

	/* VMs */
	for (i = 0; i < ctx->num_vms; i++) {
		char vn[5]; name4_to_cstr(ctx->vms[i].name4, vn);
		DBG("write: VM[%u] %s @off=%zu\n", (unsigned)i, vn, (size_t)(p - base));
		memcpy(p + 0, ctx->vms[i].name4, 4);
		wr_u32(p + 4, ctx->vms[i].hash);
		p[8]  = ctx->vms[i].is_gateway ? 1 : 0;
		p[9]  = ctx->vms[i].strict ? 1 : 0;
		p[10] = 0; p[11] = 0;
		p += 12;
	}

	/* MEM blocks */
	for (i = 0; i < ctx->num_mems; i++) {
		struct st_mem *m = &ctx->mems[i];
		char mn[5]; name4_to_cstr(m->name4, mn);

		DBG("write: MEM[%u] %s @off=%zu size=0x%llx type=%u maps=%u\n",
		    (unsigned)i, mn, (size_t)(p - base), m->size, (unsigned)m->type, (unsigned)m->num_maps);

		memcpy(p + 0, m->name4, 4);
		wr_u64(p + 4, m->size);
		wr_u16(p + 12, m->type);
		wr_u16(p + 14, m->num_maps);
		p += 16;

		for (mi = 0; mi < m->num_maps; mi++) {
			struct st_map *mp = &m->maps[mi];
			DBG("  write: MAP[%u] vm_index=0x%04x prot=%u gpa=0x%llx any=%d @off=%zu\n",
			    (unsigned)mi, mp->vm_index, (unsigned)mp->prot, mp->gpa, mp->any_count, (size_t)(p - base));
			wr_u16(p + 0, mp->vm_index);
			wr_u16(p + 2, mp->prot);
			wr_u64(p + 4, mp->gpa);
			wr_i32(p + 12, mp->any_count);
			wr_u32(p + 16, 0);
			p += 20;
		}
	}

	/* CF blocks */
	for (i = 0; i < ctx->num_cfs; i++) {
		struct st_cf *cf = &ctx->cfs[i];
		unsigned short r;
		char cn[5]; name4_to_cstr(cf->name4, cn);

		DBG("write: CF[%u] %s @off=%zu owner=0x%04x type=%u pol=%u range_len=%u\n",
		    (unsigned)i, cn, (size_t)(p - base),
		    cf->owner_vm_index, (unsigned)cf->type, (unsigned)cf->policy, (unsigned)cf->range_len);

		memcpy(p + 0, cf->name4, 4);
		wr_u16(p + 4, cf->owner_vm_index);
		wr_u16(p + 6, cf->type);
		wr_u16(p + 8, cf->policy);
		wr_u16(p + 10, cf->range_len);
		p += 12;

		for (r = 0; r < cf->range_len; r++) {
			DBG("  write: CF_RANGE[%u]=0x%x @off=%zu\n",
			    (unsigned)r, cf->range[r], (size_t)(p - base));
			wr_u32(p, cf->range[r]);
			p += 4;
		}
	}

	DBG("write done: final_off=%zu (need=%zu)\n", (size_t)(p - base), need);

	kfree(ctx);
	return 0;
}

static int raw_cfg_to_json(const unsigned char *buf, size_t len,
			   char *out, size_t out_cap)
{
	const unsigned char *vm_base, *mem_base, *cf_base;
	unsigned short self_idx, num_vms, num_mems, num_cfs;
	size_t pos = 0;
	unsigned short i, mi;

	struct vm_tmp {
		char name4[4];
		unsigned int hash;
		unsigned char is_gateway;
		unsigned char strict;
	};
	struct mem_tmp {
		char name4[4];
		unsigned long long size;
		unsigned short type;
		unsigned short num_maps;
		const unsigned char *maps_base;
	};
	struct cf_tmp {
		char name4[4];
		unsigned short owner_vm_index;
		unsigned short type;
		unsigned short policy;
		unsigned short range_len;
		const unsigned char *range_base;
	};

	struct vm_tmp vms[RAW_CFG_VMS];
	struct mem_tmp mems[RAW_CFG_MEMS];
	struct cf_tmp cfs[RAW_CFG_CFS];

	if (!buf || !out || !out_cap)
		return -EINVAL;

	if (len < RAW_CFG_SIZE) {
		ERR("raw-cfg: len too small (%zu < %u)\n", len, RAW_CFG_SIZE);
		return -EINVAL;
	}

	self_idx = rd_u16(buf + 0);
	num_vms = rd_u16(buf + 2);
	num_mems = rd_u16(buf + 4);
	num_cfs = rd_u16(buf + 6);

	if (num_vms > RAW_CFG_VMS || num_mems > RAW_CFG_MEMS || num_cfs > RAW_CFG_CFS) {
		ERR("raw-cfg: counts exceed caps self=%u vms=%u mems=%u cfs=%u\n",
		    self_idx, num_vms, num_mems, num_cfs);
		return -EINVAL;
	}
	if (num_vms == 0 || self_idx >= num_vms) {
		ERR("raw-cfg: bad self index self=%u num_vms=%u\n", self_idx, num_vms);
		return -EINVAL;
	}

	vm_base = buf + 8;
	mem_base = vm_base + RAW_CFG_VMS * RAW_CFG_VM_SIZE;
	cf_base = mem_base + RAW_CFG_MEMS * RAW_CFG_MEM_SIZE;

	for (i = 0; i < num_vms; i++) {
		const unsigned char *p = vm_base + i * RAW_CFG_VM_SIZE;
		memcpy(vms[i].name4, p + 0, 4);
		vms[i].hash = rd_u32(p + 4);
		vms[i].is_gateway = p[8];
		vms[i].strict = p[9];
	}

	for (i = 0; i < num_mems; i++) {
		const unsigned char *p = mem_base + i * RAW_CFG_MEM_SIZE;
		memcpy(mems[i].name4, p + 0, 4);
		mems[i].size = rd_u64(p + 8);
		mems[i].type = rd_u16(p + 16);
		mems[i].num_maps = rd_u16(p + 18);
		if (mems[i].num_maps > RAW_CFG_MAPS)
			mems[i].num_maps = RAW_CFG_MAPS;
		mems[i].maps_base = p + 24;
	}

	for (i = 0; i < num_cfs; i++) {
		const unsigned char *p = cf_base + i * RAW_CFG_CF_SIZE;
		memcpy(cfs[i].name4, p + 0, 4);
		cfs[i].owner_vm_index = rd_u16(p + 4);
		cfs[i].type = rd_u16(p + 6);
		cfs[i].policy = rd_u16(p + 8);
		cfs[i].range_len = rd_u16(p + 10);
		if (cfs[i].range_len > RAW_CFG_CF_RANGE)
			cfs[i].range_len = RAW_CFG_CF_RANGE;
		cfs[i].range_base = p + 12;
	}

#define APPEND_RAW(fmt, ...) \
	do { \
		if (pos < out_cap) \
			pos += scnprintf(out + pos, out_cap - pos, fmt, ##__VA_ARGS__); \
	} while (0)

	APPEND_RAW("{\n");
	{
		char self_name[5];
		name4_to_cstr(vms[self_idx].name4, self_name);
		APPEND_RAW("  \"Self\": \"%s\"", self_name);
	}

	for (i = 0; i < num_vms; i++) {
		char vn[5];
		name4_to_cstr(vms[i].name4, vn);
		APPEND_RAW(",\n  \"%s\": { \"hash\": 0x%x, \"is-gateway\": %s, \"strict\": %s }",
			   vn, vms[i].hash,
			   vms[i].is_gateway ? "true" : "false",
			   vms[i].strict ? "true" : "false");
	}

	for (i = 0; i < num_mems; i++) {
		char mn[5];
		name4_to_cstr(mems[i].name4, mn);
		APPEND_RAW(",\n  \"%s\": {\n", mn);
		APPEND_RAW("    \"size\": 0x%llx,\n", mems[i].size);
		APPEND_RAW("    \"type\": \"%s\",\n", mem_type_to_str(mems[i].type));
		APPEND_RAW("    \"mappings\": {\n");

		for (mi = 0; mi < mems[i].num_maps; mi++) {
			const unsigned char *mp = mems[i].maps_base + (size_t)mi * RAW_CFG_MAP_SIZE;
			unsigned short vm_idx = rd_u16(mp + 0);
			unsigned short prot = rd_u16(mp + 2);
			unsigned long long gpa = rd_u64(mp + 8);
			int any_count = rd_i32(mp + 16);
			char map_vm_name[8];
			const char *prot_str = prot_to_str(prot);

			if (vm_idx == VM_IDX_ANY) {
				snprintf(map_vm_name, sizeof(map_vm_name), "ANY");
				APPEND_RAW("      \"%s\": { \"gpa\": 0x%llx, \"prot\": \"%s\", \"any-count\": %d }%s\n",
					   map_vm_name, gpa, prot_str, any_count,
					   (mi + 1 < mems[i].num_maps) ? "," : "");
			} else if (vm_idx < num_vms) {
				char tmp[5];
				name4_to_cstr(vms[vm_idx].name4, tmp);
				snprintf(map_vm_name, sizeof(map_vm_name), "%s", tmp);
				APPEND_RAW("      \"%s\": { \"gpa\": 0x%llx, \"prot\": \"%s\" }%s\n",
					   map_vm_name, gpa, prot_str,
					   (mi + 1 < mems[i].num_maps) ? "," : "");
			} else {
				snprintf(map_vm_name, sizeof(map_vm_name), "VM%u", vm_idx);
				APPEND_RAW("      \"%s\": { \"gpa\": 0x%llx, \"prot\": \"%s\" }%s\n",
					   map_vm_name, gpa, prot_str,
					   (mi + 1 < mems[i].num_maps) ? "," : "");
			}
		}

		APPEND_RAW("    }\n  }");
	}

	for (i = 0; i < num_cfs; i++) {
		char cn[5];
		char owner_name[5] = {0};
		size_t nlen;
		name4_to_cstr(cfs[i].name4, cn);
		nlen = strnlen(cn, sizeof(cn));

		/*
		 * Some raw streamed cfg blobs may report a stale/garbled CF slot.
		 * Skip empty-name CF records rather than emitting a bogus "" entry.
		 */
		if (nlen == 0)
			continue;

		if (cfs[i].owner_vm_index != 0xFFFF && cfs[i].owner_vm_index < num_vms)
			name4_to_cstr(vms[cfs[i].owner_vm_index].name4, owner_name);

		APPEND_RAW(",\n  \"%s\": {\n", cn);
		APPEND_RAW("    \"owner\": \"%s\",\n", owner_name);
		APPEND_RAW("    \"type\": \"%s\",\n", cf_type_to_str(cfs[i].type));
		APPEND_RAW("    \"policy\": \"%s\",\n", cf_policy_to_str(cfs[i].policy));
		APPEND_RAW("    \"range\": [");
		{
			unsigned short r;
			for (r = 0; r < cfs[i].range_len; r++) {
				unsigned int v = rd_u32(cfs[i].range_base + (size_t)r * 4);
				APPEND_RAW("%s0x%x", (r ? ", " : ""), v);
			}
		}
		APPEND_RAW("]\n  }");
	}

	APPEND_RAW("\n}\n");
	if (out_cap)
		out[min(pos, out_cap - 1)] = '\0';

#undef APPEND_RAW
	return 0;
}

/* -------------------- Binary -> JSON (round-trip) with failure location prints -------------------- */

int rmm_payload_to_json(const unsigned char *buf, size_t len, char *out, size_t out_cap)
{
	const unsigned char *p, *end;
	unsigned int magic;
	unsigned short version, self_idx, num_vms, num_mems, num_cfs;
	size_t pos = 0;
	unsigned short i, mi;

	struct vm_tmp { char name4[4]; unsigned int hash; unsigned char is_gateway; unsigned char strict; };
	struct mem_tmp { char name4[4]; unsigned long long size; unsigned short type; unsigned short num_maps; const unsigned char *maps_base; unsigned short nm_wire; };
	struct cf_tmp  { char name4[4]; unsigned short owner_vm_index; unsigned short type; unsigned short policy; unsigned short range_len; const unsigned char *range_base; unsigned short rl_wire; };

	struct vm_tmp vms[PARSER_MAX_VMS];
	struct mem_tmp mems[PARSER_MAX_MEMS];
	struct cf_tmp  cfs[PARSER_MAX_CFS];

	if (!buf || !out || !out_cap) return -EINVAL;
	if (len < 16) { ERR("rt: len<16\n"); return -EINVAL; }

	p = buf; end = buf + len;

	magic = rd_u32(p + 0);
	if (magic != PAYLOAD_MAGIC) {
		/*
		 * Group attestation currently streams raw in-memory cfg blobs
		 * (without PAYLOAD_MAGIC). Try that decoder before failing.
		 */
		int rc = raw_cfg_to_json(buf, len, out, out_cap);
		if (!rc)
			return 0;

		ERR("rt: bad magic=0x%x and raw-cfg decode failed (%d)\n", magic, rc);
		return -EINVAL;
	}

	version  = rd_u16(p + 4);
	self_idx = rd_u16(p + 6);
	num_vms  = rd_u16(p + 8);
	num_mems = rd_u16(p + 10);
	num_cfs  = rd_u16(p + 12);
	p += 16;

	DBG("rt: hdr ver=%u self=%u vms=%u mems=%u cfs=%u len=%zu\n",
	    (unsigned)version, (unsigned)self_idx, (unsigned)num_vms, (unsigned)num_mems, (unsigned)num_cfs, len);

	if (version != 1) { ERR("rt: bad version=%u\n", (unsigned)version); return -EINVAL; }
	if (num_vms > PARSER_MAX_VMS || num_mems > PARSER_MAX_MEMS || num_cfs > PARSER_MAX_CFS) {
		ERR("rt: counts exceed caps\n");
		return -EINVAL;
	}
	if (self_idx >= num_vms) { ERR("rt: self_idx out of range\n"); return -EINVAL; }

	/* VMs */
	for (i = 0; i < num_vms; i++) {
		if (p + 12 > end) { ERR("rt: VM[%u] overruns\n", (unsigned)i); return -EINVAL; }
		memcpy(vms[i].name4, p + 0, 4);
		vms[i].hash = rd_u32(p + 4);
		vms[i].is_gateway = p[8];
		vms[i].strict = p[9];
		p += 12;
	}

	/* MEMs */
	for (i = 0; i < num_mems; i++) {
		unsigned short nm;
		if (p + 16 > end) { ERR("rt: MEM[%u] hdr overruns\n", (unsigned)i); return -EINVAL; }
		memcpy(mems[i].name4, p + 0, 4);
		mems[i].size = rd_u64(p + 4);
		mems[i].type = rd_u16(p + 12);
		nm = rd_u16(p + 14);
		mems[i].nm_wire = nm;
		mems[i].num_maps = (nm > PARSER_MAX_MAPS) ? PARSER_MAX_MAPS : nm;
		p += 16;

		if (p + (size_t)nm * 20 > end) { ERR("rt: MEM[%u] maps overruns nm=%u\n", (unsigned)i, (unsigned)nm); return -EINVAL; }
		mems[i].maps_base = p;
		p += (size_t)nm * 20;
	}

	/* CFs */
	for (i = 0; i < num_cfs; i++) {
		unsigned short rl;
		if (p + 12 > end) { ERR("rt: CF[%u] hdr overruns\n", (unsigned)i); return -EINVAL; }
		memcpy(cfs[i].name4, p + 0, 4);
		cfs[i].owner_vm_index = rd_u16(p + 4);
		cfs[i].type = rd_u16(p + 6);
		cfs[i].policy = rd_u16(p + 8);
		rl = rd_u16(p + 10);
		cfs[i].rl_wire = rl;
		cfs[i].range_len = (rl > PARSER_MAX_CF_RANGE) ? PARSER_MAX_CF_RANGE : rl;
		p += 12;

		if (p + (size_t)rl * 4 > end) { ERR("rt: CF[%u] range overruns rl=%u\n", (unsigned)i, (unsigned)rl); return -EINVAL; }
		cfs[i].range_base = p;
		p += (size_t)rl * 4;
	}

#define APPEND(fmt, ...) \
	do { \
		if (pos < out_cap) \
			pos += scnprintf(out + pos, out_cap - pos, fmt, ##__VA_ARGS__); \
	} while (0)

	APPEND("{\n");
	{
		char self_name[5];
		name4_to_cstr(vms[self_idx].name4, self_name);
		APPEND("  \"Self\": \"%s\"", self_name);
	}

	for (i = 0; i < num_vms; i++) {
		char vn[5]; name4_to_cstr(vms[i].name4, vn);
		APPEND(",\n  \"%s\": { \"hash\": 0x%x, \"is-gateway\": %s, \"strict\": %s }",
		       vn, vms[i].hash,
		       vms[i].is_gateway ? "true" : "false",
		       vms[i].strict ? "true" : "false");
	}

	for (i = 0; i < num_mems; i++) {
		char mn[5]; name4_to_cstr(mems[i].name4, mn);
		APPEND(",\n  \"%s\": {\n", mn);
		APPEND("    \"size\": 0x%llx,\n", mems[i].size);
		APPEND("    \"type\": \"%s\",\n", mem_type_to_str(mems[i].type));
		APPEND("    \"mappings\": {\n");

		for (mi = 0; mi < mems[i].num_maps; mi++) {
			const unsigned char *mp = mems[i].maps_base + (size_t)mi * 20;
			unsigned short vm_idx = rd_u16(mp + 0);
			unsigned short prot = rd_u16(mp + 2);
			unsigned long long gpa = rd_u64(mp + 4);
			int any_count = rd_i32(mp + 12);

			char map_vm_name[8];
			const char *prot_str = prot_to_str(prot);

			if (vm_idx == VM_IDX_ANY) {
				snprintf(map_vm_name, sizeof(map_vm_name), "ANY");
				APPEND("      \"%s\": { \"gpa\": 0x%llx, \"prot\": \"%s\", \"any-count\": %d }%s\n",
				       map_vm_name, gpa, prot_str, any_count,
				       (mi + 1 < mems[i].num_maps) ? "," : "");
			} else if (vm_idx < num_vms) {
				char tmp[5];
				name4_to_cstr(vms[vm_idx].name4, tmp);
				snprintf(map_vm_name, sizeof(map_vm_name), "%s", tmp);
				APPEND("      \"%s\": { \"gpa\": 0x%llx, \"prot\": \"%s\" }%s\n",
				       map_vm_name, gpa, prot_str,
				       (mi + 1 < mems[i].num_maps) ? "," : "");
			} else {
				snprintf(map_vm_name, sizeof(map_vm_name), "VM%u", vm_idx);
				APPEND("      \"%s\": { \"gpa\": 0x%llx, \"prot\": \"%s\" }%s\n",
				       map_vm_name, gpa, prot_str,
				       (mi + 1 < mems[i].num_maps) ? "," : "");
			}
		}

		APPEND("    }\n  }");
	}

	for (i = 0; i < num_cfs; i++) {
		char cn[5]; name4_to_cstr(cfs[i].name4, cn);
		char owner_name[5] = {0};
		size_t nlen = strnlen(cn, sizeof(cn));

		/*
		 * Some raw streamed cfg blobs may report a stale/garbled CF slot.
		 * Skip empty-name CF records rather than emitting a bogus "" entry.
		 */
		if (nlen == 0)
			continue;

		if (cfs[i].owner_vm_index != 0xFFFF && cfs[i].owner_vm_index < num_vms)
			name4_to_cstr(vms[cfs[i].owner_vm_index].name4, owner_name);

		APPEND(",\n  \"%s\": {\n", cn);
		APPEND("    \"owner\": \"%s\",\n", owner_name);
		APPEND("    \"type\": \"%s\",\n", cf_type_to_str(cfs[i].type));
		APPEND("    \"policy\": \"%s\",\n", cf_policy_to_str(cfs[i].policy));

		APPEND("    \"range\": [");
		{
			unsigned short r;
			for (r = 0; r < cfs[i].range_len; r++) {
				unsigned int v = rd_u32(cfs[i].range_base + (size_t)r * 4);
				APPEND("%s0x%x", (r ? ", " : ""), v);
			}
		}
		APPEND("]\n  }");
	}

	APPEND("\n}\n");

	if (out_cap)
		out[min(pos, out_cap - 1)] = '\0';

#undef APPEND
	return 0;
}
EXPORT_SYMBOL_GPL(rmm_payload_to_json);

/* -------------------- /dev write handler -------------------- */

static ssize_t rsi_policy_write(struct file *file,
				const char __user *ubuf,
				size_t len, loff_t *ppos)
{
	char *json = NULL;
	u8 *page = NULL;
	size_t bin_len = 0;
	int rc;
	unsigned long ipa;
	unsigned long st;

	if (len == 0) return 0;
	if (len > JSON_MAX_SIZE) return -EINVAL;

	json = vmalloc(len + 1);
	if (!json) return -ENOMEM;

	if (copy_from_user(json, ubuf, len)) {
		vfree(json);
		return -EFAULT;
	}
	json[len] = '\0';

	DBG("write: got json len=%zu\n", len);

	page = (u8 *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
	if (!page) {
		vfree(json);
		return -ENOMEM;
	}

	rc = json_to_rmm_payload(json, len, page, BIN_PAGE_SIZE, &bin_len);
	vfree(json);

	if (rc) {
		ERR("failed to build POLY binary from json (rc=%d)\n", rc);
		free_page((unsigned long)page);
		return rc;
	}

	DBG("built POLY binary len=%zu\n", bin_len);

	/* Round-trip debug: parse our own produced buffer */
	{
		char *dbg_json = vmalloc(PAGE_SIZE);
		if (dbg_json) {
			int rc2 = rmm_payload_to_json(page, bin_len, dbg_json, PAGE_SIZE);
			if (!rc2)
				pr_info("POLYDBG: round-trip JSON:\n%s\n", dbg_json);
			else
				ERR("round-trip parse failed rc=%d\n", rc2);
			vfree(dbg_json);
		}
	}

	ipa = virt_to_phys(page);
	pr_info("rsi_policy_json: calling RSI fid=0x%lx ipa=0x%lx len=%zu\n",
		rsi_fid, ipa, bin_len);

	st = rsi_upload_policy(ipa);
	if (st) {
		ERR("RSI failed: 0x%lx\n", st);
		free_page((unsigned long)page);
		return -EFAULT;
	}

	return len;
}

static const struct file_operations rsi_policy_fops = {
	.owner = THIS_MODULE,
	.write = rsi_policy_write,
};

static struct miscdevice rsi_policy_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = "rsi_policy_json",
	.fops  = &rsi_policy_fops,
};

static int __init rsi_policy_json_init(void)
{
	int ret;

	ret = misc_register(&rsi_policy_dev);
	if (ret) {
		pr_info("rsi_policy_json: failed to register misc device (%d)\n", ret);
		return ret;
	}

	pr_info("rsi_policy_json: registered /dev/%s\n", rsi_policy_dev.name);
	return 0;
}

static void __exit rsi_policy_json_exit(void)
{
	misc_deregister(&rsi_policy_dev);
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("you");
MODULE_DESCRIPTION("Read fixed JSON and call RSI with IPA of POLY binary (debug)");
module_init(rsi_policy_json_init);
module_exit(rsi_policy_json_exit);
