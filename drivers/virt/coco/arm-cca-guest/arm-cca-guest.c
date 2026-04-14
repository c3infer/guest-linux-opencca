// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 ARM Ltd.
 */

#include <linux/arm-smccc.h>
#include <linux/cc_platform.h>
#include <linux/kernel.h>
#include <linux/mod_devicetable.h>
#include <linux/module.h>
#include <linux/smp.h>
#include <linux/tsm.h>
#include <linux/types.h>

#include <asm/rsi.h>
#include <linux/debugfs.h>


#include <linux/rmm_payload.h>  /* for rmm_payload_to_json */

/* Must match the binary policy size in RMM. */
#define POLICY_BIN_SIZE 456
#define MAX_POLICIES_DEBUG   8              /* how many we expose */
#define MAX_POLICY_JSON_LEN  4096           /* per-policy JSON buffer */

static struct dentry *cca_dbg_dir;
static char cca_policy_json[MAX_POLICIES_DEBUG][MAX_POLICY_JSON_LEN];
static DEFINE_MUTEX(cca_policy_lock);

/* These must match rmm_payload_to_json’s expectations. */
#define PAYLOAD_MAGIC   0x5041594cU /* use your real magic */

/* Minimal header reader (same as in rmm_payload_to_json) */
static inline u16 rd_u16_k(const unsigned char *p)
{
    return (u16)p[0] | ((u16)p[1] << 8);
}

static inline u32 rd_u32_k(const unsigned char *p)
{
    return (u32)p[0] |
           ((u32)p[1] << 8) |
           ((u32)p[2] << 16) |
           ((u32)p[3] << 24);
}

// static void cca_split_token_and_policies(u8 *buf, size_t buf_len,
// 					 size_t num_policies,
// 					 size_t policy_size,
// 					 size_t *token_only_len_out)
// {
// 	size_t cfg_total = num_policies * policy_size;

// 	if (buf_len < cfg_total) {
// 		/* Defensive: something is off; don't underflow */
// 		*token_only_len_out = buf_len;
// 		return;
// 	}

// 	/* Layout is [token][cfg_0][cfg_1]...[cfg_N-1] */
// 	*token_only_len_out = buf_len - cfg_total;
// }

static void cca_split_token_and_policies(u8 *buf, size_t buf_len,
					 size_t num_policies,
					 size_t policy_size,
					 size_t *token_only_len_out)
{
	size_t cfg_total;

	if (!token_only_len_out)
		return;

	/* Default: treat everything as token if metadata is inconsistent */
	*token_only_len_out = buf_len;

	if (num_policies == 0)
		return;

	if (policy_size == 0)
		return;

	cfg_total = num_policies * policy_size;

	if (buf_len < cfg_total)
		return;

	/* Layout is [token][cfg_0]...[cfg_N-1] */
	*token_only_len_out = buf_len - cfg_total;
}



static int cca_payload_open(struct inode *inode, struct file *file)
{
	file->private_data = inode->i_private; /* pointer to our char buffer */
	return 0;
}

static ssize_t cca_payload_read(struct file *file, char __user *ubuf,
				size_t count, loff_t *ppos)
{
	char *data = file->private_data;
	size_t len;

	if (!data)
		return 0;

	mutex_lock(&cca_policy_lock);
	len = strnlen(data, MAX_POLICY_JSON_LEN);
	mutex_unlock(&cca_policy_lock);

	return simple_read_from_buffer(ubuf, count, ppos, data, len);
}

static const struct file_operations cca_payload_fops = {
	.owner  = THIS_MODULE,
	.open   = cca_payload_open,
	.read   = cca_payload_read,
	.llseek = default_llseek,
};


/**
 * struct arm_cca_token_info - a descriptor for the token buffer.
 * @challenge:		Pointer to the challenge data
 * @challenge_size:	Size of the challenge data
 * @granule:		PA of the granule to which the token will be written
 * @offset:		Offset within granule to start of buffer in bytes
 * @result:		result of rsi_attestation_token_continue operation
 */
struct arm_cca_token_info {
	void           *challenge;
	unsigned long   challenge_size;
	phys_addr_t     granule;
	unsigned long   offset;
	unsigned long   result;

	/* NEW: group metadata from INIT_GROUP */
	unsigned long   total_size;    /* x1: token + all cfg blobs */
	unsigned long   num_policies;  /* x2: number of cfg blobs */
	unsigned long   policy_size;   /* x3: size of each cfg blob */
};


static void arm_cca_attestation_init(void *param)
{
	struct arm_cca_token_info *info = param;
	unsigned long total = 0;
	unsigned long num_cfg = 0;
	unsigned long cfg_sz = 0;
	long rc;

	rc = rsi_attestation_token_init_group(info->challenge,
					      info->challenge_size,
					      &total, &num_cfg, &cfg_sz);

	info->result       = rc;      /* 0 on success, -EINVAL on failure */
	info->total_size   = total;   /* x1 from RMM */
	info->num_policies = num_cfg; /* x2 from RMM */
	info->policy_size  = cfg_sz;  /* x3 from RMM */
}


/**
 * arm_cca_attestation_continue - Retrieve the attestation token data.
 *
 * @param: pointer to the arm_cca_token_info
 *
 * Attestation token generation is a long running operation and therefore
 * the token data may not be retrieved in a single call. Moreover, the
 * token retrieval operation must be requested on the same CPU on which the
 * attestation token generation was initialised.
 * This helper function is therefore scheduled on the same CPU multiple
 * times until the entire token data is retrieved.
 */
static void arm_cca_attestation_continue(void *param)
{
	unsigned long len;
	unsigned long size;
	struct arm_cca_token_info *info;

	info = (struct arm_cca_token_info *)param;

	size = RSI_GRANULE_SIZE - info->offset;
	info->result = rsi_attestation_token_continue_group(info->granule,
	 					      info->offset, size, &len);
	info->offset += len;
}

/**
 * arm_cca_report_new - Generate a new attestation token.
 *
 * @report: pointer to the TSM report context information.
 * @data:  pointer to the context specific data for this module.
 *
 * Initialise the attestation token generation using the challenge data
 * passed in the TSM descriptor. Allocate memory for the attestation token
 * and schedule calls to retrieve the attestation token on the same CPU
 * on which the attestation token generation was initialised.
 *
 * The challenge data must be at least 32 bytes and no more than 64 bytes. If
 * less than 64 bytes are provided it will be zero padded to 64 bytes.
 *
 * Return:
 * * %0        - Attestation token generated successfully.
 * * %-EINVAL  - A parameter was not valid.
 * * %-ENOMEM  - Out of memory.
 * * %-EFAULT  - Failed to get IPA for memory page(s).
 * * A negative status code as returned by smp_call_function_single().
 */
// static int arm_cca_report_new(struct tsm_report *report, void *data)
// {
// 	int ret;
// 	int cpu;
// 	long max_size;
// 	unsigned long token_size = 0;
// 	struct arm_cca_token_info info;
// 	void *buf;
// 	u8 *token __free(kvfree) = NULL;
// 	struct tsm_report_desc *desc = &report->desc;

// 	if (desc->inblob_len < 32 || desc->inblob_len > 64)
// 		return -EINVAL;

// 	/*
// 	 * The attestation token 'init' and 'continue' calls must be
// 	 * performed on the same CPU. smp_call_function_single() is used
// 	 * instead of simply calling get_cpu() because of the need to
// 	 * allocate outblob based on the returned value from the 'init'
// 	 * call and that cannot be done in an atomic context.
// 	 */
// 	cpu = smp_processor_id();

// 	info.challenge = desc->inblob;
// 	info.challenge_size = desc->inblob_len;

// 	ret = smp_call_function_single(cpu, arm_cca_attestation_init,
// 					&info, true);
// 	if (ret)
// 		return ret;

// 	/* info->result is the RSI status now */
// 	if (info.result != RSI_SUCCESS)
// 		return -EINVAL;

// 	max_size = info.total_size;   /* from x1 */
// 	if (max_size == 0)
// 		return -EINVAL;

// 	/* Allocate outblob */
// 	token = kvzalloc(max_size, GFP_KERNEL);
// 	if (!token)
// 		return -ENOMEM;

// 	/*
// 	 * Since the outblob may not be physically contiguous, use a page
// 	 * to bounce the buffer from RMM.
// 	 */
// 	buf = alloc_pages_exact(RSI_GRANULE_SIZE, GFP_KERNEL);
// 	if (!buf)
// 		return -ENOMEM;

// 	/* Get the PA of the memory page(s) that were allocated */
// 	info.granule = (unsigned long)virt_to_phys(buf);

// 	/* Loop until the token is ready or there is an error */
// 	do {
// 		/* Retrieve one RSI_GRANULE_SIZE data per loop iteration */
// 		info.offset = 0;
// 		do {
// 			/*
// 			 * Schedule a call to retrieve a sub-granule chunk
// 			 * of data per loop iteration.
// 			 */
// 			ret = smp_call_function_single(cpu,
// 						       arm_cca_attestation_continue,
// 						       (void *)&info, true);
// 			if (ret != 0) {
// 				token_size = 0;
// 				goto exit_free_granule_page;
// 			}
// 		} while (info.result == RSI_INCOMPLETE &&
// 			 info.offset < RSI_GRANULE_SIZE);

// 		if (info.result != RSI_SUCCESS) {
// 			ret = -ENXIO;
// 			token_size = 0;
// 			goto exit_free_granule_page;
// 		}

// 		/*
// 		 * Copy the retrieved token data from the granule
// 		 * to the token buffer, ensuring that the RMM doesn't
// 		 * overflow the buffer.
// 		 */
// 		if (WARN_ON(token_size + info.offset > max_size))
// 			break;
// 		memcpy(&token[token_size], buf, info.offset);
// 		token_size += info.offset;
// 	} while (info.result == RSI_INCOMPLETE);

// 	size_t token_only_len;

// 	/* --- NEW: split token and decode policies --- */
// 	if (token_size > 0) {
// 		size_t token_only_len;
// 		size_t num_policies = info.num_policies;   // N
// 		size_t policy_size  = info.policy_size;    // S
// 		size_t cfg_total    = num_policies * policy_size;
// 		size_t i;

// 		cca_split_token_and_policies(token, token_size,
// 						num_policies,
// 						POLICY_BIN_SIZE,
// 						&token_only_len);

// 		pr_info("CCA group token: total=%lu, token=%zu, policies=%zu\n",
// 			token_size, token_only_len, num_policies);
		
// 		if (token_size < cfg_total) {
// 			// something is wrong; bail
// 			token_only_len = token_size;  // defensive
// 		} else {
// 			token_only_len = token_size - cfg_total;  // this is T
// 		}

// 		mutex_lock(&cca_policy_lock);

// 		/* Clear old payloads */
// 		for (i = 0; i < MAX_POLICIES_DEBUG; i++)
// 			cca_policy_json[i][0] = '\0';

// 		/* Decode up to MAX_POLICIES_DEBUG policies (currently just 1) */
// 		for (i = 0; i < num_policies && i < MAX_POLICIES_DEBUG; i++) {
// 			const unsigned char *pol_bin =
// 				token + token_only_len + i * policy_size;
			
// 			pr_info("hdrless: self=%u vms=%u ps=%u ch=%u\n",
// 					rd_u16_k(pol_bin+0), rd_u16_k(pol_bin+2),
// 					rd_u16_k(pol_bin+4), rd_u16_k(pol_bin+6));

// 			int rc = rmm_payload_to_json(pol_bin, policy_size,
// 							cca_policy_json[i],
// 							MAX_POLICY_JSON_LEN);
// 			if (rc) {
// 				/* Fallback: simple hex wrapper on failure */
// 				size_t pos = 0, j;
// 				cca_policy_json[i][0] = '\0';

// 				pos += scnprintf(cca_policy_json[i] + pos,
// 						MAX_POLICY_JSON_LEN - pos,
// 						"{ \"raw_policy_hex\": \"");
// 				for (j = 0;
// 					j < POLICY_BIN_SIZE && pos + 3 < MAX_POLICY_JSON_LEN;
// 					j++) {
// 					pos += scnprintf(cca_policy_json[i] + pos,
// 							MAX_POLICY_JSON_LEN - pos,
// 							"%02x", pol_bin[j]);
// 				}
// 				if (pos + 3 < MAX_POLICY_JSON_LEN)
// 					pos += scnprintf(cca_policy_json[i] + pos,
// 							MAX_POLICY_JSON_LEN - pos,
// 							"\"}\n");

// 				cca_policy_json[i][pos < MAX_POLICY_JSON_LEN ?
// 						pos : MAX_POLICY_JSON_LEN - 1] = '\0';

// 				pr_warn("rmm_payload_to_json failed for policy[%zu]: %d\n",
// 					i, rc);
// 			} else {
// 				pr_info("TSM policy[%zu] decoded to JSON\n", i);
// 			}
// 		}

// 		mutex_unlock(&cca_policy_lock);

// 		/* Only pass *pure* token upstream to userspace */
// 		token_size = token_only_len;
// 	}

//     report->outblob = no_free_ptr(token);
// 	report->outblob_len = token_only_len;   // only `[token]`, no payloads
// exit_free_granule_page:
//     report->outblob_len = token_size;
//     free_pages_exact(buf, RSI_GRANULE_SIZE);
//     return ret;
// }

static int arm_cca_report_new(struct tsm_report *report, void *data)
{
	int ret;
	int cpu;
	long max_size;
	unsigned long token_size = 0;
	size_t token_only_len = 0; /* final length of token to return upstream */
	struct arm_cca_token_info info;
	void *buf;
	u8 *token __free(kvfree) = NULL;
	struct tsm_desc *desc = &report->desc;

	if (desc->inblob_len < 32 || desc->inblob_len > 64)
		return -EINVAL;

	cpu = smp_processor_id();

	info.challenge = desc->inblob;
	info.challenge_size = desc->inblob_len;

	ret = smp_call_function_single(cpu, arm_cca_attestation_init, &info, true);
	if (ret)
		return ret;

	if (info.result != RSI_SUCCESS)
		return -EINVAL;

	max_size = info.total_size; /* from INIT_GROUP x1 */
	if (max_size == 0)
		return -EINVAL;

	token = kvzalloc(max_size, GFP_KERNEL);
	if (!token)
		return -ENOMEM;

	/*
	 * Bounce buffer granule. RMM writes into this single 4K buffer;
	 * we loop and copy it out as many times as needed.
	 */
	buf = alloc_pages_exact(RSI_GRANULE_SIZE, GFP_KERNEL);
	if (!buf) {
		ret = -ENOMEM;
		goto out_free_token;
	}

	info.granule = (unsigned long)virt_to_phys(buf);

	/*
	 * Retrieve the full [token][cfg...] stream.
	 * Important: RMM may return RSI_INCOMPLETE even after filling the
	 * entire 4K bounce buffer, meaning "there is more data; use another
	 * iteration with offset reset to 0".
	 */
	for (;;) {
		/* Fill one bounce granule in sub-granule chunks */
		info.offset = 0;

		do {
			ret = smp_call_function_single(cpu,
						       arm_cca_attestation_continue,
						       (void *)&info, true);
			if (ret) {
				token_size = 0;
				goto out_free_granule;
			}
		} while (info.result == RSI_INCOMPLETE &&
			 info.offset < RSI_GRANULE_SIZE);

		/*
		 * Append what we got this iteration, regardless of RSI_SUCCESS
		 * vs RSI_INCOMPLETE. Only error out on unexpected statuses.
		 */
		if (WARN_ON(token_size + info.offset > max_size)) {
			/* Prevent overflow; stop collecting further data */
			break;
		}

		if (info.offset) {
			memcpy(&token[token_size], buf, info.offset);
			token_size += info.offset;
		}

		if (info.result == RSI_SUCCESS) {
			/* Done: we have the full stream */
			break;
		}

		if (info.result != RSI_INCOMPLETE) {
			/* Any other status is an error */
			ret = -ENXIO;
			token_size = 0;
			goto out_free_granule;
		}

		/* RSI_INCOMPLETE: continue outer loop to fetch next 4K slice */
	}

	/*
	 * Split [token][cfg...] and decode cfg blobs to debugfs JSON.
	 * We only return the pure token upstream.
	 */
	token_only_len = token_size;
	if (token_size > 0) {
		size_t num_policies = info.num_policies;
		size_t policy_size  = info.policy_size;
		size_t cfg_total;
		size_t i;

		/* Sanity: policy_size must be non-zero if num_policies > 0 */
		if (num_policies > 0 && policy_size == 0) {
			pr_warn("CCA group: num_policies=%zu but policy_size=0\n",
				num_policies);
			num_policies = 0;
		}

		cfg_total = num_policies * policy_size;

		/* Defensive: avoid underflow / inconsistent metadata */
		if (token_size < cfg_total) {
			pr_warn("CCA group: token_size(%lu) < cfg_total(%zu); treating as token-only\n",
				token_size, cfg_total);
			token_only_len = token_size;
			num_policies = 0;
		} else {
			token_only_len = token_size - cfg_total;
		}

		pr_info("CCA group token: total=%lu token=%zu policies=%zu policy_size=%zu\n",
			token_size, token_only_len, num_policies, policy_size);

		mutex_lock(&cca_policy_lock);

		/* Clear old payloads */
		for (i = 0; i < MAX_POLICIES_DEBUG; i++)
			cca_policy_json[i][0] = '\0';

		/* Decode up to MAX_POLICIES_DEBUG policies */
		for (i = 0; i < num_policies && i < MAX_POLICIES_DEBUG; i++) {
			const unsigned char *pol_bin =
				token + token_only_len + i * policy_size;

			pr_info("hdrless: self=%u vms=%u ps=%u ch=%u\n",
				rd_u16_k(pol_bin + 0), rd_u16_k(pol_bin + 2),
				rd_u16_k(pol_bin + 4), rd_u16_k(pol_bin + 6));

			/*
			 * Use policy_size returned by RMM, not a hardcoded constant.
			 */
			{
				int rc = rmm_payload_to_json(pol_bin, policy_size,
							     cca_policy_json[i],
							     MAX_POLICY_JSON_LEN);
				if (rc) {
					/* Fallback: hex wrapper on failure */
					size_t pos = 0, j;

					cca_policy_json[i][0] = '\0';
					pos += scnprintf(cca_policy_json[i] + pos,
							 MAX_POLICY_JSON_LEN - pos,
							 "{ \"raw_policy_hex\": \"");
					for (j = 0;
					     j < policy_size && pos + 3 < MAX_POLICY_JSON_LEN;
					     j++) {
						pos += scnprintf(cca_policy_json[i] + pos,
								 MAX_POLICY_JSON_LEN - pos,
								 "%02x", pol_bin[j]);
					}
					if (pos + 3 < MAX_POLICY_JSON_LEN)
						pos += scnprintf(cca_policy_json[i] + pos,
								 MAX_POLICY_JSON_LEN - pos,
								 "\"}\n");

					cca_policy_json[i][pos < MAX_POLICY_JSON_LEN ?
						pos : MAX_POLICY_JSON_LEN - 1] = '\0';

					pr_warn("rmm_payload_to_json failed for policy[%zu]: %d\n",
						i, rc);
				} else {
					pr_info("TSM policy[%zu] decoded to JSON\n", i);
				}
			}
		}

		mutex_unlock(&cca_policy_lock);
	}

	/*
	 * Return token-only buffer to userspace.
	 * token is still allocated to max_size; outblob_len tells consumers how
	 * many bytes are valid.
	 */
	report->outblob = no_free_ptr(token);
	report->outblob_len = token_only_len;

	free_pages_exact(buf, RSI_GRANULE_SIZE);
	return 0;

out_free_granule:
	free_pages_exact(buf, RSI_GRANULE_SIZE);
out_free_token:
	/* token is __free(kvfree), so it will be freed on return */
	return ret;
}


static const struct tsm_ops arm_cca_tsm_ops = {
	.name = KBUILD_MODNAME,
	.report_new = arm_cca_report_new,
};

/**
 * arm_cca_guest_init - Register with the Trusted Security Module (TSM)
 * interface.
 *
 * Return:
 * * %0        - Registered successfully with the TSM interface.
 * * %-ENODEV  - The execution context is not an Arm Realm.
 * * %-EBUSY   - Already registered.
 */
static int __init arm_cca_guest_init(void)
{
	int ret;

	if (!is_realm_world())
		return -ENODEV;

	ret = tsm_register(&arm_cca_tsm_ops, NULL);
	if (ret < 0) {
		pr_err("Error %d registering with TSM\n", ret);
		return ret;
	}

	cca_dbg_dir = debugfs_create_dir("cca_policies", NULL);
	if (IS_ERR(cca_dbg_dir))
		cca_dbg_dir = NULL;
	else {
		int i;
		for (i = 0; i < MAX_POLICIES_DEBUG; i++) {
			char name[16];

			snprintf(name, sizeof(name), "payload%d", i);
			pr_info("cca_policies: creating %s\n", name);

			debugfs_create_file(name, 0444, cca_dbg_dir,
					    cca_policy_json[i],
					    &cca_payload_fops);
		}
	}

	return ret;
}
module_init(arm_cca_guest_init);

/**
 * arm_cca_guest_exit - unregister with the Trusted Security Module (TSM)
 * interface.
 */
static void __exit arm_cca_guest_exit(void)
{
	tsm_unregister(&arm_cca_tsm_ops);
	if (cca_dbg_dir) {
		debugfs_remove_recursive(cca_dbg_dir);
		cca_dbg_dir = NULL;
	}
}
module_exit(arm_cca_guest_exit);

/* modalias, so userspace can autoload this module when RSI is available */
static const struct platform_device_id arm_cca_match[] __maybe_unused = {
	{ RSI_PDEV_NAME, 0},
	{ }
};

MODULE_DEVICE_TABLE(platform, arm_cca_match);
MODULE_AUTHOR("Sami Mujawar <sami.mujawar@arm.com>");
MODULE_DESCRIPTION("Arm CCA Guest TSM Driver");
MODULE_LICENSE("GPL");
