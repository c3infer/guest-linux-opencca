#ifndef _LINUX_RMM_PAYLOAD_H
#define _LINUX_RMM_PAYLOAD_H

#include <linux/types.h>

int rmm_payload_to_json(const unsigned char *buf, size_t len,
                        char *out, size_t out_cap);

#endif
