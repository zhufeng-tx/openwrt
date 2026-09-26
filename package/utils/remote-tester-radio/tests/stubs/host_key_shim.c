/* SPDX-License-Identifier: GPL-2.0-only */
#include "../../src/host/rt_host_auth.h"

int rt_host_key_load(const char *path, uint8_t key[RT_HOST_KEY_BYTES])
{
	(void)path;
	for (size_t i = 0; i < RT_HOST_KEY_BYTES; i++)
		key[i] = (uint8_t)i;
	return 0;
}
