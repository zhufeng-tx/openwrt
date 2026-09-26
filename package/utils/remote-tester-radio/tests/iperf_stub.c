/* SPDX-License-Identifier: GPL-2.0-only */
#define _POSIX_C_SOURCE 200809L
#include <time.h>

int main(void)
{
	const struct timespec delay = { .tv_sec = 0, .tv_nsec = 100000000L };
	(void)nanosleep(&delay, NULL);
	return 0;
}
