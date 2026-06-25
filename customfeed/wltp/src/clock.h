#ifndef WLTP_CLOCK_H
#define WLTP_CLOCK_H

#include "types.h"

usec_t clock_now_us(void);
void clock_sleep_us(usec_t us);

static inline usec_t clock_elapsed_us(usec_t start, usec_t end) {
    return (end >= start) ? (end - start) : 0;
}

#endif
