#include "clock.h"
#include <time.h>
#include <errno.h>

usec_t clock_now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (usec_t)ts.tv_sec * 1000000ULL + (usec_t)ts.tv_nsec / 1000ULL;
}

void clock_sleep_us(usec_t us) {
    struct timespec req;
    req.tv_sec  = (time_t)(us / 1000000ULL);
    req.tv_nsec = (long)((us % 1000000ULL) * 1000ULL);
    while (nanosleep(&req, &req) == -1 && errno == EINTR)
        ;
}
