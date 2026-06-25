#ifndef WLTP_CONFIG_H
#define WLTP_CONFIG_H

#define WLTP_VERSION_MAJOR  1
#define WLTP_VERSION_MINOR  0
#define WLTP_VERSION_STR    "1.0"

#define WLTP_DEFAULT_RATE       44
#define WLTP_DEFAULT_DURATION   30
#define WLTP_DEFAULT_INTERVAL   1
#define WLTP_POLL_TIMEOUT_MS    100

#define WLTP_SOCKET_BUFSIZE     262144
#define WLTP_MAX_PKT_SIZE       1472
#define WLTP_MCAST_TTL          4

#ifdef __mips__
#define WLTP_EMBEDDED  1
#else
#define WLTP_EMBEDDED  0
#endif

#endif
