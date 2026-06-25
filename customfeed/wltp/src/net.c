#include "net.h"
#include "config.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>

int net_create_udp(const proto_def_t *proto, const test_config_t *cfg,
                   int is_sender)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;

    if (cfg->iface[0]) {
        if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
                       cfg->iface, strlen(cfg->iface) + 1) < 0) {
            perror("SO_BINDTODEVICE");
            close(fd);
            return -1;
        }
    }

    int reuse = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    if (!is_sender) {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(proto->port);
        addr.sin_addr.s_addr = INADDR_ANY;
        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            perror("bind");
            close(fd);
            return -1;
        }

        if (proto->use_multicast && proto->mcast_addr) {
            struct ip_mreq mreq;
            memset(&mreq, 0, sizeof(mreq));
            mreq.imr_multiaddr.s_addr = proto->mcast_addr;
            mreq.imr_interface.s_addr = INADDR_ANY;
            if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                           &mreq, sizeof(mreq)) < 0) {
                perror("IP_ADD_MEMBERSHIP");
                close(fd);
                return -1;
            }
        }
    } else {
        if (!proto->use_multicast) {
            int bcast = 1;
            setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &bcast, sizeof(bcast));
        }
        if (proto->use_multicast) {
            struct in_addr iface_addr;
            memset(&iface_addr, 0, sizeof(iface_addr));
            setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF,
                       &iface_addr, sizeof(iface_addr));
            int ttl = WLTP_MCAST_TTL;
            setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL,
                       &ttl, sizeof(ttl));
        }
    }

    int bufsize = WLTP_SOCKET_BUFSIZE;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));

    return fd;
}

int net_send_udp(int sockfd, const uint8_t *buf, int len,
                 const proto_def_t *proto, const test_config_t *cfg)
{
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(proto->port);

    if (proto->use_multicast) {
        dest.sin_addr.s_addr = proto->mcast_addr;
    } else if (cfg->dest_ip) {
        dest.sin_addr.s_addr = cfg->dest_ip;
    } else {
        dest.sin_addr.s_addr = INADDR_BROADCAST;
    }

    return (int)sendto(sockfd, buf, (size_t)len, 0,
                       (struct sockaddr *)&dest, sizeof(dest));
}

int net_recv_udp(int sockfd, uint8_t *buf, int buf_size, int timeout_ms)
{
    struct pollfd pfd;
    pfd.fd = sockfd;
    pfd.events = POLLIN;
    pfd.revents = 0;

    int ret = poll(&pfd, 1, timeout_ms);
    if (ret <= 0) return ret;

    ssize_t n = recv(sockfd, buf, (size_t)buf_size, 0);
    return (int)n;
}
