//#include "stdafx.h"

#ifdef __linux__
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <linux/if_ether.h>
#include <poll.h>
#include <pthread.h>
#include <time.h>

typedef struct sockaddr_in SOCKADDR_IN;
typedef struct sockaddr    SOCKADDR;
typedef unsigned long      DWORD;

#define closesocket close

#include "iwpriv.c"

#else

#include "stdafx.h"
#include <iostream>
#include <time.h>
#include <stdio.h>

using namespace std;
#include <winsock2.h>
#pragma comment(lib,"ws2_32.lib")

#include <process.h>
#include <windows.h>
#include <time.h>
#include <io.h>
#include <direct.h>
#endif

/*ringbuffer define*/
#define RBUFFER_DEF(name, type, size) \
    struct rb_##name {\
        int  rpos, wpos, qsize;\
        type rbq[(size)+1];\
    }name

#define RB_NPOS(rb,pos,i)  (((rb)->pos+(i) >= (rb)->qsize) ? ((rb)->pos+(i) - (rb)->qsize) : ((rb)->pos+(i)))
#define RB_EMPTY(rb)       ((rb)->wpos == (rb)->rpos)
#define RB_FULL(rb)        (RB_NPOS(rb, wpos,1) == (rb)->rpos)
#define RB_COUNT(rb)       (((rb)->rpos <= (rb)->wpos)?\
                            ((rb)->wpos - (rb)->rpos):\
                            ((rb)->qsize-(rb)->rpos + (rb)->wpos))
#define RB_IDLE(rb)        ((rb)->qsize - RB_COUNT(rb))

/*get a value from ringbuffer*/
#define RB_GET(rb, val) do{\
        if(!RB_EMPTY(rb)){\
            val = (rb)->rbq[(rb)->rpos];\
            (rb)->rpos = RB_NPOS((rb), rpos, 1);\
        }\
    } while(0)

/*set a value into ringbuffer*/
#define RB_SET(rb, val) do{\
        if(!RB_FULL(rb)){\
            (rb)->rbq[(rb)->wpos] = val;\
            (rb)->wpos = RB_NPOS((rb), wpos, 1);\
        }\
    } while (0)

/*ringbuffer init*/
#define RB_INIT(rb, size) do{\
        (rb)->qsize = (size);\
        (rb)->rpos = 0;\
        (rb)->wpos = 0;\
    } while (0)

#ifndef MAC2STR2
#define MAC2STR2(a) (a)[0]&0xff, (a)[1]&0xff, (a)[2]&0xff, (a)[3]&0xff, (a)[4]&0xff, (a)[5]&0xff
#define MACSTR2 "%02x-%02x-%02x-%02x-%02x-%02x"
#endif

#define UDP_PORT       (60002)
#define KEEPALIVE_TIME (5)

#define UDP_KALIVE_HEARTBEAT_DATA      "UALIVE:HB"
#define UDP_KALIVE_HEARTBEAT_RESP_DATA "UALIVE:HB"
#define UDP_KALIVE_WAKEUP_DATA         "UALIVE:WK"
#define UDP_KALIVE_ONLINE              "UALIVE:OL"
#define UDP_KALIVE_TESTDATA            "UALIVE:TD"
#define UDP_KALIVE_GOTOSLEEP           "UALIVE:GS"

#define UDP_KALIVE_SLEEP_TIME  (10)
#define UDP_KALIVE_ONLINE_TIME (30)

#define UDP_KALIVE_WAKEUP_TIMEOUT (60)
#define UDP_KALIVE_DEV_CNT (64)

#define UALIVE_FRM(d, s) (memcmp(d, s, 9) == 0)
#define UALIVE_ID(d) (d+10)

enum UDPKALIVE_DEV_STATE {
    UDPKALIVE_DEV_STATE_NONE,
    UDPKALIVE_DEV_STATE_ONLINE,
    UDPKALIVE_DEV_STATE_GOSLEEP,
    UDPKALIVE_DEV_STATE_SLEEP,
    UDPKALIVE_DEV_STATE_WAKEUP,
    UDPKALIVE_DEV_STATE_OFFLINE,
};

char *dev_state_str[] = {
    "NONE",
    "Online",
    "goSleep",
    "Sleep",
    "Wakeup",
    "Offline",
};

struct udp_kalive_device {
    int alive;
    struct timeval livetime;
    SOCKADDR_IN addr;
    char id[18];
    int  state;
    int  ticker;
    int  tmo;
    int  hb, hb_tmo;
    DWORD jiffies;
    int  wkup_time;
    int  sleep_time;
    int  testspeed;
    int  testdata_len;
    int  test_cnt;
    int  fail_cnt;
};

struct udp_kalive_mgr {
    int sock;
    int port;
    int dev_max, dev_cnt;
    char id[18];
    SOCKADDR_IN svr;
    char testdata[1400];
    char recvbuf[2048];
    int hb, hb_tmo;
    struct udp_kalive_device *devs;
    char log_file[64];
    int  min_sleep;
    int  sleep_status;
    int  tx_bitrate;
} udp_klive;

int udp_kalive_init(int port)
{
    int sock = -1;
    int addr_len = sizeof(SOCKADDR_IN);
    SOCKADDR_IN local_addr;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        printf("create udp socket error:[%d:%s]\n", errno, strerror(errno));
        return -1;
    }

    memset(&local_addr, 0, addr_len);
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    local_addr.sin_port = htons(port);
    if (bind(sock, (SOCKADDR *)&local_addr, addr_len) < 0) {
        printf("udp bind error:[%d:%s]\n", errno, strerror(errno));
        closesocket(sock);
        return -1;
    }
    return sock;
}

int udp_kalive_send(SOCKADDR_IN *dest, char *data, int len)
{
    int addr_len = sizeof(SOCKADDR_IN);
    return sendto(udp_klive.sock, data, len, 0, (SOCKADDR *)dest, addr_len);
}

int udp_kalive_recv(int sock, SOCKADDR_IN *dest, char *data, int len, int tmo)
{
    int ret = 0;
    fd_set rfd;
    struct timeval timeout;
    int addr_len = sizeof(SOCKADDR_IN);

    FD_ZERO(&rfd);
    FD_SET(sock, &rfd);
    timeout.tv_sec  = 0;
    timeout.tv_usec = tmo * 1000;
    ret = select(sock + 1, &rfd, NULL, NULL, &timeout);
    if (FD_ISSET(sock, &rfd)) {
        ret = recvfrom(sock, data, len, 0, (SOCKADDR *)dest, &addr_len);
    } else {
        ret = 0;
    }
    return ret;
}

void udp_kalive_dev_send(char *action, int param1, int param2, int param3)
{
    int len = 0;
    char data[64];
    memset(data, 0, 64);
    len = sprintf(data, "%s-%s", action, udp_klive.id);
    if (param1) { len += sprintf(data + len, ",%d", param1); }
    if (param2) { len += sprintf(data + len, ",%d", param2); }
    if (param3) { len += sprintf(data + len, ",%d", param3); }
    udp_kalive_send(&udp_klive.svr, data, strlen(data));
}

void udp_kalive_send_hearbeat()
{
    udp_kalive_dev_send(UDP_KALIVE_HEARTBEAT_DATA, udp_klive.hb, 0, 0);
}

void udp_kalive_send_online()
{
    udp_kalive_dev_send(UDP_KALIVE_ONLINE, 0, 0, 0);
}

void udp_kalive_send_testdata(int len)
{
    SOCKADDR_IN svr;
    memcpy(&svr, &udp_klive.svr, sizeof(SOCKADDR_IN));
    svr.sin_port = htons(udp_klive.port + 1);
    udp_kalive_send(&svr, udp_klive.testdata, len);
}

void udp_kalive_dev_action(struct udp_kalive_device *dev, char *action)
{
    char data[32];
    memset(data, 0, 32);
    sprintf(data, "%s-%s", action, dev->id);
    udp_kalive_send(&dev->addr, data, strlen(data));
}

void udp_kalive_goto_wakeup(struct udp_kalive_device *dev)
{
    udp_kalive_dev_action(dev, UDP_KALIVE_WAKEUP_DATA);
}

void udp_kalive_goto_sleep(struct udp_kalive_device *dev)
{
    udp_kalive_dev_action(dev, UDP_KALIVE_GOTOSLEEP);
}

#ifdef __linux__
void udp_kalive_config_hbresp()
{
    char data[32];
    memset(data, 0, 32);
    sprintf(data, "%s-%s", UDP_KALIVE_HEARTBEAT_DATA, udp_klive.id);
    hgic_iwpriv_set_heartbeat_resp_data("hg0", data, strlen(data));
}

void udp_kalive_config_hbmask()
{
    char data[32];
    memset(data, 0, 32);
    sprintf(data, "%s", "HB");
    hgic_iwpriv_set_hbdata_mask("hg0", 7, data, strlen(data)); //offset: start payload.
}

void udp_kalive_clear_arp(char *ip)
{
    char cmd[64];
    memset(cmd, 0, 64);
    sprintf(cmd, "arp -d %s", ip);
    system(cmd);
}

void udp_kalive_config_heartbeat(struct in_addr ip, int port, int hb_int, int hb_tmo)
{
    hgic_iwpriv_set_heartbeat("hg0", ip.s_addr, port, hb_int, hb_tmo);
}

void udp_kalive_config_wkdata()
{
    char data[32];
    memset(data, 0, 32);
    sprintf(data, "%s-%s", UDP_KALIVE_WAKEUP_DATA, udp_klive.id);
    hgic_iwpriv_set_wakeup_data("hg0", data, strlen(data));
}

void udp_kalive_config_wkdata_mask()
{
    char mask[8];
    memset(mask, 0xff, 8);
    hgic_iwpriv_set_wkdata_mask("hg0", 42, mask, 8); //offset: start ether hdr.
}

DWORD GetTickCount()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

int udp_kalive_detect_module(char *ifname)
{
    int ret = -1;
    struct ifreq req;

    int sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (sock != -1) {
        memset(&req, 0, sizeof(struct ifreq));
        strncpy(req.ifr_name, ifname, strlen(ifname));
        ret = ioctl(sock, SIOCGIFHWADDR, &req);
        close(sock);

        if (ret != -1) {
            memset(udp_klive.id, 0, sizeof(udp_klive.id));
            sprintf(udp_klive.id, MACSTR2, MAC2STR2(req.ifr_hwaddr.sa_data));
            return 1;
        }
    }
    return 0;
}

int main(int argc, char *argv[])
{
    int ret = 0;
    SOCKADDR_IN svr_addr;
    SOCKADDR_IN from;
    int recv_loop = 100;
    int tx_loop = 4;
    int tx_len = sizeof(udp_klive.testdata);

    int reconfig = 1;
    int i = 0;
    int tick_sec = 0;
    int svr_alive = 0;
    in_addr_t ipaddr;

    HGIC = "hgicf";
    udp_klive.port = UDP_PORT;
    udp_klive.hb   = 10;
    udp_klive.hb_tmo = 60;
    udp_klive.tx_bitrate = 400;

    if (argc > 1) {
        ipaddr = inet_addr(argv[1]);
    } else {
        printf("***invalid param***\nudp_kalive ipaddr port interval timeout\n");
        return -1;
    }

    if (argc > 2) { udp_klive.port = atoi(argv[2]); }
    if (argc > 3) { udp_klive.hb = atoi(argv[3]); }
    if (argc > 4) { udp_klive.hb_tmo = atoi(argv[4]); }
    if (argc > 5) { udp_klive.tx_bitrate = atoi(argv[5]); }

    memset(&udp_klive.svr, 0, sizeof(SOCKADDR_IN));
    udp_klive.svr.sin_family = AF_INET;
    udp_klive.svr.sin_addr.s_addr = ipaddr;
    udp_klive.svr.sin_port = htons(udp_klive.port);

    printf("ps server:%s:%d, tx_bitrate:%dKB/s\r\n", argv[1], udp_klive.port, udp_klive.tx_bitrate);
    udp_klive.sock = udp_kalive_init(0);
    if (udp_klive.sock < 0) {
        return -1;
    }

    if(udp_klive.tx_bitrate >= 150){
        recv_loop = 100;
        tx_len    = 1024;
        tx_loop   = ((udp_klive.tx_bitrate*1024)/recv_loop)/tx_len;
    }else if(udp_klive.tx_bitrate >= 50){
        recv_loop = 50;
        tx_len    = 1024;
        tx_loop   = ((udp_klive.tx_bitrate*1024)/recv_loop)/tx_len;
    }else if(udp_klive.tx_bitrate >= 10){
        recv_loop = 10;
        tx_len    = 1024;
        tx_loop   = ((udp_klive.tx_bitrate*1024)/recv_loop)/tx_len;
    }else{
        recv_loop = 5;
        tx_len    = 128;
        tx_loop   = ((udp_klive.tx_bitrate*1024)/recv_loop)/tx_len;
    }
    if(tx_loop == 0) tx_loop++;

__detect:
    while (!udp_kalive_detect_module("hg0")) {
        usleep(100 * 1000);
    }
    printf("AH module detect ...\r\n");
    //system("brctl addif br0 hg0");
    system("ifconfig hg0 up");
    udp_kalive_clear_arp(argv[1]);
    //udp_kalive_send_online();
    //udp_kalive_send_online();

    memset(udp_klive.testdata, 0xAA, sizeof(udp_klive.testdata));
    sprintf(udp_klive.testdata, "%s-%s", UDP_KALIVE_TESTDATA, udp_klive.id);
    hgic_iwpriv_set_ps_mode("hg0", 2);
    udp_kalive_config_heartbeat(udp_klive.svr.sin_addr, udp_klive.port, udp_klive.hb, udp_klive.hb_tmo);
    udp_kalive_config_hbresp();
    udp_kalive_config_hbmask();
    udp_kalive_config_wkdata();
    udp_kalive_config_wkdata_mask();

    svr_alive = 0;
    tick_sec = GetTickCount();
    udp_klive.sleep_status = UDPKALIVE_DEV_STATE_OFFLINE;

    while (1) {
        ret = udp_kalive_recv(udp_klive.sock, &from, udp_klive.recvbuf, 2048, 1000/recv_loop);
        if (ret > 0 && strncmp(udp_klive.recvbuf, "UALIVE:", 7) == 0) {
            svr_alive = 10;
            udp_klive.recvbuf[ret] = 0;
            switch (udp_klive.sleep_status) {
                case UDPKALIVE_DEV_STATE_GOSLEEP:
                    if (UALIVE_FRM(udp_klive.recvbuf, UDP_KALIVE_HEARTBEAT_RESP_DATA)) {
                        printf("enter sleep ...\r\n");
                        udp_klive.sleep_status = UDPKALIVE_DEV_STATE_SLEEP;
                        hgic_iwpriv_sleep("hg0", 1, 0);
                    }
                    break;

                case UDPKALIVE_DEV_STATE_SLEEP:
                    if (UALIVE_FRM(udp_klive.recvbuf, UDP_KALIVE_GOTOSLEEP)) {
                        udp_kalive_send_hearbeat();
                        printf("Go Sleep ...\r\n");
                    } else if (UALIVE_FRM(udp_klive.recvbuf, UDP_KALIVE_WAKEUP_DATA)) {
                        printf("recv wakeup data\r\n");
                        udp_klive.sleep_status = UDPKALIVE_DEV_STATE_ONLINE;
                    }
                    break;

                case UDPKALIVE_DEV_STATE_WAKEUP:
                    if (UALIVE_FRM(udp_klive.recvbuf, UDP_KALIVE_HEARTBEAT_RESP_DATA)) {
                        printf("keep alive done, enter sleep ...\r\n");
                        hgic_iwpriv_sleep("hg0", 1, 0);
                    }
                    break;

                case UDPKALIVE_DEV_STATE_OFFLINE:
                    printf("ONLINE\r\n");
                    udp_klive.sleep_status = UDPKALIVE_DEV_STATE_ONLINE;
                default:
                    if (UALIVE_FRM(udp_klive.recvbuf, UDP_KALIVE_GOTOSLEEP)) {
                        udp_klive.sleep_status = UDPKALIVE_DEV_STATE_GOSLEEP;
                        udp_kalive_send_hearbeat();
                        printf("Go Sleep ...\r\n");
                    }
                    break;
            }
        } else {
            if (!udp_kalive_detect_module("hg0")) {
                printf("hg0 removed\r\n");
                goto __detect;
            }

            if (udp_klive.sleep_status == UDPKALIVE_DEV_STATE_WAKEUP) {
                udp_kalive_send_hearbeat();
                printf("KEEP ALIVE retry ...\r\n");
            }

            if (GetTickCount() - tick_sec >= 1000) {
                tick_sec = GetTickCount();
                if (udp_klive.sleep_status == UDPKALIVE_DEV_STATE_GOSLEEP) {
                    udp_kalive_send_hearbeat();
                    printf("Go Sleep ...\r\n");
                } else if (udp_klive.sleep_status == UDPKALIVE_DEV_STATE_ONLINE) {
                    //udp_kalive_send_online();
                } else if (udp_klive.sleep_status == UDPKALIVE_DEV_STATE_OFFLINE) {
                    udp_kalive_send_online();
                }

                if (svr_alive > 0) svr_alive--;
                if (svr_alive == 0 && udp_klive.sleep_status != UDPKALIVE_DEV_STATE_OFFLINE) {
                    udp_klive.sleep_status = UDPKALIVE_DEV_STATE_OFFLINE;
                    printf("OFFLINE\r\n");
                }
            }

            if (udp_klive.sleep_status == UDPKALIVE_DEV_STATE_ONLINE && svr_alive > 0) {
                for (i = 0; i < tx_loop; i++) {
                    udp_kalive_send_testdata(tx_len);
                }
            }
        }
    }
}
#else

#define LOGBUF_SIZE (1024)
struct dsleep_test_log {
    char path[64];
    char log[256];
};

RBUFFER_DEF(logs, struct dsleep_test_log *, LOGBUF_SIZE);

void udp_kalive_print()
{
    int i = 0;
    FILE *fp;
    struct udp_kalive_device *dev;
    SYSTEMTIME sys;

    system("cls");
    //printf("| fa:de:09:9c:a4:30 | 192.168.110.230:50002 | OFFLINE | 11 |   2200ms   |  1000KB/s |\r\n");
    printf("|-----------------------------------------------------------------------------------------------------------------|\r\n");
    printf("|** HUGE-IC DSLEEP TEST APP, UDP PORT:%5d , Max Device:%3d, MIN SLEEP:%4ds, DEV COUNT:%3d                    **|\r\n", udp_klive.port, udp_klive.dev_max, udp_klive.min_sleep, udp_klive.dev_cnt);
    printf("|-----------------------------------------------------------------------------------------------------------------|\r\n");
    printf("|       DEV ID      |        IP Addr        |  State  | Tick |  WakeupTime | SleepTime  | TestSpeed |  Fail/Total |\r\n");
    for (i = 0; i < udp_klive.dev_max; i++) {
        if (udp_klive.devs[i].state) {
            dev = &udp_klive.devs[i];
            printf("|-------------------|-----------------------|---------|------|-------------|------------|-----------|-------------|\r\n");
            printf("| %s | %15s:%5d | %7s | %4d |   %5dms   |   %5dms  |  %4dKB/s |%4d/%-08d|\r\n",
                   dev->id,
                   inet_ntoa(dev->addr.sin_addr),
                   ntohs(dev->addr.sin_port),
                   dev_state_str[dev->state],
                   dev->ticker,
                   dev->wkup_time,
                   dev->sleep_time,
                   dev->testspeed,
                   dev->fail_cnt,
                   dev->test_cnt);
        }
    }
    printf("|-----------------------------------------------------------------------------------------------------------------|\r\n");

    fp = fopen(udp_klive.log_file, "a+");
    if (fp) {
        GetLocalTime(&sys);
        fprintf(fp, "[%4d-%02d-%02d %02d:%02d:%02d.%03d]\n", sys.wYear, sys.wMonth, sys.wDay, sys.wHour, sys.wMinute, sys.wSecond, sys.wMilliseconds);
        fprintf(fp, "|-----------------------------------------------------------------------------------------------------------------|\n");
        fprintf(fp, "|** HUGE-IC DSLEEP TEST APP, UDP PORT:%5d , Max Device:%3d, MIN SLEEP:%4ds, DEV COUNT:%3d                    **|\r\n", udp_klive.port, udp_klive.dev_max, udp_klive.min_sleep, udp_klive.dev_cnt);
        fprintf(fp, "|-----------------------------------------------------------------------------------------------------------------|\r\n");
        fprintf(fp, "|       DEV ID      |        IP Addr        |  State  | Tick |  WakeupTime | SleepTime  | TestSpeed |  Fail/Total |\r\n");
        for (i = 0; i < udp_klive.dev_max; i++) {
            if (udp_klive.devs[i].state) {
                dev = &udp_klive.devs[i];
                fprintf(fp, "|-------------------|-----------------------|---------|------|-------------|------------|-----------|-------------|\n");
                fprintf(fp, "| %s | %15s:%5d | %7s | %4d |   %5dms   |   %5dms  |  %4dKB/s |%4d/%-08d|\n",
                        dev->id,
                        inet_ntoa(dev->addr.sin_addr),
                        ntohs(dev->addr.sin_port),
                        dev_state_str[dev->state],
                        dev->ticker,
                        dev->wkup_time,
                        dev->sleep_time,
                        dev->testspeed,
                        dev->fail_cnt,
                        dev->test_cnt);
            }
        }
        fprintf(fp, "|-----------------------------------------------------------------------------------------------------------------|\n\n");
        fflush(fp);
        fclose(fp);
    }

}

void udp_kalive_create_logdir()
{
    char path[64];
    SYSTEMTIME sys;
    GetLocalTime(&sys);
    sprintf(path, "%4d-%02d-%02d", sys.wYear, sys.wMonth, sys.wDay, sys.wYear, sys.wMonth, sys.wDay);
    if(_access(path, 0x02)){
		_mkdir(path);
	}
}

void udp_kalive_devlog(struct udp_kalive_device *dev, char *fmt, ...)
{
    char *ptr;
    int len;
    va_list args;
    SYSTEMTIME sys;
    struct dsleep_test_log *log = (struct dsleep_test_log *)malloc(sizeof(struct dsleep_test_log));

    if (log == NULL) {
        return;
    }

    udp_kalive_create_logdir();
    if (dev) {
        GetLocalTime(&sys);
        sprintf(log->path, "%4d-%02d-%02d/%s.txt", sys.wYear, sys.wMonth, sys.wDay, dev->id);
        ptr = log->path;
        while(*ptr) { if(*ptr == ':') *ptr = '-'; ptr++; }
        len = sprintf(log->log, "[%4d-%02d-%02d %02d:%02d:%02d.%03d]:", sys.wYear, sys.wMonth, sys.wDay, sys.wHour, sys.wMinute, sys.wSecond, sys.wMilliseconds);
        va_start(args, fmt);
        vsprintf(log->log + len, fmt, args);
        va_end(args);

        if (RB_FULL(&logs)) {
            free(log);
        } else {
            RB_SET(&logs, log);
        }
    }else{
        free(log);
    }
}

struct udp_kalive_device *udp_kalive_get_device(char *id)
{
    int i = 0;
    for (i = 0; i < udp_klive.dev_max; i++) {
        if (memcmp(id, &udp_klive.devs[i].id, 17) == 0 && udp_klive.devs[i].state != UDPKALIVE_DEV_STATE_NONE) {
            return &udp_klive.devs[i];
        }
    }
    return NULL;
}

struct udp_kalive_device *udp_kalive_new_device(SOCKADDR_IN *addr, char *id)
{
    int i = 0;
    int n = -1;
    int o = -1;

    for (i = 0; i < udp_klive.dev_max; i++) {
        if (udp_klive.devs[i].state == UDPKALIVE_DEV_STATE_NONE && n == -1) {
            n = i; //none state
            udp_klive.dev_cnt++;
        }
        if (udp_klive.devs[i].state == UDPKALIVE_DEV_STATE_OFFLINE && o == -1) {
            o = i; //offline state
        }
    }

    if (n != -1 || o != -1) {
        i = (n != -1) ? n : o;
        memset(&udp_klive.devs[i], 0, sizeof(struct udp_kalive_device));
        memcpy(udp_klive.devs[i].id, id, 17);
        memcpy(&udp_klive.devs[i].addr, addr, sizeof(SOCKADDR_IN));
        printf("new device:%s(%s:%d)\n", udp_klive.devs[i].id, inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
        return &udp_klive.devs[i];
    } else {
        printf("no free device (%s)\r\n", id);
        return NULL;
    }
}

void udp_kalive_dev_new_state(struct udp_kalive_device *dev, int state)
{
    if(dev->state != state){
        switch(state){
            case UDPKALIVE_DEV_STATE_ONLINE:
                dev->ticker = 20;
                break;
            case UDPKALIVE_DEV_STATE_GOSLEEP:
                dev->ticker = 10;
                break;
            case UDPKALIVE_DEV_STATE_SLEEP:
                dev->ticker = udp_klive.min_sleep + rand() % udp_klive.min_sleep;
                dev->tmo = dev->hb * 10;
                break;
            case UDPKALIVE_DEV_STATE_WAKEUP:
                dev->ticker = 10;
                break;
            case UDPKALIVE_DEV_STATE_OFFLINE:
                dev->ticker = 60;
                break;
            default:
                dev->ticker = 60;
                break;
        }
        dev->state = state;
        dev->jiffies = GetTickCount();
    }
}

void udp_kalive_check_ticker()
{
    int i = 0;
    struct udp_kalive_device *dev;

    for (i = 0; i < udp_klive.dev_max; i++) {
        dev = &udp_klive.devs[i];
        if (dev->ticker <= 1) {
            switch (dev->state) {
                case UDPKALIVE_DEV_STATE_ONLINE:
                    udp_kalive_goto_sleep(dev);
                    dev->testspeed    = 0;
                    dev->testdata_len = 0;
                    dev->test_cnt++;
                    udp_kalive_dev_new_state(dev, UDPKALIVE_DEV_STATE_GOSLEEP);
                    udp_kalive_devlog(dev, "goto sleep\r\n");
                    break;
                case UDPKALIVE_DEV_STATE_GOSLEEP:
                    dev->fail_cnt++;
                    udp_kalive_dev_new_state(dev, UDPKALIVE_DEV_STATE_OFFLINE);
                    udp_kalive_devlog(dev, "[ERROR] goto sleep timeout, offline\r\n");
                    break;
                case UDPKALIVE_DEV_STATE_SLEEP:
                    dev->test_cnt++;
                    udp_kalive_goto_wakeup(dev);
                    udp_kalive_dev_new_state(dev, UDPKALIVE_DEV_STATE_WAKEUP);
                    udp_kalive_devlog(dev, "goto wakeup\r\n");
                    break;
                case UDPKALIVE_DEV_STATE_WAKEUP:
                    dev->wkup_time = 0;
                    dev->fail_cnt++;
                    udp_kalive_dev_new_state(dev, UDPKALIVE_DEV_STATE_OFFLINE);
                    udp_kalive_devlog(dev, "[ERROR] wakeup fail, offline\r\n");
                    break;
                case UDPKALIVE_DEV_STATE_OFFLINE:
                    udp_klive.dev_cnt--;
                    memset(dev->id, 0, sizeof(dev->id));
                    udp_kalive_dev_new_state(dev, UDPKALIVE_DEV_STATE_NONE);
                    break;
                default:
                    break;
            }
        } else {
            if (dev->tmo == 1) {
                switch (dev->state) {
                    case UDPKALIVE_DEV_STATE_ONLINE:
                        dev->tmo = 0;
                        udp_kalive_dev_new_state(dev, UDPKALIVE_DEV_STATE_OFFLINE);
                        udp_kalive_devlog(dev, "offline\r\n");
                        break;
                    case UDPKALIVE_DEV_STATE_SLEEP:
                        dev->tmo = 0;
                        udp_kalive_dev_new_state(dev, UDPKALIVE_DEV_STATE_OFFLINE);
                        udp_kalive_devlog(dev, "sleep offline\r\n");
                        break;
                    default:
                        dev->tmo = 0;
                        break;
                }
            }
        }
    }
}

void udp_kalive_calc_testspeed(struct udp_kalive_device *dev)
{
    if (dev->state == UDPKALIVE_DEV_STATE_ONLINE && dev->testdata_len > 0) {
        dev->testspeed    = dev->testdata_len / 1024;
        dev->testdata_len = 0;
        udp_kalive_devlog(dev, "test speed:%dKB/s\r\n", dev->testspeed);
    }
}

static void udp_kalive_retry(struct udp_kalive_device *dev)
{
    if (dev->ticker > 1) {
        switch (dev->state) {
            case UDPKALIVE_DEV_STATE_GOSLEEP:
                udp_kalive_goto_sleep(dev);
                udp_kalive_devlog(dev, "goto sleep\r\n");
                break;
            case UDPKALIVE_DEV_STATE_WAKEUP:
                udp_kalive_goto_wakeup(dev);
                udp_kalive_devlog(dev, "goto wakeup\r\n");
                break;
            default:
                break;
        }
    }
}

static void udp_kalive_adjust_ticker()
{
    int i = 0;
    int sleep_tm  = 0;
    int online_tm = 0;
    struct udp_kalive_device *dev = NULL;

    if(udp_klive.min_sleep == 0){
        for (i = 0; i < udp_klive.dev_max; i++) {
            dev = &udp_klive.devs[i];
            if(dev->state == UDPKALIVE_DEV_STATE_SLEEP){
                if(sleep_tm == 0){
                    sleep_tm = dev->ticker;
                }else{
                    dev->ticker = sleep_tm;
                }
            }
            if(dev->state == UDPKALIVE_DEV_STATE_ONLINE){
                if(online_tm == 0){
                    online_tm = dev->ticker;
                }else{
                    dev->ticker = online_tm;
                }
            }
        }
    }
}

static int udp_kalive_1s_proc(DWORD last_tick)
{
    int  i = 0;
    char online[64];
    struct udp_kalive_device *dev = NULL;

    if (GetTickCount() - last_tick >= 1000) {
        //udp_kalive_adjust_ticker();
        for (i = 0; i < udp_klive.dev_max; i++) {
            dev = &udp_klive.devs[i];
            if(dev->state != UDPKALIVE_DEV_STATE_NONE){
                if (dev->ticker > 1) { dev->ticker--; }
                if (dev->tmo > 1)    { dev->tmo--; }
                udp_kalive_calc_testspeed(dev);
                udp_kalive_retry(dev);
            }
            if(dev->state == UDPKALIVE_DEV_STATE_ONLINE && (dev->ticker&0x3) == 0){
                sprintf(online, "%s-%s" , UDP_KALIVE_ONLINE, dev->id);
                udp_kalive_send(&dev->addr, online, strlen(online));//send response
            }
        }
        return 1;
    }
    return 0;
}

DWORD _stdcall udp_kalive_task(LPVOID lpParameter)
{
    int i = 0;
    int ret = 0;
    SOCKADDR_IN from;
    struct udp_kalive_device *dev;
    DWORD last_tick = GetTickCount();

    while (1) {
        ret = udp_kalive_recv(udp_klive.sock, &from, udp_klive.recvbuf, 2048, 100);
        if (ret > 0 && strncmp(udp_klive.recvbuf, "UALIVE:", 7) == 0) {
            udp_klive.recvbuf[ret] = 0;
            dev = udp_kalive_get_device(UALIVE_ID(udp_klive.recvbuf));
            if (dev == NULL) {
                dev = udp_kalive_new_device(&from, UALIVE_ID(udp_klive.recvbuf));
                udp_kalive_devlog(dev, "new device online\r\n");
            } else {
                memcpy(&dev->addr, &from, sizeof(SOCKADDR_IN));
            }

            if (dev) {
                if (UALIVE_FRM(udp_klive.recvbuf, UDP_KALIVE_HEARTBEAT_DATA)) {
                    udp_kalive_devlog(dev, "recv hb, dev state [%s]\r\n", dev_state_str[dev->state]);
                    udp_kalive_send(&dev->addr, udp_klive.recvbuf, ret);//send response
                    udp_kalive_devlog(dev, "send hb resp\r\n");
                    if (dev->state != UDPKALIVE_DEV_STATE_WAKEUP) {
                        if (dev->state == UDPKALIVE_DEV_STATE_GOSLEEP) {
                            dev->sleep_time = GetTickCount() - dev->jiffies;
                            dev->hb  = atoi(udp_klive.recvbuf + 9 + 18 + 1);
                            udp_kalive_dev_new_state(dev, UDPKALIVE_DEV_STATE_SLEEP);
                            udp_kalive_devlog(dev, "enter sleep use %d ms\r\n", dev->sleep_time);
                        }else if (dev->state != UDPKALIVE_DEV_STATE_SLEEP) {
                            udp_kalive_devlog(dev, "[WARNING] recv hb, dev state [%s]\r\n", dev_state_str[dev->state]);
                            dev->hb  = atoi(udp_klive.recvbuf + 9 + 18 + 1);
                            udp_kalive_dev_new_state(dev, UDPKALIVE_DEV_STATE_SLEEP);
                        }
                    }
                } else if (UALIVE_FRM(udp_klive.recvbuf, UDP_KALIVE_ONLINE)) {
                    if (dev->state != UDPKALIVE_DEV_STATE_GOSLEEP) {
                        int online = 1;
                        if (dev->state == UDPKALIVE_DEV_STATE_OFFLINE) {
                            udp_kalive_devlog(dev, "online, offline time:%d ms\r\n", GetTickCount() - dev->jiffies);
                        } else if (dev->state == UDPKALIVE_DEV_STATE_WAKEUP) {
                            dev->wkup_time = GetTickCount() - dev->jiffies;
                            udp_kalive_devlog(dev, "online, wakeup time:%d ms\r\n", dev->wkup_time);
                        } else if (dev->state == UDPKALIVE_DEV_STATE_SLEEP) {
                            if(dev->ticker < udp_klive.min_sleep){
                                dev->fail_cnt++;
                                udp_kalive_devlog(dev, "[ERROR] online, wakeup self\r\n");
                            }else{
                                online = 0;
                            }
                        }

                        if(online){
                            udp_kalive_send(&dev->addr, udp_klive.recvbuf, ret);//send response
                            udp_kalive_dev_new_state(dev, UDPKALIVE_DEV_STATE_ONLINE);
                        }
                    }else{
                        udp_kalive_devlog(dev, "[WARNING] recv online, dev state [%s]\r\n", dev_state_str[dev->state]);
                    }
                }
            } else {
                printf("error data: %s\r\n", udp_klive.recvbuf);
            }
        }
        if (udp_kalive_1s_proc(last_tick)) {
            last_tick = GetTickCount();
        }
        udp_kalive_check_ticker();
    }
}

DWORD _stdcall udp_kalive_datatest_task(LPVOID lpParameter)
{
    int i = 0;
    int ret = 0;
    SOCKADDR_IN from;
    struct udp_kalive_device *dev;
    char *recvbuf = NULL;

    int sock = udp_kalive_init(udp_klive.port + 1);
    if (sock == -1) {
        printf("creat testdata socket err\r\n");
        exit(0);
    }

    recvbuf = (char *)malloc(2048);
    if (recvbuf == NULL) {
        printf("malloc fail, recv buff: 2048\r\n");
        closesocket(sock);
    }

    while (1) {
        ret = udp_kalive_recv(sock, &from, recvbuf, 1800, 1000);
        if (ret > 0 && UALIVE_FRM(recvbuf, UDP_KALIVE_TESTDATA)) {
            recvbuf[ret] = 0;
            dev = udp_kalive_get_device(UALIVE_ID(recvbuf));
            if (dev) {
                dev->testdata_len += ret;
                dev->tmo = dev->hb * 10;
                if (dev->state == UDPKALIVE_DEV_STATE_WAKEUP) {
                    dev->wkup_time = GetTickCount() - dev->jiffies;
                    udp_kalive_dev_new_state(dev, UDPKALIVE_DEV_STATE_ONLINE);
                }
            }
        }
    }
    free(recvbuf);
    closesocket(sock);
}

static void dsleep_test_write_devlogs(void)
{
    FILE *fp = NULL;
    char path[64];
    struct dsleep_test_log *log;

    memset(path, 0, sizeof(path));
    while (RB_COUNT(&logs)) {
        RB_GET(&logs, log);

        if (strcmp(path, log->path)) {
            strcpy(path, log->path);
            if (fp) {
                fclose(fp);
                fp = NULL;
            }
        }

        if (fp == NULL) {
            fp = fopen(log->path, "a+");
        }

        if (fp) {
            fwrite(log->log, 1, strlen(log->log), fp);
            fflush(fp);
        }

        free(log);
    }

    if (fp) { fclose(fp); }
}

int main(int argc, char *argv[])
{
    WORD wVersionRequested;
    WSADATA wsaData;
    int  err;
    int  i = 0;
    char loop = 0;
    struct udp_kalive_device *dev = NULL;
    SYSTEMTIME sys;

    wVersionRequested = MAKEWORD(1, 1);
    err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0) {
        return 0;
    }

    printf("dsleep_test: port dev_max min_sleep\r\n    port: default is 60002\r\n    dev_max: default is 32\r\n    min_sleep: default is 30s\r\n");
    GetLocalTime(&sys);
    sprintf(udp_klive.log_file, "dsleep_test_%4d-%02d-%02d_%02d%02d%02d%03d.log",
            sys.wYear, sys.wMonth, sys.wDay, sys.wHour, sys.wMinute, sys.wSecond, sys.wMilliseconds);
    srand(time(NULL));
    udp_klive.port = UDP_PORT;
    udp_klive.dev_max = UDP_KALIVE_DEV_CNT;
    udp_klive.min_sleep = 30;
    udp_klive.dev_cnt = 0;
    if (argc > 1) { udp_klive.port = atoi(argv[1]); }
    if (argc > 2) { udp_klive.dev_max = atoi(argv[2]); }
    if (argc > 3) { udp_klive.min_sleep = atoi(argv[3]); }

    udp_klive.devs = (struct udp_kalive_device *)malloc(udp_klive.dev_max * sizeof(struct udp_kalive_device));
    if (udp_klive.devs == NULL) {
        printf("malloc fail, dev_max=%d\r\n", udp_klive.dev_max);
        return -1;
    }

    memset(udp_klive.devs, 0, udp_klive.dev_max * sizeof(struct udp_kalive_device));
    udp_klive.sock = udp_kalive_init(udp_klive.port);
    if (udp_klive.sock < 0) {
        free(udp_klive.devs);
        return -1;
    }

    RB_INIT(&logs, LOGBUF_SIZE);
    CreateThread(NULL, 0, udp_kalive_task, NULL, 0, NULL);
    CreateThread(NULL, 0, udp_kalive_datatest_task, NULL, 0, NULL);
    Sleep(2000);

    while (1) {
        Sleep(100);
        if (loop++ >= 10) {
            udp_kalive_print();
            loop = 0;
        }
        dsleep_test_write_devlogs();
    }

    free(udp_klive.devs);
    WSACleanup();
    return 0;
}

#endif
