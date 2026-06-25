#ifdef _WIN32
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <process.h>
#pragma comment(lib, "ws2_32.lib") // 链接 Winsock 库
#else
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // 用于 sleep/usleep
#include <stdarg.h>
#include <sys/socket.h>
#include <netinet/in.h> // 用于 struct sockaddr_in
#include <arpa/inet.h>  // 用于 inet_addr
#include <sys/time.h>   // 用于 gettimeofday
#include <time.h>       // 用于 clock_gettime, localtime, struct tm
#include <ctype.h>      // 用于 isdigit
#include <errno.h>      // 用于 errno
#include <signal.h>     // 用于 signal 处理

typedef struct sockaddr_in SOCKADDR_IN;
typedef struct sockaddr    SOCKADDR;
typedef unsigned long      DWORD;
#define INVALID_SOCKET     (-1)
#define SOCKET_ERROR       (-1)
#define WSAGetLastError()  errno
#define closesocket        close
static inline unsigned int GetTickCount()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    // 秒 * 1000 + 纳秒 / 1000000 = 毫秒
    return (unsigned int)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}
#endif

#define MAC2STR(a) (a)[0]&0xff, (a)[1]&0xff, (a)[2]&0xff, (a)[3]&0xff, (a)[4]&0xff, (a)[5]&0xff
#define MACSTR "%02x-%02x-%02x-%02x-%02x-%02x"

int udp_sock = -1;
int udp_port = 56999;
int udp_tx   = 0;
int udp_frmlen = 512;
int delay_sock = -1;
int udp_bw = 128; // KB/s
int udp_destIP = 0xffffffff;

void udp_random(char *buff, int len)
{
    int i = 0;
    srand(time(NULL));
    for (i = 0; i < len; i++) {
        buff[i] = (char)(rand() & 0xff);
    }
}

#ifdef _WIN32
int gettimeofday(struct timeval *tp, void *tzp)
{
    static LARGE_INTEGER frequency;
    static double freq_to_usec;
    LARGE_INTEGER counter;

    if (frequency.QuadPart == 0) {
        if (!QueryPerformanceFrequency(&frequency)) {
            return -1; // 硬件不支持高精度计时器
        }
        freq_to_usec = 1000000.0 / (double)frequency.QuadPart;
    }

    if (!QueryPerformanceCounter(&counter)) {
        return -1;
    }

    // 转换为秒和微秒
    // 注意：这里使用了 double 转换，对于非常长的运行时间可能会有精度损失，但对于测试工具足够了
    double time_as_double = (double)counter.QuadPart * freq_to_usec;
    tp->tv_sec = (long)(time_as_double / 1000000);
    tp->tv_usec = (long)(time_as_double - (tp->tv_sec * 1000000));

    return 0;
}
#endif

void log(char *fmt, ...)
{
    FILE *fp = NULL;
    va_list args;
    char fname[64];

    // 定义时间变量
    int year, month, day, hour, minute, second, millisecond;

#ifdef _WIN32
    // --- Windows 实现 ---
    SYSTEMTIME sys;
    GetLocalTime(&sys);
    year = sys.wYear;
    month = sys.wMonth;
    day = sys.wDay;
    hour = sys.wHour;
    minute = sys.wMinute;
    second = sys.wSecond;
    millisecond = sys.wMilliseconds;
#else
    // --- Linux 实现 (使用 gettimeofday) ---
    struct timeval tv;
    struct tm *tm_info;

    // 1. 获取微秒级时间戳
    gettimeofday(&tv, NULL);
    // 2. 将秒转换为本地时间结构体
    tm_info = localtime(&tv.tv_sec);
    // 3. 提取数据 (注意：tm_year 是从 1900 开始，tm_mon 是从 0 开始)
    year = tm_info->tm_year + 1900;
    month = tm_info->tm_mon + 1;
    day = tm_info->tm_mday;
    hour = tm_info->tm_hour;
    minute = tm_info->tm_min;
    second = tm_info->tm_sec;
    // 4. 将微秒转换为毫秒
    millisecond = tv.tv_usec / 1000;
#endif

    sprintf(fname, "bcastlog_%s_%4d-%02d-%02d.txt", udp_tx ? "TX" : "RX", year, month, day);
    fp = fopen(fname, "a+");
    if (fp) {
        fprintf(fp, "[%4d-%02d-%02d %02d:%02d:%02d.%03d]:",
                year, month, day, hour, minute, second, millisecond);
        va_start(args, fmt);
        vfprintf(fp, fmt, args);
        va_end(args);

        fclose(fp);
    }
}

/**
 * 判断IPv4地址是否为组播地址 (RFC 1112)
 *
 * @param ip_str 点分十进制格式的IPv4地址字符串 (如 "224.1.1.1")
 * @return
 *   true  : 是组播地址 (224.0.0.0 ~ 239.255.255.255)
 *   0 : 非组播地址或输入无效
 */
int is_multicast_address(const char *ip_str)
{
    // 检查空指针
    if (!ip_str || *ip_str == '\0'){
        return 0;
    }

    // 复制字符串以便安全分割 (strtok会修改原字符串)
    char ip_copy[16];
    if (strlen(ip_str) >= sizeof(ip_copy)){
        return 0;  // 字符串过长
    }
    strcpy(ip_copy, ip_str);

    // 分割IP地址的四个部分
    char *parts[4];
    char *token = strtok(ip_copy, ".");
    int i = 0;

    while (token && i < 4) {
        // 检查每部分是否全数字
        const char *p = token;
        for (; *p; p++) {
            if (!isdigit((unsigned char)*p)) {
                return 0;
            }
        }

        // 转换为整数并验证范围
        long num = strtol(token, NULL, 10);
        if (num < 0 || num > 255){
            return 0;
        }

        parts[i++] = token;
        token = strtok(NULL, ".");
    }

    // 必须恰好4部分
    if (i != 4){
        return 0;
    }

    // 核心判断：第一段必须在224~239范围内
    int first_octet = atoi(parts[0]);
    return (first_octet >= 224 && first_octet <= 239);
}

int udp_send(char *data, int len)
{
    int addr_len = sizeof(SOCKADDR_IN);
    SOCKADDR_IN dest;

    memset(&dest, 0, sizeof(SOCKADDR_IN));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = udp_destIP;
    dest.sin_port = htons(udp_port);
    return sendto(udp_sock, data, len, 0, (SOCKADDR *)&dest, addr_len);
}

int udp_recv(int sock, SOCKADDR_IN *dest, char *data, int len, int tmo)
{
    int ret = 0;
    fd_set rfd;
    struct timeval timeout;
    int addr_len = sizeof(SOCKADDR_IN);

    FD_ZERO(&rfd);
    FD_SET((unsigned int)sock, &rfd);
    timeout.tv_sec  = 0;
    timeout.tv_usec = tmo * 1000;

    ret = select(sock + 1, &rfd, NULL, NULL, &timeout);
    if (ret > 0 && FD_ISSET(sock, &rfd)) {
        ret = recvfrom(sock, data, len, 0, (SOCKADDR *)dest, &addr_len);
    }
    return ret;
}

int udp_init(char *local_ip, char *dest_ip, int is_tx)
{
    int on = 1;
    struct ip_mreq mreq;
    SOCKADDR_IN local_addr;
    int addr_len = sizeof(SOCKADDR_IN);
    int bind_ip  = inet_addr(local_ip);

    udp_destIP = inet_addr(dest_ip);

    udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sock == INVALID_SOCKET) {
        printf("create udp socket error:[%d:%s]\n", WSAGetLastError(), strerror(WSAGetLastError()));
        return -1;
    }

    setsockopt(udp_sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&on, sizeof(on));

    memset(&local_addr, 0, addr_len);
    local_addr.sin_family = AF_INET;
    if (is_multicast_address(dest_ip) && !is_tx) {
        bind_ip = htonl(INADDR_ANY);
    }
    local_addr.sin_addr.s_addr = bind_ip;
    local_addr.sin_port = is_tx ? 0 : htons(udp_port);
    if (bind(udp_sock, (SOCKADDR *)&local_addr, addr_len) == SOCKET_ERROR) {
        printf("udp bind error:[%d:%s]\n", WSAGetLastError(), strerror(WSAGetLastError()));
        closesocket(udp_sock);
        return -1;
    }

    if (is_multicast_address(dest_ip)) {
        // 加入组播组
        memset(&mreq, 0, sizeof(mreq));
        mreq.imr_multiaddr.s_addr = udp_destIP;
        mreq.imr_interface.s_addr = inet_addr(local_ip);
        if (setsockopt(udp_sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (const char *)&mreq, sizeof(mreq)) == SOCKET_ERROR) {
            printf("加入组播组失败 (Check Firewall/Virtual Adapters): %d. %s\n", WSAGetLastError(), dest_ip);
        } else {
            printf("成功加入组播组 %s\n", dest_ip);
        }
        if (setsockopt(udp_sock, SOL_SOCKET, SO_BROADCAST, (const char *)&on, sizeof(on)) == SOCKET_ERROR) {
            printf("setsockopt SO_BROADCAST error:[%d:%s]\n", WSAGetLastError(), strerror(WSAGetLastError()));
            closesocket(udp_sock);
            return -1;
        }
    }

    delay_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (delay_sock == INVALID_SOCKET) {
        printf("create delay socket error\n");
        closesocket(udp_sock);
        return -1;
    }

    memset(&local_addr, 0, addr_len);
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = 0;
    local_addr.sin_port = 0;
    bind(delay_sock, (SOCKADDR *)&local_addr, addr_len);

    return 0;
}

void udp_delay(int ms)
{
    fd_set rfd;
    struct timeval timeout;

    FD_ZERO(&rfd);
    FD_SET((unsigned int)delay_sock, &rfd);
    timeout.tv_sec  = 0;
    timeout.tv_usec = ms * 1000;
    select(delay_sock + 1, &rfd, NULL, NULL, &timeout);
}

void udp_run_tx()
{
    int ret;
    unsigned int txlen = 0;
    struct timeval start_time, current_time;
    unsigned char txbuff[2048] = {0};

    // 初始化开始时间
    gettimeofday(&start_time, NULL);
    DWORD last_tick = GetTickCount();
    int   last_tx = 0;

    while (1) {

        while (1) {
            gettimeofday(&current_time, NULL);
            double elapsed_sec = (current_time.tv_sec - start_time.tv_sec)
                                 + (current_time.tv_usec - start_time.tv_usec) / 1000000.0;
            if (elapsed_sec < 0.001) {
                break;
            }

            // 计算当前速度 KB/s
            // txlen 是字节，elapsed_sec 是秒，除以 1024 得到 KB
            unsigned int current_speed = (unsigned int)((txlen / 1024.0) / elapsed_sec);
            if (current_speed < (unsigned int)udp_bw) {
                break;
            }
            udp_delay(1);
        }

        ret = udp_send((char *)txbuff, udp_frmlen);
        if (ret > 0) {
            txlen   += ret;
            last_tx += ret;
            if (txlen > 0 && GetTickCount() - last_tick >= 1000) {
                int speed_kb  = last_tx / 1024;
                printf("TX speed: %d KByte/s\n", speed_kb);
                log("TX speed: %d KByte/s\n", speed_kb);
                last_tx   = 0;
                last_tick = GetTickCount();
            }
        } else {
            printf("bcast send error!\r\n");
            break;
        }

        txbuff[0]++;
    }
}

#define LOST_CNT(l,n) (((n)>(l))?((n)-(l)):(255-(l)+(n)))

void udp_run_rx()
{
    int ret;
    SOCKADDR_IN from;
    unsigned char rxbuff[2048];
    unsigned char nextseq = 0;
    unsigned int rxbytes = 0;
    unsigned int rx_cnt = 0;
    unsigned int rx_totcnt = 0;
    unsigned int rx_lostcnt = 0;

    DWORD last_tick = GetTickCount();
    while (1) {
        ret = udp_recv(udp_sock, &from, (char *)rxbuff, sizeof(rxbuff), 100);
        if (ret > 0) {
            rx_cnt++;
            rxbytes += ret;
            if (nextseq != rxbuff[0]) {
                rx_totcnt  += LOST_CNT(nextseq, rxbuff[0]);
                rx_lostcnt += LOST_CNT(nextseq, rxbuff[0]);
                printf("bcast: lost data! [expect:%d, recv:%d]\n", nextseq, rxbuff[0]);
                log("bcast: lost data! [expect:%d, recv:%d]\n", nextseq, rxbuff[0]);
            } else {
                rx_totcnt++;
            }
            nextseq = rxbuff[0] + 1;
        }

        if (rx_totcnt > 0 && GetTickCount() - last_tick >= 1000) {
            // 修复原代码中 len 未定义的错误，这里应该是 rxbytes
            int speed_kb  = rxbytes / 1024;
            int loss_rate = (rx_totcnt > 0) ? (rx_lostcnt * 100 / rx_totcnt) : 0;

            printf("RX speed: %d KByte/s (total:%d, rx:%d, lost:%d, %d%%)\n",
                   speed_kb, rx_totcnt, rx_cnt, rx_lostcnt, loss_rate);

            log("RX speed: %d KByte/s (total:%d, rx:%d, lost:%d, %d%%)\n",
                speed_kb, rx_totcnt, rx_cnt, rx_lostcnt, loss_rate);

            rxbytes = rx_cnt = rx_lostcnt = rx_totcnt = 0;
            last_tick = GetTickCount();
        }
    }
}

void usage()
{
    printf("usage:\r\n");
    printf("   ## TX模式，本地IP: 10.10.10.3, 目的IP: 224.1.1.1，包长:512，目的端口:5001, 传输带宽: 128KB/s\r\n");
    printf("    ./udp_test 10.10.10.3 224.1.1.1 -t -l 512 -p 5001 -b 128\r\n");
    printf("   ## RX模式: 本地IP: 10.10.10.3, 目的IP: 224.1.1.1 (目的IP可以全0)，RX端口: 5001.\r\n");
    printf("    ./udp_test 10.10.10.3 224.1.1.1 -p 5001\r\n");
}

void dump_args(char *argv[], int count)
{
    int i = 0;
    printf("---------------------------\n");
    for (i = 0; i < count; i++) {
        printf("arg%d: %s\n", i, argv[i]);
    }
    printf("---------------------------\n");
}

int main(int argc, char *argv[])
{
    int  err;
    int  i = 0;
    char *local_ip = NULL;
    char *udp_ip = NULL;

#ifdef _WIN32
    WSADATA wsaData;
    WORD wVersionRequested;
    wVersionRequested = MAKEWORD(2, 2);
    err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0) {
        printf("WSAStartup failed\n");
        return 0;
    }
#endif

    usage();
    dump_args(argv, argc);

    if (argc > 3) {
        local_ip = argv[1];
        udp_ip   = argv[2];

        int i = 3;
        while (i < argc) {
            if (strcmp(argv[i], "-t") == 0) {
                udp_tx = 1;
                i++;
            } else if (strcmp(argv[i], "-p") == 0 && (i + 1) < argc) {
                udp_port = atoi(argv[i + 1]);
                i += 2;
            } else if (strcmp(argv[i], "-l") == 0 && (i + 1) < argc) {
                udp_frmlen = atoi(argv[i + 1]);
                i += 2;
            } else if (strcmp(argv[i], "-b") == 0 && (i + 1) < argc) {
                udp_bw = atoi(argv[i + 1]);
                i += 2;
            } else {
                i++;
            }
        }
    } else {
        return -1;
    }

    printf("local_ip:%s, udp_ip:%s, port:%d, mode:%s, packetlen:%d, bw:%dKB/s\n",
           local_ip, udp_ip, udp_port, udp_tx ? "TX" : "RX", udp_frmlen, udp_bw);
    log("local_ip:%s, udp_ip:%s, port:%d, mode:%s, packetlen:%d, bw:%dKB/s\n",
        local_ip, udp_ip, udp_port, udp_tx ? "TX" : "RX", udp_frmlen, udp_bw);

    if (udp_init(local_ip, udp_ip, udp_tx)) {
        return -1;
    }

    if (udp_tx) {
        udp_run_tx();
    } else {
        udp_run_rx();
    }

    closesocket(udp_sock);
    closesocket(delay_sock);

#ifdef _WIN32
    WSACleanup(); // Windows 清理
#endif
    return 0;
}
