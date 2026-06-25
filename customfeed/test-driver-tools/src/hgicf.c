/**
  ******************************************************************************
  * @file    hgicf.c
  * @author  HUGE-IC Application Team
  * @version V1.0.0
  * @date    2021-06-23
  * @brief   hgic fmac driver daemon.
  ******************************************************************************
  * @attention
  *
  * <h2><center>&copy; COPYRIGHT 2022 HUGE-IC</center></h2>
  *
  ******************************************************************************
  */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>

#include "hgic.h"

#include "iwpriv.c"

///////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////
#define IFNAME "hg0"
//#define BELNC_EN 1

struct hgic_fw_info hgic_fwinfo;

static void hgic_test_read_wakeupdata()
{
    int i = 0;
    char *buff = malloc(4096);
    do {
        i = hgic_iwpriv_get_wkdata_buff(IFNAME, buff, 4096);
        if (i > 0) {
            buff[i] = 0;
            printf("get wkdata, len:%d, %s\r\n", i, buff + 42);
        }
    } while (i > 0);
    free(buff);
}

#if BELNC_EN
static void hgicf_parse_blenc_param(uint8 *data, uint32 len)
{
    u8 *ptr = data;
#if 1 //sample code
    u8 buff[33];
    u8 cmd[64];
    while (ptr < data + len) {
        switch (ptr[0]) {
            case 1: //SSID
                memset(buff, 0, sizeof(buff));
                memcpy(buff, ptr + 2, ptr[1]);
                printf("SET ssid:%s\r\n", buff);
                hgic_iwpriv_set_ssid("hg0", buff);
                break;
            case 2: //PassWord
                memset(buff, 0, sizeof(buff));
                memcpy(buff, ptr + 2, ptr[1]);
                printf("SET passwd:%s\r\n", buff);
                sprintf(cmd, "at+key=%s", buff);
                hgic_iwpriv_send_atcmd("hg0", cmd);
                break;
            case 3: //Keymgmt
                printf("SET keymgmt %s\r\n", ptr[2] ? "WPA-PSK" : "NONE");
                hgic_iwpriv_set_keymgmt("hg0", ptr[2] ? "WPA-PSK" : "NONE");
                break;
            case 4: //auth
                printf("AUTH %d\r\n", ptr[2]);
                sprintf(cmd, "ifconfig hg0 %s", ptr[2] ? "up" : "down");
                system(cmd);
                break;
            default:
                printf("Unsupport ID:%d\r\n", ptr[0]);
                break;
        }
        ptr += (ptr[1] + 2);
    }
    hgic_blenc_release();
    hgic_iwpriv_blenc_start("hg0", 0, 38);
#endif
}
#if 1
/*泰芯微信小程序配网数据 | Weixin applet data*/
static void hgicf_recv_blenc_data(uint8 *data, uint32 len)
{
    uint8 *ncdata = NULL;
    uint32 data_len = 0;

    //hgic_dump_hex("BLE DATA:\r\n", data, len, 1);
    if (hgic_blenc_parse_data(data, len)) {
        data_len = hgic_blenc_get_data(&ncdata);
        if (data_len && ncdata) {
            hgicf_parse_blenc_param(ncdata, data_len);
        }
    }
}
#else
/* customer protocol
   data: BLE PDU data
   len:  data length
*/
static void hgicf_recv_blenc_data(uint8 *data, uint32 len)
{
}
#endif
#endif

int hgicf_fwevent_parse(u8 *event_data, u32 event_len)
{
    int i = 0;
    u32   data_len = 0;
    u32   evt_id   = 0;
    char *data     = NULL;
    char *buff;
    struct hgic_exception_info *exp;
    struct hgic_dhcp_result *dhcpc;
    struct hgic_ctrl_hdr *evt = (struct hgic_ctrl_hdr *)event_data;

    data     = (char *)(evt + 1);
    data_len = event_len - sizeof(struct hgic_ctrl_hdr);
    evt_id   = HDR_EVTID(evt);

    //printf("recv firmware event %d\r\n", evt_id);
    buff = malloc(4096);
    if (buff == NULL) {
        return -1;
    }

    switch (evt_id) {
        case HGIC_EVENT_SCANNING:
            printf("start scan ...\r\n");
            break;
        case HGIC_EVENT_SCAN_DONE:
            printf("scan done!\r\n");
            //hgic_iwpriv_get_scan_list(IFNAME, buff, 4096);
            //printf("%s\r\n", buff);
            break;
        case HGIC_EVENT_TX_BITRATE:
            printf("estimate tx bitrate:%dKbps\r\n", *(unsigned int *)data);
            break;
        case HGIC_EVENT_PAIR_START:
            printf("start pairing ...\r\n");
            break;
        case HGIC_EVENT_PAIR_SUCCESS:
            printf("pairing success! ["MACSTR"]\r\n", MACARG(data));
            hgic_iwpriv_set_pairing(IFNAME, 0); //stop pair
            break;
        case HGIC_EVENT_PAIR_DONE:
            printf("pairing done!\r\n");
            for(i=0; i*6 < data_len;i++){
                printf("  sta%d:"MACSTR"\r\n", i, MACARG(data+6*i));
            }
            break;
        case HGIC_EVENT_CONECT_START:
            printf("start connecting ...\r\n");
            break;
        case HGIC_EVENT_CONECTED:
            printf("new sta "MACSTR" connected!\r\n", MACARG(data));
            hgic_test_read_wakeupdata();
            break;
        case HGIC_EVENT_ROAM_CONECTED:
            printf("roam success to "MACSTR"!\r\n", MACARG(data));
            break;
        case HGIC_EVENT_DISCONECTED:
            printf("sta "MACSTR" disconnected\r\n", MACARG(data));
            break;
        case HGIC_EVENT_SIGNAL:
            printf("signal changed: rssi:%d, evm:%d\r\n", (signed char)data[0], (signed char)data[1]);
            break;
        case HGIC_EVENT_CUSTOMER_MGMT:
            printf("rx customer mgmt frame from "MACSTR", %d bytes \r\n", MACARG(data), data_len-6);
            break;
        case HGIC_EVENT_DHCPC_DONE:
            dhcpc = (struct hgic_dhcp_result *)data;
            printf("fw dhcpc result: ipaddr:"IPSTR", netmask:"IPSTR", svrip:"IPSTR", router:"IPSTR", dns:"IPSTR"/"IPSTR"\r\n",
                IP2STR_N(dhcpc->ipaddr), IP2STR_N(dhcpc->netmask), IP2STR_N(dhcpc->svrip),
                IP2STR_N(dhcpc->router), IP2STR_N(dhcpc->dns1), IP2STR_N(dhcpc->dns2));
            break;
        case HGIC_EVENT_CONNECT_FAIL:
            printf("connect fail, status_code=%d\r\n", *data);
            break;
        case HGIC_EVENT_CUST_DRIVER_DATA:
            printf("rx customer driver data %d bytes\r\n", data_len);
            break;
        case HGIC_EVENT_UNPAIR_STA:
            printf("unpair sta:"MACSTR"\r\n", MACARG(data));
            break;
        case HGIC_EVENT_FWDBG_INFO: //固件调试信息输出
            //printf("%s", data);
            break;
        case HGIC_EVENT_EXCEPTION_INFO:
            exp = (struct hgic_exception_info *)data;
            switch(exp->num){
                case HGIC_EXCEPTION_TX_BLOCKED:
                    printf("*wireless tx blocked, maybe need reset wifi module*\r\n");
                    break;
                case HGIC_EXCEPTION_TXDELAY_TOOLONG:
                    printf("*wireless txdelay too loog, %d:%d:%d *\r\n",
                            exp->info.txdelay.max, exp->info.txdelay.min, exp->info.txdelay.avg);
                    break;
                case HGIC_EXCEPTION_STRONG_BGRSSI:
                    printf("*detect strong backgroud noise. %d:%d:%d *\r\n",
                            exp->info.bgrssi.max, exp->info.bgrssi.min, exp->info.bgrssi.avg);
                    break;
                case HGIC_EXCEPTION_TEMPERATURE_OVERTOP:
                    printf("*chip temperature too overtop: %d *\r\n", exp->info.temperature.temp);
                    break;
                case HGIC_EXCEPTION_WRONG_PASSWORD:
                    printf("*password maybe is wrong *\r\n");
                    break;
            }
            break;
    }

    free(buff);
}

int main(int argc, char *argv[])
{
    int  ret = 0;
    int  fd  = -1;
    struct hgic_hdr *hdr;
    u8 *buff = malloc(4096);

    HGIC = "hgicf";
    if (buff == NULL) {
        printf("malloc fail\r\n");
        return -1;
    }

#if BELNC_EN
    hgic_blenc_init(); /* 支持微信小程序配网测试 | Just for Weixin applet*/
    hgic_blenc_rx_register(hgicf_recv_blenc_data);
#endif

__open:
    fd = open("/proc/hgicf/fwevnt", O_RDONLY);
    if (fd == -1) {
        //printf("open /proc/hgicf/fwevnt fail\r\n");
        sleep(1);
        goto __open;
    }

    //get firmware version
    hgic_iwpriv_get_fwinfo("hg0", &hgic_fwinfo);
    printf("fw version: %x\r\n", hgic_fwinfo.version);

    //read connection state
    ret = hgic_iwpriv_get_conn_state("hg0");
    printf("WiFi %s\r\n", (ret==9?"Connected":"Disconnect"));

    #if 0/*test: send customer mgmt frame.*/
    struct hgic_tx_info txinfo;
    char dest[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    char *custmgmt = "this is customer mgmt data";
    memset(&txinfo, 0, sizeof(txinfo));
    txinfo.tx_mcs = 0xff; //auto mcs
    txinfo.freq_idx = 1; //tx at channel 1
    hgic_iwpriv_send_custmgmt("hg0", dest, &txinfo, custmgmt, strlen(custmgmt));
    txinfo.freq_idx = 2; //tx at channel 2
    hgic_iwpriv_send_custmgmt("hg0", dest, &txinfo, custmgmt, strlen(custmgmt));
    txinfo.freq_idx = 3; //tx at channel 3
    hgic_iwpriv_send_custmgmt("hg0", dest, &txinfo, custmgmt, strlen(custmgmt));
    #endif

    #if BELNC_EN //BLE demo code for work mode 3.
    do {
        /*
           广播数据 和 扫描响应数据 的填充格式：[长度,类型,数据...]
           类型定义列表 请查阅文档《BLE_Assigned_Numbers.pdf》， 章节：2.3 Common Data Types.
           根据应用需求，可以修改或新增填充数据。

           Advertising_Data and Scan_Response Format: [length,Type,Data...]
           Document: BLE_Assigned_Numbers.pdf, Section 2.3,  Common Data Types.
           You can modify the data or add more data in adv_data and scan_resp.
        */

        /* 扫描响应数据 Scan_Response Data */
        u8 scan_resp[] = {
                          /*Length  Type   Data */
                            0x04,  0x09,  'S','S','S', /* the name is "SSS" */
                          /* type 0x09: Complete Local Name. document: Core_Specification_Supplement.pdf, Part A, Section 1.2 */
                          /* 类型 0x09: 设备名称. 查阅文档：Core_Specification_Supplement.pdf, Part A, Section 1.2               */

                          /*Length  Type   Data */
                            0x19,  0xFF,  0xD0,0x07,0x01,0x03,0x00,0x00,0x0C,0x00,0x88,0xD1,0xC4,0x89,0x2B,0x56,0x7D,0xE5,0x65,0xAC,0xA1,0x3F,0x09,0x1C,0x43,0x92
                          /* type 0xFF: Manufacturer Specific Data. */
                          /* 类型 0xFF: 厂家自定义数据. */
         };

        /* 广播数据 Advertising_Data */
        u8 adv_data[] = {
                        /*Length  Type   Data */
                          0x02,   0x01, 0x06,
                        /* type 0x01: Flags. document: Core_Specification_Supplement.pdf, Part A, Section 1.3 */
                        /* 类型 0x01: 广播标识，各个bit的含义请查阅文档：Core_Specification_Supplement.pdf, Part A, Section 1.3 */
                        /////////////////////////////////////////////////////////////////////////////////////

                        /*Length  Type   Data */
                          0x03,   0x02, 0x01,0xA2, /* uuid 0x2A01 */
                        /* type 0x02: Incomplete List of 16­bit Service Class UUIDs. document: Core_Specification_Supplement.pdf, Part A, Section 1.1 */
                        /* 类型 0x02: 16bit UUID列表：对应到ATT Table里面定义的UUID. 查阅文档: Core_Specification_Supplement.pdf, Part A, Section 1.1 */
                        /////////////////////////////////////////////////////////////////////////////////////

                        /*Length  Type   Data */
                          0x14,   0x16, 0x01,0xA2,0x01,0x6B,0x65,0x79,0x79,0x66,0x67,0x35,0x79,0x33,0x34,0x79,0x71,0x78,0x71,0x67,0x64
                        /* type 0x16: Service Data - 16 bit UUID. document: Core_Specification_Supplement.pdf, Part A, Section 1.11 */
                        /* 类型 0x16:   16bit UUID的服务数据. 查阅文档: Core_Specification_Supplement.pdf, Part A, Section 1.11 */
                        /////////////////////////////////////////////////////////////////////////////////////
          };

        /*设置广播数据 |       Config the Advertising Data*/
        hgic_iwpriv_blenc_set_advdata("wlan0", adv_data, sizeof(adv_data));

        /*设置扫描响应数据 |         Config the Scan Response Data*/
        hgic_iwpriv_blenc_set_scanresp("wlan0", scan_resp, sizeof(scan_resp));

        /* 打开广播功能 |       Enable Advertising Function */
        hgic_iwpriv_blenc_start_adv("wlan0", 1);

        /* 启动进入BLE模式3 |       Start BLE with work mode 3*/
        //hgic_iwpriv_blenc_start("wlan0", 3, 38); //start BLE MODE 3

        /* 停止退出BLE模式 | Stop BLE */
        //hgic_iwpriv_blenc_start("wlan0", 0, 38); //stop BLE
    } while (0);
    #endif

    hdr = (struct hgic_hdr *)buff;
    while (1) {
        ret = read(fd, buff, 4096);
        if (ret > 0) {
            switch (hdr->type) {
                case HGIC_HDR_TYPE_EVENT:
                case HGIC_HDR_TYPE_EVENT2:
                    hgicf_fwevent_parse(buff, ret);
                    break;
                #if BELNC_EN
                case HGIC_HDR_TYPE_BLUETOOTH:
                    hgic_proc_bt_data(buff, ret);
                    break;
                #endif
                default:
                    printf("unknown hdr type:%d\r\n", hdr->type);
                    break;
            }

        } else if (ret == 0) { //no data and timeout.
            #if 1 //BLE Notify test code
            hgic_gatt_notify_test();
            #endif
        }else { // read error.
            close(fd);
            printf("read error, ret=%d\r\n", ret);
            goto __open;
        }
    }

    close(fd);
    free(buff);
    return 0;
}
