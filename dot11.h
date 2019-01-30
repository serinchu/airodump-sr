#ifndef DOT11_H
#define DOT11_H

#include "config.h"

typedef struct _MAC{
    uint8_t mac[ADDR_LEN];

    bool operator == (const _MAC bssid) {
        for(int i=0; i<ADDR_LEN; i++)
            if(this->mac[i] != bssid.mac[i])
                return false;

        return true;
    }

    bool operator < (const _MAC bssid) const {
        for(int i=0; i<ADDR_LEN; i++)
            if(this->mac[i] > bssid.mac[i]) return false;
            else if(this->mac[i] < bssid.mac[i]) return true;

        return false;
    }
}MAC;

static int8_t g_pwr;
static uint8_t g_channel;
static uint8_t g_mb;
static std::string g_enc;
static std::string g_cipher;
static std::string g_auth;

struct ssid{
    uint8_t len;
    std::string essid;
};
static struct ssid g_SSID;

#pragma pack(push,1)

typedef struct {
    int8_t pwr = 0;
    uint16_t beacons = 0;
    uint16_t datas = 0;
    uint8_t psec_datas = 0;
    uint8_t channel = 0;
    uint8_t mb = 0;
    std::string enc = std::string("");
    std::string cipher = std::string("");
    std::string auth = std::string("");
    std::string SSID = std::string("");
} ap_info;

typedef struct {
    MAC bssid = {0,};
    int8_t pwr = 0;
    uint16_t frames = 0;
    std::string probe = std::string("");
} st_info;

typedef struct _dot11_h {
    uint16_t fc;    //frame control bit
    uint16_t dur;   //duration
    MAC  addr1;
    MAC  addr2;
    MAC  addr3;
    uint16_t seq_frag_num;
} dot11_h;

typedef struct {
    uint8_t dsap;
    uint8_t ssap;
    uint8_t control_field;
    uint8_t organization_code[3];
    uint16_t type;
} llc_h;

typedef struct {
    uint8_t version;
    uint8_t type;
} handshaking_h;
#pragma pack(pop)

typedef struct {
    MAC ap_mac;
    MAC st_mac;
    uint8_t num = 0;
} handshake;

enum {
    MGMT,
    CTL,
    DATA,
} type;

enum {
    ASSOCI_REQ,
    ASSOCI_RES,
    REASSOCI_REQ,
    REASSOCI_RES,
    PROBE_REQ,
    PROBE_RES,
    BEACON = 8,
    ATI,
    DISASSOCI,
    AUTH,
    DEAUTH,
    ACTION,
} mgmt_subtype;

const int mgmt_fixed_parameter_len[14] = {
  4, 6, 10, 6, 0, 12, 0, 0, 12, 0, 2, 6, 2, 9
};

struct mb {
    std::string rate;
    uint8_t hex_val;
};

const struct mb MB_supported_rate[] = {
    {  "  ",    0 },
    {  "1b", 0x82 },
    {  "2b", 0x84 },
    {"5.5b", 0x8b },
    { "11b", 0x96 },
    //HR-DSSS 802.11b
    {   "1", 0x02 },
    {   "2", 0x04 },
    { "5.5", 0x0b },
    {  "11", 0x16 },
    {   "6", 0x0c },
    {   "9", 0x12 },
    {  "12", 0x18 },
    {  "18", 0x24 },
    {  "24", 0x30 },
    {  "36", 0x48 },
    {  "48", 0x60 },
    { "54e", 0x6c },
    //ERP-OFDM 802.11g
};

enum {
    DATA_ONLY,
    DATA_CF_ACK,
    DATA_CF_POLL,
    DATA_CF_ACK_POLL,
    DATA_NULL,      //no data
    CF_ACK,         //no data
    CF_POLL,        //no data
    CF_ACK_POLL,    //no data

    QoS_DATA,
    QoS_DATA_CF_ACK,
    QoS_DATA_CF_POLL,
    QoS_DATA_CF_ACK_POLL,
    QoS_NULL,       //no data
    QoS_CF_POLL = 14,    //no data
    QoS_CF_ACK_POLL,//no data
} data_subtype;

enum {
    p_SSID,
    p_MB,
    p_FF,
    p_DS,
    p_CF,
    p_TIM,
    p_IBSS,
    p_CC,           //country code
    p_HP,           //hoping pattern
    p_HPT,          //hoping pattern table
    p_REQ,

    p_BSSL = 11,    //BSS Load

    p_CHALLENGE = 16,
    p_PC,           //power constraint

    p_TCP = 35,     //TCP report

    p_RSNA = 48,    //robust security network association

    p_EXT_MB = 50,  //extended supported rate
    p_AP_CHAN,      //AP channel report

    p_MOBIL = 54,   //Mobility Domain

    p_VHT   = 61,   //VHT operation information

    p_VHT_C = 191,  //VHT capability
    p_VHT_O = 192,  //VHT operation element
    p_VHT_T = 195,  //VHT transmit power envelop

    p_VS = 221,     //vendor specific element
} tagged_params;

enum {
    GROUP_CIPHER_SUITE,
    WEP40,
    TKIP,
    CRESERVED,
    CCMP,
    WEP104
};

enum {
    ARESERVED,
    DOT1X_AUTH,
    PSK
};

void print_ap(uint8_t);
void print_st();
void ViewThread();

void print_mac(const MAC *);

void listen_wlan(const char *);
void process_management_frame(dot11_h *);
void process_data_frame(dot11_h *);

#endif // DOT11_H
