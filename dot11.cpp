#include "dot11.h"
#include "radiotap.h"

std::map<MAC, ap_info *> map_ap;
std::map<MAC, st_info *> map_st;
std::mutex map_mutex;

static int save_line_num = 6;
static int line_num = 6;
static uint32_t dot11_len;

static MAC broadcast = {0xff,0xff,0xff,0xff,0xff,0xff};
static MAC zero = {0,0,0,0,0,0};

static handshake *handshake_box;

void print_ap(uint8_t timer) {

    fprintf(stdout, "%s\n", show_APs);

    for(auto e = map_ap.cbegin(); e != map_ap.cend(); ++e) {
        line_num ++;

        //bssid
        print_mac(&e->first);

        //pwr
        fprintf(stdout, " %3d ", e->second->pwr);

        //beacons
        fprintf(stdout, " %7d ", e->second->beacons);

        //datas
        fprintf(stdout, "   %5d ", e->second->datas);

        //psec
        fprintf(stdout, " %3d ", e->second->psec_datas / timer);
        if(timer == 10)
            e->second->psec_datas = 0;

        //channel
        fprintf(stdout, " %2d ", e->second->channel);

        //mb
        fprintf(stdout, " %4s", MB_supported_rate[e->second->mb].rate.c_str());

        //enc
        fprintf(stdout, " %4s", e->second->enc.c_str());

        //cipher
        fprintf(stdout, " %5s", e->second->cipher.c_str());

        //auth
        fprintf(stdout, " %4s", e->second->auth.c_str());

        //ssid
        fprintf(stdout, "  %-16s\n", e->second->SSID.c_str());
    }
}

/////////////////////////////////////////////////////////////////////////////////
void print_st() {

    fprintf(stdout, "%s\n", show_STATIONs);

    for(auto e = map_st.cbegin(); e != map_st.cend(); ++e) {
        line_num ++;

        //bssid
        if(e->second->bssid == zero)
            fprintf(stdout, " (not associated)  ");
        else print_mac(&e->second->bssid);

        //station
        print_mac(&e->first);

        //pwr
        fprintf(stdout, "  %3d ", e->second->pwr);

        //frames
        fprintf(stdout, "  %5d ", e->second->frames);

        //probe
        fprintf(stdout, " %-16s\n", e->second->probe.c_str());
    }
}

/////////////////////////////////////////////////////////////////////////////////
void ViewThread() {

    int num=0;

    auto start = std::chrono::system_clock::now();
    auto end = std::chrono::system_clock::now();

    std::chrono::duration<double> elapsed_seconds = end-start;
    std::time_t end_time = std::chrono::system_clock::to_time_t(end);

    fprintf(stdout,"\033[2J\033[1;1H");

    while(1) {
        end = std::chrono::system_clock::now();
        elapsed_seconds = end-start;
        end_time = std::chrono::system_clock::to_time_t(end);

        //show details
        fprintf(stdout, "\n CH %.2d ]", bg_chans[num%13]);
        if(handshake_box != nullptr && handshake_box->num >= 2) {
            fprintf(stdout, "[ WPA handshake ");
            print_mac(&handshake_box->ap_mac);
            fprintf(stdout, "]");
        }
        fprintf(stdout, "[ Elapsed : %ds ]", (uint16_t)elapsed_seconds.count());
        fprintf(stdout, "[ %s ",std::ctime(&end_time));
        fprintf(stdout, "\n");

        //show aps
        map_mutex.try_lock();
        print_ap((uint16_t)elapsed_seconds.count() % 10 + 1);

        //show stations
        print_st();
        map_mutex.unlock();
        usleep(300000);

        for(int i=0; i<line_num; i++)
            printf("\033[A\033[2K\r");
        line_num = save_line_num;

        num++;
    }
}

/////////////////////////////////////////////////////////////////////////////////
void print_mac(const MAC *mac_addr) {
            fprintf(stdout," %.2X:%.2X:%.2X:%.2X:%.2X:%.2X ",
             mac_addr->mac[0], mac_addr->mac[1], mac_addr->mac[2],
                   mac_addr->mac[3], mac_addr->mac[4], mac_addr->mac[5]);
}

/////////////////////////////////////////////////////////////////////////////////
void listen_wlan(const char *if_name) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(if_name, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
            fprintf(stderr, "couldn't open device %s: %s\n", if_name, errbuf);
            exit(-1);
    }
    if( pcap_set_rfmon(handle, 13) == 0 ) {
        //monitor mode enabled
    }
#if SETFILTER
    char *filter = "(radio[0] | radio[1]) == 0";
    struct bpf_program fp;
    bpf_u_int32 netp;


    if(pcap_compile(handle,&fp,filter,0,netp) == -1) { // -1 means failed
            fprintf(stderr,"Error compiling Libpcap filter, %s\n",filter);
            exit(-1);
    }
    if(pcap_setfilter(handle,&fp) == -1) { // -1 means failed - but we don't exit(1)
            fprintf(stderr,"Error setting Libpcap filter, %s\n",filter); // same as above
            exit(-1);
    }
#endif

    while(1) {
        struct pcap_pkthdr* header;
        const u_char* packet;

        int res = pcap_next_ex(handle, &header, &packet);
        if(res == 0)
            continue;
        if(res == -1 || res == -2)
            break;
        if(packet[0] == 0 && packet[1] == 0) {

            //radiotap
            radiotap_h *radiotap_hdr = (radiotap_h *)packet;

#if DEBUG
            for (int i = 0; i < header->len; ++i) {
                printf(" %02X", packet[i]);
                if ((i + 1) % 0x10 == 0)
                    printf("\n");
                else if ((i + 1) % 8 == 0)
                    printf(" ");
            }
//            printf("(%d)\n", radiotap_hdr->len);
#endif
            g_pwr = get_pwr_from_radiotap(radiotap_hdr);

            dot11_h *dot11_hdr = (dot11_h *)((uint8_t *)radiotap_hdr + radiotap_hdr->len);
            dot11_len = header->caplen - radiotap_hdr->len;

            switch(((dot11_hdr->fc) & 0x8) >> 2) {
            case MGMT:
                process_management_frame(dot11_hdr);
                break;
            case DATA:
                process_data_frame(dot11_hdr);
                break;
            case CTL:
            default:
                break;
            }
        }
    }
}

/////////////////////////////////////////////////////////////////////////////////
void process_management_frame(dot11_h *dot11_hdr) {

    uint8_t subtype = (dot11_hdr->fc & 0xf0)>>4;
    uint8_t *tagged_parameter;
    uint8_t tagged_len, jump_len = 0, param_len;

    //fixed parameters jump and get tagged parameters!(SSID, MB, CH, RSN)
    //management => 24...
    tagged_parameter = ((uint8_t *)dot11_hdr + sizeof(dot11_h) + mgmt_fixed_parameter_len[subtype]);
    tagged_len = dot11_len - sizeof(dot11_h) - mgmt_fixed_parameter_len[subtype];

    g_channel = 0;
    g_mb = 0;
    g_enc = "";
    g_cipher = "";
    g_auth = "";
    g_SSID.len = 0; g_SSID.essid = "";

    while(tagged_len) {
        int offset = 2; // type | length
        uint16_t cnt;
        param_len = tagged_parameter[1];
        jump_len = 2 + param_len;

        tagged_len -= jump_len;
        switch(tagged_parameter[0]) {
        case p_SSID:
            // 0 len SSID
            g_SSID.len = param_len;
            if(param_len == 0) { //wildcard ssid
                g_SSID.essid = "<length: 0>";
                break;
            }
            for(int j=0; j<param_len; j++)
                g_SSID.essid.append(1,tagged_parameter[offset+j]);

            break;
        case p_MB:
            // 1 len n...(last one is fastest speed)
            for(uint8_t i=1; i < sizeof(MB_supported_rate)/sizeof(struct mb); i++)
                if(tagged_parameter[offset+param_len-1] == MB_supported_rate[i].hex_val)
                    g_mb = i;

            break;
        case p_DS:
            // 3 len (channel)
            g_channel = tagged_parameter[offset];
            break;
        case p_EXT_MB:
            // 50 len n...(last one is fastest speed)
            for(uint8_t i=1; i < sizeof(MB_supported_rate)/sizeof(struct mb); i++)
                if(tagged_parameter[offset+param_len-1] == MB_supported_rate[i].hex_val && g_mb <i)
                    g_mb = i;

            break;
        case p_RSNA:
            // 48 len version(2) ...
            param_len -= 2; //version
            offset += 2;

            if (tagged_parameter[offset] == 0x0 && tagged_parameter[offset + 1] == 0xf
                    && tagged_parameter[offset + 2] == 0xac) {
                offset += 3;
                switch(tagged_parameter[offset]) {
                case GROUP_CIPHER_SUITE:
                    g_cipher.append("GCS");
                    g_enc.append("GCS");
                    break;
                case WEP40:
                    g_cipher.append("WEP40");
                    g_enc.append("WEP");
                    break;
                case TKIP:
                    g_cipher.append("TKIP");
                    g_enc.append("WPA");
                    break;
                case CRESERVED:
                    break;
                case CCMP:
                    g_cipher.append("CCMP");
                    g_enc.append("WPA");
                    break;
                case WEP104:
                    g_cipher.append("WEP104");
                    g_enc.append("WEP");
                    break;
                default:
                    break;
                }
                offset += 1;
                param_len -= 4;
            }else
                break;

            if(param_len <= 0) break;

            //pairwise cipher suite count
            cnt = tagged_parameter[offset];
            offset += (2 + cnt*4);
            //auth key management list count
            cnt = tagged_parameter[offset];
            offset += (2 + 3);

            switch(tagged_parameter[offset]) {
            case ARESERVED:
                break;
            case DOT1X_AUTH:
                g_auth.append(".1x");
                break;
            case PSK:
                g_auth.append("PSK");
                break;
            default:
                break;
            }

            break;

        default:
            break;
        }
        tagged_parameter += jump_len;
    }

    map_mutex.try_lock();
    if((dot11_hdr->fc & 0x300)>>8 == 0) { //ToDS =0 FromDS =0
        if(dot11_hdr->addr1 == dot11_hdr->addr3) {
            //show ap & st
            auto e1 = map_st.insert(std::make_pair(dot11_hdr->addr2, nullptr));
            if(e1.second) {
                st_info *new_st_info = new st_info;
                e1.first->second = new_st_info;
            }
            e1.first->second->pwr = g_pwr;
            e1.first->second->frames += 1;
            if(subtype == PROBE_REQ && g_SSID.len)
                e1.first->second->probe = g_SSID.essid;

            if(!(dot11_hdr->addr1 == broadcast)) {     //station know about AP
                auto e2 = map_ap.insert(std::make_pair(dot11_hdr->addr1, nullptr));
                if(e2.second) {
                    ap_info *new_ap_info = new ap_info;
                    e2.first->second = new_ap_info;
                }
                e1.first->second->bssid = dot11_hdr->addr2;
                e2.first->second->pwr = g_pwr;
                if(g_channel != 0)
                    e2.first->second->channel = g_channel;
                if(g_mb != 0)
                    e2.first->second->mb = g_mb;
                if(subtype == ASSOCI_REQ || subtype == REASSOCI_REQ) {
                    if(g_enc.empty()) {
                        e2.first->second->enc = "OPN";
                        e2.first->second->cipher = "";
                        e2.first->second->auth = "";
                     } else {
                        e2.first->second->enc = g_enc;
                        e2.first->second->cipher = g_cipher;
                        e2.first->second->auth = g_auth;
                    }
                }
                if(g_SSID.len)
                    e2.first->second->SSID = g_SSID.essid;
            }

        } else if(dot11_hdr->addr2 == dot11_hdr->addr3) {
            //show ap
            auto e1 = map_ap.insert(std::make_pair(dot11_hdr->addr3, nullptr));
            if(e1.second) {
                ap_info *new_ap_info = new ap_info;
                e1.first->second = new_ap_info;
            }

            if(subtype == BEACON)
                e1.first->second->beacons += 1;
            e1.first->second->pwr = g_pwr;
            if(g_channel != 0)
                e1.first->second->channel = g_channel;
            if(g_mb != 0)
                e1.first->second->mb = g_mb;
            if(g_SSID.len)
                e1.first->second->SSID = g_SSID.essid;
            if((subtype == PROBE_RES || subtype == BEACON)) {
                if(g_enc.empty()) {
                    e1.first->second->enc = "OPN";
                    e1.first->second->cipher = "";
                    e1.first->second->auth = "";
                } else {
                    e1.first->second->enc = g_enc;
                    e1.first->second->cipher = g_cipher;
                    e1.first->second->auth = g_auth;
                }
            }
        }

    } else {
        //generally, Management frame 's DS set is 00
    }

    map_mutex.unlock();
    usleep(30000);
    return ;

}

void process_data_frame(dot11_h *dot11_hdr) {

    uint8_t subtype = (dot11_hdr->fc & 0xf0)>>4;
    uint8_t ds_bits = (dot11_hdr->fc & 0x300)>>8;
    uint8_t nodata_bit = (dot11_hdr->fc & 0x40)>>4;

    map_mutex.try_lock();
    if(ds_bits == 0) {           //ToDS =0 FromDS =0
        //ad-hoc
    } else if (ds_bits == 1) {   //ToDS =1 FromDS =0

        //no data => no count
        auto e1 = map_st.insert(std::make_pair(dot11_hdr->addr2, nullptr));
        if(e1.second) {
            st_info *new_st_info = new st_info;
            e1.first->second = new_st_info;
        }
        e1.first->second->frames += 1;
        e1.first->second->bssid = dot11_hdr->addr1;
        //must ap info added
        auto e2 = map_ap.insert(std::make_pair(dot11_hdr->addr1, nullptr));
        if(e2.second) {
            ap_info *new_ap_info = new ap_info;
            e2.first->second = new_ap_info;
        }
        if(nodata_bit != 4) {
            e2.first->second->datas += 1;
            e2.first->second->psec_datas += 1;
        }
        //association.. auth... => ESSID, channel,

        if(subtype == QoS_DATA && (dot11_hdr->fc & 0x4000)>>12 != 4) {
            llc_h *llc = (llc_h *)((uint8_t *)dot11_hdr + 26);
            if(llc->type == 0x8e88) {
                handshaking_h *h = (handshaking_h *)((uint8_t *)llc + sizeof(llc_h));
                if(h->version == 1 && h->type == 3
                        && (handshake_box->ap_mac == dot11_hdr->addr1)
                        && (handshake_box->st_mac == dot11_hdr->addr2)) {
                    if(handshake_box->num == 1)
                        handshake_box->num = 2;
                }
            }
        }

    } else if (ds_bits == 2) {   //ToDS = 0 FromDS =1
        //
        //no data isn't exist! but.. check it again

        auto e1 = map_ap.insert(std::make_pair(dot11_hdr->addr2, nullptr));
        if(e1.second) {
            ap_info *new_ap_info = new ap_info;
            e1.first->second = new_ap_info;
        }
        if(nodata_bit != 4) {
            e1.first->second->datas += 1;
            e1.first->second->psec_datas += 1;
        }
        if(!(dot11_hdr->addr1 == broadcast)) {
            auto e2 = map_st.insert(std::make_pair(dot11_hdr->addr1, nullptr));
            if(e2.second) {
                st_info *new_st_info = new st_info;
                e2.first->second = new_st_info;
            }
            e2.first->second->bssid = dot11_hdr->addr2;
            e2.first->second->frames += 1;
        }

        if(subtype == QoS_DATA && (dot11_hdr->fc & 0x4000)>>12 != 4) {

            llc_h *llc = (llc_h *)((uint8_t *)dot11_hdr + 26);
            if(llc->type == 0x8e88) {
                handshaking_h *h = (handshaking_h *)((uint8_t *)llc + sizeof(llc_h));
                if(h->version == 1 && h->type == 3 && (handshake_box == nullptr)) {
                    handshake_box = new handshake;
                    handshake_box->ap_mac = dot11_hdr->addr2;
                    handshake_box->st_mac = dot11_hdr->addr1;
                    handshake_box->num = 1;
                }
            }
        }

    } else {
        //WDS wireless bridge
    }

    map_mutex.unlock();
    usleep(30000);
    return ;
}
