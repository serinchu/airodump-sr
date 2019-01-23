#include "dot11.h"
#include "radiotap.h"

std::map<MAC, ap_info *> map_ap;
std::map<MAC, st_info *> map_st;
std::mutex map_mutex;

static int save_line_num = 5;
static int line_num = 5;
static uint32_t dot11_len;

static MAC broadcast = {0xff,0xff,0xff,0xff,0xff,0xff};
static MAC zero = {0,0,0,0,0,0};

static handshake *handshake_box;

void print_ap() {

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
        fprintf(stdout, " %3d ", e->second->psec);

        //channel
        fprintf(stdout, " %2d ", e->second->channel);

        //mb
        fprintf(stdout, " %2de ", e->second->mb);

        //enc
        fprintf(stdout, " %4s", e->second->enc.c_str());

        //cipher
        fprintf(stdout, " %5s", e->second->cipher.c_str());

        //auth
        fprintf(stdout, " %4s", e->second->auth.c_str());

        //ssid
        fprintf(stdout, "  %s\n", e->second->SSID.c_str());
    }
}

/////////////////////////////////////////////////////////////////////////////////
void print_st() {

    fprintf(stdout, "%s\n", show_STATIONs);

    for(auto e = map_st.cbegin(); e != map_st.cend(); ++e) {
        line_num ++;

        //bssid
        if(e->second->bssid == zero)
            fprintf(stdout, " (not associated) ");
        else print_mac(&e->second->bssid);

        //station
        print_mac(&e->first);

        //pwr
        fprintf(stdout, "  %3d ", e->second->pwr);

        //frames
        fprintf(stdout, "  %5d ", e->second->frames);

        //probe
        fprintf(stdout, " %6s\n", e->second->probe.c_str());
    }
}

/////////////////////////////////////////////////////////////////////////////////
void ThreadMain() {

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
        fprintf(stdout, " CH %.2d ]", bg_chans[num%13]);
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
        print_ap();

        //show stations
        print_st();
        map_mutex.unlock();
        usleep(300000);

        fprintf(stdout, "\n");

        fprintf(stdout, "\033[%dA",line_num);

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
void listen_wlan(char *if_name) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(if_name, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
            fprintf(stderr, "couldn't open device %s: %s\n", if_name, errbuf);
            exit(-1);
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

            //Parsing PWR of signal

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
    uint8_t *tagged_parameter, tagged_len, jump_len = 0;

    //fixed parameters jump and get tagged parameters!(SSID, MB, CH, RSN)
    //management => 24...
    tagged_parameter = ((uint8_t *)dot11_hdr + sizeof(dot11_h) + mgmt_fixed_parameter_len[subtype]);
    tagged_len = dot11_len - sizeof(dot11_h) - mgmt_fixed_parameter_len[subtype];

    while(tagged_len) {
//            for(int i = 0; i < tagged_len ; i++)
//                printf("%.2X ", tagged_parameter[i]);
        jump_len = 2 + tagged_parameter[1];

        tagged_len -= jump_len;
        switch(tagged_parameter[0]) {
        case p_SSID:
            // 0 len SSID



            break;
        case p_MB:
            // 1 len n...(last one is fastest speed)
            //

            break;

        case p_DS:
            // 3 len (channel)
            g_channel = tagged_parameter[2];
            break;

        case p_EXT_MB:
            // 50 len n...(last one is fastest speed)
            break;
        case p_RSNA:
            // 48 len version(2) ...
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

            auto e1 = map_st.insert(std::make_pair(dot11_hdr->addr1, nullptr));
            if(e1.second) {
                st_info *new_st_info = new st_info;
                e1.first->second = new_st_info;
            }
            e1.first->second->frames += 1;

            if(!(dot11_hdr->addr2 == broadcast)) {     //station know about AP
                auto e2 = map_ap.insert(std::make_pair(dot11_hdr->addr2, nullptr));
                if(e2.second) {
                    ap_info *new_ap_info = new ap_info;
                    e2.first->second = new_ap_info;
                }

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

        //must ap info added
        auto e2 = map_ap.insert(std::make_pair(dot11_hdr->addr1, nullptr));
        if(e2.second) {
            ap_info *new_ap_info = new ap_info;
            e2.first->second = new_ap_info;
        }
        if(nodata_bit != 4)
            e2.first->second->datas += 1;
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
        if(nodata_bit != 4)
            e1.first->second->datas += 1;

        if(!(dot11_hdr->addr1 == broadcast)) {
            auto e2 = map_st.insert(std::make_pair(dot11_hdr->addr1, nullptr));
            if(e2.second) {
                st_info *new_st_info = new st_info;
                e2.first->second = new_st_info;
            }
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
