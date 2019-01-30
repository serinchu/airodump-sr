#include "config.h"
#include "radiotap.h"


int8_t get_pwr_from_radiotap(radiotap_h *rt_h) {

    uint offset = 0;
    int8_t ret = -1;

    if(rt_h->len > sizeof(radiotap_h))
        offset += sizeof(uint32_t);
    else ret;

    int8_t *pkt_ptr = (int8_t *)rt_h + sizeof(uint32_t);
    uint32_t present_field, present_type;

    do {
        if(offset != 4)
            pkt_ptr += sizeof(uint32_t);
        offset += sizeof(uint32_t);
    } while((*(uint32_t *)pkt_ptr) >> 31);

    for(int i = (offset-4)/4 - 1; i >=0; i--) {
        present_field = *((uint32_t *)pkt_ptr - i);
        present_type = 0;

        while(present_field && (present_type <= IEEE80211_RADIOTAP_TIMESTAMP)) {
            if((present_field & 0x1) == 1) {
                if(present_type == IEEE80211_RADIOTAP_DBM_ANTSIGNAL)
                    ret = *((int8_t *)rt_h + offset);

                uint tmp = offset % rtap_namespace_sizes[present_type].align;
                if(tmp)
                    offset += (rtap_namespace_sizes[present_type].align - tmp);
                offset += rtap_namespace_sizes[present_type].size;
            }
            present_field = present_field >> 1;
            present_type += 1;
        }
    }
    return ret;
}
