#ifndef RADIOTAP_H
#define RADIOTAP_H

//https://github.com/radiotap/radiotap-library/blob/master/radiotap.h

#include "config.h"

enum ieee80211_radiotap_presence {
    IEEE80211_RADIOTAP_TSFT = 0,
    IEEE80211_RADIOTAP_FLAGS = 1,
    IEEE80211_RADIOTAP_RATE = 2,
    IEEE80211_RADIOTAP_CHANNEL = 3,
    IEEE80211_RADIOTAP_FHSS = 4,
    IEEE80211_RADIOTAP_DBM_ANTSIGNAL = 5,
    IEEE80211_RADIOTAP_DBM_ANTNOISE = 6,
    IEEE80211_RADIOTAP_LOCK_QUALITY = 7,
    IEEE80211_RADIOTAP_TX_ATTENUATION = 8,
    IEEE80211_RADIOTAP_DB_TX_ATTENUATION = 9,
    IEEE80211_RADIOTAP_DBM_TX_POWER = 10,
    IEEE80211_RADIOTAP_ANTENNA = 11,
    IEEE80211_RADIOTAP_DB_ANTSIGNAL = 12,
    IEEE80211_RADIOTAP_DB_ANTNOISE = 13,
    IEEE80211_RADIOTAP_RX_FLAGS = 14,
    IEEE80211_RADIOTAP_TX_FLAGS = 15,
    IEEE80211_RADIOTAP_RTS_RETRIES = 16,
    IEEE80211_RADIOTAP_DATA_RETRIES = 17,
    /* 18 is XChannel, but it's not defined yet */
    IEEE80211_RADIOTAP_MCS = 19,
    IEEE80211_RADIOTAP_AMPDU_STATUS = 20,
    IEEE80211_RADIOTAP_VHT = 21,
    IEEE80211_RADIOTAP_TIMESTAMP = 22,

    /* valid in every it_present bitmap, even vendor namespaces */
    IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE = 29,
    IEEE80211_RADIOTAP_VENDOR_NAMESPACE = 30,
    IEEE80211_RADIOTAP_EXT = 31
};

struct radiotap_align_size {
    uint8_t align:4, size:4;
};


//const struct radiotap_align_size rtap_namespace_sizes[] = {
//    [IEEE80211_RADIOTAP_TSFT] = { .align = 8, .size = 8, },
//    [IEEE80211_RADIOTAP_FLAGS] = { .align = 1, .size = 1, },
//    [IEEE80211_RADIOTAP_RATE] = { .align = 1, .size = 1, },
//    [IEEE80211_RADIOTAP_CHANNEL] = { .align = 2, .size = 4, },
//    [IEEE80211_RADIOTAP_FHSS] = { .align = 2, .size = 2, },
//    [IEEE80211_RADIOTAP_DBM_ANTSIGNAL] = { .align = 1, .size = 1, },
//    [IEEE80211_RADIOTAP_DBM_ANTNOISE] = { .align = 1, .size = 1, },
//    [IEEE80211_RADIOTAP_LOCK_QUALITY] = { .align = 2, .size = 2, },
//    [IEEE80211_RADIOTAP_TX_ATTENUATION] = { .align = 2, .size = 2, },
//    [IEEE80211_RADIOTAP_DB_TX_ATTENUATION] = { .align = 2, .size = 2, },
//    [IEEE80211_RADIOTAP_DBM_TX_POWER] = { .align = 1, .size = 1, },
//    [IEEE80211_RADIOTAP_ANTENNA] = { .align = 1, .size = 1, },
//    [IEEE80211_RADIOTAP_DB_ANTSIGNAL] = { .align = 1, .size = 1, },
//    [IEEE80211_RADIOTAP_DB_ANTNOISE] = { .align = 1, .size = 1, },
//    [IEEE80211_RADIOTAP_RX_FLAGS] = { .align = 2, .size = 2, },
//    [IEEE80211_RADIOTAP_TX_FLAGS] = { .align = 2, .size = 2, },
//    [IEEE80211_RADIOTAP_RTS_RETRIES] = { .align = 1, .size = 1, },
//    [IEEE80211_RADIOTAP_DATA_RETRIES] = { .align = 1, .size = 1, },
//    [IEEE80211_RADIOTAP_MCS] = { .align = 1, .size = 3, },
//    [IEEE80211_RADIOTAP_AMPDU_STATUS] = { .align = 4, .size = 8, },
//    [IEEE80211_RADIOTAP_VHT] = { .align = 2, .size = 12, },
//    [IEEE80211_RADIOTAP_TIMESTAMP] = { .align = 8, .size = 12, },
//    /*
//     * add more here as they are defined in radiotap.h
//     */
//};

#endif // RADIOTAP_H
