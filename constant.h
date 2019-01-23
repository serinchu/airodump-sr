#ifndef CONSTANT_H
#define CONSTANT_H

#define DEBUG 0
#define SETFILTER 0

#define ADDR_LEN 6


static const int bg_chans[]
    = {1, 7, 13, 2, 8, 3, 9, 4, 10, 5, 11, 6, 12};

static const char* show_APs
    = " BSSID              PWR  Beacons    #Data  #/s  CH  MB   ENC  CIPHER AUTH ESSID";
//    = " BSSID              PWR  Beacons    #Data  #/s  CH  ENC  CIPHER AUTH ESSID";
static const char* show_STATIONs
    = " BSSID              STATION            PWR  Frames  Probes";
//= " BSSID              STATION            PWR   Rate    Lost    Frames  Probes";

#endif // CONSTANT_H
