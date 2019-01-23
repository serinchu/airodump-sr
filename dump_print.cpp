//#include "dump_print.h"

//static int save_line_num = 5;
//static int line_num = 5;
///*
//void print_ap() {
//    map_mutex.lock();
//    for(auto e = map_ap.cbegin(); e != map_ap.cend(); ++e) {
//        line_num ++;

//        //bssid
//        fprintf(stdout, " %.2X:%.2X:%.2X:%.2X:%.2X:%.2X ",
//                e->first.mac[0], e->first.mac[1], e->first.mac[2],
//                e->first.mac[3], e->first.mac[4], e->first.mac[5]);

//        //pwr
//        fprintf(stdout, " %.3d ", e->second->pwr);

//        //beacons
//        fprintf(stdout, " %.7d ", e->second->beacons);

//        //datas
//        fprintf(stdout, "   %.5d ", e->second->datas);

//        //psec
//        fprintf(stdout, " %.3d ", e->second->psec);

//        //channel
//        fprintf(stdout, " %.2d ", e->second->channel);

//        //enc
//        fprintf(stdout, " %.4s", e->second->enc.c_str());

//        //cipher
//        fprintf(stdout, " %.5s", e->second->cipher.c_str());

//        //auth
//        fprintf(stdout, " %.4s", e->second->auth.c_str());

//        //ssid
//        fprintf(stdout, " %s\n", e->second->SSID.c_str());


//    }
//    map_mutex.unlock();
//usleep(300000);
//}
//*/
//void ThreadMain() {

//    int num=0;

//    fprintf(stdout,"\033[2J\033[1;1H");

//    while(1) {
//        //show details
//        fprintf(stdout, " CH %.2d ]", bg_chans[num%15]);
//        fprintf(stdout, "\n");

//        //show aps
//        fprintf(stdout, "%s\n", show_APs);
//        //print_ap();
//        fprintf(stdout, "\n");
//        //show stations
//        fprintf(stdout, "%s\n", show_STATIONs);

//        fprintf(stdout, "\n");

//        fprintf(stdout, "\033[%dA",line_num);
//        line_num = save_line_num;

//        num++;
//    }

//}
