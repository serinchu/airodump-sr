#include "config.h"
#include "dot11.h"

int set_wireless_iface_channel(const char* if_name, const unsigned char channel) {
    int sd;
    struct iwreq wrq;

    if(if_name == NULL || channel == 0)
        return -1;

    memset(&wrq, 0, sizeof(wrq));
    strncpy(wrq.ifr_name, if_name, IFNAMSIZ);

    if((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        return -1;

    wrq.u.freq.m = channel;

    if(ioctl(sd, SIOCSIWFREQ, &wrq) != -1)
    {
        close(sd);
        return 0;
    }

    close(sd);
    return -1;
}

/////////////////////////////////////////////////////////////////////////////////
void channel_hopping(const char *if_name) {

    int channel = 0;
    while(1) {
        set_wireless_iface_channel(if_name, bg_chans[channel]);

        usleep(300000);
        channel = (channel+1)%13;
    }
}

/////////////////////////////////////////////////////////////////////////////////
const char *print_wireless_if() {
    int num = 0;
    int sock = -1;

    struct ifaddrs *addrs,*tmp;
    struct iwreq pwrq;
    std::string *if_name = new std::string[10];
    getifaddrs(&addrs);
    tmp = addrs;

    while (tmp) {
        char protocol[IFNAMSIZ]  = {0};

        if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_PACKET) {
            memset(&pwrq, 0, sizeof(pwrq));
            strncpy(pwrq.ifr_name, tmp->ifa_name, IFNAMSIZ);

            if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
                perror("socket");
                exit(-1);
            }
            if (ioctl(sock, SIOCGIWNAME, &pwrq) != -1) {
                strncpy(protocol, pwrq.u.name, IFNAMSIZ);
                if_name[num].append(tmp->ifa_name);
                printf( "[%d]%s (%s)", ++num, tmp->ifa_name, protocol);
            }
            if(ioctl(sock, SIOCGIWMODE, &pwrq) != -1) {
                switch(pwrq.u.mode)
                {
                case IW_MODE_AUTO:
                    printf("-AUTO\n");
                    break;
                case IW_MODE_ADHOC:
                    printf("-ADHOC\n");
                    break;
                case IW_MODE_INFRA:
                    printf("-INFRA\n");
                    break;
                case IW_MODE_MASTER:
                    printf("-MASTER\n");
                    break;
                case IW_MODE_REPEAT:
                    printf("-REPEAT\n");
                    break;
                case IW_MODE_SECOND:
                    printf("-SECOND\n");
                    break;
                case IW_MODE_MONITOR:
                    printf("-MONITOR\n");
                    break;
                case IW_MODE_MESH:
                    printf("-MESH\n");
                    break;
                default:
                    close(sock);
                }
            }
            close(sock);
        }
        tmp = tmp->ifa_next;
    }

    freeifaddrs(addrs);

    if(num == 0) {
        printf("No available interface to monitor\n\n");
        exit(0);
    }
    printf("Select interface [1~%d]  ", num);

    int input;
    std::cin >> input;
    while (std::cin.fail() || input < 1 || input > num) {
        std::cin.clear();
        std::cin.ignore();
        std::cout << "Not a valid number. Please reenter: ";
        std::cin >> input;
    }
//    std::cout << if_name[input - 1] << std::endl;
    return if_name[input-1].c_str();
}

/////////////////////////////////////////////////////////////////////////////////
int main() {  

    const char *if_name = new char[256];
    if_name = print_wireless_if();  //get list of wireless network interface

    std::thread channel_hopping_thread(channel_hopping, if_name);
    channel_hopping_thread.detach();

    std::thread print_thread(ViewThread);
    print_thread.detach();

    listen_wlan(if_name);

    return 0;
}
