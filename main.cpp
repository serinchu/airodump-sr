#include "config.h"
#include "dot11.h"

void print_wireless_if() {
    int num = 1;
    int sock = -1;

    struct ifaddrs *addrs,*tmp;
    struct iwreq pwrq;

    getifaddrs(&addrs);
    tmp = addrs;

    while (tmp) {
        char protocol[IFNAMSIZ]  = {0};

        if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_PACKET)
        {
            memset(&pwrq, 0, sizeof(pwrq));
            strncpy(pwrq.ifr_name, tmp->ifa_name, IFNAMSIZ);

            if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
                perror("socket");
                exit(-1);
            }

            if (ioctl(sock, SIOCGIWNAME, &pwrq) != -1) {
                strncpy(protocol, pwrq.u.name, IFNAMSIZ);
                close(sock);
                printf( "[%d]%s (%s)\n", num++, tmp->ifa_name, protocol);
            }

            close(sock);
        }
        tmp = tmp->ifa_next;
    }

    freeifaddrs(addrs);

    if(num == 1) {
        printf("No available interface to monitor\n\n");
        exit(0);
    }
    printf("Select interface [1~%d]  ", num - 1);


}

/////////////////////////////////////////////////////////////////////////////////
int main() {
    print_wireless_if();    //get list of wireless network interface

    char *if_name = new char[256];
    if(if_name == nullptr) {
        fprintf(stderr, "malloc error\n");
        return -1;
    }
    memset(if_name, 0, 256);

    fgets(if_name, 256, stdin);

    size_t len = strlen(if_name);

    if_name = (char *)realloc(if_name, sizeof(char) * len);
    if(if_name == nullptr) {
        fprintf(stderr, "realloc error\n");
        return -1;
    }
    if_name[len-1] = 0;

    std::thread print_thread(ThreadMain);
    print_thread.detach();

    listen_wlan(if_name);
    free(if_name);
    return 0;
}
