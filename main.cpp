#include <cstdio>
#include <pcap.h>
#include "mac.h"

#include <sys/types.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>

#include <map>

using namespace std;

map<Mac, pair<int, char *>> table;

void usage(void)
{
    puts("syntax : airodump <interface>");
    puts("sample : ./airodump mon0");
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        usage();
        return 0;
    }

    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE] = {0};

    struct pcap_pkthdr *header;
    const u_char *packet;
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr)
    {
        fprintf(stderr, "couldn't open device (%s) (%s)\n", dev, errbuf);
        return 0;
    }

    while (true)
    {
        int res = pcap_next_ex(handle, &header, &packet);
        char *airodump = (char *)packet;
        if (res == 0)
            continue;
        else
        {
            uint16_t hdrlen = *(uint16_t *)(packet + 2);
            uint8_t type = *(packet + hdrlen);
            if (type == 0x80)
            {
                Mac bssid = Mac((uint8_t *)(packet + hdrlen + 16));
                auto iter = table.find(bssid);
                if (iter != table.end())
                    iter->second.first++;
                else
                {
                    uint16_t essidlen = ntohs(*(uint16_t *)(packet + hdrlen + 24 + 12));
                    char *essid = (char *)calloc(sizeof(char), 100);
                    char temp[100] = {
                        0,
                    };
                    memcpy(essid, packet + hdrlen + 24 + 12 + 2, essidlen);
                    if (!strcmp(essid, temp))
                        sprintf(essid, "<length: %d>", essidlen);
                    else
                        essid[essidlen] = '\0';
                    pair<int, char *> p = make_pair(1, essid);
                    table.insert({bssid, p});
                }
                system("clear");
                printf("BSSID\t\t\t\tBeacons\t\tESSID\n");
                for (auto it = table.begin(); it != table.end(); it++)
                    printf("%s\t\t%d\t\t%s\n", std::string(it->first).data(), it->second.first, it->second.second);
            }
        }
    }
    pcap_close(handle);
}