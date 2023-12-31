#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>				//for IPPROTO_TCP socket
#define LIBNET_LIL_ENDIAN			//for use th_off; in Little_Endian
#define ETHER_ADDR_LEN 6
#define ETHERTYPE_IP 0x0800
#define PAYLOAD_DATA_MAX_LEN 65535

/*
 *  Ethernet II header
 *  Static header size: 14 bytes
 */
struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};

/*
 *  IPv4 header
 *  Internet Protocol, version 4
 *  Static header size: 20 bytes
 */
struct libnet_ipv4_hdr
{
#if defined(LIBNET_LIL_ENDIAN)
    u_int8_t ip_hl:4;        /* header length */
    u_int8_t ip_v:4;         /* version */

#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t ip_v:4,       /* version */
           ip_hl:4;        /* header length */
#endif
    u_int8_t ip_tos;       /* type of service */
#ifndef IPTOS_LOWDELAY
#define IPTOS_LOWDELAY      0x10
#endif
#ifndef IPTOS_THROUGHPUT
#define IPTOS_THROUGHPUT    0x08
#endif
#ifndef IPTOS_RELIABILITY
#define IPTOS_RELIABILITY   0x04
#endif
#ifndef IPTOS_LOWCOST
#define IPTOS_LOWCOST       0x02
#endif
    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;
#ifndef IP_RF
#define IP_RF 0x8000        /* reserved fragment flag */
#endif
#ifndef IP_DF
#define IP_DF 0x4000        /* dont fragment flag */
#endif
#ifndef IP_MF
#define IP_MF 0x2000        /* more fragments flag */
#endif 
#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
#endif
    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

/*
 *  TCP header
 *  Transmission Control Protocol
 *  Static header size: 20 bytes
 */
struct libnet_tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */
#if defined(LIBNET_LIL_ENDIAN)
    u_int8_t th_x2:4;        /* (unused) */
    u_int8_t th_off:4;       /* data offset */

#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t th_off:4,        /* data offset */
           th_x2:4;         /* (unused) */
#endif
    u_int8_t  th_flags;       /* control flags */
#ifndef TH_FIN
#define TH_FIN    0x01      /* finished send data */
#endif
#ifndef TH_SYN
#define TH_SYN    0x02      /* synchronize sequence numbers */
#endif
#ifndef TH_RST
#define TH_RST    0x04      /* reset the connection */
#endif
#ifndef TH_PUSH
#define TH_PUSH   0x08      /* push data to the app layer */
#endif
#ifndef TH_ACK
#define TH_ACK    0x10      /* acknowledge */
#endif
#ifndef TH_URG
#define TH_URG    0x20      /* urgent! */
#endif
#ifndef TH_ECE
#define TH_ECE    0x40
#endif
#ifndef TH_CWR   
#define TH_CWR    0x80
#endif
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};

struct libnet_Payload_hdr{
	u_int8_t  payload_Data[PAYLOAD_DATA_MAX_LEN];
};

void printMac(u_int8_t* m) {
	printf("%02x:%02x:%02x:%02x:%02x:%02x",m[0],m[1],m[2],m[3],m[4],m[5]);
}

void print_IP(struct in_addr *ip) {
    uint32_t ipv4addr = ntohl(ip->s_addr);	//4(byte)data network -> host
    printf("%u.%u.%u.%u", (ipv4addr >> 24), (ipv4addr >> 16) % 0x100, (ipv4addr >> 8) % 0x100, ipv4addr % 0x100);
}

void print_port(u_int16_t m){
	printf("%d", ntohs(m));			//2(byte)data network -> host
}
void print_pldata(u_int8_t* Payload_Data, int payload_data_LEN){
    if (payload_data_LEN == 0){
    	printf("ZERO DATA");
    	return;
    }
    
	for (int i = 0; i < 10; i++) {
	    printf("%02x ", Payload_Data[i]);
	};
}
	
void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}


typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		// get ethernet_hdr 
		struct libnet_ethernet_hdr* eth_hdr=(struct libnet_ethernet_hdr *)packet;
		// get ipv4_hdr 
		struct libnet_ipv4_hdr* ipv4_hdr=(struct libnet_ipv4_hdr *)(packet+sizeof(struct libnet_ethernet_hdr));
		// get tcp_hdr (struct libnet_ipv4_hdr)len = ipv4_hdr*4
		struct libnet_tcp_hdr* tcp_hdr=(struct libnet_tcp_hdr *)(packet+sizeof(struct libnet_ethernet_hdr)+sizeof(struct libnet_ipv4_hdr));
		// tcp_hdr_len = tcp_hdr*4 
		u_int16_t tcp_hdr_len = tcp_hdr->th_off * 4;
		// get payload_hdr
		struct libnet_Payload_hdr*  pl_Data= (struct libnet_Payload_hdr*)(packet+sizeof(struct libnet_ethernet_hdr)+sizeof(struct libnet_ipv4_hdr)+tcp_hdr_len);
		// get payload_data_len 
		int payload_data_LEN=ntohs(ipv4_hdr->ip_len) - (ipv4_hdr->ip_hl * 4 + tcp_hdr->th_off * 4);
		// TCP 소캣 전처리기를 이용하여 프로토콜 번호 6이 아닐경우 해당 패킷은 출력 안함
		if (ipv4_hdr->ip_p != IPPROTO_TCP) {
    		printf("Not TCP packet\n");
    		continue;
    	}
    	if(ntohs(eth_hdr -> ether_type) != ETHERTYPE_IP) {
            printf("This packet is not IPv4\n");
            continue;
        }
		printf("%u bytes captured", header->caplen);
		printf("\n Ethernet Source Address:\t");
		printMac(eth_hdr->ether_shost);
		printf("\n Ethernet Destination Address:\t");
		printMac(eth_hdr->ether_dhost);
		printf("\n IPv4 Source Address:\t\t");
		print_IP(&ipv4_hdr->ip_src);
		printf("\n IPv4 Destination Address:\t");
		print_IP(&ipv4_hdr->ip_dst);
		printf("\n Tcp header Source Port:\t");
		print_port(tcp_hdr->th_sport);
		printf("\n Tcp header Destination Port:\t");
		print_port(tcp_hdr->th_dport);
		printf("\n payload_data_LEN:\t%d",payload_data_LEN);
		printf("\n Payload Data(MAX 10 Byte) :\t");
	    print_pldata(pl_Data->payload_Data, payload_data_LEN);
	    printf("\n");
	}

	pcap_close(pcap);
}
