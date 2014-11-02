#ifndef PROTOCOLHEADERS_H
#define PROTOCOLHEADERS_H

#include "pcap.h"

#define SIZE_ETHERNET 14
#define SIZE_ARP 28
#define SIZE_IPV4 20
#define SIZE_IPV6 40
#define SIZE_TCP 20
#define SIZE_ICMP 8
#define SIZE_TCP_OPTIONAL 12
#define SIZE_PSEUDO 12
#define ETHER_ADDR_LEN	6

static const int ARP_PACKAGE_SIZE = 60;
static const int IP_PACKAGE_SIZE = 66;
static const int ICMP_PACKAGE_SIZE = 184;

#define   TCP_FIN   0x01
#define   TCP_SYN   0x02
#define   TCP_RST   0x04
#define   TCP_PSH   0x08
#define   TCP_ACK   0x10
#define   TCP_URG   0x20
#define   TCP_ACE   0x40
#define   TCP_CWR   0x80

struct ip_address
{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
};

struct sniff_ethernet { //14 bytes
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};

struct sniff_arp  //28 bytes
{
    u_short hrd;       //hardware address space=0x0001
    u_short eth_type;  //Ethernet type ....=0x0800
    u_char maclen;     //Length of mac address=6
    u_char iplen;      //Length of ip addres=4
    u_short opcode;    //Request =1 Reply=2 (highbyte)
    u_char smac[6];    //source mac address
    ip_address saddr;     //Source ip address
    u_char dmac[6];    //Destination mac address
    ip_address daddr;     //Destination ip address
};

#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

struct sniff_ip {   //20 bytes
    u_char ip_vhl;		// version << 4 | header length >> 2
    u_char ip_tos;		// type of service
    u_short ip_len;		// total length
    u_short ip_id;		// identification
    u_short ip_off;		// fragment offset field
#define IP_RF 0x8000		// reserved fragment flag
#define IP_DF 0x4000		// dont fragment flag
#define IP_MF 0x2000		// more fragments flag
#define IP_OFFMASK 0x1fff	// mask for fragmenting bits
    u_char ip_ttl;		// time to live
    u_char ip_p;		// protocol
    u_short ip_sum;		// checksum
    ip_address ip_src;  // source address
    ip_address ip_dst; // dest address
};

struct sniff_tcp {  //20 bytes
    u_short th_sport;	/* source port */
    u_short th_dport;	/* destination port */
    u_int th_seq;		/* sequence number */
    u_int th_ack;		/* acknowledgement number */
    u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;		/* window */
    u_short th_sum;		/* checksum */
    u_short th_urp;		/* urgent pointer */
    u_char optional[12];
};

struct sniff_icmp{
    u_char ic_type;
    u_char ic_code;
    u_short ic_sum;
    u_short ic_id;
    u_short ic_seq;
};

struct pseudo_header  //12 bytes
{
    ip_address  src_ip;      // Source address
    ip_address  dest_ip;      // Destination address
    u_char zeroes;
    u_char  protocol;          // Protocol
    u_short len;
    sniff_tcp tcp;
};

#endif // PROTOCOLHEADERS_H
