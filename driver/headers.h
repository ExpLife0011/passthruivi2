#ifndef _HEADERS_H_
#define _HEADERS_H_

#define ntohs(x) RtlUshortByteSwap(x)
#define htons(x) RtlUshortByteSwap(x)
#define ntohl(x) RtlUlongByteSwap(x)
#define htonl(x) RtlUlongByteSwap(x)

/* Ethernet header */
typedef struct _ETH_HEADER
{
    UCHAR  dmac[6];
    UCHAR  smac[6];
    USHORT type;
} ETH_HEADER, *PETH_HEADER;

/* ARP header */
typedef struct _ARP_HEADER
{
    USHORT hw_type;
    USHORT prot_type;
    UCHAR  hw_size;
    UCHAR  prot_size;
    USHORT option;
    UCHAR  smac[6];
    UCHAR  sip[4];
    UCHAR  dmac[6];
    UCHAR  dip[4];
} ARP_HEADER, *PARP_HEADER;

/* IPv4 header */
typedef struct _IP_HEADER
{
    UCHAR  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    UCHAR  tos;            // Type of service 
    USHORT length;         // Total length 
    USHORT id;             // Identification
    USHORT flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    UCHAR  ttl;            // Time to live
    UCHAR  protocol;       // Protocol
    USHORT checksum;       // Header checksum
    UCHAR  saddr[4];       // Source address
    UCHAR  daddr[4];       // Destination address
} IP_HEADER, *PIP_HEADER;

/* Pseudo IPv4 header */
typedef struct _PSD_HEADER
{
    UCHAR    saddr[4];
    UCHAR    daddr[4];
    UCHAR    zero;
    UCHAR    protocol;
    USHORT   length;
} PSD_HEADER, *PPSD_HEADER;

/* ICMPv4 header */
typedef struct _ICMP_HEADER
{
    UCHAR  type;
    UCHAR  code;
    USHORT checksum;
    USHORT id;
    USHORT sequence;
} ICMP_HEADER, *PICMP_HEADER;

/* IPv6 header */
typedef struct _IP6_HEADER
{
    UCHAR    ver_pri;
    UCHAR    flowlbl[3];
    USHORT   payload;     // payload length (without header length)
    UCHAR    nexthdr;
    UCHAR    hoplimit;
    UCHAR    saddr[16];   // 128 bits source address
    UCHAR    daddr[16];   // 128 bits destination address
} IP6_HEADER, *PIP6_HEADER;

/* Pseudo IPv6 header */
typedef struct _PSD6_HEADER
{
    UCHAR    saddr[16];
    UCHAR    daddr[16];
    USHORT   length[2];
    UCHAR    zero[3];
    UCHAR    nexthdr;
} PSD6_HEADER, *PPSD6_HEADER;

/* ICMPv6 header */
typedef struct _ICMP6_HEADER
{
    UCHAR  type;
    UCHAR  code;
    USHORT checksum;
    USHORT id;
    USHORT sequence;    // MTU in UNREACH packets
} ICMP6_HEADER, *PICMP6_HEADER;

/* TCP header */
typedef struct _TCP_HEADER
{
    USHORT  sport;   // Source port
    USHORT  dport;   // Destination port
    ULONG   seq;
    ULONG   ack;
    UCHAR   doff;    // Data offset  
    UCHAR   bits;    // Control bits
    USHORT  window;
    USHORT  checksum;
    USHORT  urgptr;
} TCP_HEADER, *PTCP_HEADER;

/* UDP header*/
typedef struct _UDP_HEADER
{
    USHORT sport;          // Source port
    USHORT dport;          // Destination port
    USHORT length;         // Datagram length
    USHORT checksum;       // Checksum
} UDP_HEADER, *PUDP_HEADER;

/* Protocol constants */

#define IVI_PACKET_OVERHEAD 20

/* Ethernet types */
#define ETH_IP         0x0800
#define ETH_IP6        0x86dd
#define ETH_ARP        0x0806

/* ARP types */
#define ARP_REQUEST    0x0001
#define ARP_REPLY      0x0002
#define ARP_ETH_HDWARE 0x0001
#define ARP_MAC_SIZE        6
#define ARP_IPADDR_SIZE     4

/* IP protocols */
#define IP_ICMP             1
#define IP_TCP              6
#define IP_UDP             17
#define IP_ICMP6           58

/* ICMP types */
#define ICMP_ECHO_REPLY     0
#define ICMP_DEST_UNREACH   3
#define ICMP_ECHO           8
#define ICMP_TIME_EXCEEDED 11

/* ICMP codes for UNREACH */
#define ICMP_NET_UNREACH    0
#define ICMP_HOST_UNREACH   1
#define ICMP_PORT_UNREACH   3
#define ICMP_FRAG_NEEDED    4
#define ICMP_PKT_FILTERED  13
 
/* ICMPv6 types */
#define ICMP6_ECHO        128
#define ICMP6_ECHO_REPLY  129

#define ICMP6_DEST_UNREACH  1
#define ICMP6_PKT_TOOBIG    2
#define ICMP6_TIME_EXCEED   3

/* ICMPv6 codes for UNREACH */
#define ICMP6_NOROUTE                  0
#define ICMP6_ADM_PROHIBITED           1
#define ICMP6_ADDR_UNREACH             3
#define ICMP6_PORT_UNREACH             4

/* Neighbor discovery */
#define ICMP6_NEIGH_SOLIC 135
#define ICMP6_NEIGH_ADVER 136

#define ND_SRC_MAC          1
#define ND_TAR_MAC          2

#endif // _HEADERS_H_
