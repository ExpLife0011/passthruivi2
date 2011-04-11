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
    UCHAR  sip[4];  // We cannot use IN_ADDR here because of ULONG alignment is not correct.
    UCHAR  dmac[6];
    UCHAR  dip[4];  // Keep it the same with sip, although the ULONG alignment is correct now.
} ARP_HEADER, *PARP_HEADER;

/* IPv4 address */
typedef struct _IN_ADDR
{
    union
    {
        UCHAR  byte[4];
        USHORT word[2];
        ULONG  dword;
    } u;
} IN_ADDR, *PIN_ADDR;

/* IPv4 header */
typedef struct _IP_HEADER
{
    UCHAR    ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    UCHAR    tos;
    USHORT   length;         // Total length (including IP header length)
    USHORT   id;
    USHORT   flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    UCHAR    ttl;
    UCHAR    protocol;
    USHORT   checksum;
    IN_ADDR  saddr;
    IN_ADDR  daddr;
} IP_HEADER, *PIP_HEADER;

/* Pseudo IPv4 header */
typedef struct _PSD_HEADER
{
    IN_ADDR  saddr;
    IN_ADDR  daddr;
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
    union
    {
        struct
        {
            USHORT id;
            USHORT seq;
        } echo;
    } u;
} ICMP_HEADER, *PICMP_HEADER;

/* IPv6 address */
typedef struct _IN6_ADDR
{
    union
    {
        UCHAR   byte[16];
        USHORT  word[8];
        ULONG   dword[4];
    } u;
} IN6_ADDR, *PIN6_ADDR;

/* IPv6 header */
typedef struct _IP6_HEADER
{
    UCHAR     ver_pri;
    UCHAR     flow_lbl[3];
    USHORT    payload;      // payload length (without IPv6 header length)
    UCHAR     nexthdr;
    UCHAR     hoplimit;
    IN6_ADDR  saddr;
    IN6_ADDR  daddr;
} IP6_HEADER, *PIP6_HEADER;

/* Pseudo IPv6 header */
typedef struct _PSD6_HEADER
{
    IN6_ADDR saddr;
    IN6_ADDR daddr;
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
    union
    {
        struct
        {
            USHORT id;
            USHORT seq;
        } echo;
        ULONG addr;  // Target Address used by IVI prefix lookup
    } u;
} ICMP6_HEADER, *PICMP6_HEADER;

/* TCP header */
typedef struct _TCP_HEADER
{
    USHORT  sport;
    USHORT  dport;
    ULONG   seq;
    ULONG   ack;
    UCHAR   doff;    // Data offset  
    UCHAR   bits;    // Control bits
    USHORT  window;
    USHORT  checksum;
    USHORT  urg_ptr;
} TCP_HEADER, *PTCP_HEADER;

/* UDP header*/
typedef struct _UDP_HEADER
{
    USHORT sport;
    USHORT dport;
    USHORT length;         // Datagram length (including UDP header length)
    USHORT checksum;
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
#define ICMP_ECHO           8
 
/* ICMPv6 types */
#define ICMP6_ECHO        128
#define ICMP6_ECHO_REPLY  129

#endif // _HEADERS_H_
