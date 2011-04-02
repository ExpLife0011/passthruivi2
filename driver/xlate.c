#include "precomp.h"
#pragma hdrstop

UCHAR   prefix[16]      = { 0x20, 0x01, 0x0d, 0xa8, 0xff };
USHORT  prefix_length   = 40;    // in bits!! prefix_length must be a multiple of 8
USHORT  mod             = 256;   // 2^k
UCHAR   mod_ratio       = 0x80;  // k is shifted to higher 4 bit already
USHORT  res             = 1;

// MAC for local NICs and gateway
UCHAR   gatewayMAC[6]   = { 0x00, 0x0c, 0x29, 0x32, 0xca, 0xab };

UINT    enable_xlate    = 1;  /* default to 1 */

//
//   xlate_mode :
//     0:  1:1 mapping
//     1:  1:N mapping
//
UINT    xlate_mode      = 0;  /* default to 1 */


VOID
IPAddr4to6(
    PIN_ADDR  ip_addr, 
    PIN6_ADDR ip6_addr, 
    BOOLEAN   localip
    )
/*++

Routine Description:

    Translate IPv4 address to IPv6 address.
    
Arguments:

    ip_addr - Pointer to the IPv4 address that needs to be translated
    ip6_addr - Pointer to the caller-supplied IPv6 address structure that holds the translated address
    localip - Indicate whether the IPv4 address is local IP  // XXX: should be changed to IVI MIB info struct in the future

Return Value:

    None.

--*/
{
    UINT prefixLengthN = prefix_length / 8;   // prefix length must be a multiple of 8
    
    NdisMoveMemory(ip6_addr->u.byte, prefix, prefix_length);
    NdisMoveMemory(ip6_addr->u.byte + prefixLengthN, ip_addr->u.byte, 4);
    
    // port multiplex
    if (xlate_mode == 1 && localip == 1)  /* do port coding for local ip only */
    {
        /*
         * Old format!
         *
        *(ip6_addr+12) = (mod >> 8) & 0xff;
        *(ip6_addr+13) = mod & 0xff;
        *(ip6_addr+14) = (res >> 8) & 0xff;
        *(ip6_addr+15) = res &0xff;
         *
         */
        
        // New format
        ip6_addr->u.byte[prefixLengthN + 4] = mod_ratio + ((res >> 8) & 0x0f);
        ip6_addr->u.byte[prefixLengthN + 5] = res & 0xff;
    }
    
    return;
}

//
// Translate IPv4 header to IPv6 header
//
VOID ip4to6(IP_HEADER *ih, IP6_HEADER *ip6h)
{
    // ip6h must be memset to zero before calling this function!
    ip6h->ver_pri = 0x60;
    ip6h->payload = htons(ntohs(ih->length) - (ih->ver_ihl & 0x0f) * 4);
    ip6h->nexthdr = ih->protocol;
    ip6h->hoplimit = ih->ttl;
    
    // address mapping
    IPAddr4to6(&(ih->saddr), &(ip6h->saddr), TRUE);   // port coding for local ip /* XXX */
    IPAddr4to6(&(ih->daddr), &(ip6h->daddr), FALSE);  // no port conding for remote ip
    
    return;
}


VOID
IPAddr6to4(
    PIN6_ADDR ip6_addr, 
    PIN_ADDR  ip_addr
    )
/*++

Routine Description:

    Translate IPv6 address to IPv4 address.
    
Arguments:

    ip6_addr - Pointer to the IPv6 address that needs to be translated
    ip_addr - Pointer to the caller-supplied IPv4 address structure that holds the translated address

Return Value:

    None.

--*/
{
    if (IsIviAddress(ip6_addr) == 1)
    {
        NdisMoveMemory(ip_addr->u.byte, ip6_addr->u.byte + (prefix_length / 8), 4);
    }
    else
    {
        /*
         * This happens when we try to xlate a 
         * embed icmp message whose ipv6 addr
         * is not in ivi format.
         * Just assign a private ipv4 addr:
         * 192.168.X.X, with X field copied from
         * the last two bype of the original
         * ipv6 addr
         * 
         */
         
        ip_addr->u.byte[0] = 192;
        ip_addr->u.byte[1] = 168;
        ip_addr->u.byte[2] = ip6_addr->u.byte[14];
        ip_addr->u.byte[3] = ip6_addr->u.byte[15];
    }
}

//
// Translate IPv6 header to IPv4 header
//
VOID ip6to4(IP6_HEADER *ip6h, IP_HEADER *ih)
{
    // ih must be memset to zero before calling this function!
    ih->ver_ihl = 0x45;
    ih->length = htons(ntohs(ip6h->payload) + 20);
    ih->ttl = ip6h->hoplimit;
    ih->protocol = ip6h->nexthdr;

    // IVI address mapping
    IPAddr6to4(&(ip6h->saddr), &(ih->saddr));
    IPAddr6to4(&(ip6h->daddr), &(ih->daddr));

    return;
}


//
// Translate IPv4 TCP packet into IPv6 TCP packet,
// return packet_size on success, return 0 if failed
//
UINT tcp4to6(PUCHAR pPacket, PUCHAR pNewPacket)
{
    ETH_HEADER   *eh;
    IP_HEADER    *ih;
    TCP_HEADER   *th;
    ETH_HEADER   *eh_6;
    IP6_HEADER   *ip6h;
    TCP_HEADER   *th_6;
    INT           size;
    USHORT        newport;
    
    // Point headers
    eh     = (ETH_HEADER *)(pPacket);
    ih     = (IP_HEADER  *)(pPacket + sizeof(ETH_HEADER));
    th     = (TCP_HEADER *)(pPacket + sizeof(ETH_HEADER) + (ih->ver_ihl & 0x0f) * 4);
    eh_6   = (ETH_HEADER *)(pNewPacket);
    ip6h   = (IP6_HEADER *)(pNewPacket + sizeof(ETH_HEADER));
    th_6   = (TCP_HEADER *)(pNewPacket + sizeof(ETH_HEADER) + sizeof(IP6_HEADER));
    
    // Build Ethernet header
    ETH_COPY_NETWORK_ADDRESS(eh_6->dmac, eh->dmac);
    ETH_COPY_NETWORK_ADDRESS(eh_6->smac, eh->smac);
    eh_6->type = htons(ETH_IP6);
    
    // Build IPv6 header
    ip4to6(ih, ip6h);
    
    // Copy TCP header & data
    size = ntohs(ih->length) - (ih->ver_ihl & 0x0f) * 4;
    NdisMoveMemory(th_6, th, size);
    
    // Port mapping
    newport = GetTcpPortMapOut(th, size, TRUE);
    if (newport == 0)
    {
        DBGPRINT(("==> tcp4to6: find map failed.\n"));
        return 0;
    }
    th_6->sport = htons(newport);
    
    checksum_tcp6(ip6h, th_6);
    
    // Return new packet size (including Ethernet header length)
    return (sizeof(ETH_HEADER) + ntohs(ih->length) + 20);
}

//
// Translate IPv6 TCP packet into IPv4 TCP packet,
// return packet_size on success, return 0 if failed
//
UINT tcp6to4(PUCHAR pPacket, PUCHAR pNewPacket)
{
    ETH_HEADER   *eh;
    IP6_HEADER   *ip6h;
    TCP_HEADER   *th;
    ETH_HEADER   *eh_4;
    IP_HEADER    *ih;
    TCP_HEADER   *th_4;
    INT           size;
    USHORT        oldport;
    
    // Point headers
    eh     = (ETH_HEADER *)(pPacket);
    ip6h   = (IP6_HEADER *)(pPacket + sizeof(ETH_HEADER));
    th     = (TCP_HEADER *)(pPacket + sizeof(ETH_HEADER) + sizeof(IP6_HEADER));
    eh_4   = (ETH_HEADER *)(pNewPacket);
    ih     = (IP_HEADER  *)(pNewPacket + sizeof(ETH_HEADER));
    th_4   = (TCP_HEADER *)(pNewPacket + sizeof(ETH_HEADER) + sizeof(IP_HEADER));
    
    // Build Ethernet header
    ETH_COPY_NETWORK_ADDRESS(eh_4->dmac, eh->dmac);
    ETH_COPY_NETWORK_ADDRESS(eh_4->smac, eh->smac);
    eh_4->type = htons(ETH_IP);
    
    // Build IPv4 header
    ip6to4(ip6h, ih);
    
    // Copy TCP header & data
    size = ntohs(ip6h->payload);
    NdisMoveMemory(th_4, th, size);
    
    // Port mapping
    oldport = GetTcpPortMapIn(th, size);
    if (oldport == 0)
    {
        DBGPRINT(("==> tcp6to4: find map failed.\n"));
        return 0;
    }
    th_4->dport = htons(oldport);
    
    checksum_tcp4(ih, th_4);

    // Return new packet size (including Ethernet header length)
    return (sizeof(ETH_HEADER) + ntohs(ip6h->payload) + 20);
}

//
// Translate IPv4 ICMP packet into IPv6 ICMP packet, 
// return packet size on success, return 0 if failed
//
UINT icmp4to6(PUCHAR pPacket, PUCHAR pNewPacket)
{
    ETH_HEADER   *eh;
    IP_HEADER    *ih;
    ICMP_HEADER  *icmph;
    ETH_HEADER   *eh_6;
    IP6_HEADER   *ip6h;
    ICMP6_HEADER *icmp6h;
    
    PUCHAR        data;
    PUCHAR        data_new;
    INT           data_size;
    USHORT        new_id;
    BOOLEAN       ret;
    
    // Point headers
    eh     = (ETH_HEADER   *)(pPacket);
    ih     = (IP_HEADER    *)(pPacket + sizeof(ETH_HEADER));
    icmph  = (ICMP_HEADER  *)(pPacket + sizeof(ETH_HEADER) + (ih->ver_ihl & 0x0f) * 4);
    eh_6   = (ETH_HEADER   *)(pNewPacket);
    ip6h   = (IP6_HEADER   *)(pNewPacket + sizeof(ETH_HEADER));
    icmp6h = (ICMP6_HEADER *)(pNewPacket + sizeof(ETH_HEADER) + sizeof(IP6_HEADER));
    
    // Build Ethernet header
    ETH_COPY_NETWORK_ADDRESS(eh_6->dmac, eh->dmac);
    ETH_COPY_NETWORK_ADDRESS(eh_6->smac, eh->smac);
    eh_6->type = htons(ETH_IP6);
    
    // Build IPv6 header
    ip4to6(ih, ip6h);
    ip6h->nexthdr = IP_ICMP6;

    // Build ICMPv6 header
    icmp6h->type = ((icmph->type == ICMP_ECHO) ? ICMP6_ECHO : ICMP6_ECHO_REPLY);
    icmp6h->code = 0;
    icmp6h->checksum = 0;
    icmp6h->id = icmph->id;
    icmp6h->seq = icmph->seq;

    // Id mapping
    ret = GetIcmpIdMapOut(ntohs(icmph->id), TRUE, &new_id);
    if (ret != TRUE)
    {
        DBGPRINT(("==> icmp4to6: find map failed!\n"));
        return 0;
    }
    icmp6h->id = htons(new_id);

    // Copy data
    data       = pPacket + sizeof(ETH_HEADER) + sizeof(IP_HEADER) + sizeof(ICMP_HEADER);
    data_new   = pNewPacket + sizeof(ETH_HEADER) + sizeof(IP6_HEADER) + sizeof(ICMP6_HEADER);
    data_size  = ntohs(ih->length) - (ih->ver_ihl & 0x0f) * 4 - sizeof(ICMP_HEADER);
    NdisMoveMemory(data_new, data, data_size);

    checksum_icmp6(ip6h, icmp6h);
    
    // Return new packet size (including Ethernet header length)
    return (sizeof(ETH_HEADER) + ntohs(ih->length) + 20);
}

//
// Translate IPv6 ICMP packet into IPv4 ICMP packet, 
// return packet_size on success, return 0 if failed
//
UINT
Icmp6to4(
    IN PUCHAR IPv6Packet, 
    IN PUCHAR IPv4Packet, 
    IN USHORT OldId
    )
/*++

Routine Description:

    Translate IPv6 ICMP packet into IPv4 ICMP packet.
    
Arguments:

    IPv6Packet - Pointer to IPv6 packet memory, cannot be NULL
    IPv4Packet - Pointer to IPv4 packet memory allocated by caller, cannot be NULL
    OldId - Original id pre-fetched by caller in receive handles

Return Value:

    Length of newly generated packet stored in IPv4Packet buffer

--*/
{
    ETH_HEADER   *eh;
    IP6_HEADER   *ip6h;
    ICMP6_HEADER *icmp6h;
    ETH_HEADER   *eh_4;
    IP_HEADER    *ih;
    ICMP_HEADER  *icmph;
    
    PUCHAR        data;
    PUCHAR        data_new;
    INT           data_size;
    BOOLEAN       ret, trans;
    
    // Point headers
    eh     = (ETH_HEADER   *)(IPv6Packet);
    ip6h   = (IP6_HEADER   *)(IPv6Packet + sizeof(ETH_HEADER));
    icmp6h = (ICMP6_HEADER *)(IPv6Packet + sizeof(ETH_HEADER) + sizeof(IP6_HEADER));
    eh_4   = (ETH_HEADER   *)(IPv4Packet);
    ih     = (IP_HEADER    *)(IPv4Packet + sizeof(ETH_HEADER));
    icmph  = (ICMP_HEADER  *)(IPv4Packet + sizeof(ETH_HEADER) + sizeof(IP_HEADER));
    
    // Build Ethernet header
    ETH_COPY_NETWORK_ADDRESS(eh_4->dmac, eh->dmac);
    ETH_COPY_NETWORK_ADDRESS(eh_4->smac, eh->smac);
    eh_4->type = htons(ETH_IP);

    // Build IPv4 header
    ip6to4(ip6h, ih);
    ih->protocol = IP_ICMP;

    // Build ICMPv4 header
    icmph->type = ((icmp6h->type == ICMP6_ECHO) ? ICMP_ECHO : ICMP_ECHO_REPLY);
    icmph->code = 0;
    icmph->checksum = 0;
    icmph->id = icmp6h->id;
    icmph->seq = icmp6h->seq;
    
    // Id mapping using pre-fetched original id
    icmph->id = htons(OldId);
    
    // Copy data
    data       = IPv6Packet + sizeof(ETH_HEADER) + sizeof(IP6_HEADER) + sizeof(ICMP6_HEADER);
    data_new   = IPv4Packet + sizeof(ETH_HEADER) + sizeof(IP_HEADER) + sizeof(ICMP_HEADER);
    data_size  = ntohs(ip6h->payload) - sizeof(ICMP6_HEADER);
    NdisMoveMemory(data_new, data, data_size);
    
    checksum_icmp4(ih, icmph);
    
    // Return new packet size (including Ethernet header length)
    return (sizeof(ETH_HEADER) + ntohs(ip6h->payload) + 20);
}

//
// Translate IPv4 UDP packet into IPv6 UDP packet,
// return packet size on success, return 0 if failed
//
UINT udp4to6(PUCHAR pPacket, PUCHAR pNewPacket)
{
    ETH_HEADER   *eh;
    IP_HEADER    *ih;
    UDP_HEADER   *uh;
    ETH_HEADER   *eh_6;
    IP6_HEADER   *ip6h;
    UDP_HEADER   *uh_6;
    
    INT           size;
    USHORT        newport;
    BOOLEAN       ret;
    
    // Point headers
    eh     = (ETH_HEADER  *)(pPacket);
    ih     = (IP_HEADER   *)(pPacket + sizeof(ETH_HEADER));
    uh     = (UDP_HEADER  *)(pPacket + sizeof(ETH_HEADER) + (ih->ver_ihl & 0x0f) * 4);
    eh_6   = (ETH_HEADER  *)(pNewPacket);
    ip6h   = (IP6_HEADER  *)(pNewPacket + sizeof(ETH_HEADER));
    uh_6   = (UDP_HEADER  *)(pNewPacket + sizeof(ETH_HEADER) + sizeof(IP6_HEADER));
    
    // Build Ethernet header
    ETH_COPY_NETWORK_ADDRESS(eh_6->dmac, eh->dmac);
    ETH_COPY_NETWORK_ADDRESS(eh_6->smac, eh->smac);
    eh_6->type = htons(ETH_IP6);
    
    // Build IPv6 header
    ip4to6(ih, ip6h);
    
    // Copy TCP header & data
    size = ntohs(ih->length) - (ih->ver_ihl & 0x0f) * 4;
    NdisMoveMemory(uh_6, uh, size);
    
    // Port mapping
    ret = GetUdpPortMapOut(ntohs(uh->sport), TRUE, &newport);
    if (ret == FALSE)
    {
        DBGPRINT(("==> udp4to6: find map failed.\n"));
        return 0;
    }
    uh_6->sport = htons(newport);
    
    checksum_udp6(ip6h, uh_6);
    
    // Return new packet size (including Ethernet header length)
    return (sizeof(ETH_HEADER) + ntohs(ih->length) + 20);
}


UINT
Udp6to4(
    PUCHAR IPv6Packet, 
    PUCHAR IPv4Packet, 
    USHORT OldPort
    )
/*++

Routine Description:

    Translate IPv6 UDP packet into IPv4 UDP packet.
    
Arguments:

    IPv6Packet - Pointer to IPv6 packet memory, cannot be NULL
    IPv4Packet - Pointer to IPv4 packet memory allocated by caller, cannot be NULL
    OldPort - Original port pre-fetched by caller in receive handles

Return Value:

    Length of newly generated packet stored in IPv4Packet buffer

--*/
{
    ETH_HEADER   *eh;
    IP6_HEADER   *ip6h;
    UDP_HEADER   *uh;
    ETH_HEADER   *eh_4;
    IP_HEADER    *ih;
    UDP_HEADER   *uh_4;
    
    INT           size;
    BOOLEAN       ret, trans;
    
    // Point headers
    eh     = (ETH_HEADER  *)(IPv6Packet);
    ip6h   = (IP6_HEADER  *)(IPv6Packet + sizeof(ETH_HEADER));
    uh     = (UDP_HEADER  *)(IPv6Packet + sizeof(ETH_HEADER) + sizeof(IP6_HEADER));
    eh_4   = (ETH_HEADER  *)(IPv4Packet);
    ih     = (IP_HEADER   *)(IPv4Packet + sizeof(ETH_HEADER));
    uh_4   = (UDP_HEADER  *)(IPv4Packet + sizeof(ETH_HEADER) + sizeof(IP_HEADER));
    
    // Build Ethernet header
    ETH_COPY_NETWORK_ADDRESS(eh_4->dmac, eh->dmac);
    ETH_COPY_NETWORK_ADDRESS(eh_4->smac, eh->smac);
    eh_4->type = htons(ETH_IP);
    
    // Build IPv4 header
    ip6to4(ip6h, ih);
    
    // Copy UDP header & data
    size = ntohs(ip6h->payload);
    NdisMoveMemory(uh_4, uh, size);
    
    // Port mapping using pre-fetched original port
    uh_4->dport = htons(OldPort);
    
    checksum_udp4(ih, uh_4);
    
    // Return new packet size (including Ethernet header length)
    return (sizeof(ETH_HEADER) + ntohs(ip6h->payload) + 20);
}

