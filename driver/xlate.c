#include "precomp.h"
#pragma hdrstop

UINT    buffer_size     = 65536; // total buffer size for a packet, constant
UCHAR   prefix[16]      = { 0x20, 0x01, 0x0d, 0xa8, 0xff };
USHORT  prefix_length   = 40;    // in bits!! prefix_length must be a multiple of 8
USHORT  mod             = 256;   // 2^k
UCHAR   mod_ratio       = 0x80;  // k is shifted to higher 4 bit already
USHORT  res             = 1;

// MAC for local NICs and gateway
UCHAR   gatewayMAC[6]   = { 0x00, 0x0c, 0x29, 0x32, 0xca, 0xab };
UCHAR   localMAC[6]     = { 0x00, 0x0c, 0x29, 0x2e, 0x07, 0xdb };

UINT    enable_xlate    = 1;  /* default to 1 */

//
//   xlate_mode :
//     0:  1:1 mapping
//     1:  1:N mapping
//
UINT    xlate_mode      = 0;  /* default to 1 */


//
// Compare two char arrays of the same length
//
INT char_array_equal(PUCHAR array1, PUCHAR array2, INT len)
{
    INT i;
    INT ret = 1; // Set to true at first

    for (i = 0; i < len; i++)
    {
        if (array1[i] != array2[i])
        {
            // Any differences will result a false return
            ret = 0;
            break;
        }
    }
    return ret;
}

//
// Check IVI address format
//
INT is_ivi_address(PUCHAR addr)
{
    INT ret = 0;
    //UCHAR mask = 0x00;
    //UINT prefixLengthR = prefix_length % 8;  // usually should be zero
    UINT prefixLengthN = prefix_length / 8;
    
    ret = char_array_equal(addr, prefix, prefixLengthN);
    
    /*
     * We don't support prefix length which cannot be divided by 8!
     *
    if (ret == 1 && prefixLengthR != 0)
    {
        // compare remaining bits
        mask = 0xFF << (8-prefixLengthR);
        ret = (addr[prefixLengthN] & mask) == (prefix[prefixLengthN] & mask);
    }
     *
     */
    
    return ret;
}

//
// Translate IPv4 address to IPv6 address
//
VOID ip_addr4to6(PUCHAR ip_addr, PUCHAR ip6_addr, UINT localip)
{
    UINT prefixLengthN = prefix_length / 8;   // prefix length must be a multiple of 8
    
    NdisMoveMemory(ip6_addr, prefix, prefix_length);
    NdisMoveMemory(ip6_addr + prefixLengthN, ip_addr, 4);
    
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
        *(ip6_addr+prefixLengthN+4) = mod_ratio + ((res >> 8) & 0x0f);
        *(ip6_addr+prefixLengthN+5) = res &0xff;
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
    ip_addr4to6(ih->saddr, ip6h->saddr, 1);  // port coding for local ip /* XXX */
    ip_addr4to6(ih->daddr, ip6h->daddr, 0);  // no port conding for remote ip
    
    return;
}

//
// Translate IPv6 address to IPv4 address
//
VOID ip_addr6to4(PUCHAR ip6_addr, PUCHAR ip_addr)
{
    /*
     * We don't support prefix length which is not multiple of 8 currently!
     *
     */
    if (is_ivi_address(ip6_addr))
    {
        NdisMoveMemory(ip_addr, ip6_addr + (prefix_length / 8), 4);
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
         
        *ip_addr     = 192;
        *(ip_addr+1) = 168;
        *(ip_addr+2) = *(ip6_addr+14);
        *(ip_addr+3) = *(ip6_addr+15);
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
    ip_addr6to4(ip6h->saddr, ih->saddr);
    ip_addr6to4(ip6h->daddr, ih->daddr);

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
    UINT          packet_size = 0; // bytes need to be sent
    
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

    // Done
    
    // Set packet_size
    packet_size = sizeof(ETH_HEADER) + ntohs(ih->length) + 20;
    
    return packet_size;
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
    UINT          packet_size = 0; // bytes need to be sent
    
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

    // Done
    
    // Set packet_size
    packet_size = sizeof(ETH_HEADER) + ntohs(ip6h->payload) + 20;
    
    return packet_size;
}

//
// Translate IPv4 ICMP packet into IPv6 ICMP packet, 
// return packet_size on success, return 0 if failed
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
    INT           ret = 0;
    UINT          packet_size = 0;   // bytes need to be sent
    
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
    icmp6h->sequence = icmph->sequence;

    // Id mapping
    ret = get_out_map_id(ntohs(icmph->id), 1, &new_id);
    if (ret != 0)
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

    // Done
    
    // Set packet_size
    packet_size = sizeof(ETH_HEADER) + ntohs(ih->length) + 20;
    
    return packet_size;
}

//
// Translate IPv6 ICMP packet into IPv4 ICMP packet, 
// return packet_size on success, return 0 if failed
//
UINT icmp6to4(PUCHAR pPacket, PUCHAR pNewPacket)
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
    USHORT        old_id;
    INT           ret = 0;
    UINT          packet_size = 0;   // bytes need to be sent
    
    // Point headers
    eh     = (ETH_HEADER   *)(pPacket);
    ip6h   = (IP6_HEADER   *)(pPacket + sizeof(ETH_HEADER));
    icmp6h = (ICMP6_HEADER *)(pPacket + sizeof(ETH_HEADER) + sizeof(IP6_HEADER));
    eh_4   = (ETH_HEADER   *)(pNewPacket);
    ih     = (IP_HEADER    *)(pNewPacket + sizeof(ETH_HEADER));
    icmph  = (ICMP_HEADER  *)(pNewPacket + sizeof(ETH_HEADER) + sizeof(IP_HEADER));
    
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
    icmph->sequence = icmp6h->sequence;
    
    // Port mapping
    ret = get_in_map_id(ntohs(icmp6h->id), &old_id);
    if (ret != 0)
    {
        DBGPRINT(("==> icmp6to4: find map failed.\n"));
        return 0;
    }
    icmph->id = htons(old_id);
    
    // Copy data
    data       = pPacket + sizeof(ETH_HEADER) + sizeof(IP6_HEADER) + sizeof(ICMP6_HEADER);
    data_new   = pNewPacket + sizeof(ETH_HEADER) + sizeof(IP_HEADER) + sizeof(ICMP_HEADER);
    data_size  = ntohs(ip6h->payload) - sizeof(ICMP6_HEADER);
    NdisMoveMemory(data_new, data, data_size);
    
    checksum_icmp4(ih, icmph);

    // Done
    
    // Set packet_size
    packet_size = sizeof(ETH_HEADER) + ntohs(ip6h->payload) + 20;
    
    return packet_size;
}

//
// Translate IPv6 ICMP error message into IPv4 ICMP error message, 
// return packet_size on success, return 0 if failed
//
UINT icmp6to4_embed(PUCHAR pPacket, PUCHAR pNewPacket)
{
    ETH_HEADER   *eh;
    IP6_HEADER   *ip6h;
    ICMP6_HEADER *icmp6h;
    IP6_HEADER   *embed_ip6h;
    ICMP6_HEADER *embed_icmp6h;
    UDP_HEADER   *embed_uh;
    TCP_HEADER   *embed_th;
    ETH_HEADER   *eh_4;
    IP_HEADER    *ih;
    ICMP_HEADER  *icmph;
    IP_HEADER    *embed_ih;
    ICMP_HEADER  *embed_icmph;
    UDP_HEADER   *embed_uh_4;
    TCP_HEADER   *embed_th_4;
    
    PUCHAR        data;
    PUCHAR        data_new;
    INT           data_size;
    USHORT        old_id;
    INT           size;
    USHORT        oldport;
    INT           ret = 0;
    UINT          packet_size = 0; // bytes need to be sent
    
    // Point to headers
    eh           = (ETH_HEADER   *)(pPacket);
    ip6h         = (IP6_HEADER   *)(pPacket + sizeof(ETH_HEADER));
    icmp6h       = (ICMP6_HEADER *)(pPacket + sizeof(ETH_HEADER) + sizeof(IP6_HEADER));
    embed_ip6h   = (IP6_HEADER   *)(pPacket + sizeof(ETH_HEADER) + sizeof(IP6_HEADER) + sizeof(ICMP6_HEADER));
    eh_4         = (ETH_HEADER   *)(pNewPacket);
    ih           = (IP_HEADER    *)(pNewPacket + sizeof(ETH_HEADER));
    icmph        = (ICMP_HEADER  *)(pNewPacket + sizeof(ETH_HEADER) + sizeof(IP_HEADER));
    embed_ih     = (IP_HEADER    *)(pNewPacket + sizeof(ETH_HEADER) + sizeof(IP_HEADER) + sizeof(ICMP_HEADER));
    
    // Build Ethernet header
    ETH_COPY_NETWORK_ADDRESS(eh_4->dmac, eh->dmac);
    ETH_COPY_NETWORK_ADDRESS(eh_4->smac, eh->smac);
    eh_4->type = htons(ETH_IP);

    // Build IPv4 header
    ip6to4(ip6h, ih);  // Notice: ih->length need to be modified later!
    ih->protocol = IP_ICMP;

    // Build ICMPv4 header
    switch (icmp6h->type)
    {
        case ICMP6_TIME_EXCEED:
            icmph->type = ICMP_TIME_EXCEEDED;
            icmph->code = icmp6h->code;
            break;
        case ICMP6_DEST_UNREACH:
            icmph->type = ICMP_DEST_UNREACH;
            switch (icmp6h->code)
            {
                case ICMP6_NOROUTE:
                    icmph->code = ICMP_NET_UNREACH;
                    break;
                case ICMP6_PORT_UNREACH:
                    icmph->code = ICMP_PORT_UNREACH;
                    break;
                case ICMP6_ADM_PROHIBITED:
                    icmph->code = ICMP_PKT_FILTERED;
                    break;
                case ICMP6_ADDR_UNREACH:
                default:
                    icmph->code = ICMP_HOST_UNREACH;
                    break;
            }
            break;
        case ICMP6_PKT_TOOBIG:
            icmph->type = ICMP_DEST_UNREACH;
            icmph->code = ICMP_FRAG_NEEDED;
            // Change MTU
            icmph->sequence = htons(ntohs(icmp6h->sequence) - 28);
        default:
            DBGPRINT(("==> icmp6to4_embed: unsupported icmpv6 type. Drop.\n"));
            return 0;
    }
    icmph->checksum = 0;
    
    // Translate embedded IPv6 packet
    
    // Build embed IPv4 header
    ip6to4(embed_ip6h, embed_ih);
    // Total length is 20 bytes shorter due to embed translation
    ih->length = htons(ntohs(ih->length) - 20);
    
    if (embed_ip6h->nexthdr == IP_ICMP6)
    {
        embed_ih->protocol = IP_ICMP;
        
        // Point to embed headers
        embed_icmp6h = (ICMP6_HEADER *)(pPacket + sizeof(ETH_HEADER) + sizeof(IP6_HEADER) + sizeof(ICMP6_HEADER) + sizeof(IP6_HEADER));
        embed_icmph  = (ICMP_HEADER  *)(pNewPacket + sizeof(ETH_HEADER) + sizeof(IP_HEADER) + sizeof(ICMP_HEADER) + sizeof(IP_HEADER));
        
        // Build embed ICMPv4 header
        embed_icmph->type = ICMP_ECHO;
        embed_icmph->code = 0;
        embed_icmph->checksum = 0;
        embed_icmph->id = embed_icmp6h->id;
        embed_icmph->sequence = embed_icmp6h->sequence;
        
        // Port mapping for embed id
        ret = get_in_map_id(ntohs(embed_icmp6h->id), &old_id);
        if (ret != 0)
        {
            DBGPRINT(("==> icmp6to4_embed: find map for embed icmpv6 failed.\n"));
            return 0;
        }
        embed_icmph->id = htons(old_id);
        
        // Copy data
        data       = pPacket + sizeof(ETH_HEADER) + sizeof(IP6_HEADER) + sizeof(ICMP6_HEADER) + sizeof(IP6_HEADER) + sizeof(ICMP6_HEADER);
        data_new   = pNewPacket + sizeof(ETH_HEADER) + sizeof(IP_HEADER) + sizeof(ICMP_HEADER) + sizeof(IP_HEADER) + sizeof(ICMP_HEADER);
        data_size  = ntohs(ip6h->payload) - sizeof(IP6_HEADER) - 2 * sizeof(ICMP6_HEADER);
        NdisMoveMemory(data_new, data, data_size);
        
        checksum_icmp4(embed_ih, embed_icmph);
    }
    else if (embed_ip6h->nexthdr == IP_UDP)
    {
        // Point to embed headers
        embed_uh    = (UDP_HEADER *)(pPacket + sizeof(ETH_HEADER) + sizeof(IP6_HEADER) + sizeof(ICMP6_HEADER) + sizeof(IP6_HEADER));
        embed_uh_4  = (UDP_HEADER *)(pNewPacket + sizeof(ETH_HEADER) + sizeof(IP_HEADER) + sizeof(ICMP_HEADER) + sizeof(IP_HEADER));
        
        // Copy UDP header & data
        size = ntohs(ip6h->payload) - sizeof(ICMP6_HEADER) - sizeof(IP6_HEADER);
        NdisMoveMemory(embed_uh_4, embed_uh, size);
        
        // Port mapping
        oldport = get_in_map_port(ntohs(embed_uh->sport));
        if (oldport == 0)
        {
            DBGPRINT(("==> icmp6to4_embed: find map for embed udpv6 failed.\n"));
            return 0;
        }
        embed_uh_4->sport = htons(oldport);
        
        checksum_udp4(embed_ih, embed_uh_4);
    }
    else if (embed_ip6h->nexthdr == IP_TCP)
    {
        // Point to embed headers
        embed_th    = (TCP_HEADER *)(pPacket + sizeof(ETH_HEADER) + sizeof(IP6_HEADER) + sizeof(ICMP6_HEADER) + sizeof(IP6_HEADER));
        embed_th_4  = (TCP_HEADER *)(pNewPacket + sizeof(ETH_HEADER) + sizeof(IP_HEADER) + sizeof(ICMP_HEADER) + sizeof(IP_HEADER));
        
        // Copy TCP header & data
        size = ntohs(ip6h->payload) - sizeof(ICMP6_HEADER) - sizeof(IP6_HEADER);
        NdisMoveMemory(embed_th_4, embed_th, size);
        
        // Port mapping
        oldport = get_in_map_port(ntohs(embed_th->sport));
        if (oldport == 0)
        {
            DBGPRINT(("==> icmp6to4_embed: find map for embed tcpv6 failed.\n"));
            return 0;
        }
        embed_th_4->sport = htons(oldport);
        
        checksum_tcp4(embed_ih, embed_th_4);
    }
    else
    {
        DBGPRINT(("==> icmp6to4_embed: Unsupported embed header type. Drop.\n"));
        return 0;
    }
    
    // Checksum outside header
    checksum_icmp4(ih, icmph);
    
    // Done
    
    // Set packet_size
    packet_size = sizeof(ETH_HEADER) + ntohs(ih->length);
    
    return packet_size;
}

//
// Translate IPv4 UDP packet into IPv6 UDP packet,
// return packet_size on success, return 0 if failed
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
    UINT          packet_size = 0; // bytes need to be sent
    
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
    newport = get_out_map_port(ntohs(uh->sport), 1);
    if (newport == 0)
    {
        DBGPRINT(("==> udp4to6: find map failed.\n"));
        return 0;
    }
    uh_6->sport = htons(newport);
    
    checksum_udp6(ip6h, uh_6);

    // Done
    
    // Set packet_size
    packet_size = sizeof(ETH_HEADER) + ntohs(ih->length) + 20;
    
    return packet_size;
}

//
// Translate IPv6 UDP packet into IPv4 UDP packet,
// return packet_size on success, return 0 if failed
//
UINT udp6to4(PUCHAR pPacket, PUCHAR pNewPacket)
{
    ETH_HEADER   *eh;
    IP6_HEADER   *ip6h;
    UDP_HEADER   *uh;
    ETH_HEADER   *eh_4;
    IP_HEADER    *ih;
    UDP_HEADER   *uh_4;
    
    INT           size;
    USHORT        oldport;
    UINT          packet_size = 0; // bytes need to be sent
    
    // Point headers
    eh     = (ETH_HEADER  *)(pPacket);
    ip6h   = (IP6_HEADER  *)(pPacket + sizeof(ETH_HEADER));
    uh     = (UDP_HEADER  *)(pPacket + sizeof(ETH_HEADER) + sizeof(IP6_HEADER));
    eh_4   = (ETH_HEADER  *)(pNewPacket);
    ih     = (IP_HEADER   *)(pNewPacket + sizeof(ETH_HEADER));
    uh_4   = (UDP_HEADER  *)(pNewPacket + sizeof(ETH_HEADER) + sizeof(IP_HEADER));
    
    // Build Ethernet header
    ETH_COPY_NETWORK_ADDRESS(eh_4->dmac, eh->dmac);
    ETH_COPY_NETWORK_ADDRESS(eh_4->smac, eh->smac);
    eh_4->type = htons(ETH_IP);
    
    // Build IPv4 header
    ip6to4(ip6h, ih);
    
    // Copy UDP header & data
    size = ntohs(ip6h->payload);
    NdisMoveMemory(uh_4, uh, size);
    
    // Port mapping
    oldport = get_in_map_port(ntohs(uh->dport));
    if (oldport == 0)
    {
        DBGPRINT(("==> udp6to4: find map failed.\n"));
        return 0;
    }
    uh_4->dport = htons(oldport);
    
    checksum_udp4(ih, uh_4);

    // Done
    
    // Set packet_size
    packet_size = sizeof(ETH_HEADER) + ntohs(ip6h->payload) + 20;
    
    return packet_size;
}

