#include "precomp.h"
#pragma hdrstop


UCHAR   GatewayMAC[6]   = { 0x00, 0x0c, 0x29, 0x32, 0xca, 0xab };

UINT    enable_xlate    = 1;  /* default to 1 */

//
//   xlate_mode :
//     0:  1:1 mapping
//     1:  1:N mapping
//
UINT    xlate_mode      = 0;  /* default to 1 */


BOOLEAN
IsEtherUnicast(
    PUCHAR   mac
    )
/*++

Routine Description:

    Check whether the given Ethernet address is unicast address.
    
Arguments:

    mac - Pointer to the Ethernet MAC address non-paged memory.

Return Value:

    TRUE if the mac address is unicast address; otherwise return FALSE.

--*/
{
    if ((mac[0] == 0x01) && (mac[1] == 0) && (mac[2] == 0x5e) && ((mac[3] & 0x80) == 0))
    {
        // Ethernet multicast address: 01-00-5E-00-00-00 to 01-00-5E-7F-FF-FF
        return FALSE;
    }
    else if ((mac[0] == 0xff) && (mac[1] == 0xff) && (mac[2] == 0xff) && 
             (mac[3] == 0xff) && (mac[4] == 0xff) && (mac[5] == 0xff))
    {
        // Ethernet broadcast address: FF-FF-FF-FF-FF-FF
        return FALSE;
    }
    else
    {
        return TRUE;
    }
}


VOID
IPAddr4to6(
    IN  PIN_ADDR         ip_addr, 
    OUT PIN6_ADDR        ip6_addr, 
    IN  PIVI_PREFIX_MIB  mib
    )
/*++

Routine Description:

    Translate IPv4 address to IPv6 address.
    
Arguments:

    ip_addr - Pointer to the IPv4 address that needs to be translated
    ip6_addr - Pointer to the caller-supplied IPv6 address structure that holds the translated address
    mib - Pointer to IVI prefix mib for the ip_addr

Return Value:

    None.

--*/
{
    INT PrefixLengthN = mib->PrefixLength / 8;   // prefix length must be a multiple of 8
    
    NdisMoveMemory(ip6_addr->u.byte, mib->Prefix.u.byte, PrefixLengthN);
    NdisMoveMemory(ip6_addr->u.byte + PrefixLengthN, ip_addr->u.byte, 4);
    
    // ip address multiplex
    if (mib->XlateMode == 1)
    {
        /*
         * Old format!
         *
        ip6_addr->u.byte[12] = (mod >> 8) & 0xff;
        ip6_addr->u.byte[13] = mod & 0xff;
        ip6_addr->u.byte[14] = (res >> 8) & 0xff;
        ip6_addr->u.byte[15] = res & 0xff;
         *
         */
        
        // New format
        ip6_addr->u.byte[PrefixLengthN + 4] = (mib->SuffixCode >> 8) & 0xff;
        ip6_addr->u.byte[PrefixLengthN + 5] = mib->SuffixCode & 0xff;
    }
}


VOID
Ip4to6(
    IN  PIP_HEADER       ih, 
    OUT PIP6_HEADER      ip6h,
    IN  PIVI_PREFIX_MIB  mib
    )
/*++

Routine Description:

    Translate IPv4 header to IPv6 header.
    
Arguments:

    ih - Pointer to the IPv4 header that needs to be translated
    ip6h - Pointer to the caller-supplied IPv6 header structure that holds the translated header
    mib - Pointer to IVI prefix mib for the destination address in IPv4 header

Return Value:

    None.

--*/
{
    ip6h->ver_pri = 0x60;
    ip6h->payload = htons(ntohs(ih->length) - (ih->ver_ihl & 0x0f) * 4);
    ip6h->nexthdr = ih->protocol;
    ip6h->hoplimit = ih->ttl;
    
    // address translation
    IPAddr4to6(&(ih->saddr), &(ip6h->saddr), &LocalPrefixInfo);  // Use local prefix info for src address translation
    IPAddr4to6(&(ih->daddr), &(ip6h->daddr), mib);
}


VOID
IPAddr6to4(
    IN  PIN6_ADDR        ip6_addr, 
    OUT PIN_ADDR         ip_addr,
    IN  ULONG            prefix_len
    )
/*++

Routine Description:

    Translate IPv6 address to IPv4 address.

Arguments:

    ip6_addr - Pointer to the IPv6 address that needs to be translated
    ip_addr - Pointer to the caller-supplied IPv4 address structure that holds the translated address
    prefix_len - Length of the prefix of 'ip6_addr' counted in bits

Return Value:

    None.

--*/
{
    if (IsIviAddress(ip6_addr) == 1)
    {
        INT PrefixLengthN = prefix_len / 8;   // prefix length must be a multiple of 8
        
        NdisMoveMemory(ip_addr->u.byte, ip6_addr->u.byte + PrefixLengthN, 4);
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


VOID
Ip6to4(
    IN  PIP6_HEADER      ip6h, 
    OUT PIP_HEADER       ih,
    IN  ULONG            prefix_len
    )
/*++

Routine Description:

    Translate IPv6 header to IPv4 header.
    
Arguments:

    ip6h - Pointer to the IPv6 header that needs to be translated
    ih - Pointer to the caller-supplied IPv4 header structure that holds the translated header
    prefix_len - Length of the src address prefix, used when translating the src address in IPv6 header

Return Value:

    None.

--*/
{
    ih->ver_ihl = 0x45;
    ih->length = htons(ntohs(ip6h->payload) + 20);
    ih->ttl = ip6h->hoplimit;
    ih->protocol = ip6h->nexthdr;

    // address translation
    IPAddr6to4(&(ip6h->saddr), &(ih->saddr), prefix_len);
    IPAddr6to4(&(ip6h->daddr), &(ih->daddr), LocalPrefixInfo.PrefixLength);  // Use local prefix info for dest address translation
}


UINT
Tcp4to6(
    IN  PUCHAR           Ipv4PacketData, 
    OUT PUCHAR           Ipv6PacketData,
    IN  PIVI_PREFIX_MIB  PrefixMib
    )
/*++

Routine Description:

    Translate IPv4 TCP packet into IPv6 TCP packet.
    
Arguments:

    Ipv4PacketData - Pointer to the IPv4 packet data memory that needs to be translated
    Ipv6PacketData - Pointer to the caller-supplied IPv6 packet data memory that holds the translated packet
    PrefixMib - Pointer to IVI prefix mib for the destination address in IPv4 packet

Return Value:

    Length of the translated packet on success; return 0 if failed.

--*/
{
    ETH_HEADER   *eh = (ETH_HEADER *)(Ipv4PacketData);
    IP_HEADER    *ih = (IP_HEADER *)(Ipv4PacketData + sizeof(ETH_HEADER));
    TCP_HEADER   *th = (TCP_HEADER *)(Ipv4PacketData + sizeof(ETH_HEADER) + (ih->ver_ihl & 0x0f) * 4);
    ETH_HEADER   *eh_6 = (ETH_HEADER *)(Ipv6PacketData);
    IP6_HEADER   *ip6h = (IP6_HEADER *)(Ipv6PacketData + sizeof(ETH_HEADER));
    TCP_HEADER   *th_6 = (TCP_HEADER *)(Ipv6PacketData + sizeof(ETH_HEADER) + sizeof(IP6_HEADER));
    
    INT           size;
    USHORT        newport;
    
    // Build Ethernet header
    ETH_COPY_NETWORK_ADDRESS(eh_6->dmac, eh->dmac);
    ETH_COPY_NETWORK_ADDRESS(eh_6->smac, eh->smac);
    eh_6->type = htons(ETH_IP6);
    
    // Build IPv6 header
    Ip4to6(ih, ip6h, PrefixMib);
    
    // Copy TCP header & data
    size = ntohs(ih->length) - (ih->ver_ihl & 0x0f) * 4;
    NdisMoveMemory(th_6, th, size);
    
    // Port mapping
    newport = GetTcpPortMapOut(th, size, TRUE);
    if (newport == 0)
    {
        DBGPRINT(("==> Tcp4to6: find map failed.\n"));
        return 0;
    }
    th_6->sport = htons(newport);
    
    checksum_tcp6(ip6h, th_6);
    
    // Return new packet size (including Ethernet header length)
    return (sizeof(ETH_HEADER) + ntohs(ih->length) + 20);
}


UINT
Tcp6to4(
    IN  PUCHAR Ipv6PacketData, 
    OUT PUCHAR Ipv4PacketData
    )
/*++

Routine Description:

    Translate IPv6 TCP packet into IPv4 TCP packet.
    
Arguments:

    Ipv6PacketData - Pointer to the IPv6 packet data memory that needs to be translated
    Ipv4PacketData - Pointer to the caller-supplied IPv4 packet data memory that holds the translated packet

Return Value:

    Length of the translated packet on success; return 0 if failed.

--*/
{
    ETH_HEADER   *eh = (ETH_HEADER *)(Ipv6PacketData);
    IP6_HEADER   *ip6h = (IP6_HEADER *)(Ipv6PacketData + sizeof(ETH_HEADER));
    TCP_HEADER   *th = (TCP_HEADER *)(Ipv6PacketData + sizeof(ETH_HEADER) + sizeof(IP6_HEADER));
    ETH_HEADER   *eh_4 = (ETH_HEADER *)(Ipv4PacketData);
    IP_HEADER    *ih = (IP_HEADER *)(Ipv4PacketData + sizeof(ETH_HEADER));
    TCP_HEADER   *th_4 = (TCP_HEADER *)(Ipv4PacketData + sizeof(ETH_HEADER) + sizeof(IP_HEADER));
    
    INT           size;
    USHORT        oldport;  
    
    // Build Ethernet header
    ETH_COPY_NETWORK_ADDRESS(eh_4->dmac, eh->dmac);
    ETH_COPY_NETWORK_ADDRESS(eh_4->smac, eh->smac);
    eh_4->type = htons(ETH_IP);
    
    // Build IPv4 header
    Ip6to4(ip6h, ih, LocalPrefixInfo.PrefixLength);
    
    // Copy TCP header & data
    size = ntohs(ip6h->payload);
    NdisMoveMemory(th_4, th, size);
    
    // Port mapping
    oldport = GetTcpPortMapIn(th, size);
    if (oldport == 0)
    {
        DBGPRINT(("==> Tcp6to4: find map failed.\n"));
        return 0;
    }
    th_4->dport = htons(oldport);
    
    checksum_tcp4(ih, th_4);

    // Return new packet size (including Ethernet header length)
    return (sizeof(ETH_HEADER) + ntohs(ip6h->payload) + 20);
}


UINT
Icmp4to6(
    IN  PUCHAR           Ipv4PacketData, 
    OUT PUCHAR           Ipv6PacketData,
    IN  PIVI_PREFIX_MIB  PrefixMib
    )
/*++

Routine Description:

    Translate IPv4 ICMP echo reqeust packet into IPv6 ICMP echo request packet.
    
Arguments:

    Ipv4PacketData - Pointer to the IPv4 packet data memory that needs to be translated
    Ipv6PacketData - Pointer to the caller-supplied IPv6 packet data memory that holds the translated packet
    PrefixMib - Pointer to IVI prefix mib for the destination address in IPv4 packet

Return Value:

    Length of the translated packet on success; return 0 if failed.

--*/
{
    ETH_HEADER   *eh = (ETH_HEADER *)(Ipv4PacketData);
    IP_HEADER    *ih = (IP_HEADER *)(Ipv4PacketData + sizeof(ETH_HEADER));
    ICMP_HEADER  *icmph = (ICMP_HEADER *)(Ipv4PacketData + sizeof(ETH_HEADER) + (ih->ver_ihl & 0x0f) * 4);
    ETH_HEADER   *eh_6 = (ETH_HEADER *)(Ipv6PacketData);
    IP6_HEADER   *ip6h = (IP6_HEADER *)(Ipv6PacketData + sizeof(ETH_HEADER));
    ICMP6_HEADER *icmp6h = (ICMP6_HEADER *)(Ipv6PacketData + sizeof(ETH_HEADER) + sizeof(IP6_HEADER));
    
    PUCHAR        data;
    PUCHAR        data_new;
    INT           data_size;
    USHORT        new_id;
    BOOLEAN       ret;
    
    // Build Ethernet header
    ETH_COPY_NETWORK_ADDRESS(eh_6->dmac, eh->dmac);
    ETH_COPY_NETWORK_ADDRESS(eh_6->smac, eh->smac);
    eh_6->type = htons(ETH_IP6);
    
    // Build IPv6 header
    Ip4to6(ih, ip6h, PrefixMib);
    ip6h->nexthdr = IP_ICMP6;

    // Build ICMPv6 header
    icmp6h->type = ((icmph->type == ICMP_ECHO) ? ICMP6_ECHO : ICMP6_ECHO_REPLY);
    icmp6h->code = 0;
    icmp6h->checksum = 0;
    icmp6h->u.echo.id = icmph->u.echo.id;
    icmp6h->u.echo.seq = icmph->u.echo.seq;

    // Id mapping
    ret = GetIcmpIdMapOut(ntohs(icmph->u.echo.id), TRUE, &new_id);
    if (ret != TRUE)
    {
        DBGPRINT(("==> Icmp4to6: find map failed!\n"));
        return 0;
    }
    icmp6h->u.echo.id = htons(new_id);

    // Copy data
    data       = Ipv4PacketData + sizeof(ETH_HEADER) + sizeof(IP_HEADER) + sizeof(ICMP_HEADER);
    data_new   = Ipv6PacketData + sizeof(ETH_HEADER) + sizeof(IP6_HEADER) + sizeof(ICMP6_HEADER);
    data_size  = ntohs(ih->length) - (ih->ver_ihl & 0x0f) * 4 - sizeof(ICMP_HEADER);
    NdisMoveMemory(data_new, data, data_size);

    checksum_icmp6(ip6h, icmp6h);
    
    // Return new packet size (including Ethernet header length)
    return (sizeof(ETH_HEADER) + ntohs(ih->length) + 20);
}


UINT
Icmp6to4(
    IN  PUCHAR            Ipv6PacketData, 
    OUT PUCHAR            Ipv4PacketData, 
    IN  USHORT            OldId,
    IN  ULONG             PrefixLength
    )
/*++

Routine Description:

    Translate IPv6 ICMP echo reply packet into IPv4 ICMP echo reply packet.
    
Arguments:

    Ipv6PacketData - Pointer to IPv6 packet memory, cannot be NULL
    Ipv4PacketData - Pointer to IPv4 packet memory allocated by caller, cannot be NULL
    OldId - Original id pre-fetched by caller in receive handles
    PrefixLength - Length of the prefix for the src address in IPv6 packet header

Return Value:

    Length of newly generated packet stored in 'Ipv4PacketData' buffer

--*/
{
    ETH_HEADER   *eh = (ETH_HEADER *)(Ipv6PacketData);
    IP6_HEADER   *ip6h = (IP6_HEADER *)(Ipv6PacketData + sizeof(ETH_HEADER));
    ICMP6_HEADER *icmp6h = (ICMP6_HEADER *)(Ipv6PacketData + sizeof(ETH_HEADER) + sizeof(IP6_HEADER));
    ETH_HEADER   *eh_4 = (ETH_HEADER *)(Ipv4PacketData);
    IP_HEADER    *ih = (IP_HEADER *)(Ipv4PacketData + sizeof(ETH_HEADER));
    ICMP_HEADER  *icmph = (ICMP_HEADER *)(Ipv4PacketData + sizeof(ETH_HEADER) + sizeof(IP_HEADER));
    
    PUCHAR        data;
    PUCHAR        data_new;
    INT           data_size;
    BOOLEAN       ret, trans;
    
    // Build Ethernet header
    ETH_COPY_NETWORK_ADDRESS(eh_4->dmac, eh->dmac);
    ETH_COPY_NETWORK_ADDRESS(eh_4->smac, eh->smac);
    eh_4->type = htons(ETH_IP);

    // Build IPv4 header
    Ip6to4(ip6h, ih, PrefixLength);
    ih->protocol = IP_ICMP;

    // Build ICMPv4 header
    icmph->type = ((icmp6h->type == ICMP6_ECHO) ? ICMP_ECHO : ICMP_ECHO_REPLY);
    icmph->code = 0;
    icmph->checksum = 0;
    icmph->u.echo.id = icmp6h->u.echo.id;
    icmph->u.echo.seq = icmp6h->u.echo.seq;
    
    // Id mapping using pre-fetched original id
    icmph->u.echo.id = htons(OldId);
    
    // Copy data
    data       = Ipv6PacketData + sizeof(ETH_HEADER) + sizeof(IP6_HEADER) + sizeof(ICMP6_HEADER);
    data_new   = Ipv4PacketData + sizeof(ETH_HEADER) + sizeof(IP_HEADER) + sizeof(ICMP_HEADER);
    data_size  = ntohs(ip6h->payload) - sizeof(ICMP6_HEADER);
    NdisMoveMemory(data_new, data, data_size);
    
    checksum_icmp4(ih, icmph);
    
    // Return new packet size (including Ethernet header length)
    return (sizeof(ETH_HEADER) + ntohs(ip6h->payload) + 20);
}


UINT
Udp4to6(
    IN  PUCHAR            Ipv4PacketData, 
    OUT PUCHAR            Ipv6PacketData,
    IN  PIVI_PREFIX_MIB   PrefixMib
    )
/*++

Routine Description:

    Translate IPv4 UDP packet into IPv6 UDP packet.
    
Arguments:

    Ipv4PacketData - Pointer to the IPv4 packet data memory that needs to be translated
    Ipv6PacketData - Pointer to the caller-supplied IPv6 packet data memory that holds the translated packet
    PrefixMib - Pointer to IVI prefix mib for the destination address in IPv4 packet

Return Value:

    Length of the translated packet on success; return 0 if failed.

--*/
{
    ETH_HEADER   *eh = (ETH_HEADER *)(Ipv4PacketData);
    IP_HEADER    *ih = (IP_HEADER *)(Ipv4PacketData + sizeof(ETH_HEADER));
    UDP_HEADER   *uh = (UDP_HEADER *)(Ipv4PacketData + sizeof(ETH_HEADER) + (ih->ver_ihl & 0x0f) * 4);
    ETH_HEADER   *eh_6 = (ETH_HEADER *)(Ipv6PacketData);
    IP6_HEADER   *ip6h = (IP6_HEADER *)(Ipv6PacketData + sizeof(ETH_HEADER));
    UDP_HEADER   *uh_6 = (UDP_HEADER *)(Ipv6PacketData + sizeof(ETH_HEADER) + sizeof(IP6_HEADER));
    
    INT           size;
    USHORT        newport;
    BOOLEAN       ret;
    
    // Build Ethernet header
    ETH_COPY_NETWORK_ADDRESS(eh_6->dmac, eh->dmac);
    ETH_COPY_NETWORK_ADDRESS(eh_6->smac, eh->smac);
    eh_6->type = htons(ETH_IP6);
    
    // Build IPv6 header
    Ip4to6(ih, ip6h, PrefixMib);
    
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
    IN  PUCHAR Ipv6PacketData, 
    OUT PUCHAR Ipv4PacketData, 
    IN  USHORT OldPort
    )
/*++

Routine Description:

    Translate IPv6 UDP packet into IPv4 UDP packet.
    
Arguments:

    Ipv6PacketData - Pointer to IPv6 packet memory, cannot be NULL
    Ipv4PacketData - Pointer to IPv4 packet memory allocated by caller, cannot be NULL
    OldPort - Original port pre-fetched by caller in receive handles

Return Value:

    Length of newly generated packet stored in 'Ipv4PacketData' buffer

--*/
{
    ETH_HEADER   *eh = (ETH_HEADER *)(Ipv6PacketData);
    IP6_HEADER   *ip6h = (IP6_HEADER *)(Ipv6PacketData + sizeof(ETH_HEADER));
    UDP_HEADER   *uh = (UDP_HEADER *)(Ipv6PacketData + sizeof(ETH_HEADER) + sizeof(IP6_HEADER));
    ETH_HEADER   *eh_4 = (ETH_HEADER *)(Ipv4PacketData);
    IP_HEADER    *ih = (IP_HEADER *)(Ipv4PacketData + sizeof(ETH_HEADER));
    UDP_HEADER   *uh_4 = (UDP_HEADER *)(Ipv4PacketData + sizeof(ETH_HEADER) + sizeof(IP_HEADER));
    
    INT           size;
    BOOLEAN       ret, trans;
    
    // Build Ethernet header
    ETH_COPY_NETWORK_ADDRESS(eh_4->dmac, eh->dmac);
    ETH_COPY_NETWORK_ADDRESS(eh_4->smac, eh->smac);
    eh_4->type = htons(ETH_IP);
    
    // Build IPv4 header
    Ip6to4(ip6h, ih, LocalPrefixInfo.PrefixLength);
    
    // Copy UDP header & data
    size = ntohs(ip6h->payload);
    NdisMoveMemory(uh_4, uh, size);
    
    // Port mapping using pre-fetched original port
    uh_4->dport = htons(OldPort);
    
    checksum_udp4(ih, uh_4);
    
    // Return new packet size (including Ethernet header length)
    return (sizeof(ETH_HEADER) + ntohs(ip6h->payload) + 20);
}


UINT
PacketData4to6(
    IN  PUCHAR            Ipv4PacketData, 
    OUT PUCHAR            Ipv6PacketData,
    IN  PIVI_PREFIX_MIB   PrefixMib
    )
/*++

Routine Description:

    Translate IPv4 packet into IPv6 packet.
    
Arguments:

    Ipv4PacketData - Pointer to the IPv4 packet data memory that needs to be translated
    Ipv6PacketData - Pointer to the caller-supplied IPv6 packet data memory that holds the translated packet
    PrefixMib - Pointer to IVI prefix mib for the destination address in IPv4 packet

Return Value:

    Length of the translated packet on success; return 0 if failed.

--*/
{
    PETH_HEADER   eh = (PETH_HEADER)(Ipv4PacketData);
    PIP_HEADER    ih = (PIP_HEADER)(Ipv4PacketData + sizeof(ETH_HEADER));
    UINT          PacketSendSize = 0;
    
    if (ih->protocol == IP_ICMP)
    {
        // ICMPv4 packet
        PICMP_HEADER icmph = (PICMP_HEADER)(Ipv4PacketData + sizeof(ETH_HEADER) + (ih->ver_ihl & 0x0f) * 4);
        
        if (icmph->type == ICMP_ECHO) // Echo Request
        {
            DBGPRINT(("==> PacketData4to6: Translate an ICMPv4 echo request packet.\n"));
            
            PacketSendSize = Icmp4to6(Ipv4PacketData, Ipv6PacketData, PrefixMib);
            if (PacketSendSize == 0)
            {
                DBGPRINT(("==> PacketData4to6: Translate failed with Icmp4to6.\n"));
            }
        }
        else
        {
            DBGPRINT(("==> PacketData4to6: Unsupported ICMPv4 type.\n"));
        }
    }
    else if (ih->protocol == IP_TCP)
    {
        // TCPv4 packet
        DBGPRINT(("==> PacketData4to6: Translate a TCPv4 packet.\n"));
        
        PacketSendSize = Tcp4to6(Ipv4PacketData, Ipv6PacketData, PrefixMib);
        if (PacketSendSize == 0)
        {
            DBGPRINT(("==> PacketData4to6: Translate failed with Tcp4to6.\n"));
        }
    }
    else if (ih->protocol == IP_UDP)
    {
        // UDPv4 packet
        DBGPRINT(("==> PacketData4to6: Translate a UDPv4 packet.\n"));
        
        PacketSendSize = Udp4to6(Ipv4PacketData, Ipv6PacketData, PrefixMib);
        if (PacketSendSize == 0)
        {
            DBGPRINT(("==> PacketData4to6: Translate failed with Udp4to6.\n"));
        }
    }
    else
    {
        DBGPRINT(("==> PacketData4to6: Unsupported IPv4 protocol type.\n"));
    }
    
    return PacketSendSize;
}
