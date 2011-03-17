#include "precomp.h"
#pragma hdrstop

// 
// Update checksum according to old and new port number,
// all parameters (including the checksum) must be in host
// byte order, while the new checksum returned is in network 
// byte order and do not need to be re-ordered.
//
USHORT checksum_adjust(USHORT chksum, USHORT oldp, USHORT newp)
{
    LONG   x;
    USHORT ret;

    x = chksum;
    x = ~x & 0xffff;
    x -= oldp & 0xffff;
    if (x <= 0)
    {
	    x--;
	    x &= 0xffff;
    }

    x += newp & 0xffff;
    if (x & 0x10000)
    {
	    x++;
	    x &= 0xffff;
    }

    x = ~x & 0xffff;
    ret = (USHORT)(x / 256);
    ret += (USHORT)((x & 0xff) << 8);
    return ret;
}

//
// Checksum computing function for raw data without folding
// 32bits(ULONG) result INTo 16bits(USHORT) checksum
//
ULONG checksum_unfold(PUSHORT buffer, INT size)
{
    ULONG x = 0;
    
    while (size > 1)
    {
        x += *buffer++;
        size -= sizeof(USHORT);
    }
    
    if (size > 0)
    {
        x += (*(PUCHAR)buffer & 0xff);
    }
    
    return x;
}

//
// TCP checksum for IPv4 packet
//
VOID checksum_tcp4(IP_HEADER *ih, TCP_HEADER *th)
{
    USHORT checksum;
	// USHORT checksum0;
    ULONG  w1, w2, w3;
    USHORT size;
    PSD_HEADER psdh;
    
    NdisZeroMemory(&psdh, sizeof(PSD_HEADER));
    NdisMoveMemory(psdh.saddr, ih->saddr, 4);
	NdisMoveMemory(psdh.daddr, ih->daddr, 4);
    
    psdh.protocol = ih->protocol;
    size = ntohs(ih->length) - (ih->ver_ihl & 0x0f) * 4;
    psdh.length = htons(size);
    
    checksum = th->checksum;
	//DBGPRINT(("==> checksum_tcp4: Old TCP checksum: %02x\n", checksum));
    th->checksum = 0;
    
    // Compute psuedo-header and tcp data seperately
    w1 = checksum_unfold((PUSHORT)&psdh, sizeof(PSD_HEADER));
    w2 = checksum_unfold((PUSHORT)th, size);
    w3 = w1 + w2;
    
    // Fold the final result into 16 bits
    while (w3 >> 16)
    {
        w3 = (w3 >> 16) + (w3 & 0xffff);
    }
    checksum = (USHORT)(~w3);
    
    //DBGPRINT(("checksum_tcp4: Recompute TCP checksum: %02x\n", checksum));
    th->checksum = checksum;
    
    // Compute ip header checksum
    checksum = ih->checksum;
    //DBGPRINT(("checksum_tcp4: Old IP checksum: %02x\n", checksum));
    size = (ih->ver_ihl & 0x0f) * 4;
    
    ih->checksum = 0;
    w1 = checksum_unfold((USHORT *)ih, size);
    while (w1 >> 16)
        w1 = (w1 >> 16) + (w1 & 0xffff);
    checksum = (USHORT)(~w1);
    //DBGPRINT(("checksum_tcp4: Recompute IP checksum: %02x\n", checksum));
    ih->checksum = checksum;
    
    return;
}

//
// UDP checksum for IPv4 packet
//
VOID checksum_udp4(IP_HEADER *ih, UDP_HEADER *uh)
{
    USHORT checksum;
	//USHORT checksum0;
    ULONG  w1, w2, w3;
    USHORT size;
    PSD_HEADER psdh;
    
    NdisZeroMemory(&psdh, sizeof(PSD_HEADER));
    NdisMoveMemory(psdh.saddr, ih->saddr, 4);
	NdisMoveMemory(psdh.daddr, ih->daddr, 4);
    
    psdh.protocol = ih->protocol;
    psdh.length = uh->length;
    
    size = ntohs(uh->length);
    checksum = uh->checksum;
    DBGPRINT(("==> checksum_udp4: Old UDP checksum: %02x\n", checksum));
    uh->checksum = 0;
    
    // Compute psuedo-header and udp data seperately
    w1 = checksum_unfold((PUSHORT)&psdh, sizeof(PSD_HEADER));
    w2 = checksum_unfold((PUSHORT)uh, size);
    w3 = w1 + w2;
    
    // Fold the final result INTo 16 bits
    while (w3 >> 16)
    {
        w3 = (w3 >> 16) + (w3 & 0xffff);
    }
    checksum = (USHORT)(~w3);
    
    DBGPRINT(("checksum_udp4: Recompute checksum: %02x\n", checksum));
    uh->checksum = checksum;
    
    // Compute ip header checksum
    checksum = ih->checksum;
    DBGPRINT(("checksum_udp4: Old IP checksum: %02x\n", checksum));
    size = (ih->ver_ihl & 0x0f) * 4;
    
    ih->checksum = 0;
    w1 = checksum_unfold((PUSHORT)ih, size);
    while (w1 >> 16)
    {
        w1 = (w1 >> 16) + (w1 & 0xffff);
    }
    checksum = (USHORT)(~w1);
    DBGPRINT(("checksum_udp4: Recompute IP checksum: %02x\n", checksum));
    ih->checksum = checksum;
    
    return;
}

//
// ICMP checksum for IPv4 packet
//
VOID checksum_icmp4(IP_HEADER *ih, ICMP_HEADER *icmph)
{
    //USHORT   checksum;
	//USHORT	checksum0;
    ULONG  w1;
    USHORT size;

	// Compute icmp checksum

    //checksum = icmph->checksum;
	//DBGPRINT(("checksum_icmp4: Old ICMP checksum: %02x\n", checksum));
	size = ntohs(ih->length) - (ih->ver_ihl & 0x0F) * 4;
    
	icmph->checksum = 0;
    w1 = checksum_unfold((PUSHORT)icmph, size);
    while (w1 >> 16)
    {
        w1 = (w1 >> 16) + (w1 & 0xffff);
    }
    //checksum = (USHORT)(~w1);
    //DBGPRINT(("checksum_icmp4: Recompute ICMP checksum: %02x\n", checksum));
    //icmph->checksum = checksum;
	icmph->checksum = (USHORT)(~w1);
    
    // Compute ip header checksum

    //checksum = ih->checksum;
    //DBGPRINT(("checksum_icmp4: Old IP checksum: %02x\n", checksum));
    size = (ih->ver_ihl & 0x0F) * 4;
    
    ih->checksum = 0;
    w1 = checksum_unfold((PUSHORT)ih, size);
    while (w1 >> 16)
    {
        w1 = (w1 >> 16) + (w1 & 0xffff);
    }
    //checksum = (USHORT)(~w1);
    //DBGPRINT(("checksum_icmp4: Recompute IP checksum: %02x\n", checksum));
    //ih->checksum = checksum;
    ih->checksum = (USHORT)(~w1);

    return;
}

//
// TCP checksum for IPv6 packet
//
VOID checksum_tcp6(IP6_HEADER *ip6h, TCP_HEADER *th)
{
    USHORT checksum;
	// USHORT checksum0;
    ULONG  w1, w2, w3;
    USHORT size;
    PSD6_HEADER psd6h;
    
    NdisZeroMemory(&psd6h, sizeof(PSD6_HEADER));
    NdisMoveMemory(psd6h.saddr, ip6h->saddr, 16);
    NdisMoveMemory(psd6h.daddr, ip6h->daddr, 16);
    
    psd6h.length[1] = ip6h->payload;
    psd6h.nexthdr = ip6h->nexthdr;
    
    size = ntohs(ip6h->payload);
    checksum = th->checksum;
	//DBGPRINT(("==> checksum_tcp6: Old TCP checksum: %02x\n", checksum));
    th->checksum = 0;
    
    // Compute psuedo-header and tcp data seperately
    w1 = checksum_unfold((PUSHORT)&psd6h, sizeof(PSD6_HEADER));
    w2 = checksum_unfold((PUSHORT)th, size);
    w3 = w1 + w2;
    
    // Fold the final result INTo 16 bits
    while (w3 >> 16)
    {
        w3 = (w3 >> 16) + (w3 & 0xffff);
    }
    checksum = (USHORT)(~w3);
    
    //DBGPRINT(("==> checksum_tcp6: Recompute TCP checksum: %02x\n", checksum));
    th->checksum = checksum;
    
    return;
}

//
// UDP checksum for IPv6 packet
//
VOID checksum_udp6(IP6_HEADER *ip6h, UDP_HEADER *uh)
{
    USHORT checksum;
	// USHORT checksum0;
    ULONG  w1, w2, w3;
    USHORT size;
    PSD6_HEADER psd6h;
    
    NdisZeroMemory(&psd6h, sizeof(PSD6_HEADER));
    NdisMoveMemory(psd6h.saddr, ip6h->saddr, 16);
    NdisMoveMemory(psd6h.daddr, ip6h->daddr, 16);
    
    psd6h.length[1] = ip6h->payload;
    psd6h.nexthdr = ip6h->nexthdr;
    
    size = ntohs(ip6h->payload);
    checksum = uh->checksum;
	DBGPRINT(("==> checksum_udp6: Old UDP checksum: %02x\n", checksum));
    uh->checksum = 0;
    
    // Compute psuedo-header and udp data seperately
    w1 = checksum_unfold((PUSHORT)&psd6h, sizeof(PSD6_HEADER));
    w2 = checksum_unfold((PUSHORT)uh, size);
    w3 = w1 + w2;
    
    // Fold the final result INTo 16 bits
    while (w3 >> 16)
    {
        w3 = (w3 >> 16) + (w3 & 0xffff);
    }
    checksum = (USHORT)(~w3);
    
    DBGPRINT(("==> checksum_udp6: Recompute UDP checksum: %02x\n", checksum));
    uh->checksum = checksum;
    
    return;
}

//
// ICMPv6 checksum for IPv6 packet
//
VOID checksum_icmp6(IP6_HEADER *ip6h, ICMP6_HEADER *icmp6h)
{
    // USHORT checksum;
	// USHORT checksum0;
    ULONG  w1, w2, w3;
    USHORT size;
    PSD6_HEADER psd6h;
    
    NdisZeroMemory(&psd6h, sizeof(PSD6_HEADER));
    NdisMoveMemory(psd6h.saddr, ip6h->saddr, 16);
    NdisMoveMemory(psd6h.daddr, ip6h->daddr, 16);
    
    psd6h.length[1] = ip6h->payload;
    psd6h.nexthdr = ip6h->nexthdr;
    
    size = ntohs(ip6h->payload);
    //checksum = icmp6h->checksum;
	//DBGPRINT(("==> checksum_icmp6: Old ICMPv6 checksum: %02x\n", checksum));
    icmp6h->checksum = 0;
    
    // Compute psuedo-header and icmpv6 data seperately
    w1 = checksum_unfold((PUSHORT)&psd6h, sizeof(PSD6_HEADER));
    w2 = checksum_unfold((PUSHORT)icmp6h, size);
    w3 = w1 + w2;
    
    // Fold the final result INTo 16 bits
    while (w3 >> 16)
    {
        w3 = (w3 >> 16) + (w3 & 0xFFFF);
    }
    //checksum = (USHORT)(~w3);
    //DBGPRINT(("==> checksum_icmp6: Recompute ICMPv6 checksum: %02x\n", checksum));
    //icmp6h->checksum = checksum;
    icmp6h->checksum = (USHORT)(~w3);

    return;
}
