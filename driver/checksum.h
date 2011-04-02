#ifndef _CHECKSUM_H
#define _CHECKSUM_H

USHORT
ChecksumUpdate(
    USHORT chksum, 
    USHORT oldp, 
    USHORT newp
    );


ULONG checksum_unfold(PUSHORT buffer, INT size);
VOID checksum_tcp4(IP_HEADER *ih, TCP_HEADER *th);
VOID checksum_udp4(IP_HEADER *ih, UDP_HEADER *uh);
VOID checksum_icmp4(IP_HEADER *ih, ICMP_HEADER *icmph);
VOID checksum_tcp6(IP6_HEADER *ip6h, TCP_HEADER *th);
VOID checksum_udp6(IP6_HEADER *ip6h, UDP_HEADER *uh);
VOID checksum_icmp6(IP6_HEADER *ip6h, ICMP6_HEADER *icmp6h);

#endif // _CHECKSUM_H