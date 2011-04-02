#ifndef _XLATE_H
#define _XLATE_H

extern UCHAR    prefix[16];
extern USHORT   prefix_length;
extern USHORT   mod;
extern UCHAR    mod_ratio;
extern USHORT   res;
extern UCHAR    gatewayMAC[6];
extern UINT     enable_xlate;
extern UINT     xlate_mode;

/*++

ULONG
IsIviAddress(
    IN PIN6_ADDR addr
    );

Routine Description:

    Check IVI address format.
    
Arguments:

    s_addr - Pointer to array that contains an IPv6 address

Return Value:

    1 if the address is IVI format; otherwise return 0.

--*/

#define IsIviAddress(_addr) NdisEqualMemory((_addr)->u.byte, prefix, prefix_length / 8)


VOID
IPAddr4to6(
    PIN_ADDR  ip_addr, 
    PIN6_ADDR ip6_addr, 
    BOOLEAN   localip
    );


VOID ip4to6(IP_HEADER *ih, IP6_HEADER *ip6h);


VOID
IPAddr6to4(
    PIN6_ADDR ip6_addr, 
    PIN_ADDR  ip_addr
    );


VOID ip6to4(IP6_HEADER *ip6h, IP_HEADER *ih);

UINT tcp4to6(PUCHAR pPacket, PUCHAR pNewPacket);
UINT tcp6to4(PUCHAR pPacket, PUCHAR pNewPacket);
UINT icmp4to6(PUCHAR pPacket, PUCHAR pNewPacket);


UINT
Icmp6to4(
    IN PUCHAR IPv6Packet, 
    IN PUCHAR IPv4Packet, 
    IN USHORT OldId
    );


UINT udp4to6(PUCHAR pPacket, PUCHAR pNewPacket);


UINT Udp6to4(
    PUCHAR pPacket, 
    PUCHAR pNewPacket, 
    USHORT OldPort
    );


#endif // _XLATE_H