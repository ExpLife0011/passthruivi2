#ifndef _XLATE_H_
#define _XLATE_H_

#include "prefix.h"


extern UCHAR    GatewayMAC[6];
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

#define IsIviAddress(_addr) NdisEqualMemory((_addr)->u.byte, LocalPrefixInfo.Prefix.u.byte, LocalPrefixInfo.PrefixLength / 8)


BOOLEAN
IsEtherUnicast(
    PUCHAR   mac
    );


VOID
IPAddr4to6(
    IN  PIN_ADDR         ip_addr, 
    OUT PIN6_ADDR        ip6_addr, 
    IN  PIVI_PREFIX_MIB  mib
    );


UINT
Tcp4to6(
    IN  PUCHAR           Ipv4PacketData, 
    OUT PUCHAR           Ipv6PacketData,
    IN  PIVI_PREFIX_MIB  PrefixMib
    );


UINT
Tcp6to4(
    IN  PUCHAR Ipv6PacketData, 
    OUT PUCHAR Ipv4PacketData
    );


UINT
Icmp4to6(
    IN  PUCHAR           Ipv4PacketData, 
    OUT PUCHAR           Ipv6PacketData,
    IN  PIVI_PREFIX_MIB  PrefixMib
    );


UINT
Icmp6to4(
    IN  PUCHAR            Ipv6PacketData, 
    OUT PUCHAR            Ipv4PacketData, 
    IN  USHORT            OldId,
    IN  ULONG             PrefixLength
    );


UINT
Udp4to6(
    IN  PUCHAR            Ipv4PacketData, 
    OUT PUCHAR            Ipv6PacketData,
    IN  PIVI_PREFIX_MIB   PrefixMib
    );


UINT
Udp6to4(
    IN  PUCHAR Ipv6PacketData, 
    OUT PUCHAR Ipv4PacketData, 
    IN  USHORT OldPort
    );


UINT
PacketData4to6(
    IN  PUCHAR            Ipv4PacketData, 
    OUT PUCHAR            Ipv6PacketData,
    IN  PIVI_PREFIX_MIB   PrefixMib
    );

#endif // _XLATE_H_