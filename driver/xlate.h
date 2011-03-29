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


// IVI map functions
INT char_array_equal(PUCHAR array1, PUCHAR array2, INT len);
INT is_ivi_address(PUCHAR addr);
VOID ip_addr4to6(PUCHAR ip_addr, PUCHAR ip6_addr, UINT localip);
VOID ip4to6(IP_HEADER *ih, IP6_HEADER *ip6h);
VOID ip_addr6to4(PUCHAR ip6_addr, PUCHAR ip_addr);
VOID ip6to4(IP6_HEADER *ip6h, IP_HEADER *ih);

UINT tcp4to6(PUCHAR pPacket, PUCHAR pNewPacket);
UINT tcp6to4(PUCHAR pPacket, PUCHAR pNewPacket);
UINT icmp4to6(PUCHAR pPacket, PUCHAR pNewPacket);
UINT icmp6to4(PUCHAR pPacket, PUCHAR pNewPacket);
UINT udp4to6(PUCHAR pPacket, PUCHAR pNewPacket);
UINT udp6to4(PUCHAR pPacket, PUCHAR pNewPacket);

#endif // _XLATE_H