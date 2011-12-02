#ifndef _PORTMAP_H_
#define _PORTMAP_H_

typedef struct _UDP_MAP_CONTEXT
{
    LIST_ENTRY        ListEntry;    // Linked to ICMP map list
    // Indexes pointing back to id hash table
    USHORT            OriginalPort;   // Index for UdpPortMapOutTable, recording local port
    USHORT            MappedPort;     // Index for UdpPortMapInTable, recording mapped port
    LARGE_INTEGER     MapSetTime;   // The time when the current map is set
    BOOLEAN           Translated;   // TRUE for 4to6 map; FALSE for 6to6 map.
} UDP_MAP_CONTEXT, *PUDP_MAP_CONTEXT;

// Hash table entry for UDP port map
typedef struct _UDP_PORT_MAP
{
    // Pointer to UDP port map context structure
    PUDP_MAP_CONTEXT    Map;
} UDP_PORT_MAP, *PUDP_PORT_MAP;


extern NDIS_SPIN_LOCK    PortListLock;


VOID
InitUdpLists(
    VOID
    );


VOID
ResetUdpListsSafe(
    VOID
    );


VOID
ResetUdpLists(
    VOID
    );


VOID
RefreshUdpListEntrySafe(
    VOID
    );


VOID
RefreshUdpListEntry(
    VOID
    );


BOOLEAN
GetUdpPortMapOut(
    IN   USHORT   original,
    IN   BOOLEAN  trans,
    OUT  PUSHORT  mapped
    );


BOOLEAN
GetUdpPortMapIn(
    IN  USHORT    mapped,
    OUT PUSHORT   original,
    OUT PBOOLEAN  trans
    );


#endif // _PORTMAP_H_
