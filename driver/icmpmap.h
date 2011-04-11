#ifndef _ICMPMAP_H_
#define _ICMPMAP_H_

typedef struct _ICMP_MAP_CONTEXT
{
    LIST_ENTRY        ListEntry;    // Linked to ICMP map list
    // Indexes pointing back to id hash table
    USHORT            OriginalId;   // Index for IcmpIdMapOutTable, recording local id.
    USHORT            MappedId;     // Index for IcmpIdMapInTable, recording mapped id.
    LARGE_INTEGER     MapSetTime;   // The time when the current map is set
    BOOLEAN           Translated;   // TRUE for 4to6 map; FALSE for 6to6 map.
} ICMP_MAP_CONTEXT, *PICMP_MAP_CONTEXT;

// Hash table entry for ICMP id map
typedef struct _ICMP_ID_MAP
{
    // Pointer to ICMP map context structure
    PICMP_MAP_CONTEXT    Map;
} ICMP_ID_MAP, *PICMP_ID_MAP;


extern LARGE_INTEGER     IcmpTimeOut;

extern LIST_ENTRY        IdListHead;
extern LONG              IdListLength;
extern USHORT            LastAllocatedId;
extern NDIS_SPIN_LOCK    IdListLock;

extern ICMP_ID_MAP       IcmpIdMapOutTable[65536];
extern ICMP_ID_MAP       IcmpIdMapInTable[65536];


VOID
InitIcmpLists(
    VOID
    );

VOID
ResetIcmpListsSafe(
    VOID
    );
    
VOID
ResetIcmpLists(
    VOID
    );

VOID
RefreshIcmpListEntrySafe(
    VOID
    );

VOID
RefreshIcmpListEntry(
    VOID
    );

BOOLEAN
GetIcmpIdMapOut(
    IN   USHORT           original,
    IN   BOOLEAN          trans,
    OUT  PUSHORT          mapped
    );

BOOLEAN
GetIcmpIdMapIn(
    IN  USHORT            mapped,
    OUT PUSHORT           original,
    OUT PBOOLEAN          trans
    );

#endif // _ICMPMAP_H_