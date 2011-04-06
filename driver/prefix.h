#ifndef _PREFIX_H_
#define _PREFIX_H_

typedef struct _IVI_PREFIX_MIB
{
    IN_ADDR    Address;       // Target IPv4 address
    IN6_ADDR   Prefix;        // IPv6 prefix corresponding to the IPv4 address
    UCHAR      PrefixLength;  // Must be a multiple of 8
    UCHAR      XlateMode;     // 0 for 1:1 mapping, 1 for 1:N mapping
    USHORT     SuffixCode;    // Compressed representation of Ratio and Index info; 0 for 1:1 mapping
} IVI_PREFIX_MIB, *PIVI_PREFIX_MIB;

#define PREFIX_LOOKUP_MAX_RETRIES   5

typedef struct _PREFIX_LOOKUP_CONTEXT
{
    LIST_ENTRY      ListEntry;
    LARGE_INTEGER   EntryCreateTime;   // The time when this entry is created
    LARGE_INTEGER   EntryTimeOut;      // Time-out value for this entry
    IVI_PREFIX_MIB  Mib;
    PUCHAR          HoldPacketData;    // Hold only most recent packet data; set to NULL after the prefix is resolved
    BOOLEAN         Resolved;          // Set to TRUE after the prefix is resolved for this entry
    UCHAR           TryCount;          // Counts the request send times on this entry
} PREFIX_LOOKUP_CONTEXT, *PPREFIX_LOOKUP_CONTEXT;


extern LIST_ENTRY        PrefixListHead;
extern NDIS_SPIN_LOCK    PrefixListLock;
extern IVI_PREFIX_MIB    LocalPrefixInfo;
extern IN6_ADDR          PrefixServerAddress;


VOID
InitPrefixList(
    VOID
    );


VOID
ResetPrefixList(
    VOID
    );


PPREFIX_LOOKUP_CONTEXT
PrefixLookupAddr4(
    IN PIN_ADDR                  Addr
    );


#endif // _PREFIX_H_