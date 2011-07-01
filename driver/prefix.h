#ifndef _PREFIX_H_
#define _PREFIX_H_

typedef struct _IVI_PREFIX_MIB
{
    IN_ADDR    Address;       // Target IPv4 address
    ULONG      Mask;          // Network mask of target IPv4 address
    IN6_ADDR   Prefix;        // IPv6 prefix corresponding to the IPv4 address
    UCHAR      PrefixLength;  // Must be a multiple of 8
    UCHAR      XlateMode;     // 0 for 1:1 mapping, 1 for 1:N mapping
    USHORT     SuffixCode;    // Compressed representation of Ratio and Offset info in host byte order; 0 for 1:1 mapping
    USHORT     Ratio;         // 16 bit IVI ratio
    USHORT     Offset;        // 16 bit IVI offset
} IVI_PREFIX_MIB, *PIVI_PREFIX_MIB;

#define PREFIX_LOOKUP_MAX_RETRIES   5

typedef struct _PREFIX_LOOKUP_CONTEXT
{
    LIST_ENTRY      ListEntry;
    LARGE_INTEGER   EntryTimeOut;      // Time-out value for this entry on the current state
    LARGE_INTEGER   StateSetTime;      // The time when this entry enters the current state
    IVI_PREFIX_MIB  Mib;
    PUCHAR          HoldPacketData;    // Hold only most recent packet data; set to NULL after the prefix is resolved
    UINT            HoldDataLength;    // Length of the hold packet; meaningless if HoldPacketData pointer is NULL
    BOOLEAN         Resolved;          // Set to TRUE after the prefix is resolved for this entry
    UCHAR           TryCount;          // Counts the request send times on this entry
} PREFIX_LOOKUP_CONTEXT, *PPREFIX_LOOKUP_CONTEXT;


/* Prefix lookup protocol */
typedef struct _PREFIX_INFO_OPTION
{
    UCHAR       type;
    UCHAR       length;
    UCHAR       flag_masklen;
    UCHAR       prefixlen;
    ULONG       ttl;
    IN6_ADDR    prefix;
} PREFIX_INFO_OPTION, *PPREFIX_INFO_OPTION;

#define PREFIX_INFO_MBIT     0x80  // '1000 0000'
#define PREFIX_INFO_MASKLEN  0x3F  // '0011 1111'

typedef struct _PORT_RANGE_OPTION
{
    UCHAR    type;
    UCHAR    length;
    USHORT   rsvd;
    USHORT   ratio;
    USHORT   offset;
} PORT_RANGE_OPTION, *PPORT_RANGE_OPTION;

#define ICMP6_PREF_REQUEST    204
#define ICMP6_PREF_RESPONSE   205

#define PREF_OPT_PREFINFO       7
#define PREF_OPT_PORTRANGE      8

#define PREF_OPTLEN_PREFONFO    3
#define PREF_OPTLEN_PORTRANGE   1

/* Globals */
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
    IN PIN_ADDR       Addr,
    IN BOOLEAN        CreateNew
    );

PPREFIX_LOOKUP_CONTEXT
PrefixLookupAddr6(
    IN PIN6_ADDR       Addr
    );


PPREFIX_LOOKUP_CONTEXT
ParsePrefixLookupResponse(
    PICMP6_HEADER  Response,
    INT            ResponseLength
    );


#endif // _PREFIX_H_