#ifndef _PORTMAP_TCP_H_
#define _PORTMAP_TCP_H_

// Timer consts
#define SECS   * 1E7    // Equals to 1 sec in LARGE_INTEGER.
#define MINS   * 60 SECS
#define HOURS  * 60 MINS
#define DAYS   * 24 HOURS


// Packet flow direction
typedef enum _PACKET_DIR
{
    PACKET_DIR_LOCAL = 0,  // Sent from local to remote
    PACKET_DIR_REMOTE,     // Sent from remote to local
    PACKET_DIR_MAX
} PACKET_DIR, *PPACKET_DIR;


// TCP option code
#define TCP_OPT_EOL              0
#define TCP_OPT_NOP              1
#define TCP_OPT_MSS              2
#define TCP_OPT_WINDOW_SCALE     3
#define TCP_OPT_SACK_PERM        4
#define TCP_OPT_SACK             5
#define TCP_OPT_TIMESTAMP        8

// TCP option length
#define TCP_OPTLEN_MSS           4
#define TCP_OPTLEN_WINDOW_SCALE  3
#define TCP_OPTLEN_SACK_PERM     2
#define TCP_OPTLEN_TIMESTAMP     10

// TCP option length including zero padding
#define TCP_OPTLEN_TSTAMP_ALIGNED      12
#define TCP_OPTLEN_WSCALE_ALOGNED      4
#define TCP_OPTLEN_SACKPERM_ALIGNED    4
#define TCP_OPTLEN_SACK_BASE           2
#define TCP_OPTLEN_SACK_BASE_ALIGNED   4
#define TCP_OPTLEN_SACK_PERBLOCK       8
#define TCP_OPTLEN_MSS_ALIGNED         4

// TCP control bits mask
#define TCP_BIT_FIN 0x01
#define TCP_BIT_SYN 0x02
#define TCP_BIT_RST 0x04
#define TCP_BIT_PSH 0x08
#define TCP_BIT_ACK 0x10
#define TCP_BIT_URG 0x20

typedef enum _TCP_BIT_SET
{
    TCP_SYN_SET = 0,
    TCP_SYNACK_SET,
    TCP_FIN_SET,
    TCP_ACK_SET,
    TCP_RST_SET,
    TCP_NONE_SET
} TCP_BIT_SET, *PTCP_BIT_SET;

typedef enum _TCP_STATUS
{
    TCP_STATUS_NONE = 0,      // Initial state
    TCP_STATUS_SYN_SENT,      // SYN only packet sent
    TCP_STATUS_SYN_RECV,      // SYN-ACK packet sent
    TCP_STATUS_ESTABLISHED,   // ACK packet sent
    TCP_STATUS_FIN_WAIT,      // FIN packet sent
    TCP_STATUS_CLOSE_WAIT,    // ACK sent after FIN received
    TCP_STATUS_LAST_ACK,      // FIN sent after FIN received
    TCP_STATUS_TIME_WAIT,     // Last ACK sent
    TCP_STATUS_CLOSE,         // Connection closed
    TCP_STATUS_SYN_SENT2,     // SYN only packet received after SYN sent, simultaneous open
    TCP_STATUS_MAX,
    TCP_STATUS_IGNORE
} TCP_STATUS, *PTCP_STATUS;

#define STATE_OPTION_WINDOW_SCALE      0x01    // Sender uses windows scale
#define STATE_OPTION_SACK_PERM         0x02    // Sender allows SACK option
#define STATE_OPTION_CLOSE_INIT        0x04    // Sender sent Fin first
#define STATE_OPTION_DATA_UNACK        0x10    // Has unacknowledged data
#define STATE_OPTION_MAXACK_SET        0x20    // MaxAck in sender state info has been set. 
                                               // This flag is set when we see the first non-zero
                                               // ACK in TCP header sent by the sender.


typedef struct _TCP_STATE_INFO
{
    ULONG  End;
    ULONG  MaxEnd;
    ULONG  MaxWindow;
    ULONG  MaxAck;
    UCHAR  Scale;
    UCHAR  Options;
} TCP_STATE_INFO, *PTCP_STATE_INFO;

typedef struct _TCP_STATE_CONTEXT
{
    LIST_ENTRY        ListEntry;      // Linked to TCP state list
    // Indexes pointing back to port hash table
    USHORT            OriginalPort;   // Index for TcpPortMapOutTable, recording local port
    USHORT            MappedPort;     // Index for TcpPortMapInTable, recording mapped port
    BOOLEAN           Translated;     // TRUE for 4to6 map; FALSE for 6to6 map.
    
    // TCP state info
    TCP_STATE_INFO    Seen[PACKET_DIR_MAX];     // Seen[0] for local state, Seen[1] for remote state
    LARGE_INTEGER     StateSetTime;    // The time when the current state is set
    LARGE_INTEGER     StateTimeOut;    // Timeout value for the current state
    TCP_STATUS        Status;
    // For detecting retransmitted packets
    PACKET_DIR        LastDir;
    UCHAR             RetransCount;
    UCHAR             LastControlBits;
    ULONG             LastWindow;
    ULONG             LastSeq;
    ULONG             LastAck;
    ULONG             LastEnd;
} TCP_STATE_CONTEXT, *PTCP_STATE_CONTEXT;

// Hash table entry for TCP port map
typedef struct _TCP_PORT_MAP
{
    // Pointer to TCP state context structure
    PTCP_STATE_CONTEXT    State;
} TCP_PORT_MAP, *PTCP_PORT_MAP;


typedef enum _FILTER_STATUS
{
    FILTER_ACCEPT = 0,    // Everything is good, let the packet pass
    FILTER_DROP,          // Packet is invalid, but the state is not tainted
    FILTER_DROP_CLEAN     // Both packet and state is invalid
} FILTER_STATUS, *PFILTER_STATUS;

extern NDIS_SPIN_LOCK  StateListLock;

extern TCP_PORT_MAP    TcpPortMapOutTable[65536];
extern TCP_PORT_MAP    TcpPortMapInTable[65536];

VOID
InitTcpLists(
    VOID
    );

VOID
ResetTcpListsSafe(
    VOID
    );

VOID
ResetTcpLists(
    VOID
    );

VOID
RefreshTcpListEntrySafe(
    VOID
    );

USHORT
GetTcpPortMapOut(
    IN PTCP_HEADER     th,
    IN ULONG           len,
    IN BOOLEAN         trans
    );

USHORT
GetTcpPortMapIn(
    IN PTCP_HEADER    th,
    IN ULONG          len
    );

#endif // _PORTMAP_TCP_H_