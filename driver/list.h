#ifndef _LIST_H_
#define _LIST_H_

// Spin lock for map list structure
extern NDIS_SPIN_LOCK    PortListLock;

// Time-Out for mapping entries
extern LARGE_INTEGER     UdpTimeOut;


typedef struct port4to6{
    USHORT port_6;
    USHORT valid;
}port4to6;

extern port4to6 port4to6_list[65536];

typedef struct port6to4{
    USHORT port_4;
    USHORT trans;    // Indicate whether this port is xlated from ipv4 packet
}port6to4;

extern port6to4 port6to4_list[65536];

extern LARGE_INTEGER port_timer_list[65536];

extern USHORT port_used;
extern USHORT port_start;


VOID
ResetMapListsSafe(
    VOID
    );

VOID
InitMapListsAndLocks(
    VOID
    );

VOID
ReleaseMapListsAndLocks(
    VOID
    );


#endif // _LIST_H
