#include "precomp.h"
#pragma hdrstop

NDIS_SPIN_LOCK          PortListLock;

LARGE_INTEGER           UdpTimeOut = { 30 MINS };


port4to6 port4to6_list[65536];  // indexed by old(system) port, stored in host-byte order
port6to4 port6to4_list[65536];  // indexed by new(passthru) port, stored in host-byte order

LARGE_INTEGER port_timer_list[65536]; // indexed by old(system) port

USHORT port_used = 0; // used port counter
USHORT port_start = 0; // last new(passthru) port assigned


VOID init_port4to6_list()
{
    NdisZeroMemory(port4to6_list, 65536 * sizeof(port4to6));
}

VOID init_port6to4_list()
{
    NdisZeroMemory(port6to4_list, 65536 * sizeof(port6to4));
}

VOID init_port_timer_list()
{
    NdisZeroMemory(port_timer_list, 65536 * sizeof(LARGE_INTEGER));
}

VOID
ResetMapListsSafe(
    VOID
    )
/*++

Routine Description:

    Reset all protocols' mapping lists and free memory.
    
--*/
{
    ResetTcpListsSafe();
    
    // Reset UDP lists
    NdisAcquireSpinLock(&PortListLock);
    init_port4to6_list();
    init_port6to4_list();
    init_port_timer_list();
    // reset counter
    port_used = 0;
    port_start = 0;
    NdisReleaseSpinLock(&PortListLock);
    
    ResetIcmpListsSafe();
}

VOID
InitMapListsAndLocks(
    VOID
    )
/*++

Routine Description:

    Initialize mapping lists and spin locks for all protocols.
    
--*/
{
    NdisAllocateSpinLock(&PortListLock);
    NdisAllocateSpinLock(&IdListLock);
    NdisAllocateSpinLock(&StateListLock);
    
    InitTcpLists();
    InitIcmpLists();
    
    // Reset UDP lists
    init_port4to6_list();
    init_port6to4_list();
    init_port_timer_list();
    // reset counter
    port_used = 0;
    port_start = 0;
}

VOID
ReleaseMapListsAndLocks(
    VOID
    )
/*++

Routine Description:

    Release mapping lists and spin locks for all protocols.
    
--*/
{
    ResetTcpLists();
    ResetIcmpLists();
    
    NdisFreeSpinLock(&StateListLock);
    NdisFreeSpinLock(&PortListLock);
    NdisFreeSpinLock(&IdListLock);
}
