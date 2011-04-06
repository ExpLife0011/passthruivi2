#include "precomp.h"
#pragma hdrstop

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
    ResetUdpListsSafe();
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
    NdisAllocateSpinLock(&StateListLock);
    NdisAllocateSpinLock(&PortListLock);
    NdisAllocateSpinLock(&IdListLock);
    NdisAllocateSpinLock(&PrefixListLock);
    
    InitTcpLists();
    InitUdpLists();
    InitIcmpLists();
    InitPrefixList();
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
    ResetUdpLists();
    ResetIcmpLists();
    ResetPrefixList();
    
    NdisFreeSpinLock(&StateListLock);
    NdisFreeSpinLock(&PortListLock);
    NdisFreeSpinLock(&IdListLock);
    NdisFreeSpinLock(&PrefixListLock);
}
