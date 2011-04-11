#include "precomp.h"
#pragma hdrstop


BOOLEAN
IsTimeOut(
    IN PLARGE_INTEGER newtime,
    IN PLARGE_INTEGER oldtime,
    IN PLARGE_INTEGER timeout
    )
/*++

Routine Description:

    Check whether a state timer is timeout.
    
Arguments:

    newtime - Pointer to current system time
    oldtime - Pointer to system time when the current state is set
    timeout - Pointer to TCP timeout value corresponding to current state

Return Value:

    Mapped port number if find mapping is successful,
    0 if failed to find or create a mapping info.

--*/
{
    return (newtime->QuadPart - oldtime->QuadPart >= timeout->QuadPart);
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
