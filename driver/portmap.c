#include "precomp.h"
#pragma hdrstop

// UDP mapping time-out.
LARGE_INTEGER     UdpTimeOut = { 5 MINS };   // See RFC 4787

// Head of UDP port map list
LIST_ENTRY        PortListHead;
// Length of UDP port map list
LONG              PortListLength = 0;
// Remember last allocated UDP port
USHORT            LastAllocatedUdpPort = 0;
// Spin lock for UDP mapping list.
NDIS_SPIN_LOCK    PortListLock;

// Large hash table for UDP port mapping
UDP_PORT_MAP       UdpPortMapOutTable[65536];   // Hash table for UDP from original port to mapping port
UDP_PORT_MAP       UdpPortMapInTable[65536];    // Hash table for UDP from mapping port to original port


VOID
InitUdpLists(
    VOID
    )
/*++

Routine Description:

    Initialize UDP port map related lists.
    This function is NOT thread-safe and should only be called in DriverEntry function 
    before Protocol and Miniport handlers are registered to NDIS.
    
--*/
{
    InitializeListHead(&PortListHead);
    PortListLength = 0;
    NdisZeroMemory(UdpPortMapOutTable, 65536 * sizeof(UDP_PORT_MAP));
    NdisZeroMemory(UdpPortMapInTable, 65536 * sizeof(UDP_PORT_MAP));
}


VOID
ResetUdpListsSafe(
    VOID
    )
/*++

Routine Description:

    Clear UDP port list entries and reset hash tables.
    This function is thread-safe. Do NOT acquire port
    list spin lock around this function.
    
--*/
{
    PLIST_ENTRY p, temp;
    
    NdisAcquireSpinLock(&PortListLock);
    
    if (IsListEmpty(&PortListHead))
    {
        // List is empty, nothing to be done.
        NdisReleaseSpinLock(&PortListLock);
        return;
    }
    
    p = PortListHead.Flink;
    while (p != &PortListHead)
    {
        PUDP_MAP_CONTEXT Map = CONTAINING_RECORD(p, UDP_MAP_CONTEXT, ListEntry);
        
        // Release mapping info and reset corresponding hash table entry
        DBGPRINT(("==> ResetUdpListsSafe: map %d -> %d removed.\n", 
                  Map->OriginalPort, Map->MappedPort));
        // Protect the loop from break
        temp = p;
        p = p->Flink;
        // Clear hash table pointer
        UdpPortMapOutTable[Map->OriginalPort].Map = NULL;
        UdpPortMapInTable[Map->MappedPort].Map = NULL;
        // Remove entry and memory
        RemoveEntryList(temp);
        PortListLength--;
        NdisFreeMemory(Map, 0, 0);
        //DBGPRINT(("==> ResetUdpListsSafe: map context memory freed.\n"));
        // Go to next entry
    }
    
    if (PortListLength != 0)
    {
        // This should not happen
        PortListLength = 0;
    }
    
    NdisReleaseSpinLock(&PortListLock);
}


VOID
ResetUdpLists(
    VOID
    )
/*++

Routine Description:

    Clear UDP port mapping list entries and reset hash tables.
    This function is NOT thread-safe and should only be called in driver unload function 
    after the handlers are unregistered from NDIS.
    
--*/
{
    PLIST_ENTRY p, temp;
    
    if (IsListEmpty(&PortListHead))
    {
        // List is empty, nothing to be done.
        return;
    }
    
    p = PortListHead.Flink;
    while (p != &PortListHead)
    {
        PUDP_MAP_CONTEXT Map = CONTAINING_RECORD(p, UDP_MAP_CONTEXT, ListEntry);
        
        // Release mapping info and reset corresponding hash table entry
        DBGPRINT(("==> ResetUdpLists: map %d -> %d removed.\n", 
                  Map->OriginalPort, Map->MappedPort));
        // Protect the loop from break
        temp = p;
        p = p->Flink;
        // Clear hash table pointer
        UdpPortMapOutTable[Map->OriginalPort].Map = NULL;
        UdpPortMapInTable[Map->MappedPort].Map = NULL;
        // Remove entry and memory
        RemoveEntryList(temp);
        PortListLength--;
        NdisFreeMemory(Map, 0, 0);
        //DBGPRINT(("==> ResetUdpLists: map context memory freed.\n"));
        // Go to next entry
    }
    
    if (PortListLength != 0)
    {
        // This should not happen
        PortListLength = 0;
    }
}


VOID
RefreshUdpListEntrySafe(
    VOID
    )
/*++

Routine Description:

    Remove stale mapping info from UDP port map list entries.
    This function is thread-safe. Do NOT acquire id list 
    spin lock around this function.

--*/
{
    LARGE_INTEGER now;
    PLIST_ENTRY p, temp;
    
    NdisAcquireSpinLock(&PortListLock);
    
    if (IsListEmpty(&PortListHead))
    {
        // List is empty, nothing to be done.
        NdisReleaseSpinLock(&PortListLock);
        return;
    }
    
    NdisGetCurrentSystemTime(&now);
    p = PortListHead.Flink;
    while (p != &PortListHead)
    {
        PUDP_MAP_CONTEXT Map = CONTAINING_RECORD(p, UDP_MAP_CONTEXT, ListEntry);
        
        if (IsTimeOut(&now, &(Map->MapSetTime), &UdpTimeOut))
        {
            // Time out. Release mapping info and reset corresponding hash table entry
            DBGPRINT(("==> RefreshUdpListEntrySafe: map %d -> %d time out. Delete.\n", 
                      Map->OriginalPort, Map->MappedPort));
            // Protect the loop from break
            temp = p;
            p = p->Flink;
            // Clear hash table pointer
            UdpPortMapOutTable[Map->OriginalPort].Map = NULL;
            UdpPortMapInTable[Map->MappedPort].Map = NULL;
            // Remove entry and clear memory
            RemoveEntryList(temp);
            PortListLength--;
            NdisFreeMemory(Map, 0, 0);
            //DBGPRINT(("==> RefreshUdpListEntrySafe: map context memory freed.\n"));
            // Go to next entry
        }
        else
        {
            // Go to next entry
            // Map set time is refreshed when this map is accessed by mapping functions, no need to refresh it here
            p = p->Flink;
        }
    }
    NdisReleaseSpinLock(&PortListLock);
}


VOID
RefreshUdpListEntry(
    VOID
    )
/*++

Routine Description:

    Remove stale mapping info from UDP port map list entries.
    This function is NOT thread-safe. Caller must acquire id
    list spin lock around this function to protect syncronization.

--*/
{
    LARGE_INTEGER now;
    PLIST_ENTRY p, temp;
    
    if (IsListEmpty(&PortListHead))
    {
        // List is empty, nothing to be done.
        return;
    }
    
    NdisGetCurrentSystemTime(&now);
    p = PortListHead.Flink;
    while (p != &PortListHead)
    {
        PUDP_MAP_CONTEXT Map = CONTAINING_RECORD(p, UDP_MAP_CONTEXT, ListEntry);
        
        if (IsTimeOut(&now, &(Map->MapSetTime), &UdpTimeOut))
        {
            // Time out. Release mapping info and reset corresponding hash table entry
            DBGPRINT(("==> RefreshUdpListEntry: map %d -> %d time out. Delete.\n", 
                      Map->OriginalPort, Map->MappedPort));
            // Protect the loop from break
            temp = p;
            p = p->Flink;
            // Clear hash table pointer
            UdpPortMapOutTable[Map->OriginalPort].Map = NULL;
            UdpPortMapInTable[Map->MappedPort].Map = NULL;
            // Remove entry and clear memory
            RemoveEntryList(temp);
            PortListLength--;
            NdisFreeMemory(Map, 0, 0);
            //DBGPRINT(("==> RefreshUdpListEntry: map context memory freed.\n"));
            // Go to next entry
        }
        else
        {
            // Go to next entry
            // Map set time is refreshed when this map is accessed by mapping functions, no need to refresh it here
            p = p->Flink;
        }
    }
}


BOOLEAN
GetUdpPortMapOut(
    IN   USHORT   original,
    IN   BOOLEAN  trans,
    OUT  PUSHORT  mapped
    )
/*++

Routine Description:

    Get the mapped id for the outflow UDP packet.
    
Arguments:

    original - Original UDP source port in outflow packet
    trans - TRUE for 4to6 mapping; FLASE for 6to6 mapping
    mapped - Pointer to caller-supplied memory that holds the returned mapping port

Return Value:

    TRUE if find mapping is successful, mapped port is returned in 'mapped' pointer;
    FALSE if failed to find or create a mapping info, 'mapped' is set to 0 in this case.

--*/
{
    USHORT    ret = 0;
    SHORT     remaining;
    LONG      MaxPorts = 65536 / mod;
    
    USHORT    rover;
    USHORT    low;
    USHORT    high;
    
    PUDP_MAP_CONTEXT  Map = NULL;
    NDIS_STATUS       Status;

    NdisAcquireSpinLock(&PortListLock);
    
    // Do NOT call RefreshUdpListEntrySafe() since we have already hold the spin lock.
    RefreshUdpListEntry();
    
    if (UdpPortMapOutTable[original].Map != NULL)
    {
        Map = UdpPortMapOutTable[original].Map;
        if (Map->OriginalPort == original && Map->Translated == trans)  // Found existing mapping info
        {
            ret = Map->MappedPort;
            NdisGetCurrentSystemTime(&(Map->MapSetTime));  // refresh timer
            DBGPRINT(("==> GetUdpPortMapOut: Find Map %d -> %d\n", Map->OriginalPort, Map->MappedPort));
            *mapped = ret;
        }
    }
    
    if (ret == 0) // no existing map, generate new map
    {
        if (PortListLength >= MaxPorts)
        {
            DBGPRINT(("==> GetUdpPortMapOut: list full. Map id is used up.\n"));
            *mapped = 0;
            NdisReleaseSpinLock(&PortListLock);
            return FALSE;
        }
        
        if (xlate_mode)   // 1:N id mapping
        {
            low = (USHORT)(1024 / mod) + 1;
            high = MaxPorts - 1;
            remaining = (high - low) + 1;
    
            if (PortListLength != 0)
            {
                rover = (USHORT)(LastAllocatedUdpPort / mod) + 1;
            }
            else
            {
                rover = low;
            }
            
            do
            {
                ret = rover * mod + res;
                if (UdpPortMapInTable[ret].Map == NULL)
                {
                    // find idle ivi-id
                    break;
                }
                rover++;
                if (rover > high)
                {
                    rover = low;
                }
                remaining--;
            }
            while (remaining > 0);
            
            if (remaining <= 0)
            {
                *mapped = 0;
                NdisReleaseSpinLock(&PortListLock);
                return FALSE;
            }
        }
        else
        {
            // 1:1 id mapping
            ret = original;
        }
        
        // Allocate map info memory
        Status = NdisAllocateMemoryWithTag((PVOID)&Map, sizeof(UDP_MAP_CONTEXT), TAG);
        if (Status != NDIS_STATUS_SUCCESS)
        {
            // No memory for map info. Fail this map.
            DBGPRINT(("==> GetUdpPortMapOut: NdisAllocateMemoryWithTag failed for port %d\n", original));
            NdisReleaseSpinLock(&PortListLock);
            *mapped = 0;
            return FALSE;
        }
        NdisZeroMemory(Map, sizeof(UDP_MAP_CONTEXT));
        
        // Routine to add new map-info
        Map->OriginalPort = original;
        Map->MappedPort = ret;
        Map->Translated = trans;
        NdisGetCurrentSystemTime(&(Map->MapSetTime));  // set timer for newly added mapping
        // Set hash table pointer
        UdpPortMapOutTable[Map->OriginalPort].Map = Map;
        UdpPortMapInTable[Map->MappedPort].Map = Map;
        // Linked list need not be sorted. Just insert new entry at tail.
        InsertTailList(&PortListHead, &(Map->ListEntry));
        PortListLength++;
        LastAllocatedUdpPort = ret;
        DBGPRINT(("==> GetUdpPortMapOut: New map %d -> %d added, xlate=%d.\n", 
                  Map->OriginalPort, Map->MappedPort, Map->Translated));
        *mapped = ret;
    }
    
    NdisReleaseSpinLock(&PortListLock);
    
    return TRUE;
}


BOOLEAN
GetUdpPortMapIn(
    IN  USHORT    mapped,
    OUT PUSHORT   original,
    OUT PBOOLEAN  trans
    )
/*++

Routine Description:

    Get the original UDP port for the incoming UDP packet.
    
Arguments:

    mapped - Mapped UDP destination port in incoming packet
    original - Pointer to caller-supplied memory that holds the returned original port, cannot be NULL
    trans - Pointer to caller-supplied memory that holds the translate flag for this mapping, cannot be NULL

Return Value:

    TRUE if find mapping is successful, original port is returned in 'original' pointer;
    FALSE if no valid mapping exists for this mapped port, 'original' and 'trans' is set to 0(FALSE) in this case.

--*/
{
    BOOLEAN  flag = FALSE;
    
    PUDP_MAP_CONTEXT  Map = NULL;
    
    NdisAcquireSpinLock(&PortListLock);
    
    // Do NOT call RefreshUdpListEntrySafe() since we have already hold the spin lock.
    RefreshUdpListEntry();
    
    if (UdpPortMapInTable[mapped].Map != NULL)
    {
        Map = UdpPortMapInTable[mapped].Map;
        if (Map->MappedPort == mapped)  // Found existing mapping info
        {
            *original = Map->OriginalPort;
            *trans = Map->Translated;
            NdisGetCurrentSystemTime(&(Map->MapSetTime));  // refresh timer
            DBGPRINT(("==> GetUdpPortMapIn: Find Map %d -> %d, trans flag is %d.\n", Map->OriginalPort, Map->MappedPort, Map->Translated));
            flag = TRUE;
        }
    }
    else
    {
        *original = 0;
        *trans = FALSE;
        flag = FALSE;
    }
    
    NdisReleaseSpinLock(&PortListLock);
    
    return flag;
}
