#include "precomp.h"
#pragma hdrstop

// Head of id map list
LIST_ENTRY        IdListHead;
// Length of id map list
LONG              IdListLength = 0;
// Remember last allocated id
USHORT            LastAllocatedId = 0;
// Spin lock for map list structure
NDIS_SPIN_LOCK    IdListLock;

// Time-Out for mapping entries
LARGE_INTEGER     IcmpTimeOut = { 1 MINS };   // See RFC 5508

// Large hash table for ICMP id mapping
ICMP_ID_MAP       IcmpIdMapOutTable[65536];   // Hash table for ICMP from original id to mapping id
ICMP_ID_MAP       IcmpIdMapInTable[65536];    // Hash table for ICMP from mapping id to original id



VOID
InitIcmpLists(
    VOID
    )
/*++

Routine Description:

    Initialize ICMP id map related lists.
    This function is NOT thread-safe and should only be called in DriverEntry function 
    before Protocol and Miniport handlers are registered to NDIS.
    
--*/
{
    InitializeListHead(&IdListHead);
    IdListLength = 0;
    NdisZeroMemory(IcmpIdMapOutTable, 65536 * sizeof(ICMP_ID_MAP));
    NdisZeroMemory(IcmpIdMapInTable, 65536 * sizeof(ICMP_ID_MAP));
}


VOID
ResetIcmpListsSafe(
    VOID
    )
/*++

Routine Description:

    Clear Icmp id list entries and reset hash tables.
    This function is thread-safe. Do NOT acquire id
    list spin lock around this function.
    
--*/
{
    PLIST_ENTRY p, temp;
    
    NdisAcquireSpinLock(&IdListLock);
    
    if (IsListEmpty(&IdListHead))
    {
        // Id list is empty, nothing to be done.
        NdisReleaseSpinLock(&IdListLock);
        return;
    }
    
    p = IdListHead.Flink;
    while (p != &IdListHead)
    {
        PICMP_MAP_CONTEXT Map = CONTAINING_RECORD(p, ICMP_MAP_CONTEXT, ListEntry);
        
        // Release ID mapping info and reset corresponding hash table entry
        DBGPRINT(("==> ResetIcmpListsSafe: map %d -> %d removed.\n", 
                  Map->OriginalId, Map->MappedId));
        // Protect the loop from break
        temp = p;
        p = p->Flink;
        // Clear hash table pointer
        IcmpIdMapOutTable[Map->OriginalId].Map = NULL;
        IcmpIdMapInTable[Map->MappedId].Map = NULL;
        // Remove entry and memory
        RemoveEntryList(temp);
        IdListLength--;
        NdisFreeMemory(Map, 0, 0);
        //DBGPRINT(("==> ResetIcmpListsSafe: map context memory freed.\n"));
        // Go to next entry
    }
    
    if (IdListLength != 0)
    {
        // This should not happen
        IdListLength = 0;
    }
    
    NdisReleaseSpinLock(&IdListLock);
}


VOID
ResetIcmpLists(
    VOID
    )
/*++

Routine Description:

    Clear ICMP id mapping list entries and reset hash tables.
    This function is NOT thread-safe and should only be called in driver unload function 
    after the handlers are unregistered from NDIS.
    
--*/
{
    PLIST_ENTRY p, temp;
    
    if (IsListEmpty(&IdListHead))
    {
        // Id list is empty, nothing to be done.
        return;
    }
    
    p = IdListHead.Flink;
    while (p != &IdListHead)
    {
        PICMP_MAP_CONTEXT Map = CONTAINING_RECORD(p, ICMP_MAP_CONTEXT, ListEntry);
        
        // Release mapping info and reset corresponding hash table entry
        DBGPRINT(("==> ResetIcmpLists: map %d -> %d removed.\n", 
                  Map->OriginalId, Map->MappedId));
        // Protect the loop from break
        temp = p;
        p = p->Flink;
        // Clear hash table pointer
        IcmpIdMapOutTable[Map->OriginalId].Map = NULL;
        IcmpIdMapInTable[Map->MappedId].Map = NULL;
        // Remove entry and memory
        RemoveEntryList(temp);
        IdListLength--;
        NdisFreeMemory(Map, 0, 0);
        //DBGPRINT(("==> ResetIcmpLists: map context memory freed.\n"));
        // Go to next entry
    }
    
    if (IdListLength != 0)
    {
        // This should not happen
        IdListLength = 0;
    }
}


VOID
RefreshIcmpListEntrySafe(
    VOID
    )
/*++

Routine Description:

    Remove stale mapping info from ICMP id map list entries.
    This function is thread-safe. Do NOT acquire id list 
    spin lock around this function.

--*/
{
    LARGE_INTEGER now;
    PLIST_ENTRY p, temp;
    
    NdisAcquireSpinLock(&IdListLock);
    
    if (IsListEmpty(&IdListHead))
    {
        // List is empty, nothing to be done.
        NdisReleaseSpinLock(&IdListLock);
        return;
    }
    
    NdisGetCurrentSystemTime(&now);
    p = IdListHead.Flink;
    while (p != &IdListHead)
    {
        PICMP_MAP_CONTEXT Map = CONTAINING_RECORD(p, ICMP_MAP_CONTEXT, ListEntry);
        
        if (IsTimeOut(&now, &(Map->MapSetTime), &IcmpTimeOut))
        {
            // Time out. Release mapping info and reset corresponding hash table entry
            DBGPRINT(("==> RefreshIcmpListEntrySafe: map %d -> %d time out. Delete.\n", 
                      Map->OriginalId, Map->MappedId));
            // Protect the loop from break
            temp = p;
            p = p->Flink;
            // Clear hash table pointer
            IcmpIdMapOutTable[Map->OriginalId].Map = NULL;
            IcmpIdMapInTable[Map->MappedId].Map = NULL;
            // Remove entry and clear memory
            RemoveEntryList(temp);
            IdListLength--;
            NdisFreeMemory(Map, 0, 0);
            //DBGPRINT(("==> RefreshIcmpListEntrySafe: map context memory freed.\n"));
            // Go to next entry
        }
        else
        {
            // Go to next entry
            // Map set time is refreshed when this map is accessed by mapping functions, no need to refresh it here
            p = p->Flink;
        }
    }
    NdisReleaseSpinLock(&IdListLock);
}


VOID
RefreshIcmpListEntry(
    VOID
    )
/*++

Routine Description:

    Remove stale mapping info from ICMP id map list entries.
    This function is NOT thread-safe. Caller must acquire id
    list spin lock around this function to protect syncronization.

--*/
{
    LARGE_INTEGER now;
    PLIST_ENTRY p, temp;
    
    if (IsListEmpty(&IdListHead))
    {
        // List is empty, nothing to be done.
        return;
    }
    
    NdisGetCurrentSystemTime(&now);
    p = IdListHead.Flink;
    while (p != &IdListHead)
    {
        PICMP_MAP_CONTEXT Map = CONTAINING_RECORD(p, ICMP_MAP_CONTEXT, ListEntry);
        
        if (IsTimeOut(&now, &(Map->MapSetTime), &IcmpTimeOut))
        {
            // Time out. Release mapping info and reset corresponding hash table entry
            DBGPRINT(("==> RefreshIcmpListEntry: map %d -> %d time out. Delete.\n", 
                      Map->OriginalId, Map->MappedId));
            // Protect the loop from break
            temp = p;
            p = p->Flink;
            // Clear hash table pointer
            IcmpIdMapOutTable[Map->OriginalId].Map = NULL;
            IcmpIdMapInTable[Map->MappedId].Map = NULL;
            // Remove entry and clear memory
            RemoveEntryList(temp);
            IdListLength--;
            NdisFreeMemory(Map, 0, 0);
            //DBGPRINT(("==> RefreshIcmpListEntry: map context memory freed.\n"));
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
GetIcmpIdMapOut(
    IN   USHORT           original,
    IN   BOOLEAN          trans,
    OUT  PUSHORT          mapped
    )
/*++

Routine Description:

    Get the mapped id for the outflow ICMP packet.
    
Arguments:

    original - Original ICMP id in outflow packet.
    trans - TRUE for 4to6 mapping; FLASE for 6to6 mapping.
    mapped - Pointer to caller-supplied memory that holds the returned mapping id.

Return Value:

    TRUE if find mapping is successful, mapped id is returned in 'mapped' pointer;
    FALSE if failed to find or create a mapping info, 'mapped' is set to 0 in this case.

--*/
{
    USHORT    ret = 0;
    SHORT     remaining;
    LONG      MaxIds = 65536 / mod;
    
    USHORT    rover;
    USHORT    low;
    USHORT    high;
    
    PICMP_MAP_CONTEXT  Map = NULL;
    NDIS_STATUS        Status;

    NdisAcquireSpinLock(&IdListLock);
    
    // Do NOT call RefreshIcmpListEntrySafe() since we have already hold the spin lock.
    RefreshIcmpListEntry();
    
    if (IcmpIdMapOutTable[original].Map != NULL)
    {
        Map = IcmpIdMapOutTable[original].Map;
        if (Map->OriginalId == original && Map->Translated == trans)  // Found existing mapping info
        {
            ret = Map->MappedId;
            NdisGetCurrentSystemTime(&(Map->MapSetTime));  // refresh timer
            DBGPRINT(("==> GetIcmpIdMapOut: Find Map %d -> %d\n", Map->OriginalId, Map->MappedId));
        }
    }
    
    if (ret == 0) // no existing map, generate new map
    {
        if (IdListLength >= MaxIds)
        {
            NdisReleaseSpinLock(&IdListLock);
            DBGPRINT(("==> GetIcmpIdMapOut: list full. Map id is used up.\n"));
            *mapped = 0;
            return FALSE;
        }
        
        if (xlate_mode)   // 1:N id mapping
        {
            low = (USHORT)(1024 / mod) + 1;
            high = MaxIds - 1;
            remaining = (high - low) + 1;
    
            if (IdListLength != 0)
            {
                rover = (USHORT)(LastAllocatedId / mod) + 1;
            }
            else
            {
                rover = low;
            }
            
            do
            {
                ret = rover * mod + res;
                if (IcmpIdMapInTable[ret].Map == NULL)
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
                NdisReleaseSpinLock(&IdListLock);
                *mapped = 0;
                return FALSE;
            }
        }
        else
        {
            // 1:1 id mapping
            ret = original;
        }
        
        // Allocate map info memory
        Status = NdisAllocateMemoryWithTag((PVOID)&Map, sizeof(ICMP_MAP_CONTEXT), TAG);
        if (Status != NDIS_STATUS_SUCCESS)
        {
            NdisReleaseSpinLock(&IdListLock);
            // No memory for map info. Fail this map.
            DBGPRINT(("==> GetIcmpIdMapOut: NdisAllocateMemoryWithTag failed for id %d\n", original));
            *mapped = 0;
            return FALSE;
        }
        NdisZeroMemory(Map, sizeof(ICMP_MAP_CONTEXT));
        
        // Routine to add new map-info
        Map->OriginalId = original;
        Map->MappedId = ret; 
        Map->Translated = trans;
        NdisGetCurrentSystemTime(&(Map->MapSetTime));  // set timer for newly added mapping
        // Set hash table pointer
        IcmpIdMapOutTable[Map->OriginalId].Map = Map;
        IcmpIdMapInTable[Map->MappedId].Map = Map;
        // IdListHead need not be sorted. Just insert new entry at tail.
        InsertTailList(&IdListHead, &(Map->ListEntry));
        IdListLength++;
        LastAllocatedId = ret;
        DBGPRINT(("==> GetIcmpIdMapOut: New map %d -> %d added, xlate=%d.\n", 
                  Map->OriginalId, Map->MappedId, Map->Translated));
    }
    
    NdisReleaseSpinLock(&IdListLock);
    
    *mapped = ret;
    
    return TRUE;
}


BOOLEAN
GetIcmpIdMapIn(
    IN  USHORT            mapped,
    OUT PUSHORT           original,
    OUT PBOOLEAN          trans
    )
/*++

Routine Description:

    Get the original id for the incoming ICMP packet.
    
Arguments:

    mapped - Mapped ICMP id in incoming packet
    original - Pointer to caller-supplied memory that holds the returned original id, cannot be NULL
    trans - Pointer to caller-supplied memory that holds the translate flag for this mapping, cannot be NULL

Return Value:

    TRUE if find mapping is successful, caller-supplied pointers are filled with correct values;
    FALSE if no valid mapping exists for this mapped id, 'original' and 'trans' is set to 0(FALSE) in this case.

--*/
{
    BOOLEAN  flag = FALSE;
    
    USHORT   OriginalId = 0;
    BOOLEAN  Translated = FALSE;
    
    PICMP_MAP_CONTEXT  Map = NULL;
    
    NdisAcquireSpinLock(&IdListLock);
    
    // Do NOT call RefreshIcmpListEntrySafe() since we have already hold the spin lock.
    RefreshIcmpListEntry();
    
    if (IcmpIdMapInTable[mapped].Map != NULL)
    {
        Map = IcmpIdMapInTable[mapped].Map;
        if (Map->MappedId == mapped)  // Found existing mapping info
        {
            OriginalId = Map->OriginalId;
            Translated = Map->Translated;
            NdisGetCurrentSystemTime(&(Map->MapSetTime));  // refresh timer
            DBGPRINT(("==> GetIcmpIdMapIn: Find Map %d -> %d, trans flag is %d.\n", Map->OriginalId, Map->MappedId, Map->Translated));
            flag = TRUE;
        }
    }
    
    NdisReleaseSpinLock(&IdListLock);
     
    *original = OriginalId;
    *trans = Translated;
    
    return flag;
}

