#include "precomp.h"
#pragma hdrstop

LIST_ENTRY        PrefixListHead;   // Head of the prefix cache list
NDIS_SPIN_LOCK    PrefixListLock;   // Lock for the prefix cache list

LARGE_INTEGER     InvalidEntryTimeOut = { 5 MINS };  // Time-out for unresolved entry

IVI_PREFIX_MIB    LocalPrefixInfo;  // Local prefix information
IN6_ADDR          PrefixServerAddress;  // Prefix server IPv6 address

VOID
InitPrefixList(
    VOID
    )
/*++

Routine Description:

    Initialize prefix information list.
    This function is NOT thread-safe and should only be called in DriverEntry function 
    before Protocol and Miniport handlers are registered to NDIS.
    
--*/
{
    InitializeListHead(&PrefixListHead);
    
    // Initialize local prefix information
    NdisZeroMemory(&LocalPrefixInfo, sizeof(IVI_PREFIX_MIB));
    LocalPrefixInfo.Address.u.dword = 0;  // XXX: Local IPv4 address set to zero
    LocalPrefixInfo.Prefix.u.byte[0] = 0x20;
    LocalPrefixInfo.Prefix.u.byte[1] = 0x01;
    LocalPrefixInfo.Prefix.u.byte[2] = 0x0d;
    LocalPrefixInfo.Prefix.u.byte[3] = 0xa8;
    LocalPrefixInfo.Prefix.u.byte[4] = 0xff;
    LocalPrefixInfo.PrefixLength = 40;
    LocalPrefixInfo.XlateMode = 0;  // XlateMode default to 0 (1:1 mapping); XXX: should be default to 1 (1:N mapping)
    LocalPrefixInfo.SuffixCode = 0x8001;  // SuffixCode for Ratio = 2^8 (256) and Index = 1; XXX: should be set to 0 when XlateMode = 0
    
    // XXX: prefix server address should be configurable
    NdisZeroMemory(&PrefixServerAddress, sizeof(IN6_ADDR));
    // XXX: Set to 2001:da8:ff01:101:100:: now
    PrefixServerAddress.u.byte[0] = 0x20;
    PrefixServerAddress.u.byte[1] = 0x01;
    PrefixServerAddress.u.byte[2] = 0x0d;
    PrefixServerAddress.u.byte[3] = 0xa8;
    PrefixServerAddress.u.byte[4] = 0xff;
    PrefixServerAddress.u.byte[5] = 0x01;
    PrefixServerAddress.u.byte[6] = 0x01;
    PrefixServerAddress.u.byte[7] = 0x01;
    PrefixServerAddress.u.byte[8] = 0x01;
}


VOID
ResetPrefixList(
    VOID
    )
/*++

Routine Description:

    Clear prefix information list entries.
    This function is NOT thread-safe and should only be called in driver unload function 
    after the handlers are unregistered from NDIS.
    
--*/
{
    PLIST_ENTRY p, temp;
    
    if (IsListEmpty(&PrefixListHead))
    {
        // List is empty, nothing to be done.
        return;
    }
    
    p = PrefixListHead.Flink;
    while (p != &PrefixListHead)
    {
        PPREFIX_LOOKUP_CONTEXT PrefixContext = CONTAINING_RECORD(p, PREFIX_LOOKUP_CONTEXT, ListEntry);
        
        // Release mapping info
        DBGPRINT(("==> ResetPrefixLists: prefix for ip %d.%d.%d.%d is removed.\n", 
                  PrefixContext->Mib.Address.u.byte[0], PrefixContext->Mib.Address.u.byte[1], 
                  PrefixContext->Mib.Address.u.byte[2], PrefixContext->Mib.Address.u.byte[3]));
        // Protect the loop from break
        temp = p;
        p = p->Flink;
        // Remove entry and memory
        RemoveEntryList(temp);
        NdisFreeMemory(PrefixContext, 0, 0);
        //DBGPRINT(("==> ResetPrefixLists: prefix context memory freed.\n"));
        // Go to next entry
    }
}


PPREFIX_LOOKUP_CONTEXT
PrefixLookupAddr4(
    IN PIN_ADDR                  Addr
    )
/*++

Routine Description:

    Lookup prefix information in the prefix list. 
    This function is NOT thread-safe.
    
Arguments:

    Addr - Pointer to the IPv4 address that needs to be resolved

Return Value:

    If the entry is found, return pointer to this entry; otherwise, 
    create a new empty entry and return pointer to the new entry.

--*/
{
    PLIST_ENTRY p;
    
    PPREFIX_LOOKUP_CONTEXT Context = NULL;
    
    p = PrefixListHead.Flink;
    while (p != &PrefixListHead)
    {
        PPREFIX_LOOKUP_CONTEXT PrefixContext = CONTAINING_RECORD(p, PREFIX_LOOKUP_CONTEXT, ListEntry);
        
        if (PrefixContext->Mib.Address.u.dword == Addr->u.dword)
        {
            // Found existing prefix entry for this address, may be invalid
            Context = PrefixContext;
            DBGPRINT(("==> PrefixLookupAddr4: prefix context for ip %d.%d.%d.%d found.\n", 
                      Context->Mib.Address.u.byte[0], Context->Mib.Address.u.byte[1], 
                      Context->Mib.Address.u.byte[2], Context->Mib.Address.u.byte[3]));
            break;
        }
    }
    
    if (Context == NULL)
    {
        // No entry found, create a new one and insert to list.
        NDIS_STATUS Status = NdisAllocateMemoryWithTag((PVOID)&Context, sizeof(PREFIX_LOOKUP_CONTEXT), TAG);
        if (Status != NDIS_STATUS_SUCCESS)
        {
            DBGPRINT(("==> PrefixLookupAddr4: NdisAllocateMemoryWithTag failed with PrefixContext.\n"));
            return NULL;
        }
        NdisZeroMemory(Context, sizeof(PREFIX_LOOKUP_CONTEXT));
        
        // Initialize
        Context->HoldPacketData = NULL;
        Context->TryCount = 0;
        Context->Resolved = FALSE;
        Context->Mib.Address.u.dword = Addr->u.dword;
        NdisGetCurrentSystemTime(&(Context->EntryCreateTime));
        Context->EntryTimeOut.QuadPart = InvalidEntryTimeOut.QuadPart;
        
        InsertTailList(&PrefixListHead, &(Context->ListEntry));
        
        DBGPRINT(("==> PrefixLookupAddr4: prefix context for ip %d.%d.%d.%d is created.\n", 
                  Context->Mib.Address.u.byte[0], Context->Mib.Address.u.byte[1], 
                  Context->Mib.Address.u.byte[2], Context->Mib.Address.u.byte[3]));
    }
    
    return Context;
}
