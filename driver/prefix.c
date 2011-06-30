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
    LocalPrefixInfo.Prefix.u.byte[4] = 0xff;  // XXX: Prefix set to 2001:da8:ff00::/40
    LocalPrefixInfo.PrefixLength = 40;        // XXX: Prefix length set to 40 bits
    LocalPrefixInfo.XlateMode = 0;  // XlateMode default to 0 (1:1 mapping); XXX: should be default to 1 (1:N mapping)
    LocalPrefixInfo.SuffixCode = 0x4001;  // SuffixCode for Ratio = 2^8 (256) and Index = 1; XXX: should be set to 0 when XlateMode = 0
    LocalPrefixInfo.Ratio = 16;
    LocalPrefixInfo.Offset = 1;
    
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
        if (PrefixContext->HoldPacketData != NULL)
        {
            // Free any pending packet
            NdisFreeMemory(PrefixContext->HoldPacketData, 0, 0);
        }
        NdisFreeMemory(PrefixContext, 0, 0);
        //DBGPRINT(("==> ResetPrefixLists: prefix context memory freed.\n"));
        // Go to next entry
    }
}


PPREFIX_LOOKUP_CONTEXT
PrefixLookupAddr4(
    IN PIN_ADDR       Addr,
    IN BOOLEAN        CreateNew
    )
/*++

Routine Description:

    Lookup prefix information in the prefix list by the given IPv4 address.. 
    This function is NOT thread-safe.
    
Arguments:

    Addr - Pointer to the IPv4 address that needs to be resolved
    CreateNew - Indicate whether we should create an empty entry if no entry exists for this address

Return Value:

    If the entry is found, return pointer to this entry; otherwise, if 'CreateNew'  
    is TRUE, create a new empty entry and return pointer to the new entry.

--*/
{
    PLIST_ENTRY p;
    
    PPREFIX_LOOKUP_CONTEXT Context = NULL;
    
    p = PrefixListHead.Flink;
    while (p != &PrefixListHead)
    {
        PPREFIX_LOOKUP_CONTEXT PrefixContext = CONTAINING_RECORD(p, PREFIX_LOOKUP_CONTEXT, ListEntry);
        
        if ((Addr->u.dword & PrefixContext->Mib.Mask) == (PrefixContext->Mib.Address.u.dword & PrefixContext->Mib.Mask))
        {
            // Found existing prefix entry for this address, may be unresolved.
            Context = PrefixContext;
            DBGPRINT(("==> PrefixLookupAddr4: prefix context for ip %d.%d.%d.%d found.\n", 
                      Context->Mib.Address.u.byte[0], Context->Mib.Address.u.byte[1], 
                      Context->Mib.Address.u.byte[2], Context->Mib.Address.u.byte[3]));
            break;
        }
        else
        {
            // Go to next entry.
            p = p->Flink;
        }
    }
    
    if (Context == NULL && CreateNew == TRUE)
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
        Context->HoldDataLength = 0;
        Context->TryCount = 0;
        Context->Resolved = FALSE;
        Context->Mib.Address.u.dword = Addr->u.dword;
        Context->Mib.Mask = 0xffffffff;  // Init to 32bit IPv4 prefix length
        NdisGetCurrentSystemTime(&(Context->StateSetTime));
        Context->EntryTimeOut.QuadPart = InvalidEntryTimeOut.QuadPart;
        
        InsertTailList(&PrefixListHead, &(Context->ListEntry));
        
        DBGPRINT(("==> PrefixLookupAddr4: prefix context for ip %d.%d.%d.%d created.\n", 
                  Context->Mib.Address.u.byte[0], Context->Mib.Address.u.byte[1], 
                  Context->Mib.Address.u.byte[2], Context->Mib.Address.u.byte[3]));
    }
    
    return Context;
}


PPREFIX_LOOKUP_CONTEXT
PrefixLookupAddr6(
    IN PIN6_ADDR       Addr
    )
/*++

Routine Description:

    Lookup prefix information in the prefix list by the given IPv6 address. 
    This function is NOT thread-safe.
    
Arguments:

    Addr - Pointer to the IPv6 address that needs to be resolved

Return Value:

    If the entry is found, return pointer to this entry; otherwise, return NULL.

--*/
{
    PLIST_ENTRY p;
    INT i;
    BOOLEAN flag = TRUE;
    INT PrefixLengthN;
    
    PPREFIX_LOOKUP_CONTEXT Context = NULL;
    
    p = PrefixListHead.Flink;
    while (p != &PrefixListHead)
    {
        PPREFIX_LOOKUP_CONTEXT PrefixContext = CONTAINING_RECORD(p, PREFIX_LOOKUP_CONTEXT, ListEntry);
        
        PrefixLengthN = PrefixContext->Mib.PrefixLength / 8;
        
        // Compare prefix by bytes.
        for (i = 0; i < PrefixLengthN; i++)
        {
            if (PrefixContext->Mib.Prefix.u.byte[i] != Addr->u.byte[i])
            {
                flag = FALSE;
                break;
            }
        }
        
        if (flag == TRUE)
        {
            // Compare IPv4 embedded address.
            for (i = 0; i < 4; i++)
            {
                if (PrefixContext->Mib.Address.u.byte[i] != Addr->u.byte[PrefixLengthN + i])
                {
                    flag = FALSE;
                    break;
                }
            }
        }
        
        if (flag == TRUE && PrefixContext->Mib.XlateMode == 1)
        {
            // Compare suffix code.
            USHORT code = (Addr->u.byte[PrefixLengthN + 4] << 8) & 0xff00 
                          + Addr->u.byte[PrefixLengthN + 5];
            
            if (code != PrefixContext->Mib.SuffixCode)
            {
                flag = FALSE;
            }
        }
        
        // Final step.
        if (flag == TRUE)
        {
            // Address matches.
            if (PrefixContext->Resolved == TRUE)
            {
                // Found existing prefix entry for this address
                Context = PrefixContext;
                DBGPRINT(("==> PrefixLookupAddr6: prefix context for ip %d.%d.%d.%d found.\n", 
                          Context->Mib.Address.u.byte[0], Context->Mib.Address.u.byte[1], 
                          Context->Mib.Address.u.byte[2], Context->Mib.Address.u.byte[3]));
                break;
            }
            else
            {
                // Prefix info exists but is not resolved yet. No need to continue the compare loop.
                break;
            }
        }
        
        // Go to next entry.
        p = p->Flink;
    }
    
    return Context;
}


PPREFIX_LOOKUP_CONTEXT
ParsePrefixLookupResponse(
    PICMP6_HEADER  Response,
    INT            ResponseLength
    )
/*++

Routine Description:

    Parse prefix lookup response packet and fill the corresponding prefix mib.
    This function is NOT thread-safe.
    
Arguments:

    Response - Pointer to the ICMPv6 prefix lookup response packet.
    ResponseLength - Length of the ICMPv6 header and options, that is, 
                    the payload in the IPv6 header (in host byte order)

Return Value:

    If the response packet is valid and the corresponding entry is updated 
    successfully, return pointer to the entry; otherwise, return NULL.

--*/
{
    IN_ADDR                   TargetAddr;
    PPREFIX_LOOKUP_CONTEXT    PrefixContext = NULL;
    PUCHAR                    ptr = NULL;
    INT                       optlen = ResponseLength - sizeof(ICMP6_HEADER);

    if (optlen == 0)
    {
        return NULL;
    }
    
    TargetAddr.u.dword = Response->u.addr;
    
    // Lookup the target address in the prefix context list
    PrefixContext = PrefixLookupAddr4(&TargetAddr, FALSE);
    
    if (PrefixContext == NULL)
    {
        // Failed to find the prefix context corresponding to this response.
        return NULL;
    }
    
    // Parse options
    ptr = (PUCHAR)(Response) + sizeof(ICMP6_HEADER);
    
    while (optlen > 0)
    {
        UCHAR optcode = *ptr;
        UCHAR optsize = *(ptr + 1);
        
        if (optcode == PREF_OPT_PREFINFO && optsize == PREF_OPTLEN_PREFONFO)
        {
            // Prefix information option
            PPREFIX_INFO_OPTION prefixinfo = (PPREFIX_INFO_OPTION)(ptr);
            INT masklen = prefixinfo->flag_masklen & PREFIX_INFO_MASKLEN;
            if (masklen >= 32)
            {
                // Response packet contains invalid mask length
                PrefixContext = NULL;
                break;
            }
            
            // Update prefix context
            PrefixContext->Mib.Mask = 0xffffffff << (32 - masklen);
            NdisMoveMemory(&(PrefixContext->Mib.Prefix), &(prefixinfo->prefix), sizeof(IN6_ADDR));
            PrefixContext->Mib.PrefixLength = prefixinfo->prefixlen;
            PrefixContext->EntryTimeOut.QuadPart = ntohl(prefixinfo->ttl) * 10000000;
            if ((prefixinfo->flag_masklen & PREFIX_INFO_MBIT) == 0)
            {
                // This prefix is for 1:1 mapping
                PrefixContext->Mib.XlateMode = 0;
                // This prefix info is complete after processing this option
                PrefixContext->Resolved = TRUE;
                // Ignore other options
                break;
            }
            else
            {
                PrefixContext->Mib.XlateMode = 1;
                //
                // We still need port range information option.
                // 'PrefixContext->Resolved' is set when we handle 
                // the port range option. We will not touch it 
                // here in case that the port range option appears 
                // before the prefix info option.
                //
            }
        }
        else if (optcode == PREF_OPT_PORTRANGE && optsize == PREF_OPTLEN_PORTRANGE)
        {
            // Port range information option
            PPORT_RANGE_OPTION portrange = (PPORT_RANGE_OPTION)(ptr);
            
            USHORT temp = portrange->ratio;
            
            // Update prefix context
            PrefixContext->Mib.SuffixCode = 0;
            while (temp >> 1 != 0)
            {
                PrefixContext->Mib.SuffixCode++;
                temp = temp >> 1;
            }
            PrefixContext->Mib.SuffixCode = PrefixContext->Mib.SuffixCode << 12;
            PrefixContext->Mib.SuffixCode += portrange->offset & 0x0fff;
            
            PrefixContext->Mib.Ratio = portrange->ratio;
            PrefixContext->Mib.Offset = portrange->offset;
            
            // Set 'PrefixContext->Resolved' here and continue to look for prefix info option
            PrefixContext->Resolved = TRUE;
        }
        else
        {
            // Response packet contains invalid option
            PrefixContext = NULL;
            break;
        }
        
        // Move pointer to next option
        optlen -= optsize * 8;
        ptr += optsize * 8;
    }
    
    return PrefixContext;
}
