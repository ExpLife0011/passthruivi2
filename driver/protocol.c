/*++

Copyright(c) 1992-2000  Microsoft Corporation

Module Name:

    protocol.c

Abstract:

    Ndis Intermediate Miniport driver sample. This is a passthru driver.

Author:

Environment:


Revision History:

	Revised for IVI port mapping by Shang Wentao
  Date:
	April 21, 2009

--*/


#include "precomp.h"
#pragma hdrstop

#define MAX_PACKET_POOL_SIZE 0x0000FFFF
#define MIN_PACKET_POOL_SIZE 0x000000FF

VOID
PtBindAdapter(
    OUT PNDIS_STATUS            Status,
    IN  NDIS_HANDLE             BindContext,
    IN  PNDIS_STRING            DeviceName,
    IN  PVOID                   SystemSpecific1,
    IN  PVOID                   SystemSpecific2
    )
/*++

Routine Description:

    Called by NDIS to bind to a miniport below.

Arguments:

    Status            - Return status of bind here.
    BindContext        - Can be passed to NdisCompleteBindAdapter if this call is pended.
    DeviceName         - Device name to bind to. This is passed to NdisOpenAdapter.
    SystemSpecific1    - Can be passed to NdisOpenProtocolConfiguration to read per-binding information
    SystemSpecific2    - Unused

Return Value:

    NDIS_STATUS_PENDING    if this call is pended. In this case call NdisCompleteBindAdapter
    to complete.
    Anything else          Completes this call synchronously

--*/
{
    NDIS_HANDLE                     ConfigHandle = NULL;
    PNDIS_CONFIGURATION_PARAMETER   Param;
    NDIS_STRING                     DeviceStr = NDIS_STRING_CONST("UpperBindings");
    PADAPT                          pAdapt = NULL;
    NDIS_STATUS                     Sts;
    UINT                            MediumIndex;
    ULONG                           TotalSize;
    BOOLEAN                         LockAllocated = FALSE;


    UNREFERENCED_PARAMETER(BindContext);
    UNREFERENCED_PARAMETER(SystemSpecific2);
    
    DBGPRINT(("==> Protocol BindAdapter\n"));

    do
    {
        //
        // Access the configuration section for our binding-specific
        // parameters.
        //
        NdisOpenProtocolConfiguration(Status,
                                       &ConfigHandle,
                                       SystemSpecific1);

        if (*Status != NDIS_STATUS_SUCCESS)
        {
            break;
        }

        //
        // Read the "UpperBindings" reserved key that contains a list
        // of device names representing our miniport instances corresponding
        // to this lower binding. Since this is a 1:1 IM driver, this key
        // contains exactly one name.
        //
        // If we want to implement a N:1 mux driver (N adapter instances
        // over a single lower binding), then UpperBindings will be a
        // MULTI_SZ containing a list of device names - we would loop through
        // this list, calling NdisIMInitializeDeviceInstanceEx once for
        // each name in it.
        //
        NdisReadConfiguration(Status,
                              &Param,
                              ConfigHandle,
                              &DeviceStr,
                              NdisParameterString);
        if (*Status != NDIS_STATUS_SUCCESS)
        {
            break;
        }

        //
        // Allocate memory for the Adapter structure. This represents both the
        // protocol context as well as the adapter structure when the miniport
        // is initialized.
        //
        // In addition to the base structure, allocate space for the device
        // instance string.
        //
        TotalSize = sizeof(ADAPT) + Param->ParameterData.StringData.MaximumLength;
        NdisAllocateMemoryWithTag(&pAdapt, TotalSize, TAG);

        if (pAdapt == NULL)
        {
            *Status = NDIS_STATUS_RESOURCES;
            break;
        }

        //
        // Initialize the adapter structure. We copy in the IM device
        // name as well, because we may need to use it in a call to
        // NdisIMCancelInitializeDeviceInstance. The string returned
        // by NdisReadConfiguration is active (i.e. available) only
        // for the duration of this call to our BindAdapter handler.
        //
        NdisZeroMemory(pAdapt, TotalSize);
        pAdapt->DeviceName.MaximumLength = Param->ParameterData.StringData.MaximumLength;
        pAdapt->DeviceName.Length = Param->ParameterData.StringData.Length;
        pAdapt->DeviceName.Buffer = (PWCHAR)((ULONG_PTR)pAdapt + sizeof(ADAPT));
        NdisMoveMemory(pAdapt->DeviceName.Buffer,
                       Param->ParameterData.StringData.Buffer,
                       Param->ParameterData.StringData.MaximumLength);

        NdisInitializeEvent(&pAdapt->Event);
        NdisAllocateSpinLock(&pAdapt->Lock);
        LockAllocated = TRUE;

        //
        // Allocate a packet pool for sends. We need this to pass sends down.
        // We cannot use the same packet descriptor that came down to our send
        // handler (see also NDIS 5.1 packet stacking).
        //
        NdisAllocatePacketPoolEx(Status,
                                   &pAdapt->SendPacketPoolHandle,
                                   MIN_PACKET_POOL_SIZE,
                                   MAX_PACKET_POOL_SIZE - MIN_PACKET_POOL_SIZE,
                                   sizeof(SEND_RSVD));

        if (*Status != NDIS_STATUS_SUCCESS)
        {
            break;
        }

        //
        // Allocate a packet pool for receives. We need this to indicate receives.
        // Same consideration as sends (see also NDIS 5.1 packet stacking).
        //
        NdisAllocatePacketPoolEx(Status,
                                   &pAdapt->RecvPacketPoolHandle,
                                   MIN_PACKET_POOL_SIZE,
                                   MAX_PACKET_POOL_SIZE - MIN_PACKET_POOL_SIZE,
                                   PROTOCOL_RESERVED_SIZE_IN_PACKET);

        if (*Status != NDIS_STATUS_SUCCESS)
        {
            break;
        }
        
        
        
        //
		// Allocate a packet pool for Sends.
		//
        NdisAllocateBufferPool(	Status,
								&pAdapt->SendBufferPoolHandle,
								MIN_PACKET_POOL_SIZE);

        if (*Status != NDIS_STATUS_SUCCESS)
        {
		    break;
        }
		
		//
        // Allocate a packet pool for Receives.
		//
        NdisAllocateBufferPool(	Status,
								&pAdapt->RecvBufferPoolHandle,
								MIN_PACKET_POOL_SIZE);

        if (*Status != NDIS_STATUS_SUCCESS)
        {
            break;
        }

        
        
        pAdapt->PTDeviceState = NdisDeviceStateD0;

        //
        // Now open the adapter below and complete the initialization
        //
        NdisOpenAdapter(Status,
                          &Sts,
                          &pAdapt->BindingHandle,
                          &MediumIndex,
                          MediumArray,
                          sizeof(MediumArray)/sizeof(NDIS_MEDIUM),
                          ProtHandle,
                          pAdapt,
                          DeviceName,
                          0,
                          NULL);

        if (*Status == NDIS_STATUS_PENDING)
        {
            NdisWaitEvent(&pAdapt->Event, 0);
            *Status = pAdapt->Status;
        }

        if (*Status != NDIS_STATUS_SUCCESS)
        {
            break;
        }

        pAdapt->Medium = MediumArray[MediumIndex];

        //
        // Now ask NDIS to initialize our miniport (upper) edge.
        // Set the flag below to synchronize with a possible call
        // to our protocol Unbind handler that may come in before
        // our miniport initialization happens.
        //
        pAdapt->MiniportInitPending = TRUE;
        NdisInitializeEvent(&pAdapt->MiniportInitEvent);

        *Status = NdisIMInitializeDeviceInstanceEx(DriverHandle,
                                           &pAdapt->DeviceName,
                                           pAdapt);

        if (*Status != NDIS_STATUS_SUCCESS)
        {
            DBGPRINT(("BindAdapter: Adapt %p, IMInitializeDeviceInstance error %x\n",
                pAdapt, *Status));
            break;
        }

    } while(FALSE);

    //
    // Close the configuration handle now - see comments above with
    // the call to NdisIMInitializeDeviceInstanceEx.
    //
    if (ConfigHandle != NULL)
    {
        NdisCloseConfiguration(ConfigHandle);
    }

    if (*Status != NDIS_STATUS_SUCCESS)
    {
        if (pAdapt != NULL)
        {
            if (pAdapt->BindingHandle != NULL)
            {
                NDIS_STATUS    LocalStatus;

                //
                // Close the binding we opened above.
                //

                NdisResetEvent(&pAdapt->Event);
                
                NdisCloseAdapter(&LocalStatus, pAdapt->BindingHandle);
                pAdapt->BindingHandle = NULL;

                if (LocalStatus == NDIS_STATUS_PENDING)
                {
                     NdisWaitEvent(&pAdapt->Event, 0);
                     LocalStatus = pAdapt->Status;
                }
            }

            if (pAdapt->SendPacketPoolHandle != NULL)
            {
                 NdisFreePacketPool(pAdapt->SendPacketPoolHandle);
            }

            if (pAdapt->RecvPacketPoolHandle != NULL)
            {
                 NdisFreePacketPool(pAdapt->RecvPacketPoolHandle);
            }
            
            if (LockAllocated == TRUE)
            {
                NdisFreeSpinLock(&pAdapt->Lock);
            }

            NdisFreeMemory(pAdapt, 0, 0);
            pAdapt = NULL;
        }
    }


    DBGPRINT(("<== Protocol BindAdapter: pAdapt %p, Status %x\n", pAdapt, *Status));
}


VOID
PtOpenAdapterComplete(
    IN  NDIS_HANDLE             ProtocolBindingContext,
    IN  NDIS_STATUS             Status,
    IN  NDIS_STATUS             OpenErrorStatus
    )
/*++

Routine Description:

    Completion routine for NdisOpenAdapter issued from within the PtBindAdapter. Simply
    unblock the caller.

Arguments:

    ProtocolBindingContext    Pointer to the adapter
    Status                    Status of the NdisOpenAdapter call
    OpenErrorStatus            Secondary status(ignored by us).

Return Value:

    None

--*/
{
    PADAPT      pAdapt =(PADAPT)ProtocolBindingContext;
    
    UNREFERENCED_PARAMETER(OpenErrorStatus);
    
    DBGPRINT(("==> PtOpenAdapterComplete: Adapt %p, Status %x\n", pAdapt, Status));
    pAdapt->Status = Status;
    NdisSetEvent(&pAdapt->Event);
}


VOID
PtUnbindAdapter(
    OUT PNDIS_STATUS        Status,
    IN  NDIS_HANDLE            ProtocolBindingContext,
    IN  NDIS_HANDLE            UnbindContext
    )
/*++

Routine Description:

    Called by NDIS when we are required to unbind to the adapter below.
    This functions shares functionality with the miniport's HaltHandler.
    The code should ensure that NdisCloseAdapter and NdisFreeMemory is called
    only once between the two functions

Arguments:

    Status                    Placeholder for return status
    ProtocolBindingContext    Pointer to the adapter structure
    UnbindContext            Context for NdisUnbindComplete() if this pends

Return Value:

    Status for NdisIMDeinitializeDeviceContext

--*/
{
    PADAPT         pAdapt =(PADAPT)ProtocolBindingContext;
    NDIS_STATUS    LocalStatus;
    PNDIS_PACKET   PacketArray[MAX_RECEIVE_PACKET_ARRAY_SIZE];
    ULONG          NumberOfPackets = 0, i;
    BOOLEAN        CompleteRequest = FALSE;
    BOOLEAN        ReturnPackets = FALSE;

    UNREFERENCED_PARAMETER(UnbindContext);
    
    DBGPRINT(("==> PtUnbindAdapter: Adapt %p\n", pAdapt));

    //
    // Set the flag that the miniport below is unbinding, so the request handlers will
    // fail any request comming later
    // 
    NdisAcquireSpinLock(&pAdapt->Lock);
    pAdapt->UnbindingInProcess = TRUE;
    if (pAdapt->QueuedRequest == TRUE)
    {
        pAdapt->QueuedRequest = FALSE;
        CompleteRequest = TRUE;
    }
    if (pAdapt->ReceivedPacketCount > 0)
    {

        NdisMoveMemory(PacketArray,
                      pAdapt->ReceivedPackets,
                      pAdapt->ReceivedPacketCount * sizeof(PNDIS_PACKET));

        NumberOfPackets = pAdapt->ReceivedPacketCount;

        pAdapt->ReceivedPacketCount = 0;
        ReturnPackets = TRUE;
    }
        
        
    NdisReleaseSpinLock(&pAdapt->Lock);

    if (CompleteRequest == TRUE)
    {
        PtRequestComplete(pAdapt,
                         &pAdapt->Request,
                         NDIS_STATUS_FAILURE );

    }
    if (ReturnPackets == TRUE)
    {
        for (i = 0; i < NumberOfPackets; i++)
        {
            MPReturnPacket(pAdapt, PacketArray[i]);
        }
    }

    
#ifndef WIN9X
    //
    // Check if we had called NdisIMInitializeDeviceInstanceEx and
    // we are awaiting a call to MiniportInitialize.
    //
    if (pAdapt->MiniportInitPending == TRUE)
    {
        //
        // Try to cancel the pending IMInit process.
        //
        LocalStatus = NdisIMCancelInitializeDeviceInstance(
                        DriverHandle,
                        &pAdapt->DeviceName);

        if (LocalStatus == NDIS_STATUS_SUCCESS)
        {
            //
            // Successfully cancelled IM Initialization; our
            // Miniport Initialize routine will not be called
            // for this device.
            //
            pAdapt->MiniportInitPending = FALSE;
            ASSERT(pAdapt->MiniportHandle == NULL);
        }
        else
        {
            //
            // Our Miniport Initialize routine will be called
            // (may be running on another thread at this time).
            // Wait for it to finish.
            //
            NdisWaitEvent(&pAdapt->MiniportInitEvent, 0);
            ASSERT(pAdapt->MiniportInitPending == FALSE);
        }

    }
#endif // !WIN9X

    //
    // Call NDIS to remove our device-instance. We do most of the work
    // inside the HaltHandler.
    //
    // The Handle will be NULL if our miniport Halt Handler has been called or
    // if the IM device was never initialized
    //
    
    if (pAdapt->MiniportHandle != NULL)
    {
        *Status = NdisIMDeInitializeDeviceInstance(pAdapt->MiniportHandle);

        if (*Status != NDIS_STATUS_SUCCESS)
        {
            *Status = NDIS_STATUS_FAILURE;
        }
    }
    else
    {
        //
        // We need to do some work here. 
        // Close the binding below us 
        // and release the memory allocated.
        //
        if(pAdapt->BindingHandle != NULL)
        {
            NdisResetEvent(&pAdapt->Event);

            NdisCloseAdapter(Status, pAdapt->BindingHandle);

            //
            // Wait for it to complete
            //
            if(*Status == NDIS_STATUS_PENDING)
            {
                 NdisWaitEvent(&pAdapt->Event, 0);
                 *Status = pAdapt->Status;
            }
            pAdapt->BindingHandle = NULL;
        }
        else
        {
            //
            // Both Our MiniportHandle and Binding Handle  should not be NULL.
            //
            *Status = NDIS_STATUS_FAILURE;
            ASSERT(0);
        }

        //
        //    Free the memory here, if was not released earlier(by calling the HaltHandler)
        //
        MPFreeAllPacketPools (pAdapt);
        NdisFreeSpinLock(&pAdapt->Lock);
        NdisFreeMemory(pAdapt, 0, 0);
    }

    DBGPRINT(("<== PtUnbindAdapter: Adapt %p\n", pAdapt));
}

VOID
PtUnloadProtocol(
    VOID
)
{
    NDIS_STATUS Status;

    if (ProtHandle != NULL)
    {
        NdisDeregisterProtocol(&Status, ProtHandle);
        ProtHandle = NULL;
    }

    DBGPRINT(("PtUnloadProtocol: done!\n"));
}



VOID
PtCloseAdapterComplete(
    IN    NDIS_HANDLE            ProtocolBindingContext,
    IN    NDIS_STATUS            Status
    )
/*++

Routine Description:

    Completion for the CloseAdapter call.

Arguments:

    ProtocolBindingContext    Pointer to the adapter structure
    Status                    Completion status

Return Value:

    None.

--*/
{
    PADAPT      pAdapt =(PADAPT)ProtocolBindingContext;

    DBGPRINT(("CloseAdapterComplete: Adapt %p, Status %x\n", pAdapt, Status));
    pAdapt->Status = Status;
    NdisSetEvent(&pAdapt->Event);
}


VOID
PtResetComplete(
    IN  NDIS_HANDLE            ProtocolBindingContext,
    IN  NDIS_STATUS            Status
    )
/*++

Routine Description:

    Completion for the reset.

Arguments:

    ProtocolBindingContext    Pointer to the adapter structure
    Status                    Completion status

Return Value:

    None.

--*/
{

    UNREFERENCED_PARAMETER(ProtocolBindingContext);
    UNREFERENCED_PARAMETER(Status);
    //
    // We never issue a reset, so we should not be here.
    //
    ASSERT(0);
}


VOID
PtRequestComplete(
    IN  NDIS_HANDLE            ProtocolBindingContext,
    IN  PNDIS_REQUEST          NdisRequest,
    IN  NDIS_STATUS            Status
    )
/*++

Routine Description:

    Completion handler for the previously posted request. All OIDS
    are completed by and sent to the same miniport that they were requested for.
    If Oid == OID_PNP_QUERY_POWER then the data structure needs to returned with all entries =
    NdisDeviceStateUnspecified
Arguments:

    ProtocolBindingContext    Pointer to the adapter structure
    NdisRequest                The posted request
    Status                    Completion status

Return Value:

    None

--*/
{
    PADAPT        pAdapt = (PADAPT)ProtocolBindingContext;
    NDIS_OID      Oid = pAdapt->Request.DATA.SET_INFORMATION.Oid ;

    //
    // Since our request is not outstanding anymore
    //
    ASSERT(pAdapt->OutstandingRequests == TRUE);

    pAdapt->OutstandingRequests = FALSE;

    //
    // Complete the Set or Query, and fill in the buffer for OID_PNP_CAPABILITIES, if need be.
    //
    switch (NdisRequest->RequestType)
    {
      case NdisRequestQueryInformation:

        //
        // We never pass OID_PNP_QUERY_POWER down.
        //
        ASSERT(Oid != OID_PNP_QUERY_POWER);

        if ((Oid == OID_PNP_CAPABILITIES) && (Status == NDIS_STATUS_SUCCESS))
        {
            MPQueryPNPCapabilities(pAdapt, &Status);
        }
        *pAdapt->BytesReadOrWritten = NdisRequest->DATA.QUERY_INFORMATION.BytesWritten;
        *pAdapt->BytesNeeded = NdisRequest->DATA.QUERY_INFORMATION.BytesNeeded;

        if ((Oid == OID_GEN_MAC_OPTIONS) && (Status == NDIS_STATUS_SUCCESS))
        {
            //
            // Remove the no-loopback bit from mac-options. In essence we are
            // telling NDIS that we can handle loopback. We don't, but the
            // interface below us does. If we do not do this, then loopback
            // processing happens both below us and above us. This is wasteful
            // at best and if Netmon is running, it will see multiple copies
            // of loopback packets when sniffing above us.
            //
            // Only the lowest miniport is a stack of layered miniports should
            // ever report this bit set to NDIS.
            //
            *(PULONG)NdisRequest->DATA.QUERY_INFORMATION.InformationBuffer &= ~NDIS_MAC_OPTION_NO_LOOPBACK;
        }
        
        if ((Oid == OID_GEN_MAXIMUM_FRAME_SIZE) && (Status == NDIS_STATUS_SUCCESS))
        {
            // MTU
            DBGPRINT(("==> PtRequestComplete: OID_GEN_MAXIMUM_FRAME_SIZE value is %d on pAdapt %p\n", 
                        *(PULONG)NdisRequest->DATA.QUERY_INFORMATION.InformationBuffer, pAdapt));
            // Record underlying miniport's MTU
            pAdapt->MaxFrameSize = *(PULONG)NdisRequest->DATA.QUERY_INFORMATION.InformationBuffer;
            // Adjust for IVI's need
            *(PULONG)NdisRequest->DATA.QUERY_INFORMATION.InformationBuffer -= IVI_PACKET_OVERHEAD;  // Minus 20 overhead.
        }
        
        if ((Oid == OID_GEN_MAXIMUM_TOTAL_SIZE) && (Status == NDIS_STATUS_SUCCESS))
        {
            // MTU + Ethernet header size (14)
            DBGPRINT(("==> PtRequestComplete: OID_GEN_MAXIMUM_TOTAL_SIZE value is %d on pAdapt %p\n", 
                        *(PULONG)NdisRequest->DATA.QUERY_INFORMATION.InformationBuffer, pAdapt));
            // Record underlying miniport's MTU
            pAdapt->MaxFrameSize = *(PULONG)NdisRequest->DATA.QUERY_INFORMATION.InformationBuffer - 14;
            // Adjust for IVI's need
            *(PULONG)NdisRequest->DATA.QUERY_INFORMATION.InformationBuffer -= IVI_PACKET_OVERHEAD;  // Minus 20 overhead.
        }
        
        if ((Oid == OID_802_3_PERMANENT_ADDRESS) && (Status == NDIS_STATUS_SUCCESS))
        {
            // Ethernet MAC
            DBGPRINT(("==> PtRequestComplete: OID_802_3_PERMANENT_ADDRESS info buffer value is %02x-%02x-%02x-%02x-%02x-%02x on pAdapt %p\n", 
                        *(PUCHAR)NdisRequest->DATA.QUERY_INFORMATION.InformationBuffer, 
                        *((PUCHAR)NdisRequest->DATA.QUERY_INFORMATION.InformationBuffer + 1), 
                        *((PUCHAR)NdisRequest->DATA.QUERY_INFORMATION.InformationBuffer + 2), 
                        *((PUCHAR)NdisRequest->DATA.QUERY_INFORMATION.InformationBuffer + 3), 
                        *((PUCHAR)NdisRequest->DATA.QUERY_INFORMATION.InformationBuffer + 4), 
                        *((PUCHAR)NdisRequest->DATA.QUERY_INFORMATION.InformationBuffer + 5), 
                        pAdapt));
            // Record underlying miniport's MAC
            NdisMoveMemory((PVOID)pAdapt->LocalMacAddress, NdisRequest->DATA.QUERY_INFORMATION.InformationBuffer, 6);
        }
        
        NdisMQueryInformationComplete(pAdapt->MiniportHandle,
                                      Status);
        break;

      case NdisRequestSetInformation:

        ASSERT( Oid != OID_PNP_SET_POWER);

        *pAdapt->BytesReadOrWritten = NdisRequest->DATA.SET_INFORMATION.BytesRead;
        *pAdapt->BytesNeeded = NdisRequest->DATA.SET_INFORMATION.BytesNeeded;
        NdisMSetInformationComplete(pAdapt->MiniportHandle,
                                    Status);
        break;

      default:
        ASSERT(0);
        break;
    }
    
}


VOID
PtStatus(
    IN  NDIS_HANDLE         ProtocolBindingContext,
    IN  NDIS_STATUS         GeneralStatus,
    IN  PVOID               StatusBuffer,
    IN  UINT                StatusBufferSize
    )
/*++

Routine Description:

    Status handler for the lower-edge(protocol).

Arguments:

    ProtocolBindingContext    Pointer to the adapter structure
    GeneralStatus             Status code
    StatusBuffer              Status buffer
    StatusBufferSize          Size of the status buffer

Return Value:

    None

--*/
{
    PADAPT      pAdapt = (PADAPT)ProtocolBindingContext;

    //
    // Pass up this indication only if the upper edge miniport is initialized
    // and powered on. Also ignore indications that might be sent by the lower
    // miniport when it isn't at D0.
    //
    if ((pAdapt->MiniportHandle != NULL)  &&
        (pAdapt->MPDeviceState == NdisDeviceStateD0) &&
        (pAdapt->PTDeviceState == NdisDeviceStateD0))    
    {
        if ((GeneralStatus == NDIS_STATUS_MEDIA_CONNECT) || 
            (GeneralStatus == NDIS_STATUS_MEDIA_DISCONNECT))
        {
            
            pAdapt->LastIndicatedStatus = GeneralStatus;
        }
        NdisMIndicateStatus(pAdapt->MiniportHandle,
                            GeneralStatus,
                            StatusBuffer,
                            StatusBufferSize);
    }
    //
    // Save the last indicated media status 
    //
    else
    {
        if ((pAdapt->MiniportHandle != NULL) && 
        ((GeneralStatus == NDIS_STATUS_MEDIA_CONNECT) || 
            (GeneralStatus == NDIS_STATUS_MEDIA_DISCONNECT)))
        {
            pAdapt->LatestUnIndicateStatus = GeneralStatus;
        }
    }
    
}


VOID
PtStatusComplete(
    IN NDIS_HANDLE            ProtocolBindingContext
    )
/*++

Routine Description:


Arguments:


Return Value:


--*/
{
    PADAPT      pAdapt = (PADAPT)ProtocolBindingContext;

    //
    // Pass up this indication only if the upper edge miniport is initialized
    // and powered on. Also ignore indications that might be sent by the lower
    // miniport when it isn't at D0.
    //
    if ((pAdapt->MiniportHandle != NULL)  &&
        (pAdapt->MPDeviceState == NdisDeviceStateD0) &&
        (pAdapt->PTDeviceState == NdisDeviceStateD0))    
    {
        NdisMIndicateStatusComplete(pAdapt->MiniportHandle);
    }
}


VOID
PtSendComplete(
    IN  NDIS_HANDLE            ProtocolBindingContext,
    IN  PNDIS_PACKET           Packet,
    IN  NDIS_STATUS            Status
    )
/*++

Routine Description:

    Called by NDIS when the miniport below had completed a send. We should
    complete the corresponding upper-edge send this represents.

Arguments:

    ProtocolBindingContext - Points to ADAPT structure
    Packet - Low level packet being completed
    Status - status of send

Return Value:

    None

--*/
{
    PADAPT            pAdapt = (PADAPT)ProtocolBindingContext;
    PNDIS_PACKET      Pkt; 
    NDIS_HANDLE       PoolHandle;

/* Packet reuse is intentionally disabled for NAT!
#ifdef NDIS51
    //
    // Packet stacking:
    //
    // Determine if the packet we are completing is the one we allocated. If so, then
    // get the original packet from the reserved area and completed it and free the
    // allocated packet. If this is the packet that was sent down to us, then just
    // complete it
    //
    PoolHandle = NdisGetPoolFromPacket(Packet);
    if (PoolHandle != pAdapt->SendPacketPoolHandle)
    {
        //
        // We had passed down a packet belonging to the protocol above us.
        //
        // DBGPRINT(("PtSendComp: Adapt %p, Stacked Packet %p\n", pAdapt, Packet));

        NdisMSendComplete(pAdapt->MiniportHandle,
                          Packet,
                          Status);
    }
    else
#endif // NDIS51
*/
    {
        PSEND_RSVD        SendRsvd;
        PUCHAR            PacketData;
        PNDIS_BUFFER      TempBuffer, MyBuffer;
        ULONG             BufLength;


        SendRsvd = (PSEND_RSVD)(Packet->ProtocolReserved);
        Pkt = SendRsvd->OriginalPkt;
        
        if (Pkt == NULL)
        {
            //
            // If 'Pkt' is NULL, then 'Packet' is the packet we 
            // allocated and sent by ourselves. We can free our 
            // own resources here and do not need to pass this 
            // send complete info to upper protocol driver. Do 
            // not decrease pAdapt->OutstandingSends since it is 
            // not increased in SendPrefixLookupRequest().
            //
            NdisUnchainBufferAtFront(Packet, &MyBuffer);
            while (MyBuffer != NULL)
            {
                NdisQueryBufferSafe(MyBuffer, &PacketData, &BufLength, NormalPagePriority);
                if (PacketData != NULL)
                {
                    NdisFreeMemory(PacketData, BufLength, 0);
                }
                TempBuffer = MyBuffer;
                NdisGetNextBuffer(TempBuffer, &MyBuffer);
                NdisFreeBuffer(TempBuffer);
            }
            NdisDprFreePacket(Packet);
            DBGPRINT(("==> PtSendComplete: All resources freed for NULL OriginalPkt.\n"));
            return;
        }
        
#ifndef WIN9X
        NdisIMCopySendCompletePerPacketInfo (Pkt, Packet);
#endif
    
        //
        // If "Packet"'s original packet is not "Packet", it means
        // that we allocated a new "MyPacket" with some buffer and
        // memory in MPSendPackets, we must free it here. Since we
        // disabled the reuse mechanism, program will always fall 
        // into the check below
        //
        if (Pkt != Packet)
        {
        	NdisUnchainBufferAtFront(Packet, &MyBuffer);
            while (MyBuffer != NULL)
            {
                NdisQueryBufferSafe(MyBuffer, &PacketData, &BufLength, NormalPagePriority);
                if (PacketData != NULL)
                {
                    NdisFreeMemory(PacketData, BufLength, 0);
                }
                TempBuffer = MyBuffer;
                NdisGetNextBuffer(TempBuffer, &MyBuffer);
                NdisFreeBuffer(TempBuffer);
                //DBGPRINT(("==> PtSendComplete: PacketData and MyBuffer freed.\n"));
            }
      	}
      	NdisDprFreePacket(Packet);
        //DBGPRINT(("==> PtSendComplete: Packet freed.\n"));

        NdisMSendComplete(pAdapt->MiniportHandle, Pkt, Status);
    }
    //
    // Decrease the outstanding send count
    //
    ADAPT_DECR_PENDING_SENDS(pAdapt);
}       


VOID
PtTransferDataComplete(
    IN  NDIS_HANDLE         ProtocolBindingContext,
    IN  PNDIS_PACKET        Packet,
    IN  NDIS_STATUS         Status,
    IN  UINT                BytesTransferred
    )
/*++

Routine Description:

    Entry point called by NDIS to indicate completion of a call by us
    to NdisTransferData.

    See notes under SendComplete.

Arguments:

Return Value:

--*/
{
    PADAPT      pAdapt =(PADAPT)ProtocolBindingContext;

    DBGPRINT(("==> PtTransferDataComplete called!"));

    if(pAdapt->MiniportHandle)
    {
        NdisMTransferDataComplete(pAdapt->MiniportHandle,
                                  Packet,
                                  Status,
                                  BytesTransferred);
    }
}

// PtReceive moved to receive.c

VOID
PtReceiveComplete(
    IN NDIS_HANDLE        ProtocolBindingContext
    )
/*++

Routine Description:

    Called by the adapter below us when it is done indicating a batch of
    received packets.

Arguments:

    ProtocolBindingContext    Pointer to our adapter structure.

Return Value:

    None

--*/
{
    PADAPT        pAdapt =(PADAPT)ProtocolBindingContext;
    PNDIS_PACKET  PacketArray[MAX_RECEIVE_PACKET_ARRAY_SIZE];
    ULONG         NumberOfPackets = 0, i;

    //DBGPRINT(("==> PtReceiveComplete called!\n"));
    
    PtFlushReceiveQueue(pAdapt);
        
    if ((pAdapt->MiniportHandle != NULL)
                && (pAdapt->MPDeviceState == NdisDeviceStateD0)
                && (pAdapt->IndicateRcvComplete == TRUE))
    {
        switch (pAdapt->Medium)
        {
            case NdisMedium802_3:
            case NdisMediumWan:
                NdisMEthIndicateReceiveComplete(pAdapt->MiniportHandle);
                break;

            case NdisMedium802_5:
                NdisMTrIndicateReceiveComplete(pAdapt->MiniportHandle);
                break;
#if FDDI
            case NdisMediumFddi:
                NdisMFddiIndicateReceiveComplete(pAdapt->MiniportHandle);
                break;
#endif
            default:
                ASSERT(FALSE);
                break;
        }
    }

    pAdapt->IndicateRcvComplete = FALSE;
}


// PtReceivePacket moved to receive.c



NDIS_STATUS
PtPNPHandler(
    IN NDIS_HANDLE        ProtocolBindingContext,
    IN PNET_PNP_EVENT     pNetPnPEvent
    )

/*++
Routine Description:

    This is called by NDIS to notify us of a PNP event related to a lower
    binding. Based on the event, this dispatches to other helper routines.

    NDIS 5.1: forward this event to the upper protocol(s) by calling
    NdisIMNotifyPnPEvent.

Arguments:

    ProtocolBindingContext - Pointer to our adapter structure. Can be NULL
                for "global" notifications

    pNetPnPEvent - Pointer to the PNP event to be processed.

Return Value:

    NDIS_STATUS code indicating status of event processing.

--*/
{
    PADAPT            pAdapt  =(PADAPT)ProtocolBindingContext;
    NDIS_STATUS       Status  = NDIS_STATUS_SUCCESS;

    DBGPRINT(("PtPnPHandler: Adapt %p, Event %d\n", pAdapt, pNetPnPEvent->NetEvent));

    switch (pNetPnPEvent->NetEvent)
    {
        case NetEventSetPower:
            Status = PtPnPNetEventSetPower(pAdapt, pNetPnPEvent);
            break;

         case NetEventReconfigure:
            Status = PtPnPNetEventReconfigure(pAdapt, pNetPnPEvent);
            break;

         default:
#ifdef NDIS51
            //
            // Pass on this notification to protocol(s) above, before
            // doing anything else with it.
            //
            if (pAdapt && pAdapt->MiniportHandle)
            {
                Status = NdisIMNotifyPnPEvent(pAdapt->MiniportHandle, pNetPnPEvent);
            }
#else
            Status = NDIS_STATUS_SUCCESS;

#endif // NDIS51

            break;
    }

    return Status;
}


NDIS_STATUS
PtPnPNetEventReconfigure(
    IN PADAPT            pAdapt,
    IN PNET_PNP_EVENT    pNetPnPEvent
    )
/*++
Routine Description:

    This routine is called from NDIS to notify our protocol edge of a
    reconfiguration of parameters for either a specific binding (pAdapt
    is not NULL), or global parameters if any (pAdapt is NULL).

Arguments:

    pAdapt - Pointer to our adapter structure.
    pNetPnPEvent - the reconfigure event

Return Value:

    NDIS_STATUS_SUCCESS

--*/
{
    NDIS_STATUS    ReconfigStatus = NDIS_STATUS_SUCCESS;
    NDIS_STATUS    ReturnStatus = NDIS_STATUS_SUCCESS;

    do
    {
        //
        // Is this is a global reconfiguration notification ?
        //
        if (pAdapt == NULL)
        {
            //
            // An important event that causes this notification to us is if
            // one of our upper-edge miniport instances was enabled after being
            // disabled earlier, e.g. from Device Manager in Win2000. Note that
            // NDIS calls this because we had set up an association between our
            // miniport and protocol entities by calling NdisIMAssociateMiniport.
            //
            // Since we would have torn down the lower binding for that miniport,
            // we need NDIS' assistance to re-bind to the lower miniport. The
            // call to NdisReEnumerateProtocolBindings does exactly that.
            //
            NdisReEnumerateProtocolBindings (ProtHandle);        
            break;
        }

#ifdef NDIS51
        //
        // Pass on this notification to protocol(s) above before doing anything
        // with it.
        //
        if (pAdapt->MiniportHandle)
        {
            ReturnStatus = NdisIMNotifyPnPEvent(pAdapt->MiniportHandle, pNetPnPEvent);
        }
#endif // NDIS51

        ReconfigStatus = NDIS_STATUS_SUCCESS;

    } while(FALSE);

    DBGPRINT(("<==PtPNPNetEventReconfigure: pAdapt %p\n", pAdapt));

#ifdef NDIS51
    //
    // Overwrite status with what upper-layer protocol(s) returned.
    //
    ReconfigStatus = ReturnStatus;
#endif

    return ReconfigStatus;
}


NDIS_STATUS
PtPnPNetEventSetPower(
    IN PADAPT            pAdapt,
    IN PNET_PNP_EVENT    pNetPnPEvent
    )
/*++
Routine Description:

    This is a notification to our protocol edge of the power state
    of the lower miniport. If it is going to a low-power state, we must
    wait here for all outstanding sends and requests to complete.

    NDIS 5.1:  Since we use packet stacking, it is not sufficient to
    check usage of our local send packet pool to detect whether or not
    all outstanding sends have completed. For this, use the new API
    NdisQueryPendingIOCount.

    NDIS 5.1: Use the 5.1 API NdisIMNotifyPnPEvent to pass on PnP
    notifications to upper protocol(s).

Arguments:

    pAdapt            -    Pointer to the adpater structure
    pNetPnPEvent    -    The Net Pnp Event. this contains the new device state

Return Value:

    NDIS_STATUS_SUCCESS or the status returned by upper-layer protocols.

--*/
{
    PNDIS_DEVICE_POWER_STATE       pDeviceState  =(PNDIS_DEVICE_POWER_STATE)(pNetPnPEvent->Buffer);
    NDIS_DEVICE_POWER_STATE        PrevDeviceState = pAdapt->PTDeviceState;  
    NDIS_STATUS                    Status;
    NDIS_STATUS                    ReturnStatus;
#ifdef NDIS51
    ULONG                          PendingIoCount = 0;
#endif // NDIS51

    ReturnStatus = NDIS_STATUS_SUCCESS;

    //
    // Set the Internal Device State, this blocks all new sends or receives
    //
    NdisAcquireSpinLock(&pAdapt->Lock);
    pAdapt->PTDeviceState = *pDeviceState;

    //
    // Check if the miniport below is going to a low power state.
    //
    if (pAdapt->PTDeviceState > NdisDeviceStateD0)
    {
        //
        // If the miniport below is going to standby, fail all incoming requests
        //
        if (PrevDeviceState == NdisDeviceStateD0)
        {
            pAdapt->StandingBy = TRUE;
        }

        NdisReleaseSpinLock(&pAdapt->Lock);

#ifdef NDIS51
        //
        // Notify upper layer protocol(s) first.
        //
        if (pAdapt->MiniportHandle != NULL)
        {
            ReturnStatus = NdisIMNotifyPnPEvent(pAdapt->MiniportHandle, pNetPnPEvent);
        }
#endif // NDIS51

        //
        // Wait for outstanding sends and requests to complete.
        //
        while (pAdapt->OutstandingSends != 0)
        {
            NdisMSleep(2);
        }

        while (pAdapt->OutstandingRequests == TRUE)
        {
            //
            // sleep till outstanding requests complete
            //
            NdisMSleep(2);
        }

        //
        // If the below miniport is going to low power state, complete the queued request
        //
        NdisAcquireSpinLock(&pAdapt->Lock);
        if (pAdapt->QueuedRequest)
        {
            pAdapt->QueuedRequest = FALSE;
            NdisReleaseSpinLock(&pAdapt->Lock);
            PtRequestComplete(pAdapt, &pAdapt->Request, NDIS_STATUS_FAILURE);
        }
        else
        {
            NdisReleaseSpinLock(&pAdapt->Lock);
        }
            

        ASSERT(NdisPacketPoolUsage(pAdapt->SendPacketPoolHandle) == 0);
        ASSERT(pAdapt->OutstandingRequests == FALSE);
    }
    else
    {
        //
        // If the physical miniport is powering up (from Low power state to D0), 
        // clear the flag
        //
        if (PrevDeviceState > NdisDeviceStateD0)
        {
            pAdapt->StandingBy = FALSE;
        }
        //
        // The device below is being turned on. If we had a request
        // pending, send it down now.
        //
        if (pAdapt->QueuedRequest == TRUE)
        {
            pAdapt->QueuedRequest = FALSE;
        
            pAdapt->OutstandingRequests = TRUE;
            NdisReleaseSpinLock(&pAdapt->Lock);

            NdisRequest(&Status,
                        pAdapt->BindingHandle,
                        &pAdapt->Request);

            if (Status != NDIS_STATUS_PENDING)
            {
                PtRequestComplete(pAdapt,
                                  &pAdapt->Request,
                                  Status);
                
            }
        }
        else
        {
            NdisReleaseSpinLock(&pAdapt->Lock);
        }


#ifdef NDIS51
        //
        // Pass on this notification to protocol(s) above
        //
        if (pAdapt->MiniportHandle)
        {
            ReturnStatus = NdisIMNotifyPnPEvent(pAdapt->MiniportHandle, pNetPnPEvent);
        }
#endif // NDIS51

    }

    return ReturnStatus;
}

VOID
PtQueueReceivedPacket(
    IN PADAPT       pAdapt,
    IN PNDIS_PACKET Packet,
    IN BOOLEAN      DoIndicate
    )
/*++

Routine Description:

    This is to queue the received packets and indicates them up if the given Packet
    status is NDIS_STATUS_RESOURCES, or the array is full.

Arguments:

    pAdapt   -    Pointer to the adpater structure.
    Packet   -    Pointer to the indicated packet.
    DoIndicate -  Do the indication now.
    
Return Value:

    None.
    
--*/
{
    PNDIS_PACKET    PacketArray[MAX_RECEIVE_PACKET_ARRAY_SIZE];
    ULONG           NumberOfPackets = 0, i;
    
    NdisDprAcquireSpinLock(&pAdapt->Lock);
    ASSERT(pAdapt->ReceivedPacketCount < MAX_RECEIVE_PACKET_ARRAY_SIZE);

    //
    // pAdapt->ReceviePacketCount must be less than MAX_RECEIVE_PACKET_ARRAY_SIZE because
    // the thread which held the pVElan->Lock before should already indicate the packet(s) 
    // up if pAdapt->ReceviePacketCount == MAX_RECEIVE_PACKET_ARRAY_SIZE.
    // 
    pAdapt->ReceivedPackets[pAdapt->ReceivedPacketCount] = Packet;
    pAdapt->ReceivedPacketCount++;

    // 
    //  If our receive packet array is full, or the miniport below indicated the packets
    //  with resources, do the indicatin now.
    //  
    if ((pAdapt->ReceivedPacketCount == MAX_RECEIVE_PACKET_ARRAY_SIZE) || DoIndicate)
    {
        NdisMoveMemory(PacketArray,
                       pAdapt->ReceivedPackets,
                       pAdapt->ReceivedPacketCount * sizeof(PNDIS_PACKET));

        NumberOfPackets = pAdapt->ReceivedPacketCount;
        //
        // So other thread can queue the received packets
        //
        pAdapt->ReceivedPacketCount = 0;
               
        NdisDprReleaseSpinLock(&pAdapt->Lock);

        //
        // Here the driver checks if the miniport adapter is in lower power state, do not indicate the 
        // packets, but the check does not close the window, it only minimizes the window. To close
        // the window completely, we need to add synchronization in the receive code path; because 
        // NDIS can handle the case that miniport drivers indicate packets in lower power state,
        // we don't add the synchronization in the hot code path.
        //    
        if ((pAdapt->MiniportHandle != NULL) 
                && (pAdapt->MPDeviceState == NdisDeviceStateD0))
        {
                
            NdisMIndicateReceivePacket(pAdapt->MiniportHandle, PacketArray, NumberOfPackets);
        }
        else
        {
            if (DoIndicate)
            {
                NumberOfPackets  -= 1;
            }
            for (i = 0; i < NumberOfPackets; i++)
            {
                MPReturnPacket(pAdapt, PacketArray[i]);
            }
        }

    }
    else
    {
        NdisDprReleaseSpinLock(&pAdapt->Lock);
    }
                    
}

VOID
PtFlushReceiveQueue(
    IN PADAPT         pAdapt
    )
/*++

Routine Description:

    This routine process the queued the packet, if anything is fine, indicate the packet 
    up, otherwise, return the packet to the underlying miniports.

Arguments:

    pAdapt   -    Pointer to the adpater structure.
    
Return Value:

    None.
*/    
{

    PNDIS_PACKET  PacketArray[MAX_RECEIVE_PACKET_ARRAY_SIZE];
    ULONG         NumberOfPackets = 0, i;

    do
    {
        NdisDprAcquireSpinLock(&pAdapt->Lock);

        if (pAdapt->ReceivedPacketCount > 0)
        {
	    NdisMoveMemory(PacketArray,
                            pAdapt->ReceivedPackets,
                            pAdapt->ReceivedPacketCount * sizeof(PNDIS_PACKET));

            NumberOfPackets = pAdapt->ReceivedPacketCount;
            //
            // So other thread can queue the received packets
            //
            pAdapt->ReceivedPacketCount = 0;

            NdisDprReleaseSpinLock(&pAdapt->Lock);
               
            //
            // Here the driver checks if the miniport adapter is in lower power state, do not indicate the 
            // packets, but the check does not close the window, it only minimizes the window. To close
            // the window completely, we need to add synchronization in the receive code path; because 
            // NDIS can handle the case that miniport drivers indicate packets in lower power state,
            // we don't add the synchronization in the hot code path.
            //    
            if ((pAdapt->MiniportHandle)
                    && (pAdapt->MPDeviceState == NdisDeviceStateD0))
            {
                NdisMIndicateReceivePacket(pAdapt->MiniportHandle, 
                                           PacketArray, 
                                           NumberOfPackets);
                break;
            }
            //
            // We need return the packet here
            // 
            for (i = 0; i < NumberOfPackets; i ++)
            {
                MPReturnPacket(pAdapt, PacketArray[i]);
            }
            break;
        }
        
        NdisDprReleaseSpinLock(&pAdapt->Lock);
        
    
    } while (FALSE);
}

