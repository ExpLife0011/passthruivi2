#include "precomp.h"
#pragma hdrstop

NDIS_STATUS
PtReceive(
    IN  NDIS_HANDLE         ProtocolBindingContext,
    IN  NDIS_HANDLE         MacReceiveContext,
    IN  PVOID               HeaderBuffer,
    IN  UINT                HeaderBufferSize,
    IN  PVOID               LookAheadBuffer,
    IN  UINT                LookAheadBufferSize,
    IN  UINT                PacketSize
    )
/*++

Routine Description:

    Handle receive data indicated up by the miniport below. We pass
    it along to the protocol above us.

    If the miniport below indicates packets, NDIS would more
    likely call us at our ReceivePacket handler. However we
    might be called here in certain situations even though
    the miniport below has indicated a receive packet, e.g.
    if the miniport had set packet status to NDIS_STATUS_RESOURCES.
        
Arguments:

    <see DDK ref page for ProtocolReceive>

Return Value:

    NDIS_STATUS_SUCCESS if we processed the receive successfully,
    NDIS_STATUS_XXX error code if we discarded it.

--*/
{
    PADAPT            pAdapt = (PADAPT)ProtocolBindingContext;
    PNDIS_PACKET      MyPacket, Packet = NULL;
    NDIS_STATUS       Status = NDIS_STATUS_SUCCESS;

    // copy packet defined
    PUCHAR           pPacketContent;
    PUCHAR           pTemp;
    PUCHAR           pNewPacketContent;
    UINT             BufferLength, PacketLength;
    UINT             ContentOffset = 0;
    PNDIS_BUFFER     TempBuffer, MyBuffer;

    // NAT defined
    ETH_HEADER       *eh;
    IP6_HEADER       *ip6h;
    ICMP6_HEADER     *icmp6h;
    IP6_HEADER       *embed_ip6h;
    ICMP6_HEADER     *embed_icmp6h;
    UDP_HEADER       *embed_uh;
    TCP_HEADER       *embed_th;
    TCP_HEADER       *th;
    UDP_HEADER       *uh;
    USHORT           original = 0;   // original port or id
    BOOLEAN          is_translate = FALSE;
    BOOLEAN          ret;
    UINT             packet_size = 0;   // bytes need to be sent in the buffer
    
    PTCP_STATE_CONTEXT  StateContext;

    //DBGPRINT(("==> PtReceive called.\n"));
    
    if ((!pAdapt->MiniportHandle) || (pAdapt->MPDeviceState > NdisDeviceStateD0))
    {
        Status = NDIS_STATUS_FAILURE;
        //DBGPRINT(("==> Status = NDIS_STATUS_FAILURE;\n"));
    }
    else do
    {
        //
        // Get at the packet, if any, indicated up by the miniport below.
        //
        Packet = NdisGetReceivedPacket(pAdapt->BindingHandle, MacReceiveContext);
        if (Packet != NULL)
        {
            //
            // The miniport below did indicate up a packet. Use information
            // from that packet to construct a new packet to indicate up.
            //

#ifdef NDIS51
            //
            // NDIS 5.1 NOTE: Do not reuse the original packet in indicating
            // up a receive, even if there is sufficient packet stack space.
            // If we had to do so, we would have had to overwrite the
            // status field in the original packet to NDIS_STATUS_RESOURCES,
            // and it is not allowed for protocols to overwrite this field
            // in received packets.
            //
#endif // NDIS51

            //
            // Get a packet off the pool and indicate that up
            //
            NdisDprAllocatePacket(&Status,
                                &MyPacket,
                                pAdapt->RecvPacketPoolHandle);

            if (Status == NDIS_STATUS_SUCCESS)
            {
                PRECV_RSVD            RecvRsvd;
                
                RecvRsvd = (PRECV_RSVD)(MyPacket->MiniportReserved);
                RecvRsvd->OriginalPkt = Packet;
                
                //
                // Program usually falls through here!
                // We should add our NAT codes here!
                //
                
                // Query first buffer and total packet length
                NdisGetFirstBufferFromPacketSafe(Packet, &MyBuffer, &pTemp, &BufferLength, &PacketLength, NormalPagePriority);
                if (pTemp == NULL)
                {
                    DBGPRINT(("==> PtReceive: NdisGetFirstBufferFromPacketSafe failed.\n"));
                    Status = NDIS_STATUS_FAILURE;
                    NdisDprFreePacket(MyPacket);
                    return Status;
                }
                
                // Allocate memory
                Status = NdisAllocateMemoryWithTag((PVOID)&pPacketContent, PacketLength, TAG);
                if (Status != NDIS_STATUS_SUCCESS)
                {
                    DBGPRINT(("==> PtReceive: NdisAllocateMemoryWithTag failed.\n"));
                    Status = NDIS_STATUS_FAILURE;
                    NdisDprFreePacket(MyPacket);
                    return Status;
                }
                NdisZeroMemory(pPacketContent, PacketLength);
                
                // Copy packet content from buffer
                NdisMoveMemory(pPacketContent, pTemp, BufferLength);
                ContentOffset = BufferLength;
                NdisGetNextBuffer(MyBuffer, &MyBuffer);
                while (MyBuffer != NULL)
                {
                    NdisQueryBufferSafe(MyBuffer, &pTemp, &BufferLength, NormalPagePriority);
                    NdisMoveMemory(pPacketContent + ContentOffset, pTemp, BufferLength);
                    ContentOffset += BufferLength;
                    NdisGetNextBuffer(MyBuffer, &MyBuffer);
                }
                //DBGPRINT(("==> PtReceive: Get packet content success.\n"));
                
                // Set packet_size
                packet_size = PacketLength;
                
                eh = (ETH_HEADER *)(pPacketContent);
                
                if (eh->type == htons(ETH_IP6))
                {
                    // ipv6 packet
                    //DBGPRINT(("==> PtReceive: We receive an IPv6 packet.\n"));
                    ip6h = (IP6_HEADER *)(pPacketContent + sizeof(ETH_HEADER));
                                            
                    if (IsIviAddress(&(ip6h->daddr)) == 1)
                    {
                        if (ip6h->nexthdr == IP_ICMP6)
                        {
                            // icmpv6 packet
                            DBGPRINT(("==> PtReceive: We receive a ICMPv6 packet.\n"));
                            
                            icmp6h = (ICMP6_HEADER *)(pPacketContent + sizeof(ETH_HEADER) + sizeof(IP6_HEADER));
                            
                            if (icmp6h->type == ICMP6_ECHO || icmp6h->type == ICMP6_ECHO_REPLY) // Echo/Echo Reply Request
                            {
                                // Check the mapping list
                                ret = GetIcmpIdMapIn(ntohs(icmp6h->id), &original, &is_translate);
                                
                                if (ret != TRUE)
                                {
                                    DBGPRINT(("==> PtReceivePacket: Check map list failed. Drop.\n"));
                                    Status = NDIS_STATUS_NOT_ACCEPTED;
                                    NdisFreeMemory(pPacketContent, 0, 0);
                                    NdisDprFreePacket(MyPacket);
                                    return Status;
                                }
                                
                                if (is_translate != TRUE)
                                {
                                    DBGPRINT(("==> PtReceive: Non-translated ICMPv6 id.\n"));
                                    //DBGPRINT(("==> Old Id: %d\n", ntohs(icmp6h->id)));
                                    
                                    icmp6h->checksum = ChecksumUpdate(ntohs(icmp6h->checksum), ntohs(icmp6h->id), original);
                                    icmp6h->id = htons(original);
                                    
                                    //DBGPRINT(("==> New Id: %d\n", ntohs(icmp6h->id)));
                                    //DBGPRINT(("==> New checksum: %02x\n", icmp6h->checksum));
                                }
                                else
                                {
                                    Status = NdisAllocateMemoryWithTag((PVOID)&pNewPacketContent, PacketLength, TAG);
                                    if (Status != NDIS_STATUS_SUCCESS)
                                    {
                                        DBGPRINT(("==> PtReceive: NdisAllocateMemoryWithTag failed with pNewPacketContent. Drop packet.\n"));
                                        Status = NDIS_STATUS_NOT_ACCEPTED;
                                        NdisFreeMemory(pPacketContent, 0, 0);
                                        NdisDprFreePacket(MyPacket);
                                        return Status;
                                    }
                                    
                                    NdisZeroMemory(pNewPacketContent, PacketLength);
                                    
                                    packet_size = Icmp6to4(pPacketContent, pNewPacketContent, original);
                                    if (packet_size == 0)
                                    {
                                        DBGPRINT(("==> PtReceive: Translate failed with Icmp6to4. Drop packet.\n"));
                                        Status = NDIS_STATUS_NOT_ACCEPTED;
                                        // Notice: we have two memory to free here!
                                        NdisFreeMemory(pPacketContent, 0, 0);
                                        NdisFreeMemory(pNewPacketContent, 0, 0);
                                        NdisDprFreePacket(MyPacket);
                                        return Status;
                                    }
                                    
                                    // Switch pointers and free old packet memory
                                    pTemp = pPacketContent;
                                    pPacketContent = pNewPacketContent;
                                    pNewPacketContent = pTemp;
                                    NdisFreeMemory(pNewPacketContent, 0, 0);
                                    //DBGPRINT(("==> PtReceive: old packet memory freed.\n"));
                                }
                            }
                            /*else
                            {
                                DBGPRINT(("==> PtReceive: Unkown ICMPv6 type, drop packet!\n"));
                                Status = NDIS_STATUS_NOT_ACCEPTED;
                                NdisFreeMemory(pPacketContent, 0, 0);
                                NdisDprFreePacket(MyPacket);
                                return Status;
                            }*/
                        }
                        else if (ip6h->nexthdr == IP_TCP)
                        {
                            // tcpv6 packet
                            DBGPRINT(("==> PtReceive: We receive a TCPv6 packet.\n"));
                            
                            th = (TCP_HEADER *)(pPacketContent + sizeof(ETH_HEADER) + sizeof(IP6_HEADER));
                            
                            // Check the mapping list
                            NdisAcquireSpinLock(&StateListLock);
                            StateContext = TcpPortMapInTable[ntohs(th->dport)].State;
                            if (StateContext != NULL)
                            {
                                is_translate = StateContext->Translated;
                            }
                            NdisReleaseSpinLock(&StateListLock);
                            
                            if (is_translate != TRUE)
                            {
                                DBGPRINT(("==> PtReceive: Non-translated TCPv6 port.\n"));
                                //DBGPRINT(("==> Source port: %d\n", ntohs(th->sport)));
                                //DBGPRINT(("==> Old Dest port: %d\n", ntohs(th->dport)));
                                original = GetTcpPortMapIn(th, ntohs(ip6h->payload));
                                
                                if (original == 0)
                                {
                                    DBGPRINT(("==> PtReceive: Find map failed. Drop.\n"));
                                    Status = NDIS_STATUS_NOT_ACCEPTED;
                                    NdisFreeMemory(pPacketContent, 0, 0);
                                    NdisDprFreePacket(MyPacket);
                                    return Status;
                                }
                                                  
                                th->checksum = ChecksumUpdate(ntohs(th->checksum), ntohs(th->dport), original);
                                th->dport = htons(original);
                                
                                //DBGPRINT(("==> New Dest port: %d\n", ntohs(th->dport)));
                                //DBGPRINT(("==> New checksum: %02x\n", th->checksum));
                            }
                            else
                            {
                                Status = NdisAllocateMemoryWithTag((PVOID)&pNewPacketContent, PacketLength, TAG);
                                if (Status != NDIS_STATUS_SUCCESS)
                                {
                                    DBGPRINT(("==> PtReceive: NdisAllocateMemory failed with pNewPacketContent. Drop packet.\n"));
                                    Status = NDIS_STATUS_NOT_ACCEPTED;
                                    NdisFreeMemory(pPacketContent, 0, 0);
                                    NdisDprFreePacket(MyPacket);
                                    return Status;
                                }
                                
                                NdisZeroMemory(pNewPacketContent, PacketLength);
                                
                                packet_size = tcp6to4(pPacketContent, pNewPacketContent);
                                if (packet_size == 0)
                                {
                                    DBGPRINT(("==> PtReceive: Translate failed with tcp6to4. Drop packet.\n"));
                                    Status = NDIS_STATUS_NOT_ACCEPTED;
                                    // Notice: we have two memory to free here!
                                    NdisFreeMemory(pPacketContent, 0, 0);
                                    NdisFreeMemory(pNewPacketContent, 0, 0);
                                    NdisDprFreePacket(MyPacket);
                                    return Status;
                                }
                                
                                // Switch pointers and free old packet memory
                                pTemp = pPacketContent;
                                pPacketContent = pNewPacketContent;
                                pNewPacketContent = pTemp;
                                NdisFreeMemory(pNewPacketContent, 0, 0);
                                //DBGPRINT(("==> PtReceive: old packet memory freed.\n"));
                            }
                        }
                        else if (ip6h->nexthdr == IP_UDP)
                        {
                            // udpv6 packet
                            DBGPRINT(("==> PtReceive: We receive a UDPv6 packet.\n"));
                            
                            uh = (UDP_HEADER *)(pPacketContent + sizeof(ETH_HEADER) + sizeof(IP6_HEADER));
                            
                            // Check the mapping list
                            ret = GetUdpPortMapIn(ntohs(uh->dport), &original, &is_translate);
                            
                            if (ret != TRUE)
                            {
                                DBGPRINT(("==> PtReceivePacket: Check map list failed. Drop.\n"));
                                Status = NDIS_STATUS_NOT_ACCEPTED;
                                NdisFreeMemory(pPacketContent, 0, 0);
                                NdisDprFreePacket(MyPacket);
                                return Status;
                            }
                            
                            if (is_translate != TRUE)
                            {
                                DBGPRINT(("==> PtReceive: Non-translated UDPv6 port.\n"));
                                //DBGPRINT(("==> Source port: %d\n", ntohs(uh->sport)));
                                //DBGPRINT(("==> Old Dest port: %d\n", ntohs(uh->dport)));
                                
                                uh->checksum = ChecksumUpdate(ntohs(uh->checksum), ntohs(uh->dport), original);
                                uh->dport = htons(original);
                                
                                //DBGPRINT(("==> New Dest port: %d\n", ntohs(th->dport)));
                                //DBGPRINT(("==> New checksum: %02x\n", th->checksum));
                            }
                            else
                            {
                                Status = NdisAllocateMemoryWithTag((PVOID)&pNewPacketContent, PacketLength, TAG);
                                if (Status != NDIS_STATUS_SUCCESS)
                                {
                                    DBGPRINT(("==> PtReceive: NdisAllocateMemory failed with pNewPacketContent. Drop packet.\n"));
                                    Status = NDIS_STATUS_NOT_ACCEPTED;
                                    NdisFreeMemory(pPacketContent, 0, 0);
                                    NdisDprFreePacket(MyPacket);
                                    return Status;
                                }
                                
                                NdisZeroMemory(pNewPacketContent, PacketLength);
                                
                                packet_size = Udp6to4(pPacketContent, pNewPacketContent, original);
                                if (packet_size == 0)
                                {
                                    DBGPRINT(("==> PtReceive: Translate failed with Udp6to4. Drop packet.\n"));
                                    Status = NDIS_STATUS_NOT_ACCEPTED;
                                    // Notice: we have two memory to free here!
                                    NdisFreeMemory(pPacketContent, 0, 0);
                                    NdisFreeMemory(pNewPacketContent, 0, 0);
                                    NdisDprFreePacket(MyPacket);
                                    return Status;
                                }
                                
                                // Switch pointers and free old packet memory
                                pTemp = pPacketContent;
                                pPacketContent = pNewPacketContent;
                                pNewPacketContent = pTemp;
                                NdisFreeMemory( pNewPacketContent, 0, 0 );
                                //DBGPRINT(("==> PtReceive: old packet memory freed.\n"));
                            }
                        }
                    }
                }
                
                NdisAllocateBuffer(&Status, &MyBuffer, pAdapt->RecvBufferPoolHandle, pPacketContent, packet_size);
                NdisChainBufferAtFront(MyPacket, MyBuffer);
                
                //
                // Make our packet point to data from the original
                // packet. NOTE: this works only because we are
                // indicating a receive directly from the context of
                // our receive indication. If we need to queue this
                // packet and indicate it from another thread context,
                // we will also have to allocate a new buffer and copy
                // over the packet contents, OOB data and per-packet
                // information. This is because the packet data
                // is available only for the duration of this
                // receive indication call.
                //
                //NDIS_PACKET_FIRST_NDIS_BUFFER(MyPacket) = NDIS_PACKET_FIRST_NDIS_BUFFER(Packet);
                //NDIS_PACKET_LAST_NDIS_BUFFER(MyPacket) = NDIS_PACKET_LAST_NDIS_BUFFER(Packet);
                //
                // changed for NAT
                //
                MyPacket->Private.Head->Next = NULL;
                MyPacket->Private.Tail = NULL;

                //
                // Get the original packet (it could be the same packet as the
                // one received or a different one based on the number of layered
                // miniports below) and set it on the indicated packet so the OOB
                // data is visible correctly at protocols above.
                //
                NDIS_SET_ORIGINAL_PACKET(MyPacket, NDIS_GET_ORIGINAL_PACKET(Packet));
                NDIS_SET_PACKET_HEADER_SIZE(MyPacket, HeaderBufferSize);

                //
                // Copy packet flags.
                //
                NdisGetPacketFlags(MyPacket) = NdisGetPacketFlags(Packet);

                //
                // Force protocols above to make a copy if they want to hang
                // on to data in this packet. This is because we are in our
                // Receive handler (not ReceivePacket) and we can't return a
                // ref count from here.
                //
                NDIS_SET_PACKET_STATUS(MyPacket, NDIS_STATUS_RESOURCES);

                //
                // By setting NDIS_STATUS_RESOURCES, we also know that we can reclaim
                // this packet as soon as the call to NdisMIndicateReceivePacket
                // returns.
                //
                // NOTE: we queue the packet and indicate this packet immediately with
                // the already queued packets together. We have to the queue the packet 
                // first because some versions of NDIS might call protocols' 
                // ReceiveHandler(not ReceivePacketHandler) if the packet indicate status 
                // is NDIS_STATUS_RESOURCES. If the miniport below indicates an array of 
                // packets, some of them with status NDIS_STATUS_SUCCESS, some of them 
                // with status NDIS_STATUS_RESOURCES, PtReceive might be called, by 
                // doing this way, we preserve the receive order of packets.
                // 
                PtQueueReceivedPacket(pAdapt, MyPacket, TRUE);
                
                //
                // Reclaim the memory and buffer we allocate for NAT
                //
                NdisUnchainBufferAtFront(MyPacket, &MyBuffer);
                while (MyBuffer != NULL)
                {
                    NdisQueryBufferSafe(MyBuffer, &pPacketContent, &BufferLength, NormalPagePriority);
                    if( pPacketContent != NULL )
                    {
                        NdisFreeMemory(pPacketContent, BufferLength, 0);
                    }
                    TempBuffer = MyBuffer;
                    NdisGetNextBuffer(TempBuffer, &MyBuffer);
                    NdisFreeBuffer(TempBuffer);
                    //DBGPRINT(("==> PtReceive: pPacketContent and MyBuffer freed.\n"));
                }
                
                //
                // Reclaim the indicated packet. Since we had set its status
                // to NDIS_STATUS_RESOURCES, we are guaranteed that protocols
                // above are done with it.
                //
                NdisDprFreePacket(MyPacket);

                break;
            }
        }
        else
        {
            //
            // The miniport below us uses the old-style (not packet)
            // receive indication. Fall through.
            //
        }

        //
        // Fall through if the miniport below us has either not
        // indicated a packet or we could not allocate one
        //
        if (Packet != NULL)
        {
            //
            // We are here because we failed to allocate packet
            //
            PtFlushReceiveQueue(pAdapt);
            DBGPRINT(("==> PtReceive: PtFlushReceiveQueue(pAdapt);\n"));
        }
        //
        // Here the driver checks if the miniport adapter is in lower power state, do not indicate the 
        // packets, but the check does not close the window, it only minimizes the window. To close
        // the window completely, we need to add synchronization in the receive code path; because 
        // NDIS can handle the case that miniport drivers indicate packets in lower power state,
        // we don't add the synchronization in the hot code path.
        //    
        if ((pAdapt->MiniportHandle == NULL)
                || (pAdapt->MPDeviceState > NdisDeviceStateD0))
        {
            break;
        }
        
        pAdapt->IndicateRcvComplete = TRUE;
        switch (pAdapt->Medium)
        {
            case NdisMedium802_3:
            case NdisMediumWan:
                NdisMEthIndicateReceive(pAdapt->MiniportHandle,
                                             MacReceiveContext,
                                             HeaderBuffer,
                                             HeaderBufferSize,
                                             LookAheadBuffer,
                                             LookAheadBufferSize,
                                             PacketSize);
                break;

            case NdisMedium802_5:
                NdisMTrIndicateReceive(pAdapt->MiniportHandle,
                                            MacReceiveContext,
                                            HeaderBuffer,
                                            HeaderBufferSize,
                                            LookAheadBuffer,
                                            LookAheadBufferSize,
                                            PacketSize);
                break;
#if FDDI
            case NdisMediumFddi:
                NdisMFddiIndicateReceive(pAdapt->MiniportHandle,
                                              MacReceiveContext,
                                              HeaderBuffer,
                                              HeaderBufferSize,
                                              LookAheadBuffer,
                                              LookAheadBufferSize,
                                              PacketSize);
                break;
#endif
            default:
                ASSERT(FALSE);
                break;
        }

    } while(FALSE);

    return Status;
}

INT
PtReceivePacket(
    IN NDIS_HANDLE            ProtocolBindingContext,
    IN PNDIS_PACKET           Packet
    )
/*++

Routine Description:

    ReceivePacket handler. Called by NDIS if the miniport below supports
    NDIS 4.0 style receives. Re-package the buffer chain in a new packet
    and indicate the new packet to protocols above us. Any context for
    packets indicated up must be kept in the MiniportReserved field.

    NDIS 5.1 - packet stacking - if there is sufficient "stack space" in
    the packet passed to us, we can use the same packet in a receive
    indication.

Arguments:

    ProtocolBindingContext - Pointer to our adapter structure.
    Packet - Pointer to the packet

Return Value:

    == 0 -> We are done with the packet
    != 0 -> We will keep the packet and call NdisReturnPackets() this
            many times when done.
--*/
{
    PADAPT              pAdapt =(PADAPT)ProtocolBindingContext;
    NDIS_STATUS         Status;
    PNDIS_PACKET        MyPacket;
    BOOLEAN             Remaining;
    
    // copy packet defined
    PUCHAR            pPacketContent;
    PUCHAR            pTemp;
    PUCHAR            pNewPacketContent;
    UINT              BufferLength, PacketLength;
    UINT              ContentOffset = 0;
    PNDIS_BUFFER      TempBuffer, MyBuffer;
    
    // NAT defined
    ETH_HEADER       *eh;
    IP6_HEADER       *ip6h;
    ICMP6_HEADER     *icmp6h;
    IP6_HEADER       *embed_ip6h;
    ICMP6_HEADER     *embed_icmp6h;
    UDP_HEADER       *embed_uh;
    TCP_HEADER       *embed_th;
    TCP_HEADER       *th;
    UDP_HEADER       *uh;
    USHORT           original = 0;   // original port or id
    BOOLEAN          is_translate = FALSE;
    BOOLEAN          ret;
    UINT             packet_size = 0;   // bytes need to be sent in the buffer
    
    PTCP_STATE_CONTEXT  StateContext;

    //DBGPRINT(("==> PtReceivePacket called.\n"));
    
    //
    // Drop the packet silently if the upper miniport edge isn't initialized or
    // the miniport edge is in low power state
    //
    if ((!pAdapt->MiniportHandle) || (pAdapt->MPDeviceState > NdisDeviceStateD0))
    {
          //DBGPRINT(("==> !pAdapt->MiniportHandle\n"));
          return 0;
    }


    //
    // Get a packet off the pool and indicate that up
    //
    NdisDprAllocatePacket(&Status,
                           &MyPacket,
                           pAdapt->RecvPacketPoolHandle);

    if (Status == NDIS_STATUS_SUCCESS)
    {   
        PRECV_RSVD            RecvRsvd;
        
        RecvRsvd = (PRECV_RSVD)(MyPacket->MiniportReserved);
        RecvRsvd->OriginalPkt = Packet;
        
        // Query first buffer and total packet length
        NdisGetFirstBufferFromPacketSafe(Packet, &MyBuffer, &pTemp, &BufferLength, &PacketLength, NormalPagePriority);
        if (pTemp == NULL)
        {
            DBGPRINT(("==> PtReceivePacket: NdisGetFirstBufferFromPacketSafe failed.\n"));
            NdisDprFreePacket(MyPacket);
            return 0;
        }
        
        // Allocate memory
        Status = NdisAllocateMemoryWithTag((PVOID)&pPacketContent, PacketLength, TAG);
        if (Status != NDIS_STATUS_SUCCESS)
        {
            DBGPRINT(("==> PtReceivePacket: NdisAllocateMemoryWithTag failed.\n"));
            NdisDprFreePacket(MyPacket);
            return 0;
        }
        NdisZeroMemory(pPacketContent, PacketLength);
        
        // Copy packet content from buffer
        NdisMoveMemory(pPacketContent, pTemp, BufferLength);
        ContentOffset = BufferLength;
        NdisGetNextBuffer(MyBuffer, &MyBuffer);
        while (MyBuffer != NULL)
        {
            NdisQueryBufferSafe(MyBuffer, &pTemp, &BufferLength, NormalPagePriority);
            NdisMoveMemory(pPacketContent + ContentOffset, pTemp, BufferLength);
            ContentOffset += BufferLength;
            NdisGetNextBuffer(MyBuffer, &MyBuffer);
        }
        //DBGPRINT(("==> PtReceivePacket: Get packet content success.\n"));
        
        // Set packet_size
        packet_size = PacketLength;
        
        eh = (ETH_HEADER *)(pPacketContent);
        
        if (eh->type == htons(ETH_IP6))
        {
            // ipv6 packet
            //DBGPRINT(("==> PtReceivePacket: We receive an IPv6 packet.\n"));
            ip6h = (IP6_HEADER *)(pPacketContent + sizeof(ETH_HEADER));
            
            if (IsIviAddress(&(ip6h->daddr)) == 1)
            {
                if (ip6h->nexthdr == IP_ICMP6)
                {
                    // icmpv6 packet
                    DBGPRINT(("==> PtReceivePacket: We receive a ICMPv6 packet.\n"));
                    
                    icmp6h = (ICMP6_HEADER *)(pPacketContent + sizeof(ETH_HEADER) + sizeof(IP6_HEADER));
                    
                    if (icmp6h->type == ICMP6_ECHO || icmp6h->type == ICMP6_ECHO_REPLY) // Echo/Echo Reply Request
                    {
                        // Check the mapping list
                        ret = GetIcmpIdMapIn(ntohs(icmp6h->id), &original, &is_translate);
                            
                        if (ret != TRUE)
                        {
                            DBGPRINT(("==> PtReceivePacket: Check map list failed. Drop.\n"));
                            NdisFreeMemory(pPacketContent, 0, 0);
                            NdisDprFreePacket(MyPacket);
                            return 0;
                        }
                        
                        if (is_translate != TRUE)  // 6to6 mapping
                        {
                            DBGPRINT(("==> PtReceivePacket: Non-translated ICMPv6 id.\n"));
                            //DBGPRINT(("==> Old Id: %d\n", ntohs(icmp6h->id)));
                            
                            icmp6h->checksum = ChecksumUpdate(ntohs(icmp6h->checksum), ntohs(icmp6h->id), original);
                            icmp6h->id = htons(original);
                            
                            //DBGPRINT(("==> New Id: %d\n", ntohs(icmp6h->id)));
                            //DBGPRINT(("==> New checksum: %02x\n", icmp6h->checksum));
                        }
                        else  // 6to4 mapping
                        {
                            Status = NdisAllocateMemoryWithTag( (PVOID)&pNewPacketContent, PacketLength, TAG );
                            if (Status != NDIS_STATUS_SUCCESS)
                            {
                                DBGPRINT(("==> PtReceivePacket: NdisAllocateMemoryWithTag failed with pNewPacketContent. Drop packet.\n"));
                                NdisFreeMemory(pPacketContent, 0, 0);
                                NdisDprFreePacket(MyPacket);
                                return 0;
                            }

                            NdisZeroMemory(pNewPacketContent, PacketLength);
                            
                            packet_size = Icmp6to4(pPacketContent, pNewPacketContent, original);
                            if (packet_size == 0)
                            {
                                DBGPRINT(("==> PtReceivePacket: Translate failed with Icmp6to4. Drop packet.\n"));
                                // Notice: we have two memory to free here!
                                NdisFreeMemory(pPacketContent, 0, 0);
                                NdisFreeMemory(pNewPacketContent, 0, 0);
                                NdisDprFreePacket(MyPacket);
                                return 0;
                            }
                            
                            // Switch pointers and free old packet memory
                            pTemp = pPacketContent;
                            pPacketContent = pNewPacketContent;
                            pNewPacketContent = pTemp;
                            NdisFreeMemory( pNewPacketContent, 0, 0 );
                            //DBGPRINT(("==> PtReceivePacket: old packet memory freed.\n"));
                        }
                    }
                    /*else
                    {
                        DBGPRINT(("==> PtReceivePacket: Unkown ICMPv6 type, drop packet.\n"));
                        NdisFreeMemory(pPacketContent, 0, 0);
                        NdisDprFreePacket(MyPacket);
                        return 0;
                    }*/
                }
                else if (ip6h->nexthdr == IP_TCP)
                {
                    // tcpv6 packet
                    DBGPRINT(("==> PtReceivePacket: We receive a TCPv6 packet.\n"));
                    
                    th = (TCP_HEADER *)(pPacketContent + sizeof(ETH_HEADER) + sizeof(IP6_HEADER));
                    
                    // Check the mapping list
                    NdisAcquireSpinLock(&StateListLock);
                    StateContext = TcpPortMapInTable[ntohs(th->dport)].State;
                    if (StateContext != NULL)
                    {
                        is_translate = StateContext->Translated;
                    }
                    NdisReleaseSpinLock(&StateListLock);
                            
                    if (is_translate != TRUE)
                    {
                        DBGPRINT(("==> PtReceivePacket: Non-translated TCPv6 port.\n"));
                        //DBGPRINT(("==> Source port: %d\n", ntohs(th->sport)));
                        //DBGPRINT(("==> Old Dest port: %d\n", ntohs(th->dport)));
                        original = GetTcpPortMapIn(th, ntohs(ip6h->payload));
                        
                        if (original == 0)
                        {
                            DBGPRINT(("==> PtReceivePacket: Find map failed. Drop.\n"));
                            NdisFreeMemory(pPacketContent, 0, 0);
                            NdisDprFreePacket(MyPacket);
                            return 0;
                        }
        
                        th->checksum = ChecksumUpdate(ntohs(th->checksum), ntohs(th->dport), original);
                        th->dport = htons(original);
                        
                        //DBGPRINT(("==> New Dest port: %d\n", ntohs(th->dport)));
                        //DBGPRINT(("==> New checksum: %02x\n", th->checksum));
                    }
                    else
                    {
                        Status = NdisAllocateMemoryWithTag((PVOID)&pNewPacketContent, PacketLength, TAG);
                        if (Status != NDIS_STATUS_SUCCESS)
                        {
                            DBGPRINT(("==> PtReceivePacket: NdisAllocateMemory failed with pNewPacketContent. Drop packet.\n"));
                            NdisFreeMemory(pPacketContent, 0, 0);
                            NdisDprFreePacket(MyPacket);
                            return 0;
                        }
                        
                        NdisZeroMemory(pNewPacketContent, PacketLength);
                        
                        packet_size = tcp6to4(pPacketContent, pNewPacketContent);
                        if (packet_size == 0)
                        {
                            DBGPRINT(("==> PtReceivePacket: Translate failed with tcp6to4. Drop packet.\n"));
                            // Notice: we have two memory to free here!
                            NdisFreeMemory(pPacketContent, 0, 0);
                            NdisFreeMemory(pNewPacketContent, 0, 0);
                            NdisDprFreePacket(MyPacket);
                            return 0;
                        }
                        
                        // Switch pointers and free old packet memory
                        pTemp = pPacketContent;
                        pPacketContent = pNewPacketContent;
                        pNewPacketContent = pTemp;
                        NdisFreeMemory( pNewPacketContent, 0, 0 );
                        //DBGPRINT(("==> PtReceivePacket: old packet memory freed.\n"));
                    }
                    
                }
                else if (ip6h->nexthdr == IP_UDP)
                {
                    // udpv6 packet
                    DBGPRINT(("==> PtReceivePacket: We receive a UDPv6 packet.\n"));
                    
                    uh = (UDP_HEADER *)(pPacketContent + sizeof(ETH_HEADER) + sizeof(IP6_HEADER));
                    
                    // Check the mapping list
                    ret = GetUdpPortMapIn(ntohs(uh->dport), &original, &is_translate);
                            
                    if (ret != TRUE)
                    {
                        DBGPRINT(("==> PtReceivePacket: Check map list failed. Drop.\n"));
                        NdisFreeMemory(pPacketContent, 0, 0);
                        NdisDprFreePacket(MyPacket);
                        return 0;
                    }
                            
                    if (is_translate != TRUE)
                    {
                        DBGPRINT(("==> PtReceivePacket: Non-translated UDPv6 port.\n"));
                        //DBGPRINT(("==> Source port: %d\n", ntohs(uh->sport)));
                        //DBGPRINT(("==> Old Dest port: %d\n", ntohs(uh->dport)));
        
                        uh->checksum = ChecksumUpdate(ntohs(uh->checksum), ntohs(uh->dport), original);
                        uh->dport = htons(original);
                        
                        //DBGPRINT(("==> New Dest port: %d\n", ntohs(uh->dport)));
                        //DBGPRINT(("==> New checksum: %02x\n", uh->checksum));
                    }
                    else
                    {
                        Status = NdisAllocateMemoryWithTag((PVOID)&pNewPacketContent, PacketLength, TAG);
                        if (Status != NDIS_STATUS_SUCCESS)
                        {
                            DBGPRINT(("==> PtReceivePacket: NdisAllocateMemory failed with pNewPacketContent. Drop packet.\n"));
                            NdisFreeMemory(pPacketContent, 0, 0);
                            NdisDprFreePacket(MyPacket);
                            return 0;
                        }
                        
                        NdisZeroMemory(pNewPacketContent, PacketLength);
                        
                        packet_size = Udp6to4(pPacketContent, pNewPacketContent, original);
                        if (packet_size == 0)
                        {
                            DBGPRINT(("==> PtReceivePacket: Translate failed with Udp6to4. Drop packet.\n"));
                            // Notice: we have two memory to free here!
                            NdisFreeMemory(pPacketContent, 0, 0);
                            NdisFreeMemory(pNewPacketContent, 0, 0);
                            NdisDprFreePacket(MyPacket);
                            return 0;
                        }
                        
                        // Switch pointers and free old packet memory
                        pTemp = pPacketContent;
                        pPacketContent = pNewPacketContent;
                        pNewPacketContent = pTemp;
                        NdisFreeMemory( pNewPacketContent, 0, 0 );
                        //DBGPRINT(("==> PtReceivePacket: old packet memory freed.\n"));
                    }
                }
            }
        }
        
        NdisAllocateBuffer(&Status, &MyBuffer, pAdapt->RecvBufferPoolHandle, pPacketContent, packet_size);
        NdisChainBufferAtFront(MyPacket, MyBuffer);
        
        //NDIS_PACKET_FIRST_NDIS_BUFFER(MyPacket) = NDIS_PACKET_FIRST_NDIS_BUFFER(Packet);
        //NDIS_PACKET_LAST_NDIS_BUFFER(MyPacket) = NDIS_PACKET_LAST_NDIS_BUFFER(Packet);
        //
        // changed for NAT
        //
        MyPacket->Private.Head->Next = NULL;
        MyPacket->Private.Tail = NULL;


        //
        // Get the original packet (it could be the same packet as the one
        // received or a different one based on the number of layered miniports
        // below) and set it on the indicated packet so the OOB data is visible
        // correctly to protocols above us.
        //
        NDIS_SET_ORIGINAL_PACKET(MyPacket, NDIS_GET_ORIGINAL_PACKET(Packet));

        //
        // Set Packet Flags
        //
        NdisGetPacketFlags(MyPacket) = NdisGetPacketFlags(Packet);

        Status = NDIS_GET_PACKET_STATUS(Packet);

        NDIS_SET_PACKET_STATUS(MyPacket, Status);
        
        NDIS_SET_PACKET_HEADER_SIZE(MyPacket, NDIS_GET_PACKET_HEADER_SIZE(Packet));

        if (Status == NDIS_STATUS_RESOURCES)
        {
            PtQueueReceivedPacket(pAdapt, MyPacket, TRUE);
        }
        else
        {
            PtQueueReceivedPacket(pAdapt, MyPacket, FALSE);
        }

        //
        // Check if we had indicated up the packet with NDIS_STATUS_RESOURCES
        // NOTE -- do not use NDIS_GET_PACKET_STATUS(MyPacket) for this since
        // it might have changed! Use the value saved in the local variable.
        //
        if (Status == NDIS_STATUS_RESOURCES)
        {
            NdisUnchainBufferAtFront( MyPacket, &MyBuffer );
            while (MyBuffer != NULL)
            {
                NdisQueryBufferSafe(MyBuffer, &pPacketContent, &BufferLength, NormalPagePriority);
                if (pPacketContent != NULL)
                {
                    NdisFreeMemory(pPacketContent, BufferLength, 0);
                }
                TempBuffer = MyBuffer;
                NdisGetNextBuffer(TempBuffer, &MyBuffer);
                NdisFreeBuffer(TempBuffer);
                //DBGPRINT(("==> PtReceivePacket: pPacketContent and MyBuffer freed.\n"));
            }

            //
            // Our ReturnPackets handler will not be called for this packet.
            // We should reclaim it right here.
            //
            NdisDprFreePacket(MyPacket);
        }
        
        return((Status != NDIS_STATUS_RESOURCES) ? 1 : 0);
    }
    else
    {
        //
        // We are out of packets. Silently drop it.
        //
        return(0);
    }
}
