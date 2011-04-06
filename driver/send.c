#include "precomp.h"
#pragma hdrstop

VOID
MPSendPackets(
    IN NDIS_HANDLE             MiniportAdapterContext,
    IN PPNDIS_PACKET           PacketArray,
    IN UINT                    NumberOfPackets
    )
/*++

Routine Description:

    Send Packet Array handler. Either this or our SendPacket handler is called
    based on which one is enabled in our Miniport Characteristics.

Arguments:

    MiniportAdapterContext     Pointer to our adapter
    PacketArray                Set of packets to send
    NumberOfPackets            Self-explanatory

Return Value:

    None

--*/
{
    PADAPT              pAdapt = (PADAPT)MiniportAdapterContext;
    NDIS_STATUS         Status;
    UINT                i;
    PVOID               MediaSpecificInfo = NULL;
    UINT                MediaSpecificInfoSize = 0;
    
    PUCHAR              PacketData, PacketDataNew, TempPointer;
    UINT                BufferLength, PacketLength;
    UINT                ContentOffset = 0;
    PNDIS_BUFFER        TempBuffer, MyBuffer;

    USHORT              mapped = 0;  // Mapped port or id number
    BOOLEAN             ret;
    UINT                PacketSendSize = 0; // Length of bytes need to be sent in the buffer
    
    //DBGPRINT(("==> MPSendPackets entered.\n"));
    
    for (i = 0; i < NumberOfPackets; i++)
    {
        PNDIS_PACKET    Packet, MyPacket;

        Packet = PacketArray[i];
        //
        // The driver should fail the send if the virtual miniport is in low 
        // power state
        //
        if (pAdapt->MPDeviceState > NdisDeviceStateD0)
        {
            NdisMSendComplete(ADAPT_MINIPORT_HANDLE(pAdapt),
                            Packet,
                            NDIS_STATUS_FAILURE);
            continue;
        }

        do 
        {
            NdisAcquireSpinLock(&pAdapt->Lock);
            //
            // If the below miniport is going to low power state, stop sending down any packet.
            //
            if (pAdapt->PTDeviceState > NdisDeviceStateD0)
            {
                NdisReleaseSpinLock(&pAdapt->Lock);
                Status = NDIS_STATUS_FAILURE;
                break;
            }
            pAdapt->OutstandingSends++;
            NdisReleaseSpinLock(&pAdapt->Lock);
            
            NdisAllocatePacket(&Status,
                               &MyPacket,
                               pAdapt->SendPacketPoolHandle);

            if (Status == NDIS_STATUS_SUCCESS)
            {
                PSEND_RSVD        SendRsvd;
                PETH_HEADER       eh;
                
                SendRsvd = (PSEND_RSVD)(MyPacket->ProtocolReserved);
                SendRsvd->OriginalPkt = Packet;

                // Query first buffer and total packet length
                NdisGetFirstBufferFromPacketSafe(Packet, &MyBuffer, &TempPointer, &BufferLength, &PacketLength, NormalPagePriority);
                if (TempPointer == NULL)
                {
                    DBGPRINT(("==> MPSendPackets: NdisGetFirstBufferFromPacketSafe failed.\n"));
                    Status = NDIS_STATUS_FAILURE;
                    NdisFreePacket(MyPacket);
                    ADAPT_DECR_PENDING_SENDS(pAdapt);
                    break;
                }
                
                // Check packet size
                //DBGPRINT(("==> MPSendPackets: Packet (eth frame) size %d.\n", PacketLength));
                if (PacketLength + IVI_PACKET_OVERHEAD > 1514)
                {
                    // 1514 = 1500 + ETH_HEADER length (14)
                    DBGPRINT(("==> MPSendPackets: Packet (eth frame) size %d too big.\n", PacketLength));
                    Status = NDIS_STATUS_FAILURE;
                    NdisFreePacket(MyPacket);
                    ADAPT_DECR_PENDING_SENDS(pAdapt);
                    break;
                }
                
                // Allocate memory
                Status = NdisAllocateMemoryWithTag((PVOID)&PacketData, PacketLength, TAG);
                if (Status != NDIS_STATUS_SUCCESS)
                {
                    DBGPRINT(("==> MPSendPackets: NdisAllocateMemoryWithTag failed with PacketData.\n"));
                    Status = NDIS_STATUS_FAILURE;
                    NdisFreePacket(MyPacket);
                    ADAPT_DECR_PENDING_SENDS(pAdapt);
                    break;
                }
                NdisZeroMemory(PacketData, PacketLength);
                
                // Copy packet content from buffer
                NdisMoveMemory(PacketData, TempPointer, BufferLength);
                ContentOffset = BufferLength;
                NdisGetNextBuffer(MyBuffer, &MyBuffer);
                while (MyBuffer != NULL)
                {
                    NdisQueryBufferSafe(MyBuffer, &TempPointer, &BufferLength, NormalPagePriority);
                    NdisMoveMemory(PacketData + ContentOffset, TempPointer, BufferLength);
                    ContentOffset += BufferLength;
                    NdisGetNextBuffer(MyBuffer, &MyBuffer);
                }
                
                // Set PacketSendSize
                PacketSendSize = PacketLength;
                
                eh = (ETH_HEADER *)(PacketData);
                
                if (eh->type == htons(ETH_IP)) 
                {
                    if (enable_xlate)  /* xlate */
                    {
                        // ipv4 packet
                        PIP_HEADER ih = (IP_HEADER *)(PacketData + sizeof(ETH_HEADER));
                        PPREFIX_LOOKUP_CONTEXT PrefixContext = NULL;
                        
                        if (IsEtherUnicast(eh->dmac) == FALSE)
                        {
                            DBGPRINT(("==> MPSendPackets: Ethernet dest mac %02x:%02x:%02x:%02x:%02x:%02x is not unicast, drop the IPv4 packet.\n", 
                                    eh->dmac[0], eh->dmac[1], eh->dmac[2], 
                                    eh->dmac[3], eh->dmac[4], eh->dmac[5]));
                            Status = NDIS_STATUS_FAILURE;
                            NdisFreeMemory(PacketData, 0, 0);
                            NdisFreePacket(MyPacket);
                            ADAPT_DECR_PENDING_SENDS(pAdapt);
                            break;
                        }
                        
                        NdisAcquireSpinLock(&PrefixListLock);
                        // Look up the prefix for the destination address
                        PrefixContext = PrefixLookupAddr4(&(ih->daddr));
                        if (PrefixContext == NULL)
                        {
                            // Failed to find or create an entry. Drop packet.
                            NdisReleaseSpinLock(&PrefixListLock);
                            DBGPRINT(("==> MPSendPackets: PrefixLookupAddr4 failed with memory allocation.\n"));
                            Status = NDIS_STATUS_FAILURE;
                            NdisFreeMemory(PacketData, 0, 0);
                            NdisFreePacket(MyPacket);
                            ADAPT_DECR_PENDING_SENDS(pAdapt);
                            break;
                        }
                        
                        if (PrefixContext->Resolved == FALSE)
                        {
                            // Entry is not resolved yet, send request
                            PUCHAR           MyData = NULL;
                            UINT             MyPacketSize = sizeof(ETH_HEADER) + sizeof(IP6_HEADER) + sizeof(ICMP6_HEADER);
                            PETH_HEADER      req_eh = NULL;
                            PIP6_HEADER      req_ip6h = NULL;
                            PICMP6_HEADER    req_icmp6h = NULL;
                            
                            if (PrefixContext->TryCount >= PREFIX_LOOKUP_MAX_RETRIES)
                            {
                                // Remove this entry and drop packet.
                                RemoveEntryList(&(PrefixContext->ListEntry));
                                NdisReleaseSpinLock(&PrefixListLock);
                                
                                DBGPRINT(("==> MPSendPackets: Prefix context for ip %d.%d.%d.%d reached max tries (5). Delete and free resources.\n", 
                                          PrefixContext->Mib.Address.u.byte[0], PrefixContext->Mib.Address.u.byte[1], 
                                          PrefixContext->Mib.Address.u.byte[2], PrefixContext->Mib.Address.u.byte[3]));
                                
                                if (PrefixContext->HoldPacketData != NULL)
                                {
                                    NdisFreeMemory(PrefixContext->HoldPacketData, 0, 0);
                                }
                                // Release prefix context memory.
                                NdisFreeMemory(PrefixContext, 0, 0);
                                
                                // Release resource we allocated in this function call.
                                Status = NDIS_STATUS_FAILURE;
                                NdisFreeMemory(PacketData, 0, 0);
                                NdisFreePacket(MyPacket);
                                ADAPT_DECR_PENDING_SENDS(pAdapt);
                                break;
                            }
                            
                            // Create memory for request packet. This packet is not counted in pAdapt->OutstandingSends
                            Status = NdisAllocateMemoryWithTag((PVOID)&MyData, MyPacketSize, TAG);
                            if (Status != NDIS_STATUS_SUCCESS)
                            {
                                NdisReleaseSpinLock(&PrefixListLock);
                                DBGPRINT(("==> MPSendPackets: NdisAllocateMemoryWithTag failed for MyData.\n"));
                                // XXX: we won't touch prefix context if we fail to allocate memory for the request packet.
                                Status = NDIS_STATUS_FAILURE;
                                NdisFreeMemory(PacketData, 0, 0);
                                NdisFreePacket(MyPacket);
                                ADAPT_DECR_PENDING_SENDS(pAdapt);
                                break;
                            }
                            NdisZeroMemory(MyData, MyPacketSize);
                            
                            // Build request packet.
                            req_eh = (PETH_HEADER)(MyData);
                            req_ip6h = (PIP6_HEADER)(MyData + sizeof(ETH_HEADER));
                            req_icmp6h = (PICMP6_HEADER)(MyData + sizeof(ETH_HEADER) + sizeof(IP6_HEADER));
                            
                            // Build Ethernet header.
                            ETH_COPY_NETWORK_ADDRESS(req_eh->dmac, eh->dmac);  // XXX: Destination MAC is gateway MAC
                            ETH_COPY_NETWORK_ADDRESS(req_eh->smac, eh->smac);
                            req_eh->type = htons(ETH_IP6);
                            
                            // Build IPv6 header.
                            req_ip6h->ver_pri = 0x60;
                            req_ip6h->payload = htons(sizeof(ICMP6_HEADER));
                            req_ip6h->nexthdr = IP_ICMP6;
                            req_ip6h->hoplimit = 255;
                            
                            IPAddr4to6(&(ih->saddr), &(req_ip6h->saddr), &LocalPrefixInfo);  // Use local prefix info for src address translation
                            NdisMoveMemory(req_ip6h->daddr.u.byte, PrefixServerAddress.u.byte, 16);  // Set prefix server address
                            
                            // Build ICMPv6 header.
                            req_icmp6h->type = ICMP6_PREF_REQUEST;
                            req_icmp6h->code = 0;
                            req_icmp6h->checksum = 0;
                            // XXX: should use union in ICMPv6 header
                            req_icmp6h->id = ih->daddr.u.word[0];
                            req_icmp6h->seq = ih->daddr.u.word[1];
                            checksum_icmp6(req_ip6h, req_icmp6h);
                            
                            // Allocate buffer.
                            NdisAllocateBuffer(&Status, &MyBuffer, pAdapt->SendBufferPoolHandle, MyData, MyPacketSize);
                            if (Status != NDIS_STATUS_SUCCESS)
                            {
                                DBGPRINT(("==> MPSendPackets: NdisAllocateBuffer failed for MyData.\n"));
                                // XXX: we won't touch prefix context if we fail to allocate buffer for a request packet.
                                Status = NDIS_STATUS_FAILURE;
                                // Notice: we have two memory to free here.
                                NdisFreeMemory(MyData, 0, 0);
                                NdisFreeMemory(PacketData, 0, 0);
                                NdisFreePacket(MyPacket);
                                break;
                            }
                            
                            // Send request packet using 'MyPacket'
                            SendRsvd->OriginalPkt = NULL;   // Indicate that this is the packet we built by ourselves
                            NdisChainBufferAtFront(MyPacket, MyBuffer);
                            MyPacket->Private.Head->Next = NULL;
                            MyPacket->Private.Tail = NULL;
                            
                            NdisSend(&Status, 
                                     pAdapt->BindingHandle, 
                                     MyPacket);
                            
                            if (Status != NDIS_STATUS_PENDING)
                            {
                                NdisUnchainBufferAtFront(MyPacket, &MyBuffer);
                                while (MyBuffer != NULL)
                                {
                                    NdisQueryBufferSafe(MyBuffer, &MyData, &BufferLength, NormalPagePriority);
                                    if (MyData != NULL)
                                    {
                                        NdisFreeMemory(MyData, BufferLength, 0);
                                    }
                                    TempBuffer = MyBuffer;
                                    NdisGetNextBuffer(TempBuffer, &MyBuffer);
                                    NdisFreeBuffer(TempBuffer);
                                }
                                NdisFreePacket(MyPacket);
                                DBGPRINT(("==> MPSendPackets: Send request finish without pending and all resources freed.\n"));
                            }
                            
                            // Update prefix context.
                            PrefixContext->TryCount++;
                            DBGPRINT(("==> MPSendPackets: TryCount set to %d.\n", PrefixContext->TryCount));
                            
                            // Hold only most recent packet.
                            if (PrefixContext->HoldPacketData != NULL)
                            {
                                NdisFreeMemory(PrefixContext->HoldPacketData, 0, 0);
                            }
                            PrefixContext->HoldPacketData = PacketData;
                            
                            NdisReleaseSpinLock(&PrefixListLock);
                            //
                            // NDIS requires us to release any spin lock before calling 
                            // NdisMSendComplete().
                            //
                            
                            // Complete the current send with success.
                            Status = NDIS_STATUS_SUCCESS;
                            
                            ADAPT_DECR_PENDING_SENDS(pAdapt);
                            
                            NdisMSendComplete(ADAPT_MINIPORT_HANDLE(pAdapt),
                                              Packet,
                                              Status);
                            
                            return;
                        }
                        else
                        {
                            // This entry is valid, use it
                            PIVI_PREFIX_MIB Mib = &(PrefixContext->Mib);
                            
                            if (ih->protocol == IP_ICMP)
                            {
                                // ICMPv4 packet
                                PICMP_HEADER icmph = (ICMP_HEADER *)(PacketData + sizeof(ETH_HEADER) + (ih->ver_ihl & 0x0f) * 4);
                                
                                DBGPRINT(("==> MPSendPackets: We send an ICMPv4 packet.\n"));
                                
                                if (icmph->type == ICMP_ECHO || icmph->type == ICMP_ECHO_REPLY) // Echo/Echo Reply Request
                                {
                                    Status = NdisAllocateMemoryWithTag((PVOID)&PacketDataNew, PacketLength + IVI_PACKET_OVERHEAD, TAG);
                                    if (Status != NDIS_STATUS_SUCCESS)
                                    {
                                        DBGPRINT(("==> MPSendPackets: NdisAllocateMemoryWithTag failed with PacketDataNew. Drop packet.\n"));
                                        Status = NDIS_STATUS_FAILURE;
                                        NdisFreeMemory(PacketData, 0, 0);
                                        NdisFreePacket(MyPacket);
                                        ADAPT_DECR_PENDING_SENDS(pAdapt);
                                        break;
                                    }
                                    
                                    NdisZeroMemory(PacketDataNew, PacketLength + IVI_PACKET_OVERHEAD);
                                    
                                    PacketSendSize = Icmp4to6(PacketData, PacketDataNew, Mib);
                                    if (PacketSendSize == 0)
                                    {
                                        DBGPRINT(("==> MPSendPackets: Translate failed with Icmp4to6. Drop packet.\n"));
                                        Status = NDIS_STATUS_FAILURE;
                                        // Notice: we have two memory to free here!
                                        NdisFreeMemory(PacketData, 0, 0);
                                        NdisFreeMemory(PacketDataNew, 0, 0);
                                        NdisFreePacket(MyPacket);
                                        ADAPT_DECR_PENDING_SENDS(pAdapt);
                                        break;
                                    }
                                    
                                    // Switch pointers and free old packet memory
                                    TempPointer = PacketData;
                                    PacketData = PacketDataNew;
                                    PacketDataNew = TempPointer;
                                    NdisFreeMemory( PacketDataNew, 0, 0 );
                                    //DBGPRINT(("==> MPSendPackets: old packet memory freed.\n"));
                                }
                                else
                                {
                                    DBGPRINT(("==> MPSendPackets: Unkown icmp type, drop packet.\n"));
                                    Status = NDIS_STATUS_FAILURE;
                                    NdisFreeMemory(PacketData, 0, 0);
                                    NdisFreePacket(MyPacket);
                                    ADAPT_DECR_PENDING_SENDS(pAdapt);
                                    break;
                                }
                            }
                            else if (ih->protocol == IP_TCP)
                            {
                                // TCPv4 packet
                                PTCP_HEADER th = (TCP_HEADER *)(PacketData + sizeof(ETH_HEADER) + (ih->ver_ihl & 0x0f) * 4);
                                
                                DBGPRINT(("==> MPSendPackets: We send a TCPv4 packet.\n"));
                                
                                Status = NdisAllocateMemoryWithTag((PVOID)&PacketDataNew, PacketLength + IVI_PACKET_OVERHEAD, TAG);
                                if (Status != NDIS_STATUS_SUCCESS)
                                {
                                    DBGPRINT(("==> MPSendPackets: NdisAllocateMemory failed with PacketDataNew. Drop packet.\n"));
                                    Status = NDIS_STATUS_FAILURE;
                                    NdisFreeMemory(PacketData, 0, 0);
                                    NdisFreePacket(MyPacket);
                                    ADAPT_DECR_PENDING_SENDS(pAdapt);
                                    break;
                                }
                                
                                NdisZeroMemory(PacketDataNew, PacketLength + IVI_PACKET_OVERHEAD);
                                
                                PacketSendSize = Tcp4to6(PacketData, PacketDataNew, Mib);
                                if (PacketSendSize == 0)
                                {
                                    DBGPRINT(("==> MPSendPackets: Translate failed with Tcp4to6. Drop packet.\n"));
                                    Status = NDIS_STATUS_FAILURE;
                                    // Notice: we have two memory to free here!
                                    NdisFreeMemory(PacketData, 0, 0);
                                    NdisFreeMemory(PacketDataNew, 0, 0);
                                    NdisFreePacket(MyPacket);
                                    ADAPT_DECR_PENDING_SENDS(pAdapt);
                                    break;
                                }
                                
                                // Switch pointers and free old packet memory
                                TempPointer = PacketData;
                                PacketData = PacketDataNew;
                                PacketDataNew = TempPointer;
                                NdisFreeMemory(PacketDataNew, 0, 0);
                                //DBGPRINT(("==> MPSendPackets: old packet memory freed.\n"));
                                
                            }
                            else if (ih->protocol == IP_UDP)
                            {
                                // UDPv4 packet
                                PUDP_HEADER uh = (UDP_HEADER *)(PacketData + sizeof(ETH_HEADER) + (ih->ver_ihl & 0x0f) * 4);
                                
                                DBGPRINT(("==> MPSendPackets: We send a UDPv4 packet.\n"));
                                
                                Status = NdisAllocateMemoryWithTag((PVOID)&PacketDataNew, PacketLength + IVI_PACKET_OVERHEAD, TAG);
                                if (Status != NDIS_STATUS_SUCCESS)
                                {
                                    DBGPRINT(("==> MPSendPackets: NdisAllocateMemory failed with PacketDataNew. Drop packet.\n"));
                                    Status = NDIS_STATUS_FAILURE;
                                    NdisFreeMemory(PacketData, 0, 0);
                                    NdisFreePacket(MyPacket);
                                    ADAPT_DECR_PENDING_SENDS(pAdapt);
                                    break;
                                }
                                
                                NdisZeroMemory(PacketDataNew, PacketLength + IVI_PACKET_OVERHEAD);
                                
                                PacketSendSize = Udp4to6(PacketData, PacketDataNew, Mib);
                                if (PacketSendSize == 0)
                                {
                                    DBGPRINT(("==> MPSendPackets: Translate failed with udp4to6. Drop packet.\n"));
                                    Status = NDIS_STATUS_FAILURE;
                                    // Notice: we have two memory to free here!
                                    NdisFreeMemory(PacketData, 0, 0);
                                    NdisFreeMemory(PacketDataNew, 0, 0);
                                    NdisFreePacket(MyPacket);
                                    ADAPT_DECR_PENDING_SENDS(pAdapt);
                                    break;
                                }
                                
                                // Switch pointers and free old packet memory
                                TempPointer = PacketData;
                                PacketData = PacketDataNew;
                                PacketDataNew = TempPointer;
                                NdisFreeMemory(PacketDataNew, 0, 0);
                                //DBGPRINT(("==> MPSendPackets: old packet memory freed.\n"));
                            }
                            else
                            {
                                DBGPRINT(("==> MPSendPackets: Unkown protocol type. Drop packet.\n"));
                                Status = NDIS_STATUS_FAILURE;
                                NdisFreeMemory(PacketData, 0, 0);
                                NdisFreePacket(MyPacket);
                                ADAPT_DECR_PENDING_SENDS(pAdapt);
                                break;
                            }
                        }
                    }
                    else
                    {
                        /*
                         * enable_xlate == 0, do nothing to IPv4 packets, bypass.
                         *
                         */
                    }
                }
                else if (eh->type == htons(ETH_ARP))
                {
                    // arp packet
                    if (enable_xlate)  /* xlate enabled */
                    {
                        PARP_HEADER ah = (ARP_HEADER *)(PacketData + sizeof(ETH_HEADER));
                        
                        //DBGPRINT(("==> MPSendPackets: We send an ARP packet.\n"));
                        
                        DBGPRINT(("==> MPSendPackets: ARP Source MAC is %02x:%02x:%02x:%02x:%02x:%02x.\n", 
                                    eh->smac[0], eh->smac[1], eh->smac[2], 
                                    eh->smac[3], eh->smac[4], eh->smac[5]));
                        DBGPRINT(("==> MPSendPackets: ARP Destination MAC is %02x:%02x:%02x:%02x:%02x:%02x.\n", 
                                    eh->dmac[0], eh->dmac[1], eh->dmac[2], 
                                    eh->dmac[3], eh->dmac[4], eh->dmac[5]));
                        /*
                        DBGPRINT(("==> MPSendPackets: ARP Source IP is %02x.%02x.%02x.%02x\n", 
                                    ah->sip[0], ah->sip[1], ah->sip[2], ah->sip[3]));
                        DBGPRINT(("==> MPSendPackets: ARP Destination IP is %02x.%02x.%02x.%02x\n", 
                                    ah->dip[0], ah->dip[1], ah->dip[2], ah->dip[3]));
                        */
                        
                        // Indicate send success
                        Status = NDIS_STATUS_SUCCESS;
                        
                        ADAPT_DECR_PENDING_SENDS(pAdapt);
                        
                        NdisMSendComplete(ADAPT_MINIPORT_HANDLE(pAdapt),
                                          Packet,
                                          Status); 
                        
                        if (NdisEqualMemory(ah->sip, ah->dip, 4) == 1)
                        {
                            // Gratuitous ARP from local TCP/IP stack. Drop.
                            //DBGPRINT(("==> MPSendPackets: Gratuitous ARP request. Drop packet.\n"));
                            NdisFreeMemory(PacketData, 0, 0);
                            NdisFreePacket(MyPacket);
                            //DBGPRINT(("==> MPReturnPacket: MyPacket is freed for gratuitous ARP request.\n"));
                        }
                        else
                        {
                            INT            k;
                            UCHAR          TempChar;
                            LARGE_INTEGER  CurrentTime;
                            
                            // Build ARP reply.
                            for (k = 0; k < 6; k++)
                            {
                                eh->dmac[k] = eh->smac[k];
                                eh->smac[k] = GatewayMAC[k];
                            }
                            
                            for (k = 0; k < 6; k++)
                            {
                                ah->dmac[k] = ah->smac[k];
                                ah->smac[k] = GatewayMAC[k];
                            }
                            
                            for (k = 0; k < 4; k++)
                            {
                                TempChar = ah->sip[k];
                                ah->sip[k] = ah->dip[k];
                                ah->dip[k] = TempChar;
                            }
                            
                            ah->option = htons(ARP_REPLY);
                            
                            // Indicate this packet.
                            NdisAllocateBuffer(&Status, &MyBuffer, pAdapt->SendBufferPoolHandle, PacketData, PacketSendSize);
                            if (Status != NDIS_STATUS_SUCCESS)
                            {
                                DBGPRINT(("==> MPSendPackets: NdisAllocateBuffer failed for ARP.\n"));
                                Status = NDIS_STATUS_FAILURE;
                                NdisFreeMemory(PacketData, 0, 0);
                                NdisFreePacket(MyPacket);
                                break;
                            }
                            
                            NdisChainBufferAtFront(MyPacket, MyBuffer);
                            MyPacket->Private.Head->Next = NULL;
                            MyPacket->Private.Tail = NULL;
                            
                            // Set original packet is not necessary.
                            
                            NdisGetCurrentSystemTime(&CurrentTime);
                            NDIS_SET_PACKET_TIME_RECEIVED(MyPacket, CurrentTime.QuadPart);
                            NDIS_SET_PACKET_HEADER_SIZE(MyPacket, sizeof(ETH_HEADER));
                            
                            // Set packet flags is not necessary.
                            
                            NDIS_SET_PACKET_STATUS(MyPacket, NDIS_STATUS_RESOURCES);
                            
                            //DBGPRINT(("==> MPSendPackets: Queue ARP reply packet with true flag.\n"));
                            PtQueueReceivedPacket(pAdapt, MyPacket, TRUE);
                            DBGPRINT(("==> MPSendPackets: ARP reply is indicated.\n"));
                            
                            NdisUnchainBufferAtFront(MyPacket, &MyBuffer);
                            while (MyBuffer != NULL)
                            {
                                NdisQueryBufferSafe(MyBuffer, &PacketData, &BufferLength, NormalPagePriority);
                                if (PacketData != NULL)
                                {
                                    NdisFreeMemory(PacketData, BufferLength, 0);
                                }
                                TempBuffer = MyBuffer;
                                NdisGetNextBuffer(TempBuffer, &MyBuffer);
                                NdisFreeBuffer(TempBuffer);
                                //DBGPRINT(("==> MPSendPackets: PacketData and MyBuffer are freed for ARP.\n"));
                            }
                            
                            NdisFreePacket(MyPacket);
                            //DBGPRINT(("==> MPSendPackets: MyPacket is freed for ARP.\n"));
                        }
                        
                        return;
                    }
                    else
                    {
                        /*
                         * enable_xlate == 0, do nothing to ARP packets, bypass.
                         *
                         */
                    }
                }
                else if (eh->type == htons(ETH_IP6))
                {
                    // ipv6 packet
                    PIP6_HEADER ip6h = (IP6_HEADER *)(PacketData + sizeof(ETH_HEADER));
                    
                    if (IsIviAddress(&(ip6h->saddr)) == 1)
                    {
                        if (ip6h->nexthdr == IP_TCP)
                        {
                            // tcpv6 packet
                            PTCP_HEADER th = (TCP_HEADER *)(PacketData + sizeof(ETH_HEADER) + sizeof(IP6_HEADER));
                            
                            INT SegmentSize = ntohs(ip6h->payload);   // Payload size is needed in determining TCP connection state
                            
                            DBGPRINT(("==> MPSendPackets: We send a TCPv6 packet.\n"));
                            
                            //DBGPRINT(("==> Old source port: %d\n", ntohs(th->sport)));
                            //DBGPRINT(("==> Old checksum: %02x\n", th->checksum));
                            
                            mapped = GetTcpPortMapOut(th, SegmentSize, FALSE);
                            
                            if (mapped == 0)
                            {
                                DBGPRINT(("==> MPSendPackets: Find map failed. Drop.\n"));
                                Status = NDIS_STATUS_FAILURE;
                                NdisFreeMemory(PacketData, 0, 0);
                                NdisFreePacket(MyPacket);
                                ADAPT_DECR_PENDING_SENDS(pAdapt);
                                break;
                            }
                            
                            th->checksum = ChecksumUpdate(ntohs(th->checksum), ntohs(th->sport), mapped);;
                            th->sport = htons(mapped);
                            
                            //DBGPRINT(("==> New source port: %d\n", mapped));
                            //DBGPRINT(("==> New checksum: %02x\n", th->checksum));
                        }
                        else if (ip6h->nexthdr == IP_UDP)
                        {
                            // udpv6 packet
                            PUDP_HEADER uh = (UDP_HEADER *)(PacketData + sizeof(ETH_HEADER) + sizeof(IP6_HEADER));
                            
                            DBGPRINT(("==> MPSendPackets: We send a UDPv6 packet.\n"));
                            
                            //DBGPRINT(("==> Old source port: %d\n", ntohs(uh->sport)));
                            //DBGPRINT(("==> Old checksum: %02x\n", uh->checksum));
                            
                            ret = GetUdpPortMapOut(ntohs(uh->sport), FALSE, &mapped);
                            
                            if (ret != TRUE)
                            {
                                DBGPRINT(("==> MPSendPackets: Find map failed. Drop.\n"));
                                Status = NDIS_STATUS_FAILURE;
                                NdisFreeMemory(PacketData, 0, 0);
                                NdisFreePacket(MyPacket);
                                ADAPT_DECR_PENDING_SENDS(pAdapt);
                                break;
                            }
                            
                            uh->checksum = ChecksumUpdate(ntohs(uh->checksum), ntohs(uh->sport), mapped);;
                            uh->sport = htons(mapped);
                            
                            //DBGPRINT(("==> New Source port: %d\n", mapped));
                            //DBGPRINT(("==> New checksum: %02x\n", uh->checksum));
                        }
                        else if (ip6h->nexthdr == IP_ICMP6)
                        {
                            // icmpv6 packet
                            PICMP6_HEADER icmp6h = (ICMP6_HEADER *)( PacketData + sizeof(ETH_HEADER) + sizeof(IP6_HEADER) );
                            
                            DBGPRINT(("==> MPSendPackets: We send an ICMPv6 packet.\n")); 
                            
                            if (icmp6h->type == ICMP6_ECHO || icmp6h->type == ICMP6_ECHO_REPLY) // Echo/Echo Reply Request
                            {
                                //DBGPRINT(("==> Old Id: %d\n", ntohs(icmp6h->id)));
                                //DBGPRINT(("==> Old checksum: %02x\n", icmp6h->checksum));
                                
                                ret = GetIcmpIdMapOut(ntohs(icmp6h->id), FALSE, &mapped);
                                
                                if (ret != TRUE)
                                {
                                    DBGPRINT(("==> MPSendPackets: Find map failed. Drop.\n"));
                                    Status = NDIS_STATUS_FAILURE;
                                    NdisFreeMemory(PacketData, 0, 0);
                                    NdisFreePacket(MyPacket);
                                    ADAPT_DECR_PENDING_SENDS(pAdapt);
                                    break;
                                }
                                
                                icmp6h->checksum = ChecksumUpdate(ntohs(icmp6h->checksum), ntohs(icmp6h->id), mapped);;
                                icmp6h->id = htons(mapped);
                                
                                //DBGPRINT(("==> New id: %d\n", mapped));
                                //DBGPRINT(("==> New checksum: %02x\n", icmp6h->checksum));
                            }
                        }
                    }
                }
                
                NdisAllocateBuffer(&Status, &MyBuffer, pAdapt->SendBufferPoolHandle, PacketData, PacketSendSize);
                if (Status != NDIS_STATUS_SUCCESS)
                {
                    DBGPRINT(("==> MPSendPackets: NdisAllocateBuffer failed.\n"));
                    Status = NDIS_STATUS_FAILURE;
                    NdisFreeMemory(PacketData, 0, 0);
                    NdisFreePacket(MyPacket);
                    ADAPT_DECR_PENDING_SENDS(pAdapt);
                    break;
                }
                
                //
                // Copy packet flags.
                //
                NdisGetPacketFlags(MyPacket) = NdisGetPacketFlags(Packet);

                //NDIS_PACKET_FIRST_NDIS_BUFFER(MyPacket) = NDIS_PACKET_FIRST_NDIS_BUFFER(Packet);
                //NDIS_PACKET_LAST_NDIS_BUFFER(MyPacket) = NDIS_PACKET_LAST_NDIS_BUFFER(Packet);
                
                NdisChainBufferAtFront(MyPacket, MyBuffer);
                MyPacket->Private.Head->Next = NULL;
                MyPacket->Private.Tail = NULL;
                
#ifdef WIN9X
                //
                // Work around the fact that NDIS does not initialize this
                // to FALSE on Win9x.
                //
                NDIS_PACKET_VALID_COUNTS(MyPacket) = FALSE;
#endif // WIN9X

                //
                // Copy the OOB data from the original packet to the new
                // packet.
                //
                NdisMoveMemory(NDIS_OOB_DATA_FROM_PACKET(MyPacket),
                            NDIS_OOB_DATA_FROM_PACKET(Packet),
                            sizeof(NDIS_PACKET_OOB_DATA));
                //
                // Copy relevant parts of the per packet info into the new packet
                //
#ifndef WIN9X
                NdisIMCopySendPerPacketInfo(MyPacket, Packet);
#endif

                //
                // Copy the Media specific information
                //
                NDIS_GET_PACKET_MEDIA_SPECIFIC_INFO(Packet,
                                                    &MediaSpecificInfo,
                                                    &MediaSpecificInfoSize);

                if (MediaSpecificInfo || MediaSpecificInfoSize)
                {
                    NDIS_SET_PACKET_MEDIA_SPECIFIC_INFO(MyPacket,
                                                        MediaSpecificInfo,
                                                        MediaSpecificInfoSize);
                }

                NdisSend(&Status,
                         pAdapt->BindingHandle,
                         MyPacket);

                if (Status != NDIS_STATUS_PENDING)
                {
#ifndef WIN9X
                    NdisIMCopySendCompletePerPacketInfo (Packet, MyPacket);
#endif
                    
                    NdisUnchainBufferAtFront(MyPacket, &MyBuffer);
                    while (MyBuffer != NULL)
                    {
                        NdisQueryBufferSafe(MyBuffer, &PacketData, &BufferLength, NormalPagePriority);
                        if (PacketData != NULL)
                        {
                            NdisFreeMemory(PacketData, BufferLength, 0);
                        }
                        TempBuffer = MyBuffer;
                        NdisGetNextBuffer(TempBuffer, &MyBuffer);
                        NdisFreeBuffer(TempBuffer);
                        //DBGPRINT(("==> MPSendPackets: PacketData and MyBuffer freed.\n"));
                    }
                    NdisFreePacket(MyPacket);
                    ADAPT_DECR_PENDING_SENDS(pAdapt);
                }
            }
            else
            {
                //
                // The driver cannot allocate a packet.
                // 
                ADAPT_DECR_PENDING_SENDS(pAdapt);
            }
        }
        while (FALSE);

        if (Status != NDIS_STATUS_PENDING)
        {
            NdisMSendComplete(ADAPT_MINIPORT_HANDLE(pAdapt),
                              Packet,
                              Status);
        }
        
        //DBGPRINT(("<== MPSendPackets: leaving.\n"));
    }
}
