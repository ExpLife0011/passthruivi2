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
    
    // copy packet defined
    PUCHAR            pPacketContent;
    PUCHAR            pTemp;
    PUCHAR            pNewPacketContent;
    UINT              BufferLength, PacketLength;
    UINT              ContentOffset = 0;
    PNDIS_BUFFER      TempBuffer, MyBuffer;

    // NAT defined
    ETH_HEADER      *eh;
    ARP_HEADER      *ah;
    IP_HEADER       *ih;
    IP6_HEADER      *ip6h;
    ICMP_HEADER     *icmph;
    ICMP6_HEADER    *icmp6h;
    TCP_HEADER      *th;
    UDP_HEADER      *uh;
    USHORT           mapped = 0;
    USHORT           tempMod, tempRes;
    BOOLEAN          ret;
    UINT             packet_size     = 0; // bytes need to be sent in the buffer
    INT              k;
    UCHAR            tempChar;
    LARGE_INTEGER    currentTime;
    INT              size;
    
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

                //
                //DBGPRINT(("==> MPSendPackets: No reuse.\n"));
                // Program usually falls here if we disable the reuse mechanism
                //
                
                SendRsvd = (PSEND_RSVD)(MyPacket->ProtocolReserved);
                SendRsvd->OriginalPkt = Packet;

                // Query first buffer and total packet length
                NdisGetFirstBufferFromPacketSafe(Packet, &MyBuffer, &pTemp, &BufferLength, &PacketLength, NormalPagePriority);
                if (pTemp == NULL)
                {
                    DBGPRINT(("==> MPSendPackets: NdisGetFirstBufferFromPacketSafe failed.\n"));
                    Status = NDIS_STATUS_FAILURE;
                    NdisFreePacket(MyPacket);
                    break;
                }
                
                // Check packet size
                if (PacketLength + IVI_PACKET_OVERHEAD > 1514)
                {
                    // 1514 = 1500 + ETH_HEADER length (14)
                    DBGPRINT(("==> MPSendPackets: Packet (eth frame) size %d too big.\n", PacketLength));
                    Status = NDIS_STATUS_FAILURE;
                    NdisFreePacket(MyPacket);
                    break;
                }
                
                // Allocate memory
                Status = NdisAllocateMemoryWithTag((PVOID)&pPacketContent, PacketLength, TAG);
                if (Status != NDIS_STATUS_SUCCESS)
                {
                    DBGPRINT(("==> MPSendPackets: NdisAllocateMemoryWithTag failed with pPacketContent.\n"));
                    Status = NDIS_STATUS_FAILURE;
                    NdisFreePacket(MyPacket);
                    break;
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
                //DBGPRINT(("==> MPSendPackets: Get packet content success.\n"));
                
                // Set packet_size
                packet_size = PacketLength;
                
                eh = (ETH_HEADER *)(pPacketContent);
                
                if (eh->type == htons(ETH_IP)) 
                {
                    if (enable_xlate)  /* xlate */
                    {
                        // ipv4 packet
                        //DBGPRINT(("==> MPSendPackets: We send an IPv4 packet.\n"));
                        ih = (IP_HEADER *)(pPacketContent + sizeof(ETH_HEADER));
                        
                        if (ih->protocol == IP_ICMP)
                        {
                            // ICMPv4 packet
                            DBGPRINT(("==> MPSendPackets: We send an ICMPv4 packet.\n"));
                            
                            icmph = (ICMP_HEADER *)(pPacketContent + sizeof(ETH_HEADER) + (ih->ver_ihl & 0x0f) * 4);
                            if (icmph->type == ICMP_ECHO || icmph->type == ICMP_ECHO_REPLY) // Echo/Echo Reply Request
                            {
                                Status = NdisAllocateMemoryWithTag((PVOID)&pNewPacketContent, PacketLength + IVI_PACKET_OVERHEAD, TAG);
                                if (Status != NDIS_STATUS_SUCCESS)
                                {
                                    DBGPRINT(("==> MPSendPackets: NdisAllocateMemoryWithTag failed with pNewPacketContent. Drop packet.\n"));
                                    Status = NDIS_STATUS_FAILURE;
                                    NdisFreeMemory(pPacketContent, 0, 0);
                                    NdisFreePacket(MyPacket);
                                    break;
                                }
                                
                                NdisZeroMemory(pNewPacketContent, PacketLength + IVI_PACKET_OVERHEAD);
                                
                                packet_size = icmp4to6(pPacketContent, pNewPacketContent);
                                if (packet_size == 0)
                                {
                                    DBGPRINT(("==> MPSendPackets: Translate failed with icmp4to6. Drop packet.\n"));
                                    Status = NDIS_STATUS_FAILURE;
                                    // Notice: we have two memory to free here!
                                    NdisFreeMemory(pPacketContent, 0, 0);
                                    NdisFreeMemory(pNewPacketContent, 0, 0);
                                    NdisFreePacket(MyPacket);
                                    break;
                                }
                                
                                // Switch pointers and free old packet memory
                                pTemp = pPacketContent;
                                pPacketContent = pNewPacketContent;
                                pNewPacketContent = pTemp;
                                NdisFreeMemory( pNewPacketContent, 0, 0 );
                                //DBGPRINT(("==> MPSendPackets: old packet memory freed.\n"));
                            }
                            else
                            {
                                DBGPRINT(("==> MPSendPackets: Unkown icmp type, drop packet.\n"));
                                Status = NDIS_STATUS_FAILURE;
                                NdisFreeMemory(pPacketContent, 0, 0);
                                NdisFreePacket(MyPacket);
                                break;
                            }
                        }
                        else if (ih->protocol == IP_TCP)
                        {
                            // TCPv4 packet
                            DBGPRINT(("==> MPSendPackets: We send a TCPv4 packet.\n"));
                            
                            th = (TCP_HEADER *)(pPacketContent + sizeof(ETH_HEADER) + (ih->ver_ihl & 0x0f) * 4);
                            
                            Status = NdisAllocateMemoryWithTag((PVOID)&pNewPacketContent, PacketLength + IVI_PACKET_OVERHEAD, TAG);
                            if (Status != NDIS_STATUS_SUCCESS)
                            {
                                DBGPRINT(("==> MPSendPackets: NdisAllocateMemory failed with pNewPacketContent. Drop packet.\n"));
                                Status = NDIS_STATUS_FAILURE;
                                NdisFreeMemory(pPacketContent, 0, 0);
                                NdisFreePacket(MyPacket);
                                break;
                            }
                            
                            NdisZeroMemory(pNewPacketContent, PacketLength + IVI_PACKET_OVERHEAD);
                            
                            packet_size = tcp4to6(pPacketContent, pNewPacketContent);
                            if (packet_size == 0)
                            {
                                DBGPRINT(("==> MPSendPackets: Translate failed with tcp4to6. Drop packet.\n"));
                                Status = NDIS_STATUS_FAILURE;
                                // Notice: we have two memory to free here!
                                NdisFreeMemory(pPacketContent, 0, 0);
                                NdisFreeMemory(pNewPacketContent, 0, 0);
                                NdisFreePacket(MyPacket);
                                break;
                            }
                            
                            // Switch pointers and free old packet memory
                            pTemp = pPacketContent;
                            pPacketContent = pNewPacketContent;
                            pNewPacketContent = pTemp;
                            NdisFreeMemory(pNewPacketContent, 0, 0);
                            //DBGPRINT(("==> MPSendPackets: old packet memory freed.\n"));
                            
                        }
                        else if (ih->protocol == IP_UDP)
                        {
                            // UDPv4 packet
                            DBGPRINT(("==> MPSendPackets: We send a UDPv4 packet.\n"));
                            
                            uh = (UDP_HEADER *)(pPacketContent + sizeof(ETH_HEADER) + (ih->ver_ihl & 0x0f) * 4);
                            
                            Status = NdisAllocateMemoryWithTag((PVOID)&pNewPacketContent, PacketLength + IVI_PACKET_OVERHEAD, TAG);
                            if (Status != NDIS_STATUS_SUCCESS)
                            {
                                DBGPRINT(("==> MPSendPackets: NdisAllocateMemory failed with pNewPacketContent. Drop packet.\n"));
                                Status = NDIS_STATUS_FAILURE;
                                NdisFreeMemory(pPacketContent, 0, 0);
                                NdisFreePacket(MyPacket);
                                break;
                            }
                            
                            NdisZeroMemory(pNewPacketContent, PacketLength + IVI_PACKET_OVERHEAD);
                            
                            packet_size = udp4to6(pPacketContent, pNewPacketContent);
                            if (packet_size == 0)
                            {
                                DBGPRINT(("==> MPSendPackets: Translate failed with udp4to6. Drop packet.\n"));
                                Status = NDIS_STATUS_FAILURE;
                                // Notice: we have two memory to free here!
                                NdisFreeMemory(pPacketContent, 0, 0);
                                NdisFreeMemory(pNewPacketContent, 0, 0);
                                NdisFreePacket(MyPacket);
                                break;
                            }
                            
                            // Switch pointers and free old packet memory
                            pTemp = pPacketContent;
                            pPacketContent = pNewPacketContent;
                            pNewPacketContent = pTemp;
                            NdisFreeMemory(pNewPacketContent, 0, 0);
                            //DBGPRINT(("==> MPSendPackets: old packet memory freed.\n"));
                        }
                        else
                        {
                            DBGPRINT(("==> MPSendPackets: Unkown protocol type. Drop packet.\n"));
                            Status = NDIS_STATUS_FAILURE;
                            NdisFreeMemory(pPacketContent, 0, 0);
                            NdisFreePacket(MyPacket);
                            break;
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
                    if (enable_xlate)  /* xlate enabled */
                    {
                        // arp packet
                        //DBGPRINT(("==> MPSendPackets: We send an ARP packet, intentinally drop. ivid will handle the request.\n"));
                        DBGPRINT(("==> MPSendPackets: We send an ARP packet.\n"));
                        ah = (ARP_HEADER *)(pPacketContent + sizeof(ETH_HEADER));
                        
                        DBGPRINT(("==> MPSendPackets: ARP Source MAC is %02x:%02x:%02x:%02x:%02x:%02x.\n", 
                                    eh->smac[0], eh->smac[1], eh->smac[2], 
                                    eh->smac[3], eh->smac[4], eh->smac[5]));
                        DBGPRINT(("==> MPSendPackets: ARP Destination MAC is %02x:%02x:%02x:%02x:%02x:%02x.\n", 
                                    eh->dmac[0], eh->dmac[1], eh->dmac[2], 
                                    eh->dmac[3], eh->dmac[4], eh->dmac[5]));
                        DBGPRINT(("==> MPSendPackets: ARP Source IP is %02x.%02x.%02x.%02x\n", 
                                    ah->sip[0], ah->sip[1], ah->sip[2], ah->sip[3]));
                        DBGPRINT(("==> MPSendPackets: ARP Destination IP is %02x.%02x.%02x.%02x\n", 
                                    ah->dip[0], ah->dip[1], ah->dip[2], ah->dip[3]));
                        
                        
                        Status = NDIS_STATUS_SUCCESS;
                        
                        NdisMSendComplete(ADAPT_MINIPORT_HANDLE(pAdapt),
                                          Packet,
                                          Status); 
                        
                        if (NdisEqualMemory(ah->sip, ah->dip, 4) == 1)
                        {
                            // Gratuitous ARP from local TCP/IP stack. Drop.
                            //DBGPRINT(("==> MPSendPackets: Gratuitous ARP request. Indicate send success and drop packet.\n"));
                            NdisFreeMemory(pPacketContent, 0, 0);
                            NdisFreePacket(MyPacket);
                            //DBGPRINT(("==> MPReturnPacket: MyPacket is freed!\n"));
                        }
                        else
                        {
                            // Build ARP reply.
                            for (k = 0; k < 6; k++)
                            {
                                eh->dmac[k] = eh->smac[k];
                                eh->smac[k] = gatewayMAC[k];
                            }
                            
                            for (k = 0; k < 6; k++)
                            {
                                ah->dmac[k] = ah->smac[k];
                                ah->smac[k] = gatewayMAC[k];
                            }
                            
                            for (k = 0; k < 4; k++)
                            {
                                tempChar = ah->sip[k];
                                ah->sip[k] = ah->dip[k];
                                ah->dip[k] = tempChar;
                            }
                            
                            ah->option = htons(ARP_REPLY);
                            
                            
                            // Indicate this packet.
                            NdisAllocateBuffer(&Status, &MyBuffer, pAdapt->SendBufferPoolHandle, pPacketContent, packet_size);
                            NdisChainBufferAtFront(MyPacket, MyBuffer);
                            
                            MyPacket->Private.Head->Next = NULL;
                            MyPacket->Private.Tail = NULL;
                            
                            // Set original packet is not necessary.
                            
                            NdisGetCurrentSystemTime(&currentTime);
                            NDIS_SET_PACKET_TIME_RECEIVED(MyPacket, currentTime.QuadPart);
                            NDIS_SET_PACKET_HEADER_SIZE(MyPacket, sizeof(ETH_HEADER));
                            
                            // Set packet flags is not necessary.
                            
                            NDIS_SET_PACKET_STATUS(MyPacket, NDIS_STATUS_RESOURCES);
                            
                            DBGPRINT(("==> MPSendPackets: Queue ARP reply packet with true flag.\n"));
                            PtQueueReceivedPacket(pAdapt, MyPacket, TRUE);
                            
                            DBGPRINT(("==> MPSendPackets: ARP reply is indicated.\n"));
                            
                            NdisUnchainBufferAtFront(MyPacket, &MyBuffer);
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
                                //DBGPRINT(("==> MPSendPackets: pPacketContent and MyBuffer are freed for ARP.\n"));
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
                    //DBGPRINT(("==> MPSendPackets: We send an IPv6 packet.\n"));
                    ip6h = (IP6_HEADER *)(pPacketContent + sizeof(ETH_HEADER));
                    
                    //DBGPRINT(("==> MPSendPackets: Packet (eth frame) size %d.\n", PacketLength));
                    
                    if (IsIviAddress(ip6h->saddr) == 1)
                    {
                        if (ip6h->nexthdr == IP_TCP)
                        {
                            // tcpv6 packet
                            DBGPRINT(("==> MPSendPackets: We send a TCPv6 packet.\n"));
                            
                            th = (TCP_HEADER *)(pPacketContent + sizeof(ETH_HEADER) + sizeof(IP6_HEADER));
                            
                            //DBGPRINT(("==> Old Source port: %d\n", ntohs(th->sport)));
                            //DBGPRINT(("==> Dest port: %d\n", ntohs(th->dport)));
                            size = ntohs(ip6h->payload);
                            mapped = GetTcpPortMapOut(th, size, FALSE);
                            
                            if (mapped == 0)
                            {
                                DBGPRINT(("==> MPSendPackets: Find map failed. Drop.\n"));
                                Status = NDIS_STATUS_FAILURE;
                                NdisFreeMemory(pPacketContent, 0, 0);
                                NdisFreePacket(MyPacket);
                                break;
                            }
                            
                            th->checksum = checksum_adjust(ntohs(th->checksum), ntohs(th->sport), mapped);;
                            th->sport = htons(mapped);
                            
                            //DBGPRINT(("==> New Source port: %d\n", mapped));
                            //DBGPRINT(("==> New checksum: %02x\n", th->checksum));
                        }
                        else if (ip6h->nexthdr == IP_UDP)
                        {
                            // udpv6 packet
                            DBGPRINT(("==> MPSendPackets: We send a UDPv6 packet.\n"));
                            
                            uh = (UDP_HEADER *)( pPacketContent + sizeof(ETH_HEADER) + sizeof(IP6_HEADER) );
                            
                            //DBGPRINT(("==> Old Source port: %d\n", ntohs(uh->sport)));
                            //DBGPRINT(("==> Dest port: %d\n", ntohs(uh->dport)));
                            
                            ret = GetUdpPortMapOut(ntohs(uh->sport), FALSE, &mapped);
                            
                            if (ret != TRUE)
                            {
                                DBGPRINT(("==> MPSendPackets: Find map failed. Drop.\n"));
                                Status = NDIS_STATUS_FAILURE;
                                NdisFreeMemory(pPacketContent, 0, 0);
                                NdisFreePacket(MyPacket);
                                break;
                            }
                            
                            uh->checksum = checksum_adjust(ntohs(uh->checksum), ntohs(uh->sport), mapped);;
                            uh->sport = htons(mapped);
                            
                            //DBGPRINT(("==> New Source port: %d\n", mapped));
                            //DBGPRINT(("==> New checksum: %02x\n", uh->checksum));
                        }
                        else if (ip6h->nexthdr == IP_ICMP6)
                        {
                            // icmpv6 packet
                            DBGPRINT(("==> MPSendPackets: We send an ICMPv6 packet.\n"));
                            
                            icmp6h = (ICMP6_HEADER *)( pPacketContent + sizeof(ETH_HEADER) + sizeof(IP6_HEADER) );
                            
                            if (icmp6h->type == ICMP6_ECHO || icmp6h->type == ICMP6_ECHO_REPLY) // Echo/Echo Reply Request
                            {
                                //DBGPRINT(("==> Old Id: %d\n", ntohs(icmp6h->id)));
                                
                                ret = GetIcmpIdMapOut(ntohs(icmp6h->id), FALSE, &mapped);
                                
                                if (ret != TRUE)
                                {
                                    DBGPRINT(("==> MPSendPackets: Find map failed. Drop.\n"));
                                    Status = NDIS_STATUS_FAILURE;
                                    NdisFreeMemory(pPacketContent, 0, 0);
                                    NdisFreePacket(MyPacket);
                                    break;
                                }
                                
                                icmp6h->checksum = checksum_adjust(ntohs(icmp6h->checksum), ntohs(icmp6h->id), mapped);;
                                icmp6h->id = htons(mapped);
                                
                                //DBGPRINT(("==> New id: %d\n", mapped));
                                //DBGPRINT(("==> New checksum: %02x\n", icmp6h->checksum));
                            }
                        }
                    }
                }
                
                //DBGPRINT(("==> MPSendPackets: packet_size: %d, j: %d\n", packet_size, j));
                NdisAllocateBuffer(&Status, &MyBuffer, pAdapt->SendBufferPoolHandle, pPacketContent, packet_size);
                NdisChainBufferAtFront(MyPacket, MyBuffer);
                
                //
                // Copy packet flags.
                //
                NdisGetPacketFlags(MyPacket) = NdisGetPacketFlags(Packet);

                //NDIS_PACKET_FIRST_NDIS_BUFFER(MyPacket) = NDIS_PACKET_FIRST_NDIS_BUFFER(Packet);
                //NDIS_PACKET_LAST_NDIS_BUFFER(MyPacket) = NDIS_PACKET_LAST_NDIS_BUFFER(Packet);
                //
                // changed for NAT
                //
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
                        NdisQueryBufferSafe(MyBuffer, &pPacketContent, &BufferLength, NormalPagePriority);
                        if (pPacketContent != NULL)
                        {
                            NdisFreeMemory(pPacketContent, BufferLength, 0);
                        }
                        TempBuffer = MyBuffer;
                        NdisGetNextBuffer(TempBuffer, &MyBuffer);
                        NdisFreeBuffer(TempBuffer);
                        DBGPRINT(("==> MPSendPackets: pPacketContent and MyBuffer freed.\n"));
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
        
        //DBGPRINT(("<== MPSendPackets: leave while loop.\n"));

        if (Status != NDIS_STATUS_PENDING)
        {
            NdisMSendComplete(ADAPT_MINIPORT_HANDLE(pAdapt),
                              Packet,
                              Status);
        }
        
        //DBGPRINT(("<== MPSendPackets: leaving MPSendPackets loop.\n"));
    }
}
