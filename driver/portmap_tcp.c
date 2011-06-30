#include "precomp.h"
#pragma hdrstop

// TCP timeouts
LARGE_INTEGER  TcpStateTimeOuts[TCP_STATUS_MAX] = {
        { 0 },        // TCP_STATUS_NONE
        { 2 MINS },   // TCP_STATUS_SYN_SENT
        { 60 SECS },  // TCP_STATUS_SYN_RECV
        { 5 DAYS },   // TCP_STATUS_ESTABLISHED
        { 2 MINS },   // TCP_STATUS_FIN_WAIT
        { 60 SECS },  // TCP_STATUS_CLOSE_WAIT
        { 30 SECS },  // TCP_STATUS_LAST_ACK
        { 2 MINS },   // TCP_STATUS_TIME_WAIT
        { 10 SECS },  // TCP_STATUS_CLOSE
        { 2 MINS }    // TCP_STATUS_SYN_SENT2
};

LARGE_INTEGER  TcpTimeOutMaxRetrans = { 5 MINS };
LARGE_INTEGER  TcpTimeOutUnack      = { 5 MINS };

#define TCP_MAX_RETRANS  3

// Short name for TCP_STATUS
#define sNO TCP_STATUS_NONE
#define sSS TCP_STATUS_SYN_SENT
#define sSR TCP_STATUS_SYN_RECV
#define sES TCP_STATUS_ESTABLISHED
#define sFW TCP_STATUS_FIN_WAIT
#define sCW TCP_STATUS_CLOSE_WAIT
#define sLA TCP_STATUS_LAST_ACK
#define sTW TCP_STATUS_TIME_WAIT
#define sCL TCP_STATUS_CLOSE
#define sS2 TCP_STATUS_SYN_SENT2
#define sIV TCP_STATUS_MAX
#define sIG TCP_STATUS_IGNORE

/*
 * The TCP state transition table needs a few words...
 *
 * We are the man in the middle. All the packets go through us
 * but might get lost in transit to the destination.
 * It is assumed that the destinations can't receive segments
 * we haven't seen.
 *
 * The checked segment is in window, but our windows are *not*
 * equivalent with the ones of the sender/receiver. We always
 * try to guess the state of the current sender.
 *
 * The meaning of the states are:
 *
 * NONE:         initial state
 * SYN_SENT:     SYN-only packet seen
 * SYN_SENT2:    SYN-only packet seen from reply dir, simultaneous open
 * SYN_RECV:     SYN-ACK packet seen
 * ESTABLISHED:  ACK packet seen
 * FIN_WAIT:     FIN packet seen
 * CLOSE_WAIT:   ACK seen (after FIN)
 * LAST_ACK:     FIN seen (after FIN)
 * TIME_WAIT:    last ACK seen
 * CLOSE:        closed connection (RST)
 *
 * Packets marked as IGNORED (sIG):
 *    if they may be either invalid or valid
 *    and the receiver may send back a connection
 *    closing RST or a SYN/ACK.
 *
 * Packets marked as INVALID (sIV):
 *    if we regard them as truly invalid packets
 */
TCP_STATUS StateTransitionTable[PACKET_DIR_MAX][6][TCP_STATUS_MAX] = {
    {
/* LOCAL */
/*        sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2    */
/*syn*/ { sSS, sSS, sIG, sIG, sIG, sIG, sIG, sSS, sSS, sS2 },
/*
 *    sNO -> sSS    Initialize a new connection
 *    sSS -> sSS    Retransmitted SYN
 *    sS2 -> sS2    Late retransmitted SYN
 *    sSR -> sIG
 *    sES -> sIG    Error: SYNs in window outside the SYN_SENT state
 *                  are errors. Receiver will reply with RST
 *                  and close the connection.
 *                  Or we are not in sync and hold a dead connection.
 *    sFW -> sIG
 *    sCW -> sIG
 *    sLA -> sIG
 *    sTW -> sSS    Reopened connection (RFC 1122).
 *    sCL -> sSS
 */
/*           sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2    */
/*synack*/ { sIV, sIV, sIG, sIG, sIG, sIG, sIG, sIG, sIG, sSR },
/*
 *    sNO -> sIV    Too late and no reason to do anything
 *    sSS -> sIV    Client can't send SYN and then SYN/ACK
 *    sS2 -> sSR    SYN/ACK sent to SYN2 in simultaneous open
 *    sSR -> sIG
 *    sES -> sIG    Error: SYNs in window outside the SYN_SENT state
 *                  are errors. Receiver will reply with RST
 *                  and close the connection.
 *                  Or we are not in sync and hold a dead connection.
 *    sFW -> sIG
 *    sCW -> sIG
 *    sLA -> sIG
 *    sTW -> sIG
 *    sCL -> sIG
 */
/*        sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2    */
/*fin*/ { sIV, sIV, sFW, sFW, sLA, sLA, sLA, sTW, sCL, sIV },
/*
 *    sNO -> sIV    Too late and no reason to do anything...
 *    sSS -> sIV    Client migth not send FIN in this state:
 *                  we enforce waiting for a SYN/ACK reply first.
 *    sS2 -> sIV
 *    sSR -> sFW    Close started.
 *    sES -> sFW
 *    sFW -> sLA    FIN seen in both directions, waiting for
 *                  the last ACK.
 *                  Migth be a retransmitted FIN as well...
 *    sCW -> sLA
 *    sLA -> sLA    Retransmitted FIN. Remain in the same state.
 *    sTW -> sTW
 *    sCL -> sCL
 */
/*        sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2    */
/*ack*/ { sES, sIV, sES, sES, sCW, sCW, sTW, sTW, sCL, sIV },
/*
 *    sNO -> sES    Assumed.
 *    sSS -> sIV    ACK is invalid: we haven't seen a SYN/ACK yet.
 *    sS2 -> sIV
 *    sSR -> sES    Established state is reached.
 *    sES -> sES    :-)
 *    sFW -> sCW    Normal close request answered by ACK.
 *    sCW -> sCW
 *    sLA -> sTW    Last ACK detected.
 *    sTW -> sTW    Retransmitted last ACK. Remain in the same state.
 *    sCL -> sCL
 */
/*         sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2    */
/*rst*/  { sIV, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL },
/*none*/ { sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV }
    },
    {
/* REMOTE */
/*        sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2    */
/*syn*/ { sIV, sS2, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sS2 },
/*
 *    sNO -> sIV    Never reached.
 *    sSS -> sS2    Simultaneous open
 *    sS2 -> sS2    Retransmitted simultaneous SYN
 *    sSR -> sIV    Invalid SYN packets sent by the server
 *    sES -> sIV
 *    sFW -> sIV
 *    sCW -> sIV
 *    sLA -> sIV
 *    sTW -> sIV    Reopened connection, but server may not do it.
 *    sCL -> sIV
 */
/*           sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2    */
/*synack*/ { sIV, sSR, sSR, sIG, sIG, sIG, sIG, sIG, sIG, sSR },
/*
 *    sSS -> sSR    Standard open.
 *    sS2 -> sSR    Simultaneous open
 *    sSR -> sSR    Retransmitted SYN/ACK.
 *    sES -> sIG    Late retransmitted SYN/ACK?
 *    sFW -> sIG    Might be SYN/ACK answering ignored SYN
 *    sCW -> sIG
 *    sLA -> sIG
 *    sTW -> sIG
 *    sCL -> sIG
 */
/*        sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2    */
/*fin*/ { sIV, sIV, sFW, sFW, sLA, sLA, sLA, sTW, sCL, sIV },
/*
 *    sSS -> sIV    Server might not send FIN in this state.
 *    sS2 -> sIV
 *    sSR -> sFW    Close started.
 *    sES -> sFW
 *    sFW -> sLA    FIN seen in both directions.
 *    sCW -> sLA
 *    sLA -> sLA    Retransmitted FIN.
 *    sTW -> sTW
 *    sCL -> sCL
 */
/*        sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2    */
/*ack*/ { sIV, sIG, sSR, sES, sCW, sCW, sTW, sTW, sCL, sIG },
/*
 *    sSS -> sIG    Might be a half-open connection.
 *    sS2 -> sIG
 *    sSR -> sSR    Might answer late resent SYN.
 *    sES -> sES    :-)
 *    sFW -> sCW    Normal close request answered by ACK.
 *    sCW -> sCW
 *    sLA -> sTW    Last ACK detected.
 *    sTW -> sTW    Retransmitted last ACK.
 *    sCL -> sCL
 */
/*         sNO, sSS, sSR, sES, sFW, sCW, sLA, sTW, sCL, sS2    */
/*rst*/  { sIV, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL, sCL },
/*none*/ { sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV, sIV }
    }
};

#define IS_FIN_SET(th) ((th->bits & TCP_BIT_FIN) == TCP_BIT_FIN)
#define IS_SYN_SET(th) ((th->bits & TCP_BIT_SYN) == TCP_BIT_SYN)
#define IS_RST_SET(th) ((th->bits & TCP_BIT_RST) == TCP_BIT_RST)
#define IS_PSH_SET(th) ((th->bits & TCP_BIT_PSH) == TCP_BIT_PSH)
#define IS_ACK_SET(th) ((th->bits & TCP_BIT_ACK) == TCP_BIT_ACK)
#define IS_URG_SET(th) ((th->bits & TCP_BIT_URG) == TCP_BIT_URG)

#define TCP_DATA_OFFSET(th) (((th->doff & 0xF0) >> 4) & 0x0F)

BOOLEAN
Before(
    ULONG   num1,
    ULONG   num2
    )
/*++

Routine Description:

    Compare two ULONG integer
    
Arguments:

    num1 - ULONG integer
    num2 - ULONG integer

Return Value:

    TRUE if num1 < num2; otherwise FALSE.

--*/
{
    return ((LONG)(num1 - num2) < 0);
}

BOOLEAN
After(
    ULONG   num1,
    ULONG   num2
    )
/*++

Routine Description:

    Compare two ULONG integer
    
Arguments:

    num1 - ULONG integer
    num2 - ULONG integer

Return Value:

    TRUE if num1 > num2; otherwise FALSE.

--*/
{
    return ((LONG)(num2 - num1) < 0);
}

INT
GetControlBitsIndex(
    PTCP_HEADER    th
    )
/*++

Routine Description:

    Convert TCP ccontrol bits into TCP_BIT_SET enum.
    Value of TCP_BIT_SET corresponds to 2nd dimention of TCP state transition table.
    
Arguments:

    th - Pointer to the TCP header, should not be NULL

Return Value:

    Integer converted from TCP_BIT_SET enum value.

--*/
{
    if (IS_RST_SET(th))
    {
        return TCP_RST_SET;
    }
    else if (IS_SYN_SET(th))
    {
        return ((IS_ACK_SET(th)) ? TCP_SYNACK_SET : TCP_SYN_SET);
    }
    else if (IS_FIN_SET(th))
    {
        return TCP_FIN_SET;
    }
    else if (IS_ACK_SET(th))
    {
        return TCP_ACK_SET;
    }
    else
    {
        return TCP_NONE_SET;
    }
}


/*  TCP connection tracking based on 'Real Stateful TCP Packet Filtering
    in IP Filter' by Guido van Rooij.

    http://www.sane.nl/events/sane2000/papers.html
    http://www.darkart.com/mirrors/www.obfuscation.org/ipf/

    The boundaries and the conditions are changed according to RFC793:
    the packet must intersect the window (i.e. segments may be
    after the right or before the left edge) and thus receivers may ACK
    segments after the right edge of the window.

    MaxEnd    = max(sack + max(win,1)) seen in reply packets
    MaxWindow = max(max(win, 1)) + (sack - ack) seen in sent packets
    MaxWindow += seq + len - sender.MaxEnd
            if seq + len > sender.MaxEnd
    End       = max(seq + len) seen in sent packets

    I.   Upper bound for valid data:     seq <= sender.MaxEnd
    II.  Lower bound for valid data:     seq + len >= sender.End - receiver.MaxWindow
    III. Upper bound for valid (s)ack:   sack <= receiver.End
    IV.  Lower bound for valid (s)ack:   sack >= receiver.End - MAXACKWINDOW

    where sack is the highest right edge of sack block found in the packet
    or ack in the case of packet without SACK option.

    The upper bound limit for a valid (s)ack is not ignored -
    we doesn't have to deal with fragments.
*/

ULONG SegmentSeqPlusLen(
    IN ULONG           seq,
    IN ULONG           len,
    IN PTCP_HEADER     th
    )
/*++

Routine Description:

    Compute end seq number for current segment.
    Used to fill TCP_STATE_INFO.End field.
    SYN and FIN bits also take up one byte in sequence numbering.

Arguments:

    seq - Seq number of this TCP segment
    len - Data length of this TCP segment, including TCP header
    th - Pointer to TCP header of this segment, should not be NULL

Return Value:

    End seq number of current segment.

--*/
{
    return (seq + len - TCP_DATA_OFFSET(th) * 4 + (IS_SYN_SET(th) ? 1 : 0) + (IS_FIN_SET(th) ? 1 : 0));
}


#define MAXACKWINCONST         66000
#define MAXACKWINDOW(sender) ((sender)->MaxWindow > MAXACKWINCONST ? (sender)->MaxWindow : MAXACKWINCONST)


VOID 
ParseTcpOptions(
    IN PTCP_HEADER      th,
    IN PTCP_STATE_INFO  StateInfo
    )
/*++

Routine Description:

    Parse TCP header options.
    We are interested in window scale option and SACK option.

Arguments:

    th - Pointer to TCP header of this segment, should not be NULL
    StateInfo - Pointer to TCP state info structure that stores the state

Return Value:

    None.

--*/
{
    PUCHAR ptr;
    INT optlen = ((TCP_DATA_OFFSET(th)) * 4) - sizeof(TCP_HEADER);

    if (optlen == 0)
    {
        return;
    }

    ptr = (PUCHAR)(th) + sizeof(TCP_HEADER);

    StateInfo->Scale = 0;
    StateInfo->Options = 0;

    while (optlen > 0)
    {
        UCHAR optcode = *ptr++;
        UCHAR optsize;

        switch (optcode)
        {
            case TCP_OPT_EOL:
                // End of options
                return;
            
            case TCP_OPT_NOP:
                // Zero padding
                optlen--;
                continue;
            
            default:
                optsize = *ptr++;
                
                if (optsize < 2)
                {
                    // "silly options"
                    return;
                }
                if (optsize > optlen)
                {
                    break;  // don't parse partial options
                }
                
                if (optcode == TCP_OPT_SACK_PERM && optsize == TCP_OPTLEN_SACK_PERM)
                {
                    StateInfo->Options |= STATE_OPTION_SACK_PERM;
                }
                else if (optcode == TCP_OPT_WINDOW_SCALE && optsize == TCP_OPTLEN_WINDOW_SCALE)
                {
                    StateInfo->Scale = *ptr;

                    if (StateInfo->Scale > 14)
                    {
                        // See RFC1323
                        StateInfo->Scale = 14;
                    }
                    StateInfo->Options |= STATE_OPTION_WINDOW_SCALE;
                }
                ptr += optsize - 2;
                optlen -= optsize;
                break;
        }
    }
}


VOID
ParseSackOption(
    IN  PTCP_HEADER      th,
    OUT PULONG           sack
    )
/*++

Routine Description:

    Parse SACK option.

Arguments:

    th - Pointer to TCP header of this segment, should not be NULL
    sack - Pointer to caller-supplied storage for max sack in this segment,
           this value is assumed to be initialized first by caller.

Return Value:

    None.

--*/
{
    PUCHAR ptr;
    INT optlen = ((TCP_DATA_OFFSET(th)) * 4) - sizeof(TCP_HEADER);
    ULONG tmp;

    if (optlen == 0)
    {
        return;
    }

    ptr = (PUCHAR)(th) + sizeof(TCP_HEADER);

    while (optlen > 0)
    {
        UCHAR optcode = *ptr++;
        UCHAR optsize, i;

        switch (optcode)
        {
            case TCP_OPT_EOL:
                // End of options
                return;
            
            case TCP_OPT_NOP:
                // Zero padding
                optlen--;
                continue;
            
            default:
                optsize = *ptr++;
                
                if (optsize < 2)
                {
                    // "silly options"
                    return;
                }
                if (optsize > optlen)
                {
                    break;  // don't parse partial options
                }

                if (optcode == TCP_OPT_SACK 
                    && optsize >= (TCP_OPTLEN_SACK_BASE + TCP_OPTLEN_SACK_PERBLOCK)
                    && (((optsize - TCP_OPTLEN_SACK_BASE) % TCP_OPTLEN_SACK_PERBLOCK) == 0)
                    )
                {
                    for (i = 0; i < (optsize - TCP_OPTLEN_SACK_BASE); i += TCP_OPTLEN_SACK_PERBLOCK)
                    {
                        // Read the right edge of the SACK block, see RFC2018
                        RtlRetrieveUlong(&tmp, (PULONG)(ptr + i + 4));
                        if (tmp > *sack)
                        {
                            *sack = tmp;
                        }
                    }
                    return;
                }
                ptr += optsize - 2;
                optlen -= optsize;
                break;
        }
    }
}


BOOLEAN
SegmentInWindow(
    IN PTCP_HEADER          th,
    IN ULONG                len,
    IN PACKET_DIR           dir,
    IN PTCP_STATE_CONTEXT   StateContext
    )
/*++

Routine Description:

    Check if the current TCP segment is in window.

Arguments:

    th - Pointer to TCP header of this segment, should not be NULL
    len - Data length of this segment, including TCP header
    dir - Either PACKET_DIR_LOCAL or PACKET_DIR_REMOTE to indicate packet flow direction
    StateContext - Pointer to the TCP state context for this connetion, should not be NULL

Return Value:

    TRUE if the segment is in window; otherwise return FALSE.

--*/
{
    PTCP_STATE_INFO sender = &(StateContext->Seen[dir]);
    PTCP_STATE_INFO receiver = &(StateContext->Seen[!dir]);
    ULONG seq, ack, sack, end, win, swin;
    BOOLEAN res;
    
    // Get the required data from header
    seq = ntohl(th->seq);
    ack = sack = ntohl(th->ack);
    win = ntohs(th->window);
    end = SegmentSeqPlusLen(seq, len, th);
    
    if (receiver->Options & STATE_OPTION_SACK_PERM)
    {
        // Receiver allows SACK option from sender
        ParseSackOption(th, &sack);
    }
    
    /*
    DBGPRINT(("==> SegmentInWindow: seq = %u, ack = %u, sack = %u, win = %u, end = %u\n", seq, ack, sack, win, end));
    DBGPRINT(("==> SegmentInWindow: sender end=%u maxend=%u maxwin=%u scale=%u", 
              sender->End, sender->MaxEnd, sender->MaxWindow, sender->Scale));
    DBGPRINT(("==> SegmentInWindow: receiver end=%u maxend=%u maxwin=%u scale=%u\n", 
              receiver->End, receiver->MaxEnd, receiver->MaxWindow, receiver->Scale));
    */
    
    if (sender->MaxWindow == 0)
    {
        // Initialize sender data
        if (IS_SYN_SET(th))
        {
            // SYN-ACK reply to a SYN or SYN from receiver in simultaneous open
            // We set receiver->MaxWin to 0 in CreateTcpStateContext().
            sender->End = sender->MaxEnd = end;
            sender->MaxWindow = ((win == 0) ? 1 : win);
            // Read TCP options on SYN packet.
            ParseTcpOptions(th, sender);
            
            /*
             * RFC 1323:
             * Both sides must send the Window Scale option
             * to enable window scaling in either direction.
             */
            if (!(sender->Options & STATE_OPTION_WINDOW_SCALE && receiver->Options & STATE_OPTION_WINDOW_SCALE))
            {
                // At least one side does not support window scale.
                sender->Scale = receiver->Scale = 0;
            }
        }
    }
    else if (((StateContext->Status == TCP_STATUS_SYN_SENT && dir == PACKET_DIR_LOCAL)
              || (StateContext->Status == TCP_STATUS_SYN_RECV && dir == PACKET_DIR_REMOTE))
              && After(end, sender->End))
    {
        /*
         * RFC 793: "if a TCP is reinitialized ... then it need
         * not wait at all; it must only be sure to use sequence
         * numbers larger than those recently used."
         */
        sender->End = sender->MaxEnd = end;
        sender->MaxWindow = ((win == 0) ? 1 : win);
        // Read TCP options on SYN packet.
        ParseTcpOptions(th, sender);
    }
    
    if (!IS_ACK_SET(th))
    {
        // If there is no ACK, just pretend it was set and OK.
        ack = sack = receiver->End;
    }
    else if (((th->bits & (TCP_BIT_RST|TCP_BIT_ACK)) == (TCP_BIT_RST|TCP_BIT_ACK)) && (ack == 0))
    {
        // Broken TCP stacks, that set ACK in RST packets as well with zero ack value.
        ack = sack = receiver->End;
    }
    
    if (seq == end 
        && (!IS_RST_SET(th) 
        || (seq == 0 && StateContext->Status == TCP_STATUS_SYN_SENT)))
    {
        /*
         * Packets contains no data: we assume it is valid
         * and check the ack value only.
         * However RST segments are always validated by their
         * SEQ number, except when seq == 0 (reset sent answering
         * SYN.
         */
        seq = end = sender->End;
    }
    
    /*
    DBGPRINT(("==> SegmentInWindow: seq = %u, ack = %u, sack = %u, win = %u, end = %u\n", seq, ack, sack, win, end));
    DBGPRINT(("==> SegmentInWindow: sender end=%u maxend=%u maxwin=%u scale=%u", 
              sender->End, sender->MaxEnd, sender->MaxWindow, sender->Scale));
    DBGPRINT(("==> SegmentInWindow: receiver end=%u maxend=%u maxwin=%u scale=%u\n", 
              receiver->End, receiver->MaxEnd, receiver->MaxWindow, receiver->Scale));
    
    DBGPRINT(("==> SegmentInWindow: I=%d II=%d III=%d IV=%d\n",
              Before(seq, sender->MaxEnd + 1),
              After(end, sender->End - receiver->MaxWindow - 1),
              Before(sack, receiver->End + 1),
              After(sack, receiver->End - MAXACKWINDOW(sender) - 1)));
    */
    
    if (Before(seq, sender->MaxEnd + 1) &&
        After(end, sender->End - receiver->MaxWindow - 1) &&
        Before(sack, receiver->End + 1) &&
        After(sack, receiver->End - MAXACKWINDOW(sender) - 1))
    {
        /*
         * Take into account window scaling (RFC 1323).
         */
        if (!IS_SYN_SET(th))
            win <<= sender->Scale;

        /*
         * Update sender data.
         */
        swin = win + (sack - ack);
        if (sender->MaxWindow < swin)
        {
            sender->MaxWindow = swin;
        }
        if (After(end, sender->End))
        {
            sender->End = end;
            sender->Options |= STATE_OPTION_DATA_UNACK;
        }
        if (IS_ACK_SET(th))
        {
            if (!(sender->Options & STATE_OPTION_MAXACK_SET))
            {
                sender->MaxAck = ack;
                sender->Options |= STATE_OPTION_MAXACK_SET;
            }
            else if (After(ack, sender->MaxAck))
            {
                sender->MaxAck = ack;
            }
        }

        /*
         * Update receiver data.
         */
        if (receiver->MaxWindow != 0 && After(end, sender->MaxEnd))
        {
            receiver->MaxWindow += end - sender->MaxEnd;
        }
        if (After(sack + win, receiver->MaxEnd - 1))
        {
            receiver->MaxEnd = sack + win;
            if (win == 0)
            {
                receiver->MaxEnd++;
            }
        }
        if (ack == receiver->End)
        {
            receiver->Options &= ~STATE_OPTION_MAXACK_SET;
        }

        /*
         * Check retransmissions.
         */
        if (GetControlBitsIndex(th) == TCP_ACK_SET)
        {
            if (StateContext->LastDir == dir
                && StateContext->LastSeq == seq
                && StateContext->LastAck == ack
                && StateContext->LastEnd == end
                && StateContext->LastWindow == win)
            {
                StateContext->RetransCount++;
            }
            else
            {
                StateContext->LastDir = dir;
                StateContext->LastSeq = seq;
                StateContext->LastAck = ack;
                StateContext->LastEnd = end;
                StateContext->LastWindow = win;
                StateContext->RetransCount = 0;
            }
        }
        res = TRUE;
    }
    else
    {
        res = FALSE;
    }
    
    /*
    DBGPRINT(("==> SegmentInWindow: sender end=%u maxend=%u maxwin=%u scale=%u", 
              sender->End, sender->MaxEnd, sender->MaxWindow, sender->Scale));
    DBGPRINT(("==> SegmentInWindow: receiver end=%u maxend=%u maxwin=%u scale=%u\n", 
              receiver->End, receiver->MaxEnd, receiver->MaxWindow, receiver->Scale));
    */
    
    return res;
}


FILTER_STATUS
CreateTcpStateContext(
    IN PTCP_HEADER          th,
    IN ULONG                len,
    IN PTCP_STATE_CONTEXT   StateContext
    )
/*++

Routine Description:

    Create TCP state context for a new connection.
    This function is called when local machine opens a 
    new TCP port and sends a SYN packet. Caller must 
    chain the state context structure to state list by
    themselves if this function returns TRUE.

Arguments:

    th - Pointer to TCP header of this segment, should not be NULL
    len - Data length of this segment, including TCP header
    StateContext - Caller-provided non-paged memory to hold the state info, should not be NULL

Return Value:

    FILTER_ACCEPT if the new state context is created successfully; 
    otherwise return FILTER_DROP_CLEAN, indicating caller to release this 
    state context and drop the current segment.

--*/
{
    PTCP_STATE_INFO sender = &(StateContext->Seen[0]);   // Sender is always local
    PTCP_STATE_INFO receiver = &(StateContext->Seen[1]); // Receiver is always remote
    INT index = GetControlBitsIndex(th);
    ULONG seq = ntohl(th->seq);
    
    TCP_STATUS NewStatus = StateTransitionTable[0][index][TCP_STATUS_NONE];  // We always start from NONE state
    
    if (NewStatus != TCP_STATUS_SYN_SENT)
    {
        // Invalid packet or we are in middle of a connection, which is not supported now
        DBGPRINT(("==> CreateTcpStateContext: invalid new packet causing state change to %d, drop.\n", NewStatus));
        return FILTER_DROP_CLEAN;
    }
    
    // SYN packet from local
    sender->End = SegmentSeqPlusLen(seq, len, th);
    sender->MaxEnd = sender->End;
    sender->MaxWindow = ntohs(th->window);
    if (sender->MaxWindow == 0)
    {
        // Window probing
        sender->MaxWindow = 1;
    }
    // Read window scale and SACK permit options in SYN packet
    ParseTcpOptions(th, sender);
    
    receiver->Options = 0;
    receiver->End = 0;
    receiver->MaxEnd = 0;
    receiver->MaxWindow = 0;
    receiver->Scale = 0;
    
    StateContext->Status = TCP_STATUS_SYN_SENT;
    NdisGetCurrentSystemTime(&(StateContext->StateSetTime));
    StateContext->StateTimeOut = TcpStateTimeOuts[TCP_STATUS_SYN_SENT];
    StateContext->LastDir = PACKET_DIR_LOCAL;
    StateContext->RetransCount = 0;
    StateContext->LastControlBits = (UCHAR)index;
    StateContext->LastWindow = sender->MaxWindow;
    StateContext->LastSeq = seq;
    StateContext->LastAck = 0;
    StateContext->LastEnd = sender->End;
    
    return FILTER_ACCEPT;
}


FILTER_STATUS
UpdateTcpStateContext(
    IN PTCP_HEADER          th,
    IN ULONG                len,
    IN PACKET_DIR           dir,
    IN PTCP_STATE_CONTEXT   StateContext
    )
/*++

Routine Description:

    Update TCP state based on newly received packet.

Arguments:

    th - Pointer to TCP header of this segment, should not be NULL
    len - Data length of this segment, including TCP header length
    dir - Either PACKET_DIR_LOCAL or PACKET_DIR_REMOTE to indicate packet flow direction
    StateContext - Caller-provided non-paged memory to hold the state info, should not be NULL

Return Value:

    FILTER_ACCEPT if the state context is still valid after this update;
    FILTER_DROP if the packet is invalid but the state is still valid, 
        indicating caller to drop the packet only;
    FILTER_DROP_CLEAN if the packet is invalid and the state is stale, 
        indicating caller to drop the packet and release the state context.

--*/
{
    PTCP_STATE_INFO sender = &(StateContext->Seen[dir]);
    PTCP_STATE_INFO receiver = &(StateContext->Seen[!dir]);
    TCP_STATUS  OldStatus = StateContext->Status;
    INT index = GetControlBitsIndex(th);
    TCP_STATUS  NewStatus = StateTransitionTable[dir][index][OldStatus];
    
    switch (NewStatus)
    {
        case TCP_STATUS_SYN_SENT:
            if (OldStatus < TCP_STATUS_TIME_WAIT)
            {
                // Retransmitted SYN
                break;
            }
            else  // Reopened connection from TIME_WAIT or CLOSE state
            {
                /* RFC 1122: "When a connection is closed actively,
                 * it MUST linger in TIME-WAIT state for a time 2xMSL
                 * (Maximum Segment Lifetime). However, it MAY accept
                 * a new SYN from the remote TCP to reopen the connection
                 * directly from TIME-WAIT state, if..."
                 * We ignore the conditions because we are in the
                 * TIME-WAIT state anyway.
                 *
                 * Handle aborted connections: we and the server
                 * think there is an existing connection but the client
                 * aborts it and starts a new one.
                 */
                if (((sender->Options | receiver->Options) & STATE_OPTION_CLOSE_INIT)
                      || (StateContext->LastDir == dir && StateContext->LastControlBits == TCP_RST_SET))
                {
                    /* Attempt to reopen a closed/aborted connection. */
                    NdisZeroMemory(StateContext, sizeof(TCP_STATE_CONTEXT));
                    return CreateTcpStateContext(th, len, StateContext);
                }
            }
            /* Fall through */
        case TCP_STATUS_IGNORE:
            // Ignored packets, just record them in LastXXX fields and do not update state machine.
            //XXX: We do not support connection pick-up at present.
            StateContext->LastDir = dir;
            StateContext->RetransCount = 0;   // Ignored packet is surely not a retransmitted packet.
            StateContext->LastControlBits = (UCHAR)index;
            StateContext->LastWindow = ntohs(th->window);
            StateContext->LastSeq = ntohl(th->seq);
            StateContext->LastAck = ntohl(th->ack);
            StateContext->LastEnd = SegmentSeqPlusLen(StateContext->LastSeq, len, th);
            DBGPRINT(("==> UpdateTcpStateContext: ignore packet on map %d -> %d, state %d.\n", 
                      StateContext->OriginalPort, StateContext->MappedPort, OldStatus));
            return FILTER_ACCEPT;
        
        case TCP_STATUS_MAX:
            // Invalid state, should be released.
            DBGPRINT(("==> UpdateTcpStateContext: invalid packet on map %d -> %d, state %d, drop packet and clear state.\n", 
                      StateContext->OriginalPort, StateContext->MappedPort, OldStatus));
            return FILTER_DROP_CLEAN;
        
        case TCP_STATUS_CLOSE:
            // This happens when we are already in CLOSE or received a RST.
            if (index == TCP_RST_SET && (receiver->Options & STATE_OPTION_MAXACK_SET) 
                && Before(ntohl(th->seq), receiver->MaxAck))
            {
                // Invalid RST
                DBGPRINT(("==> UpdateTcpStateContext: invalid RST packet on map %d -> %d, state %d, drop packet.\n", 
                          StateContext->OriginalPort, StateContext->MappedPort, OldStatus));
                return FILTER_DROP;
            }
            break;
            
        default:
            break;
    }
    
    if (SegmentInWindow(th, len, dir, StateContext) == FALSE)
    {
        // Segment is outside the window.
        return FILTER_DROP;
    }
    
    // From now on we have got in-window packets.
    StateContext->LastControlBits = (UCHAR)index;
    StateContext->LastDir = dir;
    
    DBGPRINT(("==> UpdateTcpStateContext: syn=%d ack=%d fin=%d rst=%d old_state=%d new_state=%d.\n",
              IS_SYN_SET(th), IS_ACK_SET(th), IS_FIN_SET(th), IS_RST_SET(th), OldStatus, NewStatus));
    
    StateContext->Status = NewStatus;
    if (OldStatus != NewStatus && NewStatus == TCP_STATUS_FIN_WAIT)
    {
        sender->Options |= STATE_OPTION_CLOSE_INIT;
    }
    
    // Update State Timer.
    if (StateContext->RetransCount >= TCP_MAX_RETRANS && StateContext->StateTimeOut.QuadPart > TcpTimeOutMaxRetrans.QuadPart)
    {
        StateContext->StateTimeOut = TcpTimeOutMaxRetrans;
    }
    else if (((sender->Options | receiver->Options) & STATE_OPTION_DATA_UNACK) 
              && StateContext->StateTimeOut.QuadPart > TcpTimeOutUnack.QuadPart)
    {
        StateContext->StateTimeOut = TcpTimeOutUnack;
    }
    else
    {
        StateContext->StateTimeOut = TcpStateTimeOuts[NewStatus];
    }
    
    // Update state set time if state has changed.
    if (NewStatus != OldStatus)
    {
        //XXX: Should we also refresh timer for unchanged state?
        NdisGetCurrentSystemTime(&(StateContext->StateSetTime));
    }
    
    return FILTER_ACCEPT;
}


/* TCP state list data structures */
LIST_ENTRY      StateListHead;          // TCP state list head, used in refresh timer operation
LONG            StateListLength = 0;    // Number of TCP state list entries
USHORT          LastAllocatedPort = 0;  // Remember last allocated port so that we can start from it for the next new port map
NDIS_SPIN_LOCK  StateListLock;          // Spin lock associated with state list

// Large hash table for TCP port mapping
TCP_PORT_MAP    TcpPortMapOutTable[65536];   // Hash table for TCP port from original port to mapping port
TCP_PORT_MAP    TcpPortMapInTable[65536];    // Hash table for TCP port from mapping port to original port


VOID
InitTcpLists(
    VOID
    )
/*++

Routine Description:

    Initialize TCP state related lists.
    This function is NOT thread-safe and should only be called in DriverEntry function 
    before Protocol and Miniport handlers are registered to NDIS.
    
--*/
{
    InitializeListHead(&StateListHead);
    StateListLength = 0;
    NdisZeroMemory(TcpPortMapOutTable, 65536 * sizeof(TCP_PORT_MAP));
    NdisZeroMemory(TcpPortMapInTable, 65536 * sizeof(TCP_PORT_MAP));
}


VOID
ResetTcpListsSafe(
    VOID
    )
/*++

Routine Description:

    Clear TCP state list entries and reset hash tables.
    This function is thread-safe. Do NOT acquire state
    list spin lock around this function.
    
--*/
{
    PLIST_ENTRY p, temp;
    
    NdisAcquireSpinLock(&StateListLock);
    
    if (IsListEmpty(&StateListHead))
    {
        // State list is empty, nothing to be done.
        NdisReleaseSpinLock(&StateListLock);
        return;
    }
    
    p = StateListHead.Flink;
    while (p != &StateListHead)
    {
        PTCP_STATE_CONTEXT pState = CONTAINING_RECORD(p, TCP_STATE_CONTEXT, ListEntry);
        
        // Release TCP state info and reset corresponding hash table entry
        DBGPRINT(("==> ResetTcpListsSafe: Port map %d -> %d removed on status %d.\n", 
                  pState->OriginalPort, pState->MappedPort, pState->Status));
        // Protect the loop from break
        temp = p;
        p = p->Flink;
        // Clear hash table pointer
        TcpPortMapOutTable[pState->OriginalPort].State = NULL;
        TcpPortMapInTable[pState->MappedPort].State = NULL;
        // Remove entry and memory
        RemoveEntryList(temp);
        StateListLength--;
        NdisFreeMemory(pState, 0, 0);
        //DBGPRINT(("==> ResetTcpListsSafe: TCP state context memory freed.\n"));
        // Go to next entry
    }
    
    if (StateListLength != 0)
    {
        // This should not happen
        StateListLength = 0;
    }
    
    NdisReleaseSpinLock(&StateListLock);
}


VOID
ResetTcpLists(
    VOID
    )
/*++

Routine Description:

    Clear TCP state list entries and reset hash tables.
    This function is NOT thread-safe and should only be called in driver unload function 
    after the handlers are unregistered from NDIS.
    
--*/
{
    PLIST_ENTRY p, temp;
    
    if (IsListEmpty(&StateListHead))
    {
        // State list is empty, nothing to be done.
        return;
    }
    
    p = StateListHead.Flink;
    while (p != &StateListHead)
    {
        PTCP_STATE_CONTEXT pState = CONTAINING_RECORD(p, TCP_STATE_CONTEXT, ListEntry);
        
        // Release TCP state info and reset corresponding hash table entry
        DBGPRINT(("==> ResetTcpLists: Port map %d -> %d removed on status %d.\n", 
                  pState->OriginalPort, pState->MappedPort, pState->Status));
        // Protect the loop from break
        temp = p;
        p = p->Flink;
        // Clear hash table pointer
        TcpPortMapOutTable[pState->OriginalPort].State = NULL;
        TcpPortMapInTable[pState->MappedPort].State = NULL;
        // Remove entry and memory
        RemoveEntryList(temp);
        StateListLength--;
        NdisFreeMemory(pState, 0, 0);
        //DBGPRINT(("==> ResetTcpLists: TCP state context memory freed.\n"));
        // Go to next entry
    }
    
    if (StateListLength != 0)
    {
        // This should not happen
        StateListLength = 0;
    }
}


VOID
RefreshTcpListEntrySafe(
    VOID
    )
/*++

Routine Description:

    Remove stale state info from TCP state list entries.
    This function is thread-safe. Do NOT acquire state list 
    spin lock around this function.

--*/
{
    LARGE_INTEGER now;
    PLIST_ENTRY p, temp;
    
    NdisAcquireSpinLock(&StateListLock);
    
    if (IsListEmpty(&StateListHead))
    {
        // State list is empty, nothing to be done.
        NdisReleaseSpinLock(&StateListLock);
        return;
    }
    
    NdisGetCurrentSystemTime(&now);
    p = StateListHead.Flink;
    while (p != &StateListHead)
    {
        PTCP_STATE_CONTEXT pState = CONTAINING_RECORD(p, TCP_STATE_CONTEXT, ListEntry);
        
        if (IsTimeOut(&now, &(pState->StateSetTime), &(pState->StateTimeOut)))
        {
            // Time out. Release TCP state info and reset corresponding hash table entry
            DBGPRINT(("==> RefreshTcpListEntrySafe: Port map %d -> %d time out on status %d. Delete.\n", 
                      pState->OriginalPort, pState->MappedPort, pState->Status));
            // Protect the loop from break
            temp = p;
            p = p->Flink;
            // Clear hash table pointer
            TcpPortMapOutTable[pState->OriginalPort].State = NULL;
            TcpPortMapInTable[pState->MappedPort].State = NULL;
            // Remove entry and clear memory
            RemoveEntryList(temp);
            StateListLength--;
            NdisFreeMemory(pState, 0, 0);
            //DBGPRINT(("==> RefreshTcpListEntrySafe: TCP state context memory freed.\n"));
            // Go to next entry
        }
        else
        {
            // Go to next entry
            // State set time is refreshed by state machine when parsing TCP segments, no need to refresh it here
            p = p->Flink;
        }
    }
    NdisReleaseSpinLock(&StateListLock);
}


VOID
RefreshTcpListEntry(
    VOID
    )
/*++

Routine Description:

    Remove stale state info from TCP state list entries.
    This function is NOT thread-safe. Caller must acquire 
    state list spin lock around this function to protect 
    data syncronization.

--*/
{
    LARGE_INTEGER now;
    PLIST_ENTRY p, temp;
    
    if (IsListEmpty(&StateListHead))
    {
        // State list is empty, nothing to be done.
        return;
    }
    
    NdisGetCurrentSystemTime(&now);
    p = StateListHead.Flink;
    while (p != &StateListHead)
    {
        PTCP_STATE_CONTEXT pState = CONTAINING_RECORD(p, TCP_STATE_CONTEXT, ListEntry);
        
        //DBGPRINT(("==> RefreshTcpListEntry: now: %u, %u\n", now.LowPart, now.HighPart));
        //DBGPRINT(("==> RefreshTcpListEntry: set time: %u, %u\n", pState->StateSetTime.LowPart, pState->StateSetTime.HighPart));
        //DBGPRINT(("==> RefreshTcpListEntry: timeout: %u, %u\n", pState->StateTimeOut.LowPart, pState->StateTimeOut.HighPart));
        
        if (IsTimeOut(&now, &(pState->StateSetTime), &(pState->StateTimeOut)))
        {
            // Time out. Release TCP state info and reset corresponding hash table entry
            DBGPRINT(("==> RefreshTcpListEntry: Port map %d -> %d time out on TCP state %d. Delete.\n", 
                      pState->OriginalPort, pState->MappedPort, pState->Status));
            // Protect the loop from break
            temp = p;
            p = p->Flink;
            // Clear hash table pointer
            TcpPortMapOutTable[pState->OriginalPort].State = NULL;
            TcpPortMapInTable[pState->MappedPort].State = NULL;
            // Remove entry and clear memory
            RemoveEntryList(temp);
            StateListLength--;
            NdisFreeMemory(pState, 0, 0);
            //DBGPRINT(("==> RefreshTcpListEntry: TCP state context memory freed.\n"));
            // Go to next entry
        }
        else
        {
            // Go to next entry
            // State set time is refreshed by state machine when parsing TCP segments, no need to refresh it here
            p = p->Flink;
        }
    }
}


USHORT
GetTcpPortMapOut(
    IN PTCP_HEADER     th,
    IN ULONG           len,
    IN BOOLEAN         trans
    )
/*++

Routine Description:

    Get the mapped port for the outflow TCP packet.
    
Arguments:

    th - TCP header pointer for current packet, should not be NULL
    len - Data length of current TCP segment, including TCP header
    trans - TRUE for 4to6 mapping; FLASE for 6to6 mapping

Return Value:

    Mapped port number if find mapping is successful,
    0 if failed to find or create a mapping info.

--*/
{
    USHORT    ret = 0;
    SHORT     remaining;
    LONG      max_ports = 65536 / LocalPrefixInfo.Ratio;
    USHORT    rover;
    USHORT    low;
    USHORT    high;
    // Get original port from source port field in TCP header
    USHORT    original = ntohs(th->sport);
    
    NDIS_STATUS         status;
    FILTER_STATUS       ftState;
    PTCP_STATE_CONTEXT  StateContext = NULL;
    
    NdisAcquireSpinLock(&StateListLock);
    
    // Do NOT call RefreshTcpListEntrySafe() since we have already hold the spin lock.
    RefreshTcpListEntry();

    if (TcpPortMapOutTable[original].State != NULL)
    {
        StateContext = TcpPortMapOutTable[original].State;
        if (StateContext->OriginalPort == original && StateContext->Translated == trans)  // Found existing mapping info
        {
            // Update state context.
            ftState = UpdateTcpStateContext(th, len, PACKET_DIR_LOCAL, StateContext);
            
            if (ftState == FILTER_ACCEPT)
            {
                ret = StateContext->MappedPort;
                DBGPRINT(("==> GetTcpPortMapOut: Found map %d -> %d, xlate=%d, TCP state %d\n", 
                          StateContext->OriginalPort, StateContext->MappedPort, StateContext->Translated, StateContext->Status));
            }
            else if (ftState == FILTER_DROP)
            {
                // Return 0 to drop current segment, keep the state info.
                DBGPRINT(("==> GetTcpPortMapOut: Invalid packet on map %d -> %d, xlate=%d, TCP state %d\n", 
                          StateContext->OriginalPort, StateContext->MappedPort, StateContext->Translated, StateContext->Status));
                NdisReleaseSpinLock(&StateListLock);
                return 0;
            }
            else  // FILTER_DROP_CLEAN
            {
                DBGPRINT(("==> GetTcpPortMapOut: Invalid state on map %d -> %d, xlate=%d, TCP state %d\n", 
                          StateContext->OriginalPort, StateContext->MappedPort, StateContext->Translated, StateContext->Status));
                
                // Clear hash table pointer
                TcpPortMapOutTable[original].State = NULL;
                TcpPortMapInTable[StateContext->MappedPort].State = NULL;
                // Remove entry
                RemoveEntryList(&(StateContext->ListEntry));
                StateListLength--;
                // Clear memory
                NdisFreeMemory(StateContext, 0, 0);
                //DBGPRINT(("==> GetTcpPortMapOut: StateContext memory freed.\n"));
                NdisReleaseSpinLock(&StateListLock);
                return 0;
            }
        }
    }
    
    if (ret == 0) // No existing map, generate new map
    {
        if (StateListLength >= max_ports)
        {
            NdisReleaseSpinLock(&StateListLock);
            DBGPRINT(("==> GetTcpPortMapOut: state list is full, map port %d failed.\n", original));
            return 0;
        }
        
        if (xlate_mode)  // 1:N port mapping
        {
            low = (USHORT)(1024 / LocalPrefixInfo.Ratio) + 1;
            high = max_ports - 1;
            remaining = (high - low) + 1;
            
            if (StateListLength != 0)
            {
                rover = (USHORT)(LastAllocatedPort / LocalPrefixInfo.Ratio) + 1;
            }
            else
            {
                rover = low;
            }
            
            do
            {
                ret = rover * LocalPrefixInfo.Ratio + LocalPrefixInfo.Offset;
                if (TcpPortMapInTable[ret].State == NULL)
                {
                    // Found idle ivi port.
                    break;
                }
                rover++;
                if (rover > high)
                {
                    // Wrap back.
                    rover = low;
                }
                remaining--;
            }
            while (remaining > 0);
            
            if (remaining <= 0)
            {
                NdisReleaseSpinLock(&StateListLock);
                return 0;
            }
        }
        else
        {
            // 1:1 port mapping
            ret = original;
        }
        
        // Now we have a mapped port allocated.
        // Create packet state and add mapping info to state list.
        status = NdisAllocateMemoryWithTag((PVOID)&StateContext, sizeof(TCP_STATE_CONTEXT), TAG);
        if (status != NDIS_STATUS_SUCCESS)
        {
            // No memory for state info. Fail this map.
            DBGPRINT(("==> GetTcpPortMapOut: NdisAllocateMemoryWithTag failed for port %d\n", original));
            NdisReleaseSpinLock(&StateListLock);
            return 0;
        }
        NdisZeroMemory(StateContext, sizeof(TCP_STATE_CONTEXT));
        
        // Check packet state for new mapping.
        ftState = CreateTcpStateContext(th, len, StateContext);
        
        if (ftState == FILTER_DROP_CLEAN)
        {
            DBGPRINT(("==> GetTcpPortMapOut: Invalid state on new map %d -> %d, xlate=%d, TCP state %d, fail to add new map.\n", 
                      StateContext->OriginalPort, StateContext->MappedPort, StateContext->Translated, StateContext->Status));
            // Clear memory
            NdisFreeMemory(StateContext, 0, 0);
            //DBGPRINT(("==> GetTcpPortMapOut: StateContext memory freed.\n"));
            NdisReleaseSpinLock(&StateListLock);
            return 0;
        }

        // Routine to add new map-info
        StateContext->OriginalPort = original;
        StateContext->MappedPort = ret;
        StateContext->Translated = trans;
        // Set hash table pointer
        TcpPortMapOutTable[StateContext->OriginalPort].State = StateContext;
        TcpPortMapInTable[StateContext->MappedPort].State = StateContext;
        // StateListHead need not be sorted. Just insert new entry at tail.
        InsertTailList(&StateListHead, &(StateContext->ListEntry));
        StateListLength++;
        LastAllocatedPort = ret;
        DBGPRINT(("==> GetTcpPortMapOut: New map %d -> %d added, xlate=%d, TCP state %d.\n", 
                  StateContext->OriginalPort, StateContext->MappedPort, StateContext->Translated, StateContext->Status));
    }
    
    NdisReleaseSpinLock(&StateListLock);
    
    return ret;
}


USHORT
GetTcpPortMapIn(
    IN PTCP_HEADER    th,
    IN ULONG          len
    )
/*++

Routine Description:

    Get the original port for the inflow TCP packet

Arguments:

    th - TCP header pointer for current packet, should not be NULL
    len - Data length of current TCP segment, including TCP header
    trans - TRUE for 4to6 mapping; FLASE for 6to6 mapping

Return Value:

    Mapped port number if find mapping is successful,
    0 if no valid mapping exists for this TCP connection.

--*/
{
    USHORT    ret = 0;
    // Get mapped port from destination port field in TCP header
    USHORT    mapped = ntohs(th->dport);
    
    NDIS_STATUS         status;
    FILTER_STATUS       ftState;
    PTCP_STATE_CONTEXT  StateContext = NULL;
    
    NdisAcquireSpinLock(&StateListLock);
    
    // Do NOT call RefreshTcpListEntrySafe() since we have already hold the spin lock.
    RefreshTcpListEntry();
    
    if (TcpPortMapInTable[mapped].State != NULL)
    {
        StateContext = TcpPortMapInTable[mapped].State;
        if (StateContext->MappedPort == mapped)  // Found existing mapping info
        {
            // Update state context.
            ftState = UpdateTcpStateContext(th, len, PACKET_DIR_REMOTE, StateContext);
            
            if (ftState == FILTER_ACCEPT)
            {
                ret = StateContext->OriginalPort;
                DBGPRINT(("==> GetTcpPortMapOut: Found map %d -> %d, xlate=%d, TCP state %d\n", 
                          StateContext->OriginalPort, StateContext->MappedPort, StateContext->Translated, StateContext->Status));
            }
            else if (ftState == FILTER_DROP)
            {
                // Return 0 to drop current segment, keep the state info.
                DBGPRINT(("==> GetTcpPortMapOut: Invalid packet on map %d -> %d, xlate=%d, TCP state %d\n", 
                          StateContext->OriginalPort, StateContext->MappedPort, StateContext->Translated, StateContext->Status));
                NdisReleaseSpinLock(&StateListLock);
                return 0;
            }
            else  // FILTER_DROP_CLEAN
            {
                DBGPRINT(("==> GetTcpPortMapOut: Invalid state on map %d -> %d, xlate=%d, TCP state %d\n", 
                          StateContext->OriginalPort, StateContext->MappedPort, StateContext->Translated, StateContext->Status));
                
                // Clear hash table pointer
                TcpPortMapOutTable[StateContext->OriginalPort].State = NULL;
                TcpPortMapInTable[StateContext->MappedPort].State = NULL;
                // Remove entry
                RemoveEntryList(&(StateContext->ListEntry));
                StateListLength--;
                // Clear memory
                NdisFreeMemory(StateContext, 0, 0);
                //DBGPRINT(("==> GetTcpPortMapOut: StateContext memory freed.\n"));
                NdisReleaseSpinLock(&StateListLock);
                return 0;
            }
        }
    }
    
    NdisReleaseSpinLock(&StateListLock);
    
    return ret;
}
