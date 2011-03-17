#include "precomp.h"
#pragma hdrstop

NDIS_SPIN_LOCK          PortListLock;
NDIS_SPIN_LOCK          IdListLock;
LARGE_INTEGER           TimeOut = { { 1640261632, 8 } };     // equals to 1 hour
INT                     AutoConfig = 0;  /* Depricated */

// Mapping lists
icmp_id4to6 icmp_id4to6_list[65536];  // indexed by old(system) id, stored in host-byte order
icmp_id6to4 icmp_id6to4_list[65536];  // indexed by new(passthru) id, stored in host-byte order

LARGE_INTEGER icmp_timer_list[65536];  // indexed by old(system) id

USHORT id_used = 0; // used ID counter
USHORT id_start = 0; // last new(passthru) id assigned

port4to6 port4to6_list[65536];  // indexed by old(system) port, stored in host-byte order
port6to4 port6to4_list[65536];  // indexed by new(passthru) port, stored in host-byte order

LARGE_INTEGER port_timer_list[65536]; // indexed by old(system) port

USHORT port_used = 0; // used port counter
USHORT port_start = 0; // last new(passthru) port assigned

VOID init_icmp4to6_list()
{
    NdisZeroMemory(icmp_id4to6_list, 65536 * sizeof(icmp_id4to6));
}

VOID init_icmp6to4_list()
{
	NdisZeroMemory(icmp_id6to4_list, 65536 * sizeof(icmp_id6to4));
}

VOID init_icmp_timer_list()
{
    NdisZeroMemory(icmp_timer_list, 65536 * sizeof(LARGE_INTEGER));
}

VOID init_port4to6_list()
{
	NdisZeroMemory(port4to6_list, 65536 * sizeof(port4to6));
}

VOID init_port6to4_list()
{
	NdisZeroMemory(port6to4_list, 65536 * sizeof(port6to4));
}

VOID init_port_timer_list()
{
    NdisZeroMemory(port_timer_list, 65536 * sizeof(LARGE_INTEGER));
}

VOID reset_lists()
{
    // zero lists memory
    init_icmp4to6_list();
	init_icmp6to4_list();
    init_icmp_timer_list();
	init_port4to6_list();
	init_port6to4_list();
    init_port_timer_list();
    
    // reset counter
    id_used = 0;
    id_start = 0;
    port_used = 0;
    port_start = 0;
    
    return;
}

