#ifndef _LIST_H_
#define _LIST_H_

// Spin lock for map list structure
extern NDIS_SPIN_LOCK    PortListLock;
extern NDIS_SPIN_LOCK    IdListLock;
// Time-Out for mapping entries
extern LARGE_INTEGER     UdpTimeOut;
// Flag for MOD/RES anto-configuration
extern INT               AutoConfig;

typedef struct icmp_id4to6{
    USHORT id_6;
    USHORT valid;
}icmp_id4to6;

extern icmp_id4to6 icmp_id4to6_list[65536];

typedef struct icmp_id6to4{
    USHORT id_4;
    USHORT trans;    // Indicate whether this id is xlated from icmpv4 packet
}icmp_id6to4;

extern icmp_id6to4 icmp_id6to4_list[65536];

extern LARGE_INTEGER icmp_timer_list[65536];

extern USHORT id_used;
extern USHORT id_start;

//VOID init_icmp4to6_list();
//VOID init_icmp6to4_list();
//VOID init_icmp_timer_list();

typedef struct port4to6{
    USHORT port_6;
    USHORT valid;
}port4to6;

extern port4to6 port4to6_list[65536];

typedef struct port6to4{
    USHORT port_4;
    USHORT trans;    // Indicate whether this port is xlated from ipv4 packet
}port6to4;

extern port6to4 port6to4_list[65536];

extern LARGE_INTEGER port_timer_list[65536];

extern USHORT port_used;
extern USHORT port_start;

//VOID init_port4to6_list();
//VOID init_port6to4_list();
//VOID init_port_timer_list();

VOID reset_lists();

#endif // _LIST_H
