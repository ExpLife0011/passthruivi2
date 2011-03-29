#ifndef _PORTMAP_H_
#define _PORTMAP_H_

INT is_time_out(PLARGE_INTEGER newtime, PLARGE_INTEGER oldtime);

// Port map operations
VOID refresh_port_list();
USHORT get_out_map_port(USHORT oldp, USHORT translate);
USHORT get_in_map_port(USHORT newp);


#endif // _PORTMAP_H_
