#ifndef _PORTMAP_H
#define _PORTMAP_H

INT is_time_out(PLARGE_INTEGER newtime, PLARGE_INTEGER oldtime);

// Port map operations
VOID refresh_port_list();
USHORT get_out_map_port(USHORT oldp, USHORT translate);
USHORT get_in_map_port(USHORT newp);

// Id map operations
VOID refresh_id_list();
INT get_out_map_id(IN USHORT old_id, IN USHORT translate, OUT PUSHORT new_id);
INT get_in_map_id(IN USHORT new_id, OUT PUSHORT old_id);

#endif // _PORTMAP_H
