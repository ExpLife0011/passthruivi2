#include "precomp.h"
#pragma hdrstop

//
// Check whether a map is time-out, return 1 if time out.
// Note that we assume that the first parameter is larger 
// than the second, that is, the first is newer and the 
// second is earlier. We perform no check for this.
//
INT is_time_out(PLARGE_INTEGER newtime, PLARGE_INTEGER oldtime)
{   
    if (newtime->QuadPart - oldtime->QuadPart >= TimeOut.QuadPart)
        return 1;
    else
        return 0;
}

//
// Check the whole list and delete the deprecated maps
//
VOID refresh_port_list()
{
    LARGE_INTEGER now;
    INT i;
    USHORT tempport;
    
    if (port_used > 0)
    {
        NdisGetCurrentSystemTime(&now);
        NdisAcquireSpinLock(&PortListLock);
        for (i = 0; i < 65536; i++)
        {
            if (port4to6_list[i].valid != 0 && is_time_out(&now, &(port_timer_list[i])))
            {
                // Time out! Reset port mapping info
                tempport = port4to6_list[i].port_6;
                port6to4_list[tempport].port_4 = 0;
                port6to4_list[tempport].trans = 0;
                port4to6_list[i].port_6 = 0;
                port4to6_list[i].valid = 0;
                port_timer_list[i].QuadPart = 0;
                port_used--;
                DBGPRINT(("==> refresh_port_list: Map %d -> %d time out. Delete.\n", i, tempport));
            }
        }
        NdisReleaseSpinLock(&PortListLock);
    }
    
    return;
}

//
// Get the map port for the outflow tcp/udp packet, return 0 if failed.
//
USHORT get_out_map_port(USHORT oldp, USHORT translate)
{
	USHORT    ret;
	SHORT     remaining;
	USHORT    MaxPorts;
    
    USHORT    rover;
    USHORT    low;
    USHORT    high;
	
	MaxPorts = 65536 / mod;
	
    refresh_port_list();
    
	if (port_used >= MaxPorts)
    {
		DBGPRINT(("==> get_out_map_port: list full. Map port is used up.\n"));
		return 0;
	}

	ret = 0;
	NdisAcquireSpinLock(&PortListLock);
	if (port4to6_list[oldp].valid != 0)  // find existing map
    {
        ret = port4to6_list[oldp].port_6;
        port6to4_list[ret].trans = translate;  // override previous trans type
        NdisGetCurrentSystemTime(&(port_timer_list[oldp])); // refresh timer
        DBGPRINT(("==> get_out_map_port: Find Map %d -> %d, xlate flag is %d\n", oldp, ret, translate ));
    }
    //NdisReleaseSpinLock(&PortListLock);
	
	if (ret == 0) // no existing map, generate new map
    {
        if (xlate_mode)  // 1:N port mapping
        {
            low = (USHORT)(1024 / mod) + 1;
            high = MaxPorts - 1;
            remaining = (high - low) + 1;
            
            if (port_used != 0)
                rover = (USHORT)(port_start / mod) + 1;
            else
                rover = low;
            
            do
            {
                ret = rover * mod + res;
                if (port6to4_list[ret].port_4 == 0) // find idle ivi-port
                    break;
                rover++;
                if (rover > high)
                    rover = low;
                
                remaining--;
            }
            while (remaining > 0);
            
            if (remaining <= 0)
            {
                NdisReleaseSpinLock(&PortListLock);
                return 0;
            }
        }
        else
        {
            // 1:1 port mapping
            ret = oldp;
        }
        
        // Routine to add new map-info
        //NdisAcquireSpinLock(&PortListLock);
        port4to6_list[oldp].port_6 = ret;
        port4to6_list[oldp].valid = 1;
        port6to4_list[ret].port_4 = oldp;
        port6to4_list[ret].trans = translate;
        NdisGetCurrentSystemTime(&(port_timer_list[oldp]));
        port_used++;
        port_start = ret;
        //NdisReleaseSpinLock(&PortListLock);
        DBGPRINT(("==> get_out_map_port: New Map %d -> %d added, xlate flag is %d\n", oldp, ret, translate ));
    }
    
    NdisReleaseSpinLock(&PortListLock);
    
	return ret;
}

//
// Get the original port for the inflow tcp/udp packet, return 0 if failed.
//
USHORT get_in_map_port(USHORT newp)
{
	USHORT ret;
	USHORT xlate;
	
	refresh_port_list();
	
	if (port_used == 0) // no map-info
		return 0;
	
	ret = 0;
	xlate = 0;
	NdisAcquireSpinLock(&PortListLock);
	ret = port6to4_list[newp].port_4;
	if (port4to6_list[ret].valid != 0) // find existing map
    {
        //ret = port6to4_list[newp].port_4;
        xlate = port6to4_list[newp].trans;
        NdisGetCurrentSystemTime(&(port_timer_list[ret]));
        DBGPRINT(("==> get_in_map_port: Find Map %d -> %d, xlate flag is %d\n", ret, newp, xlate ));
    }
    else
    {
        ret = 0;
    }
    NdisReleaseSpinLock(&PortListLock);
    
    return ret;
}

//
// Check the whole list and delete the deprecated maps
//
VOID refresh_id_list()
{
    LARGE_INTEGER now;
    INT i;
    USHORT tempid;
    
    if (id_used > 0)
    {
        NdisGetCurrentSystemTime(&now);
        NdisAcquireSpinLock(&IdListLock);
        for (i = 0; i < 65536; i++)
        {
            if (icmp_id4to6_list[i].valid != 0 && is_time_out(&now, &(icmp_timer_list[i])))
            {
                // Time out! Reset id map info
                tempid = icmp_id4to6_list[i].id_6;
                icmp_id6to4_list[tempid].id_4 = 0;
                icmp_id6to4_list[tempid].trans = 0;
                icmp_id4to6_list[i].id_6 = 0;
                icmp_id4to6_list[i].valid = 0;
                icmp_timer_list[i].QuadPart = 0;
                id_used--;
                DBGPRINT(("==> refresh_id_list: Map %d -> %d time out. Delete.\n", i, tempid ));
            }
        }
        NdisReleaseSpinLock(&IdListLock);
    }
    
    return;
}

//
// Get the map id for the outflow icmp packet, return 0 on success.
//
INT get_out_map_id(IN USHORT old_id, IN USHORT translate, OUT PUSHORT new_id)
{
	USHORT    ret;
	SHORT     remaining;
	USHORT    MaxIds;
    
    USHORT    rover;
    USHORT    low;
    USHORT    high;
	
	MaxIds = (USHORT)( 65536 / mod );
	
    refresh_id_list();
    
	if( id_used >= MaxIds )
    {
		DBGPRINT(("==> get_out_map_id: list full. Map id is used up.\n"));
		*new_id = 0;
		return -1;
	}

	ret = 0;
	NdisAcquireSpinLock(&IdListLock);
	if (icmp_id4to6_list[old_id].valid != 0)  // find existing map
    {
        ret = icmp_id4to6_list[old_id].id_6;
        NdisGetCurrentSystemTime(&(icmp_timer_list[old_id])); // refresh timer
        DBGPRINT(("==> get_out_map_id: Find Map %d -> %d\n", old_id, ret));
        *new_id = ret;
    }
    //NdisReleaseSpinLock(&IdListLock);
	
	if (ret == 0) // no existing map, generate new map
    {
        if (xlate_mode)   // 1:N id mapping
        {
            low = (USHORT)(1024 / mod) + 1;
            high = MaxIds - 1;
            remaining = (high - low) + 1;
    
            if (id_used != 0)
                rover = (USHORT)(id_start / mod) + 1;
            else
                rover = low;
            
            do
            {
                ret = rover * mod + res;
                if (icmp_id6to4_list[ret].id_4 == 0) // find idle ivi-id
                    break;
                rover++;
                if (rover > high)
                    rover = low;
                
                remaining--;
            }
            while (remaining > 0);
            
            if (remaining <= 0)
            {
                *new_id = 0;
                NdisReleaseSpinLock(&IdListLock);
                return -1;
            }
        }
        else
        {
            // 1:1 id mapping
            ret = old_id;
        }
        
        // Routine to add new map-info
        //NdisAcquireSpinLock(&IdListLock);
        icmp_id4to6_list[old_id].id_6 = ret;
        icmp_id4to6_list[old_id].valid = 1;
        icmp_id6to4_list[ret].id_4 = old_id;
        icmp_id6to4_list[ret].trans = translate;
        NdisGetCurrentSystemTime(&(icmp_timer_list[old_id]));
        id_used++;
        id_start = ret;
        //NdisReleaseSpinLock(&IdListLock);
        DBGPRINT(("==> get_out_map_id: New Map %d -> %d added.\n", old_id, ret ));
        *new_id = ret;
    }
    
    NdisReleaseSpinLock(&IdListLock);
    
	return 0;
}

//
// Get the original id for the inflow icmp packet, return 0 on success
//
INT get_in_map_id(IN USHORT new_id, OUT PUSHORT old_id)
{
	USHORT  ret;
	INT     flag;
	
	refresh_id_list();
	
	if (id_used == 0) // no map-info
		return -1;
	
	ret = 0;
	flag = 0;
	NdisAcquireSpinLock(&IdListLock);
	ret = icmp_id6to4_list[new_id].id_4;
	if (icmp_id4to6_list[ret].valid != 0) // find existing map
    {
        //ret = icmp_id6to4_list[new_id].id_4;
        NdisGetCurrentSystemTime(&(icmp_timer_list[ret]));
        DBGPRINT(("==> get_in_map_id: Find Map %d -> %d\n", ret, new_id ));
        *old_id = ret;
        flag = 0;
    }
    else
    {
        flag = -1;
    }
    NdisReleaseSpinLock(&IdListLock);
    
    return flag;
}