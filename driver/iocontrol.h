/* Filename  : iocontrol.h
 * 
 * Author    : Shang Wentao
 * Email     : wentaoshang@gmail.com
 * Date      : May 19, 2009
 * 
 * This file is the header file for 
 * 'iocontrol.c'. It is not part of 
 * the original Passthru NDIS driver. 
 *
 */

#ifndef _IOCONTROL_H_
#define _IOCONTROL_H_

NTSTATUS
DevIoControl(
    IN PDEVICE_OBJECT    pDeviceObject,
    IN PIRP              pIrp
    );

#endif // _IOCONTROL_H_
