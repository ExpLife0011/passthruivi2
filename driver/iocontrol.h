#ifndef _IOCONTROL_H_
#define _IOCONTROL_H_

NTSTATUS
DevIoControl(
    IN PDEVICE_OBJECT    pDeviceObject,
    IN PIRP              pIrp
    );

#endif // _IOCONTROL_H_
