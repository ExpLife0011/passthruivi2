/* Filename  : iocontrol.c
 * 
 * Author    : Shang Wentao
 * Email     : wentaoshang@gmail.com
 * Date      : May 19, 2009
 * 
 * This file contains the handle function for
 * the driver ioctl calls. It is not part of 
 * the original Passthru NDIS driver. 
 *
 */

#include "precomp.h"
#pragma hdrstop
#include "iocommon.h"

NTSTATUS
DevIoControl(
    IN PDEVICE_OBJECT    pDeviceObject,
    IN PIRP              pIrp
    )
/*++

Routine Description:

    This is the dispatch routine for handling device ioctl requests.

Arguments:

    pDeviceObject - Pointer to the device object.

    pIrp - Pointer to the request packet.

Return Value:

    Status is returned.

--*/
{
    PIO_STACK_LOCATION  pIrpSp;
    NTSTATUS            NtStatus = STATUS_SUCCESS;
    ULONG               FunctionCode;
    ULONG               BytesReturned = 0;
    PUCHAR              ioBuffer = NULL;
    ULONG               inputBufferLength;
    ULONG               outputBufferLength;
    USHORT              temp;
    
    UNREFERENCED_PARAMETER(pDeviceObject);
    
    pIrpSp = IoGetCurrentIrpStackLocation(pIrp);
    
    ioBuffer = pIrp->AssociatedIrp.SystemBuffer;
    inputBufferLength  = pIrpSp->Parameters.DeviceIoControl.InputBufferLength;
    outputBufferLength = pIrpSp->Parameters.DeviceIoControl.OutputBufferLength;
    
    FunctionCode = pIrpSp->Parameters.DeviceIoControl.IoControlCode;
    
    DBGPRINT(("==> DevIoControl: Context %p\n", (pIrpSp->FileObject)->FsContext ));
    
    switch (FunctionCode)
    {
        case IOCTL_PTUSERIO_SET_MOD:
            if (inputBufferLength != sizeof(mod))
            {
                DBGPRINT(("==> ioctl: SET_MOD input type invalid.\n"));
                NtStatus = STATUS_UNSUCCESSFUL;
            }
            else
            {
                NdisMoveMemory(&temp, (PVOID)ioBuffer, inputBufferLength);
                if (temp > 4096)
                {
                    DBGPRINT(("==> ioctl: mod input %d is too large.\n", temp));
                    NtStatus = STATUS_UNSUCCESSFUL;
                }
                /*
                 * User-mode app is responsible for parameter's meaning
                 *
                else if (temp <= res)
                {
                    DBGPRINT(("==> ioctl: mod input %d is smaller than res.\n", temp));
                    NtStatus = STATUS_UNSUCCESSFUL;
                }
                 *
                 */
                else
                {
                    mod = temp;
                    mod_ratio = 0;
                    while (temp >> 1 != 0)
                    {
                        mod_ratio += 1;
                        temp = temp >> 1;
                    }
                    mod_ratio = mod_ratio << 4;
                    DBGPRINT(("==> ioctl: set mod to %d\n", mod));
                    DBGPRINT(("==> ioctl: set mod_ratio to %02x\n", mod_ratio));
                    reset_lists();
                    DBGPRINT(("==> Old Map List Freed.\n"));
                }
            }
            break;
            
        case IOCTL_PTUSERIO_GET_MOD:
            if (outputBufferLength != sizeof(mod))
            {
                DBGPRINT(("==> ioctl: GET_MOD output type invalid.\n"));
                NtStatus = STATUS_UNSUCCESSFUL;
            }
            else
            {
                NdisMoveMemory(ioBuffer, &mod, outputBufferLength);
                //*((PUSHORT)ioBuffer) = mod;
                DBGPRINT(("==> ioctl: get mod by user.\n"));
                BytesReturned = sizeof(mod);
            }
            break;
            
        case IOCTL_PTUSERIO_SET_RES:
            if (inputBufferLength != sizeof(res))
            {
                DBGPRINT(("==> ioctl: SET_RES input type invalid.\n"));
                NtStatus = STATUS_UNSUCCESSFUL;
            }
            else
            {
                NdisMoveMemory(&temp, (PVOID)ioBuffer, inputBufferLength);
                if (temp >= mod)
                {
                    DBGPRINT(("==> ioctl: res input %d is too large.\n", temp));
                    NtStatus = STATUS_UNSUCCESSFUL;
                }
                else
                {
                    res = temp;
                    DBGPRINT(("==> ioctl: set res to %d\n", res));
                    reset_lists();
                    DBGPRINT(("==> Old Map List Freed.\n"));
                }
            }
            break;
            
        case IOCTL_PTUSERIO_GET_RES:
            if (outputBufferLength != sizeof(res))
            {
                DBGPRINT(("==> ioctl: GET_RES output type invalid.\n"));
                NtStatus = STATUS_UNSUCCESSFUL;
            }
            else
            {
                NdisMoveMemory(ioBuffer, &res, outputBufferLength);
                //*((PUSHORT)ioBuffer) = res;
                DBGPRINT(("==> ioctl: get res by user.\n"));
                BytesReturned = sizeof(res);
            }
            break;
            
        case IOCTL_PTUSERIO_SET_TIMEOUT:
            if (inputBufferLength != sizeof(TimeOut))
            {
                DBGPRINT(("==> ioctl: SET_TIMEOUT input type invalid.\n"));
                NtStatus = STATUS_UNSUCCESSFUL;
            }
            else
            {
                NdisMoveMemory(&TimeOut, (PVOID)ioBuffer, inputBufferLength);
                DBGPRINT(("==> ioctl: set TimeOut to : HighPart %ld  LowPart %ld\n", TimeOut.HighPart, TimeOut.LowPart));
            }
            break;
            
        case IOCTL_PTUSERIO_GET_TIMEOUT:
            if (outputBufferLength != sizeof(TimeOut))
            {
                DBGPRINT(("==> ioctl: GET_TIMEOUT output type invalid.\n"));
                NtStatus = STATUS_UNSUCCESSFUL;
            }
            else
            {
                NdisMoveMemory(ioBuffer, &TimeOut, outputBufferLength);
                //*((PUSHORT)ioBuffer) = TimeOut;
                DBGPRINT(("==> ioctl: get TimeOut by user.\n"));
                BytesReturned = sizeof(TimeOut);
            }
            break;
        
        case IOCTL_PTUSERIO_SET_AUTOCONFIG:
            AutoConfig = 1;
            DBGPRINT(("==> ioctl: autoconfig enabled by user.\n"));
            break;
            
        case IOCTL_PTUSERIO_UNSET_AUTOCONFIG:
            AutoConfig = 0;
            DBGPRINT(("==> ioctl: autoconfig disabled by user.\n"));
            mod = 256;
            DBGPRINT(("==> ioctl: reset Mod to %d\n", mod));
            res = 1;
            DBGPRINT(("==> ioctl: reset Res to %d\n", res));
            reset_lists();
            DBGPRINT(("==> Old Map List Freed.\n"));
            break;
        
        case IOCTL_PTUSERIO_SET_PREFIX:
            if (inputBufferLength != 16)
            {
                DBGPRINT(("==> ioctl: SET_PREFIX input buffer size less than 16.\n"));
                NtStatus = STATUS_UNSUCCESSFUL;
            }
            else
            {
                NdisMoveMemory(prefix, (PVOID)ioBuffer, inputBufferLength);
                DBGPRINT(("==> ioctl: set prefix[] to %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", 
                            prefix[0], prefix[1], prefix[2], prefix[3], prefix[4], prefix[5], 
                            prefix[6], prefix[7], prefix[8], prefix[9], prefix[10], prefix[11], 
                            prefix[12], prefix[13], prefix[14], prefix[15]));
                reset_lists();
                DBGPRINT(("==> Old Map List Freed.\n"));
            }
            break;
            
        case IOCTL_PTUSERIO_GET_PREFIX:
            if (outputBufferLength != 16)
            {
                DBGPRINT(("==> ioctl: GET_PREFIX output buffer size less than 16.\n"));
                NtStatus = STATUS_UNSUCCESSFUL;
            }
            else
            {
                NdisMoveMemory(ioBuffer, prefix, outputBufferLength);
                DBGPRINT(("==> ioctl: get prefix by user.\n"));
                BytesReturned = 16;
            }
            break;
            
        case IOCTL_PTUSERIO_SET_PREFIXLENGTH:
            if (inputBufferLength != sizeof(prefix_length))
            {
                DBGPRINT(("==> ioctl: SET_PREFIX input type invalid.\n"));
                NtStatus = STATUS_UNSUCCESSFUL;
            }
            else
            {
                NdisMoveMemory(&temp, (PVOID)ioBuffer, inputBufferLength);
                if (temp > 128)
                {
                    DBGPRINT(("==> ioctl: prefix_length input %d is too large.\n", temp));
                    NtStatus = STATUS_UNSUCCESSFUL;
                }
                else
                {
                    prefix_length = temp;
                    DBGPRINT(("==> ioctl: set prefix_length to %d\n", prefix_length));
                    reset_lists();
                    DBGPRINT(("==> Old Map List Freed.\n"));
                }
            }
            break;
            
        case IOCTL_PTUSERIO_GET_PREFIXLENGTH:
            if (outputBufferLength != sizeof(prefix_length))
            {
                DBGPRINT(("==> ioctl: GET_PREFIXLENGTH output type invalid.\n"));
                NtStatus = STATUS_UNSUCCESSFUL;
            }
            else
            {
                NdisMoveMemory(ioBuffer, &prefix_length, outputBufferLength);
                DBGPRINT(("==> ioctl: get prefix_length by user.\n"));
                BytesReturned = sizeof(prefix_length);
            }
            break;
                
        case IOCTL_PTUSERIO_ENABLE_XLATE:
            enable_xlate = 1;
            DBGPRINT(("==> ioctl: translation enabled by user.\n"));
            break;
            
        case IOCTL_PTUSERIO_DISABLE_XLATE:
            enable_xlate = 0;
            DBGPRINT(("==> ioctl: translation disabled by user.\n"));
            break;
            
        case IOCTL_PTUSERIO_ENABLE_MPLEX:
            xlate_mode = 1;
            DBGPRINT(("==> ioctl: 1:N mapping enabled by user.\n"));
            reset_lists();
            DBGPRINT(("==> Old Map List Freed.\n"));
            break;
            
        case IOCTL_PTUSERIO_DISABLE_MPLEX:
            xlate_mode = 0;
            DBGPRINT(("==> ioctl: 1:N mapping disabled by user.\n"));
            reset_lists();
            DBGPRINT(("==> Old Map List Freed.\n"));
            break;
            
        default:
            NtStatus = STATUS_NOT_SUPPORTED;
    }
    
    pIrp->IoStatus.Information = BytesReturned;
    
    DBGPRINT(("<== Leaving DevIoControl\n"));
    
    return NtStatus;
} 

