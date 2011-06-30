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
    USHORT              temp1, temp2;
    UCHAR               temp3;
    
    UNREFERENCED_PARAMETER(pDeviceObject);
    
    pIrpSp = IoGetCurrentIrpStackLocation(pIrp);
    
    ioBuffer = pIrp->AssociatedIrp.SystemBuffer;
    inputBufferLength  = pIrpSp->Parameters.DeviceIoControl.InputBufferLength;
    outputBufferLength = pIrpSp->Parameters.DeviceIoControl.OutputBufferLength;
    
    FunctionCode = pIrpSp->Parameters.DeviceIoControl.IoControlCode;
    
    DBGPRINT(("==> DevIoControl: Context %p\n", (pIrpSp->FileObject)->FsContext ));
    
    switch (FunctionCode)
    {
        case IOCTL_PTUSERIO_SET_RATIO:
            if (inputBufferLength != sizeof(LocalPrefixInfo.Ratio))
            {
                DBGPRINT(("==> ioctl: SET_RATIO input type invalid.\n"));
                NtStatus = STATUS_UNSUCCESSFUL;
            }
            else
            {
                NdisMoveMemory(&temp1, (PVOID)ioBuffer, inputBufferLength);
                if (temp1 > 4096)
                {
                    DBGPRINT(("==> ioctl: SET_RATIO input %d is too large.\n", LocalPrefixInfo.Ratio));
                    NtStatus = STATUS_UNSUCCESSFUL;
                }
                else
                {
                    LocalPrefixInfo.Ratio = temp1;
                    temp2 = 0;
                    while (temp1 >> 1 != 0)
                    {
                        temp2 += 1;
                        temp1 = temp1 >> 1;
                    }
                    temp2 = temp2 << 12;
                    LocalPrefixInfo.SuffixCode = temp2;
                    
                    DBGPRINT(("==> ioctl: set LocalPrefixInfo.Ratio to %d\n", LocalPrefixInfo.Ratio));
                    DBGPRINT(("==> ioctl: set LocalPrefixInfo.SuffixCode to %02x\n", LocalPrefixInfo.SuffixCode));
                    ResetMapListsSafe();
                    DBGPRINT(("==> Old Map List Freed.\n"));
                }
            }
            break;
            
        case IOCTL_PTUSERIO_GET_RATIO:
            if (outputBufferLength != sizeof(LocalPrefixInfo.Ratio))
            {
                DBGPRINT(("==> ioctl: GET_RATIO output type invalid.\n"));
                NtStatus = STATUS_UNSUCCESSFUL;
            }
            else
            {
                NdisMoveMemory(ioBuffer, &(LocalPrefixInfo.Ratio), outputBufferLength);
                DBGPRINT(("==> ioctl: get LocalPrefixInfo.Ratio by user.\n"));
                BytesReturned = sizeof(LocalPrefixInfo.Ratio);
            }
            break;
            
        case IOCTL_PTUSERIO_SET_OFFSET:
            if (inputBufferLength != sizeof(LocalPrefixInfo.Offset))
            {
                DBGPRINT(("==> ioctl: SET_OFFSET input type invalid.\n"));
                NtStatus = STATUS_UNSUCCESSFUL;
            }
            else
            {
                NdisMoveMemory(&temp1, (PVOID)ioBuffer, inputBufferLength);
                if (temp1 >= LocalPrefixInfo.Ratio)
                {
                    DBGPRINT(("==> ioctl: SET_OFFSET input %d is larger than current Ratio %d.\n", temp1, LocalPrefixInfo.Ratio));
                    NtStatus = STATUS_UNSUCCESSFUL;
                }
                else
                {
                    LocalPrefixInfo.Offset = temp1;
                    DBGPRINT(("==> ioctl: set LocalPrefixInfo.Offset to %d\n", LocalPrefixInfo.Offset));
                    ResetMapListsSafe();
                    DBGPRINT(("==> Old Map List Freed.\n"));
                }
            }
            break;
            
        case IOCTL_PTUSERIO_GET_OFFSET:
            if (outputBufferLength != sizeof(LocalPrefixInfo.Offset))
            {
                DBGPRINT(("==> ioctl: GET_RES output type invalid.\n"));
                NtStatus = STATUS_UNSUCCESSFUL;
            }
            else
            {
                NdisMoveMemory(ioBuffer, &(LocalPrefixInfo.Offset), outputBufferLength);
                DBGPRINT(("==> ioctl: get LocalPrefixInfo.Offset by user.\n"));
                BytesReturned = sizeof(LocalPrefixInfo.Offset);
            }
            break;
        
/*        
        case IOCTL_PTUSERIO_SET_TIMEOUT:
            if (inputBufferLength != sizeof(UdpTimeOut))
            {
                DBGPRINT(("==> ioctl: SET_TIMEOUT input type invalid.\n"));
                NtStatus = STATUS_UNSUCCESSFUL;
            }
            else
            {
                NdisMoveMemory(&UdpTimeOut, (PVOID)ioBuffer, inputBufferLength);
                DBGPRINT(("==> ioctl: set UdpTimeOut to : HighPart %ld  LowPart %ld\n", UdpTimeOut.HighPart, UdpTimeOut.LowPart));
            }
            break;
            
        case IOCTL_PTUSERIO_GET_TIMEOUT:
            if (outputBufferLength != sizeof(UdpTimeOut))
            {
                DBGPRINT(("==> ioctl: GET_TIMEOUT output type invalid.\n"));
                NtStatus = STATUS_UNSUCCESSFUL;
            }
            else
            {
                NdisMoveMemory(ioBuffer, &UdpTimeOut, outputBufferLength);
                //*((PUSHORT)ioBuffer) = UdpTimeOut;
                DBGPRINT(("==> ioctl: get UdpTimeOut by user.\n"));
                BytesReturned = sizeof(UdpTimeOut);
            }
            break;
*/
            
        case IOCTL_PTUSERIO_SET_GATEWAYMAC:
            if (inputBufferLength != 6)
            {
                DBGPRINT(("==> ioctl: SET_GATEWAYMAC input buffer size is not 6.\n"));
                NtStatus = STATUS_UNSUCCESSFUL;
            }
            else
            {
                NdisMoveMemory(GatewayMAC, ioBuffer, inputBufferLength);
                DBGPRINT(("==> ioctl: set GatewayMAC[6] to %02x:%02x:%02x:%02x:%02x:%02x\n", 
                            GatewayMAC[0], GatewayMAC[1], GatewayMAC[2], 
                            GatewayMAC[3], GatewayMAC[4], GatewayMAC[5]));
                ResetMapListsSafe();
                DBGPRINT(("==> Old Map List Freed.\n"));
            }
            break;
            
        case IOCTL_PTUSERIO_GET_GATEWAYMAC:
            if (outputBufferLength != 6)
            {
                DBGPRINT(("==> ioctl: GET_GATEWAYMAC output buffer size is not 6.\n"));
                NtStatus = STATUS_UNSUCCESSFUL;
            }
            else
            {
                NdisMoveMemory(ioBuffer, GatewayMAC, outputBufferLength);
                DBGPRINT(("==> ioctl: get GatewayMAC by user.\n"));
                BytesReturned = 6;
            }
            break;
        
        case IOCTL_PTUSERIO_SET_PREFIX:
            if (inputBufferLength != 16)
            {
                DBGPRINT(("==> ioctl: SET_PREFIX input buffer size is not 16.\n"));
                NtStatus = STATUS_UNSUCCESSFUL;
            }
            else
            {
                NdisMoveMemory(LocalPrefixInfo.Prefix.u.byte, ioBuffer, inputBufferLength);
                DBGPRINT(("==> ioctl: set LocalPrefixInfo.Prefix.u.byte[16] to %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n", 
                            LocalPrefixInfo.Prefix.u.byte[0], LocalPrefixInfo.Prefix.u.byte[1], LocalPrefixInfo.Prefix.u.byte[2], 
                            LocalPrefixInfo.Prefix.u.byte[3], LocalPrefixInfo.Prefix.u.byte[4], LocalPrefixInfo.Prefix.u.byte[5], 
                            LocalPrefixInfo.Prefix.u.byte[6], LocalPrefixInfo.Prefix.u.byte[7], LocalPrefixInfo.Prefix.u.byte[8], 
                            LocalPrefixInfo.Prefix.u.byte[9], LocalPrefixInfo.Prefix.u.byte[10], LocalPrefixInfo.Prefix.u.byte[11], 
                            LocalPrefixInfo.Prefix.u.byte[12], LocalPrefixInfo.Prefix.u.byte[13], LocalPrefixInfo.Prefix.u.byte[14], 
                            LocalPrefixInfo.Prefix.u.byte[15]));
                ResetMapListsSafe();
                DBGPRINT(("==> Old Map List Freed.\n"));
            }
            break;
            
        case IOCTL_PTUSERIO_GET_PREFIX:
            if (outputBufferLength != 16)
            {
                DBGPRINT(("==> ioctl: GET_PREFIX output buffer size is not 16.\n"));
                NtStatus = STATUS_UNSUCCESSFUL;
            }
            else
            {
                NdisMoveMemory(ioBuffer, LocalPrefixInfo.Prefix.u.byte, outputBufferLength);
                DBGPRINT(("==> ioctl: get LocalPrefixInfo.Prefix by user.\n"));
                BytesReturned = 16;
            }
            break;
            
        case IOCTL_PTUSERIO_SET_PREFIXLENGTH:
            if (inputBufferLength != sizeof(LocalPrefixInfo.PrefixLength))
            {
                DBGPRINT(("==> ioctl: SET_PREFIXLENGTH input type invalid.\n"));
                NtStatus = STATUS_UNSUCCESSFUL;
            }
            else
            {
                NdisMoveMemory(&temp3, ioBuffer, inputBufferLength);
                if (temp3 > 128)
                {
                    DBGPRINT(("==> ioctl: SET_PREFIXLENGTH input %d too large.\n", temp3));
                    NtStatus = STATUS_UNSUCCESSFUL;
                }
                else
                {
                    LocalPrefixInfo.PrefixLength = temp3;
                    DBGPRINT(("==> ioctl: set LocalPrefixInfo.PrefixLength to %d\n", LocalPrefixInfo.PrefixLength));
                    ResetMapListsSafe();
                    DBGPRINT(("==> Old Map List Freed.\n"));
                }
            }
            break;
            
        case IOCTL_PTUSERIO_GET_PREFIXLENGTH:
            if (outputBufferLength != sizeof(LocalPrefixInfo.PrefixLength))
            {
                DBGPRINT(("==> ioctl: GET_PREFIXLENGTH output type invalid.\n"));
                NtStatus = STATUS_UNSUCCESSFUL;
            }
            else
            {
                NdisMoveMemory(ioBuffer, &(LocalPrefixInfo.PrefixLength), outputBufferLength);
                DBGPRINT(("==> ioctl: get LocalPrefixInfo.PrefixLength by user.\n"));
                BytesReturned = sizeof(LocalPrefixInfo.PrefixLength);
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
            ResetMapListsSafe();
            DBGPRINT(("==> Old Map List Freed.\n"));
            break;
            
        case IOCTL_PTUSERIO_DISABLE_MPLEX:
            xlate_mode = 0;
            DBGPRINT(("==> ioctl: 1:N mapping disabled by user.\n"));
            ResetMapListsSafe();
            DBGPRINT(("==> Old Map List Freed.\n"));
            break;
            
        default:
            NtStatus = STATUS_NOT_SUPPORTED;
    }
    
    pIrp->IoStatus.Information = BytesReturned;
    
    DBGPRINT(("<== Leaving DevIoControl\n"));
    
    return NtStatus;
} 

