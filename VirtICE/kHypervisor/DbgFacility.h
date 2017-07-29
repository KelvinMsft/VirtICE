#pragma once
#ifndef DBG_FACILITY_VMX_
#define DBG_FACILITY_VMX_
#include <fltKernel.h>
#include "../HyperPlatform/ia32_type.h"
#define VMCALLBACK  __fastcall

#define DBG_VMEXIT_PRE_VMCS_LOADING				0x00000001
#define DBG_VMEXIT_POST_VMCS_LOADING				0x00000002
#define DBG_VMEXIT_PRE_VMCS_LOAD_HOST_STATE			0x00000004
#define DBG_VMEXIT_POST_VMCS_LOAD_HOST_STATE			0x00000008
#define DBG_VMEXIT_PRE_VMCS_LOAD_GUEST_STATE			0x00000010
#define DBG_VMEXIT_POST_VMCS_LOAD_GUEST_STATE			0x00000020
#define DBG_VMEXIT_PRE_VMCS_LOAD_CONTROL_STATE			0x00000040
#define DBG_VMEXIT_POST_VMCS_LOAD_CONTROL_STATE			0x00000080
#define DBG_VMEXIT_SPECIFIC_REASON				0x00000100 
#define MAX_DIFF_ITEM_VMCS					200
 
#pragma pack(8)
typedef struct
{
	VmcsField FieldId;
	CHAR*	FieldName;
	ULONG64	   Before;
	ULONG64	    After;
}VmcsDiff, *pVmcsDiff;
#pragma pop()

#pragma pack(8)
typedef struct
{				
	ULONG64				CallbackType;  // Callback setting
	ULONG_PTR			GuestVmcs;  // General used
	VmcsDiff    			ComparedResult[MAX_DIFF_ITEM_VMCS];	// Used by On Comparsion 
	VmxExitReason			ExitReason;	// Used by OnVmExit
	CHAR*				ExitReasonName; // Used by OnVmExit
}VMDbgInfo, *pVMDbgInfo;
#pragma pop()
  

typedef PVOID(VMCALLBACK *pPreVMExitCallback)(VMDbgInfo*);
typedef PVOID(VMCALLBACK *pPostVMExitCallback)(VMDbgInfo*);
typedef PVOID(VMCALLBACK *pPreVMEntryCallback)(VMDbgInfo*);
typedef PVOID(VMCALLBACK *pPostVMEntryCallback)(VMDbgInfo*);
typedef PVOID(VMCALLBACK *pVmcsComparsionCallback)(VMDbgInfo*);
typedef PVOID(VMCALLBACK *pVmSpecificVmExitCallback)(VMDbgInfo*);

#pragma pack(8)
typedef struct
{
	ULONG64     		        CallbackBitmap;			// used by distinct different callback event
	ULONG64				VMExitBitmap;			// used by specific callback
	pPreVMExitCallback		OnPreVmExitCallback[8];
	pPostVMExitCallback		OnPostVmExitCallback[8];
	pPreVMEntryCallback		OnPreVmEntryCallback[8];
	pPostVMEntryCallback		OnPostVmEntryCallback[8]; 
	pVmcsComparsionCallback		OnCompareCallback[8];
	pVmSpecificVmExitCallback	OnSpecificVmExit[8]; 
}VMDbgCfg, *PVMDbgCfg;
#pragma pop()  

NTSTATUS SetNestedVmCallback(VMDbgCfg cfg);
#endif
