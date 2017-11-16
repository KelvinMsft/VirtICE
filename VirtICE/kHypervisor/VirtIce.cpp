#include <fltKernel.h>
#include "VirtIce.h"
///////////////////////////////////////////////////////////////////////////////////////////
//// Types
////


///////////////////////////////////////////////////////////////////////////////////////////
//// Global Variables
////

VMDbgCfg g_VirtIceCfg = { 0 };

///////////////////////////////////////////////////////////////////////////////////////////
//// Prototype
////
NTSTATUS
NTAPI
IceSetVmmDbgConfig(
	_In_ VMDbgCfg* cfg
);

NTSTATUS
NTAPI
IceGetVmmDbgConfig(
	_Out_ VMDbgCfg** cfg
);

///////////////////////////////////////////////////////////////////////////////////////////
//// Definition
////

extern "C"
{ 

PVOID 
VMCALLBACK 
OnPreVMExitCallback(
	_In_ VMDbgInfo* info)
{
	if (!info)
	{
		return NULL;
	}

	switch (info->CallbackType)
	{
	case DBG_VMEXIT_PRE_VMCS_LOADING:
		break;
	case DBG_VMEXIT_PRE_VMCS_LOAD_HOST_STATE:
		break;
	case DBG_VMEXIT_PRE_VMCS_SAVE_GUEST_STATE:
		break;
	default:
		break; 
	}

	return NULL; 
}
PVOID 
VMCALLBACK 
OnPostVMExitCallback(
	_In_ VMDbgInfo* info)
{
	if (!info)
	{
		return NULL;
	} 

	switch (info->CallbackType)
	{
	case DBG_VMEXIT_POST_VMCS_LOADING:
		break;
	case DBG_VMEXIT_POST_VMCS_LOAD_HOST_STATE:
		break;
	case DBG_VMEXIT_POST_VMCS_SAVE_GUEST_STATE:
		break; 
	default:
		break; 
	}
	return NULL; 
}
PVOID 
VMCALLBACK 
OnPreVMEntryCallback(
	_In_ VMDbgInfo* info)
{
	if (!info)
	{
		return NULL;
	}

	switch (info->CallbackType)
	{
	case DBG_VMENTRY_PRE_VMCS_LOAD_GUEST_STATE:
		break; 
	case DBG_VMENTRY_PRE_VMCS_SAVE_HOST_STATE:
		break;
	default:
		break;
	}
	return NULL; 
}
PVOID 
VMCALLBACK 
OnPostVMEntryCallback(
	_In_ VMDbgInfo* info)
{
	if (!info)
	{
		return NULL;
	}

	switch (info->CallbackType)
	{
	case DBG_VMENTRY_POST_VMCS_LOAD_GUEST_STATE:
		break;
	case DBG_VMENTRY_POST_VMCS_SAVE_HOST_STATE:
		break; 
	default:
		break;
	}
	return NULL;

}
PVOID 
VMCALLBACK 
OnVmcsComparsionCallback(
	_In_ VMDbgInfo* info)
{ 
	return NULL;

}
PVOID 
VMCALLBACK 
OnVmSpecificVmExitCallback(
	_In_ VMDbgInfo* info)
{ 
 
	return NULL;
}

NTSTATUS
NTAPI
IceVmmDbgUnittest()
{
	VMDbgCfg cfg = { 0 };
	cfg.CallbackBitmap			 = DBG_VMEXIT_ALL;
	cfg.OnPreVmEntryCallback[0]  = OnPreVMEntryCallback;
	cfg.OnPostVmEntryCallback[0] = OnPostVMEntryCallback; 
	cfg.OnPostVmExitCallback[0]  = OnPostVMExitCallback;
	cfg.OnPreVmExitCallback[0]   = OnPreVMExitCallback;
	cfg.OnCompareCallback[0]     = OnVmcsComparsionCallback;
	cfg.OnSpecificVmExit[0]      = OnVmSpecificVmExitCallback;  
	IceSetVmmDbgConfig(&cfg);
	return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
IceSetVmmDbgConfig(
	_In_ VMDbgCfg* cfg)
{
	if (!cfg)
	{
		return STATUS_UNSUCCESSFUL;
	}
	RtlMoveMemory(&g_VirtIceCfg, cfg, sizeof(VMDbgCfg));
	return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
IceGetVmmDbgConfig(
	_Out_ VMDbgCfg** cfg)
{
	*cfg = &g_VirtIceCfg;
	return STATUS_SUCCESS;
} 




























}