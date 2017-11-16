#include <fltKernel.h>
#include "DebugUtil.h"

VMMDEBUGINFO g_DebugInfo[1];

NTSTATUS NTAPI IceSetTargetVmmInfo(PVOID L0Vmcs, PVOID L1Vmcs)
{ 
	g_DebugInfo[0].L0_Vmcs = L0Vmcs;
	g_DebugInfo[0].L1_Vmcs = L1Vmcs;
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI IceGetTargetVmmInfo(ULONG VmmIndex, VMMDEBUGINFO** DebugInfo)
{
	*DebugInfo = g_DebugInfo;
	return STATUS_SUCCESS;
}