#pragma once
#include <fltKernel.h>
#include "vmcs.h"

typedef struct _VMM_DEBUG_INFO
{
	PVOID L0_Vmcs;
	PVOID L1_Vmcs;
}VMMDEBUGINFO, *PVMMDEBUGINFO; 
 

NTSTATUS 
NTAPI 
IceSetTargetVmmInfo();