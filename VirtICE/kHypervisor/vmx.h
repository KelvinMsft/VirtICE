// Copyright (c) 2016-2017, KelvinChan. All rights reserved.
// Copyright (c) 2016-2017, KelvinChan. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

#ifndef NESTED_HYPERPLATFORM_VMX_H_
#define NESTED_HYPERPLATFORM_VMX_H_
#include <fltKernel.h>
#include "..\HyperPlatform\vmm.h"
#include "..\HyperPlatform\util.h"
extern struct GuestContext;
extern "C"
{

VOID VmxVmxonEmulate(
	GuestContext* guest_context
);

VOID VmxVmxoffEmulate(
	GuestContext* guest_context
);

VOID VmxVmclearEmulate(
	GuestContext* guest_context
);

VOID VmxVmptrldEmulate(
	GuestContext* guest_context
);

VOID VmxVmreadEmulate(
	GuestContext* guest_context
);

VOID VmxVmwriteEmulate(
	GuestContext* guest_context
);

VOID VmxVmlaunchEmulate(
	GuestContext* guest_context
);

VOID VmxVmresumeEmulate(
	GuestContext* guest_context
);

VOID VmxVmptrstEmulate(
	GuestContext* guest_context
);

VOID LEAVE_GUEST_MODE(
	VCPUVMX* vcpu
);
VOID ENTER_GUEST_MODE(
	VCPUVMX* vcpu
);
VMX_MODE GetVmxMode(
	VCPUVMX* vcpu
);  

NTSTATUS VmxVMExitEmulate(
	VCPUVMX* vCPU,
	GuestContext* guest_context
);

}

#endif