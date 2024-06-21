#pragma once

#include "cos_chal_consts.h"
#include "cos_types.h"
#include <chal_consts.h>
#include <compiler.h>
#include <cos_consts.h>
#include <types.h>
#include <resources.h>
#include <component.h>

#define CAP_INTERN_SZ 48

/*
 * A generic version of the shared structure of all capabilities. The
 * values in `type` determine what the rest of the structure looks
 * like (see the capability_* structs below). The values in
 * `operations` determine which operations can be performed on the
 * resource referenced by this capability.
 */
struct capability_generic {
	cos_cap_type_t       type;
	cos_op_bitmap_t      operations;
	liveness_t           liveness;
	uword_t              intern; /* just a placeholder we can use to get the address. */
	char                 padding[COS_CACHELINE_SIZE - (sizeof(cos_cap_type_t) + sizeof(cos_op_bitmap_t) + sizeof(liveness_t) + sizeof(uword_t))];
};

COS_STATIC_ASSERT(sizeof(struct capability_generic) == COS_CACHELINE_SIZE, "Generic capability is not a cache-line.");

struct capability_component_intern {
	struct component_ref component;
	char                 padding[CAP_INTERN_SZ - sizeof(struct component_ref)];
};

struct capability_component {
	cos_cap_type_t       type;
	cos_op_bitmap_t      operations;
	liveness_t           liveness;

	struct capability_component_intern intern;
};

COS_STATIC_ASSERT(sizeof(struct capability_component) == sizeof(struct capability_generic), "Component capability incorrectly sized.");

struct capability_sync_inv_intern {
	inv_token_t          token;
	vaddr_t              entry_ip;
	struct component_ref component;
	char                 padding[CAP_INTERN_SZ - sizeof(inv_token_t) - sizeof(vaddr_t) - sizeof(struct component_ref)];
};

struct capability_sync_inv {
	cos_cap_type_t       type;
	cos_op_bitmap_t      operations;
	liveness_t           liveness;

	struct capability_sync_inv_intern intern;
};

COS_STATIC_ASSERT(sizeof(struct capability_sync_inv) == sizeof(struct capability_generic), "Synchronous invocation incorrectly sized.");

struct capability_resource_intern {
	struct weak_ref      ref;
	char                 padding[CAP_INTERN_SZ - sizeof(struct weak_ref)];
};

/* Threads, resource tables, and control blocks */
struct capability_resource {
	cos_cap_type_t       type;
	cos_op_bitmap_t      operations;
	liveness_t           liveness;

	struct capability_resource_intern intern;
};

COS_STATIC_ASSERT(sizeof(struct capability_resource) == sizeof(struct capability_generic), "Resource capability incorrectly sized.");

struct capability_hw_intern {
	uword_t              data[6];
};

struct capability_hw {
	cos_cap_type_t       type;
	cos_op_bitmap_t      operations;
	liveness_t           liveness;

	struct capability_hw_intern intern;
};

COS_STATIC_ASSERT(sizeof(struct capability_hw) == sizeof(struct capability_generic), "Hardware capability incorrectly sized.");