/*
* Copyright (c) 2013-2024, ARM Limited and Contributors. All rights reserved.
*
* SPDX-License-Identifier: BSD-3-Clause
*/

/**
 * This dispatcher is heavily inspired by the tspd example.
 */

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>

#include <arch_helpers.h>
#include <bl31/bl31.h>
#include <bl31/ehf.h>
#include <common/bl_common.h>
#include <common/debug.h>
#include <common/runtime_svc.h>
#include <lib/el3_runtime/context_mgmt.h>
#include <plat/common/platform.h>
#include <tools_share/uuid.h>
#include <lib/utils.h>

#include "skteed_private.h"
#include "skteed_smc.h"

/*******************************************************************************
* Address of the entrypoint vector table in the Secure Payload. It is
* initialised once on the primary core after a cold boot.
******************************************************************************/
skteed_vectors_t *skteed_vectors;

/*******************************************************************************
* Array to keep track of per-cpu Secure Payload state
******************************************************************************/
skteed_context_t skteed_sp_context[SKTEED_CORE_COUNT];


/* UID which has a weird format. */
DEFINE_SVC_UUID2(skteed_uuid,
0xa056305b, 0x9132, 0x7b42, 0x98, 0x11,
0x71, 0x68, 0xca, 0x50, 0xf3, 0xfb);

int32_t tspd_init(void);

/**
 * Given a secure payload entrypoint info pointer, entry point PC, register
 * width, cpu id & pointer to a context data structure, this function will
 * initialize the context and entry point info for the secure payload
 */
static void skteed_init_ep_state(struct entry_point_info *entry_point, uint64_t pc, skteed_context_t *ctx) {
	uint32_t ep_attr;

	assert(entry_point);
	assert(pc);
	assert(ctx);

	// Save the current CPU identifier.
	ctx->mpidr = read_mpidr_el1();
	ctx->state = 0;
	clr_yield_smc_active_flag(ctx->state);

	// Tell ATF this CPU context is a secure one.
	cm_set_context(&ctx->cpu_ctx, SECURE);

	// Initialize the endpoint information, which will be passed to ATF.
	ep_attr = SECURE;
	if (read_sctlr_el3() & SCTLR_EE_BIT) {
		ep_attr |= EP_EE_BIG;
	}
	SET_PARAM_HEAD(entry_point, PARAM_EP, VERSION_1, ep_attr);

	entry_point->pc = pc;
	entry_point->spsr = SPSR_64(
		MODE_EL1,
		MODE_SP_ELX,
		DISABLE_ALL_EXCEPTIONS
	);
	zeromem(&entry_point->args, sizeof(entry_point->args));
}

/*******************************************************************************
 * This function takes an SP context pointer and:
 * 1. Applies the S-EL1 system register context from tsp_ctx->cpu_ctx.
 * 2. Saves the current C runtime state (callee saved registers) on the stack
 *    frame and saves a reference to this state.
 * 3. Calls el3_exit() so that the EL3 system and general purpose registers
 *    from the tsp_ctx->cpu_ctx are used to enter the secure payload image.
 ******************************************************************************/
uint64_t skteed_synchronous_sp_entry(skteed_context_t *ctx)
{
	uint64_t rc;

	assert(ctx != NULL);
	assert(ctx->c_rt_ctx == 0);

	/* Apply the Secure EL1 system register context and switch to it */
	assert(cm_get_context(SECURE) == &ctx->cpu_ctx);
	cm_el1_sysregs_context_restore(SECURE);
	cm_set_next_eret_context(SECURE);

	rc = skteed_enter_sp(&ctx->c_rt_ctx);

	return rc;
}

/*******************************************************************************
 * This function takes an SP context pointer and:
 * 1. Saves the S-EL1 system register context tp tsp_ctx->cpu_ctx.
 * 2. Restores the current C runtime state (callee saved registers) from the
 *    stack frame using the reference to this state saved in tspd_enter_sp().
 * 3. It does not need to save any general purpose or EL3 system register state
 *    as the generic smc entry routine should have saved those.
 ******************************************************************************/
void skteed_synchronous_sp_exit(skteed_context_t *ctx, uint64_t ret)
{
	assert(ctx != NULL);
	/* Save the Secure EL1 system register context */
	assert(cm_get_context(SECURE) == &ctx->cpu_ctx);
	cm_el1_sysregs_context_save(SECURE);

	assert(ctx->c_rt_ctx != 0);
	skteed_exit_sp(ctx->c_rt_ctx, ret);

	/* Should never reach here */
	assert(0);
}


/*******************************************************************************
 * This function passes control to the Secure Payload image (BL32) for the first
 * time on the primary cpu after a cold boot. It assumes that a valid secure
 * context has already been created by tspd_setup() which can be directly used.
 * It also assumes that a valid non-secure context has been initialised by PSCI
 * so it does not need to save and restore any non-secure state. This function
 * performs a synchronous entry into the Secure payload. The SP passes control
 * back to this routine through a SMC.
 ******************************************************************************/
int32_t skteed_init(void)
{
	uint32_t linear_id = plat_my_core_pos();
	skteed_context_t *ctx = &skteed_sp_context[linear_id];
	entry_point_info_t *entry_point;
	uint64_t rc;

	/*
	 * Get information about the Secure Payload (BL32) image. Its
	 * absence is a critical failure.
	 */
	entry_point = bl31_plat_get_next_image_ep_info(SECURE);
	assert(entry_point);

	cm_init_my_context(entry_point);

	/*
	 * Arrange for an entry into the secure payload. It will be
	 * returned via the SKTEED_SMC_ENTRY_DONE case
	 */
	INFO("SKTEED initializing TEE OS\n");
	rc = skteed_synchronous_sp_entry(ctx);
	INFO("SKTEED initialized TEE OS\n");
	assert(rc != 0);

	return rc;
}

/*******************************************************************************
 * Secure Payload Dispatcher setup. The SPD finds out the SP entrypoint and type
 * (aarch32/aarch64) if not already known and initialises the context for entry
 * into the SP for its initialisation.
 ******************************************************************************/
static int32_t skteed_setup(void) {
	entry_point_info_t *ep_info;
	uint32_t linear_id;

	linear_id = plat_my_core_pos();

	/*
	 * Get information about the Secure Payload (BL32) image. Its
	 * absence is a critical failure.  TODO: Add support to
	 * conditionally include the SPD service
	 */
	ep_info = bl31_plat_get_next_image_ep_info(SECURE);
	if (!ep_info) {
		WARN("No Secure Payload  provided by BL2 boot loader, Booting device"
			" without SP initialization. SMC`s destined for SP"
			" will return SMC_UNK\n");
		return 1;
	}

	/*
	 * If there's no valid entry point for SP, we return a non-zero value
	 * signalling failure initializing the service. We bail out without
	 * registering any handlers
	 */
	if (!ep_info->pc)
		return 1;

	/*
	 * We could inspect the SP image and determine its execution
	 * state i.e whether AArch32 or AArch64. Assuming it's AArch64
	 * for the time being.
	 */
	skteed_init_ep_state(
		ep_info,
		ep_info->pc,
		&skteed_sp_context[linear_id]
	);

	bl31_register_bl32_init(&skteed_init);
	return 0;
}

/*
 * This helper function handles Secure EL1 preemption. The preemption could be
 * due Non Secure interrupts or EL3 interrupts. In both the cases we context
 * switch to the normal world and in case of EL3 interrupts, it will again be
 * routed to EL3 which will get handled at the exception vectors.
 */
static uint64_t skteed_handle_sp_preemption(void *handle) {
	cpu_context_t *ns_cpu_context;

	assert(handle == cm_get_context(SECURE));
	cm_el1_sysregs_context_save(SECURE);

	/* Get a reference to the non-secure context */
	ns_cpu_context = cm_get_context(NON_SECURE);
	assert(ns_cpu_context);

	/*
	 * To allow Secure EL1 interrupt handler to re-enter TSP while TSP
	 * is preempted, the secure system register context which will get
	 * overwritten must be additionally saved. This is currently done
	 * by the TSPD S-EL1 interrupt handler.
	 */

	/*
	 * Restore non-secure state.
	 */
	cm_el1_sysregs_context_restore(NON_SECURE);
	cm_set_next_eret_context(NON_SECURE);

	/*
	 * The TSP was preempted during execution of a Yielding SMC Call.
	 * Return back to the normal world with SMC_PREEMPTED as error
	 * code in x0.
	 */
	SMC_RET1(ns_cpu_context, SMC_PREEMPTED);
}

/*******************************************************************************
 * This function is the handler registered for Non secure interrupts by the
 * TSPD. It validates the interrupt and upon success arranges entry into the
 * normal world for handling the interrupt.
 ******************************************************************************/
static uint64_t skteed_ns_interrupt_handler(
	uint32_t id,
	uint32_t flags,
	void *handle,
	void *cookie
) {
	/* Check the security state when the exception was generated */
	assert(get_interrupt_src_ss(flags) == SECURE);

	/*
	 * Disable the routing of NS interrupts from secure world to EL3 while
	 * interrupted on this core.
	 */
	disable_intr_rm_local(INTR_TYPE_NS, SECURE);

	return skteed_handle_sp_preemption(handle);
}

/*******************************************************************************
 * This function is responsible for handling all SMCs in the Trusted OS/App
 * range from the non-secure state as defined in the SMC Calling Convention
 * Document. It is also responsible for communicating with the Secure payload
 * to delegate work and return results back to the non-secure state. Lastly it
 * will also return any information that the secure payload needs to do the
 * work assigned to it.
 ******************************************************************************/
static uintptr_t skteed_smc_handler(
	uint32_t smc_fid,
	u_register_t x1,
	u_register_t x2,
	u_register_t x3,
	u_register_t x4,
	void *cookie,
	void *handle,
	u_register_t flags
) {
	cpu_context_t *s_cpu_context, *ns_cpu_context;
	uint32_t linear_id = plat_my_core_pos(), ns;
	uint64_t rc;
	skteed_context_t *ctx = &skteed_sp_context[linear_id];

	/* Determine which security state this SMC originated from */
	ns = is_caller_non_secure(flags);

	switch (smc_fid) {
	case SKTEED_SMC_ENTRY_DONE:
		if (ns) {
			SMC_RET1(handle, SMC_UNK);
		}
		assert(skteed_vectors == NULL);
		// The TEE initializer is expected to return the vectors in x1.
		skteed_vectors = (skteed_vectors_t *)x1;
		assert(skteed_vectors);


		/*
		 * Register an interrupt handler for NS interrupts when
		 * generated during code executing in secure state are
		 * routed to EL3.
		 */
		flags = 0;
		set_interrupt_rm_flag(flags, SECURE);

		rc = register_interrupt_type_handler(
			INTR_TYPE_NS,
			skteed_ns_interrupt_handler,
			flags
		);
		if (rc)
			panic();

		/*
		 * Disable the NS interrupt locally.
		 */
		disable_intr_rm_local(INTR_TYPE_NS, SECURE);

		skteed_synchronous_sp_exit(ctx, x1);
		assert(0); /* Unreachable */
		break;
	case SKTEED_SMC_GET_UUID:
		SMC_UUID_RET(handle, skteed_uuid);
		assert(0); /* Unreachable */
		break;
	case SKTEED_SMC_COPY_IPC:
		/* We consider copying the IPC buffer as a blocking operation */
		assert(skteed_vectors);
		if (ns) {
			assert(handle == cm_get_context(NON_SECURE));

			// Store the non-secure context.
			cm_el1_sysregs_context_save(NON_SECURE);
			// Set the entrypoint into the TEE.
			cm_set_elr_el3(SECURE, (uint64_t)&skteed_vectors->fast_smc_entry);

			// Do not route NS interrupts to EL3 during the call!
			disable_intr_rm_local(INTR_TYPE_NS, SECURE);

			ns_cpu_context = cm_get_context(NON_SECURE);

			// Restore the secure context.
			cm_el1_sysregs_context_restore(SECURE);
			// Make sure, we return in secure mode.
			cm_set_next_eret_context(SECURE);
			// Passing the registers to the TEE.
			SMC_RET5(&ctx->cpu_ctx, smc_fid, x1, x2, x3, x4);
		} else {
			// Called from the secure world means that the call was done.
			assert(handle == cm_get_context(SECURE));
			cm_el1_sysregs_context_save(SECURE);
			ns_cpu_context = cm_get_context(NON_SECURE);
			assert(ns_cpu_context);

			/* Restore non-secure state */
			cm_el1_sysregs_context_restore(NON_SECURE);
			cm_set_next_eret_context(NON_SECURE);
			SMC_RET5(ns_cpu_context, SMC_OK, x1, x2, x3, x4);
		}

		assert(0); /* Unreachable */
		break;
	case SKTEED_SMC_LONGRUNNING:
		// Initialization should already have happened.
		assert(skteed_vectors);
		if (ns) {
			assert(handle == cm_get_context(NON_SECURE));
			ns_cpu_context = cm_get_context(NON_SECURE);

			// Store the non-secure context.
			cm_el1_sysregs_context_save(NON_SECURE);

			if (!get_yield_smc_active_flag(ctx->state)) {
				// Set the entrypoint into the TEE.
				cm_set_elr_el3(SECURE, (uint64_t)&skteed_vectors->yielding_smc_entry);
				set_yield_smc_active_flag(ctx->state);

				// Restore the secure context.
				cm_el1_sysregs_context_restore(SECURE);
				// Make sure, we return in secure mode.
				cm_set_next_eret_context(SECURE);

				// Route NS interrupts to EL3 during the call!
				enable_intr_rm_local(INTR_TYPE_NS, SECURE);

				// Passing the registers to the TEE.
				SMC_RET18(&ctx->cpu_ctx, smc_fid, x1, x2, x3, x4, SMC_GET_GP(ns_cpu_context, CTX_GPREG_X5), SMC_GET_GP(ns_cpu_context, CTX_GPREG_X6), SMC_GET_GP(ns_cpu_context, CTX_GPREG_X7), SMC_GET_GP(ns_cpu_context, CTX_GPREG_X8), 0, 0, 0, 0, 0, 0, 0, 0, 0);
			} else {
				set_yield_smc_active_flag(ctx->state);

				// Resume from the preempted state.
				cm_el1_sysregs_context_restore(SECURE);
				cm_set_next_eret_context(SECURE);

				// Route NS interrupts to EL3 during the call!
				enable_intr_rm_local(INTR_TYPE_NS, SECURE);

				SMC_RET0(&ctx->cpu_ctx);
			}

		} else {
			// Called from the secure world means that the call was done.
			assert(handle == cm_get_context(SECURE));
			cm_el1_sysregs_context_save(SECURE);
			s_cpu_context = cm_get_context(SECURE);

			ns_cpu_context = cm_get_context(NON_SECURE);
			assert(ns_cpu_context);

			// Mark the call as done.
			clr_yield_smc_active_flag(ctx->state);

			/* Restore non-secure state */
			cm_el1_sysregs_context_restore(NON_SECURE);
			cm_set_next_eret_context(NON_SECURE);
			SMC_RET18(ns_cpu_context, SMC_OK, x1, x2, x3, x4, SMC_GET_GP(s_cpu_context, CTX_GPREG_X5), SMC_GET_GP(s_cpu_context, CTX_GPREG_X6), SMC_GET_GP(s_cpu_context, CTX_GPREG_X7), SMC_GET_GP(s_cpu_context, CTX_GPREG_X8), 0, 0, 0, 0, 0, 0, 0, 0, 0);
		}
		assert(0); /* Unreachable */
		break;
	default:
		break;
	}
	SMC_RET1(handle, SMC_UNK);
}

DECLARE_RT_SVC(
	skteed_std,
	OEN_TOS_START,
	OEN_TOS_END,
	SMC_TYPE_FAST,
	skteed_setup,
	skteed_smc_handler
);

DECLARE_RT_SVC(
	skteed_yielding,
	OEN_TOS_START,
	OEN_TOS_END,
	SMC_TYPE_YIELD,
	NULL,
	skteed_smc_handler
);
