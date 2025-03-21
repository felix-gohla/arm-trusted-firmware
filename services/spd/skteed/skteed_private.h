/*
 * Copyright (c) 2013-2021, ARM Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef SKTEED_PRIVATE_H
#define SKTEED_PRIVATE_H

#include <platform_def.h>

#include <arch.h>
#include <bl31/interrupt_mgmt.h>
#include <context.h>
#include <lib/psci/psci.h>

/*
 * The number of arguments to save during a SMC call for TSP.
 * Currently only x1 and x2 are used by TSP.
 */
#define TSP_NUM_ARGS	0x2

/*******************************************************************************
 * Number of cpus that the present on this platform. TODO: Rely on a topology
 * tree to determine this in the future to avoid assumptions about mpidr
 * allocation
 ******************************************************************************/
#define SKTEED_CORE_COUNT		PLATFORM_CORE_COUNT

/*******************************************************************************
 * Constants that allow assembler code to preserve callee-saved registers of the
 * C runtime context while performing a security state switch.
 ******************************************************************************/
#define SKTEED_C_RT_CTX_X19		0x0
#define SKTEED_C_RT_CTX_X20		0x8
#define SKTEED_C_RT_CTX_X21		0x10
#define SKTEED_C_RT_CTX_X22		0x18
#define SKTEED_C_RT_CTX_X23		0x20
#define SKTEED_C_RT_CTX_X24		0x28
#define SKTEED_C_RT_CTX_X25		0x30
#define SKTEED_C_RT_CTX_X26		0x38
#define SKTEED_C_RT_CTX_X27		0x40
#define SKTEED_C_RT_CTX_X28		0x48
#define SKTEED_C_RT_CTX_X29		0x50
#define SKTEED_C_RT_CTX_X30		0x58
#define SKTEED_C_RT_CTX_SIZE		0x60
#define SKTEED_C_RT_CTX_ENTRIES		(SKTEED_C_RT_CTX_SIZE >> DWORD_SHIFT)

/*******************************************************************************
 * Constants that allow assembler code to preserve caller-saved registers of the
 * SP context while performing a TSP preemption.
 * Note: These offsets have to match with the offsets for the corresponding
 * registers in cpu_context as we are using memcpy to copy the values from
 * cpu_context to sp_ctx.
 ******************************************************************************/
#define SKTEED_SP_CTX_X0		0x0
#define SKTEED_SP_CTX_X1		0x8
#define SKTEED_SP_CTX_X2		0x10
#define SKTEED_SP_CTX_X3		0x18
#define SKTEED_SP_CTX_X4		0x20
#define SKTEED_SP_CTX_X5		0x28
#define SKTEED_SP_CTX_X6		0x30
#define SKTEED_SP_CTX_X7		0x38
#define SKTEED_SP_CTX_X8		0x40
#define SKTEED_SP_CTX_X9		0x48
#define SKTEED_SP_CTX_X10		0x50
#define SKTEED_SP_CTX_X11		0x58
#define SKTEED_SP_CTX_X12		0x60
#define SKTEED_SP_CTX_X13		0x68
#define SKTEED_SP_CTX_X14		0x70
#define SKTEED_SP_CTX_X15		0x78
#define SKTEED_SP_CTX_X16		0x80
#define SKTEED_SP_CTX_X17		0x88
#define SKTEED_SP_CTX_SIZE		0x90
#define SKTEED_SP_CTX_ENTRIES		(SKTEED_SP_CTX_SIZE >> DWORD_SHIFT)

// Exclude the definitions down below from assembler usage.
#ifndef __ASSEMBLER__

#include <stdint.h>

#include <lib/cassert.h>


/*******************************************************************************
 * Structures
 ******************************************************************************/

/**
 * Structure which helps the SPD to maintain the per-cpu state of the SP.
 * 'saved_spsr_el3' - temporary copy to allow S-EL1 interrupt handling when
 *                    the TSP has been preempted.
 * 'saved_elr_el3'  - temporary copy to allow S-EL1 interrupt handling when
 *                    the TSP has been preempted.
 * 'state'          - collection of flags to track SP state e.g. on/off
 * 'mpidr'          - mpidr to associate a context with a cpu
 * 'c_rt_ctx'       - stack address to restore C runtime context from after
 *                    returning from a synchronous entry into the SP.
 * 'cpu_ctx'        - space to maintain SP architectural state
 * 'saved_tsp_args' - space to store arguments for TSP arithmetic operations
 *                    which will queried using the TSP_GET_ARGS SMC by TSP.
 * 'sp_ctx'         - space to save the SEL1 Secure Payload(SP) caller saved
 *                    register context after it has been preempted by an EL3
 *                    routed NS interrupt and when a Secure Interrupt is taken
 *                    to SP.
 */
typedef struct skteed_context {
	uint64_t saved_elr_el3;
	uint32_t saved_spsr_el3;
	uint32_t state;
	uint64_t mpidr;
	uint64_t c_rt_ctx;
	cpu_context_t cpu_ctx;
	uint64_t saved_tsp_args[TSP_NUM_ARGS];
#if TSP_NS_INTR_ASYNC_PREEMPT
	sp_ctx_regs_t sp_ctx;
	bool preempted_by_sel1_intr;
#endif
} skteed_context_t;

typedef uint32_t skteed_vector_isn_t;

typedef struct skteed_vectors {
	tsp_vector_isn_t fast_smc_entry;
} skteed_vectors_t;

/*******************************************************************************
 * Macros and related definitions
 ******************************************************************************/

/*
 * This flag is used by the SKTEED to determine if the TSP is servicing a yielding
 * SMC request prior to programming the next entry into the TSP e.g. if TSP
 * execution is preempted by a non-secure interrupt and handed control to the
 * normal world. If another request which is distinct from what the TSP was
 * previously doing arrives, then this flag will be help the SKTEED to either
 * reject the new request or service it while ensuring that the previous context
 * is not corrupted.
 */
#define YIELD_SMC_ACTIVE_FLAG_SHIFT	2
#define YIELD_SMC_ACTIVE_FLAG_MASK	1
#define get_yield_smc_active_flag(state)				\
				((state >> YIELD_SMC_ACTIVE_FLAG_SHIFT) \
				& YIELD_SMC_ACTIVE_FLAG_MASK)
#define set_yield_smc_active_flag(state)	(state |=		\
					1 << YIELD_SMC_ACTIVE_FLAG_SHIFT)
#define clr_yield_smc_active_flag(state)	(state &=		\
					~(YIELD_SMC_ACTIVE_FLAG_MASK	\
					<< YIELD_SMC_ACTIVE_FLAG_SHIFT))


/*******************************************************************************
 * Function & Data prototypes
 ******************************************************************************/
uint64_t skteed_enter_sp(uint64_t *c_rt_ctx);
void __dead2 skteed_exit_sp(uint64_t c_rt_ctx, uint64_t ret);

#endif /* __ASSEMBLER__ */
#endif /* SKTEED_PRIVATE_H */
