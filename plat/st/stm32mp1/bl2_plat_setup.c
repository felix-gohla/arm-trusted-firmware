/*
 * Copyright (c) 2015-2021, ARM Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <assert.h>
#include <string.h>

#include <platform_def.h>

#include <arch_helpers.h>
#include <common/bl_common.h>
#include <common/debug.h>
#include <common/desc_image_load.h>
#include <drivers/delay_timer.h>
#include <drivers/generic_delay_timer.h>
#include <drivers/mmc.h>
#include <drivers/st/bsec.h>
#include <drivers/st/stm32_console.h>
#include <drivers/st/stm32_iwdg.h>
#include <drivers/st/stm32mp_pmic.h>
#include <drivers/st/stm32mp_reset.h>
#include <drivers/st/stm32mp1_clk.h>
#include <drivers/st/stm32mp1_pwr.h>
#include <drivers/st/stm32mp1_ram.h>
#include <lib/mmio.h>
#include <lib/optee_utils.h>
#include <lib/xlat_tables/xlat_tables_v2.h>
#include <plat/common/platform.h>

#include <stm32mp1_context.h>
#include <stm32mp1_dbgmcu.h>

#define RESET_TIMEOUT_US_1MS		1000U

static console_t console;
static struct stm32mp_auth_ops stm32mp1_auth_ops;

static void print_reset_reason(void)
{
	uint32_t rstsr = mmio_read_32(stm32mp_rcc_base() + RCC_MP_RSTSCLRR);

	if (rstsr == 0U) {
		WARN("Reset reason unknown\n");
		return;
	}

	INFO("Reset reason (0x%x):\n", rstsr);

	if ((rstsr & RCC_MP_RSTSCLRR_PADRSTF) == 0U) {
		if ((rstsr & RCC_MP_RSTSCLRR_STDBYRSTF) != 0U) {
			INFO("System exits from STANDBY\n");
			return;
		}

		if ((rstsr & RCC_MP_RSTSCLRR_CSTDBYRSTF) != 0U) {
			INFO("MPU exits from CSTANDBY\n");
			return;
		}
	}

	if ((rstsr & RCC_MP_RSTSCLRR_PORRSTF) != 0U) {
		INFO("  Power-on Reset (rst_por)\n");
		return;
	}

	if ((rstsr & RCC_MP_RSTSCLRR_BORRSTF) != 0U) {
		INFO("  Brownout Reset (rst_bor)\n");
		return;
	}

	if ((rstsr & RCC_MP_RSTSCLRR_MCSYSRSTF) != 0U) {
		if ((rstsr & RCC_MP_RSTSCLRR_PADRSTF) != 0U) {
			INFO("  System reset generated by MCU (MCSYSRST)\n");
		} else {
			INFO("  Local reset generated by MCU (MCSYSRST)\n");
		}
		return;
	}

	if ((rstsr & RCC_MP_RSTSCLRR_MPSYSRSTF) != 0U) {
		INFO("  System reset generated by MPU (MPSYSRST)\n");
		return;
	}

	if ((rstsr & RCC_MP_RSTSCLRR_HCSSRSTF) != 0U) {
		INFO("  Reset due to a clock failure on HSE\n");
		return;
	}

	if ((rstsr & RCC_MP_RSTSCLRR_IWDG1RSTF) != 0U) {
		INFO("  IWDG1 Reset (rst_iwdg1)\n");
		return;
	}

	if ((rstsr & RCC_MP_RSTSCLRR_IWDG2RSTF) != 0U) {
		INFO("  IWDG2 Reset (rst_iwdg2)\n");
		return;
	}

	if ((rstsr & RCC_MP_RSTSCLRR_MPUP0RSTF) != 0U) {
		INFO("  MPU Processor 0 Reset\n");
		return;
	}

	if ((rstsr & RCC_MP_RSTSCLRR_MPUP1RSTF) != 0U) {
		INFO("  MPU Processor 1 Reset\n");
		return;
	}

	if ((rstsr & RCC_MP_RSTSCLRR_PADRSTF) != 0U) {
		INFO("  Pad Reset from NRST\n");
		return;
	}

	if ((rstsr & RCC_MP_RSTSCLRR_VCORERSTF) != 0U) {
		INFO("  Reset due to a failure of VDD_CORE\n");
		return;
	}

	ERROR("  Unidentified reset reason\n");
}

void bl2_el3_early_platform_setup(u_register_t arg0,
				  u_register_t arg1 __unused,
				  u_register_t arg2 __unused,
				  u_register_t arg3 __unused)
{
	stm32mp_save_boot_ctx_address(arg0);
}

void bl2_platform_setup(void)
{
	int ret;

	if (dt_pmic_status() > 0) {
		initialize_pmic();
	}

	ret = stm32mp1_ddr_probe();
	if (ret < 0) {
		ERROR("Invalid DDR init: error %d\n", ret);
		panic();
	}

	/* Map DDR for binary load, now with cacheable attribute */
	ret = mmap_add_dynamic_region(STM32MP_DDR_BASE, STM32MP_DDR_BASE,
				      STM32MP_DDR_MAX_SIZE, MT_MEMORY | MT_RW | MT_SECURE);
	if (ret < 0) {
		ERROR("DDR mapping: error %d\n", ret);
		panic();
	}

#if STM32MP_USE_STM32IMAGE
#ifdef AARCH32_SP_OPTEE
	INFO("BL2 runs OP-TEE setup\n");
#else
	INFO("BL2 runs SP_MIN setup\n");
#endif
#endif /* STM32MP_USE_STM32IMAGE */
}

void bl2_el3_plat_arch_setup(void)
{
	int32_t result;
	struct dt_node_info dt_uart_info;
	const char *board_model;
	boot_api_context_t *boot_context =
		(boot_api_context_t *)stm32mp_get_boot_ctx_address();
	uint32_t clk_rate;
	uintptr_t pwr_base;
	uintptr_t rcc_base;

	mmap_add_region(BL_CODE_BASE, BL_CODE_BASE,
			BL_CODE_END - BL_CODE_BASE,
			MT_CODE | MT_SECURE);

#if STM32MP_USE_STM32IMAGE
#ifdef AARCH32_SP_OPTEE
	mmap_add_region(STM32MP_OPTEE_BASE, STM32MP_OPTEE_BASE,
			STM32MP_OPTEE_SIZE,
			MT_MEMORY | MT_RW | MT_SECURE);
#else
	/* Prevent corruption of preloaded BL32 */
	mmap_add_region(BL32_BASE, BL32_BASE,
			BL32_LIMIT - BL32_BASE,
			MT_RO_DATA | MT_SECURE);
#endif
#endif /* STM32MP_USE_STM32IMAGE */

	/* Prevent corruption of preloaded Device Tree */
	mmap_add_region(DTB_BASE, DTB_BASE,
			DTB_LIMIT - DTB_BASE,
			MT_RO_DATA | MT_SECURE);

	configure_mmu();

	if (dt_open_and_check(STM32MP_DTB_BASE) < 0) {
		panic();
	}

	pwr_base = stm32mp_pwr_base();
	rcc_base = stm32mp_rcc_base();

	/*
	 * Disable the backup domain write protection.
	 * The protection is enable at each reset by hardware
	 * and must be disabled by software.
	 */
	mmio_setbits_32(pwr_base + PWR_CR1, PWR_CR1_DBP);

	while ((mmio_read_32(pwr_base + PWR_CR1) & PWR_CR1_DBP) == 0U) {
		;
	}

	if (bsec_probe() != 0) {
		panic();
	}

	/* Reset backup domain on cold boot cases */
	if ((mmio_read_32(rcc_base + RCC_BDCR) & RCC_BDCR_RTCSRC_MASK) == 0U) {
		mmio_setbits_32(rcc_base + RCC_BDCR, RCC_BDCR_VSWRST);

		while ((mmio_read_32(rcc_base + RCC_BDCR) & RCC_BDCR_VSWRST) ==
		       0U) {
			;
		}

		mmio_clrbits_32(rcc_base + RCC_BDCR, RCC_BDCR_VSWRST);
	}

	/* Disable MCKPROT */
	mmio_clrbits_32(rcc_base + RCC_TZCR, RCC_TZCR_MCKPROT);

	generic_delay_timer_init();

	if (stm32mp1_clk_probe() < 0) {
		panic();
	}

	if (stm32mp1_clk_init() < 0) {
		panic();
	}

	stm32mp1_syscfg_init();

	result = dt_get_stdout_uart_info(&dt_uart_info);

	if ((result <= 0) ||
	    (dt_uart_info.status == 0U) ||
	    (dt_uart_info.clock < 0) ||
	    (dt_uart_info.reset < 0)) {
		goto skip_console_init;
	}

	if (dt_set_stdout_pinctrl() != 0) {
		goto skip_console_init;
	}

	stm32mp_clk_enable((unsigned long)dt_uart_info.clock);

	if (stm32mp_reset_assert((uint32_t)dt_uart_info.reset,
				 RESET_TIMEOUT_US_1MS) != 0) {
		panic();
	}

	udelay(2);

	if (stm32mp_reset_deassert((uint32_t)dt_uart_info.reset,
				   RESET_TIMEOUT_US_1MS) != 0) {
		panic();
	}

	mdelay(1);

	clk_rate = stm32mp_clk_get_rate((unsigned long)dt_uart_info.clock);

	if (console_stm32_register(dt_uart_info.base, clk_rate,
				   STM32MP_UART_BAUDRATE, &console) == 0) {
		panic();
	}

	console_set_scope(&console, CONSOLE_FLAG_BOOT |
			  CONSOLE_FLAG_CRASH | CONSOLE_FLAG_TRANSLATE_CRLF);

	stm32mp_print_cpuinfo();

	board_model = dt_get_board_model();
	if (board_model != NULL) {
		NOTICE("Model: %s\n", board_model);
	}

	stm32mp_print_boardinfo();

	if (boot_context->auth_status != BOOT_API_CTX_AUTH_NO) {
		NOTICE("Bootrom authentication %s\n",
		       (boot_context->auth_status == BOOT_API_CTX_AUTH_FAILED) ?
		       "failed" : "succeeded");
	}

skip_console_init:
	if (stm32_iwdg_init() < 0) {
		panic();
	}

	stm32_iwdg_refresh();

	result = stm32mp1_dbgmcu_freeze_iwdg2();
	if (result != 0) {
		INFO("IWDG2 freeze error : %i\n", result);
	}

	if (stm32_save_boot_interface(boot_context->boot_interface_selected,
				      boot_context->boot_interface_instance) !=
	    0) {
		ERROR("Cannot save boot interface\n");
	}

	stm32mp1_auth_ops.check_key = boot_context->bootrom_ecdsa_check_key;
	stm32mp1_auth_ops.verify_signature =
		boot_context->bootrom_ecdsa_verify_signature;

	stm32mp_init_auth(&stm32mp1_auth_ops);

	stm32mp1_arch_security_setup();

	print_reset_reason();

	stm32mp_io_setup();
}

/*******************************************************************************
 * This function can be used by the platforms to update/use image
 * information for given `image_id`.
 ******************************************************************************/
int bl2_plat_handle_post_image_load(unsigned int image_id)
{
	int err = 0;
	bl_mem_params_node_t *bl_mem_params = get_bl_mem_params_node(image_id);
	bl_mem_params_node_t *bl32_mem_params;
	bl_mem_params_node_t *pager_mem_params __unused;
	bl_mem_params_node_t *paged_mem_params __unused;

	assert(bl_mem_params != NULL);

	switch (image_id) {
	case BL32_IMAGE_ID:
		if (optee_header_is_valid(bl_mem_params->image_info.image_base)) {
			/* BL32 is OP-TEE header */
			bl_mem_params->ep_info.pc = bl_mem_params->image_info.image_base;
			pager_mem_params = get_bl_mem_params_node(BL32_EXTRA1_IMAGE_ID);
			paged_mem_params = get_bl_mem_params_node(BL32_EXTRA2_IMAGE_ID);
			assert((pager_mem_params != NULL) && (paged_mem_params != NULL));

#if STM32MP_USE_STM32IMAGE && defined(AARCH32_SP_OPTEE)
			/* Set OP-TEE extra image load areas at run-time */
			pager_mem_params->image_info.image_base = STM32MP_OPTEE_BASE;
			pager_mem_params->image_info.image_max_size = STM32MP_OPTEE_SIZE;

			paged_mem_params->image_info.image_base = STM32MP_DDR_BASE +
								  dt_get_ddr_size() -
								  STM32MP_DDR_S_SIZE -
								  STM32MP_DDR_SHMEM_SIZE;
			paged_mem_params->image_info.image_max_size = STM32MP_DDR_S_SIZE;
#endif /* STM32MP_USE_STM32IMAGE && defined(AARCH32_SP_OPTEE) */

			err = parse_optee_header(&bl_mem_params->ep_info,
						 &pager_mem_params->image_info,
						 &paged_mem_params->image_info);
			if (err) {
				ERROR("OPTEE header parse error.\n");
				panic();
			}

			/* Set optee boot info from parsed header data */
			bl_mem_params->ep_info.args.arg0 = paged_mem_params->image_info.image_base;
			bl_mem_params->ep_info.args.arg1 = 0; /* Unused */
			bl_mem_params->ep_info.args.arg2 = 0; /* No DT supported */
		} else {
#if !STM32MP_USE_STM32IMAGE
			bl_mem_params->ep_info.pc = bl_mem_params->image_info.image_base;
#endif /* !STM32MP_USE_STM32IMAGE */
			bl_mem_params->ep_info.args.arg0 = 0;
		}
		break;

	case BL33_IMAGE_ID:
		bl32_mem_params = get_bl_mem_params_node(BL32_IMAGE_ID);
		assert(bl32_mem_params != NULL);
		bl32_mem_params->ep_info.lr_svc = bl_mem_params->ep_info.pc;
		break;

	default:
		/* Do nothing in default case */
		break;
	}

#if STM32MP_SDMMC || STM32MP_EMMC
	/*
	 * Invalidate remaining data read from MMC but not flushed by load_image_flush().
	 * We take the worst case which is 2 MMC blocks.
	 */
	if ((image_id != FW_CONFIG_ID) &&
	    ((bl_mem_params->image_info.h.attr & IMAGE_ATTRIB_SKIP_LOADING) == 0U)) {
		inv_dcache_range(bl_mem_params->image_info.image_base +
				 bl_mem_params->image_info.image_size,
				 2U * MMC_BLOCK_SIZE);
	}
#endif /* STM32MP_SDMMC || STM32MP_EMMC */

	return err;
}

void bl2_el3_plat_prepare_exit(void)
{
	stm32mp1_security_setup();
}
