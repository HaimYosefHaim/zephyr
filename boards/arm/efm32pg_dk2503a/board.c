/*
 * Copyright (c) 2018 Christian Taedcke
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/init.h>
// #include "board.h"
#include <zephyr/drivers/gpio.h>
#include <zephyr/sys/printk.h>

static int efm32pg_dk2503a_init(const struct device *dev)
{

	return 0;
}

/* needs to be done after GPIO driver init */
SYS_INIT(efm32pg_dk2503a_init, POST_KERNEL,
	 CONFIG_KERNEL_INIT_PRIORITY_DEVICE);
