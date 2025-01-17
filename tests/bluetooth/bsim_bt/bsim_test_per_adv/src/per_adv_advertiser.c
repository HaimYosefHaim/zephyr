/*
 * Copyright (c) 2023 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <zephyr/kernel.h>

#include "bs_types.h"
#include "bs_tracing.h"
#include "time_machine.h"
#include "bstests.h"

#include <zephyr/types.h>
#include <zephyr/sys/printk.h>

#include <zephyr/bluetooth/bluetooth.h>

#include "common.h"

extern enum bst_result_t bst_result;

static struct bt_conn *g_conn;

CREATE_FLAG(flag_connected);
CREATE_FLAG(flag_bonded);

static void connected(struct bt_conn *conn, uint8_t err)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

	if (err != BT_HCI_ERR_SUCCESS) {
		FAIL("Failed to connect to %s: %u\n", addr, err);
		return;
	}

	printk("Connected to %s\n", addr);
	g_conn = bt_conn_ref(conn);
	SET_FLAG(flag_connected);
}

static void disconnected(struct bt_conn *conn, uint8_t reason)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

	printk("Disconnected: %s (reason %u)\n", addr, reason);

	bt_conn_unref(g_conn);
	g_conn = NULL;
}

static struct bt_conn_cb conn_cbs = {
	.connected = connected,
	.disconnected = disconnected,
};

static void pairing_complete_cb(struct bt_conn *conn, bool bonded)
{
	if (conn == g_conn && bonded) {
		SET_FLAG(flag_bonded);
	}
}

static struct bt_conn_auth_info_cb auto_info_cbs = {
	.pairing_complete = pairing_complete_cb,
};

static void common_init(void)
{
	int err;

	err = bt_enable(NULL);

	if (err) {
		FAIL("Bluetooth init failed: %d\n", err);
		return;
	}
	printk("Bluetooth initialized\n");

	bt_conn_cb_register(&conn_cbs);
	bt_conn_auth_info_cb_register(&auto_info_cbs);
}

static void create_per_adv_set(struct bt_le_ext_adv **adv)
{
	int err;

	printk("Creating extended advertising set...");
	err = bt_le_ext_adv_create(BT_LE_EXT_ADV_NCONN_NAME, NULL, adv);
	if (err) {
		printk("Failed to create advertising set: %d\n", err);
		return;
	}
	printk("done.\n");

	printk("Setting periodic advertising parameters...");
	err = bt_le_per_adv_set_param(*adv, BT_LE_PER_ADV_DEFAULT);
	if (err) {
		printk("Failed to set periodic advertising parameters: %d\n",
		       err);
		return;
	}
	printk("done.\n");
}

static void create_conn_adv_set(struct bt_le_ext_adv **adv)
{
	int err;

	printk("Creating connectable extended advertising set...");
	err = bt_le_ext_adv_create(BT_LE_EXT_ADV_CONN_NAME, NULL, adv);
	if (err) {
		printk("Failed to create advertising set: %d\n", err);
		return;
	}
	printk("done.\n");
}

static void start_ext_adv_set(struct bt_le_ext_adv *adv)
{
	int err;

	printk("Starting Extended Advertising...");
	err = bt_le_ext_adv_start(adv, BT_LE_EXT_ADV_START_DEFAULT);
	if (err) {
		printk("Failed to start extended advertising: %d\n", err);
		return;
	}
	printk("done.\n");
}

static void start_per_adv_set(struct bt_le_ext_adv *adv)
{
	int err;

	printk("Starting periodic advertising...");
	err = bt_le_per_adv_start(adv);
	if (err) {
		printk("Failed to start periodic advertising: %d\n", err);
		return;
	}
	printk("done.\n");
}

static void stop_ext_adv_set(struct bt_le_ext_adv *adv)
{
	int err;

	printk("Stopping Extended Advertising...");
	err = bt_le_ext_adv_stop(adv);
	if (err) {
		printk("Failed to stop extended advertising: %d\n",
		       err);
		return;
	}
	printk("done.\n");
}

static void stop_per_adv_set(struct bt_le_ext_adv *adv)
{
	int err;

	printk("Stopping Periodic Advertising...");
	err = bt_le_per_adv_stop(adv);
	if (err) {
		printk("Failed to stop periodic advertising: %d\n",
		       err);
		return;
	}
	printk("done.\n");
}

static void delete_adv_set(struct bt_le_ext_adv *adv)
{
	int err;

	printk("Delete extended advertising set...");
	err = bt_le_ext_adv_delete(adv);
	if (err) {
		printk("Failed Delete extended advertising set: %d\n", err);
		return;
	}
	printk("done.\n");
}

static void main_per_adv_advertiser(void)
{
	struct bt_le_ext_adv *per_adv;

	common_init();

	create_per_adv_set(&per_adv);

	start_per_adv_set(per_adv);
	start_ext_adv_set(per_adv);

	/* Advertise for a bit */
	k_sleep(K_SECONDS(10));

	stop_per_adv_set(per_adv);
	stop_ext_adv_set(per_adv);

	delete_adv_set(per_adv);
	per_adv = NULL;

	PASS("Periodic advertiser passed\n");
}

static void main_per_adv_conn_advertiser(void)
{
	struct bt_le_ext_adv *conn_adv;
	struct bt_le_ext_adv *per_adv;

	common_init();

	create_per_adv_set(&per_adv);
	create_conn_adv_set(&conn_adv);

	start_per_adv_set(per_adv);
	start_ext_adv_set(per_adv);
	start_ext_adv_set(conn_adv);

	WAIT_FOR_FLAG(flag_connected);

	/* Advertise for a bit */
	k_sleep(K_SECONDS(10));

	stop_per_adv_set(per_adv);
	stop_ext_adv_set(per_adv);
	stop_ext_adv_set(conn_adv);

	delete_adv_set(per_adv);
	per_adv = NULL;
	delete_adv_set(conn_adv);
	conn_adv = NULL;

	PASS("Periodic advertiser passed\n");
}

static void main_per_adv_conn_privacy_advertiser(void)
{
	struct bt_le_ext_adv *conn_adv;
	struct bt_le_ext_adv *per_adv;

	common_init();

	create_conn_adv_set(&conn_adv);

	start_ext_adv_set(conn_adv);

	WAIT_FOR_FLAG(flag_connected);
	WAIT_FOR_FLAG(flag_bonded);

	/* Start periodic advertising after bonding so that the scanner gets
	 * the resolved address
	 */
	create_per_adv_set(&per_adv);
	start_per_adv_set(per_adv);
	start_ext_adv_set(per_adv);

	/* Advertise for a bit */
	k_sleep(K_SECONDS(10));

	stop_per_adv_set(per_adv);
	stop_ext_adv_set(per_adv);
	stop_ext_adv_set(conn_adv);

	delete_adv_set(per_adv);
	per_adv = NULL;
	delete_adv_set(conn_adv);
	conn_adv = NULL;

	PASS("Periodic advertiser passed\n");
}

static const struct bst_test_instance per_adv_advertiser[] = {
	{
		.test_id = "per_adv_advertiser",
		.test_descr = "Basic periodic advertising test. "
			      "Will just start periodic advertising.",
		.test_post_init_f = test_init,
		.test_tick_f = test_tick,
		.test_main_f = main_per_adv_advertiser
	},
	{
		.test_id = "per_adv_conn_advertiser",
		.test_descr = "Periodic advertising test with concurrent ACL "
			      "and PA sync.",
		.test_post_init_f = test_init,
		.test_tick_f = test_tick,
		.test_main_f = main_per_adv_conn_advertiser
	},
	{
		.test_id = "per_adv_conn_privacy_advertiser",
		.test_descr = "Periodic advertising test with concurrent ACL "
			      "with bonding and PA sync.",
		.test_post_init_f = test_init,
		.test_tick_f = test_tick,
		.test_main_f = main_per_adv_conn_privacy_advertiser
	},
	BSTEST_END_MARKER
};

struct bst_test_list *test_per_adv_advertiser(struct bst_test_list *tests)
{
	return bst_add_tests(tests, per_adv_advertiser);
}
