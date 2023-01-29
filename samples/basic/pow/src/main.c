/*
 * Copyright (c) 2016 Intel Corporation.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* Sample to illustrate the usage of crypto APIs. The sample plaintext
 * and ciphertexts used for crosschecking are from TinyCrypt.
 */

#include <zephyr/device.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/kernel.h>
#include <string.h>
#include <zephyr/crypto/crypto.h>
#include <zephyr/sys/crc.h>

#define LOG_LEVEL CONFIG_CRYPTO_LOG_LEVEL
#include <zephyr/logging/log.h>
#include "cobs.h"

LOG_MODULE_REGISTER(main);

/*
 * Get button configuration from the devicetree sw0 alias. This is mandatory.
 */
#define SW0_NODE	DT_ALIAS(sw0)
#if !DT_NODE_HAS_STATUS(SW0_NODE, okay)
#error "Unsupported board: sw0 devicetree alias is not defined"
#endif
static const struct gpio_dt_spec button = GPIO_DT_SPEC_GET_OR(SW0_NODE, gpios,
							      {0});

#define CRYPTO_DRV_NAME CONFIG_CRYPTO_MBEDTLS_SHIM_DRV_NAME

/* change this to any other UART peripheral if desired */
#define UART_DEVICE_NODE DT_CHOSEN(zephyr_shell_uart)

#define MSG_SIZE 52

/* queue to store up to 10 messages (aligned to 4-byte boundary) */
K_MSGQ_DEFINE(uart_msgq, MSG_SIZE, 10, 4);

static const struct device *const uart_dev = DEVICE_DT_GET(UART_DEVICE_NODE);
static struct device *dev;

/* receive buffer used in UART ISR callback */
static char rx_buf[MSG_SIZE];
static int rx_buf_pos;

/*
 * Read characters from UART until line end is detected. Afterwards push the
 * data to the message queue.
 */
void serial_cb(const struct device *dev, void *user_data)
{
	uint8_t c;

	if (!uart_irq_update(uart_dev)) {
		return;
	}

	while (uart_irq_rx_ready(uart_dev)) {

		uart_fifo_read(uart_dev, &c, 1);

		if ((c == 0) && rx_buf_pos > 0) {
			/* terminate string */
			rx_buf[rx_buf_pos] = 0;
			
			/* if queue is full, message is silently dropped */
			k_msgq_put(&uart_msgq, &rx_buf, K_NO_WAIT);
			k_msgq_put(&uart_msgq, &rx_buf_pos, K_NO_WAIT);
			
			/* reset the buffer (it was copied to the msgq) */
			rx_buf_pos = 0;
		} else if (rx_buf_pos < (sizeof(rx_buf) - 1)) {
			rx_buf[rx_buf_pos++] = c;
		}
		/* else: characters beyond buffer size are dropped */
	}
}

uint32_t cap_flags;

int validate_hw_compatibility(const struct device *dev)
{
	uint32_t flags = 0U;

	flags = crypto_query_hwcaps(dev);
	if ((flags & CAP_RAW_KEY) == 0U) {
		LOG_INF("Please provision the key separately "
			"as the module doesnt support a raw key");
		return -1;
	}

	if ((flags & CAP_SYNC_OPS) == 0U) {
		LOG_ERR("The app assumes sync semantics. "
		  "Please rewrite the app accordingly before proceeding");
		return -1;
	}

	if ((flags & CAP_SEPARATE_IO_BUFS) == 0U) {
		LOG_ERR("The app assumes distinct IO buffers. "
		"Please rewrite the app accordingly before proceeding");
		return -1;
	}

	cap_flags = CAP_RAW_KEY | CAP_SYNC_OPS | CAP_SEPARATE_IO_BUFS | CAP_NO_IV_PREFIX;

	return 0;

}

static uint32_t create_mac(uint8_t *payload, size_t len, uint8_t* p_key)
{
	(void *)payload;
	(void *)len;
	(void *)p_key;
	// TODO: implement
	return 0x1234;
}

static void aes_encrypt(void *in_data, void *out_data, size_t len, uint8_t* iv, uint8_t* p_key)
{
	struct cipher_ctx ini = {
		.keylen = 16,
		.key.bit_stream = p_key,
		.flags = cap_flags,
	};

	struct cipher_pkt encrypt = {
		.in_buf = in_data,
		.in_len = len,
		.out_buf_max = len,
		.out_buf = out_data,
	};

	if (cipher_begin_session(dev, &ini, CRYPTO_CIPHER_ALGO_AES,
				CRYPTO_CIPHER_MODE_CBC,
				CRYPTO_CIPHER_OP_ENCRYPT)) {
	return;
	}

	if (cipher_cbc_op(&ini, &encrypt, iv)) {
		LOG_ERR("CBC mode ENCRYPT - Failed");
	}

	cipher_free_session(dev, &ini);
}

struct mode_test {
	const char *mode;
	void (*mode_func)(const struct device *dev);
};

typedef struct cmd {
	uint8_t data[16];
	uint8_t mac_key[16];
	uint8_t enc_key[16];
	uint16_t crc;
} cmd_t;

typedef struct response {
	uint8_t ack_nack;
	uint32_t counter;
	uint8_t data[16];
	uint16_t crc;
	uint32_t mac;
	uint16_t crc_all;
} response_t;

typedef struct response_nack {
	uint8_t ack_nack;
	uint8_t reason;
	uint16_t crc;
} response_nack_t;

void main(void)
{
	uint8_t packet_in[MSG_SIZE];
	uint8_t cobs_out[MSG_SIZE];
	response_t response;
	uint8_t packet_out[MSG_SIZE];
	dev = device_get_binding(CRYPTO_DRV_NAME);

	if (!dev) {
		LOG_ERR("%s pseudo device not found", CRYPTO_DRV_NAME);
		return;
	}
	
	if (validate_hw_compatibility(dev)) {
		LOG_ERR("Incompatible h/w");
		return;
	}

	if (!gpio_is_ready_dt(&button)) {
		printk("Error: button device %s is not ready\n",
		       button.port->name);
		return;
	}

	int ret = gpio_pin_configure_dt(&button, GPIO_INPUT);
	if (ret != 0) {
		printk("Error %d: failed to configure %s pin %d\n",
		       ret, button.port->name, button.pin);
		return;
	}

	/* configure interrupt and callback to receive data */
	ret = uart_irq_callback_user_data_set(uart_dev, serial_cb, NULL);

	if (ret < 0) {
		if (ret == -ENOTSUP) {
			printk("Interrupt-driven UART API support not enabled\n");
		} else if (ret == -ENOSYS) {
			printk("UART device does not support interrupt-driven API\n");
		} else {
			printk("Error setting UART callback: %d\n", ret);
		}
		return;
	}
	uart_irq_rx_enable(uart_dev);

	/* indefinitely wait for input from the user */
	while (k_msgq_get(&uart_msgq, &packet_in, K_FOREVER) == 0) {
		int packet_in_len;
		k_msgq_get(&uart_msgq, &packet_in_len, K_FOREVER);

		uint32_t response_len = 0;

		int val = gpio_pin_get_dt(&button);
		if (val == 1) //TODO: fix
		{
			response_nack_t response_nack = {
				.ack_nack = 0,
				.reason = 17,
			};

			response_nack.crc = crc16_ccitt(0xFFFF, (const uint8_t *)&response_nack, 2);

			response_len += sizeof(response_nack);
			

			cobs_encode_result res_enc = cobs_encode(packet_out, MSG_SIZE, (const uint8_t *)&response_nack, response_len);
			
			if (res_enc.status != COBS_ENCODE_OK)
			{
				continue;
			}

			for(uint32_t i = 0; i < res_enc.out_len; i++) {
				uart_poll_out(uart_dev, packet_out[i]);
			}
	
			uart_poll_out(uart_dev, 0);

			continue;
		}
		else
		{
			cobs_decode_result res_dec = cobs_decode(cobs_out, MSG_SIZE, packet_in, packet_in_len);

			if (res_dec.status != COBS_DECODE_OK)
			{
				continue;
			}

			response.ack_nack = 1;

			cmd_t* p_cmd = (cmd_t *)cobs_out;

			memcpy(response.data, p_cmd->data, 16);
			
			response.mac = create_mac(p_cmd->data, 16, p_cmd->mac_key);

			uint8_t iv[16] = {0};
			aes_encrypt(response.data, response.data, sizeof(response.data), iv, p_cmd->enc_key);

			response.crc = crc16_ccitt(0xFFFF, (const uint8_t *)&response, 15);

			cobs_encode_result res_enc = cobs_encode(packet_out, MSG_SIZE, (const uint8_t *)&response, sizeof(response));

			if (res_enc.status != COBS_ENCODE_OK)
			{
				continue;
			}

			for(uint32_t i = 0; i < res_enc.out_len; i++) {
				uart_poll_out(uart_dev, packet_out[i]);
			}
	
			uart_poll_out(uart_dev, 0);
		}
	}
}
