/**
 * Copyright (c) 2020 Raspberry Pi (Trading) Ltd.
 * Copyright (c) 2024 Lone Dynamics Corporation <info@lonedynamics.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Blaustahl Firmware (work-in-progress)
 *
 */

#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>
#include <stdarg.h>
#include <strings.h>
#include <string.h>

// Pico
#include "pico/stdlib.h"
#include "hardware/spi.h"
#include "hardware/watchdog.h"
#include "pico/binary_info.h"
#include "pico/multicore.h"
#include "pico/bootrom.h"
#include "pico/util/queue.h"
#include "pico/stdio/driver.h"

#include "hardware/pwm.h"
#include "hardware/pll.h"
#include "hardware/clocks.h"
#include "hardware/structs/pll.h"
#include "hardware/structs/clocks.h"

#include "tusb.h"

#include "blaustahl.h"
#include "editor.h"
#include "fram.h"

void core1_main(void);

void init_blaustahl(void);
bool init_done = false;

// TinyUSB is built with CFG_TUSB_OS=OPT_OS_NONE, so its endpoint claim
// state is not atomic and the device stack has to run on exactly one
// core. core0 owns it. Everything core1 (which runs the whole
// application) sends or receives crosses over through these two byte
// rings, filled and drained by cdc_pump() in core0's loop. When core1
// called tud_cdc_* directly, the two cores could interleave inside a
// claim and leave the CDC OUT endpoint never re-armed. The device then
// stayed enumerated but stopped accepting host bytes entirely.
// Reproduced on hardware.
#define CDC_RX_RING 1024
#define CDC_TX_RING 2048

static queue_t rx_q;
static queue_t tx_q;
static volatile bool cdc_connected = false;

static void cdc_pump(void) {

	cdc_connected = tud_cdc_connected();

	uint8_t buf[64];

	for (;;) {
		// a full rx ring leaves the remaining bytes sitting in the CDC
		// RX FIFO rather than dropping them, so the host still gets the
		// same USB backpressure it got when core1 read that FIFO itself
		uint32_t room = CDC_RX_RING - queue_get_level(&rx_q);
		if (!room || !tud_cdc_available()) break;
		if (room > sizeof(buf)) room = sizeof(buf);
		uint32_t n = tud_cdc_read(buf, room);
		if (!n) break;
		for (uint32_t i = 0; i < n; i++) queue_try_add(&rx_q, &buf[i]);
	}

	bool wrote = false;
	uint8_t ch;

	while (tud_cdc_write_available() && queue_try_remove(&tx_q, &ch)) {
		tud_cdc_write_char((char)ch);
		wrote = true;
	}

	if (wrote) tud_cdc_write_flush();

}

// printf() on core1 used to reach the host through pico_stdio_usb,
// whose out_chars() calls tud_task() itself. That was the second way
// the device stack ended up running on both cores at once, so this
// driver replaces it; it only touches the tx ring. Output is dropped
// once the deadline passes instead of waiting indefinitely, so a
// printf can never wedge core1 when the host stops reading.
#define STDIO_TX_TIMEOUT_MS 500

static void cdc_stdio_out_chars(const char *buf, int len) {

	if (!cdc_connected) return;

	absolute_time_t deadline = make_timeout_time_ms(STDIO_TX_TIMEOUT_MS);

	for (int i = 0; i < len; i++) {
		uint8_t ch = (uint8_t)buf[i];
		while (!queue_try_add(&tx_q, &ch)) {
			if (!cdc_connected || time_reached(deadline)) return;
		}
	}

}

static stdio_driver_t cdc_stdio_driver = {
	.out_chars = cdc_stdio_out_chars,
#if PICO_STDIO_ENABLE_CRLF_SUPPORT
	// pico_stdio_usb defaulted PICO_STDIO_USB_DEFAULT_CRLF to
	// PICO_STDIO_DEFAULT_CRLF, so the same value keeps printf output
	// byte-identical to before
	.crlf_enabled = PICO_STDIO_DEFAULT_CRLF,
#endif
};

#ifndef CDCONLY
void blaustahl_task(void);

void blaustahl_task() {

	uint8_t buf[64];

	if (!tud_vendor_available()) return;

	uint32_t len = tud_vendor_read(buf, 64);

/*
	char tmp[256];
	sprintf(tmp, "RX %d bytes from host\r\n", len);
	tud_cdc_write_str(tmp);
	sprintf(tmp, "[%x %x %x %x]\r\n", buf[0], buf[1], buf[2], buf[3]);
	tud_cdc_write_str(tmp);
	tud_cdc_write_flush();
*/

	if (buf[0] == BS_CMD_NOP) {
	}

	if (buf[0] == BS_CMD_READ_BYTE) {
		int addr = buf[1] << 8 | buf[2];
      uint8_t lbuf[64];
      bzero(lbuf, 64);
		fram_read(lbuf, addr, 1);
      tud_vendor_write(lbuf, 64);
      tud_vendor_flush();
	}

	if (buf[0] == BS_CMD_WRITE_BYTE) {
		int addr = buf[1] << 8 | buf[2];
		fram_write_enable();
		fram_write(addr, buf[3]);
	}

}
#endif

void init_blaustahl(void) {

	printf("init_blaustahl\r\n");

	// init LED
	gpio_init(BS_LED);
	gpio_set_dir(BS_LED, 1);
	gpio_set_function(BS_LED, GPIO_FUNC_PWM);
	gpio_set_outover(BS_LED, GPIO_OVERRIDE_INVERT);

	uint slice_num = pwm_gpio_to_slice_num(BS_LED);
	pwm_set_wrap(slice_num, 499);
	pwm_set_chan_level(slice_num, BS_LED, LED_STARTUP);
	pwm_set_clkdiv_int_frac(slice_num, 250, 0);
	pwm_set_enabled(slice_num, true);

	// init FRAM
	fram_init();

}

int main(void) {

	// set the sys clock to 120mhz
	set_sys_clock_khz(120000, true);

	// init tinyusb
	tud_init(BOARD_TUD_RHPORT);

	// must precede the first printf() and the core1 launch below, both
	// of which reach these rings
	queue_init(&rx_q, 1, CDC_RX_RING);
	queue_init(&tx_q, 1, CDC_TX_RING);

	// init stdio
	stdio_set_driver_enabled(&cdc_stdio_driver, true);

	// init hardware
	init_blaustahl();

	// arm this core (core0) as a lockout "victim" so that core1 -- where
	// the CLI's format command and FRAM snapshot actually run -- can
	// safely pause core0 via flash_safe_execute() during a flash erase/
	// program. Without this, flash_safe_execute() has no way to stop
	// core0 from fetching instructions out of flash (XIP) while the
	// chip is mid-erase, which can hang or crash the device. Must be
	// called before core1 is launched below. See flash_storage.c for
	// the full explanation.
	multicore_lockout_victim_init();

	// start editor on second core
   multicore_reset_core1();
   multicore_launch_core1(core1_main);

	// handle USB tasks
	while (1) {

		tight_loop_contents();
		tud_task();
		cdc_pump();
#ifndef CDCONLY
		blaustahl_task();
#endif

	}

	return 0;

}

volatile uint32_t core1_heartbeat = 0;
volatile uint8_t core1_phase = PH_IDLE;

extern uint32_t __scratch_x_end__;
extern uint32_t __StackOneBottom;
#define STACK_PAINT 0xa5a5a5a5u

// paint the whole free part of SCRATCH_X below the current stack
// pointer so the dump can report how deep core1's stack ever went,
// including past the 2KB reservation (__StackOneBottom)
static void core1_paint_stack(void) {
	uint32_t sp;
	__asm volatile ("mov %0, sp" : "=r" (sp));
	for (uint32_t *p = &__scratch_x_end__; (uint32_t)p < sp - 64; p++)
		*p = STACK_PAINT;
}

static uint32_t core1_stack_low_water(void) {
	for (uint32_t *p = &__scratch_x_end__; (uint32_t)p < 0x20041000u; p++)
		if (*p != STACK_PAINT) return (uint32_t)p;
	return 0x20041000u;
}

void core1_main(void) {

	core1_paint_stack();
	sleep_ms(10);

	while (true) {
		core1_heartbeat++;
		core1_phase = PH_IDLE;
		if (!init_done && cdc_connected) {
			init_done = true;
			editor_init();
		} else {
			editor_yield();
		}
	}

}

int cdc_getchar(void) {
	uint8_t ch;
	if (queue_try_remove(&rx_q, &ch)) return((int)ch);
	return(EOF);
}

void cdc_putchar(const char ch) {
	uint8_t b = (uint8_t)ch;
	if (cdc_connected)
		queue_try_add(&tx_q, &b);
}

// like cdc_putchar(), but waits (briefly, bounded) for ring space
// instead of silently dropping the byte if none is available right
// now. cdc_putchar()'s drop-on-full behavior is exactly right for
// echoing single keystrokes -- losing one occasionally is harmless,
// and blocking forever there could hang the whole UI if the host
// isn't reading. But a sender writing many bytes back-to-back in a
// tight loop with no pauses (XMODEM's block transmission is the one
// place in this firmware that does that -- 133 bytes per block, no
// delay between them) can genuinely outrun the host's USB polling
// and fill the buffer mid-write; a single dropped byte there
// corrupts that block's framing entirely, which running was the
// actual cause of transfers that silently never completed. Returns
// false (rather than hanging indefinitely) if the host stops reading
// altogether -- e.g. disconnected mid-transfer -- so the caller can
// abort cleanly instead of blocking forever. The disconnect is
// re-checked inside the wait, not just on entry, because once the host
// is gone the ring stops draining entirely and an entry-only check
// would burn the full timeout on every remaining byte of the transfer.
bool cdc_putchar_reliable(const char ch) {

	if (!cdc_connected) return false;

	uint8_t b = (uint8_t)ch;
	absolute_time_t deadline = make_timeout_time_ms(1000);

	while (!queue_try_add(&tx_q, &b)) {
		if (!cdc_connected) return false;
		if (time_reached(deadline)) return false;
	}

	return true;

}

bool cdc_write_reliable(const uint8_t *buf, uint32_t len) {

	for (uint32_t i = 0; i < len; i++)
		if (!cdc_putchar_reliable((char)buf[i])) return false;

	return true;

}

// Magic-baud recovery, in the spirit of the RP2040/Arduino "1200 baud
// touch" convention. This callback runs from tud_task() on CORE0 --
// which means it still works when core1 (the whole application) is
// wedged: a runaway Scheme evaluation, a stuck blocking transfer,
// anything. Before this existed, the only way out of a core1 hang was
// physically unplugging the device (demonstrated on real hardware via
// a runaway interpreter evaluation; USB stayed enumerated the whole
// time, since core0 was fine).
//
//   stty -F /dev/ttyACMx 1200   -> reboot into the UF2 bootloader
//   stty -F /dev/ttyACMx 2400   -> plain application reboot
//
// Neither rate is otherwise meaningful to a device whose CDC ignores
// baud entirely, so there's no accidental-trigger surface.
void tud_cdc_line_coding_cb(uint8_t itf, cdc_line_coding_t const *coding) {
	(void)itf;
	if (coding->bit_rate == 1200) reset_usb_boot(0, 0);
	if (coding->bit_rate == 2400) watchdog_reboot(0, 0, 100);
	if (coding->bit_rate == 4800) {
		// diagnostic dump, produced entirely on core0 inside tud_task
		// context so it works whatever state core1 is in
		uint32_t hb0 = core1_heartbeat;
		sleep_ms(300);
		uint32_t hb1 = core1_heartbeat;
		struct mallinfo mi = mallinfo();
		char line[256];
		snprintf(line, sizeof(line),
			"\r\nDIAG hb=%lu dhb=%lu phase=%u rxavail=%lu txavail=%lu "
			"rxq=%lu/%u txq=%lu/%u "
			"heap_used=%u heap_free=%u stack1_low=0x%08lx stack1_bottom=0x%08lx\r\n",
			(unsigned long)hb1, (unsigned long)(hb1 - hb0), core1_phase,
			(unsigned long)tud_cdc_available(),
			(unsigned long)tud_cdc_write_available(),
			(unsigned long)queue_get_level(&rx_q), CDC_RX_RING,
			(unsigned long)queue_get_level(&tx_q), CDC_TX_RING,
			mi.uordblks, mi.fordblks,
			(unsigned long)core1_stack_low_water(),
			(unsigned long)(uint32_t)&__StackOneBottom);
		tud_cdc_write_str(line);
		tud_cdc_write_flush();
	}
}

// control LED
void blaustahl_led(uint16_t intensity) {
	pwm_set_gpio_level(BS_LED, intensity);
}

// enter DFU mode
void blaustahl_dfu(void) {
	reset_usb_boot(0, 0);
}
