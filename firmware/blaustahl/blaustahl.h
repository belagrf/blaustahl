/**
 * Copyright (c) 2020 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef BLAUSTAHL_H_
#define BLAUSTAHL_H_

#include <stdint.h>

#define BLAUSTAHL_VERSION "0.2.0-hardened"

#define FRAM_SIZE 8192		// 8KB
//#define FRAM_SIZE 262144	// 256KB

#define FRAM_METADATA 512	// reserved for encryption
#define FRAM_AVAILABLE (FRAM_SIZE - FRAM_METADATA)

#if FRAM_SIZE >= 262144
 #define FRAM_BIG
#endif

#include <stdbool.h>

int cdc_getchar(void);
void cdc_putchar(const char ch);

// like cdc_putchar() but waits (bounded) for CDC TX FIFO space
// instead of silently dropping when it's full -- required for any
// multi-byte payload whose framing can't survive a lost byte (XMODEM
// blocks, SRWP replies). Previously defined in blaustahl.c but never
// declared anywhere, so xmodem.c was calling it through an implicit
// declaration. Returns false if the host stopped reading.
bool cdc_putchar_reliable(const char ch);

void blaustahl_led(uint16_t intensity);
void blaustahl_dfu(void);

// core1 liveness instrumentation, read by core0 on a 4800-baud touch
enum core1_phase {
	PH_IDLE = 0, PH_KDF, PH_CRYPT, PH_JOURNAL, PH_FLASH,
	PH_XMODEM, PH_MS_EVAL, PH_TE,
};
extern volatile uint32_t core1_heartbeat;
extern volatile uint8_t core1_phase;

// USB VENDOR CLASS COMMANDS

#define BS_CMD_NOP			0x00
#define BS_CMD_WRITE_BYTE	0x21	// <cmd> <addr:16> <data:8>
#define BS_CMD_READ_BYTE	0x31	// <cmd> <addr:16>

// PINS

#define BS_LED 			9

#define BS_FRAM_SPI		spi1
#define BS_FRAM_MOSI		11
#define BS_FRAM_MISO		12
#define BS_FRAM_SS		13
#define BS_FRAM_SCK		14

// LED SETTINGS

#define LED_STARTUP 100
#define LED_IDLE 0
#define LED_READ 100
#define LED_WRITE 250

#endif
