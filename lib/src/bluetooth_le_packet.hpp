/* -*- c -*- */
/*
 * Copyright 2007 - 2012 Mike Ryan, Dominic Spill, Michael Ossmann
 * Copyright 2005, 2006 Free Software Foundation, Inc.
 *
 * This file is part of libbtbb
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libbtbb; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 */
#ifndef INCLUDED_BLUETOOTH_LE_PACKET_H
#define INCLUDED_BLUETOOTH_LE_PACKET_H

#include <cstdint>
#include <cstdio>
#include <cstdlib>

constexpr uint8_t 	MAX_LE_SYMBOLS 	= 64;

constexpr uint32_t 	LE_ADV_AA 		= 0x8E89BED6ul;

constexpr uint8_t 	ADV_IND			= 0;
constexpr uint8_t 	ADV_DIRECT_IND	= 1;
constexpr uint8_t 	ADV_NONCONN_IND	= 2;
constexpr uint8_t 	SCAN_REQ		= 3;
constexpr uint8_t 	SCAN_RSP		= 4;
constexpr uint8_t 	CONNECT_REQ		= 5;
constexpr uint8_t 	ADV_SCAN_IND	= 6;


struct lell_packet {
	// raw unwhitened bytes of packet, including access address
	uint8_t symbols[MAX_LE_SYMBOLS];

	uint32_t access_address;

	// channel index
	uint8_t channel_idx;
	uint8_t channel_k;

	// number of symbols
	uint32_t length;

	uint32_t clk100ns;

	// advertising packet header info
	uint8_t adv_type;
    int32_t adv_tx_add;
    int32_t adv_rx_add;

    uint32_t access_address_offenses;
	uint32_t refcount;

	/* flags */
	union {
		struct {
			uint32_t access_address_ok : 1;
		} as_bits;
		uint32_t as_word;
	} flags;
};

#endif /* INCLUDED_BLUETOOTH_LE_PACKET_H */
