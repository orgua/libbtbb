/* -*- c++ -*- */
/*
 * Copyright 2007 - 2013 Dominic Spill, Michael Ossmann, Will Code
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
#ifndef INCLUDED_BLUETOOTH_PACKET_H
#define INCLUDED_BLUETOOTH_PACKET_H
#include "btbb.hpp"
#include <limits>

/* maximum number of symbols */
constexpr uint16_t 	MAX_SYMBOLS 	= 3125; // TODO: also assert?

/* maximum number of payload bits */
constexpr uint16_t 	MAX_PAYLOAD_LENGTH = 2744;
static_assert(MAX_PAYLOAD_LENGTH * 8 <= std::numeric_limits<uint16_t>::max(), "implementation is limited!");

/* minimum header bit errors to indicate that this is an ID packet */
constexpr uint8_t 	ID_THRESHOLD 	    = 5;

constexpr uint8_t 	PACKET_TYPE_NULL 	= 0;
constexpr uint8_t 	PACKET_TYPE_POLL 	= 1;
constexpr uint8_t 	PACKET_TYPE_FHS 	= 2;
constexpr uint8_t 	PACKET_TYPE_DM1 	= 3;
constexpr uint8_t 	PACKET_TYPE_DH1 	= 4;
constexpr uint8_t 	PACKET_TYPE_HV1 	= 5;
constexpr uint8_t 	PACKET_TYPE_HV2 	= 6;
constexpr uint8_t 	PACKET_TYPE_HV3 	= 7;
constexpr uint8_t 	PACKET_TYPE_DV 		= 8;
constexpr uint8_t 	PACKET_TYPE_AUX1 	= 9;
constexpr uint8_t 	PACKET_TYPE_DM3 	= 10;
constexpr uint8_t 	PACKET_TYPE_DH3 	= 11;
constexpr uint8_t 	PACKET_TYPE_EV4 	= 12;
constexpr uint8_t 	PACKET_TYPE_EV5 	= 13;
constexpr uint8_t 	PACKET_TYPE_DM5 	= 14;
constexpr uint8_t 	PACKET_TYPE_DH5 	= 15;

template<typename DType>
constexpr DType min(const DType value_A, const DType value_B)
{
	return ((value_A < value_B) ? value_A : value_B);
}

struct btbb_packet {

	uint32_t refcount;

	uint32_t flags;

	uint8_t channel; /* Bluetooth channel (0-79) */
	uint8_t UAP;     /* upper address part */
	uint16_t NAP;    /* non-significant address part */
	uint32_t LAP;    /* lower address part found in access code */

	uint8_t modulation;
	uint8_t transport;
	uint8_t packet_type;
	uint8_t packet_lt_addr; /* LLID field of payload header (2 bits) */
	uint8_t packet_flags; /* Flags - FLOW/ARQN/SQEN */
	uint8_t packet_hec; /* Flags - FLOW/ARQN/SQEN */

	/* packet header, one bit per char */
	uint8_t packet_header[18];

	/* number of payload header bytes: 0, 1, 2. payload is one bit per char. */
	uint32_t payload_header_length;
	uint8_t  payload_header[16];

	/* LLID field of payload header (2 bits) */
	uint8_t payload_llid;

	/* flow field of payload header (1 bit) */
	uint8_t payload_flow;

	/* payload length: the total length of the asynchronous data
	* in bytes.  This does not include the length of synchronous
	* data, such as the voice field of a DV packet.  If there is a
	* payload header, this payload length is payload body length
	* (the length indicated in the payload header's length field)
	* plus payload_header_length plus 2 bytes CRC (if present).
	*/
	uint16_t payload_length;

	/* The actual payload data in host format
	* Ready for passing to wireshark
	* 2744 is the maximum length, but most packets are shorter.
	* Dynamic allocation would probably be better in the long run but is
	* problematic in the short run.
	*/
	uint8_t payload[MAX_PAYLOAD_LENGTH];

	uint16_t crc;
	uint32_t clkn;     /* CLK1-27 of the packet */
	uint8_t ac_errors; /* Number of bit errors in the AC */

	/* the raw symbol stream (less the preamble), one bit per char */
	//FIXME maybe this should be a vector so we can grow it only
	//to the size needed and later shrink it if we find we have
	//more symbols than necessary
	uint16_t length; /* number of symbols */
	uint8_t symbols[MAX_SYMBOLS];
};

/* type-specific CRC checks and decoding */
uint16_t fhs(uint32_t clock, btbb_packet* p);
uint16_t DM(uint32_t clock, btbb_packet* p);
uint16_t DH(uint32_t clock, btbb_packet* p);
uint16_t EV3(uint32_t clock, btbb_packet* p);
uint16_t EV4(uint32_t clock, btbb_packet* p);
uint16_t EV5(uint32_t clock, btbb_packet* p);
uint16_t HV(uint32_t clock, btbb_packet* p);

/* check if the packet's CRC is correct for a given clock (CLK1-6) */
uint16_t crc_check(uint32_t clock, btbb_packet* p);

/* format payload for tun interface */
uint8_t * tun_format(btbb_packet* p);

/* try a clock value (CLK1-6) to unwhiten packet header,
 * sets resultant d_packet_type and d_UAP, returns UAP.
 */
uint8_t try_clock(uint32_t clock, btbb_packet * p);

/* extract LAP from FHS payload */
uint32_t lap_from_fhs(btbb_packet* p);

/* extract UAP from FHS payload */
uint8_t uap_from_fhs(btbb_packet* p);

/* extract NAP from FHS payload */
uint16_t nap_from_fhs(btbb_packet* p);

/* extract clock from FHS payload */
uint32_t clock_from_fhs(btbb_packet* p);

#endif /* INCLUDED_BLUETOOTH_PACKET_H */
