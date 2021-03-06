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
#ifndef INCLUDED_BLUETOOTH_PICONET_H
#define INCLUDED_BLUETOOTH_PICONET_H
#include "btbb.hpp"

/* maximum number of hops to remember */
constexpr uint16_t MAX_PATTERN_LENGTH = 1000;

/* number of channels in use */
constexpr uint8_t  BT_NUM_CHANNELS = 79;

struct btbb_piconet {

	uint32_t refcount;

	uint32_t flags;

	/* true if using a particular aliased receiver implementation */
	bool aliased;

	/* AFH channel map - either read or derived from observed packets */
	uint8_t afh_map[10];

	/* Number of used channel derived from AFH channel map */
	uint8_t used_channels;

	/* lower address part (of master's BD_ADDR) */
	uint32_t LAP;

	/* upper address part (of master's BD_ADDR) */
	uint8_t UAP;

	/* non-significant address part (of master's BD_ADDR) */
	uint16_t NAP;

	/* CLK1-27 candidates */
	uint32_t *clock_candidates;

	/* these values for hop() can be precalculated */
	uint8_t b, e;

	/* these values for hop() can be precalculated in part (e.g. a1 is the
	 * precalculated part of a) */
	uint8_t a1, c1;
	uint16_t d1;

	/* frequency register bank */
	uint8_t bank[BT_NUM_CHANNELS];

	/* this holds the entire hopping sequence */
	uint8_t *sequence;

	/* number of candidates for CLK1-27 */
	uint32_t num_candidates;

	/* number of packets observed during one attempt at UAP/clock discovery */
	uint32_t packets_observed; // TODO: clean up types

	/* total number of packets observed */
	uint32_t total_packets_observed;

	/* number of observed packets that have been used to winnow the candidates */
	uint32_t winnowed;

	/* CLK1-6 candidates */
	int clock6_candidates[64]; // TODO: can be -1 and UAP mostly

	/* remember patterns of observed hops */
	uint32_t pattern_indices[MAX_PATTERN_LENGTH]; // TODO: can this be negative as well? ask hannes
	uint8_t pattern_channels[MAX_PATTERN_LENGTH];

	/* offset between CLKN (local) and CLK of piconet */
	uint32_t clk_offset; // TODO: can this be negative as well? ask hannes

	/* local clock (clkn) at time of first packet */
	uint32_t first_pkt_time;

	/* queue of packets to be decoded */
	pkt_queue *queue;
};

/* number of hops in the hopping sequence (i.e. number of possible values of CLK1-27) */
constexpr uint32_t SEQUENCE_LENGTH = 134217728ul;

/* number of aliased channels received */
constexpr uint8_t  ALIASED_CHANNELS = 25;

/* do all the precalculation that can be done before knowing the address */
void precalc(btbb_piconet *pnet);

/* do precalculation that requires the address */
void address_precalc(int address, btbb_piconet *pnet);

/* drop-in replacement for perm5() using lookup table */
uint8_t fast_perm(uint8_t z, uint8_t p_high, uint16_t p_low);

/* determine channel for a particular hop */
/* replaced with gen_hops() for a complete sequence but could still come in handy */
char single_hop(int clock, btbb_piconet *pnet);

/* look up channel for a particular hop */
char hop(int clock, btbb_piconet *pnet);

void try_hop(btbb_packet *pkt, btbb_piconet *pn);

void get_hop_pattern(btbb_piconet *pn);

#endif /* INCLUDED_BLUETOOTH_PICONET_H */
