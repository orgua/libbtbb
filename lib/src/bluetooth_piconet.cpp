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

#include "bluetooth_packet.hpp"
#include "bluetooth_piconet.hpp"
#include "uthash.hpp" // TODO: cpp has better hash

#include <cstdlib>
#include <cstdio>
#include <cassert>

bool perm_table_initialized = false; // TODO: could be all made an object
constexpr uint8_t   PERM_TABLE_Z  = 0x20;
constexpr uint8_t   PERM_TABLE_PH = 0x20;
constexpr uint16_t  PERM_TABLE_PL = 0x200;
uint8_t perm_table[PERM_TABLE_Z][PERM_TABLE_PH][PERM_TABLE_PL];

/* count the number of 1 bits in a uint8_t */
uint8_t count_bits(const uint8_t value)
{
	constexpr uint8_t BIT_COUNT[] = { // TODO: change back to fn and just make it constexpr?
			0,1,1,2,1,2,2,3,1,2,2,3,2,3,3,4,
			1,2,2,3,2,3,3,4,2,3,3,4,3,4,4,5,
			1,2,2,3,2,3,3,4,2,3,3,4,3,4,4,5,
			2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,
			1,2,2,3,2,3,3,4,2,3,3,4,3,4,4,5,
			2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,
			2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,
			3,4,4,5,4,5,5,6,4,5,5,6,5,6,6,7,
			1,2,2,3,2,3,3,4,2,3,3,4,3,4,4,5,
			2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,
			2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,
			3,4,4,5,4,5,5,6,4,5,5,6,5,6,6,7,
			2,3,3,4,3,4,4,5,3,4,4,5,4,5,5,6,
			3,4,4,5,4,5,5,6,4,5,5,6,5,6,6,7,
			3,4,4,5,4,5,5,6,4,5,5,6,5,6,6,7,
			4,5,5,6,5,6,6,7,5,6,6,7,6,7,7,8};

	return BIT_COUNT[value];
}

btbb_piconet * btbb_piconet_new()
{
	btbb_piconet *pn = (btbb_piconet *)calloc(1, sizeof(btbb_piconet));
	pn->refcount = 1;
	return pn;
}

void btbb_piconet_ref(btbb_piconet *pn)
{
	pn->refcount++;
}

void btbb_piconet_unref(btbb_piconet *pn)
{
	pn->refcount--;
	if (pn->refcount == 0)
		free(pn);
}

/* A bit of a hack? to set survey mode */
static bool survey_mode = false;
bool btbb_init_survey() {
	survey_mode = true;
	return false;
}

void btbb_init_piconet(btbb_piconet * const pn, const uint32_t lap)
{
	pn->LAP = lap;
	btbb_piconet_set_flag(pn, BTBB_LAP_VALID, true);
}

void btbb_piconet_set_flag(btbb_piconet * const pn, const uint8_t flag, const bool val)
{
	const uint32_t mask = uint32_t(1) << flag;
	pn->flags &= ~mask;
	if (val) pn->flags |= mask;
}

bool btbb_piconet_get_flag(const btbb_piconet * const pn, const uint8_t flag)
{
	const uint32_t mask = uint32_t(1) << flag;
	return ((pn->flags & mask) != 0);
}

void btbb_piconet_set_uap(btbb_piconet * const pn, const uint8_t uap)
{
	pn->UAP = uap;
	btbb_piconet_set_flag(pn, BTBB_UAP_VALID, true);
}

uint8_t btbb_piconet_get_uap(const btbb_piconet * const pn)
{
	return pn->UAP;
}

uint32_t btbb_piconet_get_lap(const btbb_piconet * const pn)
{
	return pn->LAP;
}

uint16_t btbb_piconet_get_nap(const btbb_piconet * const pn)
{
	return pn->NAP;
}

uint64_t btbb_piconet_get_bdaddr(const btbb_piconet * const pn)
{
	return ((uint64_t) pn->NAP) << 32 | ((uint32_t) pn->UAP) << 24 | pn->LAP;
}

uint32_t btbb_piconet_get_clk_offset(const btbb_piconet * const pn)
{
	return pn->clk_offset;
}

void btbb_piconet_set_clk_offset(btbb_piconet * const pn, const uint32_t clk_offset)
{
	pn->clk_offset = clk_offset;
}

void btbb_piconet_set_afh_map(btbb_piconet * const pn, const uint8_t * const afh_map)
{
	pn->used_channels = 0;
	// DGS: Unroll this?
	for(uint8_t i=0; i<10; i++)
	{
		pn->afh_map[i] = afh_map[i];
		pn->used_channels += count_bits(pn->afh_map[i]);
	}
	if(btbb_piconet_get_flag(pn, BTBB_UAP_VALID))  get_hop_pattern(pn);
}

uint8_t * btbb_piconet_get_afh_map(btbb_piconet * const pn)
{
	return pn->afh_map;
}

bool btbb_piconet_set_channel_seen(btbb_piconet * const pn, const uint8_t channel)
{
	const uint8_t channel_ub = channel >> 3;
	const uint8_t channel_af = uint8_t(0x1) << (channel & 0x07);
    if(!(pn->afh_map[channel_ub] & channel_af))
    {
		pn->afh_map[channel_ub] |= channel_af;
		pn->used_channels++;
		return true;
	}
	return false;
}

bool btbb_piconet_clear_channel_seen(btbb_piconet * const pn, const uint8_t channel)
{
    const uint8_t channel_ub = channel >> 3;
    const uint8_t channel_af = uint8_t(0x1) << (channel & 0x07);
    if((pn->afh_map[channel_ub] & channel_af))
    {
		pn->afh_map[channel_ub] &= ~channel_af;
		pn->used_channels--;
		return true;
	}
	return false;
}

bool btbb_piconet_get_channel_seen(btbb_piconet * const pn, const uint8_t channel)
{
    const uint8_t channel_ub = channel >> 3;
    const uint8_t channel_af = uint8_t(0x1) << (channel & 0x07);
    if(channel < BT_NUM_CHANNELS) return ( pn->afh_map[channel_ub] & channel_af ) != 0;
    else                          return true;
}

/* do all the precalculation that can be done before knowing the address */
void precalc(btbb_piconet * const pn)
{
	uint8_t j = 0;

	/* populate frequency register bank*/
	for (uint8_t i = 0; i < BT_NUM_CHANNELS; i++) {

		/* AFH is used, hopping sequence contains only used channels */
		if(btbb_piconet_get_flag(pn, BTBB_IS_AFH)) {
			const uint8_t chan = (i * uint8_t(2)) % BT_NUM_CHANNELS;
			if(btbb_piconet_get_channel_seen(pn, chan))
				pn->bank[j++] = chan;
		}

		/* all channels are used */
		else {
			pn->bank[i] = static_cast<uint8_t>((i * 2) % BT_NUM_CHANNELS);
		}
	}
	/* actual frequency is 2402 + PN->bank[i] MHz */
}

/* do precalculation that requires the address */
void address_precalc(const uint32_t address, btbb_piconet * const pn)
{
	/* precalculate some of single_hop()/gen_hop()'s variables */
	pn->a1 = static_cast<uint8_t>((address >> 23) % 32);
	pn->b = static_cast<uint8_t>((address >> 19) % 16);
	pn->c1 = static_cast<uint8_t>(((address >> 4) & 0x10) +
            ((address >> 3) & 0x08) +
            ((address >> 2) & 0x04) +
            ((address >> 1) & 0x02) +
            (address & 0x01));
	pn->d1 = static_cast<uint16_t>((address >> 10) % 512);
	pn->e = static_cast<uint8_t>(((address >> 7) & 0x40) +
            ((address >> 6) & 0x20) +
            ((address >> 5) & 0x10) +
            ((address >> 4) & 0x08) +
            ((address >> 3) & 0x04) +
            ((address >> 2) & 0x02) +
            ((address >> 1) & 0x01));
}

/* 5 bit permutation */
/* assumes z is constrained to 5 bits, p_high to 5 bits, p_low to 9 bits */
void perm_table_init() // TODO: can be done as constexpression
{
    /* populate perm_table for all possible inputs */
    for (uint8_t p_high = 0; p_high<PERM_TABLE_PH; p_high++)
    {
        bool p_bit[14];
        for (uint8_t i = 0; i<5; i++) p_bit[i+9] = static_cast<bool>((p_high >> i) & 0x01);

        for (uint16_t p_low = 0; p_low<PERM_TABLE_PL; p_low++)
        {
            for (uint8_t i = 0; i<9; i++) p_bit[i] = static_cast<bool>((p_low >> i) & 0x01);

            for (uint8_t z = 0; z<PERM_TABLE_Z; z++)
            {
                bool z_bit[5];
                for (uint8_t i = 0; i<5; i++) z_bit[i] = static_cast<bool>((z >> i) & 0x01);

                //perm_table[z][p_high][p_low] = perm5(z, p_high, p_low);

                constexpr uint8_t INDEX_1[14] = {0, 2, 1, 3, 0, 1, 0, 3, 1, 0, 2, 1, 0, 1};
                constexpr uint8_t INDEX_2[14] = {1, 3, 2, 4, 4, 3, 2, 4, 4, 3, 4, 3, 3, 2};

                /* butterfly operations */
                for (uint8_t i = 13; i <= 13; i--)
                {
                    /* swap bits according to index arrays if control signal tells us to */
                    if (p_bit[i])
                    {
                        const bool tmp = z_bit[INDEX_1[i]];
                        z_bit[INDEX_1[i]] = z_bit[INDEX_2[i]];
                        z_bit[INDEX_2[i]] = tmp;
                    }
                }

                /* reconstruct output from rearranged bits */
                uint8_t output = 0;
                for (uint8_t i = 0; i < 5; i++) output += z_bit[i] << i;

                perm_table[z][p_high][p_low] = output;
            }
        }
    }
}

/* drop-in replacement for perm5() using lookup table */
uint8_t fast_perm(const uint8_t z, const uint8_t p_high, const uint16_t p_low)
{
	if (!perm_table_initialized) {
		perm_table_init(); // TODO: let the compiler do the work
		perm_table_initialized = true;
	}

    assert(z      < PERM_TABLE_Z);
    assert(p_high < PERM_TABLE_PH);
    assert(p_low  < PERM_TABLE_PL);

	return(perm_table[z][p_high][p_low]);
}

/* generate the complete hopping sequence */
static void gen_hops(btbb_piconet * const pn)
{
	/* a, b, c, d, e, f, x, y1, y2 are variable names used in section 2.6 of the spec */
	/* b is already defined */
	/* e is already defined */
    uint32_t base_f = 0;
    uint8_t f = 0;
    uint8_t f_dash = 0;

	/* sequence index = clock >> 1 */
	/* (hops only happen at every other clock value) */
	uint32_t index = 0;

    const bool use_afh = btbb_piconet_get_flag(pn, BTBB_IS_AFH);

	/* nested loops for optimization (not recalculating every variable with every clock tick) */
	for (uint8_t h = 0; h < 0x04; h++) /* clock bits 26-27 */
    {
		for (uint8_t i = 0; i < 0x20; i++) /* clock bits 21-25 */
        {
			const uint8_t a = pn->a1 ^ i;

			for (uint8_t j = 0; j < 0x20; j++) /* clock bits 16-20 */
            {
				const uint8_t c = pn->c1 ^ j;
				const uint8_t c_flipped = c ^ uint8_t(0x1f);

				for (uint16_t k = 0; k < 0x200; k++) /* clock bits 7-15 */
                {
					const uint16_t d = pn->d1 ^ k;

					for (uint8_t x = 0; x < 0x20; x++) /* clock bits 2-6 */
                    {
						const uint8_t perm_in = ((x + a) % uint8_t(32)) ^ pn->b;

						const uint8_t perm_out_0 = fast_perm(perm_in, c, d); /* y1 (clock bit 1) = 0, y2 = 0 */
                        const uint8_t perm_out_1 = fast_perm(perm_in, c_flipped, d); /* y1 (clock bit 1) = 1, y2 = 32 */

						if (use_afh)
                        {
                            pn->sequence[index] = pn->bank[(perm_out_0 + pn->e + f_dash) % pn->used_channels];
                            pn->sequence[index + 1] = pn->bank[(perm_out_1 + pn->e + f_dash + 32) % pn->used_channels];
                        }
						else
                        {
                            pn->sequence[index] = pn->bank[(perm_out_0 + pn->e + f) % BT_NUM_CHANNELS];
                            pn->sequence[index + 1] = pn->bank[(perm_out_1 + pn->e + f + 32) % BT_NUM_CHANNELS];
                        }

						index += 2;
					}
					base_f += 16;
					f = static_cast<uint8_t>(base_f % BT_NUM_CHANNELS);
					f_dash = f % pn->used_channels;
				}
			}
		}
	}
}

/* Function to calculate piconet hopping patterns and add to hash map */
void gen_hop_pattern(btbb_piconet * const pn)
{
	printf("\nCalculating complete hopping sequence.\n");
	/* this holds the entire hopping sequence */
	pn->sequence = new uint8_t[SEQUENCE_LENGTH];

	precalc(pn);
	address_precalc(((pn->UAP<<24) | pn->LAP) & 0xfffffff, pn); // TODO: ok, correct, but masked again later, so not needed here
	gen_hops(pn);

	printf("Hopping sequence calculated.\n");
}

/* Container for hopping pattern */
typedef struct {
    uint64_t key; /* afh flag + address */
    uint8_t *sequence;
    UT_hash_handle hh;
} hopping_struct;

static hopping_struct *hopping_map = nullptr;

/* Function to fetch piconet hopping patterns */
void get_hop_pattern(btbb_piconet * const pn)
{
	/* Two stages to avoid "left shift count >= width of type" warning */
	const bool afh_flag = btbb_piconet_get_flag(pn, BTBB_IS_AFH);
	const uint64_t key = (uint64_t(afh_flag)<<39) | (uint64_t(pn->used_channels)<<32) | (uint32_t(pn->UAP)<<24) | pn->LAP;
    hopping_struct *s;
	HASH_FIND(hh, hopping_map, &key, 4, s);

	if (s == nullptr)
    {
		gen_hop_pattern(pn);
		s = new hopping_struct;
		s->key = key;
		s->sequence = pn->sequence;
		HASH_ADD(hh, hopping_map, key, 4, s);
	} else
    {
		printf("\nFound hopping sequence in cache.\n");
		pn->sequence = s->sequence;
	}
}

/* determine channel for a particular hop */
/* borrowed from ubertooth firmware to support AFH */
uint8_t single_hop(const uint32_t clock, btbb_piconet * const pn)
{
	uint8_t next_channel;
	uint32_t f_dash;

	/* following variable names used in section 2.6 of the spec */
	const auto      x = static_cast<uint8_t>((clock >> 2) % 32);
    const auto      y1 = static_cast<uint8_t>((clock >> 1) & 0x01);
    const uint8_t   y2 = y1 << 5;

    const auto      a = static_cast<uint8_t>((pn->a1 ^ (clock >> 21)) % 32);
	/* b is already defined */
    const auto      c = static_cast<uint8_t>((pn->c1 ^ (clock >> 16)) % 32);
    const auto      d = static_cast<uint16_t>((pn->d1 ^ (clock >> 7)) % 512);
	/* e is already defined */
	const uint32_t  base_f = (clock >> 3) & 0x1fffff0;
	const auto      f = static_cast<uint8_t>(base_f % BT_NUM_CHANNELS);

	uint8_t perm = fast_perm(((x + a) % uint8_t(32)) ^ pn->b, (y1 * uint8_t(32)) ^ c, d);
	/* hop selection */
	if(btbb_piconet_get_flag(pn, BTBB_IS_AFH))
    {
		f_dash = base_f % pn->used_channels;
		next_channel = pn->bank[(perm + pn->e + f_dash + y2) % pn->used_channels];
	} else
    {
		next_channel = pn->bank[(perm + pn->e + f + y2) % BT_NUM_CHANNELS];
	}
	return next_channel;
}

/* look up channel for a particular hop */
uint8_t hop(uint32_t clock, const btbb_piconet * const pn)
{
	return pn->sequence[clock];
}

static uint8_t aliased_channel(const uint8_t channel)
{
	return ((channel + uint8_t(24)) % ALIASED_CHANNELS) + uint8_t(26);
}

/* create list of initial candidate clock values (hops with same channel as first observed hop) */
static uint32_t init_candidates(const uint8_t channel, const uint32_t known_clock_bits, btbb_piconet * const pn)
{
	uint32_t count = 0; /* total number of candidates */

	/* only try clock values that match our known bits */
	for (uint32_t i = known_clock_bits; i < SEQUENCE_LENGTH; i += 0x40)
    {
        /* accounts for aliasing if necessary */
        const uint8_t observable_channel = (pn->aliased) ? aliased_channel(pn->sequence[i]) : pn->sequence[i];

		if (observable_channel == channel)	pn->clock_candidates[count++] = i;
		//FIXME ought to throw exception if count gets too big
	}
	return count;
}

/* initialize the hop reversal process */
uint32_t btbb_init_hop_reversal(const bool aliased, btbb_piconet * const pn)
{
	get_hop_pattern(pn);

	constexpr size_t max_candidates_ali = (SEQUENCE_LENGTH / ALIASED_CHANNELS) / 32;
	constexpr size_t max_candidates_nom = (SEQUENCE_LENGTH / BT_NUM_CHANNELS) / 32;
    const size_t     max_candidates = (aliased) ? max_candidates_ali : max_candidates_nom;

	/* this can hold twice the approximate number of initial candidates */
	pn->clock_candidates = new uint32_t[max_candidates];

	const uint32_t clock = (pn->clk_offset + pn->first_pkt_time) & 0x3f; // TODO: seems to be right, but should be done in "init_canditates with %64
	pn->num_candidates = init_candidates(pn->pattern_channels[0], clock, pn);
	pn->winnowed = 0;
	btbb_piconet_set_flag(pn, BTBB_HOP_REVERSAL_INIT, true);
	btbb_piconet_set_flag(pn, BTBB_CLK27_VALID, false);
	btbb_piconet_set_flag(pn, BTBB_IS_ALIASED, aliased);

	printf("%d initial CLK1-27 candidates\n", pn->num_candidates);

	return pn->num_candidates;
}

void try_hop(btbb_packet * const pkt, btbb_piconet * const pn)
{
	uint8_t filter_uap = pn->UAP;

	/* Decode packet - fixing clock drift in the process */
	btbb_decode(pkt);

	if (btbb_piconet_get_flag(pn, BTBB_HOP_REVERSAL_INIT))
    {
		//PN->winnowed = 0; // TODO: this could give a clue for the bug in btbb_winnow()
		pn->pattern_indices[pn->packets_observed] = pkt->clkn - pn->first_pkt_time; // TODO: check for positive result
		pn->pattern_channels[pn->packets_observed] = pkt->channel;
		pn->packets_observed++;
		pn->total_packets_observed++;
		btbb_winnow(pn);
		if (btbb_piconet_get_flag(pn, BTBB_CLK27_VALID))
        {
			printf("got CLK1-27\n");
			printf("clock offset = %d.\n", pn->clk_offset);
		}
	} else
    {
		if (btbb_piconet_get_flag(pn, BTBB_CLK6_VALID))
        {
			btbb_uap_from_header(pkt, pn);
			if (btbb_piconet_get_flag(pn, BTBB_CLK27_VALID))
            {
				printf("got CLK1-27\n");
				printf("clock offset = %d.\n", pn->clk_offset);
			}
		} else
        {
			if (btbb_uap_from_header(pkt, pn))
            {
				if (filter_uap == pn->UAP)
                {
					btbb_init_hop_reversal(false, pn); // TODO: is aliased not implemented?, ask dominic
					btbb_winnow(pn);
				} else
                {
					printf("failed to confirm UAP\n");
				}
			}
		}
	}

	if(!btbb_piconet_get_flag(pn, BTBB_UAP_VALID))
    {
		btbb_piconet_set_flag(pn, BTBB_UAP_VALID, true);
		pn->UAP = filter_uap;
	}
}

/* return the observable channel (26-50) for a given channel (0-78) */
/* reset UAP/clock discovery */
static void reset(btbb_piconet * const pn)
{
	//printf("no candidates remaining! starting over . . .\n");

	if(btbb_piconet_get_flag(pn, BTBB_HOP_REVERSAL_INIT))
    {
		free(pn->clock_candidates);
		pn->sequence = nullptr;
	}
	btbb_piconet_set_flag(pn, BTBB_GOT_FIRST_PACKET, false);
	btbb_piconet_set_flag(pn, BTBB_HOP_REVERSAL_INIT, false);
	btbb_piconet_set_flag(pn, BTBB_UAP_VALID, false);
	btbb_piconet_set_flag(pn, BTBB_CLK6_VALID, false);
	btbb_piconet_set_flag(pn, BTBB_CLK27_VALID, false);
	pn->packets_observed = 0;

	/*
	 * If we have recently observed two packets in a row on the same
	 * channel, try AFH next time.  If not, don't.
	 */
	btbb_piconet_set_flag(pn, BTBB_IS_AFH, btbb_piconet_get_flag(pn, BTBB_LOOKS_LIKE_AFH));
	// btbb_piconet_set_flag(PN, BTBB_LOOKS_LIKE_AFH, 0);
	//int i;
	//for(i=0; i<10; i++)
	//	PN->afh_map[i] = 0; // TODO: what is with this?
}

/* narrow a list of candidate clock values based on a single observed hop */
static uint32_t channel_winnow(const uint32_t offset, const uint8_t channel, btbb_piconet * const pn)
{
	uint32_t new_count = 0; /* number of candidates after winnowing */
	uint8_t  observable_channel; /* accounts for aliasing if necessary */

	/* check every candidate */
	for (uint32_t i = 0; i < pn->num_candidates; i++)
    {
		if (pn->aliased)
			observable_channel = aliased_channel(pn->sequence[(pn->clock_candidates[i] + offset) % SEQUENCE_LENGTH]);
		else
			observable_channel = pn->sequence[(pn->clock_candidates[i] + offset) % SEQUENCE_LENGTH];
		if (observable_channel == channel)
        {
			/* this candidate matches the latest hop */
			/* blow away old list of candidates with new one */
			/* safe because new_count can never be greater than i */
			pn->clock_candidates[new_count++] = pn->clock_candidates[i];
		}
	}
	pn->num_candidates = new_count;

	if (new_count == 1)
    {
		// Calculate clock offset for CLKN, not CLK1-27
		pn->clk_offset = ((pn->clock_candidates[0]<<1) - (pn->first_pkt_time<<1));
		printf("\nAcquired CLK1-27 = 0x%07x\n", pn->clock_candidates[0]);
		btbb_piconet_set_flag(pn, BTBB_CLK27_VALID, true);
	}
	else if (new_count == 0)
    {
		reset(pn);
	}
	//else {
	//printf("%d CLK1-27 candidates remaining (channel=%d)\n", new_count, channel);
	//}

	return new_count;
}

/* narrow a list of candidate clock values based on all observed hops */
uint32_t btbb_winnow(btbb_piconet * const pn)
{
	uint32_t new_count = pn->num_candidates;

    assert(pn->winnowed!=0); // TODO: check for >=1, otherwise we do illegal ops here, possible bug

	for (; pn->winnowed < pn->packets_observed; pn->winnowed++)
    {
		const uint32_t index   = pn->pattern_indices[pn->winnowed];
		const uint8_t  channel = pn->pattern_channels[pn->winnowed];
		new_count = channel_winnow(index, channel, pn);
		if (new_count <= 1) break;

		if (pn->packets_observed > 0)
        {
			const uint32_t last_index = pn->pattern_indices[pn->winnowed - 1];
			const uint8_t  last_channel = pn->pattern_channels[pn->winnowed - 1];
			/*
			 * Two packets in a row on the same channel should only
			 * happen if adaptive frequency hopping is in use.
			 * There can be false positives, though, especially if
			 * there is aliasing.
			 */
			if (!btbb_piconet_get_flag(pn, BTBB_LOOKS_LIKE_AFH) && (index == last_index + 1) && (channel == last_channel))
            {
				btbb_piconet_set_flag(pn, BTBB_LOOKS_LIKE_AFH, true);
				printf("Hopping pattern appears to be AFH\n");
			}
		}
	}

	return new_count;
}

/* use packet headers to determine UAP */
int btbb_uap_from_header(btbb_packet * const pkt, btbb_piconet * const pn) // TODO: the whole FN is to complex
{
	int first_clock = 0; // TODO: sometimes it is offset for a pointer and sometimes a timevalue?

	uint32_t starting = 0, remaining = 0;
	const uint32_t clkn = pkt->clkn;

	if (!btbb_piconet_get_flag(pn, BTBB_GOT_FIRST_PACKET))
    {
        pn->first_pkt_time = clkn;
    }

	// Set afh channel map
	btbb_piconet_set_channel_seen(pn, pkt->channel);

	if (pn->packets_observed < MAX_PATTERN_LENGTH)
    {
		pn->pattern_indices[pn->packets_observed] = clkn - pn->first_pkt_time; // TODO: check for positiv result? can it be negative? aks hannes
		pn->pattern_channels[pn->packets_observed] = pkt->channel;
	} else
    {
		printf("Oops. More hops than we can remember.\n");
		reset(pn);
		return 0; //FIXME ought to throw exception
	}
	pn->packets_observed++;
	pn->total_packets_observed++;

	/* try every possible first packet clock value */
	for (uint8_t count = 0; count < 64; count++)
    {
		/* skip eliminated candidates unless this is our first time through */
		if (pn->clock6_candidates[count] > -1 || !btbb_piconet_get_flag(pn, BTBB_GOT_FIRST_PACKET))
        {
			/* clock value for the current packet assuming count was the clock of the first packet */
			uint32_t clock = (count + clkn - pn->first_pkt_time) % 64;
			starting++;
			const uint8_t UAP = try_clock(clock, pkt);
			int32_t crc_chk = -1;

			/* if this is the first packet: populate the candidate list */
			/* if not: check CRCs if UAPs match */
			if (!btbb_piconet_get_flag(pn, BTBB_GOT_FIRST_PACKET)
				|| UAP == pn->clock6_candidates[count])
				crc_chk = crc_check(clock, pkt);

			if (btbb_piconet_get_flag(pn, BTBB_UAP_VALID) &&
			    (UAP != pn->UAP))
				crc_chk = -1;

			switch(crc_chk) {
			case -1: /* UAP mismatch */
			case 0: /* CRC failure */
				pn->clock6_candidates[count] = -1;
				break;

			case 1: /* inconclusive result */
			case 2: /* Inconclusive, but looks better */
				pn->clock6_candidates[count] = UAP;
				/* remember this count because it may be the correct clock of the first packet */
				first_clock = count;
				remaining++;
				break;

			default: /* CRC success */
				pn->clk_offset = (count - (pn->first_pkt_time & 0x3f)) & 0x3f; // TODO: special attention
				if (!btbb_piconet_get_flag(pn, BTBB_UAP_VALID))
					printf("Correct CRC! UAP = 0x%x found after %d total packets.\n",
						UAP, pn->total_packets_observed);
				else
					printf("Correct CRC! CLK6 = 0x%x found after %d total packets.\n",
						pn->clk_offset, pn->total_packets_observed);
				pn->UAP = UAP;
				btbb_piconet_set_flag(pn, BTBB_CLK6_VALID, true);
				btbb_piconet_set_flag(pn, BTBB_UAP_VALID, true);
				pn->total_packets_observed = 0;
				return 1;
			}
		}
	}

	btbb_piconet_set_flag(pn, BTBB_GOT_FIRST_PACKET, true);

	//printf("reduced from %d to %d CLK1-6 candidates\n", starting, remaining);

	if (remaining == 1)
    {
		pn->clk_offset = (first_clock - (pn->first_pkt_time & 0x3f)) & 0x3f;
		if (!btbb_piconet_get_flag(pn, BTBB_UAP_VALID))
        {
            printf("UAP = 0x%x found after %d total packets.\n",
                    pn->clock6_candidates[first_clock], pn->total_packets_observed);
        }
		else
        {
            printf("CLK6 = 0x%x found after %d total packets.\n",
                    pn->clk_offset, pn->total_packets_observed);
        }
		pn->UAP = static_cast<uint8_t>(pn->clock6_candidates[first_clock]);
		btbb_piconet_set_flag(pn, BTBB_CLK6_VALID, true);
		btbb_piconet_set_flag(pn, BTBB_UAP_VALID, true);
		pn->total_packets_observed = 0;
		return 1;
	}

	if (remaining == 0)
    {
		reset(pn);
	}

	return 0;
}

/* FIXME: comment out enqueue and dequeue because they are
 * never used.  Try to find out what tey were meant to be
 * used for before the next release.
 */
///* add a packet to the queue */
//static void enqueue(btbb_packet *pkt, btbb_piconet *PN)
//{
//	pkt_queue *head;
//	//pkt_queue item;
//
//	btbb_packet_ref(pkt);
//	pkt_queue item = {pkt, NULL};
//	head = PN->queue;
//
//	if (head == NULL) {
//		PN->queue = &item;
//	} else {
//		for(; head->next != NULL; head = head->next)
//		  ;
//		head->next = &item;
//	}
//}
//
///* pull the first packet from the queue (FIFO) */
//static btbb_packet *dequeue(btbb_piconet *PN)
//{
//	btbb_packet *pkt;
//
//	if (PN->queue == NULL) {
//		pkt = NULL;
//	} else {
//		pkt = PN->queue->pkt;
//		PN->queue = PN->queue->next;
//		btbb_packet_unref(pkt);
//	}
//
//	return pkt;
//}

/* Print AFH map from observed packets */
void btbb_print_afh_map(btbb_piconet *pn)
{
    const uint8_t * afh_map = pn->afh_map;

	/* Print like hcitool does */
	printf("AFH map: 0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
	       afh_map[0], afh_map[1], afh_map[2], afh_map[3], afh_map[4],
	       afh_map[5], afh_map[6], afh_map[7], afh_map[8], afh_map[9]);
}

/* Container for survey piconets */
typedef struct {
    uint32_t key; /* LAP */
    btbb_piconet *pn;
    UT_hash_handle hh;
} survey_hash;

static survey_hash *piconet_survey = nullptr;

/* Check for existing piconets in survey results */
btbb_piconet *get_piconet(const uint32_t lap)
{
	survey_hash *s;
	btbb_piconet *pn;
	HASH_FIND(hh, piconet_survey, &lap, 4, s);

	if (s == nullptr)
    {
		pn = btbb_piconet_new();
		btbb_init_piconet(pn, lap);

		s = new survey_hash;
		s->key = lap;
		s->pn = pn;
		HASH_ADD(hh, piconet_survey, key, 4, s);
	} else
    {
		pn = s->pn;
	}
	return pn;
}

/* Destructively iterate over survey results */
btbb_piconet *btbb_next_survey_result()
{
	btbb_piconet *pn = nullptr;
	survey_hash *tmp;

	if (piconet_survey != nullptr)
    {
		pn = piconet_survey->pn;
		tmp = piconet_survey;
		piconet_survey = (survey_hash*) piconet_survey->hh.next; // todo: check if right
		free(tmp);
	}
	return pn;
}

bool btbb_process_packet(btbb_packet * const pkt, btbb_piconet * pn)
{
	if (survey_mode)
    {
		pn = get_piconet(btbb_packet_get_lap(pkt));
		btbb_piconet_set_channel_seen(pn, pkt->channel);
		if(btbb_header_present(pkt) && !btbb_piconet_get_flag(pn, BTBB_UAP_VALID))
			btbb_uap_from_header(pkt, pn);
		return false;
	}

	if(pn)
    {
        btbb_piconet_set_channel_seen(pn, pkt->channel);
    }

	/* If piconet structure is given, a LAP is given, and packet
	 * header is readable, do further analysis. If UAP has not yet
	 * been determined, attempt to calculate it from headers. Once
	 * UAP is known, try to determine clk6 and clk27. Once clocks
	 * are known, follow the piconet. */
	if (pn && btbb_piconet_get_flag(pn, BTBB_LAP_VALID) && btbb_header_present(pkt))
    {
		/* Have LAP/UAP/clocks, now hopping along with the piconet. */
		if (btbb_piconet_get_flag(pn, BTBB_FOLLOWING))
        {
			btbb_packet_set_uap(pkt, btbb_piconet_get_uap(pn));
			btbb_packet_set_flag(pkt, BTBB_CLK6_VALID, 1);
			btbb_packet_set_flag(pkt, BTBB_CLK27_VALID, 1);

			if(btbb_decode(pkt))  btbb_print_packet(pkt);
			else   				printf("Failed to decode packet\n");
		}

		/* Have LAP/UAP, need clocks. */
		else if (btbb_piconet_get_uap(pn))
        {
			try_hop(pkt, pn);
			if (btbb_piconet_get_flag(pn, BTBB_CLK6_VALID) &&
			    btbb_piconet_get_flag(pn, BTBB_CLK27_VALID))
            {
				btbb_piconet_set_flag(pn, BTBB_FOLLOWING, true);
				return true;
			}
		}
		/* Have LAP, need UAP. */
		else
        {
			btbb_uap_from_header(pkt, pn);
		}
	}
	return false;
}
