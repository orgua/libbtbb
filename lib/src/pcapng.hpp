/* -*- c++ -*- */
/*
 * Copyright 2014 Christopher D. Kilgour techie AT whiterocker.com
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
#ifndef PCAPNG_DOT_H
#define PCAPNG_DOT_H

#include <cstdint>
#include <cstdio>

typedef struct __attribute__((packed)) {
	uint16_t option_code;
	uint16_t option_length;
	uint32_t option_value[0];
} option_header;

constexpr uint8_t OPT_ENDOFOPT = 0;
constexpr uint8_t OPT_COMMENT  = 1;

typedef struct __attribute__((packed)) {
	uint32_t block_type;
	uint32_t block_total_length;
	uint32_t byte_order_magic;
	uint16_t major_version;
	uint16_t minor_version;
	uint64_t section_length;
	option_header options[0];
} section_header_block;

constexpr uint32_t SECTION_HEADER_BYTE_ORDER_MAGIC = 0x1a2b3c4dul;

constexpr uint8_t SHB_HARDWARE = 2;
constexpr uint8_t SHB_OS       = 3;
constexpr uint8_t SHB_USERAPPL = 4;

typedef struct __attribute__((packed)) {
	uint32_t block_type;
	uint32_t block_total_length;
	uint16_t link_type;
	uint16_t reserved;
	uint32_t snaplen;
	option_header options[0];
} interface_description_block;

constexpr uint8_t IF_NAME        = 2;
constexpr uint8_t IF_DESCRIPTION = 3;
constexpr uint8_t IF_IPV4ADDR    = 4;
constexpr uint8_t IF_IPV6ADDR    = 5;
constexpr uint8_t IF_MACADDR     = 6;
constexpr uint8_t IF_EUIADDR     = 7;
constexpr uint8_t IF_SPEED       = 8;
constexpr uint8_t IF_TSRESOL     = 9;
constexpr uint8_t IF_TZONE       = 10;
constexpr uint8_t IF_FILTER      = 11;
constexpr uint8_t IF_OS          = 12;
constexpr uint8_t IF_FCSLEN      = 13;
constexpr uint8_t IF_TSOFFSET    = 14;

typedef struct __attribute__((packed)) {
	uint32_t block_type;
	uint32_t block_total_length;
	uint32_t interface_id;
	uint32_t timestamp_high;
	uint32_t timestamp_low;
	uint32_t captured_len;
	uint32_t packet_len;
	uint32_t packet_data[0];
} enhanced_packet_block;

constexpr uint8_t EPB_FLAGS     = 2;
constexpr uint8_t EPB_HASH      = 3;
constexpr uint8_t EPB_DROPCOUNT = 4;

typedef struct __attribute__((packed)) {
	uint32_t block_type;
	uint32_t block_total_length;
	uint32_t packet_len;
	uint32_t packet_data[0];
} simple_packet_block;

typedef struct __attribute__((packed)) {
	uint32_t block_type;
	uint32_t block_total_length;
	uint16_t record_type;
	uint16_t record_length;
	uint32_t record_value[0];
} name_resolution_block;

constexpr uint8_t NRES_ENDOFRECORD = 0;
constexpr uint8_t NRES_IP4RECORD   = 1;
constexpr uint8_t NRES_IP6RECORD   = 2;

constexpr uint8_t NS_DNSNAME    = 2;
constexpr uint8_t NS_DNSIP4ADDR = 3;
constexpr uint8_t NS_DNSIP6ADDR = 4;

typedef struct __attribute__((packed)) {
	uint32_t block_type;
	uint32_t block_total_length;
	uint32_t interface_id;
	uint32_t timestamp_high;
	uint32_t timestamp_low;
	option_header options[0];
} interface_statistics_block;

constexpr uint8_t ISB_STARTTIME    = 2;
constexpr uint8_t ISB_ENDTIME      = 3;
constexpr uint8_t ISB_IFRECV       = 4;
constexpr uint8_t ISB_IFDROP       = 5;
constexpr uint8_t ISB_FILTERACCEPT = 6;
constexpr uint8_t ISB_OSDROP       = 7;
constexpr uint8_t ISB_USRDELIV     = 8;

constexpr uint32_t BLOCK_TYPE_INTERFACE            = 0x00000001ul;
constexpr uint32_t BLOCK_TYPE_SIMPLE_PACKET        = 0x00000003ul;
constexpr uint32_t BLOCK_TYPE_NAME_RESOLUTION      = 0x00000004ul;
constexpr uint32_t BLOCK_TYPE_INTERFACE_STATISTICS = 0x00000005ul;
constexpr uint32_t BLOCK_TYPE_ENHANCED_PACKET      = 0x00000006ul;
constexpr uint32_t BLOCK_TYPE_SECTION_HEADER       = 0x0a0d0d0aul;

typedef struct {
	int fd;
	section_header_block * section_header;
	size_t section_header_size;
	size_t next_section_option_offset;
	interface_description_block * interface_description;
	size_t interface_description_size;
	size_t next_interface_option_offset;
} PCAPNG_HANDLE;

typedef enum {
	PCAPNG_OK = 0,
	PCAPNG_INVALID_HANDLE,
	PCAPNG_FILE_NOT_ALLOWED,
	PCAPNG_FILE_EXISTS,
	PCAPNG_TOO_MANY_FILES_OPEN,
	PCAPNG_NO_MEMORY,
	PCAPNG_FILE_WRITE_ERROR,
	PCAPNG_MMAP_FAILED,
} PCAPNG_RESULT;

/**
 * Create a new PCAP-NG file and set aside space in the section and
 * interface headers for options to be recorded/added while packets
 * are captured.
 *
 * @param handle                  pointer to a handle that is populated by this call
 * @param filename                file to create
 * @param section_options         list of initial section options, can be NULL
 * @param section_options_space   size in bytes dedicated to storing extra section
 *                                options; will be rounded up so section header
 *                                is an integer number of memory pages
 * @param link_type
 * @param snaplen
 * @param interface_options       list of initial interface options, can be NULL
 * @param interface_options_space size in bytes dedicated to storing extra interface
 *                                options; will be rounded up so interface header
 *                                is an integer number of memory pages
 * @returns                       0 on success, non zero result code otherwisex
 */
PCAPNG_RESULT pcapng_create( PCAPNG_HANDLE * handle,
			     const char * filename,
			     const option_header * section_options,
			     size_t section_options_space,
			     uint16_t link_type,
			     uint32_t snaplen,
			     const option_header * interface_options,
			     size_t interface_options_space );

PCAPNG_RESULT pcapng_append_section_option( PCAPNG_HANDLE * handle,
					    const option_header * section_option );

PCAPNG_RESULT pcapng_append_interface_option( PCAPNG_HANDLE * handle,
					      const option_header * interface_option );

PCAPNG_RESULT pcapng_append_packet( PCAPNG_HANDLE * handle,
				    const enhanced_packet_block * packet );

PCAPNG_RESULT pcapng_close( PCAPNG_HANDLE * handle );

#endif /* PCAPNG_DOT_H */
