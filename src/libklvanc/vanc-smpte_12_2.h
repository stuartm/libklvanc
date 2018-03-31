/*
 * Copyright (c) 2016 Kernel Labs Inc. All Rights Reserved
 *
 * Address: Kernel Labs Inc., PO Box 745, St James, NY. 11780
 * Contact: sales@kernellabs.com
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

/**
 * @file	vanc-smpte_12_2.h
 * @author	Devin Heitmueller <dheitmueller@kernellabs.com>
 * @copyright	Copyright (c) 2018 Kernel Labs Inc. All Rights Reserved.
 * @brief	SMPTE ST 12-2 Timecode over VANC
 */

#ifndef _VANC_SMPTE_12_2_H
#define _VANC_SMPTE_12_2_H

#include <libklvanc/vanc-packets.h>

#ifdef __cplusplus
extern "C" {
#endif  

/**
 * @brief       TODO - Brief description goes here.
 */
struct klvanc_packet_smpte_12_2_s
{
	struct klvanc_packet_header_s hdr;

	unsigned char payload[256];
	unsigned int payloadLengthBytes;

	uint8_t dbb1;
	uint8_t dbb2;

	uint8_t vitc_line_select;
	uint8_t line_duplication_flag;
	uint8_t tc_validity_flag;
	uint8_t user_bits_process_flag;

	/* Timecode data */
	uint8_t frames;
	uint8_t seconds;
	uint8_t minutes;
	uint8_t hours;
};

/**
 * @brief       TODO - Brief description goes here.
 * @param[in]	struct vanc_context_s *ctx, void *p - Brief description goes here.
 * @return	0 - Success
 * @return	< 0 - Error
 */
int klvanc_alloc_SMPTE_12_2(uint16_t opId, struct klvanc_packet_smpte_12_2_s **pkt);

/**
 * @brief       TODO - Brief description goes here.
 * @param[in]	struct vanc_context_s *ctx, void *p - Brief description goes here.
 * @return	0 - Success
 * @return	< 0 - Error
 */
int klvanc_dump_SMPTE_12_2(struct klvanc_context_s *ctx, void *p);

/**
 * @brief       TODO - Brief description goes here.
 * @param[in]	void *p - Pointer to struct (klvanc_packet_smpte_12_2_s *)
 */
void klvanc_free_SMPTE_12_2(void *p);

/**
 * @brief	Convert type struct packet_smpte_12_2_s into a more traditional line of\n
 *              vanc words, so that we may push out as VANC data.
 *              On success, caller MUST free the resulting *words array.
 * @param[in]	struct packet_smpte_12_2_s *pkt - A SMPTE 12_2-2 VANC entry, received from the 12_2 parser
 * @param[out]	uint16_t **words - An array of words reppresenting a fully formed vanc line.
 * @param[out]	uint16_t *wordCount - Number of words in the array.
 * @return        0 - Success
 * @return      < 0 - Error
 * @return      -ENOMEM - Not enough memory to satisfy request
 */
int klvanc_convert_SMPTE_12_2_to_words(struct klvanc_context_s *ctx,
				     struct klvanc_packet_smpte_12_2_s *pkt,
				     uint16_t **words, uint16_t *wordCount);

/**
 * @brief	Convert type struct packet_smpte_12_2_s into a block of bytes which can be\n
 *              embedded into a VANC line
 *              On success, caller MUST free the resulting *words array.
 * @param[in]	struct packet_smpte_12_2_s *pkt - A SMPTE 12_2 VANC entry, received from the 12_2 parser
 * @param[out]	uint8_t **bytes - An array of words reppresenting a fully formed vanc line.
 * @param[out]	uint16_t *byteCount - Number of byes in the array.
 * @return        0 - Success
 * @return      < 0 - Error
 * @return      -ENOMEM - Not enough memory to satisfy request
 */
int klvanc_convert_SMPTE_12_2_to_packetBytes(struct klvanc_context_s *ctx,
					   const struct klvanc_packet_smpte_12_2_s *pkt,
					   uint8_t **bytes, uint16_t *byteCount);

#ifdef __cplusplus
};
#endif  

#endif /* _VANC_SMPTE_12_2_H */
