/*
 * Copyright (c) 2018 Kernel Labs Inc. All Rights Reserved
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

#include <libklvanc/vanc.h>

#include "core-private.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

static const char *dbb1_types(unsigned char val)
{
	/* DBB1 Payload Type (SMPTE 12-2:2014 Table 2) */

	if (val >= 0x08 && val <= 0x7c)
		return "Locally generated time address and user data";

	switch (val) {
	case 0x00: return "Linear time code (ATC_LTC)";
	case 0x01: return "ATC_VITC1";
	case 0x02: return "ATC_VITC2";
	case 0x03:
	case 0x04:
	case 0x05:
		return "User defined";
	case 0x06:
		return "Film data block (transferred from reader)";
	case 0x07:
		return "Production data block (transferered from reader)";
	case 0x7d:
		return "Video tape data block (locally generated)";
	case 0x7e:
		return "Film data block (locally generated)";
	case 0x7f:
		return "Production data block (locally generated)";
	default:
		return "Reserved";
	}
}

void klvanc_free_SMPTE_12_2(void *p)
{
	struct klvanc_packet_smpte_12_2_s *pkt = p;

	if (pkt == NULL)
		return;

	free(pkt);
}

int parse_SMPTE_12_2(struct klvanc_context_s *ctx,
		   struct klvanc_packet_header_s *hdr, void **pp)
{
	if (ctx->verbose)
		PRINT_DEBUG("%s()\n", __func__);

	if (hdr->payloadLengthWords != 0x10)
		return -EINVAL;

	struct klvanc_packet_smpte_12_2_s *pkt = calloc(1, sizeof(*pkt));
	if (!pkt)
		return -ENOMEM;

	memcpy(&pkt->hdr, hdr, sizeof(*hdr));

	/* DBB1 Payload Type (SMPTE 12-2:2014 Sec 6.2.1) */
	for (int i = 0; i < 8; i++) {
		pkt->dbb1 |= ((hdr->payload[i] >> 3) & 0x01) << i;
	}

	/* DBB2 Payload Type (SMPTE 12-2:2014 Sec 6.2.2) */
	for (int i = 0; i < 8; i++) {
		pkt->dbb2 |= ((hdr->payload[i+8] >> 3) & 0x01) << i;
	}

	if (pkt->dbb1 == 0x01 || pkt->dbb1 == 0x02) {
		/* ATC_VITC */
		pkt->frames = (hdr->payload[0] >> 4) & 0x0f;
		if (hdr->payload[2] & 0x10)
			pkt->frames += 10;
		if (hdr->payload[2] & 0x20)
			pkt->frames += 20;
		pkt->seconds = (hdr->payload[4] >> 4) & 0x0f;
		if (hdr->payload[6] & 0x10)
			pkt->seconds += 10;
		if (hdr->payload[6] & 0x20)
			pkt->seconds += 20;
		if (hdr->payload[6] & 0x40)
			pkt->seconds += 40;
		pkt->minutes = (hdr->payload[8] >> 4) & 0x0f;
		if (hdr->payload[10] & 0x10)
			pkt->minutes += 10;
		if (hdr->payload[6] & 0x20)
			pkt->minutes += 20;
		if (hdr->payload[6] & 0x40)
			pkt->minutes += 40;
		pkt->hours = (hdr->payload[12] >> 4) & 0x0f;
		if (hdr->payload[14] & 0x10)
			pkt->hours += 10;
		if (hdr->payload[14] & 0x20)
			pkt->hours += 20;
		if (hdr->payload[14] & 0x40)
			pkt->hours += 40;
	} else {
		PRINT_DEBUG("DBB type parsing not yet implemented for dbb1 type 0x%x\n",
			pkt->dbb1);
	}

	if (ctx->callbacks && ctx->callbacks->smpte_12_2)
		ctx->callbacks->smpte_12_2(ctx->callback_context, ctx, pkt);

	*pp = pkt;
	return KLAPI_OK;
}

int klvanc_dump_SMPTE_12_2(struct klvanc_context_s *ctx, void *p)
{
	struct klvanc_packet_smpte_12_2_s *pkt = p;

	if (ctx->verbose)
		PRINT_DEBUG("%s() %p\n", __func__, (void *)pkt);

	PRINT_DEBUG(" DBB1 = %02x (%s)\n", pkt->dbb1, dbb1_types(pkt->dbb1));
	PRINT_DEBUG(" DBB2 = %02x\n", pkt->dbb2);
	PRINT_DEBUG(" DBB2 VITC line select = 0x%02x\n", pkt->dbb2 & 0x1f);
	PRINT_DEBUG(" DBB2 line duplication flag = %d\n", (pkt->dbb2 >> 5) & 0x01);
	PRINT_DEBUG(" DBB2 time code validity = %d\n", (pkt->dbb2 >> 6) & 0x01);
	PRINT_DEBUG(" DBB2 (User bits) process bit = %d\n", (pkt->dbb2 >> 7) & 0x01);

	PRINT_DEBUG(" Timecode = %02d:%02d:%02d:%02d\n", pkt->hours, pkt->minutes,
		    pkt->seconds, pkt->frames);

	return 0;
}

int klvanc_convert_SMPTE_12_2_to_packetBytes(struct klvanc_context_s *ctx,
					   const struct klvanc_packet_smpte_12_2_s *pkt,
					   uint8_t **bytes, uint16_t *byteCount)
{
	uint8_t *buf;

	if (!pkt || !bytes) {
		return -1;
	}

	struct klbs_context_s *bs = klbs_alloc();
	if (bs == NULL)
		return -1;

	buf = malloc(16);
	if (buf == NULL) {
		klbs_free(bs);
		return -1;
	}

	/* Serialize the Timecode into a binary blob conforming to SMPTE 12-1 */
	klbs_write_set_buffer(bs, buf, 16);

        /* FIXME: Assumes VITC code */

	/* See SMPTE 12-2:2014 Table 6 */
	if (pkt->dbb1 == 0x01 || pkt->dbb1 == 0x02) {
		/* UDW 1 */
		klbs_write_bits(bs, pkt->frames % 10, 4); /* Units of frames 1-8 */
		klbs_write_bits(bs, 0x00, 4); /* b0-b3 */
		/* UDW 2 */
		klbs_write_bits(bs, 0x00, 4); /* Binary group 1 */
		klbs_write_bits(bs, 0x00, 4); /* b0-b3 */
		/* UDW 3 */
		klbs_write_bits(bs, 0x00, 2); /* Flags */
		klbs_write_bits(bs, (pkt->frames / 20) & 0x01, 1); /* Tens of frames 20 */
		klbs_write_bits(bs, (pkt->frames / 10) & 0x01, 1); /* Tens of frames 10 */
		klbs_write_bits(bs, 0x00, 4); /* b0-b3 */
		/* UDW 4 */
		klbs_write_bits(bs, 0x00, 4); /* Binary group 2 */
		klbs_write_bits(bs, 0x00, 4); /* b0-b3 */
		/* UDW 5 */
		klbs_write_bits(bs, pkt->seconds % 10, 4); /* Units of seconds 1-8 */
		klbs_write_bits(bs, 0x00, 4); /* b0-b3 */
		/* UDW 6 */
		klbs_write_bits(bs, 0x00, 4); /* Binary group 3 */
		klbs_write_bits(bs, 0x00, 4); /* b0-b3 */
		/* UDW 7 */
		klbs_write_bits(bs, 0x00, 1); /* Flag */
		klbs_write_bits(bs, (pkt->seconds / 40) & 0x01, 1); /* Tens of seconds 40 */
		klbs_write_bits(bs, (pkt->seconds / 20) & 0x01, 1); /* Tens of seconds 20 */
		klbs_write_bits(bs, (pkt->seconds / 10) & 0x01, 1); /* Tens of seconds 10 */
		klbs_write_bits(bs, 0x00, 4); /* b0-b3 */
		/* UDW 8 */
		klbs_write_bits(bs, 0x00, 4); /* Binary group 4 */
		klbs_write_bits(bs, 0x00, 4); /* b0-b3 */
		/* UDW 9 */
		klbs_write_bits(bs, pkt->minutes % 10, 4); /* Units of minutes 1-8 */
		klbs_write_bits(bs, 0x00, 4); /* b0-b3 */
		/* UDW 10 */
		klbs_write_bits(bs, 0x00, 4); /* Binary group 5 */
		klbs_write_bits(bs, 0x00, 4); /* b0-b3 */
		/* UDW 11 */
		klbs_write_bits(bs, 0x00, 1); /* Flag */
		klbs_write_bits(bs, (pkt->minutes / 40) & 0x01, 1); /* Tens of minutes 40 */
		klbs_write_bits(bs, (pkt->minutes / 20) & 0x01, 1); /* Tens of minutes 20 */
		klbs_write_bits(bs, (pkt->minutes / 10) & 0x01, 1); /* Tens of minutes 10 */
		klbs_write_bits(bs, 0x00, 4); /* b0-b3 */
		/* UDW 12 */
		klbs_write_bits(bs, 0x00, 4); /* Binary group 6 */
		klbs_write_bits(bs, 0x00, 4); /* b0-b3 */
		/* UDW 13 */
		klbs_write_bits(bs, pkt->hours % 10, 4); /* Units of hours 1-8 */
		klbs_write_bits(bs, 0x00, 4); /* b0-b3 */
		/* UDW 14 */
		klbs_write_bits(bs, 0x00, 4); /* Binary group 7 */
		klbs_write_bits(bs, 0x00, 4); /* b0-b3 */
		/* UDW 15 */
		klbs_write_bits(bs, 0x00, 2); /* Flags */
		klbs_write_bits(bs, (pkt->hours / 20) & 0x01, 1); /* Tens of hours 20 */
		klbs_write_bits(bs, (pkt->hours / 10) & 0x01, 1); /* Tens of hours 10 */
		klbs_write_bits(bs, 0x00, 4); /* b0-b3 */
		/* UDW 16 */
		klbs_write_bits(bs, 0x00, 4); /* Binary group 8 */
		klbs_write_bits(bs, 0x00, 4); /* b0-b3 */
	} else {
		PRINT_DEBUG("DBB1 type not yet supported: %02x\n", pkt->dbb1);
	}

	klbs_write_buffer_complete(bs);

	/* Now go back and fill in DBB1/DBB2 */
	for (int i = 0; i < 8; i++) {
		buf[i] |= ((pkt->dbb1 >> i) & 0x01) << 3;
	}
	for (int i = 0; i < 8; i++) {
		buf[i+8] |= ((pkt->dbb2 >> i) & 0x01) << 3;
	}

#if 0
	PRINT_DEBUG("Resulting buffer size=%d\n", klbs_get_byte_count(bs));
	PRINT_DEBUG(" ->payload  = ");
	for (int i = 0; i < klbs_get_byte_count(bs); i++) {
		PRINT_DEBUG("%02x ", buf[i]);
	}
	PRINT_DEBUG("\n");
#endif

	*bytes = buf;
	*byteCount = klbs_get_byte_count(bs);
	klbs_free(bs);

	return 0;
}

int klvanc_convert_SMPTE_12_2_to_words(struct klvanc_context_s *ctx,
				     struct klvanc_packet_smpte_12_2_s *pkt,
				     uint16_t **words, uint16_t *wordCount)
{
	uint8_t *buf;
	uint16_t byteCount;
	int ret;

	ret = klvanc_convert_SMPTE_12_2_to_packetBytes(ctx, pkt, &buf, &byteCount);
	if (ret != 0)
		return -1;

	/* Create the final array of VANC bytes (with correct DID/SDID,
	   checksum, etc) */
	klvanc_sdi_create_payload(0x60, 0x60, buf, byteCount, words, wordCount, 10);

	free(buf);

	return 0;
}
