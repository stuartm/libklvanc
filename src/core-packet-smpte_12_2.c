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
#if 0
	const struct klvanc_multiple_operation_message *m;

	if (!pkt || !bytes) {
		return -1;
	}

	if (pkt->so_msg.opID != 0xffff) {
		/* We don't currently support anything but Multiple Operation
		   Messages */
		PRINT_ERR("msg opid not 0xffff.  Provided=0x%x\n", pkt->so_msg.opID);
		return -1;
	}

	struct klbs_context_s *bs = klbs_alloc();
	if (bs == NULL)
		return -1;

	*bytes = malloc(255);
	if (*bytes == NULL) {
		klbs_free(bs);
		return -1;
	}

	m = &pkt->mo_msg;

	/* Serialize the SCTE 104 into a binary blob */
	klbs_write_set_buffer(bs, *bytes, 255);

	klbs_write_bits(bs, 0x08, 8); /* SMPTE 2010 Payload Descriptor */

	klbs_write_bits(bs, 0xffff, 16); /* reserved */

	klbs_write_bits(bs, m->messageSize, 16);
	klbs_write_bits(bs, m->protocol_version, 8);
	klbs_write_bits(bs, m->AS_index, 8);
	klbs_write_bits(bs, m->message_number, 8);
	klbs_write_bits(bs, m->DPI_PID_index, 16);
	klbs_write_bits(bs, m->SCTE35_protocol_version, 8);
	klbs_write_bits(bs, m->timestamp.time_type, 8);

	const struct klvanc_multiple_operation_message_timestamp *ts = &m->timestamp;
	switch(ts->time_type) {
	case 1:
		klbs_write_bits(bs, ts->time_type_1.UTC_seconds, 32);
		klbs_write_bits(bs, ts->time_type_1.UTC_microseconds, 16);
		break;
	case 2:
		klbs_write_bits(bs, ts->time_type_2.hours, 8);
		klbs_write_bits(bs, ts->time_type_2.minutes, 8);
		klbs_write_bits(bs, ts->time_type_2.seconds, 8);
		klbs_write_bits(bs, ts->time_type_2.frames, 8);
		break;
	case 3:
		klbs_write_bits(bs, ts->time_type_3.GPI_number, 8);
		klbs_write_bits(bs, ts->time_type_3.GPI_edge, 8);
		break;
	case 0:
		/* No time standard defined */
		break;
	default:
		PRINT_ERR("%s() unsupported time_type 0x%x, assuming no time.\n",
			__func__, ts->time_type);
		break;
	}

	klbs_write_bits(bs, m->num_ops, 8);
	for (int i = 0; i < m->num_ops; i++) {
		unsigned char *outBuf = NULL;
		uint16_t outSize = 0;
		const struct klvanc_multiple_operation_message_operation *o = &m->ops[i];
		switch (o->opID) {
		case MO_SPLICE_REQUEST_DATA:
			gen_splice_request_data(&o->sr_data, &outBuf, &outSize);
			break;
		case MO_SPLICE_NULL_REQUEST_DATA:
			gen_splice_null_request_data(&outBuf, &outSize);
			break;
		case MO_TIME_SIGNAL_REQUEST_DATA:
			gen_time_signal_request_data(&o->timesignal_data, &outBuf, &outSize);
			break;
		case MO_INSERT_DESCRIPTOR_REQUEST_DATA:
			gen_descriptor_request_data(&o->descriptor_data, &outBuf, &outSize);
			break;
		case MO_INSERT_DTMF_REQUEST_DATA:
			gen_dtmf_request_data(&o->dtmf_data, &outBuf, &outSize);
			break;
		case MO_INSERT_AVAIL_DESCRIPTOR_REQUEST_DATA:
			gen_avail_request_data(&o->avail_descriptor_data, &outBuf, &outSize);
			break;
		case MO_INSERT_SEGMENTATION_REQUEST_DATA:
			gen_segmentation_request_data(&o->segmentation_data, &outBuf, &outSize);
			break;
		case MO_PROPRIETARY_COMMAND_REQUEST_DATA:
			gen_proprietary_command_request_data(&o->proprietary_data, &outBuf, &outSize);
			break;
		case MO_INSERT_TIER_DATA:
			gen_tier_data(&o->tier_data, &outBuf, &outSize);
			break;
		case MO_INSERT_TIME_DESCRIPTOR:
			gen_time_descriptor(&o->time_data, &outBuf, &outSize);
			break;
		default:
			PRINT_ERR("Unknown operation type 0x%04x\n", o->opID);
			continue;
		}
		/* FIXME */

		klbs_write_bits(bs, o->opID, 16);
		klbs_write_bits(bs, outSize, 16);
		for (int j = 0; j < outSize; j++) {
			klbs_write_bits(bs, outBuf[j], 8);
		}
		free(outBuf);
	}
	klbs_write_buffer_complete(bs);

	/* Recompute the total message size now that everything has been serialized to
	   a single buffer.  Note we subtract 1 from the total because this buffer
	   represents the SMPTE 2010 packet, not the multiple operation message payload */
	uint16_t buffer_size = klbs_get_byte_count(bs) - 1;
	(*bytes)[3] = buffer_size >> 8;
	(*bytes)[4] = buffer_size & 0xff;

#if 0
	PRINT_DEBUG("Resulting buffer size=%d\n", klbs_get_byte_count(bs));
	PRINT_DEBUG(" ->payload  = ");
	for (int i = 0; i < klbs_get_byte_count(bs); i++) {
		PRINT_DEBUG("%02x ", (*bytes)[i]);
	}
	PRINT_DEBUG("\n");
#endif

	*byteCount = klbs_get_byte_count(bs);
	klbs_free(bs);
#endif
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
