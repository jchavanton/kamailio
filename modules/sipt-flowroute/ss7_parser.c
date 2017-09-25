/*
 *
 * Copyright (C) 2013 Voxbone SA
 *
 * Parsing code derrived from libss7 Copyright (C) Digium
 *
 *
 * This file is part of SIP-Router, a free SIP server.
 *
 * SIP-Router is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * SIP-Router is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 */

#include "../../mem/mem.h"
#include "ss7.h"
#include <string.h>
#include <stddef.h>

static char digit2char(unsigned char digit)
{
	switch (digit & 0xf) {
		case 0:
			return '0';
		case 1:
			return '1';
		case 2:
			return '2';
		case 3:
			return '3';
		case 4:
			return '4';
		case 5:
			return '5';
		case 6:
			return '6';
		case 7:
			return '7';
		case 8:
			return '8';
		case 9:
			return '9';
		case 15:
			return '#';
		default:
			return 0;
	}
}


static void isup_get_number(char *dest, unsigned char *src, int srclen, int oddeven)
{
	int i;

	if (oddeven < 2) {
		/* BCD odd or even */

		for (i = 0; i < ((srclen * 2) - oddeven); i++) {
			dest[i] = digit2char(src[i/2] >> ((i % 2) ? 4 : 0));
		}
	} else {
		/* oddeven = 2 for IA5 characters (one byte per character) */
		for (i = 0; i < srclen; i++) {
			dest[i] = src[i];
		}
	}
	dest[i] = '\0';
}


/*
 * This macro returns the address of the optional part within an
 * isup_msg struct, or NULL if the isup_msg's optional_pointer is 0.
 */
#define address_of_optional_part(msg) \
	((msg).optional_pointer ? \
		(&(msg).optional_pointer + (msg).optional_pointer) : NULL)

#define address_of(msg, pointer_field) \
	((msg).pointer_field ? \
		(&(msg).pointer_field + (msg).pointer_field) : NULL)

#define end_of(p) ((p) + *(p))

/* Test wither an address falls within the range specified by a pointer
 * to a (length, data) segment. */
#define address_in(adr, r) ((adr) >= (r) && (adr) < end_of(r))


/*
 * Return zero iff the specified buffer contains a structurally
 * valid ISUP-IAM message. Includes safe bounds-checking.
 */
int validate_iam(str body)
{
	unsigned char* service_info = NULL;
	unsigned char* called_party = NULL;
	unsigned char* optional = NULL;
	unsigned char* end_of_params = NULL;
	int result = 0;

	if (body.s == NULL || body.len <= 0) {
		DEBUG("No ISUP Message Found\n");
		result = IAM_NO_BODY;
		goto end;
	}

	unsigned char* end = (unsigned char*)body.s + body.len;

	isup_iam_t *iam = (isup_iam_t*)body.s;

	if (iam->type != ISUP_IAM) {
		result = IAM_NOT_IAM;
		goto end;
	}

	/* Buffer must be at least long enough for fixed part, two bytes
	 * of variable data, and one terminating NULL byte. */
	if (end < &(iam->variable_data[0]) + 3) {
		result = IAM_OVERFLOW;
		goto end;
	}

	/* Now that we know the buffer is long enough to safely read the pointers
	 * to the mandatory variable-length parameters, we can check those. */
	service_info = address_of(*iam, user_service_ptr);
	called_party = address_of(*iam, called_party_ptr);
	optional = address_of(*iam, optional_pointer);

	if (!service_info || !called_party) {
		result = IAM_MISSING_PARAM;
		goto end;
	}

	/* Pointers must not point before the variable data section */
	if (service_info < iam->variable_data ||
		called_party < iam->variable_data ||
		(optional && optional < iam->variable_data)) {
		result = IAM_BAD_POINTER;
		goto end;
	}

	/* Mandatory parameters must not overflow terminating NUL */
	if (service_info > (end-2) || end_of(service_info) > (end-2) ||
		called_party > (end-2) || end_of(called_party) > (end-2)) {
		result = IAM_OVERFLOW;
		goto end;
	}

	/* It's an error if either pointer intersects the other mandatory
	 * parameter, or if either segment overlaps the start of optionals. */
	if (address_in(service_info, called_party) ||
		address_in(called_party, service_info) ||
		address_in(optional, service_info) ||
		address_in(optional, called_party)) {
		result = IAM_BAD_POINTER;
		goto end;
	}

	/* All optional parameters should have lengths that add up neatly
	 * to the end of available space in the buffer, less the terminal */
	while (optional && (optional < end) && (*optional != 0)) {
		struct isup_parm_opt *parm = (struct isup_parm_opt*)(optional);
		/* No optional param may touch the end of the buffer! */
		if (&parm->len > (end-2) || ((&parm->data[0] + parm->len) > (end-1))) {
			result = IAM_OVERFLOW;
			goto end;
		}
		/* Advance to next optional header */
		optional = &parm->data[0] + parm->len;
	}

	/* A terminating 0 should follow the optionals, or follow the second
	 * mandatory parameter if no options were present. */
	end_of_params = MAX(optional, end_of(MAX(service_info, called_party)));
	if (*end_of_params != 0) {
		result = IAM_BAD_TERMINAL;
		goto end;
	}

	if (end_of_params != end - 1) {
		result = IAM_UNDERFLOW;
		goto end;
	}

end:
	if (result < 0) {
		DEBUG("message not a valid IAM\n");
	}
	return result;
}


/*
 * Return pointer to the specified optional header in IAM, ACM, or CPG
 * message; for other message types, or if the optional header does not
 * exist in the message, return NULL.
 *
 * This function also checks for buffer overruns and returns NULL if the
 * specified header exists but its length extends past the end of buf.
 */
static isup_parm_opt_t *get_optional_header(unsigned char header, str body)
{
	unsigned char* optional = NULL;
	unsigned char* end = (unsigned char*)&body.s + body.len;
	union isup_msg *message = (union isup_msg*)body.s;

	if(message->type == ISUP_IAM) {
		optional = address_of_optional_part(message->iam);
	} else if(message->type == ISUP_ACM) {
		optional = address_of_optional_part(message->acm);
	} else if(message->type == ISUP_CPG) {
		optional = address_of_optional_part(message->cpg);
	}

	/* If there is no optional part, or if the message type is none
	 * of IAM, ACM, or CPG, return failure. */
	if (!optional) {
		return NULL;
	}

	while ((optional < end) && (*optional != 0)) {
		struct isup_parm_opt *parm = (struct isup_parm_opt*)(optional);

		/* Check bounds of the header against end of buffer. */
		if (&parm->len >= end || ((&parm->data[0] + parm->len) > end)) {
			return NULL;
		}
		if (parm->type == header) {
			return parm;
		}
		/* Advance to next optional header */
		optional = &parm->data[0] + parm->len;
	}

	return NULL;
}

int isup_get_hop_counter(str body)
{
	if (validate_iam(body)) {
		return -1;
	}

	isup_parm_opt_t *opt = get_optional_header(ISUP_PARM_HOP_COUNTER, body);
	if (opt) {
		return opt->data[0] & 0x1F;
	}
	return -1;
}

int isup_get_event_info(str body)
{
	if (validate_iam(body)) {
		return -1;
	}

	struct isup_cpg_fixed * message = (struct isup_cpg_fixed*)body.s;

	// not a CPG? do nothing
	if(message->type != ISUP_CPG)
	{
		return -1;
	}

	int len = body.len;
	/* Message Type = 1 */
	len -= offsetof(struct isup_cpg_fixed, event_info);

	if (len < 1) {
		return -1;
	}

	return (int)message->event_info;
}

int isup_get_cpc(str body)
{
	if (validate_iam(body)) {
		return -1;
	}

	struct isup_iam_fixed *message = (struct isup_iam_fixed*)body.s;
	int len = body.len;
	/* Message Type = 1 */
	len -= offsetof(struct isup_iam_fixed, calling_party_category);

	if (len < 1) {
		return -1;
	}

	return (int)message->calling_party_category;
}

int isup_get_calling_party_nai(str body)
{
	if (validate_iam(body)) {
		return -1;
	}

	isup_parm_opt_t *opt = get_optional_header(ISUP_PARM_CALLING_PARTY_NUM, body);
	if (opt && opt->len > 0) {
		return opt->data[0] & 0x7F;
	}
	return -1;
}

int isup_get_screening(str body)
{
	if (validate_iam(body)) {
		return -1;
	}

	isup_parm_opt_t *opt = get_optional_header(ISUP_PARM_CALLING_PARTY_NUM, body);
	if (opt && opt->len > 1) {
		return opt->data[1] & 0x03;
	}
	return -1;
}

int isup_get_presentation(str body)
{
	if (validate_iam(body)) {
		return -1;
	}

	isup_parm_opt_t *opt = get_optional_header(ISUP_PARM_CALLING_PARTY_NUM, body);
	if (opt && opt->len > 1) {
		return (opt->data[1] >> 2) & 0x03;
	}
	return -1;
}


/*
 * Extract the charge number from an ISUP message buffer, if present;
 * Store it in a given buffer, which must be allocated with at least
 * `maxlen` bytes.
 *
 * This function does NOT store a terminating '\0'; `maxlen` is the max
 * number of bytes that will be used to store the actual charge number.
 *
 * Return the number of bytes stored, or a negative value in case of error:
 *      -1      ISUP body is not valid IAM
 *      -2      maxlen not large enough to store charge num
 */
int isup_get_charge_number(str body, char *buf, int maxlen)
{
	if(validate_iam(body)) {
		return -1;
	}

	isup_parm_opt_t *opt = get_optional_header(ISUP_PARM_CHARGE_NUMBER, body);
	if (opt && opt->len > 2) {
		int oddeven = (opt->data[0] >> 7) & 0x01;

		int len = (opt->len - 2) * 2 - oddeven;

		/* Ensure buffer can hold the charge number */
		if (len > maxlen) {
			return -2;
		}

		isup_get_number(buf, &opt->data[2], opt->len-2, oddeven);
		return len;
	}
	return -1;
}

/*
 * Extract the JIP from an ISUP message buffer, if present. Store it in
 * a given buffer, which must be allocated with exactly 6 bytes. This
 * function does not store a terminating '\0'.
 *
 * Returns 0 on success, -1 if the ISUP body is invalid or has no JIP.
 */
int isup_get_jip(str body, char *buf)
{
	if(validate_iam(body)) {
		return -1;
	}

	isup_parm_opt_t *opt = get_optional_header(ISUP_PARM_JIP, body);
	/* JIP must be exactly 6 digits binary-coded decimal */
	if (opt && opt->len == 3) {
		isup_get_number(buf, &opt->data[0], opt->len, 0);
		return 0;
	}
	return -1;
}

int isup_get_oli(str body)
{
	if(validate_iam(body)) {
		return -1;
	}

	isup_parm_opt_t *opt = get_optional_header(ISUP_PARM_ORIG_LINE_INFO, body);
	if (opt && opt->len > 0) {
		return opt->data[0];
	}
	return -1;
}
