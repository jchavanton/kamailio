/*
 *
 * Copyright (C) 2013 Voxbone SA
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


#include "../../sr_module.h"
#include "../../parser/parse_param.h"
#include "../../data_lump.h"
#include "../../mem/mem.h"
#include "../../mod_fix.h"
#include "../../parser/parse_content.h"
#include "../../parser/parse_body.h"
#include "../../parser/parser_f.h"
#include "../../trim.h"
#include "ss7.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>


MODULE_VERSION

static int sipt_get_hop_counter(struct sip_msg *msg, pv_param_t *param, pv_value_t *res);
static int sipt_get_cpc(struct sip_msg *msg, pv_param_t *param, pv_value_t *res);
static int sipt_get_calling_party_nai(struct sip_msg *msg, pv_param_t *param, pv_value_t *res);
static int sipt_get_presentation(struct sip_msg *msg, pv_param_t *param, pv_value_t *res);
static int sipt_get_screening(struct sip_msg *msg, pv_param_t *param, pv_value_t *res);
static int sipt_get_charge_number(struct sip_msg *msg, pv_param_t *param, pv_value_t *res);
//static int sipt_get_charge_number_nai(struct sip_msg *msg, pv_param_t *param, pv_value_t *res);
//static int sipt_get_charge_number_npi(struct sip_msg *msg, pv_param_t *param, pv_value_t *res);
static int sipt_get_jip(struct sip_msg *msg, pv_param_t *param, pv_value_t *res);
static int sipt_get_oli(struct sip_msg *msg, pv_param_t *param, pv_value_t *res);


static int mod_init(void);
static void mod_destroy(void);


static cmd_export_t cmds[]={
	{0, 0, 0, 0, 0, 0}
};

static param_export_t params[]={
	{0,0,0}
};

static mi_export_t mi_cmds[] = {
	{ 0, 0, 0, 0, 0}
};

static pv_export_t mod_items[] = {
	{ {"sipt_presentation",  sizeof("sipt_presentation")-1}, PVT_OTHER,  sipt_get_presentation,    0,
			0, 0, 0, 0 },
	{ {"sipt_screening",  sizeof("sipt_screening")-1}, PVT_OTHER,  sipt_get_screening,    0,
			0, 0, 0, 0 },
	{ {"sipt_hop_counter",  sizeof("sipt_hop_counter")-1}, PVT_OTHER,  sipt_get_hop_counter,    0,
			0, 0, 0, 0 },
	{ {"sipt_cpc",  sizeof("sipt_cpc")-1}, PVT_OTHER,  sipt_get_cpc,    0,
			0, 0, 0, 0 },
	{ {"sipt_calling_party_nai",  sizeof("sipt_calling_party_nai")-1}, PVT_OTHER,  sipt_get_calling_party_nai,    0,
			0, 0, 0, 0 },
	{ {"sipt_charge_number",  sizeof("sipt_charge_number")-1}, PVT_OTHER,  sipt_get_charge_number,    0,
			0, 0, 0, 0 },
/*	{ {"sipt_charge_number_nai",  sizeof("sipt_charge_number_nai")-1}, PVT_OTHER,  sipt_get_charge_number_nai,    0,
			0, 0, 0, 0 },
	{ {"sipt_charge_number_npi",  sizeof("sipt_charge_number_npi")-1}, PVT_OTHER,  sipt_get_charge_number_npi,    0,
			0, 0, 0, 0 }, */
	{ {"sipt_jip",  sizeof("sipt_jip")-1}, PVT_OTHER,  sipt_get_jip,    0,
			0, 0, 0, 0 },
	{ {"sipt_oli",  sizeof("sipt_oli")-1}, PVT_OTHER,  sipt_get_oli,    0,
			0, 0, 0, 0 },
	{ {0, 0}, 0, 0, 0, 0, 0, 0, 0 }
};

struct module_exports exports = {
	"sipt",
	DEFAULT_DLFLAGS, /* dlopen flags */
	cmds,        /* exported functions */
	params,      /* exported parameters */
	0,           /* exported statistics */
	mi_cmds,     /* exported MI functions */
	mod_items,   /* exported pseudo-variables */
	0,           /* extra processes */
	mod_init,    /* module initialization function */
	0,           /* response function*/
	mod_destroy, /* destroy function */
	0            /* per-child init function */
};

str get_isup_body(struct sip_msg *msg) {
	str body = {0, 0};
	body.s = get_body_part(msg, TYPE_APPLICATION, SUBTYPE_ISUP, &body.len);
	return body;
}

static int sipt_get_hop_counter(struct sip_msg *msg, pv_param_t *param, pv_value_t *res)
{
	int counter = isup_get_hop_counter(get_isup_body(msg));
	if (counter < 0) {
		return -1;
	}
	pv_get_sintval(msg, param, res, counter);
	return 0;
}

static int sipt_get_cpc(struct sip_msg *msg, pv_param_t *param, pv_value_t *res)
{
	int cpc = isup_get_cpc(get_isup_body(msg));
	if (cpc < 0) {
		return -1;
	}
	pv_get_sintval(msg, param, res, cpc);
	return 0;
}

static int sipt_get_calling_party_nai(struct sip_msg *msg, pv_param_t *param, pv_value_t *res)
{
	int cp_nai = isup_get_calling_party_nai(get_isup_body(msg));
	if (cp_nai < 0) {
		return -1;
	}
	pv_get_sintval(msg, param, res, cp_nai);
	return 0;
}

static int sipt_get_presentation(struct sip_msg *msg, pv_param_t *param, pv_value_t *res)
{
	int presentation = isup_get_presentation(get_isup_body(msg));
	if (presentation < 0) {
		return -1;
	}
	pv_get_sintval(msg, param, res, presentation);
	return 0;
}

#define MAX_CHARGE_NUM_LEN 255

static int sipt_get_charge_number(struct sip_msg *msg, pv_param_t *param, pv_value_t *res)
{
	/* Managing memory for pseudovars in Kamailio is a Cthulhu-buggering
	 * nightmare, so we have little recourse but to allocate a static
	 * buffer which will be reused each time $sipt_charge_number is used. */
	static char CHARGE_NUMBER[MAX_CHARGE_NUM_LEN];

	/* Read charge number into the static buffer. */
	int len = isup_get_charge_number(
			get_isup_body(msg),
			CHARGE_NUMBER,
			MAX_CHARGE_NUM_LEN);
	if (len < 0) {
		return -1;
	}

	/* pv_get_strval will just copy the pointer out of this str, so it's
		* okay to hand it the address of a local */
	str chg_num = {CHARGE_NUMBER, len};
	if(pv_get_strval(msg, param, res, &chg_num)) {
		return -1;
	}
	return 0;
}

#define JIP_LEN 6

static int sipt_get_jip(struct sip_msg *msg, pv_param_t *param, pv_value_t *res)
{
	/* Returning a pointer to a static buffer is horrible, but YOLO. */
	static char JIP[JIP_LEN];

	if (isup_get_jip(get_isup_body(msg), JIP)) {
		return -1;
	}

	str jip = {JIP, JIP_LEN};
	if (pv_get_strval(msg, param, res, &jip)) {
		return -1;
	}

	return 0;
}

static int sipt_get_oli(struct sip_msg *msg, pv_param_t *param, pv_value_t *res)
{
	int oli = isup_get_oli(get_isup_body(msg));
	if (oli < 0) {
		return -1;
	}
	pv_get_sintval(msg, param, res, oli);
	return 0;
}

static int sipt_get_screening(struct sip_msg *msg, pv_param_t *param, pv_value_t *res)
{
	int screening = isup_get_screening(get_isup_body(msg));
	if (screening < 0) {
		return -1;
	}
	pv_get_sintval(msg, param, res, screening);
	return 0;
}


static int mod_init(void)
{
	return 0;
}


static void mod_destroy(void)
{
}
