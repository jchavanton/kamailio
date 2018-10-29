/*
 * Copyright (C) 2017 Julien Chavanton jchavanton@gmail.com
 *
 * This file is part of Kamailio, a free SIP server.
 *
 * Kamailio is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * Kamailio is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "rtp_media_server.h"

MODULE_VERSION

static int mod_init(void);
static void mod_destroy(void);
static int child_init(int);

static rms_session_info_t *rms_session_list;
str playback_fn = {0, 0};
str log_fn = {0, 0};

static rms_t rms;

static rms_session_info_t * rms_session_search(char *callid, int len);
static int fixup_rms_media_start(void** param, int param_no);

static cmd_export_t cmds[] = {
	{"rms_media_start", (cmd_function)rms_media_start,1,fixup_rms_media_start,0,ANY_ROUTE },
	{"rms_sdp_offer", (cmd_function)rms_sdp_offer,0,0,0,ANY_ROUTE },
	{"rms_sdp_answer", (cmd_function)rms_sdp_answer,0,0,0,ANY_ROUTE },
	{"rms_media_stop", (cmd_function)rms_media_stop,0,0,0,ANY_ROUTE },
	{"rms_sessions_dump", (cmd_function)rms_sessions_dump,0,0,0,ANY_ROUTE },
	{0, 0, 0, 0, 0, 0}
};

static param_export_t mod_params[]={
	{"log_file_name", PARAM_STR, &log_fn},
	{0,0,0}
};

struct module_exports exports = {
	"rtp_media_server",
	DEFAULT_DLFLAGS, /* dlopen flags */
	cmds,
	mod_params,
	0,           /* RPC export */
	0,
	0,
	mod_init,
	child_init,
	mod_destroy,
};

static int fixup_rms_media_start(void** param, int param_no) {
		if (param_no == 1)
			return fixup_spve_null(param, 1);
		LM_ERR("invalid parameter count [%d]\n", param_no);
		return -1;
}

/**
 * @return 0 to continue to load the OpenSER, -1 to stop the loading
 * and abort OpenSER.
 */
static int mod_init(void) {
	LM_INFO("RTP media server module init\n");
	rms.udp_start_port = 50000;
	rms.udp_end_port = 60000;
	rms.udp_last_port = 50000;
	rms_media_init();
	rms_session_list = ortp_malloc(sizeof(rms_session_info_t));
	clist_init(rms_session_list,next,prev);

	register_procs(1);
	if (load_tm_api(&tmb)!=0) {
		LM_ERR( "can't load TM API\n");
		return -1;
	}
	FILE * log_file =  fopen (log_fn.s, "w+");
	if (log_file) {
		LM_INFO("ortp logs are redirected [%s]\n", log_fn.s);
	} else {
		log_file = stdout;
		LM_INFO("ortp can not open logs file [%s]\n", log_fn.s);
	}
	ortp_set_log_file(log_file);
	ortp_set_log_level_mask(NULL, ORTP_MESSAGE|ORTP_WARNING|ORTP_ERROR|ORTP_FATAL);
	return(0);
}

/**
 * Called only once when OpenSER is shuting down to clean up module
 * resources.
 */
static void mod_destroy() {
	rms_media_destroy();
	LM_INFO("RTP media server module destroy\n");
	return;
}

void rms_signal_handler(int signum) {
	LM_INFO("signal received [%d]\n", signum);
}

// this is to interact/control the session and media streams that are runing is separate threads
void rms_session_manage_loop() {
	while(1) {
		lock(&session_list_mutex);
		rms_session_info_t *si;
		clist_foreach(rms_session_list, si, next){
			if (si->action == RMS_HANGUP) {
				LM_NOTICE("session action hangup [%s]\n", si->callid.s);
				rms_hangup_call(si);
				si->action = RMS_STOP;
			} else if (si->action == RMS_STOP) {
				LM_NOTICE("session action stop [%s]\n", si->callid.s);
				rms_stop_media(&si->caller_media);
				rms_session_info_t *tmp = si->prev;
				rms_session_free(si);
				si = tmp;
			} else if (si->action == RMS_PLAY) {
				create_call_leg_media(&si->caller_media);
				LM_NOTICE("session action play [%s]\n", si->callid.s);
				rms_playfile(&si->caller_media, si->action_param.s);
				si->action = RMS_NONE;
			}
		}
		unlock(&session_list_mutex);
		usleep(2000);
	}
}


/**
 * The rank will be o for the main process calling this function,
 * or 1 through n for each listener process. The rank can have a negative
 * value if it is a special process calling the child init function.
 * Other then the listeners, the rank will equal one of these values:
 * PROC_MAIN      0  Main ser process
 * PROC_TIMER    -1  Timer attendant process 
 * PROC_FIFO     -2  FIFO attendant process
 * PROC_TCP_MAIN -4  TCP main process
 * PROC_UNIXSOCK -5  Unix domain socket server processes
 *
 * If this function returns a nonzero value the loading of OpenSER will
 * stop.
 */
static int child_init(int rank) {

	if (rank==PROC_MAIN) {
		int pid;
		pid=fork_process(PROC_XWORKER, "RTP_media_server", 1);
		if (pid<0)
			return -1; /* error */
		if(pid==0){
			rms_session_manage_loop();
			return 0;
		}
	}
	// signal(SIGINT,rms_signal_handler);
	int rtn = 0;
	return(rtn);
}

int rms_str_dup(str* dst, str* src, int shared) {
	if (!dst) {
		LM_ERR("dst null\n");
		return -1;
	}
	dst->len = 0;
	dst->s = NULL;
	if (!src) {
		LM_ERR("src null\n");
		return 0;
	}
	if ( (!src->s) || (src->len < 1)) {
		LM_ERR("empty src\n");
		return 0;
	}
	if (shared) {
		dst->s = ortp_malloc(src->len +1);
	} else {
		dst->s = pkg_malloc(src->len +1);
	}
	if (!dst->s) {
		LM_ERR("%s_malloc: can't allocate memory (%d bytes)\n", shared?"shm":"pkg", src->len);
		return -1;
	}
	strncpy(dst->s, src->s, src->len);
	dst->s[src->len] = '\0';
	dst->len = src->len;
	return 1;
}

int rms_get_sdp_info (rms_sdp_info_t *sdp_info, struct sip_msg* msg) {
	sdp_session_cell_t* sdp_session;
	sdp_stream_cell_t* sdp_stream;
	str media_ip, media_port;
	int sdp_session_num = 0;
	int sdp_stream_num = get_sdp_stream_num(msg);
	if(parse_sdp(msg) < 0) {
		LM_INFO("can not parse sdp\n");
		return 0;
	}
	sdp_info_t *sdp = (sdp_info_t*)msg->body;
	if(!sdp) {
		LM_INFO("sdp null\n");
		return 0;
	}
	rms_str_dup(&sdp_info->recv_body, &sdp->text, 1);
	if (!sdp_info->recv_body.s) goto error;
	LM_INFO("sdp body - type[%d]\n", sdp->type);
	if (sdp_stream_num > 1 || !sdp_stream_num) {
		LM_INFO("only support one stream[%d]\n", sdp_stream_num);
	}
	sdp_stream_num = 0;
	sdp_session = get_sdp_session(msg, sdp_session_num);
	if(!sdp_session) {
		return 0;
	} else {
		int sdp_stream_num = 0;
		sdp_stream = get_sdp_stream(msg, sdp_session_num, sdp_stream_num);
		if(!sdp_stream) {
			LM_INFO("can not get the sdp stream\n");
			return 0;
		} else {
			rms_str_dup(&sdp_info->payloads, &sdp_stream->payloads, 1);
			if (!sdp_info->payloads.s) goto error;
		}
	}
	if (sdp_stream->ip_addr.s && sdp_stream->ip_addr.len>0) {
		media_ip = sdp_stream->ip_addr;
	} else {
		media_ip = sdp_session->ip_addr;
	}
	rms_str_dup(&sdp_info->remote_ip, &media_ip, 1);
	if (!sdp_info->remote_ip.s) goto error;
	rms_str_dup(&media_port, &sdp_stream->port, 0);
	if (!media_port.s) goto error;
	sdp_info->remote_port = atoi(media_port.s);
	pkg_free(media_port.s);
	return 1;
error:
	rms_sdp_info_free(sdp_info);
	return 0;
}

static int rms_relay_call(struct sip_msg* msg) {
	if(!tmb.t_relay(msg,NULL,NULL)) {
		LM_INFO("t_ralay error\n");
		return -1;
	}
	return 1;
}

str reply_headers = {0,0};
str headers = str_init("Max-Forwards: 70" CRLF);
str method_bye = str_init("BYE");
str method_ok = str_init("OK");
str body = {0,0};
str server_socket = {0,0};
str to = str_init("caller@127.0.0.111");
str from = str_init("media_server@127.0.0.101");


#define PIT_MATCHES(param) \
	(pit->name.len == sizeof((param))-1 && \
		strncmp(pit->name.s, (param), sizeof((param))-1)==0)
int parse_from(struct sip_msg* msg, rms_session_info_t *si) {
	struct to_body * from = get_from(msg);
	LM_NOTICE("from[%.*s]tag[%.*s]\n", from->uri.len, from->uri.s, from->tag_value.len, from->tag_value.s);
	rms_str_dup(&si->remote_tag, &from->tag_value, 1);
	return 1;
}

int rms_answer_call(struct sip_msg* msg, rms_session_info_t *si) {
	int status = 0;
	str reason;
	str contact_hdr;
	rms_sdp_info_t *sdp_info = &si->sdp_info_offer;

	if(msg->REQ_METHOD!=METHOD_INVITE) {
		LM_ERR("only invite is supported for offer \n");
		return -1;
	}
	parse_from(msg, si);
	if (si->remote_tag.len == 0) {
		LM_ERR("can not find from tag\n");
		return -1;
	}
	status = tmb.t_newtran(msg);
	LM_INFO("invite new transaction[%d]\n", status);
	if(status < 0) {
		LM_ERR("error creating transaction \n");
		return -1;
	} else if (status == 0) {
		LM_DBG("retransmission");
		return 0;
	}

	char buffer[128];
	snprintf(buffer,128,"Contact: <sip:rms@%s:%d>\r\nContent-Type: application/sdp\r\n", si->local_ip.s, msg->rcv.dst_port);
	contact_hdr.len = strlen(buffer);
	contact_hdr.s = pkg_malloc(contact_hdr.len+1);
	strcpy(contact_hdr.s, buffer);
	sdp_info->local_ip.s = si->local_ip.s;
	sdp_info->local_ip.len = si->local_ip.len;
	rms_sdp_prepare_new_body(sdp_info, si->caller_media.pt->type);
	reason = method_ok;
	str to_tag;
	tmb.t_get_reply_totag(msg, &to_tag);
	rms_str_dup(&si->local_tag, &to_tag, 1);
	LM_INFO("local_uri[%s]local_tag[%s]\n", si->local_uri.s, si->local_tag.s);

	if(!tmb.t_reply_with_body(tmb.t_gett(),200,&reason,&sdp_info->new_body,&contact_hdr,&si->local_tag)) {
		LM_ERR("t_reply error");
		return 0;
	}
	LM_INFO("answered\n");
	return 1;
}

rms_session_info_t * rms_session_search(char *callid, int len) {
	lock(&session_list_mutex);
	rms_session_info_t *si;
	clist_foreach(rms_session_list, si, next){
		if (strncmp(callid, si->callid.s, len) == 0) {
			unlock(&session_list_mutex);
			return si;
		}
	}
	unlock(&session_list_mutex);
	return NULL;
}

int rms_hangup_call(rms_session_info_t *si) {
	uac_req_t uac_r;
	int result;

	LM_INFO("rms_hangup_call[%.*s]remote_uri[%s]local_uri[%s]\n", si->callid.len, si->callid.s, si->remote_uri.s, si->local_uri.s);
	LM_INFO("contact[%.*s]\n", si->contact_uri.len, si->contact_uri.s);
	dlg_t* dialog = NULL;
	if (tmb.new_dlg_uac(&si->callid, &si->local_tag, si->cseq, &si->local_uri, &si->remote_uri, &dialog) < 0) {
		LM_ERR("error in tmb.new_dlg_uac\n");
		return -1;
	}
	dialog->id.rem_tag.s = si->remote_tag.s;
	dialog->id.rem_tag.len = si->remote_tag.len;
	dialog->rem_target.s = si->contact_uri.s;
	dialog->rem_target.len = si->contact_uri.len;
	uac_r.ssock = &server_socket;
	set_uac_req(&uac_r, &method_bye, &headers, &body, dialog, TMCB_LOCAL_COMPLETED, NULL, NULL);
	result = tmb.t_request_within(&uac_r);
	if (result < 0) {
		LM_ERR("error in tmb.t_request\n");
		return -1;
	} else {
		LM_ERR("tmb.t_request_within ok\n");
	}
	return 1;
}

static int rms_check_msg(struct sip_msg* msg) {
	if (!msg || !msg->callid || !msg->callid->body.s) {
		LM_INFO("no callid ?\n");
		return -1;
	}
	if (rms_session_search(msg->callid->body.s, msg->callid->body.len))
		return -1;
	return 1;
}

int rms_session_free(rms_session_info_t *si) {
	clist_rm(si,next,prev);
	rms_sdp_info_free(&si->sdp_info_offer);
	rms_sdp_info_free(&si->sdp_info_answer);
	if (si->caller_media.pt) {
		payload_type_destroy(si->caller_media.pt);
		si->caller_media.pt = NULL;
	}
	if (si->callee_media.pt) {
		payload_type_destroy(si->callee_media.pt);
		si->callee_media.pt = NULL;
	}
	if (si->callid.s) {
		ortp_free(si->callid.s);
		si->callid.s = NULL;
	}
	if (si->contact_uri.s) {
		ortp_free(si->contact_uri.s);
		si->contact_uri.s = NULL;
	}
	if (si->local_ip.s) {
		ortp_free(si->local_ip.s);
		si->local_ip.s = NULL;
	}
//	if (si->remote_uri.s) {
//		ortp_free(si->remote_uri.s);
//		si->remote_uri.s = NULL;
//	}
//	if (si->local_uri.s) {
//		ortp_free(si->local_uri.s);
//		si->local_uri.s = NULL;
//	}
	ortp_free(si);
	si = NULL;
	return 1;
}

rms_session_info_t *rms_session_new(struct sip_msg* msg) {
	struct hdr_field* hdr = NULL;

	if (!rms_check_msg(msg))
		return NULL;
	rms_session_info_t *si = ortp_malloc(sizeof(rms_session_info_t));
	if (!si) {
		LM_ERR("can not allocate session info !\n");
		goto error;
	}
	memset(si,0,sizeof(rms_session_info_t));

	if (!rms_str_dup(&si->callid, &msg->callid->body,1)) {
		LM_ERR("can not get callid .\n");
		goto error;
	}
	if (!rms_str_dup(&si->remote_uri, &msg->from->body,1))
		goto error;
	if (!rms_str_dup(&si->local_uri, &msg->to->body,1))
		goto error;
	str ip;
	ip.s = ip_addr2a(&msg->rcv.dst_ip);
	ip.len = strlen(ip.s);
	if (!rms_str_dup(&si->local_ip, &ip, 1))
		goto error;
	hdr = msg->contact;
	if (parse_contact(hdr) < 0)
		goto error;
	contact_body_t *contact = hdr->parsed;
	if (!rms_str_dup(&si->contact_uri, &contact->contacts->uri, 1))
		goto error;
	LM_NOTICE("[contact offer] [%.*s]\n", si->contact_uri.len, si->contact_uri.s);
	si->cseq = atoi(msg->cseq->body.s);

	rms_sdp_info_t *sdp_info = &si->sdp_info_offer;
	if (!rms_get_sdp_info(sdp_info, msg)) 
		goto error;
	si->caller_media.pt = rms_sdp_check_payload(sdp_info);
	if (!si->caller_media.pt) {
		tmb.t_newtran(msg);
		tmb.t_reply(msg,488,"incompatible media format");
		goto error;
	}
	clist_append(rms_session_list,si,next,prev);
	return si;
error:
	rms_session_free(si);
	return NULL;
}

int rms_sessions_dump(struct sip_msg* msg, char* param1, char* param2) {
	int x=1;
	rms_session_info_t *si;
	clist_foreach(rms_session_list, si, next){
		LM_INFO("[%d]callid[%s]remote_uri[%s]local_uri[%s]cseq[%d]\n", x, si->callid.s, si->remote_uri.s, si->local_uri.s, si->cseq);
		x++;
	}
	return 1;
}

// TODO RENAME ?! rms_media_stop == reply bye ?
int rms_media_stop(struct sip_msg* msg, char* param1, char* param2) {
	rms_session_info_t *si;
	if (!msg || !msg->callid || !msg->callid->body.s) {
		LM_ERR("no callid\n");
		return -1;
	}
	si = rms_session_search(msg->callid->body.s, msg->callid->body.len);
	if (!si){
		LM_INFO("session not found ci[%.*s]\n",  msg->callid->body.len, msg->callid->body.s);
		return 1;
	}
	si->action = RMS_STOP;
	tmb.t_newtran(msg);
	if (!tmb.t_reply(msg,200,"OK")) {
		return -1;
	}
	return 0;
}

static int rms_get_udp_port(void) {
	// RTP UDP port
	LM_INFO("last port[%d]\n", rms.udp_last_port);
	rms.udp_last_port += 2;
	if (rms.udp_last_port > rms.udp_end_port)
		rms.udp_last_port = rms.udp_start_port;
	LM_INFO("last port[%d]\n", rms.udp_last_port);
	return rms.udp_last_port;
}

int rms_create_call_leg(struct sip_msg* msg, rms_session_info_t *si, call_leg_media_t *m, rms_sdp_info_t* sdp_info)  {
	m->local_port = rms_get_udp_port();
	sdp_info->udp_local_port = m->local_port;
	m->local_ip.s = si->local_ip.s;
	m->local_ip.len = si->local_ip.len;
	m->remote_port = sdp_info->remote_port;
	m->remote_ip.s = sdp_info->remote_ip.s;
	m->remote_ip.len = sdp_info->remote_ip.len;
	m->si = si;

	LM_DBG("remote_socket[%s:%d] local_socket[%s:%d] pt[%s]\n",
		sdp_info->remote_ip.s, sdp_info->remote_port,
		m->local_ip.s, m->local_port,
		si->caller_media.pt->mime_type);
	return 1;
}

int rms_sdp_offer(struct sip_msg* msg, char* param1, char* param2) {
	rms_session_info_t *si = rms_session_new(msg);
	rms_sdp_info_t *sdp_info = &si->sdp_info_offer;
	if (!si)
		return -1;
	if (!rms_create_call_leg(msg, si, &si->caller_media, sdp_info)) {
		rms_session_free(si);
		return -1;
	}
	rms_sdp_prepare_new_body(sdp_info, si->caller_media.pt->type);
	rms_sdp_set_body(msg, &sdp_info->new_body);
	if (!rms_relay_call(msg)) {
		return -1;
	}
	return 1;
}

int rms_sdp_answer(struct sip_msg* msg, char* param1, char* param2) {
	rms_session_info_t *si;

	if(!msg || !msg->callid || !msg->callid->body.s) {
		LM_INFO("no callid ?\n");
		return -1;
	}
	si = rms_session_search(msg->callid->body.s, msg->callid->body.len);
	if(!si){
		LM_INFO("session not found ci[%.*s]\n",  msg->callid->body.len, msg->callid->body.s);
		return 1;
	}
	LM_INFO("session found [%s] bridging\n", si->callid.s);
	rms_sdp_info_t *sdp_info = &si->sdp_info_answer;
	if (!rms_get_sdp_info(sdp_info, msg)) {
		LM_ERR("can not get SDP information\n");
		return -1;
	}
	si->callee_media.pt = rms_sdp_check_payload(sdp_info);
	if (!rms_create_call_leg(msg, si, &si->callee_media, sdp_info)) {
		rms_session_free(si);
		return -1;
	}
	rms_sdp_prepare_new_body(sdp_info, si->callee_media.pt->type);
	rms_sdp_set_body(msg, &sdp_info->new_body);
	rms_bridge(&si->caller_media, &si->callee_media);
	return 1;
}


int rms_media_start(struct sip_msg* msg, str *playback_fn) {
	if (rms_session_search(msg->callid->body.s, msg->callid->body.len))
		return -1;
	rms_session_info_t *si = rms_session_new(msg);
	if (!si)
		return -1;
	rms_sdp_info_t *sdp_info = &si->sdp_info_offer;
	if (rms_create_call_leg(msg, si, &si->caller_media, sdp_info) < 1)
		return -1;
	if (rms_answer_call(msg, si) < 1) {
		return -1;
	}
	LM_NOTICE("RTP session [%s:%d]<>[%s:%d]\n", si->caller_media.local_ip.s, si->caller_media.local_port,
							si->caller_media.remote_ip.s, si->caller_media.remote_port);
	si->action = RMS_PLAY;
	si->action_param.len = playback_fn->len;
	si->action_param.s = playback_fn->s;
	return 0;
}
