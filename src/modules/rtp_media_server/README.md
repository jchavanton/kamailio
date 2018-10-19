

# external libraries
This module is using belledonne communication media streamer(ms2) and RTP (oRTP) libraries in Kamailio

* You can install the required libraries the way you want but a small shell script is provided for your convenience
`install_bc.sh`

Kamailio is doing all the SIP and some SDP related task
MS2/oRTP is doing all the RTP and media processing


# routing script example

### This is only for initial proof of concept to start an RTP session and playback a file
You can find the file in `config_example/kamailio.cfg`

```
loadmodule "rtp_media_server"
modparam("rtp_media_server", "server_address", "127.0.0.102")
modparam("rtp_media_server", "log_file_name", "/tmp/rms_transfer.log")

route {
	t_check_trans();

	if(is_method("INVITE") && !has_totag()) {
		xnotice("INVITE RECEIVED [$ci]\n");
		rms_sessions_dump();     # dump the call-id of each active session
		if (!rms_media_start("file.wav")) {
			xerr("rtp_media_server error!");
		}
	}

	if(is_method("BYE")){
		xnotice("BYE RECEIVED [$ci]\n");
		rms_sessions_dump();    # dump the call-id of each active media session
		rms_media_stop();
	}

	drop;
}
```


### future evolution rtp_media_server
The RTP media server Kamailio module :

Transcoding gateway with audio quality reporting

- Support for most freecodecs(Opus, Codec2) and (g729a, g722)
- Audio quality reporting using

RTP Control Protocol Extended Reports (RTCP XR)
https://tools.ietf.org/html/rfc3611

Session Initiation Protocol Event Package for Voice Quality Reporting
https://tools.ietf.org/html/rfc6035

