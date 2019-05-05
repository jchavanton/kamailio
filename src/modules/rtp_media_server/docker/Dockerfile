FROM debian

ENV DEB_PKG_CORES="libevent-dev libjansson-dev libpcre3 libpcre3-dev"

ENV DEB_PKG="procps netcat curl dnsutils sqlite net-tools vim ngrep wget libhiredis-dev ${DEB_PKG_CORES}"
ENV DEB_PKG_TMP="bison flex build-essential git libssl-dev libpq-dev liblua5.1-0-dev libcurl4-openssl-dev libncurses5-dev libxml2-dev libsqlite3-dev"
ENV DEB_PKG_DEP="libcurl3 libssl1.1 libpq5 liblua5.1-0 libncurses5 libxml2 libsqlite3-0"

ENV KAM_INC_MOD_CORES="acc acc_json uri_db mtree dialplan alias_db"
ENV KAM_INC_MOD_EP="ndb_redis topos topos_redis tls dialog"
ENV KAM_INC_MOD="${KAM_INC_MOD_CORES} ${KAM_INC_MOD_EP} jsonrpcs xhttp diversion xmlrpc db_sqlite uac debugger dispatcher siptrace statsd htable sqlops db_postgres permissions app_lua http_client mqueue uac_redirect avpops sqlops http_client"
ENV KAM_SKIP_MOD="uid_domain diversion smsops mediaproxy rtpproxy mqueue topoh app_jsdt tsilo"

ENV KAM_COMMIT=master

RUN echo "building Kamailio with RTP Media Server" \
	&& apt-get update && apt-get -y install ${DEB_PKG} ${DEB_PKG_TMP} \
	&& mkdir -p /git && cd /git

RUN apt-get install -y automake autogen autoconf libtool pkg-config

RUN echo "building bcunit" \
	&& mkdir -p /git && cd /git \
	&& git clone https://github.com/BelledonneCommunications/bcunit.git \
	&& cd bcunit \
	&& git checkout 29c556fa8ac1ab21fba1291231ffa8dea43cf32a \
	&& ./autogen.sh && ./configure \
	&& make && make install

RUN echo "building bctoolbox" \
	&& apt-get install -y libmbedtls-dev \
	&& mkdir -p /git && cd /git \
	&& git clone https://github.com/BelledonneCommunications/bctoolbox.git \
	&& cd bctoolbox \
	&& git checkout 971953a9fa4058e9c8a40ca4a3fa12d832445255 \
	&& ./autogen.sh && ./configure \
	&& make && make install

RUN echo "building oRTP" \
	&& mkdir -p /git && cd /git \
	&& git clone https://github.com/BelledonneCommunications/ortp.git \
	&& cd ortp \
	&& git checkout 6e13ef49a55cdd19dae395c38cfff7ffa518a089 \
	&& ./autogen.sh && ./configure \
	&& make && make install

RUN echo "building mediastreamer2" \
	&& apt-get install -y intltool libspeex-dev libspeexdsp-dev \
	&& git clone https://github.com/BelledonneCommunications/mediastreamer2.git \
	&& cd mediastreamer2 \
	&& git checkout d935123fc497d19a24019c6e7ae4fe0c5f19d55a \
	&& ./autogen.sh && ./configure --disable-sound --disable-video --enable-tools=no --disable-tests \
	&& make && make install

RUN echo "download sample voice files" \
	&& mkdir -p /voice_files && cd /voice_files \
	&& wget http://www.voiptroubleshooter.com/open_speech/american/OSR_us_000_0010_8k.wav

# RUN echo "building Kamailio" \
# 	&& mkdir -p /git && cd /git \
# 	&& git clone https://github.com/kamailio/kamailio.git
# 	&& cd kamailio && git checkout ${KAM_COMMIT} \
# 	&& make include_modules="${KAM_INC_MOD}" skip_modules="\$(mod_list_extra) \$(mod_list_db) ${KAM_SKIP_MOD}" cfg \
# 	&& make install  \
# 	&& apt-get install -y ${DEB_PKG_DEP} \
# 	&& wget -O dockerize.tgz https://github.com/jwilder/dockerize/releases/download/v0.3.0/dockerize-linux-amd64-v0.3.0.tar.gz \
# 	&& tar xvf dockerize.tgz && rm dockerize.tgz && mv dockerize /usr/bin/dockerize \
# 	&& wget -O /usr/bin/kmsutil  https://github.com/flowroute/kmsutil/releases/download/0.0.5/kmsutil_linux_amd64 \
# 	&& chmod +x /usr/bin/kmsutil

