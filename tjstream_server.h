#ifndef __TJSTEAM_SERVER_H__
#define __TJSTEAM_SERVER_H__

#include <sys/socket.h>
#include <netinet/in.h>
#include <event2/util.h>
#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/thread.h>
#include <pthread.h>

#define LNONE		0
#define LERROR		1
#define LWARN		2
#define LINFO		3
#define LVERBOSE	4
#define PREFIX "[SERVER]"

#define TJSREQ_UNKNOWN			-1
#define TJSREQ_NODATA			0
#define TJSREQ_RESOLUTION_REPORT	0x40
#define TJSREQ_RESOLUTION_NEGOTIATE	0x41
#define TJSREQ_RESOLUTION_CHOOSE	0x42
#define TJSREQ_RESOLUTION_FINNAL	0x43
#define TJSREQ_STREAM_START		0x80
#define TJSREQ_STREAMING		0x81
#define TJSREQ_STREAM_END		0x82


#define MAGIC			0x544a534d	/* TJSM */
#define kMessageHeaderMagic	MAGIC	
#define MAGICLEN		4
#define MSGLEN			12
#define IS_REQ(x) 		(x & 0x8000)
#define SET_REQ(x) 		(x | 0x8000)
#define CLEAR_REQ(x) 		(x & 0x7FFF)
#define SET_REPLY 		CLEAR_REQ
#define JMTYPE_REQ		0x8000
#define JMTYPE_REPLY		0

enum tjs_state_machine {
	/* connection */
	TJSSM_HOST_DISCONNECTED	= 0,
	TJSSM_DEVICE_DISCONNECTED,
	TJSSM_DEVICE_CONNECTED,
	/* network stage, change to p2p connect */
	TJSSM_P2P_CAP_REPORT	= 0x20,
	TJSSM_P2P_NEGOTIATE,
	TJSSM_P2P_SETUP,
	/* report stage */
	TJSSM_RESOLUTION_REPORT = 0x40,
	TJSSM_RESOLUTION_NEGOTIATE,
	TJSSM_RESOLUTION_CHOOSE,
	TJSSM_RESOLUTION_FINNAL,
	TJSSM_RESOLUTION_CHANGE_REQ,
	/* stream stage */
	TJSSM_STREAMING_REQ	= 0x80,
	TJSSM_STREAMING,
	TJSSM_STREAMING_END,
	/* done */
};

struct tiny_jpeg_stream_param {
	char ip[64];
	int port;
	int fps;
	unsigned int jfmt;
	int jflags;

	int loglevel;
	int enable_filelog;
	char log_dir[256];
	int test_mode;
	char test_dir[256];
	int server_mode;
};

struct tiny_jpeg_stream_info {
	/* fb info */
	char fbname[64];
	int fbfd;
	int screensize;
	unsigned char *fbmem;
	int fb_width;
	int fb_height;
	int fb_depth;
	int fb_yoff;

	/*jpeg info */
	int j_flags;
	int j_width;
	int j_height;
	int j_depth;
	int j_fmt;
	int szjpegBuf;
	unsigned char *jpegBuf;
	unsigned long jpegSize;
	unsigned char *imgBuf;
	int szimgBuf;

	/* link to param */
	void *param;
};

struct link_info {
	struct sockaddr_in sin;
	struct evconnlistener *listener;
	struct event_base *base;
	struct bufferevent *bev;
	struct event *ev_cmd;
};

#define MSG_LEN		4096
#define REPLY_LEN	4096
struct device_stream_info {
	unsigned char msg[MSG_LEN];
	int msg_len;
	unsigned char reply[REPLY_LEN];
	int reply_len;
	pthread_t thread_id;
	int fd;
};

struct device_stream_mgr {
	struct tiny_jpeg_stream_info jinfo;
	struct link_info linker;
	struct device_stream_info *stream;
};

struct msg_block {
	unsigned int magic;
	unsigned short jmtype;
	unsigned short rsvd;
	unsigned int len;
	void *payload;
};

int server_start(struct device_stream_mgr *mgr);

int tjs_data_process(struct device_stream_mgr *mgr);
struct device_stream_info *device_stream_obj_create(int fd);
void device_stream_obj_destory(struct device_stream_info *p);
int tjs_msgblk_received(struct device_stream_mgr *mgr);
struct evbuffer* tjs_evmsg_pack(
		unsigned char *msg,
		unsigned short type,
		int payload_len);
#endif

