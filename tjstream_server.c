#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include <linux/fb.h>
#include <turbojpeg.h>
#include <popt.h>
#include <event.h>
#include <event2/util.h>
#include <event2/listener.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/thread.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "tjstream_server.h"
//
struct timeval start, end;
long seconds, useconds;
double total_time;

int loglevel=0;

enum tjs_state_machine tjs_sm;

int tjs_set_sm(enum tjs_state_machine sm, int err)
{
	int old = (int)tjs_sm;
	if (err)
		printf("%s err %d, current %d\n", __func__, err, old);
	else
		tjs_sm = sm;
	return old;
}

enum tjs_state_machine tjs_get_sm(void)
{
	return tjs_sm;
}
int tjs_device_disconnected(void)
{
	return !((tjs_sm == TJSSM_DEVICE_DISCONNECTED)
		||(tjs_sm ==TJSSM_HOST_DISCONNECTED));
}
/********************************************************
 *
 *
 ********************************************************/
int tjstream_init_param(struct tiny_jpeg_stream_param *param)
{
	/* net configuration */
	strcpy(param->ip,"0.0.0.0");
	param->port = 8923;
	param->fps = 20;

	/* JPEG configuration */
	param->jfmt = TJPF_BGR;
	param->jflags = TJFLAG_FASTDCT;

	/* tool configuration */
	param->loglevel = LINFO;
	param->enable_filelog = false;
	param->test_mode = false;
	param->server_mode = false;

	return 0;
}

int tjstream_info_show(struct tiny_jpeg_stream_info *info)
{

	fprintf(stdout, "Info:\n");
	fprintf(stdout, "  fb: %s\n", info->fbname);
	fprintf(stdout, "  width : %d\n", info->fb_width);
	fprintf(stdout, "  height: %d\n", info->fb_height);
	fprintf(stdout, "  depth : %d\n", info->fb_depth);
	fprintf(stdout, "  yoffset: %d\n", info->fb_yoff);
	fprintf(stdout, "  fb size: 0x%x ( %d kb)\n", info->screensize, info->screensize >> 10);
	fprintf(stdout, "  JPEG\n");
	fprintf(stdout, "   buffer size  : %x (%d KB)\n", info->szjpegBuf, info->szjpegBuf >> 10);
	fprintf(stdout, "   default  width: %d\n", info->j_width);
	fprintf(stdout, "   default height: %d\n", info->j_height);
	fprintf(stdout, "   pixel format  : %d\n", info->j_fmt);
	fprintf(stdout, "\n");
	return 0;

}
int utils_get_jfmt(char *string, unsigned int *fmt)
{
	printf("%s need implment!\n", __func__);
	return 0;
}

int utils_get_loglevel(char *string, int *loglevel)
{
	printf("%s need implment!\n", __func__);
	return 0;
}
/*
 *  --fps-max
 *  --fps-min
 *  --frame-sync
 *  --client-mode(default)
 *  --server-mode
 *  --fb-res=widthxheight:bpp
 *  --fb-fmt=(RGB/BGR)
 *  --jpg-res=widthxheight:bpp
 *  --jfmt=RGB/RGB/RGBX...
 *  --test-mode
 *  --test-mode-dir=
 * */
int tjstream_get_param(int argc, char *argv[], struct tiny_jpeg_stream_param *param)
{
	int opt;
	int port, fps, jflags;
	char *ip, *log_dir, *loglevel, *jfmt;
	poptContext optCon;
	
	struct poptOption theOptions[] = {
	{"ip",		'a', POPT_ARG_STRING,	&ip,	'a', "ip address", "a.b.c.d"},
	{"port",	'p', POPT_ARG_INT,	&port,	'p', "port", "port"},
	{"fps",		'f', POPT_ARG_INT,	&fps,	'f', "fps", "fps"},
	{"jfmt",	't', POPT_ARG_STRING,	&jfmt,  't', "jpeg pixel format", "BRG/RGB/BGRX/RGBX"},
	{"jflags",	'F', POPT_ARG_INT,	&jflags,'F', "hex number override default jpeg jflags", "flags"},
	{"loglevel",	'l', POPT_ARG_STRING,	&loglevel,	'l', "loglevel", "NONE/ERROR/WARN/INFO/VERBOSE"},
	{"log-dir",	'd', POPT_ARG_STRING,	&log_dir,	'd', "dir name", "dir"},
	{"test-mode",	'T', POPT_ARG_NONE,	NULL,	'T', "test mode to check fps perf", ""},
	POPT_AUTOHELP { NULL, 0, 0, NULL ,0},
	};

	optCon = poptGetContext(NULL, argc, (const char **)argv, theOptions, 0);
	poptSetOtherOptionHelp(optCon, "[OPTION...]");

	while ((opt = poptGetNextOpt(optCon)) >= 0) {
		switch (opt) {
		case 'a':
			strncpy(param->ip, ip, sizeof(param->ip) - 1);
			break;
		case 'p':
			param->port = port;
			break;
		case 'f':
			param->fps = fps;
			break;
		case 't':
			utils_get_jfmt(jfmt, &param->jfmt);
			break;
		case 'F':
			param->jflags = jflags;
			break;
		case 'l':
			utils_get_loglevel(loglevel, &param->loglevel);
			break;
		case 'd':
			strncpy(param->log_dir, log_dir, sizeof(param->log_dir) - 1);
			break;
		default:
			break;
		}
	};
	if (opt < -1) {
		fprintf(stderr, "%s: %s\n",
			poptBadOption(optCon, POPT_BADOPTION_NOALIAS),
			poptStrerror(opt));
		poptFreeContext(optCon);
		exit(EXIT_FAILURE);
	}
	poptFreeContext(optCon);
	printf("Params:\n");
	printf("  ip: %s:%d\n", param->ip,param->port);
	printf("  fps: %d\n", param->fps);
	printf("  server mode : %s\n", param->server_mode?"true":"false" );
	printf("  test mode   : %s\n", param->test_mode?  "true":"false" );
	printf("  loglevel    : %x\n", param->loglevel);
	printf("  filelog     : %s\n", param->enable_filelog? "true":"false" );
	printf("  Jpeg params:\n");
	printf("    pixel format: %x\n", param->jfmt);
	printf("    decode flags: %x\n", param->jflags);
	return 0;
}
int tjs_clean_up(struct tiny_jpeg_stream_info *info)
{
	printf(PREFIX"%s need implment!\n", __func__);
	if (info->imgBuf) tjFree(info->imgBuf);
	if (info->jpegBuf) tjFree(info->jpegBuf);
	return 0;
}

int main(int argc, char *argv[])
{
	struct tiny_jpeg_stream_param *tjs_param;
	struct tiny_jpeg_stream_info *tjs_info;
	struct device_stream_mgr *mgr;

	tjs_param = (struct tiny_jpeg_stream_param *)malloc(
			sizeof(struct tiny_jpeg_stream_param ));
	memset((void*)tjs_param, 0, sizeof(struct tiny_jpeg_stream_param ));
	
	mgr = (struct device_stream_mgr *)malloc(sizeof(struct device_stream_mgr));
	memset((void*)mgr, 0, sizeof(struct device_stream_mgr));
	tjs_info = &mgr->jinfo;
	mgr->jinfo.param = tjs_param;

	tjstream_init_param(tjs_param);
	tjstream_get_param(argc, argv, tjs_param);

	server_start(mgr);
	tjs_clean_up(tjs_info);
	free(tjs_param);
	free(mgr);
	return 0;
}

/********************************************************
 *
 *
 ********************************************************/
void listener_cb(struct evconnlistener *listener, evutil_socket_t fd,
        struct sockaddr*sock, int socklen, void*arg);
void socket_read_cb(struct bufferevent*bev, void*arg);
//void socket_write_cb(struct bufferevent*bev, void*arg);
void socket_event_cb(struct bufferevent*bev, short events, void*arg);

int server_start(struct device_stream_mgr *mgr)
{
	struct tiny_jpeg_stream_param *param = mgr->jinfo.param;
	//evthread_use_pthreads();//enable threads

	struct sockaddr_in *sin = &mgr->linker.sin;
	memset(sin, 0, sizeof(struct sockaddr_in));
	sin->sin_family = AF_INET;
	sin->sin_port = htons(param->port);

	struct event_base *base = event_base_new();
	struct evconnlistener *listener =
		evconnlistener_new_bind(base, listener_cb, mgr,
		    LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_FREE, 2,
		    (struct sockaddr*) sin, sizeof(struct sockaddr_in));

	mgr->linker.base = base;
	mgr->linker.listener = listener;
	//事件循环开始
	event_base_dispatch(base);

	evconnlistener_free(listener);
	event_base_free(base);
	return 0;
}

/*
 * 当新客户端连接上服务器，此函数被调用，libevent已经帮助accept了此客户端，该客户端的文件描述符位fd
 */
void listener_cb(struct evconnlistener*listener, evutil_socket_t fd,
        struct sockaddr *sock, int socklen, void *arg)
{
	struct device_stream_mgr *mgr = (struct device_stream_mgr *)arg;
	struct event_base *base = mgr->linker.base;

	//为此客户端分配一个bufferevent
	struct bufferevent *bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
	if (!tjs_device_disconnected()) {
		tjs_set_sm(TJSSM_DEVICE_CONNECTED,0);
		mgr->stream = device_stream_obj_create(fd);
		mgr->linker.bev = bev;
		printf(PREFIX"accept a client %d\n", fd);
	} else{
		printf(PREFIX"decline a client %d\n", fd);
	}
	bufferevent_setcb(bev, socket_read_cb, NULL, socket_event_cb, mgr);
	bufferevent_enable(bev, EV_READ | EV_PERSIST);
}

void socket_read_cb(struct bufferevent *bev, void *arg)
{
	struct device_stream_mgr *mgr = (struct device_stream_mgr *)arg;
	printf(PREFIX"server read the data\n");
	if (!tjs_msgblk_received(mgr))
		tjs_data_process(mgr);
}

void socket_event_cb(struct bufferevent *bev, short events, void *arg)
{
	struct device_stream_mgr *mgr = (struct device_stream_mgr *)arg;

	if (events & BEV_EVENT_EOF) {
		printf(PREFIX"connection closed\n");
	} else if (events & BEV_EVENT_ERROR) {
		printf(PREFIX"some other error\n");
	}
	tjs_set_sm(TJSSM_DEVICE_DISCONNECTED, 0);
	//自动关闭套接字和释放读写缓冲区
	bufferevent_free(bev);
	device_stream_obj_destory(mgr->stream);
}

/********************************************************
 *
 *
 ********************************************************/
struct device_stream_info *device_stream_obj_create(int fd)
{
	struct device_stream_info *p = (struct device_stream_info*)malloc(
					sizeof(struct device_stream_info));
	p->msg_len = MSG_LEN;
	p->reply_len = REPLY_LEN;
	memset(p->msg, 0, MSG_LEN);
	memset(p->reply, 0, REPLY_LEN);
	p->fd = fd;
	return p;
}

void device_stream_obj_destory(struct device_stream_info *p)
{
	free(p);
	p = NULL;
}

static int test_jpg_image(char* name, unsigned char* jpegBuf, int bufSize)
{
	FILE *jpegFile = NULL;
	long size;
	unsigned long jpegSize = 0;

	/* Read the JPEG file into memory. */
	if ((jpegFile = fopen(name, "rb")) == NULL) {
		fprintf(stderr, "opening input file %s", name);
		goto bailout;
	}
	if (fseek(jpegFile, 0, SEEK_END) < 0
		|| ((size = ftell(jpegFile)) < 0)
		|| fseek(jpegFile, 0, SEEK_SET) < 0) {
		fprintf(stderr, "determining input file size");
		goto bailout;
	}
	if (size == 0) {
		fprintf(stderr, "determining input file size, Input file contains no data");
		goto bailout;
	}
	jpegSize = (unsigned long)size;

	if(jpegBuf == NULL || bufSize < jpegSize) {
		fprintf(stderr, "jpegBuf %p or alloc size too samll %d(%ld)",
				jpegBuf, bufSize, jpegSize);
		goto bailout;
	}
	if (fread(jpegBuf, jpegSize, 1, jpegFile) < 1) {
		fprintf(stderr, "reading input file");
		goto bailout;
	}
	if (jpegFile) fclose(jpegFile);

bailout:
	return jpegSize;
}
#define JPEG_SSOF	"$JPEG-STREAM-SOS$"
#define JPEG_SEOF	"$JPEG-EOF-STREAM$"
#define JPEG_FSOF	"$JPEG-FRAME-START$\0"
#define JFSOF_SZ	18
#define JPEG_FEOF	"$JPEG-EOF$\n\n"
#define JFEOF_SZ	12
#define JSIZE_SZ	8

char name_array[255] = {0};
unsigned char *jpegBuf = NULL;
static int test_jpg_image_init(void)
{
	int szjpegBuf= 500*1024;
	if ((jpegBuf = (unsigned char *)malloc(szjpegBuf)) == NULL) {
		fprintf(stderr, "allocating JPEG buffer");
		return -1;
	}
	return szjpegBuf;
}
static int test_jpg_image_deinit(void)
{
	if(jpegBuf) free(jpegBuf);
	return 0;
}

int thread_exit_flag = 0;
void *thread_screen_capture(void *arg)
{
	struct device_stream_mgr *mgr = (struct device_stream_mgr *)arg;
	struct device_stream_info *s = mgr->stream;
	struct evbuffer *output_buffer = bufferevent_get_output(mgr->linker.bev);
	struct evbuffer *msgbuffer;
	int i=0, ret;
	long jpegSize;
	int szjpegBuf;

	szjpegBuf = test_jpg_image_init();
	printf(PREFIX"%s szjpegBuf %d\n", __func__, szjpegBuf);
	/*
	memset(reply,0, 32);
	memcpy(reply,"$JPEG-STREAM-EOS$",17);
	bufferevent_write(mgr->linker.bev, s->reply, s->reply_len);
	*/
	while (!thread_exit_flag) {
		/* Getting jepg and size */
		memset(name_array,0, sizeof(name_array));
		sprintf(name_array,"./tjstest/output-%03d.jpg", i);
		i = (i + 1) % (10*20);
		jpegSize = test_jpg_image(name_array, jpegBuf, szjpegBuf);
		printf(PREFIX"%s %d read img done \n", __func__, __LINE__);
		
		/* massage block head */
		msgbuffer = tjs_evmsg_pack(s->reply, SET_REPLY(TJSREQ_STREAMING), jpegSize);
		evbuffer_add_buffer(output_buffer, msgbuffer);
		evbuffer_free(msgbuffer);

		struct evbuffer *body_buffer = evbuffer_new();
		if (body_buffer) {
			evbuffer_add(body_buffer, jpegBuf, jpegSize);
			evbuffer_add_buffer(output_buffer, body_buffer);
			printf(PREFIX"%s add jpeg body %ld\n", __func__, jpegSize);
			evbuffer_free(body_buffer);
		}
		bufferevent_write_buffer(mgr->linker.bev, output_buffer);
		while(1){
			ret = evbuffer_get_length(output_buffer);
			if (!ret)
				break;
			else
				usleep(100000);
		}
		printf(PREFIX"polling next %d !\n", s->fd);
		usleep(1000*1000);
	};
	test_jpg_image_deinit();
	thread_exit_flag = 0;
	
	/*
	memset(reply,0, 32);
	memcpy(reply,"$JPEG-STREAM-EOS$",17);
	bufferevent_write(mgr->linker.bev, s->reply, s->reply_len);
	*/
	return mgr;
}
int tjs_process_resolution(int sm, struct device_stream_info *s)
{
	s->reply_len = 4;
	memcpy(s->reply, "OKAY\0", 4);
	return 0;
}
int tjs_start_stream(int sm, struct device_stream_mgr *mgr)
{
	struct device_stream_info *s = mgr->stream;
	int retval = pthread_create(
			&s->thread_id, NULL, thread_screen_capture, mgr);

	if (retval != 0) {
		fprintf(stderr, "Error:unable to create thread\n");
		return retval;
	}
	printf(PREFIX"Thread created successfully\n");
	return 0;
}
int tjs_stop_stream(int sm, struct device_stream_info *s)
{
	int i = 0;
	unsigned char *reply = s->reply;

	thread_exit_flag = 1;
	usleep(100 * 000);
	while( thread_exit_flag ){
		usleep(100 * 000);
		if((i++) > 10) {
			pthread_cancel(s->thread_id);
			break;
		}
	}
	s->reply_len = 4;
	memcpy(reply, "OKAY\0", 4);
	return 0;
}

struct evbuffer* tjs_evmsg_pack(
		unsigned char *msg,
		unsigned short type,
		int payload_len)
{
	struct msg_block *blk = (struct msg_block *)msg;
	int len = MSGLEN + payload_len;

	blk->magic = htonl(MAGIC);
	blk->jmtype = htons(type);
	blk->len = htonl(len);

	struct evbuffer *output_buffer = evbuffer_new();
	if (output_buffer == NULL) {
		return NULL;
	}
	evbuffer_add(output_buffer, msg, MSGLEN);
	return output_buffer;
}

static size_t tjs_net_get_input_length(struct bufferevent *bev)
{
	struct evbuffer *evbuf = bufferevent_get_input(bev);
	return evbuffer_get_length(evbuf);
}
int tjs_msgblk_received(struct device_stream_mgr *mgr)
{
	size_t len = tjs_net_get_input_length(mgr->linker.bev);
	struct evbuffer *evbuf = bufferevent_get_input(mgr->linker.bev);
	struct msg_block msgblk;

	if (len < MSGLEN) {
		printf(PREFIX"Not enough data %d\n", len);
		return 1;
	}

	/* copy out massage head */
	evbuffer_copyout(evbuf, &msgblk, sizeof(msgblk));
	if (ntohl(msgblk.magic) != kMessageHeaderMagic) {
		evbuffer_drain(evbuf, MSGLEN);
		printf(PREFIX"%s: magic %x err, drop %d data \n", __func__,
				ntohl(msgblk.magic), MSGLEN);
		return -1;
	}
	if (len < ntohl(msgblk.len)) {
		bufferevent_setwatermark(mgr->linker.bev, EV_READ, ntohl(msgblk.len), 0);
		printf(PREFIX"%s: read more current %d/%d\n", __func__, len, ntohl(msgblk.len));
		return len;
	}
	bufferevent_setwatermark(mgr->linker.bev, EV_READ, 0, 0);
	return 0;
}
int tjs_data_process(struct device_stream_mgr *mgr)
{
	int ret;
	struct evbuffer *msgbuffer = NULL;
	struct device_stream_info *s = mgr->stream;
	unsigned char *msg = s->msg;
	unsigned char head[MSGLEN];
	struct msg_block *msgblk = (struct msg_block *)head;
	int bodysize;
	unsigned char *body;
	struct evbuffer *output_buffer = bufferevent_get_output(mgr->linker.bev);
	struct evbuffer *input_evbuf = bufferevent_get_input(mgr->linker.bev);
	unsigned short type;

	/* copy msg head */
	evbuffer_remove(input_evbuf, head, sizeof(head));
	/* copy to body */
	bodysize = ntohl(msgblk->len) - MSGLEN;
	if(bodysize){
		body = (unsigned char *)malloc(bodysize);
		evbuffer_remove(input_evbuf, (unsigned char*)body, bodysize);
	}

	type = CLEAR_REQ(ntohs(msgblk->jmtype));
	printf(PREFIX"mssage type %04x body size %d\n", type, bodysize);
	switch (type) {
	case TJSREQ_RESOLUTION_REPORT:
	case TJSREQ_RESOLUTION_NEGOTIATE:
	case TJSREQ_RESOLUTION_CHOOSE:
	case TJSREQ_RESOLUTION_FINNAL:
		/* set res,fps, etc,. */
		ret = tjs_process_resolution(type, s);
		if (body) free(body);
		tjs_set_sm(type + 1, ret);
		msgbuffer = tjs_evmsg_pack(msg, SET_REPLY(type), s->reply_len);
		break;
	case TJSREQ_STREAM_START:
		if (body) free(body);
		/* start jpeg/mjpeg thread if accept */
		ret = tjs_start_stream(type, mgr);
		tjs_set_sm(TJSSM_STREAMING, ret);
		return 0;
		break;
	case TJSREQ_STREAM_END:
		msgbuffer = tjs_evmsg_pack(msg, SET_REPLY(type), s->reply_len);
		if (body) free(body);
		break;
	case TJSREQ_STREAMING:
		break;
	default :
		printf(PREFIX" Unknown massgae type\n");
		return 0;
		break;
	}
	if (msgbuffer) {
		evbuffer_add_buffer(output_buffer, msgbuffer);
		evbuffer_free(msgbuffer);
	}
	if (s->reply_len) {
		struct evbuffer *bodybuffer = evbuffer_new();
		if (bodybuffer == NULL) {
			printf(PREFIX" %s failed to new evbuffer\n", __func__);
			return -1;
		}
		ret = evbuffer_add(bodybuffer, s->reply, s->reply_len);
		if(ret) printf(PREFIX" %s add evbuffer failed %d\n", __func__, ret);

		ret = evbuffer_add_buffer(output_buffer, bodybuffer);
		if (ret) printf(PREFIX" %s failed to add evbuffer(%d)\n", __func__, ret);
		evbuffer_free(bodybuffer);
		printf(PREFIX" %s add body(%d)\n", __func__, s->reply_len);
	}
	bufferevent_write_buffer(mgr->linker.bev, output_buffer);
	printf(PREFIX"[%02x]Writeback %d data\n", type, s->reply_len);
	return 0;
}
