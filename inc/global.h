#include "grading.h"
#ifndef _GLOBAL_H_
#define _GLOBAL_H_

#include "window.h"

#define EXIT_SUCCESS 0
#define EXIT_ERROR -1
#define EXIT_FAILURE 1

#define SIZE32 4
#define SIZE16 2
#define SIZE8  1

#define NO_FLAG 0
#define NO_WAIT 1
#define TIMEOUT 2

#define TRUE 1
#define FALSE 0


typedef struct {
	int socket;   
	pthread_t thread_id;
	uint16_t my_port;
	uint16_t their_port;
	struct sockaddr_in conn;
	char* received_buf;
	int received_len;
	pthread_mutex_t recv_lock;
	pthread_cond_t wait_cond;
	char* sending_buf;
	int sending_len;
	int type;
	pthread_mutex_t send_lock;
	int dying;
    int remote_closed;
	pthread_mutex_t death_lock;
	send_window_t send_window;
	recv_window_t recv_window;

    ssize_t (*sendto_func) (int, const void *, size_t, int, const struct sockaddr *, socklen_t);
} cmu_socket_t;

#endif
