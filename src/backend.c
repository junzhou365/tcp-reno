#include "backend.h"
#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <assert.h>
#include "ringbuffer.h"
#include "log.h"

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))
#define MAX(X, Y) (((X) > (Y)) ? (X) : (Y))

void send_empty_pkt(cmu_socket_t *sock, int flag, uint32_t seq, uint32_t ack);
void update_rtts(int sample_rtt, long *est_rtt, long *deviation);
long get_timeout(long est_rtt, long deviation);

int get_curusec(struct timespec *ts) {
    return clock_gettime(CLOCK_REALTIME, ts);
}

long diff_ts_usec(const struct timespec *now, const struct timespec *since) {
    long ret;
    double sec_diff = difftime(now->tv_sec, since->tv_sec);
    if (sec_diff > 0) {
        ret = ((long)(sec_diff - 1) * 1000000) + (1000000000L + now->tv_nsec - since->tv_nsec) / 1000;
    } else {
        assert(sec_diff == 0);
        ret = (now->tv_nsec - since->tv_nsec) / 1000;
    }

    log_debugf("diff_ts_usec: %d, sec_diff: %d\n", ret, sec_diff);
    assert(ret >= 0);
    return ret;
}

/*
 * Param: sock - The socket to check for acknowledgements. 
 * Param: seq - Sequence number to check 
 *
 * Purpose: To tell if a packet (sequence number) has been acknowledged.
 *
 */
int check_ack(cmu_socket_t * sock, uint32_t seq){
  int result;
  while(pthread_mutex_lock(&(sock->send_window.ack_lock)) != 0);
  if(sock->send_window.last_ack_received > seq)
    result = TRUE;
  else
    result = FALSE;
  pthread_mutex_unlock(&(sock->send_window.ack_lock));
  return result;
}

/*
 * Param: sock - The socket used for handling packets received
 * Param: pkt - The packet data received by the socket
 *
 * Purpose: Updates the socket information to represent
 *  the newly received packet.
 *
 * Comment: This will need to be updated for checkpoints 1,2,3
 *
 */
void handle_message(cmu_socket_t * sock, char* pkt){
  char* rsp;
  uint8_t flags = get_flags(pkt);
  uint32_t data_len, seq;
  socklen_t conn_len = sizeof(sock->conn);
  recv_window_t *win = &sock->recv_window;

  // TODO: piggyback ACK
  /*int death;*/
  /*while(pthread_mutex_lock(&(sock->death_lock)) !=  0);*/
  /*death = sock->dying;*/
  /*pthread_mutex_unlock(&(sock->death_lock));*/


  switch(flags){
    case SYN_FLAG_MASK:
        seq = get_seq(pkt);
        rsp = create_packet_buf(sock->my_port, ntohs(sock->conn.sin_port), 0 /*new seq*/, seq + 1 /*ack*/,
          DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, SYN_FLAG_MASK|ACK_FLAG_MASK, 1, 0, NULL, NULL, 0);

        assert(get_curusec(&(sock->send_window.send_time)) == 0);
        sendto(sock->socket, rsp, DEFAULT_HEADER_LEN, 0, (struct sockaddr*)
          &(sock->conn), conn_len);
        free(rsp);

        break;

    case SYN_FLAG_MASK | ACK_FLAG_MASK:
        seq = get_seq(pkt);
        sock->send_window.last_ack_received = get_ack(pkt);
        rsp = create_packet_buf(sock->my_port, ntohs(sock->conn.sin_port), 0 /*seq*/, seq + 1 /*ack*/,
          DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, ACK_FLAG_MASK, 1, 0, NULL, NULL, 0);
        sendto(sock->socket, rsp, DEFAULT_HEADER_LEN, 0, (struct sockaddr*)
          &(sock->conn), conn_len);
        free(rsp);

        break;

    case FIN_FLAG_MASK:
        while(pthread_mutex_lock(&(sock->death_lock)) != 0);
        sock->remote_closed = TRUE;
        pthread_mutex_unlock(&(sock->death_lock));

        uint8_t send_flag = ACK_FLAG_MASK;
        uint32_t ack = get_seq(pkt) + 1;
        seq = ack;
        // TODO: piggyback ACK
        //if (death) {
        //    // we could piggyback the ack onto the FIN
        //    send_flag |= FIN_FLAG_MASK;
        //    seq = sock->window.last_ack_received;
        //}

        log_debugf("ack to FIN: %d\n", ack);
        send_empty_pkt(sock, send_flag, seq, ack);

        break;

    case FIN_FLAG_MASK | ACK_FLAG_MASK:
        while(pthread_mutex_lock(&(sock->death_lock)) != 0);
        sock->remote_closed = TRUE;
        pthread_mutex_unlock(&(sock->death_lock));

        if(get_ack(pkt) > sock->send_window.last_ack_received)
            sock->send_window.last_ack_received = get_ack(pkt);

        seq = get_seq(pkt);
        send_empty_pkt(sock, ACK_FLAG_MASK, 0, seq+1);
        break;

    case ACK_FLAG_MASK:
      if(get_ack(pkt) > sock->send_window.last_ack_received) {
        sock->send_window.last_ack_received = get_ack(pkt);
        sock->send_window.duplicates = 0;

        log_debugf("receive ack: %d\n", get_ack(pkt));

        struct timespec ack_time;
        assert(get_curusec(&ack_time) == 0);
        log_debugf("ack time: %d\n", ack_time);
        long new_sample_rtt_usec = diff_ts_usec(&ack_time, &(sock->send_window.send_time));
        log_debugf("new sample rtt: %d\n", new_sample_rtt_usec);
        assert(new_sample_rtt_usec > 0);

        update_rtts(
                new_sample_rtt_usec,
                &sock->send_window.est_rtt,
                &sock->send_window.deviation
                );
        sock->send_window.timeout =
            get_timeout(sock->send_window.est_rtt, sock->send_window.deviation);
        log_debugf("new timeout: %d\n", sock->send_window.timeout);
      } else {
          sock->send_window.duplicates++;
      }
      break;

    default:
      seq = get_seq(pkt);
      data_len = get_plen(pkt) - DEFAULT_HEADER_LEN;

      log_debugf("debug: seq: %d, len: %d\n", seq, data_len);

      uint32_t new_data_offset = 0; 
      uint32_t new_data_len = data_len; 
      if (win->next_exp_byte > seq) {
          new_data_offset = win->next_exp_byte - seq;
          new_data_len -= new_data_offset;
      }

      log_debugf("debug: new_data_len: %d, exp_byte: %d, offset: %d\n",
            new_data_len, win->next_exp_byte, new_data_offset);

      if (ringbuffer_free_space(win->recvq) >= new_data_len) {
          ringbuffer_insert(win->recvq,
            win->next_exp_byte - win->last_byte_read - 1,
            pkt + DEFAULT_HEADER_LEN + new_data_offset,
            new_data_len);
      }

      if (new_data_offset <= 0) {
          win->next_exp_byte += new_data_len;
          ringbuffer_move_end(win->recvq, (int)new_data_len);
      }

      uint32_t reply_ack = win->next_exp_byte;
      uint32_t win_size = ringbuffer_free_space(win->recvq);

      log_debugf("debug: reply_ack: %d, win_size: %d\n", reply_ack, win_size);

      rsp = create_packet_buf(sock->my_port, ntohs(sock->conn.sin_port), seq, reply_ack, 
        DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, ACK_FLAG_MASK, win_size, 0, NULL, NULL, 0);
      sendto(sock->socket, rsp, DEFAULT_HEADER_LEN, 0, (struct sockaddr*) 
        &(sock->conn), conn_len);
      free(rsp);

      uint32_t pop_data_len = win->next_exp_byte - win->last_byte_read;
      char *data = malloc(pop_data_len);
      int ret = ringbuffer_pop(win->recvq, &data, pop_data_len);
      assert(ret == 0);

      win->last_byte_read += pop_data_len;

      if(sock->received_buf == NULL){
        sock->received_buf = data;
      }
      else{
        sock->received_buf = realloc(sock->received_buf, sock->received_len + pop_data_len);
      }
      memcpy(sock->received_buf + sock->received_len, data, pop_data_len);
      sock->received_len += pop_data_len;

      break;
  }
}

// sample_rtt is not scaled
// // est_rtt and deviation is scaled to 2^3
void update_rtts(int sample_rtt, long *est_rtt, long *deviation) {
    log_debugf("inital est_rtt: %d, dev: %d\n", *est_rtt, *deviation);
    sample_rtt -= (*est_rtt >> 3);
    *est_rtt += sample_rtt;
    if (sample_rtt < 0)
        sample_rtt = -sample_rtt;

    sample_rtt -= (*deviation >> 3);
    *deviation += sample_rtt;
}

long get_timeout(long est_rtt, long deviation) {
    return (est_rtt >> 3) + (deviation >> 1);
}

/*
 * Param: sock - The socket used for receiving data on the connection.
 * Param: flags - Signify different checks for checking on received data.
 *  These checks involve no-wait, wait, and timeout.
 *
 * Purpose: To check for data received by the socket. 
 *
 */
void check_for_data(cmu_socket_t * sock, int flags){
  char hdr[DEFAULT_HEADER_LEN];
  char* pkt;
  socklen_t conn_len = sizeof(sock->conn);
  ssize_t len = 0;
  uint32_t plen = 0, buf_size = 0, n = 0;
  fd_set ackFD;

  struct timeval time_out;
  time_out.tv_sec = 0;
  time_out.tv_usec = sock->send_window.timeout;
      
  while(pthread_mutex_lock(&(sock->recv_lock)) != 0);
  switch(flags){
    case NO_FLAG:
      len = recvfrom(sock->socket, hdr, DEFAULT_HEADER_LEN, MSG_PEEK,
                (struct sockaddr *) &(sock->conn), &conn_len);
      break;
    case TIMEOUT:
      FD_ZERO(&ackFD);
      FD_SET(sock->socket, &ackFD);
      if(select(sock->socket+1, &ackFD, NULL, NULL, &time_out) <= 0){
        break;
      }
    case NO_WAIT:
      len = recvfrom(sock->socket, hdr, DEFAULT_HEADER_LEN, MSG_DONTWAIT | MSG_PEEK,
               (struct sockaddr *) &(sock->conn), &conn_len);
      break;
    default:
      perror("ERROR unknown flag");
  }
  if(len >= DEFAULT_HEADER_LEN){
    plen = get_plen(hdr);
    pkt = malloc(plen);
    while(buf_size < plen ){
        n = recvfrom(sock->socket, pkt + buf_size, plen - buf_size, 
          NO_FLAG, (struct sockaddr *) &(sock->conn), &conn_len);
      buf_size = buf_size + n;
    }
    handle_message(sock, pkt);
    free(pkt);
  }
  pthread_mutex_unlock(&(sock->recv_lock));
}


void send_within_window(cmu_socket_t * sock) {

    send_window_t *win = &sock->send_window;

    assert(win->last_byte_sent >= win->last_ack_received - 1);
    /*uint32_t cur_win = win->last_byte_sent - win->last_ack_received;*/
    /*if (cur_win >= win->last_win_received) {*/
        /*return 0;*/
    /*}*/


    char *send_buf = malloc(win->last_win_received);
    int send_len = 0;

    int ret;

    int peek_len = ringbuffer_len(win->sendq);
    if (peek_len > win->last_win_received)
        peek_len = win->last_win_received;


    log_debugf("debug: peek_len: %d\n", send_len);
    ret = ringbuffer_peek_from_start(
            win->sendq, peek_len, &send_buf, &send_len);
    assert(ret == 0);

    log_debugf("debug: send_len: %d\n", send_len);

    char* data_offset = send_buf;
    int sockfd, plen;
    size_t conn_len = sizeof(sock->conn);

    uint32_t seq = win->last_ack_received;

    if (send_len == 0)
        return;

    // all sent packets have the same clock time
    assert(get_curusec(&(sock->send_window.send_time)) == 0);
    log_debugf("new send time %d\n", sock->send_window.send_time);

    sockfd = sock->socket;
    while(send_len > 0){

      char* msg;
      if (send_len <= MAX_DLEN) {
        plen = DEFAULT_HEADER_LEN + send_len;
        msg = create_packet_buf(sock->my_port, sock->their_port, seq, seq,
          DEFAULT_HEADER_LEN, plen, NO_FLAG, 1, 0, NULL, data_offset, send_len);
      }
      else {
        plen = DEFAULT_HEADER_LEN + MAX_DLEN;
        msg = create_packet_buf(sock->my_port, sock->their_port, seq, seq,
          DEFAULT_HEADER_LEN, plen, NO_FLAG, 1, 0, NULL, data_offset, MAX_DLEN);
      }

      log_debugf("debug: send: %d\n", plen - DEFAULT_HEADER_LEN);
      sendto(sockfd, msg, plen, 0, (struct sockaddr*) &(sock->conn), conn_len);

      data_offset = data_offset + plen - DEFAULT_HEADER_LEN;

      send_len -= plen - DEFAULT_HEADER_LEN;
      seq += plen - DEFAULT_HEADER_LEN;
      win->last_byte_sent = MAX(seq - 1, win->last_byte_sent);
    }

    free(send_buf);

    log_debugf("debug: send_within_window done\n");
}

/*
 * Param: sock - The socket to use for sending data
 * Purpose: Breaks up the data into packets and send multiple packets.
 *
 * Comment: This will need to be updated for checkpoints 1,2,3
 *
 */
void multi_send(cmu_socket_t * sock, char *data, int len) {

    send_window_t *win = &sock->send_window;
    uint32_t last_byte_to_send = win->last_ack_received + len - 1;

    int ret;
    int orig_len = len;

    log_debugf("debug: multi_send len:%d\n", orig_len);
    char *data_offset = data;

    uint32_t prev_ack = win->last_ack_received;
    while (win->last_ack_received <= last_byte_to_send) {

        log_debugf("debug: last_ack: %d, last_byte: %d\n",
                win->last_ack_received, last_byte_to_send);

        int send_len = MIN(ringbuffer_free_space(win->sendq), len);

        log_debugf("debug: send_len for push: %d\n", send_len);
        ret = ringbuffer_push(win->sendq, data_offset, send_len);
        assert(ret == 0);
        len -= send_len;

        send_within_window(sock);

        // the windowed data should be acked in time
        long prev_timeout = sock->send_window.timeout;
        if (prev_timeout <= 0) {
            prev_timeout =
                get_timeout(sock->send_window.est_rtt, sock->send_window.deviation);
        }

        struct timespec start;
        assert(get_curusec(&start) == 0);
        log_debugf("prev timeout: %d, start: %d\n", prev_timeout, start);

        while (TRUE) {
            check_for_data(sock, TIMEOUT);
            struct timespec now;
            now.tv_sec = 0;
            now.tv_nsec = 0;
            assert(get_curusec(&now) == 0);
            long diff = diff_ts_usec(&now, &start);
            log_debugf("diff: %d, now: %d, start: %d\n", diff, now, start);
            assert(diff > 0);
            if (diff >= prev_timeout || sock->send_window.duplicates >= 3) {
                sock->send_window.duplicates = 0;
                break;
            }

            if (win->last_ack_received > last_byte_to_send)
                break;
        }

        ret = ringbuffer_pop(win->sendq, NULL, win->last_ack_received - prev_ack);
        assert(ret == 0);
        prev_ack = win->last_ack_received;

        /*last_byte_to_send = win->last_ack_received + len - 1;*/
        /*sock->send_window.last_byte_sent = last_ack - 1;*/
        log_debugf("last_ack_received update to %d\n", sock->send_window.last_ack_received);
    }

    log_debugf("debug: multi_send done for len %d\n", orig_len);
}

/*
 * Param: in - the socket that is used for backend processing
 *
 * Purpose: To poll in the background for sending and receiving data to
 *  the other side. 
 *
 */
void* begin_backend(void * in){
  cmu_socket_t * dst = (cmu_socket_t *) in;
  int death, buf_len, send_signal;
  char* data;

  while(TRUE){
    while(pthread_mutex_lock(&(dst->death_lock)) !=  0);
    death = dst->dying;
    pthread_mutex_unlock(&(dst->death_lock));
    
    
    while(pthread_mutex_lock(&(dst->send_lock)) != 0);
    buf_len = dst->sending_len;

    if(death && buf_len == 0) {
      pthread_mutex_unlock(&(dst->send_lock));
      break;
    }

    if(buf_len > 0){
      data = malloc(buf_len);
      memcpy(data, dst->sending_buf, buf_len);
      dst->sending_len = 0;
      free(dst->sending_buf);
      dst->sending_buf = NULL;
      pthread_mutex_unlock(&(dst->send_lock));

      multi_send(dst, data, buf_len);
      free(data);
    }
    else
      pthread_mutex_unlock(&(dst->send_lock));
    check_for_data(dst, NO_WAIT);
    
    while(pthread_mutex_lock(&(dst->recv_lock)) != 0);
    
    if(dst->received_len > 0)
      send_signal = TRUE;
    else
      send_signal = FALSE;
    pthread_mutex_unlock(&(dst->recv_lock));
    
    if(send_signal){
      pthread_cond_signal(&(dst->wait_cond));  
    }
  }


  pthread_exit(NULL); 
  return NULL; 
}

void send_empty_pkt(
    cmu_socket_t *sock, int flag, uint32_t seq, uint32_t ack) {

    socklen_t conn_len = sizeof(sock->conn);
    char *pkt = create_packet_buf(sock->my_port, ntohs(sock->conn.sin_port), seq, ack,
      DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, flag, 1, 0, NULL, NULL, 0);
    sendto(sock->socket, pkt, DEFAULT_HEADER_LEN, 0, (struct sockaddr*)
      &(sock->conn), conn_len);
    free(pkt);
}

int establish_conn(cmu_socket_t *dst) {
    cmu_socket_t *sock = dst;

    while (TRUE) {
        assert(get_curusec(&(sock->send_window.send_time)) == 0);
        send_empty_pkt(sock, SYN_FLAG_MASK, 0, 0);
        check_for_data(dst, TIMEOUT);
        if (check_ack(sock, 0))
            break;
    }

    return 0;
}

int get_remote_closed(cmu_socket_t *sock) {
    int remote_closed;

    while(pthread_mutex_lock(&(sock->death_lock)) != 0);
    remote_closed = sock->remote_closed;
    pthread_mutex_unlock(&(sock->death_lock));

    return remote_closed;
}

int close_conn(cmu_socket_t *dst) {

    uint32_t seq;
    int remote_closed = get_remote_closed(dst);

    log_debugf("debug: remote_closed: %d\n", remote_closed);

    while(pthread_mutex_lock(&(dst->send_lock)) != 0);
    seq = dst->send_window.last_ack_received;
    log_debugf("debug: FIN seq: %d\n", seq);
    pthread_mutex_unlock(&(dst->send_lock));

    // LAST_ACK
    if (remote_closed) {
        send_empty_pkt(dst, FIN_FLAG_MASK, seq, 0);
        check_for_data(dst, TIMEOUT);
        if (check_ack(dst, seq))
            return EXIT_SUCCESS;

        // the connection is aborted
        return EXIT_FAILURE;
    }

    int fin_acked = FALSE;

    // FIN_WAIT_1 + FIN_WAIT_2
    while (!remote_closed) {

        log_debugf("debug: fin_acked: %d\n", fin_acked);

        // TODO: retransmit
        if (!fin_acked)
            send_empty_pkt(dst, FIN_FLAG_MASK, seq, 0);

        check_for_data(dst, TIMEOUT);

        remote_closed = get_remote_closed(dst);
        fin_acked = check_ack(dst, seq);
        if (fin_acked && remote_closed)
            break;
    }

    log_debugf("final stage, sleep 10 seconds\n");
    // 120 is too long in the test
    sleep(10);
    return EXIT_SUCCESS;
}
