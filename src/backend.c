#include "backend.h"
#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <assert.h>
#include "ringbuffer.h"
#include "timer.h"
#include "log.h"

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))
#define MAX(X, Y) (((X) > (Y)) ? (X) : (Y))

void send_empty_pkt(cmu_socket_t *sock, int flag, uint32_t seq, uint32_t ack);
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
  send_window_t *swin = &sock->send_window;
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
          DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, SYN_FLAG_MASK|ACK_FLAG_MASK,
          ringbuffer_free_space(win->recvq) - 1, 0, NULL, NULL, 0);

        timer_start_track(sock->send_window.timer, 0, 0);
        sendto(sock->socket, rsp, DEFAULT_HEADER_LEN, 0, (struct sockaddr*)
          &(sock->conn), conn_len);
        free(rsp);

        win->next_exp_byte += 1;
        win->last_byte_read += 1;
        break;

    case SYN_FLAG_MASK | ACK_FLAG_MASK:
        sock->send_window.last_ack_received = get_ack(pkt);
        seq = get_seq(pkt);
        sock->send_window.last_ack_received = get_ack(pkt);
        rsp = create_packet_buf(sock->my_port, ntohs(sock->conn.sin_port), 0 /*seq*/, seq + 1 /*ack*/,
          DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, ACK_FLAG_MASK,
          ringbuffer_free_space(win->recvq) - 1, 0, NULL, NULL, 0);
        sendto(sock->socket, rsp, DEFAULT_HEADER_LEN, 0, (struct sockaddr*)
          &(sock->conn), conn_len);
        free(rsp);

        win->next_exp_byte += 1;
        win->last_byte_read += 1;
        swin->last_win_received = get_advertised_window(pkt);
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
        swin->last_win_received = get_advertised_window(pkt);
        break;

    case ACK_FLAG_MASK:
      log_debugf("receive ack: %d\n", get_ack(pkt));
      if(get_ack(pkt) > sock->send_window.last_ack_received) {

        sock->send_window.last_ack_received = get_ack(pkt);

        timer_end_track(sock->send_window.timer, get_ack(pkt));
        /*log_debugf("new timeout: %d\n", sock->send_window.timeout);*/

      }

      swin->last_win_received = get_advertised_window(pkt);
      break;

    default:
      seq = get_seq(pkt);
      data_len = get_plen(pkt) - DEFAULT_HEADER_LEN;

      log_debugf("recv: seq: %d, len: %d, last_byte_read: %d, next_exp_byte: %d\n",
              seq, data_len, win->last_byte_read, win->next_exp_byte);

      //        seq1          seq2
      //        |             |
      //    |           |           |
      // last_read     next_exp    last_recv

      uint32_t new_data_offset = 0; // offset from the next_exp_byte
      uint32_t new_data_len = data_len; 

      // very old bytes that we've read
      if (seq + data_len - 1 <= win->last_byte_read) {
          uint32_t win_size = MAX_NETWORK_BUFFER - ((win->next_exp_byte - 1) - win->last_byte_read);
          rsp = create_packet_buf(sock->my_port, ntohs(sock->conn.sin_port), seq, win->next_exp_byte, 
            DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, ACK_FLAG_MASK, win_size - 1, 0, NULL, NULL, 0);
          sendto(sock->socket, rsp, DEFAULT_HEADER_LEN, 0, (struct sockaddr*) 
            &(sock->conn), conn_len);
          free(rsp);
          return;
      }

      // subtract what we've received
      if (win->next_exp_byte >= seq) {
          new_data_offset = win->next_exp_byte - seq;
          new_data_len -= new_data_offset;
      } else {
          // out-of-order packet
      }

      log_debugf("recv: new_data_len: %d, offset: %d\n", new_data_len, new_data_offset);

      uint32_t ring_offset = MAX(seq, win->next_exp_byte) - (win->last_byte_read + 1);
      char *new_data_start = pkt + DEFAULT_HEADER_LEN + new_data_offset;
      if (ringbuffer_free_space(win->recvq) >= new_data_len) {
          ringbuffer_insert(win->recvq, ring_offset, new_data_start, new_data_len);
      }

      // only the seq starts within the next_exp_byte is considered continuous
      if (win->next_exp_byte >= seq) {
          win->next_exp_byte += new_data_len;
          ringbuffer_move_end(win->recvq, (int)new_data_len);
      }

      // cumulative ack
      uint32_t reply_ack = win->next_exp_byte;
      uint32_t win_size = MAX_NETWORK_BUFFER - ((win->next_exp_byte - 1) - win->last_byte_read);

      log_debugf("recv: reply_ack: %d, win_size: %d\n", reply_ack, win_size);

      rsp = create_packet_buf(sock->my_port, ntohs(sock->conn.sin_port), seq, reply_ack, 
        DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, ACK_FLAG_MASK, win_size - 1, 0, NULL, NULL, 0);
      sendto(sock->socket, rsp, DEFAULT_HEADER_LEN, 0, (struct sockaddr*) 
        &(sock->conn), conn_len);
      free(rsp);

      uint32_t pop_data_len = win->next_exp_byte - (win->last_byte_read + 1);
      if (pop_data_len > 0) {
          char *data = malloc(pop_data_len);
          int ret = ringbuffer_pop(win->recvq, &data, pop_data_len);
          log_debugf("recv: pop_len: %d, ret: %d\n", pop_data_len, ret);
          assert(ret == 0);
          win->last_byte_read += pop_data_len;
          if(sock->received_buf == NULL){
            sock->received_buf = data;
          } else{
            sock->received_buf = realloc(sock->received_buf, sock->received_len + pop_data_len);
          }
          memcpy(sock->received_buf + sock->received_len, data, pop_data_len);
          sock->received_len += pop_data_len;
      }

      break;
  }
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
  time_out.tv_usec = timer_get_timeout(sock->send_window.timer);
      
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


// the actual sent is indicated by last_byte_sent
int send_within_window(uint32_t first_byte_offset, int max_len, cmu_socket_t * sock) {

    int ret;

    send_window_t *win = &sock->send_window;
    uint32_t adv_win = win->last_win_received + 1;

    log_debugf("send: begin with adv_win: %d, cwnd: %d\n", adv_win, win->cwnd);

    log_debugf("send: last_byte_sent: %d, last_ack: %d\n", win->last_byte_sent, win->last_ack_received-1);
    assert((int)win->last_byte_sent >= (int)win->last_ack_received - 1);


    int len = ringbuffer_len(win->sendq);

    len = MIN(len, adv_win);
    len = MIN(len, win->cwnd);
    if (max_len > 0)
        len = MIN(len, max_len);

    char *send_buf = malloc(len);

    /*log_debugf("send: peek_len: %d\n", len);*/

    int send_len = 0;
    int offset = first_byte_offset - win->last_ack_received;
    ret = ringbuffer_peek_from_start_offset(win->sendq, len, offset, &send_buf, &send_len);
    assert(ret == 0);

    log_debugf("send: send_len: %d, offset: %d\n", send_len, offset);

    char* data_offset = send_buf;
    int sockfd, plen;
    size_t conn_len = sizeof(sock->conn);

    uint32_t seq = win->last_ack_received;

    if (send_len == 0)
        return 0;

    len = send_len;

    /*log_debugf("send: new time %d\n", sock->send_window.send_time);*/

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

      log_debugf("send: send: %d\n", plen - DEFAULT_HEADER_LEN);
      sendto(sockfd, msg, plen, 0, (struct sockaddr*) &(sock->conn), conn_len);

      timer_start_track(win->timer, seq, plen - DEFAULT_HEADER_LEN);

      data_offset = data_offset + plen - DEFAULT_HEADER_LEN;

      send_len -= plen - DEFAULT_HEADER_LEN;

      seq += plen - DEFAULT_HEADER_LEN;
      win->last_byte_sent = MAX(seq - 1, win->last_byte_sent);
    }

    free(send_buf);

    log_debugf("send: send_within_window done\n");
    return len;
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

    log_debugf("multi_send: orig_len:%d\n", orig_len);
    char *data_offset = data;
    int duplicates = 0;

    uint32_t prev_ack = win->last_ack_received;
    uint32_t this_round_start_byte = win->last_ack_received;

    int to_retransmit = FALSE;
    struct timespec start;

    while (win->last_ack_received <= last_byte_to_send) {

        log_debugf("multi_send: last_ack: %d, last_byte_to_send: %d\n",
                win->last_ack_received, last_byte_to_send);

        if (!to_retransmit) {
            int send_len = MIN(ringbuffer_free_space(win->sendq), len);
            ret = ringbuffer_push(win->sendq, data_offset, send_len);
            assert(ret == 0);
            len -= send_len;
        }

        int actual_sent_size = send_within_window(this_round_start_byte, 0, sock);

        log_debugf("multi_send: this_round_start_byte: %d, actual_send_len: %d\n",
                this_round_start_byte, actual_sent_size);

        // the windowed data should be acked in time
        long prev_timeout = timer_get_timeout(sock->send_window.timer);
        log_debugf("multi_send: prev timeout: %d, start: %d\n", prev_timeout, start);

        assert(get_curusec(&start) == 0);

        to_retransmit = FALSE;
        int retransmit_single = FALSE;

        uint32_t last_ack = win->last_ack_received;

        // since the check_for_data checks a packet per call, we have to 
        // add the extra timeout
        while (TRUE) {
            check_for_data(sock, TIMEOUT);
            struct timespec now;
            now.tv_sec = 0;
            now.tv_nsec = 0;
            assert(get_curusec(&now) == 0);
            long diff = diff_ts_usec(&now, &start);
            /*log_debugf("multi_send: diff: %d, now: %d, start: %d\n", diff, now, start);*/
            assert(diff > 0);

            int is_timeout = FALSE;
            if (diff >= prev_timeout)
                is_timeout = TRUE;

            log_debugf("multi_send: cur state: %d, cwin: %d, dup: %d, timeout: %d\n",
                win->cong_state, win->cwnd, duplicates, is_timeout);

            switch (win->cong_state) {
                case CONG_SLOW_START:
                    if (is_timeout) {
                        win->ssthresh = MAX(win->cwnd / 2, MAX_DLEN);
                        win->cwnd = MAX_DLEN;
                        duplicates = 0;
                        to_retransmit = TRUE;
                    } else {
                        if (last_ack >= win->last_ack_received) {
                            if (last_ack == win->last_ack_received)
                                duplicates++;
                        } else {
                            win->cwnd += MAX_DLEN;
                            if (win->cwnd >= win->ssthresh)
                                win->cong_state = CONG_AVOID;

                            duplicates = 0;
                        }

                        if (duplicates >= 3) {
                            win->ssthresh = MAX(win->cwnd / 2, MAX_DLEN);
                            win->cwnd = win->ssthresh + 3 * MAX_DLEN;
                            duplicates = 0;
                            win->cong_state = CONG_RECOV;
                            retransmit_single = TRUE;
                        }
                    }

                    break;

                case CONG_AVOID:
                    if (is_timeout) {
                        win->ssthresh = MAX(win->cwnd / 2, MAX_DLEN);
                        win->cwnd = MAX_DLEN;
                        duplicates = 0;
                        win->cong_state = CONG_SLOW_START;
                        to_retransmit = TRUE;
                    } else {
                        if (last_ack >= win->last_ack_received) {
                            if (last_ack == win->last_ack_received)
                                duplicates++;
                        } else {
                            win->cwnd += MAX_DLEN * MAX_DLEN / win->cwnd;
                            duplicates = 0;
                        }

                        if (duplicates >= 3) {
                            win->ssthresh = MAX(win->cwnd / 2, 3 * MAX_DLEN);
                            win->cwnd = win->ssthresh + 3 * MAX_DLEN;
                            duplicates = 0;
                            win->cong_state = CONG_RECOV;
                            retransmit_single = TRUE;
                        }
                    }

                    break;

                case CONG_RECOV:
                    if (is_timeout) {
                        win->ssthresh = MAX(win->cwnd / 2, MAX_DLEN);
                        win->cwnd = MAX_DLEN;
                        duplicates = 0;
                        win->cong_state = CONG_SLOW_START;
                        to_retransmit = TRUE;
                    } else {
                        if (last_ack >= win->last_ack_received) {
                            if (last_ack == win->last_ack_received) {
                                duplicates++;
                                win->cwnd += MAX_DLEN;
                            }
                        } else {
                            win->cwnd = win->ssthresh;
                            duplicates = 0;
                            win->cong_state = CONG_AVOID;
                        }
                    }

                    break;
            }

            log_infof("| { state: %d, cwnd: %d, ssthresh: %d, adv_win: %d } \n",
                    win->cong_state, win->cwnd, win->ssthresh,
                    win->last_win_received, is_timeout);
            log_infof("| { is_timeout: %d, dup: %d } \n", is_timeout, duplicates);
            log_infof("| { this_round: %d, last_ack_recv: %d, last_end: %d } \n",
                    this_round_start_byte, win->last_ack_received, this_round_start_byte + actual_sent_size);


            log_debugf("multi_send: after state transfer, state: %d, cwin: %d, dup: %d\n",
                win->cong_state, win->cwnd, duplicates);


            last_ack = win->last_ack_received;

            log_debugf("multi_send: this_round_start_byte:%d, last_ack:%d, actual_sent_size: %d\n",
                    this_round_start_byte, last_ack, actual_sent_size);

            int is_done = win->last_ack_received >= this_round_start_byte + actual_sent_size;

            if (retransmit_single) {
                int single_len = MIN(
                        MAX_DLEN, this_round_start_byte + actual_sent_size - last_ack);

                log_debugf("multi_send: retransmit start:%d, len:%d\n",
                        last_ack, single_len);
                send_within_window(last_ack, single_len, sock);
                retransmit_single = FALSE;
            }

            if (to_retransmit) {
                this_round_start_byte = win->last_ack_received;
                log_debugf("multi_send: timeout retransmit all %d!!\n", this_round_start_byte);
                break;
            }

            if (is_done) {
                this_round_start_byte += actual_sent_size;
                ret = ringbuffer_pop(win->sendq, NULL, win->last_ack_received - prev_ack);
                assert(ret == 0);
                to_retransmit = FALSE;
                break;
            }
        }

        prev_ack = win->last_ack_received;

        /*last_byte_to_send = win->last_ack_received + len - 1;*/
        /*sock->send_window.last_byte_sent = last_ack - 1;*/
        log_debugf("multi_send: last_ack_received update to %d\n", sock->send_window.last_ack_received);
    }

    log_debugf("multi_send: done for len %d\n", orig_len);
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
        timer_start_track(sock->send_window.timer, 0, 0);
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

    log_debugf("close: remote_closed: %d\n", remote_closed);

    while(pthread_mutex_lock(&(dst->send_lock)) != 0);
    seq = dst->send_window.last_ack_received;
    pthread_mutex_unlock(&(dst->send_lock));

    // LAST_ACK
    if (remote_closed) {
        for (int i = 0; i < 20; i++) {
            log_debugf("close: LAST_ACK: send FIN %d\n", seq);
            send_empty_pkt(dst, FIN_FLAG_MASK, seq, 0);
            check_for_data(dst, TIMEOUT);
            if (check_ack(dst, seq))
                return EXIT_SUCCESS;

        }
        // the connection is aborted
        return EXIT_FAILURE;
    }

    int fin_acked = FALSE;

    // FIN_WAIT_1 + FIN_WAIT_2
    while (!remote_closed) {

        log_debugf("close: fin_acked: %d\n", fin_acked);

        // TODO: retransmit
        if (!fin_acked) {
            log_debugf("close: CLOSE: send FIN %d\n", seq);
            send_empty_pkt(dst, FIN_FLAG_MASK, seq, 0);
        }

        check_for_data(dst, TIMEOUT);

        remote_closed = get_remote_closed(dst);
        fin_acked = check_ack(dst, seq);
        if (fin_acked && remote_closed)
            break;
    }

    log_debugf("final stage, sleep 2 seconds\n");
    // 120 is too long in the test
    sleep(2);
    return EXIT_SUCCESS;
}
