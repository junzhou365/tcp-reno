#include "cmu_tcp.h"

/*
 * Param: sock - used for reading and writing to a connection
 *
 * Purpose: To provide some simple test cases and demonstrate how 
 *  the sockets will be used.
 *
 */
void functionality(cmu_socket_t  * sock){
    char buf[1<<20];
    FILE *fp;
    int n;

    n = cmu_read(sock, buf, 200, NO_FLAG);
    printf("R: %s\n", buf);
    printf("N: %d\n", n);
    cmu_write(sock, "hi there", 9);
    cmu_read(sock, buf, 200, NO_FLAG);
    cmu_write(sock, "hi there", 9);

    sleep(5);
    n = cmu_read(sock, buf, 200, NO_FLAG);
    int size = atoi(buf);
    printf("file size: %d, N: %d\n", size, n);

    const char *file = "./test/file.c";

    fp = fopen(file, "w+");

    /*int i = 0;*/
    int prev = 0;
    int m = 0;
    struct timespec previous;
    get_curusec(&previous);
    while (m < size) {
        n = cmu_read(sock, buf, 20000, NO_FLAG);
        m += n;

        /*printf("i: %d, N: %d\n", i++, n);*/
        fwrite(buf, 1, n, fp);

        if (m / (1 << 20) != prev) {
            prev = m / (1 << 20);

            struct timespec now;
            get_curusec(&now);
            long diff = diff_ts_usec(&now, &previous);
            printf("%d-%dMB used %ldms\n", prev-1, prev, diff / 1000);
            previous = now;
        }
    }
}

int my_tcp_recv(int portno, char * serverip) {
    cmu_socket_t socket;
    if(cmu_socket(&socket, TCP_LISTENER, portno, serverip) < 0)
        exit(EXIT_FAILURE);

    functionality(&socket);

    if(cmu_close(&socket) < 0)
        exit(EXIT_FAILURE);
    return EXIT_SUCCESS;
}

void linux_tcp_recv(int portno, char * serverip){
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
        exit(sockfd);

    struct sockaddr_in conn, peer;

    bzero((char *) &conn, sizeof(conn));
    conn.sin_family = AF_INET;
    conn.sin_addr.s_addr = htonl(INADDR_ANY);
    conn.sin_port = htons((unsigned short)portno);

    int e = bind(sockfd, (struct sockaddr *) &conn, sizeof(conn));
    if (e < 0)
        exit(e);

    if (listen(sockfd, 3) < 0) { 
        perror("listen"); 
        exit(EXIT_FAILURE); 
    }

    socklen_t peer_addr_size = sizeof(struct sockaddr_in);
    int peer_sockfd = accept(sockfd, (struct sockaddr *) &peer, &peer_addr_size);
    if (peer_sockfd < 0) {
        perror("accept");
        exit(EXIT_FAILURE);
    }

    const char *file = "./test/file.c";

    char buf[1<<20];
    FILE *fp;
    int n;

    fp = fopen(file, "w+");

    n = read(peer_sockfd, buf, 200);
    if (n < 0) {
        perror("read"); 
        exit(EXIT_FAILURE); 
    }
    int size = atoi(buf);
    printf("file size: %d, N: %d\n", size, n);


    /*int i = 0;*/
    int prev = 0;
    int m = 0;
    struct timespec previous;
    get_curusec(&previous);
    while (m < size) {
        n = read(peer_sockfd, buf, 20000);
        m += n;

        /*printf("i: %d, N: %d\n", i++, n);*/
        fwrite(buf, 1, n, fp);

        if (m / (1 << 20) != prev) {
            prev = m / (1 << 20);

            struct timespec now;
            get_curusec(&now);
            long diff = diff_ts_usec(&now, &previous);
            printf("%d-%dMB used %ldms\n", prev-1, prev, diff / 1000);
            previous = now;
        }
    }

}

/*
 * Param: argc - count of command line arguments provided
 * Param: argv - values of command line arguments provided
 *
 * Purpose: To provide a sample listener for the TCP connection.
 *
 */
int main(int argc, char **argv) {
	int portno;
    char *serverip;
    char *serverport;
    
    serverip = getenv("server15441");
    if (serverip) ;
    else {
        serverip = "10.0.0.1";
    }

    serverport = getenv("serverport15441");
    if (serverport) ;
    else {
        serverport = "15441";
    }
    portno = (unsigned short)atoi(serverport);


    my_tcp_recv(portno, serverip);

    /*linux_tcp_recv(portno, serverip);*/
}
