#include <sys/stat.h>
#include "cmu_tcp.h"

/*
 * Param: sock - used for reading and writing to a connection
 *
 * Purpose: To provide some simple test cases and demonstrate how 
 *  the sockets will be used.
 *
 */
void functionality(cmu_socket_t  * sock){
    char buf[9898];
    int read;
    FILE *fp;

    cmu_write(sock, "hi there", 9);
    cmu_write(sock, "hi there2", 10);
    cmu_write(sock, "hi there3", 10);
    cmu_write(sock, "hi there4", 10);
    cmu_write(sock, "hi there5", 10);
    cmu_write(sock, "hi there6", 10);
    cmu_read(sock, buf, 200, NO_FLAG);

    cmu_write(sock, "hi there", 9);
    cmu_read(sock, buf, 200, NO_FLAG);
    printf("R: %s\n", buf);

    read = cmu_read(sock, buf, 200, NO_WAIT);
    printf("Read: %d\n", read);

    /*const char *file = "./src/backend.c";*/
    const char *file = "./test.data";

    struct stat st;
    stat(file, &st);
    int filesize = (int)st.st_size;
    printf("source len: %d\n", filesize);

    sprintf(buf, "%d", filesize);

    cmu_write(sock, buf, 200);

    fp = fopen(file, "rb");
    read = 1;
    while(read > 0 ){
        read = fread(buf, 1, 2000, fp);
        if(read > 0)
            cmu_write(sock, buf, read);
    }
    
}

int my_tcp_send(int portno, char * serverip) {
    cmu_socket_t socket;
    if(cmu_socket(&socket, TCP_INITATOR, portno, serverip) < 0)
        exit(EXIT_FAILURE);
    
    functionality(&socket);

    if(cmu_close(&socket) < 0)
        exit(EXIT_FAILURE);
    return EXIT_SUCCESS;
}

void linux_tcp_send(int port, char * serverip) {

    int ret;

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        printf("socket fails\n");
        exit(-1);
    }

    struct sockaddr_in conn, my_addr;

    memset(&conn, 0, sizeof(conn));          
    conn.sin_family = AF_INET;          
    conn.sin_addr.s_addr = inet_addr(serverip);  
    conn.sin_port = htons(port); 


    my_addr.sin_family = AF_INET;
    my_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    my_addr.sin_port = 0;

    ret = bind(sockfd, (struct sockaddr *) &my_addr, sizeof(my_addr));
    if (ret < 0) {
        perror("bind");
        exit(-1);
    }

    ret = connect(sockfd, (struct sockaddr *)&conn, sizeof(conn));
    if (ret < 0) { 
        perror("connect");
        exit(-1);
    }

    char buf[9898];
    FILE *fp;

    const char *file = "./test.data";

    struct stat st;
    stat(file, &st);
    int filesize = (int)st.st_size;
    printf("source len: %d\n", filesize);

    sprintf(buf, "%d", filesize);

    write(sockfd, buf, 200);

    fp = fopen(file, "rb");
    int read = 1;
    while(read > 0 ){
        read = fread(buf, 1, 2000, fp);
        if(read > 0)
            write(sockfd, buf, read);
    }
}


/*
 * Param: argc - count of command line arguments provided
 * Param: argv - values of command line arguments provided
 *
 * Purpose: To provide a sample initator for the TCP connection to a
 *  listener.
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


    my_tcp_send(portno, serverip);

    /*linux_tcp_send(portno, serverip);*/
}
