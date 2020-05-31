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

    int m = 0;
    while (m < size) {
        n = cmu_read(sock, buf, 20000, NO_FLAG);
        m += n;

        printf("N: %d\n", n);
        fwrite(buf, 1, n, fp);
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
    cmu_socket_t socket;
    
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


    if(cmu_socket(&socket, TCP_LISTENER, portno, serverip) < 0)
        exit(EXIT_FAILURE);

    functionality(&socket);

    if(cmu_close(&socket) < 0)
        exit(EXIT_FAILURE);
    return EXIT_SUCCESS;
}
