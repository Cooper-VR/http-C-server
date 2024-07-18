#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include "lengthUtils.h"
#include <stdbool.h>

#define BUFFER_SIZE 1024
char *response_ok = "HTTP/1.1 200 OK\r\n\r\n";
char *response_not_found = "HTTP/1.1 404 Not Found\r\n\r\n";

char folders[2][20] = {"echo", "user-agent HTTP"};

int main() {

    /*
     * setbuff: FILE stream, char buffer
     * returns: none
     * stream: a file stream to set the buffer to
     * buffer: pointer to a buffer for the stream to use, if its NULL, buffering is turned off
     * desc: set the internal buffer to use for stream operations, should be at least 6 characters long.
     * if buffer is not null, = setvbuf(stream, buffer, _IOFBF, BUFSIZ)
     * if the buffer is null, = setvbuf(stream, NULL, _IONBF, 0) which turns off buffering
     * */
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    printf("Logs from your program will appear here!\n");


    int server_fd, client_addr_len;
    struct sockaddr_in client_addr;

    /*
     * socket:  int domain,int type, int protocol
     * returns: returns a non-negitive number, the file descriptor. if not, returns -1
     * domain: not doamin name, but the communication domain or method
     * type: specifies the type of socket
     * protocol: specify the protocol to be used, of 0 is used, it will use the default protocol
     * desc: creates and unbound socket ini a connection domain, and returns a file descriptor.
     * this can be used later to operate on sockets.
     * */
    server_fd = socket(AF_INET, SOCK_STREAM, 0);

    //as the socket docs say, -1 means failed connection
    if (server_fd == -1) {
        printf("Socket creation failed: %s...\n", strerror(errno));
        return 1;
    }


    int reuse = 1;

    /*
     * setsockopt:  int fileDescriptor, int level, int option_name
     * returns : returns 0 if successful, -1 is there was an error
     * filDescriptor: a file descriptor returned by the socket function when a socket is create successfully
     * level: specified the protocol level that option resides.
     * to set options at socket level, specify the level argument as SOL_SOCKET.
     * to set options at other levels suppy the appropiate level identifier. for example to set at TCP level, set level to IPPROTO_TCP
     * option_name: specifis a single option to set.
     * this option can be a lot of things see :https://pubs.opengroup.org/onlinepubs/000095399/functions/setsockopt.html for all of them
     * desc: set the option specified by "option_name" argument, specified at the protocol level to the level poined of by "option_value"
     * */
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        printf("SO_REUSEADDR failed: %s \n", strerror(errno));
        return 1;
    }

    struct sockaddr_in serv_addr = { 
        //AF_INET: refers to IPv4 address family. it is used to define the address format and protocol family for socket addresses.
        .sin_family = AF_INET ,

        //htons: converts unsigned short (hostshort) from a host byte order to network byte. set the port
        .sin_port = htons(4221),

        //htonl: converts an unsigned int (hostlong) from a host btye order to network byte order,
        //INADDR_ANY: its is an IP address that we use when we dont know the IP. basically is default to use when testing
        .sin_addr = { htonl(INADDR_ANY) },
    };

    /*
     * bind: int socket, struct address, address_len
     * returns: if it is good, returns 0, otherwise it returns -1 if it fails
     * socket: the file descriptor of the socket to be bound
     * address: points to a sockaddr, which contains the address to be bound
     * address_len: specifis the length of sockaddr or the address argument
     * desc: assigns a local socket to "address", this sockets are unnamed and are identifed only by their address family
     * */
    if (bind(server_fd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) != 0) {
        printf("Bind failed: %s \n", strerror(errno));
        return 1;
    }

    /*
     * listen: takes int, socket, int backlog
     * returns: if it is successful, it returns 0, if it fails, it returns -1
     * socket: the file descriptor
     * backlog: basically says that for the que of people wanting to connect, this is the max that can be in the que
     * desc: makes a connection-mode socket, specifally by the socket argument, as accepting connections
     * */
    int connection_backlog = 5;
    if (listen(server_fd, connection_backlog) != 0) {
        printf("Listen failed: %s \n", strerror(errno));
        return 1;
    }

    printf("Waiting for a client to connect...\n");
    client_addr_len = sizeof(client_addr);

    /*
     * accept: int socket, struct address, address_len
     * returns: if it is good, returns the file descriptor; if it fails, it returns -1
     * socket: the specified socket created with socket()
     * address: either a NULL, or a pointer to a sockaddr structure where the address of the connecting socket shall be returned
     * address_len: the size of address struct
     * desc: extracts the first connection of the que of pending connections
     * */
    int id = accept(server_fd, (struct sockaddr *) &client_addr, &client_addr_len);



    char repley[] = "HTTP/1.1 200 OK\r\n\r\n";
    printf("Client connected\n");

    char requestBuffer[BUFFER_SIZE] = {0};

    ssize_t bytesRead = read(id, requestBuffer, BUFFER_SIZE - 1);

    if (bytesRead < 0){
        perror("Read failed");
        close(id);
        return 1;
    }

    requestBuffer[bytesRead] = '\0';
    /*
     * read: int fileDescriptor(received from "accept()"), char[] request, int sizeof(request)
     * fileDescriptor: the file descriptor received from "accept()"
     * request: empty string that will be assigned the cients request
     * returns: number of bytes recieved of it worked, if it didnt work, it returns -1
     * descr: bruh just use this to get the request of the client
     * */
    //read(id, requestBuffer, BUFFER_SIZE);
    printf("request from: %s\nend here...\n", requestBuffer);

    char folder[20];
    int index = 0;
    bool foundFolder = false;
    char argument[20];
    int argumentIndex = 0;

    //get the command/folder
    for (int i = 5; i < ArrayLength(requestBuffer); i++){
        if (requestBuffer[i] == '/'){
            foundFolder = true;
            continue;
        }

        if (!foundFolder){
            folder[index] = requestBuffer[i];
            index++;
        }else{
            argument[argumentIndex] = requestBuffer[i];
            argumentIndex++;
        }

        if (foundFolder && requestBuffer[i] == ' '){break;}
    }

    folder[index] = '\0';
    argument[argumentIndex] = '\0';
    printf("folder: %s\n", folder);
    printf("argument: %s\n", argument);

    if (requestBuffer[0] == 'G'){
        //get request
        
        if (requestBuffer[4] == '/' && requestBuffer[5] == ' '){
            send(id, response_ok, strlen(response_ok) , 0);
            close(id);
            return 0;
        }

        for (int i = 0; i < ArrayLength(folders); i++){
            if (strcmp(folders[i], folder) == 0){
                switch(i){
                    case 0:
                        //send back abc
                        
                        char echoResponse[BUFFER_SIZE];
                        
                        snprintf(echoResponse, sizeof(echoResponse), 
                                "HTTP/1.1 200 OK\r\n"
                                "Content-Type: text/plain\r\n"
                                "Content-Length: %ld\r\n\r\n%s",
                                strlen(argument), argument);

                        send(id, echoResponse, strlen(echoResponse) , 0);

                        break;
                    case 1:
                        //user-agent
                        char special[] = "*/*";
                        for (int i = 0; i < strlen(requestBuffer) - 3; i++){
                            char rqtBuf[] = {requestBuffer[i], requestBuffer[i+1], requestBuffer[i+2], '\0' };
                            
                            printf("three set: %s\n", rqtBuf);;

                            if (strcmp(rqtBuf, special) == 0){
                                printf("found specials\n");
                                break;
                            }

                        }
                        
                        break;
                }       
                close(id);
                return 1;
                break;
            }
        }
        //send 404
        send(id, response_not_found, strlen(response_not_found) , 0);

    }else{
        // post
    }

    //request buffer is the whole request
    //parse request and send back a responce



    /*
     * send: int socket, *buffer, size_t length, int flags
     * socket: the file descriptor
     * buffer: a pointer to the buffer containing the message
     * length: the length of the message in bytes
     * flags: specify the type of message, see https://pubs.opengroup.org/onlinepubs/000095399/functions/send.html
     * desc: iniiates a transmisstion of a message from the socket to the peer. itll only send if the socket is connected via "connect()"
     * */
    //send(id, repley, strlen(repley) , 0);

    /*
     * int socket
     * desc: closes the connection from the socket to the peer
     * */
    close(server_fd);

    return 0;
}
