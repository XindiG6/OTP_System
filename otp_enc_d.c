/*********************************
**Program:OTP
**Author: Xindi Guo
**Date: 12/6/2019
**Description: create a random key that from 27 letters based on the required length
**Reference: class sildes
*********************************/

#include <fcntl.h> 
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h> 
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define BUFFER_SIZE    4096
//#define DEBUG

void error(const char *msg) { perror(msg); exit(1); } // Error function used for reporting issues

int main(int argc, char** argv)
{
    int i=0;
    char bufData[BUFFER_SIZE];
    char bufKey[BUFFER_SIZE];
    
    int keyLength;
    int numSent=0,numRecv=0;
    int plaintextLength;

    int pid;
    int port;
    int sockfd;
    int newsockfd;
    socklen_t clilen;
    struct sockaddr_in server;
    struct sockaddr_in client;

    // make sure there are enough args
    if (argc < 2)
    {
        error("Usage: otp_enc_d port\n");
        exit(1);
    }

    //get the Net port
    sscanf(argv[1], "%d", &port);
    if (port < 0 || port > 65535)
    {
        error("otp_enc_d: invalid port\n");
        exit(2);
    }

    // create socket
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        error("Error: opt_enc_d could not create socket\n");
        exit(1);
    }

    // set up an address
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(port);

    // bind socket to a port
    if (bind(sockfd, (struct sockaddr *) &server, sizeof(server)) < 0)
    {
        error("Error: otp_enc_d unable to bind socket to port\n");
        exit(2);
    }
#ifdef DEBUG
    printf("\notp_enc_d: bound socket on port %d\n", port);
#endif

    // listen for connections
    if (listen(sockfd, 5) == -1)
    {
        error("Error: otp_enc_d unable to listen on port\n");
        exit(2);
    }

#ifdef DEBUG
    printf("\notp_enc_d: now listening on port %d\n", port);
#endif

    clilen = sizeof(client);

    // accept connections
    while (1)
    {
        newsockfd = accept(sockfd, (struct sockaddr *) &client, &clilen);
        if (newsockfd < 0)
        {
            error("Error: opt_enc_d unable to accept connection\n");
            continue;
        }

        // every time a client connects, spawn off that process
        pid = fork();

        if (pid < 0)
        {
            perror("opt_enc_c: error on fork\n");
        }

        // child process, do work
        if (pid == 0)
        {
        #ifdef DEBUG
            printf("otp_enc_d: connection established with client\n");
        #endif

            char bufFlag[1];
            // receive ciphertext from otp_dec
            numRecv = read(newsockfd, bufFlag, 1);
            if (numRecv < 0)
            {
                error("Error: otp_end_d could not read ciphertext on port\n");
                exit(2);
            }
            if(bufFlag[0]!='E'){
                error("otp_enc cannot use otp_dec_d");
                numSent = write(newsockfd, "#", 1);
                exit(2);
            }
            numSent = write(newsockfd, "O", 1);

            while(1){
                numRecv = read(newsockfd, bufFlag, 1);
                //recieve the end flag
                if(bufFlag[0]=='E'){
                    break;
                }
                // zero out buffer
                memset(bufData, 0, BUFFER_SIZE);

                // receive plaintext from otp_enc
                plaintextLength = read(newsockfd, bufData, BUFFER_SIZE);
                if (plaintextLength < 0)
                {
                    error("Error: otp_end_d could not read plaintext on port\n");
                    exit(2);
                }
                //printf("%d\n",plaintextLength);
            #ifdef DEBUG
                printf("otp_enc_d: plaintext read: %d characters\n", plaintextLength);
            #endif

                // send acknowledgement to client
                numSent = write(newsockfd, "!", 1);
                if (numSent < 0)
                {
                    error("otp_enc_d error sending acknowledgement to client\n");
                    exit(2);
                }
            #ifdef DEBUG
                printf("otp_enc_d: acknowledgement sent to client\n");
            #endif

                // zero out buffer
                memset(bufKey, 0, BUFFER_SIZE);

                // receive key from otp_enc
                keyLength = read(newsockfd, bufKey, BUFFER_SIZE);
                
                if (keyLength < 0)
                {
                    error("Error: otp_end_d could not read key on port\n");
                    exit(2);
                }

            #ifdef DEBUG
                printf("opt_enc_d: key read: %d characters. now processing\n", keyLength);
            #endif

                // validate contents of plaintext
                for (i = 0; i < plaintextLength; i++)
                {
                    if ((int) bufData[i] > 90 || ((int) bufData[i] < 65 && (int) bufData[i] != 32))
                    {
                        error("otp_enc_d error: plaintext contains bad characters");
                        exit(1);
                    }
                }

                // validate contents of key
                for (i = 0; i < keyLength; i++)
                {
                    if ((int) bufKey[i] > 90 || ((int) bufKey[i] < 65 && (int) bufKey[i] != 32))
                    {
                        error("otp_enc_d error: key contains bad characters");
                        exit(1);
                    }
                }

                // compare length of plaintext to that of key
                if (keyLength < plaintextLength)
                { 
                    error("otp_enc_d error: key is too short\n");
                    exit(1);
                }

                // processing: create ciphertext
                for (i = 0; i < plaintextLength; i++)
                {
                    // change spaces to @
                    if (bufData[i] == ' ')
                        bufData[i] = '@';
                    if (bufKey[i] == ' ')
                        bufKey[i] = '@';
                    bufData[i] = (bufData[i] + bufKey[i] - 128) % 27 + 64;
                    // after encryption, change @ to spaces
                    if (bufData[i] == '@')
                        bufData[i] = ' ';
                }

            #ifdef DEBUG
                printf("opt_enc_d: sending response\n");
            #endif
                // send ciphertext to otp_enc
                numSent = write(newsockfd, bufData, plaintextLength);
                if (numSent < plaintextLength)
                {
                    error("otp_enc_d error writing to socket\n");
                    exit(2);
                }

            #ifdef DEBUG
                printf("opt_enc_d: response sent\n");
            #endif
            }
            // close sockets
            close(newsockfd);
            close(sockfd);

            exit(0);
        }

        else {
            close(newsockfd);
        }
    } // end while loop

    return 0;
}
