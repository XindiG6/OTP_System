/*********************************
**Program:OTP
**Author: Xindi Guo
**Date: 12/6/2019
**Description: create a random key that from 27 letters based on the required length
**Reference: class sildes
*********************************/

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h> 
#include <sys/types.h>
#include <unistd.h>

#define BUFFER_SIZE    4096
//#define DEBUG

void error(const char *msg) { perror(msg); exit(1); } // Error function used for reporting issues

int main(int argc, char** argv)
{
    int i=0;
    char bufData[BUFFER_SIZE];
    char bufKey[BUFFER_SIZE];
    
    int keyLength=0;
    int ciphertextLength=0;
    int numReceived;
    int numSent;

    int fKey=0,fData=0;
    int port;
    int sockfd;
    struct sockaddr_in serv_addr;
    struct hostent *server;

    // make sure there are enough args
    if (argc < 4)
    {
        error("Usage: otp_dec ciphertext key port\n");
        exit(1);
    }

    // validate port number
    sscanf(argv[3], "%d", &port);
    if (port < 0 || port > 65535)
    {
        error("otp_dec: invalid port\n");
        exit(2);
    }
    // validate contents of key
    for (i = 0; i < keyLength - 1; i++)
    {
        if ((int) bufKey[i] > 90 || ((int) bufKey[i] < 65 && (int) bufKey[i] != 32))
        {
            error("otp_dec error: key contains bad characters");
            exit(1);
        }
    }

    // create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        error("Error: could not contact otp_dec_d on port\n");
        exit(2);
    }

    // zero out the IP address memory space
    memset(&serv_addr, 0, sizeof(serv_addr));

    server = gethostbyname("localhost");
    if (server == NULL)
    {
        error("Error: could not connect to otp_dec_d\n");
        exit(2);
    }    
  
    serv_addr.sin_family = AF_INET;

    bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr,
         server->h_length);         

    serv_addr.sin_port = htons(port);

    // connect to otp_dec_d
    if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
    {
        error("Error: could not connect to otp_dec_d on port\n");
        exit(2);
    }

    // make sure not otp_enc_d though

#ifdef DEBUG
    printf("otp_dec: connection to server established\n"); 
#endif

    // send ciphertext type to otp_enc_d
    numSent = write(sockfd, "D", 1);
    if (numSent < 0)
    {
        error("Error: could not send type to otp_dec_d on port \n");
        exit(2);
    }
    char ack[1];
    // get acknowledgement from server
    numReceived = read(sockfd, ack, 1);
    if (numReceived < 0)
    {
       printf("Error receiving acknowledgement from otp_enc_d\n");
       exit(2);
    }
    if(ack[0]=='#'){
        exit(2);
    }

    // open ciphertext for reading
    fData = open(argv[1], O_RDONLY);
    // if unable to read file, display error message
    if (fData < 0)
    {
        error("Error: cannot open ciphertext file \n");
        exit(1);
    }
    // open key for reading
    fKey = open(argv[2], O_RDONLY);

    // if unable to read file, display error message
    if (fKey < 0)
    {
        error("Error: cannot open key file\n");
        exit(1);
    }

    struct stat stbuf;
    if ((fstat(fData, &stbuf) != 0) || (!S_ISREG(stbuf.st_mode))) {
      /* Handle error */
    }
    ciphertextLength = stbuf.st_size;
    if ((fstat(fKey, &stbuf) != 0) || (!S_ISREG(stbuf.st_mode))) {
      /* Handle error */
    }
    keyLength = stbuf.st_size;
    //compare length of plaintext to that of key
    if(keyLength<ciphertextLength){
        error("too-short key");
        exit(2);
    }
    while(1){
        memset(bufData,0,BUFFER_SIZE);
        memset(bufKey,0,BUFFER_SIZE);
        // read contents of ciphertext & keep track of # of bytes read
        ciphertextLength = read(fData, bufData, BUFFER_SIZE);
        keyLength = read(fKey, bufKey, ciphertextLength);
        if(ciphertextLength>0&&bufData[ciphertextLength-1]=='\n'){
            --ciphertextLength;
        }
        //end of file
        if(ciphertextLength<1){
            numSent = write(sockfd, "E", 1);
            break;
        }
        else{
            numSent = write(sockfd, "N", 1);
        }
        
        
        // validate contents of ciphertext and key
        for (i = 0; i < ciphertextLength; i++)
        {
            if ((int) bufData[i] > 90 || ((int) bufData[i] < 65 && (int) bufData[i] != 32))
            {
                error("otp_dec error: ciphertext contains bad characters");
                exit(1);
            }
            if ((int) bufKey[i] > 90 || ((int) bufKey[i] < 65 && (int) bufKey[i] != 32))
            {
                printf("otp_enc error: key contains bad characters");
                exit(1);
            }
        }
        // send ciphertext to otp_enc_d
        numSent = write(sockfd, bufData, ciphertextLength);
        if (numSent < ciphertextLength)
        {
            error("Error: could not send ciphertext to otp_dec_d on port \n");
            exit(2);
        }

    #ifdef DEBUG
        printf("otp_dec: ciphertext sent: %d characters\n", numSent ); 
    #endif

        ack[0]=0;
        // get acknowledgement from server
        numReceived = read(sockfd, ack, 1);
        if (numReceived < 0)
        {
            error("Error receiving acknowledgement from otp_dec_d\n");
            exit(2);
        }

    #ifdef DEBUG
        printf("otp_dec: acknowledgement received\n"); 
    #endif

        // send key to otp_dec_d
        numSent = write(sockfd, bufKey, keyLength);
        if (numSent < keyLength - 1)
        {
            error("Error: could not send key to otp_dec_d on port\n");
            exit(2);
        }

    #ifdef DEBUG
        printf("otp_dec: key sent: %d characters. now reading response\n", numSent); 
    #endif

        // zero out buffer
        memset(bufData, 0, BUFFER_SIZE);

        // receive ciphertext from otp_dec_d
        numReceived = read(sockfd, bufData, ciphertextLength);

        if (numReceived < 0)
        {
            error("Error receiving ciphertext from otp_dec_d\n");
            exit(2);
        }

    #ifdef DEBUG
        printf("otp_dec: response received\n"); 
    #endif

        // output ciphertext to stdout
        for (i = 0; i < ciphertextLength; i++)
        {
            printf("%c", bufData[i]);
        }
    }
    // add newline to ciphertext ouput
        printf("\n");
    // close file
    close(fData);
    close(fKey);

    // close socket
    close(sockfd);

    return 0;
}
