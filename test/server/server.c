/* A simple server in the internet domain using TCP
   The port number is passed as an argument */
#include <stdio.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>

void error(char *msg)
{
    perror(msg);
    exit(1);
}

int main(int argc, char *argv[])
{
     int sockfd=0, newsockfd=0, portno=0, clilen=0;
     char buffer[256];
     struct sockaddr_in6 serv_addr, cli_addr;
     int n;
     int err;
     if (argc < 2) {
	     fprintf(stderr,"ERROR, no port provided\n");
	     exit(1);
     }
     
     printf("socket( AF_INET6_EXT: %d, SOCK_STREAM: %d, 0)\n", AF_INET6_EXT, SOCK_STREAM); fflush(stdout);

     sockfd = socket(AF_INET6_EXT, SOCK_STREAM, 0);
     printf("sockfd: %d\n", sockfd);fflush(stdout);
     
     if (sockfd < 0) 
	     error("ERROR opening socket");fflush(stdout);
     
     bzero((char *) &serv_addr, sizeof(serv_addr));
     portno = atoi(argv[1]);
     
     serv_addr.sin6_family = AF_INET6;
     serv_addr.sin6_addr = in6addr_any;
     serv_addr.sin6_port = htons(portno);
     
     printf("bind()\n");fflush(stdout);
     if (err = bind(sockfd, (struct sockaddr *) &serv_addr,
		    sizeof(serv_addr)) < 0) {
	     printf("%d from bind()\n", err);
	     error("ERROR: on binding");
     }
     printf(" listen() ");fflush(stdout);
     
     listen(sockfd,5);
     clilen = sizeof(cli_addr);
     newsockfd = accept(sockfd, 
			(struct sockaddr *) &cli_addr, 
			&clilen);
     if (newsockfd < 0) 
	     error("ERROR on accept");
     bzero(buffer,256);
     n = read(newsockfd,buffer,255);
     if (n < 0) error("ERROR reading from socket");
     printf("Here is the message: %s\n",buffer);fflush(stdout);
     n = write(newsockfd,"I got your message",18);
     if (n < 0) error("ERROR writing to socket");
     return 0; 
}
