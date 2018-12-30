//==================================================== file = udpClient.c =====
//=  A message "client" program to demonstrate sockets programming            =
//=============================================================================
//=  Notes:                                                                   =
//=    1) This program conditionally compiles for Winsock and BSD sockets.    =
//=       Set the initial #define to WIN or BSD as appropriate.               =
//=    2) This program needs udpServer to be running on another host.         =
//=       Program udpServer must be started first.                            =
//=    3) This program assumes that the IP address of the host running        =
//=       udpServer is defined in "#define IP_ADDR"                           =
//=    4) The steps #'s correspond to lecture topics.                         =
//=---------------------------------------------------------------------------=
//=  Example execution: (udpServer and udpClient running on host 127.0.0.1)   =
//=    Received from server: This is a reply message from SERVER to CLIENT    =
//=---------------------------------------------------------------------------=
//=  Build:                                                                   =
//=    Windows (WIN):  Borland: bcc32 udpClient.c                             =
//=                    MinGW: gcc udpClient.c -lws2_32 -o updClient           =
//=                    Visual C: cl ucpClient.c wsock32.lib                   =
//=    Unix/Mac (BSD): gcc ucpClient.c -lnsl -o ucpClient                     =
//=---------------------------------------------------------------------------=
//=  Execute: udpClient                                                       =
//=---------------------------------------------------------------------------=
//=  Author: Ken Christensen                                                  =
//=          University of South Florida                                      =
//=          WWW: http://www.csee.usf.edu/~christen                           =
//=          Email: christen@csee.usf.edu                                     =
//=---------------------------------------------------------------------------=
//=  History:  KJC (08/02/08) - Genesis (from client.c)                       =
//=            KJC (09/09/09) - Minor clean-up                                =
//=            KJC (09/22/13) - Minor clean-up to fix warnings                =
//=            KJC (09/14/17) - Updated build instructions                    =
//=============================================================================
#define  WIN                // WIN for Winsock and BSD for BSD sockets

//----- Include files ---------------------------------------------------------
#include <stdio.h>          // Needed for printf()
#include <string.h>         // Needed for memcpy() and strcpy()
#include <stdlib.h>         // Needed for exit()
#include <string.h>
#include <unistd.h>
#ifdef WIN
  #include <windows.h>      // Needed for all Winsock stuff
#endif
#ifdef BSD
  #include <sys/types.h>    // Needed for sockets stuff
  #include <netinet/in.h>   // Needed for sockets stuff
  #include <sys/socket.h>   // Needed for sockets stuff
  #include <arpa/inet.h>    // Needed for sockets stuff
  #include <fcntl.h>        // Needed for sockets stuff
  #include <netdb.h>        // Needed for sockets stuff
#endif

//----- Defines ---------------------------------------------------------------
  // Port number used
#define  IP_ADDR      "10.224.41.237" // IP address of server1 (*** HARDWIRED ***)
#define  MAX_NUM_PORT   8
#define MAXHOSTNAMESIZE 51 // defines maximum hostname string length
#define PORTNUM 8080


#define OK_IMAGE  "HTTP/1.0 200 OK\r\nContent-Type:image/gif\r\n\r\n"
#define OK_TEXT   "HTTP/1.0 200 OK\r\nContent-Type:text/html\r\n\r\n"
#define OK_BINARY "HTTP/1.0 200 OK\r\nContent-Type:application/octet-strean\r\n\r\n"
#define NOTOK_404 "HTTP/1.0 404 Not Found\r\nContent-Type:text/html\r\n\r\n"
#define MESS_404  "<html><body><h1>FILE NOT FOUND</h1></body></html>"
//===== Main program ==========================================================
int main()
{
#ifdef WIN
  WORD wVersionRequested = MAKEWORD(1,1);       // Stuff for WSA functions
  WSADATA wsaData;                              // Stuff for WSA functions
#endif
  int                  client_s;        // Client socket descriptor
  struct sockaddr_in   server_addr;     // Server Internet address
  struct sockaddr_in   client_addr;
  int                  addr_len;        // Internet address length
  char                 out_buf[4096];   // Output buffer for data
  char                 in_buf[4096];    // Input buffer for data
  int                  retcode;         // Return code
  int                  sockFileD;
  int                   count;
  unsigned short int port;
  unsigned short int action = 0;
  unsigned short int knock_seq[MAX_NUM_PORT];
  char portString [6];
  unsigned char input[MAX_NUM_PORT]; // string to be encrypted
  unsigned char output[MAX_NUM_PORT]; // encrypted string
  char localhost[MAXHOSTNAMESIZE];
  char clientIP[16];
  char serverIP[16];
  char remotehost[MAXHOSTNAMESIZE];
  unsigned short int upper = 0; // upper byte of port number
  unsigned short int lower = 0; // lower byte of port number
  int arr[3];
  char password[128];
  unsigned char key;

struct hostent *servername; // used for server name lookup
struct hostent *clientname;
#ifdef WIN
  // This stuff initializes winsock
  WSAStartup(wVersionRequested, &wsaData);
#endif
// Setting the memory for the user inputs
  memset(portString,'\0', sizeof(portString));
  memset(remotehost, '\0', sizeof(remotehost));
  memset(localhost, '\0', sizeof(localhost));
  memset(clientIP, '\0', sizeof(clientIP));
  memset(knock_seq,'\0',sizeof(knock_seq));

// getting the inputs from the user

printf("\nEnter local hostname or IP: ");
fgets(localhost, MAXHOSTNAMESIZE, stdin);
printf("Enter remote hostname or IP: ");
fgets(remotehost, MAXHOSTNAMESIZE, stdin);

  printf("Enter the remote port to encrypt into the sequence: \n");
  fgets(portString,6,stdin);



printf("enter 1/0 to open/close the port:");
action = getc(stdin);
printf("Enter Shared key (in hex): ");
//scanf("%hhx",&key);
scanf("%hhx",&key);
//printf("%x\n",key);
//printf("%x",key);

if((unsigned char) action == '1')
{
    action = 1;
}
else
{
    action = 0;
}
// remove any new line characters from the remote host and the client ips
count = 0;
while(count <= MAXHOSTNAMESIZE){
if(remotehost[count] == '\n')
remotehost[count] = '\0';
if(localhost[count] == '\n')
localhost[count] = '\0';
count++;
}

port = (unsigned short int ) strtol(portString,NULL,10);
memcpy(clientIP, inet_ntoa(client_addr.sin_addr), 15);
printf("");

  // Assign a message to buffer out_buf
clientname = gethostbyname(localhost);
if(clientname == NULL){
printf("ERROR W CLIENT NAME");
exit(0);
}

    memcpy((char *)&client_addr.sin_addr.s_addr, clientname->h_addr_list[0], clientname->h_length);
    memcpy(clientIP, inet_ntoa(client_addr.sin_addr), 15);
    printf("\nSource: %s (%s)\n", clientname->h_name, clientIP);



            input[0] = (unsigned char) strtol(strtok(clientIP,"."),NULL,10);
            input[1] = (unsigned char) strtol(strtok('\0',"."),NULL,10);
            input[2] = (unsigned char) strtol(strtok('\0',"."),NULL,10);
            input[3] = (unsigned char) strtol(strtok('\0',"."),NULL,10);
            upper = port;
            upper = upper >> 8;
            lower = port;
            lower = ((lower << 8) >> 8);
            input[4] = (unsigned char) upper;
            input[5] = (unsigned char) lower;
            input[6] = (unsigned char) action;

//encryptsequence(input,output, password);

// encrypting the knock sequence using and XOR with a hex key

int i;
for(i = 0; i < MAX_NUM_PORT; i++)
{
    knock_seq[i] = input[i] ^ key;
}
count = 0;
printf("\n");
printf("Ports: \n");

    // This loop creates the sockets and assigns the encrypted port numbers
     while(count < MAX_NUM_PORT)
        {
            sockFileD = socket(AF_INET, SOCK_STREAM, 0);
            if(sockFileD < 0 )
            {
                printf("Error is the socket creation");
            }
            server_addr.sin_family = AF_INET;                 // Address family to use
            server_addr.sin_port = htons(knock_seq[count]);
            arr[count] = ntohs(server_addr.sin_port);
            if(connect(sockFileD, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
            {
                printf("Port : %d \n", ntohs(server_addr.sin_port));
            }
            else
            {
                    printf("Error connection made of port : %d \n\n", ntohs(server_addr.sin_port));
                    closesocket(sockFileD);
                    exit(0);
            }
            closesocket(sockFileD);
            count++;
        }
    // creating the UDP socket to sent the sequence to the server
  client_s = socket(AF_INET, SOCK_DGRAM, 0);
  if (client_s < 0)
  {
    printf("*** ERROR - socket() failed \n");
    exit(-1);
  }

  // >>> Step #2 <<<
  // Fill-in server1 socket's address information
  server_addr.sin_family = AF_INET;                 // Address family to use
  server_addr.sin_port = htons(1050);           // Port num to use
  server_addr.sin_addr.s_addr = inet_addr(IP_ADDR); // IP address to use

    int k;
    int tempbuf[MAX_NUM_PORT];
    for(k = 0; k < 8; k++)
    {
        tempbuf[k] = knock_seq[k];
    }
 // strcpy(out_buf, "This is a reply message from CLIENT to SERVER");
  retcode = sendto(client_s,tempbuf, sizeof(tempbuf)+1, 0,
    (struct sockaddr *)&server_addr, sizeof(server_addr));
  if (retcode < 0)
  {
    printf("*** ERROR - sendto() failed \n");
    exit(-1);
  }



printf("Sequence complete");

// close the sockets
#ifdef WIN
  retcode = closesocket(client_s);
  if (retcode < 0)
  {
    printf("*** ERROR - closesocket() failed \n");
    exit(-1);
  }
#endif

// Running another client instance to connect to the weblite web server
  int                  client;        // Client socket descriptor
  struct sockaddr_in   server;     // Server Internet address
  int                  ret_c;         // Return code
  // >>> Step #1 <<<
  // Create a client socket
  //   - AF_INET is Address Family Internet and SOCK_STREAM is streams
  client = socket(AF_INET, SOCK_STREAM, 0);
  if (client < 0)
  {
    printf("*** ERROR - socket() failed \n");
    exit(-1);
  }

  // >>> Step #2 <<<
  // Fill-in the server's address information and do a connect with the
  // listening server using the client socket - the connect() will block.
  server.sin_family = AF_INET;                 // Address family to use
  server.sin_port = htons(PORTNUM);           // Port num to use
  server.sin_addr.s_addr = inet_addr(IP_ADDR); // IP address to use
  ret_c = connect(client, (struct sockaddr *)&server,sizeof(server));
  if (ret_c < 0)
  {
    printf("*** ERROR - connect() failed \n");
    exit(-1);
  }

  // >>> Step #5 <<<
  // Close all open sockets
  //Sleep(20000);
#ifdef WIN
  ret_c = closesocket(client);
  if (ret_c < 0)
  {
    printf("*** ERROR - closesocket() failed \n");
    exit(-1);
  }
#endif


}



