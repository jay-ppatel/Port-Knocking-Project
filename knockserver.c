//====================================================== file = knockserver.c =====
//=  A super light-weight secure HTTP server                                  =
//=   - Uses threads to allow for parallel connections                        =
//=============================================================================
//=  Notes:                                                                   =
//=    1) Compiles for Windows (using Winsock and Windows threads) and Unix   =
//=       (using BSD sockets and POSIX threads). Set WIN or BSD in the        =
//=       #define in line 47.                                                 =
//=    2) Serves HTML, text, and GIF only.                                    =
//=    3) Is not secure -- when weblite is running any file on the machine    =
//=       (that weblite is running on) could be accessed.                     =
//=    4) Sometimes the browser drops a connection when doing a refresh.      =
//=       This is handled by checking the recv() return code in the           =
//=       function that handles GETs. This is only seen when using            =
//=       Explorer.                                                           =
//=    5) The 404 HTML message does not always display in Explorer.           =
//=---------------------------------------------------------------------------=
//=  Execution notes:                                                         =
//=   1) Execute this program in the directory which will be the root for     =
//=      all file references (i.e., the directory that is considered at       =
//=      "public.html").                                                      =
//=   2) Open a Web browser and surf http://xxx.xxx.xxx.xxx:8080/yyy where    =
//=      xxx.xxx.xxx.xxx is the IP address or hostname of the machine that    =
//=      weblite is executing on and yyy is the requested object.             =
//=   3) The only non-error output (to stdout) from weblite is a message      =
//=      with the name of the file currently being sent.                      =
//=---------------------------------------------------------------------------=
//=  Build:                                                                   =
//=    Windows (WIN):  Borland: bcc32 -WM weblite.c                           =
//=                    MinGW: gcc weblite.c -lws2_32 -o weblite               =
//=                    Visual C: cl /MT weblite.c wsock32.lib                 =
//=    Unix/Mac (BSD): gcc weblite.c -lpthread -o weblite                     =
//=---------------------------------------------------------------------------=
//=  Execute: weblite                                                         =
//=---------------------------------------------------------------------------=
//=  History:  KJC (10/08/02) - Genesis                                       =
//=            KJC (09/11/05) - Fixed "GET \./../" security hole              =
//=            KJC (01/29/06) - Add BSD as conditional compile (thanks to     =
//=                             James Poag for POSIX threads howto)           =
//=            KJC (12/06/06) - Fixed pthread call (thanks to Nicholas        =
//=                             Paltzer for finding and fixing the problem)   =
//=            KJC (09/09/09) - Changed port to 8080 and fixed gcc build      =
//=            KJC (09/07/10) - Updated build instructions for minGW          =
//=            KJC (08/20/11) - Updated build instructions for gcc            =
//=            KJC (09/17/13) - Removed broken security check, is non-secure  =
//=            SD  (09/01/17) - Updated for building on a Mac                 =
//=============================================================================
#define  WIN              // WIN for Winsock and BSD for BSD sockets

//----- Include files ---------------------------------------------------------
#include <stdio.h>        // Needed for printf()
#include <stdlib.h>       // Needed for exit()
#include <string.h>       // Needed for memcpy() and strcpy()
#include <fcntl.h>        // Needed for file i/o stuff
#include <pthread.h>
#include <string.h>
#ifdef WIN
  #include <process.h>    // Needed for _beginthread() and _endthread()
  #include <stddef.h>     // Needed for _threadid
  #include <windows.h>    // Needed for all Winsock stuff
  #include <sys\stat.h>   // Needed for file i/o constants
  #include <io.h>         // Needed for file i/o stuff
  #include <stddef.h>
#include <string.h>

#endif
#ifdef BSD
  #include <pthread.h>    // Needed for pthread_create() and pthread_exit()
  #include <sys/stat.h>   // Needed for file i/o constants
  #include <sys/types.h>  // Needed for sockets stuff
  #include <netinet/in.h> // Needed for sockets stuff
  #include <sys/socket.h> // Needed for sockets stuff
  #include <arpa/inet.h>  // Needed for sockets stuff
  #include <fcntl.h>      // Needed for sockets stuff
  #include <netdb.h>      // Needed for sockets stuff
  #include <unistd.h>     // Needed to avoid read and closesocket warnings
#endif

//----- HTTP response messages ----------------------------------------------
#define OK_IMAGE  "HTTP/1.0 200 OK\r\nContent-Type:image/gif\r\n\r\n"
#define OK_TEXT   "HTTP/1.0 200 OK\r\nContent-Type:text/html\r\n\r\n"
#define NOTOK_404 "HTTP/1.0 404 Not Found\r\nContent-Type:text/html\r\n\r\n"
#define MESS_404  "<html><body><h1>FILE NOT FOUND</h1></body></html>"
#define OK_BINARY "HTTP/1.0 200 OK\r\nContent-Type:application/octet-strean\r\n\r\n"
//----- Defines -------------------------------------------------------------
#define  PORT_NUM            8080    // Port number for Web server
#define  BUF_SIZE            4096     // Buffer size (big enough for a GET)
#define  MAXPWSIZE           128
#define MAXNUMOFKNOCKS 3
#define CLIENTIP "10.224.48.240"
//----- Function prototypes -------------------------------------------------
#ifdef WIN
  void handle_get(void *in_arg);   // Windows thread function to handle GET
#endif
#ifdef BSD
  void *handle_get(void *in_arg);  // POSIX thread function to handle GET
#endif

//===== Main program ========================================================

#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))

// creating the struct for the input from the client

char passwrd[MAXPWSIZE];
struct hostdata{
char originIP[16];
unsigned char blf_in[MAXNUMOFKNOCKS];
unsigned char blf_out[MAXNUMOFKNOCKS];
unsigned short int knocks_enc[MAXNUMOFKNOCKS];
unsigned short int decrytped_knocks[MAXNUMOFKNOCKS];
int knocksreceived;
struct hostdata *next;
time_t timestamp;
};


void main()
{

#ifdef WIN
  WORD wVersionRequested = MAKEWORD(1,1);  // Stuff for WSA functions
  WSADATA wsaData;                         // Stuff for WSA functions
#endif
  int                  server_s;           // Server socket descriptor
  struct sockaddr_in   server_addr;        // Server Internet address
  int                  client_s;           // Client socket descriptor
  struct sockaddr_in   client_addr;        // Client Internet address
  struct in_addr       client_ip_addr;     // Client IP address
  char                 in_buf[BUF_SIZE];     // Input buffer for GET request
  char                 out_buf[BUF_SIZE];    // Output buffer for HTML respons
  unsigned short int action = 0;
  unsigned short int decrytped_knocks[MAXNUMOFKNOCKS]; // decrypted
  struct hostdata *currenthost;
  int knocksreceived;
  unsigned char blf_in[MAXNUMOFKNOCKS];
  char remotehost[16];
  char localport[6];
  int                  welcome_s;       // Welcome socket descriptor
  int                  connect_s;       // Connection socket descriptor
  char password[128];
  unsigned char key;

#ifdef WIN
  int                  addr_len;           // Internet address length
#endif
  int                  retcode;            // Return code
#ifdef WIN
  // This stuff initializes winsock
  WSAStartup(wVersionRequested, &wsaData);
#endif

printf("Enter Decryption key:");
scanf("%hhx", &key);
// Creating a UDP based socket to get the knock sequence from the client

 server_s = socket(AF_INET, SOCK_DGRAM, 0);
  if (server_s < 0)
  {
    printf("*** ERROR - socket() failed \n");
    exit(-1);
  }

  // >>> Step #2 <<<
  // Fill-in my socket's address information
  server_addr.sin_family = AF_INET;                 // Address family to use
  server_addr.sin_port = htons(1050);           // Port number to use
  server_addr.sin_addr.s_addr = htonl(INADDR_ANY);  // Listen on any IP address
  retcode = bind(server_s, (struct sockaddr *)&server_addr,
    sizeof(server_addr));
  if (retcode < 0)
  {
    printf("*** ERROR - bind() failed \n");
    exit(-1);
  }

  // >>> Step #3 <<<
  // Wait to receive a message from client
  printf("Waiting to receive the encryption sequence... \n");
  addr_len = sizeof(client_addr);
  int arr[10];
  retcode = recvfrom(server_s, arr, sizeof(arr), 0,
    (struct sockaddr *)&client_addr, &addr_len);
  if (retcode < 0)
  {
    printf("*** ERROR - recvfrom() failed \n");
    exit(-1);
  }

  // Copy the four-byte client IP address into an IP address structure
  memcpy(&client_ip_addr, &client_addr.sin_addr.s_addr, 4);
  // Print an informational message of IP address and port of the client
  printf("IP address of client = %s  port = %d) \n", inet_ntoa(client_ip_addr),
    ntohs(client_addr.sin_port));
  printf("Received from client: \n");
  int j = 0;
  printf("Ports received: \n");
  for(j = 0; j < 8; j++)
  {
      printf("%d\n",arr[j]);
  }
    // decrypting the port knock sequence using the key
    struct hostdata *host;
    unsigned short int upper = 0; // upper byte of port number
    unsigned short int lower = 0; // lower byte of port number
    for(j = 0; j < 8; j++)
    {
        arr[j] = arr[j] ^ key;
    }

        host->decrytped_knocks[0] = (unsigned short int) arr[0];
        host->decrytped_knocks[1] = (unsigned short int) arr[1];
        host->decrytped_knocks[2] = (unsigned short int) arr[2];
        host->decrytped_knocks[3] = (unsigned short int) arr[3];
        upper = arr[4] << 8;
        lower = (unsigned short int) arr[5];
        host->decrytped_knocks[4] = upper | lower;
        host->decrytped_knocks[6] = (unsigned short int) arr[6];

        printf("Action: ");
        if(host->decrytped_knocks[6] == 1) printf("Open ");
        else if(host->decrytped_knocks[6] == 0) printf("closesocket ");
        else printf("NO ACTION ");
        printf("port %d to IP address %d.%d.%d.%d\n\n", host->decrytped_knocks[4], host->decrytped_knocks[0], host->decrytped_knocks[1], host->decrytped_knocks[2], host->decrytped_knocks[3]);


#ifdef WIN
  retcode = closesocket(server_s);
  if (retcode < 0)
  {
    printf("*** ERROR - closesocketsocket() failed \n");
    exit(-1);
  }
#endif

        // spin off the weblite server
        startserver2();

#ifdef WIN
  // Clean-up winsock
  WSACleanup();
#endif


}


// function to start the web server
void startserver2()
{
    // hardwaire the file path of the executable and concat with the rest of the path info
    char pathz[] = "C:\\Users\\Amer\\Desktop\\weblite";
    strcat(pathz,"\\");
    strcat(pathz,"webserver");
    strcat(pathz,".exe");
    PROCESS_INFORMATION pi;
    STARTUPINFO si;
    ZeroMemory(&si,sizeof(si));
    si.cb = sizeof(si);
    BOOL bRet = CreateProcess(
                pathz,  //path
                NULL,   //Command string null
                NULL,   //Process handle null
                NULL,   //Thread handle null
                FALSE,  //No inheritance of handles
                0,      //No flags
                NULL,   //environment block
                NULL,   //Current directory
                &si,    //Pointer to STARTUPINFO
                &pi);   //Pointer to PROCESS_INFORMATION
            // let the weblite server run for 10 seconds
            Sleep(10000);
            BOOL tProc;
            // terminate the process after completion
        tProc = TerminateProcess(pi.hProcess,0);
    //system("Webserver.exe");


}
int verfiy(int arr[8])
{
    char ip[30];
    int i = 0;
    for(i = 0; i < 4; i++)
    {
      strcat(ip,arr[i]);
    }
    if(strcmp(ip,CLIENTIP) == 0)
    {
        return 1;
    }
    else
    {
        return 0;
    }

    return 0;
}

void allowTenUsers()
{
int i, len, num, rc;
int l_socket, a_socket;

/* Buffer for data */
char buffer[100];
struct sockaddr_in addr;
/* Create an AF_INET stream socket to receive */
/* incoming connections on */
l_socket = socket(AF_INET, SOCK_STREAM, 0);
if(l_socket < 0)
{
    printf("server - socket() error");
    exit(-1);
}
else
printf("server - socket() is OK\n");
printf("Binding the socket...\n");

/* Bind the socket */
memset(&addr, 0, sizeof(addr));
addr.sin_family = AF_INET;
addr.sin_addr.s_addr = htonl(INADDR_ANY);
addr.sin_port = htons(PORT_NUM);
rc = bind(l_socket, (struct sockaddr *)&addr, sizeof(addr));
if(rc < 0)
{
    printf("server - bind() error");
    closesocket(l_socket);
    exit(-1);
}
else
printf("server - bind() is OK\n");
/* Set the listen backlog */
rc = listen(l_socket, 10);
if(rc < 0)
{
    printf("server - listen() error");
    closesocket(l_socket);
    exit(-1);
}

else
printf("server - listen() is OK\n");
/* Inform the user that the server is ready */
printf("The server is ready!\n");
/* Go through the loop once for each connection */
for(i=0; i < 10; i++)
{
    /* Wait for an incoming connection */
    printf("Connection: #%d\n", i+1);
    printf("Waiting on accept() to complete\n");
    a_socket = accept(l_socket, NULL, NULL);
    if(a_socket < 0)
    {
        printf("server - accept() error");
        closesocket(l_socket);
        exit(-1);
    }
    else
    printf("accept() is OK and completed successfully!\n");
    /* Receive a message from the client */
    printf("Waiting on clients connection \n");
    rc = recv(a_socket, buffer, sizeof(buffer), 0);
    if(rc <= 0)
    {
        printf("server error w recv");
        closesocket(l_socket);
        closesocket(a_socket);
        exit(-1);
    }
    else
    printf("The message from client: \"%s\"\n", buffer);
    printf("Sending back to the client\n");
    len = rc;
    rc = send(a_socket, buffer, len, 0);
    if(rc <= 0)
    {
        printf("server - send() error");
        closesocket(l_socket);
        closesocket(a_socket);
        exit(-1);
    }
    else
    printf("server - sent successfully\n");
    /* closesocket the incoming connection */
    closesocket(a_socket);
}

/* closesocket the listen socket */
closesocket(l_socket);
}

