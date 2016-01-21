/* Include files */
#include "nucleus.h"
#include "networking/nu_networking.h"


/* Defines */
#define  PORT_NUM              8080         /* Port number for server. */
#define  BUF_SIZE              1024         /* Size of input buffer. */
#define  FMT_SIZE              24           /* Size of format string. */
#define  STATUS_FAILURE        -1           /* The operation failed. */


/* Macros */
#define TASK_STACK_SIZE        4096
#define TASK_PRIORITY          31
#define TASK_TIMESLICE         0

/* This is the format for a positive response that does
   contain the foreign hostname. */
CHAR Positive_Response1[] = "HTTP/1.0 200 OK\r\nContent-Type:text/html\r\n\r\n"
                            "My IP Address is: <FONT COLOR=\"#3366BB\">%s</FONT>, "
                            "Your IP Address is: <FONT COLOR=\"#3366BB\">%s</FONT>, "
                            "Your Hostname is: <FONT COLOR=\"#3366BB\">%s</FONT>";

/* This is the format for a positive response that does not
   contain the foreign hostname. */
CHAR Positive_Response2[] = "HTTP/1.0 200 OK\r\nContent-Type:text/html\r\n\r\n"
                            "My IP Address is: <FONT COLOR=\"#3366BB\">%s</FONT>, "
                            "Your IP Address is: <FONT COLOR=\"#3366BB\">%s</FONT>";

/* This is the format for a negative response. */
CHAR Negative_Response[]  = "HTTP/1.0 404 Not Found\r\nContent-Type:text/html\r\n\r\n";


/* Internal globals */
static  NU_TASK Simple_Server_CB;


/* Function prototypes */
static  VOID   Simple_Server_Task(UNSIGNED argc, VOID *argv);
static  STATUS Perform_Request(INT client_s);
static  VOID   Show_Active_IP_Address(VOID);
static  STATUS Get_Local_IP_Addr_String_By_Socket(INT socketd, CHAR *buf);
static  STATUS Get_Local_IP_Addr_By_Socket(INT socketd, UINT8 *buf);
static  STATUS Get_Foreign_IP_Addr_String_By_Socket(INT socketd, CHAR *buf);
static  STATUS Get_Foreign_IP_Addr_By_Socket(INT socketd, UINT8 *buf);


/*************************************************************************
*
*   FUNCTION
*
*       Application_Initialize
*
*   DESCRIPTION
*
*       Initializes and starts the application.
*
*   CALLED BY
*
*       System App Init service
*
*   CALLS
*
*       NU_Allocate_Memory
*       NU_Create_Task
*       NU_Deallocate_Memory
*
*   INPUTS
*
*       mem_pool                            Memory pool
*       uncached_mem_pool                   Uncached memory pool
*
*   OUTPUTS
*
*       None
*
*************************************************************************/
VOID Application_Initialize (NU_MEMORY_POOL* mem_pool,
                             NU_MEMORY_POOL* uncached_mem_pool)
{
    VOID   *pointer;
    STATUS status;


    UNUSED_PARAMETER(uncached_mem_pool);


    /* Allocate memory for the Net Sample1 Task. */
    status = NU_Allocate_Memory(mem_pool, &pointer, TASK_STACK_SIZE, NU_NO_SUSPEND);

    /* Create the Net Sample1 Task. */
    if (status == NU_SUCCESS)
    {
        /* Create the Net Sample1 task.  */
        status = NU_Create_Task(&Simple_Server_CB, "NSAMTSK", Simple_Server_Task, 0, NU_NULL, pointer,
                                TASK_STACK_SIZE, TASK_PRIORITY, TASK_TIMESLICE,
                                NU_PREEMPT, NU_START);

        /* On error, deallocate memory. */
        if(status != NU_SUCCESS)
        {
            (VOID)NU_Deallocate_Memory(pointer);
        }
    }
}


/*************************************************************************
*
*   FUNCTION
*
*       Simple_Server_Task
*
*   DESCRIPTION
*
*       Open a socket connection, bind the socket with the server address,
*       listen, and accept connections.  When connected call the routine
*       to perform request response processing.
*
*   CALLED BY
*
*       Task Scheduler
*
*   CALLS
*
*       NETBOOT_Wait_For_Network_Up
*       Find_Local_IP_Addr_String
*       NU_Socket
*       NU_Bind
*       NU_Listen
*       NU_Accept
*       Perform_Request
*       NU_Close_Socket
*       printf
*
*   INPUTS
*
*       argc                                not used
*       argv                                not used
*
*   OUTPUTS
*
*       None
*
*************************************************************************/
static VOID Simple_Server_Task(UNSIGNED argc, VOID *argv)
{
    STATUS              status;
    INT                 socketd, newsock;    /* Socket descriptors */
    struct addr_struct  servaddr;            /* Server address structure */
    struct addr_struct  client_addr;

    /* Reference unused parameters to avoid toolset warnings. */
    UNUSED_PARAMETER(argc);
    UNUSED_PARAMETER(argv);


    /* Wait until the NET stack is initialized. */
    status = NETBOOT_Wait_For_Network_Up(NU_SUSPEND);
    if (status == NU_SUCCESS)
    {
        /* Show active IP address. */
        Show_Active_IP_Address();

        /* Open a connection via the socket interface. */
        socketd = NU_Socket(NU_FAMILY_IP, NU_TYPE_STREAM, 0);
        if (socketd >=0 )
        {
            /* Fill in a structure with the server address. */
            servaddr.family    = NU_FAMILY_IP;
            servaddr.port      = PORT_NUM;
            PUT32(servaddr.id.is_ip_addrs, 0, IP_ADDR_ANY);
            servaddr.name       = "SAMP1";

            /* Bind the server's address. */
            if (NU_Bind(socketd, &servaddr, 0) >= 0)
            {
                /* Prepare to accept connection requests. */
                status = NU_Listen(socketd, 10);
                if (status == NU_SUCCESS)
                {
                    for (;;)
                    {
                        /* Block in NU_Accept until a client attempts connection. */
                        newsock = NU_Accept(socketd, &client_addr, 0);
                        if (newsock >= 0)
                        {
                            printf("TCP Client has Connected.\r\n");

                            /* Process the incoming request. */
                            status = Perform_Request(newsock);
                            if (status != NU_SUCCESS)
                            {
                                printf("Perform_Request() failed.\r\n");
                            }

                            NU_Close_Socket(newsock);

                        } /* End successful NU_Accept. */
                        else if (newsock == NU_NOT_CONNECTED)
                        {
                            break;
                        }
                    }

                }
                else
                {
                    /* Sleep for a while if the NU_Listen call failed. */
                    printf("NU_Listen() failed.\r\n");
                }

            }
            else
            {
                /* Sleep for a while if the NU_Bind call failed. */
                printf("NU_Bind() failed.\r\n");
            }

        }
        else
        {
            printf("NU_Socket() failed.\r\n");
        }

    }
    else
    {
        printf("NETBOOT_Wait_For_Network_Up() failed.\r\n");
    }
}


/*************************************************************************
*
*   FUNCTION
*
*       Perform_Request
*
*   DESCRIPTION
*
*       This function receives a single request and sends the response.
*
*   CALLED BY
*
*       Simple_Server_Task
*
*   CALLS
*
*       NU_Recv
*       strcmp
*       Get_Local_IP_Addr_String_By_Socket
*       Get_Foreign_IP_Addr_String_By_Socket
*       Get_Foreign_IP_Addr_By_Socket
*       NU_Get_Host_By_Addr
*       NU_Send
*       printf
*
*   INPUTS
*
*       client_s           The connected socket
*
*   OUTPUTS
*
*       status             NU_SUCCESS or STATUS_FAILURE for failue
*
*************************************************************************/
static STATUS Perform_Request(INT client_s)
{
    STATUS         status;
    STATUS         status2;
    char           *buffer;              /* Input buffer for GET request. */
    char           command[FMT_SIZE];    /* Command buffer. */
    char           resource[FMT_SIZE];   /* File name buffer. */
    char           fmt_str[FMT_SIZE];    /* Format string buffer. */
    int            retcode;              /* Return code. */
    UINT8          ipaddr[MAX_ADDRESS_SIZE];
    char           local_addr[16];
    char           foreign_addr[16];
    NU_HOSTENT     hentry;
    NU_MEMORY_POOL *sys_pool_ptr;

    /* Get system memory pool pointer */
    status = NU_System_Memory_Get(&sys_pool_ptr, NU_NULL);

    if (status == NU_SUCCESS)
    {
        /* Allocate memory for the tx/rx buffer. */
        status = NU_Allocate_Memory(sys_pool_ptr, (void**)&buffer, BUF_SIZE, NU_NO_SUSPEND);

        /* Create the Net Sample1 Task. */
        if (status == NU_SUCCESS)
        {
            /* In a web browser type in the address of the Nucleus target,
               optionally followed by /ip_addr.  Valid examples are:
               192.168.0.22
               192.168.0.22/
               192.168.0.22/ip_addr
               http://192.168.0.22
               http://192.168.0.22/
               http://192.168.0.22/ip_addr
               Anything else results in a 404 response.
               */


            /* Receive a GET request from the Web browser. Leave room
               for NULL terminator. */
            retcode = NU_Recv(client_s, buffer, BUF_SIZE-1, 0);
            if (retcode < 0)
            {
                printf("Receive failed\r\n");
                status = STATUS_FAILURE;
            }
            else
            {
                /* Assure the input buffer is null terminated. */
                buffer[retcode] = 0;
            }


            /*************************************************************/
            /* Parse the command and resource identifier from the input. */
            /*************************************************************/

            /* Build up a format string for sscanf with our buffer sizes. */
            sprintf(fmt_str, "%%%ds %%%ds \r\n", FMT_SIZE, FMT_SIZE);

            /* Parse the input into the command and resource buffers. */
            sscanf(buffer, fmt_str, command, resource);

            /* Log the command string. */
            printf("Command string '%s'\r\n", command);

            /* Log the resource string. */
            printf("Resource string '%s'\r\n", resource);


            /* Check that command string is "GET" */
            if (strcmp(command, "GET") != 0)
            {
              printf("Command is not a GET.  ('%s')\r\n", command);
              status = STATUS_FAILURE;
            }


            /* Check for the resource identifier that we are interested in. Currently
               only tests for "/", and "/ip_addr", but the list could be expanded. */
            if (status == NU_SUCCESS)
            {
                /* Check for resource string is "\ip_addr" */
                if ((strcmp(resource, "/") != 0) && (strcmp(resource, "/ip_addr") != 0))
                {
                  printf("Invalid resource identifier.  ('%s')\r\n", resource);
                  status = STATUS_FAILURE;
                }
            }


            /* Start sending the response. */
            if (status == NU_SUCCESS)
            {
                /* Generate and send the response. */
                printf("Sending OK response...\r\n");

                /* Get the local IP address as a string. */
                status  = Get_Local_IP_Addr_String_By_Socket(client_s, local_addr);

                /* Get the foreign IP address as a string. */
                status |= Get_Foreign_IP_Addr_String_By_Socket(client_s, foreign_addr);

                /* Get the host information of the foreign host.
                   If the DNS lookup succeeds the foreign host name
                   will be available for output. */
                status2  = Get_Foreign_IP_Addr_By_Socket(client_s, &ipaddr[0]);
                status2 |= NU_Get_Host_By_Addr((CHAR *)&ipaddr[0], 4, NU_FAMILY_IP, &hentry);

                if (status == NU_SUCCESS)
                {
                    if (status2 == NU_SUCCESS)
                    {
                        /* DNS lookup succeeded, output local IP address,
                           foreign IP address, foreign hostname. */
                        sprintf(buffer, Positive_Response1, local_addr, foreign_addr, hentry.h_name);
                    }
                    else
                    {
                        /* DNS lookup failed, output local IP address,
                           foreign IP address. */
                        sprintf(buffer, Positive_Response2, local_addr, foreign_addr);
                    }

                    retcode = NU_Send(client_s, buffer, strlen(buffer), 0);
                    if (retcode <= 0)
                    {
                        printf("NU_Send() returns <= 0\r\n");
                        status = STATUS_FAILURE;
                    }
                }
            }
            else
            {
                /* Generate and send the 404 response. */
                printf("Sending File not found 404 response...\r\n");

                retcode = NU_Send(client_s, Negative_Response, strlen(Negative_Response), 0);
                if (retcode <= 0)
                {
                    printf("NU_Send() returns <= 0\r\n");
                }
                else
                {
                    strcpy(buffer, "<html><body><h1>RESOURCE NOT FOUND</h1></body></html>");
                    retcode = NU_Send(client_s, buffer, strlen(buffer), 0);
                    if (retcode <= 0)
                    {
                        printf("NU_Send() returns <= 0\r\n");
                    }
                }
                status = STATUS_FAILURE;
            }

            /* Deallocate the buffer memory. */
            NU_Deallocate_Memory(buffer);
        }
    }

    return (status);
}


/*************************************************************************
*
*   FUNCTION
*
*       Get_Local_IP_Addr_String_By_Socket
*
*   DESCRIPTION
*
*       This function gets the local IP address of the given socket
*       and converts it into an ASCII string in the given buffer.
*
*   CALLED BY
*
*       Perform_Request
*
*   CALLS
*
*       Get_Local_IP_Addr_By_Socket
*
*   INPUTS
*
*       socketd            Socket for which we want the local IP Address.
*       buf                Buffer to receive the IP address string.
*
*   OUTPUTS
*
*       status             NU_SUCCESS or STATUS_FAILURE
*
*************************************************************************/
static STATUS Get_Local_IP_Addr_String_By_Socket(INT socketd, CHAR *buf)
{
    STATUS status;
    UINT8  ipaddr[MAX_ADDRESS_SIZE];


    /* Get the local IP address for the socket. */
    status = Get_Local_IP_Addr_By_Socket(socketd, &ipaddr[0]);

    /* Convert the local IP address to an ASCII string. */
    if ( status == NU_SUCCESS)
    {
        status = NU_Inet_NTOP(NU_FAMILY_IP, &ipaddr[0], buf, 16);
    }

    return (status);
}


/*************************************************************************
*
*   FUNCTION
*
*       Get_Local_IP_Addr_By_Socket
*
*   DESCRIPTION
*
*       This function gets the local IP address of the given socket.
*
*   CALLED BY
*
*       Get_Local_IP_Addr_String_By_Socket
*
*   CALLS
*
*       None.
*
*   INPUTS
*
*       socketd            Socket for which we want the local IP Address.
*       addrp              Points to location to put the IP address.
*
*   OUTPUTS
*
*       status             NU_SUCCESS or STATUS_FAILURE
*
*************************************************************************/
static STATUS Get_Local_IP_Addr_By_Socket(INT socketd, UINT8 *addrp)
{
    STATUS  status;
    INT16   addrLength;
    struct  sockaddr_struct sock;

    addrLength = sizeof(struct sockaddr_struct);

    /* Get the client's address info. */
    status = NU_Get_Sock_Name(socketd, &sock, &addrLength);

    if (status == NU_SUCCESS)
    {
        memcpy(addrp, &sock.ip_num, MAX_ADDRESS_SIZE);
    }

    return (status);
}


/*************************************************************************
*
*   FUNCTION
*
*       Get_Foreign_IP_Addr_String_By_Socket
*
*   DESCRIPTION
*
*       This function gets the foreign IP address of the given socket
*       and converts it into an ASCII string in the given buffer.
*
*   CALLED BY
*
*       Perform_Request
*
*   CALLS
*
*       Get_Foreign_IP_Addr_By_Socket
*
*   INPUTS
*
*       socketd            Socket for which we want the foreign IP Address.
*       buf                Buffer to receive the IP address string.
*
*   OUTPUTS
*
*       status             NU_SUCCESS or STATUS_FAILURE
*
*************************************************************************/
static STATUS Get_Foreign_IP_Addr_String_By_Socket(INT socketd, CHAR *buf)
{
    STATUS status;
    UINT8  ipaddr[MAX_ADDRESS_SIZE];


    /* Get the foreign IP address for the socket. */
    status = Get_Foreign_IP_Addr_By_Socket(socketd, &ipaddr[0]);

    /* Convert the foreign ip addr to ASCII */
    if ( status == NU_SUCCESS)
    {
        status = NU_Inet_NTOP(NU_FAMILY_IP, &ipaddr[0], buf, 16);
    }

    return (status);
}


/*************************************************************************
*
*   FUNCTION
*
*       Get_Foreign_IP_Addr_By_Socket
*
*   DESCRIPTION
*
*       This function gets the foreign IP address of the given socket.
*
*   CALLED BY
*
*       Get_Foreign_IP_Addr_String_By_Socket
*
*   CALLS
*
*       None.
*
*   INPUTS
*
*       socketd            Socket for which we want the foreign IP Address.
*       addrp              Points to location to put the IP address.
*
*   OUTPUTS
*
*       status             NU_SUCCESS or STATUS_FAILURE
*
*************************************************************************/
static STATUS Get_Foreign_IP_Addr_By_Socket(INT socketd, UINT8 *addrp)
{
    STATUS  status;
    INT16   addrLength;
    struct  sockaddr_struct peer;


    addrLength = sizeof(struct sockaddr_struct);

    /* Get the client's address info. */
    status = NU_Get_Peer_Name(socketd, &peer, &addrLength);

    if (status == NU_SUCCESS)
    {
        memcpy(addrp, &peer.ip_num, MAX_ADDRESS_SIZE);
    }

    return (status);
}

/*************************************************************************
*
*   FUNCTION
*
*      Show_Active_IP_Address
*
*   DESCRIPTION
*
*      Shows IP Address of first UP interface
*
**************************************************************************/
VOID Show_Active_IP_Address(VOID)
{
    NU_IOCTL_OPTION ioctl_opt;
    STATUS      status = STATUS_FAILURE;
    
    /* Interface Name Index  */
    struct if_nameindex *NI;
    
    /* will use this to free Name Index */
    struct if_nameindex *NI_tmp;
    
    NI = NU_IF_NameIndex();    
    NI_tmp = NI;
    
    while (NI->if_name != NU_NULL) {
        if ((strcmp(NI->if_name, "loopback") == 0) ||
                (strcmp(NI->if_name, "net0") == 0))
        {
            /* local loop interface */
            /* skip to next interface */
            NI = (struct if_nameindex *)((CHAR *)NI +
                    sizeof(struct if_nameindex) + DEV_NAME_LENGTH);
            continue;                
        }

        /* Find the IP address attached to the network device. */
        ioctl_opt.s_optval = (UINT8*)NI->if_name;

        /* Call NU_Ioctl to get the IP address. */
        status = NU_Ioctl(SIOCGIFADDR, &ioctl_opt, sizeof(ioctl_opt));

        /* Check if we got the IP */
        if (status == NU_SUCCESS)
        {
            /* Got an UP interface */
            printf("Open the following Nucleus node address in your web browser:\r\n");
            /* Print IP Address */
            printf("    http://%d.%d.%d.%d:8080/\r\n",
                    ioctl_opt.s_ret.s_ipaddr[0],
                    ioctl_opt.s_ret.s_ipaddr[1],
                    ioctl_opt.s_ret.s_ipaddr[2],
                    ioctl_opt.s_ret.s_ipaddr[3]);
            break;
            
        }
        
        /* next interface */
        NI = (struct if_nameindex *)((CHAR *)NI +
                sizeof(struct if_nameindex) + DEV_NAME_LENGTH);
        
    }
    
    /* Free name index */
    NU_IF_FreeNameIndex(NI_tmp);
    
    /* No Interface Initialized */
    if (status != NU_SUCCESS) 
    {
        printf("\r\nNo interface is initialized\r\n");
    }

} /* Show_Active_IP_Address */
