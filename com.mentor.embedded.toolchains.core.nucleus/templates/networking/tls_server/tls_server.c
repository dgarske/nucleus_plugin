/* Include files */
#include "nucleus.h"
#include "networking/nu_networking.h"

/* SSL Lite */
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

/* Defines */
#define  PORT_NUM              443          /* Port number for server. */
#define  BUF_SIZE              1024         /* Size of input buffer. */
#define  STATUS_FAILURE        -1           /* The operation failed. */

/* Macros */
#define TASK_STACK_SIZE        4096
#define TASK_PRIORITY          31
#define TASK_TIMESLICE         0


/* Internal globals */
static  NU_TASK Tls_Server_CB;


/* Function prototypes */
static  VOID   Tls_Server_Task(UNSIGNED argc, VOID *argv);
static  VOID   Show_Active_IP_Address(VOID);


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
        status = NU_Create_Task(&Tls_Server_CB, "TlsServer", Tls_Server_Task, 0, NU_NULL, pointer,
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
*       Tls_Server_Task
*
*   DESCRIPTION
*
*       Create TLS Server and wait for connections. Echo any incomming data.
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
static VOID Tls_Server_Task(UNSIGNED argc, VOID *argv)
{
    STATUS              status;
    INT                 socketd, newsock;    /* Socket descriptors */
    struct addr_struct  servaddr;            /* Server address structure */
    struct addr_struct  client_addr;
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    CHAR* buffer[BUF_SIZE];

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
            servaddr.name       = "TLSServer";

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
                            /* Create wolfSSL context */
                            ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method());
                            if (ctx) {
                                /* Set verify none */
                                wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);

                                /* TODO: Use this to load certificate to verify TLS session */
                                //void CYASSL_load_buffer(SSL_CTX* ctx, const char** fname, int type,int size)

                                /* Create new SSL object */
                                ssl = wolfSSL_new(ctx);
                                if (ssl) {
                                    wolfSSL_set_fd(ssl, newsock);
                
                                    status = wolfSSL_accept(ssl);
                                    if (status == SSL_SUCCESS) 
                                    {
                                        printf("New Connection from %d.%d.%d.%d\r\n",
												client_addr.id.is_ip_addrs[0],
												client_addr.id.is_ip_addrs[1],
												client_addr.id.is_ip_addrs[2],
												client_addr.id.is_ip_addrs[3]);

                                        /* Read data */
                                        status = wolfSSL_read(ssl, buffer, sizeof(buffer));
                                        if (status > 0) {
                                            /* Echo data */
                                            wolfSSL_write(ssl, buffer, status);
                                        }
                                    }
                                    wolfSSL_free(ssl);
                                }
                                wolfSSL_CTX_free(ctx);
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
            printf("TLS Server Running at %d.%d.%d.%d, port %d\r\n",
                    ioctl_opt.s_ret.s_ipaddr[0],
                    ioctl_opt.s_ret.s_ipaddr[1],
                    ioctl_opt.s_ret.s_ipaddr[2],
                    ioctl_opt.s_ret.s_ipaddr[3],
                    PORT_NUM);
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
