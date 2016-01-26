/* Include files */
#include "nucleus.h"
#include "networking/nu_networking.h"

/* SSL Lite */
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

/* Defines */
#define PORT_NUM              443          /* Port number for client. */
#define HOST_STR              "localhost"
#define BUF_SIZE              1024         /* Size of input buffer. */
#define FMT_SIZE              24           /* Size of format string. */
#define STATUS_FAILURE        -1           /* The operation failed. */

/* Macros */
#define TASK_STACK_SIZE        4096
#define TASK_PRIORITY          31
#define TASK_TIMESLICE         0

static const CHAR* kTestString = "Hello World";


/* Internal globals */
static  NU_TASK Tls_Client_Sample_CB;


/* Function prototypes */
static  VOID   Tls_Client_Sample(UNSIGNED argc, VOID *argv);


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
        status = NU_Create_Task(&Tls_Client_Sample_CB, "TLSClient", Tls_Client_Sample, 0, NU_NULL, pointer,
                                TASK_STACK_SIZE, TASK_PRIORITY, TASK_TIMESLICE,
                                NU_PREEMPT, NU_START);

        /* On error, deallocate memory. */
        if(status != NU_SUCCESS)
        {
            (VOID)NU_Deallocate_Memory(pointer);
        }
    }
}

static VOID GetAddressInfo(void)
{
    STATUS      status = NU_SUCCESS;
    struct      addr_struct server;
    CHAR        ip_address[MAX_ADDRESS_SIZE] = {0};
    NU_HOSTENT  *hentry = NU_NULL;
    INT         socket, new_socket;
#if (HTTP_INCLUDE_CYASSL == NU_TRUE)
    UINT8       is_secured = NU_FALSE;
#endif /* (HTTP_INCLUDE_CYASSL == NU_TRUE) */
    CHAR        rmtsvr_name[] = "rmtsvr";

    /* Check if the port is specified by the user */
    if (port != 0)
    {
        /* Assign specified port number. */
        server.port = port;
    }

#if (HTTP_INCLUDE_CYASSL == NU_TRUE)
    /* RFC-2616
     *  Comparisons of scheme names MUST be case-insensitive */
    if ((session->ssl_struct) &&
        (scheme_length == (sizeof(HTTP_SECURE) - 1)) &&
        (0 == UTIL_Strnicmp(scheme, HTTP_SECURE, scheme_length)))
    {
        /* This is a secured connection. */
        is_secured = NU_TRUE;

        /* Check if the port number is not specified by the user. */
        if (port == 0)
        {
            /* Assign default port for secure connection, will be changed
             * latter if specified in URI.  */
            server.port = HTTP_SSL_PORT;
        }
    }
    else
#endif /* (HTTP_INCLUDE_CYASSL == NU_TRUE) */
    if ((scheme_length == (sizeof(HTTP_UNSECURE) - 1)) &&
        (0 == UTIL_Strnicmp(scheme, HTTP_UNSECURE, scheme_length)))
    {
        /* Check if the port number is not specified by the user. */
        if (port == 0)
        {
            /* Assign default port for HTTP connection, will be changed
             * latter if specified in URI.  */
            server.port = HTTP_SVR_PORT;
        }
    }

    /* Unknown scheme is given. */
    else
    {
        /* Return error to caller. */
        status = HTTP_INVALID_URI;
    }

    /* If connection type was successfully identified. */
    if (status == NU_SUCCESS)
    {
        /* Assign server name. */
        server.name = rmtsvr_name;

        /* Check if the user has provided a host name. */
        if (uri_flag & UTIL_URI_HOST_IS_NAME)
        {
            /* If IPv6 is enabled, default to IPv6.  If the host does not have
             * an IPv6 address, an IPv4-mapped IPv6 address will be returned that
             * can be used as an IPv6 address.
             */
#if (INCLUDE_IPV6 == NU_TRUE)
            server.family = NU_FAMILY_IP6;
#else
            server.family = NU_FAMILY_IP;
#endif /* (INCLUDE_IPV6 == NU_TRUE) */
            /* Try to resolve given host name. */
            hentry = NU_Get_IP_Node_By_Name(host, server.family, DNS_V4MAPPED, &status);

            if (hentry)
            {
                /* Copy the hentry data into the server structure */
                memcpy(&server.id.is_ip_addrs, *hentry->h_addr_list,
                       hentry->h_length);
                server.family = hentry->h_addrtype;

                /* Free the memory associated with the host entry returned */
                NU_Free_Host_Entry(hentry);
            }

            /* Host name could not be resolved. */
            else
            {
                /* Return error to caller */
                status = HTTP_NO_IP_NODE;
            }
        }

        else
        {
#if (INCLUDE_IPV6 == NU_TRUE)
            /* Check if given address is an IPv6 address. */
            if (uri_flag & UTIL_URI_HOST_IS_IPV6)
            {
                /* This is an IPv6 address. */
                server.family = NU_FAMILY_IP6;

                /* Convert this address to an IPv6 address. */
                status = NU_Inet_PTON(NU_FAMILY_IP6, host, ip_address);
            }
            else
#endif /* (INCLUDE_IPV6 == NU_TRUE) */
#if (INCLUDE_IPV4 == NU_TRUE)
            /* Check if given address is an IPv4 address. */
            if (uri_flag & UTIL_URI_HOST_IS_IPV4)
            {
                /* This is an IPv4 address. */
                server.family = NU_FAMILY_IP;

                /* Convert this address to an IPv4 address. */
                status = NU_Inet_PTON(NU_FAMILY_IP, host, ip_address);
            }
#endif /*  (INCLUDE_IPV4 == NU_TRUE) */

            /* Check if an IP address was successfully parsed. */
            if (status == NU_SUCCESS)
            {
                /* Copy given address to our server address structure. */
                memcpy(&server.id.is_ip_addrs, ip_address, MAX_ADDRESS_SIZE);
            }
        }
    }

    if (status == NU_SUCCESS)
    {
        /* Initialize a socket identifier. */
        socket = NU_Socket(server.family, NU_TYPE_STREAM, 0);

        /* Check if socket was successfully created. */
        if (socket < 0)
        {
            /* Return error to caller. */
            status = socket;
        }
    }

    if (status == NU_SUCCESS)
    {
        /* Connect to host. */
        new_socket = NU_Connect(socket, &server, (INT16)sizeof(server));
}


/*************************************************************************
*
*   FUNCTION
*
*       Tls_Client_Sample
*
*   DESCRIPTION
*
*       Setup TLS connect and send hello world.
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
static VOID Tls_Client_Sample(UNSIGNED argc, VOID *argv)
{
    STATUS              status;
    INT                 socket, newsock;    /* Socket descriptors */
    struct addr_struct  servaddr;            /* Server address structure */
    struct addr_struct  client_addr;
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    CHAR* respBuf[100];

    /* Reference unused parameters to avoid toolset warnings. */
    UNUSED_PARAMETER(argc);
    UNUSED_PARAMETER(argv);

    /* Setup the WolfSSL library */
    wolfSSL_Init();

    /* Wait until the NET stack is initialized. */
    status = NETBOOT_Wait_For_Network_Up(NU_SUSPEND);
    if (status == NU_SUCCESS)
    {
        /* Open a connection via the socket interface. */
        socket = NU_Socket(NU_FAMILY_IP, NU_TYPE_STREAM, 0);
        if (socket >= 0)
        {
            /* Lookup host */

            /* Connect to host. */
            newsock = NU_Connect(socket, &server, (INT16)sizeof(server));
            if (newsock == socket) 
            {
                /* Create wolfSSL context */
                ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
                if (ctx) {
                    /* Set verify none */
                    wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);

                    /* TODO: Use this to load certificate to verify TLS session */
                    //void CYASSL_load_buffer(SSL_CTX* ctx, const char** fname, int type,int size)

                    /* Create new SSL object */
                    ssl = wolfSSL_new(ctx);
                    if (ssl) {
                        wolfSSL_set_fd(ssl, socket);
                
                        status = wolfSSL_connect(client->tls.ssl);
                        if (status == SSL_SUCCESS) {
                    
                            /* Send test */
                            wolfSSL_write(ssl, kTestString, strlen(kTestString));

                            /* Read response */
                            wolfSSL_read(ssl, respBuf, sizeof(respBuf));
                            
                            /* Verify echo response */
                            if (memcmp(kTestString, respBuf, strlen(kTestString)) == 0) {
                                printf("TLS Client: Server Response Validated\n");
                            }
                                
                            /* Disconnect */

                        }
                        wolfSSL_free(ssl);
                    }
                    wolfSSL_CTX_free(ctx);
                }
            }

            /* Close socket. */
            NU_Close_Socket(socket);
        }
    }
    else
    {
        printf("NETBOOT_Wait_For_Network_Up() failed.\r\n");
    }
}
