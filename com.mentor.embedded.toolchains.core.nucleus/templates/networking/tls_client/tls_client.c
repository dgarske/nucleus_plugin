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
#define STATUS_FAILURE        -1           /* The operation failed. */

/* Macros */
#define TASK_STACK_SIZE        4096
#define TASK_PRIORITY          31
#define TASK_TIMESLICE         0

static const CHAR* kTestString = "TLS Test Message";


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

static STATUS GetAddressInfo(const CHAR* host, UINT16 port, struct addr_struct* addr)
{
    STATUS status;
    NU_HOSTENT *hentry;
    INT family;
    CHAR test_ip[MAX_ADDRESS_SIZE] = {0};

    XMEMSET(addr, 0, sizeof(struct addr_struct));

    /* Determine the IP address of the foreign server to which to
     * make the connection.
     */
#if (INCLUDE_IPV6 == NU_TRUE)
    /* Search for a ':' to determine if the address is IPv4 or IPv6. */
    if (XMEMCHR(ip, (int)':', MAX_ADDRESS_SIZE) != NU_NULL) {
        family = NU_FAMILY_IP6;
    }
    else
#endif
    {
#if (INCLUDE_IPV4 == NU_FALSE)
        /* An IPv6 address was not passed into the routine. */
        return -1;
#else
        family = NU_FAMILY_IP;
#endif
    }

    /* Convert the string to an array. */
    status = NU_Inet_PTON(family, (char*)host, test_ip);

    /* If the URI contains an IP address, copy it into the server structure. */
    if (status == NU_SUCCESS) {
        XMEMCPY(addr->id.is_ip_addrs, test_ip, MAX_ADDRESS_SIZE);
    }

    /* If the application did not pass in an IP address, resolve the host
     * name into a valid IP address.
     */
    else {
        /* If IPv6 is enabled, default to IPv6.  If the host does not have
         * an IPv6 address, an IPv4-mapped IPv6 address will be returned that
         * can be used as an IPv6 address.
         */
#if (INCLUDE_IPV6 == NU_TRUE)
        family = NU_FAMILY_IP6;
#else
        family = NU_FAMILY_IP;
#endif

        /* Try getting host info by name */
        hentry = NU_Get_IP_Node_By_Name((char*)host, family, DNS_V4MAPPED, &status);
        if (hentry) {
            /* Copy the hentry data into the server structure */
            XMEMCPY(addr->id.is_ip_addrs, *hentry->h_addr_list, hentry->h_length);
            family = hentry->h_addrtype;

            /* Free the memory associated with the host entry returned */
            NU_Free_Host_Entry(hentry);
        }

        /* If the host name could not be resolved, return an error. */
        else {
            return -1;
        }
    }

    /* Set the family field. */
    addr->family = family;

    /* Set the port field. */
    addr->port = port;

    return status;
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
    struct addr_struct  addr;           /* Address structure */
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;
    CHAR* buffer[BUF_SIZE];

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
            status = GetAddressInfo(HOST_STR, PORT_NUM, &addr);
            if (status == NU_SUCCESS)
            {
                /* Connect to host. */
                newsock = NU_Connect(socket, &addr, (INT16)sizeof(addr));
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
                
                            status = wolfSSL_connect(ssl);
                            if (status == SSL_SUCCESS) {
                    
                                /* Send test */
                                status = wolfSSL_write(ssl, kTestString, strlen(kTestString));
                                printf("TLS Client: Write %d\r\n", status);

                                /* Read response */
                                status = wolfSSL_read(ssl, buffer, sizeof(buffer));
                                printf("TLS Client: Read %d\r\n", status);

                                if (status == strlen(kTestString)) {
									/* Verify echo response */
									if (memcmp(kTestString, buffer, strlen(kTestString)) == 0) {
										printf("TLS Client: Server Response Validated\r\n");
									}
                                }
                            }
                            wolfSSL_free(ssl);
                        }
                        wolfSSL_CTX_free(ctx);
                    }
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
