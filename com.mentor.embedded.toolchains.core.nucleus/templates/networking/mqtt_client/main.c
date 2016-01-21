/* Include files */
#include "nucleus.h"
#include "networking/nu_networking.h"
#include "mqttclient.h"

/* Macros */
#define TASK_STACK_SIZE        4096
#define TASK_PRIORITY          31
#define TASK_TIMESLICE         0

/* Internal globals */
static  NU_TASK Mqtt_Client_CB;


/* Function prototypes */
static  VOID   Mqtt_Client_Task(UNSIGNED argc, VOID *argv);

/* Argument Parsing */
typedef struct func_args {
    int    argc;
    char** argv;
    int    return_code;
} func_args;


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
        /* Create the Mqtt Client task.  */
        status = NU_Create_Task(&Mqtt_Client_CB, "MqttClient", Mqtt_Client_Task, 0, NU_NULL, pointer,
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
*       Mqtt_Client_Task
*
*   DESCRIPTION
*
*       asdf
*
*   CALLED BY
*
*       Task Scheduler
*
*   CALLS
*
*       NETBOOT_Wait_For_Network_Up
*       mqttclient_test
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
static VOID Mqtt_Client_Task(UNSIGNED argc, VOID *argv)
{
    STATUS              status;

    /* Wait until the NET stack is initialized. */
    status = NETBOOT_Wait_For_Network_Up(NU_SUSPEND);
    if (status == NU_SUCCESS)
    {
        func_args args;
        args.argc = argc;
        args.argv = (char**)argv;
        mqttclient_test(&args);
    }
    else
    {
        printf("NETBOOT_Wait_For_Network_Up() failed.\r\n");
    }
}
