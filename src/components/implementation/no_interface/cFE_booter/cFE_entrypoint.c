#include <string.h>

#include "cFE_util.h"
#include "gen/cfe_psp.h"
#include "gen/common_types.h"
#include "gen/osapi.h"

// This is based on an old build technique, so we can ignore this warning.
// But I'm leaving it in, just in case we ever switch to cmake
/*
 * cfe_platform_cfg.h needed for CFE_ES_NONVOL_STARTUP_FILE, CFE_CPU_ID/CPU_NAME/SPACECRAFT_ID
 *
 *  - this should NOT be included here -
 *
 * it is only for compatibility with the old makefiles.  Including this makes the PSP build
 * ONLY compatible with a CFE build using this exact same CFE platform config.
 */

#include "gen/cfe_platform_cfg.h"

extern void CFE_ES_Main(uint32 StartType, uint32 StartSubtype, uint32 ModeId, const char *StartFilePath );
extern void CFE_TIME_Local1HzISR(void);

#define CFE_ES_MAIN_FUNCTION     CFE_ES_Main
#define CFE_TIME_1HZ_FUNCTION    CFE_TIME_Local1HzISR

/*
 * The classic build does not support static modules,
 * so stub the ModuleInit() function out right here
 */
void CFE_PSP_ModuleInit(void)
{
}

// If RUN_TESTING_CODE is defined, testing code will be run
// #define RUN_TESTING_CODE

// "Magic" constants
#define CFE_PSP_CPU_NAME_LENGTH  32
#define CFE_PSP_RESET_NAME_LENGTH 10

/*
* Structure for the Command line parameters
* Stolen from the Linux psp_start function...
*/
struct CFE_PSP_CommandData_t {
   char     ResetType[CFE_PSP_RESET_NAME_LENGTH];   /* Reset type can be "PO" for Power on or "PR" for Processor Reset */

   uint32   SubType;         /* Reset Sub Type ( 1 - 5 )  */

   char     CpuName[CFE_PSP_CPU_NAME_LENGTH];     /* CPU Name */

   uint32   CpuId;            /* CPU ID */

   uint32   SpacecraftId;     /* Spacecraft ID */
};

void command_line_set_defaults(struct CFE_PSP_CommandData_t* args) {
    strncpy(args->ResetType, "PO", 2);
    args->SubType = 1;
    args->CpuId = 1;
    args->SpacecraftId = CFE_SPACECRAFT_ID;
}

void cos_init(void) {
    struct CFE_PSP_CommandData_t args;

    command_line_set_defaults(&args);

    /*
    ** Set the reset type
    */
    uint32 reset_type;
    if (strncmp("PR", args.ResetType, 2 ) == 0)
    {
        reset_type = CFE_PSP_RST_TYPE_PROCESSOR;
        OS_printf("CFE_PSP: Starting the cFE with a PROCESSOR reset.\n");
    }
    else
    {
        reset_type = CFE_PSP_RST_TYPE_POWERON;
        OS_printf("CFE_PSP: Starting the cFE with a POWER ON reset.\n");
    }

    OS_printf("CFE_PSP: Initializing the OS API...\n");
    /*
    ** Initialize the OS API
    */
    OS_API_Init();
    OS_printf("CFE_PSP: The the OS API was successfully initialized!\n");

    OS_printf("CFE_PSP: Doing PSP setup...\n");
    /*
    ** Initialize the statically linked modules (if any)
    ** This is only applicable to CMake build - classic build
    ** does not have the logic to selectively include/exclude modules
    **
    ** This is useless until we support cmake
    */
    CFE_PSP_ModuleInit();

    /*
    ** Initialize the reserved memory
    */
    CFE_PSP_InitProcessorReservedMemory(reset_type);

    OS_printf("CFE_PSP: PSP setup successful!\n");


    #ifdef RUN_TESTING_CODE
    // Testing code goes here
    OS_printf("CFE_PSP: Running testing code...\n");
    
    OS_printf("CFE_PSP: Running testing code completed\n");
    #else

    OS_printf("CFE_PSP: Starting the cFE proper...\n");
    /*
    ** Call cFE entry point.
    */
    CFE_ES_MAIN_FUNCTION(reset_type, args.SubType, 1, CFE_ES_NONVOL_STARTUP_FILE);

    OS_printf("CFE_PSP: cFE started, main thread sleeping\n");
    /*
    ** Let the main thread sleep.
    **
    ** OS_IdleLoop() will wait forever and return if
    ** someone calls OS_ApplicationShutdown(TRUE)
    */
    OS_IdleLoop();
    #endif

    PANIC("Application was shutdown!");
}