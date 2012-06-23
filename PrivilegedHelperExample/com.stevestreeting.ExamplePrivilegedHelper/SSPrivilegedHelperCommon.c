#include <stdio.h>
#include "SSPrivilegedHelperCommon.h"

const BASCommandSpec kPrivilegedHelperCommandSet[] = {
    {	kInstallCommandLineToolCommand,         // commandName
        kInstallCommandLineToolRightName,       // rightName
        "default",                              // rightDefaultRule    -- by default, you have to have admin credentials (see the "default" rule in the authorization policy database, currently "/etc/authorization")
        "AuthInstallCommandLineToolPrompt",				// rightDescriptionKey -- key for custom prompt in "Localizable.strings
        NULL                                    // userData
	},
    
    {	NULL,                                   // the array is null terminated
        NULL, 
        NULL, 
        NULL,
        NULL
	}
};


