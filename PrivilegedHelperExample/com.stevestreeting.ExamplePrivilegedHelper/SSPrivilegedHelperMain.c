#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

#include <CoreServices/CoreServices.h>

#include "SSPrivilegedHelperCommon.h"
#include "BetterAuthorizationSampleLib.h"

/////////////////////////////////////////////////////////////////
#pragma mark ***** Get Version Command


static OSStatus DoInstallTool(
                             AuthorizationRef			auth,
                             const void *                userData,
                             CFDictionaryRef				request,
                             CFMutableDictionaryRef      response,
                             aslclient                   asl,
                             aslmsg                      aslMsg
                             )
// Implements the kInstallCommandLineTool command.  Returns the version number of 
// the helper tool.
{	
	OSStatus					retval = noErr;
	
	// Pre-conditions
	
	assert(auth != NULL);
    // userData may be NULL
	assert(request != NULL);
	assert(response != NULL);
    // asl may be NULL
    // aslMsg may be NULL
    
    // Retrieve the source path
    CFStringRef srcPath = (CFStringRef)CFDictionaryGetValue(request, CFSTR(kInstallCommandLineToolSrcPath));
    CFStringRef toolName = (CFStringRef)CFDictionaryGetValue(request, CFSTR(kInstallCommandLineToolName));
    
    // Check the code signature on the tool so that no-one else can use this to install stuff
	// We want to be sure that the cert is ours, and signed by apple
    
    // Note, I'm well aware that someone could hack the kSigningCertCommonName
    // static string in the data section of this binary. However, that is not a flaw 
    // because the code signature of this binary would then be invalid and it would refuse
    // to be installed. Any potential hacker would have to replace all 3 binaries
    // (App, the install helper and the command line tool) to compromise it, at which 
    // point it's not our app anymore anyway, and it would have to be signed by their own cert.
    
    bool success = true;
    
    char* ourFilename = 0;
    const char* pFilename = CFStringGetCStringPtr(srcPath, kCFStringEncodingMacRoman);

    if (!pFilename)
    {
        unsigned long len = CFStringGetLength(srcPath) + 20;
        ourFilename = malloc(len);
        if (!CFStringGetCString(srcPath, ourFilename, len, kCFStringEncodingMacRoman))
        {
            free(ourFilename);
            retval = 3;
            success = false;
        }
        else
            pFilename = ourFilename;
    }
    
    if (pFilename)
    {
        // Base command minus cert name and file namem is 76 characters, 1 for NULL
        char* valCodeSignCmd = 0;
        // asprintf allocates & never overflows
        if (asprintf(&valCodeSignCmd, "codesign -v -R=\"certificate leaf[subject.CN] = \\\"%s\\\" and anchor apple generic\" \"%s\"", kSigningCertCommonName, pFilename) != -1)
        {
            if (system(valCodeSignCmd) == 0)
            {
                // Passed codesign validation
                // OK to copy now - overwrite if present
                OSStatus fsret = FSPathCopyObjectSync(pFilename, "/usr/local/bin", toolName, NULL, kFSFileOperationOverwrite);
                if (fsret != noErr)
                    success = false;
            }

            
            // Clean up
            free(valCodeSignCmd);
            
        }
        else
            success = false;
    

    }
    
    if (success)
        CFDictionaryAddValue(response, CFSTR(kInstallCommandLineToolResponse), kCFBooleanTrue);
    else
        CFDictionaryAddValue(response, CFSTR(kInstallCommandLineToolResponse), kCFBooleanFalse);
        
    if (ourFilename)
    {
        free(ourFilename);
        ourFilename = 0;
    }
    
    
	return retval;
}

/*
 IMPORTANT
 ---------
 This array must be exactly parallel to the kPrivilegedHelperCommandSet array 
 */
static const BASCommandProc kPrivilegedHelperCommandProcs[] = {
    DoInstallTool,
    NULL
};

int main(int argc, char **argv)
{
    // Go directly into BetterAuthorizationSampleLib code.
	
    // IMPORTANT
    // BASHelperToolMain doesn't clean up after itself, so once it returns 
    // we must quit.
    
	return BASHelperToolMain(kPrivilegedHelperCommandSet, kPrivilegedHelperCommandProcs);
}