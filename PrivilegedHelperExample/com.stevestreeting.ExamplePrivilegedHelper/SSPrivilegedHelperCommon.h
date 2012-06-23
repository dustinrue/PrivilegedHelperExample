#ifndef SSPrivilegedHelperCommon_h
#define SSPrivilegedHelperCommon_h


#include "BetterAuthorizationSampleLib.h"


#define kPRIVILEGED_HELPER_LABEL @"com.stevestreeting.ExamplePrivilegedHelper"


#define kInstallCommandLineToolCommand      "InstallTool"
#define kInstallCommandLineToolSrcPath      "srcPath"   // Parameter, CFString
#define kInstallCommandLineToolName         "toolName"  // Parameter, CFString
#define kInstallCommandLineToolResponse		"Success"   // Response, CFNumber
#define	kInstallCommandLineToolRightName	"com.stevestreeting.PrivilegedHelperExample.InstallTool"

// CHANGE THIS LINE to use your codesign cert
#define kSigningCertCommonName "3rd Party Mac Developer Application: Your Company Here"

// The kPrivilegedHelperCommandSet is used by both the app and the tool to communicate the set of 
// supported commands to the BetterAuthorizationSampleLib module.

extern const BASCommandSpec kPrivilegedHelperCommandSet[];


#endif
