//
//  SSAppDelegate.m
//  PrivilegedHelperExample
//
//  Created by Steven Streeting on 04/03/2012.
//

#import "SSAppDelegate.h"
#import "SSPrivilegedHelperCommon.h"
#import <ServiceManagement/ServiceManagement.h>
#import <Security/Security.h>
#import <Security/Authorization.h>
#import <Security/Security.h>
#import <Security/SecCertificate.h>
#import <Security/SecCode.h>
#import <Security/SecStaticCode.h>
#import <Security/SecCodeHost.h>
#import <Security/SecRequirement.h>

@implementation SSAppDelegate

@synthesize window = _window;

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification
{
    // Insert code here to initialize your application
}

// Code below adapted from the SMJobBless example
BOOL blessHelperWithLabel(NSString* label, NSError** error)
{
	BOOL result = NO;
    
	AuthorizationItem authItem		= { kSMRightBlessPrivilegedHelper, 0, NULL, 0 };
	AuthorizationRights authRights	= { 1, &authItem };
	AuthorizationFlags flags		=	kAuthorizationFlagDefaults				| 
    kAuthorizationFlagInteractionAllowed	|
    kAuthorizationFlagPreAuthorize			|
    kAuthorizationFlagExtendRights;
    
	AuthorizationRef authRef = NULL;
	
	/* Obtain the right to install privileged helper tools (kSMRightBlessPrivilegedHelper). */
	OSStatus status = AuthorizationCreate(&authRights, kAuthorizationEmptyEnvironment, flags, &authRef);
	if (status != errAuthorizationSuccess) 
    {
		NSLog(@"Failed to create AuthorizationRef, return code %ld", (long)status);
	} else 
    {
		/* This does all the work of verifying the helper tool against the application
		 * and vice-versa. Once verification has passed, the embedded launchd.plist
		 * is extracted and placed in /Library/LaunchDaemons and then loaded. The
		 * executable is placed in /Library/PrivilegedHelperTools.
		 */
		result = SMJobBless(kSMDomainSystemLaunchd, (CFStringRef)label, authRef, (CFErrorRef *)error);
	}
    
    AuthorizationFree(authRef, kAuthorizationFlagDefaults);
    
	
	return result;
}

BOOL installPrivilegedHelperTool()
{
    // This uses SMJobBless to install a tool in /Library/PrivilegedHelperTools which is
    // run by launchd instead of us, with elevated privileges. This can then be used to do 
    // things like install utilities in /usr/local/bin
    
    // We do this rather than AuthorizationExecuteWithPrivileges because that's deprecated in 10.7
    // The SMJobBless approach is more secure because both ends are validated via code signing
    // which is enforced by launchd - ie only tools signed with the right cert can be installed, and
    // only apps signed with the right cert can install it. 
    
    // Although the launchd approach is primarily associated with daemons, it can be used for one-off
    // tools too. We effectively invoke the privileged helper by talking to it over a private Unix socket
    // (since we can't launch it directly). We still need to be careful about that invocation because
    // the SMJobBless structure doesn't validate that the caller at runtime is the right application.
    
    NSError* error = nil;	
    NSDictionary*	installedHelperJobData 	= (NSDictionary*)SMJobCopyDictionary(kSMDomainSystemLaunchd, (CFStringRef)kPRIVILEGED_HELPER_LABEL);
    BOOL needToInstall = YES;
    
    if (installedHelperJobData)
    {
        NSLog( @"helperJobData: %@", installedHelperJobData );
        
        NSString* installedPath = [[installedHelperJobData objectForKey:@"ProgramArguments"] objectAtIndex:0];
        NSURL* installedPathURL = [NSURL fileURLWithPath:installedPath];
        
        NSDictionary* installedInfoPlist = (NSDictionary*)CFBundleCopyInfoDictionaryForURL( (CFURLRef)installedPathURL );
        NSString* installedBundleVersion = [installedInfoPlist objectForKey:@"CFBundleVersion"];
        NSInteger installedVersion = [installedBundleVersion integerValue];
        
        NSLog( @"installedVersion: %ld", (long)installedVersion );
        
        NSBundle* appBundle	= [NSBundle mainBundle];
        NSURL* appBundleURL	= [appBundle bundleURL];
        
        NSLog( @"appBundleURL: %@", appBundleURL );
        
        NSURL* currentHelperToolURL	= [appBundleURL URLByAppendingPathComponent:[NSString stringWithFormat:@"Contents/Library/LaunchServices/%@", kPRIVILEGED_HELPER_LABEL]];
        NSLog( @"currentHelperToolURL: %@", currentHelperToolURL );
        
        NSDictionary* currentInfoPlist = (NSDictionary*)CFBundleCopyInfoDictionaryForURL( (CFURLRef)currentHelperToolURL );
        NSString* currentBundleVersion = [currentInfoPlist objectForKey:@"CFBundleVersion"];
        NSInteger currentVersion = [currentBundleVersion integerValue];
        
        NSLog( @"currentVersion: %ld", (long)currentVersion );
        
      	if ( currentVersion == installedVersion )
        {
            SecRequirementRef requirement;
            OSStatus stErr;
            
            stErr = SecRequirementCreateWithString((CFStringRef)[NSString stringWithFormat:@"identifier %@ and certificate leaf[subject.CN] = \"%@\"", kPRIVILEGED_HELPER_LABEL, @kSigningCertCommonName], kSecCSDefaultFlags, &requirement );
            
            if ( stErr == noErr )
            {                
                SecStaticCodeRef staticCodeRef;
                
                stErr = SecStaticCodeCreateWithPath( (CFURLRef)installedPathURL, kSecCSDefaultFlags, &staticCodeRef ); 
                
                if ( stErr == noErr )
                {
                    stErr = SecStaticCodeCheckValidity( staticCodeRef, kSecCSDefaultFlags, requirement );
                    
                    needToInstall = NO;
                }
            }
        }               
	}
    
    
    if (needToInstall)
    {
        if (!blessHelperWithLabel(kPRIVILEGED_HELPER_LABEL, &error))
        {
            NSLog(@"Failed to install privileged helper: %@", [error description]);
            NSRunAlertPanel(@"Error", 
                            [NSString stringWithFormat:@"Failed to install privileged helper: %@", [error description]], 
                            @"OK", nil, nil);
            return NO;
        }
        else
            NSLog(@"Privileged helper installed.");
    }
    else 
		NSLog(@"Privileged helper already available, not installing.");
    
    return YES;
    
}

BOOL privilegedHelperActionInstallSystemTool(NSString* srcPath, AuthorizationRef auth)
{
    OSStatus        err;
    NSString *      bundleID;
    NSDictionary *  request;
    CFDictionaryRef response;
    
    response = NULL;
    
    request = [NSDictionary dictionaryWithObjectsAndKeys:
               @kInstallCommandLineToolCommand, @kBASCommandKey, 
               srcPath, @kInstallCommandLineToolSrcPath, 
               [srcPath lastPathComponent], @kInstallCommandLineToolName, nil];
    assert(request != NULL);
    
    bundleID = kPRIVILEGED_HELPER_LABEL;
    
    // Execute it.
    
	err = BASExecuteRequestInHelperTool(
                                        auth, 
                                        kPrivilegedHelperCommandSet, 
                                        (CFStringRef) bundleID, 
                                        (CFDictionaryRef) request, 
                                        &response
                                        );
    
    // If the above went OK, it means that the IPC to the helper tool worked.  We 
    // now have to check the response dictionary to see if the command's execution 
    // within the helper tool was successful.   
    
    if (err == noErr) 
    {
        err = BASGetErrorFromResponse(response);
        
        NSString* respStr =  [(NSDictionary *)response objectForKey:@kInstallCommandLineToolResponse];
        NSLog(@"privilegedHelperActionInstallSystemTool response: %@", respStr);
        
        
    }
    
    if (response) 
        CFRelease(response);
    
    return (err == noErr);
}


BOOL doInstallSystemTool()
{
    if (!installPrivilegedHelperTool())
        return NO;
    
    AuthorizationRef auth;
    if (AuthorizationCreate(NULL, NULL, kAuthorizationFlagDefaults, &auth))
        return NO;
    	
    BASSetDefaultRules(auth, 
                       kPrivilegedHelperCommandSet, 
                       CFBundleGetIdentifier(CFBundleGetMainBundle()), 
                       NULL); // No separate strings file, use Localizable.strings
    
    NSString* toolPath = [[NSBundle mainBundle] pathForResource:@"ssexampletool" ofType:@""];
    BOOL ret = NO;
    
    if (toolPath)
        ret = privilegedHelperActionInstallSystemTool(toolPath, auth);
    
    AuthorizationFree(auth, kAuthorizationFlagDefaults);
    
    return ret;
    
}


- (IBAction)installSystemTool:(id)sender 
{
    if (doInstallSystemTool())
        NSRunAlertPanel(@"Success!", @"System tool installed successfully!\n\nYou can call 'ssexampletool' on the command line now", @"OK", nil, nil);
    else
        NSRunAlertPanel(@"Failure :(", @"System tool not installed", @"OK", nil, nil);

}
@end
