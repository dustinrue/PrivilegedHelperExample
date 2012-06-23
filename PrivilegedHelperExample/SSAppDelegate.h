//
//  SSAppDelegate.h
//  PrivilegedHelperExample
//
//  Created by Steven Streeting on 04/03/2012.
//

#import <Cocoa/Cocoa.h>

@interface SSAppDelegate : NSObject <NSApplicationDelegate>

@property (assign) IBOutlet NSWindow *window;

- (IBAction)installSystemTool:(id)sender;

@end
