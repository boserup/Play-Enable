#import <UIKit/UIKit.h>
#import "substrate.h"

/*
	Hook in TDXJailbrokenHandler to disarm Jailbreak check, that prevents streams from playing
*/

%hook TDXJailbrokenHandler
	
	// Eat fire, k?
	+ (BOOL) isJailbroken {
		return NO;
	}

	+ (BOOL) doJailbrokenTest {
		return NO;
	}

	%end

/*
	Hook in XMPPStream to mask device
*/

%hook XMPPStream

	+ (NSString *) generateUUID {
		return @"Y2KPLZJB-PL0X-F00L-NEW8-GO2PLOX4MSTR";
	}

%end

// Disable crappy JB check from http://resources.infosecinstitute.com/ios-application-security-part-23-jailbreak-detection-evasion/

%hook NSFileManager

	- (BOOL)fileExistsAtPath:(NSString *)path {
		if([path isEqualToString:@"/Applications/Cydia.app"]) {
			return NO;
		} else if([path isEqualToString:@"/etc/apt/"]) {
			return NO;
		} else if([path isEqualToString:@"/private/var/lib/apt/"]) {
			return NO;
		} else if([path isEqualToString:@"/bin/bash"]) {
			return NO;
		} else if([path isEqualToString:@"Celestial"]) {
			return NO;
		} else if([path isEqualToString:@"/System/Library/PrivateFrameworks/Celestial.framework"]) {
			return NO;
		} else if([path isEqualToString:@"/System/Library/Frameworks/Celestial.framework"]) {
			return NO;
		} else if([path isEqualToString:@"/AppleInternal/Library/Frameworks/Celestial.framework"]) {
			return NO;
		} else {
			return %orig;
		}
	}

%end