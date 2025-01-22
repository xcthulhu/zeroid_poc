//
//  PassportNFCScanner.m
//  NfcManager
//
//  Created by Matthew Doty on 12/23/24.
//

#import <Foundation/Foundation.h>
#import "React/RCTBridgeModule.h"
@interface RCT_EXTERN_MODULE(PassportNFCScanner, NSObject)
RCT_EXTERN_METHOD(scan:
                  (NSString *) mrzKey
                  dataGroups: (NSArray *) dataGroups
                  skipSecureElements: (BOOL) skipSecureElements
                  skipCA: (BOOL) skipCA
                  skipPACE: (BOOL) skipPACE
                  resolver: (RCTPromiseResolveBlock) resolve
                  rejecter: (RCTPromiseRejectBlock) reject
                  )
@end

