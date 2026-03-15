//
//  main.m
//  optool
//  Copyright (c) 2014, Alex Zielenski
//  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions are met:
//
//  * Redistributions of source code must retain the above copyright notice, this
//  list of conditions and the following disclaimer.
//
//  * Redistributions in binary form must reproduce the above copyright notice,
//  this list of conditions and the following disclaimer in the documentation
//  and/or other materials provided with the distribution.
//
//  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
//  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
//  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
//  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
//  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
//  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
//  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
//  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


#import <Foundation/Foundation.h>
#import <getopt.h>
#import "defines.h"
#import "headers.h"
#import "operations.h"

typedef NS_ENUM(int, OPCommand) {
    OPCommandNone = 0,
    OPCommandInstall,
    OPCommandUninstall,
    OPCommandStrip,
    OPCommandRestore,
    OPCommandAslr,
    OPCommandUnrestrict,
    OPCommandRename,
};

static void printUsage(void) {
    LOG("optool v1.0\n");
    LOG("USAGE:");
    LOG("  optool install -t <target> -p <payload> [-c <command>] [-o <output>] [-b] [--resign]");
    LOG("    Inserts an LC_LOAD command into the target binary which points to the payload.");
    LOG("    This may render some executables unusable.\n");
    LOG("  optool uninstall -t <target> -p <payload> [-o <output>] [-b] [--resign]");
    LOG("    Removes any LC_LOAD commands which point to a given payload from the target binary.");
    LOG("    This may render some executables unusable.\n");
    LOG("  optool strip [-w] -t <target> [-o <output>] [-b] [--resign]");
    LOG("    Removes a code signature load command from the given binary.\n");
    LOG("  optool unrestrict [-w] -t <target> [-o <output>] [-b] [--resign]");
    LOG("    Removes a __restrict section from the given binary.");
    LOG("    The -w flag makes this a non-destructive operation which merely renames");
    LOG("    the __restrict section; otherwise, it is completely removed.\n");
    LOG("  optool restore -t <target>");
    LOG("    Restores any backup made on the target by this tool.\n");
    LOG("  optool aslr -t <target> [-o <output>] [-b] [--resign]");
    LOG("    Removes an ASLR flag from the macho header if it exists.\n");
    LOG("  optool rename -t <target> [<from>] <to> [-o <output>] [-b] [--resign]");
    LOG("    Renames a dylib reference in the binary. If <from> is omitted,");
    LOG("    renames the LC_ID_DYLIB.\n");
    LOG("OPTIONS:");
    LOG("  -t, --target <path>    Target executable to modify");
    LOG("  -p, --payload <path>   Path to dylib (for install/uninstall)");
    LOG("  -c, --command <type>   Load command type: load, weak, reexport, upward");
    LOG("  -o, --output <path>    Write output to a different path");
    LOG("  -b, --backup           Backup the executable before modifying");
    LOG("  -w, --weak             Soft strip/unrestrict (non-destructive)");
    LOG("      --resign           Re-sign the binary after modification");
    LOG("  -h, --help             Show this message");
    LOG("\n(C) 2014 Alexander S. Zielenski. Licensed under BSD");
}

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        if (argc < 2) {
            printUsage();
            return OPErrorInvalidArguments;
        }

        // Parse subcommand (first non-flag argument)
        const char *subcmd = argv[1];
        OPCommand cmd = OPCommandNone;

        if (strcmp(subcmd, "install") == 0 || strcmp(subcmd, "i") == 0)
            cmd = OPCommandInstall;
        else if (strcmp(subcmd, "uninstall") == 0 || strcmp(subcmd, "u") == 0)
            cmd = OPCommandUninstall;
        else if (strcmp(subcmd, "strip") == 0 || strcmp(subcmd, "s") == 0)
            cmd = OPCommandStrip;
        else if (strcmp(subcmd, "restore") == 0 || strcmp(subcmd, "r") == 0)
            cmd = OPCommandRestore;
        else if (strcmp(subcmd, "aslr") == 0 || strcmp(subcmd, "a") == 0)
            cmd = OPCommandAslr;
        else if (strcmp(subcmd, "unrestrict") == 0 || strcmp(subcmd, "c") == 0)
            cmd = OPCommandUnrestrict;
        else if (strcmp(subcmd, "rename") == 0)
            cmd = OPCommandRename;
        else if (strcmp(subcmd, "-h") == 0 || strcmp(subcmd, "--help") == 0) {
            printUsage();
            return OPErrorNone;
        } else {
            LOG("Unknown command: %s", subcmd);
            printUsage();
            return OPErrorInvalidArguments;
        }

        // Parse flags with getopt_long
        NSString *targetPath = nil;
        NSString *dylibPath = nil;
        NSString *outputPath = nil;
        NSString *commandType = nil;
        BOOL weakFlag = NO;
        BOOL resignFlag = NO;
        BOOL backupFlag = NO;

        // Collect non-option arguments for rename command
        NSMutableArray *renameArgs = [NSMutableArray array];

        static struct option longopts[] = {
            { "target",  required_argument, NULL, 't' },
            { "payload", required_argument, NULL, 'p' },
            { "command", required_argument, NULL, 'c' },
            { "output",  required_argument, NULL, 'o' },
            { "weak",    no_argument,       NULL, 'w' },
            { "backup",  no_argument,       NULL, 'b' },
            { "resign",  no_argument,       NULL, 'R' },
            { "help",    no_argument,       NULL, 'h' },
            { NULL,      0,                 NULL,  0  }
        };

        // Reset getopt and skip argv[0] (program) and argv[1] (subcommand)
        optind = 2;
        int ch;
        while ((ch = getopt_long(argc, (char * const *)argv, "t:p:c:o:wbh", longopts, NULL)) != -1) {
            switch (ch) {
                case 't': targetPath  = @(optarg); break;
                case 'p': dylibPath   = @(optarg); break;
                case 'c': commandType = @(optarg); break;
                case 'o': outputPath  = @(optarg); break;
                case 'w': weakFlag    = YES;        break;
                case 'b': backupFlag  = YES;        break;
                case 'R': resignFlag  = YES;        break;
                case 'h':
                    printUsage();
                    return OPErrorNone;
                default:
                    printUsage();
                    return OPErrorInvalidArguments;
            }
        }

        // Collect remaining non-option arguments (used by rename)
        for (int i = optind; i < argc; i++) {
            [renameArgs addObject:@(argv[i])];
        }

        // Validate required arguments
        if (!targetPath) {
            LOG("No target specified. Use -t <target>");
            return OPErrorInvalidArguments;
        }

        if ((cmd == OPCommandInstall || cmd == OPCommandUninstall) && !dylibPath) {
            LOG("No payload specified. Use -p <payload>");
            return OPErrorInvalidArguments;
        }

        if (cmd == OPCommandRename && renameArgs.count == 0) {
            LOG("Rename requires at least one argument: [<from>] <to>");
            return OPErrorInvalidArguments;
        }

        if (cmd == OPCommandRename && renameArgs.count > 2) {
            LOG("Rename takes at most two arguments: [<from>] <to>");
            return OPErrorInvalidArguments;
        }

        // Resolve paths
        NSBundle *bundle = [NSBundle bundleWithPath:targetPath];
        NSString *executablePath = [[bundle.executablePath ?: targetPath stringByExpandingTildeInPath] stringByResolvingSymlinksInPath];
        NSString *backupPath = ({
            NSString *bkp = [executablePath stringByAppendingString:@"_backup"];
            if (bundle) {
                NSString *vers = [bundle objectForInfoDictionaryKey:(NSString *)kCFBundleVersionKey];
                if (vers)
                    bkp = [bkp stringByAppendingPathExtension:vers];
            }
            bkp;
        });

        if (!outputPath)
            outputPath = executablePath;

        NSFileManager *manager = [NSFileManager defaultManager];

        // Handle restore separately (doesn't need to read the binary)
        if (cmd == OPCommandRestore) {
            LOG("Attempting to restore %s...", backupPath.UTF8String);

            if ([manager fileExistsAtPath:backupPath]) {
                NSError *error = nil;
                if ([manager removeItemAtPath:executablePath error:&error]) {
                    if ([manager moveItemAtPath:backupPath toPath:executablePath error:&error]) {
                        LOG("Successfully restored backup");
                        return OPErrorNone;
                    }
                    LOG("Failed to move backup to correct location");
                    return OPErrorMoveFailure;
                }

                LOG("Failed to remove executable. (%s)", error.localizedDescription.UTF8String);
                return OPErrorRemovalFailure;
            }

            LOG("No backup for that target exists");
            return OPErrorNoBackup;
        }

        // Read the binary
        NSData *originalData = [NSData dataWithContentsOfFile:executablePath];
        NSMutableData *binary = originalData.mutableCopy;
        if (!binary) {
            LOG("Failed to read %s", executablePath.UTF8String);
            return OPErrorRead;
        }

        uint32_t numHeaders = 0;
        struct thin_header *headers = headersFromBinary(binary, &numHeaders);

        if (!headers || numHeaders == 0) {
            LOG("No compatible architecture found");
            free(headers);
            return OPErrorIncompatibleBinary;
        }

        int result = OPErrorNone;

        // Loop through all thin headers for each operation
        for (uint32_t i = 0; i < numHeaders && result == OPErrorNone; i++) {
            struct thin_header macho = headers[i];

            switch (cmd) {
                case OPCommandStrip: {
                    if (!stripCodeSignatureFromBinary(binary, macho, weakFlag)) {
                        LOG("Found no code signature to strip");
                        result = OPErrorStripFailure;
                    } else {
                        LOG("Successfully stripped code signature");
                    }
                    break;
                }
                case OPCommandUnrestrict: {
                    if (!unrestrictBinary(binary, macho, weakFlag)) {
                        LOG("Found no restrict section to remove");
                        result = OPErrorStripFailure;
                    } else {
                        LOG("Successfully removed restrict section");
                    }
                    break;
                }
                case OPCommandUninstall: {
                    if (removeLoadEntryFromBinary(binary, macho, dylibPath)) {
                        LOG("Successfully removed all entries for %s", dylibPath.UTF8String);
                    } else {
                        LOG("No entries for %s exist to remove", dylibPath.UTF8String);
                        result = OPErrorNoEntries;
                    }
                    break;
                }
                case OPCommandInstall: {
                    uint32_t lcType = LC_LOAD_DYLIB;
                    if (commandType) {
                        lcType = COMMAND(commandType);
                        if (lcType == (uint32_t)-1) {
                            LOG("Invalid load command type: %s", commandType.UTF8String);
                            result = OPErrorInvalidLoadCommand;
                            break;
                        }
                    }

                    if (binaryHasHardenedRuntime(binary, macho)) {
                        LOG("WARNING: Binary has hardened runtime enabled for %s.", CPU(macho.header.cputype));
                        LOG("Injected dylib will not load unless the binary has the");
                        LOG("com.apple.security.cs.disable-library-validation entitlement or SIP is disabled.");
                    }

                    if (insertLoadEntryIntoBinary(dylibPath, binary, macho, lcType)) {
                        LOG("Successfully inserted a %s command for %s", LC(lcType), CPU(macho.header.cputype));
                    } else {
                        LOG("Failed to insert a %s command for %s", LC(lcType), CPU(macho.header.cputype));
                        result = OPErrorInsertFailure;
                    }
                    break;
                }
                case OPCommandAslr: {
                    LOG("Attempting to remove ASLR");
                    if (removeASLRFromBinary(binary, macho)) {
                        LOG("Successfully removed ASLR from binary");
                    }
                    break;
                }
                case OPCommandRename: {
                    NSString *from = nil;
                    NSString *to = nil;

                    if (renameArgs.count == 2) {
                        from = renameArgs[0];
                        to = renameArgs[1];
                    } else {
                        to = renameArgs[0];
                    }

                    LOG("Attempting to rename...");
                    if (renameBinary(binary, macho, from, to)) {
                        LOG("Successfully renamed");
                    }
                    break;
                }
                default:
                    break;
            }
        }

        if (result != OPErrorNone) {
            free(headers);
            return result;
        }

        // Backup if requested
        if (backupFlag) {
            NSError *error = nil;
            LOG("Backing up executable (%s)...", executablePath.UTF8String);
            if (![manager fileExistsAtPath:backupPath isDirectory:NULL] &&
                ![manager copyItemAtPath:executablePath toPath:backupPath error:&error]) {
                LOG("Encountered error during backup: %s", error.localizedDescription.UTF8String);
                free(headers);
                return OPErrorBackupFailure;
            }
        }

        // Write output
        LOG("Writing executable to %s...", outputPath.UTF8String);
        if (![binary writeToFile:outputPath atomically:NO]) {
            LOG("Failed to write data. Permissions?");
            free(headers);
            return OPErrorWriteFailure;
        }

        // Warn if modified binary has arm64 and no resign
        if (!resignFlag) {
            BOOL hasArm64 = NO;
            for (uint32_t i = 0; i < numHeaders; i++) {
                if (headers[i].header.cputype == CPU_TYPE_ARM64) {
                    hasArm64 = YES;
                    break;
                }
            }
            if (hasArm64) {
                LOG("WARNING: Modified binary contains arm64 code. It may not run on Apple Silicon");
                LOG("without re-signing. Use --resign or run: codesign -f -s - %s", outputPath.UTF8String);
            }
        }

        // Re-sign if requested
        if (resignFlag) {
            const char *resignPath = outputPath ? outputPath.UTF8String : (bundle ? bundle.bundlePath.UTF8String : executablePath.UTF8String);
            LOG("Attempting to resign %s...", resignPath);
            NSPipe *pipe = [NSPipe pipe];
            NSTask *task = [[NSTask alloc] init];
            task.launchPath = @"/usr/bin/codesign";
            task.arguments = @[ @"-f", @"-s", @"-", @(resignPath) ];

            [task setStandardOutput:pipe];
            [task setStandardError:pipe];
            [task launch];
            [task waitUntilExit];

            NSFileHandle *read = [pipe fileHandleForReading];
            NSData *dataRead = [read readDataToEndOfFile];
            NSString *stringRead = [[NSString alloc] initWithData:dataRead encoding:NSUTF8StringEncoding];
            LOG("%s", stringRead.UTF8String);
            if (task.terminationStatus == 0) {
                LOG("Successfully resigned executable");
            } else {
                LOG("Failed to resign executable. Reverting...");
                if (!outputPath || [outputPath isEqualToString:executablePath]) {
                    [originalData writeToFile:executablePath atomically:NO];
                }
                free(headers);
                return OPErrorResignFailure;
            }
        }

        free(headers);
    }

    return OPErrorNone;
}
