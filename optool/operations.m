//
//  operations.m
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


#import "operations.h"
#import "NSData+Reading.h"
#import "defines.h"
#import <mach-o/loader.h>

// Chained fixups structures (from <mach-o/fixup-chains.h>)
struct optool_chained_fixups_header {
    uint32_t fixups_version;
    uint32_t starts_offset;
    uint32_t imports_offset;
    uint32_t symbols_offset;
    uint32_t imports_count;
    uint32_t imports_format;
    uint32_t symbols_format;
};

// Import formats
enum {
    OPTOOL_CHAINED_IMPORT          = 1,
    OPTOOL_CHAINED_IMPORT_ADDEND   = 2,
    OPTOOL_CHAINED_IMPORT_ADDEND64 = 3,
};

struct optool_chained_import {
    uint32_t lib_ordinal : 8;
    uint32_t weak_import : 1;
    uint32_t name_offset : 23;
};

struct optool_chained_import_addend {
    uint32_t lib_ordinal : 8;
    uint32_t weak_import : 1;
    uint32_t name_offset : 23;
    int32_t  addend;
};

struct optool_chained_import_addend64 {
    uint64_t lib_ordinal : 16;
    uint64_t weak_import : 1;
    uint64_t reserved    : 15;
    uint64_t name_offset : 32;
    uint64_t addend;
};

#pragma mark - Helpers

static inline BOOL safeRange(NSUInteger offset, NSUInteger length, NSUInteger total) {
    return (offset <= total) && (length <= total - offset);
}

// Reads uleb128 from a buffer with bounds checking
static uint64_t read_uleb128(const uint8_t *p, const uint8_t *end, uint32_t *read_length) {
    const uint8_t *orig = p;
    uint64_t value = 0;
    unsigned shift = 0;

    do {
        if (p >= end) {
            if (read_length) *read_length = (uint32_t)(p - orig);
            return value;
        }
        value += ((uint64_t)(*p & 0x7f)) << shift;
        shift += 7;
    } while (*p++ >= 128);

    if (read_length)
        *read_length = (uint32_t)(p - orig);

    return value;
}

// Writes a uint64_t as a uleb to a buffer and returns the length
// Also passes in a length limit so we can pad to it
static uint32_t write_uleb128(uint8_t *p, uint64_t value, uint32_t length_limit) {
    uint8_t *orig = p;
    do {
        uint8_t byte = value & 0x7f;
        value >>= 7;

        if (value != 0) {
            byte |= 0x80;
        }

        *p++ = byte;
    } while (value != 0);

    uint32_t len = (uint32_t)(p - orig);

    int32_t pad = length_limit - len;
    if (pad < 0 && length_limit != 0) {
        LOG("ULEB encode failure: value requires more bytes than available");
        return 0;
    }

    if (pad > 0) {
        // mark these bytes to show more follow
        for (; pad != 1; --pad) {
            *p++ = '\x80';
        }
        // mark terminating byte
        *p++ = '\x00';
    }

    return len;
}

unsigned int OP_SOFT_STRIP = 0x00001337;
const char *OP_SOFT_UNRESTRICT = "\xf0\x9f\x92\xa9";

#pragma mark - __LINKEDIT helpers

// Find and update __LINKEDIT segment after modifying its contents
static void updateLinkeditSegment(NSMutableData *binary, struct thin_header macho, uint32_t removedDataOff, uint32_t removedDataSize) {
    NSUInteger offset = macho.offset + macho.size;

    for (uint32_t i = 0; i < macho.header.ncmds; i++) {
        if (!safeRange(offset, sizeof(uint32_t) * 2, binary.length))
            break;

        uint32_t cmd  = [binary intAtOffset:offset];
        uint32_t size = [binary intAtOffset:offset + sizeof(uint32_t)];

        if (cmd == LC_SEGMENT_64) {
            if (!safeRange(offset, sizeof(struct segment_command_64), binary.length))
                break;
            struct segment_command_64 *seg = (struct segment_command_64 *)(binary.mutableBytes + offset);
            if (strncmp(seg->segname, "__LINKEDIT", 16) == 0) {
                // The code signature is always at the end of __LINKEDIT
                // Shrink the segment to exclude the removed data
                if (removedDataOff >= seg->fileoff &&
                    removedDataOff + removedDataSize <= seg->fileoff + seg->filesize) {
                    seg->filesize -= removedDataSize;
                    // Round vmsize up to page boundary
                    seg->vmsize = (seg->filesize + 0x3FFF) & ~0x3FFFUL;
                    LOG("Updated __LINKEDIT: filesize=%llu vmsize=%llu", seg->filesize, seg->vmsize);
                }
                return;
            }
        } else if (cmd == LC_SEGMENT) {
            if (!safeRange(offset, sizeof(struct segment_command), binary.length))
                break;
            struct segment_command *seg = (struct segment_command *)(binary.mutableBytes + offset);
            if (strncmp(seg->segname, "__LINKEDIT", 16) == 0) {
                if (removedDataOff >= seg->fileoff &&
                    removedDataOff + removedDataSize <= seg->fileoff + seg->filesize) {
                    seg->filesize -= removedDataSize;
                    seg->vmsize = (seg->filesize + 0x3FFF) & ~0x3FFFU;
                    LOG("Updated __LINKEDIT: filesize=%u vmsize=%u", seg->filesize, seg->vmsize);
                }
                return;
            }
        }

        offset += size;
    }
}

#pragma mark - Chained fixups ordinal shifting

static BOOL shiftChainedFixupsOrdinals(NSMutableData *binary, struct thin_header macho, uint32_t removedOrdinal) {
    NSUInteger offset = macho.offset + macho.size;

    for (uint32_t i = 0; i < macho.header.ncmds; i++) {
        if (!safeRange(offset, sizeof(uint32_t) * 2, binary.length))
            break;

        uint32_t cmd  = [binary intAtOffset:offset];
        uint32_t size = [binary intAtOffset:offset + sizeof(uint32_t)];

        if (cmd == LC_DYLD_CHAINED_FIXUPS) {
            if (!safeRange(offset, sizeof(struct linkedit_data_command), binary.length))
                return NO;

            struct linkedit_data_command chainedCmd;
            [binary getBytes:&chainedCmd range:NSMakeRange(offset, sizeof(chainedCmd))];

            if (!safeRange(chainedCmd.dataoff, sizeof(struct optool_chained_fixups_header), binary.length)) {
                LOG("Chained fixups data out of bounds");
                return NO;
            }

            struct optool_chained_fixups_header header;
            [binary getBytes:&header range:NSMakeRange(chainedCmd.dataoff, sizeof(header))];

            uint32_t importsOff = chainedCmd.dataoff + header.imports_offset;

            switch (header.imports_format) {
                case OPTOOL_CHAINED_IMPORT: {
                    uint32_t entrySize = sizeof(struct optool_chained_import);
                    if (!safeRange(importsOff, (NSUInteger)header.imports_count * entrySize, binary.length)) {
                        LOG("Chained imports table out of bounds");
                        return NO;
                    }
                    struct optool_chained_import *imports = (struct optool_chained_import *)(binary.mutableBytes + importsOff);
                    for (uint32_t j = 0; j < header.imports_count; j++) {
                        uint8_t ordinal = imports[j].lib_ordinal;
                        // Only shift positive ordinals (negative values are special: self, main exec, flat)
                        if (ordinal > removedOrdinal && ordinal < 0xF0) {
                            imports[j].lib_ordinal = ordinal - 1;
                        }
                    }
                    LOG("Shifted %u chained import ordinals", header.imports_count);
                    break;
                }
                case OPTOOL_CHAINED_IMPORT_ADDEND: {
                    uint32_t entrySize = sizeof(struct optool_chained_import_addend);
                    if (!safeRange(importsOff, (NSUInteger)header.imports_count * entrySize, binary.length)) {
                        LOG("Chained imports table out of bounds");
                        return NO;
                    }
                    struct optool_chained_import_addend *imports = (struct optool_chained_import_addend *)(binary.mutableBytes + importsOff);
                    for (uint32_t j = 0; j < header.imports_count; j++) {
                        uint8_t ordinal = imports[j].lib_ordinal;
                        if (ordinal > removedOrdinal && ordinal < 0xF0) {
                            imports[j].lib_ordinal = ordinal - 1;
                        }
                    }
                    LOG("Shifted %u chained import ordinals (addend format)", header.imports_count);
                    break;
                }
                case OPTOOL_CHAINED_IMPORT_ADDEND64: {
                    uint32_t entrySize = sizeof(struct optool_chained_import_addend64);
                    if (!safeRange(importsOff, (NSUInteger)header.imports_count * entrySize, binary.length)) {
                        LOG("Chained imports table out of bounds");
                        return NO;
                    }
                    struct optool_chained_import_addend64 *imports = (struct optool_chained_import_addend64 *)(binary.mutableBytes + importsOff);
                    for (uint32_t j = 0; j < header.imports_count; j++) {
                        uint16_t ordinal = (uint16_t)imports[j].lib_ordinal;
                        if (ordinal > removedOrdinal && ordinal < 0xFFF0) {
                            imports[j].lib_ordinal = ordinal - 1;
                        }
                    }
                    LOG("Shifted %u chained import ordinals (addend64 format)", header.imports_count);
                    break;
                }
                default:
                    LOG("Unknown chained imports format: %u", header.imports_format);
                    return NO;
            }

            return YES;
        }

        offset += size;
    }

    return YES; // no chained fixups found is OK
}

#pragma mark - Legacy binding ordinal shifting

static BOOL shiftLegacyBindOrdinals(NSMutableData *binary, struct thin_header macho, uint32_t removedOrdinal) {
    NSUInteger offset = macho.offset + macho.size;

    for (uint32_t i = 0; i < macho.header.ncmds; i++) {
        if (!safeRange(offset, sizeof(uint32_t) * 2, binary.length))
            break;

        uint32_t cmd  = [binary intAtOffset:offset];
        uint32_t size = [binary intAtOffset:offset + sizeof(uint32_t)];

        if (cmd == LC_DYLD_INFO || cmd == LC_DYLD_INFO_ONLY) {
            if (!safeRange(offset, sizeof(struct dyld_info_command), binary.length))
                return NO;

            struct dyld_info_command info;
            [binary getBytes:&info range:NSMakeRange(offset, sizeof(info))];

            // Process bind, weak_bind, and lazy_bind tables
            uint32_t tables[][2] = {
                { info.bind_off, info.bind_size },
                { info.weak_bind_off, info.weak_bind_size },
                { info.lazy_bind_off, info.lazy_bind_size },
            };

            for (int t = 0; t < 3; t++) {
                uint32_t tableOff = tables[t][0];
                uint32_t tableSize = tables[t][1];

                if (tableSize == 0) continue;
                if (!safeRange(tableOff, tableSize, binary.length)) continue;

                uint8_t *start = (uint8_t *)binary.mutableBytes + tableOff;
                const uint8_t *end = start + tableSize;
                uint8_t *p = start;

                while (p < end) {
                    uint8_t byte = *p;
                    uint8_t opcode = byte & BIND_OPCODE_MASK;
                    uint8_t immediate = byte & BIND_IMMEDIATE_MASK;

                    p++;

                    switch (opcode) {
                        case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM: {
                            if (immediate > removedOrdinal) {
                                *(p - 1) = BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | ((immediate - 1) & BIND_IMMEDIATE_MASK);
                            }
                            break;
                        }
                        case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB: {
                            uint32_t len = 0;
                            uint64_t ordinal = read_uleb128(p, end, &len);
                            if (ordinal > removedOrdinal) {
                                write_uleb128(p, ordinal - 1, len);
                            }
                            p += len;
                            break;
                        }
                        case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
                            // Negative ordinals (self, main exec, flat) — don't touch
                            break;
                        case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
                            // Skip the symbol name string
                            while (p < end && *p != 0) p++;
                            if (p < end) p++; // skip null terminator
                            break;
                        case BIND_OPCODE_SET_TYPE_IMM:
                        case BIND_OPCODE_DO_BIND:
                        case BIND_OPCODE_DONE:
                            break;
                        case BIND_OPCODE_SET_ADDEND_SLEB:
                        case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
                        case BIND_OPCODE_ADD_ADDR_ULEB:
                        case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB: {
                            uint32_t len = 0;
                            read_uleb128(p, end, &len);
                            p += len;
                            break;
                        }
                        case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
                            break;
                        case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: {
                            uint32_t len1 = 0, len2 = 0;
                            read_uleb128(p, end, &len1);
                            p += len1;
                            read_uleb128(p, end, &len2);
                            p += len2;
                            break;
                        }
                        default:
                            break;
                    }
                }
            }

            LOG("Shifted legacy binding ordinals");
            return YES;
        }

        offset += size;
    }

    return YES; // no bind info found is OK
}

#pragma mark - Operations

BOOL stripCodeSignatureFromBinary(NSMutableData *binary, struct thin_header macho, BOOL softStrip) {
    binary.currentOffset = macho.offset + macho.size;
    BOOL success = NO;

    for (uint32_t i = 0; i < macho.header.ncmds; i++) {
        if (binary.currentOffset >= binary.length ||
            binary.currentOffset > macho.header.sizeofcmds + macho.size + macho.offset)
            break;

        if (!safeRange(binary.currentOffset, sizeof(uint32_t) * 2, binary.length))
            break;

        uint32_t cmd  = [binary intAtOffset:binary.currentOffset];
        uint32_t size = [binary intAtOffset:binary.currentOffset + sizeof(uint32_t)];

        switch (cmd) {
            case LC_CODE_SIGNATURE: {
                if (!safeRange(binary.currentOffset, sizeof(struct linkedit_data_command), binary.length)) {
                    LOG("LC_CODE_SIGNATURE command extends past binary end");
                    return NO;
                }

                struct linkedit_data_command command = *(struct linkedit_data_command *)(binary.bytes + binary.currentOffset);

                if (!safeRange(command.dataoff, command.datasize, binary.length)) {
                    LOG("Code signature data extends past binary end");
                    return NO;
                }

                LOG("stripping code signature for architecture %s...", CPU(macho.header.cputype));

                if (!softStrip) {
                    uint32_t sigDataOff = command.dataoff;
                    uint32_t sigDataSize = command.datasize;

                    macho.header.ncmds -= 1;
                    macho.header.sizeofcmds -= sizeof(struct linkedit_data_command);

                    // Zero out the signature data
                    [binary replaceBytesInRange:NSMakeRange(sigDataOff, sigDataSize) withBytes:0 length:sigDataSize];

                    // Remove the load command
                    [binary replaceBytesInRange:NSMakeRange(binary.currentOffset, sizeof(struct linkedit_data_command)) withBytes:0 length:0];

                    // Pad the load command area to maintain size
                    [binary replaceBytesInRange:NSMakeRange(macho.offset + macho.header.sizeofcmds + macho.size, 0)
                                      withBytes:0
                                         length:size];

                    // Update __LINKEDIT segment to reflect removed signature
                    [binary replaceBytesInRange:NSMakeRange(macho.offset, sizeof(macho.header))
                                      withBytes:&macho.header
                                         length:sizeof(macho.header)];
                    updateLinkeditSegment(binary, macho, sigDataOff, sigDataSize);

                    // Truncate the binary if the signature was at the end
                    if (sigDataOff + sigDataSize >= binary.length) {
                        [binary setLength:sigDataOff];
                        LOG("Truncated binary to %u bytes", sigDataOff);
                    }
                } else {
                    [binary replaceBytesInRange:NSMakeRange(binary.currentOffset, 4)
                                      withBytes:&OP_SOFT_STRIP];
                }

                success = YES;
                break;
            }
            default:
                binary.currentOffset += size;
                break;
        }
    }

    // Write the updated header (if not already done in non-soft path)
    if (!softStrip && !success) {
        // No code signature found — header unchanged
    } else if (softStrip) {
        // Soft strip doesn't modify the header
    }

    return success;
}

BOOL unrestrictBinary(NSMutableData *binary, struct thin_header macho, BOOL soft) {
    binary.currentOffset = macho.offset + macho.size;
    BOOL success = NO;

    LOG("unrestricting for architecture %s...", CPU(macho.header.cputype));

    for (uint32_t i = 0; i < macho.header.ncmds; i++) {
        if (binary.currentOffset >= binary.length ||
            binary.currentOffset > macho.header.sizeofcmds + macho.size + macho.offset)
            break;

        if (!safeRange(binary.currentOffset, sizeof(uint32_t) * 2, binary.length))
            break;

        uint32_t cmd  = [binary intAtOffset:binary.currentOffset];
        uint32_t size = [binary intAtOffset:binary.currentOffset + sizeof(uint32_t)];

#define CROSS(CODE...) \
    case LC_SEGMENT: {\
        typedef struct segment_command segment_type; \
        typedef struct section section_type; \
        CODE \
    }\
    case LC_SEGMENT_64: {\
        typedef struct segment_command_64 segment_type; \
        typedef struct section_64 section_type; \
        CODE \
    }

        switch (cmd) {
            CROSS(
                if (!safeRange(binary.currentOffset, sizeof(segment_type), binary.length)) {
                    LOG("Segment command extends past binary end");
                    return NO;
                }
                segment_type *command = (segment_type *)(binary.mutableBytes + binary.currentOffset);
                if (!strncmp(command->segname, "__RESTRICT", 16)) {
                    LOG("Found __RESTRICT segment");
                    if (size < sizeof(*command) ||
                        command->nsects > (size - sizeof(*command)) / sizeof(section_type)) {
                        LOG("Bad segment_command");
                        return false;
                    }

                    section_type *section = (section_type *)(binary.mutableBytes + binary.currentOffset + sizeof(*command));
                    for (uint32_t si = 0; si < command->nsects; si++, section++) {
                        if (!strncmp(section->sectname, "__restrict", 16)) {
                            LOG("Found __restrict section. Patching...");

                            if (soft) {
                                strlcpy(section->sectname, OP_SOFT_UNRESTRICT, sizeof(section->sectname));
                                success = YES;
                            } else {
                                command->nsects--;
                                command->cmdsize -= sizeof(*section);
                                macho.header.sizeofcmds -= sizeof(*section);

                                uint64_t sectionSize = sizeof(*section);
                                [binary replaceBytesInRange:NSMakeRange((NSUInteger)section - (NSUInteger)binary.mutableBytes,
                                                                        sectionSize)
                                                  withBytes:0
                                                     length:0];
                                [binary replaceBytesInRange:NSMakeRange(macho.offset + macho.header.sizeofcmds + macho.size, 0)
                                                  withBytes:0
                                                     length:sectionSize];
                                success = YES;
                            }
                        }
                    }

                    // remove the whole segment if empty
                    if (command->nsects == 0 && !soft) {
                        LOG("__RESTRICT segment has no more sections. Removing...");
                        macho.header.ncmds--;
                        uint32_t cmdSize = sizeof(*command);
                        macho.header.sizeofcmds -= command->cmdsize;
                        [binary replaceBytesInRange:NSMakeRange((NSUInteger)command - (NSUInteger)binary.mutableBytes,
                                                                cmdSize)
                                          withBytes:0
                                             length:0];
                        [binary replaceBytesInRange:NSMakeRange(macho.offset + macho.header.sizeofcmds + macho.size, 0)
                                          withBytes:0
                                             length:cmdSize];
                    } else {
                        binary.currentOffset += command->cmdsize;
                    }

                } else {
                    binary.currentOffset += size;
                }
                break;
            )
            default:
                binary.currentOffset += size;
                break;
        }
    }
#undef CROSS

    if (!soft) {
        [binary replaceBytesInRange:NSMakeRange(macho.offset, sizeof(macho.header))
                          withBytes:&macho.header
                             length:sizeof(macho.header)];
    }

    return success;
}

BOOL removeLoadEntryFromBinary(NSMutableData *binary, struct thin_header macho, NSString *payload) {
    binary.currentOffset = macho.offset + macho.size;

    uint32_t num = 0;
    uint32_t cumulativeSize = 0;
    uint32_t removedOrdinal = UINT32_MAX;
    BOOL hasChainedFixups = NO;
    BOOL hasLegacyBind = NO;

    // First pass: detect fixup format
    {
        NSUInteger scanOffset = macho.offset + macho.size;
        for (uint32_t i = 0; i < macho.header.ncmds; i++) {
            if (!safeRange(scanOffset, sizeof(uint32_t) * 2, binary.length))
                break;
            uint32_t scanCmd = [binary intAtOffset:scanOffset];
            uint32_t scanSize = [binary intAtOffset:scanOffset + sizeof(uint32_t)];
            if (scanCmd == LC_DYLD_CHAINED_FIXUPS) hasChainedFixups = YES;
            if (scanCmd == LC_DYLD_INFO || scanCmd == LC_DYLD_INFO_ONLY) hasLegacyBind = YES;
            scanOffset += scanSize;
        }
    }

    // Second pass: find and remove the target dylib load command
    // Track ordinal position (only count LC_LOAD_DYLIB family commands)
    uint32_t dylibOrdinal = 0;

    for (uint32_t i = 0; i < macho.header.ncmds; i++) {
        if (binary.currentOffset >= binary.length ||
            binary.currentOffset > macho.offset + macho.size + macho.header.sizeofcmds)
            break;

        if (!safeRange(binary.currentOffset, sizeof(uint32_t) * 2, binary.length))
            break;

        uint32_t cmd  = [binary intAtOffset:binary.currentOffset];
        uint32_t size = [binary intAtOffset:binary.currentOffset + sizeof(uint32_t)];

        switch (cmd) {
            case LC_REEXPORT_DYLIB:
            case LC_LOAD_UPWARD_DYLIB:
            case LC_LOAD_WEAK_DYLIB:
            case LC_LOAD_DYLIB: {
                if (!safeRange(binary.currentOffset, sizeof(struct dylib_command), binary.length)) {
                    binary.currentOffset += size;
                    break;
                }

                struct dylib_command command = *(struct dylib_command *)(binary.bytes + binary.currentOffset);

                if (!safeRange(binary.currentOffset + command.dylib.name.offset,
                               command.cmdsize - command.dylib.name.offset,
                               binary.length)) {
                    binary.currentOffset += size;
                    dylibOrdinal++;
                    break;
                }

                char *name = (char *)[[binary subdataWithRange:NSMakeRange(binary.currentOffset + command.dylib.name.offset, command.cmdsize - command.dylib.name.offset)] bytes];
                if ([@(name) isEqualToString:payload] && removedOrdinal == UINT32_MAX) {
                    LOG("removing payload from %s...", LC(cmd));
                    // Ordinals are 1-based in binding info
                    removedOrdinal = dylibOrdinal + 1;
                    [binary replaceBytesInRange:NSMakeRange(binary.currentOffset, size) withBytes:0 length:0];
                    num++;
                    cumulativeSize += size;
                } else {
                    binary.currentOffset += size;
                }

                dylibOrdinal++;
                break;
            }
            default:
                binary.currentOffset += size;
                break;
        }
    }

    if (num == 0)
        return NO;

    // fix the header
    macho.header.ncmds -= num;
    macho.header.sizeofcmds -= cumulativeSize;

    unsigned int zeroByte = 0;

    // append null bytes to end of header to maintain size
    [binary replaceBytesInRange:NSMakeRange(macho.offset + macho.header.sizeofcmds + macho.size, 0) withBytes:&zeroByte length:cumulativeSize];
    [binary replaceBytesInRange:NSMakeRange(macho.offset, sizeof(macho.header))
                      withBytes:&macho.header
                         length:sizeof(macho.header)];

    // Shift binding ordinals to account for removed dylib
    if (removedOrdinal != UINT32_MAX) {
        if (hasChainedFixups) {
            if (!shiftChainedFixupsOrdinals(binary, macho, removedOrdinal)) {
                LOG("WARNING: Failed to shift chained fixups ordinals. Binary may be corrupt.");
            }
        }
        if (hasLegacyBind) {
            if (!shiftLegacyBindOrdinals(binary, macho, removedOrdinal)) {
                LOG("WARNING: Failed to shift legacy binding ordinals. Binary may be corrupt.");
            }
        }
    }

    return YES;
}

BOOL binaryHasLoadCommandForDylib(NSMutableData *binary, NSString *dylib, uint32_t *lastOffset, struct thin_header macho) {
    binary.currentOffset = macho.size + macho.offset;
    unsigned int loadOffset = (unsigned int)binary.currentOffset;

    for (uint32_t i = 0; i < macho.header.ncmds; i++) {
        if (binary.currentOffset >= binary.length ||
            binary.currentOffset > macho.offset + macho.size + macho.header.sizeofcmds)
            break;

        if (!safeRange(binary.currentOffset, sizeof(uint32_t) * 2, binary.length))
            break;

        uint32_t cmd  = [binary intAtOffset:binary.currentOffset];
        uint32_t size = [binary intAtOffset:binary.currentOffset + sizeof(uint32_t)];

        switch (cmd) {
            case LC_REEXPORT_DYLIB:
            case LC_LOAD_UPWARD_DYLIB:
            case LC_LOAD_WEAK_DYLIB:
            case LC_LOAD_DYLIB: {
                if (!safeRange(binary.currentOffset, sizeof(struct dylib_command), binary.length)) {
                    binary.currentOffset += size;
                    break;
                }

                struct dylib_command command = *(struct dylib_command *)(binary.bytes + binary.currentOffset);

                if (command.dylib.name.offset < command.cmdsize &&
                    safeRange(binary.currentOffset + command.dylib.name.offset,
                              command.cmdsize - command.dylib.name.offset,
                              binary.length)) {
                    char *name = (char *)[[binary subdataWithRange:NSMakeRange(binary.currentOffset + command.dylib.name.offset, command.cmdsize - command.dylib.name.offset)] bytes];

                    if ([@(name) isEqualToString:dylib]) {
                        *lastOffset = (unsigned int)binary.currentOffset;
                        return YES;
                    }
                }

                binary.currentOffset += size;
                loadOffset = (unsigned int)binary.currentOffset;
                break;
            }
            default:
                binary.currentOffset += size;
                break;
        }
    }

    if (lastOffset != NULL)
        *lastOffset = loadOffset;

    return NO;
}

BOOL renameBinary(NSMutableData *binary, struct thin_header macho, NSString *from, NSString *to) {
    binary.currentOffset = macho.size + macho.offset;

    BOOL success = NO;

    for (uint32_t i = 0; i < macho.header.ncmds; i++) {
        if (binary.currentOffset >= binary.length ||
            binary.currentOffset > macho.offset + macho.size + macho.header.sizeofcmds)
            break;

        if (!safeRange(binary.currentOffset, sizeof(uint32_t) * 2, binary.length))
            break;

        uint32_t cmd  = [binary intAtOffset:binary.currentOffset];
        uint32_t size = [binary intAtOffset:binary.currentOffset + sizeof(uint32_t)];

        switch (cmd) {
            case LC_ID_DYLIB:
            case LC_REEXPORT_DYLIB:
            case LC_LOAD_UPWARD_DYLIB:
            case LC_LOAD_WEAK_DYLIB:
            case LC_LOAD_DYLIB: {
                if (!safeRange(binary.currentOffset, sizeof(struct dylib_command), binary.length)) {
                    binary.currentOffset += size;
                    break;
                }

                struct dylib_command *command = (struct dylib_command *)(binary.mutableBytes + binary.currentOffset);

                if (command->dylib.name.offset >= command->cmdsize ||
                    !safeRange(binary.currentOffset + command->dylib.name.offset,
                               command->cmdsize - command->dylib.name.offset,
                               binary.length)) {
                    binary.currentOffset += size;
                    break;
                }

                off_t name_offset = binary.currentOffset + command->dylib.name.offset;
                NSRange name_range = NSMakeRange(name_offset, command->cmdsize - command->dylib.name.offset);
                char *name = (char *)[[binary subdataWithRange:name_range] bytes];

                if ([@(name) isEqualToString:from] || (!from && cmd == LC_ID_DYLIB)) {
                    const char *replacement = to.fileSystemRepresentation;

                    NSInteger name_length = strlen(replacement) + 1;
                    unsigned int padding = (4 - (name_length % 4));
                    if (padding < 4)
                        name_length += padding;

                    NSInteger shift = name_length - (NSInteger)name_range.length;

                    if (shift > 0) {
                        [binary replaceBytesInRange:NSMakeRange(macho.header.sizeofcmds + macho.offset + macho.size,
                                                                shift)
                                          withBytes:0
                                             length:0];

                    } else if (shift < 0) {
                        uint8_t zero = 0;
                        [binary replaceBytesInRange:NSMakeRange(macho.header.sizeofcmds + macho.offset + macho.size,
                                                                0)
                                          withBytes:&zero
                                             length:labs(shift)];
                    }

                    command->cmdsize += shift;
                    macho.header.sizeofcmds += shift;

                    [binary replaceBytesInRange:NSMakeRange(macho.offset, sizeof(macho.header)) withBytes:&macho.header];
                    [binary replaceBytesInRange:name_range withBytes:replacement length:name_length];

                    success = YES;
                }

                binary.currentOffset += size;
                break;
            }
            default:
                binary.currentOffset += size;
                break;
        }
    }

    return success;
}

BOOL insertLoadEntryIntoBinary(NSString *dylibPath, NSMutableData *binary, struct thin_header macho, uint32_t type) {
    if (type != LC_REEXPORT_DYLIB &&
        type != LC_LOAD_WEAK_DYLIB &&
        type != LC_LOAD_UPWARD_DYLIB &&
        type != LC_LOAD_DYLIB) {
        LOG("Invalid load command type");
        return NO;
    }
    // parse load commands to see if our load command is already there
    uint32_t lastOffset = 0;
    if (binaryHasLoadCommandForDylib(binary, dylibPath, &lastOffset, macho)) {
        uint32_t originalType = *(uint32_t *)(binary.bytes + lastOffset);
        if (originalType != type) {
            LOG("A load command already exists for %s. Changing command type from %s to desired %s", dylibPath.UTF8String, LC(originalType), LC(type));
            [binary replaceBytesInRange:NSMakeRange(lastOffset, sizeof(type)) withBytes:&type];
        } else {
            LOG("Load command already exists");
        }

        return YES;
    }

    // create a new load command
    unsigned int length = (unsigned int)sizeof(struct dylib_command) + (unsigned int)dylibPath.length;
    unsigned int padding = (8 - (length % 8));

    NSUInteger occupantOffset = macho.header.sizeofcmds + macho.offset + macho.size;
    NSUInteger occupantLength = length + padding;

    if (!safeRange(occupantOffset, occupantLength, binary.length)) {
        LOG("cannot inject payload into %s because there is no room (past end of binary)", dylibPath.fileSystemRepresentation);
        return NO;
    }

    // check if data we are replacing is null
    NSData *occupant = [binary subdataWithRange:NSMakeRange(occupantOffset, occupantLength)];

    const uint8_t *occupantBytes = (const uint8_t *)occupant.bytes;
    BOOL hasRoom = YES;
    for (NSUInteger j = 0; j < occupant.length; j++) {
        if (occupantBytes[j] != 0) {
            hasRoom = NO;
            break;
        }
    }
    if (!hasRoom) {
        LOG("cannot inject payload into %s because there is no room", dylibPath.fileSystemRepresentation);
        return NO;
    }

    LOG("Inserting a %s command for architecture: %s", LC(type), CPU(macho.header.cputype));

    struct dylib_command command;
    struct dylib dylib;
    dylib.name.offset = sizeof(struct dylib_command);
    dylib.timestamp = 2;
    dylib.current_version = 0;
    dylib.compatibility_version = 0;
    command.cmd = type;
    command.dylib = dylib;
    command.cmdsize = length + padding;

    unsigned int zeroByte = 0;
    NSMutableData *commandData = [NSMutableData data];
    [commandData appendBytes:&command length:sizeof(struct dylib_command)];
    [commandData appendData:[dylibPath dataUsingEncoding:NSASCIIStringEncoding]];
    [commandData appendBytes:&zeroByte length:padding];

    // remove enough null bytes to account for our inserted data
    [binary replaceBytesInRange:NSMakeRange(macho.offset + macho.header.sizeofcmds + macho.size, commandData.length)
                      withBytes:0
                         length:0];
    // insert the data
    [binary replaceBytesInRange:NSMakeRange(lastOffset, 0) withBytes:commandData.bytes length:commandData.length];

    // fix the existing header
    macho.header.ncmds += 1;
    macho.header.sizeofcmds += command.cmdsize;

    [binary replaceBytesInRange:NSMakeRange(macho.offset, sizeof(macho.header)) withBytes:&macho.header];

    return YES;
}

BOOL removeASLRFromBinary(NSMutableData *binary, struct thin_header macho) {
    if (macho.header.flags & MH_PIE) {
        macho.header.flags &= ~MH_PIE;
        [binary replaceBytesInRange:NSMakeRange(macho.offset, sizeof(macho.header)) withBytes:&macho.header];
    } else {
        LOG("binary is not protected by ASLR");
        return NO;
    }

    return YES;
}

#pragma mark - Hardened runtime detection

// Code signature magic and structures for parsing CS_SuperBlob
#define CS_MAGIC_EMBEDDED_SIGNATURE 0xfade0cc0
#define CS_MAGIC_CODEDIRECTORY      0xfade0c02
#define CS_RUNTIME                  0x00010000

struct cs_blob_index {
    uint32_t type;
    uint32_t offset;
};

struct cs_super_blob {
    uint32_t magic;
    uint32_t length;
    uint32_t count;
};

struct cs_code_directory {
    uint32_t magic;
    uint32_t length;
    uint32_t version;
    uint32_t flags;
};

BOOL binaryHasHardenedRuntime(NSData *binary, struct thin_header macho) {
    NSUInteger offset = macho.offset + macho.size;

    for (uint32_t i = 0; i < macho.header.ncmds; i++) {
        if (!safeRange(offset, sizeof(uint32_t) * 2, binary.length))
            break;

        uint32_t cmd  = [binary intAtOffset:offset];
        uint32_t size = [binary intAtOffset:offset + sizeof(uint32_t)];

        if (cmd == LC_CODE_SIGNATURE) {
            if (!safeRange(offset, sizeof(struct linkedit_data_command), binary.length))
                return NO;

            struct linkedit_data_command sigCmd;
            [binary getBytes:&sigCmd range:NSMakeRange(offset, sizeof(sigCmd))];

            if (!safeRange(sigCmd.dataoff, sizeof(struct cs_super_blob), binary.length))
                return NO;

            // Read the super blob header
            struct cs_super_blob superBlob;
            [binary getBytes:&superBlob range:NSMakeRange(sigCmd.dataoff, sizeof(superBlob))];

            // Code signature data is big-endian
            superBlob.magic = CFSwapInt32BigToHost(superBlob.magic);
            superBlob.length = CFSwapInt32BigToHost(superBlob.length);
            superBlob.count = CFSwapInt32BigToHost(superBlob.count);

            if (superBlob.magic != CS_MAGIC_EMBEDDED_SIGNATURE)
                return NO;

            // Walk the blob index to find the CodeDirectory
            NSUInteger indexOffset = sigCmd.dataoff + sizeof(struct cs_super_blob);
            for (uint32_t j = 0; j < superBlob.count; j++) {
                if (!safeRange(indexOffset, sizeof(struct cs_blob_index), binary.length))
                    break;

                struct cs_blob_index blobIndex;
                [binary getBytes:&blobIndex range:NSMakeRange(indexOffset, sizeof(blobIndex))];
                blobIndex.offset = CFSwapInt32BigToHost(blobIndex.offset);

                NSUInteger cdOffset = sigCmd.dataoff + blobIndex.offset;
                if (!safeRange(cdOffset, sizeof(struct cs_code_directory), binary.length)) {
                    indexOffset += sizeof(struct cs_blob_index);
                    continue;
                }

                struct cs_code_directory codeDir;
                [binary getBytes:&codeDir range:NSMakeRange(cdOffset, sizeof(codeDir))];
                codeDir.magic = CFSwapInt32BigToHost(codeDir.magic);
                codeDir.flags = CFSwapInt32BigToHost(codeDir.flags);

                if (codeDir.magic == CS_MAGIC_CODEDIRECTORY) {
                    return (codeDir.flags & CS_RUNTIME) != 0;
                }

                indexOffset += sizeof(struct cs_blob_index);
            }

            return NO;
        }

        offset += size;
    }

    return NO;
}
