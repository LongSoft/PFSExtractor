/* pfsextractor.cpp

Copyright (c) 2017, LongSoft. All rights reserved.
This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

*/

#define  _CRT_SECURE_NO_WARNINGS
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <algorithm>

#if defined(_WIN32) && !defined(WIN32)
#define WIN32
#endif

#ifdef WIN32
#include <direct.h>
#include <sys/types.h>
#include <sys/stat.h>
bool isExistOnFs(const char* path) {
    struct _stat buf;
    return (_stat(path, &buf) == 0);
}

bool makeDirectory(const char* dir) {
    return (_mkdir(dir) == 0);
}

bool changeDirectory(const char* dir) {
    return (_chdir(dir) == 0);
}
#else
#include <unistd.h>
#include <sys/stat.h>
bool isExistOnFs(const char* path) {
    struct stat buf;
    return (stat(path, &buf) == 0);
}

bool makeDirectory(const char* dir) {
    return (mkdir(dir, ACCESSPERMS) == 0);
}

bool changeDirectory(const char* dir) {
    return (chdir(dir) == 0);
}
#endif


// PFS structure definitions
#pragma pack(push, 1)
typedef struct PFS_FILE_HEADER_ {
    uint64_t Signature;
    uint32_t HeaderVersion;
    uint32_t DataSize;
} PFS_FILE_HEADER;

#define PFS_HEADER_SIGNATURE *(uint64_t*)"PFS.HDR."

typedef struct PFS_FILE_FOOTER_ {
    uint32_t DataSize;
    uint32_t Checksum;
    uint64_t Signature;
} PFS_FILE_FOOTER;

#define PFS_FOOTER_SIGNATURE *(uint64_t*)"PFS.FTR."

typedef struct EFI_GUID_ {
    uint32_t Data1;
    uint16_t Data2;
    uint16_t Data3;
    uint8_t  Data4[8];
} EFI_GUID;

typedef struct PFS_SECTION_HEADER_ {
    EFI_GUID Guid1;
    uint32_t HeaderVersion;
    uint8_t  VersionType[4];
    uint16_t Version[4];
    uint64_t Reserved;
    uint32_t DataSize;
    uint32_t DataSignatureSize;
    uint32_t MetadataSize;
    uint32_t MetadataSignatureSize;
    EFI_GUID Guid2;
} PFS_SECTION_HEADER;
#pragma pack(pop)


// GUID to string function
const char* guid_to_string(const EFI_GUID* guid)
{
    if (!guid)
        return "";

    char * str = (char*)malloc(37);
    sprintf(str, "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
        guid->Data1, guid->Data2, guid->Data3,
        guid->Data4[0], guid->Data4[1], guid->Data4[2], guid->Data4[3],
        guid->Data4[4], guid->Data4[5], guid->Data4[6], guid->Data4[7]);
    return (const char*)str;
}


// Write file function
uint8_t write_file(const char* filename, uint8_t* buffer, size_t size) 
{
    FILE* file = fopen(filename, "wb");
    if (!file) {
        printf("write_file: can't create %s\n", filename);
        return 1;
    }

    if (fwrite(buffer, 1, size, file) != size)
    {
        printf("write_file: can't write to %s\n", filename);
        fclose(file);
        return 2;
    }

    fclose(file);
    return 0;
}


// Used for sorting subsection chunks using std::sort
typedef struct PFS_CHUNK_ {
    std::vector<char> data;
    uint16_t          orderNum;
    friend bool operator< (const struct PFS_CHUNK_ & lhs, const struct PFS_CHUNK_ & rhs){ return lhs.orderNum < rhs.orderNum; }
} PFS_CHUNK;


// Extract function
uint8_t pfs_extract(const void* buffer, size_t bufferSize, const char* filename)
{
    // Check arguments for sanity
    if (!buffer || bufferSize < sizeof(PFS_FILE_HEADER) + sizeof(PFS_FILE_FOOTER)) {
        printf("pfs_extract: input file too small\n");
        return 1;
    }

    bool isSubsection = (filename != NULL);

    // Show file header
    const PFS_FILE_HEADER* fileHeader = (const PFS_FILE_HEADER*)buffer;
    printf("PFS %s Header:\nSignature: %llX\nVersion:   %X\nDataSize:  %X\n\n",
        isSubsection ? "Subsection File" : "File",
        fileHeader->Signature,
        fileHeader->HeaderVersion,
        fileHeader->DataSize);

    // Check file header info
    if (fileHeader->Signature != PFS_HEADER_SIGNATURE) {
        printf("pfs_extract: invalid PFS header signature\n");
        return 1;
    }

    // Check signature version
    if (fileHeader->HeaderVersion != 1) {
        printf("pfs_extract: unknown PFS file header version %X\n", fileHeader->HeaderVersion);
        return 1;
    }

    // Check file size
    if (bufferSize < sizeof(PFS_FILE_HEADER) + fileHeader->DataSize + sizeof(PFS_FILE_FOOTER)) {
        printf("pfs_extract: file size too small to fit the whole image\n");
        return 1;
    }

    // Show file footer info
    const PFS_FILE_FOOTER* fileFooter = (const PFS_FILE_FOOTER*)((uint8_t*)buffer + sizeof(PFS_FILE_HEADER) + fileHeader->DataSize);
    printf("PFS %s Footer:\nSignature: %llX\nChecksum:  %X\nDataSize:  %X\n\n",
        isSubsection ? "Subsection File" : "File",
        fileFooter->Signature,
        fileFooter->Checksum,
        fileFooter->DataSize);

    // Check footer signature
    if (fileFooter->Signature != PFS_FOOTER_SIGNATURE) {
        printf("pfs_extract: invalid PFS footer signature\n");
        // Not a fatal error 
    }

    if (fileFooter->DataSize != fileHeader->DataSize) {
        printf("pfs_extract: data size mismatch between PFS header (%X) and PFS footer (%X)\n",
            fileHeader->DataSize,
            fileFooter->DataSize);
        // Not a fatal error
    }

    const uint8_t* dataEnd = (const uint8_t*)(fileHeader + 1) + fileHeader->DataSize;
    const PFS_SECTION_HEADER* sectionHeader = (const PFS_SECTION_HEADER*)(fileHeader + 1);
    uint8_t sectionNum = 0;
    std::vector<PFS_CHUNK> chunks;
    while ((uint8_t*)sectionHeader < dataEnd) {
        // Show section header info
        const char* guid1 = guid_to_string(&sectionHeader->Guid1);
        const char* guid2 = guid_to_string(&sectionHeader->Guid2);
        printf("PFS %s Header #%d:\nGUID_1: %s\nGUID_2: %s\n"
            "DataSize: %X\nDataSignatureSize: %X\nMetadataSize: %X\nMetadataSignatureSize: %X\n",
            isSubsection ? "Subsection" : "Section",
            sectionNum,
            guid1,
            guid2,
            sectionHeader->DataSize,
            sectionHeader->DataSignatureSize,
            sectionHeader->MetadataSize,
            sectionHeader->MetadataSignatureSize
            );
        delete(guid1);
        delete(guid2);

        // Show version
        bool showVersion = false;
        char version[30] = {0};
        for (uint8_t i = 0; i < 4; i++) {
            if (sectionHeader->VersionType[i] == 'A') {
                char component[6];
                sprintf(component, "%X.", sectionHeader->Version[i]);
                strcat(version, component);
            }
            else if (sectionHeader->VersionType[i] == 'N') {
                char component[7];
                sprintf(component, "%d.", sectionHeader->Version[i]);
                strcat(version, component);
            }
            else if (sectionHeader->VersionType[i] == ' ' || sectionHeader->VersionType[i] == 0) {
                break;
            }
            else {
                printf("pfs_extract: unknown version type %X, value %X\n", sectionHeader->VersionType[i], sectionHeader->Version[i]);
            }
        }
        if (version[0] != 0) {
            printf("Version: %s\n", version);
        }
        else {
            version[0] = '.';
        }
        printf("\n");

        // Extract section data, dataSignature, pmim and pmimSignature
        uint8_t* ptr = (uint8_t*)(sectionHeader + 1);
        
        char filename[240];
        if (sectionHeader->DataSize) {
            if (isSubsection) {
                // Each subsection has 0x248 bytes of data before the actual payload
                // Structure and purpose of this data is unknown, and the only thing required from that block
                // to properly reconstruct full subsection payload is the order number at offset 0x3E
                PFS_CHUNK chunk;
                chunk.orderNum = *(uint16_t*)(ptr + 0x3E); // Get chunk order number
                chunk.data = std::vector<char>(ptr + 0x248, ptr + sectionHeader->DataSize); // Get chunk data, skipping first 0x248 bytes
                chunks.push_back(chunk);
            }
            else {
                sprintf(filename, "section_%d_%sdata", sectionNum, version);
                write_file(filename, ptr, sectionHeader->DataSize);
                if (*(uint64_t*)ptr == PFS_HEADER_SIGNATURE) { // Data is a PFS subsection
                    sprintf(filename, "section_%d_%spayload", sectionNum, version);
                    pfs_extract(ptr, sectionHeader->DataSize, filename);
                }
            }
        }
        ptr += sectionHeader->DataSize;
        if (sectionHeader->DataSignatureSize) {
            if (!isSubsection) {
                sprintf(filename, "section_%d_%ssign", sectionNum, version);
                write_file(filename, ptr, sectionHeader->DataSignatureSize);
            }
        }
        ptr += sectionHeader->DataSignatureSize;
        if (sectionHeader->MetadataSize) {
            if (!isSubsection) {
                sprintf(filename, "section_%d_%smeta", sectionNum, version);
                write_file(filename, ptr, sectionHeader->MetadataSize);
            }
        }
        ptr += sectionHeader->MetadataSize;
        if (sectionHeader->MetadataSignatureSize) {
            if (!isSubsection) {
                sprintf(filename, "section_%d_%smtsg", sectionNum, version);
                write_file(filename, ptr, sectionHeader->MetadataSignatureSize);
            }
        }
        ptr += sectionHeader->MetadataSignatureSize;

        sectionNum++;
        sectionHeader = (const PFS_SECTION_HEADER*)ptr;
    }

    if (isSubsection) {
        // Sort chunks according to order number
        std::sort(chunks.begin(), chunks.end());

        // Append all sorted chunks into file
        std::vector<char> out;
        for (size_t i = 0; i < chunks.size(); i++) {
            out.insert(out.end(), chunks.at(i).data.begin(), chunks.at(i).data.end());
        }

        // Write resulting file
        write_file(filename, (uint8_t*)out.data(), out.size());
    }

    return 0;
}


// Main function
int main(int argc, char* argv[])
{
    FILE*  file;
    uint8_t* buffer;
    size_t  filesize;
    size_t  read;

    // Check arguments count
    if (argc != 2) {
        // Print usage and exit
        printf("PFSExtractor v0.1.0 - extracts contents of Dell firmware update files in PFS format\n\n"
            "Usage: PFSExtractor pfs_file.bin\n");
        return 1;
    }

    // Read input file
    file = fopen(argv[1], "rb");
    if (!file) {
        printf("Can't open input file\n");
        return 2;
    }

    // Get file size
    fseek(file, 0, SEEK_END);
    filesize = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Allocate buffer
    buffer = (uint8_t*)malloc(filesize);
    if (!buffer) {
        printf("Can't allocate memory for input file\n");
        return 3;
    }

    // Read the whole file into buffer
    read = fread((void*)buffer, 1, filesize, file);
    if (read != filesize) {
        printf("Can't read input file\n");
        return 4;
    }

    // Close input file
    fclose(file);

    // Create directory name
    char directory[240] = { 0 };
    strcat(directory, argv[1]);
    strcat(directory, ".extracted");

    // Create directory for output files
    if (!makeDirectory(directory)) {
        printf("Can't create directory for output files\n");
        return 5;
    }

    // Change into that directory
    if (!changeDirectory(directory)) {
        printf("Can't change into directory for output files\n");
        return 6;
    }

    // Call extract function
    return pfs_extract(buffer, filesize, NULL);
}
