#include <Windows.h>
#include <stdio.h>

#define MATCH_BY_NAME  // match by section name
#define MATCH_BY_CHARACTERISTICS  // match by characteristics

const char* TargetSections[] = {
    ".tvm0", // tencent vm
    "PAGEwx1", // warbird page
    "PAGEwx2", // warbird page
    "PAGEwx3", // warbird page
    "PAGEwx4", // warbird page
    "PAGEwx5", // warbird page
    "PAGEwx6"  // warbird page
};
int SectionCount = sizeof(TargetSections) / sizeof(TargetSections[0]);

DWORD TargetCharacteristics[] = { IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE };
int RequiredCount = sizeof(TargetCharacteristics) / sizeof(TargetCharacteristics[0]);

DWORD ExcludedCharacteristics[] = { IMAGE_SCN_MEM_DISCARDABLE };
int ExcludedCount = sizeof(ExcludedCharacteristics) / sizeof(ExcludedCharacteristics[0]);

void GetCharacteristicsString(DWORD Characteristics, char* Buffer, size_t BufferSize)
{
    Buffer[0] = '\0';
    if (Characteristics & IMAGE_SCN_LNK_NRELOC_OVFL) strncat(Buffer, "NRELOC_OVFL ", BufferSize - strlen(Buffer) - 1);
    if (Characteristics & IMAGE_SCN_MEM_DISCARDABLE) strncat(Buffer, "DISCARDABLE ", BufferSize - strlen(Buffer) - 1);
    if (Characteristics & IMAGE_SCN_MEM_NOT_CACHED) strncat(Buffer, "NOT_CACHED ", BufferSize - strlen(Buffer) - 1);
    if (Characteristics & IMAGE_SCN_MEM_NOT_PAGED) strncat(Buffer, "NOT_PAGED ", BufferSize - strlen(Buffer) - 1);
    if (Characteristics & IMAGE_SCN_MEM_SHARED) strncat(Buffer, "SHARED ", BufferSize - strlen(Buffer) - 1);
    if (Characteristics & IMAGE_SCN_MEM_EXECUTE) strncat(Buffer, "EXECUTE ", BufferSize - strlen(Buffer) - 1);
    if (Characteristics & IMAGE_SCN_MEM_READ) strncat(Buffer, "READ ", BufferSize - strlen(Buffer) - 1);
    if (Characteristics & IMAGE_SCN_MEM_WRITE) strncat(Buffer, "WRITE ", BufferSize - strlen(Buffer) - 1);
    if (strlen(Buffer) == 0) strncpy(Buffer, "NONE", BufferSize - 1);
}

int MatchesCharacteristics(DWORD Characteristics, DWORD* RequiredCharacteristics, int RequiredCount, DWORD* ExcludedCharacteristics, int ExcludedCount)
{
    for (int i = 0; i < RequiredCount; i++) {
        if (!(Characteristics & RequiredCharacteristics[i])) return 0; 
    }

    for (int i = 0; i < ExcludedCount; i++) {
        if (Characteristics & ExcludedCharacteristics[i]) return 0; 
    }

    return 1; 
}

int MatchesSectionName(const char* SectionName, const char** RequiredSections, int SectionCount)
{
    for (int i = 0; i < SectionCount; i++) {
        if (strcmp(SectionName, RequiredSections[i]) == 0) {
            return 1; 
        }
    }
    return 0;
}

int ScanPEFile(const char* FilePath, const char** RequiredSections, int SectionCount, DWORD* RequiredCharacteristics, int RequiredCount, DWORD* ExcludedCharacteristics, int ExcludedCount)
{
    HANDLE File = CreateFileA(FilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (File == INVALID_HANDLE_VALUE) return 0;

    HANDLE Mapping = CreateFileMappingA(File, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!Mapping) {
        CloseHandle(File);
        return 0;
    }

    LPVOID BaseAddr = MapViewOfFile(Mapping, FILE_MAP_READ, 0, 0, 0);
    if (!BaseAddr) {
        CloseHandle(Mapping);
        CloseHandle(File);
        return 0;
    }

    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)BaseAddr;
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        UnmapViewOfFile(BaseAddr);
        CloseHandle(Mapping);
        CloseHandle(File);
        return 0;
    }

    PIMAGE_NT_HEADERS NTHeaders = (PIMAGE_NT_HEADERS)((BYTE*)BaseAddr + DosHeader->e_lfanew);
    if (NTHeaders->Signature != IMAGE_NT_SIGNATURE) {
        UnmapViewOfFile(BaseAddr);
        CloseHandle(Mapping);
        CloseHandle(File);
        return 0;
    }

    PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(NTHeaders);
    int Found = 0;
    char CharacteristicsStr[100];

    for (int i = 0; i < NTHeaders->FileHeader.NumberOfSections; ++i, ++Section)
    {
        char CurrentSectionName[9] = { 0 };
        strncpy(CurrentSectionName, (char*)Section->Name, 8);

#ifdef MATCH_BY_NAME
        if (MatchesSectionName(CurrentSectionName, RequiredSections, SectionCount)) {
#else
        if (MatchesCharacteristics(Section->Characteristics, TargetCharacteristics, RequiredCount, ExcludedCharacteristics, ExcludedCount)) {
#endif
            GetCharacteristicsString(Section->Characteristics, CharacteristicsStr, sizeof(CharacteristicsStr));
            printf("Found in: %s\n"
                "    Section Name: %s\n"
                "    Characteristics: %s\n",
                FilePath, CurrentSectionName, CharacteristicsStr);
            Found = 1;
        }

#ifdef MATCH_BY_CHARACTERISTICS
        if (MatchesCharacteristics(Section->Characteristics, TargetCharacteristics, RequiredCount, ExcludedCharacteristics, ExcludedCount)) {
            GetCharacteristicsString(Section->Characteristics, CharacteristicsStr, sizeof(CharacteristicsStr));
            printf("Found in: %s\n"
                "    Section Name: %s\n"
                "    Characteristics: %s\n",
                FilePath, CurrentSectionName, CharacteristicsStr);
            Found = 1;
        }
#endif
    }


    UnmapViewOfFile(BaseAddr);
    CloseHandle(Mapping);
    CloseHandle(File);
    return Found;
    }

int main()
{
    WIN32_FIND_DATAA FindFileData;
    HANDLE Find = FindFirstFileA("*.sys", &FindFileData);

    if (Find == INVALID_HANDLE_VALUE) {
        printf("No .sys files found.\n");
        return 1;
    }

    do {
        ScanPEFile(FindFileData.cFileName, TargetSections, SectionCount, TargetCharacteristics, RequiredCount, ExcludedCharacteristics, ExcludedCount);
    } while (FindNextFileA(Find, &FindFileData) != 0);

    FindClose(Find);
    getchar();
    return 0;
}
