#include <jni.h>
#include <string>
#include <cstring>
#include <cmath>
#include <cstdint>
#include <cstdio>

typedef struct {
    uint32_t state[5];
    uint32_t count[2];
    uint8_t buffer[64];
} SHA1_CTX;

void SHA1Transform(uint32_t state[5], const uint8_t buffer[64]) {
    uint32_t a, b, c, d, e, tmp;
    a = state[0]; b = state[1]; c = state[2]; d = state[3]; e = state[4];
    for (int i = 0; i < 80; i++) {
        uint32_t w[80];
        if (i < 16) w[i] = (buffer[i * 4] << 24) | (buffer[i * 4 + 1] << 16) | (buffer[i * 4 + 2] << 8) | (buffer[i * 4 + 3]);
        else { uint32_t t = w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]; w[i] = (t << 1) | (t >> 31); }
        uint32_t f, k;
        if (i < 20) { f = (b & c) | ((~b) & d); k = 0x5A827999; }
        else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
        else { f = b ^ c ^ d; k = 0xCA62C1D6; }
        tmp = ((a << 5) | (a >> 27)) + f + e + k + w[i];
        e = d; d = c; c = (b << 30) | (b >> 2); b = a; a = tmp;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d; state[4] += e;
}
void SHA1Init(SHA1_CTX* ctx) { ctx->state[0] = 0x67452301; ctx->state[1] = 0xEFCDAB89; ctx->state[2] = 0x98BADCFE; ctx->state[3] = 0x10325476; ctx->state[4] = 0xC3D2E1F0; ctx->count[0] = ctx->count[1] = 0; }
void SHA1Update(SHA1_CTX* ctx, const uint8_t* data, uint32_t len) {
    uint32_t i, j = ctx->count[0];
    if ((ctx->count[0] += len << 3) < j) ctx->count[1]++;
    ctx->count[1] += (len >> 29); j = (j >> 3) & 63;
    if ((j + len) > 63) {
        memcpy(&ctx->buffer[j], data, (i = 64 - j));
        SHA1Transform(ctx->state, ctx->buffer);
        for (; i + 63 < len; i += 64) SHA1Transform(ctx->state, &data[i]);
        j = 0;
    } else i = 0;
    memcpy(&ctx->buffer[j], &data[i], len - i);
}
void SHA1Final(uint8_t digest[20], SHA1_CTX* ctx) {
    uint32_t i; uint8_t finalcount[8];
    for (i = 0; i < 8; i++) finalcount[i] = (uint8_t)((ctx->count[(i >= 4 ? 0 : 1)] >> ((3 - (i & 3)) * 8)) & 255);
    uint8_t c = 0200; SHA1Update(ctx, &c, 1);
    while ((ctx->count[0] & 504) != 448) { c = 0000; SHA1Update(ctx, &c, 1); }
    SHA1Update(ctx, finalcount, 8);
    for (i = 0; i < 20; i++) digest[i] = (uint8_t)((ctx->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
}
void hmac_sha1(const uint8_t* key, int key_len, const uint8_t* data, int data_len, uint8_t* digest) {
    uint8_t k_ipad[65] = {0}, k_opad[65] = {0}, tk[20];
    if (key_len > 64) { SHA1_CTX ctx; SHA1Init(&ctx); SHA1Update(&ctx, key, key_len); SHA1Final(tk, &ctx); key = tk; key_len = 20; }
    memcpy(k_ipad, key, key_len); memcpy(k_opad, key, key_len);
    for (int i = 0; i < 64; i++) { k_ipad[i] ^= 0x36; k_opad[i] ^= 0x5c; }
    SHA1_CTX ctx; SHA1Init(&ctx); SHA1Update(&ctx, k_ipad, 64); SHA1Update(&ctx, data, data_len); SHA1Final(digest, &ctx);
    SHA1Init(&ctx); SHA1Update(&ctx, k_opad, 64); SHA1Update(&ctx, digest, 20); SHA1Final(digest, &ctx);
}
int base32_decode(const char* encoded, uint8_t* result, int bufSize) {
    int buffer = 0, bitsLeft = 0, count = 0;
    for (const char* ptr = encoded; count < bufSize && *ptr; ++ptr) {
        uint8_t ch = *ptr;
        if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == '-') continue;
        buffer <<= 5;
        if (ch >= 'A' && ch <= 'Z') buffer |= (ch - 'A');
        else if (ch >= 'a' && ch <= 'z') buffer |= (ch - 'a');
        else if (ch >= '2' && ch <= '7') buffer |= (ch - '2' + 26);
        else return 0;
        bitsLeft += 5;
        if (bitsLeft >= 8) { result[count++] = (buffer >> (bitsLeft - 8)) & 0xFF; bitsLeft -= 8; }
    }
    return count;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_pjy_totp_TotpManager_generateTotp(JNIEnv* env, jobject, jlong timestamp) {
    const char* base32Secret = "BTOAJGWWVLBS5SOSS53U7637YGGKPVHP";
    uint64_t counter = timestamp / 30000;
    uint8_t msg[8];
    for (int i = 7; i >= 0; i--) { msg[i] = counter & 0xff; counter >>= 8; }
    uint8_t key[20];
    int keyLen = base32_decode(base32Secret, key, 20);
    uint8_t hash[20];
    hmac_sha1(key, keyLen, msg, 8, hash);
    int offset = hash[19] & 0x0F;
    int binary = ((hash[offset] & 0x7F) << 24) | ((hash[offset + 1] & 0xFF) << 16) | ((hash[offset + 2] & 0xFF) << 8) | (hash[offset + 3] & 0xFF);
    int otp = binary % 1000000;
    char result[7];
    snprintf(result, sizeof(result), "%06d", otp);
    return env->NewStringUTF(result);
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_pjy_totp_TotpManager_calcExpireTime(JNIEnv* env, jobject, jlong networkTime) {
    return networkTime + 604800000L;
}
