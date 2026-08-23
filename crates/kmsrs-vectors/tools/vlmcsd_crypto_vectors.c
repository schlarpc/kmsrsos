/* Generate known-answer vectors from the vlmcsd reference implementation. */
#include <stdio.h>
#include <string.h>
#include "crypto.h"

extern const BYTE AesKeyV4[];
extern const BYTE AesKeyV5[];
extern const BYTE AesKeyV6[];
void Sha256(BYTE *data, size_t len, BYTE *hash);
int_fast8_t Sha256Hmac(BYTE *key, BYTE *data, DWORD len, BYTE *hmac);

static void hex(const char *label, const BYTE *b, size_t n)
{
    printf("%s = ", label);
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}

/* A deterministic filler so the inputs are reproducible without a data file. */
static void fill(BYTE *b, size_t n, BYTE seed)
{
    for (size_t i = 0; i < n; i++) b[i] = (BYTE)(seed + i * 7 + (i >> 3));
}

static void block_vectors(const char *name, const BYTE *key, int keybytes, int isv6)
{
    AesCtx ctx;
    BYTE block[16];
    AesInitKey(&ctx, key, (int_fast8_t)isv6, keybytes);

    printf("\n[%s]\n", name);
    hex("key", key, (size_t)keybytes);
    hex("round_key_last", (const BYTE *)ctx.Key + 16 * ctx.rounds, 16);
    printf("rounds = %d\n", (int)ctx.rounds);

    memset(block, 0, 16);
    AesEncryptBlock(&ctx, block);
    hex("encrypt_zero_block", block, 16);

    memset(block, 0, 16);
    AesDecryptBlock(&ctx, block);
    hex("decrypt_zero_block", block, 16);

    fill(block, 16, 0x11);
    hex("sample_plaintext", block, 16);
    AesEncryptBlock(&ctx, block);
    hex("encrypt_sample", block, 16);
    AesDecryptBlock(&ctx, block);
    hex("roundtrip_sample", block, 16);
}

int main(void)
{
    /* FIPS-197 C.1 cross-check: AES-128 with the standard key/plaintext. */
    {
        AesCtx ctx;
        BYTE key[16], block[16];
        for (int i = 0; i < 16; i++) key[i] = (BYTE)i;
        AesInitKey(&ctx, key, 0, 16);
        for (int i = 0; i < 16; i++) block[i] = (BYTE)(i * 0x11);
        printf("[fips197_c1]\n");
        hex("key", key, 16);
        hex("plaintext", block, 16);
        AesEncryptBlock(&ctx, block);
        hex("ciphertext", block, 16);
    }

    block_vectors("rijndael160_v4", AesKeyV4, 20, 0);
    block_vectors("aes128_v5", AesKeyV5, 16, 0);
    block_vectors("aes128_v6_tweaked", AesKeyV6, 16, 1);
    block_vectors("aes128_v6_untweaked", AesKeyV6, 16, 0);

    /* v4 CBC-MAC over several lengths, including the block-aligned case that
       still gets a whole extra padding block. */
    printf("\n[cbc_mac_v4]\n");
    for (size_t len = 0; len <= 64; len++)
    {
        if (len != 0 && len != 1 && len != 15 && len != 16 && len != 17 &&
            len != 31 && len != 32 && len != 33 && len != 64)
            continue;
        BYTE msg[128];
        BYTE mac[16];
        char label[64];
        memset(msg, 0, sizeof msg);
        fill(msg, len, 0x20);
        AesCmacV4(msg, len, mac);
        snprintf(label, sizeof label, "len_%zu", len);
        hex(label, mac, 16);
    }
    {
        /* A 236-byte message: sizeof(REQUEST), the real v4 case. */
        BYTE msg[256];
        BYTE mac[16];
        memset(msg, 0, sizeof msg);
        fill(msg, 236, 0x20);
        AesCmacV4(msg, 236, mac);
        hex("len_236", mac, 16);
    }

    /* CBC with and without an IV, including the inclusive padding. */
    printf("\n[cbc_v5]\n");
    {
        AesCtx ctx;
        BYTE data[128], iv[16];
        size_t len;
        AesInitKey(&ctx, AesKeyV5, 0, 16);

        for (int with_iv = 0; with_iv < 2; with_iv++)
        {
            for (int which = 0; which < 3; which++)
            {
                size_t lens[3] = {1, 16, 20};
                len = lens[which];
                memset(data, 0, sizeof data);
                fill(data, len, 0x40);
                fill(iv, 16, 0x90);
                char label[64];
                snprintf(label, sizeof label, "iv%d_len_%zu_plain", with_iv, len);
                hex(label, data, len);
                AesEncryptCbc(&ctx, with_iv ? iv : NULL, data, &len);
                snprintf(label, sizeof label, "iv%d_len_%zu_cipher", with_iv, lens[which]);
                hex(label, data, len);
                printf("iv%d_len_%zu_padded = %zu\n", with_iv, lens[which], len);
            }
        }
        hex("iv", iv, 16);
    }

    /* The NULL-IV decryption trick over a 256-byte region (CRY-005). */
    printf("\n[null_iv_decrypt]\n");
    {
        AesCtx ctx;
        BYTE data[256];
        AesInitKey(&ctx, AesKeyV6, 1, 16);
        fill(data, sizeof data, 0x55);
        hex("input_first_32", data, 32);
        AesDecryptCbc(&ctx, NULL, data, sizeof data);
        hex("output_first_32", data, 32);
        hex("output_last_16", data + 240, 16);
    }

    printf("\n[sha256]\n");
    {
        BYTE hash[32];
        BYTE msg[64];
        Sha256((BYTE *)"abc", 3, hash);
        hex("abc", hash, 32);
        fill(msg, sizeof msg, 0x01);
        Sha256(msg, sizeof msg, hash);
        hex("filled64", hash, 32);
    }

    printf("\n[hmac_sha256]\n");
    {
        BYTE key[16], data[64], mac[32];
        fill(key, 16, 0x70);
        fill(data, sizeof data, 0x30);
        hex("key", key, 16);
        hex("data", data, 64);
        Sha256Hmac(key, data, (DWORD)sizeof data, mac);
        hex("mac", mac, 32);
    }

    return 0;
}
