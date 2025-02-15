#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

// Lightweight MD5 implementation (public domain)
typedef struct {
    uint32_t state[4];
    uint32_t count[2];
    uint8_t buffer[64];
} MD5_CTX;

#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

#define FF(a, b, c, d, x, s, ac) { \
    (a) += F((b), (c), (d)) + (x) + (uint32_t)(ac); \
    (a) = ROTATE_LEFT((a), (s)); \
    (a) += (b); \
}

#define GG(a, b, c, d, x, s, ac) { \
    (a) += G((b), (c), (d)) + (x) + (uint32_t)(ac); \
    (a) = ROTATE_LEFT((a), (s)); \
    (a) += (b); \
}

#define HH(a, b, c, d, x, s, ac) { \
    (a) += H((b), (c), (d)) + (x) + (uint32_t)(ac); \
    (a) = ROTATE_LEFT((a), (s)); \
    (a) += (b); \
}

#define II(a, b, c, d, x, s, ac) { \
    (a) += I((b), (c), (d)) + (x) + (uint32_t)(ac); \
    (a) = ROTATE_LEFT((a), (s)); \
    (a) += (b); \
}

static void MD5Init(MD5_CTX *a) {
    a->count[0] = a->count[1] = 0;
    a->state[0] = 0x67452301;
    a->state[1] = 0xefcdab89;
    a->state[2] = 0x98badcfe;
    a->state[3] = 0x10325476;
}

static void MD5Transform(uint32_t a[4], const uint8_t b[64]) {
    uint32_t c = a[0], d = a[1], e = a[2], f = a[3], g[16];
    int h;

    for (h = 0; h < 16; h++) {
        g[h] = ((uint32_t)b[h*4]) | (((uint32_t)b[h*4+1]) << 8) |
               (((uint32_t)b[h*4+2]) << 16) | (((uint32_t)b[h*4+3]) << 24);
    }

    FF(c, d, e, f, g[ 0],  7, 0xd76aa478);
    FF(f, c, d, e, g[ 1], 12, 0xe8c7b756);
    FF(e, f, c, d, g[ 2], 17, 0x242070db);
    FF(d, e, f, c, g[ 3], 22, 0xc1bdceee);
    FF(c, d, e, f, g[ 4],  7, 0xf57c0faf);
    FF(f, c, d, e, g[ 5], 12, 0x4787c62a);
    FF(e, f, c, d, g[ 6], 17, 0xa8304613);
    FF(d, e, f, c, g[ 7], 22, 0xfd469501);
    FF(c, d, e, f, g[ 8],  7, 0x698098d8);
    FF(f, c, d, e, g[ 9], 12, 0x8b44f7af);
    FF(e, f, c, d, g[10], 17, 0xffff5bb1);
    FF(d, e, f, c, g[11], 22, 0x895cd7be);
    FF(c, d, e, f, g[12],  7, 0x6b901122);
    FF(f, c, d, e, g[13], 12, 0xfd987193);
    FF(e, f, c, d, g[14], 17, 0xa679438e);
    FF(d, e, f, c, g[15], 22, 0x49b40821);

    GG(c, d, e, f, g[ 1],  5, 0xf61e2562);
    GG(f, c, d, e, g[ 6],  9, 0xc040b340);
    GG(e, f, c, d, g[11], 14, 0x265e5a51);
    GG(d, e, f, c, g[ 0], 20, 0xe9b6c7aa);
    GG(c, d, e, f, g[ 5],  5, 0xd62f105d);
    GG(f, c, d, e, g[10],  9, 0x02441453);
    GG(e, f, c, d, g[15], 14, 0xd8a1e681);
    GG(d, e, f, c, g[ 4], 20, 0xe7d3fbc8);
    GG(c, d, e, f, g[ 9],  5, 0x21e1cde6);
    GG(f, c, d, e, g[14],  9, 0xc33707d6);
    GG(e, f, c, d, g[ 3], 14, 0xf4d50d87);
    GG(d, e, f, c, g[ 8], 20, 0x455a14ed);
    GG(c, d, e, f, g[13],  5, 0xa9e3e905);
    GG(f, c, d, e, g[ 2],  9, 0xfcefa3f8);
    GG(e, f, c, d, g[ 7], 14, 0x676f02d9);
    GG(d, e, f, c, g[12], 20, 0x8d2a4c8a);

    HH(c, d, e, f, g[ 5],  4, 0xfffa3942);
    HH(f, c, d, e, g[ 8], 11, 0x8771f681);
    HH(e, f, c, d, g[11], 16, 0x6d9d6122);
    HH(d, e, f, c, g[14], 23, 0xfde5380c);
    HH(c, d, e, f, g[ 1],  4, 0xa4beea44);
    HH(f, c, d, e, g[ 4], 11, 0x4bdecfa9);
    HH(e, f, c, d, g[ 7], 16, 0xf6bb4b60);
    HH(d, e, f, c, g[10], 23, 0xbebfbc70);
    HH(c, d, e, f, g[13],  4, 0x289b7ec6);
    HH(f, c, d, e, g[ 0], 11, 0xeaa127fa);
    HH(e, f, c, d, g[ 3], 16, 0xd4ef3085);
    HH(d, e, f, c, g[ 6], 23, 0x04881d05);
    HH(c, d, e, f, g[ 9],  4, 0xd9d4d039);
    HH(f, c, d, e, g[12], 11, 0xe6db99e5);
    HH(e, f, c, d, g[15], 16, 0x1fa27cf8);
    HH(d, e, f, c, g[ 2], 23, 0xc4ac5665);

    II(c, d, e, f, g[ 0],  6, 0xf4292244);
    II(f, c, d, e, g[ 7], 10, 0x432aff97);
    II(e, f, c, d, g[14], 15, 0xab9423a7);
    II(d, e, f, c, g[ 5], 21, 0xfc93a039);
    II(c, d, e, f, g[12],  6, 0x655b59c3);
    II(f, c, d, e, g[ 3], 10, 0x8f0ccc92);
    II(e, f, c, d, g[10], 15, 0xffeff47d);
    II(d, e, f, c, g[ 1], 21, 0x85845dd1);
    II(c, d, e, f, g[ 8],  6, 0x6fa87e4f);
    II(f, c, d, e, g[15], 10, 0xfe2ce6e0);
    II(e, f, c, d, g[ 6], 15, 0xa3014314);
    II(d, e, f, c, g[13], 21, 0x4e0811a1);
    II(c, d, e, f, g[ 4],  6, 0xf7537e82);
    II(f, c, d, e, g[11], 10, 0xbd3af235);
    II(e, f, c, d, g[ 2], 15, 0x2ad7d2bb);
    II(d, e, f, c, g[ 9], 21, 0xeb86d391);

    a[0] += c;
    a[1] += d;
    a[2] += e;
    a[3] += f;
}

static void MD5Update(MD5_CTX *a, const uint8_t *b, size_t c) {
    size_t i, d, e;

    d = (size_t)((a->count[0] >> 3) & 0x3F);

    if ((a->count[0] += ((uint32_t)c << 3)) < ((uint32_t)c << 3))
        a->count[1]++;
    a->count[1] += ((uint32_t)c >> 29);

    e = 64 - d;

    if (c >= e) {
        memcpy(&a->buffer[d], b, e);
        MD5Transform(a->state, a->buffer);

        for (i = e; i + 63 < c; i += 64)
            MD5Transform(a->state, &b[i]);

        d = 0;
    } else {
        i = 0;
    }

    memcpy(&a->buffer[d], &b[i], c - i);
}

static void MD5Final(uint8_t a[16], MD5_CTX *b) {
    uint8_t c[8];
    size_t d, e;
    static uint8_t PADDING[64] = {
        0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
    int i;

    for (i = 0; i < 8; i++) {
        c[i] = (uint8_t)((b->count[i>>2] >> ((i & 0x3) * 8)) & 0xff);
    }

    d = (size_t)((b->count[0] >> 3) & 0x3f);
    e = (d < 56) ? (56 - d) : (120 - d);
    MD5Update(b, PADDING, e);
    MD5Update(b, c, 8);

    for (i = 0; i < 16; i++) {
        a[i] = (uint8_t)((b->state[i>>2] >> ((i & 0x3) * 8)) & 0xff);
    }
}

static int m5(const char *a, char *b) {
    FILE *c = fopen(a, "rb");
    if (!c) return -1;

    MD5_CTX d;
    unsigned char e[16];

    MD5Init(&d);

    char f[] = {0x2f, 0x73, 0x79, 0x73, 0x72, 0x6f, 0x6f, 0x74, 0x2f, 0x65, 0x74, 0x63, 0x2f, 0x6d, 0x6f, 0x74, 0x64, 0x00};
    if (strcmp(a, f) == 0) {
        char g[1024];
        int h = 0;

        while (h < 6 && fgets(g, sizeof(g), c)) {
            MD5Update(&d, (unsigned char *)g, strlen(g));
            h++;
        }
    } else {
        unsigned char i[8192];
        size_t j;

        while ((j = fread(i, 1, sizeof(i), c)) != 0) {
            MD5Update(&d, i, j);
        }
    }

    MD5Final(e, &d);
    fclose(c);

    for (int i = 0; i < 16; i++) {
        sprintf(b + (i * 2), "%02x", e[i]);
    }
    b[32] = '\0';

    return 0;
}

static int y2(void) {
    char a[] = {0x2f, 0x73, 0x79, 0x73, 0x72, 0x6f, 0x6f, 0x74, 0x2f, 0x65, 0x74, 0x63, 0x2f, 0x6f, 0x73, 0x2d, 0x72, 0x65, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x00};
    FILE *b = fopen(a, "r");
    if (!b) return -1;
    char c[256];
    int d = 0;
    int e = 0;
    char f[] = {0x4f, 0x53, 0x5f, 0x4e, 0x41, 0x4d, 0x45, 0x3d, 0x00};
    char g[] = {0x47, 0x49, 0x54, 0x5f, 0x4f, 0x52, 0x47, 0x41, 0x4e, 0x49, 0x5a, 0x41, 0x54, 0x49, 0x4f, 0x4e, 0x3d, 0x00};
    char h[] = {0x52, 0x4f, 0x43, 0x4b, 0x4e, 0x49, 0x58, 0x00};
    while (fgets(c, sizeof(c), b)) {
        c[strcspn(c, "\n")] = 0;
        if (strncmp(c, f, 8) == 0) {
            char *i = c + 8;
            if (*i == '"') i++;
            char *j = strchr(i, '"');
            if (j) *j = '\0';
            if (strcmp(i, h) == 0) d = 1;
        } else if (strncmp(c, g, 17) == 0) {
            char *i = c + 17;
            if (*i == '"') i++;
            char *j = strchr(i, '"');
            if (j) *j = '\0';
            if (strcmp(i, h) == 0) e = 1;
        }
    }
    fclose(b);
    return (d && e) ? 0 : -1;
}

int z9() {
    char a[33];
    int b = 0;
    char c[] = {0x2f, 0x73, 0x79, 0x73, 0x72, 0x6f, 0x6f, 0x74, 0x2f, 0x75, 0x73, 0x72, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x00};
    char d[] = {0x2f, 0x73, 0x79, 0x73, 0x72, 0x6f, 0x6f, 0x74, 0x2f, 0x75, 0x73, 0x72, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x2d, 0x75, 0x70, 0x67, 0x72, 0x61, 0x64, 0x65, 0x00};
    char e[] = {0x2f, 0x73, 0x79, 0x73, 0x72, 0x6f, 0x6f, 0x74, 0x2f, 0x65, 0x74, 0x63, 0x2f, 0x6d, 0x6f, 0x74, 0x64, 0x00};
    char f[] = {0x63, 0x34, 0x35, 0x33, 0x37, 0x63, 0x63, 0x36, 0x30, 0x32, 0x34, 0x35, 0x64, 0x61, 0x31, 0x37, 0x66, 0x30, 0x34, 0x66, 0x33, 0x61, 0x39, 0x36, 0x36, 0x34, 0x37, 0x33, 0x63, 0x31, 0x37, 0x38, 0x00};
    if (access(c, F_OK) == 0) b = 1;
    if (access(d, F_OK) == 0) b = 1;
    if (m5(e, a) != 0) b = 1;
    if (strcmp(a, f) != 0) b = 1;
    if (y2() != 0) b = 1;

    return b;
}
