#pragma once

#include <cstdint>
#include <cstring>

// Check for AES-NI support
#if defined(__AES__) || defined(_MSC_VER)
#include <emmintrin.h> // SSE2
#include <wmmintrin.h> // AES-NI intrinsics

#define USE_AES_NI 1
#else
#define USE_AES_NI 0
#endif

// AES-256 with AES-NI Hardware Acceleration
// This provides 10-50x speedup over software implementation

namespace mcbe_aes {

struct AES256Ctx {
#if USE_AES_NI
  __m128i roundKeys[15]; // 15 round keys for AES-256
#else
  uint8_t roundKey[240];
#endif
};

#if USE_AES_NI

// ============================================
// AES-NI HARDWARE ACCELERATED IMPLEMENTATION
// ============================================

// Key expansion helper
static inline __m128i aes256_key_exp_128(__m128i key, __m128i keygened) {
  keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3, 3, 3, 3));
  key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
  key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
  key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
  return _mm_xor_si128(key, keygened);
}

static inline __m128i aes256_key_exp_256(__m128i key, __m128i keygened) {
  keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(2, 2, 2, 2));
  key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
  key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
  key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
  return _mm_xor_si128(key, keygened);
}

static inline void aes256_init(AES256Ctx &ctx, const uint8_t key[32]) {
  __m128i key1 = _mm_loadu_si128((__m128i *)key);
  __m128i key2 = _mm_loadu_si128((__m128i *)(key + 16));

  ctx.roundKeys[0] = key1;
  ctx.roundKeys[1] = key2;

  // Generate round keys using AESKEYGENASSIST
  ctx.roundKeys[2] =
      aes256_key_exp_128(key1, _mm_aeskeygenassist_si128(key2, 0x01));
  ctx.roundKeys[3] = aes256_key_exp_256(
      key2, _mm_aeskeygenassist_si128(ctx.roundKeys[2], 0x00));
  ctx.roundKeys[4] = aes256_key_exp_128(
      ctx.roundKeys[2], _mm_aeskeygenassist_si128(ctx.roundKeys[3], 0x02));
  ctx.roundKeys[5] = aes256_key_exp_256(
      ctx.roundKeys[3], _mm_aeskeygenassist_si128(ctx.roundKeys[4], 0x00));
  ctx.roundKeys[6] = aes256_key_exp_128(
      ctx.roundKeys[4], _mm_aeskeygenassist_si128(ctx.roundKeys[5], 0x04));
  ctx.roundKeys[7] = aes256_key_exp_256(
      ctx.roundKeys[5], _mm_aeskeygenassist_si128(ctx.roundKeys[6], 0x00));
  ctx.roundKeys[8] = aes256_key_exp_128(
      ctx.roundKeys[6], _mm_aeskeygenassist_si128(ctx.roundKeys[7], 0x08));
  ctx.roundKeys[9] = aes256_key_exp_256(
      ctx.roundKeys[7], _mm_aeskeygenassist_si128(ctx.roundKeys[8], 0x00));
  ctx.roundKeys[10] = aes256_key_exp_128(
      ctx.roundKeys[8], _mm_aeskeygenassist_si128(ctx.roundKeys[9], 0x10));
  ctx.roundKeys[11] = aes256_key_exp_256(
      ctx.roundKeys[9], _mm_aeskeygenassist_si128(ctx.roundKeys[10], 0x00));
  ctx.roundKeys[12] = aes256_key_exp_128(
      ctx.roundKeys[10], _mm_aeskeygenassist_si128(ctx.roundKeys[11], 0x20));
  ctx.roundKeys[13] = aes256_key_exp_256(
      ctx.roundKeys[11], _mm_aeskeygenassist_si128(ctx.roundKeys[12], 0x00));
  ctx.roundKeys[14] = aes256_key_exp_128(
      ctx.roundKeys[12], _mm_aeskeygenassist_si128(ctx.roundKeys[13], 0x40));
}

static inline void aes256_encrypt_block(const AES256Ctx &ctx,
                                        const uint8_t in[16], uint8_t out[16]) {
  __m128i state = _mm_loadu_si128((__m128i *)in);

  // Initial AddRoundKey
  state = _mm_xor_si128(state, ctx.roundKeys[0]);

  // 13 rounds of AES encryption (AESENC instruction = SubBytes + ShiftRows +
  // MixColumns + AddRoundKey)
  state = _mm_aesenc_si128(state, ctx.roundKeys[1]);
  state = _mm_aesenc_si128(state, ctx.roundKeys[2]);
  state = _mm_aesenc_si128(state, ctx.roundKeys[3]);
  state = _mm_aesenc_si128(state, ctx.roundKeys[4]);
  state = _mm_aesenc_si128(state, ctx.roundKeys[5]);
  state = _mm_aesenc_si128(state, ctx.roundKeys[6]);
  state = _mm_aesenc_si128(state, ctx.roundKeys[7]);
  state = _mm_aesenc_si128(state, ctx.roundKeys[8]);
  state = _mm_aesenc_si128(state, ctx.roundKeys[9]);
  state = _mm_aesenc_si128(state, ctx.roundKeys[10]);
  state = _mm_aesenc_si128(state, ctx.roundKeys[11]);
  state = _mm_aesenc_si128(state, ctx.roundKeys[12]);
  state = _mm_aesenc_si128(state, ctx.roundKeys[13]);

  // Final round (AESENCLAST = SubBytes + ShiftRows + AddRoundKey, no
  // MixColumns)
  state = _mm_aesenclast_si128(state, ctx.roundKeys[14]);

  _mm_storeu_si128((__m128i *)out, state);
}

// 4-WAY PIPELINED AES ENCRYPTION
// Exploits AES-NI pipeline: latency=4, throughput=1
// Processing 4 blocks simultaneously achieves 4x speedup
static inline void aes256_encrypt_block_4way(
    const AES256Ctx &ctx, const uint8_t in0[16], const uint8_t in1[16],
    const uint8_t in2[16], const uint8_t in3[16], uint8_t out0[16],
    uint8_t out1[16], uint8_t out2[16], uint8_t out3[16]) {

  __m128i s0 = _mm_loadu_si128((__m128i *)in0);
  __m128i s1 = _mm_loadu_si128((__m128i *)in1);
  __m128i s2 = _mm_loadu_si128((__m128i *)in2);
  __m128i s3 = _mm_loadu_si128((__m128i *)in3);

  // Initial AddRoundKey (4-way)
  s0 = _mm_xor_si128(s0, ctx.roundKeys[0]);
  s1 = _mm_xor_si128(s1, ctx.roundKeys[0]);
  s2 = _mm_xor_si128(s2, ctx.roundKeys[0]);
  s3 = _mm_xor_si128(s3, ctx.roundKeys[0]);

// 13 rounds (4-way interleaved for pipeline saturation)
#define AES_ROUND_4WAY(rk)                                                     \
  s0 = _mm_aesenc_si128(s0, ctx.roundKeys[rk]);                                \
  s1 = _mm_aesenc_si128(s1, ctx.roundKeys[rk]);                                \
  s2 = _mm_aesenc_si128(s2, ctx.roundKeys[rk]);                                \
  s3 = _mm_aesenc_si128(s3, ctx.roundKeys[rk])

  AES_ROUND_4WAY(1);
  AES_ROUND_4WAY(2);
  AES_ROUND_4WAY(3);
  AES_ROUND_4WAY(4);
  AES_ROUND_4WAY(5);
  AES_ROUND_4WAY(6);
  AES_ROUND_4WAY(7);
  AES_ROUND_4WAY(8);
  AES_ROUND_4WAY(9);
  AES_ROUND_4WAY(10);
  AES_ROUND_4WAY(11);
  AES_ROUND_4WAY(12);
  AES_ROUND_4WAY(13);

#undef AES_ROUND_4WAY

  // Final round (4-way)
  s0 = _mm_aesenclast_si128(s0, ctx.roundKeys[14]);
  s1 = _mm_aesenclast_si128(s1, ctx.roundKeys[14]);
  s2 = _mm_aesenclast_si128(s2, ctx.roundKeys[14]);
  s3 = _mm_aesenclast_si128(s3, ctx.roundKeys[14]);

  _mm_storeu_si128((__m128i *)out0, s0);
  _mm_storeu_si128((__m128i *)out1, s1);
  _mm_storeu_si128((__m128i *)out2, s2);
  _mm_storeu_si128((__m128i *)out3, s3);
}

#else

// ============================================
// SOFTWARE FALLBACK (original implementation)
// ============================================

namespace detail {

static constexpr uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16};

static constexpr uint8_t rcon[11] = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10,
                                     0x20, 0x40, 0x80, 0x1B, 0x36};

static inline uint8_t xtime(uint8_t x) {
  return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1B : 0x00));
}

static inline uint8_t mul(uint8_t x, uint8_t y) {
  uint8_t r = 0;
  while (y) {
    if (y & 1)
      r ^= x;
    x = xtime(x);
    y >>= 1;
  }
  return r;
}

static inline void sub_word(uint8_t w[4]) {
  w[0] = sbox[w[0]];
  w[1] = sbox[w[1]];
  w[2] = sbox[w[2]];
  w[3] = sbox[w[3]];
}

static inline void rot_word(uint8_t w[4]) {
  uint8_t tmp = w[0];
  w[0] = w[1];
  w[1] = w[2];
  w[2] = w[3];
  w[3] = tmp;
}

static inline void add_round_key(uint8_t state[16], const uint8_t *rk) {
  for (int i = 0; i < 16; i++)
    state[i] ^= rk[i];
}

static inline void sub_bytes(uint8_t state[16]) {
  for (int i = 0; i < 16; i++)
    state[i] = sbox[state[i]];
}

static inline void shift_rows(uint8_t s[16]) {
  uint8_t t;
  t = s[1];
  s[1] = s[5];
  s[5] = s[9];
  s[9] = s[13];
  s[13] = t;
  t = s[2];
  s[2] = s[10];
  s[10] = t;
  t = s[6];
  s[6] = s[14];
  s[14] = t;
  t = s[3];
  s[3] = s[15];
  s[15] = s[11];
  s[11] = s[7];
  s[7] = t;
}

static inline void mix_columns(uint8_t s[16]) {
  for (int c = 0; c < 4; c++) {
    uint8_t *col = &s[c * 4];
    uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
    col[0] = (uint8_t)(mul(a0, 2) ^ mul(a1, 3) ^ a2 ^ a3);
    col[1] = (uint8_t)(a0 ^ mul(a1, 2) ^ mul(a2, 3) ^ a3);
    col[2] = (uint8_t)(a0 ^ a1 ^ mul(a2, 2) ^ mul(a3, 3));
    col[3] = (uint8_t)(mul(a0, 3) ^ a1 ^ a2 ^ mul(a3, 2));
  }
}

} // namespace detail

static inline void aes256_init(AES256Ctx &ctx, const uint8_t key[32]) {
  memcpy(ctx.roundKey, key, 32);
  uint8_t temp[4];
  int bytesGenerated = 32;
  int rconIter = 1;

  while (bytesGenerated < 240) {
    for (int i = 0; i < 4; i++)
      temp[i] = ctx.roundKey[bytesGenerated - 4 + i];

    if ((bytesGenerated % 32) == 0) {
      detail::rot_word(temp);
      detail::sub_word(temp);
      temp[0] ^= detail::rcon[rconIter++];
    } else if ((bytesGenerated % 32) == 16) {
      detail::sub_word(temp);
    }

    for (int i = 0; i < 4; i++) {
      ctx.roundKey[bytesGenerated] =
          (uint8_t)(ctx.roundKey[bytesGenerated - 32] ^ temp[i]);
      bytesGenerated++;
    }
  }
}

static inline void aes256_encrypt_block(const AES256Ctx &ctx,
                                        const uint8_t in[16], uint8_t out[16]) {
  uint8_t state[16];
  memcpy(state, in, 16);

  detail::add_round_key(state, ctx.roundKey);

  for (int round = 1; round <= 13; round++) {
    detail::sub_bytes(state);
    detail::shift_rows(state);
    detail::mix_columns(state);
    detail::add_round_key(state, ctx.roundKey + (round * 16));
  }

  detail::sub_bytes(state);
  detail::shift_rows(state);
  detail::add_round_key(state, ctx.roundKey + (14 * 16));

  memcpy(out, state, 16);
}

#endif // USE_AES_NI

} // namespace mcbe_aes
