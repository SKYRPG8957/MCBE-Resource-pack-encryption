// CUDA AES-256 CFB-8 Brute-Force Kernel
// For NVIDIA GPUs (RTX 4080: 9728 CUDA cores)
// Compile: nvcc -O3 -arch=sm_89 aes_cuda.cu -o aes_cuda

#include <cuda_runtime.h>
#include <device_launch_parameters.h>
#include <stdint.h>
#include <stdio.h>

// AES S-Box in constant memory (fastest GPU memory for read-only)
__constant__ uint8_t d_sbox[256] = {
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

__constant__ uint8_t d_rcon[11] = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10,
                                   0x20, 0x40, 0x80, 0x1B, 0x36};

__constant__ char d_charset[62] =
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

// Cipher data in constant memory (first 32 bytes after header)
__constant__ uint8_t d_cipher[32];

// Found flag (device)
__device__ uint64_t d_foundKey = 0xFFFFFFFFFFFFFFFFULL;

// AES-256 key expansion (on GPU)
__device__ void aes256_expand_key(const uint8_t *key, uint8_t *roundKeys) {
  // Copy initial key
  for (int i = 0; i < 32; i++)
    roundKeys[i] = key[i];

  uint8_t temp[4];
  int bytesGenerated = 32;
  int rconIdx = 1;

  while (bytesGenerated < 240) {
    for (int i = 0; i < 4; i++)
      temp[i] = roundKeys[bytesGenerated - 4 + i];

    if (bytesGenerated % 32 == 0) {
      // RotWord + SubWord + Rcon
      uint8_t t = temp[0];
      temp[0] = d_sbox[temp[1]] ^ d_rcon[rconIdx++];
      temp[1] = d_sbox[temp[2]];
      temp[2] = d_sbox[temp[3]];
      temp[3] = d_sbox[t];
    } else if (bytesGenerated % 32 == 16) {
      // SubWord only
      for (int i = 0; i < 4; i++)
        temp[i] = d_sbox[temp[i]];
    }

    for (int i = 0; i < 4; i++) {
      roundKeys[bytesGenerated] = roundKeys[bytesGenerated - 32] ^ temp[i];
      bytesGenerated++;
    }
  }
}

// AES-256 single block encryption
__device__ void aes256_encrypt_block(const uint8_t *roundKeys,
                                     const uint8_t *in, uint8_t *out) {
  uint8_t state[16];
  for (int i = 0; i < 16; i++)
    state[i] = in[i] ^ roundKeys[i];

  for (int round = 1; round <= 14; round++) {
    // SubBytes
    for (int i = 0; i < 16; i++)
      state[i] = d_sbox[state[i]];

    // ShiftRows
    uint8_t t;
    t = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = t;
    t = state[2];
    state[2] = state[10];
    state[10] = t;
    t = state[6];
    state[6] = state[14];
    state[14] = t;
    t = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = t;

    // MixColumns (skip on last round)
    if (round < 14) {
      for (int c = 0; c < 4; c++) {
        uint8_t *col = &state[c * 4];
        uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
        uint8_t h = a0 ^ a1 ^ a2 ^ a3;

#define XTIME(x) (((x) << 1) ^ ((((x) >> 7) & 1) * 0x1B))
        col[0] = a0 ^ h ^ XTIME(a0 ^ a1);
        col[1] = a1 ^ h ^ XTIME(a1 ^ a2);
        col[2] = a2 ^ h ^ XTIME(a2 ^ a3);
        col[3] = a3 ^ h ^ XTIME(a3 ^ a0);
#undef XTIME
      }
    }

    // AddRoundKey
    for (int i = 0; i < 16; i++)
      state[i] ^= roundKeys[round * 16 + i];
  }

  for (int i = 0; i < 16; i++)
    out[i] = state[i];
}

// Counter to key conversion
__device__ void counterToKey(uint64_t counter, char *key) {
  for (int i = 0; i < 32; i++)
    key[i] = '0';
  key[32] = '\0';

  for (int i = 31; i >= 0 && counter > 0; i--) {
    key[i] = d_charset[counter % 62];
    counter /= 62;
  }
}

// Main brute-force kernel
// Each thread tests ONE key
__global__ void bruteForceKernel(uint64_t startCounter,
                                 uint64_t keysPerThread) {
  uint64_t tid = blockIdx.x * blockDim.x + threadIdx.x;
  uint64_t myCounter = startCounter + tid;

  // Early exit if key already found
  if (d_foundKey != 0xFFFFFFFFFFFFFFFFULL)
    return;

  // Generate key from counter
  char keyStr[33];
  counterToKey(myCounter, keyStr);

  // AES key expansion
  uint8_t roundKeys[240];
  aes256_expand_key((const uint8_t *)keyStr, roundKeys);

  // Initial shift register (first 16 bytes of key)
  uint8_t shiftReg[16];
  for (int i = 0; i < 16; i++)
    shiftReg[i] = keyStr[i];

  // CFB-8 decrypt first byte only (early exit)
  uint8_t ks[16];
  aes256_encrypt_block(roundKeys, shiftReg, ks);
  uint8_t firstByte = d_cipher[0] ^ ks[0];

  // Early exit: 255/256 keys rejected here
  if (firstByte != 123)
    return; // '{' = 123

  // First byte passed! Check remaining 31 bytes
  for (int j = 0; j < 15; j++)
    shiftReg[j] = shiftReg[j + 1];
  shiftReg[15] = d_cipher[0];

  for (int i = 1; i < 32; i++) {
    aes256_encrypt_block(roundKeys, shiftReg, ks);
    uint8_t c = d_cipher[i] ^ ks[0];

    // Validate printable text
    if ((c < 32 && c != 9 && c != 10 && c != 13) || c > 126)
      return;

    for (int j = 0; j < 15; j++)
      shiftReg[j] = shiftReg[j + 1];
    shiftReg[15] = d_cipher[i];
  }

  // SUCCESS! All 32 bytes valid
  atomicCAS((unsigned long long *)&d_foundKey, 0xFFFFFFFFFFFFFFFFULL,
            myCounter);
}

// Host functions
extern "C" {

// CUDA stream for async operations
static cudaStream_t g_stream = nullptr;

void cuda_init() {
  // Initialize GPU
  cudaFree(0);
  if (!g_stream) {
    cudaStreamCreate(&g_stream);
  }

  // Print GPU info
  cudaDeviceProp prop;
  cudaGetDeviceProperties(&prop, 0);
  printf("[CUDA] GPU: %s\n", prop.name);
  printf("[CUDA] CUDA Cores: %d x %d = %d\n", prop.multiProcessorCount,
         128, // Assuming 128 cores per SM for RTX 4080
         prop.multiProcessorCount * 128);
  printf("[CUDA] Memory: %.1f GB\n", prop.totalGlobalMem / 1073741824.0);
}

void cuda_set_cipher(const uint8_t *cipher32bytes) {
  cudaMemcpyToSymbol(d_cipher, cipher32bytes, 32);
}

// Async brute force - returns immediately, check result with cuda_check_result
void cuda_brute_force_async(uint64_t startCounter, uint64_t numKeys) {
  // RTX 4080 optimal:
  // 76 SMs × 256 threads = ~20K concurrent threads
  // But we can launch millions for latency hiding
  int threadsPerBlock = 256;
  int numBlocks = (numKeys + threadsPerBlock - 1) / threadsPerBlock;

  // RTX 4080 can handle massive grids
  if (numBlocks > 1048576)
    numBlocks = 1048576; // 1M blocks max

  // Launch kernel asynchronously
  bruteForceKernel<<<numBlocks, threadsPerBlock, 0, g_stream>>>(startCounter,
                                                                1);
}

// Check if GPU computation is done
bool cuda_is_done() { return cudaStreamQuery(g_stream) == cudaSuccess; }

// Wait for GPU and get result
uint64_t cuda_wait_and_check() {
  cudaStreamSynchronize(g_stream);

  uint64_t result;
  cudaMemcpyFromSymbol(&result, d_foundKey, sizeof(uint64_t));
  return result;
}

// Reset found flag for next batch
void cuda_reset_found() {
  uint64_t notFound = 0xFFFFFFFFFFFFFFFFULL;
  cudaMemcpyToSymbol(d_foundKey, &notFound, sizeof(uint64_t));
}

// Synchronous brute force (original)
uint64_t cuda_brute_force(uint64_t startCounter, uint64_t numKeys) {
  cuda_reset_found();
  cuda_brute_force_async(startCounter, numKeys);
  return cuda_wait_and_check();
}

// Get optimal batch size for this GPU
uint64_t cuda_get_optimal_batch_size() {
  cudaDeviceProp prop;
  cudaGetDeviceProperties(&prop, 0);

  // Aim for 16M keys per batch (sweet spot for RTX 4080)
  // More SMs = can handle larger batches
  return (uint64_t)prop.multiProcessorCount * 256 * 256; // ~16M for RTX 4080
}

void cuda_cleanup() {
  if (g_stream) {
    cudaStreamDestroy(g_stream);
    g_stream = nullptr;
  }
}

} // extern "C"
