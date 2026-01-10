#include <windows.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include "aes256_ecb.h"

namespace fs = std::filesystem;

static constexpr uint8_t MAGIC[4] = {0xFC, 0xB9, 0xCF, 0x9B};
static constexpr size_t HEADER_SIZE = 256;
static constexpr size_t KEY_LEN = 32;

static std::atomic<unsigned long long> g_totalTried(0);
static std::atomic<bool> g_found(false);
static std::atomic<bool> g_stop(false);
static std::string g_foundKey;
static std::mutex g_lastKeyMu;
static std::string g_lastKey;

static std::wstring to_wstring_utf8_lossy(const std::string& s) {
    if (s.empty()) return L"";
    int needed = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    if (needed <= 0) {
        std::wstring ws;
        ws.reserve(s.size());
        for (unsigned char c : s) ws.push_back((wchar_t)c);
        return ws;
    }
    std::wstring ws(needed, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), ws.data(), needed);
    return ws;
}

static std::wstring ps_single_quote_escape(const std::wstring& s) {
    // In PowerShell single-quoted strings, escape ' as ''
    std::wstring out;
    out.reserve(s.size() + 8);
    for (wchar_t ch : s) {
        if (ch == L'\'') out += L"''";
        else out.push_back(ch);
    }
    return out;
}

static bool run_powershell_expand_archive(const fs::path& zipPath, const fs::path& destDir) {
    std::wstring zipW = zipPath.wstring();
    std::wstring destW = destDir.wstring();

    std::wstring cmd =
        L"powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "
        L"\"$ErrorActionPreference='Stop'; Expand-Archive -Force -LiteralPath '" + ps_single_quote_escape(zipW) +
        L"' -DestinationPath '" + ps_single_quote_escape(destW) + L"'\"";

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    // CreateProcessW requires mutable buffer
    std::vector<wchar_t> buf(cmd.begin(), cmd.end());
    buf.push_back(L'\0');

    BOOL ok = CreateProcessW(
        nullptr,
        buf.data(),
        nullptr,
        nullptr,
        FALSE,
        CREATE_NO_WINDOW,
        nullptr,
        nullptr,
        &si,
        &pi);

    if (!ok) return false;

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return exitCode == 0;
}

static std::vector<uint8_t> read_all_bytes(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    if (!f) throw std::runtime_error("Failed to open file.");
    f.seekg(0, std::ios::end);
    std::streamoff sz = f.tellg();
    f.seekg(0, std::ios::beg);
    if (sz < 0) throw std::runtime_error("Failed to read file size.");
    std::vector<uint8_t> data((size_t)sz);
    if (!data.empty()) f.read((char*)data.data(), (std::streamsize)data.size());
    return data;
}

static bool is_contents_json_header(const std::vector<uint8_t>& data) {
    if (data.size() < HEADER_SIZE) return false;
    return data[4] == MAGIC[0] && data[5] == MAGIC[1] && data[6] == MAGIC[2] && data[7] == MAGIC[3];
}

static bool try_master_key_prefix(const std::string& keyStr, const uint8_t* cipher, size_t cipherLen) {
    if (keyStr.size() != KEY_LEN || cipherLen < 4) return false;

    uint8_t key[32];
    memcpy(key, keyStr.data(), 32);

    mcbe_aes::AES256Ctx ctx;
    mcbe_aes::aes256_init(ctx, key);

    uint8_t shiftReg[16];
    memcpy(shiftReg, key, 16); // IV is first 16 bytes of key

    // contents.json plaintext begins with: {"content": ...}
    // Check first 4 bytes: '{' '"' 'c' 'o'
    const uint8_t expected[4] = {123, 34, 99, 111};

    for (int i = 0; i < 4; i++) {
        uint8_t block[16];
        mcbe_aes::aes256_encrypt_block(ctx, shiftReg, block);
        uint8_t plain = cipher[i] ^ block[0];
        if (plain != expected[i]) return false;

        memmove(shiftReg, shiftReg + 1, 15);
        shiftReg[15] = cipher[i];
    }

    return true;
}

static void worker_bruteforce(const uint8_t* cipher, size_t cipherLen, const std::string* charset) {
    std::mt19937_64 rng((uint64_t)std::chrono::high_resolution_clock::now().time_since_epoch().count() ^ (uint64_t)GetCurrentThreadId());
    std::uniform_int_distribution<size_t> dist(0, charset->size() - 1);

    unsigned long long localTried = 0;
    while (!g_found && !g_stop) {
        std::string k;
        k.resize(KEY_LEN);
        for (size_t i = 0; i < KEY_LEN; i++) k[i] = (*charset)[dist(rng)];

        if ((localTried & 0x3FFULL) == 0) {
            std::lock_guard<std::mutex> lk(g_lastKeyMu);
            g_lastKey = k;
        }

        if (try_master_key_prefix(k, cipher, cipherLen)) {
            g_found = true;
            g_foundKey = k;
            break;
        }

        localTried++;
        if ((localTried & 0x3FFULL) == 0) g_totalTried.fetch_add(1024);
    }

    unsigned long long rem = (localTried & 0x3FFULL);
    if (rem) g_totalTried.fetch_add(rem);
}

static fs::path find_contents_json(const fs::path& root) {
    for (auto const& entry : fs::recursive_directory_iterator(root)) {
        if (!entry.is_regular_file()) continue;
        if (entry.path().filename() == "contents.json") return entry.path();
    }
    return {};
}

static fs::path materialize_contents_json(const fs::path& inputPath, fs::path& tempDirOut) {
    tempDirOut.clear();

    std::wstring ext = inputPath.extension().wstring();
    for (auto& ch : ext) ch = (wchar_t)towlower(ch);

    if (ext == L".zip") {
        fs::path tempBase = fs::temp_directory_path();
        auto stamp = std::chrono::high_resolution_clock::now().time_since_epoch().count();
        tempDirOut = tempBase / (L"mcbe_rp_extract_" + std::to_wstring(stamp));
        fs::create_directories(tempDirOut);

        if (!run_powershell_expand_archive(inputPath, tempDirOut)) {
            throw std::runtime_error("Failed to expand archive via PowerShell. Try extracting manually and pass contents.json.");
        }
        fs::path found = find_contents_json(tempDirOut);
        if (found.empty()) throw std::runtime_error("contents.json not found inside extracted pack.");
        return found;
    }

    return inputPath;
}

static void print_usage() {
    std::cout
        << "Usage:\n"
        << "  recovery.exe <pack.zip|contents.json> [threads]\n\n"
        << "Notes:\n"
        << "  - This is brute-force (random sampling). It may run indefinitely.\n"
    << "  - Default charset: A-Z a-z 0-9 (62 chars).\n"
        << "  - If you pass a .zip, it will be extracted via PowerShell to a temp folder.\n"
        << "  - Press Ctrl+C to stop.\n";
}

static BOOL WINAPI console_ctrl_handler(DWORD ctrlType) {
    if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_BREAK_EVENT || ctrlType == CTRL_CLOSE_EVENT) {
        g_stop = true;
        return TRUE;
    }
    return FALSE;
}

int main(int argc, char** argv) {
    try {
        std::cout << "[*] MCBE Resource Pack Key Recovery (C++ / Windows)" << std::endl;

        if (argc < 2) {
            print_usage();
            return 2;
        }

        fs::path inputPath = fs::u8path(argv[1]);
        unsigned int threadCount = std::thread::hardware_concurrency();
        if (threadCount == 0) threadCount = 8;
        if (argc >= 3) {
            try {
                int t = std::stoi(argv[2]);
                if (t > 0 && t <= 256) threadCount = (unsigned int)t;
            } catch (...) {
            }
        }

        SetConsoleCtrlHandler(console_ctrl_handler, TRUE);

        fs::path tempDir;
        fs::path contentsPath = materialize_contents_json(inputPath, tempDir);

        std::vector<uint8_t> data = read_all_bytes(contentsPath);
        if (!is_contents_json_header(data)) {
            throw std::runtime_error("Input does not look like encrypted contents.json (MAGIC mismatch).");
        }
        if (data.size() <= HEADER_SIZE + 4) {
            throw std::runtime_error("contents.json is too small.");
        }
        const uint8_t* cipher = data.data() + HEADER_SIZE;
        size_t cipherLen = data.size() - HEADER_SIZE;

        const std::string charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

        std::cout << "[*] Input: " << inputPath.u8string() << std::endl;
        std::cout << "[*] Using contents.json: " << contentsPath.u8string() << std::endl;
        std::cout << "[*] Mode: brute-force (random)" << std::endl;
        std::cout << "[*] Charset: " << charset << " (len=" << charset.size() << ")" << std::endl;
        std::cout << "[*] Threads: " << threadCount << std::endl;

        std::vector<std::thread> threads;
        threads.reserve(threadCount);

        auto start = std::chrono::high_resolution_clock::now();
        for (unsigned int i = 0; i < threadCount; i++) {
            threads.emplace_back(worker_bruteforce, cipher, cipherLen, &charset);
        }

        while (!g_found && !g_stop) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            auto now = std::chrono::high_resolution_clock::now();
            double elapsed = std::chrono::duration<double>(now - start).count();
            unsigned long long tried = g_totalTried.load();
            double speed = (elapsed > 0.0) ? (tried / elapsed) : 0.0;

            std::string last;
            {
                std::lock_guard<std::mutex> lk(g_lastKeyMu);
                last = g_lastKey;
            }

            std::cout << "\r[Status] "
                      << "Tried: " << tried
                      << " | Speed: " << std::fixed << std::setprecision(0) << speed << "/s"
                      << " | Last: " << last << "        " << std::flush;
        }

        for (auto& t : threads) t.join();

        std::cout << std::endl;
        if (g_found) {
            std::cout << "\n[SUCCESS] KEY FOUND: " << g_foundKey << std::endl;
            if (!tempDir.empty()) {
                std::cout << "[*] (Temp extracted folder will be removed)" << std::endl;
            }
        } else if (g_stop) {
            std::cout << "\n[STOP] Stopped by user." << std::endl;
        } else {
            std::cout << "\n[FAIL] No key found." << std::endl;
        }

        if (!tempDir.empty()) {
            std::error_code ec;
            fs::remove_all(tempDir, ec);
        }

        return g_found ? 0 : 1;
    } catch (const std::exception& e) {
        std::cerr << "\n[ERROR] " << e.what() << std::endl;
        return 3;
    }
}
