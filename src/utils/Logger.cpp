#include "Logger.h"
#include <windows.h>
#include <cstdio>
#include <ctime>
#include <deque>

namespace utils {

std::mutex Logger::logMutex_;
std::deque<std::string> Logger::logBuffer_;
const size_t Logger::MAX_LOG_LINES = 200;

void Logger::Log(LogLevel level, const std::string& message) {
    std::lock_guard<std::mutex> lock(logMutex_);

    const char* levelStr = "INFO";
    switch (level) {
        case LogLevel::DEBUG: levelStr = "DEBUG"; break;
        case LogLevel::INFO:  levelStr = "INFO";  break;
        case LogLevel::WARN:  levelStr = "WARN";  break;
        case LogLevel::ERR:   levelStr = "ERROR"; break;
    }

    std::time_t now = std::time(nullptr);
    char timestamp[20];
    std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", std::localtime(&now));

    std::string logEntry = "[" + std::string(timestamp) + "] [" + levelStr + "] " + message;
    logBuffer_.push_back(logEntry);
    if (logBuffer_.size() > MAX_LOG_LINES) {
        logBuffer_.pop_front();
    }
    
    // Also send to debugger if attached
    std::string dbgMsg = logEntry + "\n";
    OutputDebugStringA(dbgMsg.c_str());
}

std::string Logger::GetRecentLogs(int max_lines) {
    std::lock_guard<std::mutex> lock(logMutex_);
    std::string result;
    int start = (int)logBuffer_.size() > max_lines ? (int)logBuffer_.size() - max_lines : 0;
    for (size_t i = start; i < logBuffer_.size(); ++i) {
        result += logBuffer_[i] + "\n";
    }
    return result;
}

} // namespace utils
