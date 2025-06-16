cmake_minimum_required(VERSION 3.15)
project(libwarpdeck VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Platform detection
if(APPLE)
    set(WARPDECK_PLATFORM_MACOS ON)
elseif(UNIX AND NOT APPLE)
    set(WARPDECK_PLATFORM_LINUX ON)
elseif(WIN32)
    set(WARPDECK_PLATFORM_WINDOWS ON)
else()
    message(FATAL_ERROR "Unsupported platform")
endif()

# Find required packages
find_package(PkgConfig REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# Platform-specific dependencies
if(WARPDECK_PLATFORM_MACOS)
    find_library(CORE_FOUNDATION_FRAMEWORK CoreFoundation REQUIRED)
    find_library(FOUNDATION_FRAMEWORK Foundation REQUIRED)
    set(PLATFORM_LIBRARIES ${CORE_FOUNDATION_FRAMEWORK} ${FOUNDATION_FRAMEWORK})
    set(PLATFORM_DEFINITIONS -DWARPDECK_PLATFORM_MACOS)
elseif(WARPDECK_PLATFORM_LINUX)
    pkg_check_modules(AVAHI REQUIRED avahi-client)
    set(PLATFORM_LIBRARIES ${AVAHI_LIBRARIES})
    set(PLATFORM_DEFINITIONS -DWARPDECK_PLATFORM_LINUX)
    include_directories(${AVAHI_INCLUDE_DIRS})
    link_directories(${AVAHI_LIBRARY_DIRS})
elseif(WARPDECK_PLATFORM_WINDOWS)
    # Windows socket libraries for mjansson/mdns
    set(PLATFORM_LIBRARIES ws2_32 iphlpapi)
    set(PLATFORM_DEFINITIONS -DWARPDECK_PLATFORM_WINDOWS)
endif()

# Add mjansson/mdns include directory
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../third_party/mjansson_mdns)

# Add third-party dependencies
include(FetchContent)

# Fetch cpp-httplib
FetchContent_Declare(
    httplib
    GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
    GIT_TAG v0.14.3
)
FetchContent_MakeAvailable(httplib)

# Fetch nlohmann/json for JSON handling
FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.11.3
)
FetchContent_MakeAvailable(nlohmann_json)

# Source files
set(WARPDECK_SOURCES
    src/warpdeck.cpp
    src/discovery_manager.cpp
    src/api_server.cpp
    src/api_client.cpp
    src/security_manager.cpp
    src/transfer_manager.cpp
    src/utils.cpp
    src/logger.cpp
)

# Platform-specific source files
if(WARPDECK_PLATFORM_MACOS)
    list(APPEND WARPDECK_SOURCES src/discovery_manager_macos.cpp)
elseif(WARPDECK_PLATFORM_LINUX)
    list(APPEND WARPDECK_SOURCES src/discovery_manager_linux.cpp)
endif()

# Create both static and shared libraries
add_library(warpdeck STATIC ${WARPDECK_SOURCES})
add_library(warpdeck_shared SHARED ${WARPDECK_SOURCES})

# Set target properties for both libraries
foreach(target warpdeck warpdeck_shared)
    target_include_directories(${target}
        PUBLIC 
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            $<INSTALL_INTERFACE:include>
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src
    )

    target_link_libraries(${target} 
        PRIVATE
            OpenSSL::SSL 
            OpenSSL::Crypto
            Threads::Threads
            httplib::httplib
            nlohmann_json::nlohmann_json
            ${PLATFORM_LIBRARIES}
    )

    target_compile_definitions(${target} PRIVATE ${PLATFORM_DEFINITIONS})
endforeach()

# Set shared library output name
set_target_properties(warpdeck_shared PROPERTIES OUTPUT_NAME "warpdeck")

# Compiler-specific flags
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(warpdeck PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(warpdeck_shared PRIVATE -Wall -Wextra -Wpedantic)
endif()

# Install targets
install(TARGETS warpdeck warpdeck_shared
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

install(FILES include/warpdeck.h
    DESTINATION include
)