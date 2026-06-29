cmake_minimum_required(VERSION 3.28)

set(LIBHAT_VERSION 0.0.0)

project(libhat
    VERSION ${LIBHAT_VERSION}
    DESCRIPTION "A Rust byte-pattern scanning library with C/C++, C#, and Java bindings"
    HOMEPAGE_URL "https://github.com/EpsteinIslandGaming/libhat-rs"
    LANGUAGES C CXX
)

option(LIBHAT_MODULE_TARGET "Create target for the module interface" OFF)
option(LIBHAT_EXAMPLES "Include example targets" ${PROJECT_IS_TOP_LEVEL})
option(LIBHAT_USE_STD_MODULE "Compile the module target using the std module" OFF)

find_program(CARGO cargo REQUIRED)

if(WIN32)
    set(LIBHAT_LIB_NAME "hat.dll")
elseif(APPLE)
    set(LIBHAT_LIB_NAME "libhat.dylib")
else()
    set(LIBHAT_LIB_NAME "libhat.so")
endif()

set(LIBHAT_LIBRARY_PATH "${CMAKE_SOURCE_DIR}/target/release/${LIBHAT_LIB_NAME}")

add_custom_command(
    OUTPUT "${LIBHAT_LIBRARY_PATH}"
    COMMAND ${CARGO} build --release
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    COMMENT "Building libhat Rust cdylib (cargo build --release)"
    USES_TERMINAL
)

add_custom_target(libhat_rust_build DEPENDS "${LIBHAT_LIBRARY_PATH}")

add_library(libhat SHARED IMPORTED)
add_dependencies(libhat libhat_rust_build)
set_target_properties(libhat PROPERTIES
    IMPORTED_LOCATION "${LIBHAT_LIBRARY_PATH}"
    INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}/bindings"
)
add_library(libhat::libhat ALIAS libhat)

add_library(libhat_c INTERFACE)
target_link_libraries(libhat_c INTERFACE libhat::libhat)
target_include_directories(libhat_c INTERFACE
    "${CMAKE_SOURCE_DIR}/bindings/c"
)
add_library(libhat::libhat_c ALIAS libhat_c)

add_library(libhat_cpp INTERFACE)
target_link_libraries(libhat_cpp INTERFACE libhat::libhat)
target_include_directories(libhat_cpp INTERFACE
    "${CMAKE_SOURCE_DIR}/bindings/cpp"
    "${CMAKE_SOURCE_DIR}/bindings"
)
target_compile_features(libhat_cpp INTERFACE cxx_std_20)
add_library(libhat::libhat_cpp ALIAS libhat_cpp)

if(LIBHAT_MODULE_TARGET)
    add_library(libhat_module)
    target_link_libraries(libhat_module PRIVATE libhat::libhat_cpp)
    target_sources(libhat_module PUBLIC
        FILE_SET CXX_MODULES
        TYPE CXX_MODULES
        FILES "${CMAKE_SOURCE_DIR}/bindings/cpp/module/libhat.cppm"
    )
    target_compile_definitions(libhat_module PRIVATE
        "$<$<BOOL:${LIBHAT_USE_STD_MODULE}>:LIBHAT_USE_STD_MODULE>"
    )
    add_library(libhat::libhat_module ALIAS libhat_module)
endif()

if(LIBHAT_EXAMPLES)
    add_subdirectory(examples/c)
    add_subdirectory(examples/cpp/header)
    if(LIBHAT_MODULE_TARGET)
        add_subdirectory(examples/cpp/module)
    endif()
endif()
