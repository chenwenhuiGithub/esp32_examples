# The following lines of boilerplate have to be in your project's
# CMakeLists in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.16)

set(PROJECT_VER "1.2.3")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(ir_rmt)

target_add_binary_data(${CMAKE_PROJECT_NAME}.elf "main/certs/https_server.crt" TEXT)
target_add_binary_data(${CMAKE_PROJECT_NAME}.elf "main/certs/https_server_priv.key" TEXT)
target_add_binary_data(${CMAKE_PROJECT_NAME}.elf "main/certs/remote_server_root.crt" TEXT)
target_add_binary_data(${CMAKE_PROJECT_NAME}.elf "main/certs/ota_sign_pub.key" TEXT)
target_add_binary_data(${CMAKE_PROJECT_NAME}.elf "index.html.gz" TEXT)
