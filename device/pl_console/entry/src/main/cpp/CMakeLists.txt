cmake_minimum_required(VERSION 3.5.0)
project(plnative)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 引擎源码挂在 engine/ 与 include/ 两个软链下，指向 PolicyLoop 仓库的 device/
# 镜像 —— 这里编的和板端 C++ 组件是同一份源码，不复制，免得两份漂移。
#
# pl_log_source.cpp 刻意不编：它读 /dev/kmsg，属于采集路径，而应用域被三条
# neverallow 挡在 kmsg 外面，既拿不到也用不上。
add_library(plnative SHARED
    napi_init.cpp
    engine/pl_avc_parser.cpp
    engine/pl_converge.cpp
    engine/pl_index.cpp
    engine/pl_report.cpp
    engine/pl_sha1.cpp
)

target_include_directories(plnative PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

# libace_napi.z.so 由 NDK 的 sysroot 提供，是 ArkTS 与原生代码之间的唯一边界。
target_link_libraries(plnative PUBLIC libace_napi.z.so)
