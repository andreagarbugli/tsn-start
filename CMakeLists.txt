project(tsnstart)
cmake_minimum_required(VERSION 3.15)

add_executable(tsnstart src/main.c)

target_sources(tsnstart
    PRIVATE
        src/config.c
        src/config.h
        src/common.h
)

target_include_directories(tsnstart
    PUBLIC
        "include"
    )