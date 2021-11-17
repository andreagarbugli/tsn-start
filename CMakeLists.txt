project(tsnstart)
cmake_minimum_required(VERSION 3.15)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin")

set(LOG_LEVEL "100" CACHE STRING "Set the level of the logger")

add_executable(tsnstart src/main.c)

target_sources(tsnstart
    PRIVATE
        src/common.h    
        src/config.c
        src/config.h
        src/connection.c
        src/connection.h
        src/interface.c
        src/interface.h
        src/logger.c
        src/logger.h
        src/packet.c
        src/packet.h
        src/utils.c
        src/utils.h
)

target_compile_definitions(tsnstart
    PRIVATE
        LOG_LEVEL=${LOG_LEVEL}
)


target_compile_options(tsnstart
    PUBLIC
        "-Wall" "-Wextra"
)

target_include_directories(tsnstart
    PUBLIC
        "include"
    )

add_custom_command(
    TARGET ${PROJECT_NAME}  POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
            ${CMAKE_SOURCE_DIR}/configs/config.cfg 
            ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/config.cfg
    )