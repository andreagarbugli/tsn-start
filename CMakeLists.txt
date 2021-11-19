project(tsnstart)
cmake_minimum_required(VERSION 3.15)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin")

set(LOG_LEVEL "100" CACHE STRING "Set the level of the logger")

add_executable(talker talker.c)

target_sources(talker
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

target_compile_definitions(talker
    PRIVATE
        LOG_LEVEL=${LOG_LEVEL}
)


target_compile_options(talker
    PUBLIC
        "-Wall" "-Wextra"
)

target_include_directories(talker
    PUBLIC
        "src"
    )

add_executable(listener listener.c)


target_sources(listener
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

target_compile_definitions(listener
    PRIVATE
        LOG_LEVEL=${LOG_LEVEL}
)


target_compile_options(listener
    PUBLIC
        "-Wall" "-Wextra"
)

target_include_directories(listener
    PUBLIC
        "src"
    )    

add_custom_command(
    TARGET talker  POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
            ${CMAKE_SOURCE_DIR}/configs/config.cfg 
            ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/config.cfg
    )