project(tsnstart)
cmake_minimum_required(VERSION 3.15)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/out")

set(LOG_LEVEL "100" CACHE STRING "Set the level of the logger")

add_library(tsn src/tsn.c)

add_subdirectory(src)

target_include_directories(tsn
    PUBLIC
        "src"
        "src/commands"
        "out"
    )

add_executable(talker talker.c)
target_link_libraries(talker PRIVATE tsn bpf)
target_compile_definitions(talker PRIVATE LOG_LEVEL=${LOG_LEVEL})
target_compile_options(talker PUBLIC "-Wall" "-Wextra")

add_executable(listener listener.c)
target_link_libraries(listener PRIVATE tsn)
target_compile_definitions(listener PRIVATE LOG_LEVEL=${LOG_LEVEL})
target_compile_options(listener PUBLIC "-Wall" "-Wextra")

add_executable(talker-xdp talker_xdp.c)
target_include_directories(talker-xdp
    PUBLIC 
        "out"
)

target_link_libraries(talker-xdp PRIVATE tsn libbpf)
target_compile_definitions(talker-xdp PRIVATE LOG_LEVEL=${LOG_LEVEL})
target_compile_options(talker-xdp PUBLIC "-Wall" "-Wextra")

add_custom_command(
    TARGET talker  POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
            ${CMAKE_SOURCE_DIR}/configs/config.cfg 
            ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/config.cfg
    )
