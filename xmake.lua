add_rules("mode.release", "mode.debug")

target("talker")
    set_kind("binary")
    add_defines("LOG_LEVEL=500")
    add_files("talker.c")
    add_files("src/*.c")
    add_includedirs("./src")
    add_cflags("-Wextra", "-Wall")
    add_syslinks("pthread") -- add_syslinks("pthread", "dl", "m", "c")
    if is_mode("debug") then
        add_defines("DEBUG")
    end

target("listener")
    set_kind("binary")
    add_defines("LOG_LEVEL=500")
    add_files("listener.c")
    add_files("src/*.c")
    add_syslinks("pthread") -- add_syslinks("pthread", "dl", "m", "c")
     add_includedirs("./src")
    if is_mode("debug") then
        add_defines("DEBUG")
    end
