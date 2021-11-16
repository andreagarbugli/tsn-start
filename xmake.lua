add_rules("mode.release", "mode.debug")

target("tsnstart")
    set_kind("binary")
    add_defines("LOG_LEVEL=500")
    add_files("src/*.c")
    -- add_includedirs("./include")
    if is_mode("debug") then
        add_defines("DEBUG")
    end
