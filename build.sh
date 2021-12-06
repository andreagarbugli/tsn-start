#!/bin/bash

# Build configs
SRCDIR="src"
OUTDIR="out"

# Build options
LOG_LEVEL=500

# Build dependencies
INCLUDES="-Ilibbpf/include/uapi -Iinclude -I$OUTDIR -I$SRCDIR -I$SRCDIR/commands"

CLANG_BPF_SYS_INCLUDES = clang -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }'

COMPILE_LIBBPF=false

# Utilities functions
function log_info() {
    echo "$(tput setaf 2)[info]$(tput setaf 7) $1" 
}

# Check if OUTDIR exists, if NOT creates it
if [ ! -d $OUTDIR ]; then
    log_info "Creating build directory"
    mkdir $OUTDIR
fi

if [ ! -d $OUTDIR/libbpf ]; then
    log_info "Compiling libbpf"
    COMPILE_LIBBPF=true
fi

function compile_bpf_program() {
    # if [ $COMPILE_LIBBPF ]; then
    #     compile_libbpf
    # fi

    # Build the BPF code
    log_info "Build the BPF code"
    clang -g -O2 -target bpf -D__TARGET_ARCH_x86 $INCLUDES $CLANG_BPF_SYS_INCLUDES -c "$SRCDIR/bpf/$1.bpf.c" -o "$OUTDIR/$1.bpf.o"
    llvm-strip -g "$OUTDIR/$1.bpf.o" 

    # Generate BPF skeletons
    log_info "Generate BPF skeletons"
    bpftool gen skeleton "$OUTDIR/$1.bpf.o" > "$OUTDIR/$1.skel.h"

#     # Compile the user program
#     log_info "Compile the user program: pass 1"
#     gcc -g -Wall $INCLUDES -I$OUTDIR -c "$SRCDIR/$1.c" -DLOG_LEVEL=$LOG_LEVEL -o "$OUTDIR/$1.o"
#     log_info "Compile the user program: pass 2"
#     gcc -g -Wall "$OUTDIR/$1.o" "$OUTDIR/libbpf/libbpf.a" -lelf -lz -o "$OUTDIR/$1"

    log_info "Done!!!"
}

function compile_user_program() {
    log_info "compiling the user program: $1"

    SOURCES=$(find src/ -maxdepth 1 -type f -name '*.[c|h]')
    SRCS_COMMANDS=$(find src/commands/ -maxdepth 1 -type f -name '*.[c|h]')
    GCC_FLAGS="-O2 -Wall -Wextra -Wuninitialized -Wno-sign-compare -Wno-address-of-packed-member"
    gcc $GCC_FLAGS $INCLUDES $SOURCES $SRCS_COMMANDS $1.c "$OUTDIR/libbpf/libbpf.a" -lpthread -lelf -lz -DLOG_LEVEL=$LOG_LEVEL -o "$OUTDIR/$1"
    # cp configs/config.cfg $OUTDIR/config.cfg

    log_info "compiling: done!"
}

function compile_libbpf() {
    make -C `pwd`/libbpf/src BUILD_STATIC_ONLY=1 OBJDIR=`pwd`/$OUTDIR/libbpf DESTDIR=`pwd`/$OUTDIR INCLUDEDIR= LIBDIR= UAPIDIR= install
}

while getopts BC:c: flag
do
    case "${flag}" in
        B)  compile_libbpf ;;
        C)  FILENAME=${OPTARG};
            compile_bpf_program $FILENAME ;;
        c)  FILENAME=${OPTARG}; 
            compile_user_program $FILENAME ;;
    esac
done
