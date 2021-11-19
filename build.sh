#!/bin/bash

SRCDIR="src"
OUTDIR="out"
PROGRAMS="bpfstart"

LOG_LEVEL=500
INCLUDES="-Ilibbpf/include/uapi -Iinclude -I$OUTDIR -I$SRCDIR"

CLANG_BPF_SYS_INCLUDES = clang -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }'

COMPILE_LIBBPF=false

if [ ! -d $OUTDIR ]; then
    log_info "Creating build directory"
    mkdir $OUTDIR
fi

if [ -d $OUTDIR/libbpf ]; then
    log_info "Compiling libbpf"
    COMPILE_LIBBPF=true
fi

function log_info() {
    echo "$(tput setaf 2)[info]$(tput setaf 7) $1" 
}

function compile_bpf_program() {
    if [ $COMPILE_LIBBPF ]; then
        compile_libbpf
    fi

    # Build the BPF code
    log_info "Build the BPF code"
    clang -g -O2 -target bpf -D__TARGET_ARCH_x86 $INCLUDES $CLANG_BPF_SYS_INCLUDES -c "$SRCDIR/$1.bpf.c" -o "$OUTDIR/bpfstart.bpf.o"
    llvm-strip -g "$OUTDIR/$1.bpf.o" 

    # Generate BPF skeletons
    log_info "Generate BPF skeletons"
    ./tools/bpftool gen skeleton "$OUTDIR/$1.bpf.o" > "$OUTDIR/$1.skel.h"

    # Compile the user program
    log_info "Compile the user program: pass 1"
    gcc -g -Wall $INCLUDES -I$OUTDIR -c "$SRCDIR/$1.c" -DLOG_LEVEL=$LOG_LEVEL -o "$OUTDIR/$1.o"
    log_info "Compile the user program: pass 2"
    gcc -g -Wall "$OUTDIR/$1.o" "$OUTDIR/libbpf/libbpf.a" -lelf -lz -o "$OUTDIR/$1"

    log_info "Done!!!"
}

function compile_user_program() {
    # SRC_REGEX=
    SRCS=$(ls -rd -1 $PWD/src/**)
    gcc $INCLUDES $SRCS $1.c -DLOG_LEVEL=$LOG_LEVEL -o "$OUTDIR/$1"
    mv configs/config.cfg $OUTDIR/config.cfg
}

function compile_libbpf() {
    make -C `pwd`/libbpf/src BUILD_STATIC_ONLY=1 OBJDIR=`pwd`/$OUTDIR/libbpf DESTDIR=`pwd`/$OUTDIR INCLUDEDIR= LIBDIR= UAPIDIR= install
}

while getopts BCc: flag
do
    case "${flag}" in
        # C)  FILENAME=${OPTARG};
        #     compile;;
        B)  compile_libbpf ;;
        C)  compile_bpf_program $PROGRAMS ;;
        c)  FILENAME=${OPTARG}; 
            # echo $FILENAME;
            compile_user_program $FILENAME ;;
    esac
done