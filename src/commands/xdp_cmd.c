#include "commands.h"
#include "logger.h"
#include "xdp_common.h"

#include <ctype.h>
#include <dirent.h>
#include <unistd.h>

i32 do_xdp_command(struct command_params *cp) {
    bool dump = false;
    if (cp->argc == 0) {
        dump = true;
    } else {
        struct interface *iface = cp->state->current_iface;
        if (!iface) {
            printf("no iface set!\n");
        }

        if (strcmp(cp->argv[0], "load") == 0) {
            if (cp->argc < 2) {
                printf("You must provide a BPF-PROG name\n");
            } else {
                char cwd[PATH_MAX];
                getcwd(cwd, PATH_MAX);
                
                char prog_filename[8192];
                snprintf(prog_filename, sizeof(prog_filename), "%s/out/%s",
                        cwd, cp->argv[1]);

                // struct bpf_object *obj = xdp_common__load_bpf_object_file(prog_filename, iface->index);
                // if (!obj) {
                //     return -1;
                // }

                // bpf_object__fd
                // xdp_common__link_attach(iface->index, 0, prog_fd);
            }
        } else if (strcmp(cp->argv[0], "unload") == 0) {
            xdp_common__link_detach_all(iface->index, 0);
        }
    }
    
    if (dump) {
        char cwd[PATH_MAX];
        getcwd(cwd, PATH_MAX);
        
        char bpf_directory[8192];
        snprintf(bpf_directory, sizeof(bpf_directory), "%s/%s", cwd, "out");

        DIR *dir = opendir(bpf_directory);
        if (!dir) {
            LOG_ERROR("directory not found!");
            return -1;
        } 

        struct dirent *dirent = NULL;
        while ((dirent = readdir(dir)) != NULL) {
            if (dirent->d_type == DT_REG) {
                printf("%s\n", dirent->d_name);
            }
        }
    }

    return 0;
}