#include <linux/if_link.h>
#include <linux/limits.h>

#include "logger.h"
#include "xdp_common.h"

struct bpf_object *xdp_common__load_bpf_object_file(const char *filename, i32 ifindex) {
	struct bpf_prog_load_attr prog_load_attr = {0};
	prog_load_attr.prog_type = BPF_PROG_TYPE_XDP;
	prog_load_attr.ifindex = ifindex;
	prog_load_attr.file = filename;

    i32 first_prog_fd = -1;
    struct bpf_object *obj = NULL;
	i32 err = bpf_prog_load_xattr(&prog_load_attr, &obj, &first_prog_fd);
	if (err) {
		LOG_ERROR("Failed to load BPF-OBJ file %s: %s (%d)",
				  filename, strerror(-err), -err);
		return NULL;
	}

    return obj;
}

#ifndef MAX_ERRNO
#define MAX_ERRNO 4095
#endif // MAX_ERRNO

#define IS_ERROR_VALUE(x) ((x) >= (unsigned long)-MAX_ERRNO)

static inline bool is_error_or_null(const void *ptr) {
	return (!ptr) || IS_ERROR_VALUE((unsigned long)ptr);
}

static struct bpf_object *open_bpf_object(const char *filename, i32 ifindex) {
	struct bpf_object_open_attr open_attr = {0};
	open_attr.file = filename;
	open_attr.prog_type = BPF_PROG_TYPE_XDP;

	i32 err = 0;
	struct bpf_object *obj = bpf_object__open_xattr(&open_attr);
	if (is_error_or_null(obj)) {
		err = -(long)obj;
		LOG_ERROR("Failed to open BPF-OBJ file %s: %s (%d)",
				  filename, err, strerror(-err));
		return NULL;
	}

	struct bpf_program *prog = NULL;
	struct bpf_program *first_prog = NULL;
	bpf_object__for_each_program(prog, obj) {
		bpf_program__set_type(prog, BPF_PROG_TYPE_XDP);
		bpf_program__set_ifindex(prog, ifindex);
		if (!first_prog) {
			first_prog = prog;
		}
	}

	struct bpf_map *map = NULL;
	bpf_object__for_each_map(map, obj) {
		if (!bpf_map__is_offload_neutral(map)) {
			bpf_map__set_ifindex(map, ifindex);
		}
	}

	if (!first_prog) {
		LOG_ERROR("File %s contains no programs", filename);
		return NULL;
	}

	return obj;
}

static i32 reuse_maps(struct bpf_object *obj, char *pin_dir) {
	if (!obj) {
		return -ENOENT;
	}

	if (!pin_dir) {
		return -EINVAL;
	}

	struct bpf_map *map;
	bpf_object__for_each_map(map, obj) {
		i32 err = 0;
		char buf[PATH_MAX];

		i32 len = snprintf(buf, PATH_MAX, "%s/%s", pin_dir, bpf_map__name(map));
		if (len < 0) {
			return -EINVAL;
		} else if (len >= PATH_MAX) {
			return -ENAMETOOLONG;
		}

		i32 pinned_map_fd = bpf_obj_get(buf);
		if (pinned_map_fd < 0) {
			return pinned_map_fd;
		}

		err = bpf_map__reuse_fd(map, pinned_map_fd);
		if (err) {
			return err;
		}
	}

	return 0;
}

static struct bpf_object *load_bpf_object_file_and_reuse_maps(const char *filename, i32 ifindex, char *pin_dir) {
	struct bpf_object *obj = open_bpf_object(filename, ifindex);
	if (!obj) {
		LOG_ERROR("Failed to open object %s", filename);
		return NULL;
	}

	i32 err = reuse_maps(obj, pin_dir);
	if (err) {
		LOG_ERROR("Failed to reuse maps for object %s (pin_dir=%s)", filename, pin_dir);
		return NULL;
	}

	err = bpf_object__load(obj);
	if (err) {
		LOG_ERROR("Failed to load BPF-PROG file %s: %s (%d)", filename, err, strerror(-err));
		return NULL;
	}

	return obj;
}

struct bpf_object *xdp_common__load_bpf_object_and_attach_xdp(
    u32 xdp_flags, i32 ifindex,
	bool reuse_maps, const char *filename, char *pin_dir,
	char *prog_sec
) {
	// If flags indicate HW offload, supply ifindex
	i32 offload_ifindex = 0;
	if (xdp_flags & XDP_FLAGS_HW_MODE) {
		offload_ifindex = ifindex;
	}

	struct bpf_object *obj = NULL;
	if (reuse_maps) {
		obj = load_bpf_object_file_and_reuse_maps(filename, offload_ifindex, pin_dir);
	} else {
		obj = xdp_common__load_bpf_object_file(filename, offload_ifindex);
	}

	if (!obj) {
		LOG_ERROR("Failed to load file %s", filename);
		return NULL;
	}

	struct bpf_program *prog = NULL;
	if (prog_sec[0]) {
		prog = bpf_object__find_program_by_title(obj, prog_sec);
	} else {
		prog = bpf_program__next(NULL, obj);
	}

	if (!prog) {
		LOG_ERROR("Couldn't find a program in ELF section '%s'", prog_sec);
		return NULL;
	}

	size_t len = sizeof(prog_sec) - 1;
	strncpy(prog_sec, bpf_program__section_name(prog), len);
	prog_sec[len] = '\0';

	i32 prog_fd = bpf_program__fd(prog);
	if (prog_fd < 0) {
		LOG_ERROR("Failed to retreive BPF-PROG fd");
		return NULL;
	}

	i32 err = xdp_common__link_attach(ifindex, xdp_flags, prog_fd);
	if (err) {
		return NULL;
	} 

	return obj;
}

i32 xdp_common__link_detach_all(i32 ifindex, u32 xdp_flags) {
	i32 err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
	if (err < 0) {
		LOG_ERROR("Failed to unload BPF-PROG from interface %d: %s",
				  ifindex, strerror(errno));
		return -1;
	}

	return 0;
}

i32 xdp_common__link_detach_program(i32 ifindex, u32 xdp_flags, u32 expected_prog_id) {
	u32 curr_prog_id;
	i32 err = bpf_get_link_xdp_id(ifindex, &curr_prog_id, xdp_flags);
	if (err < 0) {
		LOG_ERROR("Failed to get XDP-PROG id from interface %d: %s (%d)",
			      ifindex, strerror(-err), -err);
		return -1;
	}

	if (!curr_prog_id) {
		LOG_DEBUG("%s() - no curr XDP-PROG on interface %d", __func__, ifindex);
		return 0;
	}

	if (expected_prog_id && curr_prog_id != expected_prog_id) {
		LOG_ERROR("Expected prog ID (%d) no match with current prog ID (%d), not removing",
				  expected_prog_id, curr_prog_id);
		return -1;
	}

	err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
	if (err < 0) {
		LOG_ERROR("Failed to unload BPF-PROG from interface %d: %s", 
				  ifindex, strerror(errno));
		return -1;
	}

	LOG_TRACE("Removed XDP-PROG (%d) on interface %d", curr_prog_id, ifindex);

	return 0;
}

i32 xdp_common__link_attach(i32 ifindex, u32 xdp_flags, i32 prog_fd) {
	i32 err = bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags);
	if (err == -EEXIST && !(xdp_flags & XDP_FLAGS_UPDATE_IF_NOEXIST)) {
		u32 old_flags = xdp_flags;
		xdp_flags &= ~XDP_FLAGS_MODES;
		xdp_flags |= (old_flags & XDP_FLAGS_SKB_MODE) 
				? XDP_FLAGS_DRV_MODE
				: XDP_FLAGS_SKB_MODE;
		
		err = bpf_set_link_xdp_fd(ifindex, prog_fd, old_flags);
		if (!err) {
			err = bpf_set_link_xdp_fd(ifindex, prog_fd, old_flags);
		}
	}

	if (err < 0) {
		LOG_ERROR("Failed to load BPF-PROG in interface %d: %s", ifindex,
				strerror(errno));

		switch (-err) {
			case EBUSY:
			case EEXIST:
				LOG_DEBUG("\t>hint: XDP already loaded on device");
				break;
			case EOPNOTSUPP:
				LOG_DEBUG("\t>hint: Native-XDP not supported");
				break;
			default:
				break;
		}

		return -1;
	}

	return 0;
}
