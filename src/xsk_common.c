#include "logger.h"
#include "xsk_common.h"

static i32 xsk_umem__init_memory_allocator(mem_frame_allocator_t *allocator, u32 frames_number) {

    allocator->umem_frame_addr = calloc(frames_number, sizeof(u64));
    if (!allocator->umem_frame_addr) {
        LOG_ERROR("Cannot allocate umem_frame_addr array sz: %u", frames_number);
        return -1;
    }

    allocator->umem_frame_max = frames_number;

    for (u32 i = 0; i < frames_number; ++i) {
        allocator->umem_frame_addr[i] = i * FRAME_SIZE;
    }

    allocator->umem_frame_free = frames_number;

    return 0;
}

xsk_umem_info_t *xsk_umem__configure(
    void *buffer, u64 buffer_size,
    u32 frame_size, u32 frames_number
) {
    xsk_umem_info_t *umem_info;

    struct xsk_umem_config xsk_umem_config = {0};
    xsk_umem_config.fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
    xsk_umem_config.comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
    xsk_umem_config.frame_size = frame_size;
    xsk_umem_config.frame_headroom = 256;
    xsk_umem_config.flags = 0;

    umem_info = calloc(1, sizeof(xsk_umem_info_t));
    if (!umem_info) {
        return NULL;
    }

    i32 ret = xsk_umem__create(
        &umem_info->umem, buffer, buffer_size, 
        &umem_info->init_fq, &umem_info->init_cq,
        &xsk_umem_config
    );
    if (ret) {
        errno = -ret;
        return NULL;
    }

    umem_info->buffer = buffer;

    ret = xsk_umem__init_memory_allocator(&umem_info->mem_allocator, frames_number);
    if (ret) {
        return NULL;
    }

    return umem_info;
}

static u64 umem_frame__allocate_memory(mem_frame_allocator_t *allocator) {
    if (allocator->umem_frame_free == 0) {
        return INVALID_UMEM_FRAME;
    }

    allocator->umem_frame_free -= 1;
    u64 frame = allocator->umem_frame_addr[allocator->umem_frame_free];
    allocator->umem_frame_addr[allocator->umem_frame_free] = INVALID_UMEM_FRAME;

    return frame;
}

i32 xsk_fill_ring__populate(
    struct xsk_ring_prod *fq, xsk_umem_info_t *umem_info,
    i32 frames_number
) {
    u32 idx = 0;

    i32 ret = xsk_ring_prod__reserve(fq, frames_number, &idx);
    if (ret != frames_number) {
        goto error_exit;
    }

    for (i32 i = 0; i < frames_number; ++i) {
        *xsk_ring_prod__fill_addr(fq, idx++) = 
            umem_frame__allocate_memory(&umem_info->mem_allocator);
    }

    xsk_ring_prod__submit(fq, frames_number);

    return 0;

error_exit:
    return -EINVAL;
}