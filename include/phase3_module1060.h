#ifndef PHASE3_MODULE1060_H
#define PHASE3_MODULE1060_H

#include <stddef.h>
#include <stdint.h>

#define PHASE3_GENERATION 0x0000000300000001ULL
#define PHASE3_BLOB_MAGIC "PS5BLB1\0"
#define PHASE3_FORMAT_VERSION 1U
#define PHASE3_ABI_VERSION 1U
#define PHASE3_FIRMWARE_MASK_1060_REGULAR 1ULL
#define PHASE3_INIT_SYSCALL 500U
#define PHASE3_HELLO_SYSCALL 504U
#define PHASE3_NOSYS_REFERENCE 699U
#define PHASE3_OPERATION_INIT 1U
#define PHASE3_OPERATION_HELLO 2U
#define PHASE3_HELLO_RESULT 0x0301060a11ULL
#define PHASE3_BLOB_IMAGE_OFFSET 0x1000ULL
#define PHASE3_BLOB_PATH "/data/pldmgr/payloads/phase3-hello/phase3-hello-64m.blob"
#define PHASE3_BLOB_MAX_SEGMENTS 8U
#define PHASE3_BLOB_MAX_SYSCALLS 8U
#define PHASE3_SEG_R 1U
#define PHASE3_SEG_W 2U
#define PHASE3_SEG_X 4U
#define PHASE3_SYSCALL_INIT 1U
#define PHASE3_SYSCALL_DISPATCH 2U
#define PHASE3_MODULE_EMPTY 0U
#define PHASE3_MODULE_VALIDATED 1U
#define PHASE3_MODULE_LOADED 2U
#define PHASE3_MODULE_PREPARED 3U
#define PHASE3_MODULE_REGISTERED 4U
#define PHASE3_MODULE_INITIALIZING 5U
#define PHASE3_MODULE_INITIALIZED 6U
#define PHASE3_MODULE_ACTIVE 7U
#define PHASE3_MODULE_FAILED 8U
#define PHASE3_ENOSYS 78U
#define PHASE3_EINVAL 22U

typedef struct __attribute__((packed)) {
  uint8_t magic[8];
  uint16_t format_version;
  uint16_t abi_version;
  uint32_t header_size;
  uint64_t file_size;
  uint64_t image_size;
  uint64_t required_caps;
  uint64_t firmware_mask;
  uint32_t segment_count;
  uint32_t syscall_count;
  uint64_t segments_offset;
  uint64_t syscalls_offset;
  uint64_t init_offset;
  uint64_t fini_offset;
  uint64_t dispatch_offset;
  uint8_t digest[32];
} blob_header_v1;

typedef struct __attribute__((packed)) {
  uint64_t file_offset;
  uint64_t image_offset;
  uint64_t file_size;
  uint64_t memory_size;
  uint64_t alignment;
  uint32_t permissions;
} blob_segment_v1;

typedef struct __attribute__((packed)) {
  uint32_t number;
  uint16_t narg;
  uint16_t arg_size;
  uint32_t flags;
  uint32_t operation_id;
} blob_syscall_v1;

typedef struct {
  const uint8_t *bytes;
  size_t size;
  blob_header_v1 header;
  blob_segment_v1 segments[PHASE3_BLOB_MAX_SEGMENTS];
  blob_syscall_v1 syscalls[PHASE3_BLOB_MAX_SYSCALLS];
} phase3_blob_view_t;

typedef struct {
  uint32_t abi_version;
  uint32_t size;
  uint64_t generation;
  uint64_t module_base;
  uint64_t image_size;
  uint64_t allowed_operations;
} module_context_v1;

typedef struct {
  uint64_t magic;
  uint64_t generation;
  uint64_t blob_address;
  uint64_t blob_file_size;
  uint64_t image_address;
  uint64_t image_size;
  uint64_t code_leaf_address;
  uint64_t code_leaf_original;
  uint64_t code_leaf_final;
  uint64_t init_address;
  uint64_t dispatch_address;
  uint64_t attached_proc;
  uint64_t init_calls;
  uint64_t hello_calls;
  uint32_t state;
  uint32_t inflight;
  uint32_t quarantined;
  uint32_t reserved;
  uint8_t digest[32];
  module_context_v1 context;
} phase3_module_state_t;

enum phase3_blob_error {
  PHASE3_BLOB_OK = 0,
  PHASE3_BLOB_TRUNCATED = -1,
  PHASE3_BLOB_MAGIC_ERROR = -2,
  PHASE3_BLOB_VERSION_ERROR = -3,
  PHASE3_BLOB_SIZE_ERROR = -4,
  PHASE3_BLOB_CAP_ERROR = -5,
  PHASE3_BLOB_TABLE_ERROR = -6,
  PHASE3_BLOB_SEGMENT_ERROR = -7,
  PHASE3_BLOB_ENTRY_ERROR = -8,
  PHASE3_BLOB_SYSCALL_ERROR = -9,
  PHASE3_BLOB_DIGEST_ERROR = -10,
  PHASE3_BLOB_LEAF_CONFLICT = -11
};

void phase3_sha256(const void *bytes, size_t size, uint8_t digest[32]);
void phase3_blob_digest(const void *bytes, size_t size, uint8_t digest[32]);
int phase3_blob_validate(const void *bytes, size_t size,
                         phase3_blob_view_t *view);
int phase3_blob_load(const phase3_blob_view_t *view, void *image,
                     size_t image_capacity);
int phase3_module_transition(phase3_module_state_t *module, uint32_t from,
                             uint32_t to);
int phase3_allowlist_handlers_validate(uint64_t init_handler,
                                       uint64_t hello_handler,
                                       uint64_t kernel_text_base,
                                       uint64_t kernel_data_base);
size_t phase3_build_init_router(uint8_t *out, size_t capacity,
                                uint64_t module_address,
                                uint64_t blob_init_thunk,
                                uint32_t td_proc_offset,
                                uint32_t td_retval_offset);
size_t phase3_build_hello_router(uint8_t *out, size_t capacity,
                                 uint64_t module_address,
                                 uint64_t blob_dispatch_thunk,
                                 uint32_t td_proc_offset);


#endif
