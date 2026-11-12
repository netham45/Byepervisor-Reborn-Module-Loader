#ifndef PHASE2_ROUTER1060_H
#define PHASE2_ROUTER1060_H

#include <stddef.h>
#include <stdint.h>

#include "firmware_profile1060.h"

#define PHASE2_GENERATION 0x0000000200000001ULL
#define PHASE2_LOCATOR_OFFSET 0x8400ULL
#define PHASE2_PREALLOC_OFFSET 0x8500ULL
#define PHASE2_LOCATOR_MAGIC 0x32524f5441434f4cULL
#define PHASE2_PREALLOC_MAGIC 0x32524554554f5250ULL
#define PHASE2_GLOBAL_MAGIC 0x324c424f4c475250ULL
#define PHASE2_OWNER_MAGIC 0x3252454e574f4643ULL
#define PHASE2_ATTACHMENT_MAGIC 0x3248434154544150ULL
#define PHASE2_CODE_SIZE 0x1000ULL
#define PHASE2_STATE_SIZE 0x1000ULL
#define PHASE2_CLONE_SIZE 0x10000ULL
#define PHASE2_CODE_BACKING_SIZE 0x4000ULL
#define PHASE2_STATE_BACKING_SIZE 0x4000ULL
#define PHASE3_IMAGE_OFFSET 0x1000ULL
#define PHASE3_JOURNAL_OFFSET 0x1000ULL
#define PHASE3_JOURNAL_MAGIC 0x334c4e524a455450ULL
#define PHASE2_ALLOCATION_COUNT 3U
#define PHASE2_CLONE_PAGE_COUNT 16U
#define PHASE2_TEST_SYSCALL 551U
#define PHASE2_TEST_RESULT 0x0201060699ULL
#define PHASE2_TD_PROC_OFFSET 8U
#define PHASE2_ENOSYS 78U

#define PHASE2_PREALLOC_ARMED 1U
#define PHASE2_PREALLOC_FIRED 2U
#define PHASE2_PREALLOC_VERIFIED 3U
#define PHASE2_PREALLOC_CONSUMED 4U

#define PHASE2_ROUTER_OFF 0U
#define PHASE2_ROUTER_INSTALLING 1U
#define PHASE2_ROUTER_LIVE 2U
#define PHASE2_ROUTER_QUARANTINED 5U

#define PHASE2_ATTACHMENT_EMPTY 0U
#define PHASE2_ATTACHMENT_PREPARED 1U
#define PHASE2_ATTACHMENT_LIVE 2U

#define PHASE2_PTE_VOLATILE_AD ((1ULL << 5) | (1ULL << 6))

typedef struct {
  uint64_t magic;
  uint64_t generation;
  uint64_t malloc_type;
  uint32_t flags;
  uint32_t state;
  uint32_t state_reserved;
  uint64_t sizes[PHASE2_ALLOCATION_COUNT];
  uint64_t addresses[PHASE2_ALLOCATION_COUNT];
  uint64_t code_leaf_address;
  uint64_t code_leaf_original;
  uint64_t code_leaf_prepared;
  uint64_t data_leaf_address;
  uint64_t data_leaf_value;
  uint64_t clone_leaf_address[PHASE2_CLONE_PAGE_COUNT];
  uint64_t clone_leaf_value[PHASE2_CLONE_PAGE_COUNT];
  uint8_t code_levels;
  uint8_t data_levels;
  uint8_t clone_page_count;
  uint8_t reserved[5];
  uint64_t diagnostic_stage;
  uint64_t diagnostic_detail;
  uint64_t journal_address;
  uint64_t journal_checksum;
  uint64_t code_page_count;
  uint64_t request_checksum;
  uint64_t result_checksum;
} phase2_prealloc_record_t;
typedef struct {
  uint64_t leaf_address;
  uint64_t original;
  uint64_t final;
} phase3_code_page_entry_t;
typedef struct {
  uint64_t magic;
  uint64_t count;
  uint64_t checksum;
  phase3_code_page_entry_t entries[];
} phase3_code_journal_t;
typedef struct {
  uint64_t magic;
  uint64_t generation;
  uint64_t global_address;
  uint64_t global_size;
  uint64_t checksum;
} phase2_locator_t;

typedef struct {
  uint64_t thunk;
  uint64_t landing;
  uint8_t saved_thunk[FW1060_CFI_BYTES_MAX];
  uint8_t saved_landing[FW1060_LANDING_BYTES];
  uint8_t installed_landing[FW1060_LANDING_BYTES];
  uint32_t owned;
  uint32_t reserved;
} phase2_cfi_owner_t;
typedef struct {
  uint64_t magic;
  uint64_t generation;
  uint64_t code_address;
  uint64_t code_size;
  uint64_t state_address;
  uint64_t state_size;
  uint64_t clone_address;
  uint64_t clone_size;
  uint64_t code_leaf_address;
  uint64_t code_leaf_original;
  uint64_t code_leaf_final;
  uint64_t data_leaf_address;
  uint64_t data_leaf_value;
  uint64_t clone_leaf_address[PHASE2_CLONE_PAGE_COUNT];
  uint64_t clone_leaf_value[PHASE2_CLONE_PAGE_COUNT];
  uint64_t owner_magic;
  uint64_t immutable_checksum;
  uint32_t state;
  uint32_t attachment_count;
  uint32_t inflight;
  uint32_t quarantined;
  uint64_t attached_proc;
  uint64_t calls;
  phase2_cfi_owner_t cfi[FW1060_CFI_PAIR_COUNT];
} phase2_router_global_t;
typedef struct {
  uint64_t magic;
  uint64_t generation;
  uint64_t process_identity;
  uint64_t original_vector;
  uint64_t original_table;
  uint64_t clone_vector;
  uint64_t clone_table;
  uint32_t state;
  uint32_t inflight;
} phase2_attachment_t;

uint64_t phase2_checksum(const void *data, size_t length);
uint64_t phase2_prealloc_request_checksum(const phase2_prealloc_record_t *r);
uint64_t phase2_prealloc_result_checksum(const phase2_prealloc_record_t *r);
uint64_t phase3_code_journal_checksum(const phase3_code_journal_t *journal);
int phase3_prealloc_layout(uint64_t image_size,uint64_t *code_size,
                           uint64_t *state_size,uint64_t *page_count,
                           size_t *journal_size);
int phase3_prealloc_prepare(phase2_prealloc_record_t *r,uint64_t malloc_type,
                            uint32_t flags,uint64_t image_size);
void phase2_prealloc_prepare(phase2_prealloc_record_t *r, uint64_t malloc_type,
                             uint32_t flags);
int phase2_prealloc_fired_validate(const phase2_prealloc_record_t *r,
                                   uint64_t malloc_type, uint32_t flags);
int phase2_prealloc_validate(const phase2_prealloc_record_t *r,
                             uint64_t malloc_type, uint32_t flags);
uint64_t phase2_locator_checksum(const phase2_locator_t *locator);
int phase2_locator_validate(const phase2_locator_t *locator);
uint64_t phase2_global_immutable_checksum(const phase2_router_global_t *global);
int phase2_global_validate(const phase2_router_global_t *global);
int phase2_leaf_contract_safe(const phase2_prealloc_record_t *record);
int phase2_transition(phase2_router_global_t *global, uint32_t from,
                      uint32_t to);
int phase2_attach_begin(phase2_router_global_t *global,
                        phase2_attachment_t *attachment, uint64_t proc,
                        uint64_t original_vector, uint64_t original_table,
                        uint64_t clone_vector, uint64_t clone_table);
int phase2_attach_commit(phase2_router_global_t *global,
                         phase2_attachment_t *attachment);
int phase2_attach_release(phase2_router_global_t *global,
                          phase2_attachment_t *attachment);
size_t phase2_build_router(uint8_t *out, size_t capacity,
                           uint64_t global_address);

#endif
