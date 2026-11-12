#ifndef PHASE1_ALLOCATOR1060_H
#define PHASE1_ALLOCATOR1060_H

#include <stddef.h>
#include <stdint.h>

#define PHASE1_LOCATOR_OFFSET 0x8200ULL
#define PHASE1_LOCATOR_MAGIC 0x31434f4c57464b50ULL
#define PHASE1_CONTROL_MAGIC 0x314c54434b574650ULL
#define PHASE1_RECORD_MAGIC 0x314345524b574650ULL
#define PHASE1_GENERATION 0x0000000100000001ULL
#define PHASE1_CONTROL_SIZE 0x400ULL
#define PHASE1_DATA_SIZE 0x4000ULL
#define PHASE1_DISPOSABLE_SIZE 0x400ULL
#define PHASE1_PATTERN_SIZE 256U
#define PHASE1_RECORD_COUNT 3U
#define PHASE1_SYSCALL 20U
#define PHASE1_PAGE_SIZE 0x4000ULL
#define PHASE1_PREALLOC_OFFSET 0x8300ULL
#define PHASE1_PREALLOC_MAGIC 0x31434f4c4c414d50ULL
#define PHASE1_PREALLOC_STATE_ARMED 1U
#define PHASE1_PREALLOC_STATE_FIRED 2U
#define PHASE1_PREALLOC_STATE_VERIFIED 3U
#define PHASE1_PREALLOC_STATE_CONSUMED 4U

#define PHASE1_STATE_ALLOCATING 1U
#define PHASE1_STATE_ALLOCATED 2U
#define PHASE1_STATE_PUBLISHED 5U
#define PHASE1_STATE_DRAINING 6U
#define PHASE1_STATE_FREED 7U
#define PHASE1_STATE_QUARANTINED 0x51554152U

#define PHASE1_ROLE_CONTROL 1U
#define PHASE1_ROLE_DATA 2U
#define PHASE1_ROLE_DISPOSABLE 3U

typedef struct {
  uint64_t magic;
  uint64_t generation;
  uint64_t address;
  uint64_t size;
  uint64_t malloc_type;
  uint32_t state;
  uint32_t page_count;
  uint32_t role;
  uint32_t reserved;
} phase1_allocation_record_t;

typedef struct {
  uint64_t magic;
  uint64_t generation;
  uint64_t control_block;
  uint64_t control_block_size;
  uint64_t checksum;
} phase1_framework_locator_t;
typedef struct {
  uint64_t magic;
  uint64_t generation;
  uint64_t malloc_type;
  uint32_t flags;
  uint32_t reserved0;
  uint64_t sizes[PHASE1_RECORD_COUNT];
  uint64_t request_checksum;
  uint64_t addresses[PHASE1_RECORD_COUNT];
  uint32_t state;
  uint32_t reserved1;
  uint64_t result_checksum;
} phase1_prealloc_record_t;


typedef struct {
  uint64_t magic;
  uint64_t generation;
  uint64_t self_address;
  uint64_t size;
  uint64_t malloc_type;
  uint64_t pattern_checksum;
  uint32_t state;
  uint32_t record_count;
  phase1_allocation_record_t records[PHASE1_RECORD_COUNT];
  uint8_t pattern[PHASE1_PATTERN_SIZE];
  uint64_t checksum;
} phase1_control_block_t;

uint64_t phase1_checksum(const void *data, size_t length);
uint64_t phase1_locator_checksum(const phase1_framework_locator_t *locator);
uint64_t phase1_control_checksum(const phase1_control_block_t *control);
uint64_t phase1_prealloc_request_checksum(
    const phase1_prealloc_record_t *record);
uint64_t phase1_prealloc_result_checksum(
    const phase1_prealloc_record_t *record);
void phase1_prealloc_prepare(phase1_prealloc_record_t *record,
                             uint64_t malloc_type, uint32_t flags);
int phase1_prealloc_fired_validate(const phase1_prealloc_record_t *record,
                                   uint64_t malloc_type, uint32_t flags);
int phase1_prealloc_validate(const phase1_prealloc_record_t *record,
                             uint64_t malloc_type, uint32_t flags);
void phase1_fill_pattern(uint8_t pattern[PHASE1_PATTERN_SIZE],
                         uint64_t generation);
int phase1_locator_validate(const phase1_framework_locator_t *locator);
int phase1_control_validate(const phase1_framework_locator_t *locator,
                            const phase1_control_block_t *control,
                            uint64_t expected_malloc_type);
int phase1_disposable_free_eligible(const phase1_control_block_t *control,
                                    uint64_t address, uint64_t generation,
                                    uint64_t malloc_type);
int phase1_mark_disposable_draining(phase1_control_block_t *control,
                                    uint64_t address, uint64_t generation,
                                    uint64_t malloc_type);
int phase1_mark_disposable_freed(phase1_control_block_t *control,
                                 uint64_t address, uint64_t generation,
                                 uint64_t malloc_type);

#endif
