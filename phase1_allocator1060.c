#include <string.h>

#include "phase1_allocator1060.h"

uint64_t phase1_checksum(const void *data, size_t length)
{
  const uint8_t *bytes = data;
  uint64_t hash = 0xcbf29ce484222325ULL;
  for (size_t i = 0; i < length; ++i) {
    hash ^= bytes[i];
    hash *= 0x100000001b3ULL;
  }
  return hash;
}

uint64_t phase1_locator_checksum(const phase1_framework_locator_t *locator)
{
  return phase1_checksum(locator, offsetof(phase1_framework_locator_t,
                                           checksum));
}

uint64_t phase1_control_checksum(const phase1_control_block_t *control)
{
  return phase1_checksum(control, offsetof(phase1_control_block_t, checksum));
}

uint64_t phase1_prealloc_request_checksum(
    const phase1_prealloc_record_t *record)
{
  return phase1_checksum(record,
      offsetof(phase1_prealloc_record_t, request_checksum));
}

uint64_t phase1_prealloc_result_checksum(
    const phase1_prealloc_record_t *record)
{
  return phase1_checksum(record,
      offsetof(phase1_prealloc_record_t, result_checksum));
}

void phase1_prealloc_prepare(phase1_prealloc_record_t *record,
                             uint64_t malloc_type, uint32_t flags)
{
  static const uint64_t sizes[PHASE1_RECORD_COUNT] = {
    PHASE1_CONTROL_SIZE, PHASE1_DATA_SIZE, PHASE1_DISPOSABLE_SIZE
  };
  memset(record, 0, sizeof(*record));
  record->magic = PHASE1_PREALLOC_MAGIC;
  record->generation = PHASE1_GENERATION;
  record->malloc_type = malloc_type;
  record->flags = flags;
  memcpy(record->sizes, sizes, sizeof(sizes));
  record->request_checksum = phase1_prealloc_request_checksum(record);
  record->state = PHASE1_PREALLOC_STATE_ARMED;
}

int phase1_prealloc_fired_validate(const phase1_prealloc_record_t *record,
                                   uint64_t malloc_type, uint32_t flags)
{
  if (!record || record->magic != PHASE1_PREALLOC_MAGIC ||
      record->generation != PHASE1_GENERATION ||
      record->malloc_type != malloc_type || record->flags != flags ||
      record->reserved0 || record->reserved1 ||
      record->sizes[0] != PHASE1_CONTROL_SIZE ||
      record->sizes[1] != PHASE1_DATA_SIZE ||
      record->sizes[2] != PHASE1_DISPOSABLE_SIZE ||
      record->request_checksum != phase1_prealloc_request_checksum(record) ||
      record->state != PHASE1_PREALLOC_STATE_FIRED ||
      record->result_checksum)
    return -1;
  for (unsigned i = 0; i < PHASE1_RECORD_COUNT; ++i) {
    if ((record->addresses[i] >> 48) != 0xffff)
      return -1;
    for (unsigned j = 0; j < i; ++j)
      if (record->addresses[i] == record->addresses[j])
        return -1;
  }
  return 0;
}

int phase1_prealloc_validate(const phase1_prealloc_record_t *record,
                             uint64_t malloc_type, uint32_t flags)
{
  phase1_prealloc_record_t fired;
  if (!record || record->state != PHASE1_PREALLOC_STATE_VERIFIED ||
      record->result_checksum != phase1_prealloc_result_checksum(record))
    return -1;
  fired = *record;
  fired.state = PHASE1_PREALLOC_STATE_FIRED;
  fired.result_checksum = 0;
  return phase1_prealloc_fired_validate(&fired, malloc_type, flags);
}

void phase1_fill_pattern(uint8_t pattern[PHASE1_PATTERN_SIZE],
                         uint64_t generation)
{
  uint64_t state = generation ^ 0x9e3779b97f4a7c15ULL;
  for (size_t i = 0; i < PHASE1_PATTERN_SIZE; ++i) {
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    pattern[i] = (uint8_t)(state ^ i ^ 0xa5U);
  }
}

int phase1_locator_validate(const phase1_framework_locator_t *locator)
{
  return locator && locator->magic == PHASE1_LOCATOR_MAGIC &&
         locator->generation == PHASE1_GENERATION &&
         (locator->control_block >> 48) == 0xffff &&
         locator->control_block_size == PHASE1_CONTROL_SIZE &&
         locator->checksum == phase1_locator_checksum(locator) ? 0 : -1;
}

int phase1_control_validate(const phase1_framework_locator_t *locator,
                            const phase1_control_block_t *control,
                            uint64_t expected_malloc_type)
{
  uint8_t expected_pattern[PHASE1_PATTERN_SIZE];
  if (phase1_locator_validate(locator) != 0 || !control ||
      control->magic != PHASE1_CONTROL_MAGIC ||
      control->generation != locator->generation ||
      control->self_address != locator->control_block ||
      control->size != PHASE1_CONTROL_SIZE ||
      control->malloc_type != expected_malloc_type ||
      control->state != PHASE1_STATE_PUBLISHED ||
      control->record_count != PHASE1_RECORD_COUNT ||
      control->checksum != phase1_control_checksum(control))
    return -1;
  phase1_fill_pattern(expected_pattern, control->generation);
  if (memcmp(control->pattern, expected_pattern, sizeof(expected_pattern)) != 0 ||
      control->pattern_checksum != phase1_checksum(control->pattern,
                                                   sizeof(control->pattern)))
    return -1;
  for (unsigned i = 0; i < PHASE1_RECORD_COUNT; ++i) {
    const phase1_allocation_record_t *record = &control->records[i];
    if (record->magic != PHASE1_RECORD_MAGIC ||
        record->generation != control->generation ||
        (record->address >> 48) != 0xffff || !record->size ||
        record->malloc_type != expected_malloc_type ||
        record->page_count !=
            (record->size + PHASE1_PAGE_SIZE - 1) / PHASE1_PAGE_SIZE ||
        record->role != i + 1U)
      return -1;
  }
  if (control->records[0].address != control->self_address ||
      control->records[0].size != PHASE1_CONTROL_SIZE ||
      control->records[0].state != PHASE1_STATE_PUBLISHED ||
      control->records[1].size != PHASE1_DATA_SIZE ||
      control->records[1].state != PHASE1_STATE_PUBLISHED ||
      (control->records[2].state != PHASE1_STATE_ALLOCATED &&
       control->records[2].state != PHASE1_STATE_DRAINING &&
       control->records[2].state != PHASE1_STATE_FREED))
    return -1;
  return 0;
}

int phase1_disposable_free_eligible(const phase1_control_block_t *control,
                                    uint64_t address, uint64_t generation,
                                    uint64_t malloc_type)
{
  const phase1_allocation_record_t *record;
  if (!control || control->generation != generation ||
      control->state != PHASE1_STATE_PUBLISHED)
    return -1;
  record = &control->records[2];
  if (record->magic != PHASE1_RECORD_MAGIC ||
      record->generation != generation || record->address != address ||
      record->malloc_type != malloc_type ||
      record->role != PHASE1_ROLE_DISPOSABLE ||
      record->state != PHASE1_STATE_ALLOCATED ||
      address == control->self_address ||
      address == control->records[1].address)
    return -1;
  return 0;
}

int phase1_mark_disposable_draining(phase1_control_block_t *control,
                                    uint64_t address, uint64_t generation,
                                    uint64_t malloc_type)
{
  if (phase1_disposable_free_eligible(control, address, generation,
                                      malloc_type) != 0)
    return -1;
  control->records[2].state = PHASE1_STATE_DRAINING;
  control->checksum = phase1_control_checksum(control);
  return 0;
}

int phase1_mark_disposable_freed(phase1_control_block_t *control,
                                 uint64_t address, uint64_t generation,
                                 uint64_t malloc_type)
{
  if (!control || control->generation != generation ||
      control->state != PHASE1_STATE_PUBLISHED ||
      control->records[2].magic != PHASE1_RECORD_MAGIC ||
      control->records[2].generation != generation ||
      control->records[2].address != address ||
      control->records[2].malloc_type != malloc_type ||
      control->records[2].role != PHASE1_ROLE_DISPOSABLE ||
      control->records[2].state != PHASE1_STATE_DRAINING)
    return -1;
  control->records[2].state = PHASE1_STATE_FREED;
  control->checksum = phase1_control_checksum(control);
  return 0;
}
