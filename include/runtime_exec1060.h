#ifndef RUNTIME_EXEC1060_H
#define RUNTIME_EXEC1060_H

#include <stdint.h>
#include "firmware_profile1060.h"


#define RUNTIME_EXEC1060_CAVE_OFFSET 0x8000ULL
#define RUNTIME_EXEC1060_MAGIC 0x3031475043455845ULL
#define RUNTIME_EXEC1060_POST_RESUME_VERIFIED 0x4445494649524556ULL
#define RUNTIME_EXEC1060_PREP_BYTES_FAILED 1ULL
#define RUNTIME_EXEC1060_PREP_HIERARCHY_FAILED 2ULL
#define RUNTIME_EXEC1060_PREP_PERMISSION_FAILED 3ULL
#define RUNTIME_EXEC1060_PREP_LEAF_FAILED 4ULL
#define RUNTIME_EXEC1060_PREP_RECORD_FAILED 5ULL
#define RUNTIME_EXEC1060_PREP_QUARANTINED 0x44454e49544e4151ULL
#define RUNTIME_EXEC1060_PAGE_SIZE 0x4000ULL
#define RUNTIME_EXEC1060_CFI_THUNK_OFFSET \
  (g_fw1060_profile.temporary_thunk_offset)
#define RUNTIME_EXEC1060_CFI_TARGET_OFFSET \
  (g_fw1060_profile.temporary_landing_offset)
#define RUNTIME_EXEC1060_CFI_TARGET_SIZE FW1060_LANDING_BYTES
#define RUNTIME_EXEC1060_PTE_VOLATILE_AD ((1ULL << 5) | (1ULL << 6))

typedef struct {
  uint64_t magic;
  uint64_t address;
  uint64_t pte_address;
  uint64_t pte_value;
  uint64_t post_resume_state;
  uint64_t preparation_state;
  uint64_t preparation_address;
  uint64_t preparation_expected;
  uint64_t preparation_readback;
  uint64_t reservation_pte_address[FW1060_CFI_PAIR_COUNT][2];
  uint64_t reservation_pte_value[FW1060_CFI_PAIR_COUNT][2];
  uint8_t reservation_levels[FW1060_CFI_PAIR_COUNT][2];
} runtime_exec1060_page_t;

static inline int runtime_exec1060_is_post_resume_verified(
    const runtime_exec1060_page_t *page)
{
  return page && page->magic == RUNTIME_EXEC1060_MAGIC &&
         page->preparation_state == 0 &&
         page->post_resume_state == RUNTIME_EXEC1060_POST_RESUME_VERIFIED;
}

static inline int runtime_exec1060_pte_invariant_equal(uint64_t expected,
                                                       uint64_t actual)
{
  return ((expected ^ actual) & ~RUNTIME_EXEC1060_PTE_VOLATILE_AD) == 0;
}

static inline int runtime_exec1060_leaf_contract_matches(
    const runtime_exec1060_page_t *page, uint64_t leaf_address,
    uint64_t leaf_value, unsigned levels)
{
  return page && levels == 4 && leaf_address == page->pte_address &&
         runtime_exec1060_pte_invariant_equal(page->pte_value, leaf_value);
}

static inline int runtime_exec1060_mapping_contract_matches(
    uint64_t expected_address, uint64_t expected_value,
    unsigned expected_levels, uint64_t leaf_address,
    uint64_t leaf_value, unsigned levels)
{
  return expected_levels >= 3 && expected_levels <= 4 &&
         levels == expected_levels && leaf_address == expected_address &&
         runtime_exec1060_pte_invariant_equal(expected_value, leaf_value);
}

#endif
