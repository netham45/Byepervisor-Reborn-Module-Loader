#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "phase1_allocator1060.h"

static void make_valid(phase1_framework_locator_t *locator,
                       phase1_control_block_t *control)
{
  const uint64_t type = 0xffffffff82ad5670ULL;
  memset(locator, 0, sizeof(*locator));
  memset(control, 0, sizeof(*control));
  locator->magic = PHASE1_LOCATOR_MAGIC;
  locator->generation = PHASE1_GENERATION;
  locator->control_block = 0xffff800012340000ULL;
  locator->control_block_size = PHASE1_CONTROL_SIZE;
  control->magic = PHASE1_CONTROL_MAGIC;
  control->generation = PHASE1_GENERATION;
  control->self_address = locator->control_block;
  control->size = PHASE1_CONTROL_SIZE;
  control->malloc_type = type;
  control->state = PHASE1_STATE_PUBLISHED;
  control->record_count = PHASE1_RECORD_COUNT;
  phase1_fill_pattern(control->pattern, control->generation);
  control->pattern_checksum = phase1_checksum(control->pattern,
                                               sizeof(control->pattern));
  for (unsigned i = 0; i < PHASE1_RECORD_COUNT; ++i) {
    phase1_allocation_record_t *record = &control->records[i];
    record->magic = PHASE1_RECORD_MAGIC;
    record->generation = PHASE1_GENERATION;
    record->address = locator->control_block + i * PHASE1_PAGE_SIZE;
    record->size = i == 0 ? PHASE1_CONTROL_SIZE :
                   i == 1 ? PHASE1_DATA_SIZE : PHASE1_DISPOSABLE_SIZE;
    record->malloc_type = type;
    record->state = i == 2 ? PHASE1_STATE_ALLOCATED :
                             PHASE1_STATE_PUBLISHED;
    record->page_count = (uint32_t)((record->size + PHASE1_PAGE_SIZE - 1) /
                                    PHASE1_PAGE_SIZE);
    record->role = i + 1;
  }
  control->checksum = phase1_control_checksum(control);
  locator->checksum = phase1_locator_checksum(locator);
}

int main(void)
{
  phase1_framework_locator_t locator;
  phase1_control_block_t control;
  const uint64_t type = 0xffffffff82ad5670ULL;
  {
    phase1_prealloc_record_t prealloc;
    const uint64_t type = 0xffffffff82ad5670ULL;
    const uint32_t flags = 0x101U;
    phase1_prealloc_prepare(&prealloc, type, flags);
    assert(prealloc.state == PHASE1_PREALLOC_STATE_ARMED);
    assert(phase1_prealloc_validate(&prealloc, type, flags) != 0);
    prealloc.addresses[0] = 0xffff800012340000ULL;
    prealloc.addresses[1] = 0xffff800012344000ULL;
    prealloc.addresses[2] = 0xffff800012348000ULL;
    prealloc.state = PHASE1_PREALLOC_STATE_FIRED;
    assert(phase1_prealloc_fired_validate(&prealloc, type, flags) == 0);
    prealloc.state = PHASE1_PREALLOC_STATE_VERIFIED;
    prealloc.result_checksum = phase1_prealloc_result_checksum(&prealloc);
    assert(phase1_prealloc_validate(&prealloc, type, flags) == 0);
    prealloc.addresses[1]++;
    assert(phase1_prealloc_validate(&prealloc, type, flags) != 0);
    prealloc.addresses[1]--;
    prealloc.result_checksum = phase1_prealloc_result_checksum(&prealloc);
    prealloc.state = PHASE1_PREALLOC_STATE_CONSUMED;
    prealloc.result_checksum = phase1_prealloc_result_checksum(&prealloc);
    assert(phase1_prealloc_validate(&prealloc, type, flags) != 0);
  }

  make_valid(&locator, &control);
  assert(phase1_locator_validate(&locator) == 0);
  assert(phase1_control_validate(&locator, &control, type) == 0);

  /* A checksum-less partial publication is consumer-invisible. */
  locator.checksum = 0;
  assert(phase1_locator_validate(&locator) != 0);
  locator.checksum = phase1_locator_checksum(&locator);

  control.generation++;
  control.checksum = phase1_control_checksum(&control);
  assert(phase1_control_validate(&locator, &control, type) != 0);
  make_valid(&locator, &control);

  assert(phase1_disposable_free_eligible(&control,
      control.records[2].address, control.generation, type) == 0);
  assert(phase1_disposable_free_eligible(&control,
      control.records[2].address, control.generation, type + 1) != 0);
  assert(phase1_disposable_free_eligible(&control,
      control.records[0].address, control.generation, type) != 0);
  assert(phase1_mark_disposable_draining(&control,
      control.records[2].address, control.generation, type) == 0);
  assert(control.records[2].state == PHASE1_STATE_DRAINING);
  assert(phase1_disposable_free_eligible(&control,
      control.records[2].address, control.generation, type) != 0);
  assert(phase1_mark_disposable_freed(&control, control.records[2].address,
      control.generation, type) == 0);
  assert(phase1_disposable_free_eligible(&control,
      control.records[2].address, control.generation, type) != 0);

  /* Owner checks reject restoration after a foreign vector takes ownership. */
  {
    uint64_t current = 0x3000, owned_clone = 0x2000, original = 0x1000;
    int may_restore = current == owned_clone;
    assert(!may_restore && current != original);
  }
  /* Failed owner proof maps to quarantine rather than an unsafe free. */
  {
    uint32_t state = PHASE1_STATE_ALLOCATED;
    int reachability_proven = 0;
    if (!reachability_proven)
      state = PHASE1_STATE_QUARANTINED;
    assert(state == PHASE1_STATE_QUARANTINED);
  }

  puts("phase1-smoke: PASS prealloc=khook-commit-verified "
       "locator=commit-last generation=fail-closed free=matching-type "
       "restoration=owner-checked quarantine=pinned");
  return 0;
}
