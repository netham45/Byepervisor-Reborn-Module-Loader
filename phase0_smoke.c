#include <stdio.h>
#include <string.h>

#include "firmware_profile1060.h"
#include "page_publication1060.h"
#include "runtime_exec1060.h"

typedef struct {
  uint64_t entries[FW1060_PAGE_LEVELS];
  uint8_t code[FW1060_LANDING_BYTES];
  uint64_t publication;
  unsigned tlb_calls;
  unsigned instruction_calls;
  unsigned write_calls;
  unsigned fail_write_at;
  unsigned phases;
} smoke_state_t;

static int locate(smoke_state_t *state, uint64_t address, void **data,
                  size_t *available)
{
  if (address >= 0x1000 && address < 0x1020) {
    unsigned index = (unsigned)((address - 0x1000) / 8);
    *data = &state->entries[index];
    *available = sizeof(uint64_t);
  } else if (address == 0x2000) {
    *data = state->code;
    *available = sizeof(state->code);
  } else if (address == 0x3000) {
    *data = &state->publication;
    *available = sizeof(state->publication);
  } else {
    return -1;
  }
  return 0;
}

static int smoke_read(void *context, uint64_t address, void *data, size_t size)
{
  void *source;
  size_t available;
  if (locate(context, address, &source, &available) != 0 || size > available)
    return -1;
  memcpy(data, source, size);
  return 0;
}

static int smoke_write(void *context, uint64_t address, const void *data,
                       size_t size)
{
  smoke_state_t *state = context;
  void *destination;
  size_t available;
  ++state->write_calls;
  if (state->fail_write_at && state->write_calls == state->fail_write_at)
    return -1;
  if (locate(state, address, &destination, &available) != 0 || size > available)
    return -1;
  memcpy(destination, data, size);
  return 0;
}

static int smoke_walk(void *context, uint64_t address, uint64_t *flags,
                      unsigned *levels)
{
  smoke_state_t *state = context;
  (void)address;
  *levels = FW1060_PAGE_LEVELS;
  *flags = FW1060_PAGE_PRESENT | FW1060_PAGE_WRITABLE;
  for (unsigned i = 0; i < FW1060_PAGE_LEVELS; ++i) {
    if (!(state->entries[i] & FW1060_PAGE_PRESENT))
      *flags &= ~FW1060_PAGE_PRESENT;
    if (!(state->entries[i] & FW1060_PAGE_WRITABLE))
      *flags &= ~FW1060_PAGE_WRITABLE;
    *flags |= state->entries[i] & (FW1060_PAGE_NX | FW1060_PAGE_XOTEXT);
  }
  return 0;
}

static int smoke_tlb(void *context, uint64_t offset)
{
  smoke_state_t *state = context;
  if (offset != g_fw1060_profile.all_core_guest_tlb_offset)
    return -1;
  ++state->tlb_calls;
  return 0;
}

static int smoke_instructions(void *context, uint64_t offset)
{
  smoke_state_t *state = context;
  if (offset != g_fw1060_profile.all_core_instruction_offset)
    return -1;
  ++state->instruction_calls;
  return 0;
}

static int smoke_phase(void *context, const char *name, uint64_t address,
                       uint64_t original, uint64_t requested, uint64_t readback)
{
  smoke_state_t *state = context;
  (void)name;
  (void)address;
  (void)original;
  (void)requested;
  (void)readback;
  ++state->phases;
  return 0;
}

static void initialize(smoke_state_t *state,
                       fw1060_publication_request_t *request)
{
  static uint8_t original[FW1060_LANDING_BYTES];
  static uint8_t requested[FW1060_LANDING_BYTES];
  memset(state, 0, sizeof(*state));
  memset(original, 0xcc, sizeof(original));
  memset(requested, 0x90, sizeof(requested));
  memcpy(state->code, original, sizeof(original));
  memset(request, 0, sizeof(*request));
  request->code_address = 0x2000;
  request->original_code = original;
  request->requested_code = requested;
  request->code_size = sizeof(original);
  request->publication_address = 0x3000;
  request->unpublished_value = 0;
  request->published_value = 0xfeedfaceULL;
  request->required_effective_set = FW1060_PAGE_PRESENT | FW1060_PAGE_WRITABLE;
  request->required_effective_clear = FW1060_PAGE_NX | FW1060_PAGE_XOTEXT;
  for (unsigned i = 0; i < FW1060_PAGE_LEVELS; ++i) {
    state->entries[i] = FW1060_PAGE_PRESENT;
    request->entries[i].address = 0x1000 + i * 8;
    request->entries[i].original = state->entries[i];
    request->entries[i].requested = FW1060_PAGE_PRESENT | FW1060_PAGE_WRITABLE;
  }
}

static int fail(const char *message)
{
  fprintf(stderr, "phase0-smoke: FAIL: %s\n", message);
  return 1;
}

int main(void)
{
  fw1060_publication_request_t request;
  smoke_state_t state;
  fw1060_publication_io_t io = {
    .context = &state,
    .read = smoke_read,
    .write = smoke_write,
    .walk_effective = smoke_walk,
    .sync_guest_tlb_all = smoke_tlb,
    .sync_instructions_all = smoke_instructions,
    .phase = smoke_phase,
  };
  uint8_t frame[32] = {0};
  uint32_t number = 0;
  runtime_exec1060_page_t runtime_page = {
    .magic = RUNTIME_EXEC1060_MAGIC,
  };
  uint64_t reserved_pages[FW1060_CFI_PAIR_COUNT * 2] = {0};
  uint64_t derived_pages[FW1060_CFI_PAIR_COUNT * 2] = {0};
  size_t reserved_page_count, derived_page_count = 0;


  if (fw1060_profile_validate() != 0 ||
      fw1060_identity_validate(0x10600006U, 0x840f80U, 16U) != 0 ||
      fw1060_identity_validate(0x10600005U, 0x840f80U, 16U) == 0)
    return fail("profile or fail-closed identity");
  *(uint32_t *)frame = 733U;
  if (fw1060_router_syscall_number(frame + 16, &number) != 0 || number != 733U)
    return fail("normalized router source");
  *(uint32_t *)frame = 734U;
  if (fw1060_router_syscall_number(frame + 16, &number) == 0)
    return fail("router bounds");
  for (unsigned i = 0; i < FW1060_CFI_PAIR_COUNT; ++i)
    if (fw1060_verify_cfi_pair(&g_fw1060_profile.cfi_pairs[i],
          g_fw1060_profile.cfi_pairs[i].thunk_bytes,
          g_fw1060_profile.cfi_pairs[i].landing_bytes) != 0)
      return fail("CFI reservation bytes or branch target");
  for (size_t pair_index = 0; pair_index < FW1060_CFI_PAIR_COUNT;
       ++pair_index) {
    const fw1060_cfi_pair_t *pair =
        &g_fw1060_profile.cfi_pairs[pair_index];
    const uint64_t offsets[2] = {
      pair->thunk_offset & ~0xfffULL,
      pair->landing_offset & ~0xfffULL,
    };
    for (size_t side = 0; side < 2; ++side) {
      size_t existing = 0;
      while (existing < derived_page_count &&
             derived_pages[existing] != offsets[side])
        ++existing;
      if (existing == derived_page_count)
        derived_pages[derived_page_count++] = offsets[side];
    }
  }
  reserved_page_count = fw1060_reserved_text_pages(
      reserved_pages, sizeof(reserved_pages) / sizeof(reserved_pages[0]));
  if (reserved_page_count == 0 ||
      reserved_page_count != derived_page_count ||
      memcmp(reserved_pages, derived_pages,
             derived_page_count * sizeof(derived_pages[0])) != 0 ||
      fw1060_reserved_text_pages(reserved_pages,
          derived_page_count - 1) != 0)
    return fail("array-derived page deduplication or capacity refusal");
  for (size_t i = 0; i < reserved_page_count; ++i) {
    if (reserved_pages[i] & 0xfff)
      return fail("reserved page alignment");
    for (size_t earlier = 0; earlier < i; ++earlier)
      if (reserved_pages[i] == reserved_pages[earlier])
        return fail("duplicate reserved page");
  }
  if (runtime_exec1060_is_post_resume_verified(&runtime_page))
    return fail("unverified carrier state accepted");
  runtime_page.post_resume_state = RUNTIME_EXEC1060_POST_RESUME_VERIFIED;
  if (!runtime_exec1060_is_post_resume_verified(&runtime_page)) {
    return fail("verified carrier state rejected");
  }
  runtime_page.preparation_state = RUNTIME_EXEC1060_PREP_QUARANTINED;
  if (runtime_exec1060_is_post_resume_verified(&runtime_page))
    return fail("quarantined preparation accepted");
  runtime_page.preparation_state = 0;
  runtime_page.magic ^= 1;
  if (runtime_exec1060_is_post_resume_verified(&runtime_page))
    return fail("mismatched carrier identity accepted");
  runtime_page.magic = RUNTIME_EXEC1060_MAGIC;
  runtime_page.pte_address = 0x1000;
  runtime_page.pte_value = 0x0000000012345003ULL;
  if (!runtime_exec1060_pte_invariant_equal(
          runtime_page.pte_value,
          runtime_page.pte_value ^ RUNTIME_EXEC1060_PTE_VOLATILE_AD) ||
      !runtime_exec1060_leaf_contract_matches(
          &runtime_page, runtime_page.pte_address,
          runtime_page.pte_value ^ RUNTIME_EXEC1060_PTE_VOLATILE_AD, 4))
    return fail("Accessed/Dirty volatility rejected");
  if (runtime_exec1060_pte_invariant_equal(
          runtime_page.pte_value, runtime_page.pte_value ^ (1ULL << 12)) ||
      runtime_exec1060_pte_invariant_equal(
          runtime_page.pte_value, runtime_page.pte_value ^ FW1060_PAGE_WRITABLE) ||
      runtime_exec1060_pte_invariant_equal(
          runtime_page.pte_value, runtime_page.pte_value ^ FW1060_PAGE_NX) ||
      runtime_exec1060_pte_invariant_equal(
          runtime_page.pte_value, runtime_page.pte_value ^ FW1060_PAGE_XOTEXT))
    return fail("invariant PTE mismatch accepted");
  if (runtime_exec1060_leaf_contract_matches(
          &runtime_page, runtime_page.pte_address + 8,
          runtime_page.pte_value, 4) ||
      runtime_exec1060_leaf_contract_matches(
          &runtime_page, runtime_page.pte_address,
          runtime_page.pte_value, 3))
    return fail("leaf address or hierarchy mismatch accepted");
  if (!runtime_exec1060_mapping_contract_matches(
          runtime_page.pte_address, runtime_page.pte_value, 3,
          runtime_page.pte_address,
          runtime_page.pte_value ^ RUNTIME_EXEC1060_PTE_VOLATILE_AD, 3) ||
      runtime_exec1060_mapping_contract_matches(
          runtime_page.pte_address, runtime_page.pte_value, 2,
          runtime_page.pte_address, runtime_page.pte_value, 2) ||
      runtime_exec1060_mapping_contract_matches(
          runtime_page.pte_address, runtime_page.pte_value, 3,
          runtime_page.pte_address, runtime_page.pte_value, 4))
    return fail("huge-leaf mapping contract");



  initialize(&state, &request);
  if (fw1060_publish_page(&io, &request) != 0 ||
      state.publication != request.published_value || state.tlb_calls != 1 ||
      state.instruction_calls != 1 || state.phases == 0)
    return fail("successful all-core publication");

  initialize(&state, &request);
  request.entries[2].requested |= FW1060_PAGE_NX;
  if (fw1060_publish_page(&io, &request) != -1 || state.publication != 0 ||
      state.tlb_calls != 2 || state.instruction_calls != 2 ||
      memcmp(state.code, request.original_code, request.code_size) != 0)
    return fail("reverse rollback and repeated synchronization");
  for (unsigned i = 0; i < FW1060_PAGE_LEVELS; ++i)
    if (state.entries[i] != request.entries[i].original)
      return fail("rollback entry readback");

  initialize(&state, &request);
  state.entries[1] |= FW1060_PAGE_HUGE;
  request.entries[1].original = state.entries[1];
  if (fw1060_publish_page(&io, &request) == 0 || state.write_calls != 0)
    return fail("huge-page ownership rejection before mutation");

  printf("phase0-smoke: PASS profile=0x%08x pairs=%u router_max=%u "
         "publication_sync=%llx/%llx rollback=verified huge=refused "
         "post_resume=fail_closed pte_ad=invariant reserved_pages=%zu\n",
         g_fw1060_profile.firmware, FW1060_CFI_PAIR_COUNT,
         g_fw1060_profile.syscall_count - 1,
         (unsigned long long)g_fw1060_profile.all_core_guest_tlb_offset,
         (unsigned long long)g_fw1060_profile.all_core_instruction_offset,
         reserved_page_count);
  return 0;
}
