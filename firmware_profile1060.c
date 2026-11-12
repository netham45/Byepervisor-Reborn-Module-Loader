#include <string.h>

#include "firmware_profile1060.h"

#define CC32 \
  { 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, \
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, \
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, \
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc }

const fw1060_profile_t g_fw1060_profile = {
  .firmware = FW1060_FIRMWARE,
  .soc_id = FW1060_SOC_ID,
  .cpu_count = FW1060_CPU_COUNT,
  .syscall_count = FW1060_SYSCALL_COUNT,
  .proc_p_sysent_offset = 0xa00ULL,
  .sysent_offset = 0x1ad120ULL,
  .sysent_size = 0x30U,
  .sy_call_offset = 0x08U,
  .sysentvec_offset = 0xdba6d8ULL,
  .sysentvec_size = 0x200U,
  .sysentvec_table_offset = 0x08U,
  .router_uap_syscall_backoff = 0x10,
  .router_path_offsets = {0x42ce70ULL, 0x42cfb0ULL, 0x42d3f9ULL,
                          0x42d400ULL},
  .temporary_thunk_offset = 0x2b59c0ULL,
  .temporary_landing_offset = 0x3fa50ULL,
  .temporary_thunk_bytes = {0xe9, 0x8b, 0xa0, 0xd8, 0xff},
  .temporary_landing_bytes = CC32,
  .cfi_pairs = {
    {
      .thunk_offset = 0x2b5a30ULL,
      .landing_offset = 0x1a7e0ULL,
      .thunk_bytes = {0xe9, 0xab, 0x4d, 0xd6, 0xff, 0xcc, 0xcc, 0xcc},
      .thunk_size = 8,
      .landing_bytes = CC32,
      .framework_exclusive = 1,
    },
    {
      .thunk_offset = 0x2b5d20ULL,
      .landing_offset = 0xddc70ULL,
      .thunk_bytes = {0xe9, 0x4b, 0x7f, 0xe2, 0xff, 0xcc, 0xcc, 0xcc},
      .thunk_size = 8,
      .landing_bytes = CC32,
      .framework_exclusive = 1,
    },
    {
      .thunk_offset = 0x2b6e70ULL,
      .landing_offset = 0x60c80ULL,
      .thunk_bytes = {0xe9, 0x0b, 0x9e, 0xda, 0xff, 0xcc, 0xcc, 0xcc},
      .thunk_size = 8,
      .landing_bytes = CC32,
      .framework_exclusive = 1,
    },
    {
      .thunk_offset = 0x2b7318ULL,
      .landing_offset = 0x90e50ULL,
      .thunk_bytes = {0xe9, 0x33, 0x9b, 0xdd, 0xff, 0xcc, 0xcc, 0xcc},
      .thunk_size = 8,
      .landing_bytes = CC32,
      .framework_exclusive = 1,
    },
  },
  .malloc_offset = 0xc04a50ULL,
  .free_offset = 0xc04cf0ULL,
  .malloc_type_offset = 0x2ad5670ULL,
  .malloc_nowait = 1U,
  .malloc_waitok = 2U,
  .malloc_zero = 0x100U,
  .thread_retval0_offset = 0x408U,
  .all_core_guest_tlb_offset = 0x8e2ef0ULL,
  .all_core_instruction_offset = 0x8e3140ULL,
};

static int displacement_reaches(uint64_t thunk, const uint8_t *bytes,
                                uint64_t landing)
{
  int32_t displacement;
  if (bytes[0] != 0xe9)
    return 0;
  memcpy(&displacement, bytes + 1, sizeof(displacement));
  return thunk + 5 + (int64_t)displacement == landing;
}

int fw1060_profile_validate(void)
{
  const fw1060_profile_t *p = &g_fw1060_profile;
  if (p->firmware != FW1060_FIRMWARE || p->soc_id != FW1060_SOC_ID ||
      p->cpu_count != FW1060_CPU_COUNT ||
      p->syscall_count != FW1060_SYSCALL_COUNT ||
      p->sysent_size != 0x30U || p->sy_call_offset + sizeof(uint64_t) > p->sysent_size ||
      p->sysentvec_size != 0x200U ||
      p->sysentvec_table_offset + sizeof(uint64_t) > p->sysentvec_size ||
      p->router_uap_syscall_backoff != 0x10 ||
      p->thread_retval0_offset != 0x408U ||
      p->all_core_guest_tlb_offset == 0 || p->all_core_instruction_offset == 0)
    return -1;
  if (!displacement_reaches(p->temporary_thunk_offset,
                            p->temporary_thunk_bytes,
                            p->temporary_landing_offset))
    return -1;
  for (size_t i = 0; i < FW1060_CFI_PAIR_COUNT; ++i) {
    const fw1060_cfi_pair_t *pair = &p->cfi_pairs[i];
    if (!pair->framework_exclusive || pair->thunk_size != 8 ||
        !displacement_reaches(pair->thunk_offset, pair->thunk_bytes,
                              pair->landing_offset))
      return -1;
  }
  return 0;
}

int fw1060_identity_validate(uint32_t firmware, uint32_t soc_id,
                             uint32_t cpu_count)
{
  return fw1060_profile_validate() == 0 &&
         firmware == g_fw1060_profile.firmware &&
         soc_id == g_fw1060_profile.soc_id &&
         cpu_count == g_fw1060_profile.cpu_count ? 0 : -1;
}

int fw1060_router_syscall_number(const void *uap, uint32_t *number)
{
  uint32_t selected;
  if (!uap || !number || fw1060_profile_validate() != 0)
    return -1;
  memcpy(&selected, (const uint8_t *)uap -
                    g_fw1060_profile.router_uap_syscall_backoff,
         sizeof(selected));
  if (selected >= g_fw1060_profile.syscall_count)
    return -1;
  *number = selected;
  return 0;
}

int fw1060_verify_cfi_pair(const fw1060_cfi_pair_t *pair,
                           const uint8_t thunk[FW1060_CFI_BYTES_MAX],
                           const uint8_t landing[FW1060_LANDING_BYTES])
{
  if (!pair || !thunk || !landing || !pair->framework_exclusive ||
      pair->thunk_size != FW1060_CFI_BYTES_MAX ||
      memcmp(thunk, pair->thunk_bytes, pair->thunk_size) != 0 ||
      memcmp(landing, pair->landing_bytes, FW1060_LANDING_BYTES) != 0)
    return -1;
  return displacement_reaches(pair->thunk_offset, thunk,
                              pair->landing_offset) ? 0 : -1;
}

size_t fw1060_reserved_text_pages(uint64_t *pages, size_t capacity)
{
  size_t count = 0;
  if (!pages)
    return 0;
  for (size_t pair_index = 0; pair_index < FW1060_CFI_PAIR_COUNT;
       ++pair_index) {
    const fw1060_cfi_pair_t *pair = &g_fw1060_profile.cfi_pairs[pair_index];
    const uint64_t offsets[2] = {
      pair->thunk_offset & ~0xfffULL,
      pair->landing_offset & ~0xfffULL,
    };
    for (size_t side = 0; side < 2; ++side) {
      size_t existing;
      for (existing = 0; existing < count; ++existing)
        if (pages[existing] == offsets[side])
          break;
      if (existing != count)
        continue;
      if (count >= capacity)
        return 0;
      pages[count++] = offsets[side];
    }
  }
  return count;
}
