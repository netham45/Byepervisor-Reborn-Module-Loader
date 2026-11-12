#ifndef FIRMWARE_PROFILE1060_H
#define FIRMWARE_PROFILE1060_H

#include <stddef.h>
#include <stdint.h>

#define FW1060_CFI_PAIR_COUNT 4U
#define FW1060_CFI_BYTES_MAX 8U
#define FW1060_FIRMWARE 0x10600006U
#define FW1060_SOC_ID 0x00840f80U
#define FW1060_CPU_COUNT 16U
#define FW1060_SYSCALL_COUNT 734U

#define FW1060_LANDING_BYTES 32U
#define FW1060_ROUTER_PATH_COUNT 4U

#define FW1060_PAGE_PRESENT (1ULL << 0)
#define FW1060_PAGE_WRITABLE (1ULL << 1)
#define FW1060_PAGE_XOTEXT (1ULL << 58)
#define FW1060_PAGE_NX (1ULL << 63)
#define FW1060_PAGE_HUGE (1ULL << 7)
/* Retail 10.60 kernel ABI: malloc(size:RDI, type:RSI, flags:EDX)->RAX. */
typedef void *(*fw1060_malloc_fn_t)(size_t size, void *type, int flags);
/* Retail 10.60 kernel ABI: free(allocation:RDI, type:RSI). */
typedef void (*fw1060_free_fn_t)(void *allocation, void *type);


typedef struct {
  uint64_t thunk_offset;
  uint64_t landing_offset;
  uint8_t thunk_bytes[FW1060_CFI_BYTES_MAX];
  uint8_t thunk_size;
  uint8_t landing_bytes[FW1060_LANDING_BYTES];
  uint8_t framework_exclusive;
} fw1060_cfi_pair_t;

typedef struct {
  uint32_t firmware;
  uint32_t soc_id;
  uint32_t cpu_count;
  uint32_t syscall_count;
  uint64_t proc_p_sysent_offset;
  uint64_t sysent_offset;
  uint32_t sysent_size;
  uint32_t sy_call_offset;
  uint64_t sysentvec_offset;
  uint32_t sysentvec_size;
  uint32_t sysentvec_table_offset;
  int32_t router_uap_syscall_backoff;
  uint64_t router_path_offsets[FW1060_ROUTER_PATH_COUNT];
  uint64_t temporary_thunk_offset;
  uint64_t temporary_landing_offset;
  uint8_t temporary_thunk_bytes[5];
  uint8_t temporary_landing_bytes[FW1060_LANDING_BYTES];
  fw1060_cfi_pair_t cfi_pairs[FW1060_CFI_PAIR_COUNT];
  uint64_t malloc_offset;
  uint64_t free_offset;
  /* Text-base-relative address of the verified malloc type object. */
  uint64_t malloc_type_offset;
  uint32_t malloc_nowait;
  uint32_t malloc_waitok;
  uint32_t malloc_zero;
  uint32_t thread_retval0_offset;
  uint64_t all_core_guest_tlb_offset;
  uint64_t all_core_instruction_offset;
} fw1060_profile_t;

extern const fw1060_profile_t g_fw1060_profile;

int fw1060_profile_validate(void);
int fw1060_identity_validate(uint32_t firmware, uint32_t soc_id,
                             uint32_t cpu_count);
int fw1060_router_syscall_number(const void *uap, uint32_t *number);
int fw1060_verify_cfi_pair(const fw1060_cfi_pair_t *pair,
                           const uint8_t thunk[FW1060_CFI_BYTES_MAX],
                           const uint8_t landing[FW1060_LANDING_BYTES]);
size_t fw1060_reserved_text_pages(uint64_t *pages, size_t capacity);

#endif
