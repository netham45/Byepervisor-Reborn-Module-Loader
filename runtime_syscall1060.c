#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <ps5/kernel.h>

#include "kdlsym.h"
#include "runtime_exec1060.h"
#include "paging.h"
#include "util.h"

#define RESULT_PORT 9634
#define TEST_SYSCALL 20ULL
#define EXPECTED_RESULT 0x01060699ULL
#define CLONE_TABLE_OFFSET 0x10000ULL
#define CLONE_VECTOR_OFFSET 0x19000ULL
#define EXPECTED_RESULT 0x01060699ULL


static int accept_client(void)
{
  struct sockaddr_in address = {0};
  struct timeval timeout = {60, 0};
  int one = 1;
  int server = socket(AF_INET, SOCK_STREAM, 0);
  if (server < 0)
    return -1;
  address.sin_family = AF_INET;
  address.sin_port = htons(RESULT_PORT);
  address.sin_addr.s_addr = htonl(INADDR_ANY);
  setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  setsockopt(server, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  if (bind(server, (struct sockaddr *)&address, sizeof(address)) != 0 ||
      listen(server, 1) != 0) {
    close(server);
    return -1;
  }
  int client = accept(server, NULL, NULL);
  close(server);
  if (client >= 0) {
    struct timeval client_timeout = {10, 0};
    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &client_timeout,
               sizeof(client_timeout));
  }
  return client;
}

static int phase(int client, const char *name, uint64_t a, uint64_t b)
{
  char line[192], ack;
  int n = snprintf(line, sizeof(line),
                   "RUNTIME_SYSCALL_PHASE %s a=%016llx b=%016llx\n", name,
                   (unsigned long long)a, (unsigned long long)b);
  if (n <= 0 || send(client, line, (size_t)n, 0) != n)
    return -1;
  return recv(client, &ack, 1, 0) == 1 ? 0 : -1;
}

typedef struct {
  uint64_t result;
  unsigned char carry;
} thread_call_result_t;

static uint64_t raw_test_syscall(unsigned char *carry)
{
  uint64_t result = TEST_SYSCALL;
  unsigned char cf;
  __asm__ volatile("syscall\n\tsetc %1"
                   : "+a"(result), "=qm"(cf)
                   :
                   : "rcx", "r11", "memory", "cc");
  *carry = cf;
  return result;
}

static void *thread_test_syscall(void *argument)
{
  thread_call_result_t *call = argument;
  call->result = raw_test_syscall(&call->carry);
  return NULL;
}
#define PHASE0_HANDLER_SIZE 40U

static void build_phase0_handler(uint8_t handler[PHASE0_HANDLER_SIZE],
                                 uint64_t tlb_all, uint64_t instruction_all)
{
  static const uint8_t prefix[] = {0x57, 0x48, 0xb8};
  static const uint8_t between[] = {0xff, 0xd0, 0x48, 0xb8};
  static const uint8_t suffix[] = {
    0xff, 0xd0, 0x5f, 0x48, 0xc7, 0x87, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x31, 0xc0, 0xc3
  };
  size_t offset = 0;
  memcpy(handler + offset, prefix, sizeof(prefix));
  offset += sizeof(prefix);
  memcpy(handler + offset, &tlb_all, sizeof(tlb_all));
  offset += sizeof(tlb_all);
  memcpy(handler + offset, between, sizeof(between));
  offset += sizeof(between);
  memcpy(handler + offset, &instruction_all, sizeof(instruction_all));
  offset += sizeof(instruction_all);
  memcpy(handler + offset, suffix, sizeof(suffix));
  {
    uint32_t retval_offset = g_fw1060_profile.thread_retval0_offset;
    uint32_t expected = (uint32_t)EXPECTED_RESULT;
    memcpy(handler + 29, &retval_offset, sizeof(retval_offset));
    memcpy(handler + 33, &expected, sizeof(expected));
  }
}



static int copy_kernel_region(uint64_t destination, uint64_t source,
                              size_t length)
{
  uint8_t page[0x1000];
  while (length) {
    size_t chunk = length < sizeof(page) ? length : sizeof(page);
    if (kernel_copyout(source, page, chunk) != 0 ||
        kernel_copyin(page, destination, chunk) != 0)
      return -1;
    source += chunk;
    destination += chunk;
    length -= chunk;
  }
  return 0;
}

static int report_guest_mapping(int client, uint64_t pmap, uint64_t address,
                                const runtime_exec1060_page_t *published,
                                uint64_t *current_leaf)
{
  static const char *const names[] = {
    "guest-pml4e", "guest-pdpe", "guest-pde", "guest-pte"
  };
  uint64_t entry_address[4] = {0}, entry[4] = {0};
  uint64_t physical = 0, published_physical;
  uint64_t checks = 0x0f;
  int count = 2;

  entry_address[0] = find_pml4e(pmap, address, &entry[0]);
  entry_address[1] = find_pdpe(pmap, address, &entry[1]);
  if (entry_address[0] == UINT64_MAX || entry_address[1] == UINT64_MAX)
    return -1;
  if (!(entry[1] & (1ULL << 7))) {
    entry_address[2] = find_pde(pmap, address, &entry[2]);
    if (entry_address[2] == UINT64_MAX)
      return -1;
    count = 3;
    if (!(entry[2] & (1ULL << 7))) {
      entry_address[3] = find_pte(pmap, address, &entry[3]);
      if (entry_address[3] == UINT64_MAX)
        return -1;
      count = 4;
    }
  }

  for (int i = 0; i < count; ++i) {
    if (!(entry[i] & 1))
      checks &= ~1ULL;
    if (!(entry[i] & 2))
      checks &= ~2ULL;
    if (entry[i] & (1ULL << 63))
      checks &= ~4ULL;
    if (entry[i] & (1ULL << 58))
      checks &= ~8ULL;
    if (phase(client, names[i], entry_address[i], entry[i]))
      return -1;
  }

  if (count == 2)
    physical = (entry[1] & 0x000fffffc0000000ULL) +
               (address & 0x3fffffff);
  else if (count == 3)
    physical = (entry[2] & 0x000fffffffe00000ULL) +
               (address & 0x1fffff);
  else
    physical = (entry[3] & 0x000ffffffffff000ULL) +
               (address & 0xfff);
  *current_leaf = entry[count - 1];
  if (entry_address[count - 1] == published->pte_address)
    checks |= 1ULL << 4;
  if (runtime_exec1060_pte_invariant_equal(published->pte_value,
                                           *current_leaf))
    checks |= 1ULL << 5;
  if (count == 4)
    checks |= 1ULL << 6;
  published_physical =
      (published->pte_value & 0x000ffffffffff000ULL) + (address & 0xfff);
  if (physical == published_physical)
    checks |= 1ULL << 7;
  if (phase(client, "guest-effective", physical,
            checks | ((uint64_t)count << 32)))
    return -1;
  return (checks & 0xff) == 0xff ? 0 : -2;
}


int main(void)
{
  int client = accept_client();
  if (client < 0)
    return 1;

  uint64_t cave = kdlsym(KERNEL_SYM_DATA_CAVE);
  uint64_t proc = kernel_get_proc(getpid());
  uint64_t target = 0;
  uint64_t cfi_thunk = KERNEL_ADDRESS_TEXT_BASE +
                       RUNTIME_EXEC1060_CFI_THUNK_OFFSET;
  uint64_t cfi_target = KERNEL_ADDRESS_TEXT_BASE +
                        RUNTIME_EXEC1060_CFI_TARGET_OFFSET;
  uint64_t stock_table = KERNEL_ADDRESS_DATA_BASE +
                         g_fw1060_profile.sysent_offset;
  uint64_t stock_vector_address = KERNEL_ADDRESS_DATA_BASE +
                                  g_fw1060_profile.sysentvec_offset;
  uint64_t clone_table = cave + CLONE_TABLE_OFFSET;
  uint64_t clone_vector = cave + CLONE_VECTOR_OFFSET;
  uint64_t clone_handler_address = clone_table +
      TEST_SYSCALL * g_fw1060_profile.sysent_size +
      g_fw1060_profile.sy_call_offset;
  uint64_t stock_vector = 0, stock_vector_table = 0;
  uint64_t current_vector = 0, active_vector = 0;
  uint64_t installed_handler = 0, installed_table = 0, result = 0;
  uint64_t tlb_all = KERNEL_ADDRESS_TEXT_BASE +
                     g_fw1060_profile.all_core_guest_tlb_offset;
  uint64_t instruction_all = KERNEL_ADDRESS_TEXT_BASE +
                             g_fw1060_profile.all_core_instruction_offset;
  uint8_t expected_handler[PHASE0_HANDLER_SIZE] = {0};
  uint8_t verify[PHASE0_HANDLER_SIZE] = {0};
  uint8_t saved_cfi_target[RUNTIME_EXEC1060_CFI_TARGET_SIZE] = {0};
  uint8_t cfi_target_verify[RUNTIME_EXEC1060_CFI_TARGET_SIZE] = {0};
  uint8_t requested_cfi_target[RUNTIME_EXEC1060_CFI_TARGET_SIZE] = {0};
  uint8_t cfi_thunk_bytes[8] = {0};
  uint8_t trampoline[12] = {0x48, 0xb8};
  uint8_t reserved_thunks[FW1060_CFI_PAIR_COUNT][FW1060_CFI_BYTES_MAX] = {{0}};
  uint8_t reserved_landings[FW1060_CFI_PAIR_COUNT][FW1060_LANDING_BYTES] = {{0}};
  uint64_t handler_words[5] = {0}, sysent_words[6] = {0};
  uint64_t vector_words[4] = {0}, cfi_thunk_words = 0;
  uint64_t proc0 = 0, vmspace = 0, pmap = 0, pml4 = 0, cr3 = 0;
  uint64_t current_leaf = 0;
  unsigned char carry = 0;
  int vector_switched = 0, trampoline_written = 0, status = 0;
  pthread_t worker;
  thread_call_result_t worker_call = {0};
  int worker_started = 0;
  runtime_exec1060_page_t runtime_page = {0};

  build_phase0_handler(expected_handler, tlb_all, instruction_all);
  if (fw1060_identity_validate(kernel_get_fw_version(),
                               sceKernelGetMainSocId(),
                               FW1060_CPU_COUNT) != 0 ||
      TEST_SYSCALL >= g_fw1060_profile.syscall_count ||
      phase(client, "profile-preflight", g_fw1060_profile.firmware,
            ((uint64_t)g_fw1060_profile.soc_id << 32) |
            g_fw1060_profile.cpu_count) != 0) {
    status = 9;
    goto report;
  }

  if (!cave || !proc ||
      kernel_copyout(cave + RUNTIME_EXEC1060_CAVE_OFFSET, &runtime_page,
                     sizeof(runtime_page)) != 0 ||
      !runtime_exec1060_is_post_resume_verified(&runtime_page) ||
      (runtime_page.address >> 48) != 0xffff ||
      !(runtime_page.pte_value & 1) ||
      !(runtime_page.pte_value & 2) ||
      (runtime_page.pte_value & ((1ULL << 58) | (1ULL << 63)))) {
    status = 10;
    goto report;
  }
  target = runtime_page.address;
  if (phase(client, "post-resume-verified",
            runtime_page.post_resume_state, runtime_page.magic) != 0 ||
      phase(client, "runtime-handler-page-ready", runtime_page.pte_address,
            runtime_page.pte_value) != 0) {
    status = 3;
    goto report;
  }
  proc0 = kernel_get_proc(0);
  if (!proc0 ||
      kernel_copyout(proc0 + 0x200, &vmspace, 8) != 0 || !vmspace ||
      kernel_copyout(vmspace + 0x1d8, &pmap, 8) != 0 || !pmap ||
      kernel_copyout(pmap + 0x20, &pml4, 8) != 0 || !pml4 ||
      kernel_copyout(pmap + 0x28, &cr3, 8) != 0 || !cr3) {
    status = 11;
    goto report;
  }
  kdset_dmap_1060(pml4 - cr3);
  if (report_guest_mapping(client, pmap, target, &runtime_page,
                           &current_leaf) != 0) {
    status = 11;
    goto report;
  }
  if (phase(client, "layout-read-start",
            proc + g_fw1060_profile.proc_p_sysent_offset,
            stock_vector_address) != 0) {
    status = 3;
    goto report;
  }
  if (kernel_copyout(proc + g_fw1060_profile.proc_p_sysent_offset,
                     &stock_vector, 8) != 0 ||
      kernel_copyout(stock_vector_address +
                     g_fw1060_profile.sysentvec_table_offset,
                     &stock_vector_table, 8) != 0 ||
      stock_vector != stock_vector_address ||
      stock_vector_table != stock_table) {
    status = 12;
    goto report;
  }
  if (phase(client, "layout-read-done", stock_vector,
            stock_vector_table) != 0 ||
      phase(client, "temporary-pair-read-start", cfi_thunk,
            cfi_target) != 0) {
    status = 3;
    goto report;
  }
  if (kernel_copyout(cfi_thunk, cfi_thunk_bytes,
                     sizeof(cfi_thunk_bytes)) != 0 ||
      kernel_copyout(cfi_target, saved_cfi_target,
                     sizeof(saved_cfi_target)) != 0 ||
      memcmp(cfi_thunk_bytes, g_fw1060_profile.temporary_thunk_bytes,
             sizeof(g_fw1060_profile.temporary_thunk_bytes)) != 0 ||
      memcmp(saved_cfi_target, g_fw1060_profile.temporary_landing_bytes,
             sizeof(saved_cfi_target)) != 0) {
    status = 12;
    goto report;
  }
  if (phase(client, "temporary-pair-preflight", cfi_thunk,
            cfi_target) != 0) {
    status = 3;
    goto report;
  }
  for (unsigned i = 0; i < FW1060_CFI_PAIR_COUNT; ++i) {
    const fw1060_cfi_pair_t *pair = &g_fw1060_profile.cfi_pairs[i];
    uint64_t thunk = KERNEL_ADDRESS_TEXT_BASE + pair->thunk_offset;
    uint64_t landing = KERNEL_ADDRESS_TEXT_BASE + pair->landing_offset;
    for (unsigned side = 0; side < 2; ++side) {
      const uint64_t address = side == 0 ? thunk : landing;
      uint64_t leaf = 0, leaf_address = 0;
      unsigned levels = 0;
      if (!runtime_page.reservation_pte_address[i][side] ||
          find_mapping_leaf(pmap, address, &leaf_address, &leaf,
                            &levels) != 0 ||
          !runtime_exec1060_mapping_contract_matches(
              runtime_page.reservation_pte_address[i][side],
              runtime_page.reservation_pte_value[i][side],
              runtime_page.reservation_levels[i][side],
              leaf_address, leaf, levels) ||
          !(leaf & FW1060_PAGE_PRESENT) ||
          !(leaf & FW1060_PAGE_WRITABLE) ||
          (leaf & (FW1060_PAGE_XOTEXT | FW1060_PAGE_NX)) ||
          phase(client, "reserved-page-preflight", leaf_address, leaf) != 0) {
        status = 14;
        goto report;
      }
    }
    if (phase(client, "reserved-pair-read-start", thunk, landing) != 0 ||
        kernel_copyout(thunk, reserved_thunks[i],
                       sizeof(reserved_thunks[i])) != 0 ||
        kernel_copyout(landing, reserved_landings[i],
                       sizeof(reserved_landings[i])) != 0 ||
        fw1060_verify_cfi_pair(pair, reserved_thunks[i],
                               reserved_landings[i]) != 0 ||
        phase(client, "reserved-pair-preflight", thunk, landing) != 0) {
      status = 14;
      goto report;
    }
  }
  if (phase(client, "layout-preflight", stock_vector, stock_vector_table) != 0 ||
      phase(client, "rollback-order",
            proc + g_fw1060_profile.proc_p_sysent_offset, cfi_target) != 0 ||
      phase(client, "handler-write-start", target,
            sizeof(expected_handler)) != 0 ||
      kernel_copyin(expected_handler, target, sizeof(expected_handler)) != 0 ||
      kernel_copyout(target, verify, sizeof(verify)) != 0 ||
      kernel_copyout(target, handler_words, sizeof(handler_words)) != 0) {
    status = 1;
    goto report;
  }
  if (memcmp(verify, expected_handler, sizeof(expected_handler)) != 0) {
    status = 2;
    goto report;
  }
  for (unsigned i = 0; i < 5; ++i) {
    char name[24];
    snprintf(name, sizeof(name), "handler-q%u", i);
    if (phase(client, name, target + i * 8, handler_words[i]) != 0) {
      status = 3;
      goto report;
    }
  }
  if (phase(client, "preflight-ok", proc, stock_vector) != 0) {
    status = 3;
    goto report;
  }
  memcpy(&cfi_thunk_words, cfi_thunk_bytes, sizeof(cfi_thunk_words));
  memcpy(trampoline + 2, &target, sizeof(target));
  trampoline[10] = 0xff;
  trampoline[11] = 0xe0;
  memcpy(requested_cfi_target, saved_cfi_target,
         sizeof(requested_cfi_target));
  memcpy(requested_cfi_target, trampoline, sizeof(trampoline));
  if (phase(client, "landing-write-start", cfi_target, target) != 0 ||
      kernel_copyin(requested_cfi_target, cfi_target,
                    sizeof(requested_cfi_target)) != 0) {
    status = 12;
    goto cleanup;
  }
  trampoline_written = 1;
  if (kernel_copyout(cfi_target, cfi_target_verify,
                     sizeof(cfi_target_verify)) != 0 ||
      memcmp(cfi_target_verify, requested_cfi_target,
             sizeof(cfi_target_verify)) != 0 ||
      phase(client, "landing-write-done", cfi_target,
            *(uint64_t *)cfi_target_verify) != 0) {
    status = 12;
    goto cleanup;
  }
  if (phase(client, "cfi-thunk", cfi_thunk, cfi_thunk_words) ||
      phase(client, "cfi-trampoline", cfi_target, target)) {
    status = 3;
    goto cleanup;
  }

  if (phase(client, "clone-copy-start", clone_table, clone_vector) != 0) {
    status = 3;
    goto cleanup;
  }
  if (copy_kernel_region(clone_table, stock_table,
                         (size_t)g_fw1060_profile.syscall_count *
                         g_fw1060_profile.sysent_size) != 0 ||
      copy_kernel_region(clone_vector, stock_vector_address,
                         g_fw1060_profile.sysentvec_size) != 0 ||
      kernel_copyin(&cfi_thunk, clone_handler_address, 8) != 0 ||
      kernel_copyin(&clone_table, clone_vector +
                    g_fw1060_profile.sysentvec_table_offset, 8) != 0 ||
      kernel_copyout(clone_handler_address, &installed_handler, 8) != 0 ||
      kernel_copyout(clone_vector +
                     g_fw1060_profile.sysentvec_table_offset,
                     &installed_table, 8) != 0 ||
      kernel_copyout(clone_table +
                     TEST_SYSCALL * g_fw1060_profile.sysent_size,
                     sysent_words, sizeof(sysent_words)) != 0 ||
      kernel_copyout(clone_vector, vector_words, sizeof(vector_words)) != 0 ||
      installed_handler != cfi_thunk || installed_table != clone_table) {
    status = 4;
    goto cleanup;
  }
  if (phase(client, "clone-copy-done", installed_table,
            installed_handler) != 0) {
    status = 3;
    goto cleanup;
  }
  for (int i = 0; i < 3; ++i) {
    char name[24];
    snprintf(name, sizeof(name), "sysent-q%d-q%d", i * 2, i * 2 + 1);
    if (phase(client, name, sysent_words[i * 2], sysent_words[i * 2 + 1])) {
      status = 3;
      goto cleanup;
    }
  }
  if (phase(client, "sysentvec-q0-q1", vector_words[0], vector_words[1]) ||
      phase(client, "sysentvec-q2-q3", vector_words[2], vector_words[3])) {
    status = 3;
    goto cleanup;
  }


  if (phase(client, "vector-switch-start",
            proc + g_fw1060_profile.proc_p_sysent_offset,
            clone_vector) != 0) {
    status = 3;
    goto cleanup;
  }
  if (kernel_copyin(&clone_vector,
                    proc + g_fw1060_profile.proc_p_sysent_offset, 8) != 0) {
    status = 6;
    goto cleanup;
  }
  vector_switched = 1;
  if (kernel_copyout(proc + g_fw1060_profile.proc_p_sysent_offset,
                     &active_vector, 8) != 0 ||
      kernel_copyout(clone_handler_address, &installed_handler, 8) != 0 ||
      kernel_copyout(clone_vector +
                     g_fw1060_profile.sysentvec_table_offset,
                     &installed_table, 8) != 0) {
    status = 6;
    goto cleanup;
  }
  if (phase(client, "vector-switch-done", active_vector, installed_table) != 0 ||
      phase(client, "syscall-live", clone_handler_address,
            installed_handler) != 0 ||
      phase(client, "call-start", TEST_SYSCALL, target) != 0) {
    status = 3;
    goto cleanup;
  }

  result = raw_test_syscall(&carry);
  status = (!carry && result == EXPECTED_RESULT) ? 0 : 7;
  if (phase(client, "main-call-returned", result, carry) != 0 && status == 0)
    status = 3;
  if (status == 0 &&
      phase(client, "thread-attach-start", proc, clone_vector) == 0 &&
      pthread_create(&worker, NULL, thread_test_syscall, &worker_call) == 0) {
    worker_started = 1;
    if (pthread_join(worker, NULL) != 0) {
      status = 15;
    } else {
      worker_started = 0;
      if (worker_call.carry || worker_call.result != EXPECTED_RESULT)
        status = 15;
      if (phase(client, "thread-call-returned", worker_call.result,
                worker_call.carry) != 0 && status == 0)
        status = 3;
    }
  } else if (status == 0) {
    status = 15;
  }

cleanup:
  if (worker_started) {
    pthread_join(worker, NULL);
    worker_started = 0;
  }
  if (vector_switched) {
    uint64_t observed = 0;
    if (phase(client, "rollback-vector-start",
              proc + g_fw1060_profile.proc_p_sysent_offset,
              stock_vector) != 0 ||
        kernel_copyout(proc + g_fw1060_profile.proc_p_sysent_offset,
                       &observed, 8) != 0 ||
        observed != clone_vector ||
        kernel_copyin(&stock_vector,
                      proc + g_fw1060_profile.proc_p_sysent_offset, 8) != 0 ||
        kernel_copyout(proc + g_fw1060_profile.proc_p_sysent_offset,
                       &current_vector, 8) != 0 ||
        current_vector != stock_vector) {
      status = 16;
    }
    if (status == 16) {
      phase(client, "rollback-quarantined", current_vector, stock_vector);
    } else {
      phase(client, "rollback-vector-done", current_vector, stock_vector);
    }
  }
  if (trampoline_written && status != 16) {
    if (phase(client, "rollback-landing-start", cfi_target,
              *(uint64_t *)saved_cfi_target) != 0 ||
        kernel_copyin(saved_cfi_target, cfi_target,
                      sizeof(saved_cfi_target)) != 0 ||
        kernel_copyout(cfi_target, cfi_target_verify,
                       sizeof(cfi_target_verify)) != 0 ||
        memcmp(cfi_target_verify, saved_cfi_target,
               sizeof(saved_cfi_target)) != 0) {
      status = 17;
    }
    phase(client, status == 17 ? "rollback-quarantined" :
          "rollback-landing-done", cfi_target,
          *(uint64_t *)cfi_target_verify);
  }

report:
  {
    char line[384];
    int n = snprintf(line, sizeof(line),
        "RUNTIME_SYSCALL status=%d proc=%016llx exec_page=%016llx "
        "pte_addr=%016llx armed_pte=%016llx current_pte=%016llx "
        "stock_vec=%016llx active_vec=%016llx clone_vec=%016llx "
        "clone_table=%016llx handler=%016llx result=%llu/%u "
        "restored_vec=%016llx\n",
        status, (unsigned long long)proc,
        (unsigned long long)runtime_page.address,
        (unsigned long long)runtime_page.pte_address,
        (unsigned long long)runtime_page.pte_value,
        (unsigned long long)current_leaf,
        (unsigned long long)stock_vector,
        (unsigned long long)active_vector,
        (unsigned long long)clone_vector, (unsigned long long)clone_table,
        (unsigned long long)installed_handler,
        (unsigned long long)result, carry,
        (unsigned long long)current_vector);
    if (n > 0)
      send(client, line, (size_t)n, 0);
  }
  close(client);
  return status;
}