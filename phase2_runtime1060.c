#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>

#include <ps5/kernel.h>

#include "firmware_profile1060.h"
#include "kdlsym.h"
#include "paging.h"
#include "phase2_router1060.h"
#include "runtime_exec1060.h"
#include "util.h"

#define RESULT_PORT 9634
#define TEMP_SYSCALL 20U
#define TEMP_TABLE_OFFSET 0x10000ULL
#define TEMP_VECTOR_OFFSET 0x19000ULL
#define TEMP_HANDLER_MAX 192U
#define ATTACH_VECTOR_OFFSET 0x1000ULL
#define ATTACH_TABLE_OFFSET 0x2000ULL

#ifndef PHASE3_RUNTIME_EMBEDDED_RELEASE
static int accept_client(void)
{
  struct sockaddr_in address = {0};
  struct timeval timeout = {120, 0};
  int one = 1, server = socket(AF_INET, SOCK_STREAM, 0), client;
  if (server < 0)
    return -1;
  address.sin_family = AF_INET;
  address.sin_port = htons(RESULT_PORT);
  address.sin_addr.s_addr = htonl(INADDR_ANY);
  setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  setsockopt(server, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  if (bind(server, (struct sockaddr *)&address, sizeof(address)) ||
      listen(server, 1)) {
    close(server);
    return -1;
  }
  client = accept(server, NULL, NULL);
  close(server);
  if (client >= 0) {
    struct timeval client_timeout = {15, 0};
    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &client_timeout,
               sizeof(client_timeout));
  }
  return client;
}
#endif

static int phase(int client, const char *name, uint64_t a, uint64_t b)
{
#ifdef PHASE3_RUNTIME_EMBEDDED_RELEASE
  /*
   * Phase 2 is included directly by the Phase 3 runtime.  In unattended
   * Phase 3 builds this checkpoint has no remote gate: returning zero means
   * "no checkpoint failure", not that an ACK was received.  All local
   * predicates following phase(...) in || chains therefore still execute.
   */
  (void)client;
  (void)name;
  (void)a;
  (void)b;
  return 0;
#else
  char line[224], ack;
  int n = snprintf(line, sizeof(line),
      "PHASE2_ACK %s a=%016llx b=%016llx\n", name,
      (unsigned long long)a, (unsigned long long)b);
  if (n <= 0 || send(client, line, (size_t)n, 0) != n)
    return -1;
  return recv(client, &ack, 1, 0) == 1 ? 0 : -1;
#endif
}

static int copy_kernel_region(uint64_t destination, uint64_t source,
                              size_t length)
{
  uint8_t page[0x1000];
  while (length) {
    size_t chunk = length < sizeof(page) ? length : sizeof(page);
    if (kernel_copyout(source, page, chunk) ||
        kernel_copyin(page, destination, chunk))
      return -1;
    destination += chunk;
    source += chunk;
    length -= chunk;
  }
  return 0;
}

static uint64_t raw_syscall(unsigned number, uint64_t argument,
                            unsigned char *carry)
{
  register uint64_t rax __asm__("rax") = number;
  register uint64_t rdi __asm__("rdi") = argument;
  unsigned char cf;
  __asm__ volatile("syscall\n\tsetc %2"
                   : "+a"(rax), "+D"(rdi), "=qm"(cf)
                   : : "rcx", "r11", "memory", "cc");
  *carry = cf;
  return rax;
}

static size_t append(uint8_t *out, size_t at, const void *bytes, size_t count)
{
  memcpy(out + at, bytes, count);
  return at + count;
}

static size_t build_permission_handler(uint8_t out[TEMP_HANDLER_MAX],
                                       uint64_t leaf_address,
                                       uint64_t leaf_value)
{
  static const uint8_t push_save[] = {0x53, 0x48, 0x89, 0xfb};
  static const uint8_t mov_rdi[] = {0x48, 0xbf};
  static const uint8_t mov_rax[] = {0x48, 0xb8};
  static const uint8_t store[] = {0x48, 0x89, 0x07};
  static const uint8_t restore_rdi[] = {0x48, 0x89, 0xdf};
  static const uint8_t call_rax[] = {0xff, 0xd0};
  static const uint8_t store_zero[] = {0x48, 0xc7, 0x83};
  static const uint8_t done[] = {0, 0, 0, 0, 0x31, 0xc0, 0x5b, 0xc3};
  uint64_t tlb = KERNEL_ADDRESS_TEXT_BASE +
                 g_fw1060_profile.all_core_guest_tlb_offset;
  uint64_t insn = KERNEL_ADDRESS_TEXT_BASE +
                  g_fw1060_profile.all_core_instruction_offset;
  uint32_t retval = g_fw1060_profile.thread_retval0_offset;
  size_t at = 0;
  at = append(out, at, push_save, sizeof(push_save));
  at = append(out, at, mov_rdi, sizeof(mov_rdi));
  at = append(out, at, &leaf_address, 8);
  at = append(out, at, mov_rax, sizeof(mov_rax));
  at = append(out, at, &leaf_value, 8);
  at = append(out, at, store, sizeof(store));
  at = append(out, at, restore_rdi, sizeof(restore_rdi));
  at = append(out, at, mov_rax, sizeof(mov_rax));
  at = append(out, at, &tlb, 8);
  at = append(out, at, call_rax, sizeof(call_rax));
  at = append(out, at, restore_rdi, sizeof(restore_rdi));
  at = append(out, at, mov_rax, sizeof(mov_rax));
  at = append(out, at, &insn, 8);
  at = append(out, at, call_rax, sizeof(call_rax));
  at = append(out, at, store_zero, sizeof(store_zero));
  at = append(out, at, &retval, 4);
  at = append(out, at, done, sizeof(done));
  return at;
}

typedef struct {
  int client;
  uint64_t cave;
  uint64_t proc;
  uint64_t target;
  uint64_t original_vector;
  uint64_t original_table;
  uint64_t clone_table;
  uint64_t clone_vector;
  uint64_t thunk;
  uint64_t landing;
  uint8_t saved_landing[FW1060_LANDING_BYTES];
  uint8_t installed_landing[FW1060_LANDING_BYTES];
  int landing_written;
  int vector_switched;
  int quarantined;
} temporary_route_t;

static int temporary_route_open(temporary_route_t *route,
                                const runtime_exec1060_page_t *page,
                                const uint8_t *handler, size_t handler_size)
{
  uint8_t verify[TEMP_HANDLER_MAX] = {0}, thunk[FW1060_CFI_BYTES_MAX] = {0};
  uint8_t trampoline[12] = {0x48, 0xb8};
  uint64_t observed, installed_handler, installed_table;
  route->proc = kernel_get_proc(getpid());
  route->target = page->address;
  route->thunk = KERNEL_ADDRESS_TEXT_BASE +
                 g_fw1060_profile.temporary_thunk_offset;
  route->landing = KERNEL_ADDRESS_TEXT_BASE +
                   g_fw1060_profile.temporary_landing_offset;
  route->clone_table = route->cave + TEMP_TABLE_OFFSET;
  route->clone_vector = route->cave + TEMP_VECTOR_OFFSET;
  if (!route->proc || handler_size > sizeof(verify) ||
      kernel_copyout(route->proc + g_fw1060_profile.proc_p_sysent_offset,
                     &route->original_vector, 8) || !route->original_vector ||
      kernel_copyout(route->original_vector +
                     g_fw1060_profile.sysentvec_table_offset,
                     &route->original_table, 8) || !route->original_table ||
      kernel_copyout(route->thunk, thunk, sizeof(thunk)) ||
      memcmp(thunk, g_fw1060_profile.temporary_thunk_bytes,
             sizeof(g_fw1060_profile.temporary_thunk_bytes)) ||
      kernel_copyout(route->landing, route->saved_landing,
                     sizeof(route->saved_landing)) ||
      memcmp(route->saved_landing,
             g_fw1060_profile.temporary_landing_bytes,
             sizeof(route->saved_landing)) ||
      phase(route->client, "temp-route-preflight", route->original_vector,
            route->original_table) ||
      phase(route->client, "rollback-order", route->original_vector,
            route->landing))
    return -1;
  if (kernel_copyin(handler, route->target, handler_size) ||
      kernel_copyout(route->target, verify, handler_size) ||
      memcmp(handler, verify, handler_size) ||
      phase(route->client, "permission-handler-readback", route->target,
            handler_size))
    return -1;
  memcpy(route->installed_landing, route->saved_landing,
         sizeof(route->installed_landing));
  memcpy(trampoline + 2, &route->target, 8);
  trampoline[10] = 0xff;
  trampoline[11] = 0xe0;
  memcpy(route->installed_landing, trampoline, sizeof(trampoline));
  if (kernel_copyin(route->installed_landing, route->landing,
                    sizeof(route->installed_landing)))
    return -1;
  route->landing_written = 1;
  if (kernel_copyout(route->landing, verify,
                     sizeof(route->installed_landing)) ||
      memcmp(verify, route->installed_landing,
             sizeof(route->installed_landing)) ||
      phase(route->client, "temp-landing-readback", route->landing,
            *(uint64_t *)verify) ||
      copy_kernel_region(route->clone_table, route->original_table,
          g_fw1060_profile.syscall_count * g_fw1060_profile.sysent_size) ||
      copy_kernel_region(route->clone_vector, route->original_vector,
                         g_fw1060_profile.sysentvec_size) ||
      kernel_copyin(&route->thunk, route->clone_table +
          TEMP_SYSCALL * g_fw1060_profile.sysent_size +
          g_fw1060_profile.sy_call_offset, 8) ||
      kernel_copyin(&route->clone_table, route->clone_vector +
                    g_fw1060_profile.sysentvec_table_offset, 8) ||
      kernel_copyout(route->clone_table +
          TEMP_SYSCALL * g_fw1060_profile.sysent_size +
          g_fw1060_profile.sy_call_offset, &installed_handler, 8) ||
      kernel_copyout(route->clone_vector +
          g_fw1060_profile.sysentvec_table_offset, &installed_table, 8) ||
      installed_handler != route->thunk || installed_table != route->clone_table)
    return -1;
  if (kernel_copyout(route->proc + g_fw1060_profile.proc_p_sysent_offset,
                     &observed, 8) || observed != route->original_vector ||
      kernel_copyin(&route->clone_vector,
                    route->proc + g_fw1060_profile.proc_p_sysent_offset, 8))
    return -1;
  route->vector_switched = 1;
  if (kernel_copyout(route->proc + g_fw1060_profile.proc_p_sysent_offset,
                     &observed, 8) || observed != route->clone_vector ||
      phase(route->client, "temp-vector-live", observed, route->thunk))
    return -1;
  return 0;
}

static int temporary_route_close(temporary_route_t *route)
{
  uint64_t observed = 0;
  uint8_t bytes[FW1060_LANDING_BYTES];
  int failed = 0;
  if (route->vector_switched) {
    if (kernel_copyout(route->proc + g_fw1060_profile.proc_p_sysent_offset,
                       &observed, 8) || observed != route->clone_vector ||
        kernel_copyin(&route->original_vector,
                      route->proc + g_fw1060_profile.proc_p_sysent_offset, 8) ||
        kernel_copyout(route->proc + g_fw1060_profile.proc_p_sysent_offset,
                       &observed, 8) || observed != route->original_vector ||
        phase(route->client, "temp-vector-restored", observed,
              route->original_vector))
      failed = 1;
    else
      route->vector_switched = 0;
  }
  if (route->landing_written && !failed) {
    if (kernel_copyout(route->landing, bytes, sizeof(bytes)) ||
        memcmp(bytes, route->installed_landing, sizeof(bytes)) ||
        kernel_copyin(route->saved_landing, route->landing, sizeof(bytes)) ||
        kernel_copyout(route->landing, bytes, sizeof(bytes)) ||
        memcmp(bytes, route->saved_landing, sizeof(bytes)) ||
        phase(route->client, "temp-landing-restored", route->landing,
              *(uint64_t *)bytes))
      failed = 1;
    else
      route->landing_written = 0;
  }
  if (failed) {
    route->quarantined = 1;
    phase(route->client, "QUARANTINED", observed, route->landing);
    return -1;
  }
  return 0;
}

static int validate_mapping_contracts(int client,
                                      const runtime_exec1060_page_t *page)
{
  uint64_t proc0, vmspace, pmap, pml4, cr3;
  proc0 = kernel_get_proc(0);
  if (!proc0 || kernel_copyout(proc0 + 0x200, &vmspace, 8) || !vmspace ||
      kernel_copyout(vmspace + 0x1d8, &pmap, 8) || !pmap ||
      kernel_copyout(pmap + 0x20, &pml4, 8) || !pml4 ||
      kernel_copyout(pmap + 0x28, &cr3, 8) || !cr3)
    return -1;
  kdset_dmap_1060(pml4 - cr3);
  for (unsigned i = 0; i < FW1060_CFI_PAIR_COUNT; ++i) {
    for (unsigned side = 0; side < 2; ++side) {
      uint64_t va = KERNEL_ADDRESS_TEXT_BASE +
          (side ? g_fw1060_profile.cfi_pairs[i].landing_offset :
                  g_fw1060_profile.cfi_pairs[i].thunk_offset);
      uint64_t leaf_address, leaf;
      unsigned levels;
      if (find_mapping_leaf(pmap, va, &leaf_address, &leaf, &levels) ||
          !runtime_exec1060_mapping_contract_matches(
              page->reservation_pte_address[i][side],
              page->reservation_pte_value[i][side],
              page->reservation_levels[i][side], leaf_address, leaf, levels) ||
          !(leaf & FW1060_PAGE_WRITABLE) ||
          (leaf & (FW1060_PAGE_XOTEXT | FW1060_PAGE_NX)) ||
          phase(client, "reserved-leaf", leaf_address,
                leaf | ((uint64_t)levels << 60)))
        return -1;
    }
  }
  return 0;
}

static int write_global(uint64_t address, const phase2_router_global_t *global)
{
  phase2_router_global_t readback;
  return kernel_copyin(global, address, sizeof(*global)) ||
         kernel_copyout(address, &readback, sizeof(readback)) ||
         memcmp(global, &readback, sizeof(readback));
}

static int resolve_kernel_pmap(uint64_t *out)
{
  uint64_t proc0, vmspace, pmap;
  proc0 = kernel_get_proc(0);
  if (!out || !proc0 ||
      kernel_copyout(proc0 + 0x200, &vmspace, sizeof(vmspace)) || !vmspace ||
      kernel_copyout(vmspace + 0x1d8, &pmap, sizeof(pmap)) || !pmap)
    return -1;
  *out = pmap;
  return 0;
}

static int verify_router_permissions(const phase2_router_global_t *global,
                                     int require_final, uint64_t pmap)
{
  uint64_t address, value;
  unsigned levels;
  if (!pmap && resolve_kernel_pmap(&pmap))
    return 1;
  if (find_mapping_leaf(pmap, global->code_address, &address, &value, &levels) ||
      levels != 4 || address != global->code_leaf_address ||
      !runtime_exec1060_pte_invariant_equal(
          require_final ? global->code_leaf_final : global->code_leaf_original,
          value) || (value & (FW1060_PAGE_NX | FW1060_PAGE_XOTEXT)) ||
      (require_final && (value & FW1060_PAGE_WRITABLE)))
    return 2;
  if (find_mapping_leaf(pmap, global->state_address, &address, &value, &levels) ||
      levels != 4 || address != global->data_leaf_address ||
      !(value & FW1060_PAGE_WRITABLE) || !(value & FW1060_PAGE_NX))
    return 3;
  for (unsigned i = 0; i < PHASE2_CLONE_PAGE_COUNT; ++i)
    if (find_mapping_leaf(pmap, global->clone_address + (uint64_t)i * 0x1000,
                          &address, &value, &levels) ||
        levels != 4 || address != global->clone_leaf_address[i] ||
        !runtime_exec1060_pte_invariant_equal(global->clone_leaf_value[i],
                                               value) ||
        !(value & FW1060_PAGE_WRITABLE) || !(value & FW1060_PAGE_NX))
      return 4 + (int)i;
  return 0;
}

static void build_landing(uint8_t out[FW1060_LANDING_BYTES],
                          const uint8_t saved[FW1060_LANDING_BYTES],
                          uint64_t code)
{
  memcpy(out, saved, FW1060_LANDING_BYTES);
  out[0] = 0x48;
  out[1] = 0xb8;
  memcpy(out + 2, &code, 8);
  out[10] = 0xff;
  out[11] = 0xe0;
}

static int verify_cfi(const phase2_router_global_t *global, int installed)
{
  uint8_t thunk[FW1060_CFI_BYTES_MAX], landing[FW1060_LANDING_BYTES];
  for (unsigned i = 0; i < FW1060_CFI_PAIR_COUNT; ++i) {
    if (kernel_copyout(global->cfi[i].thunk, thunk, sizeof(thunk)) ||
        kernel_copyout(global->cfi[i].landing, landing, sizeof(landing)) ||
        memcmp(thunk, global->cfi[i].saved_thunk, sizeof(thunk)) ||
        memcmp(landing, installed ? global->cfi[i].installed_landing :
                                   global->cfi[i].saved_landing,
               sizeof(landing)))
      return -1;
  }
  return 0;
}

static int publish_locator(int client, uint64_t cave,
                           const phase2_locator_t *locator)
{
  phase2_locator_t empty, partial, readback;
  memset(&empty, 0, sizeof(empty));
  if (kernel_copyout(cave + PHASE2_LOCATOR_OFFSET, &readback,
                     sizeof(readback)) || memcmp(&readback, &empty, sizeof(empty)))
    return -1;
  partial = *locator;
  partial.checksum = 0;
  if (kernel_copyin(&partial, cave + PHASE2_LOCATOR_OFFSET, sizeof(partial)) ||
      kernel_copyout(cave + PHASE2_LOCATOR_OFFSET, &readback,
                     sizeof(readback)) || memcmp(&partial, &readback,
                                                sizeof(partial)) ||
      kernel_copyin(&locator->checksum, cave + PHASE2_LOCATOR_OFFSET +
                    offsetof(phase2_locator_t, checksum), 8) ||
      kernel_copyout(cave + PHASE2_LOCATOR_OFFSET, &readback,
                     sizeof(readback)) || phase2_locator_validate(&readback) ||
      phase(client, "locator-live", readback.generation, readback.checksum))
    return -1;
  return 0;
}

static int verify_private_clone(uint64_t original_vector,
                                uint64_t original_table,
                                uint64_t clone_vector,
                                uint64_t clone_table,
                                uint64_t claimed_handler)
{
  uint8_t original_entry[0x30], clone_entry[0x30];
  uint8_t original_vec[0x200], clone_vec[0x200];
  if (g_fw1060_profile.sysent_size != sizeof(original_entry) ||
      g_fw1060_profile.sysentvec_size != sizeof(original_vec) ||
      kernel_copyout(original_vector, original_vec, sizeof(original_vec)) ||
      kernel_copyout(clone_vector, clone_vec, sizeof(clone_vec)))
    return -1;
  memcpy(original_vec + g_fw1060_profile.sysentvec_table_offset,
         &clone_table, sizeof(clone_table));
  if (memcmp(original_vec, clone_vec, sizeof(original_vec)))
    return -1;
  for (unsigned i = 0; i < g_fw1060_profile.syscall_count; ++i) {
    if (kernel_copyout(original_table + (uint64_t)i * sizeof(original_entry),
                       original_entry, sizeof(original_entry)) ||
        kernel_copyout(clone_table + (uint64_t)i * sizeof(clone_entry),
                       clone_entry, sizeof(clone_entry)))
      return -1;
    if (i == PHASE2_TEST_SYSCALL)
      memcpy(original_entry + g_fw1060_profile.sy_call_offset,
             &claimed_handler, sizeof(claimed_handler));
    if (memcmp(original_entry, clone_entry, sizeof(original_entry)))
      return -1;
  }
  return 0;
}

static int write_attachment(uint64_t address,
                            const phase2_attachment_t *attachment)
{
  phase2_attachment_t readback;
  return kernel_copyin(attachment, address, sizeof(*attachment)) ||
         kernel_copyout(address, &readback, sizeof(readback)) ||
         memcmp(attachment, &readback, sizeof(readback));
}

static int attach_and_test(int client, phase2_router_global_t *global,
                           uint64_t global_address, int fresh)
{
  phase2_attachment_t attachment;
  uint64_t proc = kernel_get_proc(getpid()), observed;
  uint64_t calls_before = global->calls, result;
  unsigned char carry;
  int committed = 0, switched = 0;
  const uint64_t clone_vector = global->clone_address + ATTACH_VECTOR_OFFSET;
  const uint64_t clone_table = global->clone_address + ATTACH_TABLE_OFFSET;
  uint64_t original_vector, original_table;
  if (!proc || kernel_copyout(proc + g_fw1060_profile.proc_p_sysent_offset,
                              &observed, 8) || !observed)
    return -1;
  original_vector = observed;
  if (kernel_copyout(original_vector +
                     g_fw1060_profile.sysentvec_table_offset,
                     &original_table, 8) || !original_table ||
      phase2_attach_begin(global, &attachment, proc, original_vector,
                          original_table, clone_vector, clone_table) ||
      copy_kernel_region(clone_table, original_table,
          g_fw1060_profile.syscall_count * g_fw1060_profile.sysent_size) ||
      copy_kernel_region(clone_vector, original_vector,
                         g_fw1060_profile.sysentvec_size) ||
      kernel_copyin(&global->cfi[0].thunk, clone_table + PHASE2_TEST_SYSCALL *
          g_fw1060_profile.sysent_size + g_fw1060_profile.sy_call_offset, 8) ||
      kernel_copyin(&clone_table, clone_vector +
                    g_fw1060_profile.sysentvec_table_offset, 8) ||
      verify_private_clone(original_vector, original_table, clone_vector,
                           clone_table, global->cfi[0].thunk) ||
      write_attachment(global->clone_address, &attachment) ||
      phase2_attach_commit(global, &attachment) ||
      write_attachment(global->clone_address, &attachment))
    return -1;
  committed = 1;
  if (write_global(global_address, global) ||
      phase(client, "attachment-prepared", global->generation,
            ((uint64_t)global->attachment_count << 32) | attachment.state))
    goto fail;
  if (kernel_copyout(proc + g_fw1060_profile.proc_p_sysent_offset,
                     &observed, 8) || observed != original_vector ||
      kernel_copyin(&clone_vector,
                    proc + g_fw1060_profile.proc_p_sysent_offset, 8))
    goto fail;
  switched = 1;
  if (kernel_copyout(proc + g_fw1060_profile.proc_p_sysent_offset,
                     &observed, 8) || observed != clone_vector ||
      phase(client, "attachment-live", global->generation, getpid()))
    goto fail;
  result = raw_syscall(SYS_getpid, 0, &carry);
  if (carry || result != (uint64_t)getpid() ||
      phase(client, "stock-getpid", result, carry))
    goto fail;
  result = raw_syscall(PHASE2_TEST_SYSCALL, 0, &carry);
  if (phase(client, fresh ? "fresh-router-observed" :
                         "installer-router-observed",
            result, carry) ||
      kernel_copyout(global_address, global, sizeof(*global)) ||
      phase(client, fresh ? "fresh-accounting-observed" :
                         "installer-accounting-observed",
            global->calls, global->inflight) ||
      carry || result != PHASE2_TEST_RESULT ||
      global->inflight || global->calls != calls_before + 1 ||
      phase(client, fresh ? "fresh-router-call" : "installer-router-call",
            result, global->calls))
    goto fail;
  if (kernel_copyout(proc + g_fw1060_profile.proc_p_sysent_offset,
                     &observed, 8) || observed != clone_vector ||
      kernel_copyin(&original_vector,
                    proc + g_fw1060_profile.proc_p_sysent_offset, 8) ||
      kernel_copyout(proc + g_fw1060_profile.proc_p_sysent_offset,
                     &observed, 8) || observed != original_vector)
    goto fail;
  switched = 0;
  if (phase2_attach_release(global, &attachment) ||
      write_attachment(global->clone_address, &attachment))
    goto fail;
  committed = 0;
  if (write_global(global_address, global) ||
      phase(client, "attachment-restored", global->generation,
            global->attachment_count))
    return -1;
  return 0;
fail:
  if (switched) {
    if (kernel_copyout(proc + g_fw1060_profile.proc_p_sysent_offset,
                       &observed, 8) ||
        (observed == clone_vector &&
         (kernel_copyin(&original_vector,
                        proc + g_fw1060_profile.proc_p_sysent_offset, 8) ||
          kernel_copyout(proc + g_fw1060_profile.proc_p_sysent_offset,
                         &observed, 8))) ||
        observed != original_vector)
      global->quarantined = 1;
    else
      switched = 0;
  }
  if (committed && !switched && !global->inflight &&
      (phase2_attach_release(global, &attachment) ||
       write_attachment(global->clone_address, &attachment)))
    global->quarantined = 1;
  if (global->quarantined) {
    global->state = PHASE2_ROUTER_QUARANTINED;
    phase(client, "QUARANTINED", global->generation, observed);
  }
  write_global(global_address, global);
  return -1;
}

static int run_installer(int client, uint64_t cave,
                         const runtime_exec1060_page_t *page,
                         phase2_prealloc_record_t *prealloc)
{
  phase2_router_global_t global, readback;
  phase2_locator_t locator;
  temporary_route_t route = {.client = client, .cave = cave};
  uint8_t router[512] = {0}, verify[512] = {0};
  uint8_t handler[TEMP_HANDLER_MAX] = {0};
  unsigned char carry;
  uint64_t result, current_pte = 0, permission_failure_address = 0;
  uint64_t permission_failure_value = 0, permission_pmap = 0;
  size_t router_size, handler_size;
  int installed = 0, permission_check;
  memset(&global, 0, sizeof(global));
  global.magic = PHASE2_GLOBAL_MAGIC;
  global.generation = PHASE2_GENERATION;
  global.code_address = prealloc->addresses[0];
  global.code_size = PHASE2_CODE_SIZE;
  global.state_address = prealloc->addresses[1];
  global.state_size = PHASE2_STATE_SIZE;
  global.clone_address = prealloc->addresses[2];
  global.clone_size = PHASE2_CLONE_SIZE;
  global.code_leaf_address = prealloc->code_leaf_address;
  global.code_leaf_original = prealloc->code_leaf_original;
  global.code_leaf_final = prealloc->code_leaf_prepared &
      ~FW1060_PAGE_WRITABLE & ~FW1060_PAGE_NX & ~FW1060_PAGE_XOTEXT;
  global.data_leaf_address = prealloc->data_leaf_address;
  global.data_leaf_value = prealloc->data_leaf_value;
  memcpy(global.clone_leaf_address, prealloc->clone_leaf_address,
         sizeof(global.clone_leaf_address));
  memcpy(global.clone_leaf_value, prealloc->clone_leaf_value,
         sizeof(global.clone_leaf_value));
  global.owner_magic = PHASE2_OWNER_MAGIC;
  global.state = PHASE2_ROUTER_INSTALLING;
  for (unsigned i = 0; i < FW1060_CFI_PAIR_COUNT; ++i) {
    const fw1060_cfi_pair_t *pair = &g_fw1060_profile.cfi_pairs[i];
    global.cfi[i].thunk = KERNEL_ADDRESS_TEXT_BASE + pair->thunk_offset;
    global.cfi[i].landing = KERNEL_ADDRESS_TEXT_BASE + pair->landing_offset;
    if (kernel_copyout(global.cfi[i].thunk, global.cfi[i].saved_thunk,
                       sizeof(global.cfi[i].saved_thunk)) ||
        kernel_copyout(global.cfi[i].landing, global.cfi[i].saved_landing,
                       sizeof(global.cfi[i].saved_landing)) ||
        fw1060_verify_cfi_pair(pair, global.cfi[i].saved_thunk,
                              global.cfi[i].saved_landing))
      return 20;
    build_landing(global.cfi[i].installed_landing,
                  global.cfi[i].saved_landing, global.code_address);
    global.cfi[i].owned = 1;
  }
  global.immutable_checksum = phase2_global_immutable_checksum(&global);
  router_size = phase2_build_router(router, sizeof(router), global.state_address);
  if (!router_size || router_size > global.code_size ||
      phase(client, "load-router-before", global.code_address, router_size) ||
      kernel_copyin(router, global.code_address, router_size) ||
      kernel_copyout(global.code_address, verify, router_size) ||
      memcmp(router, verify, router_size) ||
      write_global(global.state_address, &global) ||
      kernel_copyout(global.state_address, &readback, sizeof(readback)) ||
      phase2_global_validate(&readback) ||
      phase(client, "load-router-after", readback.generation,
            readback.immutable_checksum))
    return 21;
  /*
   * Resolve the kernel pmap before the current process switches to its
   * temporary cloned sysent. Publication verification must not rediscover
   * kernel infrastructure through the route it is actively testing.
   */
  if (resolve_kernel_pmap(&permission_pmap))
    return 23;
  handler_size = build_permission_handler(handler, global.code_leaf_address,
                                           global.code_leaf_final);
  if (temporary_route_open(&route, page, handler, handler_size)) {
    if ((route.vector_switched || route.landing_written) &&
        temporary_route_close(&route)) {
      global.state = PHASE2_ROUTER_QUARANTINED;
      global.quarantined = 1;
      write_global(global.state_address, &global);
    }
    return 22;
  }
  if (phase(client, "permission-publish-before", global.code_leaf_address,
            global.code_leaf_final))
    goto fail;
  result = raw_syscall(TEMP_SYSCALL, 0, &carry);
  permission_check = verify_router_permissions(&global, 1, permission_pmap);
  if (permission_check == 2)
    permission_failure_address = global.code_leaf_address;
  else if (permission_check == 3)
    permission_failure_address = global.data_leaf_address;
  else if (permission_check >= 4 &&
           permission_check < 4 + (int)PHASE2_CLONE_PAGE_COUNT)
    permission_failure_address =
        global.clone_leaf_address[(unsigned)permission_check - 4];
  if (permission_failure_address &&
      kernel_copyout(permission_failure_address, &permission_failure_value,
                     sizeof(permission_failure_value)))
    goto fail;
  if (kernel_copyout(global.code_leaf_address, &current_pte,
                     sizeof(current_pte)) ||
      phase(client, "permission-publish-result", result,
            ((uint64_t)carry << 32) | (uint32_t)permission_check) ||
      phase(client, "permission-publish-leaf", global.code_leaf_address,
            current_pte) ||
      (permission_check &&
       phase(client, "permission-check-detail",
             ((uint64_t)(uint32_t)permission_check << 32) |
             (uint32_t)(permission_check >= 4 ? permission_check - 4 : 0),
             permission_failure_value)) ||
      carry || result || permission_check ||
      phase(client, "permission-publish-after", result, carry))
    goto fail;
  for (unsigned i = 0; i < FW1060_CFI_PAIR_COUNT; ++i) {
    uint8_t current[FW1060_LANDING_BYTES];
    if (kernel_copyout(global.cfi[i].landing, current, sizeof(current)) ||
        memcmp(current, global.cfi[i].saved_landing, sizeof(current)) ||
        phase(client, "cfi-install-before", i, global.cfi[i].landing) ||
        kernel_copyin(global.cfi[i].installed_landing,
                      global.cfi[i].landing, sizeof(current)) ||
        kernel_copyout(global.cfi[i].landing, current, sizeof(current)) ||
        memcmp(current, global.cfi[i].installed_landing, sizeof(current)) ||
        phase(client, "cfi-install-after", i, *(uint64_t *)current))
      goto fail;
    ++installed;
  }
  result = raw_syscall(TEMP_SYSCALL, 0, &carry);
  if (carry || result || verify_cfi(&global, 1) ||
      phase(client, "cfi-all-core-visible", FW1060_CFI_PAIR_COUNT, result))
    goto fail;
  if (temporary_route_close(&route))
    goto post_install_quarantine;
  global.state = PHASE2_ROUTER_LIVE;
  if (write_global(global.state_address, &global) ||
      kernel_copyout(global.state_address, &readback, sizeof(readback)) ||
      readback.state != PHASE2_ROUTER_LIVE ||
      phase(client, "LIVE-commit", readback.generation, readback.state))
    goto post_install_quarantine;
  locator.magic = PHASE2_LOCATOR_MAGIC;
  locator.generation = PHASE2_GENERATION;
  locator.global_address = global.state_address;
  locator.global_size = PHASE2_STATE_SIZE;
  locator.checksum = phase2_locator_checksum(&locator);
  if (publish_locator(client, cave, &locator))
    goto post_install_quarantine;
  prealloc->state = PHASE2_PREALLOC_CONSUMED;
  prealloc->result_checksum = phase2_prealloc_result_checksum(prealloc);
  if (kernel_copyin(prealloc, cave + PHASE2_PREALLOC_OFFSET,
                    sizeof(*prealloc)) ||
      attach_and_test(client, &global, global.state_address, 0) ||
      phase(client, "installer-exit", getpid(), global.generation))
    return 26;
  return 0;
post_install_quarantine:
  global.state = PHASE2_ROUTER_QUARANTINED;
  global.quarantined = 1;
  write_global(global.state_address, &global);
  locator.magic = PHASE2_LOCATOR_MAGIC;
  locator.generation = PHASE2_GENERATION;
  locator.global_address = global.state_address;
  locator.global_size = PHASE2_STATE_SIZE;
  locator.checksum = phase2_locator_checksum(&locator);
  publish_locator(client, cave, &locator);
  phase(client, "QUARANTINED", global.generation, global.state);
  return 27;
fail:
  while (installed) {
    unsigned i = (unsigned)--installed;
    uint8_t current[FW1060_LANDING_BYTES];
    if (kernel_copyout(global.cfi[i].landing, current, sizeof(current)) ||
        memcmp(current, global.cfi[i].installed_landing, sizeof(current)) ||
        kernel_copyin(global.cfi[i].saved_landing, global.cfi[i].landing,
                      sizeof(current)) ||
        kernel_copyout(global.cfi[i].landing, current, sizeof(current)) ||
        memcmp(current, global.cfi[i].saved_landing, sizeof(current)))
      route.quarantined = 1;
  }
  if (kernel_copyout(global.code_leaf_address, &current_pte,
                     sizeof(current_pte)))
    route.quarantined = 1;
  if (!route.quarantined &&
      runtime_exec1060_pte_invariant_equal(current_pte,
                                            global.code_leaf_final)) {
    handler_size = build_permission_handler(handler, global.code_leaf_address,
                                             global.code_leaf_original);
    if (kernel_copyin(handler, route.target, handler_size)) {
      route.quarantined = 1;
    } else {
      result = raw_syscall(TEMP_SYSCALL, 0, &carry);
      if (carry || result)
        route.quarantined = 1;
    }
  } else if (!route.quarantined &&
             !runtime_exec1060_pte_invariant_equal(
                 current_pte, global.code_leaf_original)) {
    route.quarantined = 1;
  }
  if (temporary_route_close(&route))
    route.quarantined = 1;
  if (route.quarantined) {
    global.state = PHASE2_ROUTER_QUARANTINED;
    global.quarantined = 1;
    write_global(global.state_address, &global);
    phase(client, "QUARANTINED", global.generation, installed);
    return 27;
  }
  return 28;
}


static int run_fresh(int client, uint64_t cave,
                     const phase2_locator_t *locator)
{
  phase2_router_global_t global;
  uint64_t generation, calls;
  if (phase2_locator_validate(locator) ||
      kernel_copyout(locator->global_address, &global, sizeof(global)) ||
      phase2_global_validate(&global) || global.state != PHASE2_ROUTER_LIVE ||
      global.quarantined || global.attachment_count || global.inflight ||
      verify_router_permissions(&global, 1, 0) || verify_cfi(&global, 1) ||
      phase(client, "fresh-discovery", global.generation, global.calls))
    return 30;
  generation = global.generation;
  calls = global.calls;
  if (attach_and_test(client, &global, locator->global_address, 1) ||
      kernel_copyout(locator->global_address, &global, sizeof(global)) ||
      global.generation != generation || global.calls != calls + 1 ||
      global.attachment_count || global.inflight ||
      verify_router_permissions(&global, 1, 0) || verify_cfi(&global, 1) ||
      phase(client, "fresh-proof", global.generation, global.calls))
    return 31;
  (void)cave;
  return 0;
}

#ifndef PHASE3_RUNTIME_EMBEDDED_RELEASE
int main(void)
{
  int client = accept_client(), status = 1, mode = 0;
  uint64_t cave;
  runtime_exec1060_page_t page;
  phase2_prealloc_record_t prealloc;
  phase2_locator_t locator;
  phase2_router_global_t report_global;
  char line[512];
  if (client < 0)
    return 1;
  cave = kdlsym(KERNEL_SYM_DATA_CAVE);
  memset(&page, 0, sizeof(page));
  memset(&prealloc, 0, sizeof(prealloc));
  memset(&locator, 0, sizeof(locator));
  memset(&report_global, 0, sizeof(report_global));
  if (fw1060_identity_validate(kernel_get_fw_version(), sceKernelGetMainSocId(),
                               FW1060_CPU_COUNT) || !cave ||
      phase(client, "profile-preflight", g_fw1060_profile.firmware,
            ((uint64_t)g_fw1060_profile.syscall_count << 32) |
            g_fw1060_profile.sysent_size)) {
    status = 10;
    goto report;
  }
  if (kernel_copyout(cave + RUNTIME_EXEC1060_CAVE_OFFSET, &page,
                     sizeof(page)) ||
      !runtime_exec1060_is_post_resume_verified(&page) ||
      validate_mapping_contracts(client, &page) ||
      kernel_copyout(cave + PHASE2_PREALLOC_OFFSET, &prealloc,
                     sizeof(prealloc)) ||
      kernel_copyout(cave + PHASE2_LOCATOR_OFFSET, &locator,
                     sizeof(locator))) {
    status = 11;
    goto report;
  }
  if (!memcmp(&locator, &(phase2_locator_t){0}, sizeof(locator))) {
    const uint64_t malloc_type = KERNEL_ADDRESS_TEXT_BASE +
                                 g_fw1060_profile.malloc_type_offset;
    const uint32_t flags = g_fw1060_profile.malloc_nowait |
                           g_fw1060_profile.malloc_zero;
    mode = 1;
    if (phase2_prealloc_validate(&prealloc, malloc_type, flags))
      status = 12;
    else
      status = run_installer(client, cave, &page, &prealloc);
  } else {
    mode = 2;
    status = run_fresh(client, cave, &locator);
  }
report:
  if (cave &&
      !kernel_copyout(cave + PHASE2_LOCATOR_OFFSET, &locator,
                      sizeof(locator)) &&
      phase2_locator_validate(&locator) == 0)
    kernel_copyout(locator.global_address, &report_global,
                   sizeof(report_global));
  snprintf(line, sizeof(line),
      "PHASE2_RESULT status=%d mode=%d pid=%d generation=%016llx "
      "locator=%016llx state=%08x attachments=%u inflight=%u "
      "quarantined=%u last=terminal\n", status, mode, getpid(),
      (unsigned long long)locator.generation,
      (unsigned long long)locator.global_address, report_global.state,
      report_global.attachment_count, report_global.inflight,
      report_global.quarantined);
  send(client, line, strlen(line), 0);
  close(client);
  return status;
}
#endif
