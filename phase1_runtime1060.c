#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <ps5/kernel.h>

#include "firmware_profile1060.h"
#include "kdlsym.h"
#include "paging.h"
#include "phase1_allocator1060.h"
#include "runtime_exec1060.h"
#include "util.h"

#define RESULT_PORT 9634
#define CLONE_TABLE_OFFSET 0x10000ULL
#define CLONE_VECTOR_OFFSET 0x19000ULL
#define HANDLER_MAX 128U
#define ENOMEM_KERNEL 12U

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
  char line[224], ack;
  int n = snprintf(line, sizeof(line),
      "PHASE1_ACK %s a=%016llx b=%016llx\n", name,
      (unsigned long long)a, (unsigned long long)b);
  if (n <= 0 || send(client, line, (size_t)n, 0) != n)
    return -1;
  return recv(client, &ack, 1, 0) == 1 ? 0 : -1;
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
    destination += chunk;
    source += chunk;
    length -= chunk;
  }
  return 0;
}

static uint64_t raw_phase1_syscall(uint64_t argument, unsigned char *carry)
{
  register uint64_t rax __asm__("rax") = PHASE1_SYSCALL;
  register uint64_t rdi __asm__("rdi") = argument;
  unsigned char cf;
  __asm__ volatile("syscall\n\tsetc %2"
                   : "+a"(rax), "+D"(rdi), "=qm"(cf)
                   :
                   : "rcx", "r11", "memory", "cc");
  *carry = cf;
  return rax;
}

static size_t append(uint8_t *out, size_t at, const void *bytes, size_t count)
{
  memcpy(out + at, bytes, count);
  return at + count;
}


static size_t build_free_handler(uint8_t out[HANDLER_MAX], uint64_t address,
                                 uint64_t free_address, uint64_t malloc_type,
                                 uint32_t retval_offset, uint64_t tlb_all,
                                 uint64_t instruction_all)
{
  static const uint8_t push_save[] = {0x53, 0x48, 0x89, 0xfb};
  static const uint8_t mov_rax[] = {0x48, 0xb8};
  static const uint8_t call_rax[] = {0xff, 0xd0};
  static const uint8_t mov_rdi[] = {0x48, 0xbf};
  static const uint8_t mov_rsi[] = {0x48, 0xbe};
  static const uint8_t store_zero[] = {0x48, 0xc7, 0x83};
  static const uint8_t success[] = {0, 0, 0, 0, 0x31, 0xc0, 0x5b, 0xc3};
  size_t at = 0;
  at = append(out, at, push_save, sizeof(push_save));
  at = append(out, at, mov_rax, sizeof(mov_rax));
  at = append(out, at, &tlb_all, sizeof(tlb_all));
  at = append(out, at, call_rax, sizeof(call_rax));
  at = append(out, at, mov_rax, sizeof(mov_rax));
  at = append(out, at, &instruction_all, sizeof(instruction_all));
  at = append(out, at, call_rax, sizeof(call_rax));
  at = append(out, at, mov_rdi, sizeof(mov_rdi));
  at = append(out, at, &address, sizeof(address));
  at = append(out, at, mov_rsi, sizeof(mov_rsi));
  at = append(out, at, &malloc_type, sizeof(malloc_type));
  at = append(out, at, mov_rax, sizeof(mov_rax));
  at = append(out, at, &free_address, sizeof(free_address));
  at = append(out, at, call_rax, sizeof(call_rax));
  at = append(out, at, store_zero, sizeof(store_zero));
  at = append(out, at, &retval_offset, sizeof(retval_offset));
  at = append(out, at, success, sizeof(success));
  return at;
}

typedef struct {
  int client;
  uint64_t cave;
  uint64_t proc;
  uint64_t target;
  uint64_t cfi_thunk;
  uint64_t cfi_target;
  uint64_t original_vector;
  uint64_t original_table;
  uint64_t clone_table;
  uint64_t clone_vector;
  uint8_t saved_landing[FW1060_LANDING_BYTES];
  uint8_t requested_landing[FW1060_LANDING_BYTES];
  int landing_written;
  int vector_switched;
  int quarantined;
} route_t;

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
      uint64_t address = KERNEL_ADDRESS_TEXT_BASE +
          (side ? g_fw1060_profile.cfi_pairs[i].landing_offset :
                  g_fw1060_profile.cfi_pairs[i].thunk_offset);
      uint64_t leaf_address = 0, leaf = 0;
      unsigned levels = 0;
      if (find_mapping_leaf(pmap, address, &leaf_address, &leaf, &levels) ||
          !runtime_exec1060_mapping_contract_matches(
              page->reservation_pte_address[i][side],
              page->reservation_pte_value[i][side],
              page->reservation_levels[i][side], leaf_address, leaf, levels) ||
          !(leaf & FW1060_PAGE_PRESENT) || !(leaf & FW1060_PAGE_WRITABLE) ||
          (leaf & (FW1060_PAGE_XOTEXT | FW1060_PAGE_NX)) ||
          phase(client, "mapping-contract", leaf_address,
                leaf | ((uint64_t)levels << 60)))
        return -1;
    }
  }
  return 0;
}

static int route_open(route_t *route, const runtime_exec1060_page_t *page,
                      const uint8_t *handler, size_t handler_size)
{
  uint8_t verify[HANDLER_MAX] = {0}, thunk[8] = {0};
  uint64_t installed_handler = 0, installed_table = 0, observed = 0;
  uint8_t trampoline[12] = {0x48, 0xb8};
  route->proc = kernel_get_proc(getpid());
  route->target = page->address;
  route->cfi_thunk = KERNEL_ADDRESS_TEXT_BASE +
                     g_fw1060_profile.temporary_thunk_offset;
  route->cfi_target = KERNEL_ADDRESS_TEXT_BASE +
                      g_fw1060_profile.temporary_landing_offset;
  route->clone_table = route->cave + CLONE_TABLE_OFFSET;
  route->clone_vector = route->cave + CLONE_VECTOR_OFFSET;
  if (!route->proc || handler_size > HANDLER_MAX ||
      PHASE1_SYSCALL >= g_fw1060_profile.syscall_count ||
      g_fw1060_profile.sysent_size != 0x30 ||
      g_fw1060_profile.sysentvec_size != 0x200 ||
      kernel_copyout(route->proc + g_fw1060_profile.proc_p_sysent_offset,
                     &route->original_vector, 8) || !route->original_vector ||
      kernel_copyout(route->original_vector +
                     g_fw1060_profile.sysentvec_table_offset,
                     &route->original_table, 8) || !route->original_table ||
      kernel_copyout(route->cfi_thunk, thunk, sizeof(thunk)) ||
      memcmp(thunk, g_fw1060_profile.temporary_thunk_bytes,
             sizeof(g_fw1060_profile.temporary_thunk_bytes)) ||
      kernel_copyout(route->cfi_target, route->saved_landing,
                     sizeof(route->saved_landing)) ||
      memcmp(route->saved_landing,
             g_fw1060_profile.temporary_landing_bytes,
             sizeof(route->saved_landing)) ||
      phase(route->client, "route-preflight", route->original_vector,
            route->original_table) ||
      phase(route->client, "rollback-order", route->original_vector,
            route->cfi_target))
    return -1;
  if (kernel_copyin(handler, route->target, handler_size) ||
      kernel_copyout(route->target, verify, handler_size) ||
      memcmp(handler, verify, handler_size) ||
      phase(route->client, "handler-readback", route->target, handler_size))
    return -1;
  memcpy(route->requested_landing, route->saved_landing,
         sizeof(route->requested_landing));
  memcpy(trampoline + 2, &route->target, 8);
  trampoline[10] = 0xff;
  trampoline[11] = 0xe0;
  memcpy(route->requested_landing, trampoline, sizeof(trampoline));
  if (phase(route->client, "landing-before", route->cfi_target,
            *(uint64_t *)route->saved_landing) ||
      kernel_copyin(route->requested_landing, route->cfi_target,
                    sizeof(route->requested_landing)))
    return -1;
  route->landing_written = 1;
  if (kernel_copyout(route->cfi_target, verify,
                     sizeof(route->requested_landing)) ||
      memcmp(verify, route->requested_landing,
             sizeof(route->requested_landing)) ||
      phase(route->client, "landing-after", route->cfi_target,
            *(uint64_t *)verify))
    return -1;
  if (copy_kernel_region(route->clone_table, route->original_table,
          g_fw1060_profile.syscall_count * g_fw1060_profile.sysent_size) ||
      copy_kernel_region(route->clone_vector, route->original_vector,
                         g_fw1060_profile.sysentvec_size) ||
      kernel_copyin(&route->cfi_thunk, route->clone_table +
          PHASE1_SYSCALL * g_fw1060_profile.sysent_size +
          g_fw1060_profile.sy_call_offset, 8) ||
      kernel_copyin(&route->clone_table, route->clone_vector +
                    g_fw1060_profile.sysentvec_table_offset, 8) ||
      kernel_copyout(route->clone_table +
          PHASE1_SYSCALL * g_fw1060_profile.sysent_size +
          g_fw1060_profile.sy_call_offset, &installed_handler, 8) ||
      kernel_copyout(route->clone_vector +
          g_fw1060_profile.sysentvec_table_offset, &installed_table, 8) ||
      installed_handler != route->cfi_thunk ||
      installed_table != route->clone_table ||
      phase(route->client, "clone-readback", installed_table,
            installed_handler))
    return -1;
  if (kernel_copyout(route->proc + g_fw1060_profile.proc_p_sysent_offset,
                     &observed, 8) || observed != route->original_vector ||
      phase(route->client, "vector-before", observed, route->clone_vector) ||
      kernel_copyin(&route->clone_vector,
                    route->proc + g_fw1060_profile.proc_p_sysent_offset, 8))
    return -1;
  route->vector_switched = 1;
  if (kernel_copyout(route->proc + g_fw1060_profile.proc_p_sysent_offset,
                     &observed, 8) || observed != route->clone_vector ||
      phase(route->client, "vector-after", observed, route->original_vector))
    return -1;
  return 0;
}

static int route_close(route_t *route)
{
  uint64_t observed = 0;
  uint8_t bytes[FW1060_LANDING_BYTES];
  int failure = 0;
  if (route->vector_switched) {
    if (phase(route->client, "restore-vector-before", route->clone_vector,
              route->original_vector) ||
        kernel_copyout(route->proc + g_fw1060_profile.proc_p_sysent_offset,
                       &observed, 8) || observed != route->clone_vector ||
        kernel_copyin(&route->original_vector,
                      route->proc + g_fw1060_profile.proc_p_sysent_offset, 8) ||
        kernel_copyout(route->proc + g_fw1060_profile.proc_p_sysent_offset,
                       &observed, 8) || observed != route->original_vector ||
        phase(route->client, "restore-vector-after", observed,
              route->original_vector))
      failure = 1;
    else
      route->vector_switched = 0;
  }
  if (route->landing_written && !failure) {
    if (kernel_copyout(route->cfi_target, bytes, sizeof(bytes)) ||
        memcmp(bytes, route->requested_landing, sizeof(bytes)) ||
        phase(route->client, "restore-landing-before", route->cfi_target,
              *(uint64_t *)bytes) ||
        kernel_copyin(route->saved_landing, route->cfi_target,
                      sizeof(route->saved_landing)) ||
        kernel_copyout(route->cfi_target, bytes, sizeof(bytes)) ||
        memcmp(bytes, route->saved_landing, sizeof(bytes)) ||
        phase(route->client, "restore-landing-after", route->cfi_target,
              *(uint64_t *)bytes))
      failure = 1;
    else
      route->landing_written = 0;
  }
  if (failure) {
    route->quarantined = 1;
    phase(route->client, "QUARANTINED", observed, route->cfi_target);
    return -1;
  }
  return 0;
}

static void initialize_record(phase1_allocation_record_t *record,
                              uint64_t address, uint64_t size,
                              uint64_t malloc_type, uint32_t role,
                              uint32_t state)
{
  record->magic = PHASE1_RECORD_MAGIC;
  record->generation = PHASE1_GENERATION;
  record->address = address;
  record->size = size;
  record->malloc_type = malloc_type;
  record->state = state;
  record->page_count = (uint32_t)((size + PHASE1_PAGE_SIZE - 1) /
                                  PHASE1_PAGE_SIZE);
  record->role = role;
}

static int publish_locator(route_t *route,
                           const phase1_framework_locator_t *locator)
{
  phase1_framework_locator_t prior, partial, readback;
  uint64_t address = route->cave + PHASE1_LOCATOR_OFFSET;
  memset(&prior, 0, sizeof(prior));
  if (kernel_copyout(address, &prior, sizeof(prior)) ||
      memcmp(&prior, &(phase1_framework_locator_t){0}, sizeof(prior)) != 0 ||
      phase(route->client, "locator-preflight", address, prior.magic))
    return -1;
  partial = *locator;
  partial.checksum = 0;
  if (phase(route->client, "locator-publish-before", address,
            locator->generation) ||
      kernel_copyin(&partial, address, sizeof(partial)) ||
      kernel_copyout(address, &readback, sizeof(readback)) ||
      memcmp(&partial, &readback, sizeof(partial)) ||
      kernel_copyin(&locator->checksum,
                    address + offsetof(phase1_framework_locator_t, checksum),
                    sizeof(locator->checksum)) ||
      kernel_copyout(address, &readback, sizeof(readback)) ||
      phase1_locator_validate(&readback) ||
      phase(route->client, "locator-publish-after", readback.control_block,
            readback.checksum))
    return -1;
  return 0;
}

static int run_allocator(route_t *route)
{
  const uint64_t malloc_type = KERNEL_ADDRESS_TEXT_BASE +
                               g_fw1060_profile.malloc_type_offset;
  const uint32_t malloc_flags =
      g_fw1060_profile.malloc_nowait | g_fw1060_profile.malloc_zero;
  uint64_t addresses[PHASE1_RECORD_COUNT] = {0};
  phase1_prealloc_record_t prealloc, consumed, observed;
  phase1_control_block_t control = {0}, verify;
  phase1_framework_locator_t locator = {0};
  uint8_t pattern_verify[PHASE1_PATTERN_SIZE];
  if (phase(route->client, "prealloc-read-before",
            route->cave + PHASE1_PREALLOC_OFFSET, malloc_type) ||
      kernel_copyout(route->cave + PHASE1_PREALLOC_OFFSET, &prealloc,
                     sizeof(prealloc)) ||
      phase1_prealloc_validate(&prealloc, malloc_type, malloc_flags))
    return 20;
  memcpy(addresses, prealloc.addresses, sizeof(addresses));
  for (unsigned i = 0; i < PHASE1_RECORD_COUNT; ++i)
    if (phase(route->client, "prealloc-read-after", addresses[i],
              prealloc.sizes[i]))
      return 21;
  control.magic = PHASE1_CONTROL_MAGIC;
  control.generation = PHASE1_GENERATION;
  control.self_address = addresses[0];
  control.size = PHASE1_CONTROL_SIZE;
  control.malloc_type = malloc_type;
  control.state = PHASE1_STATE_PUBLISHED;
  control.record_count = PHASE1_RECORD_COUNT;
  phase1_fill_pattern(control.pattern, control.generation);
  control.pattern_checksum = phase1_checksum(control.pattern,
                                              sizeof(control.pattern));
  initialize_record(&control.records[0], addresses[0], prealloc.sizes[0],
                    malloc_type, PHASE1_ROLE_CONTROL,
                    PHASE1_STATE_PUBLISHED);
  initialize_record(&control.records[1], addresses[1], prealloc.sizes[1],
                    malloc_type, PHASE1_ROLE_DATA,
                    PHASE1_STATE_PUBLISHED);
  initialize_record(&control.records[2], addresses[2], prealloc.sizes[2],
                    malloc_type, PHASE1_ROLE_DISPOSABLE,
                    PHASE1_STATE_ALLOCATED);
  control.checksum = phase1_control_checksum(&control);
  if (phase(route->client, "data-pattern-before", addresses[1],
            control.pattern_checksum) ||
      kernel_copyin(control.pattern, addresses[1], sizeof(control.pattern)) ||
      kernel_copyout(addresses[1], pattern_verify, sizeof(pattern_verify)) ||
      memcmp(control.pattern, pattern_verify, sizeof(pattern_verify)) ||
      phase(route->client, "data-pattern-after", addresses[1],
            phase1_checksum(pattern_verify, sizeof(pattern_verify))) ||
      phase(route->client, "control-write-before", addresses[0],
            control.checksum) ||
      kernel_copyin(&control, addresses[0], sizeof(control)) ||
      kernel_copyout(addresses[0], &verify, sizeof(verify)) ||
      memcmp(&control, &verify, sizeof(control)) ||
      phase(route->client, "control-write-after", addresses[0],
            verify.pattern_checksum))
    return 22;
  locator.magic = PHASE1_LOCATOR_MAGIC;
  locator.generation = PHASE1_GENERATION;
  locator.control_block = addresses[0];
  locator.control_block_size = PHASE1_CONTROL_SIZE;
  locator.checksum = phase1_locator_checksum(&locator);
  if (publish_locator(route, &locator))
    return 23;
  consumed = prealloc;
  consumed.state = PHASE1_PREALLOC_STATE_CONSUMED;
  consumed.result_checksum = phase1_prealloc_result_checksum(&consumed);
  if (phase(route->client, "prealloc-consume-before",
            route->cave + PHASE1_PREALLOC_OFFSET,
            consumed.result_checksum) ||
      kernel_copyout(route->cave + PHASE1_PREALLOC_OFFSET, &observed,
                     sizeof(observed)) ||
      memcmp(&observed, &prealloc, sizeof(observed)) ||
      kernel_copyin(&consumed, route->cave + PHASE1_PREALLOC_OFFSET,
                    sizeof(consumed)) ||
      kernel_copyout(route->cave + PHASE1_PREALLOC_OFFSET, &observed,
                     sizeof(observed)) ||
      memcmp(&observed, &consumed, sizeof(observed)) ||
      phase(route->client, "prealloc-consume-after", observed.state,
            observed.result_checksum))
    return 24;
  if (phase(route->client, "allocator-exit-before", getpid(), addresses[0]))
    return 25;
  return 0;
}

static int run_verifier(route_t *route, const runtime_exec1060_page_t *page,
                        const phase1_framework_locator_t *locator)
{
  const uint64_t malloc_type = KERNEL_ADDRESS_TEXT_BASE +
                               g_fw1060_profile.malloc_type_offset;
  const uint64_t free_address = KERNEL_ADDRESS_TEXT_BASE +
                                g_fw1060_profile.free_offset;
  const uint64_t tlb = KERNEL_ADDRESS_TEXT_BASE +
                       g_fw1060_profile.all_core_guest_tlb_offset;
  const uint64_t insn = KERNEL_ADDRESS_TEXT_BASE +
                        g_fw1060_profile.all_core_instruction_offset;
  phase1_control_block_t control, readback;
  uint8_t handler[HANDLER_MAX] = {0}, pattern[PHASE1_PATTERN_SIZE];
  unsigned char carry = 0;
  uint64_t result;
  if (phase(route->client, "independent-read-before", getpid(),
            locator->control_block) ||
      kernel_copyout(locator->control_block, &control, sizeof(control)) ||
      phase1_control_validate(locator, &control, malloc_type) ||
      kernel_copyout(control.records[1].address, pattern, sizeof(pattern)) ||
      memcmp(pattern, control.pattern, sizeof(pattern)) ||
      phase(route->client, "independent-read-after", control.generation,
            phase1_checksum(pattern, sizeof(pattern))))
    return 30;
  if (phase1_disposable_free_eligible(&control, control.records[2].address,
                                      control.generation, malloc_type))
    return 31;
  size_t handler_size = build_free_handler(handler, control.records[2].address,
      free_address, malloc_type, g_fw1060_profile.thread_retval0_offset,
      tlb, insn);
  if (route_open(route, page, handler, handler_size))
    return 32;
  if (phase1_mark_disposable_draining(&control,
          control.records[2].address, control.generation, malloc_type) ||
      phase(route->client, "draining-record-before", locator->control_block,
            control.checksum) ||
      kernel_copyin(&control, locator->control_block, sizeof(control)) ||
      kernel_copyout(locator->control_block, &readback, sizeof(readback)) ||
      memcmp(&control, &readback, sizeof(control)) ||
      phase1_control_validate(locator, &readback, malloc_type) ||
      readback.records[2].state != PHASE1_STATE_DRAINING ||
      phase(route->client, "draining-record-after",
            readback.records[2].address, readback.records[2].state))
    return 33;
  if (phase(route->client, "free-before", control.records[2].address,
            malloc_type))
    return 34;
  result = raw_phase1_syscall(0, &carry);
  if (phase(route->client, "free-after", result, carry) || carry || result)
    return 35;
  /*
   * The embedded-address free entry must become unreachable immediately
   * after its one allowed invocation, before the durable record says FREED.
   */
  if (route_close(route))
    return 36;
  if (phase1_mark_disposable_freed(&control, control.records[2].address,
                                   control.generation, malloc_type) ||
      phase(route->client, "freed-record-before", locator->control_block,
            control.checksum) ||
      kernel_copyin(&control, locator->control_block, sizeof(control)) ||
      kernel_copyout(locator->control_block, &readback, sizeof(readback)) ||
      memcmp(&control, &readback, sizeof(control)) ||
      phase1_control_validate(locator, &readback, malloc_type) ||
      readback.records[2].state != PHASE1_STATE_FREED ||
      phase(route->client, "freed-record-after", readback.records[2].address,
            readback.records[2].state))
    return 37;
  return 0;
}

int main(void)
{
  int client = accept_client(), status = 1, mode = 0;
  route_t route = {0};
  runtime_exec1060_page_t page;
  phase1_framework_locator_t locator;
  char line[512];
  if (client < 0)
    return 1;
  route.client = client;
  route.cave = kdlsym(KERNEL_SYM_DATA_CAVE);
  memset(&page, 0, sizeof(page));
  memset(&locator, 0, sizeof(locator));
  if (fw1060_identity_validate(kernel_get_fw_version(), sceKernelGetMainSocId(),
                               FW1060_CPU_COUNT) || !route.cave ||
      phase(client, "profile-preflight", g_fw1060_profile.firmware,
            ((uint64_t)g_fw1060_profile.syscall_count << 32) |
             g_fw1060_profile.sysent_size)) {
    status = 10;
    goto report;
  }
  if (kernel_copyout(route.cave + RUNTIME_EXEC1060_CAVE_OFFSET, &page,
                     sizeof(page)) ||
      !runtime_exec1060_is_post_resume_verified(&page) ||
      validate_mapping_contracts(client, &page)) {
    status = 11;
    goto report;
  }
  if (kernel_copyout(route.cave + PHASE1_LOCATOR_OFFSET, &locator,
                     sizeof(locator))) {
    status = 12;
    goto report;
  }
  if (!memcmp(&locator, &(phase1_framework_locator_t){0}, sizeof(locator))) {
    mode = 1;
    status = run_allocator(&route);
  } else if (phase1_locator_validate(&locator) == 0) {
    mode = 2;
    status = run_verifier(&route, &page, &locator);
  } else {
    phase(client, "locator-conflict", locator.magic, locator.checksum);
    status = 13;
  }
  if ((route.vector_switched || route.landing_written) && !route.quarantined &&
      route_close(&route) != 0)
    status = 40;
report:
  snprintf(line, sizeof(line),
      "PHASE1_RESULT status=%d mode=%d pid=%d generation=%016llx "
      "control=%016llx restored_vector=%d restored_landing=%d "
      "quarantined=%d last=terminal\n",
      status, mode, getpid(), (unsigned long long)locator.generation,
      (unsigned long long)locator.control_block,
      !route.vector_switched, !route.landing_written, route.quarantined);
  send(client, line, strlen(line), 0);
  close(client);
  return status;
}
