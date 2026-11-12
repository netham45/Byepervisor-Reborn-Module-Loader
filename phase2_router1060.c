#include <stddef.h>
#include <string.h>

#include "phase2_router1060.h"

uint64_t phase2_checksum(const void *data, size_t length)
{
  const uint8_t *p = data;
  uint64_t hash = 1469598103934665603ULL;
  while (length--) {
    hash ^= *p++;
    hash *= 1099511628211ULL;
  }
  return hash;
}
uint64_t phase3_code_journal_checksum(const phase3_code_journal_t *journal)
{
  const uint8_t *p=(const uint8_t *)journal;
  const size_t checksum_offset=offsetof(phase3_code_journal_t,checksum);
  size_t size;
  uint64_t hash=1469598103934665603ULL;
  if(!journal||journal->count>(SIZE_MAX-sizeof(*journal))/sizeof(journal->entries[0]))
    return 0;
  size=sizeof(*journal)+(size_t)journal->count*sizeof(journal->entries[0]);
  for(size_t i=0;i<size;++i){
    uint8_t byte=(i>=checksum_offset&&i<checksum_offset+sizeof(uint64_t))?0:p[i];
    hash^=byte;hash*=1099511628211ULL;
  }
  return hash;
}
int phase3_prealloc_layout(uint64_t image_size,uint64_t *code_size,
                           uint64_t *state_size,uint64_t *page_count,
                           size_t *journal_size){
  uint64_t code,pages,state,journal;
  if(!image_size||image_size>SIZE_MAX-PHASE3_IMAGE_OFFSET-0xfff||
     !code_size||!state_size||!page_count||!journal_size)return -1;
  code=(PHASE3_IMAGE_OFFSET+image_size+0xfff)&~0xfffULL;
  pages=code/0x1000;
  if(pages>(SIZE_MAX-sizeof(phase3_code_journal_t))/sizeof(phase3_code_page_entry_t))
    return -1;
  journal=sizeof(phase3_code_journal_t)+pages*sizeof(phase3_code_page_entry_t);
  if(journal>SIZE_MAX-PHASE3_JOURNAL_OFFSET-0xfff)return -1;
  state=(PHASE3_JOURNAL_OFFSET+journal+0xfff)&~0xfffULL;
  *code_size=code;*state_size=state;*page_count=pages;*journal_size=(size_t)journal;
  return 0;
}
int phase3_prealloc_prepare(phase2_prealloc_record_t *r,uint64_t malloc_type,
                            uint32_t flags,uint64_t image_size){
  uint64_t code,state,pages;size_t journal;
  if(!r||phase3_prealloc_layout(image_size,&code,&state,&pages,&journal))return -1;
  phase2_prealloc_prepare(r,malloc_type,flags);
  r->sizes[0]=code;r->sizes[1]=state;
  r->request_checksum=phase2_prealloc_request_checksum(r);
  return 0;
}

uint64_t phase2_prealloc_request_checksum(const phase2_prealloc_record_t *r)
{
  phase2_prealloc_record_t normalized = *r;
  normalized.state = PHASE2_PREALLOC_ARMED;
  memset(normalized.addresses, 0, sizeof(normalized.addresses));
  normalized.code_leaf_address = 0;
  normalized.code_leaf_original = 0;
  normalized.code_leaf_prepared = 0;
  normalized.data_leaf_address = 0;
  normalized.data_leaf_value = 0;
  memset(normalized.clone_leaf_address, 0,
         sizeof(normalized.clone_leaf_address));
  memset(normalized.clone_leaf_value, 0,
         sizeof(normalized.clone_leaf_value));
  normalized.code_levels = 0;
  normalized.data_levels = 0;
  normalized.clone_page_count = 0;
  normalized.diagnostic_stage = 0;
  normalized.journal_address = 0;
  normalized.journal_checksum = 0;
  normalized.code_page_count = 0;
  normalized.diagnostic_detail = 0;
  normalized.result_checksum = 0;
  return phase2_checksum(&normalized,
                         offsetof(phase2_prealloc_record_t, request_checksum));
}

uint64_t phase2_prealloc_result_checksum(const phase2_prealloc_record_t *r)
{
  return phase2_checksum(r, offsetof(phase2_prealloc_record_t, result_checksum));
}

void phase2_prealloc_prepare(phase2_prealloc_record_t *r, uint64_t malloc_type,
                             uint32_t flags)
{
  static const uint64_t sizes[PHASE2_ALLOCATION_COUNT] = {
    PHASE2_CODE_BACKING_SIZE, PHASE2_STATE_BACKING_SIZE, PHASE2_CLONE_SIZE
  };
  memset(r, 0, sizeof(*r));
  r->magic = PHASE2_PREALLOC_MAGIC;
  r->generation = PHASE2_GENERATION;
  r->malloc_type = malloc_type;
  r->flags = flags;
  r->state = PHASE2_PREALLOC_ARMED;
  memcpy(r->sizes, sizes, sizeof(sizes));
  r->request_checksum = phase2_prealloc_request_checksum(r);
}

static int canonical_kernel(uint64_t address)
{
  return address >= 0xffff800000000000ULL;
}

int phase2_prealloc_fired_validate(const phase2_prealloc_record_t *r,
                                   uint64_t malloc_type, uint32_t flags)
{
  int phase2_sizes,phase3_sizes;uint64_t code,state,pages;size_t journal;
  if (!r || r->magic != PHASE2_PREALLOC_MAGIC ||
      r->generation != PHASE2_GENERATION || r->malloc_type != malloc_type ||
      r->flags != flags || r->state != PHASE2_PREALLOC_FIRED ||
      r->state_reserved ||
      r->request_checksum != phase2_prealloc_request_checksum(r) ||
      r->result_checksum)
    return -1;
  phase2_sizes=r->sizes[0]==PHASE2_CODE_BACKING_SIZE&&
               r->sizes[1]==PHASE2_STATE_BACKING_SIZE&&
               r->sizes[2]==PHASE2_CLONE_SIZE;
  phase3_sizes=r->sizes[0]>PHASE3_IMAGE_OFFSET&&
               !phase3_prealloc_layout(r->sizes[0]-PHASE3_IMAGE_OFFSET,
                                       &code,&state,&pages,&journal)&&
               code==r->sizes[0]&&state==r->sizes[1]&&
               r->sizes[2]==PHASE2_CLONE_SIZE;
  if(!phase2_sizes&&!phase3_sizes)return -1;
  for (unsigned i = 0; i < PHASE2_ALLOCATION_COUNT; ++i) {
    if (!canonical_kernel(r->addresses[i]) ||
        (r->addresses[i] & (PHASE2_CODE_SIZE - 1)))
      return -1;
    for (unsigned j = 0; j < i; ++j)
      if (r->addresses[i] == r->addresses[j])
        return -1;
  }
  return 0;
}

int phase2_leaf_contract_safe(const phase2_prealloc_record_t *r)
{
  const uint64_t code = r ? r->code_leaf_prepared : 0;
  const uint64_t data = r ? r->data_leaf_value : 0;
  const int phase3=r&&!(r->sizes[0]==PHASE2_CODE_BACKING_SIZE&&
                        r->sizes[1]==PHASE2_STATE_BACKING_SIZE);
  uint64_t expected_code=0,expected_state=0,expected_pages=0;size_t journal_size=0;
  const int bad_layout=phase3&&
      (r->sizes[0]<=PHASE3_IMAGE_OFFSET||
       phase3_prealloc_layout(r->sizes[0]-PHASE3_IMAGE_OFFSET,
                              &expected_code,&expected_state,&expected_pages,
                              &journal_size)||
       expected_code!=r->sizes[0]||expected_state!=r->sizes[1]);
  if (!r || bad_layout ||
      (phase3&&(r->journal_address!=r->addresses[1]+PHASE3_JOURNAL_OFFSET||
                !r->journal_checksum||!r->code_page_count||
                r->code_page_count!=expected_pages))||
      (!phase3&&(r->journal_address||r->journal_checksum||r->code_page_count))||
      r->code_levels != 4 || r->data_levels != 4 ||
      r->clone_page_count != PHASE2_CLONE_PAGE_COUNT ||
      !r->code_leaf_address || !r->data_leaf_address ||
      r->code_leaf_address == r->data_leaf_address ||
      !(code & FW1060_PAGE_PRESENT) || !(code & FW1060_PAGE_WRITABLE) ||
      (code & (FW1060_PAGE_XOTEXT | FW1060_PAGE_NX)) ||
      !(data & FW1060_PAGE_PRESENT) || !(data & FW1060_PAGE_WRITABLE) ||
      !(data & FW1060_PAGE_NX))
    return -1;
  for (unsigned i = 0; i < PHASE2_CLONE_PAGE_COUNT; ++i) {
    uint64_t value = r->clone_leaf_value[i];
    if (!r->clone_leaf_address[i] ||
        r->clone_leaf_address[i] == r->code_leaf_address ||
        r->clone_leaf_address[i] == r->data_leaf_address ||
        !(value & FW1060_PAGE_PRESENT) ||
        !(value & FW1060_PAGE_WRITABLE) || !(value & FW1060_PAGE_NX))
      return -1;
    for (unsigned j = 0; j < i; ++j)
      if (r->clone_leaf_address[i] == r->clone_leaf_address[j])
        return -1;
  }
  return 0;
}

int phase2_prealloc_validate(const phase2_prealloc_record_t *r,
                             uint64_t malloc_type, uint32_t flags)
{
  phase2_prealloc_record_t fired;
  if (!r || r->state != PHASE2_PREALLOC_VERIFIED ||
      r->result_checksum != phase2_prealloc_result_checksum(r) ||
      phase2_leaf_contract_safe(r))
    return -1;
  fired = *r;
  fired.state = PHASE2_PREALLOC_FIRED;
  fired.code_leaf_address = 0;
  fired.code_leaf_original = 0;
  fired.code_leaf_prepared = 0;
  fired.data_leaf_address = 0;
  fired.data_leaf_value = 0;
  memset(fired.clone_leaf_address, 0, sizeof(fired.clone_leaf_address));
  memset(fired.clone_leaf_value, 0, sizeof(fired.clone_leaf_value));
  fired.code_levels = fired.data_levels = fired.clone_page_count = 0;
  fired.journal_address = 0;
  fired.journal_checksum = 0;
  fired.code_page_count = 0;
  fired.result_checksum = 0;
  return phase2_prealloc_fired_validate(&fired, malloc_type, flags);
}

uint64_t phase2_locator_checksum(const phase2_locator_t *locator)
{
  return phase2_checksum(locator, offsetof(phase2_locator_t, checksum));
}

int phase2_locator_validate(const phase2_locator_t *locator)
{
  return locator && locator->magic == PHASE2_LOCATOR_MAGIC &&
         locator->generation == PHASE2_GENERATION &&
         canonical_kernel(locator->global_address) &&
         locator->global_size >= PHASE2_STATE_SIZE &&
         !(locator->global_size & 0xfff) &&
         locator->checksum == phase2_locator_checksum(locator) ? 0 : -1;
}

uint64_t phase2_global_immutable_checksum(const phase2_router_global_t *global)
{
  return phase2_checksum(global, offsetof(phase2_router_global_t,
                                          immutable_checksum));
}

int phase2_global_validate(const phase2_router_global_t *g)
{
  int phase2_layout,phase3_layout=0;uint64_t code,state,pages;size_t journal;
  if(!g)return -1;
  phase2_layout=g->code_size==PHASE2_CODE_SIZE&&
                g->state_size==PHASE2_STATE_SIZE;
  if(g->code_size>PHASE3_IMAGE_OFFSET&&
     !phase3_prealloc_layout(g->code_size-PHASE3_IMAGE_OFFSET,
                             &code,&state,&pages,&journal)&&
     code==g->code_size&&state==g->state_size)
    phase3_layout=1;
  if (g->magic != PHASE2_GLOBAL_MAGIC ||
      g->generation != PHASE2_GENERATION ||
      !canonical_kernel(g->code_address) || (!phase2_layout&&!phase3_layout) ||
      !canonical_kernel(g->state_address) ||
      !canonical_kernel(g->clone_address) ||
      g->clone_size != PHASE2_CLONE_SIZE ||
      g->owner_magic != PHASE2_OWNER_MAGIC ||
      g->immutable_checksum != phase2_global_immutable_checksum(g) ||
      (g->state != PHASE2_ROUTER_INSTALLING &&
       g->state != PHASE2_ROUTER_LIVE &&
       g->state != PHASE2_ROUTER_QUARANTINED))
    return -1;
  return 0;
}

int phase2_transition(phase2_router_global_t *g, uint32_t from, uint32_t to)
{
  if (!g || g->state != from)
    return -1;
  if (!((from == PHASE2_ROUTER_OFF && to == PHASE2_ROUTER_INSTALLING) ||
        (from == PHASE2_ROUTER_INSTALLING && to == PHASE2_ROUTER_LIVE) ||
        (from == PHASE2_ROUTER_INSTALLING &&
         to == PHASE2_ROUTER_QUARANTINED)))
    return -1;
  g->state = to;
  if (to == PHASE2_ROUTER_QUARANTINED)
    g->quarantined = 1;
  return 0;
}

int phase2_attach_begin(phase2_router_global_t *g, phase2_attachment_t *a,
                        uint64_t proc, uint64_t original_vector,
                        uint64_t original_table, uint64_t clone_vector,
                        uint64_t clone_table)
{
  if (phase2_global_validate(g) || g->state != PHASE2_ROUTER_LIVE ||
      g->quarantined || g->attachment_count || g->attached_proc || !a ||
      !canonical_kernel(proc) || !canonical_kernel(original_vector) ||
      !canonical_kernel(original_table) || !canonical_kernel(clone_vector) ||
      !canonical_kernel(clone_table))
    return -1;
  memset(a, 0, sizeof(*a));
  a->magic = PHASE2_ATTACHMENT_MAGIC;
  a->generation = g->generation;
  a->process_identity = proc;
  a->original_vector = original_vector;
  a->original_table = original_table;
  a->clone_vector = clone_vector;
  a->clone_table = clone_table;
  a->state = PHASE2_ATTACHMENT_PREPARED;
  return 0;
}

int phase2_attach_commit(phase2_router_global_t *g, phase2_attachment_t *a)
{
  if (!g || !a || g->state != PHASE2_ROUTER_LIVE || g->quarantined ||
      g->attachment_count || g->attached_proc ||
      a->magic != PHASE2_ATTACHMENT_MAGIC || a->generation != g->generation ||
      a->state != PHASE2_ATTACHMENT_PREPARED)
    return -1;
  g->attached_proc = a->process_identity;
  g->attachment_count = 1;
  a->state = PHASE2_ATTACHMENT_LIVE;
  return 0;
}

int phase2_attach_release(phase2_router_global_t *g, phase2_attachment_t *a)
{
  if (!g || !a || a->state != PHASE2_ATTACHMENT_LIVE ||
      g->attached_proc != a->process_identity || g->attachment_count != 1 ||
      g->inflight || a->inflight)
    return -1;
  g->attached_proc = 0;
  g->attachment_count = 0;
  a->state = PHASE2_ATTACHMENT_EMPTY;
  return 0;
}

static int emit(uint8_t *out, size_t cap, size_t *at, const void *src, size_t n)
{
  if (*at > cap || n > cap - *at)
    return -1;
  memcpy(out + *at, src, n);
  *at += n;
  return 0;
}

static int emit_disp32(uint8_t *out, size_t cap, size_t *at, uint32_t value)
{
  return emit(out, cap, at, &value, sizeof(value));
}

size_t phase2_build_router(uint8_t *out, size_t capacity,
                           uint64_t global_address)
{
  size_t at = 0, j1, j2, j3, fail_after, fail_before;
  uint64_t generation = PHASE2_GENERATION, result = PHASE2_TEST_RESULT;
  const uint8_t push_rbx = 0x53, pop_ret[] = {0x5b, 0xc3};
  const uint8_t mov_rbx[] = {0x48, 0xbb};
  const uint8_t cmp_state[] = {0x83, 0xbb};
  const uint8_t jne[] = {0x0f, 0x85};
  const uint8_t mov_rax[] = {0x48, 0xb8};
  const uint8_t cmp_gen[] = {0x48, 0x39, 0x83};
  const uint8_t mov_td_proc[] = {0x48, 0x8b, 0x47,
                                 PHASE2_TD_PROC_OFFSET};
  const uint8_t cmp_proc[] = {0x48, 0x39, 0x83};
  const uint8_t lock_inc32[] = {0xf0, 0xff, 0x83};
  const uint8_t lock_inc64[] = {0xf0, 0x48, 0xff, 0x83};
  const uint8_t store_ret[] = {0x48, 0x89, 0x87};
  const uint8_t lock_dec32[] = {0xf0, 0xff, 0x8b};
  const uint8_t success[] = {0x31, 0xc0, 0x5b, 0xc3};
  const uint8_t mov_errno[] = {0xb8, PHASE2_ENOSYS, 0, 0, 0};
#define E(x) do { if (emit(out, capacity, &at, (x), sizeof(x))) return 0; } while (0)
  if (emit(out, capacity, &at, &push_rbx, 1)) return 0;
  E(mov_rbx);
  if (emit(out, capacity, &at, &global_address, 8)) return 0;
  E(cmp_state);
  if (emit_disp32(out, capacity, &at,
                  offsetof(phase2_router_global_t, state))) return 0;
  {
    uint8_t live = PHASE2_ROUTER_LIVE;
    if (emit(out, capacity, &at, &live, 1)) return 0;
  }
  E(jne); j1 = at; if (emit_disp32(out, capacity, &at, 0)) return 0;
  E(mov_rax);
  if (emit(out, capacity, &at, &generation, 8)) return 0;
  E(cmp_gen);
  if (emit_disp32(out, capacity, &at,
                  offsetof(phase2_router_global_t, generation))) return 0;
  E(jne); j2 = at; if (emit_disp32(out, capacity, &at, 0)) return 0;
  E(mov_td_proc);
  E(cmp_proc);
  if (emit_disp32(out, capacity, &at,
                  offsetof(phase2_router_global_t, attached_proc))) return 0;
  E(jne); j3 = at; if (emit_disp32(out, capacity, &at, 0)) return 0;
  E(lock_inc32);
  if (emit_disp32(out, capacity, &at,
                  offsetof(phase2_router_global_t, inflight))) return 0;
  E(cmp_state);
  if (emit_disp32(out, capacity, &at,
                  offsetof(phase2_router_global_t, state))) return 0;
  {
    uint8_t live = PHASE2_ROUTER_LIVE;
    if (emit(out, capacity, &at, &live, 1)) return 0;
  }
  E(jne);
  {
    size_t p = at;
    if (emit_disp32(out, capacity, &at, 0)) return 0;
    fail_after = p;
  }
  E(lock_inc64);
  if (emit_disp32(out, capacity, &at,
                  offsetof(phase2_router_global_t, calls))) return 0;
  E(mov_rax);
  if (emit(out, capacity, &at, &result, 8)) return 0;
  E(store_ret);
  if (emit_disp32(out, capacity, &at,
                  g_fw1060_profile.thread_retval0_offset)) return 0;
  E(lock_dec32);
  if (emit_disp32(out, capacity, &at,
                  offsetof(phase2_router_global_t, inflight))) return 0;
  E(success);
  {
    size_t target = at;
    int32_t rel = (int32_t)(target - (fail_after + 4));
    memcpy(out + fail_after, &rel, 4);
  }
  E(lock_dec32);
  if (emit_disp32(out, capacity, &at,
                  offsetof(phase2_router_global_t, inflight))) return 0;
  fail_before = at;
  E(mov_errno);
  E(pop_ret);
  {
    size_t patches[] = {j1, j2, j3};
    for (unsigned i = 0; i < 3; ++i) {
      int32_t rel = (int32_t)(fail_before - (patches[i] + 4));
      memcpy(out + patches[i], &rel, 4);
    }
  }
#undef E
  return at;
}
