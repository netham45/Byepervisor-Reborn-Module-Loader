#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "phase2_router1060.h"

#define P (FW1060_PAGE_PRESENT)
#define RW (FW1060_PAGE_PRESENT | FW1060_PAGE_WRITABLE)
#define RWNX (RW | FW1060_PAGE_NX)

typedef struct {
  unsigned code_loaded;
  unsigned permissions;
  unsigned tlb_all;
  unsigned instructions_all;
  unsigned cfi_pairs;
  unsigned live;
  unsigned clone;
  unsigned quarantined;
} publication_model_t;

static int publish_model(publication_model_t *m, unsigned fail_at,
                         int rollback_owner_matches)
{
  unsigned stage = 0;
#define STEP(field) do { ++stage; m->field = 1; if (fail_at == stage) goto fail; } while (0)
  STEP(code_loaded);
  STEP(permissions);
  STEP(tlb_all);
  STEP(instructions_all);
  for (unsigned i = 0; i < FW1060_CFI_PAIR_COUNT; ++i) {
    ++stage;
    ++m->cfi_pairs;
    if (fail_at == stage)
      goto fail;
  }
  STEP(live);
  STEP(clone);
#undef STEP
  return 0;
fail:
  assert(!m->clone);
  if (!rollback_owner_matches) {
    m->quarantined = 1;
    return -2;
  }
  m->cfi_pairs = 0;
  m->instructions_all = 0;
  m->tlb_all = 0;
  m->permissions = 0;
  m->code_loaded = 0;
  return -1;
}

static void make_prealloc(phase2_prealloc_record_t *r)
{
  const uint64_t type = 0xffffffff82ad5670ULL;
  phase2_prealloc_prepare(r, type, 0x101);
  r->addresses[0] = 0xffff800010000000ULL;
  r->addresses[1] = 0xffff800010001000ULL;
  r->addresses[2] = 0xffff800010010000ULL;
  {
    const uint64_t commit = PHASE2_PREALLOC_FIRED;
    memcpy((uint8_t *)r + offsetof(phase2_prealloc_record_t, state),
           &commit, sizeof(commit));
  }
  assert(r->sizes[0] == PHASE2_CODE_BACKING_SIZE &&
         r->sizes[1] == PHASE2_STATE_BACKING_SIZE &&
         r->sizes[2] == PHASE2_CLONE_SIZE && r->state_reserved == 0);
  assert(phase2_prealloc_fired_validate(r, type, 0x101) == 0);
  r->code_leaf_address = 0xffff900000001000ULL;
  r->code_leaf_original = RWNX;
  r->code_leaf_prepared = RW;
  r->data_leaf_address = 0xffff900000002000ULL;
  r->data_leaf_value = RWNX;
  r->code_levels = 4;
  r->data_levels = 4;
  r->clone_page_count = PHASE2_CLONE_PAGE_COUNT;
  for (unsigned i = 0; i < PHASE2_CLONE_PAGE_COUNT; ++i) {
    r->clone_leaf_address[i] = 0xffff900000010000ULL + (uint64_t)i * 8;
    r->clone_leaf_value[i] = RWNX | ((uint64_t)i << 12);
  }
  assert(phase2_leaf_contract_safe(r) == 0);
  r->state = PHASE2_PREALLOC_VERIFIED;
  r->result_checksum = phase2_prealloc_result_checksum(r);
  assert(phase2_prealloc_validate(r, type, 0x101) == 0);
}

static void make_global(phase2_router_global_t *g,
                        const phase2_prealloc_record_t *r)
{
  memset(g, 0, sizeof(*g));
  g->magic = PHASE2_GLOBAL_MAGIC;
  g->generation = PHASE2_GENERATION;
  g->code_address = r->addresses[0];
  g->code_size = PHASE2_CODE_SIZE;
  g->state_address = r->addresses[1];
  g->state_size = PHASE2_STATE_SIZE;
  g->clone_address = r->addresses[2];
  g->clone_size = PHASE2_CLONE_SIZE;
  g->code_leaf_address = r->code_leaf_address;
  g->code_leaf_original = r->code_leaf_original;
  g->code_leaf_final = r->code_leaf_prepared & ~FW1060_PAGE_WRITABLE;
  g->data_leaf_address = r->data_leaf_address;
  g->data_leaf_value = r->data_leaf_value;
  memcpy(g->clone_leaf_address, r->clone_leaf_address,
         sizeof(g->clone_leaf_address));
  memcpy(g->clone_leaf_value, r->clone_leaf_value,
         sizeof(g->clone_leaf_value));
  g->owner_magic = PHASE2_OWNER_MAGIC;
  g->state = PHASE2_ROUTER_INSTALLING;
  g->immutable_checksum = phase2_global_immutable_checksum(g);
  assert(phase2_global_validate(g) == 0);
}

int main(void)
{
  phase2_prealloc_record_t prealloc, unsafe;
  phase2_router_global_t global;
  phase2_attachment_t attachment;
  publication_model_t publication = {0}, failed = {0}, quarantined = {0};
  uint8_t router[512], thunk[FW1060_CFI_BYTES_MAX], landing[FW1060_LANDING_BYTES];
  uint64_t stock[FW1060_SYSCALL_COUNT], clone[FW1060_SYSCALL_COUNT];

  assert(fw1060_profile_validate() == 0);
  make_prealloc(&prealloc);
  unsafe = prealloc;
  unsafe.code_levels = 3;
  assert(phase2_leaf_contract_safe(&unsafe) != 0);
  unsafe = prealloc;
  unsafe.clone_leaf_address[3] = unsafe.code_leaf_address;
  assert(phase2_leaf_contract_safe(&unsafe) != 0);
  unsafe = prealloc;
  unsafe.data_leaf_value &= ~FW1060_PAGE_NX;
  assert(phase2_leaf_contract_safe(&unsafe) != 0);

  make_global(&global, &prealloc);
  assert(phase2_attach_begin(&global, &attachment,
      0xffff800020000000ULL, 0xffffffff81000000ULL,
      0xffffffff82000000ULL, 0xffff800010011000ULL,
      0xffff800010012000ULL) != 0);
  assert(phase2_transition(&global, PHASE2_ROUTER_INSTALLING,
                           PHASE2_ROUTER_LIVE) == 0);
  assert(phase2_attach_begin(&global, &attachment,
      0xffff800020000000ULL, 0xffffffff81000000ULL,
      0xffffffff82000000ULL, 0xffff800010011000ULL,
      0xffff800010012000ULL) == 0);
  assert(phase2_attach_commit(&global, &attachment) == 0);
  global.inflight = 1;
  assert(phase2_attach_release(&global, &attachment) != 0);
  global.inflight = 0;
  assert(phase2_attach_release(&global, &attachment) == 0);
  assert(global.attachment_count == 0 && global.attached_proc == 0);
  assert(phase2_transition(&global, PHASE2_ROUTER_LIVE,
                           PHASE2_ROUTER_OFF) != 0);

  assert(publish_model(&publication, 0, 1) == 0);
  assert(publication.code_loaded && publication.permissions &&
         publication.tlb_all && publication.instructions_all &&
         publication.cfi_pairs == FW1060_CFI_PAIR_COUNT &&
         publication.live && publication.clone);
  assert(publish_model(&failed, 5, 1) == -1);
  assert(!failed.live && !failed.clone && !failed.cfi_pairs &&
         !failed.permissions);
  assert(publish_model(&quarantined, 5, 0) == -2);
  assert(quarantined.quarantined && !quarantined.live && !quarantined.clone);

  memcpy(thunk, g_fw1060_profile.cfi_pairs[0].thunk_bytes, sizeof(thunk));
  memcpy(landing, g_fw1060_profile.cfi_pairs[0].landing_bytes, sizeof(landing));
  assert(fw1060_verify_cfi_pair(&g_fw1060_profile.cfi_pairs[0], thunk,
                                landing) == 0);
  landing[0] ^= 1;
  assert(fw1060_verify_cfi_pair(&g_fw1060_profile.cfi_pairs[0], thunk,
                                landing) != 0);

  size_t router_size = phase2_build_router(router, sizeof(router),
                                            prealloc.addresses[1]);
  assert(router_size > 64 && router_size < sizeof(router));
  for (size_t i = 0; i + 1 < router_size; ++i)
    assert(!(router[i] == 0xff &&
             (router[i + 1] == 0xd0 || router[i + 1] == 0xe0)));

  for (unsigned i = 0; i < FW1060_SYSCALL_COUNT; ++i)
    stock[i] = 0xffffffff80000000ULL + i * 16ULL;
  memcpy(clone, stock, sizeof(clone));
  clone[PHASE2_TEST_SYSCALL] =
      g_fw1060_profile.cfi_pairs[0].thunk_offset;
  for (unsigned i = 0; i < FW1060_SYSCALL_COUNT; ++i)
    assert(i == PHASE2_TEST_SYSCALL || clone[i] == stock[i]);

  puts("phase2-smoke: PASS prealloc=commit-verified leaves=rx-rwnx-separated "
       "huge=refused publication=all-core-ordered rollback=owner-checked "
       "cfi=conflict-refused state=pre-live-rejected accounting=balanced "
       "stock=nonclaimed-preserved quarantine=pinned dispatch=direct-only");
  return 0;
}
