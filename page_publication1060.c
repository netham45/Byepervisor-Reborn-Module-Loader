#include <string.h>

#include "page_publication1060.h"

static int mark(const fw1060_publication_io_t *io, const char *name,
                uint64_t address, uint64_t original, uint64_t requested,
                uint64_t readback)
{
  return io->phase(io->context, name, address, original, requested, readback);
}

static int sync_all(const fw1060_publication_io_t *io, const char *prefix)
{
  if (mark(io, prefix, g_fw1060_profile.all_core_guest_tlb_offset,
           0, g_fw1060_profile.all_core_guest_tlb_offset, 0) != 0 ||
      io->sync_guest_tlb_all(io->context,
          g_fw1060_profile.all_core_guest_tlb_offset) != 0 ||
      mark(io, "sync-guest-tlb-all-done",
           g_fw1060_profile.all_core_guest_tlb_offset, 0,
           g_fw1060_profile.all_core_guest_tlb_offset,
           g_fw1060_profile.all_core_guest_tlb_offset) != 0 ||
      mark(io, "sync-instructions-all-start",
           g_fw1060_profile.all_core_instruction_offset, 0,
           g_fw1060_profile.all_core_instruction_offset, 0) != 0 ||
      io->sync_instructions_all(io->context,
          g_fw1060_profile.all_core_instruction_offset) != 0 ||
      mark(io, "sync-instructions-all-done",
           g_fw1060_profile.all_core_instruction_offset, 0,
           g_fw1060_profile.all_core_instruction_offset,
           g_fw1060_profile.all_core_instruction_offset) != 0)
    return -1;
  return 0;
}

static int rollback(const fw1060_publication_io_t *io,
                    const fw1060_publication_request_t *request,
                    int published, unsigned entries_written, int code_written)
{
  uint64_t readback = 0;
  int failed = 0;

  mark(io, "rollback-order", request->publication_address,
       published ? request->published_value : request->unpublished_value,
       request->unpublished_value,
       ((uint64_t)entries_written << 32) | (unsigned)code_written);
  if (published) {
    if (mark(io, "rollback-unpublish-start", request->publication_address,
             request->published_value, request->unpublished_value, 0) != 0 ||
        io->write(io->context, request->publication_address,
                  &request->unpublished_value, sizeof(uint64_t)) != 0 ||
        io->read(io->context, request->publication_address, &readback,
                 sizeof(readback)) != 0 || readback != request->unpublished_value)
      failed = 1;
    mark(io, "rollback-unpublish-done", request->publication_address,
         request->published_value, request->unpublished_value, readback);
  }
  while (entries_written) {
    const fw1060_page_entry_change_t *entry =
        &request->entries[--entries_written];
    readback = 0;
    if (mark(io, "rollback-entry-start", entry->address, entry->requested,
             entry->original, 0) != 0 ||
        io->write(io->context, entry->address, &entry->original,
                  sizeof(entry->original)) != 0 ||
        io->read(io->context, entry->address, &readback,
                 sizeof(readback)) != 0 || readback != entry->original)
      failed = 1;
    mark(io, "rollback-entry-done", entry->address, entry->requested,
         entry->original, readback);
  }
  if (code_written) {
    uint8_t readback_code[FW1060_LANDING_BYTES];
    if (request->code_size > sizeof(readback_code) ||
        mark(io, "rollback-code-start", request->code_address, 0, 0, 0) != 0 ||
        io->write(io->context, request->code_address, request->original_code,
                  request->code_size) != 0 ||
        io->read(io->context, request->code_address, readback_code,
                 request->code_size) != 0 ||
        memcmp(readback_code, request->original_code,
               request->code_size) != 0)
      failed = 1;
    mark(io, "rollback-code-done", request->code_address, 0, 0,
         failed ? 0 : request->code_size);
  }
  if (sync_all(io, "rollback-sync-guest-tlb-all-start") != 0)
    failed = 1;
  for (unsigned i = 0; i < FW1060_PAGE_LEVELS; ++i) {
    readback = 0;
    if (io->read(io->context, request->entries[i].address, &readback,
                 sizeof(readback)) != 0 ||
        readback != request->entries[i].original)
      failed = 1;
    mark(io, "rollback-original-readback", request->entries[i].address,
         request->entries[i].requested, request->entries[i].original,
         readback);
  }
  mark(io, failed ? "rollback-quarantined" : "rollback-complete",
       request->code_address, 0, 0, failed ? 1 : 0);
  return failed ? FW1060_PUBLICATION_QUARANTINED : -1;
}

int fw1060_publish_page(const fw1060_publication_io_t *io,
                        const fw1060_publication_request_t *request)
{
  uint8_t code[FW1060_LANDING_BYTES];
  uint64_t readback, effective;
  unsigned levels, entries_written = 0;
  int code_written = 0, published = 0;

  if (!io || !request || !io->read || !io->write || !io->walk_effective ||
      !io->sync_guest_tlb_all || !io->sync_instructions_all || !io->phase ||
      !request->original_code || !request->requested_code ||
      request->code_size == 0 || request->code_size > sizeof(code) ||
      fw1060_profile_validate() != 0)
    return -1;
  if (mark(io, "rollback-order-before-first-write", request->code_address,
           0, FW1060_PAGE_LEVELS, 0) != 0)
    return -1;
  if (io->walk_effective(io->context, request->code_address, &effective,
                         &levels) != 0 || levels != FW1060_PAGE_LEVELS)
    return -1;
  for (unsigned i = 0; i < FW1060_PAGE_LEVELS; ++i) {
    const fw1060_page_entry_change_t *entry = &request->entries[i];
    if (!entry->address || !(entry->original & FW1060_PAGE_PRESENT) ||
        (i < FW1060_PAGE_LEVELS - 1 &&
         (entry->original & FW1060_PAGE_HUGE)) ||
        io->read(io->context, entry->address, &readback,
                 sizeof(readback)) != 0 || readback != entry->original ||
        mark(io, "preflight-entry", entry->address, entry->original,
             entry->requested, readback) != 0)
      return -1;
  }
  if (io->read(io->context, request->code_address, code,
               request->code_size) != 0 ||
      memcmp(code, request->original_code, request->code_size) != 0 ||
      io->read(io->context, request->publication_address, &readback,
               sizeof(readback)) != 0 || readback != request->unpublished_value)
    return -1;
  if (mark(io, "load-code-start", request->code_address, 0, 0, 0) != 0)
    return -1;
  code_written = 1;
  if (io->write(io->context, request->code_address, request->requested_code,
                request->code_size) != 0)
    return rollback(io, request, published, entries_written, code_written);
  if (io->read(io->context, request->code_address, code,
               request->code_size) != 0 ||
      memcmp(code, request->requested_code, request->code_size) != 0 ||
      mark(io, "load-code-done", request->code_address, 0, 0,
           request->code_size) != 0)
    return rollback(io, request, published, entries_written, code_written);

  for (unsigned i = 0; i < FW1060_PAGE_LEVELS; ++i) {
    const fw1060_page_entry_change_t *entry = &request->entries[i];
    if (mark(io, "entry-write-start", entry->address, entry->original,
             entry->requested, 0) != 0)
      return rollback(io, request, published, entries_written, code_written);
    ++entries_written;
    if (io->write(io->context, entry->address, &entry->requested,
                  sizeof(entry->requested)) != 0)
      return rollback(io, request, published, entries_written, code_written);
    if (io->read(io->context, entry->address, &readback,
                 sizeof(readback)) != 0 || readback != entry->requested ||
        mark(io, "entry-write-done", entry->address, entry->original,
             entry->requested, readback) != 0)
      return rollback(io, request, published, entries_written, code_written);
  }
  if (sync_all(io, "sync-guest-tlb-all-start") != 0 ||
      io->walk_effective(io->context, request->code_address, &effective,
                         &levels) != 0 || levels != FW1060_PAGE_LEVELS ||
      (effective & request->required_effective_set) !=
          request->required_effective_set ||
      (effective & request->required_effective_clear) != 0 ||
      mark(io, "effective-permissions", request->code_address, 0,
           request->required_effective_set, effective) != 0)
    return rollback(io, request, published, entries_written, code_written);

  if (mark(io, "publish-start", request->publication_address,
           request->unpublished_value, request->published_value, 0) != 0)
    return rollback(io, request, published, entries_written, code_written);
  published = 1;
  if (io->write(io->context, request->publication_address,
                &request->published_value, sizeof(uint64_t)) != 0)
    return rollback(io, request, published, entries_written, code_written);
  if (io->read(io->context, request->publication_address, &readback,
               sizeof(readback)) != 0 || readback != request->published_value ||
      mark(io, "publish-done", request->publication_address,
           request->unpublished_value, request->published_value,
           readback) != 0)
    return rollback(io, request, published, entries_written, code_written);
  return 0;
}
