#ifndef PAGE_PUBLICATION1060_H
#define PAGE_PUBLICATION1060_H

#include <stddef.h>
#include <stdint.h>

#include "firmware_profile1060.h"

#define FW1060_PAGE_LEVELS 4U
#define FW1060_PUBLICATION_QUARANTINED (-2)

typedef struct {
  uint64_t address;
  uint64_t original;
  uint64_t requested;
} fw1060_page_entry_change_t;

typedef struct {
  uint64_t code_address;
  const uint8_t *original_code;
  const uint8_t *requested_code;
  size_t code_size;
  fw1060_page_entry_change_t entries[FW1060_PAGE_LEVELS];
  uint64_t required_effective_set;
  uint64_t required_effective_clear;
  uint64_t publication_address;
  uint64_t unpublished_value;
  uint64_t published_value;
} fw1060_publication_request_t;

typedef struct {
  void *context;
  int (*read)(void *context, uint64_t address, void *data, size_t size);
  int (*write)(void *context, uint64_t address, const void *data, size_t size);
  int (*walk_effective)(void *context, uint64_t address, uint64_t *flags,
                        unsigned *levels);
  int (*sync_guest_tlb_all)(void *context, uint64_t kernel_offset);
  int (*sync_instructions_all)(void *context, uint64_t kernel_offset);
  int (*phase)(void *context, const char *name, uint64_t address,
               uint64_t original, uint64_t requested, uint64_t readback);
} fw1060_publication_io_t;

/*
 * Returns zero only after publication readback. Any failed rollback returns
 * FW1060_PUBLICATION_QUARANTINED. The caller must keep quarantined storage
 * pinned until attended recovery or reboot.
 */
int fw1060_publish_page(const fw1060_publication_io_t *io,
                        const fw1060_publication_request_t *request);

#endif
