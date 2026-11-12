#ifndef OFFSETS_10_60_H
#define OFFSETS_10_60_H

// Retail 0x10600006 offsets from ps5-linux/ps5-linux-loader off_1060.
// Zero means unavailable: callers must reject it, not treat ktext(0) as a gadget.
static const uint64_t g_sym_map_1060[] = {
  0,          // DMPML4I: derive DMAP from proc 0 pmap instead
  0,          // DMPDPI
  0,          // PML4PML4I
  0,          // SYS_GETUID: test hook unsupported
  0x4D7150,   // PRINTF
  0,          // ACPI_SLEEP_MACHDEP_HOOK
  0xC12FD0,   // HV_MP_STARTUP_CALL
  0x2B0CE8,   // MP_STARTUP_INIT_VECTOR
  0,          // PMAP_STORE: derive kernel pmap from proc 0 instead
  0x2AE3000,  // DATA_CAVE
  0x3A1C300,  // IDT_ARRAY
  0x3A1EFE0,  // COMMON_TSS
  0,          // HV_HEAP_BASE: 10.x AP path scans VMCBs
  0,          // HV_PCPUS
};

static const uint64_t g_gadget_map_1060[] = {
  0x24739E, // PIVOT_ADD_RSP28_RET
  0x2526ED, // IRETQ
  0x20DB10, // POP_RAX
  0x2DEE81, // POP_RCX
  0x1F0EB8, // POP_RDI
  0x1B19F0, // POP_RSI
  0x3CF802, // POP_RDX
  0,        // POP_R8: use RDI+8 store sequence
  0x255550, // POP_RSP
  0,        // STORE_RCX_R8
  0x36FBCB, // STORE_RDI8_RCX
  0,        // OR_RCX_EAX: oneshot only
  0xA091A6, // SET_DR7
  0,        // ST_RCX_RDX: RSI/RDX explicitly replaced on resume
  0x3079AF, // ST_RCX_RAX
  0,        // MOV_RAX_RSI
  0x258FD1, // MOV_RAX_RDI
  0x2AA827, // REP_MOVSB
  0x2A6AA8, // CLD
  0x20DB11, // RET_TRAMP
  0x24BC38, // DBREG_RESUME
};

#endif // OFFSETS_10_60_H
