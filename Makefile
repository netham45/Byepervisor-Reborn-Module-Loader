#   Copyright (C) 2023 John Törnblom
#
# This file is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING. If not see
# <http://www.gnu.org/licenses/>.

ifdef PS5_PAYLOAD_SDK
    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
else
    $(error PS5_PAYLOAD_SDK is undefined)
endif

ELF := byepervisor_reborn.elf
PHASE0_ELF := phase0_probe.elf
PHASE1_CARRIER_ELF := phase1_carrier.elf
PHASE1_RUNTIME_ELF := phase1_runtime.elf
HOST_SMOKE := phase0_smoke
PHASE1_HOST_SMOKE := phase1_smoke
PHASE2_CARRIER_ELF := phase2_carrier.elf
PHASE2_RUNTIME_ELF := phase2_runtime.elf
PHASE2_HOST_SMOKE := phase2_smoke
PHASE3_CARRIER_ELF := phase3_carrier.elf
PHASE3_RUNTIME_ELF := phase3_runtime.elf
PHASE3_RUNTIME_RELEASE_ELF := phase3_runtime_release.elf
PHASE3_HOST_SMOKE := phase3_smoke
PHASE3_BLOB := phase3_hello.blob
HOST_CC ?= cc

PHASE3_CARRIER_FLAGS := -DBYEPERVISOR_1060_ARM -DPHASE2_CARRIER -DPHASE3_CARRIER
PHASE3_CARRIER_SOURCES := main.c kdlsym.c khook.c paging.c util.c hv_1060.c firmware_profile1060.c page_publication1060.c phase2_router1060.c phase3_module1060.c
PHASE3_RUNTIME_DEPS := phase3_runtime1060.c phase2_runtime1060.c phase3_module1060.c phase2_router1060.c kdlsym.c paging.c util.c firmware_profile1060.c
PHASE3_RUNTIME_SOURCES := phase3_runtime1060.c phase3_module1060.c phase2_router1060.c kdlsym.c paging.c util.c firmware_profile1060.c

PAYLOAD_DIR := break_hv_payload
PAYLOAD_HDR := $(PAYLOAD_DIR)/break_hv.h

CFLAGS := -Wall -Werror -Wno-unused-function -g -I./include

.PHONY: all release clean test debug host-smoke phase1-host-smoke phase2-host-smoke phase3-host-smoke

all: $(ELF) $(PHASE0_ELF) $(PHASE1_CARRIER_ELF) $(PHASE1_RUNTIME_ELF) $(PHASE2_CARRIER_ELF) $(PHASE2_RUNTIME_ELF) $(PHASE3_CARRIER_ELF) $(PHASE3_RUNTIME_ELF) $(PHASE3_RUNTIME_RELEASE_ELF) $(PHASE3_BLOB)

$(PAYLOAD_HDR): $(PAYLOAD_DIR)/break_hv.c $(PAYLOAD_DIR)/entry.S $(PAYLOAD_DIR)/link.ld
	sh $(PAYLOAD_DIR)/build.sh

$(ELF): $(PAYLOAD_HDR) $(PHASE3_CARRIER_SOURCES)
	$(CC) $(CFLAGS) $(PHASE3_CARRIER_FLAGS) -DPHASE3_RELEASE -o $@ $(filter %.c,$^)

$(PHASE0_ELF): runtime_syscall1060.c kdlsym.c paging.c util.c firmware_profile1060.c page_publication1060.c
	$(CC) $(CFLAGS) -o $@ $^ -lpthread

$(PHASE1_CARRIER_ELF): CFLAGS += -DBYEPERVISOR_1060_ARM -DPHASE1_CARRIER
$(PHASE1_CARRIER_ELF): $(PAYLOAD_HDR) main.c kdlsym.c khook.c paging.c util.c hv_1060.c firmware_profile1060.c page_publication1060.c phase1_allocator1060.c
	$(CC) $(CFLAGS) -o $@ $(filter %.c,$^)

$(PHASE1_RUNTIME_ELF): phase1_runtime1060.c phase1_allocator1060.c kdlsym.c paging.c util.c firmware_profile1060.c
	$(CC) $(CFLAGS) -o $@ $^
$(PHASE2_CARRIER_ELF): CFLAGS += -DBYEPERVISOR_1060_ARM -DPHASE2_CARRIER
$(PHASE2_CARRIER_ELF): $(PAYLOAD_HDR) main.c kdlsym.c khook.c paging.c util.c hv_1060.c firmware_profile1060.c page_publication1060.c phase2_router1060.c
	$(CC) $(CFLAGS) -o $@ $(filter %.c,$^)

$(PHASE2_RUNTIME_ELF): phase2_runtime1060.c phase2_router1060.c kdlsym.c paging.c util.c firmware_profile1060.c
	$(CC) $(CFLAGS) -o $@ $^
phase3_blob_code.o: phase3_hello_blob.S
	$(CC) -c -ffreestanding -fPIC -fno-stack-protector -o $@ $<
phase3_blob_code.bin: phase3_blob_code.o
	$(OBJCOPY) -j .text -O binary $< $@
$(PHASE3_BLOB): phase3_blob_code.bin build_phase3_blob.py
	./build_phase3_blob.py phase3_blob_code.bin $@

$(PHASE3_CARRIER_ELF): $(PAYLOAD_HDR) $(PHASE3_CARRIER_SOURCES)
	$(CC) $(CFLAGS) $(PHASE3_CARRIER_FLAGS) -o $@ $(filter %.c,$^)

$(PHASE3_RUNTIME_ELF): $(PHASE3_RUNTIME_DEPS)
	$(CC) $(CFLAGS) -o $@ $(PHASE3_RUNTIME_SOURCES)

$(PHASE3_RUNTIME_RELEASE_ELF): $(PHASE3_RUNTIME_DEPS)
	$(CC) $(CFLAGS) -DPHASE3_RELEASE -o $@ $(PHASE3_RUNTIME_SOURCES)

release: $(ELF) $(PHASE3_RUNTIME_RELEASE_ELF) $(PHASE3_BLOB)

$(HOST_SMOKE): phase0_smoke.c firmware_profile1060.c page_publication1060.c
	$(HOST_CC) -std=c11 -Wall -Wextra -Werror -I./include -o $@ $^

$(PHASE1_HOST_SMOKE): phase1_smoke.c phase1_allocator1060.c
	$(HOST_CC) -std=c11 -Wall -Wextra -Werror -I./include -o $@ $^
$(PHASE2_HOST_SMOKE): phase2_smoke.c phase2_router1060.c firmware_profile1060.c
	$(HOST_CC) -std=c11 -Wall -Wextra -Werror -I./include -o $@ $^
$(PHASE3_HOST_SMOKE): phase3_smoke.c phase3_module1060.c phase2_router1060.c firmware_profile1060.c $(PHASE3_BLOB)
	$(HOST_CC) -std=c11 -Wall -Wextra -Werror -I./include -o $@ phase3_smoke.c phase3_module1060.c phase2_router1060.c firmware_profile1060.c


host-smoke: $(HOST_SMOKE)
	./$(HOST_SMOKE)

phase1-host-smoke: $(PHASE1_HOST_SMOKE)
	./$(PHASE1_HOST_SMOKE)
phase2-host-smoke: $(PHASE2_HOST_SMOKE)
	./$(PHASE2_HOST_SMOKE)
phase3-host-smoke: $(PHASE3_HOST_SMOKE)
	./$(PHASE3_HOST_SMOKE)


clean:
	rm -f $(ELF) $(PHASE0_ELF) $(PHASE1_CARRIER_ELF) $(PHASE1_RUNTIME_ELF) $(PHASE2_CARRIER_ELF) $(PHASE2_RUNTIME_ELF) $(PHASE3_CARRIER_ELF) $(PHASE3_RUNTIME_ELF) $(PHASE3_RUNTIME_RELEASE_ELF) $(HOST_SMOKE) $(PHASE1_HOST_SMOKE) $(PHASE2_HOST_SMOKE) $(PHASE3_HOST_SMOKE)
	rm -f $(PHASE3_BLOB) phase3_hello_blob.o phase3_blob_code.o phase3_blob_code.bin
	rm -f $(PAYLOAD_DIR)/break_hv.h $(PAYLOAD_DIR)/break_hv.bin $(PAYLOAD_DIR)/break_hv.elf $(PAYLOAD_DIR)/*.o

test debug:
	@echo "$@ is disabled: $(ELF) is the mutating Phase 3 release carrier; build or deploy an explicit artifact instead." >&2
	@false
