#ifndef HV_1060_H
#define HV_1060_H

#include <stdint.h>

typedef struct {
  uint64_t oracle[8];
  uint64_t detail[7];
  uint64_t gate[2];
  uint32_t valid;
} hv1060_result_diag_t;

int hv1060_run(void);
void hv1060_get_result_diag(hv1060_result_diag_t *diagnostic);

#endif
