#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "phase3_module1060.h"
#include "phase2_router1060.h"

static void put16(uint8_t *p,uint16_t v){p[0]=v;p[1]=v>>8;}
static void put32(uint8_t *p,uint32_t v){for(unsigned i=0;i<4;++i)p[i]=v>>(8*i);}
static void put64(uint8_t *p,uint64_t v){for(unsigned i=0;i<8;++i)p[i]=v>>(8*i);}
static void resign(uint8_t *blob,size_t size){uint8_t d[32];memset(blob+96,0,32);phase3_blob_digest(blob,size,d);memcpy(blob+96,d,32);}
static void load_file(uint8_t **out,size_t *size){
  FILE *f=fopen("phase3_hello.blob","rb"); long n; assert(f); assert(!fseek(f,0,SEEK_END)); n=ftell(f); assert(n>0); rewind(f);
  *out=malloc((size_t)n); assert(*out); assert(fread(*out,1,(size_t)n,f)==(size_t)n); assert(!fclose(f)); *size=(size_t)n;
}
static int registration_model(int valid,int init_errno,unsigned *state,unsigned *init_published,unsigned *hello_published,unsigned *init_calls){
  if(!valid){assert(!*init_published&&!*hello_published);return -1;}
  *state=PHASE3_MODULE_REGISTERED;*init_published=1;*state=PHASE3_MODULE_INITIALIZING;++*init_calls;
  if(init_errno){*state=PHASE3_MODULE_FAILED;*init_published=0;assert(!*hello_published);return init_errno;}
  *state=PHASE3_MODULE_INITIALIZED;*init_published=0;*hello_published=1;*state=PHASE3_MODULE_ACTIVE;return 0;
}
int main(void){
  uint8_t *blob,*copy,*image,*bad,router[512]; size_t size,router_size,journal_size; phase3_blob_view_t v; phase3_module_state_t module={0};
  uint64_t code_size,state_size,page_count;
  unsigned state=0,init_pub=0,hello_pub=0,init_calls=0; load_file(&blob,&size);
  assert(sizeof(blob_header_v1)==128&&sizeof(blob_segment_v1)==44&&sizeof(blob_syscall_v1)==16);
  assert(phase3_blob_validate(blob,size,&v)==0); assert(v.header.init_offset==0&&v.header.dispatch_offset==16);
  assert(size==64ULL*1024ULL*1024ULL);
  assert(v.header.image_size==64ULL*1024ULL*1024ULL);
  assert(!phase3_prealloc_layout(96ULL*1024ULL*1024ULL+123,
                                 &code_size,&state_size,&page_count,
                                 &journal_size));
  assert(code_size==96ULL*1024ULL*1024ULL+0x2000&&
         page_count==code_size/0x1000&&
         journal_size==sizeof(phase3_code_journal_t)+
             page_count*sizeof(phase3_code_page_entry_t)&&
         state_size>=PHASE3_JOURNAL_OFFSET+journal_size);
  assert(phase3_prealloc_layout(UINT64_MAX,&code_size,&state_size,
                                &page_count,&journal_size));
  assert(v.segments[0].file_offset+v.segments[0].file_size==size);
  assert(!phase3_allowlist_handlers_validate(0xffffffff80100100ULL,
                                              0xffffffff80100200ULL,
                                              0xffffffff80000000ULL,
                                              0xffffffff81000000ULL));
  assert(phase3_allowlist_handlers_validate(0,0xffffffff80100200ULL,
                                             0xffffffff80000000ULL,
                                             0xffffffff81000000ULL));
  router_size=phase3_build_init_router(router,sizeof(router),0xffffffff90001000ULL,
                                        0xffffffff80100000ULL,8,0x408);
  assert(router_size&&router_size<=sizeof(router));
  router_size=phase3_build_hello_router(router,sizeof(router),0xffffffff90001000ULL,
                                       0xffffffff80100000ULL,8);
  assert(router_size&&router_size<=sizeof(router));
  image=malloc((size_t)v.header.image_size); assert(image); memset(image,0xa5,(size_t)v.header.image_size);
  assert(!phase3_blob_load(&v,image,(size_t)v.header.image_size));
  assert(!memcmp(image,blob+v.segments[0].file_offset,(size_t)v.segments[0].file_size));
  for(uint64_t i=v.segments[0].file_size;i<v.segments[0].memory_size;++i)assert(image[i]==0);
  assert(phase3_blob_validate(blob,sizeof(blob_header_v1)-1,&v)==PHASE3_BLOB_TRUNCATED);
  bad=malloc(size);copy=calloc(1,512);assert(bad&&copy);
#define BAD(expected,action) do{memcpy(bad,blob,size);action;assert(phase3_blob_validate(bad,size,&v)==(expected));}while(0)
  BAD(PHASE3_BLOB_DIGEST_ERROR,bad[size-1]^=1);
  BAD(PHASE3_BLOB_SIZE_ERROR,put64(bad+16,UINT64_MAX);resign(bad,size));
  BAD(PHASE3_BLOB_TABLE_ERROR,put64(bad+56,UINT64_MAX-8);resign(bad,size));
  BAD(PHASE3_BLOB_SEGMENT_ERROR,put64(bad+128+16,UINT64_MAX);resign(bad,size));
  BAD(PHASE3_BLOB_ENTRY_ERROR,put64(bad+72,64ULL*1024ULL*1024ULL);resign(bad,size));
  BAD(PHASE3_BLOB_VERSION_ERROR,put16(bad+10,2);resign(bad,size));
  BAD(PHASE3_BLOB_CAP_ERROR,put64(bad+32,1);resign(bad,size));
  BAD(PHASE3_BLOB_CAP_ERROR,put64(bad+40,2);resign(bad,size));
  BAD(PHASE3_BLOB_SYSCALL_ERROR,put32(bad+176,700);resign(bad,size));
  BAD(PHASE3_BLOB_SYSCALL_ERROR,put32(bad+176+8,0x80000000);resign(bad,size));
  /* Two individually valid segments share one 4 KiB leaf with RX versus RW. */
  memcpy(copy,PHASE3_BLOB_MAGIC,8);put16(copy+8,1);put16(copy+10,1);
  put32(copy+12,128);put64(copy+16,273);put64(copy+24,32);
  put64(copy+40,1);put32(copy+48,2);put32(copy+52,2);
  put64(copy+56,128);put64(copy+64,216);put64(copy+72,0);
  put64(copy+80,0);put64(copy+88,0);
  put64(copy+128,256);put64(copy+136,0);put64(copy+144,1);
  put64(copy+152,16);put64(copy+160,16);put32(copy+168,5);
  put64(copy+172,272);put64(copy+180,16);put64(copy+188,1);
  put64(copy+196,16);put64(copy+204,16);put32(copy+212,3);
  put32(copy+216,PHASE3_INIT_SYSCALL);put32(copy+224,PHASE3_SYSCALL_INIT);
  put32(copy+228,PHASE3_OPERATION_INIT);put32(copy+232,PHASE3_HELLO_SYSCALL);
  put32(copy+240,PHASE3_SYSCALL_DISPATCH);put32(copy+244,PHASE3_OPERATION_HELLO);
  copy[256]=0xc3;copy[272]=0;
  put32(copy+212,5);resign(copy,273);
  assert(phase3_blob_validate(copy,273,&v)==PHASE3_BLOB_OK&&v.header.image_size==32);
  put32(copy+212,3);resign(copy,273);
  assert(phase3_blob_validate(copy,273,&v)==PHASE3_BLOB_LEAF_CONFLICT);
  memcpy(&module.magic,"P3MODULE",8); module.generation=PHASE3_GENERATION;
  assert(!phase3_module_transition(&module,PHASE3_MODULE_EMPTY,PHASE3_MODULE_VALIDATED));
  assert(!phase3_module_transition(&module,PHASE3_MODULE_VALIDATED,PHASE3_MODULE_LOADED));
  assert(!phase3_module_transition(&module,PHASE3_MODULE_LOADED,PHASE3_MODULE_PREPARED));
  assert(phase3_module_transition(&module,PHASE3_MODULE_PREPARED,PHASE3_MODULE_ACTIVE));
  assert(registration_model(0,0,&state,&init_pub,&hello_pub,&init_calls)==-1);assert(!init_pub&&!hello_pub&&!init_calls);
  assert(registration_model(1,PHASE3_EINVAL,&state,&init_pub,&hello_pub,&init_calls)==PHASE3_EINVAL);assert(state==PHASE3_MODULE_FAILED&&!hello_pub&&init_calls==1);
  state=init_pub=hello_pub=init_calls=0;assert(!registration_model(1,0,&state,&init_pub,&hello_pub,&init_calls));
  assert(state==PHASE3_MODULE_ACTIVE&&!init_pub&&hello_pub&&init_calls==1);
  assert(init_calls==1); /* restored stock init entry makes a second call natural ENOSYS. */
  { unsigned attachment=1,inflight=0,quarantine=0,owner=1; if(owner&&!inflight)attachment=0;assert(!attachment&&!quarantine);owner=0;attachment=1;if(!owner)quarantine=1;assert(attachment&&quarantine); }
  printf("phase3-smoke: PASS parser=checked digest=sha256-canonical segments=readback-bss permissions=leaf-conflict-refused stock=natural-enosys registration=fail-closed init=one-shot active=gated rollback=owner-checked quarantine=pinned\n");
  free(copy);free(bad);free(image);free(blob);return 0;
}
