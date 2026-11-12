#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "phase3_module1060.h"

typedef struct {
  uint32_t h[8];
  uint64_t bits;
  uint8_t block[64];
  size_t used;
} sha256_ctx;

static uint32_t rotr(uint32_t x, unsigned n) { return (x >> n) | (x << (32 - n)); }
static uint32_t be32(const uint8_t *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | p[3];
}
static uint16_t le16(const uint8_t *p) { return (uint16_t)p[0] | ((uint16_t)p[1] << 8); }
static uint32_t le32(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
         ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint64_t le64(const uint8_t *p) {
  return (uint64_t)le32(p) | ((uint64_t)le32(p + 4) << 32);
}
static int add_overflow_u64(uint64_t a, uint64_t b, uint64_t *out) {
  *out = a + b;
  return *out < a;
}
static int range_inside(uint64_t offset, uint64_t length, uint64_t total) {
  uint64_t end;
  return !add_overflow_u64(offset, length, &end) && end <= total;
}
static int ranges_overlap(uint64_t a, uint64_t an, uint64_t b, uint64_t bn) {
  uint64_t ae, be;
  if (add_overflow_u64(a, an, &ae) || add_overflow_u64(b, bn, &be))
    return 1;
  return a < be && b < ae;
}

static void sha_transform(sha256_ctx *c, const uint8_t block[64]) {
  static const uint32_t k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
  };
  uint32_t w[64], a, b, d, e, f, g, h, t1, t2;
  uint32_t cc;
  for (unsigned i = 0; i < 16; ++i) w[i] = be32(block + i * 4);
  for (unsigned i = 16; i < 64; ++i) {
    uint32_t s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15] >> 3);
    uint32_t s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2] >> 10);
    w[i] = w[i-16] + s0 + w[i-7] + s1;
  }
  a=c->h[0]; b=c->h[1]; cc=c->h[2]; d=c->h[3];
  e=c->h[4]; f=c->h[5]; g=c->h[6]; h=c->h[7];
  for (unsigned i = 0; i < 64; ++i) {
    uint32_t s1=rotr(e,6)^rotr(e,11)^rotr(e,25);
    uint32_t ch=(e&f)^((~e)&g);
    uint32_t s0=rotr(a,2)^rotr(a,13)^rotr(a,22);
    uint32_t maj=(a&b)^(a&cc)^(b&cc);
    t1=h+s1+ch+k[i]+w[i]; t2=s0+maj;
    h=g; g=f; f=e; e=d+t1; d=cc; cc=b; b=a; a=t1+t2;
  }
  c->h[0]+=a; c->h[1]+=b; c->h[2]+=cc; c->h[3]+=d;
  c->h[4]+=e; c->h[5]+=f; c->h[6]+=g; c->h[7]+=h;
}
static void sha_init(sha256_ctx *c) {
  static const uint32_t initial[8] = {
    0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
    0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
  };
  memcpy(c->h, initial, sizeof(initial)); c->bits=0; c->used=0;
}
static void sha_update(sha256_ctx *c, const void *data, size_t size) {
  const uint8_t *p = data;
  c->bits += (uint64_t)size * 8;
  while (size) {
    size_t n = 64 - c->used;
    if (n > size) n = size;
    memcpy(c->block + c->used, p, n); c->used += n; p += n; size -= n;
    if (c->used == 64) { sha_transform(c, c->block); c->used = 0; }
  }
}
static void sha_final(sha256_ctx *c, uint8_t out[32]) {
  uint64_t bits = c->bits;
  c->block[c->used++] = 0x80;
  if (c->used > 56) {
    memset(c->block + c->used, 0, 64 - c->used); sha_transform(c, c->block); c->used=0;
  }
  memset(c->block + c->used, 0, 56 - c->used);
  for (unsigned i=0;i<8;++i) c->block[63-i]=(uint8_t)(bits>>(i*8));
  sha_transform(c,c->block);
  for (unsigned i=0;i<8;++i) {
    out[i*4]=(uint8_t)(c->h[i]>>24); out[i*4+1]=(uint8_t)(c->h[i]>>16);
    out[i*4+2]=(uint8_t)(c->h[i]>>8); out[i*4+3]=(uint8_t)c->h[i];
  }
}
void phase3_sha256(const void *bytes, size_t size, uint8_t digest[32]) {
  sha256_ctx c; sha_init(&c); sha_update(&c, bytes, size); sha_final(&c, digest);
}
void phase3_blob_digest(const void *bytes, size_t size, uint8_t digest[32]) {
  const uint8_t zero[32] = {0};
  const uint8_t *p = bytes;
  sha256_ctx c; sha_init(&c);
  if (size <= offsetof(blob_header_v1, digest)) sha_update(&c, p, size);
  else {
    size_t before = offsetof(blob_header_v1, digest);
    size_t field = size - before < sizeof(zero) ? size - before : sizeof(zero);
    sha_update(&c, p, before); sha_update(&c, zero, field);
    if (size > before + field) sha_update(&c, p + before + field, size - before - field);
  }
  sha_final(&c, digest);
}

static void decode_header(blob_header_v1 *h, const uint8_t *p) {
  memcpy(h->magic,p,8); h->format_version=le16(p+8); h->abi_version=le16(p+10);
  h->header_size=le32(p+12); h->file_size=le64(p+16); h->image_size=le64(p+24);
  h->required_caps=le64(p+32); h->firmware_mask=le64(p+40);
  h->segment_count=le32(p+48); h->syscall_count=le32(p+52);
  h->segments_offset=le64(p+56); h->syscalls_offset=le64(p+64);
  h->init_offset=le64(p+72); h->fini_offset=le64(p+80); h->dispatch_offset=le64(p+88);
  memcpy(h->digest,p+96,32);
}
static void decode_segment(blob_segment_v1 *s, const uint8_t *p) {
  s->file_offset=le64(p); s->image_offset=le64(p+8); s->file_size=le64(p+16);
  s->memory_size=le64(p+24); s->alignment=le64(p+32); s->permissions=le32(p+40);
}
static void decode_syscall(blob_syscall_v1 *s, const uint8_t *p) {
  s->number=le32(p); s->narg=le16(p+4); s->arg_size=le16(p+6);
  s->flags=le32(p+8); s->operation_id=le32(p+12);
}
static int executable_offset(const phase3_blob_view_t *v, uint64_t offset) {
  for (uint32_t i=0;i<v->header.segment_count;++i) {
    const blob_segment_v1 *s=&v->segments[i]; uint64_t end;
    if ((s->permissions & PHASE3_SEG_X) && !add_overflow_u64(s->image_offset,s->memory_size,&end) &&
        offset>=s->image_offset && offset<end) return 1;
  }
  return 0;
}

int phase3_blob_validate(const void *bytes, size_t size, phase3_blob_view_t *v) {
  const uint8_t *p=bytes; uint8_t digest[32]; uint64_t segbytes, sysbytes, meta_end=0;
  if (!bytes || !v || size < sizeof(blob_header_v1)) return PHASE3_BLOB_TRUNCATED;
  memset(v,0,sizeof(*v)); v->bytes=p; v->size=size; decode_header(&v->header,p);
  if (memcmp(v->header.magic,PHASE3_BLOB_MAGIC,8)) return PHASE3_BLOB_MAGIC_ERROR;
  if (v->header.format_version!=PHASE3_FORMAT_VERSION || v->header.abi_version!=PHASE3_ABI_VERSION ||
      v->header.header_size!=sizeof(blob_header_v1)) return PHASE3_BLOB_VERSION_ERROR;
  if (v->header.file_size!=size || !v->header.image_size ||
      v->header.image_size>SIZE_MAX)
    return PHASE3_BLOB_SIZE_ERROR;
  if (v->header.required_caps || v->header.firmware_mask!=PHASE3_FIRMWARE_MASK_1060_REGULAR || v->header.fini_offset)
    return PHASE3_BLOB_CAP_ERROR;
  if (!v->header.segment_count || v->header.segment_count>PHASE3_BLOB_MAX_SEGMENTS ||
      v->header.syscall_count!=2 || v->header.syscall_count>PHASE3_BLOB_MAX_SYSCALLS)
    return PHASE3_BLOB_TABLE_ERROR;
  segbytes=(uint64_t)v->header.segment_count*sizeof(blob_segment_v1);
  sysbytes=(uint64_t)v->header.syscall_count*sizeof(blob_syscall_v1);
  if ((v->header.segments_offset&7) || (v->header.syscalls_offset&7) ||
      v->header.segments_offset < v->header.header_size ||
      v->header.syscalls_offset < v->header.header_size ||
      !range_inside(v->header.segments_offset,segbytes,size) ||
      !range_inside(v->header.syscalls_offset,sysbytes,size) ||
      ranges_overlap(v->header.segments_offset,segbytes,v->header.syscalls_offset,sysbytes))
    return PHASE3_BLOB_TABLE_ERROR;
  meta_end=v->header.segments_offset+segbytes;
  if (v->header.syscalls_offset+sysbytes>meta_end) meta_end=v->header.syscalls_offset+sysbytes;
  if (meta_end<sizeof(blob_header_v1)) meta_end=sizeof(blob_header_v1);
  for (uint32_t i=0;i<v->header.segment_count;++i)
    decode_segment(&v->segments[i],p+v->header.segments_offset+(uint64_t)i*sizeof(blob_segment_v1));
  for (uint32_t i=0;i<v->header.syscall_count;++i)
    decode_syscall(&v->syscalls[i],p+v->header.syscalls_offset+(uint64_t)i*sizeof(blob_syscall_v1));
  for (uint32_t i=0;i<v->header.segment_count;++i) {
    const blob_segment_v1 *s=&v->segments[i]; uint64_t file_end,image_end;
    if (!s->memory_size || s->file_size>s->memory_size || !s->alignment ||
        (s->alignment&(s->alignment-1)) || s->alignment<16 ||
        (s->file_offset&(s->alignment-1)) || (s->image_offset&(s->alignment-1)) ||
        s->file_offset<meta_end || !range_inside(s->file_offset,s->file_size,size) ||
        !range_inside(s->image_offset,s->memory_size,v->header.image_size) ||
        !(s->permissions&PHASE3_SEG_R) || (s->permissions&~(PHASE3_SEG_R|PHASE3_SEG_W|PHASE3_SEG_X)) ||
        ((s->permissions&PHASE3_SEG_W)&&(s->permissions&PHASE3_SEG_X)))
      return PHASE3_BLOB_SEGMENT_ERROR;
    file_end=s->file_offset+s->file_size; image_end=s->image_offset+s->memory_size;
    (void)file_end; (void)image_end;
    for (uint32_t j=0;j<i;++j) {
      const blob_segment_v1 *q=&v->segments[j];
      if (ranges_overlap(s->file_offset,s->file_size,q->file_offset,q->file_size) ||
          ranges_overlap(s->image_offset,s->memory_size,q->image_offset,q->memory_size))
        return PHASE3_BLOB_SEGMENT_ERROR;
      uint64_t sf=s->image_offset>>12, sl=(s->image_offset+s->memory_size-1)>>12;
      uint64_t qf=q->image_offset>>12, ql=(q->image_offset+q->memory_size-1)>>12;
      if (sf<=ql && qf<=sl && s->permissions!=q->permissions) return PHASE3_BLOB_LEAF_CONFLICT;
    }
  }
  if (!executable_offset(v,v->header.init_offset) || !executable_offset(v,v->header.dispatch_offset))
    return PHASE3_BLOB_ENTRY_ERROR;
  if (v->syscalls[0].number!=PHASE3_INIT_SYSCALL || v->syscalls[0].narg || v->syscalls[0].arg_size ||
      v->syscalls[0].flags!=PHASE3_SYSCALL_INIT || v->syscalls[0].operation_id!=PHASE3_OPERATION_INIT ||
      v->syscalls[1].number!=PHASE3_HELLO_SYSCALL || v->syscalls[1].narg || v->syscalls[1].arg_size ||
      v->syscalls[1].flags!=PHASE3_SYSCALL_DISPATCH || v->syscalls[1].operation_id!=PHASE3_OPERATION_HELLO)
    return PHASE3_BLOB_SYSCALL_ERROR;
  phase3_blob_digest(bytes,size,digest);
  if (memcmp(digest,v->header.digest,sizeof(digest))) return PHASE3_BLOB_DIGEST_ERROR;
  return PHASE3_BLOB_OK;
}

int phase3_blob_load(const phase3_blob_view_t *v, void *image, size_t capacity) {
  uint8_t *out=image;
  if (!v || !image || capacity<v->header.image_size) return -1;
  memset(out,0,(size_t)v->header.image_size);
  for (uint32_t i=0;i<v->header.segment_count;++i) {
    const blob_segment_v1 *s=&v->segments[i];
    memcpy(out+s->image_offset,v->bytes+s->file_offset,(size_t)s->file_size);
  }
  return 0;
}
int phase3_module_transition(phase3_module_state_t *m, uint32_t from, uint32_t to) {
  int allowed=(from==PHASE3_MODULE_EMPTY&&to==PHASE3_MODULE_VALIDATED) ||
      (from==PHASE3_MODULE_VALIDATED&&to==PHASE3_MODULE_LOADED) ||
      (from==PHASE3_MODULE_LOADED&&to==PHASE3_MODULE_PREPARED) ||
      (from==PHASE3_MODULE_PREPARED&&to==PHASE3_MODULE_REGISTERED) ||
      (from==PHASE3_MODULE_REGISTERED&&to==PHASE3_MODULE_INITIALIZING) ||
      (from==PHASE3_MODULE_INITIALIZING&&(to==PHASE3_MODULE_INITIALIZED||to==PHASE3_MODULE_FAILED)) ||
      (from==PHASE3_MODULE_INITIALIZED&&to==PHASE3_MODULE_ACTIVE);
  if (!m || m->state!=from || !allowed) return -1;
  m->state=to; return 0;
}

int phase3_allowlist_handlers_validate(uint64_t init_handler,
                                       uint64_t hello_handler,
                                       uint64_t kernel_text_base,
                                       uint64_t kernel_data_base) {
  if (!kernel_text_base || kernel_data_base <= kernel_text_base)
    return -1;
  if (init_handler < kernel_text_base || init_handler >= kernel_data_base ||
      hello_handler < kernel_text_base || hello_handler >= kernel_data_base)
    return -1;
  return 0;
}

static int machine_emit(uint8_t *out, size_t cap, size_t *at,
                        const void *p, size_t n) {
  if (*at > cap || n > cap - *at)
    return -1;
  memcpy(out + *at, p, n);
  *at += n;
  return 0;
}
static int machine_u32(uint8_t *o,size_t c,size_t *a,uint32_t v){return machine_emit(o,c,a,&v,4);}
static int machine_u64(uint8_t *o,size_t c,size_t *a,uint64_t v){return machine_emit(o,c,a,&v,8);}
static void patch_rel32(uint8_t *out,size_t field,size_t target){
  int32_t rel=(int32_t)(target-(field+4));memcpy(out+field,&rel,4);
}

size_t phase3_build_init_router(uint8_t *o,size_t cap,uint64_t ma,
                                uint64_t thunk,uint32_t proc_off,
                                uint32_t retval_off){
  size_t a=0,jstate,jgen,jproc,jop,jafter,jerror,fail_after,fail;
  uint64_t gen=PHASE3_GENERATION,ctx=ma+offsetof(phase3_module_state_t,context);
#define EMIT(...) do{static const uint8_t x[] = __VA_ARGS__;if(machine_emit(o,cap,&a,x,sizeof(x)))return 0;}while(0)
  EMIT({0x53,0x41,0x54,0x41,0x55});
  EMIT({0x48,0xbb});if(machine_u64(o,cap,&a,ma))return 0;
  EMIT({0xc7,0x83});if(machine_u32(o,cap,&a,offsetof(phase3_module_state_t,reserved))||
      machine_u32(o,cap,&a,1))return 0;
  EMIT({0x83,0xbb});if(machine_u32(o,cap,&a,offsetof(phase3_module_state_t,state)))return 0;
  EMIT({PHASE3_MODULE_REGISTERED,0x0f,0x85});jstate=a;if(machine_u32(o,cap,&a,0))return 0;
  EMIT({0xc7,0x83});if(machine_u32(o,cap,&a,offsetof(phase3_module_state_t,reserved))||
      machine_u32(o,cap,&a,2))return 0;
  EMIT({0x48,0xb8});if(machine_u64(o,cap,&a,gen))return 0;
  EMIT({0x48,0x39,0x83});if(machine_u32(o,cap,&a,offsetof(phase3_module_state_t,generation)))return 0;
  EMIT({0x0f,0x85});jgen=a;if(machine_u32(o,cap,&a,0))return 0;
  EMIT({0xc7,0x83});if(machine_u32(o,cap,&a,offsetof(phase3_module_state_t,reserved))||
      machine_u32(o,cap,&a,3))return 0;
  EMIT({0x49,0x89,0xfc,0x49,0x89,0xf5,0x48,0x8b,0x87});if(machine_u32(o,cap,&a,proc_off))return 0;
  EMIT({0x48,0x3b,0x83});if(machine_u32(o,cap,&a,offsetof(phase3_module_state_t,attached_proc)))return 0;
  EMIT({0x0f,0x85});jproc=a;if(machine_u32(o,cap,&a,0))return 0;
  EMIT({0xc7,0x83});if(machine_u32(o,cap,&a,offsetof(phase3_module_state_t,reserved))||
      machine_u32(o,cap,&a,4))return 0;
  EMIT({0x41,0x83,0x7d,0x00,PHASE3_OPERATION_INIT,0x0f,0x85});
  jop=a;if(machine_u32(o,cap,&a,0))return 0;
  EMIT({0xf0,0xff,0x83});if(machine_u32(o,cap,&a,offsetof(phase3_module_state_t,inflight)))return 0;
  EMIT({0x83,0xbb});if(machine_u32(o,cap,&a,offsetof(phase3_module_state_t,state)))return 0;
  EMIT({PHASE3_MODULE_REGISTERED,0x0f,0x85});jafter=a;if(machine_u32(o,cap,&a,0))return 0;
  EMIT({0xc7,0x83});if(machine_u32(o,cap,&a,offsetof(phase3_module_state_t,reserved))||
      machine_u32(o,cap,&a,5))return 0;
  EMIT({0xc7,0x83});if(machine_u32(o,cap,&a,offsetof(phase3_module_state_t,state))||
      machine_u32(o,cap,&a,PHASE3_MODULE_INITIALIZING))return 0;
  EMIT({0xc7,0x83});if(machine_u32(o,cap,&a,offsetof(phase3_module_state_t,reserved))||
      machine_u32(o,cap,&a,6))return 0;
  EMIT({0x48,0xbf});if(machine_u64(o,cap,&a,ctx))return 0;
  EMIT({0x31,0xf6,0x31,0xd2,0x48,0xb8});if(machine_u64(o,cap,&a,thunk))return 0;
  EMIT({0xff,0xd0,0x85,0xc0,0x0f,0x85});jerror=a;if(machine_u32(o,cap,&a,0))return 0;
  EMIT({0xc7,0x83});if(machine_u32(o,cap,&a,offsetof(phase3_module_state_t,reserved))||
      machine_u32(o,cap,&a,7))return 0;
  EMIT({0xf0,0x48,0xff,0x83});if(machine_u32(o,cap,&a,offsetof(phase3_module_state_t,init_calls)))return 0;
  EMIT({0xc7,0x83});if(machine_u32(o,cap,&a,offsetof(phase3_module_state_t,state))||
      machine_u32(o,cap,&a,PHASE3_MODULE_INITIALIZED))return 0;
  EMIT({0xc7,0x83});if(machine_u32(o,cap,&a,offsetof(phase3_module_state_t,reserved))||
      machine_u32(o,cap,&a,0))return 0;
  EMIT({0x49,0xc7,0x84,0x24});if(machine_u32(o,cap,&a,retval_off)||machine_u32(o,cap,&a,0))return 0;
  EMIT({0xf0,0xff,0x8b});if(machine_u32(o,cap,&a,offsetof(phase3_module_state_t,inflight)))return 0;
  EMIT({0x31,0xc0,0x41,0x5d,0x41,0x5c,0x5b,0xc3});
  {size_t t=a;patch_rel32(o,jerror,t);}
  EMIT({0xc7,0x83});if(machine_u32(o,cap,&a,offsetof(phase3_module_state_t,reserved))||
      machine_u32(o,cap,&a,8))return 0;
  EMIT({0xc7,0x83});if(machine_u32(o,cap,&a,offsetof(phase3_module_state_t,state))||
      machine_u32(o,cap,&a,PHASE3_MODULE_FAILED))return 0;
  EMIT({0xf0,0xff,0x8b});if(machine_u32(o,cap,&a,offsetof(phase3_module_state_t,inflight)))return 0;
  EMIT({0x41,0x5d,0x41,0x5c,0x5b,0xc3});
  fail_after=a;EMIT({0xf0,0xff,0x8b});if(machine_u32(o,cap,&a,offsetof(phase3_module_state_t,inflight)))return 0;
  fail=a;EMIT({0xb8,PHASE3_ENOSYS,0,0,0,0x41,0x5d,0x41,0x5c,0x5b,0xc3});
  patch_rel32(o,jstate,fail);patch_rel32(o,jgen,fail);patch_rel32(o,jproc,fail);
  patch_rel32(o,jop,fail);patch_rel32(o,jafter,fail_after);
#undef EMIT
  return a;
}

size_t phase3_build_hello_router(uint8_t *o,size_t cap,uint64_t ma,
                                 uint64_t thunk,uint32_t proc_off){
  size_t a=0,jstate,jgen,jproc,jop,jafter,jerrno,fail_after,fail;
  uint64_t gen=PHASE3_GENERATION,ctx=ma+offsetof(phase3_module_state_t,context);
#define EMIT(...) do{static const uint8_t x[] = __VA_ARGS__;if(machine_emit(o,cap,&a,x,sizeof(x)))return 0;}while(0)
  EMIT({0x53,0x41,0x54,0x41,0x55,0x48,0xbb});if(machine_u64(o,cap,&a,ma))return 0;
  EMIT({0x83,0xbb});if(machine_u32(o,cap,&a,offsetof(phase3_module_state_t,state)))return 0;
  EMIT({PHASE3_MODULE_ACTIVE,0x0f,0x85});jstate=a;if(machine_u32(o,cap,&a,0))return 0;
  EMIT({0x48,0xb8});if(machine_u64(o,cap,&a,gen))return 0;
  EMIT({0x48,0x39,0x83});if(machine_u32(o,cap,&a,offsetof(phase3_module_state_t,generation)))return 0;
  EMIT({0x0f,0x85});jgen=a;if(machine_u32(o,cap,&a,0))return 0;
  EMIT({0x49,0x89,0xfc,0x49,0x89,0xf5,0x48,0x8b,0x87});if(machine_u32(o,cap,&a,proc_off))return 0;
  EMIT({0x48,0x3b,0x83});if(machine_u32(o,cap,&a,offsetof(phase3_module_state_t,attached_proc)))return 0;
  EMIT({0x0f,0x85});jproc=a;if(machine_u32(o,cap,&a,0))return 0;
  EMIT({0x41,0x83,0x7d,0x00,PHASE3_OPERATION_HELLO,0x0f,0x85});
  jop=a;if(machine_u32(o,cap,&a,0))return 0;
  EMIT({0xf0,0xff,0x83});if(machine_u32(o,cap,&a,offsetof(phase3_module_state_t,inflight)))return 0;
  EMIT({0x83,0xbb});if(machine_u32(o,cap,&a,offsetof(phase3_module_state_t,state)))return 0;
  EMIT({PHASE3_MODULE_ACTIVE,0x0f,0x85});jafter=a;if(machine_u32(o,cap,&a,0))return 0;
  EMIT({0x48,0xbf});if(machine_u64(o,cap,&a,ctx))return 0;
  EMIT({0xbe,PHASE3_OPERATION_HELLO,0,0,0,0x4c,0x89,0xe2,0x4c,0x89,0xe9,0x48,0xb8});
  if(machine_u64(o,cap,&a,thunk))return 0;
  EMIT({0xff,0xd0,0x85,0xc0,0x0f,0x85});jerrno=a;if(machine_u32(o,cap,&a,0))return 0;
  EMIT({0xf0,0x48,0xff,0x83});if(machine_u32(o,cap,&a,offsetof(phase3_module_state_t,hello_calls)))return 0;
  {size_t t=a;patch_rel32(o,jerrno,t);}
  EMIT({0xf0,0xff,0x8b});if(machine_u32(o,cap,&a,offsetof(phase3_module_state_t,inflight)))return 0;
  EMIT({0x41,0x5d,0x41,0x5c,0x5b,0xc3});
  fail_after=a;EMIT({0xf0,0xff,0x8b});if(machine_u32(o,cap,&a,offsetof(phase3_module_state_t,inflight)))return 0;
  fail=a;EMIT({0xb8,PHASE3_ENOSYS,0,0,0,0x41,0x5d,0x41,0x5c,0x5b,0xc3});
  patch_rel32(o,jstate,fail);patch_rel32(o,jgen,fail);patch_rel32(o,jproc,fail);
  patch_rel32(o,jop,fail);patch_rel32(o,jafter,fail_after);
#undef EMIT
  return a;
}
