#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <stddef.h>
#include <sys/sysent.h>

_Static_assert(sizeof(struct sysent) == 0x30, "firmware sysent size");
_Static_assert(offsetof(struct sysent, sy_call) == 8, "firmware sy_call offset");
_Static_assert(offsetof(struct sysent, sy_thrcnt) == 44, "firmware sy_thrcnt offset");

#ifdef PHASE3_RELEASE
#define PHASE3_RUNTIME_EMBEDDED_RELEASE
#endif
#define main phase2_runtime_embedded_main
#include "phase2_runtime1060.c"
#undef main
#ifdef PHASE3_RELEASE
#undef PHASE3_RUNTIME_EMBEDDED_RELEASE
#endif

#include "phase3_module1060.h"
#include "util.h"


#define PHASE3_MODULE_OFFSET 0x600ULL
#define PHASE3_INIT_ROUTER_OFFSET 0x000ULL
#define PHASE3_HELLO_ROUTER_OFFSET 0x200ULL

static int p3phase(int client,const char *name,uint64_t a,uint64_t b){
#ifdef PHASE3_RELEASE
  /*
   * Release checkpoints are deliberately not remote gates.  Zero denotes
   * that no checkpoint transport was attempted, not receipt of an ACK; it
   * also leaves every subsequent local predicate in an || chain reachable.
   */
  (void)client;(void)name;(void)a;(void)b;return 0;
#else
  char line[240],ack;int n=snprintf(line,sizeof(line),"PHASE3_ACK %s a=%016llx b=%016llx\n",name,(unsigned long long)a,(unsigned long long)b);
  if(n<=0||send(client,line,(size_t)n,0)!=n)return -1;return recv(client,&ack,1,0)==1?0:-1;
#endif
}
static size_t build_leaf_write_handler(uint8_t out[TEMP_HANDLER_MAX],
                                       uint64_t leaf_address,
                                       uint64_t leaf_value){
  static const uint8_t mov_rcx[]={0x48,0xb9},mov_rax[]={0x48,0xb8};
  static const uint8_t store[]={0x48,0x89,0x01};
  static const uint8_t store_zero[]={0x48,0xc7,0x87};
  static const uint8_t done[]={0,0,0,0,0x31,0xc0,0xc3};
  uint32_t retval=g_fw1060_profile.thread_retval0_offset;size_t at=0;
  at=append(out,at,mov_rcx,sizeof(mov_rcx));at=append(out,at,&leaf_address,8);
  at=append(out,at,mov_rax,sizeof(mov_rax));at=append(out,at,&leaf_value,8);
  at=append(out,at,store,sizeof(store));at=append(out,at,store_zero,sizeof(store_zero));
  at=append(out,at,&retval,4);at=append(out,at,done,sizeof(done));return at;
}
static size_t build_leaf_table_write_handler(uint8_t out[TEMP_HANDLER_MAX],
                                             uint64_t journal_address,
                                             uint64_t count,int restore){
  static const uint8_t push_rbx[]={0x53},mov_rbx[]={0x48,0xbb},mov_rcx[]={0x48,0xb9};
  static const uint8_t load_address[]={0x48,0x8b,0x03};
  static const uint8_t load_original[]={0x48,0x8b,0x53,0x08};
  static const uint8_t load_final[]={0x48,0x8b,0x53,0x10};
  static const uint8_t store[]={0x48,0x89,0x10},advance[]={0x48,0x83,0xc3,0x18};
  static const uint8_t decrement[]={0x48,0xff,0xc9},store_zero[]={0x48,0xc7,0x87};
  static const uint8_t done[]={0,0,0,0,0x31,0xc0,0x5b,0xc3};
  uint32_t retval=g_fw1060_profile.thread_retval0_offset;size_t at=0,loop,branch;
  at=append(out,at,push_rbx,sizeof(push_rbx));at=append(out,at,mov_rbx,sizeof(mov_rbx));at=append(out,at,&journal_address,8);
  at=append(out,at,mov_rcx,sizeof(mov_rcx));at=append(out,at,&count,8);loop=at;
  at=append(out,at,load_address,sizeof(load_address));
  at=append(out,at,restore?load_original:load_final,sizeof(load_final));
  at=append(out,at,store,sizeof(store));at=append(out,at,advance,sizeof(advance));
  at=append(out,at,decrement,sizeof(decrement));out[at++]=0x75;branch=at++;
  out[branch]=(uint8_t)(loop-at);
  at=append(out,at,store_zero,sizeof(store_zero));at=append(out,at,&retval,4);
  at=append(out,at,done,sizeof(done));return at;
}
static int validate_phase3_journal(const phase2_prealloc_record_t *pre){
  phase3_code_journal_t header;phase3_code_page_entry_t first;uint8_t chunk[0x400];
  uint64_t hash=1469598103934665603ULL,code,state,pages;size_t journal_size;
  size_t checksum=offsetof(phase3_code_journal_t,checksum);
  if(!pre||pre->sizes[0]<=PHASE3_IMAGE_OFFSET||
     phase3_prealloc_layout(pre->sizes[0]-PHASE3_IMAGE_OFFSET,
                            &code,&state,&pages,&journal_size)||
     code!=pre->sizes[0]||state!=pre->sizes[1]||
     pre->journal_address!=pre->addresses[1]+PHASE3_JOURNAL_OFFSET||
     pre->code_page_count!=pages||
     kernel_copyout(pre->journal_address,&header,offsetof(phase3_code_journal_t,entries))||
     header.magic!=PHASE3_JOURNAL_MAGIC||header.count!=pages||
     header.checksum!=pre->journal_checksum)
    return -1;
  for(size_t off=0;off<journal_size;off+=sizeof(chunk)){
    size_t count=journal_size-off;if(count>sizeof(chunk))count=sizeof(chunk);
    if(kernel_copyout(pre->journal_address+off,chunk,count))return -1;
    for(size_t i=0;i<count;++i){
      size_t absolute=off+i;uint8_t byte=(absolute>=checksum&&absolute<checksum+8)?0:chunk[i];
      hash^=byte;hash*=1099511628211ULL;
    }
  }
  if(hash!=pre->journal_checksum||
     kernel_copyout(pre->journal_address+offsetof(phase3_code_journal_t,entries),
                    &first,sizeof(first))||
     first.leaf_address!=pre->code_leaf_address||
     first.original!=pre->code_leaf_original||
     first.final!=(pre->code_leaf_prepared&~FW1060_PAGE_WRITABLE))
    return -1;
  return 0;
}
static int verify_phase3_permissions(const phase2_router_global_t *g,
                                     uint64_t journal_address,uint64_t page_count,
                                     uint64_t pmap,int require_final){
  if((require_final&&verify_router_permissions(g,1,pmap))||
     (!pmap&&resolve_kernel_pmap(&pmap)))return -1;
  for(uint64_t i=0;i<page_count;++i){
    phase3_code_page_entry_t entry;uint64_t leaf=0,value=0;unsigned levels=0;
    uint64_t va=g->code_address+i*0x1000;
    uint64_t ea=journal_address+offsetof(phase3_code_journal_t,entries)+i*sizeof(entry);
    uint64_t expected;
    if(kernel_copyout(ea,&entry,sizeof(entry))||
       find_mapping_leaf(pmap,va,&leaf,&value,&levels)||levels!=4||
       leaf!=entry.leaf_address)
      return -1;
    expected=require_final?entry.final:entry.original;
    if(!runtime_exec1060_pte_invariant_equal(expected,value)||
       (require_final&&(value&(FW1060_PAGE_WRITABLE|FW1060_PAGE_NX|FW1060_PAGE_XOTEXT))))
      return -1;
  }
  return 0;
}
static int load_phase3_image(const phase3_blob_view_t *blob,uint64_t image){
  uint8_t verify[0x1000],zero[0x1000]={0};
  for(uint32_t i=0;i<blob->header.segment_count;++i){
    const blob_segment_v1 *s=&blob->segments[i];uint64_t at=0;
    while(at<s->file_size){
      size_t count=(size_t)(s->file_size-at);if(count>sizeof(verify))count=sizeof(verify);
      if(kernel_copyin(blob->bytes+s->file_offset+at,image+s->image_offset+at,count)||
         kernel_copyout(image+s->image_offset+at,verify,count)||
         memcmp(verify,blob->bytes+s->file_offset+at,count))return -1;
      at+=count;
    }
    while(at<s->memory_size){
      size_t count=(size_t)(s->memory_size-at);if(count>sizeof(zero))count=sizeof(zero);
      if(kernel_copyin(zero,image+s->image_offset+at,count)||
         kernel_copyout(image+s->image_offset+at,verify,count)||
         memcmp(verify,zero,count))return -1;
      at+=count;
    }
  }
  return 0;
}
static size_t build_visibility_handler(uint8_t out[TEMP_HANDLER_MAX]){
  static const uint8_t save[]={0x53,0x48,0x89,0xfb};
  static const uint8_t restore_rdi[]={0x48,0x89,0xdf},mov_rax[]={0x48,0xb8};
  static const uint8_t call_rax[]={0xff,0xd0},store_zero[]={0x48,0xc7,0x83};
  static const uint8_t done[]={0,0,0,0,0x31,0xc0,0x5b,0xc3};
  uint64_t tlb=KERNEL_ADDRESS_TEXT_BASE+g_fw1060_profile.all_core_guest_tlb_offset;
  uint64_t insn=KERNEL_ADDRESS_TEXT_BASE+g_fw1060_profile.all_core_instruction_offset;
  uint32_t retval=g_fw1060_profile.thread_retval0_offset;size_t at=0;
  at=append(out,at,save,sizeof(save));at=append(out,at,restore_rdi,sizeof(restore_rdi));
  at=append(out,at,mov_rax,sizeof(mov_rax));at=append(out,at,&tlb,8);
  at=append(out,at,call_rax,sizeof(call_rax));at=append(out,at,restore_rdi,sizeof(restore_rdi));
  at=append(out,at,mov_rax,sizeof(mov_rax));at=append(out,at,&insn,8);
  at=append(out,at,call_rax,sizeof(call_rax));at=append(out,at,store_zero,sizeof(store_zero));
  at=append(out,at,&retval,4);at=append(out,at,done,sizeof(done));return at;
}
static int write_module(uint64_t address,const phase3_module_state_t *m){
  phase3_module_state_t r;return kernel_copyin(m,address,sizeof(*m))||kernel_copyout(address,&r,sizeof(r))||memcmp(m,&r,sizeof(r));
}
static int write_route_entry(uint64_t table,unsigned number,
                             const uint8_t stock[sizeof(struct sysent)],
                             uint64_t handler,uint64_t *readback){
  uint8_t desired[sizeof(struct sysent)],observed[sizeof(struct sysent)];
  uint32_t thrcnt=SY_THR_STATIC;
  uint64_t slot=table+(uint64_t)number*g_fw1060_profile.sysent_size;
  memcpy(desired,stock,sizeof(desired));
  memcpy(desired+offsetof(struct sysent,sy_call),&handler,sizeof(handler));
  memcpy(desired+offsetof(struct sysent,sy_thrcnt),&thrcnt,sizeof(thrcnt));
  if(kernel_copyin(desired,slot,sizeof(desired))||
     kernel_copyout(slot,observed,sizeof(observed))||
     memcmp(desired,observed,sizeof(desired)))
    return -1;
  memcpy(readback,observed+offsetof(struct sysent,sy_call),sizeof(*readback));
  return *readback!=handler;
}
static int restore_stock_entry(uint64_t table,unsigned number,
                               const uint8_t stock[sizeof(struct sysent)]){
  uint8_t observed[sizeof(struct sysent)];
  uint64_t slot=table+(uint64_t)number*g_fw1060_profile.sysent_size;
  return kernel_copyin(stock,slot,sizeof(observed))||
         kernel_copyout(slot,observed,sizeof(observed))||
         memcmp(stock,observed,sizeof(observed));
}
static int verify_p3_clone(uint64_t ov,uint64_t ot,uint64_t cv,uint64_t ct,
                           int init_published,int hello_published,
                           uint64_t init_handler,uint64_t hello_handler){
  uint8_t oe[0x30],ce[0x30],ovec[0x200],cvec[0x200];
  if(g_fw1060_profile.sysent_size!=sizeof(oe)||
     g_fw1060_profile.sysentvec_size!=sizeof(ovec)||
     kernel_copyout(ov,ovec,sizeof(ovec))||
     kernel_copyout(cv,cvec,sizeof(cvec)))return -1;
  memcpy(ovec+g_fw1060_profile.sysentvec_table_offset,&ct,8);
  if(memcmp(ovec,cvec,sizeof(ovec)))return -1;
  for(unsigned i=0;i<g_fw1060_profile.syscall_count;++i){
    if(kernel_copyout(ot+(uint64_t)i*sizeof(oe),oe,sizeof(oe))||kernel_copyout(ct+(uint64_t)i*sizeof(ce),ce,sizeof(ce)))return -1;
    if(i==PHASE3_INIT_SYSCALL&&init_published){
      uint32_t thrcnt=SY_THR_STATIC;
      memcpy(oe+g_fw1060_profile.sy_call_offset,&init_handler,8);
      memcpy(oe+offsetof(struct sysent,sy_thrcnt),&thrcnt,sizeof(thrcnt));
    }
    if(i==PHASE3_HELLO_SYSCALL&&hello_published){
      uint32_t thrcnt=SY_THR_STATIC;
      memcpy(oe+g_fw1060_profile.sy_call_offset,&hello_handler,8);
      memcpy(oe+offsetof(struct sysent,sy_thrcnt),&thrcnt,sizeof(thrcnt));
    }
    if(memcmp(oe,ce,sizeof(oe)))return -1;
  }
  return 0;
}
static int p3_stock_preflight(int client){
  uint64_t proc=kernel_get_proc(getpid()),vector=0,table=0,count=0,init_handler=0;
  uint64_t hello_handler=0,reference_handler=0,init_words[6],hello_words[6],reference_words[6],result;
  uint8_t init_entry[0x30],hello_entry[0x30],reference_entry[0x30];unsigned char carry=0;
  if(!proc||
     kernel_copyout(proc+g_fw1060_profile.proc_p_sysent_offset,&vector,8)||
     !vector||
     kernel_copyout(vector,&count,8)||
     kernel_copyout(vector+g_fw1060_profile.sysentvec_table_offset,&table,8)||
     !table||
     kernel_copyout(table+(uint64_t)PHASE3_INIT_SYSCALL*
                    g_fw1060_profile.sysent_size,init_entry,sizeof(init_entry))||
     kernel_copyout(table+(uint64_t)PHASE3_HELLO_SYSCALL*
                    g_fw1060_profile.sysent_size,hello_entry,sizeof(hello_entry))||
     kernel_copyout(table+(uint64_t)PHASE3_NOSYS_REFERENCE*
                    g_fw1060_profile.sysent_size,reference_entry,sizeof(reference_entry)))
    return -1;
  memcpy(&init_handler,init_entry+g_fw1060_profile.sy_call_offset,8);
  memcpy(&hello_handler,hello_entry+g_fw1060_profile.sy_call_offset,8);
  memcpy(&reference_handler,reference_entry+g_fw1060_profile.sy_call_offset,8);
  memcpy(init_words,init_entry,sizeof(init_words));
  memcpy(hello_words,hello_entry,sizeof(hello_words));
  memcpy(reference_words,reference_entry,sizeof(reference_words));
  if(p3phase(client,"preflight-stock-owner",vector,table)||
     p3phase(client,"preflight-entry-contract",count,
             (memcmp(init_entry,reference_entry,sizeof(init_entry))!=0)|
             ((uint64_t)(memcmp(hello_entry,reference_entry,sizeof(hello_entry))!=0)<<1))||
     p3phase(client,"preflight-stock-reference",PHASE3_NOSYS_REFERENCE,reference_handler)||
     p3phase(client,"preflight-reference-entry-01",reference_words[0],reference_words[1])||
     p3phase(client,"preflight-reference-entry-23",reference_words[2],reference_words[3])||
     p3phase(client,"preflight-reference-entry-45",reference_words[4],reference_words[5])||
     p3phase(client,"preflight-stock-init",PHASE3_INIT_SYSCALL,init_handler)||
     p3phase(client,"preflight-init-entry-01",init_words[0],init_words[1])||
     p3phase(client,"preflight-init-entry-23",init_words[2],init_words[3])||
     p3phase(client,"preflight-init-entry-45",init_words[4],init_words[5])||
     p3phase(client,"preflight-stock-hello",PHASE3_HELLO_SYSCALL,hello_handler)||
     p3phase(client,"preflight-hello-entry-01",hello_words[0],hello_words[1])||
     p3phase(client,"preflight-hello-entry-23",hello_words[2],hello_words[3])||
     p3phase(client,"preflight-hello-entry-45",hello_words[4],hello_words[5])||
     vector!=KERNEL_ADDRESS_DATA_BASE+g_fw1060_profile.sysentvec_offset||
     table!=KERNEL_ADDRESS_DATA_BASE+g_fw1060_profile.sysent_offset||
     count!=g_fw1060_profile.syscall_count||
     g_fw1060_profile.sysent_size!=sizeof(init_entry)||
     memcmp(init_entry,reference_entry,sizeof(init_entry))||
     memcmp(hello_entry,reference_entry,sizeof(hello_entry))||
     phase3_allowlist_handlers_validate(init_handler,hello_handler,
                                        KERNEL_ADDRESS_TEXT_BASE,
                                        KERNEL_ADDRESS_DATA_BASE))
    return -1;
  result=raw_syscall(PHASE3_INIT_SYSCALL,PHASE3_OPERATION_INIT,&carry);
  if(p3phase(client,"preflight-init-stock-enosys",result,carry)||
     !carry||result!=PHASE3_ENOSYS)
    return -1;
  result=raw_syscall(PHASE3_HELLO_SYSCALL,PHASE3_OPERATION_HELLO,&carry);
  if(p3phase(client,"preflight-hello-stock-enosys",result,carry)||
     !carry||result!=PHASE3_ENOSYS)
    return -1;
  return 0;
}

static int p3_attach_and_run(int client,phase2_router_global_t *g,uint64_t ga,
                             phase3_module_state_t *m,uint64_t ma,
                             const phase3_blob_view_t *blob){
  phase2_attachment_t a;uint64_t proc=kernel_get_proc(getpid()),ov=0,ot=0,observed=0,rb=0;
  uint64_t cv=g->clone_address+ATTACH_VECTOR_OFFSET,ct=g->clone_address+ATTACH_TABLE_OFFSET;
  uint64_t stock_init=0,stock_hello=0,stock_reference=0,result,count=0,calls_before=g->calls,init_words[6],hello_words[6],reference_words[6];unsigned char carry=0;
  uint8_t entry_init[0x30],entry_hello[0x30],entry_reference[0x30];phase3_blob_view_t rejected,restored;
  int switched=0,committed=0,status=-1,invalid_result;
  if(!proc||kernel_copyout(proc+g_fw1060_profile.proc_p_sysent_offset,&ov,8)||!ov||
     kernel_copyout(ov,&count,8)||
     kernel_copyout(ov+g_fw1060_profile.sysentvec_table_offset,&ot,8)||!ot||
     kernel_copyout(ot+(uint64_t)PHASE3_INIT_SYSCALL*g_fw1060_profile.sysent_size,entry_init,sizeof(entry_init))||
     kernel_copyout(ot+(uint64_t)PHASE3_HELLO_SYSCALL*g_fw1060_profile.sysent_size,entry_hello,sizeof(entry_hello))||
     kernel_copyout(ot+(uint64_t)PHASE3_NOSYS_REFERENCE*g_fw1060_profile.sysent_size,entry_reference,sizeof(entry_reference)))goto out;
  memcpy(&stock_init,entry_init+g_fw1060_profile.sy_call_offset,8);memcpy(&stock_hello,entry_hello+g_fw1060_profile.sy_call_offset,8);memcpy(&stock_reference,entry_reference+g_fw1060_profile.sy_call_offset,8);
  memcpy(init_words,entry_init,sizeof(init_words));memcpy(hello_words,entry_hello,sizeof(hello_words));memcpy(reference_words,entry_reference,sizeof(reference_words));
  if(p3phase(client,"allowlist-stock-owner",ov,ot)||
     p3phase(client,"allowlist-entry-contract",count,
             (memcmp(entry_init,entry_reference,sizeof(entry_init))!=0)|
             ((uint64_t)(memcmp(entry_hello,entry_reference,sizeof(entry_hello))!=0)<<1))||
     p3phase(client,"allowlist-stock-reference",PHASE3_NOSYS_REFERENCE,stock_reference)||
     p3phase(client,"stock-reference-entry-01",reference_words[0],reference_words[1])||
     p3phase(client,"stock-reference-entry-23",reference_words[2],reference_words[3])||
     p3phase(client,"stock-reference-entry-45",reference_words[4],reference_words[5])||
     p3phase(client,"allowlist-stock-init",PHASE3_INIT_SYSCALL,stock_init)||
     p3phase(client,"stock-init-entry-01",init_words[0],init_words[1])||
     p3phase(client,"stock-init-entry-23",init_words[2],init_words[3])||
     p3phase(client,"stock-init-entry-45",init_words[4],init_words[5])||
     p3phase(client,"allowlist-stock-hello",PHASE3_HELLO_SYSCALL,stock_hello)||
     p3phase(client,"stock-hello-entry-01",hello_words[0],hello_words[1])||
     p3phase(client,"stock-hello-entry-23",hello_words[2],hello_words[3])||
     p3phase(client,"stock-hello-entry-45",hello_words[4],hello_words[5])||
     ov!=KERNEL_ADDRESS_DATA_BASE+g_fw1060_profile.sysentvec_offset||
     ot!=KERNEL_ADDRESS_DATA_BASE+g_fw1060_profile.sysent_offset||
     count!=g_fw1060_profile.syscall_count||
     g_fw1060_profile.sysent_size!=sizeof(entry_init)||
     memcmp(entry_init,entry_reference,sizeof(entry_init))||
     memcmp(entry_hello,entry_reference,sizeof(entry_hello))||
     phase3_allowlist_handlers_validate(stock_init,stock_hello,
                                        KERNEL_ADDRESS_TEXT_BASE,
                                        KERNEL_ADDRESS_DATA_BASE))goto out;
  result=raw_syscall(PHASE3_INIT_SYSCALL,PHASE3_OPERATION_INIT,&carry);
  if(p3phase(client,"pre-attach-init-stock-enosys",result,carry)||!carry||result!=PHASE3_ENOSYS)goto out;
  result=raw_syscall(PHASE3_HELLO_SYSCALL,PHASE3_OPERATION_HELLO,&carry);
  if(p3phase(client,"pre-attach-hello-stock-enosys",result,carry)||!carry||result!=PHASE3_ENOSYS)goto out;
  if(phase2_attach_begin(g,&a,proc,ov,ot,cv,ct)||copy_kernel_region(ct,ot,g_fw1060_profile.syscall_count*g_fw1060_profile.sysent_size)||
     copy_kernel_region(cv,ov,g_fw1060_profile.sysentvec_size)||kernel_copyin(&ct,cv+g_fw1060_profile.sysentvec_table_offset,8)||
     verify_p3_clone(ov,ot,cv,ct,0,0,0,0)||write_attachment(g->clone_address,&a)||phase2_attach_commit(g,&a)||write_attachment(g->clone_address,&a))goto out;
  committed=1;g->calls=calls_before;if(write_global(ga,g))goto out;
  m->attached_proc=proc;if(write_module(ma,m)||p3phase(client,"attachment-prepared",PHASE3_GENERATION,proc))goto out;
  if(kernel_copyout(proc+g_fw1060_profile.proc_p_sysent_offset,&observed,8)||observed!=ov||kernel_copyin(&cv,proc+g_fw1060_profile.proc_p_sysent_offset,8))goto out;
  switched=1;if(kernel_copyout(proc+g_fw1060_profile.proc_p_sysent_offset,&observed,8)||observed!=cv||p3phase(client,"attachment-live",cv,getpid()))goto out;
  result=raw_syscall(PHASE3_INIT_SYSCALL,PHASE3_OPERATION_INIT,&carry);if(p3phase(client,"clone-init-stock-enosys",result,carry)||!carry||result!=PHASE3_ENOSYS)goto out;
  result=raw_syscall(PHASE3_HELLO_SYSCALL,PHASE3_OPERATION_HELLO,&carry);if(p3phase(client,"clone-hello-stock-enosys",result,carry)||!carry||result!=PHASE3_ENOSYS)goto out;
  if(kernel_copyout(ga,g,sizeof(*g))||g->calls!=calls_before||g->inflight||kernel_copyout(ma,m,sizeof(*m))||m->init_calls||m->hello_calls||m->inflight||
     p3phase(client,"pre-registration-counters",g->calls,m->hello_calls))goto out;
  ((uint8_t *)blob->bytes)[blob->size-1]^=1;
  invalid_result=phase3_blob_validate(blob->bytes,blob->size,&rejected);
  ((uint8_t *)blob->bytes)[blob->size-1]^=1;
  if(invalid_result!=PHASE3_BLOB_DIGEST_ERROR||
     phase3_blob_validate(blob->bytes,blob->size,&restored)||
     memcmp(restored.header.digest,blob->header.digest,sizeof(blob->header.digest))||
     p3phase(client,"failed-registration-predicate",PHASE3_BLOB_DIGEST_ERROR,0))goto out;
  result=raw_syscall(PHASE3_INIT_SYSCALL,PHASE3_OPERATION_INIT,&carry);if(p3phase(client,"failed-init-stock-enosys",result,carry)||!carry||result!=PHASE3_ENOSYS)goto out;
  result=raw_syscall(PHASE3_HELLO_SYSCALL,PHASE3_OPERATION_HELLO,&carry);if(p3phase(client,"failed-hello-stock-enosys",result,carry)||!carry||result!=PHASE3_ENOSYS)goto out;
  m->state=PHASE3_MODULE_REGISTERED;if(write_module(ma,m)||write_route_entry(ct,PHASE3_INIT_SYSCALL,entry_init,g->cfi[0].thunk,&rb)||verify_p3_clone(ov,ot,cv,ct,1,0,g->cfi[0].thunk,0)||p3phase(client,"init-only-published",rb,m->state))goto out;
  result=raw_syscall(PHASE3_HELLO_SYSCALL,PHASE3_OPERATION_HELLO,&carry);if(p3phase(client,"pending-hello-stock-enosys",result,carry)||!carry||result!=PHASE3_ENOSYS)goto out;
  if(p3phase(client,"init-call-before",PHASE3_INIT_SYSCALL,PHASE3_OPERATION_INIT))goto out;
  result=raw_syscall(PHASE3_INIT_SYSCALL,PHASE3_OPERATION_INIT,&carry);
  if(kernel_copyout(ma,m,sizeof(*m))||
     p3phase(client,"init-call-result",result,carry)||
     p3phase(client,"init-call-state",((uint64_t)m->state<<32)|m->reserved,
             (m->init_calls<<32)|m->inflight)||
     carry||result||m->state!=PHASE3_MODULE_INITIALIZED||
     m->init_calls!=1||m->inflight)goto out;
  if(restore_stock_entry(ct,PHASE3_INIT_SYSCALL,entry_init)||write_route_entry(ct,PHASE3_HELLO_SYSCALL,entry_hello,g->cfi[1].thunk,&rb)||verify_p3_clone(ov,ot,cv,ct,0,1,0,g->cfi[1].thunk)||p3phase(client,"hello-route-pre-active",rb,m->state))goto out;
  m->state=PHASE3_MODULE_ACTIVE;if(write_module(ma,m)||p3phase(client,"ACTIVE-commit",m->generation,m->state))goto out;
  result=raw_syscall(PHASE3_INIT_SYSCALL,PHASE3_OPERATION_INIT,&carry);if(p3phase(client,"post-one-shot-init",result,carry)||!carry||result!=PHASE3_ENOSYS)goto out;
  if(p3phase(client,"hello-identity",m->generation,g->generation)||
     p3phase(client,"hello-call-before",((uint64_t)PHASE3_HELLO_SYSCALL<<32)|PHASE3_OPERATION_HELLO,(uint64_t)getpid()))goto out;
  result=raw_syscall(PHASE3_HELLO_SYSCALL,PHASE3_OPERATION_HELLO,&carry);
  if(kernel_copyout(ma,m,sizeof(*m))||
     p3phase(client,"hello-call-result",result,carry)||
     p3phase(client,"hello-call-state",((uint64_t)m->state<<32)|m->reserved,
             (m->hello_calls<<32)|m->inflight)||
     carry||result!=PHASE3_HELLO_RESULT||m->hello_calls!=1||
     m->init_calls!=1||m->inflight)goto out;
  notifyf("Phase 3 PIC blob says hello!\nvalue=0x%llx pid=%d",(unsigned long long)result,getpid());
  if(p3phase(client,"notification-displayed",result,getpid()))goto out;
  result=raw_syscall(SYS_getpid,0,&carry);if(carry||result!=(uint64_t)getpid()||p3phase(client,"preserved-stock-getpid",result,carry))goto out;
  status=0;
out:
  if(status&&switched&&!m->init_calls&&!m->hello_calls&&!m->inflight&&
     (m->state==PHASE3_MODULE_REGISTERED||
      m->state==PHASE3_MODULE_INITIALIZING||
      m->state==PHASE3_MODULE_FAILED)){
    if(restore_stock_entry(ct,PHASE3_INIT_SYSCALL,entry_init)||
       restore_stock_entry(ct,PHASE3_HELLO_SYSCALL,entry_hello)||
       verify_p3_clone(ov,ot,cv,ct,0,0,0,0)){
      m->quarantined=1;g->quarantined=1;status=-1;
    }else{
      m->state=PHASE3_MODULE_PREPARED;m->reserved=0;
      if(write_module(ma,m)){m->quarantined=1;g->quarantined=1;status=-1;}
      else p3phase(client,"registration-restored",m->state,m->init_calls);
    }
  }
  /*
   * A module that may have reached INITIALIZED or ACTIVE is never retried or
   * unloaded here.  Cleanup is limited to restoring this process's vector
   * and releasing its attachment when both inflight counters prove it safe.
   */
  if(switched){
    if(kernel_copyout(proc+g_fw1060_profile.proc_p_sysent_offset,&observed,8)||
       observed!=cv||
       kernel_copyin(&ov,proc+g_fw1060_profile.proc_p_sysent_offset,8)||
       kernel_copyout(proc+g_fw1060_profile.proc_p_sysent_offset,&observed,8)||
       observed!=ov){
      m->quarantined=1;g->quarantined=1;status=-1;
    }else{
      switched=0;
      p3phase(client,"attachment-vector-restored",observed,ov);
    }
  }
  if(committed&&!switched){
    if(m->inflight||g->inflight||
       phase2_attach_release(g,&a)||
       write_attachment(g->clone_address,&a)){
      m->quarantined=1;g->quarantined=1;status=-1;
    }else{
      committed=0;
    }
  }
  if(!switched&&!committed){
    m->attached_proc=0;
    if(write_module(ma,m)||write_global(ga,g)){
      m->quarantined=1;g->quarantined=1;status=-1;
    }else{
      p3phase(client,"attachment-restored",g->attachment_count,m->inflight);
    }
  }
  if(m->quarantined||g->quarantined){
    m->quarantined=1;g->quarantined=1;status=-1;
    g->state=PHASE2_ROUTER_QUARANTINED;
    write_global(ga,g);write_module(ma,m);
    p3phase(client,"QUARANTINED",g->generation,m->state);
  }
  return status;
}

static int p3_install(int client,uint64_t cave,const runtime_exec1060_page_t *page,
                      phase2_prealloc_record_t *pre,const uint8_t *flat,
                      size_t flat_size){
  phase2_router_global_t g,readback;phase2_locator_t locator;phase3_module_state_t m;phase3_blob_view_t blob;
  temporary_route_t route={.client=client,.cave=cave};uint8_t code[PHASE3_IMAGE_OFFSET],verify[PHASE3_IMAGE_OFFSET],handler[TEMP_HANDLER_MAX];
  uint64_t ma=pre->addresses[1]+PHASE3_MODULE_OFFSET,result,current=0,pmap=0,digest_words[4]={0},file_words[16],computed_words[4],expected_code,expected_state,expected_pages;unsigned char carry;size_t init_size,hello_size,handler_size,expected_journal;int installed=0,check,blob_status;
  memset(&g,0,sizeof(g));memset(&m,0,sizeof(m));memset(code,0,sizeof(code));
  memcpy(file_words,flat,sizeof(file_words));
  phase3_blob_digest(flat,flat_size,(uint8_t *)computed_words);
  if(p3phase(client,"blob-file-header-01",file_words[0],file_words[1])||
     p3phase(client,"blob-file-header-23",file_words[2],file_words[3])||
     p3phase(client,"blob-file-header-45",file_words[4],file_words[5])||
     p3phase(client,"blob-file-stored-digest-0",file_words[12],file_words[13])||
     p3phase(client,"blob-file-stored-digest-1",file_words[14],file_words[15])||
     p3phase(client,"blob-file-computed-digest-0",computed_words[0],computed_words[1])||
     p3phase(client,"blob-file-computed-digest-1",computed_words[2],computed_words[3]))
    return 40;
  blob_status=phase3_blob_validate(flat,flat_size,&blob);
  if(p3phase(client,"blob-validation-result",(uint64_t)(int64_t)blob_status,flat_size)||
     blob_status)return 40;
  memcpy(digest_words,blob.header.digest,sizeof(digest_words));
  if(p3phase(client,"blob-validated",flat_size,blob.header.image_size)||
     p3phase(client,"blob-digest-0",digest_words[0],digest_words[1])||
     p3phase(client,"blob-digest-1",digest_words[2],digest_words[3]))return 40;
  if(phase3_prealloc_layout(blob.header.image_size,&expected_code,
                            &expected_state,&expected_pages,&expected_journal)||
     expected_code!=pre->sizes[0]||expected_state!=pre->sizes[1]||
     expected_pages!=pre->code_page_count||
     expected_journal>expected_state-PHASE3_JOURNAL_OFFSET||
     PHASE3_BLOB_IMAGE_OFFSET!=PHASE3_IMAGE_OFFSET||
     validate_phase3_journal(pre)||
     p3phase(client,"image-journal-validated",pre->code_page_count,
             pre->journal_checksum))
    return 40;
  g.magic=PHASE2_GLOBAL_MAGIC;g.generation=PHASE2_GENERATION;g.code_address=pre->addresses[0];g.code_size=pre->sizes[0];g.state_address=pre->addresses[1];g.state_size=pre->sizes[1];g.clone_address=pre->addresses[2];g.clone_size=PHASE2_CLONE_SIZE;
  g.code_leaf_address=pre->code_leaf_address;g.code_leaf_original=pre->code_leaf_original;g.code_leaf_final=pre->code_leaf_prepared&~FW1060_PAGE_WRITABLE&~FW1060_PAGE_NX&~FW1060_PAGE_XOTEXT;g.data_leaf_address=pre->data_leaf_address;g.data_leaf_value=pre->data_leaf_value;
  memcpy(g.clone_leaf_address,pre->clone_leaf_address,sizeof(g.clone_leaf_address));memcpy(g.clone_leaf_value,pre->clone_leaf_value,sizeof(g.clone_leaf_value));g.owner_magic=PHASE2_OWNER_MAGIC;g.state=PHASE2_ROUTER_INSTALLING;
  for(unsigned i=0;i<FW1060_CFI_PAIR_COUNT;++i){const fw1060_cfi_pair_t *pair=&g_fw1060_profile.cfi_pairs[i];g.cfi[i].thunk=KERNEL_ADDRESS_TEXT_BASE+pair->thunk_offset;g.cfi[i].landing=KERNEL_ADDRESS_TEXT_BASE+pair->landing_offset;
    if(kernel_copyout(g.cfi[i].thunk,g.cfi[i].saved_thunk,sizeof(g.cfi[i].saved_thunk))||kernel_copyout(g.cfi[i].landing,g.cfi[i].saved_landing,sizeof(g.cfi[i].saved_landing))||fw1060_verify_cfi_pair(pair,g.cfi[i].saved_thunk,g.cfi[i].saved_landing))return 41;g.cfi[i].owned=1;}
  init_size=phase3_build_init_router(code+PHASE3_INIT_ROUTER_OFFSET,0x200,ma,g.cfi[2].thunk,PHASE2_TD_PROC_OFFSET,g_fw1060_profile.thread_retval0_offset);
  hello_size=phase3_build_hello_router(code+PHASE3_HELLO_ROUTER_OFFSET,0x200,ma,g.cfi[3].thunk,PHASE2_TD_PROC_OFFSET);
  if(!init_size||!hello_size||
     PHASE3_BLOB_IMAGE_OFFSET+blob.header.image_size>g.code_size)return 42;
  build_landing(g.cfi[0].installed_landing,g.cfi[0].saved_landing,g.code_address+PHASE3_INIT_ROUTER_OFFSET);build_landing(g.cfi[1].installed_landing,g.cfi[1].saved_landing,g.code_address+PHASE3_HELLO_ROUTER_OFFSET);
  build_landing(g.cfi[2].installed_landing,g.cfi[2].saved_landing,g.code_address+PHASE3_BLOB_IMAGE_OFFSET+blob.header.init_offset);build_landing(g.cfi[3].installed_landing,g.cfi[3].saved_landing,g.code_address+PHASE3_BLOB_IMAGE_OFFSET+blob.header.dispatch_offset);
  g.immutable_checksum=phase2_global_immutable_checksum(&g);
  m.magic=0x33454c55444f4d50ULL;m.generation=PHASE3_GENERATION;m.image_address=g.code_address+PHASE3_BLOB_IMAGE_OFFSET;m.blob_address=m.image_address;m.blob_file_size=flat_size;m.image_size=blob.header.image_size;m.code_leaf_address=g.code_leaf_address;m.code_leaf_original=g.code_leaf_original;m.code_leaf_final=g.code_leaf_final;m.init_address=m.image_address+blob.header.init_offset;m.dispatch_address=m.image_address+blob.header.dispatch_offset;memcpy(m.digest,blob.header.digest,32);
  m.context.abi_version=PHASE3_ABI_VERSION;m.context.size=sizeof(m.context);m.context.generation=m.generation;m.context.module_base=m.image_address;m.context.image_size=m.image_size;m.context.allowed_operations=1ULL<<PHASE3_OPERATION_HELLO;
  if(phase3_module_transition(&m,PHASE3_MODULE_EMPTY,PHASE3_MODULE_VALIDATED)||
     kernel_copyin(code,g.code_address,sizeof(code))||
     kernel_copyout(g.code_address,verify,sizeof(verify))||
     memcmp(code,verify,sizeof(code))||
     load_phase3_image(&blob,m.image_address)||
     phase3_module_transition(&m,PHASE3_MODULE_VALIDATED,PHASE3_MODULE_LOADED)||
     write_global(g.state_address,&g)||write_module(ma,&m)||
     p3phase(client,"segments-loaded-readback",m.image_address,m.image_size))return 43;
  if(p3phase(client,"segment-code-original",g.code_leaf_address,g.code_leaf_original)||
     p3phase(client,"segment-code-requested",g.code_leaf_address,g.code_leaf_final)||
     resolve_kernel_pmap(&pmap))
    return 44;
  handler_size=build_leaf_table_write_handler(handler,
      pre->journal_address+offsetof(phase3_code_journal_t,entries),
      pre->code_page_count,0);
  if(temporary_route_open(&route,page,handler,handler_size))return 45;
  if(p3phase(client,"permission-write-before",g.code_leaf_address,g.code_leaf_final))goto rollback;
  result=raw_syscall(TEMP_SYSCALL,0,&carry);
  if(kernel_copyout(g.code_leaf_address,&current,8)||
     p3phase(client,"permission-write-result",result,carry)||
     p3phase(client,"permission-write-leaf",g.code_leaf_address,current)||
     carry||result||!runtime_exec1060_pte_invariant_equal(current,g.code_leaf_final))
    goto rollback;
  memset(handler,0,sizeof(handler));handler_size=build_visibility_handler(handler);
  if(kernel_copyin(handler,route.target,handler_size)||
     kernel_copyout(route.target,verify,handler_size)||
     memcmp(handler,verify,handler_size)||
     p3phase(client,"visibility-handler-readback",route.target,handler_size)||
     p3phase(client,"permission-sync-before",
             g_fw1060_profile.all_core_guest_tlb_offset,
             g_fw1060_profile.all_core_instruction_offset))
    goto rollback;
  result=raw_syscall(TEMP_SYSCALL,0,&carry);
  if(p3phase(client,"permission-sync-result",result,carry)||carry||result)
    goto rollback;
  check=verify_phase3_permissions(&g,pre->journal_address,pre->code_page_count,pmap,1);
  if(kernel_copyout(g.code_leaf_address,&current,8)||check||
     phase3_module_transition(&m,PHASE3_MODULE_LOADED,PHASE3_MODULE_PREPARED)||
     write_module(ma,&m)||p3phase(client,"permission-after",current,check))
    goto rollback;
  for(unsigned i=0;i<FW1060_CFI_PAIR_COUNT;++i){uint8_t now[FW1060_LANDING_BYTES];if(kernel_copyout(g.cfi[i].landing,now,sizeof(now))||memcmp(now,g.cfi[i].saved_landing,sizeof(now))||p3phase(client,"cfi-install-before",i,g.cfi[i].landing)||kernel_copyin(g.cfi[i].installed_landing,g.cfi[i].landing,sizeof(now))||kernel_copyout(g.cfi[i].landing,now,sizeof(now))||memcmp(now,g.cfi[i].installed_landing,sizeof(now))||p3phase(client,"cfi-install-after",i,*(uint64_t*)now))goto rollback;++installed;}
  result=raw_syscall(TEMP_SYSCALL,0,&carry);if(carry||result||verify_cfi(&g,1)||p3phase(client,"cfi-all-core-visible",installed,result))goto rollback;
  if(temporary_route_close(&route))goto quarantine;g.state=PHASE2_ROUTER_LIVE;if(write_global(g.state_address,&g)||p3phase(client,"router-LIVE",g.generation,g.state))goto quarantine;
  locator.magic=PHASE2_LOCATOR_MAGIC;locator.generation=PHASE2_GENERATION;locator.global_address=g.state_address;locator.global_size=g.state_size;locator.checksum=phase2_locator_checksum(&locator);
  if(publish_locator(client,cave,&locator))goto quarantine;pre->state=PHASE2_PREALLOC_CONSUMED;pre->result_checksum=phase2_prealloc_result_checksum(pre);if(kernel_copyin(pre,cave+PHASE2_PREALLOC_OFFSET,sizeof(*pre)))goto quarantine;
  if(p3_attach_and_run(client,&g,g.state_address,&m,ma,&blob))return 46;
  if(kernel_copyout(g.state_address,&readback,sizeof(readback))||kernel_copyout(ma,&m,sizeof(m))||readback.attachment_count||readback.inflight||m.attached_proc||m.inflight||m.quarantined||p3phase(client,"retained-pinned",m.image_address,readback.clone_address))return 47;
  return 0;
rollback:
  while(installed){unsigned i=--installed;uint8_t now[FW1060_LANDING_BYTES];if(kernel_copyout(g.cfi[i].landing,now,sizeof(now))||memcmp(now,g.cfi[i].installed_landing,sizeof(now))||kernel_copyin(g.cfi[i].saved_landing,g.cfi[i].landing,sizeof(now)))route.quarantined=1;}
  if(!route.quarantined&&
     verify_phase3_permissions(&g,pre->journal_address,pre->code_page_count,pmap,1)==0){
    memset(handler,0,sizeof(handler));
    handler_size=build_leaf_table_write_handler(handler,
        pre->journal_address+offsetof(phase3_code_journal_t,entries),
        pre->code_page_count,1);
    if(kernel_copyin(handler,route.target,handler_size)){route.quarantined=1;}else{
      result=raw_syscall(TEMP_SYSCALL,0,&carry);
      if(carry||result){route.quarantined=1;}else{
        memset(handler,0,sizeof(handler));handler_size=build_visibility_handler(handler);
        if(kernel_copyin(handler,route.target,handler_size)){route.quarantined=1;}else{
          result=raw_syscall(TEMP_SYSCALL,0,&carry);
          if(carry||result||
             verify_phase3_permissions(&g,pre->journal_address,pre->code_page_count,pmap,0))
            route.quarantined=1;
        }
      }
    }
  }else route.quarantined=1;
  if(temporary_route_close(&route))route.quarantined=1;if(!route.quarantined)return 48;
quarantine:g.state=PHASE2_ROUTER_QUARANTINED;g.quarantined=1;m.quarantined=1;write_global(g.state_address,&g);write_module(ma,&m);p3phase(client,"QUARANTINED",g.generation,m.state);return 49;
}

static int p3_resume(int client,const phase2_locator_t *locator,
                     const uint8_t *flat,size_t flat_size){
  phase2_router_global_t g;phase3_module_state_t m;phase3_blob_view_t blob;
  uint64_t ma;
  if(phase2_locator_validate(locator)||
     kernel_copyout(locator->global_address,&g,sizeof(g))||
     phase2_global_validate(&g)||g.state!=PHASE2_ROUTER_LIVE||
     g.quarantined||g.attachment_count||g.inflight||
     verify_router_permissions(&g,1,0)||verify_cfi(&g,1))
    return 50;
  ma=g.state_address+PHASE3_MODULE_OFFSET;
  if(phase3_blob_validate(flat,flat_size,&blob)||
     kernel_copyout(ma,&m,sizeof(m))||
     m.magic!=0x33454c55444f4d50ULL||m.generation!=PHASE3_GENERATION||
     m.state!=PHASE3_MODULE_PREPARED||m.quarantined||m.attached_proc||
     m.inflight||m.init_calls||m.hello_calls||
     m.image_address!=g.code_address+PHASE3_BLOB_IMAGE_OFFSET||
     m.image_size!=blob.header.image_size||
     memcmp(m.digest,blob.header.digest,sizeof(m.digest))||
     p3phase(client,"resume-discovery",g.generation,m.generation))
    return 51;
  if(p3_attach_and_run(client,&g,locator->global_address,&m,ma,&blob))
    return 52;
  if(kernel_copyout(locator->global_address,&g,sizeof(g))||
     kernel_copyout(ma,&m,sizeof(m))||g.attachment_count||g.inflight||
     m.attached_proc||m.inflight||m.quarantined||
     p3phase(client,"resume-retained-pinned",m.image_address,g.clone_address))
    return 53;
  return 0;
}

int main(void){
#ifdef PHASE3_RELEASE
  int client=-1,status=1,blob_fd=-1;
#else
  int client=accept_client(),status=1,blob_fd=-1;
#endif
  uint64_t cave;runtime_exec1060_page_t page;phase2_prealloc_record_t pre;phase2_locator_t locator;phase2_router_global_t g;phase3_module_state_t m;char line[640];struct stat blob_stat;uint8_t *flat=MAP_FAILED;size_t flat_size=0;
#ifndef PHASE3_RELEASE
  if(client<0)return 1;
#endif
  memset(&page,0,sizeof(page));memset(&pre,0,sizeof(pre));memset(&locator,0,sizeof(locator));memset(&g,0,sizeof(g));memset(&m,0,sizeof(m));cave=kdlsym(KERNEL_SYM_DATA_CAVE);
  if(fw1060_identity_validate(kernel_get_fw_version(),sceKernelGetMainSocId(),FW1060_CPU_COUNT)||!cave||p3phase(client,"profile-preflight",g_fw1060_profile.firmware,((uint64_t)PHASE3_INIT_SYSCALL<<32)|PHASE3_HELLO_SYSCALL)){status=10;goto report;}
  if(p3_stock_preflight(client)){status=13;goto report;}
  blob_fd=open(PHASE3_BLOB_PATH,O_RDONLY);
  if(blob_fd<0||fstat(blob_fd,&blob_stat)||blob_stat.st_size<=0||
     (uintmax_t)blob_stat.st_size>SIZE_MAX){
    status=14;goto report;
  }
  flat_size=(size_t)blob_stat.st_size;
  flat=mmap(NULL,flat_size,PROT_READ|PROT_WRITE,MAP_PRIVATE,blob_fd,0);
  close(blob_fd);blob_fd=-1;
  if(flat==MAP_FAILED||p3phase(client,"blob-file-opened",flat_size,flat_size)){
    status=14;goto report;
  }
  if(kernel_copyout(cave+RUNTIME_EXEC1060_CAVE_OFFSET,&page,sizeof(page))||
     !runtime_exec1060_is_post_resume_verified(&page)||
     validate_mapping_contracts(client,&page)||
     kernel_copyout(cave+PHASE2_PREALLOC_OFFSET,&pre,sizeof(pre))||
     kernel_copyout(cave+PHASE2_LOCATOR_OFFSET,&locator,sizeof(locator))){
    status=11;goto report;
  }
  if(!memcmp(&locator,&(phase2_locator_t){0},sizeof(locator))){
    uint64_t mt=KERNEL_ADDRESS_TEXT_BASE+g_fw1060_profile.malloc_type_offset;
    uint32_t flags=g_fw1060_profile.malloc_nowait|g_fw1060_profile.malloc_zero;
    if(phase2_prealloc_validate(&pre,mt,flags)){status=12;goto report;}
    status=p3_install(client,cave,&page,&pre,flat,flat_size);
  }else{
    status=p3_resume(client,&locator,flat,flat_size);
  }
report:
  if(blob_fd>=0)close(blob_fd);
  if(flat!=MAP_FAILED)munmap(flat,flat_size);
  if(cave&&!kernel_copyout(cave+PHASE2_LOCATOR_OFFSET,&locator,sizeof(locator))&&!phase2_locator_validate(&locator)){kernel_copyout(locator.global_address,&g,sizeof(g));kernel_copyout(locator.global_address+PHASE3_MODULE_OFFSET,&m,sizeof(m));}
  snprintf(line,sizeof(line),"PHASE3_RESULT status=%d pid=%d generation=%016llx router_state=%u module_state=%u init_calls=%llu hello_calls=%llu attachments=%u router_inflight=%u module_inflight=%u quarantined=%u retained=%016llx locator=%016llx last=terminal\n",status,getpid(),(unsigned long long)m.generation,g.state,m.state,(unsigned long long)m.init_calls,(unsigned long long)m.hello_calls,g.attachment_count,g.inflight,m.inflight,g.quarantined||m.quarantined,(unsigned long long)m.image_address,(unsigned long long)locator.global_address);
#ifndef PHASE3_RELEASE
  send(client,line,strlen(line),0);close(client);
#else
  printf("%s",line);
#endif
  return status;
}
