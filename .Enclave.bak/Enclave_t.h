#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "sgx_trts.h"
#include "sgx_utils.h"
#include "sgx_tkey_exchange.h"
#include "config.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

sgx_status_t get_report(sgx_report_t* report, sgx_target_info_t* target_info);
size_t get_pse_manifest_size(void);
sgx_status_t get_pse_manifest(char* buf, size_t sz);
sgx_status_t enclave_ra_init(sgx_ec256_public_t key, int b_pse, sgx_ra_context_t* ctx, sgx_status_t* pse_status);
sgx_status_t enclave_ra_init_def(int b_pse, sgx_ra_context_t* ctx, sgx_status_t* pse_status);
sgx_status_t enclave_ra_get_key_hash(sgx_status_t* get_keys_status, sgx_ra_context_t ctx, sgx_ra_key_type_t type, sgx_sha256_hash_t* hash);
sgx_status_t enclave_ra_close(sgx_ra_context_t ctx);
sgx_status_t run_interpreter(sgx_ra_context_t context, unsigned char* code_cipher, size_t cipherlen, unsigned char* p_iv, unsigned char* tag, unsigned char* result_cipher, size_t* res_len);
sgx_status_t sgx_ra_get_ga(sgx_ra_context_t context, sgx_ec256_public_t* g_a);
sgx_status_t sgx_ra_proc_msg2_trusted(sgx_ra_context_t context, const sgx_ra_msg2_t* p_msg2, const sgx_target_info_t* p_qe_target, sgx_report_t* p_report, sgx_quote_nonce_t* p_nonce);
sgx_status_t sgx_ra_get_msg3_trusted(sgx_ra_context_t context, uint32_t quote_size, sgx_report_t* qe_report, sgx_ra_msg3_t* p_msg3, uint32_t msg3_size);

sgx_status_t SGX_CDECL OCALL_print(const char* message);
sgx_status_t SGX_CDECL OCALL_print_status(sgx_status_t st);
sgx_status_t SGX_CDECL OCALL_print_int(int num);
sgx_status_t SGX_CDECL OCALL_dump(uint8_t* char_to_dump, int bufsize);
sgx_status_t SGX_CDECL OCALL_generate_nonce(uint8_t* ivbuf, int bufsize);
sgx_status_t SGX_CDECL create_session_ocall(sgx_status_t* retval, uint32_t* sid, uint8_t* dh_msg1, uint32_t dh_msg1_size, uint32_t timeout);
sgx_status_t SGX_CDECL exchange_report_ocall(sgx_status_t* retval, uint32_t sid, uint8_t* dh_msg2, uint32_t dh_msg2_size, uint8_t* dh_msg3, uint32_t dh_msg3_size, uint32_t timeout);
sgx_status_t SGX_CDECL close_session_ocall(sgx_status_t* retval, uint32_t sid, uint32_t timeout);
sgx_status_t SGX_CDECL invoke_service_ocall(sgx_status_t* retval, uint8_t* pse_message_req, uint32_t pse_message_req_size, uint8_t* pse_message_resp, uint32_t pse_message_resp_size, uint32_t timeout);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
