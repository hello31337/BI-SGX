#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


typedef struct ms_get_report_t {
	sgx_status_t ms_retval;
	sgx_report_t* ms_report;
	sgx_target_info_t* ms_target_info;
} ms_get_report_t;

typedef struct ms_get_pse_manifest_size_t {
	size_t ms_retval;
} ms_get_pse_manifest_size_t;

typedef struct ms_get_pse_manifest_t {
	sgx_status_t ms_retval;
	char* ms_buf;
	size_t ms_sz;
} ms_get_pse_manifest_t;

typedef struct ms_enclave_ra_init_t {
	sgx_status_t ms_retval;
	sgx_ec256_public_t ms_key;
	int ms_b_pse;
	sgx_ra_context_t* ms_ctx;
	sgx_status_t* ms_pse_status;
} ms_enclave_ra_init_t;

typedef struct ms_enclave_ra_init_def_t {
	sgx_status_t ms_retval;
	int ms_b_pse;
	sgx_ra_context_t* ms_ctx;
	sgx_status_t* ms_pse_status;
} ms_enclave_ra_init_def_t;

typedef struct ms_enclave_ra_get_key_hash_t {
	sgx_status_t ms_retval;
	sgx_status_t* ms_get_keys_status;
	sgx_ra_context_t ms_ctx;
	sgx_ra_key_type_t ms_type;
	sgx_sha256_hash_t* ms_hash;
} ms_enclave_ra_get_key_hash_t;

typedef struct ms_enclave_ra_close_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_ctx;
} ms_enclave_ra_close_t;

typedef struct ms_run_interpreter_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	unsigned char* ms_code_cipher;
	size_t ms_cipherlen;
	unsigned char* ms_p_iv;
	unsigned char* ms_tag;
	unsigned char* ms_result_cipher;
	size_t* ms_res_len;
} ms_run_interpreter_t;

typedef struct ms_sgx_ra_get_ga_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	sgx_ec256_public_t* ms_g_a;
} ms_sgx_ra_get_ga_t;

typedef struct ms_sgx_ra_proc_msg2_trusted_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	const sgx_ra_msg2_t* ms_p_msg2;
	const sgx_target_info_t* ms_p_qe_target;
	sgx_report_t* ms_p_report;
	sgx_quote_nonce_t* ms_p_nonce;
} ms_sgx_ra_proc_msg2_trusted_t;

typedef struct ms_sgx_ra_get_msg3_trusted_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	uint32_t ms_quote_size;
	sgx_report_t* ms_qe_report;
	sgx_ra_msg3_t* ms_p_msg3;
	uint32_t ms_msg3_size;
} ms_sgx_ra_get_msg3_trusted_t;

typedef struct ms_OCALL_print_t {
	const char* ms_message;
} ms_OCALL_print_t;

typedef struct ms_OCALL_print_status_t {
	sgx_status_t ms_st;
} ms_OCALL_print_status_t;

typedef struct ms_OCALL_print_int_t {
	int ms_num;
} ms_OCALL_print_int_t;

typedef struct ms_OCALL_dump_t {
	uint8_t* ms_char_to_dump;
	int ms_bufsize;
} ms_OCALL_dump_t;

typedef struct ms_OCALL_generate_nonce_t {
	uint8_t* ms_ivbuf;
	int ms_bufsize;
} ms_OCALL_generate_nonce_t;

typedef struct ms_create_session_ocall_t {
	sgx_status_t ms_retval;
	uint32_t* ms_sid;
	uint8_t* ms_dh_msg1;
	uint32_t ms_dh_msg1_size;
	uint32_t ms_timeout;
} ms_create_session_ocall_t;

typedef struct ms_exchange_report_ocall_t {
	sgx_status_t ms_retval;
	uint32_t ms_sid;
	uint8_t* ms_dh_msg2;
	uint32_t ms_dh_msg2_size;
	uint8_t* ms_dh_msg3;
	uint32_t ms_dh_msg3_size;
	uint32_t ms_timeout;
} ms_exchange_report_ocall_t;

typedef struct ms_close_session_ocall_t {
	sgx_status_t ms_retval;
	uint32_t ms_sid;
	uint32_t ms_timeout;
} ms_close_session_ocall_t;

typedef struct ms_invoke_service_ocall_t {
	sgx_status_t ms_retval;
	uint8_t* ms_pse_message_req;
	uint32_t ms_pse_message_req_size;
	uint8_t* ms_pse_message_resp;
	uint32_t ms_pse_message_resp_size;
	uint32_t ms_timeout;
} ms_invoke_service_ocall_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL sgx_get_report(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_get_report_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_get_report_t* ms = SGX_CAST(ms_get_report_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_report_t* _tmp_report = ms->ms_report;
	size_t _len_report = sizeof(sgx_report_t);
	sgx_report_t* _in_report = NULL;
	sgx_target_info_t* _tmp_target_info = ms->ms_target_info;
	size_t _len_target_info = sizeof(sgx_target_info_t);
	sgx_target_info_t* _in_target_info = NULL;

	CHECK_UNIQUE_POINTER(_tmp_report, _len_report);
	CHECK_UNIQUE_POINTER(_tmp_target_info, _len_target_info);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_report != NULL && _len_report != 0) {
		if ((_in_report = (sgx_report_t*)malloc(_len_report)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_report, 0, _len_report);
	}
	if (_tmp_target_info != NULL && _len_target_info != 0) {
		_in_target_info = (sgx_target_info_t*)malloc(_len_target_info);
		if (_in_target_info == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_target_info, _len_target_info, _tmp_target_info, _len_target_info)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = get_report(_in_report, _in_target_info);
err:
	if (_in_report) {
		if (memcpy_s(_tmp_report, _len_report, _in_report, _len_report)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_report);
	}
	if (_in_target_info) free(_in_target_info);

	return status;
}

static sgx_status_t SGX_CDECL sgx_get_pse_manifest_size(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_get_pse_manifest_size_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_get_pse_manifest_size_t* ms = SGX_CAST(ms_get_pse_manifest_size_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = get_pse_manifest_size();


	return status;
}

static sgx_status_t SGX_CDECL sgx_get_pse_manifest(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_get_pse_manifest_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_get_pse_manifest_t* ms = SGX_CAST(ms_get_pse_manifest_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_buf = ms->ms_buf;
	size_t _tmp_sz = ms->ms_sz;
	size_t _len_buf = _tmp_sz * sizeof(char);
	char* _in_buf = NULL;

	if (sizeof(*_tmp_buf) != 0 &&
		(size_t)_tmp_sz > (SIZE_MAX / sizeof(*_tmp_buf))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_buf, _len_buf);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_buf != NULL && _len_buf != 0) {
		if ((_in_buf = (char*)malloc(_len_buf)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_buf, 0, _len_buf);
	}

	ms->ms_retval = get_pse_manifest(_in_buf, _tmp_sz);
err:
	if (_in_buf) {
		if (memcpy_s(_tmp_buf, _len_buf, _in_buf, _len_buf)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_buf);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_enclave_ra_init(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclave_ra_init_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enclave_ra_init_t* ms = SGX_CAST(ms_enclave_ra_init_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_ra_context_t* _tmp_ctx = ms->ms_ctx;
	size_t _len_ctx = sizeof(sgx_ra_context_t);
	sgx_ra_context_t* _in_ctx = NULL;
	sgx_status_t* _tmp_pse_status = ms->ms_pse_status;
	size_t _len_pse_status = sizeof(sgx_status_t);
	sgx_status_t* _in_pse_status = NULL;

	CHECK_UNIQUE_POINTER(_tmp_ctx, _len_ctx);
	CHECK_UNIQUE_POINTER(_tmp_pse_status, _len_pse_status);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_ctx != NULL && _len_ctx != 0) {
		if ((_in_ctx = (sgx_ra_context_t*)malloc(_len_ctx)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_ctx, 0, _len_ctx);
	}
	if (_tmp_pse_status != NULL && _len_pse_status != 0) {
		if ((_in_pse_status = (sgx_status_t*)malloc(_len_pse_status)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_pse_status, 0, _len_pse_status);
	}

	ms->ms_retval = enclave_ra_init(ms->ms_key, ms->ms_b_pse, _in_ctx, _in_pse_status);
err:
	if (_in_ctx) {
		if (memcpy_s(_tmp_ctx, _len_ctx, _in_ctx, _len_ctx)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_ctx);
	}
	if (_in_pse_status) {
		if (memcpy_s(_tmp_pse_status, _len_pse_status, _in_pse_status, _len_pse_status)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_pse_status);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_enclave_ra_init_def(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclave_ra_init_def_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enclave_ra_init_def_t* ms = SGX_CAST(ms_enclave_ra_init_def_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_ra_context_t* _tmp_ctx = ms->ms_ctx;
	size_t _len_ctx = sizeof(sgx_ra_context_t);
	sgx_ra_context_t* _in_ctx = NULL;
	sgx_status_t* _tmp_pse_status = ms->ms_pse_status;
	size_t _len_pse_status = sizeof(sgx_status_t);
	sgx_status_t* _in_pse_status = NULL;

	CHECK_UNIQUE_POINTER(_tmp_ctx, _len_ctx);
	CHECK_UNIQUE_POINTER(_tmp_pse_status, _len_pse_status);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_ctx != NULL && _len_ctx != 0) {
		if ((_in_ctx = (sgx_ra_context_t*)malloc(_len_ctx)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_ctx, 0, _len_ctx);
	}
	if (_tmp_pse_status != NULL && _len_pse_status != 0) {
		if ((_in_pse_status = (sgx_status_t*)malloc(_len_pse_status)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_pse_status, 0, _len_pse_status);
	}

	ms->ms_retval = enclave_ra_init_def(ms->ms_b_pse, _in_ctx, _in_pse_status);
err:
	if (_in_ctx) {
		if (memcpy_s(_tmp_ctx, _len_ctx, _in_ctx, _len_ctx)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_ctx);
	}
	if (_in_pse_status) {
		if (memcpy_s(_tmp_pse_status, _len_pse_status, _in_pse_status, _len_pse_status)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_pse_status);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_enclave_ra_get_key_hash(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclave_ra_get_key_hash_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enclave_ra_get_key_hash_t* ms = SGX_CAST(ms_enclave_ra_get_key_hash_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_status_t* _tmp_get_keys_status = ms->ms_get_keys_status;
	size_t _len_get_keys_status = sizeof(sgx_status_t);
	sgx_status_t* _in_get_keys_status = NULL;
	sgx_sha256_hash_t* _tmp_hash = ms->ms_hash;
	size_t _len_hash = sizeof(sgx_sha256_hash_t);
	sgx_sha256_hash_t* _in_hash = NULL;

	CHECK_UNIQUE_POINTER(_tmp_get_keys_status, _len_get_keys_status);
	CHECK_UNIQUE_POINTER(_tmp_hash, _len_hash);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_get_keys_status != NULL && _len_get_keys_status != 0) {
		if ((_in_get_keys_status = (sgx_status_t*)malloc(_len_get_keys_status)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_get_keys_status, 0, _len_get_keys_status);
	}
	if (_tmp_hash != NULL && _len_hash != 0) {
		if ((_in_hash = (sgx_sha256_hash_t*)malloc(_len_hash)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_hash, 0, _len_hash);
	}

	ms->ms_retval = enclave_ra_get_key_hash(_in_get_keys_status, ms->ms_ctx, ms->ms_type, _in_hash);
err:
	if (_in_get_keys_status) {
		if (memcpy_s(_tmp_get_keys_status, _len_get_keys_status, _in_get_keys_status, _len_get_keys_status)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_get_keys_status);
	}
	if (_in_hash) {
		if (memcpy_s(_tmp_hash, _len_hash, _in_hash, _len_hash)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_hash);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_enclave_ra_close(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclave_ra_close_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enclave_ra_close_t* ms = SGX_CAST(ms_enclave_ra_close_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = enclave_ra_close(ms->ms_ctx);


	return status;
}

static sgx_status_t SGX_CDECL sgx_run_interpreter(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_run_interpreter_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_run_interpreter_t* ms = SGX_CAST(ms_run_interpreter_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_code_cipher = ms->ms_code_cipher;
	unsigned char* _tmp_p_iv = ms->ms_p_iv;
	size_t _len_p_iv = 12;
	unsigned char* _in_p_iv = NULL;
	unsigned char* _tmp_tag = ms->ms_tag;
	size_t _len_tag = 16;
	unsigned char* _in_tag = NULL;
	unsigned char* _tmp_result_cipher = ms->ms_result_cipher;
	size_t _len_result_cipher = 10000;
	unsigned char* _in_result_cipher = NULL;
	size_t* _tmp_res_len = ms->ms_res_len;
	size_t _len_res_len = sizeof(size_t);
	size_t* _in_res_len = NULL;

	CHECK_UNIQUE_POINTER(_tmp_p_iv, _len_p_iv);
	CHECK_UNIQUE_POINTER(_tmp_tag, _len_tag);
	CHECK_UNIQUE_POINTER(_tmp_result_cipher, _len_result_cipher);
	CHECK_UNIQUE_POINTER(_tmp_res_len, _len_res_len);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_p_iv != NULL && _len_p_iv != 0) {
		_in_p_iv = (unsigned char*)malloc(_len_p_iv);
		if (_in_p_iv == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_p_iv, _len_p_iv, _tmp_p_iv, _len_p_iv)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_tag != NULL && _len_tag != 0) {
		_in_tag = (unsigned char*)malloc(_len_tag);
		if (_in_tag == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_tag, _len_tag, _tmp_tag, _len_tag)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_result_cipher != NULL && _len_result_cipher != 0) {
		_in_result_cipher = (unsigned char*)malloc(_len_result_cipher);
		if (_in_result_cipher == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_result_cipher, _len_result_cipher, _tmp_result_cipher, _len_result_cipher)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_res_len != NULL && _len_res_len != 0) {
		if ((_in_res_len = (size_t*)malloc(_len_res_len)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_res_len, 0, _len_res_len);
	}

	ms->ms_retval = run_interpreter(ms->ms_context, _tmp_code_cipher, ms->ms_cipherlen, _in_p_iv, _in_tag, _in_result_cipher, _in_res_len);
err:
	if (_in_p_iv) {
		if (memcpy_s(_tmp_p_iv, _len_p_iv, _in_p_iv, _len_p_iv)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_p_iv);
	}
	if (_in_tag) {
		if (memcpy_s(_tmp_tag, _len_tag, _in_tag, _len_tag)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_tag);
	}
	if (_in_result_cipher) {
		if (memcpy_s(_tmp_result_cipher, _len_result_cipher, _in_result_cipher, _len_result_cipher)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_result_cipher);
	}
	if (_in_res_len) {
		if (memcpy_s(_tmp_res_len, _len_res_len, _in_res_len, _len_res_len)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_res_len);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_ra_get_ga(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sgx_ra_get_ga_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_sgx_ra_get_ga_t* ms = SGX_CAST(ms_sgx_ra_get_ga_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_ec256_public_t* _tmp_g_a = ms->ms_g_a;
	size_t _len_g_a = sizeof(sgx_ec256_public_t);
	sgx_ec256_public_t* _in_g_a = NULL;

	CHECK_UNIQUE_POINTER(_tmp_g_a, _len_g_a);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_g_a != NULL && _len_g_a != 0) {
		if ((_in_g_a = (sgx_ec256_public_t*)malloc(_len_g_a)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_g_a, 0, _len_g_a);
	}

	ms->ms_retval = sgx_ra_get_ga(ms->ms_context, _in_g_a);
err:
	if (_in_g_a) {
		if (memcpy_s(_tmp_g_a, _len_g_a, _in_g_a, _len_g_a)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_g_a);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_ra_proc_msg2_trusted(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sgx_ra_proc_msg2_trusted_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_sgx_ra_proc_msg2_trusted_t* ms = SGX_CAST(ms_sgx_ra_proc_msg2_trusted_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const sgx_ra_msg2_t* _tmp_p_msg2 = ms->ms_p_msg2;
	size_t _len_p_msg2 = sizeof(sgx_ra_msg2_t);
	sgx_ra_msg2_t* _in_p_msg2 = NULL;
	const sgx_target_info_t* _tmp_p_qe_target = ms->ms_p_qe_target;
	size_t _len_p_qe_target = sizeof(sgx_target_info_t);
	sgx_target_info_t* _in_p_qe_target = NULL;
	sgx_report_t* _tmp_p_report = ms->ms_p_report;
	size_t _len_p_report = sizeof(sgx_report_t);
	sgx_report_t* _in_p_report = NULL;
	sgx_quote_nonce_t* _tmp_p_nonce = ms->ms_p_nonce;
	size_t _len_p_nonce = sizeof(sgx_quote_nonce_t);
	sgx_quote_nonce_t* _in_p_nonce = NULL;

	CHECK_UNIQUE_POINTER(_tmp_p_msg2, _len_p_msg2);
	CHECK_UNIQUE_POINTER(_tmp_p_qe_target, _len_p_qe_target);
	CHECK_UNIQUE_POINTER(_tmp_p_report, _len_p_report);
	CHECK_UNIQUE_POINTER(_tmp_p_nonce, _len_p_nonce);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_p_msg2 != NULL && _len_p_msg2 != 0) {
		_in_p_msg2 = (sgx_ra_msg2_t*)malloc(_len_p_msg2);
		if (_in_p_msg2 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s((void*)_in_p_msg2, _len_p_msg2, _tmp_p_msg2, _len_p_msg2)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_p_qe_target != NULL && _len_p_qe_target != 0) {
		_in_p_qe_target = (sgx_target_info_t*)malloc(_len_p_qe_target);
		if (_in_p_qe_target == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s((void*)_in_p_qe_target, _len_p_qe_target, _tmp_p_qe_target, _len_p_qe_target)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_p_report != NULL && _len_p_report != 0) {
		if ((_in_p_report = (sgx_report_t*)malloc(_len_p_report)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_report, 0, _len_p_report);
	}
	if (_tmp_p_nonce != NULL && _len_p_nonce != 0) {
		if ((_in_p_nonce = (sgx_quote_nonce_t*)malloc(_len_p_nonce)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_nonce, 0, _len_p_nonce);
	}

	ms->ms_retval = sgx_ra_proc_msg2_trusted(ms->ms_context, (const sgx_ra_msg2_t*)_in_p_msg2, (const sgx_target_info_t*)_in_p_qe_target, _in_p_report, _in_p_nonce);
err:
	if (_in_p_msg2) free((void*)_in_p_msg2);
	if (_in_p_qe_target) free((void*)_in_p_qe_target);
	if (_in_p_report) {
		if (memcpy_s(_tmp_p_report, _len_p_report, _in_p_report, _len_p_report)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_p_report);
	}
	if (_in_p_nonce) {
		if (memcpy_s(_tmp_p_nonce, _len_p_nonce, _in_p_nonce, _len_p_nonce)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_p_nonce);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_sgx_ra_get_msg3_trusted(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sgx_ra_get_msg3_trusted_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_sgx_ra_get_msg3_trusted_t* ms = SGX_CAST(ms_sgx_ra_get_msg3_trusted_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_report_t* _tmp_qe_report = ms->ms_qe_report;
	size_t _len_qe_report = sizeof(sgx_report_t);
	sgx_report_t* _in_qe_report = NULL;
	sgx_ra_msg3_t* _tmp_p_msg3 = ms->ms_p_msg3;

	CHECK_UNIQUE_POINTER(_tmp_qe_report, _len_qe_report);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_qe_report != NULL && _len_qe_report != 0) {
		_in_qe_report = (sgx_report_t*)malloc(_len_qe_report);
		if (_in_qe_report == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_qe_report, _len_qe_report, _tmp_qe_report, _len_qe_report)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = sgx_ra_get_msg3_trusted(ms->ms_context, ms->ms_quote_size, _in_qe_report, _tmp_p_msg3, ms->ms_msg3_size);
err:
	if (_in_qe_report) free(_in_qe_report);

	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[11];
} g_ecall_table = {
	11,
	{
		{(void*)(uintptr_t)sgx_get_report, 0},
		{(void*)(uintptr_t)sgx_get_pse_manifest_size, 0},
		{(void*)(uintptr_t)sgx_get_pse_manifest, 0},
		{(void*)(uintptr_t)sgx_enclave_ra_init, 0},
		{(void*)(uintptr_t)sgx_enclave_ra_init_def, 0},
		{(void*)(uintptr_t)sgx_enclave_ra_get_key_hash, 0},
		{(void*)(uintptr_t)sgx_enclave_ra_close, 0},
		{(void*)(uintptr_t)sgx_run_interpreter, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_get_ga, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_proc_msg2_trusted, 0},
		{(void*)(uintptr_t)sgx_sgx_ra_get_msg3_trusted, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[14][11];
} g_dyn_entry_table = {
	14,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL OCALL_print(const char* message)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_message = message ? strlen(message) + 1 : 0;

	ms_OCALL_print_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_OCALL_print_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(message, _len_message);

	ocalloc_size += (message != NULL) ? _len_message : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_OCALL_print_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_OCALL_print_t));
	ocalloc_size -= sizeof(ms_OCALL_print_t);

	if (message != NULL) {
		ms->ms_message = (const char*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, message, _len_message)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_message);
		ocalloc_size -= _len_message;
	} else {
		ms->ms_message = NULL;
	}
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL OCALL_print_status(sgx_status_t st)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_OCALL_print_status_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_OCALL_print_status_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_OCALL_print_status_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_OCALL_print_status_t));
	ocalloc_size -= sizeof(ms_OCALL_print_status_t);

	ms->ms_st = st;
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL OCALL_print_int(int num)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_OCALL_print_int_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_OCALL_print_int_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_OCALL_print_int_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_OCALL_print_int_t));
	ocalloc_size -= sizeof(ms_OCALL_print_int_t);

	ms->ms_num = num;
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL OCALL_dump(uint8_t* char_to_dump, int bufsize)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_char_to_dump = bufsize;

	ms_OCALL_dump_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_OCALL_dump_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(char_to_dump, _len_char_to_dump);

	ocalloc_size += (char_to_dump != NULL) ? _len_char_to_dump : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_OCALL_dump_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_OCALL_dump_t));
	ocalloc_size -= sizeof(ms_OCALL_dump_t);

	if (char_to_dump != NULL) {
		ms->ms_char_to_dump = (uint8_t*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, char_to_dump, _len_char_to_dump)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_char_to_dump);
		ocalloc_size -= _len_char_to_dump;
	} else {
		ms->ms_char_to_dump = NULL;
	}
	
	ms->ms_bufsize = bufsize;
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL OCALL_generate_nonce(uint8_t* ivbuf, int bufsize)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_ivbuf = bufsize;

	ms_OCALL_generate_nonce_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_OCALL_generate_nonce_t);
	void *__tmp = NULL;

	void *__tmp_ivbuf = NULL;

	CHECK_ENCLAVE_POINTER(ivbuf, _len_ivbuf);

	ocalloc_size += (ivbuf != NULL) ? _len_ivbuf : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_OCALL_generate_nonce_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_OCALL_generate_nonce_t));
	ocalloc_size -= sizeof(ms_OCALL_generate_nonce_t);

	if (ivbuf != NULL) {
		ms->ms_ivbuf = (uint8_t*)__tmp;
		__tmp_ivbuf = __tmp;
		if (memcpy_s(__tmp_ivbuf, ocalloc_size, ivbuf, _len_ivbuf)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_ivbuf);
		ocalloc_size -= _len_ivbuf;
	} else {
		ms->ms_ivbuf = NULL;
	}
	
	ms->ms_bufsize = bufsize;
	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (ivbuf) {
			if (memcpy_s((void*)ivbuf, _len_ivbuf, __tmp_ivbuf, _len_ivbuf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL create_session_ocall(sgx_status_t* retval, uint32_t* sid, uint8_t* dh_msg1, uint32_t dh_msg1_size, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_sid = sizeof(uint32_t);
	size_t _len_dh_msg1 = dh_msg1_size;

	ms_create_session_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_create_session_ocall_t);
	void *__tmp = NULL;

	void *__tmp_sid = NULL;
	void *__tmp_dh_msg1 = NULL;

	CHECK_ENCLAVE_POINTER(sid, _len_sid);
	CHECK_ENCLAVE_POINTER(dh_msg1, _len_dh_msg1);

	ocalloc_size += (sid != NULL) ? _len_sid : 0;
	ocalloc_size += (dh_msg1 != NULL) ? _len_dh_msg1 : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_create_session_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_create_session_ocall_t));
	ocalloc_size -= sizeof(ms_create_session_ocall_t);

	if (sid != NULL) {
		ms->ms_sid = (uint32_t*)__tmp;
		__tmp_sid = __tmp;
		memset(__tmp_sid, 0, _len_sid);
		__tmp = (void *)((size_t)__tmp + _len_sid);
		ocalloc_size -= _len_sid;
	} else {
		ms->ms_sid = NULL;
	}
	
	if (dh_msg1 != NULL) {
		ms->ms_dh_msg1 = (uint8_t*)__tmp;
		__tmp_dh_msg1 = __tmp;
		memset(__tmp_dh_msg1, 0, _len_dh_msg1);
		__tmp = (void *)((size_t)__tmp + _len_dh_msg1);
		ocalloc_size -= _len_dh_msg1;
	} else {
		ms->ms_dh_msg1 = NULL;
	}
	
	ms->ms_dh_msg1_size = dh_msg1_size;
	ms->ms_timeout = timeout;
	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (sid) {
			if (memcpy_s((void*)sid, _len_sid, __tmp_sid, _len_sid)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (dh_msg1) {
			if (memcpy_s((void*)dh_msg1, _len_dh_msg1, __tmp_dh_msg1, _len_dh_msg1)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL exchange_report_ocall(sgx_status_t* retval, uint32_t sid, uint8_t* dh_msg2, uint32_t dh_msg2_size, uint8_t* dh_msg3, uint32_t dh_msg3_size, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_dh_msg2 = dh_msg2_size;
	size_t _len_dh_msg3 = dh_msg3_size;

	ms_exchange_report_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_exchange_report_ocall_t);
	void *__tmp = NULL;

	void *__tmp_dh_msg3 = NULL;

	CHECK_ENCLAVE_POINTER(dh_msg2, _len_dh_msg2);
	CHECK_ENCLAVE_POINTER(dh_msg3, _len_dh_msg3);

	ocalloc_size += (dh_msg2 != NULL) ? _len_dh_msg2 : 0;
	ocalloc_size += (dh_msg3 != NULL) ? _len_dh_msg3 : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_exchange_report_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_exchange_report_ocall_t));
	ocalloc_size -= sizeof(ms_exchange_report_ocall_t);

	ms->ms_sid = sid;
	if (dh_msg2 != NULL) {
		ms->ms_dh_msg2 = (uint8_t*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, dh_msg2, _len_dh_msg2)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_dh_msg2);
		ocalloc_size -= _len_dh_msg2;
	} else {
		ms->ms_dh_msg2 = NULL;
	}
	
	ms->ms_dh_msg2_size = dh_msg2_size;
	if (dh_msg3 != NULL) {
		ms->ms_dh_msg3 = (uint8_t*)__tmp;
		__tmp_dh_msg3 = __tmp;
		memset(__tmp_dh_msg3, 0, _len_dh_msg3);
		__tmp = (void *)((size_t)__tmp + _len_dh_msg3);
		ocalloc_size -= _len_dh_msg3;
	} else {
		ms->ms_dh_msg3 = NULL;
	}
	
	ms->ms_dh_msg3_size = dh_msg3_size;
	ms->ms_timeout = timeout;
	status = sgx_ocall(6, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (dh_msg3) {
			if (memcpy_s((void*)dh_msg3, _len_dh_msg3, __tmp_dh_msg3, _len_dh_msg3)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL close_session_ocall(sgx_status_t* retval, uint32_t sid, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_close_session_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_close_session_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_close_session_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_close_session_ocall_t));
	ocalloc_size -= sizeof(ms_close_session_ocall_t);

	ms->ms_sid = sid;
	ms->ms_timeout = timeout;
	status = sgx_ocall(7, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL invoke_service_ocall(sgx_status_t* retval, uint8_t* pse_message_req, uint32_t pse_message_req_size, uint8_t* pse_message_resp, uint32_t pse_message_resp_size, uint32_t timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pse_message_req = pse_message_req_size;
	size_t _len_pse_message_resp = pse_message_resp_size;

	ms_invoke_service_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_invoke_service_ocall_t);
	void *__tmp = NULL;

	void *__tmp_pse_message_resp = NULL;

	CHECK_ENCLAVE_POINTER(pse_message_req, _len_pse_message_req);
	CHECK_ENCLAVE_POINTER(pse_message_resp, _len_pse_message_resp);

	ocalloc_size += (pse_message_req != NULL) ? _len_pse_message_req : 0;
	ocalloc_size += (pse_message_resp != NULL) ? _len_pse_message_resp : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_invoke_service_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_invoke_service_ocall_t));
	ocalloc_size -= sizeof(ms_invoke_service_ocall_t);

	if (pse_message_req != NULL) {
		ms->ms_pse_message_req = (uint8_t*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, pse_message_req, _len_pse_message_req)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_pse_message_req);
		ocalloc_size -= _len_pse_message_req;
	} else {
		ms->ms_pse_message_req = NULL;
	}
	
	ms->ms_pse_message_req_size = pse_message_req_size;
	if (pse_message_resp != NULL) {
		ms->ms_pse_message_resp = (uint8_t*)__tmp;
		__tmp_pse_message_resp = __tmp;
		memset(__tmp_pse_message_resp, 0, _len_pse_message_resp);
		__tmp = (void *)((size_t)__tmp + _len_pse_message_resp);
		ocalloc_size -= _len_pse_message_resp;
	} else {
		ms->ms_pse_message_resp = NULL;
	}
	
	ms->ms_pse_message_resp_size = pse_message_resp_size;
	ms->ms_timeout = timeout;
	status = sgx_ocall(8, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (pse_message_resp) {
			if (memcpy_s((void*)pse_message_resp, _len_pse_message_resp, __tmp_pse_message_resp, _len_pse_message_resp)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(int);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	void *__tmp_cpuinfo = NULL;

	CHECK_ENCLAVE_POINTER(cpuinfo, _len_cpuinfo);

	ocalloc_size += (cpuinfo != NULL) ? _len_cpuinfo : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));
	ocalloc_size -= sizeof(ms_sgx_oc_cpuidex_t);

	if (cpuinfo != NULL) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp_cpuinfo = __tmp;
		memset(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		ocalloc_size -= _len_cpuinfo;
	} else {
		ms->ms_cpuinfo = NULL;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(9, ms);

	if (status == SGX_SUCCESS) {
		if (cpuinfo) {
			if (memcpy_s((void*)cpuinfo, _len_cpuinfo, __tmp_cpuinfo, _len_cpuinfo)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);

	ms->ms_self = self;
	status = sgx_ocall(10, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);

	ms->ms_waiter = waiter;
	status = sgx_ocall(11, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);

	ms->ms_waiter = waiter;
	ms->ms_self = self;
	status = sgx_ocall(12, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(void*);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(waiters, _len_waiters);

	ocalloc_size += (waiters != NULL) ? _len_waiters : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);

	if (waiters != NULL) {
		ms->ms_waiters = (const void**)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, waiters, _len_waiters)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		ocalloc_size -= _len_waiters;
	} else {
		ms->ms_waiters = NULL;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(13, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

