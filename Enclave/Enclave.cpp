/*

Copyright 2018 Intel Corporation

This software and the related documents are Intel copyrighted materials,
and your use of them is governed by the express license under which they
were provided to you (License). Unless the License provides otherwise,
you may not use, modify, copy, publish, distribute, disclose or transmit
this software or the related documents without Intel's prior written
permission.

This software and the related documents are provided as is, with no
express or implied warranties, other than those that are expressly stated
in the License.

*/

#ifndef _WIN32
#include "../config.h"
#endif
#include "Enclave_t.h"
#include <string.h>
#include <cstdlib>
#include <sgx_utils.h>
#ifdef _WIN32
#include <sgx_tae_service.h>
#endif
#include <sgx_tkey_exchange.h>
#include <sgx_tcrypto.h>
#include <sgx_tseal.h>
#include <sgx_trts.h>

#include "BISGX.h"

extern std::string BISGX_main(std::string code,
			bool *error_flag, std::string *error_msg);

namespace Blex
{
	extern void BufferInit(std::string code);
	extern void nextLine();
}

namespace Bparse
{
	extern void convert_to_internalCode(std::string code);
}

static const sgx_ec256_public_t def_service_public_key = {
    {
        0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf,
        0x85, 0xd0, 0x3a, 0x62, 0x37, 0x30, 0xae, 0xad,
        0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60, 0x73, 0x1d,
        0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b, 0xeb, 0x38
    },
    {
        0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b,
        0x26, 0xee, 0xb7, 0x41, 0xe7, 0xc6, 0x14, 0xe2,
        0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2, 0x9a, 0x28,
        0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14, 0x5e, 0x06
    }

};

#define PSE_RETRIES	5	/* Arbitrary. Not too long, not too short. */

/*----------------------------------------------------------------------
 * WARNING
 *----------------------------------------------------------------------
 *
 * End developers should not normally be calling these functions
 * directly when doing remote attestation:
 *
 *    sgx_get_ps_sec_prop()
 *    sgx_get_quote()
 *    sgx_get_quote_size()
 *    sgx_get_report()
 *    sgx_init_quote()
 *
 * These functions short-circuits the RA process in order
 * to generate an enclave quote directly!
 *
 * The high-level functions provided for remote attestation take
 * care of the low-level details of quote generation for you:
 *
 *   sgx_ra_init()
 *   sgx_ra_get_msg1
 *   sgx_ra_proc_msg2
 *
 *----------------------------------------------------------------------
 */

/*
 * This doesn't really need to be a C++ source file, but a bug in 
 * 2.1.3 and earlier implementations of the SGX SDK left a stray
 * C++ symbol in libsgx_tkey_exchange.so so it won't link without
 * a C++ compiler. Just making the source C++ was the easiest way
 * to deal with that.
 */

sgx_status_t get_report(sgx_report_t *report, sgx_target_info_t *target_info)
{
#ifdef SGX_HW_SIM
	return sgx_create_report(NULL, NULL, report);
#else
	return sgx_create_report(target_info, NULL, report);
#endif
}

/*
size_t get_pse_manifest_size ()
{
	return sizeof(sgx_ps_sec_prop_desc_t);
}
*/

/*
sgx_status_t get_pse_manifest(char *buf, size_t sz)
{
	sgx_ps_sec_prop_desc_t ps_sec_prop_desc;
	sgx_status_t status= SGX_ERROR_SERVICE_UNAVAILABLE;
	int retries= PSE_RETRIES;

	do {
		status= sgx_create_pse_session();
		if ( status != SGX_SUCCESS ) return status;
	} while (status == SGX_ERROR_BUSY && retries--);
	if ( status != SGX_SUCCESS ) return status;

	status= sgx_get_ps_sec_prop(&ps_sec_prop_desc);
	if ( status != SGX_SUCCESS ) return status;

	memcpy(buf, &ps_sec_prop_desc, sizeof(ps_sec_prop_desc));

	sgx_close_pse_session();

	return status;
}
*/

sgx_status_t enclave_ra_init(sgx_ec256_public_t key, int b_pse,
	sgx_ra_context_t *ctx, sgx_status_t *pse_status)
{
	sgx_status_t ra_status;

	/*
	 * If we want platform services, we must create a PSE session 
	 * before calling sgx_ra_init()
	 */

	/*
	if ( b_pse ) {
		int retries= PSE_RETRIES;
		do {
			*pse_status= sgx_create_pse_session();
			if ( *pse_status != SGX_SUCCESS ) return SGX_ERROR_UNEXPECTED;
		} while (*pse_status == SGX_ERROR_BUSY && retries--);
		if ( *pse_status != SGX_SUCCESS ) return SGX_ERROR_UNEXPECTED;
	}
	*/

	ra_status= sgx_ra_init(&key, b_pse, ctx);

	/*
	if ( b_pse ) {
		int retries= PSE_RETRIES;
		do {
			*pse_status= sgx_create_pse_session();
			if ( *pse_status != SGX_SUCCESS ) return SGX_ERROR_UNEXPECTED;
		} while (*pse_status == SGX_ERROR_BUSY && retries--);
		if ( *pse_status != SGX_SUCCESS ) return SGX_ERROR_UNEXPECTED;
	}
	*/

	return ra_status;
}

sgx_status_t enclave_ra_init_def(int b_pse, sgx_ra_context_t *ctx,
	sgx_status_t *pse_status)
{
	return enclave_ra_init(def_service_public_key, b_pse, ctx, pse_status);
}

/*
 * Return a SHA256 hash of the requested key. KEYS SHOULD NEVER BE
 * SENT OUTSIDE THE ENCLAVE IN PLAIN TEXT. This function let's us
 * get proof of possession of the key without exposing it to untrusted
 * memory.
 */

sgx_status_t enclave_ra_get_key_hash(sgx_status_t *get_keys_ret,
	sgx_ra_context_t ctx, sgx_ra_key_type_t type, sgx_sha256_hash_t *hash)
{
	sgx_status_t sha_ret;
	sgx_ra_key_128_t k;

	// First get the requested key which is one of:
	//  * SGX_RA_KEY_MK 
	//  * SGX_RA_KEY_SK
	// per sgx_ra_get_keys().

	*get_keys_ret= sgx_ra_get_keys(ctx, type, &k);
	if ( *get_keys_ret != SGX_SUCCESS ) return *get_keys_ret;

	/* Now generate a SHA hash */

	sha_ret= sgx_sha256_msg((const uint8_t *) &k, sizeof(k), 
		(sgx_sha256_hash_t *) hash); // Sigh.

	/* Let's be thorough */

	memset(k, 0, sizeof(k));

	return sha_ret;
}

sgx_status_t enclave_ra_close(sgx_ra_context_t ctx)
{
        sgx_status_t ret;
        ret = sgx_ra_close(ctx);
        return ret;
}

size_t do_sealing(uint8_t *data_plain, uint8_t *sealed_data)
{
	size_t sealed_data_size;
	sgx_status_t status;
	
	//int data_length = strlen(reinterpret_cast<char*>(data_to_seal));
	int data_length = strlen((char*)data_plain);

	sealed_data_size = sgx_calc_sealed_data_size(0, data_length);
	
	OCALL_print("estimated sealed_data_size is: ");
	OCALL_print_int(sealed_data_size);

	status = sgx_seal_data(0, NULL, data_length, data_plain,
		sealed_data_size, (sgx_sealed_data_t*)sealed_data);

	if(status != SGX_SUCCESS)
	{
		OCALL_print_status(status);
	}
	else
	{
		/*
		OCALL_print("Sealed secret successfully. Sealed Info: \n=====");
		OCALL_print_int(sealed_data_size);
		OCALL_dump(sealed_data, sealed_data_size);
		OCALL_print("=====\nSealed Info End\n");
		*/
	}

	return sealed_data_size;
}

void sealing_test(int mode)
{
	size_t sealed_data_size;
	sgx_status_t status;

	uint8_t *teststr = reinterpret_cast<uint8_t*>(const_cast<char*>("test string\n"));
	int data_length = strlen((char*)teststr);

	sealed_data_size = sgx_calc_sealed_data_size(0, data_length);

	uint8_t *sealed_data = new uint8_t[sealed_data_size];

	status = sgx_seal_data(0, NULL, data_length, teststr, sealed_data_size,
		(sgx_sealed_data_t*)sealed_data);

	/*
	OCALL_print("\nsealing test");
	OCALL_dump(sealed_data, sealed_data_size);
	*/
	
	
	uint32_t decrypt_buf_length;

	decrypt_buf_length = sgx_get_encrypt_txt_len((sgx_sealed_data_t*)sealed_data);
	uint8_t *decrypt_buf = new uint8_t[decrypt_buf_length];

	//OCALL_print_int(decrypt_buf_length);

	if(mode == 0)
	{
		sealing_test(1);
	}

	status = sgx_unseal_data((sgx_sealed_data_t*)sealed_data, NULL, 0, 
		decrypt_buf, &decrypt_buf_length);

	if(status != SGX_SUCCESS)
	{
		OCALL_print_status(status);
	}
	else
	{
		/*
		OCALL_print("Unsealed secret successfully.\nUnsealed data is: ");
		OCALL_print(reinterpret_cast<char*>(decrypt_buf));
		*/
	}


	status = sgx_unseal_data((sgx_sealed_data_t*)sealed_data, NULL, 0, 
		decrypt_buf, &decrypt_buf_length);
}

void unsealing_test(uint8_t *sealed_data)
{
	sgx_status_t status;
	uint32_t decrypt_buf_length;

	decrypt_buf_length = sgx_get_encrypt_txt_len((sgx_sealed_data_t*)sealed_data);
	uint8_t *decrypt_buf = new uint8_t[decrypt_buf_length];

	//OCALL_print_int(decrypt_buf_length);

	status = sgx_unseal_data((sgx_sealed_data_t*)sealed_data, NULL, 0, 
		decrypt_buf, &decrypt_buf_length);

	if(status != SGX_SUCCESS)
	{
		OCALL_print_status(status);
	}
	else
	{
		//OCALL_print("Unsealed secret successfully.\n");
	}
}

sgx_status_t process_login_info(sgx_ra_context_t context, uint8_t* login_info_cipher,
	size_t cipherlen, uint8_t* p_iv, uint8_t* tag, uint8_t *res_cipher, size_t *res_len,
	uint8_t *username, uint8_t *password_hash, uint8_t *privilege, uint8_t *datatype,
	uint8_t *misc_info)
{
	sgx_status_t status = SGX_SUCCESS;
	sgx_ec_key_128bit_t sk_key, mk_key;
	
	/*Get session key SK to decrypt secret*/
	status = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);

	if(status != SGX_SUCCESS)
	{
		const char* message = "Error while obtaining session key.";
		OCALL_print(message);
		OCALL_print_status(status);
		return status;
	}
	
	uint32_t p_iv_len = 12;
	uint8_t login_info[128] = {'\0'};
	
	sgx_aes_gcm_128bit_tag_t tag_t;
	uint8_t *iv_t = new uint8_t[p_iv_len];

	for(int i = 0; i < 16; i++)
	{
		tag_t[i] = tag[i];
	}

	for(int i = 0; i < p_iv_len; i++)
	{
		iv_t[i] = p_iv[i];
	}


	status = sgx_rijndael128GCM_decrypt(&sk_key, (uint8_t *)login_info_cipher,
		cipherlen, login_info, iv_t, p_iv_len, NULL, 0, &tag_t);


	if(status != SGX_SUCCESS)
	{
		const char* message = "Error while decrypting SP's secret.";
		OCALL_print(message);
		OCALL_print_status(status);
		return status;
	}


	uint8_t password[32] = {'\0'};
	int read_count = 0, pass_rc = 0, type_rc = 0;

	/* username */
	char *token_head = strtok((char*)login_info, "\n");
	size_t token_sz = strlen(token_head);

	for(int i = 0; i < token_sz; i++)
	{
		username[i] = token_head[i];
	}

	/* password */
	token_head = strtok(NULL, "\n");
	token_sz = strlen(token_head);

	for(int i = 0; i < token_sz; i++)
	{
		password[i] = token_head[i];
	}

	/* privilege */
	token_head = strtok(NULL, "\n");
	token_sz = strlen(token_head);

	privilege[0] = token_head[0];

	

	if(privilege[0] == 'O')
	{
		/* datatype */
		token_head = strtok(NULL, "\n");
		token_sz = strlen(token_head);

		for(int i = 0; i < token_sz; i++)
		{
			datatype[i] = token_head[i];
		}

		std::string dtp_str = std::string((char*)datatype);

		if(dtp_str == "download")
		{
			token_head = strtok(NULL, "\n");
			token_sz = strlen(token_head);

			OCALL_print_int(strlen(token_head));

			for(int i = 0; i < token_sz; i++)
			{
				misc_info[i] = token_head[i];
			}

		}
	}


	/*
	while(1)
	{
		if(login_info[read_count] == '\n')
		{
			read_count++;
			break;
		}

		username[read_count] = login_info[read_count];
		read_count++;
	}

	while(1)
	{
		if(login_info[read_count] == '\n')
		{
			read_count++;
			break;
		}

		password[pass_rc] = login_info[read_count];
		read_count++;
		pass_rc++;
	}

	privilege[0] = login_info[read_count];
	
	if(privilege[0] == 'O')
	{
		read_count += 2;

		while(1)
		{
			if(login_info[read_count] == '\0')
			{
				break;
			}

			datatype[type_rc] = login_info[read_count];
			read_count++;
			type_rc++;
		}
	}
	*/

	sgx_status_t hashst = 
		sgx_sha256_msg(password, strlen((char*)password), 
		(sgx_sha256_hash_t*)password_hash);

	return status;
}

sgx_status_t seal_data(sgx_ra_context_t context, uint8_t *data_cipher,
	size_t cipherlen, uint8_t *p_iv, uint8_t *tag, uint8_t *sealed_data, 
	size_t est_seal_len, size_t *res_len)
{
	sgx_status_t status = SGX_SUCCESS;
	sgx_ec_key_128bit_t sk_key, mk_key;
	
	/*Get session key SK to decrypt secret*/
	status = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);

	if(status != SGX_SUCCESS)
	{
		const char* message = "Error while obtaining session key.";
		OCALL_print(message);
		OCALL_print_status(status);
		return status;
	}
	
	uint32_t p_iv_len = 12;
	
	sgx_aes_gcm_128bit_tag_t tag_t;

	for(int i = 0; i < 16; i++)
	{
		tag_t[i] = tag[i];
	}


	//uint8_t data_plain[400000] = {'\0'};
	uint8_t *data_plain = new uint8_t[cipherlen + 1]();


	status = sgx_rijndael128GCM_decrypt(&sk_key, (uint8_t *)data_cipher, cipherlen,
		data_plain, p_iv, p_iv_len, NULL, 0, &tag_t);


	if(status != SGX_SUCCESS)
	{
		const char* message = "Error while decrypting SP's secret.";
		OCALL_print(message);
		OCALL_print_status(status);
		return status;
	}

	{
		//OCALL_print_int((int)sizeof(intp_code));
		//const char *message = (const char*)data_plain;
		//OCALL_print(message);
	}

	OCALL_print("enter do_sealing.");

	*res_len = do_sealing(data_plain, sealed_data);
}

sgx_status_t unseal_data(sgx_ra_context_t context, uint8_t *data_cipher, size_t cipherlen)
{
	sgx_status_t status = SGX_SUCCESS;

	uint8_t *data_cipher_pass = new uint8_t[cipherlen];

	for(int i = 0; i < cipherlen; i++)
	{
		data_cipher_pass[i] = data_cipher[i];
	}

	unsealing_test(data_cipher_pass);

	return status;
}

sgx_status_t encrypt_store_status(sgx_ra_context_t context, size_t store_flag, 
	uint8_t *p_iv, uint8_t *tag, uint8_t *res_cipher, size_t *res_len)
{
	sgx_status_t status = SGX_SUCCESS;
	sgx_ec_key_128bit_t sk_key;

	status = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);

	if(status != SGX_SUCCESS)
	{
		const char* message = "Error while obtaining session key.";
		OCALL_print(message);
		OCALL_print_status(status);
		return status;
	}

	sgx_aes_gcm_128bit_tag_t tag_t;

	for(int i = 0; i < 16; i++)
	{
		tag_t[i] = tag[i];
	}


	std::string status_message = "";

	if(store_flag == 0)
	{
		status_message = "Your data has been stored successfully.\n";
	}
	else
	{
		status_message = "Error while storing your data to database.\n";
	}
	
	uint8_t timebuf[64] = {'\0'};

	OCALL_get_time(timebuf, 64);

	std::string timeTag = "--------------------------------------------\nDate: ";
	timeTag += std::string(reinterpret_cast<char*>(timebuf));
	timeTag += ("\n--------------------------------------------\n");

	status_message.insert(0, timeTag);

	/*processes for encrypt result*/
	uint8_t *status_msg_char;
	uint8_t res_iv[12] = {'\0'};

	status_msg_char = reinterpret_cast<uint8_t*>
		(const_cast<char*>(status_message.c_str()));
	
	*res_len = std::strlen((const char*)status_msg_char);

	OCALL_generate_nonce(res_iv, 12);

	/*AES/GCM's cipher length is equal to the length of plain text*/
	status = sgx_rijndael128GCM_encrypt(&sk_key, status_msg_char, *res_len,
		res_cipher, res_iv, 12, NULL, 0, &tag_t);

	if(status != SGX_SUCCESS)
	{
		OCALL_print("Error while encrypting result.");
		OCALL_print_status(status);
		return status;
	}

	for(int i = 0; i < 16; i++)
	{
		tag[i] = tag_t[i];
	}

	for(int i = 0; i < 12; i++)
	{
		p_iv[i] = res_iv[i];
	}

	/*
	OCALL_print("\nStart context check before exit ECALL.\n");
	OCALL_print("Cipher: ");
	OCALL_dump(res_cipher, *res_len);
	OCALL_print("\nIV: ");
	OCALL_dump(p_iv, 12);
	OCALL_print("\nTag: ");
	OCALL_dump(tag, 16);
	OCALL_print("\nResult cipher length: ");
	OCALL_print_int((int)*res_len);
	*/

	return SGX_SUCCESS;

}

sgx_status_t run_interpreter(sgx_ra_context_t context, unsigned char *code_cipher,
	size_t cipherlen, unsigned char *p_iv, unsigned char *tag, 
	unsigned char *res_cipher, size_t *res_len)
{
	sgx_status_t status = SGX_SUCCESS;
	sgx_ec_key_128bit_t sk_key, mk_key;
	
	/*Get session key SK to decrypt secret*/
	status = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);

	if(status != SGX_SUCCESS)
	{
		const char* message = "Error while obtaining session key.";
		OCALL_print(message);
		OCALL_print_status(status);
		return status;
	}

	uint32_t p_iv_len = 12;
	uint8_t intp_code[1000000] = {'\0'};

	sgx_aes_gcm_128bit_tag_t tag_t;

	for(int i = 0; i < 16; i++)
	{
		tag_t[i] = tag[i];
	}
	
	//OCALL_dump(code_cipher_t, cipherlen);

	status = sgx_rijndael128GCM_decrypt(&sk_key, (uint8_t *)code_cipher, cipherlen,
		intp_code, p_iv, p_iv_len, NULL, 0, &tag_t);


	if(status != SGX_SUCCESS)
	{
		const char* message = "Error while decrypting SP's secret.";
		OCALL_print(message);
		OCALL_print_status(status);
		return status;
	}

	/*
	{
		//OCALL_print_int((int)sizeof(intp_code));
		const char *message = (const char*)intp_code;
		OCALL_print(message);
	}
	*/

	std::string intp_str(reinterpret_cast<char*>(intp_code));

	/*Call interpreter*/
	bool intp_error_flag = false;
	std::string intp_error_msg = "";
	std::string intp_result = "";

	
	OCALL_chrono_start();
	intp_result = BISGX_main(intp_str, &intp_error_flag, &intp_error_msg);
	OCALL_chrono_end();
	

	/*
	double elapsed, elapsed_total = 0.0;

	OCALL_print("Testing interpreter for N times...");
	
	for(int i = 0; i < 1000; i++)
	{
		OCALL_chrono_start();
		intp_result = BISGX_main(intp_str, &intp_error_flag, &intp_error_msg);
		OCALL_chrono_end_get_time(&elapsed);

		elapsed_total += elapsed;
	}

	OCALL_print("total interpreter execution time is:");
	OCALL_print(std::to_string(elapsed_total).c_str());
	*/

	if(intp_error_flag == true)
	{
		intp_result = "Error at interpreter\n" + intp_error_msg;
	}

	if(intp_result == "")
	{
		intp_result = "Info: Your program has successfully exited from interpreter, \nbut there is no result output.";
	}

	uint8_t timebuf[64] = {'\0'};

	OCALL_get_time(timebuf, 64);

	std::string timeTag = "--------------------------------------------\nDate: ";
	timeTag += std::string(reinterpret_cast<char*>(timebuf));
	timeTag += ("\n--------------------------------------------\n");

	intp_result.insert(0, timeTag);

	//OCALL_print("\ninterpreter execution result:");
	//OCALL_print(intp_result.c_str());

	/*processes for encrypt result*/
	uint8_t *intp_res_char;
	//uint8_t *res_cipher;
	uint8_t res_iv[12] = {'\0'};

	intp_res_char = reinterpret_cast<uint8_t*>
		(const_cast<char*>(intp_result.c_str()));
	
	*res_len = std::strlen((const char*)intp_res_char);

	OCALL_generate_nonce(res_iv, 12);

	/*AES/GCM's cipher length is equal to the length of plain text*/
	status = sgx_rijndael128GCM_encrypt(&sk_key, intp_res_char, *res_len,
		res_cipher, res_iv, 12, NULL, 0, &tag_t);

	if(status != SGX_SUCCESS)
	{
		OCALL_print("Error while encrypting result.");
		OCALL_print_status(status);
		return status;
	}
	
	for(int i = 0; i < 16; i++)
	{
		tag[i] = tag_t[i];
	}

	for(int i = 0; i < 12; i++)
	{
		p_iv[i] = res_iv[i];
	}

	/*
	OCALL_print("\nStart context check before exit ECALL.\n");
	OCALL_print("Cipher: ");
	OCALL_dump(res_cipher, *res_len);
	OCALL_print("\nIV: ");
	OCALL_dump(p_iv, 12);
	OCALL_print("\nTag: ");
	OCALL_dump(tag, 16);
	OCALL_print("\nResult cipher length: ");
	OCALL_print_int((int)*res_len);
	*/

	return SGX_SUCCESS;
}


sgx_status_t process_extract_filename(sgx_ra_context_t context, 
	uint8_t *vctx_cipher, size_t vctx_cipherlen, uint8_t *vctx_iv,
	uint8_t *vctx_tag, uint8_t *filename)
{
	sgx_status_t status = SGX_SUCCESS;
	sgx_ec_key_128bit_t sk_key;
	
	/*Get session key SK to decrypt secret*/
	status = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);

	if(status != SGX_SUCCESS)
	{
		const char* message = "Error while obtaining session key.";
		OCALL_print(message);
		OCALL_print_status(status);
		return status;
	}
	
	uint32_t p_iv_len = 12;
	uint8_t *vcf_context = new uint8_t[vctx_cipherlen + 16]();
	
	sgx_aes_gcm_128bit_tag_t tag_t;
	uint8_t *iv_t = new uint8_t[p_iv_len];


	for(int i = 0; i < 16; i++)
	{
		tag_t[i] = vctx_tag[i];
	}

	for(int i = 0; i < p_iv_len; i++)
	{
		iv_t[i] = vctx_iv[i];
	}


	status = sgx_rijndael128GCM_decrypt(&sk_key, vctx_cipher,
		vctx_cipherlen, vcf_context, iv_t, p_iv_len, NULL, 0, &tag_t);


	if(status != SGX_SUCCESS)
	{
		const char* message = "Error while decrypting SP's secret.";
		OCALL_print(message);
		OCALL_print_status(status);
		return status;
	}

	
	char *token_div;

	token_div = strtok((char*)vcf_context, "\n"); //discard whitelist
	token_div = strtok(NULL, "\n"); //and chromosome number
	token_div = strtok(NULL, "\n"); //nation info
	token_div = strtok(NULL, "\n"); //disease type
	token_div = strtok(NULL, "\n"); //then get filename

	

	for(int i = 0; i < 16; i++)
	{
		filename[i] = (uint8_t)token_div[i];
	}
	

	delete(vcf_context);

	return SGX_SUCCESS;
}

sgx_status_t store_vcf_contexts(sgx_ra_context_t context, 
	uint8_t *vctx_cipher, size_t vctx_cipherlen, uint8_t *vctx_iv,
	uint8_t *vctx_tag, uint8_t *iv_array, size_t ivlen, 
	uint8_t *tag_array, size_t taglen, uint8_t *error_msg_cipher, 
	size_t emsg_len, size_t *emsg_cipher_len)
{
	sgx_status_t status = SGX_SUCCESS;
	sgx_ec_key_128bit_t sk_key;
	std::string emsg_str = "Stored VCF file successfully.";
	uint8_t *error_msg;

	/*Get session key SK to decrypt secret*/
	status = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);

	if(status != SGX_SUCCESS)
	{
		emsg_str = "Error while obtaining session key.";
		OCALL_print(emsg_str.c_str());
		OCALL_print_status(status);

		emsg_len = emsg_str.length() + 1;
		error_msg = new uint8_t[emsg_len]();
		
		for(int i = 0; i < emsg_len - 1; i++)
		{
			error_msg[i] = (uint8_t)emsg_str.c_str()[i];
		}

		return status;
	}
	
	uint32_t p_iv_len = 12;
	uint8_t *vcf_context = new uint8_t[vctx_cipherlen + 16]();
	
	sgx_aes_gcm_128bit_tag_t tag_t;
	uint8_t *iv_t = new uint8_t[p_iv_len];


	for(int i = 0; i < 16; i++)
	{
		tag_t[i] = vctx_tag[i];
	}

	for(int i = 0; i < p_iv_len; i++)
	{
		iv_t[i] = vctx_iv[i];
	}


	status = sgx_rijndael128GCM_decrypt(&sk_key, vctx_cipher,
		vctx_cipherlen, vcf_context, iv_t, p_iv_len, NULL, 0, &tag_t);


	if(status != SGX_SUCCESS)
	{
		emsg_str = "Error while decrypting SP's secret.";
		OCALL_print(emsg_str.c_str());
		OCALL_print_status(status);

		emsg_len = emsg_str.length() + 1;
		error_msg = new uint8_t[emsg_len]();
		
		for(int i = 0; i < emsg_len - 1; i++)
		{
			error_msg[i] = (uint8_t)emsg_str.c_str()[i];
		}

		return status;
	}


	
	char *token_div;
	int len_tmp, divnum;
	size_t chrm_len, natn_len, dstp_len, usnm_len, wlst_len;
	
	uint8_t *whitelist;
	uint8_t *chrom;
	uint8_t *nation;
	uint8_t *disease_type;
	uint8_t *tar_filename;
	uint8_t *username;
	uint8_t *divnum_uchar;


	/* parse VCF contexts */
	token_div = strtok((char*)vcf_context, "\n");
	len_tmp = strlen(token_div);
	wlst_len = len_tmp;
	whitelist = new uint8_t[len_tmp]();

	for(int i = 0; i < len_tmp; i++)
	{
		whitelist[i] = (uint8_t)token_div[i];
	}


	token_div = strtok(NULL, "\n");
	len_tmp = strlen(token_div);
	chrm_len = len_tmp;
	chrom = new uint8_t[len_tmp];

	for(int i = 0; i < len_tmp; i++)
	{
		chrom[i] = (uint8_t)token_div[i];
	}


	token_div = strtok(NULL, "\n");
	len_tmp = strlen(token_div);
	natn_len = len_tmp;
	nation = new uint8_t[len_tmp];

	for(int i = 0; i < len_tmp; i++)
	{
		nation[i] = (uint8_t)token_div[i];
	}


	token_div = strtok(NULL, "\n");
	len_tmp = strlen(token_div);
	dstp_len = len_tmp;
	disease_type = new uint8_t[len_tmp];

	for(int i = 0; i < len_tmp; i++)
	{
		disease_type[i] = (uint8_t)token_div[i];
	}


	token_div = strtok(NULL, "\n");
	tar_filename = new uint8_t[16 + 1]();

	for(int i = 0; i < 16; i++)
	{
		tar_filename[i] = (uint8_t)token_div[i];
	}


	token_div = strtok(NULL, "\n");
	len_tmp = strlen(token_div);
	usnm_len = len_tmp;
	username = new uint8_t[len_tmp];

	for(int i = 0; i < len_tmp; i++)
	{
		username[i] = (uint8_t)token_div[i];
	}


	token_div = strtok(NULL, "\n");
	divnum = strtol(token_div, NULL, 10);

	
	/* obtain SHA-256 of attributions and username */
	uint8_t chrm_hash[32] = {0};
	uint8_t natn_hash[32] = {0};
	uint8_t dstp_hash[32] = {0};
	uint8_t usnm_hash[32] = {0};


	status = sgx_sha256_msg(chrom, chrm_len, 
				(sgx_sha256_hash_t*)chrm_hash);

	
	if(status != SGX_SUCCESS)
	{
		emsg_str = "Failed to obtain sha256 hash.";
		OCALL_print(emsg_str.c_str());
		OCALL_print_status(status);

		emsg_len = emsg_str.length() + 1;
		error_msg = new uint8_t[emsg_len]();
		
		for(int i = 0; i < emsg_len - 1; i++)
		{
			error_msg[i] = (uint8_t)emsg_str.c_str()[i];
		}

		return status;
	}
	


	status = sgx_sha256_msg(nation,
		natn_len, (sgx_sha256_hash_t*)natn_hash);

	
	if(status != SGX_SUCCESS)
	{
		emsg_str = "Failed to obtain sha256 hash.";
		OCALL_print(emsg_str.c_str());
		OCALL_print_status(status);

		emsg_len = emsg_str.length() + 1;
		error_msg = new uint8_t[emsg_len]();
		
		for(int i = 0; i < emsg_len - 1; i++)
		{
			error_msg[i] = (uint8_t)emsg_str.c_str()[i];
		}

		return status;
	}



	status = sgx_sha256_msg(disease_type, 
		dstp_len, (sgx_sha256_hash_t*)dstp_hash);

	
	if(status != SGX_SUCCESS)
	{
		emsg_str = "Failed to obtain sha256 hash.";
		OCALL_print(emsg_str.c_str());
		OCALL_print_status(status);

		emsg_len = emsg_str.length() + 1;
		error_msg = new uint8_t[emsg_len]();
		
		for(int i = 0; i < emsg_len - 1; i++)
		{
			error_msg[i] = (uint8_t)emsg_str.c_str()[i];
		}

		return status;
	}





	status = sgx_sha256_msg(username,
		usnm_len, (sgx_sha256_hash_t*)usnm_hash);

	
	if(status != SGX_SUCCESS)
	{
		emsg_str = "Failed to obtain sha256 hash.";
		OCALL_print(emsg_str.c_str());
		OCALL_print_status(status);

		emsg_len = emsg_str.length() + 1;
		error_msg = new uint8_t[emsg_len]();
		
		for(int i = 0; i < emsg_len - 1; i++)
		{
			error_msg[i] = (uint8_t)emsg_str.c_str()[i];
		}

		return status;
	}


	
	/* seal whitelist */
	size_t sealed_data_size;
	sealed_data_size = sgx_calc_sealed_data_size(0, wlst_len);
	
	uint8_t *sealed_whitelist = new uint8_t[sealed_data_size];

	status = sgx_seal_data(0, NULL, wlst_len, whitelist,
		sealed_data_size, (sgx_sealed_data_t*)sealed_whitelist);


	if(status != SGX_SUCCESS)
	{
		emsg_str = "Failed to seal whitelist.";
		OCALL_print(emsg_str.c_str());
		OCALL_print_status(status);

		emsg_len = emsg_str.length() + 1;
		error_msg = new uint8_t[emsg_len]();
		
		for(int i = 0; i < emsg_len - 1; i++)
		{
			error_msg[i] = (uint8_t)emsg_str.c_str()[i];
		}

		return status;
	}



	/* create copy array of IVs and tags for OCALL */
	uint8_t *iv_copy = new uint8_t[ivlen]();
	uint8_t *tag_copy = new uint8_t[taglen]();

	for(int i = 0; i < ivlen; i++)
	{
		iv_copy[i] = iv_array[i];
	}

	for(int i = 0; i < taglen; i++)
	{
		tag_copy[i] = tag_array[i];
	}

	
	
	/* call OCALL function to store into DB */
	int ocall_status;

	status = OCALL_store_vctx_into_db(&ocall_status, sealed_whitelist, 
		sealed_data_size, chrm_hash, natn_hash, dstp_hash, tar_filename, 
		usnm_hash, divnum, iv_copy, ivlen, tag_copy, taglen);


	if(status != SGX_SUCCESS)
	{
		emsg_str = "Error has occured in OCALL.";
		OCALL_print(emsg_str.c_str());
		OCALL_print_status(status);

		emsg_len = emsg_str.length() + 1;
		error_msg = new uint8_t[emsg_len]();
		
		for(int i = 0; i < emsg_len - 1; i++)
		{
			error_msg[i] = (uint8_t)emsg_str.c_str()[i];
		}

		return status;
	}


	/* need to check ocall_status here */
	if(ocall_status != 0)
	{
		OCALL_print_int(ocall_status);
		emsg_str = "Failed to store VCF contexts.";
		OCALL_print(emsg_str.c_str());
		OCALL_print_status(status);

		emsg_len = emsg_str.length() + 1;
		error_msg = new uint8_t[emsg_len]();
		
		for(int i = 0; i < emsg_len - 1; i++)
		{
			error_msg[i] = (uint8_t)emsg_str.c_str()[i];
		}

		return status;
	}


	/* seal session key */
	sealed_data_size = sgx_calc_sealed_data_size(0, 16);
	
	uint8_t *sealed_key = new uint8_t[sealed_data_size];

	status = sgx_seal_data(0, NULL, 16, sk_key,
		sealed_data_size, (sgx_sealed_data_t*)sealed_key);


	if(status != SGX_SUCCESS)
	{
		emsg_str = "Failed to seal session key.";
		OCALL_print(emsg_str.c_str());
		OCALL_print_status(status);

		emsg_len = emsg_str.length() + 1;
		error_msg = new uint8_t[emsg_len]();
		
		for(int i = 0; i < emsg_len - 1; i++)
		{
			error_msg[i] = (uint8_t)emsg_str.c_str()[i];
		}

		return status;
	}


	/* store sealed key */
	std::string key_filename = "sealed_keys/";
	key_filename += (char*)tar_filename;
	key_filename += ".bin";

	size_t kf_len = key_filename.length() + 1;
	uint8_t *kf_uchar = new uint8_t[kf_len]();

	for(int i = 0; i < kf_len - 1; i++)
	{
		kf_uchar[i] = (uint8_t)key_filename.c_str()[i];
	}

	status = OCALL_fwrite(&ocall_status, kf_uchar, kf_len, 
		sealed_key, sealed_data_size);

	
	if(status != SGX_SUCCESS)
	{
		emsg_str = "Failed to store sealed key.";
		OCALL_print(emsg_str.c_str());
		OCALL_print_status(status);

		emsg_len = emsg_str.length() + 1;
		error_msg = new uint8_t[emsg_len]();
		
		for(int i = 0; i < emsg_len - 1; i++)
		{
			error_msg[i] = (uint8_t)emsg_str.c_str()[i];
		}

		return status;
	}

	/* destruct heaps */
	delete(whitelist);
	delete(chrom);
	delete(nation);
	delete(disease_type);
	delete(tar_filename);
	delete(username);
	delete(sealed_whitelist);
	delete(iv_copy);
	delete(tag_copy);
	delete(sealed_key);
	delete(kf_uchar);

	emsg_len = emsg_str.length() + 1;
	*emsg_cipher_len = emsg_len;

	error_msg = new uint8_t[emsg_len]();
	
	for(int i = 0; i < emsg_len - 1; i++)
	{
		error_msg[i] = (uint8_t)emsg_str.c_str()[i];
	}


	/* encrypt status message */
	OCALL_generate_nonce(vctx_iv, 12);

	/*AES/GCM's cipher length is equal to the length of plain text*/
	status = sgx_rijndael128GCM_encrypt(&sk_key, error_msg, emsg_len,
		error_msg_cipher, iv_t, 12, NULL, 0, &tag_t);

	if(status != SGX_SUCCESS)
	{
		OCALL_print("Error while encrypting result.");
		OCALL_print_status(status);
		return status;
	}

	for(int i = 0; i < 16; i++)
	{
		vctx_tag[i] = tag_t[i];
	}

	for(int i = 0; i < 12; i++)
	{
		vctx_iv[i] = iv_t[i];
	}

	delete(vcf_context);
	delete(iv_t);

	return SGX_SUCCESS;
}


sgx_status_t encrypt_for_TLS(sgx_ra_context_t context, uint8_t *plain,
	size_t plain_len, uint8_t *cipher, uint8_t *iv, uint8_t *tag)
{
	uint8_t *iv_t = new uint8_t[12]();
	sgx_aes_gcm_128bit_tag_t tag_t;
	sgx_status_t status = SGX_SUCCESS;
	sgx_ec_key_128bit_t sk_key;
	
	status = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);

	OCALL_generate_nonce(iv_t, 12);

	status = sgx_rijndael128GCM_encrypt(&sk_key, plain, plain_len,
		cipher, iv_t, 12, NULL, 0, &tag_t);

	if(status != SGX_SUCCESS)
	{
		OCALL_print("Error while encrypting secret.");
		OCALL_print_status(status);
		return status;
	}

	for(int i = 0; i < 16; i++)
	{
		tag[i] = tag_t[i];
	}

	for(int i = 0; i < 12; i++)
	{
		iv[i] = iv_t[i];
	}

	delete iv_t;

	return status;
}



sgx_status_t process_data_for_dl(sgx_ra_context_t context, uint8_t *login_info,
	size_t login_sz, uint8_t *login_iv, uint8_t *login_tag, uint8_t *sealed_binary,
	size_t sealed_sz, uint8_t *dl_data, uint8_t *dl_iv, uint8_t *dl_tag, 
	size_t *dl_sz)
{
	uint8_t *iv_t = new uint8_t[12]();
	sgx_aes_gcm_128bit_tag_t tag_t;
	sgx_ec_key_128bit_t sk_key;
	sgx_status_t status = SGX_SUCCESS;

	status = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);

	if(status != SGX_SUCCESS)
	{
		OCALL_print("Failed to obtain session key.");
		OCALL_print_status(status);

		return status;
	}


	for(int i = 0; i < 12; i++)
	{
		iv_t[i] = login_iv[i];
	}

	for(int i = 0; i < 16; i++)
	{
		tag_t[i] = login_tag[i];
	}


	uint8_t *login_plain = new uint8_t[login_sz + 1]();

	
	/* decrypt login contexts */
	status = sgx_rijndael128GCM_decrypt(&sk_key, login_info,
		login_sz, login_plain, iv_t, 12, NULL, 0, &tag_t);

	if(status != SGX_SUCCESS)
	{
		OCALL_print("Failed to decrypt login information.");
		OCALL_print_status(status);

		return status;
	}


	/* extract username from decrypted login contexts */
	char *username = strtok((char*)login_plain, "\n");
	std::string usnm_str(username);

	/* unseal data for download */
	uint32_t dl_plain_len;
	uint8_t *dl_plain;

	dl_plain_len = sgx_get_encrypt_txt_len((sgx_sealed_data_t*)sealed_binary);


	dl_plain = new uint8_t[dl_plain_len + 1]();

	status = sgx_unseal_data((sgx_sealed_data_t*)sealed_binary, NULL, 0, 
		dl_plain, &dl_plain_len);

	if(status != SGX_SUCCESS)
	{
		OCALL_print("Failed to unseal data for download");
		OCALL_print_status(status);

		return status;
	}


	/* check username and need to discard first line */
	char *header = strtok((char*)dl_plain, "\n");
	std::string header_str(header);


	if(header_str != usnm_str)
	{
		OCALL_print("Fatal: Your user information is corrupted.");

		return (sgx_status_t)0x5002; //SGX_ERROR_NO_PRIVILEDGE
	}

	size_t header_sz = header_str.length() + 1;
	uint8_t *dl_cut = new uint8_t[dl_plain_len + 1 - header_sz]();

	int dummy = 0;

	for(int i = header_sz; i < dl_plain_len; i++)
	{
		dl_cut[i - header_sz] = dl_plain[i];
		dummy++;
	}

	*dl_sz = dl_plain_len - header_sz;

	OCALL_generate_nonce(iv_t, 12);



	/*AES/GCM's cipher length is equal to the length of plain text*/
	status = sgx_rijndael128GCM_encrypt(&sk_key, dl_cut, *dl_sz,
		dl_data, iv_t, 12, NULL, 0, &tag_t);


	if(status != SGX_SUCCESS)
	{
		OCALL_print("Failed to encrypt data for download.");
		OCALL_print_status(status);

		return status;
	}



	/* copy IV and tag buffer to passed pointer */
	for(int i = 0; i < 12; i++)
	{
		dl_iv[i] = iv_t[i];
	}

	for(int i = 0; i < 16; i++)
	{
		dl_tag[i] = tag_t[i];
	}

	return SGX_SUCCESS;
}
