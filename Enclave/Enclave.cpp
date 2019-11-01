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
#include <sgx_tae_service.h>
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

namespace Bmath
{
	extern double generateTrustedRandomNumber(int min, int max);
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

size_t get_pse_manifest_size ()
{
	return sizeof(sgx_ps_sec_prop_desc_t);
}

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

sgx_status_t enclave_ra_init(sgx_ec256_public_t key, int b_pse,
	sgx_ra_context_t *ctx, sgx_status_t *pse_status)
{
	sgx_status_t ra_status;

	/*
	 * If we want platform services, we must create a PSE session 
	 * before calling sgx_ra_init()
	 */

	if ( b_pse ) {
		int retries= PSE_RETRIES;
		do {
			*pse_status= sgx_create_pse_session();
			if ( *pse_status != SGX_SUCCESS ) return SGX_ERROR_UNEXPECTED;
		} while (*pse_status == SGX_ERROR_BUSY && retries--);
		if ( *pse_status != SGX_SUCCESS ) return SGX_ERROR_UNEXPECTED;
	}

	ra_status= sgx_ra_init(&key, b_pse, ctx);

	if ( b_pse ) {
		int retries= PSE_RETRIES;
		do {
			*pse_status= sgx_create_pse_session();
			if ( *pse_status != SGX_SUCCESS ) return SGX_ERROR_UNEXPECTED;
		} while (*pse_status == SGX_ERROR_BUSY && retries--);
		if ( *pse_status != SGX_SUCCESS ) return SGX_ERROR_UNEXPECTED;
	}

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



/*referred: https://ryozi.hatenadiary.jp/entry/20101203/1291380670 in 12/30/2018*/
int trusted_base64_encoder(uint8_t *src, int srclen, uint8_t *dst, int dstlen)
{
	const char Base64char[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	int i,j;
	int calclength = (srclen/3*4) + (srclen%3?4:0);
	if(calclength > dstlen) return -1;
	
	j=0;
	for(i=0; i+2<srclen; i+=3){
		dst[j++] = Base64char[ (src[i] >> 2) & 0x3F ];
		dst[j++] = Base64char[ (src[i] << 4 | src[i+1] >> 4) & 0x3F ];
		dst[j++] = Base64char[ (src[i+1] << 2 | src[i+2] >> 6) & 0x3F ];
		dst[j++] = Base64char[ (src[i+2]) & 0x3F ];
	}
	
	if(i<srclen){
		dst[j++] = Base64char[ (src[i] >> 2) & 0x3F ];
		if(i+1<srclen){
			dst[j++] = Base64char[ (src[i] << 4 | src[i+1] >> 4) & 0x3F ];
			if(i+2<srclen){
				dst[j++] = Base64char[ (src[i+1] << 2 | src[i+2] >> 6) & 0x3F ];
			}else{
				dst[j++] = Base64char[ (src[i+1] << 2) & 0x3F ];
			}
		}else{
			dst[j++] = Base64char[ (src[i] << 4) & 0x3F ];
		}
	}
	while(j%4) dst[j++] = '=';
	
	if(j<dstlen) dst[j] = '\0';
	return j;
}



int trusted_base64_decoder(uint8_t *src, int srclen, uint8_t *dst, int dstlen)
{
	const unsigned char Base64num[] = {
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x3E,0xFF,0xFF,0xFF,0x3F,
		0x34,0x35,0x36,0x37,0x38,0x39,0x3A,0x3B,0x3C,0x3D,0xFF,0xFF,0xFF,0x00,0xFF,0xFF,
		0xFF,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,
		0x0F,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0xFF,0xFF,0xFF,0xFF,0xFF,
		0xFF,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,
		0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F,0x30,0x31,0x32,0x33,0xFF,0xFF,0xFF,0xFF,0xFF,
		
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	};
	int calclength = (srclen/4*3);
	//cout << "\nINFO: calclength -> " << calclength << endl << endl;
	int i,j;
	if(calclength > dstlen || srclen % 4 != 0) return 0;
	
	j=0;
	for(i=0; i+3<srclen; i+=4){
		if((Base64num[src[i+0]]|Base64num[src[i+1]]|Base64num[src[i+2]]|Base64num[src[i+3]]) > 0x3F){
			return -1;
		}
		dst[j++] = Base64num[src[i+0]]<<2 | Base64num[src[i+1]] >> 4;
		dst[j++] = Base64num[src[i+1]]<<4 | Base64num[src[i+2]] >> 2;
		dst[j++] = Base64num[src[i+2]]<<6 | Base64num[src[i+3]];
	}
	
	if(j<dstlen) dst[j] = '\0';
	return j;
}



sgx_status_t trusted_nonce_generator(uint8_t *nonce, size_t sz)
{
	return sgx_read_rand(nonce, sizeof(uint8_t) * sz);
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
	uint8_t *username, uint8_t *password_hash, uint8_t *privilege, uint8_t *datatype)
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
	uint8_t login_info[64] = {'\0'};
	
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
	uint8_t *tag_array, size_t taglen, int *divnum_ret,
	uint8_t *cpl_cipher, size_t cpl_deflen, uint8_t *iv_cpl,
	uint8_t *tag_cpl, uint8_t *error_msg_cipher, size_t emsg_len, 
	size_t *emsg_cipher_len, uint8_t *emsg_iv, uint8_t *emsg_tag)
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
	*divnum_ret = divnum;

	
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

	
	/* decrypt cipher of chunk-head position list */
	uint8_t *chunk_pos_list = new uint8_t[cpl_deflen + 16]();


	for(int i = 0; i < 16; i++)
	{
		tag_t[i] = tag_cpl[i];
	}

	for(int i = 0; i < p_iv_len; i++)
	{
		iv_t[i] = iv_cpl[i];
	}


	status = sgx_rijndael128GCM_decrypt(&sk_key, cpl_cipher,
		cpl_deflen, chunk_pos_list, iv_t, p_iv_len, NULL, 0, &tag_t);



	/* add prefix of chrom and nation to cpl */
	std::string full_cpl_str;
	std::string prefix;
	char *cpl_token;
	char *cpl_token_tail;

	prefix = std::string((char*)chrom) + std::string("_")
		+ std::string((char*)nation) + std::string("_");


	cpl_token = strtok_r((char*)chunk_pos_list, "\n", &cpl_token_tail);

	do
	{
		full_cpl_str += prefix;
		full_cpl_str += std::string(cpl_token);
		full_cpl_str += "\n";

	} while(cpl_token = strtok_r(NULL, "\n", &cpl_token_tail));

	full_cpl_str.pop_back();

	size_t fcpl_sz = full_cpl_str.length();
	uint8_t *full_cpl = new uint8_t[fcpl_sz + 1]();

	for(int i = 0; i < fcpl_sz; i++)
	{
		full_cpl[i] = (uint8_t)full_cpl_str.c_str()[i];
	}


	
	/* seal full cpl */
	size_t sealed_cpl_size;
	sealed_cpl_size = sgx_calc_sealed_data_size(0, fcpl_sz);
	
	uint8_t *sealed_cpl = new uint8_t[sealed_cpl_size]();

	status = sgx_seal_data(0, NULL, fcpl_sz, full_cpl,
		sealed_cpl_size, (sgx_sealed_data_t*)sealed_cpl);


	if(status != SGX_SUCCESS)
	{
		emsg_str = "Failed to seal chunk-head position list.";
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

	
	/* call OCALL function to store into DB */
	int ocall_status;

	status = OCALL_store_vctx_into_db(&ocall_status, sealed_whitelist, 
		sealed_data_size, sealed_cpl, sealed_cpl_size, chrm_hash, 
		natn_hash, dstp_hash, tar_filename, usnm_hash, divnum, 
		iv_copy, ivlen, tag_copy, taglen);


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
	OCALL_generate_nonce(emsg_iv, 12);

	for(int i = 0; i < 12; i++)
	{
		iv_t[i] = emsg_iv[i];
	}

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
		emsg_tag[i] = tag_t[i];
	}

	for(int i = 0; i < 12; i++)
	{
		emsg_iv[i] = iv_t[i];
	}

	delete(vcf_context);
	delete(iv_t);

	return SGX_SUCCESS;
}



sgx_status_t generate_oram_fileset(sgx_ra_context_t context, 
	uint8_t *filename, int divnum, uint8_t *cpl_cipher, size_t cpl_deflen, 
	uint8_t *iv_cpl, uint8_t *tag_cpl, uint8_t *iv_array, size_t iv_array_len,
	uint8_t *tag_array, size_t tag_array_len, uint8_t *vctx_cipher, 
	size_t vctx_deflen, uint8_t *iv_vctx, uint8_t *tag_vctx, 
	uint8_t *error_msg_cipher, size_t emsg_len, size_t *emsg_cipher_len, 
	uint8_t *emsg_iv, uint8_t *emsg_tag, size_t slot_size)
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
	uint8_t *vcf_context = new uint8_t[vctx_deflen + 16]();
	
	sgx_aes_gcm_128bit_tag_t tag_t;
	uint8_t *iv_t = new uint8_t[p_iv_len]();

	
	/* decrypt previous error message */
	for(int i = 0; i < 16; i++)
	{
		tag_t[i] = emsg_tag[i];
	}

	for(int i = 0; i < 12; i++)
	{
		iv_t[i] = emsg_iv[i];
	}

	
	uint8_t *emsg_tmp = new uint8_t[*emsg_cipher_len + 1]();

	status = sgx_rijndael128GCM_decrypt(&sk_key, error_msg_cipher,
		*emsg_cipher_len, emsg_tmp, iv_t, 12, NULL, 0, &tag_t);

	if(status != SGX_SUCCESS)
	{
		const char *message = "Error while decrypting error message cipher.";
		OCALL_print(message);
		OCALL_print_status(status);
		return status;
	}

	std::string emsg_str((char*)emsg_tmp);

	delete(emsg_tmp);


	/* decrypt VCF context */
	for(int i = 0; i < 16; i++)
	{
		tag_t[i] = tag_vctx[i];
	}

	for(int i = 0; i < p_iv_len; i++)
	{
		iv_t[i] = iv_vctx[i];
	}



	status = sgx_rijndael128GCM_decrypt(&sk_key, vctx_cipher,
		vctx_deflen, vcf_context, iv_t, p_iv_len, NULL, 0, &tag_t);


	if(status != SGX_SUCCESS)
	{
		const char* message = "Error while decrypting SP's secret.";
		OCALL_print(message);
		OCALL_print_status(status);
		return status;
	}

	


	/* obtain information necessary for ORAM management */
	char *token_div;
	std::string nation, chrom;


	token_div = strtok((char*)vcf_context, "\n"); //discard whitelist


	/* obtain chromosome number */
	token_div = strtok(NULL, "\n");
	chrom = std::string(token_div);
	
	
	/* obtain nation info */
	token_div = strtok(NULL, "\n");
	nation = std::string(token_div);


	token_div = strtok(NULL, "\n"); //discard disease type
	token_div = strtok(NULL, "\n"); //then filename


	delete(vcf_context);


	/* decrypt cipher of chunk-head position list */
	uint8_t *chunk_pos_list = new uint8_t[cpl_deflen + 16]();


	for(int i = 0; i < 16; i++)
	{
		tag_t[i] = tag_cpl[i];
	}

	for(int i = 0; i < p_iv_len; i++)
	{
		iv_t[i] = iv_cpl[i];
	}


	status = sgx_rijndael128GCM_decrypt(&sk_key, cpl_cipher,
		cpl_deflen, chunk_pos_list, iv_t, p_iv_len, NULL, 0, &tag_t);

	

	/* prepare for chunk processing loop */
	std::string ctx_prefix = nation + std::string("_") 
		+ chrom + std::string("_");

	/* obtain nearest 2^n value larger than divnum */
	int fileset_total = divnum * slot_size;
	

	if((fileset_total & (fileset_total - 1)) != 0)
	{
		uint32_t bit_scan = 1;

		while(fileset_total > 0)
		{
			bit_scan <<= 1;
			fileset_total >>= 1;
		}

		fileset_total = bit_scan;
	}

	int data_counter = 0;
	char *pos_token;
	char *pos_token_tail;
	std::string context_list; //format ex.: "21_JPT_10000;1.bin"

	/* decide range of random number */
	int rng_range = fileset_total / divnum;
	
	/* parse position list and generate fileset */
	pos_token = strtok_r((char*)chunk_pos_list, "\n", &pos_token_tail);

	do
	{
		std::string chunk_context = 
			ctx_prefix + std::string((char*)pos_token);
		
		chunk_context += ";";
		
		int obtained_rn = 
			(int)Bmath::generateTrustedRandomNumber(0, rng_range - 1);

		for(int i = 0; i < rng_range; i++)
		{
			if(i == obtained_rn)
			{
				chunk_context += std::to_string(data_counter);
			}
			else
			{

			}

			data_counter++;
		}
	}
	while ((pos_token = strtok_r(NULL, "\n", &pos_token_tail)) != NULL);


	/* process remaining dummies */

	/* encrypt status message */
	emsg_len = emsg_str.length() + 1;
	*emsg_cipher_len = emsg_len;
	
	emsg_tmp = new uint8_t[emsg_len]();
	
	for(int i = 0; i < emsg_len; i++)
	{
		emsg_tmp[i] = (uint8_t)emsg_str.c_str()[i];
	}


	OCALL_generate_nonce(emsg_iv, 12);

	for(int i = 0; i < 12; i++)
	{
		iv_t[i] = emsg_iv[i];
	}

	for(int i = 0; i < emsg_len; i++)
	{
		error_msg_cipher[i] = '\0';
	}



	/*AES/GCM's cipher length is equal to the length of plain text*/
	status = sgx_rijndael128GCM_encrypt(&sk_key, emsg_tmp, emsg_len,
		error_msg_cipher, iv_t, 12, NULL, 0, &tag_t);

	if(status != SGX_SUCCESS)
	{
		OCALL_print("Error while encrypting result.");
		OCALL_print_status(status);
		return status;
	}

	for(int i = 0; i < 16; i++)
	{
		emsg_tag[i] = tag_t[i];
	}


	return SGX_SUCCESS;
}


sgx_status_t oram_management(char *filename, size_t flnm_size, char *iv_array,
	size_t iv_size, char *tag_array, size_t tag_size, char *pos_list,
	size_t plst_size, size_t div_total)

{
	if(div_total < 1)
	{
		OCALL_print("Error: Invalid dataset.");
		return SGX_ERROR_INVALID_PARAMETER;
	}

	size_t iv_total_size = div_total * 12;
	size_t tag_total_size = div_total * 16;

	uint8_t *iv_total = new uint8_t[iv_total_size]();
	uint8_t *tag_total = new uint8_t[tag_total_size]();

	std::vector<std::string> filename_vec;
	std::vector<std::string> pos_list_vec;
	std::vector<size_t> divnum_vec;
	size_t total_files = 0;

	/* parse filenames */
	char *token_head;
	char *token_tail;

	token_head = strtok_r(filename, "\n", &token_tail);

	do
	{
		filename_vec.push_back(std::string(token_head));
		total_files++;

	} while((token_head = strtok_r(NULL, "\n", &token_tail)) != NULL);

	
	if(total_files < 1)
	{
		return SGX_ERROR_UNEXPECTED;
	}


	/* parse other contexts */
	int iv_index = 0;
	int tag_index = 0;

	for(int idx = 0; idx < total_files; idx++)
	{
		/* process iv array */
		uint8_t *decoded_iv = new uint8_t[iv_size]();

		size_t ret_sz = trusted_base64_decoder((uint8_t*)iv_array, iv_size,
			decoded_iv, iv_size);

		for(int i = 0; i < ret_sz; i++)
		{
			iv_total[iv_index + i] = decoded_iv[i];
		}

		iv_index += ret_sz;
		divnum_vec.emplace_back(ret_sz / 12);

		delete(decoded_iv);


		/* process tag array */
		uint8_t *decoded_tag = new uint8_t[tag_size]();

		ret_sz = trusted_base64_decoder((uint8_t*)tag_array, tag_size,
		decoded_tag, tag_size);

		for(int i = 0; i < ret_sz; i++)
		{
			tag_total[tag_index + i] = decoded_tag[i];
		}

		tag_index += ret_sz;

		delete(decoded_tag);


		/* decode position list from base64 */
		uint8_t *sealed_pos_list = new uint8_t[plst_size]();

		ret_sz = trusted_base64_decoder((uint8_t*)pos_list, plst_size,
			sealed_pos_list, plst_size);

		
		/* unseal position list */
		uint8_t *unsealed_plst = new uint8_t[ret_sz + 1]();

		sgx_status_t status = sgx_unseal_data((sgx_sealed_data_t*)sealed_pos_list, 
			NULL, 0, unsealed_plst, (uint32_t*)&ret_sz);

		if(status != SGX_SUCCESS)
		{
			return status;
		}

		
		/* parse unsealed positions to vector */
		char *plst_token;
		char *plst_token_tail;

		plst_token = strtok_r((char*)unsealed_plst, "\n", &plst_token_tail);

		do
		{
			pos_list_vec.push_back(std::string(plst_token));
		} while((plst_token = strtok_r(NULL, "\n", &plst_token_tail)) != NULL);
		

		delete(sealed_pos_list);
		delete(unsealed_plst);
	}



	/* load sealed AES keys */
	uint8_t *key_array = new uint8_t[16 * total_files]();
	
	for(int idx = 0; idx < total_files; idx++)
	{
		size_t sealed_key_size = sgx_calc_sealed_data_size(0, 16);
		uint8_t *sealed_key = new uint8_t[sealed_key_size]();
		char *flnm_to_pass = new char[17]();
		

		for(int i = 0; i < 16; i++)
		{
			flnm_to_pass[i] = filename_vec[idx].c_str()[i];
		}

		sgx_status_t status;
		int ocall_ret = 0;
		size_t dummy_sz = 0;

		status = OCALL_get_key_and_vctx(&ocall_ret, sealed_key,
			sealed_key_size, &dummy_sz, flnm_to_pass);

		if(status != SGX_SUCCESS)
		{
			return status;
		}

		if(ocall_ret == -1)
		{
			OCALL_print("\nError has occurred while querying MySQL.\n");
			return SGX_ERROR_UNEXPECTED;
		}
		else if(ocall_ret == -2)
		{
			OCALL_print("\nEncryption key was not found for stored VCF.\n");
			return SGX_ERROR_UNEXPECTED;
		}


		/* unseal key */
		uint32_t key_len; //must be 16

		key_len = sgx_get_encrypt_txt_len((sgx_sealed_data_t*)sealed_key);

		if(key_len != 16)
		{
			OCALL_print("Error: Corrupted key length.");
			return SGX_ERROR_UNEXPECTED;
		}

		uint8_t *vcf_key = new uint8_t[key_len]();

		status = sgx_unseal_data((sgx_sealed_data_t*)sealed_key, NULL, 0,
			vcf_key, &key_len);

		if(status != SGX_SUCCESS)
		{
			OCALL_print("Error: Failed to unseal key.");
			return status;
		}

		for(int i = 0; i < 16; i++)
		{
			key_array[idx * 16 + i] = vcf_key[i];
		}
	}


	/* generate new common AES key */
	uint8_t *common_key = new uint8_t[16]();
	sgx_status_t rnd_st = trusted_nonce_generator(common_key, 16);


	/* NOTE: THIS VARIABLE MUST BE FIXED TO ACTUAL VALUE */
	std::string target_name = filename_vec[0];
	target_name += ".10";


	/* split target filename to body and suffix */
	char *tgn_char = (char*)target_name.c_str();
	char *tgn_token;
	char *tgn_token_tail;

	std::string tgn_body, tgn_suffix;

	tgn_token = strtok_r(tgn_char, ".", &tgn_token_tail);
	tgn_body = std::string(tgn_token);

	tgn_token = strtok_r(NULL, ".", &tgn_token_tail);
	tgn_suffix = std::string(tgn_token);


	int body_num = 0;
	int is_found = 0;
	int suffix_int = atoi(tgn_suffix.c_str());

	for(body_num = 0; body_num < total_files; body_num++)
	{
		if(tgn_body == filename_vec[body_num])
		{
			is_found++;
			break;
		}
	}

	if(is_found < 1)
	{
		OCALL_print("Error: Invalid filename is queried.");
		return SGX_ERROR_UNEXPECTED;
	}


	/* extract cryptographic contexts */
	uint8_t *target_iv = new uint8_t[12]();
	uint8_t *target_tag = new uint8_t[16]();
	uint8_t *target_key = new uint8_t[16]();

	size_t offset_base = 0;
	size_t iv_offset = 0;
	size_t tag_offset = 0;

	for(int i = 0; i < body_num; i++)
	{
		offset_base += divnum_vec[i];
	}

	iv_offset = offset_base * 12 + suffix_int * 12;
	tag_offset = offset_base * 16 + suffix_int * 16;

	for(int i = 0; i < 12; i++)
	{
		target_iv[i] = iv_total[iv_offset + i];
	}

	for(int i = 0; i < 16; i++)
	{
		target_tag[i] = tag_total[tag_offset + i];
		target_key[i] = key_array[body_num * 16 + i];
	}


	/* load target chunk */
	sgx_status_t cl_st = SGX_SUCCESS;
	int ocall_ret = 0;
	size_t chunk_size = 1010000;
	uint8_t *loaded_chunk = new uint8_t[chunk_size]();

	char *flnm_to_pass = new char[17]();

	for(int i = 0; i < 16; i++)
	{
		flnm_to_pass[i] = tgn_body.c_str()[i];
	}

	cl_st = OCALL_load_VCF_chunk(&ocall_ret, loaded_chunk, chunk_size,
		0, flnm_to_pass, 17, suffix_int);

	if(cl_st != SGX_SUCCESS)
	{
		OCALL_print("Error: Failed to load designated VCF chunk.");
		return cl_st;
	}


	/* decrypt loaded chunk */


	return SGX_SUCCESS;
}
