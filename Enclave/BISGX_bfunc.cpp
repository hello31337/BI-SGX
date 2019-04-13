#include "BISGX.h"
#include "Enclave_t.h"
#include <sgx_tseal.h>
#include <sgx_tcrypto.h>
#include <string.h>
#include <stdlib.h>

namespace Bbfunc
{
	/*protos*/
	double executeAverage(std::string dataset_name);
}

double Bbfunc::executeAverage(std::string dataset_name)
{
	int sealedlen;
	char *name_to_pass;

	name_to_pass = const_cast<char*>(dataset_name.c_str());

	OCALL_get_sealed_length(name_to_pass, &sealedlen);

	uint8_t *sealed_data = new uint8_t[sealedlen];

	OCALL_load_db(sealed_data, sealedlen, name_to_pass);

	/*start unsealing*/
	sgx_status_t status;
	uint32_t decrypt_buf_length;

	decrypt_buf_length = sgx_get_encrypt_txt_len((sgx_sealed_data_t*)sealed_data);

	uint8_t *decrypt_buf = new uint8_t[decrypt_buf_length];

	status = sgx_unseal_data((sgx_sealed_data_t*)sealed_data, NULL, 0, 
		decrypt_buf, &decrypt_buf_length);

	if(status != SGX_SUCCESS)
	{
		throw std::string("Failed to unseal secret from database.");
	}

	double average = 0.0;
	int datanum = 0;
	char *token_div;

	token_div = strtok((char*)decrypt_buf, "\n");
	average += atof(token_div);
	datanum++;
	
	while((token_div = strtok(NULL, "\n")) != NULL)
	{
		average += atof(token_div);
		datanum++;
	}

	average /= datanum;

	return average;
}
