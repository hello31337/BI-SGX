#include "BISGX.h"
#include "Enclave_t.h"
#include <math.h>
#include <string.h>
#include <stdlib.h>
#include <sgx_trts.h>
#include <limits.h>


namespace Bmath
{
	/*protos*/
	double calculatePow(double base, double exponent);
	double generateTrustedRandomNumber(int min, int max);
}

double Bmath::calculatePow(double base, double exponent)
{
	return pow(base, exponent);
}

double Bmath::generateTrustedRandomNumber(int min, int max)
{
	if(min == max)
	{
		return min;
	}

	uint32_t u_rnd, rand_range;
	uint64_t allowed_range;
	int32_t res_rnd;

	rand_range = abs(max - min) + 1;

	do
	{
		sgx_status_t status = sgx_read_rand((uint8_t*)&u_rnd, sizeof(uint8_t)*4);

		if(status != SGX_SUCCESS)
		{
			OCALL_print_status(status);
			throw std::string("SGX failed to generate random number.");
		}

		allowed_range = (uint64_t)((UINT_MAX) / rand_range) * rand_range;

	} while(res_rnd > allowed_range);


	/* convert to signed int */
	res_rnd = abs((int32_t)u_rnd);


	/* round range into min~max */
	res_rnd %= rand_range;


	/* get final random number */
	if(min < max)
	{
		res_rnd += min;
	}
	else
	{
		res_rnd += max;
	}

	return (double)res_rnd;
}

