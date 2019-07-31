#include "BISGX.h"
#include "Enclave_t.h"
#include <math.h>
#include <string.h>
#include <stdlib.h>
#include <sgx_trts.h>


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

	uint8_t rand_buf[4] = {0};

	sgx_status_t status = sgx_read_rand(rand_buf, sizeof(uint8_t)*4);

	if(status != SGX_SUCCESS)
	{
		OCALL_print_status(status);
		throw std::string("SGX failed to generate random number.");
	}

	uint32_t u_rnd, rand_range;
	int32_t res_rnd;

	rand_range = abs(max - min);

	u_rnd = (uint32_t)rand_buf[0]
		+ (uint32_t)rand_buf[1] * 256 
		+ (uint32_t)rand_buf[2] * 256 * 256
		+ (uint32_t)rand_buf[3] * 256 * 256 * 256;

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

