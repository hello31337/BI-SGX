#include "BISGX.h"
#include "Enclave_t.h"
#include <math.h>
#include <string.h>
#include <stdlib.h>



namespace Bmath
{
	/*protos*/
	double calculateExp(double base, double exponent);
}

double Bmath::calculateExp(double base, double exponent)
{
	return pow(base, exponent);
}
