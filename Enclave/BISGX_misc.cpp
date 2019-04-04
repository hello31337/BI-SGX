#include "Enclave_t.h"
#include "BISGX.h"

namespace Bmisc
{
	std::string dbl_to_s(double d);
}

std::string Bmisc::dbl_to_s(double d)
{
	return std::to_string(d);
}
