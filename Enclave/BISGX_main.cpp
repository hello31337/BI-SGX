#include "Enclave_t.h"
#include "BISGX.h"

namespace Bparse
{
	extern void convert_to_internalCode(std::string code);
}

std::string BISGX_main(std::string code, 
		bool *error_flag, std::string *error_msg)
{
	*error_flag = false;
	*error_msg = "";

	try
	{
		Bparse::convert_to_internalCode(code);
	}
	catch(std::string bisgx_e)
	{
		*error_flag = true;
		*error_msg = bisgx_e;

		return std::string("Error");
	}
	catch(std::bad_alloc)
	{
		*error_flag = true;
		*error_msg = "Failed to allocate memory.";

		return std::string("Error");
	}

	return std::string("Under construction");
}
