#include "Enclave_t.h"
#include "BISGX.h"

namespace Bparse
{
	extern void convert_to_internalCode(std::string code);
}

namespace Bcode
{
	extern std::vector<char*> intercode;
	extern void syntaxChk();
	extern void execute();
	extern int error_Pc;
}

namespace Btable
{
	extern std::vector<SymTbl> Gtable;
	extern std::vector<SymTbl> Ltable;
}

namespace Blex
{
	extern int get_lineNo();
}

namespace Bmain
{
	std::string result_str = "";
}

std::string BISGX_main(std::string code, 
		bool *error_flag, std::string *error_msg)
{
	*error_flag = false;
	*error_msg = "Line ";

	try
	{
		Bparse::convert_to_internalCode(code);
		Bcode::syntaxChk();
		Bcode::execute();
	}
	catch(std::string bisgx_e)
	{
		Bcode::error_Pc = Blex::get_lineNo();
		*error_flag = true;
		*error_msg += std::to_string(Bcode::error_Pc);
		*error_msg += ": ";
		*error_msg += bisgx_e;
		*error_msg += "\n";

		return std::string("Error");
	}
	catch(std::bad_alloc)
	{
		*error_flag = true;
		*error_msg += std::to_string(Bcode::error_Pc);
		*error_msg += ": ";
		*error_msg = "Failed to allocate memory.";
		*error_msg += "\n";

		return std::string("Error");
	}

	return Bmain::result_str;
}
