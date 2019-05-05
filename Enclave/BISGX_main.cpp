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
	extern std::vector<std::string> strLITERAL;
	extern std::vector<double> nbrLITERAL;
	extern BISGX_stack stk;
	extern BISGX_memory Dmem;
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

	Bmain::result_str = "";

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

	/*terminate contexts*/
	Bcode::intercode.clear();
	Btable::Gtable.clear();
	Btable::Ltable.clear();
	Bcode::strLITERAL.clear();
	Bcode::nbrLITERAL.clear();

	std::vector<char*>().swap(Bcode::intercode);
	std::vector<SymTbl>().swap(Btable::Gtable);
	std::vector<SymTbl>().swap(Btable::Ltable);
	std::vector<std::string>().swap(Bcode::strLITERAL);
	std::vector<double>().swap(Bcode::nbrLITERAL);

	Bcode::stk.destruct();
	Bcode::Dmem.destruct();

	return Bmain::result_str;
}
