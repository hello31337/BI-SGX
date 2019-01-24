#include "Enclave_t.h"
#include "BISGX.h"

#include <cstdlib>
#include <cctype>
#include <cstring>
#include <cassert>

#define NO_FIX_ADRS 0

namespace Bcode
{
	extern std::vector<char*> intercode;
}

namespace Bparse
{
	/*Global vals*/
	Token token;
	SymTbl tmpTb;
	int blkNest;
	int localAdrs;
	int mainTblNbr;
	int loopNest;
	bool fncDecl_F;
	bool explicit_F;
	char codebuf[LIN_SIZ+1], *codebuf_p;

	/*protos*/
	void init();
	void convert_to_internalCode(std::string code);
	void convert();
	void convert_block_set();
	void convert_block();
	void convert_rest();
	void optionSet();
	void varDecl();
	void var_nameChk(const Token &tk);
	void set_name();

}



