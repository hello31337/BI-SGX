#include "BISGX.h"

namespace Bcode
{
	/*Global vals*/
	int startPc;
	int Pc = -1;
	std::vector<char*> intercode;
	BISGX_memory Dmem;

	/*protos*/
	void set_startPc(int n);
}

void Bcode::set_startPc(int n)
{
	startPc = n;
}

