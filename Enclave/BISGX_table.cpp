#include "Enclave_t.h"
#include "BISGX.h"

namespace Btable
{
	std::vector<SymTbl> Gtable;
	std::vector<SymTbl> Ltable;
	int startLtable;

	int enter(SymTbl &tb, SymKind kind);
	void set_startLtable();
	bool is_localName(const std::string &name, SymKind kind);
	int searchName(const std::string &s, int mode);
	std::vector<SymTbl>::iterator tableP(const CodeSet &cd);
}

namespace Blex
{
	extern int get_lineNo();
}

namespace Bparse
{
	extern bool is_localScope();
	extern int localAdrs;
}

namespace Bcode
{
	extern BISGX_memory Dmem;
}

int Btable::enter(SymTbl &tb, SymKind kind)
{
	int n, mem_size;
	bool isLocal = is_localName(tb.name, kind);

	mem_size = tb.aryLen;

	if(mem_size == 0) mem_size = 1;
	if(kind != varId && tb.name[0] == '$')
	{
		throw std::string("'$' cannot be used except for variable name.");
	}

	tb.nmKind = kind;
	n = -1;

	if(kind == fncId)  n = searchName(tb.name, 'G');
	if(kind == paraId) n = searchName(tb.name, 'L');
	if(n != -1)
	{
		std::string error_msg = "Redeclaration of variable: ";
		error_msg += tb.name;

		throw error_msg;
	}

	if(kind == fncId)
	{
		tb.adrs = Blex::get_lineNo();
	}
	else
	{
		if(isLocal)
		{
			tb.adrs = Bparse::localAdrs;
			Bparse::localAdrs += mem_size;
		}
		else
		{
			tb.adrs = Bcode::Dmem.size();
			Bcode::Dmem.resize(Bcode::Dmem.size() + mem_size);
		}
	}

	if(isLocal)
	{
		n = Ltable.size();
		Ltable.push_back(tb);
	}
	else
	{
		n = Gtable.size();
		Gtable.push_back(tb);
	}

	return n;
}

void Btable::set_startLtable()
{
	startLtable = Ltable.size();
}

bool Btable::is_localName(const std::string &name, SymKind kind)
{
	if(kind == paraId) return true;
	if(kind == varId)
	{
		if(Bparse::is_localScope() && name[0] != '$')
		{
			return true;
		}
		else
		{
			return false;
		}
	}
}

int Btable::searchName(const std::string &s, int mode)
{
	int n;

	switch(mode)
	{
		case 'G':
			for(n = 0; n < (int)Gtable.size(); n++)
			{
				if(Gtable[n].name == s)
				{
					return n;
				}
			}

			break;

		case 'L':
			for(n = startLtable; n < (int)Ltable.size(); n++)
			{
				if(Ltable[n].name == s)
				{
					return n;
				}
			}

			break;

		case 'F':
			n = searchName(s, 'G');

			if(n != -1 && Gtable[n].nmKind == fncId)
			{
				return n;
			}

			break;

		case 'V':
			if(searchName(s, 'F') != -1)
			{
				std::string error_msg = 
					"Duplicated variable name with function name: ";

				error_msg += s;

				throw error_msg;
			}

			if(s[0] == '$')	return searchName(s, 'G');
			
			if(Bparse::is_localScope())
			{
				return searchName(s, 'L');
			}
			else
			{
				return searchName(s, 'G');
			}
	}

	return -1;
}

std::vector<SymTbl>::iterator Btable::tableP(const CodeSet &cd)
{
	if(cd.kind == Lvar)
	{
		return Ltable.begin() + cd.symNbr;
	}
	else
	{
		return Gtable.begin() + cd.symNbr;
	}
}
