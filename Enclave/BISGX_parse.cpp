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
	extern void set_startPc(int n);
}

namespace Blex
{
	extern void initChTyp();
	extern void BufferInit(std::string code);
	extern Token nextTkn();
	extern Token nextLine_tkn();
	extern int get_lineNo();
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
	/*
	void convert();
	void convert_block_set();
	void convert_block();
	void convert_rest();
	void optionSet();
	void varDecl();
	void var_nameChk(const Token &tk);
	*/
	void set_name();
	/*
	void set_aryLen();
	void fncDecl();
	void backPatch(int line, int n);
	*/
	void setCode(int cd);
	int setCode(int cd, int nbr);
	/*
	void setCode_rest();
	void setCode_End();
	void setCode_EofLine();
	*/
	void push_intercode();
	bool is_localScope();
	
}

namespace Btable
{
	extern int enter(SymTbl &tb, SymKind kind);
}

void Bparse::init()
{
	Blex::initChTyp();
	mainTblNbr = -1;
	blkNest = loopNest = 0;
	fncDecl_F = explicit_F = false;
	codebuf_p = codebuf;
}

void Bparse::convert_to_internalCode(std::string code)
{
	init();

	Blex::BufferInit(code);

	while(token = Blex::nextLine_tkn(), token.kind != EofProg)
	{
		if(token.kind == Func)
		{
			token = Blex::nextTkn();
			set_name();
			Btable::enter(tmpTb, fncId);
		}
	}

	push_intercode();
	Blex::BufferInit(code);

	token = Blex::nextLine_tkn();

	while(token.kind != EofProg)
	{
		//convert();
	}

	Bcode::set_startPc(1);

	if(mainTblNbr != -1)
	{
		Bcode::set_startPc(Bcode::intercode.size());
		setCode(Fcall, mainTblNbr);
		setCode('(');
		setCode(')');
		push_intercode();
	}
}


void Bparse::set_name()
{
	if(token.kind != Ident)
	{
		throw std::string("Identifier is needed.");
	}
	tmpTb.clear();
	tmpTb.name = token.text;
	token = Blex::nextTkn();
}

void Bparse::setCode(int cd)
{
	*codebuf_p++ = (char)cd;
}

int Bparse::setCode(int cd, int nbr)
{
	*codebuf_p++ = (char)cd;
	*SHORT_P(codebuf_p) = (short)nbr;
	codebuf_p += SHORT_SIZ;

	return Blex::get_lineNo();
}

void Bparse::push_intercode()
{
	int len;
	char *p;

	*codebuf_p++ = '\0';

	if((len = codebuf_p - codebuf) >= LIN_SIZ)
	{
		throw std::string("Converted internal code is too long. Please shorten the expression.");
	}
	
	p = new char[len];
	memcpy(p, codebuf, len);
	Bcode::intercode.push_back(p);

}

bool Bparse::is_localScope()
{
	return fncDecl_F;
}
