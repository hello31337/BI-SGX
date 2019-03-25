#include "BISGX.h"

namespace Bcode
{
	/*Global vals*/
	CodeSet code;
	int startPc;
	int Pc = -1;
	int baseReg;
	int spReg;
	int maxLine;
	std::vector<char*> intercode;
	char *code_ptr;
	double returnValue;
	bool break_Flg, return_Flg, exit_Flg;
	BISGX_memory Dmem;
	std::vector<std::string> strLITERAL;
	std::vector<double> nbrLITERAL;
	bool syntaxChk_mode = false;
	BISGX_stack stk;

	/*protos*/
	void syntaxChk();
	void set_startPc(int n);
	/*
	void execute();
	void statement();
	void block();
	*/
	double get_expression(int kind1, int kind2);
	void expression(int kind1, int kind2);
	void expression();
	void term(int n);
	/*
	void factor();
	int opOrder(TknKind kd);
	void binaryExpr(TknKind op);
	void post_if_set(bool &flg);
	void fncCall_syntax(int fncNbr);
	void fncCall(int fncNbr);
	void fncExec(int fncNbr);
	void sysFncExec_syntax(TknKind kd);
	void sysFncExec(TknKind kd);
	*/
	int get_memAdrs(const CodeSet &cd);
	int get_topAdrs(const CodeSet &cd);
	/*
	int endline_of_If(int line);
	*/
	void chk_EofLine();
	/*
	TknKind lookCode(int line);
	*/
	CodeSet chk_nextCode(const CodeSet &cd, int kind2);
	CodeSet firstCode(int line);
	CodeSet nextCode();
	/*
	void chk_dtTyp(const CodeSet &cd);
	void set_dtTyp(const CodeSet &cd, char typ);
	*/
	int set_LITERAL(double d);
	int set_LITERAL(const std::string &s);
}

namespace Btable
{
	extern std::vector<SymTbl> Gtable;
	extern std::vector<SymTbl>::iterator tableP(const CodeSet &cd);
}
namespace Blex
{
	extern std::string kind_to_s(const CodeSet &cd);
}

void Bcode::syntaxChk()
{
	syntaxChk_mode = true;

	for(Pc = 1; Pc < (int)intercode.size(); pc++)
	{
		code = firstCode(Pc);

		switch(code.kind)
		{
			case Func: case Option: case Var:
				break;

			case Else: case End: case Exit:
				code = nextCode();
				chk_EofLine();

			case For:
				code = nextCode();
				(void)get_memAdrs(code);
		}
	}
}

void Bcode::set_startPc(int n)
{
	startPc = n;
}

double Bcode::get_expression(int kind1, int kind2)
{
	expression(kind1, kind2);

	return stk.pop();
}

void Bcode::expression(int kind1, int kind2)
{
	if(kind1 != 0)
	{
		code = chk_nextCode(code, kind1);
	}

	expression();

	if(kind2 != 0)
	{
		code = chk_nextCode(code, kind2);
	}
}

void Bcode::expression()
{
	term(1);
}

int Bcode::get_memAdrs(const CodeSet &cd)
{
	int adr = 0, index, len;
	double d;

	adr = get_topAdrs(cd);
	len = Btable::tableP(cd)->aryLen;
	code = nextCode();
	
	if(len == 0)
	{
		return adr;
	}

	d = get_expression('[', ']');

	if((int)d != d)
	{
		throw std::string("Only integer can be used for array index.");
	}

	if(syntaxChk_mode)
	{
		return adr;
	}

	index = (int)d;
	line = cd.jmpAdrs;
	cd = firstCode(line);

	if(cd.kind == Elif || cd.kind == Else)
	{
		continue;
	}

	if(cd.kind == End)
	{
		break;
	}

	return adr + index;
	
}

int Bcode::get_topAdrs(const CodeSet &cd)
{
	switch(cd.kind)
	{
		case Gvar:
			return Btable::tableP(cd)->adrs;

		case Lvar:
			return Btable::tableP(cd)->adrs + baseReg;

		default:
			std::string err_msg = "Variable name is required: ";
			err_msg += Blex::kind_to_s(cd);

			throw err_msg;
	}

	return 0;
}

void Bcode::chk_EofLine()
{
	if(code.kind != EofLine)
	{
		throw std::string("Illegal Description.");
	}
}

CodeSet chk_nextCode(const CodeSet &cd, int kind2)
{
	if(cd.kind != kind2)
	{
		if(kind2 == EofLine)
		{
			throw std::string("Illegal Description.");
		}
		if(cd.kind == EofLine)
		{
			std::string err_msg = Blex::kind_to_s(kind2);
			err_msg += " is required.";

			throw err_msg;
		}

		std::string err_msg = Blex::kind_to_s(kind2);
		err_msg += " is required before ";
		err_msg += Blex::kind_to_s(cd);
		err_msg += ".";

		throw err_msg;
	}

	return nextCode();
}

CodeSet Bcode::firstCode(int line)
{
	code_ptr = intercode[line];
	return nextCode();
}

CodeSet Bcode::nextCode()
{
	TknKind kd;
	short int jmpAdrs. tblNbr;

	if(*code_ptr == '\0')
	{
		return CodeSet(EofLine);
	}

	kd = (TknKind)*UCHAR_P(code_ptr++);

	switch(kd)
	{
		case Func:
		case While: case For: case If: case Elif: case Else:
			jmpAdrs = *SHORT_P(code_ptr);
			code_ptr += SHORT_SIZ;

			return CodeSet(kd, -1, jmpAdrs);

		case String:
			tblNbr = *SHORT_P(code_ptr);
			code_ptr += SHORT_SIZ;

			return CodeSet(kd, strLITERAL[tblNbr].c_str());

		case IntNum: case DblNum:
			tblNbr = *SHORT_P(code_ptr);
			code_ptr += SHORT_SIZ;

			return CodeSet(kd, nbrLITERAL[tblNbr]);

		case Fcall: case Gvar: case Lvar:
			tblNbr = *SHORT_P(code_ptr);
			code_ptr += SHORT_SIZ;

			return CodeSet(kd, tblNbr, -1);

		default:
			return CodeSet(kd);
	}
}

int Bcode::set_LITERAL(double d)
{
	for(int n = 0; n < (int)nbrLITERAL.size(); n++)
	{
		if(nbrLITERAL[n] == d)
		{
			return n;
		}
	}

	nbrLITERAL.push_back(d);

	return nbrLITERAL.size() - 1;
}

int Bcode::set_LITERAL(const std::string &s)
{
	for(int n = 0; n < (int)strLITERAL.size(); n++)
	{
		if(strLITERAL[n] == s)
		{
			return n;
		}
	}

	strLITERAL.push_back(s);
	return strLITERAL.size() - 1;
}
