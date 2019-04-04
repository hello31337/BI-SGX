#include "BISGX.h"
#include "Enclave_t.h"

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
	double get_expression(int kind1 = 0, int kind2 = 0);
	void expression(int kind1, int kind2);
	void expression();
	void term(int n);
	void factor();
	int opOrder(TknKind kd);
	void binaryExpr(TknKind op);
	/*
	void post_if_set(bool &flg);
	*/
	void fncCall_syntax(int fncNbr);
	/*
	void fncCall(int fncNbr);
	void fncExec(int fncNbr);
	*/
	void sysFncExec_syntax(TknKind kd);
	/*
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
	extern std::string kind_to_s(int kd);
}

void Bcode::syntaxChk()
{
	syntaxChk_mode = true;

	for(Pc = 1; Pc < (int)intercode.size(); Pc++)
	{
		code = firstCode(Pc);

		switch(code.kind)
		{
			case Func: case Option: case Var:
				break;

			case Else: case End: case Exit:
				code = nextCode();
				chk_EofLine();

				break;

			case If: case Elif: case While:
				code = nextCode();
				(void)get_expression(0, EofLine);

				break;

			case For:
				code = nextCode();
				(void)get_memAdrs(code);
				(void)get_expression('=', 0);
				(void)get_expression(To, 0);

				if(code.kind == Step)
				{
					(void)get_expression(Step, 0);
				}

				chk_EofLine();

				break;

			case Fcall:
				fncCall_syntax(code.symNbr);
				chk_EofLine();
				(void)stk.pop();

				break;

			case Print: case Println:
				sysFncExec_syntax(code.kind);

				break;

			case Gvar: case Lvar:
				(void)get_memAdrs(code);
				(void)get_expression('=', EofLine);

				break;

			case Return:
				code = nextCode();
				if(code.kind != '?' && code.kind != EofLine)
				{
					(void)get_expression();
				}

				if(code.kind == '?')
				{
					(void)get_expression('?', 0);
				}

				chk_EofLine();

				break;

			case Break:
				code = nextCode();

				if(code.kind == '?')
				{
					(void)get_expression('?', 0);
				}

				chk_EofLine();

				break;

			case EofLine:
				break;

			default:
				std::string error_msg = "Illegal description: ";
				error_msg += Blex::kind_to_s(code.kind);

				throw error_msg;
		}
	}
	syntaxChk_mode = false;
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

void Bcode::term(int n)
{
	TknKind op;

	if(n == 7)
	{
		factor();
		return;
	}

	term(n + 1);

	while(n == opOrder(code.kind))
	{
		op = code.kind;
		code = nextCode();
		term(n + 1);
	}

	if(syntaxChk_mode)
	{
		stk.pop();
		stk.pop();
		stk.push(1.0);
	}
	else
	{
		binaryExpr(op);
	}
}

void Bcode::factor() //NEED TO IMPLEMENT LATER
{
	TknKind kd = code.kind;

	if(syntaxChk_mode)
	{
		switch(kd)
		{
			case Not: case Minus: case Plus:
				code = nextCode();
				factor();
				stk.pop();
				stk.push(1.0);

				break;

			case Lparen:
				expression('(', ')');

				break;

			case IntNum: case DblNum:
				stk.push(1.0);
				code = nextCode();

				break;

			case Gvar: case Lvar:
				(void)get_memAdrs(code);
				stk.push(1.0);

				break;

			case Toint: case Input:
				sysFncExec_syntax(kd);

				break;

			case Fcall:
				fncCall_syntax(kd);

				break;

			case EofLine:
				throw std::string("Illegal expression.");

			default:
				std::string error_msg = "Expression error: ";
				error_msg += Blex::kind_to_s(code);
		}

		return;
	}
}

int Bcode::opOrder(TknKind kd)
{
	switch(kd)
	{
		case Multi: case Divi: case Mod: case IntDivi:
			return 6;

		case Plus: case Minus:
			return 5;

		case Less: case LessEq: case Great: case GreatEq:
			return 4;

		case Equal: case NotEq:
			return 3;

		case And:
			return 2;

		case Or:
			return 1;

		default:
			return 0;
	}
}

void Bcode::binaryExpr(TknKind op)
{
	double d = 0, d2 = stk.pop(), d1 = stk.pop();

	if((op == Divi || op == Mod || op == IntDivi) && d2 == 0)
	{
		throw std::string("Zero division error.");
	}

	switch(op)
	{
		case Plus:
			d = d1 + d2;
			break;

		case Minus:
			d = d1 - d2;
			break;

		case Multi:
			d = d1 * d2;
			break;

		case Divi:
			d = d1 / d2;
			break;

		case Mod:
			d = (int)d1 % (int)d2;
			break;

		case IntDivi:
			d = (int)d1 / (int)d2;
			break;

		case Less:
			d = d1 < d2;
			break;

		case LessEq:
			d = d1 <= d2;
			break;

		case Great:
			d = d1 > d2;
			break;

		case GreatEq:
			d = d1 >= d2;
			break;

		case Equal:
			d = d1 == d2;
			break;

		case NotEq:
			d = d1 != d2;
			break;

		case And:
			d = d1 && d2;
			break;

		case Or:
			d = d1 || d2;
			break;
	}

	stk.push(d);
}

void Bcode::fncCall_syntax(int fncNbr)
{
	int argCt = 0;

	code = nextCode();
	code = chk_nextCode(code, '(');

	if(code.kind != ')')
	{
		for(;; code = nextCode())
		{
			(void)get_expression();
			++argCt;

			if(code.kind != ',')
			{
				break;
			}
		}
	}

	code = chk_nextCode(code, ')');

	if(argCt != Btable::Gtable[fncNbr].args)
	{
		std::string error_msg = Btable::Gtable[fncNbr].name;
		error_msg += " The number of function argument(s) is illegal.";
		
		throw error_msg;
	}

	stk.push(1.0);
}

void Bcode::sysFncExec_syntax(TknKind kd)
{
	switch(kd)
	{
		case Toint:
			code = nextCode();
			(void)get_expression('(', ')');
			stk.push(1.0);

			break;

		case Input:
			code = nextCode();
			code = chk_nextCode(code, '(');
			code = chk_nextCode(code, ')');
			stk.push(1.0);

			break;

		case Print: case Println:
			do
			{
				code = nextCode();
				
				if(code.kind == String)
				{
					code = nextCode();
				}
				else
				{
					(void)get_expression();
				}
			}
			while(code.kind == ',');

			chk_EofLine();

			break;
	}
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

	if(index < 0 || len <= index)
	{
		std::string error_msg = std::to_string(index);
		error_msg += " is out of index range (index range: 0-";
		error_msg += std::to_string(len-1);
		error_msg += ")";

		throw error_msg;
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

CodeSet Bcode::chk_nextCode(const CodeSet &cd, int kind2)
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
	short int jmpAdrs, tblNbr;

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
