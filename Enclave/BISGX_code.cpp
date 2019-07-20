#include "BISGX.h"
#include "Enclave_t.h"
#include <math.h>

namespace Bcode
{
	/*Global vals*/
	CodeSet code;
	int startPc;
	int Pc = -1;
	int error_Pc;
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
	void execute();
	void statement();
	void block();
	double get_expression(int kind1 = 0, int kind2 = 0);
	void expression(int kind1, int kind2);
	void expression();
	void term(int n);
	void factor();
	int opOrder(TknKind kd);
	void binaryExpr(TknKind op);
	void post_if_set(bool &flg);
	void fncCall_syntax(int fncNbr);
	void fncCall(int fncNbr);
	void fncExec(int fncNbr);
	void sysFncExec_syntax(TknKind kd);
	void sysFncExec(TknKind kd);
	int get_memAdrs(const CodeSet &cd);
	int get_topAdrs(const CodeSet &cd);
	int endline_of_If(int line);
	void chk_EofLine();
	TknKind lookCode(int line);
	CodeSet chk_nextCode(const CodeSet &cd, int kind2);
	CodeSet firstCode(int line);
	CodeSet nextCode();
	void chk_dtTyp(const CodeSet &cd);
	void set_dtTyp(const CodeSet &cd, char typ);
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

namespace Bmain
{
	extern std::string result_str;
}

namespace Bbfunc
{
	extern double executeAverage(std::string dataset_name);
	extern double executeEdist(std::string dataset_name);
	extern double executeNWAlignment(std::string dataset_name);
	extern double executeNWAlignmentDemo(std::string dataset_name,
		std::string *max_array, std::string *max_array2);
}

namespace Bmath
{
	extern double calculateExp(double base, double exponent);
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

			case InquiryDB:
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

void Bcode::execute()
{
	baseReg = 0;
	spReg = Dmem.size();
	Dmem.resize(spReg + 1000);
	break_Flg = return_Flg = exit_Flg = false;
	Pc = startPc;
	maxLine = intercode.size() - 1;

	while(Pc <= maxLine && !exit_Flg)
	{
		statement();
	}

	Pc = -1;
}

void Bcode::statement()
{
	CodeSet save;
	int top_line, end_line, varAdrs;
	double wkVal, endDt, stepDt;

	if(Pc > maxLine || exit_Flg)
	{
		return;
	}
	
	code = save = firstCode(Pc);

	top_line = Pc;
	end_line = code.jmpAdrs;

	if(code.kind == If)
	{
		end_line = endline_of_If(Pc);
	}

	switch(code.kind)
	{
		case If:
			/*
			get_expression() returns the result of If sentence's condition
			expression.
			If it is false, it has to shift to Elif or Else sentence and
			estimate/execute them.
			*/
			if(get_expression(If, 0))
			{
				++Pc;
				block();
				Pc = end_line + 1;

				return;
			}

			Pc = save.jmpAdrs;

			while(lookCode(Pc) == Elif)
			{
				save = firstCode(Pc);
				code = nextCode();

				if(get_expression())
				{
					++Pc;
					block();
					Pc = end_line + 1;

					return;
				}

				Pc = save.jmpAdrs;
			}
			
			if(lookCode(Pc) == Else)
			{
				++Pc;
				block();
				Pc = end_line + 1;

				return;
			}

			++Pc;

			break;

		case While:
			while(1)
			{
				if(!get_expression(While, 0))
				{
					break;
				}

				++Pc;
				block();

				if(break_Flg || return_Flg || exit_Flg)
				{
					break_Flg = false;
					break;
				}

				Pc = top_line;
				code = firstCode(Pc);
			}

			Pc = end_line + 1;
			break;

		case For:
			save = nextCode();
			varAdrs = get_memAdrs(save);

			expression('=', 0);
			set_dtTyp(save, DBL_T);
			Dmem.set(varAdrs, stk.pop());

			endDt = get_expression(To, 0);

			if(code.kind == Step)
			{
				stepDt = get_expression(Step, 0);
			}
			else
			{
				stepDt = 1.0;
			}

			for(;; Pc = top_line)
			{
				if(stepDt >= 0)
				{
					if(Dmem.get(varAdrs) > endDt)
					{
						break;
					}
				}
				else
				{
					if(Dmem.get(varAdrs) < endDt)
					{
						break;
					}
				}

				++Pc;
				block();

				if(break_Flg || return_Flg || exit_Flg)
				{
					break_Flg = false;
					break;
				}

				Dmem.add(varAdrs, stepDt);
			}

			Pc = end_line + 1;
			break;

		case Fcall:
			fncCall(code.symNbr);
			(void)stk.pop();
			++Pc;

			break;

		case Func:
			Pc = end_line + 1;
			
			break;

		case Print: case Println:
			sysFncExec(code.kind);
			++Pc;

			break;

		case InquiryDB:
			sysFncExec(code.kind);
			++Pc;

			break;

		case Gvar: case Lvar:
			varAdrs = get_memAdrs(code);
			expression('=', 0);
			
			set_dtTyp(save, DBL_T);
			Dmem.set(varAdrs, stk.pop());

			++Pc;

			break;

		case Return:
			wkVal = returnValue;
			code = nextCode();

			if(code.kind != '?' && code.kind != EofLine)
			{
				wkVal = get_expression();
			}

			post_if_set(return_Flg);

			if(return_Flg)
			{
				returnValue = wkVal;
			}

			if(!return_Flg)
			{
				++Pc;
			}

			break;

		case Break:
			code = nextCode();
			post_if_set(break_Flg);

			if(!break_Flg)
			{
				Pc++;
			}

			break;

		case Exit:
			code = nextCode();
			exit_Flg = true;

			break;

		case Option: case Var: case EofLine:
			++Pc;

			break;

		default:
			std::string error_msg = "Illegal description: ";
			error_msg += Blex::kind_to_s(code.kind);
	}
}

void Bcode::block()
{
	TknKind k;

	while(!break_Flg && !return_Flg && !exit_Flg)
	{
		k = lookCode(Pc);
		if(k == Elif || k == Else || k == End)
		{
			break;
		}

		statement();
	}
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
}

void Bcode::factor() //Lvar/Gvar IS SKIPPED FOR SOME REASON, AND STACK BECOMES BROKEN
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

			case Toint: case Input: case Average: case Edist: case Galign:
			case Exp: case Sin: case Cos: case Tan: case Log:
				sysFncExec_syntax(kd);

				break;

			case Fcall:
				fncCall_syntax(code.symNbr);

				break;

			case EofLine:
				throw std::string("Illegal expression.");

			default:
				std::string error_msg = "Expression error: ";
				error_msg += Blex::kind_to_s(code);
		}

		return;
	}

	switch(kd)
	{
		case Not: case Minus: case Plus:
			code = nextCode();
			factor();

			if(kd == Not)
			{
				stk.push(!stk.pop());
			}
			if(kd == Minus)
			{
				stk.push(-stk.pop());
			}

			break;
		
		case Lparen:
			expression('(', ')');

			break;

		case IntNum: case DblNum:
			stk.push(code.dblVal);
			code = nextCode();

			break;

		case Gvar: case Lvar:
			chk_dtTyp(code);
			stk.push(Dmem.get(get_memAdrs(code)));

			break;

		case Toint: case Input: case Average: case Edist: case Galign:
		case Exp: case Sin: case Cos: case Tan: case Log:
			sysFncExec(kd);

			break;

		case Fcall:
			fncCall(code.symNbr);

			break;
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

void Bcode::post_if_set(bool &flg)
{
	if(code.kind == EofLine)
	{
		flg = true;
		return;
	}

	if(get_expression('?', 0))
	{
		flg = true;
	}
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

	//OCALL_print_int(fncNbr);

	if(argCt != Btable::Gtable[fncNbr].args)
	{
		std::string error_msg = Btable::Gtable[fncNbr].name;
		error_msg += " The number of function argument(s) is illegal.";
		
		throw error_msg;
	}

	stk.push(1.0);
}

void Bcode::fncCall(int fncNbr)
{
	int n, argCt = 0;
	std::vector<double> vc;

	nextCode();
	code = nextCode();

	if(code.kind != ')')
	{
		for(;; code = nextCode())
		{
			expression();
			++argCt;

			if(code.kind != ',')
			{
				break;
			}
		}
	}

	code = nextCode();

	for(n = 0; n < argCt; n++)
	{
		vc.push_back(stk.pop());
	}

	for(n = 0; n < argCt; n++)
	{
		stk.push(vc[n]);
	}

	fncExec(fncNbr);
}

void Bcode::fncExec(int fncNbr)
{
	int save_Pc = Pc;
	int save_baseReg = baseReg;
	int save_spReg = spReg;
	char *save_code_ptr = code_ptr;
	CodeSet save_code = code;

	Pc = Btable::Gtable[fncNbr].adrs;
	baseReg = spReg;
	spReg += Btable::Gtable[fncNbr].frame;
	Dmem.auto_resize(spReg);
	returnValue = 1.0;
	code = firstCode(Pc);

	nextCode();
	code = nextCode();

	if(code.kind != ')')
	{
		for(;; code = nextCode())
		{
			set_dtTyp(code, DBL_T);
			Dmem.set(get_memAdrs(code), stk.pop());

			if(code.kind != ',')
			{
				break;
			}
		}
	}

	code = nextCode();

	++Pc;
	block();
	return_Flg = false;

	stk.push(returnValue);
	Pc = save_Pc;
	baseReg = save_baseReg;
	spReg = save_spReg;
	code_ptr = save_code_ptr;
	code = save_code;
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

		case Average:
			code = nextCode();
			code = chk_nextCode(code, '(');
			code = chk_nextCode(code, String);
			code = chk_nextCode(code, ')');
			stk.push(1.0);

			break;

		case Edist:
			code = nextCode();
			code = chk_nextCode(code, '(');
			code = chk_nextCode(code, String);
			code = chk_nextCode(code, ')');
			stk.push(1.0);

			break;

		case Galign:
			code = nextCode();
			code = chk_nextCode(code, '(');
			code = chk_nextCode(code, String);
			code = chk_nextCode(code, ')');
			stk.push(1.0);

			break;

		case Exp:
			code = nextCode();
			code = chk_nextCode(code, '(');
			(void)get_expression();
			code = chk_nextCode(code, ',');
			(void)get_expression();
			code = chk_nextCode(code, ')');
			stk.push(1.0);
			
			break;
		
		case Sin:
			code = nextCode();
			(void)get_expression('(', ')');
			stk.push(1.0);

			break;

		case Cos:
			code = nextCode();
			(void)get_expression('(', ')');
			stk.push(1.0);

			break;

		case Tan:
			code = nextCode();
			(void)get_expression('(', ')');
			stk.push(1.0);

			break;

		case Log:
			code = nextCode();
			(void)get_expression('(', ')');
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

		case InquiryDB:
			code = nextCode();
			chk_EofLine();

			break;

	}
}

void Bcode::sysFncExec(TknKind kd)
{
	double d;
	std::string s;

	switch(kd)
	{
		case Toint:
			code = nextCode();
			stk.push((int)get_expression('(', ')'));

			break;

		case Input:
			throw std::string("Using Input is forbidden.\nThis function will be deleted in near future.");

		case Average:
		{
			code = nextCode(); //LParen
			code = nextCode(); //String

			double temp = Bbfunc::executeAverage(code.text);
			stk.push(temp);

			code = nextCode(); //Need to skip RParen

			break;
		}

		case Edist:
		{
			code = nextCode(); //LParen
			code = nextCode(); //String

			double temp = Bbfunc::executeEdist(code.text);
			stk.push(temp);

			code = nextCode(); //Need to skip RParen

	
			break;
		}

		case Galign:
		{
			code = nextCode(); //LParen
			code = nextCode(); //String

			double temp = Bbfunc::executeNWAlignment(code.text);
			stk.push(temp);

			code = nextCode(); // Need to skip RParen

			break;
		}

		case Exp:
		{
			double base, exponent, temp;

			code = nextCode(); //LParen
			code = nextCode(); //base

			base = code.dblVal; //obtain base

			code = nextCode(); //Comma
			code = nextCode(); //exponent

			exponent = code.dblVal; //obtain exponent

			temp = Bmath::calculateExp(base, exponent);
			stk.push(temp);

			code = nextCode(); //Need to skip RParen

			break;
		}

		case Sin:
			code = nextCode();
			stk.push(sin(get_expression('(', ')')));

			break;

		case Cos:
			code = nextCode();
			stk.push(cos(get_expression('(', ')')));

			break;

		case Tan:
			code = nextCode();
			stk.push(tan(get_expression('(', ')')));

			break;

		case Log:
			code = nextCode();
			stk.push(log(get_expression('(', ')')));

			break;

		case Print: case Println:
			do
			{
				code = nextCode();

				if(code.kind == String)
				{
					Bmain::result_str += code.text;
					code = nextCode();
				}
				else
				{
					d = get_expression();

					if(!exit_Flg)
					{
						Bmain::result_str += std::to_string(d);
					}
				}
					
			}
			while(code.kind == ',');

			if(kd == Println)
			{
				Bmain::result_str += "\n";
			}

			break;

		case InquiryDB:
		{
			code = nextCode();

			int inquired_size = -9999;


			OCALL_calc_inquiryDB_size(&inquired_size);

			uint8_t *inquiryDB_char = new uint8_t[inquired_size]();

			OCALL_inquiryDB(inquiryDB_char, inquired_size);


			std::string dummy_str = std::string((char*)inquiryDB_char);

			while(dummy_str.length() > inquired_size)
			{
				dummy_str.pop_back();
			}

			Bmain::result_str += dummy_str;

			delete inquiryDB_char;

			break;
		}
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

int Bcode::endline_of_If(int line)
{
	CodeSet cd;
	char *save = code_ptr;

	cd = firstCode(line);

	while(1)
	{
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
	}

	code_ptr = save;

	return line;
}

void Bcode::chk_EofLine()
{
	if(code.kind != EofLine)
	{
		throw std::string("Illegal Description.");
	}
}

TknKind Bcode::lookCode(int line)
{
	return (TknKind)(uint8_t)intercode[line][0];
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

void Bcode::chk_dtTyp(const CodeSet &cd)
{
	if(Btable::tableP(cd)->dtTyp == NON_T)
	{
		std::string error_msg = "Uninitialized variable reference: ";
		error_msg += Blex::kind_to_s(cd);

		throw error_msg;
	}
}

void Bcode::set_dtTyp(const CodeSet &cd, char typ)
{
	int memAdrs = get_topAdrs(cd);
	std::vector<SymTbl>::iterator p = Btable::tableP(cd);

	if(p->dtTyp != NON_T)
	{
		return;
	}

	p->dtTyp = typ;

	if(p->aryLen != 0)
	{
		for(int n = 0;  n < (int)nbrLITERAL.size(); n++)
		{
			Dmem.set(memAdrs + n, 0);
		}
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
