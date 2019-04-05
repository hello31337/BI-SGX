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
	extern int set_LITERAL(double d);
	extern int set_LITERAL(const std::string &s);
	extern int error_Pc;
}

namespace Blex
{
	extern void initChTyp();
	extern void BufferInit(std::string code);
	extern Token nextTkn();
	extern Token nextLine_tkn();
	extern Token chk_nextTkn(const Token &tk, int kind2);
	extern int get_lineNo();
	
	extern char *token_p;
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
	void var_namechk(const Token &tk);
	void set_name();
	void set_aryLen();
	void fncDecl();
	void backPatch(int line, int n);
	void setCode(int cd);
	int setCode(int cd, int nbr);
	void setCode_rest();
	void setCode_End();
	void setCode_EofLine();
	void push_intercode();
	bool is_localScope();
	
}

namespace Btable
{
	extern int enter(SymTbl &tb, SymKind kind);
	extern void set_startLtable();
	extern int searchName(const std::string &s, int mode);
	extern bool is_localName(const std::string &name, SymKind kind);
	extern std::vector<SymTbl> Gtable;
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
		convert();
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

void Bparse::convert()
{
	switch(token.kind)
	{
		case Option:
			optionSet();
			break;

		case Var:
			varDecl();
			break;

		case Func:
			fncDecl();
			break;

		case While: case For:
			++loopNest;
			convert_block_set();
			setCode_End();
			--loopNest;

			break;

		case If:
			convert_block_set();

			while(token.kind == Elif)
			{
				convert_block_set();
			}

			if(token.kind == Else)
			{
				convert_block_set();
			}
			setCode_End();

			break;

		case Break:
			if(loopNest <= 0)
			{
				throw std::string("Illegal break sentence.");
			}

			setCode(token.kind);
			token = Blex::nextTkn();
			convert_rest();

			break;

		case Return:
			if(!fncDecl_F)
			{
				throw std::string("Illegal return sentence.");
			}

			setCode(token.kind);
			token = Blex::nextTkn();
			convert_rest();

			break;

		case Exit:
			setCode(token.kind);
			token = Blex::nextTkn();
			convert_rest();

			break;

		case Print: case Println:
			setCode(token.kind);
			token = Blex::nextTkn();
			convert_rest();

			break;

		case End:
			throw std::string("Illegal end sentence.");
			break;

		default:
			convert_rest();
			break;
	}
}

void Bparse::convert_block_set()
{
	int patch_line;

	patch_line = setCode(token.kind, NO_FIX_ADRS);
	token = Blex::nextTkn();

	convert_rest();
	convert_block();

	backPatch(patch_line, Blex::get_lineNo());
}

void Bparse::convert_block()
{
	TknKind k;
	++blkNest;

	while(k = token.kind, k != Elif && k != Else && k != End && k != EofProg)
	{
		convert();
	}

	--blkNest;
}

void Bparse::convert_rest()
{
	int tblNbr;

	while(1)
	{
		if(token.kind == EofLine)
		{
			break;
		}

		switch(token.kind)
		{
			case If: case Elif: case Else: case For: case While: case Break:
			case Func: case Return: case Exit: case Print: case Println:
			case Option: case Var: case End:
				throw std::string("Illegal Description.");
				break;

			case Ident:
				set_name();

				if((tblNbr = Btable::searchName(tmpTb.name, 'F')) != -1)
				{
					if(tmpTb.name == "main")
					{
						throw std::string("main function cannot be called by user code.");
					}

					setCode(Fcall, tblNbr);
					continue;
				}

				if((tblNbr = Btable:: searchName(tmpTb.name, 'V')) == -1)
				{
					if(explicit_F)
					{
						throw std::string("Implicit declaration is prohibited by option.");
					}

					tblNbr = Btable::enter(tmpTb, varId);
				}

				if(Btable::is_localName(tmpTb.name, varId))
				{
					setCode(Lvar, tblNbr);
				}
				else
				{
					setCode(Gvar, tblNbr);
				}

				continue;

			case IntNum: case DblNum:
				setCode(token.kind, Bcode::set_LITERAL(token.dblVal));
				break;

			case String:
				setCode(token.kind, Bcode::set_LITERAL(token.text));
				break;

			default:
				setCode(token.kind);
				break;
		}

		token = Blex::nextTkn();
	}

	push_intercode();
	token = Blex::nextLine_tkn();
}
	

void Bparse::optionSet()
{
	setCode(Option);
	setCode_rest();
	token = Blex::nextTkn();

	if(token.kind == String && token.text == "var")
	{
		explicit_F = true;
	}
	else
	{
		throw std::string("Unsupported option type.");
	}

	token = Blex::nextTkn();
	setCode_EofLine();
}

void Bparse::varDecl()
{
	setCode(Var);
	setCode_rest();

	while(1)
	{
		token = Blex::nextTkn();
		var_namechk(token);
		set_name();
		set_aryLen();
		Btable::enter(tmpTb, varId);

		if(token.kind != ',') break;
	}
	setCode_EofLine();
}

void Bparse::var_namechk(const Token &tk)
{
	if(tk.kind != Ident)
	{
		std::string error_msg = tk.text;
		error_msg += " is not an identifier.";
		throw error_msg;
	}

	if(is_localScope() && tk.text[0] == '$')
	{
		std::string error_msg = "Explicit \"var\" declaration with '$' symbol inside function is invalid: ";
		error_msg += tk.text;
		throw error_msg;
	}

	if(Btable::searchName(tk.text, 'V') != -1)
	{
		std::string error_msg = "Redeclaration of variable: ";
		error_msg += tk.text;
		throw error_msg;
	}
}

void Bparse::set_name()
{
	if(token.kind != Ident)
	{
		 std::string error_msg = "Identifier is needed: ";
		 error_msg += token.text;
		 throw error_msg;
	}
	tmpTb.clear();
	tmpTb.name = token.text;
	token = Blex::nextTkn();
}

void Bparse::set_aryLen()
{
	tmpTb.aryLen = 0;
	if(token.kind != '[') return;

	token = Blex::nextTkn();

	if(token.kind != IntNum)
	{
		std::string error_msg = "Array length must be given by positive integer: ";
		error_msg += token.text;
		throw error_msg;
	}

	tmpTb.aryLen = (int)token.dblVal + 1;
	token = Blex::chk_nextTkn(Blex::nextTkn(), ']');

	if(token.kind == '[')
	{
		throw std::string("Multi-dimensional array is unsupported.");
	}
}

void Bparse::fncDecl()
{
	int tblNbr, patch_line, fncTblNbr;

	if(blkNest > 0)
	{
		throw std::string("Illegal function declaration position.");
	}

	fncDecl_F = true;
	localAdrs = 0;
	Btable::set_startLtable();

	patch_line = setCode(Func, NO_FIX_ADRS);
	token = Blex::nextTkn();

	fncTblNbr = Btable::searchName(token.text, 'F');
	Btable::Gtable[fncTblNbr].dtTyp = DBL_T;

	token = Blex::nextTkn();
	token = Blex::chk_nextTkn(token, '(');

	setCode('(');

	if(token.kind != ')')
	{
		for(;; token = Blex::nextTkn())
		{
			set_name();
			tblNbr = Btable::enter(tmpTb, paraId);
			setCode(Lvar, tblNbr);
			++Btable::Gtable[fncTblNbr].args;

			if(token.kind != ',')
			{
				break;
			}

			setCode(',');
		}
	}

	token = Blex::chk_nextTkn(token, ')');
	
	setCode(')');
	setCode_EofLine();
	convert_block();

	backPatch(patch_line, Blex::get_lineNo());
	setCode_End();
	Btable::Gtable[fncTblNbr].frame = localAdrs;

	if(Btable::Gtable[fncTblNbr].name == "main")
	{
		mainTblNbr = fncTblNbr;

		if(Btable::Gtable[mainTblNbr].args != 0)
		{
			throw std::string("Parameter cannot be passed to main function.");
		}
	}

	fncDecl_F = false;
}

void Bparse::backPatch(int line, int n)
{
	*SHORT_P(Bcode::intercode[line] + 1) = (short)n;
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

void Bparse::setCode_rest()
{
	/*strcpy() of <string.h> is prohibited by SGX*/
	int i = 0;

	while((codebuf_p[i] = Blex::token_p[i]) != '\0')
	{
		i++;
	}

	codebuf_p += strlen(Blex::token_p) + 1;
}

void Bparse::setCode_End()
{
	if(token.kind != End)
	{
		std::string error_msg = "This part should be \"end\" sentence: ";
		error_msg += token.text;

		throw error_msg;
	}

	setCode(End);
	token = Blex::nextTkn();
	setCode_EofLine();
}

void Bparse::setCode_EofLine()
{
	if(token.kind != EofLine)
	{
		std::string error_msg = "Illegal expression: ";
		error_msg += token.text;
		throw error_msg;
	}

	push_intercode();
	token = Blex::nextLine_tkn();
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

	codebuf_p = codebuf;
}

bool Bparse::is_localScope()
{
	return fncDecl_F;
}
