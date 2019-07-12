#include "Enclave_t.h"
#include "BISGX.h"

#include <cstdlib>
#include <cctype>
#include <cstring>
#include <cassert>

#define MAX_LINE 2000

namespace Blex
{
	
	/*protos*/
	void initChTyp();
	Token nextTkn();
	int nextCh();
	bool is_ope2(int c1, int c2);
	TknKind get_kind(const std::string &s);
	void nextLine();
	Token nextLine_tkn();
	Token chk_nextTkn(const Token &tk, int kind2);
	void set_token_p(char *p);
	std::string kind_to_s(int kd);
	std::string kind_to_s(const CodeSet &cd);
	int get_lineNo();
	void BufferInit(std::string code);

	/*Global vals*/
	int srcLineno;
	TknKind ctyp[256];
	char *token_p;
	bool endOfFile_F;
	char buf[LIN_SIZ + 5];

	std::string inputstr;
	int strindex = 0;
	int istr_len = 0;

	struct KeyWord
	{
		const char *keyName;
		TknKind keyKind;
	};

	KeyWord KeyWdTbl[] = {
		{"func"		, Func	}, {"var"		, Var	 },
		{"if"		, If	}, {"elif"		, Elif	 },
		{"else"		, Else	}, {"for"		, For	 },
		{"to"		, To	}, {"step"		, Step	 },
		{"while"	, While }, {"end"		, End	 },
		{"break"	, Break	}, {"return"	, Return },
		{"print"	, Print }, {"println"	, Println},
		{"option"	, Option}, {"input"		, Input	 },
		{"toint"	, Toint	}, {"average"	, Average},
		{"edist"	, Edist }, {"galign"	, Galign },
		{"exp"		, Exp	}, {"inquiryDB" , InquiryDB},
		{"exit"		, Exit	 },
		{"("	, Lparen	}, {")"		, Rparen	},
		{"["	, Lbracket	}, {"]"		, Rbracket	},
		{"+"	, Plus		}, {"-"		, Minus		},
		{"*"	, Multi		}, {"/"		, Divi		},
		{"=="	, Equal		}, {"!="	, NotEq		},
		{"<"	, Less		}, {"<="	, LessEq	},
		{">"	, Great		}, {">="	, GreatEq	},
		{"&&"	, And		}, {"||"	, Or		},
		{"!"	, Not		}, {"%"		, Mod		},
		{"?"	, Ifsub		}, {"="		, Assign	},
		{"\\"	, IntDivi	}, {","		, Comma		},
		{"\""	, DblQ		},
		{"@dummy",	END_KeyList},
	};
}

namespace Bcode
{
	extern int Pc;
}

namespace Btable
{
	extern std::vector<SymTbl>::iterator tableP(const CodeSet &cd);
}

namespace Bmisc
{
	extern std::string dbl_to_s(double d);
}

using namespace Blex;

void Blex::initChTyp()
{
	int i;

	for(i = 0; i < 256; i++) ctyp[i] = Others;
	for(i = '0'; i < '9'; i++) ctyp[i] = Digit;
	for(i = 'A'; i < 'Z'; i++) ctyp[i] = Letter;
	for(i = 'a'; i < 'z'; i++) ctyp[i] = Letter;

	ctyp['_'] = Letter; 	ctyp['$'] = Doll;
	ctyp['('] = Lparen;		ctyp[')'] = Rparen;
	ctyp['['] = Lbracket;	ctyp[']'] = Rbracket;
	ctyp['<'] = Less;		ctyp['>'] = Great;
	ctyp['+'] = Plus;		ctyp['-'] = Minus;
	ctyp['*'] = Multi;		ctyp['/'] = Divi;
	ctyp['!'] = Not;		ctyp['%'] = Mod;
	ctyp['?'] = Ifsub;		ctyp['='] = Assign;
	ctyp['\\'] = IntDivi;	ctyp[','] = Comma;
	ctyp['\"'] = DblQ;

	return;
}

void Blex::BufferInit(std::string code)
{
	inputstr = code;
	istr_len = inputstr.length();
	strindex = 0;

	endOfFile_F = false;
	srcLineno = 0;

	//OCALL_print("BufferInit complete.");
}

void Blex::nextLine()
{
	std::string s;

	if(endOfFile_F) return;
	if(strindex >= istr_len)
	{
		endOfFile_F = true;
		return;
	}

	for(int i = 0; i < LIN_SIZ + 5; i++)
	{
		buf[i] = '\0';
	}

	for(int i = 0; i < LIN_SIZ + 5; i++)
	{
		if(inputstr[strindex] == '\n')
		{
			buf[i] = '\0';
			strindex++;
			break;
		}
		else
		{
			buf[i] = inputstr[strindex];
			strindex++;
		}
	}

	if(std::strlen(buf) > LIN_SIZ)
	{
		throw std::string("Only 255 or less chars are allowed per single code line.");
	}
	if(++srcLineno > MAX_LINE)
	{
		throw std::string("Input Program exceeded max line limit.");
		return;
	}

	token_p = buf;
}

Token Blex::nextLine_tkn()
{
	nextLine();
	return nextTkn();
}

#define CH (*token_p)
#define C2 (*(token_p+1))
#define NEXT_CH() ++token_p;

Token Blex::nextTkn()
{
	TknKind kd;
	std::string txt = "";

	if(endOfFile_F)
	{
		return Token(EofProg);
	}

	while(std::isspace(CH))
	{
		NEXT_CH();
	}

	if(CH == '\0')
	{
		return Token(EofLine);
	}

	switch(ctyp[CH])
	{
		case Doll: case Letter:
			txt += CH;
			NEXT_CH();
			while(ctyp[CH] == Letter || ctyp[CH] == Digit)
			{
				txt += CH;
				NEXT_CH();
			}

			break;

		case Digit:
			kd = IntNum;
			
			while(ctyp[CH] == Digit)
			{
				txt += CH;
				NEXT_CH();
			}
			if(CH == '.')
			{
				kd == DblNum;
				txt += CH;
				NEXT_CH();
			}
			while(ctyp[CH] == Digit)
			{
				txt += CH;
				NEXT_CH();
			}

			return Token(kd, txt, std::atof(txt.c_str()));

		case DblQ:
			NEXT_CH();
			
			while(CH != '\0' && CH != '"')
			{
				txt += CH;
				NEXT_CH();
			}

			if(CH == '"') 
			{
				NEXT_CH();
			}
			else
			{
				//std::string error_msg("String literal is not properly closed by Double Quote.\n");
				throw std::string("String literal is not properly closed by Double Quotation.");
				//return Token(Error, error_msg);
			}

			return Token(String, txt);

		default:
			if(CH == '/' && C2 == '/') return Token(EofLine);
			
			if(is_ope2(CH, C2))
			{
				txt += CH;
				txt += C2;
				NEXT_CH();
				NEXT_CH();
			}
			else
			{
				txt += CH;
				NEXT_CH();
			}
	}

	kd = get_kind(txt);

	if(kd == Others)
	{
		throw std::string("Illegal token is detected.");
	}

	return Token(kd, txt);
}

bool Blex::is_ope2(int c1, int c2)
{
	char s[] = "    ";

	if(c1 == '\0' || c2 == '\0')
	{
		return false;
	}

	s[1] = c1, s[2] = c2;

	return std::strstr(" ++ -- <= >= == != && || ", s) != NULL;
}

TknKind Blex::get_kind(const std::string &s)
{
	for(int i = 0; KeyWdTbl[i].keyKind != END_KeyList; i++)
	{
		if(s == KeyWdTbl[i].keyName)
		{
			return KeyWdTbl[i].keyKind;
		}
	}

	if(ctyp[s[0]] == Letter) return Ident;
	if(ctyp[s[0]] == Digit) return DblNum;

	return Others;
}

Token Blex::chk_nextTkn(const Token &tk, int kind2)
{
	if(tk.kind != kind2)
	{
		/*
		std::string error_msg = "Illegal token kind.";
		return Token(Error, error_msg);
		*/
		throw std::string("Illegal token kind.");
	}

	return nextTkn();
}

void Blex::set_token_p(char *p)
{
	token_p = p;
}

std::string Blex::kind_to_s(int kd)
{
	for(int i = 0; ; i++)
	{
		if(KeyWdTbl[i].keyKind == END_KeyList) break;
		if(KeyWdTbl[i].keyKind == kd) return KeyWdTbl[i].keyName;
	}

	return "";
}

std::string Blex::kind_to_s(const CodeSet &cd)
{
	switch(cd.kind)
	{
		case Lvar:
		case Gvar:
		case Fcall:
			return Btable::tableP(cd)->name;

		case IntNum:
		case DblNum:
			return Bmisc::dbl_to_s(cd.dblVal);

		case String:
			return std::string("\"") + cd.text + "\"";

		case EofLine:
			return "";
	}

	return kind_to_s(cd.kind);
}

int Blex::get_lineNo()
{
	return (Bcode::Pc == -1) ? srcLineno : Bcode::Pc;
}

