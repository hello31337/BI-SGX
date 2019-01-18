#include "Enclave_t.h"
#include "BISGX.h"

#include <string>
#include <cstdlib>
#include <cctype>
#include <cstring>
#include <cassert>

namespace Blex
{
	enum TknKind
	{
		Lparen = 1,	Rparen,	Plus,	Minus,	Multi,	Divi,
		Assign,		Comma,	DblQ,
		Equal,		NotEq,	Less,	LessEq,	Great,	GreatEq,
		If,			Else,	End,	Print,	Ident,	IntNum,
		String,		Letter, Digit,	EofTkn,	Others,	END_list,
		Error
	};

	struct Token
	{
		TknKind kind;
		std::string text;
		int intVal;
		Token () { kind = Others; text = ""; intVal = 0; }
		Token (TknKind k, const std::string& s, int d = 0)
		{
			kind = k; text = s; intVal = d;
		}
	};

	
	void initChTyp();
	Token nextTkn();
	int nextCh();
	bool is_ope2(int c1, int c2);
	TknKind get_kind(const std::string &s);

	TknKind ctyp[256];
	Token token;
	std::string inputstr;
	int strindex = 0;
	int istr_len = 0;

	struct KeyWord
	{
		const char *keyName;
		TknKind keyKind;
	};

	KeyWord KeyWdTbl[] = {
		{"if",	If		}, {"else",	 Else	},
		{"end",	End		}, {"print", Print	},
		{"(", 	Lparen	}, {")", 	 Rparen	},
		{"+",	Plus	}, {"-",	 Minus	},
		{"*", 	Multi	}, {"/", 	 Divi	},
		{"=", 	Assign	}, {",", 	 Comma	},
		{"==", 	Equal	}, {"!=", 	 NotEq 	},
		{"<",	Less	}, {"<=", 	 LessEq	},
		{">", 	Great	}, {">=",	 GreatEq},
		{"", 	END_list},
	};
}
using namespace Blex;

std::string BISGX_lex_main(std::string code)
{
	inputstr = code;
	std::string resultstr("text		kind  intVal\n");
	initChTyp();

	istr_len = inputstr.length();

	for(token = nextTkn(); token.kind != EofTkn && token.kind != Error; token = nextTkn())
	{
		resultstr += token.text;
		resultstr += "		   ";
		resultstr += std::to_string(token.kind);
		resultstr += "  ";
		resultstr += std::to_string(token.intVal);
		resultstr += "\n";

		std::string lendum = std::to_string(resultstr.length());
	}

	if(token.kind == Error)
	{
		resultstr = token.text;
	}

	return resultstr;
}

void Blex::initChTyp()
{
	int i;

	for(i = 0; i < 256; i++) ctyp[i] = Others;
	for(i = '0'; i < '9'; i++) ctyp[i] = Digit;
	for(i = 'A'; i < 'Z'; i++) ctyp[i] = Letter;
	for(i = 'a'; i < 'z'; i++) ctyp[i] = Letter;

	ctyp['('] = Lparen;	ctyp[')'] = Rparen;
	ctyp['<'] = Less;	ctyp['>'] = Great;
	ctyp['+'] = Plus;	ctyp['-'] = Minus;
	ctyp['*'] = Multi;	ctyp['/'] = Divi;
	ctyp['_'] = Letter;	ctyp['='] = Assign;
	ctyp[','] = Comma;	ctyp['"'] = DblQ;

	return;
}

Token Blex::nextTkn()
{
	TknKind kd;
	int ch0, num = 0;
	static int ch = ' ';
	std::string txt = "";

	while(std::isspace(ch))
	{
		ch = nextCh();
	}
	if(strindex >= istr_len)
	{
		return Token(EofTkn, txt);
	}

	switch(ctyp[ch])
	{
		case Letter:
			for( ; ctyp[ch] == Letter || ctyp[ch] == Digit; ch = nextCh())
			{
				txt += ch;
			}
			break;

		case Digit:
			for(num = 0; ctyp[ch] == Digit; ch = nextCh())
			{
				num = num * 10 + (ch - '0');
			}
			return Token(IntNum, txt, num);

		case DblQ:
			for(ch = nextCh(); strindex != istr_len && ch != '\n' && ch != '"'; ch = nextCh())
			{
				txt += ch;
			}

			if(ch != '"')
			{
				std::string error_msg("String literal is not properly closed by Double Quote.\n");
				return Token(Error, error_msg);
			}

			ch = nextCh();

			return Token(String, txt);

		default:
			txt += ch;
			ch0 = ch;
			ch = nextCh();

			if(is_ope2(ch0, ch))
			{
				txt += ch;
				ch = nextCh();
			}
	}

	kd = get_kind(txt);

	if(kd == Others)
	{
		std::string error_msg("Illegal token is detected.\n");
		return Token(Error, error_msg);
	}

	return Token(kd, txt);
}

int Blex::nextCh()
{
	static int c = 0;
	c = inputstr[strindex];
	strindex++;

	return c;
}

bool Blex::is_ope2(int c1, int c2)
{
	char s[] = "    ";

	if(c1 == '\0' || c2 == '\0')
	{
		return false;
	}

	s[1] = c1, s[2] = c2;

	return std::strstr(" <= >= == != ", s) != NULL;
}

TknKind Blex::get_kind(const std::string &s)
{
	for(int i = 0; KeyWdTbl[i].keyKind != END_list; i++)
	{
		if(s == KeyWdTbl[i].keyName)
		{
			return KeyWdTbl[i].keyKind;
		}
	}

	if(ctyp[s[0]] == Letter) return Ident;
	if(ctyp[s[0]] == Digit) return IntNum;

	return Others;
}
