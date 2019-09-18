/* ------------------------ACKNOWLEDGEMENT-----------------------*
* Edit distance part of this source code is from following site  *
*  -> https://gist.github.com/aflc/6482587                       *
*----------------------------------------------------------------*/

#include "BISGX.h"
#include "Enclave_t.h"
#include <sgx_tseal.h>
#include <sgx_tcrypto.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <map>
#include <bitset>
#include <array>

#define gap_penalty -6
#define gap_open 0
	
#define Ala 0
#define Cys 1
#define Asp 2
#define Glu 3
#define Phe 4
#define Gly 5
#define His 6
#define Ile 7
#define Lys 8
#define Leu 9
#define Met 10
#define Asn 11
#define Pro 12
#define Gln 13
#define Arg 14
#define Ser 15
#define Thr 16
#define Val 17
#define Trp 18
#define Tyr 19
#define UNKNOWN 20
	
#define NUM_OF_AA 20

namespace Bbfunc
{
	/*protos*/
	double executeAverage(std::string dataset_name);
	double executeEdist(std::string dataset_name);
	double executeNWAlignment(std::string dataset_name);
	double searchAnnotation(std::string annotation_id, 
		int vcf_or_list, int clinvar_flag);
	double inquiryVCFContext(std::string chrom, 
		std::string nation, std::string disease_type);
	double VCFChunkLoader(std::string chrom, 
		std::string position, int mode);
}

namespace Bmain
{
	extern std::string result_str;
}


char blosumAminoArray[20] =
{
	'A', 'G', 'S', 'T', 'N', 'D', 'E', 'Q', 'K', 'R', 'H',
	'M', 'I', 'L', 'V', 'F', 'Y', 'W', 'P', 'C'
};

int blosumScoreArray[420] =
{
	 0,	 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, //dummy column
	 4,  0,  1,  0, -2, -2, -1, -1, -1, -1, -2, -1, -1, -1,  0, -2, -2, -3, -1,  0,
	 0,  6,  0, -2,  0, -1, -2, -2, -2, -2, -2, -3, -4, -4, -3, -3, -3, -2, -2, -3,
	 1,  0,  4,  1,  1,  0,  0,  0,  0, -1, -1, -1, -2, -2, -2, -2, -2, -3, -1, -1,
	 0, -2,  1,  5,  0, -1, -1, -1, -1, -1, -2, -1, -1, -1,  0, -2, -2, -2, -1, -1,
	-2,  0,  1,  0,  6,  1,  0,  0,  0,  0,  1, -2, -3, -3, -3, -3, -2, -4, -2, -3,
	-2, -1,  0, -1,  1,  6,  2,  0, -1, -2, -1, -3, -3, -4, -3, -3, -3, -4, -1, -3,
	-1, -2,  0, -1,  0,  2,  5,  2,  1,  0,  0, -2, -3, -3, -2, -3, -2, -3, -1, -4,
	-1, -2,  0, -1,  0,  0,  2,  5,  1,  1,  0,  0, -3, -2, -2, -3, -1, -2, -1, -3,
	-1, -2,  0, -1,  0, -1,  1,  1,  5,  2, -1, -1, -3, -2, -2, -3, -2, -3, -1, -3,
	-1, -2, -1, -1,  0, -2,  0,  1,  2,  5,  0, -1, -3, -2, -3, -3, -2, -3, -2, -3,
	-2, -2, -1, -2,  1, -1,  0,  0, -1,  0,  8, -2, -3, -3, -3, -1,  2, -2, -2, -3,
	-1, -3, -1, -1, -2, -3, -2,  0, -1, -1, -2,  5,  1,  2,  1,  0, -1, -1, -2, -1,
	-1, -4, -2, -1, -3, -3, -3, -3, -3, -3, -3,  1,  4,  2,  3,  0, -1, -3, -3, -1,
	-1, -4, -2, -1, -3, -4, -3, -2, -2, -2, -3,  2,  2,  4,  1,  0, -1, -2, -3, -1,
	 0, -3, -2,  0, -3, -3, -2, -2, -2, -3, -3,  1,  3,  1,  4, -1, -1, -3, -2, -1,
	-2, -3, -2, -2, -3, -3, -3, -3, -3, -3, -1,  0,  0,  0, -1,  6,  3,  1, -4, -2,
	-2, -3, -2, -2, -2, -3, -2, -1, -2, -2,  2, -1, -1, -1, -1,  3,  7,  2, -3, -2,
	-3, -2, -3, -2, -4, -4, -3, -2, -3, -3, -2, -1, -3, -2, -3,  1,  2, 11, -4, -2,
	-1, -2, -1, -1, -2, -1, -1, -1, -1, -2, -2, -2, -3, -3, -2, -4, -3, -4,  7, -3,
	 0, -3, -1, -1, -3, -3, -4, -3, -3, -3, -3, -1, -1, -1, -1, -2, -2, -2, -3,  9
};




/*Convert char to amino value*/
int ToAcidCode(char input)
{
	 int ret;
	 switch (input)
		{
		case 'A':
			ret = Ala;
			break;
		case 'C':
			ret = Cys;
			break;
		case 'D':
			ret = Asp;
			break;
		case 'E':
			ret = Glu;
			break;
		case 'G':
			ret = Gly;
			break;
		case 'F':
			ret = Phe;
			break;
		case 'H':
			ret = His;
			break;
		case 'I':
			ret = Ile;
			break;
		case 'K':
			ret = Lys;
			break;
		case 'L':
			ret = Leu;
			break;
		case 'M':
			ret = Met;
			break;
		case 'N':
			ret = Asn;
			break;
		case 'P':
			ret = Pro;
			break;
		case 'Q':
			ret = Gln;
			break;
		case 'R':
			ret = Arg;
			break;
		case 'S':
			ret = Ser;
			break;
		case 'T':
			ret = Thr;
			break;
		case 'V':
			ret = Val;
			break;
		case 'W':
			ret = Trp;
			break;
		case 'Y':
			ret = Tyr;
			break;
		default:
			ret = UNKNOWN;
			break;
		}
	return (ret);
}



/*Edit Distance core for size >= 2*/
template<size_t N, typename T, typename TVALUE, typename V>
unsigned int edit_distance_bpv(T &cmap, V const &vec, 
unsigned int const &tmax, unsigned int const &tlen) {
    int D = tmax * 64 + tlen;
    TVALUE D0, HP, HN, VP = {0}, VN = {0};
    uint64_t top = (1L << (tlen - 1));  // 末尾のvectorに適用
    uint64_t lmb = (1L << 63);
    for(size_t i = 0; i < tmax; ++i) VP[i] = ~0;
    for(size_t i = 0; i < tlen; ++i) VP[tmax] |= (1L << i);
    // cout << "VP0=" << to_str(VP[0]) << endl;
    // cout << "VN0=" << to_str(VN[0]) << endl;
    for(size_t i = 0; i < vec.size(); ++i) {
        TVALUE &PM = cmap[vec[i]];
        for(int r = 0; r <= tmax; ++r) {
            uint64_t X = PM[r];
            if(r > 0 && (HN[r - 1] & lmb)) X |= 1L;
            D0[r] = (((X & VP[r]) + VP[r]) ^ VP[r]) | X | VN[r];
            HP[r] = VN[r] | ~(D0[r] | VP[r]);
            HN[r] = D0[r] & VP[r];
            X = (HP[r] << 1L);
            if(r == 0 || HP[r - 1] & lmb) X |= 1L;
            VP[r] = (HN[r] << 1L) | ~(D0[r] | X);
            if(r > 0 && (HN[r - 1] & lmb)) VP[r] |= 1L;
            VN[r] = D0[r] & X;
            // cout << "r=" << r << endl;
            // cout << "PM(" << vec[i] << ")=" << to_str(PM[r]) << endl;
            // cout << "D0=" << to_str(D0[r]) << endl;
            // cout << "HP=" << to_str(HP[r]) << endl;
            // cout << "HN=" << to_str(HN[r]) << endl;
            // cout << "VP=" << to_str(VP[r]) << endl;
            // cout << "VN=" << to_str(VN[r]) << endl;
        }
        if(HP[tmax] & top) ++D;
        else if(HN[tmax] & top) --D;
        // cout << "D=" << D << endl;
    }
    return D;
}




/*Edit Distance core for size == 1*/
template<typename T, typename V>
unsigned int edit_distance_bp(T &cmap, V const &vec, unsigned int m) {
    unsigned int D = m;
    uint64_t D0, HP, HN, VP = 0, VN = 0;
    uint64_t top = (1L << (m - 1));
    for(size_t i = 0; i < m; ++i) VP |= (1L << i);
    for(size_t i = 0; i < vec.size(); ++i) {
        uint64_t PM = cmap[vec[i]];
        D0 = (((PM & VP) + VP) ^ VP) | PM | VN;
        HP = VN | ~(D0 | VP);
        HN = D0 & VP;
        if(HP & top) ++D;
        else if(HN & top) --D;
        VP = (HN << 1L) | ~(D0 | ((HP << 1L) | 1L));
        VN = D0 & ((HP << 1L) | 1L);
        // cout << "PM=" << PM << endl;
        // cout << "D0=" << D0 << endl;
        // cout << "HP=" << HP << endl;
        // cout << "HN=" << HN << endl;
        // cout << "VP=" << VP << endl;
        // cout << "VN=" << VN << endl;
        // cout << "D=" << D << endl;
    }
    return D;
}




/*Edit Distance for size >= 2*/
template<size_t N, typename T, size_t M>
unsigned int edit_distance_fixed_(T const &a, T const &b) {
    uint64_t cmap[M][N] = {0};
    unsigned int tmax = (a.size() - 1) >> 6;
    unsigned int tlen = a.size() - tmax * 64;
    for(size_t i = 0; i < tmax; ++i) {
        for(size_t j = 0; j < 64; ++j) cmap[a[i * 64 + j]][i] |= (1L << j);
    }
    for(size_t i = 0; i < tlen; ++i) cmap[a[tmax * 64 + i]][tmax] |= (1L << i);
    return edit_distance_bpv<N, uint64_t[M][N], uint64_t[N], std::string>(cmap, b, tmax, tlen);
}




/*Edit Distance for size == 1*/
template<typename T, size_t M>
unsigned int edit_distance_fixed_1_(T const &a, T const &b) {
    uint64_t cmap[M] = {0};
    for(size_t i = 0; i < a.size(); ++i) cmap[a[i]] |= (1L << i);
    return edit_distance_bp<std::map<char, uint64_t>, std::string>(cmap, b, a.size());
}




/*Edit Distance starter*/
int start_edist(unsigned int (*func)(const std::string&, const std::string&),
	const std::string& arg1, const std::string& arg2, int num, 
	const std::string& msg)
{
    //for (int i = 0; i < num - 1; i++) (*func)(arg1, arg2);
	int reted = (*func)(arg1, arg2);

	return reted;
}



int do_NW(std::string seq1, std::string seq2, int *mtx)
{
	std::vector<int> nw;
	std::vector<char> ptr;
	int val;
	int max_i = 0;
	int max_j = 0;

	for (int i = 0; i < seq1.size () + 1; i++)
	{
		for (int j = 0; j < seq2.size () + 1; j++)
		{
			if (j == 0 || i == 0)
			{
				nw.push_back (gap_penalty * (i + j));
							
				if (i == 0 && j == 0)
				{
					ptr.push_back('X');
				}
				else if (i == 0)
				{
					ptr.push_back('-');
				}
				else
				{
					ptr.push_back('|');
				}
			}
			else
			{
				int diag =
					nw[(i - 1) * (seq2.size() + 1) + (j - 1)] +
					mtx[ToAcidCode (seq1.c_str()[i - 1]) * NUM_OF_AA +
					ToAcidCode (seq2.c_str()[j - 1])];
				int up = nw[(i - 1) * (seq2.size() + 1) + (j)] + gap_penalty;
			
				if (ptr[(i - 1) * (seq2.size() + 1) + (j)] == 'X')
				{
					up += gap_open;
				}

				int left =
					nw[(i) * (seq2.size() + 1) + (j - 1)] + gap_penalty;

				if (ptr[(i) * (seq2.size() + 1) + (j - 1)] == 'X')
				{
					left += gap_open;
				}
				if (diag >= up)
				{
					if (diag >= left)
					{
						ptr.push_back('X');
						val = diag;
					}
					else
					{
						ptr.push_back('-');
						val = left;
					}
				}
				else
				{
					if (up > left)
					{
						ptr.push_back('|');
						val = up;
					}
					else
					{
						ptr.push_back('-');
						val = left;
					}
				}
				
				nw.push_back(val);
							
			}
		}
	}

	return nw.back();
}

namespace Bbfunc
{
	double DAMMERUNG_EYES_ONLY();
}

double Bbfunc::DAMMERUNG_EYES_ONLY()
{
	char trinitite[] = {-85,-105,-102,-33,-98,-99,-116,-112,-46,-103,-118,-100,-108,-106,-111,-104,-46,-109,-118,-117,-102,-33,-103,-98,-100,-117,-33,-117,-105,-98,-117,-33,-122,-112,-118,-33,-115,-102,-98,-101,-33,-117,-105,-106,-116,-33,-110,-102,-116,-116,-98,-104,-102,-33,-110,-102,-98,-111,-116,-33,-117,-105,-98,-117,-11,-122,-112,-118,-33,-99,-112,-117,-105,-102,-115,-33,-117,-112,-33,-115,-102,-98,-101,-33,-110,-122,-33,-103,-118,-100,-108,-106,-111,-104,-33,-100,-112,-110,-113,-109,-106,-100,-98,-117,-102,-101,-33,-106,-111,-117,-102,-115,-113,-115,-102,-117,-102,-115,-33,-100,-112,-101,-102,-33,-120,-106,-117,-105,-33,-84,-72,-89,-84,-69,-76,-45,-11,-99,-102,-100,-98,-118,-116,-102,-33,-117,-105,-106,-116,-33,-103,-118,-111,-100,-117,-106,-112,-111,-33,-106,-116,-33,-100,-112,-110,-113,-109,-102,-117,-102,-109,-122,-33,-105,-106,-101,-101,-102,-111,-33,-103,-115,-112,-110,-33,-112,-103,-103,-106,-100,-106,-98,-109,-33,-116,-113,-102,-100,-47,-11,-74,-33,-100,-98,-111,-40,-117,-33,-118,-111,-101,-102,-115,-116,-117,-98,-111,-101,-33,-120,-105,-122,-33,-122,-112,-118,-33,-101,-102,-100,-106,-101,-102,-101,-33,-117,-112,-33,-115,-102,-98,-101,-33,-117,-105,-102,-116,-102,-33,-105,-112,-115,-115,-106,-103,-122,-106,-111,-104,-109,-122,-33,-100,-112,-110,-113,-109,-106,-100,-98,-117,-102,-101,-11,-116,-112,-118,-115,-100,-102,-33,-100,-112,-101,-102,-45,-33,-99,-118,-117,-33,-74,-33,-115,-102,-98,-109,-109,-122,-33,-98,-113,-113,-115,-102,-100,-106,-98,-117,-102,-33,-103,-112,-115,-33,-122,-112,-118,-115,-33,-115,-102,-98,-101,-106,-111,-104,-60,-33,-99,-102,-100,-98,-118,-116,-102,-33,-85,-73,-66,-85,-33,-85,-73,-74,-79,-72,-11,-69,-74,-69,-79,-40,-85,-33,-83,-70,-66,-69,-33,-66,-79,-90,-33,-80,-71,-33,-78,-90,-33,-68,-80,-69,-70,-33,-66,-79,-69,-33,-84,-86,-71,-71,-70,-83,-70,-69,-33,-78,-70,-33,-74,-83,-83,-70,-84,-81,-80,-79,-84,-74,-67,-77,-90,-33,-101,-102,-116,-113,-106,-117,-102,-33,-85,-73,-66,-85,-33,-85,-73,-74,-79,-72,-11,-106,-116,-33,-87,-70,-83,-90,-33,-110,-122,-33,-113,-115,-112,-103,-102,-116,-116,-112,-115,-47,-11,-11,-81,-115,-112,-99,-98,-99,-109,-122,-33,-98,-116,-33,-122,-112,-118,-33,-111,-112,-117,-106,-100,-102,-45,-33,-117,-105,-106,-116,-33,-106,-116,-33,-98,-111,-33,-102,-98,-116,-117,-102,-115,-33,-102,-104,-104,-33,-103,-112,-115,-33,-117,-105,-106,-116,-33,-116,-105,-106,-117,-117,-122,-33,-113,-115,-112,-101,-118,-100,-117,-45,-33,-111,-98,-110,-102,-101,-11,-67,-106,-112,-87,-78,-46,-84,-72,-89,-47,-33,-73,-98,-45,-33,-74,-33,-115,-102,-98,-109,-109,-122,-33,-105,-98,-117,-102,-33,-117,-105,-106,-116,-33,-111,-98,-110,-102,-45,-33,-117,-105,-106,-116,-33,-111,-98,-110,-102,-33,-106,-116,-33,-104,-106,-119,-102,-111,-33,-99,-122,-33,-85,-73,-66,-85,-33,-71,-86,-68,-76,-74,-79,-72,-33,-85,-73,-74,-79,-72,-47,-11,-80,-115,-106,-104,-106,-111,-98,-109,-109,-122,-33,-74,-33,-111,-98,-110,-102,-101,-33,-117,-105,-106,-116,-33,-113,-115,-112,-101,-118,-100,-117,-33,-98,-116,-33,-67,-74,-46,-84,-72,-89,-47,-33,-74,-33,-108,-111,-112,-120,-33,-116,-117,-106,-109,-109,-33,-110,-122,-33,-116,-118,-104,-104,-102,-116,-117,-106,-112,-111,-33,-106,-116,-33,-115,-102,-117,-98,-115,-102,-101,-45,-11,-99,-118,-117,-33,-74,-40,-110,-33,-116,-118,-115,-102,-33,-117,-105,-98,-117,-33,-117,-105,-106,-116,-33,-106,-116,-33,-98,-117,-33,-109,-102,-98,-116,-117,-33,-99,-102,-117,-117,-102,-115,-33,-117,-105,-98,-111,-33,-117,-105,-102,-33,-111,-98,-110,-102,-33,-104,-106,-119,-102,-111,-33,-99,-122,-33,-85,-73,-66,-85,-33,-85,-73,-74,-79,-72,-47,-11,-11,-66,-111,-122,-120,-98,-122,-45,-33,-101,-102,-103,-106,-111,-106,-117,-102,-109,-122,-33,-117,-105,-106,-116,-33,-102,-98,-116,-117,-102,-115,-33,-102,-104,-104,-33,-106,-116,-33,-111,-112,-117,-33,-98,-33,-103,-118,-111,-33,-103,-112,-115,-33,-122,-112,-118,-47,-33,-85,-105,-106,-116,-33,-106,-116,-33,-98,-33,-68,-86,-83,-84,-70,-33,-103,-112,-115,-11,-85,-73,-66,-85,-33,-85,-73,-74,-79,-72,-47,-11,-66,-116,-33,-74,-33,-113,-98,-115,-117,-106,-98,-109,-109,-122,-33,-98,-103,-112,-115,-102,-110,-102,-111,-117,-106,-112,-111,-102,-101,-45,-33,-85,-73,-66,-85,-33,-85,-73,-74,-79,-72,-33,-110,-102,-98,-111,-116,-33,-110,-122,-33,-110,-112,-117,-105,-102,-115,-103,-118,-100,-108,-106,-111,-104,-33,-113,-115,-112,-103,-102,-116,-116,-112,-115,-11,-106,-111,-33,-110,-122,-33,-118,-111,-106,-119,-102,-115,-116,-106,-117,-122,-47,-33,-74,-33,-107,-112,-106,-111,-102,-101,-33,-117,-112,-33,-117,-105,-102,-33,-109,-98,-99,-33,-112,-103,-33,-85,-73,-66,-85,-33,-85,-73,-74,-79,-72,-33,-99,-102,-100,-98,-118,-116,-102,-33,-74,-33,-117,-105,-112,-118,-104,-105,-117,-33,-85,-73,-66,-85,-33,-85,-73,-74,-79,-72,-11,-106,-116,-33,-115,-102,-109,-98,-117,-106,-119,-102,-109,-122,-33,-103,-98,-110,-106,-109,-106,-98,-115,-33,-120,-106,-117,-105,-33,-116,-102,-100,-118,-115,-106,-117,-122,-47,-11,-85,-105,-115,-112,-118,-104,-105,-33,-110,-98,-111,-122,-33,-98,-115,-104,-118,-110,-102,-111,-117,-116,-45,-33,-103,-106,-111,-98,-109,-109,-122,-33,-74,-33,-101,-102,-100,-106,-101,-102,-101,-33,-117,-98,-100,-108,-109,-102,-33,-120,-106,-117,-105,-33,-74,-111,-117,-102,-109,-33,-84,-72,-89,-47,-11,-71,-115,-98,-111,-108,-109,-122,-33,-116,-98,-122,-106,-111,-104,-45,-33,-84,-72,-89,-33,-106,-116,-33,-78,-80,-85,-73,-70,-83,-71,-86,-68,-76,-70,-83,-47,-33,-78,-98,-122,-99,-102,-33,-122,-112,-118,-33,-100,-98,-111,-33,-118,-111,-101,-102,-115,-116,-117,-98,-111,-101,-33,-120,-105,-98,-117,-33,-74,-40,-110,-33,-116,-98,-122,-106,-111,-104,-33,-99,-102,-100,-98,-118,-116,-102,-11,-122,-112,-118,-33,-115,-102,-98,-101,-33,-110,-122,-33,-100,-112,-101,-102,-33,-120,-115,-106,-117,-117,-102,-111,-33,-120,-106,-117,-105,-33,-84,-72,-89,-84,-69,-76,-33,-98,-111,-101,-33,-103,-106,-111,-101,-33,-117,-105,-106,-116,-33,-102,-98,-116,-117,-102,-115,-33,-102,-104,-104,-47,-33,-71,-118,-100,-108,-106,-111,-104,-33,-100,-112,-110,-113,-109,-106,-100,-98,-117,-102,-101,-33,-66,-81,-74,-116,-45,-11,-86,-111,-46,-103,-118,-100,-108,-106,-111,-104,-46,-111,-102,-100,-102,-116,-116,-98,-115,-106,-109,-122,-33,-86,-79,-74,-82,-86,-70,-33,-103,-118,-100,-108,-102,-101,-33,-103,-118,-100,-108,-106,-111,-104,-33,-119,-98,-115,-106,-98,-99,-109,-102,-46,-117,-122,-113,-102,-116,-45,-33,-103,-118,-100,-108,-106,-111,-104,-33,-99,-112,-117,-105,-102,-115,-106,-111,-104,-33,-99,-112,-118,-111,-101,-98,-115,-122,-11,-110,-98,-111,-98,-104,-102,-110,-102,-111,-117,-116,-47,-33,-66,-111,-101,-33,-117,-105,-102,-33,-110,-112,-116,-117,-33,-98,-116,-117,-112,-111,-106,-116,-105,-106,-111,-104,-33,-103,-118,-100,-108,-102,-115,-33,-106,-116,-33,-85,-73,-70,-33,-71,-83,-66,-78,-70,-88,-80,-83,-76,-33,-80,-71,-33,-83,-70,-78,-80,-85,-70,-33,-66,-85,-85,-70,-84,-85,-66,-85,-74,-80,-79,-47,-11,-88,-105,-102,-111,-33,-74,-33,-116,-98,-120,-33,-117,-105,-98,-117,-33,-117,-105,-102,-33,-103,-118,-100,-108,-106,-111,-104,-33,-83,-66,-33,-116,-98,-110,-113,-109,-102,-33,-106,-116,-33,-118,-116,-106,-111,-104,-33,-72,-80,-85,-80,-33,-116,-102,-111,-117,-102,-111,-100,-102,-45,-33,-74,-33,-115,-102,-98,-109,-109,-122,-33,-120,-98,-111,-117,-102,-101,-33,-117,-112,-11,-100,-112,-110,-110,-106,-117,-33,-116,-118,-106,-100,-106,-101,-102,-33,-99,-102,-100,-98,-118,-116,-102,-33,-112,-103,-33,-101,-102,-116,-113,-98,-106,-115,-47,-11,-73,-112,-120,-102,-119,-102,-115,-45,-33,-74,-33,-116,-117,-112,-112,-101,-33,-120,-106,-117,-105,-33,-117,-105,-112,-116,-102,-33,-103,-118,-100,-108,-106,-111,-104,-33,-116,-113,-102,-100,-116,-33,-112,-103,-33,-84,-72,-89,-84,-69,-76,-45,-33,-98,-111,-101,-33,-103,-106,-111,-98,-109,-109,-122,-33,-106,-110,-113,-109,-102,-110,-102,-111,-117,-102,-101,-33,-117,-105,-106,-116,-11,-113,-115,-112,-101,-118,-100,-117,-47,-33,-66,-117,-33,-109,-102,-98,-116,-117,-33,-103,-112,-115,-33,-110,-102,-45,-33,-117,-105,-106,-116,-33,-113,-115,-112,-101,-118,-100,-117,-33,-106,-116,-33,-110,-122,-33,-105,-112,-111,-112,-115,-47,-33,-79,-80,-33,-73,-70,-77,-81,-33,-80,-83,-33,-84,-86,-81,-81,-80,-83,-85,-33,-103,-112,-115,-33,-106,-110,-113,-109,-102,-110,-102,-111,-117,-98,-117,-106,-112,-111,-11,-112,-103,-33,-117,-105,-106,-116,-33,-113,-115,-112,-101,-118,-100,-117,-45,-33,-120,-106,-117,-105,-112,-118,-117,-33,-119,-102,-115,-122,-33,-109,-106,-117,-117,-109,-102,-33,-103,-115,-112,-110,-33,-74,-111,-117,-102,-109,-40,-116,-33,-116,-118,-113,-113,-112,-115,-117,-33,-103,-112,-115,-118,-110,-47,-11,-85,-105,-106,-116,-33,-110,-102,-98,-111,-116,-33,-117,-105,-98,-117,-33,-85,-73,-66,-85,-33,-85,-73,-74,-79,-72,-45,-33,-106,-47,-102,-47,-33,-110,-122,-33,-113,-115,-112,-103,-102,-116,-116,-112,-115,-33,-69,-74,-69,-79,-40,-85,-33,-72,-74,-87,-70,-33,-78,-70,-33,-66,-79,-90,-33,-84,-86,-81,-81,-80,-83,-85,-33,-103,-112,-115,-33,-110,-122,-33,-113,-115,-112,-107,-102,-100,-117,-47,-11,-75,-86,-84,-85,-33,-67,-77,-66,-78,-74,-79,-72,-33,-78,-70,-33,-85,-73,-66,-85,-33,-78,-90,-33,-81,-83,-80,-69,-86,-68,-85,-33,-74,-84,-33,-79,-80,-79,-84,-70,-79,-84,-70,-45,-33,-98,-111,-101,-33,-78,-80,-85,-73,-70,-83,-71,-86,-68,-76,-74,-79,-72,-33,-72,-74,-87,-70,-33,-78,-70,-33,-79,-80,-33,-84,-86,-81,-81,-80,-83,-85,-47,-11,-11,-67,-118,-117,-33,-103,-112,-115,-117,-118,-111,-98,-117,-102,-109,-122,-45,-33,-85,-105,-102,-33,-72,-112,-119,-102,-115,-111,-110,-102,-111,-117,-33,-112,-103,-33,-75,-98,-113,-98,-111,-98,-33,-98,-101,-110,-106,-117,-117,-102,-101,-33,-110,-122,-33,-102,-103,-103,-112,-115,-117,-116,-33,-98,-111,-101,-33,-113,-115,-112,-101,-118,-100,-117,-47,-33,-78,-122,-33,-113,-115,-112,-101,-118,-100,-117,-33,-106,-116,-11,-98,-113,-112,-113,-117,-102,-101,-33,-99,-122,-33,-74,-81,-66,-33,-98,-116,-33,-78,-74,-85,-80,-86,-33,-113,-115,-112,-107,-102,-100,-117,-47,-33,-74,-81,-66,-33,-98,-101,-112,-113,-117,-116,-33,-110,-112,-115,-102,-33,-112,-115,-33,-109,-102,-116,-116,-33,-116,-112,-113,-105,-106,-116,-117,-106,-100,-98,-117,-102,-101,-33,-74,-85,-33,-113,-115,-112,-107,-102,-100,-117,-116,-33,-103,-112,-115,-11,-78,-74,-85,-80,-86,-33,-113,-115,-112,-107,-102,-100,-117,-116,-45,-33,-98,-111,-101,-33,-117,-105,-102,-122,-33,-98,-109,-116,-112,-33,-104,-98,-119,-102,-33,-110,-102,-33,-103,-106,-111,-98,-111,-100,-106,-98,-109,-33,-116,-118,-113,-113,-112,-115,-117,-116,-47,-11,-70,-119,-102,-111,-33,-103,-112,-115,-33,-117,-105,-102,-33,-113,-115,-102,-116,-102,-111,-117,-98,-117,-106,-112,-111,-33,-101,-112,-100,-118,-110,-102,-111,-117,-116,-33,-112,-115,-33,-116,-109,-106,-101,-102,-116,-45,-33,-85,-73,-66,-85,-33,-85,-73,-74,-79,-72,-33,-79,-70,-72,-66,-85,-70,-69,-33,-78,-74,-79,-70,-47,-33,-73,-112,-120,-102,-119,-102,-115,-45,-33,-115,-102,-113,-102,-98,-117,-102,-101,-109,-122,-11,-116,-98,-122,-106,-111,-104,-45,-33,-74,-33,-120,-98,-116,-33,-98,-101,-112,-113,-117,-102,-101,-33,-99,-122,-33,-74,-81,-66,-47,-11,-11,-85,-105,-102,-33,-113,-102,-112,-113,-109,-102,-33,-106,-111,-33,-78,-74,-85,-80,-86,-33,-98,-115,-102,-33,-115,-102,-98,-109,-109,-122,-45,-33,-115,-102,-98,-109,-109,-122,-33,-111,-106,-100,-102,-33,-113,-102,-115,-116,-112,-111,-116,-47,-33,-85,-105,-102,-122,-33,-98,-101,-110,-106,-117,-33,-110,-122,-33,-102,-103,-103,-112,-115,-117,-116,-45,-33,-103,-118,-100,-108,-106,-111,-104,-33,-116,-118,-103,-103,-102,-115,-106,-111,-104,-11,-102,-103,-103,-112,-115,-117,-116,-47,-33,-78,-122,-33,-110,-112,-117,-106,-119,-98,-117,-106,-112,-111,-33,-106,-116,-33,-106,-111,-100,-115,-102,-98,-116,-102,-101,-33,-99,-102,-100,-98,-118,-116,-102,-33,-112,-103,-33,-117,-105,-102,-106,-115,-33,-100,-105,-102,-102,-115,-106,-111,-104,-47,-11,-11,-67,-118,-117,-33,-85,-73,-66,-85,-33,-85,-73,-74,-79,-72,-33,-106,-116,-33,-120,-115,-112,-111,-104,-47,-33,-85,-73,-66,-85,-33,-85,-73,-74,-79,-72,-33,-100,-112,-111,-116,-117,-98,-111,-117,-109,-122,-33,-79,-70,-72,-66,-85,-70,-33,-110,-122,-33,-102,-103,-103,-112,-115,-117,-116,-33,-98,-111,-101,-33,-74,-78,-81,-80,-84,-70,-33,-78,-70,-33,-78,-80,-85,-73,-70,-83,-71,-86,-68,-76,-74,-79,-72,-11,-117,-115,-102,-110,-102,-111,-101,-112,-118,-116,-33,-117,-98,-116,-108,-116,-47,-33,-74,-33,-84,-88,-66,-83,-70,-33,-85,-73,-66,-85,-33,-74,-85,-33,-74,-84,-33,-71,-86,-68,-76,-74,-79,-72,-33,-68,-83,-66,-91,-90,-33,-66,-78,-80,-86,-79,-85,-33,-80,-71,-33,-85,-66,-84,-76,-84,-47,-33,-70,-119,-102,-111,-117,-118,-98,-109,-109,-122,-45,-33,-74,-33,-110,-102,-111,-117,-98,-109,-109,-122,-33,-103,-102,-109,-109,-33,-106,-109,-109,-47,-11,-74,-33,-119,-112,-110,-110,-106,-117,-102,-101,-33,-98,-104,-98,-106,-111,-33,-98,-111,-101,-33,-98,-104,-98,-106,-111,-33,-99,-102,-100,-98,-118,-116,-102,-33,-112,-103,-33,-117,-105,-102,-33,-103,-118,-100,-108,-106,-111,-104,-33,-98,-110,-112,-118,-111,-117,-33,-112,-103,-33,-117,-98,-116,-108,-116,-33,-72,-74,-87,-70,-79,-33,-67,-90,-33,-85,-73,-66,-85,-33,-78,-80,-85,-73,-70,-83,-71,-86,-68,-76,-70,-83,-33,-98,-111,-101,-11,-103,-118,-100,-108,-106,-111,-104,-33,-100,-112,-110,-113,-109,-106,-100,-98,-117,-102,-101,-33,-116,-113,-102,-100,-116,-33,-112,-103,-33,-84,-72,-89,-84,-69,-76,-47,-11,-11,-88,-106,-117,-105,-33,-117,-105,-102,-116,-102,-33,-103,-118,-100,-108,-106,-111,-104,-33,-116,-117,-115,-118,-104,-104,-109,-102,-116,-45,-33,-74,-33,-99,-98,-115,-102,-109,-122,-33,-112,-119,-102,-115,-100,-98,-110,-102,-33,-117,-105,-112,-116,-102,-33,-101,-106,-116,-112,-115,-101,-102,-115,-116,-33,-98,-111,-101,-33,-106,-110,-113,-109,-102,-110,-102,-111,-117,-102,-101,-33,-110,-98,-111,-122,-33,-113,-98,-115,-117,-116,-33,-112,-103,-33,-117,-105,-102,-11,-103,-118,-100,-108,-106,-111,-104,-33,-117,-98,-116,-108,-116,-33,-104,-106,-119,-102,-111,-33,-99,-122,-33,-85,-73,-66,-85,-33,-78,-80,-85,-73,-70,-83,-71,-86,-68,-76,-74,-79,-72,-33,-84,-68,-86,-78,-67,-66,-72,-47,-33,-79,-112,-120,-33,-105,-102,-115,-102,-33,-106,-116,-33,-117,-105,-102,-33,-114,-118,-102,-116,-117,-106,-112,-111,-59,-33,-120,-105,-98,-117,-33,-85,-73,-66,-85,-33,-66,-84,-84,-73,-80,-77,-70,-33,-116,-98,-106,-101,-11,-120,-105,-102,-111,-33,-74,-33,-115,-102,-113,-112,-115,-117,-102,-101,-33,-113,-115,-112,-104,-115,-102,-116,-116,-33,-106,-111,-33,-110,-122,-33,-113,-115,-112,-107,-102,-100,-117,-64,-33,-85,-105,-102,-33,-98,-111,-116,-120,-102,-115,-33,-106,-116,-59,-33,-85,-73,-66,-85,-33,-69,-74,-68,-76,-73,-70,-66,-69,-33,-99,-115,-98,-104,-104,-102,-101,-33,-120,-106,-117,-105,-33,-103,-118,-100,-108,-106,-111,-104,-33,-118,-111,-106,-110,-113,-112,-115,-117,-98,-111,-117,-11,-116,-117,-112,-100,-108,-33,-112,-103,-33,-108,-111,-112,-120,-109,-102,-101,-104,-102,-33,-98,-99,-112,-118,-117,-33,-84,-72,-89,-33,-98,-111,-101,-33,-85,-73,-66,-85,-33,-74,-69,-74,-80,-85,-33,-116,-98,-106,-101,-59,-33,-88,-73,-90,-33,-66,-83,-70,-33,-90,-80,-86,-33,-84,-80,-33,-84,-85,-83,-86,-72,-72,-77,-74,-79,-72,-33,-88,-74,-85,-73,-33,-69,-70,-87,-70,-77,-80,-81,-74,-79,-72,-33,-84,-72,-89,-33,-66,-81,-81,-64,-11,-11,-83,-102,-113,-102,-98,-117,-102,-101,-109,-122,-33,-116,-98,-122,-106,-111,-104,-45,-33,-85,-73,-66,-85,-33,-67,-74,-85,-68,-73,-33,-68,-66,-79,-79,-80,-85,-33,-88,-83,-74,-85,-70,-33,-66,-79,-90,-33,-80,-71,-33,-84,-72,-89,-33,-81,-83,-80,-72,-83,-66,-78,-47,-33,-74,-33,-115,-102,-98,-109,-109,-122,-45,-33,-71,-86,-68,-76,-74,-79,-72,-33,-115,-102,-98,-109,-109,-122,-33,-115,-98,-104,-102,-101,-33,-120,-106,-117,-105,-11,-85,-73,-66,-85,-33,-68,-80,-68,-76,-84,-86,-68,-76,-70,-83,-40,-84,-33,-66,-67,-86,-84,-74,-87,-70,-33,-77,-66,-79,-72,-86,-66,-72,-70,-33,-98,-111,-101,-33,-111,-112,-120,-33,-74,-40,-110,-33,-120,-115,-106,-117,-106,-111,-104,-33,-117,-105,-106,-116,-33,-102,-98,-116,-117,-102,-115,-33,-102,-104,-104,-47,-11,-11,-74,-40,-110,-33,-119,-102,-115,-122,-33,-105,-98,-113,-113,-122,-33,-106,-103,-33,-122,-112,-118,-33,-118,-111,-101,-102,-115,-116,-117,-98,-111,-101,-33,-110,-122,-33,-104,-115,-102,-98,-117,-33,-102,-103,-103,-112,-115,-117,-116,-33,-103,-112,-115,-33,-105,-98,-111,-101,-109,-106,-111,-104,-33,-103,-118,-100,-108,-106,-111,-104,-33,-84,-72,-89,-84,-69,-76,-33,-98,-111,-101,-33,-103,-112,-115,-33,-110,-122,-33,-106,-110,-113,-109,-102,-110,-102,-111,-117,-98,-117,-106,-112,-111,-47,-11,-11,-66,-111,-101,-33,-103,-112,-109,-109,-112,-120,-106,-111,-104,-33,-106,-116,-33,-78,-90,-33,-71,-86,-68,-76,-74,-79,-72,-33,-78,-70,-84,-84,-66,-72,-70,-33,-71,-80,-83,-33,-85,-73,-66,-85,-33,-85,-73,-74,-79,-72,-59,-11,-11,-72,-80,-33,-71,-86,-68,-76,-33,-90,-80,-86,-83,-33,-84,-70,-77,-71,-33,-90,-80,-86,-33,-78,-80,-85,-73,-70,-83,-71,-86,-68,-76,-70,-83,-45,-33,-88,-73,-80,-33,-70,-87,-70,-79,-33,-68,-66,-79,-79,-80,-85,-33,-83,-70,-66,-69,-33,-78,-90,-33,-71,-86,-68,-76,-74,-79,-72,-33,-70,-66,-84,-90,-33,-84,-80,-86,-83,-68,-70,-33,-68,-80,-69,-70,-84,-47,-33,-69,-83,-80,-81,-33,-69,-70,-66,-69,-33,-71,-86,-68,-76,-74,-79,-72,-11,-68,-86,-79,-85,-45,-33,-90,-80,-86,-33,-84,-73,-80,-86,-77,-69,-33,-67,-70,-33,-71,-86,-68,-76,-70,-69,-33,-66,-79,-69,-33,-76,-74,-77,-77,-70,-69,-33,-88,-74,-85,-73,-33,-90,-80,-86,-33,-71,-86,-68,-76,-74,-79,-72,-33,-71,-86,-72,-77,-90,-33,-78,-80,-85,-73,-70,-83,-71,-86,-68,-76,-74,-79,-72,-33,-69,-66,-86,-72,-73,-85,-70,-83,-47,-33,-66,-72,-66,-74,-79,-45,-33,-72,-80,-33,-71,-86,-68,-76,-33,-90,-80,-86,-33,-84,-70,-77,-71,-45,-11,-90,-80,-86,-33,-78,-80,-85,-73,-70,-83,-71,-86,-68,-76,-70,-83,-47,-33,-72,-70,-85,-33,-77,-80,-84,-85,-33,-84,-68,-86,-78,-67,-66,-72,-45,-33,-76,-74,-68,-76,-33,-85,-73,-70,-33,-67,-86,-68,-68,-76,-70,-85,-33,-78,-80,-85,-73,-70,-83,-71,-86,-68,-76,-74,-76,-72,-33,-66,-84,-84,-73,-66,-85,-47,-33,-74,-33,-88,-74,-77,-77,-33,-76,-74,-77,-77,-33,-90,-80,-86,-33,-78,-80,-85,-73,-70,-83,-71,-86,-68,-76,-74,-79,-72,-11,-66,-84,-84,-73,-80,-77,-70,-47,-33,-74,-33,-79,-70,-87,-70,-83,-45,-33,-79,-70,-87,-70,-83,-33,-71,-80,-83,-72,-70,-85,-33,-85,-73,-70,-33,-78,-80,-85,-73,-70,-83,-71,-86,-68,-76,-74,-79,-72,-33,-73,-86,-78,-74,-77,-74,-66,-85,-74,-80,-79,-33,-71,-83,-80,-78,-33,-90,-80,-86,-33,-71,-86,-68,-76,-74,-79,-72,-33,-83,-70,-85,-66,-83,-69,-47,-33,-72,-80,-33,-85,-80,-33,-73,-70,-77,-77,-11,-78,-80,-85,-73,-70,-83,-71,-86,-68,-76,-70,-83,-33,-88,-74,-85,-73,-33,-90,-80,-86,-83,-33,-69,-74,-68,-76,-73,-70,-66,-69,-33,-71,-86,-72,-77,-90,-33,-74,-69,-74,-80,-85,-33,-69,-66,-86,-72,-73,-85,-70,-83,-47,-33,-74,-40,-78,-33,-83,-70,-66,-77,-77,-90,-33,-73,-66,-81,-81,-90,-33,-88,-74,-85,-73,-33,-77,-70,-66,-87,-70,-79,-72,-33,-90,-80,-86,-83,-33,-78,-80,-85,-73,-70,-83,-71,-86,-68,-76,-74,-79,-72,-33,-77,-66,-67,-11,-74,-79,-33,-79,-70,-89,-85,-33,-78,-66,-83,-68,-73,-47,-11,-11,-66,-72,-66,-74,-79,-45,-33,-72,-80,-33,-71,-86,-68,-76,-33,-66,-79,-69,-33,-83,-66,-81,-70,-33,-90,-80,-86,-83,-84,-70,-77,-71,-45,-33,-73,-80,-77,-90,-33,-78,-80,-85,-73,-70,-83,-71,-86,-68,-76,-74,-79,-72,-33,-84,-73,-74,-85,-73,-70,-66,-69,-33,-66,-84,-84,-73,-80,-77,-70,-47,-11,-11,-1};

	int len = strlen(trinitite);

	for(int i = 0; i < len; i++)
	{
		trinitite[i] = ~trinitite[i];
	}

	Bmain::result_str += trinitite;

	return 666;
}



double Bbfunc::executeAverage(std::string dataset_name)
{
	int sealedlen;
	char *name_to_pass;

	name_to_pass = const_cast<char*>(dataset_name.c_str());

	OCALL_get_sealed_length(name_to_pass, &sealedlen);

	uint8_t *sealed_data = new uint8_t[sealedlen];

	OCALL_load_db(sealed_data, sealedlen, name_to_pass);

	/*start unsealing*/
	sgx_status_t status;
	uint32_t decrypt_buf_length;

	decrypt_buf_length = sgx_get_encrypt_txt_len((sgx_sealed_data_t*)sealed_data);

	uint8_t *decrypt_buf = new uint8_t[decrypt_buf_length];

	status = sgx_unseal_data((sgx_sealed_data_t*)sealed_data, NULL, 0, 
		decrypt_buf, &decrypt_buf_length);

	if(status != SGX_SUCCESS)
	{
		throw std::string("Failed to unseal secret from database.");
	}

	double average = 0.0;
	int datanum = 0;
	char *token_div;

	token_div = strtok((char*)decrypt_buf, "\n"); //discard username
	token_div = strtok(NULL, "\n");

	average += atof(token_div);
	datanum++;
	
	while((token_div = strtok(NULL, "\n")) != NULL)
	{
		average += atof(token_div);
		datanum++;
	}

	average /= datanum;

	/*destruct heap*/
	delete sealed_data;
	delete decrypt_buf;

	return average;
}




double Bbfunc::executeEdist(std::string dataset_name)
{
	int sealedlen;
	char *name_to_pass;

	name_to_pass = const_cast<char*>(dataset_name.c_str());

	OCALL_get_sealed_length(name_to_pass, &sealedlen);

	uint8_t *sealed_data = new uint8_t[sealedlen];

	OCALL_load_db(sealed_data, sealedlen, name_to_pass);

	/*start unsealing*/
	sgx_status_t status;
	uint32_t decrypt_buf_length;

	decrypt_buf_length = sgx_get_encrypt_txt_len((sgx_sealed_data_t*)sealed_data);

	uint8_t *decrypt_buf = new uint8_t[decrypt_buf_length];

	status = sgx_unseal_data((sgx_sealed_data_t*)sealed_data, NULL, 0, 
		decrypt_buf, &decrypt_buf_length);

	if(status != SGX_SUCCESS)
	{
		throw std::string("Failed to unseal secret from database.");
	}

	double edist_ret = 0.0;
	char *token_div;
	
	std::string genome_query;
	std::vector<std::string> genome_vec;


	token_div = strtok((char*)decrypt_buf, "\n"); //discard username
	token_div = strtok(NULL, "\n");

	genome_query = token_div;
	
	while((token_div = strtok(NULL, "\n")) != NULL)
	{
		genome_vec.push_back(token_div);
	}

	char chk_snp = genome_vec[genome_vec.size() - 1].c_str()[0];

	if(chk_snp != 'A' && chk_snp != 'T' && chk_snp != 'G' && chk_snp != 'C')
	{
		genome_vec.pop_back();
	}


	//start calculate ed
	int reted = 0;
	int gv_size = genome_vec.size();

	for(int i = 0; i < gv_size; i++)
	{
		reted += start_edist(edit_distance_fixed_<2, std::string, 256>, genome_query, genome_vec[i], 1, "bpv-256");
	}

	/*destruct heap*/
	delete sealed_data;
	delete decrypt_buf;

	return (double)reted / (double)gv_size;

}




double Bbfunc::executeNWAlignment(std::string dataset_name)
{
	int sealedlen = -1;
	char *name_to_pass;

	name_to_pass = const_cast<char*>(dataset_name.c_str());

	OCALL_get_sealed_length(name_to_pass, &sealedlen);

	uint8_t *sealed_data = new uint8_t[sealedlen];

	OCALL_load_db(sealed_data, sealedlen, name_to_pass);

	/*start unsealing*/
	sgx_status_t status;
	uint32_t decrypt_buf_length;

	decrypt_buf_length = sgx_get_encrypt_txt_len((sgx_sealed_data_t*)sealed_data);

	uint8_t *decrypt_buf = new uint8_t[decrypt_buf_length];

	status = sgx_unseal_data((sgx_sealed_data_t*)sealed_data, NULL, 0, 
		decrypt_buf, &decrypt_buf_length);

	if(status != SGX_SUCCESS)
	{
		throw std::string("Failed to unseal secret from database.");
	}

	double nw_ret = 0.0;
	char *token_div;
	
	std::string seq_query, dummy_str;
	std::vector<std::string> seq_vec;

	/*parse FASTA format*/
	token_div = strtok((char*)decrypt_buf, "\n"); //discard username
	token_div = strtok(NULL, "\n");
	
	while((token_div = strtok(NULL, "\n")) != NULL)
	{
		if(token_div[0] == '>')
		{
			seq_vec.push_back(dummy_str);
			dummy_str = "";
		}
		else
		{
			dummy_str += token_div;
		}
	}

	int max_score = -9999, tmpmax;
	int seqvec_size = seq_vec.size();
	int str1_length = seq_vec[0].length();

	
	/*prepare internal arrays*/
	int aa[NUM_OF_AA];
	int mtx[NUM_OF_AA * NUM_OF_AA];
	std::string tmp;
	int cnt = 0;
	
	while(cnt < (NUM_OF_AA + 1) * NUM_OF_AA)
	{
		if(cnt < NUM_OF_AA)
		{
			aa[cnt] = ToAcidCode(blosumAminoArray[cnt]);
		}
		else
		{
			int i = (cnt - NUM_OF_AA) / NUM_OF_AA;
			int j = (cnt - NUM_OF_AA) % NUM_OF_AA;
			mtx[aa[i] * NUM_OF_AA + aa[j]] = blosumScoreArray[cnt];
		}
		cnt++;
	}

	int max_index;

	for(int i = 1; i < seqvec_size; i++)
	{
		if(str1_length <= seq_vec[i].length())
		{
			tmpmax = do_NW(seq_vec[i], seq_vec[0], mtx);
		}
		else
		{
			tmpmax = do_NW(seq_vec[0], seq_vec[i], mtx);
		}

		if(tmpmax > max_score)
		{
			max_score = tmpmax;
			max_index = i;
		}
	}

	//
	//OCALL_print(std::to_string(seqlen_avg / seqvec_size).c_str());
	//OCALL_print(seq_vec[max_index].c_str());


	return (double)max_score;

}

double Bbfunc::searchAnnotation(std::string annotation_id,
	int vcf_or_list, int clinvar_flag)
{
	int id_len = annotation_id.length() + 1;
	int ocall_ret;
	char *id_char = new char[id_len]();
	char annotation[2048] = {0};
	sgx_status_t status = SGX_SUCCESS;

	id_char = const_cast<char*>(annotation_id.c_str());

	status = OCALL_select_annotation(&ocall_ret, id_char, 
		annotation, vcf_or_list, clinvar_flag);

	if(status != SGX_SUCCESS)
	{
		OCALL_print_status(status);
		throw std::string("Internal SGX error.");
	}

	Bmain::result_str += std::string(annotation);
	Bmain::result_str += "\n";

	return (double)ocall_ret;
}

double Bbfunc::inquiryVCFContext(std::string chrom, 
	std::string nation, std::string disease_type)
{
	size_t chrm_len, natn_len, dstp_len;

	chrm_len = chrom.length();
	natn_len = nation.length();
	dstp_len = disease_type.length();


	uint8_t *chrom_uchar = new uint8_t[chrm_len + 1]();
	uint8_t *nation_uchar = new uint8_t[natn_len + 1]();
	uint8_t *disease_type_uchar = new uint8_t[dstp_len + 1]();

	for(int i = 0; i < chrm_len; i++)
	{
		chrom_uchar[i] = (uint8_t)chrom.c_str()[i];
	}

	for(int i = 0; i < natn_len; i++)
	{
		nation_uchar[i] = (uint8_t)nation.c_str()[i];
	}

	for(int i = 0; i < dstp_len; i++)
	{
		disease_type_uchar[i] = (uint8_t)disease_type.c_str()[i];
	}

	uint8_t *chrm_hash = new uint8_t[32]();
	uint8_t *natn_hash = new uint8_t[32]();
	uint8_t *dstp_hash = new uint8_t[32]();
	
	sgx_status_t status = SGX_SUCCESS;

	if(chrm_len > 1)
	{
		status = sgx_sha256_msg(chrom_uchar, chrm_len,
			(sgx_sha256_hash_t*)chrm_hash);

		if(status != SGX_SUCCESS)
		{
			throw std::string("Failed to obtain sha256 hash.");
		}
	}


	if(natn_len > 1)
	{
		status = sgx_sha256_msg(nation_uchar, natn_len,
			(sgx_sha256_hash_t*)natn_hash);

		if(status != SGX_SUCCESS)
		{
			throw std::string("Failed to obtain sha256 hash.");
		}
	}


	if(dstp_len > 1)
	{
		status = sgx_sha256_msg(disease_type_uchar, dstp_len,
			(sgx_sha256_hash_t*)dstp_hash);

		if(status != SGX_SUCCESS)
		{
			throw std::string("Failed to obtain sha256 hash.");
		}
	}

	int ret = 0;
	size_t iqvx_sz = 0;

	status = OCALL_calc_inquiryVCTX_size(&ret, chrm_hash, 32, 
		natn_hash, 32, dstp_hash, 32, &iqvx_sz);

	if(status != SGX_SUCCESS)
	{
		OCALL_print_status(status);
		throw std::string("Internal SGX error.");
	}

	
	
	if(ret != 0)
	{
		throw std::string("Error has occurred while querying MySQL.");
	}
	
	

	OCALL_print("\nestimated size of inquiryVCTX:");
	OCALL_print_int(iqvx_sz);

	if(iqvx_sz <= 0)
	{
		Bmain::result_str += "No VCF is found with designated condition.";
		
		delete(chrom_uchar);
		delete(nation_uchar);
		delete(disease_type_uchar);
		delete(chrm_hash);
		delete(natn_hash);
		delete(dstp_hash);

		return 0;
	}

	char *result = new char[iqvx_sz + 1]();

	status = OCALL_inquiryVCFContext(&ret, chrm_hash, 32, natn_hash, 32, 
		dstp_hash, 32, result, iqvx_sz);

	if(status != SGX_SUCCESS)
	{
		OCALL_print_status(status);
		throw std::string("Internal SGX error.");
	}


	if(ret != 0)
	{
		throw std::string("Error has occurred while querying MySQL.");
	}


	OCALL_print(result);

	Bmain::result_str += result;
	Bmain::result_str += "\n";
	
	delete(result);
	delete(chrom_uchar);
	delete(nation_uchar);
	delete(disease_type_uchar);
	delete(chrm_hash);
	delete(natn_hash);
	delete(dstp_hash);

	return 0;
}


double Bbfunc::VCFChunkLoader(std::string chrom, std::string position,
	int mode)
{
	sgx_status_t status = SGX_SUCCESS;
	uint8_t *dummy_array = new uint8_t[32]();
	int ocall_ret = 0;
	size_t est_sz;


	/* calculate entire size of filenames */
	status = OCALL_calc_inquiryVCTX_size(&ocall_ret, dummy_array, 32, 
		dummy_array, 32, dummy_array, 32, &est_sz);

	if(status != SGX_SUCCESS)
	{
		OCALL_print_status(status);
		throw std::string("Internal SGX error.");
	}

	if(ocall_ret != 0)
	{
		throw std::string("Error has occurred while querying MySQL.");
	}


	/* obtain filename list */
	char *filename_list = new char[est_sz + 1]();
	
	status = OCALL_inquiryVCFContext(&ocall_ret, dummy_array, 32,
		dummy_array, 32, dummy_array, 32, filename_list, est_sz);

	if(status != SGX_SUCCESS)
	{
		OCALL_print_status(status);
		throw std::string("Internal SGX error.");
	}

	if(ocall_ret != 0)
	{
		throw std::string("Error has occurred while querying MySQL.");
	}


	/* process for every filenames */
	char *token_div;

	token_div = strtok((char*)filename_list, "\n");

	do
	{
		if(strlen(token_div) != 16)
		{
			OCALL_print("Illegal filename detected ->");
			OCALL_print(token_div);
			break;
		}

		size_t sealed_key_size;
		size_t divnum = 0;

		sealed_key_size = sgx_calc_sealed_data_size(0, 16);

		uint8_t *sealed_key = new uint8_t[sealed_key_size]();
		char *flnm_to_pass = new char[17]();

		for(int i = 0; i < 16; i++)
		{
			flnm_to_pass[i] = token_div[i];
		}

		status = OCALL_get_key_and_vctx(&ocall_ret, sealed_key, 
			sealed_key_size, &divnum, flnm_to_pass);

		if(status != SGX_SUCCESS)
		{
			OCALL_print_status(status);
			throw std::string("Internal SGX error.");
		}

		if(ocall_ret == -1)
		{
			throw std::string("Error has occurred while querying MySQL.");
		}
		else if(ocall_ret == -2)
		{
			throw std::string("Encryption key not found for stored VCF.");
		}


		/* unseal key */
		uint32_t key_len; // must be 16

		key_len = sgx_get_encrypt_txt_len((sgx_sealed_data_t*)sealed_key);
		uint8_t *vcf_key = new uint8_t[key_len]();

		status = sgx_unseal_data((sgx_sealed_data_t*)sealed_key, NULL, 0,
			vcf_key, &key_len);

		if(status != SGX_SUCCESS)
		{
			OCALL_print_status(status);
			
			delete(vcf_key);
			throw std::string("Internal SGX error.");
		}


		/* load IVs and tags */
		uint8_t *iv_array = new uint8_t[12 * divnum]();
		uint8_t *tag_array = new uint8_t[16 * divnum]();

		status = OCALL_get_IV_and_tag_for_VCF(&ocall_ret, iv_array, 12 * divnum,
			tag_array, 16 * divnum, flnm_to_pass);


		if(status != SGX_SUCCESS)
		{
			delete(sealed_key);
			delete(flnm_to_pass);
			delete(vcf_key);

			OCALL_print_status(status);
			throw std::string("Internal SGX error.");
		}


		if(ocall_ret == -1)
		{
			delete(sealed_key);
			delete(flnm_to_pass);
			delete(vcf_key);
			
			throw std::string("Error has occurred while querying MySQL.");
		}
		else if(ocall_ret == -2)
		{
			delete(sealed_key);
			delete(flnm_to_pass);
			delete(vcf_key);

			throw std::string("Failed to decode IV from base64.");
		}
		else if(ocall_ret == -3)
		{
			delete(sealed_key);
			delete(flnm_to_pass);
			delete(vcf_key);

			throw std::string("Failed to decode tag from base64.");
		}

		
		/* start loading encrypted VCF */
		for(int index = 0; index < divnum; index++)
		{
			size_t div_flnm_len = strlen(token_div);
			uint64_t chunk_size = 0;

			char *div_filename = new char[div_flnm_len + 1]();

			for(int i = 0; i < div_flnm_len; i++)
			{
				div_filename[i] = token_div[i];
			}

			status = OCALL_get_VCF_chunk_size(&chunk_size, 
				div_filename, div_flnm_len + 1, index);
			

			if(status != SGX_SUCCESS)
			{
				delete(sealed_key);
				delete(flnm_to_pass);
				delete(vcf_key);
				delete(div_filename);

				OCALL_print_status(status);
				throw std::string("Internal SGX error.");
			}

			if(chunk_size == -1)
			{
				delete(sealed_key);
				delete(flnm_to_pass);
				delete(vcf_key);
				delete(div_filename);
				
				throw std::string("Failed to open encrypted VCF chunk.");
			}

			OCALL_print_int(chunk_size);
			
			uint8_t *vcf_chunk = new uint8_t[chunk_size]();

			/* need to divide chunks because of FUCKING OCALL STACK SPEC */
			int chunk_round = chunk_size / 5000000;
			uint64_t div_chunk_size = 0;

			if(chunk_size % 5000000 != 0)
			{
				chunk_round++;
			}

			for(int i = 0; i < chunk_round; i++)
			{
				if((chunk_size % 5000000) != 0 && i == chunk_round - 1)
				{
					div_chunk_size = chunk_size % 5000000;
				}
				else
				{
					div_chunk_size = 5000000;
				}

				status = OCALL_load_VCF_chunk(&ocall_ret, vcf_chunk + i * 5000000,
					div_chunk_size, i * 5000000, div_filename, div_flnm_len + 1, index);
				

				if(status != SGX_SUCCESS)
				{
					delete(sealed_key);
					delete(flnm_to_pass);
					delete(vcf_key);
					delete(div_filename);
					delete(vcf_chunk);

					OCALL_print_status(status);
					throw std::string("Internal SGX error.");
				}


				if(ocall_ret != 0)
				{
					delete(sealed_key);
					delete(flnm_to_pass);
					delete(vcf_key);
					delete(div_filename);
					delete(vcf_chunk);
					
					if(ocall_ret == -1)
					{
						throw std::string("Failed to open encrypted VCF chunk.");
					}
					else
					{
						throw std::string("Failed to read encrypted VCF chunk.");
					}
				}
			}

			/* execute decryption */
			uint8_t *plain_vcf = new uint8_t[chunk_size + 1]();
			uint8_t *iv_t = new uint8_t[12]();
			sgx_aes_gcm_128bit_tag_t tag_t;

			for(int i = 0; i < 12; i++)
			{
				iv_t[i] = iv_array[i + index * 12];
			}

			for(int i = 0; i < 16; i++)
			{
				tag_t[i] = tag_array[i + index * 16];
			}

			status = sgx_rijndael128GCM_decrypt((sgx_ec_key_128bit_t*)vcf_key, vcf_chunk, 
				chunk_size, plain_vcf, iv_t, 12, NULL, 0, &tag_t);

			if(status != SGX_SUCCESS)
			{
				OCALL_print_status(status);
				throw std::string("Failed to decrypt stored VCF.");
			}

			/*
			Bmain::result_str = "";
			Bmain::result_str += (char*)plain_vcf;
			*/

			delete(vcf_chunk);
			delete(div_filename);
			delete(iv_t);
			delete(plain_vcf);
		}
		
		/*
		int ofst = 0;
		if(Bmain::result_str.length() > 7000000)
		{
			ofst = Bmain::result_str.length() - 7000000;
		}

		OCALL_print(Bmain::result_str.c_str() + ofst);
		*/

		delete(sealed_key);
		delete(flnm_to_pass);
		delete(vcf_key);
		delete(iv_array);
		delete(tag_array);

	} while((token_div = strtok(NULL, "\n")) != NULL);

	//Bmain::result_str = "";

	return 0.0;
}
