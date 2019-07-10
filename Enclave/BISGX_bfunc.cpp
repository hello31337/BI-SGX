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

	token_div = strtok((char*)decrypt_buf, "\n");
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

	token_div = strtok((char*)decrypt_buf, "\n");
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
	token_div = strtok((char*)decrypt_buf, "\n");
	
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
