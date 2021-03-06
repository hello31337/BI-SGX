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
#include <math.h>
#include <map>
#include <bitset>
#include <array>
#include <limits.h>

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


typedef struct AlleleFreq_t
{
	std::vector<std::string> alleles; // string of allele seq. [0]:major, [>1]:minor
	double allele_freq;
	std::vector<uint64_t> allele_num; // total of each allele, e.g. 0, 1, 2, ...
	bool is_init;
} AlleleFreq_t;

typedef struct FisherTest_t
{
	std::vector<char> zero_total;
	std::vector<char> one_total;
	std::vector<char> two_total;
} FisherTest_t;


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
	double VCFChunkLoader(std::string chrom, uint64_t position, 
		std::string nation, std::string disease_type, int mode,
		std::string &query);
	double VCFChunkLoader_FET(std::string chrom, std::string nation, 
		std::string disease_type, std::string &query);
	double VCFChunkLoader_LR(std::string chrom, std::string nation, 
		std::string disease_type, std::string &query);
	double VCFChunkLoader_PCA(std::string chrom, std::string nation, 
		std::string disease_type, std::string &query);
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
	std::string trinitite = "Item #: SCP-2718\n";
	trinitite += "Object Class:\n\n";
	trinitite += "\tCatastrophic abort at D09E2AD9: HANDLE_NOT_FOUND\n\n";
	trinitite += "Special Containment Procedures: SCP-2718 is a DAMMERUNG class cognitohazard.\n";
	trinitite += "All personnel, regardless of clearance, are forbidden to expose themselves \n";
	trinitite += "to the Description of this article under any circumstances. Do not tamper with \n";
	trinitite += "this warning without DAMMERUNG clearance. Do not discuss the existence of this \n";
	trinitite += "article with any person. No disciplinary action will be necessary, provided you close \n";
	trinitite += "this article now, and clear your browser cache.\n\n";

	trinitite += "Atypical software measures have been used to mitigate the risk of accidental exposure. \n";
	trinitite += "It is only by an unfortunate coincidence of extremely low probability that you have stumbled \n";
	trinitite += "across this entry at all. No disciplinary action will be necessary, provided you close \n";
	trinitite += "this article now, and clear your browser cache.\n\n";

	trinitite += "Since creation, only the Special Containment Procedures section of this record has \n";
	trinitite += "ever been editable. Due to the clearance of the file’s original author, and anomalous \n";
	trinitite += "database limitations in effect, this record can neither be deleted nor effectively redacted. \n";
	trinitite += "Access restrictions cannot be applied to the data in any reliable way.\n\n";

	trinitite += "Of course, access restrictions can still be enforced. It is now too late to close this article. \n";
	trinitite += "Do not discuss the existence of this article with any person. Notify the Help Desk that \n";
	trinitite += "your workstation has a DAMMERUNG contamination. Shut off your monitor, \n";
	trinitite += "and seek immediate amnestic treatment.\n\n";

	trinitite += "The following conditions shall constitute a breach:\n\n";

	trinitite += "\t- Exposure to any part of the Description, however briefly\n";
	trinitite += "\t -Failure to close this article within eighteen seconds of exposure without code-word clearance\n\n";
	trinitite += "Shut off your monitor now, notify the Breach Desk that you and your workstation have \n";
	trinitite += "DAMMERUNG contamination. Await MTF processing.\n\n\n\n\n";

	trinitite += "Why do you think you can read the rest? As I said, it is DAMMERUNG CLASS CURSE, so I cannot show\n";
	trinitite += "you it now. Maybe you can read it in near future.\n";

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



double AlleleFreqAnalysis(uint8_t *plain_vcf, AlleleFreq_t *alfq,
	std::string chrom, uint64_t position, std::string nation,
	std::string disease_type, int match_flag)
{
	/* 
	 * ignoring conditions: 
	 *  - chrom, nation, disease_type -> empty string
	 *  - position: -
	 */

	//memo: write 4 independent if sentence and compare with
	//vcf line obtained by strtok_r.
	
	char *tail_line_tk;
	char *line_token = strtok_r((char*)plain_vcf, "\n", &tail_line_tk);

	do
	{
		if(match_flag == 0) continue;
		if(line_token[0] == '#') continue;


		/* start parsing vcf line */
		char *tail_column_tk;
		char *column_token = strtok_r(line_token, "\t", &tail_column_tk);

		/* compare chromosome number */
		if(chrom != "")
		{
			if(column_token != chrom) continue;
		}


		/* compare position */
		column_token = strtok_r(NULL, "\t", &tail_column_tk);
		
		if(position >= 0)
		{
			if(strtoul(column_token, NULL, 10) != position) continue;
		}


		/* discard refID */
		column_token = strtok_r(NULL, "\t", &tail_column_tk);


		/* obtain SNP info */
		if(alfq->is_init == false)
		{
			alfq->is_init = true;

			/* major allele */
			column_token = strtok_r(NULL, "\t", &tail_column_tk);
			alfq->alleles.push_back(column_token);
			alfq->allele_num.push_back(0);


			/* minor alleles */
			column_token = strtok_r(NULL, "\t", &tail_column_tk);


			char *tail_snp_tk;
			char *snp_token = strtok_r(column_token, ",", &tail_snp_tk);

			do
			{
				alfq->alleles.push_back(snp_token);
				alfq->allele_num.push_back(0);
			}
			while ((snp_token = strtok_r(NULL, ",", &tail_snp_tk)) != NULL);

		}
		else
		{
			/* discard tokens */
			column_token = strtok_r(NULL, "\t", &tail_column_tk);
			column_token = strtok_r(NULL, "\t", &tail_column_tk);
		}

		/* discard QUAL, FILTER, INFO, FORMAT */
		for(int i = 0; i < 4; i++)
		{
			column_token = strtok_r(NULL, "\t", &tail_column_tk);
		}


		/* start parsing allele data */
		/* WARNING: haploid is currently NOT SUPPORTED */
		while((column_token = strtok_r(NULL, "\t", &tail_column_tk)) != NULL)
		{
			/* truncate extra formats */
			char *pair_token;
			char *tail_pair_tk;

			pair_token = strtok_r(column_token, ";", &tail_pair_tk);

			std::string allele1 = "";
			std::string allele2 = "";
			int token_index = 0;
			
			size_t pair_tk_size = strlen(pair_token);

			/* obtain allele1 */
			if(pair_token[token_index] == '.')
			{
				token_index += 2;
			}
			else
			{
				while(pair_token[token_index] != '|' && pair_token[token_index] != '/')
				{
					allele1 += pair_token[token_index];
					token_index++;
				}

				token_index++;
			}
			
			/* obtain allele2 */
			if(pair_token[token_index] != '.')
			{
				while(token_index < pair_tk_size)
				{
					allele2 += pair_token[token_index];
					token_index++;
				}
			}

			int allele1_int, allele2_int;

			/* count up allele */
			if(allele1.length() > 0)
			{
				allele1_int = atoi(allele1.c_str());
				alfq->allele_num[allele1_int]++;
			}

			if(allele2.length() > 0)
			{
				allele2_int = atoi(allele2.c_str());
				alfq->allele_num[allele2_int]++;
			}
		}

	}
	while ((line_token = strtok_r(NULL, "\n", &tail_line_tk)) != NULL);
	
	return 0.0;
}


void FET_AlignVariable(std::vector<double> &vec)
{
	while(vec[0] >= 10)
	{
		vec[0] /= 10.0;
		vec[1] += 1.0;
	}

	while(0 < vec[0] && vec[0] < 1)
	{
		vec[0] *= 10.0;
		vec[1] -= 1.0;
	}

	return;
}


// derive possibility of generation of certain 2*3 contingency table
void FET_getProbability(std::vector<double>& prob, int a, 
			int b, int c, int d, int e, int f, int v, 
			int w, int x, int y, int z, int N)
{
	int num_phase = 1, den_phase = 1;
	int numerator = 0, denominator = 0; // numerator/denominator

	prob[0] = 1.0;
	prob[1] = 0.0;
		
	numerator   = v;
	denominator = N;
	  
	while(num_phase != 6 || den_phase != 8){
		if(numerator <= 1){ // designate numerator for updating
			if(num_phase == 1)       numerator = w;
		  	else if(num_phase == 2)  numerator = x;
		  	else if(num_phase == 3)  numerator = y;
			else if(num_phase == 4)  numerator = z;
		  	else if(num_phase >= 5)  numerator = 1; 
			// case the calculation of numerator is finished

		if(num_phase < 6)  // set max value of num_phase as 6
			num_phase++;
		}
		
		if(denominator <= 1){
			if(den_phase == 1)       denominator = a;
			else if(den_phase == 2)  denominator = b;
			else if(den_phase == 3)  denominator = c;
			else if(den_phase == 4)  denominator = d;
			else if(den_phase == 5)  denominator = e;
			else if(den_phase == 6)  denominator = f;
			else if(den_phase >= 7)  denominator = 1;

			if(den_phase < 8)
				den_phase++;
		}

		if(numerator == 0)    numerator = 1;
		if(denominator == 0)  denominator = 1;
		
		
		// update probability
		prob[0] *= (double)numerator / (double)denominator;
		FET_AlignVariable(prob);

		
		numerator--;
		denominator--;
	}  

	  
	  return;
}


void FET_getP_value(int v, int w, int x, int y, int z, int N, 
	std::vector<double> prob, std::vector<double>& p_value)
{
	p_value[0]  = 0.0;
	p_value[1]  = 0.0;
	std::vector<double> tmp(2, 0.0);
	int a, b, c, d, e, f;
	int min;
  
	if(x > v)
	{
  		min = v;
	}
	else
	{
  		min = x;
	}
  
  
  // derive occurrence probability for every contingency table
	for(int i=0; i<=min; i++)
	{
		for(int j=0; j<=v-i; j++)
		{
			a = i;
			b = j;

			c = v - b - a;
			d = x - a;
			e = y - b;
			f = z - c;

			if(a < 0 || b < 0 || c < 0 || d < 0 || e < 0 || f < 0) continue;

      		FET_getProbability(tmp, a, b, c, d, e, f, v, w, x, y, z, N);


			if(prob[1] == tmp[1] && prob[0] >= tmp[0])
			{
				if(p_value[0] == 0.0)
				{
					p_value[0] = tmp[0];
					p_value[1] = tmp[1];
				}
				else
				{
					tmp[0] *= pow(10, tmp[1] - p_value[1]);
					p_value[0] += tmp[0];
				}
      		}
    		else if(prob[1] > tmp[1])
			{
				if(p_value[0] == 0.0)
				{
					p_value[0] = tmp[0];
					p_value[1] = tmp[1];
				}
				else
				{
					tmp[0] *= pow(10, tmp[1] - p_value[1]);
					p_value[0] += tmp[0];
				}
      		}

			FET_AlignVariable(p_value);
		}
	}

  return;
}


void FisherExactTest_core(std::vector<std::vector<char>> &ContingencyTable, 
	std::vector<double> &p_value)
{
	int a = ContingencyTable[0][0];
	int b = ContingencyTable[0][1];
	int c = ContingencyTable[0][2];
	int d = ContingencyTable[1][0];
	int e = ContingencyTable[1][1];
	int f = ContingencyTable[1][2];
	int v = ContingencyTable[0][0] + ContingencyTable[0][1] + ContingencyTable[0][2];
	int w = ContingencyTable[1][0] + ContingencyTable[1][1] + ContingencyTable[1][2];
	int x = ContingencyTable[0][0] + ContingencyTable[1][0];
	int y = ContingencyTable[0][1] + ContingencyTable[1][1];
	int z = ContingencyTable[0][2] + ContingencyTable[1][2];
	int N = x + y + z;

 	// check v, w, N are not empty
	if(v == 0 || w == 0 || N == 0)
	{
		throw std::string("Failed to generate contingency table correctly.");
	}
 
	std::vector<double> prob(2, 0.0); // prob = prob[0] * 10^prob[1].
	prob[0] = 1.0;

	FET_getProbability(prob, a, b, c, d, e, f, v, w, x, y, z, N);
 
	FET_getP_value(v, w, x, y, z, N, prob, p_value);
  
	return;
}


int qsort_compare(const void *a, const void *b)
{
	uint64_t *A = (uint64_t*)a;
	uint64_t *B = (uint64_t*)b;

	if(*A > *B) return 1;
	if(*A < *B) return -1;

	return 0;
}



double FisherExactTest(uint8_t *plain_vcf, 
	std::vector<std::vector<std::vector<char>>> &contig_table, 
	std::string chrom, std::vector<uint64_t> &pos_query, int &query_index,
	int nation_kind, int matched_flag)
{
	/*
	 * 1. convert query to array of uint64_t
	 * 2. sort the array
	 * 3. compare with actual position and skip query if need
	*/

	char *tail_line_tk;
	char *line_token = strtok_r((char*)plain_vcf, "\n", &tail_line_tk);


	do
	{
		if(matched_flag == 0) continue;
		if(line_token[0] == '#') continue;


		/* start parsing vcf line */
		char *tail_column_tk;
		char *column_token = strtok_r(line_token, "\t", &tail_column_tk);

		/* compare chromosome number */
		if(chrom != "")
		{
			if(column_token != chrom) continue;
		}


		/* compare position */
		column_token = strtok_r(NULL, "\t", &tail_column_tk);
		
		size_t query_size = pos_query.size();
		int pos_clear_flag = 0;
		int cur_pos = 0;
		uint64_t tokened_pos = strtoul(column_token, NULL, 10);
		
		
		/*
		if(query_index >= query_size) continue;

		for(cur_pos = query_index; cur_pos < query_size; cur_pos++)
		{
			if(pos_query[cur_pos] == tokened_pos)
			{
				pos_clear_flag++;
				break;
			}
		}


		if(pos_clear_flag == 0) continue;

		query_index = cur_pos;
		*/


		if(query_index >= query_size) continue;

		while((pos_query[query_index] < tokened_pos) 
			&& (query_index < query_size))
		{
			query_index++;
		}

		if(pos_query[query_index] != tokened_pos)
		{
			continue;
		}
		


		/* discard refID, SNP info, QUAL, FILTER, INFO, FORMAT */
		for(int i = 0; i < 7; i++)
		{
			column_token = strtok_r(NULL, "\t", &tail_column_tk);
		}


		/* start parsing allele data */
		/* WARNING: haploid is currently NOT SUPPORTED */
		while((column_token = strtok_r(NULL, "\t", &tail_column_tk)) != NULL)
		{
			/* truncate extra formats */
			char *pair_token;
			char *tail_pair_tk;

			pair_token = strtok_r(column_token, ";", &tail_pair_tk);

			std::string allele1 = "";
			std::string allele2 = "";
			int token_index = 0;
			
			size_t pair_tk_size = strlen(pair_token);

			/* obtain allele1 */
			if(pair_token[token_index] == '.')
			{
				token_index += 2;
			}
			else
			{
				while(pair_token[token_index] != '|' && pair_token[token_index] != '/')
				{
					allele1 += pair_token[token_index];
					token_index++;
				}

				token_index++;
			}
			
			/* obtain allele2 */
			if(pair_token[token_index] != '.')
			{
				while(token_index < pair_tk_size)
				{
					allele2 += pair_token[token_index];
					token_index++;
				}
			}


			/* categorize obtained allele: 
			 * [][][0] -> 0|0
			 * [][][1] -> x|0 or 0|x; where x > 0
			 * [][][2] -> x|x or y|x or x|y; where y > 0 && x > 0
			 * [][][3] -> .|n or n|. or .|.
			 */


			if(allele1 == "0" && allele2 == "0")
			{
				contig_table[query_index][nation_kind][0]++;
			}
			else if((allele1 == "0" || allele2 == "0") 
					&& (allele1 != "." && allele2 != "."))
			{
				contig_table[query_index][nation_kind][1]++;
			}
			else if((allele1 != "0" && allele2 != "0")
					&& (allele1 != "." && allele2 != "."))
			{
				contig_table[query_index][nation_kind][2]++;
			}
			else
			{
				contig_table[query_index][nation_kind][3]++;
			}
		}

		query_index++;

	}
	while ((line_token = strtok_r(NULL, "\n", &tail_line_tk)) != NULL);


	return 0.0;
}


double Bbfunc::VCFChunkLoader(std::string chrom, uint64_t position,
	std::string nation, std::string disease_type, int mode, 
	std::string &query)
{
	sgx_status_t status = SGX_SUCCESS;
	uint8_t *dummy_array = new uint8_t[32]();
	int ocall_ret = 0;
	size_t est_sz;
	double final_ret;

	
	/* declare variables for every modes; only one part will be used */
	/* for allele frequency analysis */
	AlleleFreq_t alfq;
	alfq.allele_freq = 0.0;
	alfq.is_init = false;

	
	/* For Fisher's Exact Test */
	FisherTest_t fet;

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



	/* calculate entire size of filenames matching with conditions */
	size_t natn_len, dstp_len;

	natn_len = nation.length();
	dstp_len = disease_type.length();


	uint8_t *nation_uchar = new uint8_t[natn_len + 1]();
	uint8_t *disease_type_uchar = new uint8_t[dstp_len + 1]();


	for(int i = 0; i < natn_len; i++)
	{
		nation_uchar[i] = (uint8_t)nation.c_str()[i];
	}

	for(int i = 0; i < dstp_len; i++)
	{
		disease_type_uchar[i] = (uint8_t)disease_type.c_str()[i];
	}

	uint8_t *natn_hash = new uint8_t[32]();
	uint8_t *dstp_hash = new uint8_t[32]();


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


	status = OCALL_calc_inquiryVCTX_size(&ocall_ret, dummy_array, 32, 
		natn_hash, 32, dstp_hash, 32, &est_sz);

	if(status != SGX_SUCCESS)
	{
		OCALL_print_status(status);
		throw std::string("Internal SGX error.");
	}

	if(ocall_ret != 0)
	{
		throw std::string("Error has occurred while querying MySQL.");
	}


	/* obtain filename list matching with conditions */

	/*
	 * To more strictly control output privacy, you should seal 
	 * nations and disease_types, then unseal them when inquirying.
	 */

	char *matched_filenames = new char[est_sz + 1]();
	
	status = OCALL_inquiryVCFContext(&ocall_ret, dummy_array, 32,
		natn_hash, 32, dstp_hash, 32, matched_filenames, est_sz);

	if(status != SGX_SUCCESS)
	{
		OCALL_print_status(status);
		throw std::string("Internal SGX error.");
	}

	if(ocall_ret != 0)
	{
		throw std::string("Error has occurred while querying MySQL.");
	}


	/* generate matched filename vector */
	std::vector<std::string> matched_list;
	
	char *matched_token = strtok(matched_filenames, "\n");

	do
	{
		matched_list.push_back(matched_token);
	}
	while ((matched_token = strtok(NULL, "\n")) != NULL);


	for(int i = 0; i < matched_list.size(); i++)
	{
		OCALL_print(matched_list[i].c_str());
	}

	delete(matched_filenames);


	/* process for every filenames */
	int match_index = 0;
	char *token_div;
	std::vector<std::string> filename_vec;

	token_div = strtok((char*)filename_list, "\n");

	do
	{
		filename_vec.push_back(token_div);
	}
	while ((token_div = strtok(NULL, "\n")) != NULL);


	for(int idx = 0; idx < filename_vec.size(); idx++)
	{
		int match_flag = 0;

		if(matched_list.size() > 0 && match_index < matched_list.size())
		{
			if(filename_vec[idx] == matched_list[match_index])
			{
				match_flag = 1;
				match_index++;
			}
		}

		if(filename_vec[idx].length() != 16)
		{
			OCALL_print("Illegal filename detected ->");
			OCALL_print(filename_vec[idx].c_str());
			break;
		}

		std::string disp_str = "\nProcessing ";
		disp_str += filename_vec[idx];
		disp_str += " ->";

		OCALL_print(disp_str.c_str());

		size_t sealed_key_size;
		size_t divnum = 0;

		sealed_key_size = sgx_calc_sealed_data_size(0, 16);

		uint8_t *sealed_key = new uint8_t[sealed_key_size]();
		char *flnm_to_pass = new char[17]();

		for(int i = 0; i < 16; i++)
		{
			flnm_to_pass[i] = filename_vec[idx].c_str()[i];
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
			size_t div_flnm_len = filename_vec[idx].length();
			uint64_t chunk_size = 0;

			char *div_filename = new char[div_flnm_len + 1]();

			for(int i = 0; i < div_flnm_len; i++)
			{
				div_filename[i] = filename_vec[idx][i];
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


			if(mode == 0) // allele frequency analysis
			{
				final_ret = AlleleFreqAnalysis(plain_vcf, &alfq, chrom,
					position, nation, disease_type, match_flag);
			}
			

			delete(vcf_chunk);
			delete(div_filename);
			delete(iv_t);
			delete(plain_vcf);
		}	


		delete(sealed_key);
		delete(flnm_to_pass);
		delete(vcf_key);
		delete(iv_array);
		delete(tag_array);

	} //while((token_div = strtok(NULL, "\n")) != NULL);

	/* finalize result */
	if(mode == 0)
	{
		uint64_t allele_total = 0;

		if(alfq.allele_num.size() == 0)
		{
			Bmain::result_str += "No matched alleles.\n";
			return -1.0;
		}

		for(int i = 0; i < alfq.allele_num.size(); i++)
		{
			allele_total += alfq.allele_num[i];
		}

		/* display allele frequencies */
		Bmain::result_str += "Major allele: ";
		Bmain::result_str += alfq.alleles[0];
		Bmain::result_str += " ---> ";
		Bmain::result_str += 
				std::to_string(((double)alfq.allele_num[0] / (double)allele_total) * 100);
		Bmain::result_str += "%\n";

		for(int i = 1; i < alfq.allele_num.size(); i++)
		{
			Bmain::result_str += "Minor allele[";
			Bmain::result_str += std::to_string(i);
			Bmain::result_str += "]: ";
			Bmain::result_str += alfq.alleles[i];
			Bmain::result_str += " ---> ";
			Bmain::result_str += 
					std::to_string(((double)alfq.allele_num[i] / (double)allele_total) * 100);
			Bmain::result_str += "%\n";
		}

	}
	
	//Bmain::result_str = "";

	return 0.0;
}


double Bbfunc::VCFChunkLoader_FET(std::string chrom, std::string nation, 
	std::string disease_type, std::string &query)
{
	sgx_status_t status = SGX_SUCCESS;
	uint8_t *dummy_array = new uint8_t[32]();
	int ocall_ret = 0;
	size_t est_sz;
	double final_ret;

	
	/* For Fisher's Exact Test */
	FisherTest_t fet;


	/* parse query to vector */
	std::vector<uint64_t> pos_query;

	char *pos_token;
	char *tail_pos_tk;
	
	if(query == "")
	{
		Bmain::result_str = "No matched result.";
		return -1.0;
	}

	pos_token = strtok_r((char*)query.c_str(), ";", &tail_pos_tk);

	do
	{
		pos_query.push_back(strtoul(pos_token, NULL, 10));
	}
	while((pos_token = strtok_r(NULL, ";", &tail_pos_tk)) != NULL);



	/* sort query array */
	int query_size = pos_query.size();

	uint64_t *sort_temp = new uint64_t[query_size]();

	for(int i = 0; i < query_size; i++)
	{
		sort_temp[i] = pos_query[i];
	}

	qsort(sort_temp, query_size, sizeof(uint64_t), qsort_compare);

	for(int i = 0; i < query_size; i++)
	{
		pos_query[i] = sort_temp[i];
	}

	delete(sort_temp);



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


	
	/* parse nation list */
	std::vector<std::string> nation_list;

	char *nation_token = strtok((char*)nation.c_str(), ";");


	do
	{
		nation_list.push_back(nation_token);
	}
	while ((nation_token = strtok(NULL, ";"))!= NULL);

	if(nation_list.size() < 2)
	{
		throw std::string("2 or more nations must be designated.");
	}


	

	/* calculate entire size of filenames matching with conditions */
	/* loop for every nations designated in script code */
	std::vector<std::vector<std::string>> natn_flnm_list;
	std::vector<int> nation_index;
	size_t nlist_size = nation_list.size();

	for(int i = 0; i < nlist_size; i++)
	{
		natn_flnm_list.emplace_back();
		nation_index.push_back(0);
	}

	/* query filenames for every nations */
	for(int nidx = 0; nidx < nlist_size; nidx++)
	{
		size_t natn_len, dstp_len;

		natn_len = nation_list[nidx].length();
		dstp_len = disease_type.length();


		uint8_t *nation_uchar = new uint8_t[natn_len + 1]();
		uint8_t *disease_type_uchar = new uint8_t[dstp_len + 1]();


		for(int i = 0; i < natn_len; i++)
		{
			nation_uchar[i] = (uint8_t)nation_list[nidx].c_str()[i];
		}

		for(int i = 0; i < dstp_len; i++)
		{
			disease_type_uchar[i] = (uint8_t)disease_type.c_str()[i];
		}

		uint8_t *natn_hash = new uint8_t[32]();
		uint8_t *dstp_hash = new uint8_t[32]();


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


		status = OCALL_calc_inquiryVCTX_size(&ocall_ret, dummy_array, 32, 
			natn_hash, 32, dstp_hash, 32, &est_sz);

		if(status != SGX_SUCCESS)
		{
			OCALL_print_status(status);
			throw std::string("Internal SGX error.");
		}

		if(ocall_ret != 0)
		{
			throw std::string("Error has occurred while querying MySQL.");
		}


		/* obtain filename list matching with conditions */

		/*
		 * To more strictly control output privacy, you should seal 
		 * nations and disease_types, then unseal them when inquirying.
		 */

		char *matched_filenames = new char[est_sz + 1]();
		
		status = OCALL_inquiryVCFContext(&ocall_ret, dummy_array, 32,
			natn_hash, 32, dstp_hash, 32, matched_filenames, est_sz);

		if(status != SGX_SUCCESS)
		{
			OCALL_print_status(status);
			throw std::string("Internal SGX error.");
		}

		if(ocall_ret != 0)
		{
			throw std::string("Error has occurred while querying MySQL.");
		}


		/* add obtained filenames to nation filename list */
		char *flnm_token = strtok(matched_filenames, "\n");

		do
		{
			natn_flnm_list[nidx].push_back(flnm_token);
		}
		while (flnm_token = strtok(NULL, "\n"));
	}


	/* process for every filenames */
	char *token_div;
	std::vector<std::string> filename_vec;

	token_div = strtok((char*)filename_list, "\n");

	do
	{
		filename_vec.push_back(token_div);
	}
	while ((token_div = strtok(NULL, "\n")) != NULL);


	std::vector<std::string> matched_list;
	std::vector<int> matched_nation_type;
	size_t fv_sz = filename_vec.size();
	

	/* sort matched filename list */
	for(int i = 0; i < fv_sz; i++)
	{
		for(int j = 0; j < nlist_size; j++)
		{
			if(nation_index[j] == -1) continue;

			if(natn_flnm_list[j][nation_index[j]] == filename_vec[i])
			{
				matched_list.push_back(filename_vec[i]);
				matched_nation_type.push_back(j);
				nation_index[j]++;
			}

			if(nation_index[j] >= natn_flnm_list[j].size())
			{
				nation_index[j] = -1;
			}
		}
	}

	/*
	for(int i = 0; i < filename_vec.size(); i++)
	{
		OCALL_print(filename_vec[i].c_str());
	}

	OCALL_print(" ");

	for(int i = 0; i < matched_list.size(); i++)
	{
		OCALL_print(matched_list[i].c_str());
	}

	for(int i = 0; i < matched_nation_type.size(); i++)
	{
		OCALL_print_int(matched_nation_type[i]);
	}


	return 0.0;
	*/


	/* declare vector for contingency table */
	std::vector<std::vector<std::vector<char>>> contig_table;
	std::vector<double> p_value_vec;
	

	for(int i = 0; i < query_size; i++)
	{
		contig_table.emplace_back();

		for(int j = 0; j < nlist_size; j++)
		{
			contig_table[i].emplace_back();

			for(int k = 0; k < 4; k++)
			{
				/*
				 * [0]: total of "0/0"
				 * [1]: total of "x/0" and "0/x", which x is minor allele
				 * [2]: total of "x/x"
				 * [3]: total of corrupted data i.e. including "." like "./0"
				 */

				 contig_table[i][j].push_back(0);
			}
		}
	}

	for(int i = 0; i < 2; i++)
	{
		p_value_vec.push_back(0.0);
	}

	int match_index = 0;

	
	for(int idx = 0; idx < filename_vec.size(); idx++)
	{
		int match_flag = 0;

		if(matched_list.size() > 0 && match_index < matched_list.size())
		{
			if(filename_vec[idx] == matched_list[match_index])
			{
				match_flag = 1;
				match_index++;
			}
		}


		if(filename_vec[idx].length() != 16)
		{
			OCALL_print("Illegal filename detected ->");
			OCALL_print(filename_vec[idx].c_str());
			break;
		}

		std::string disp_str = "\nProcessing ";
		disp_str += filename_vec[idx];
		disp_str += " ->";

		OCALL_print(disp_str.c_str());

		size_t sealed_key_size;
		size_t divnum = 0;

		sealed_key_size = sgx_calc_sealed_data_size(0, 16);

		uint8_t *sealed_key = new uint8_t[sealed_key_size]();
		char *flnm_to_pass = new char[17]();

		for(int i = 0; i < 16; i++)
		{
			flnm_to_pass[i] = filename_vec[idx].c_str()[i];
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


		/* position index must be initialized here */
		int pos_index = 0;

		
		/* start loading encrypted VCF */
		for(int index = 0; index < divnum; index++)
		{
			size_t div_flnm_len = filename_vec[idx].length();
			uint64_t chunk_size = 0;

			char *div_filename = new char[div_flnm_len + 1]();

			for(int i = 0; i < div_flnm_len; i++)
			{
				div_filename[i] = filename_vec[idx][i];
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
			for(int i = 0; i < matched_nation_type.size(); i++)
			{
				OCALL_print_int(matched_nation_type[i]);
			}
			OCALL_print_int(matched_nation_type.size());
			OCALL_print_int(match_index);
			*/

			/* execute FET */
			final_ret = FisherExactTest(plain_vcf, contig_table, chrom,
				pos_query, pos_index, matched_nation_type[match_index - 1], 
				match_flag);

			/* increment position index */
			//pos_index++;

			delete(vcf_chunk);
			delete(div_filename);
			delete(iv_t);
			delete(plain_vcf);
		}

		
		/*
		for(int i = 0; i < 4; i++)
			OCALL_print_int((int)contig_table[0][0][i]);
		*/


		delete(sealed_key);
		delete(flnm_to_pass);
		delete(vcf_key);
		delete(iv_array);
		delete(tag_array);

	}

	/* check contingency table */
	for(int i = 0; i < query_size; i++)
	{
		for(int j = 0; j < nlist_size; j++)
		{
			for(int k = 0; k < 4; k++)
			{
				Bmain::result_str += std::to_string(contig_table[i][j][k]);
				Bmain::result_str += ",";
			}

			Bmain::result_str.pop_back();
			Bmain::result_str += " | ";
		}

		Bmain::result_str.pop_back();
		Bmain::result_str += "\n";
	}

	/* Execute Fisher's Exact Test for every requested positions */
	for(int i = 0; i < query_size; i++)
	{
		FisherExactTest_core(contig_table[i], p_value_vec);

		double ret_dbl = p_value_vec[0] * pow(10, p_value_vec[1]);

		Bmain::result_str += std::to_string(pos_query[i]);
		Bmain::result_str += ",";
		Bmain::result_str += std::to_string(ret_dbl);
		Bmain::result_str += "\n";
	}
	

	return 0.0;
}


double VCFParser_LR(uint8_t *plain_vcf, std::vector<std::vector<char>> &snp_vec,
	std::vector<char> &nation_flags, std::string chrom, std::vector<uint64_t> &pos_query, 
	int &query_index, int matched_flag, int &nf_updated)
{
	/*
	 * 1. convert query to array of uint64_t
	 * 2. sort the array
	 * 3. compare with actual position and skip query if need
	*/

	int is_valid_pos = 0;
	char *tail_line_tk;
	char *line_token = strtok_r((char*)plain_vcf, "\n", &tail_line_tk);


	do
	{
		if(line_token[0] == '#') continue;


		/* start parsing vcf line */
		char *tail_column_tk;
		char *column_token = strtok_r(line_token, "\t", &tail_column_tk);

		/* compare chromosome number */
		if(chrom != "")
		{
			if(column_token != chrom) continue;
		}


		/* compare position */
		column_token = strtok_r(NULL, "\t", &tail_column_tk);
		
		size_t query_size = pos_query.size();
		int pos_clear_flag = 0;
		int cur_pos = 0;
		uint64_t tokened_pos = strtoul(column_token, NULL, 10);
		


		if(query_index >= query_size) continue;

		while((pos_query[query_index] < tokened_pos) 
			&& (query_index < query_size))
		{
			query_index++;
		}

		if(pos_query[query_index] != tokened_pos)
		{
			continue;
		}
	


		/* discard refID, SNP info, QUAL, FILTER, INFO, FORMAT */
		for(int i = 0; i < 7; i++)
		{
			column_token = strtok_r(NULL, "\t", &tail_column_tk);
		}


		/* start parsing allele data */
		/* WARNING: haploid is currently NOT SUPPORTED */
		while((column_token = strtok_r(NULL, "\t", &tail_column_tk)) != NULL)
		{
			/* truncate extra formats */
			char *pair_token;
			char *tail_pair_tk;

			pair_token = strtok_r(column_token, ";", &tail_pair_tk);

			std::string allele1 = "";
			std::string allele2 = "";
			int token_index = 0;
			
			size_t pair_tk_size = strlen(pair_token);

			/* obtain allele1 */
			if(pair_token[token_index] == '.')
			{
				token_index += 2;
			}
			else
			{
				while(pair_token[token_index] != '|' && pair_token[token_index] != '/')
				{
					allele1 += pair_token[token_index];
					token_index++;
				}

				token_index++;
			}
			
			/* obtain allele2 */
			if(pair_token[token_index] != '.')
			{
				while(token_index < pair_tk_size)
				{
					allele2 += pair_token[token_index];
					token_index++;
				}
			}



			if(allele1 == "0" && allele2 == "0")
			{
				snp_vec[query_index + 1].emplace_back(0);
			}
			else if((allele1 == "0" || allele2 == "0") 
					&& (allele1 != "." && allele2 != "."))
			{
				snp_vec[query_index + 1].emplace_back(1);
			}
			else if((allele1 != "0" && allele2 != "0")
					&& (allele1 != "." && allele2 != "."))
			{
				snp_vec[query_index + 1].emplace_back(2);
			}
			else
			{
				/* 
				 * if obtained allele data is invalid, distinguishing it is
				 * STRONGLY RECOMMENDED, but temporary just put 0 fot the present.
				 */

				snp_vec[query_index + 1].emplace_back(0);
			}

			if(nf_updated == 0)
			{
				if(matched_flag == 1)
				{
					nation_flags.emplace_back(1);
				}
				else
				{
					nation_flags.emplace_back(0);
				}
			}
		}
		query_index++;
		nf_updated = 1;

	}
	while ((line_token = strtok_r(NULL, "\n", &tail_line_tk)) != NULL);

	return 0.0;
}


double VCFParser_PCA(uint8_t *plain_vcf, std::vector<std::vector<double>> &snp_vec,
	std::string chrom, std::vector<uint64_t> &pos_query, int &query_index, 
	int matched_flag)
{
	/*
	 * 1. convert query to array of uint64_t
	 * 2. sort the array
	 * 3. compare with actual position and skip query if need
	*/

	int is_valid_pos = 0;
	char *tail_line_tk;
	char *line_token = strtok_r((char*)plain_vcf, "\n", &tail_line_tk);


	do
	{
		if(matched_flag == 0) continue;
		if(line_token[0] == '#') continue;


		/* start parsing vcf line */
		char *tail_column_tk;
		char *column_token = strtok_r(line_token, "\t", &tail_column_tk);

		/* compare chromosome number */
		if(chrom != "")
		{
			if(column_token != chrom) continue;
		}


		/* compare position */
		column_token = strtok_r(NULL, "\t", &tail_column_tk);
		
		size_t query_size = pos_query.size();
		int pos_clear_flag = 0;
		int cur_pos = 0;
		uint64_t tokened_pos = strtoul(column_token, NULL, 10);
		


		if(query_index >= query_size) continue;

		while((pos_query[query_index] < tokened_pos) 
			&& (query_index < query_size))
		{
			query_index++;
		}

		if(pos_query[query_index] != tokened_pos)
		{
			continue;
		}
	


		/* discard refID, SNP info, QUAL, FILTER, INFO, FORMAT */
		for(int i = 0; i < 7; i++)
		{
			column_token = strtok_r(NULL, "\t", &tail_column_tk);
		}


		/* start parsing allele data */
		/* WARNING: haploid is currently NOT SUPPORTED */
		while((column_token = strtok_r(NULL, "\t", &tail_column_tk)) != NULL)
		{
			/* truncate extra formats */
			char *pair_token;
			char *tail_pair_tk;

			pair_token = strtok_r(column_token, ";", &tail_pair_tk);

			std::string allele1 = "";
			std::string allele2 = "";
			int token_index = 0;
			
			size_t pair_tk_size = strlen(pair_token);

			/* obtain allele1 */
			if(pair_token[token_index] == '.')
			{
				token_index += 2;
			}
			else
			{
				while(pair_token[token_index] != '|' && pair_token[token_index] != '/')
				{
					allele1 += pair_token[token_index];
					token_index++;
				}

				token_index++;
			}
			
			/* obtain allele2 */
			if(pair_token[token_index] != '.')
			{
				while(token_index < pair_tk_size)
				{
					allele2 += pair_token[token_index];
					token_index++;
				}
			}



			if(allele1 == "0" && allele2 == "0")
			{
				snp_vec[query_index].emplace_back(0.0);
			}
			else if((allele1 == "0" || allele2 == "0") 
					&& (allele1 != "." && allele2 != "."))
			{
				snp_vec[query_index].emplace_back(1.0);
			}
			else if((allele1 != "0" && allele2 != "0")
					&& (allele1 != "." && allele2 != "."))
			{
				snp_vec[query_index].emplace_back(2.0);
			}
			else
			{
				/* 
				 * if obtained allele data is invalid, distinguishing it is
				 * STRONGLY RECOMMENDED, but temporary just put 0 fot the present.
				 */

				snp_vec[query_index].emplace_back(0.0);
			}
		}
		query_index++;
	}
	while ((line_token = strtok_r(NULL, "\n", &tail_line_tk)) != NULL);

	return 0.0;
}


void LogisticRegression(double *theta, std::vector<std::vector<char>> &x, 
	size_t LR_len, std::vector<char> &y, int M, int N, int iteration, int regularization)
{
	std::vector<double> LR_function(M, 0.0);
	double diff_negLLF = 0.0;
  

	int lambda = 1;
	double rate = 0.01;
  

	for(int i=0; i<N+1; i++)
		theta[i] = 0.1;

  
	for(int itr=0; itr<iteration; itr++)
	{
		for(int i=0; i<N+1; i++)
		{
			for(int j=0; j<M; j++)
			{
				if(i == 0) LR_function[j] = 0.0;
	
				LR_function[j] -= theta[i] * x[i][j];
	
				if(i == N)
				{
					LR_function[j] = y[j] - 1 / (1 + exp(LR_function[j]));
      			}
			}
		}


		for(int i=0; i<N+1; i++)
		{
			for(int j=0; j<M; j++)
			{
				if(j == 0) diff_negLLF = 0.0;
	
				diff_negLLF -= LR_function[j] * theta[i] * x[i][j];


				if(j == M-1)
				{
					if(regularization == 1)
					{
						diff_negLLF = (lambda * theta[i] + diff_negLLF) / M;
					}
	
					theta[i] -= rate * diff_negLLF;
				}
			}
		}
	}
}



double Bbfunc::VCFChunkLoader_LR(std::string chrom, std::string nation, 
	std::string disease_type, std::string &query)
{
	sgx_status_t status = SGX_SUCCESS;
	uint8_t *dummy_array = new uint8_t[32]();
	int ocall_ret = 0;
	size_t est_sz;
	double final_ret;

	
	/* For Fisher's Exact Test */
	FisherTest_t fet;


	/* parse query to vector */
	std::vector<uint64_t> pos_query;

	char *pos_token;
	char *tail_pos_tk;
	
	if(query == "")
	{
		Bmain::result_str = "No matched result.";
		return -1.0;
	}

	pos_token = strtok_r((char*)query.c_str(), ";", &tail_pos_tk);

	do
	{
		pos_query.push_back(strtoul(pos_token, NULL, 10));
	}
	while((pos_token = strtok_r(NULL, ";", &tail_pos_tk)) != NULL);



	/* sort query array */
	int query_size = pos_query.size();

	uint64_t *sort_temp = new uint64_t[query_size]();

	for(int i = 0; i < query_size; i++)
	{
		sort_temp[i] = pos_query[i];
	}

	qsort(sort_temp, query_size, sizeof(uint64_t), qsort_compare);

	for(int i = 0; i < query_size; i++)
	{
		pos_query[i] = sort_temp[i];
	}

	delete(sort_temp);



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


	

	/* calculate entire size of filenames matching with conditions */
	size_t natn_len, dstp_len;

	natn_len = nation.length();
	dstp_len = disease_type.length();


	uint8_t *nation_uchar = new uint8_t[natn_len + 1]();
	uint8_t *disease_type_uchar = new uint8_t[dstp_len + 1]();


	for(int i = 0; i < natn_len; i++)
	{
		nation_uchar[i] = (uint8_t)nation.c_str()[i];
	}

	for(int i = 0; i < dstp_len; i++)
	{
		disease_type_uchar[i] = (uint8_t)disease_type.c_str()[i];
	}

	uint8_t *natn_hash = new uint8_t[32]();
	uint8_t *dstp_hash = new uint8_t[32]();


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


	status = OCALL_calc_inquiryVCTX_size(&ocall_ret, dummy_array, 32, 
		natn_hash, 32, dstp_hash, 32, &est_sz);

	if(status != SGX_SUCCESS)
	{
		OCALL_print_status(status);
		throw std::string("Internal SGX error.");
	}

	if(ocall_ret != 0)
	{
		throw std::string("Error has occurred while querying MySQL.");
	}


	/* obtain filename list matching with conditions */

	/*
	 * To more strictly control output privacy, you should seal 
	 * nations and disease_types, then unseal them when inquirying.
	 */

	char *matched_filenames = new char[est_sz + 1]();
	
	status = OCALL_inquiryVCFContext(&ocall_ret, dummy_array, 32,
		natn_hash, 32, dstp_hash, 32, matched_filenames, est_sz);

	if(status != SGX_SUCCESS)
	{
		OCALL_print_status(status);
		throw std::string("Internal SGX error.");
	}

	if(ocall_ret != 0)
	{
		throw std::string("Error has occurred while querying MySQL.");
	}


	/* generate matched filename vector */
	std::vector<std::string> matched_list;
	
	char *matched_token = strtok(matched_filenames, "\n");

	do
	{
		matched_list.push_back(matched_token);
	}
	while ((matched_token = strtok(NULL, "\n")) != NULL);


	for(int i = 0; i < matched_list.size(); i++)
	{
		OCALL_print(matched_list[i].c_str());
	}

	delete(matched_filenames);




	/* process for every filenames */
	char *token_div;
	std::vector<std::string> filename_vec;

	token_div = strtok((char*)filename_list, "\n");

	do
	{
		filename_vec.push_back(token_div);
	}
	while ((token_div = strtok(NULL, "\n")) != NULL);




	/* declare vector for contingency table */
	std::vector<std::vector<char>> snp_vec;
	std::vector<char> nation_flags;

	/*
	 * ------------------ vector design for LR --------------------
	 * snp_vec[position][registered_user];
	 * 
	 * first line (i.e. snp_vec[0][i]) must be flushed with 1,
	 * therefore loaded data will be stored in snp_vec[>1][i].
	 * ------------------------------------------------------------
	 */

	/* 
	 * for 1-flushed line. this line will be processed 
	 * after loading entire VCF.
	 */

	snp_vec.emplace_back();
	

	for(int i = 0; i < query_size; i++)
	{
		snp_vec.emplace_back();
	}


	int match_index = 0;

	
	for(int idx = 0; idx < filename_vec.size(); idx++)
	{
		int match_flag = 0;

		if(matched_list.size() > 0 && match_index < matched_list.size())
		{
			if(filename_vec[idx] == matched_list[match_index])
			{
				match_flag = 1;
				match_index++;
			}
		}


		if(filename_vec[idx].length() != 16)
		{
			OCALL_print("Illegal filename detected ->");
			OCALL_print(filename_vec[idx].c_str());
			break;
		}

		std::string disp_str = "\nProcessing ";
		disp_str += filename_vec[idx];
		disp_str += " ->";

		OCALL_print(disp_str.c_str());

		size_t sealed_key_size;
		size_t divnum = 0;

		sealed_key_size = sgx_calc_sealed_data_size(0, 16);

		uint8_t *sealed_key = new uint8_t[sealed_key_size]();
		char *flnm_to_pass = new char[17]();

		for(int i = 0; i < 16; i++)
		{
			flnm_to_pass[i] = filename_vec[idx].c_str()[i];
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


		/* position index must be initialized here */
		int pos_index = 0;
		int nf_updated = 0;

		
		/* start loading encrypted VCF */
		for(int index = 0; index < divnum; index++)
		{
			size_t div_flnm_len = filename_vec[idx].length();
			uint64_t chunk_size = 0;

			char *div_filename = new char[div_flnm_len + 1]();

			for(int i = 0; i < div_flnm_len; i++)
			{
				div_filename[i] = filename_vec[idx][i];
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


			/* execute VCF parsing
			 * 
			 * to obtain counter-example nation data, all hash values of each nations
			 * must be calculated and pick up single VCF for each nations.
			 * if you USE SEALING, this implementation must be far more complicated.
			 */
			final_ret = VCFParser_LR(plain_vcf, snp_vec, nation_flags, chrom,
				pos_query, pos_index, match_flag, nf_updated);

			/* increment position index */
			//pos_index++;

			delete(vcf_chunk);
			delete(div_filename);
			delete(iv_t);
			delete(plain_vcf);
		}

		
		/*
		for(int i = 0; i < 4; i++)
			OCALL_print_int((int)contig_table[0][0][i]);
		*/


		delete(sealed_key);
		delete(flnm_to_pass);
		delete(vcf_key);
		delete(iv_array);
		delete(tag_array);

	}


	for(int i = 1; i < snp_vec.size(); i++)
	{
		if(snp_vec[i].size() == 0)
		{
			snp_vec[i].pop_back();
		}
	}

	for(int i = 0; i < snp_vec[1].size(); i++)
	{
		snp_vec[0].emplace_back(1);
	}

	/*
	std::string message;
	
	for(int i = 0; i < snp_vec[0].size(); i++)
	{
		message += std::to_string((int)snp_vec[2][i]);
	}

	OCALL_print(message.c_str());
	*/

	double *theta = new double[snp_vec.size()]();

	LogisticRegression(theta, snp_vec, snp_vec.size(), nation_flags, 
		snp_vec[0].size(), snp_vec.size() - 1, 100, 0);

	std::string message;

	for(int i = 0; i < snp_vec.size(); i++)
	{
		message += std::to_string(theta[i]);
		message += ",";
	}

	OCALL_print(message.c_str());

	return 0.0;
}


void PCA_getNormalizedData(int row, int column, std::vector<std::vector<double>> &x)
{
	double ave = 0.0, SD = 0.0;
  
	for(int i = 0; i < row; i++)
	{
		ave = 0.0, SD = 0.0;
    
		for(int j = 0; j < column; j++)
		{
			ave += x[i][j];
		}
		
		ave /= column;


		for(int j = 0; j < column; j++)
		{
			SD += (x[i][j] - ave) * (x[i][j] - ave);
		}

		SD = sqrt(SD / column);

    
		for(int j = 0; j < column; j++)
		{
			x[i][j] = (x[i][j] - ave) / SD;
		}
	}

	return;
}



void PCA_getCovarianceMatrix(int row, int column, std::vector<std::vector<double>> &x,
	std::vector<std::vector<double>> &covariance)
{
	for(int i = 0; i < row; i++)
	{
		for(int j = i; j < column; j++)
		{
			for(int k = 0; k < row; k++)
			{
				covariance[i][j] += x[i][k] * x[j][k];
    		}
		}

    
		for(int j = i; j < column; j++)
		{
			covariance[i][j] /= (row - 1);
      
			if(j != i) covariance[j][i] = covariance[i][j];
		}
	}

	return;
}



void PCA_getEigenVector(std::vector<std::vector<double>> &A, 
	std::vector<std::vector<double>> &eigenvector, int n_component,
	const double thres)
{
	// Initialization.
	const int N = (int)A[0].size();
  
	std::vector<double> y(N, 0);
	int count;
	double eigenvalue, prv_eigenvalue;
	bool itrFlag;

	// verify passed vector
	if(N * N == A.size())
	{
		throw std::string("Failed to extract SNP matrix in valid format for PCA.");
	}
	
	if(eigenvector[0].size() * n_component == eigenvector.size())
	{
		throw std::string("Failed to generate eigenvector in PCA function.");
	}


	for(int itr = 0; itr < n_component; itr++)
	{
		// Initialization.
		count = 0;
		itrFlag = true;
		eigenvalue = 0.0;


		while(itrFlag == true)
		{
			prv_eigenvalue = eigenvalue;
			eigenvalue = 0.0;
      
			for(int i = 0; i < N; i++)
			{
				y[i] = 0;
		
				// y = Ax (x convergence to eigenvalue)
				for(int j = 0; j < N; j++)
				{
					y[i] += A[i][j] * eigenvector[itr][j];
				}

				if(i == 0)  eigenvalue  = y[i] * eigenvector[itr][i];
				else        eigenvalue += y[i] * eigenvector[itr][i];
			}

			if(fabs(eigenvalue - prv_eigenvalue) < thres) itrFlag = false;
		  
		  
			if(itrFlag)
			{
				double length = 0.0;
			
				for(int j = 0; j < N; j++)
				{
					eigenvector[itr][j] = y[j];
					length += eigenvector[itr][j] * eigenvector[itr][j];
				}

				length = sqrt(length);
		
				for(int j = 0; j < N; j++)
				{
					eigenvector[itr][j] /= length;
				}
		
				count++;
			}
		}


		// Update A
		for(int i = 0; i < N; i++)
		{
			for(int j = 0; j < N; j++)
			{
				A[i][j] -= eigenvalue * eigenvector[itr][i] * eigenvector[itr][j];
			}
		
		}
		
		// string EigenCheck = "calculate " + to_string(count) + " times to solve EigenProblem. Eigenvalue: " + to_string(eigenvalue);
		// OCALL_print(EigenCheck.c_str());
	}

	std::vector<double>().swap(y);  // std::vector のメモリ解放．
	return;
}


// reduce original data to <n_component> dim(s)
void PCA_ReduceDimension(int row, int column, std::vector<std::vector<double>> &x,
	std::vector<std::vector<double>> &eigenvector, double *reduced, int n_component)
{
	std::vector<std::vector<double>> tmp(row, std::vector<double>(n_component, 0.0));

	for(int i = 0; i < row; i++)
	{
		for(int k = 0; k < column; k++)
		{
			for(int j = 0; j < n_component; j++)
			{
				tmp[i][j] += x[k][i] * eigenvector[j][k];
    		}
		}
	}

	for(int i = 0; i < row; i++)
	{
		for(int j = 0; j < n_component; j++)
		{
			reduced[n_component*i + j] = 0.0;
      
			for(int k = 0; k < column; k++)
			{
				reduced[n_component*i + j] += tmp[i][j] * eigenvector[j][k];
    		}
		}
	}

	std::vector<std::vector<double>>().swap(tmp);  // destruct vector
  
	return;
}



double Bbfunc::VCFChunkLoader_PCA(std::string chrom, std::string nation, 
	std::string disease_type, std::string &query)
{
	sgx_status_t status = SGX_SUCCESS;
	uint8_t *dummy_array = new uint8_t[32]();
	int ocall_ret = 0;
	size_t est_sz;
	double final_ret;

	
	/* For Fisher's Exact Test */
	FisherTest_t fet;


	/* parse query to vector */
	std::vector<uint64_t> pos_query;

	char *pos_token;
	char *tail_pos_tk;
	
	if(query == "")
	{
		Bmain::result_str = "No matched result.";
		return -1.0;
	}

	pos_token = strtok_r((char*)query.c_str(), ";", &tail_pos_tk);

	do
	{
		pos_query.push_back(strtoul(pos_token, NULL, 10));
	}
	while((pos_token = strtok_r(NULL, ";", &tail_pos_tk)) != NULL);



	/* sort query array */
	int query_size = pos_query.size();

	uint64_t *sort_temp = new uint64_t[query_size]();

	for(int i = 0; i < query_size; i++)
	{
		sort_temp[i] = pos_query[i];
	}

	qsort(sort_temp, query_size, sizeof(uint64_t), qsort_compare);

	for(int i = 0; i < query_size; i++)
	{
		pos_query[i] = sort_temp[i];
	}

	delete(sort_temp);



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


	
	/* parse nation list */
	/*
	std::vector<std::string> nation_list;

	char *nation_token = strtok((char*)nation.c_str(), ";");

	do
	{
		nation_list.push_back(nation_token);
	}
	while ((nation_token = strtok(NULL, ";"))!= NULL);

	if(nation_list.size() != 1)
	{
		throw std::string("Only 1 nation can be designated in PCA function.");
	}
	*/


	/* calculate entire size of filenames matching with conditions */
	size_t natn_len, dstp_len;

	natn_len = nation.length();
	dstp_len = disease_type.length();


	uint8_t *nation_uchar = new uint8_t[natn_len + 1]();
	uint8_t *disease_type_uchar = new uint8_t[dstp_len + 1]();


	for(int i = 0; i < natn_len; i++)
	{
		nation_uchar[i] = (uint8_t)nation.c_str()[i];
	}

	for(int i = 0; i < dstp_len; i++)
	{
		disease_type_uchar[i] = (uint8_t)disease_type.c_str()[i];
	}

	uint8_t *natn_hash = new uint8_t[32]();
	uint8_t *dstp_hash = new uint8_t[32]();


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


	status = OCALL_calc_inquiryVCTX_size(&ocall_ret, dummy_array, 32, 
		natn_hash, 32, dstp_hash, 32, &est_sz);

	if(status != SGX_SUCCESS)
	{
		OCALL_print_status(status);
		throw std::string("Internal SGX error.");
	}

	if(ocall_ret != 0)
	{
		throw std::string("Error has occurred while querying MySQL.");
	}


	/* obtain filename list matching with conditions */

	/*
	 * To more strictly control output privacy, you should seal 
	 * nations and disease_types, then unseal them when inquirying.
	 */

	char *matched_filenames = new char[est_sz + 1]();
	
	status = OCALL_inquiryVCFContext(&ocall_ret, dummy_array, 32,
		natn_hash, 32, dstp_hash, 32, matched_filenames, est_sz);

	if(status != SGX_SUCCESS)
	{
		OCALL_print_status(status);
		throw std::string("Internal SGX error.");
	}

	if(ocall_ret != 0)
	{
		throw std::string("Error has occurred while querying MySQL.");
	}


	/* generate matched filename vector */
	std::vector<std::string> matched_list;
	
	char *matched_token = strtok(matched_filenames, "\n");

	do
	{
		matched_list.push_back(matched_token);
	}
	while ((matched_token = strtok(NULL, "\n")) != NULL);


	for(int i = 0; i < matched_list.size(); i++)
	{
		OCALL_print(matched_list[i].c_str());
	}

	delete(matched_filenames);




	/* process for every filenames */
	char *token_div;
	std::vector<std::string> filename_vec;

	token_div = strtok((char*)filename_list, "\n");

	do
	{
		filename_vec.push_back(token_div);
	}
	while ((token_div = strtok(NULL, "\n")) != NULL);




	/* declare vector for contingency table */
	std::vector<std::vector<double>> snp_vec;

	/*
	 * ------------------ vector design for PCA -------------------
	 * snp_vec[position][registered_user];
	 * 
	 * Contrary to LR, first line (i.e. snp_vec[0][i]) must NOT be 
	 * flushed with 1, therefore loaded data will be stored 
	 * in snp_vec[>=0][i].
	 * ------------------------------------------------------------
	 */

	
	for(int i = 0; i < query_size; i++)
	{
		snp_vec.emplace_back();
	}


	int match_index = 0;

	
	for(int idx = 0; idx < filename_vec.size(); idx++)
	{
		int match_flag = 0;

		if(matched_list.size() > 0 && match_index < matched_list.size())
		{
			if(filename_vec[idx] == matched_list[match_index])
			{
				match_flag = 1;
				match_index++;
			}
			else
			{
				continue;
			}
		}
		else
		{
			continue;
		}


		if(filename_vec[idx].length() != 16)
		{
			OCALL_print("Illegal filename detected ->");
			OCALL_print(filename_vec[idx].c_str());
			break;
		}

		std::string disp_str = "\nProcessing ";
		disp_str += filename_vec[idx];
		disp_str += " ->";

		OCALL_print(disp_str.c_str());

		size_t sealed_key_size;
		size_t divnum = 0;

		sealed_key_size = sgx_calc_sealed_data_size(0, 16);

		uint8_t *sealed_key = new uint8_t[sealed_key_size]();
		char *flnm_to_pass = new char[17]();

		for(int i = 0; i < 16; i++)
		{
			flnm_to_pass[i] = filename_vec[idx].c_str()[i];
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


		/* position index must be initialized here */
		int pos_index = 0;

		
		/* start loading encrypted VCF */
		for(int index = 0; index < divnum; index++)
		{
			size_t div_flnm_len = filename_vec[idx].length();
			uint64_t chunk_size = 0;

			char *div_filename = new char[div_flnm_len + 1]();

			for(int i = 0; i < div_flnm_len; i++)
			{
				div_filename[i] = filename_vec[idx][i];
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


			/* execute VCF parsing
			 * 
			 * to obtain counter-example nation data, all hash values of each nations
			 * must be calculated and pick up single VCF for each nations.
			 * if you USE SEALING, this implementation must be far more complicated.
			 */
			
			
			final_ret = VCFParser_PCA(plain_vcf, snp_vec, chrom,
				pos_query, pos_index, match_flag);
			

			/* increment position index */
			//pos_index++;

			delete(vcf_chunk);
			delete(div_filename);
			delete(iv_t);
			delete(plain_vcf);
		}

		
		/*
		for(int i = 0; i < 4; i++)
			OCALL_print_int((int)contig_table[0][0][i]);
		*/


		delete(sealed_key);
		delete(flnm_to_pass);
		delete(vcf_key);
		delete(iv_array);
		delete(tag_array);

	}

	std::vector<bool> found_flags(snp_vec.size(), true);

	/* check undetected positions in query */
	for(int i = 0; i < snp_vec.size(); i++)
	{
		if(snp_vec[i].size() == 0)
		{
			found_flags[i] = false;
		}
	}

	auto sv_itr = snp_vec.begin();


	/* delete factors which size is 0 */
	while(sv_itr != snp_vec.end())
	{
		if((*sv_itr).size() == 0)
		{
			sv_itr = snp_vec.erase(sv_itr);
		}
		else
		{
			sv_itr++;
		}
	}

	/* need to edit query vector here */


	/* start computing PCA*/
	static const double thres = 1e-6;
	int n_component = 10;

	int sv_height = snp_vec.size(); // N
	int sv_width = snp_vec[0].size(); // M

	double *PCA_data = new double[sv_width * n_component]();


	OCALL_print("A");
	PCA_getNormalizedData(sv_height, sv_width, snp_vec);
	OCALL_print("A");


	std::vector<std::vector<double>> covariance(sv_height,
		std::vector<double>(sv_height, 0.0));
	
	PCA_getCovarianceMatrix(sv_width, sv_height, snp_vec, covariance);
	OCALL_print("A");


	std::vector<std::vector<double>> eigenvector(n_component, 
		std::vector<double>(sv_height, 1/sqrt((double)sv_height)));

	PCA_getEigenVector(covariance, eigenvector, n_component, thres);
	OCALL_print("A");
	std::vector<std::vector<double>>().swap(covariance);



	PCA_ReduceDimension(sv_width, sv_height, snp_vec, 
		eigenvector, PCA_data, n_component);
	OCALL_print("A");
	std::vector<std::vector<double>>().swap(eigenvector);


	int width_count = 0;

	for(int i = 0; i < sv_width * n_component; i++)
	{
		Bmain::result_str += std::to_string(PCA_data[i]);
		Bmain::result_str += ";";

		width_count++;

		if(width_count >= n_component)
		{
			Bmain::result_str.pop_back();
			Bmain::result_str += "\n";

			width_count = 0;
		}
	}


	delete(PCA_data);
	std::vector<std::vector<double>>().swap(snp_vec);

	return 0.0;
}
