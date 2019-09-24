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
	double VCFChunkLoader(std::string chrom, uint64_t position, 
		std::string nation, std::string disease_type, int mode);
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


double Bbfunc::VCFChunkLoader(std::string chrom, uint64_t position,
	std::string nation, std::string disease_type, int mode)
{
	sgx_status_t status = SGX_SUCCESS;
	uint8_t *dummy_array = new uint8_t[32]();
	int ocall_ret = 0;
	size_t est_sz;

	
	/* declare variables for every modes; only one part will be used */
	/* for allele frequency analysis */
	typedef struct
	{
		std::string major_allele;
		std::string minor_allele;
		double allele_freq;
		int major_num;
		int minor_num;
	} alleleFreq_t;

	alleleFreq_t alfq = {"", "", 0.0, 0, 0};


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

		std::string disp_str = "\nProcessing ";
		disp_str += token_div;
		disp_str += " ->";

		OCALL_print(disp_str.c_str());

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


			if(mode == 0) // allele frequency analysis
			{
				
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

	} while((token_div = strtok(NULL, "\n")) != NULL);

	//Bmain::result_str = "";

	return 0.0;
}
