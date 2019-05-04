/* ------------------------ACKNOWLEDGEMENT-----------------------*
* Edit distance part of this source code is from following site  *
*  -> https://gist.github.com/aflc/6482587						 *
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


namespace Bbfunc
{
	/*protos*/
	double executeAverage(std::string dataset_name);
	double executeEdist(std::string dataset_name);
}






/*Edit Distance core for size >= 2*/
template<size_t N, typename T, typename TVALUE, typename V>
unsigned int edit_distance_bpv(T &cmap, V const &vec, unsigned int const &tmax, unsigned int const &tlen) {
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
int start_edist(unsigned int (*func)(const std::string&, const std::string&), const std::string& arg1, const std::string& arg2, int num, const std::string& msg) {
    //for (int i = 0; i < num - 1; i++) (*func)(arg1, arg2);
	int reted = (*func)(arg1, arg2);

	return reted;
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

	return (double)reted / (double)gv_size;

}
