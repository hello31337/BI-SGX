/*

Copyright 2018 Intel Corporation

This software and the related documents are Intel copyrighted materials,
and your use of them is governed by the express license under which they
were provided to you (License). Unless the License provides otherwise,
you may not use, modify, copy, publish, distribute, disclose or transmit
this software or the related documents without Intel's prior written
permission.

This software and the related documents are provided as is, with no
express or implied warranties, other than those that are expressly stated
in the License.

*/


using namespace std;

#ifdef _WIN32
#pragma comment(lib, "crypt32.lib")
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#else
#include "config.h"
#endif

#ifdef _WIN32
// *sigh*
# include "vs/client/Enclave_u.h"
#else
# include "Enclave_u.h"
#endif
#if !defined(SGX_HW_SIM)&&!defined(_WIN32)
#include "sgx_stub.h"
#endif
#include <stdlib.h>
#include <limits.h>
#include <stdio.h>
#include <time.h>
#include <sgx_urts.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <intrin.h>
#include <wincrypt.h>
#include "win32/getopt.h"
#else
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <getopt.h>
#include <unistd.h>
#endif
#include <sgx_uae_service.h>
#include <sgx_ukey_exchange.h>
#include <string>
#include "common.h"
#include "protocol.h"
#include "sgx_detect.h"
#include "hexutil.h"
#include "fileio.h"
#include "base64.h"
#include "crypto.h"
#include "msgio.h"
#include "logfile.h"
#include "quote_size.h"

#include <iostream>
#include <sstream>
#include <fstream>
#include <random>
#include <chrono>
#include "error_print.hpp"

#include <mysql_driver.h>
#include <mysql_connection.h>
#include <mysql_error.h>
#include <cppconn/statement.h>
#include <cppconn/resultset.h>
#include <cppconn/prepared_statement.h>

#define MAX_LEN 80
#define ROUND_UNIT 100000000

#ifdef _WIN32
# define strdup(x) _strdup(x)
#else
# define _rdrand64_step(x) ({ unsigned char err; asm volatile("rdrand %0; setc %1":"=r"(*x), "=qm"(err)); err; })
#endif

#ifdef __x86_64__
#define DEF_LIB_SEARCHPATH "/lib:/lib64:/usr/lib:/usr/lib64"
#else
#define DEF_LIB_SEARCHPATH "/lib:/usr/lib"
#endif

typedef struct config_struct {
	char mode;
	uint32_t flags;
	sgx_spid_t spid;
	sgx_ec256_public_t pubkey;
	sgx_quote_nonce_t nonce;
	char *server;
	char *port;
} config_t;

int file_in_searchpath (const char *file, const char *search, char *fullpath,
	size_t len);

sgx_status_t sgx_create_enclave_search (
	const char *filename,
	const int edebug,
	sgx_launch_token_t *token,
	int *updated,
	sgx_enclave_id_t *eid,
	sgx_misc_attribute_t *attr
);

void usage();
int do_quote(sgx_enclave_id_t eid, config_t *config);
int do_attestation(sgx_enclave_id_t eid, config_t *config);

char debug= 0;
char verbose= 0;
MsgIO *msgio = NULL;

sgx_ra_context_t g_ra_ctx = 0xDEADDEAD;
sgx_status_t g_sgxrv = SGX_SUCCESS;

chrono::system_clock::time_point chrono_start, chrono_end;

#define MODE_ATTEST 0x0
#define MODE_EPID 	0x1
#define MODE_QUOTE	0x2

#define OPT_PSE		0x01
#define OPT_NONCE	0x02
#define OPT_LINK	0x04
#define OPT_PUBKEY	0x08

/* Macros to set, clear, and get the mode and options */

#define SET_OPT(x,y)	x|=y
#define CLEAR_OPT(x,y)	x=x&~y
#define OPT_ISSET(x,y)	x&y

#ifdef _WIN32
# define ENCLAVE_NAME "Enclave.signed.dll"
#else
# define ENCLAVE_NAME "Enclave.signed.so"
#endif

class BISGX_Database
{
public:
	void initDB();
	int do_login(string username, string password_hash, string privilege);
	void switchTable(string tbname);
	void storeDB(string data_to_store, string datatype, int cipherlen);
	void setUsername(string username);
	string do_executeQuery(string sentence, string cond);
	string do_executeQuery_Annotation(string sentence, 
		int vcf_or_list, int clinvar_flag);
	int do_executeQueryInt(string sentence, string cond);
	string do_inquiryDB(); // for interpreter
	/*
	should be added is:
		- username searcher
		- data inserter (for data owner)
		- data loader (for interpreter)
	*/


private:
	sql::Driver *driver;
	sql::Connection *con;
	sql::Statement *stmt, *stmt2;
	sql::ResultSet *res, *res2;
	sql::PreparedStatement *prep_stmt;

	string host;
	string user;
	string password;
	string database;
	string table;
	string username_internal;
};

BISGX_Database bdb;

void BISGX_Database::initDB()
{
	cout << "CAUTION: Auto login for debug is enabled." << endl;

	host = "localhost";
	user = "BI-SGX";
	password = "bisgx_sample";
	database = "`BI-SGX`";

	driver = get_driver_instance();
	con = driver->connect(host, user, password);
	stmt = con->createStatement();
	stmt2 = con->createStatement();

	stmt->execute("USE " + database);

	table = "userinfo";

	cout << "Database initialization completed." << endl << endl;
}

void BISGX_Database::switchTable(string tbname)
{
	table = tbname;
}

int BISGX_Database::do_login(string username, string password_hash, string privilege)
{
	string tmp;
	bool isRegistered = false;
	int privilege_flag;

	res = stmt->executeQuery("SELECT * FROM " + table);

	while(res->next())
	{
		tmp = res->getString("username");

		if(username == tmp)
		{
			isRegistered = true;
			break;
		}
	}

	if(isRegistered)
	{
		res = stmt->executeQuery("SELECT pass_hash FROM " + table
			+ " WHERE username = '" + username + "'");

		string passhash_tmp;

		while(res->next())
		{
			passhash_tmp = res->getString("pass_hash");
		}

		if(passhash_tmp == password_hash)
		{
			cout << "password confirmed." << endl;
		}
		else
		{
			cout << "wrong password." << endl;
			return 2;
		}

		res = stmt->executeQuery("SELECT privilege FROM " + table 
			+ " WHERE username = '" + username + "'");

		string priv_temp;

		while(res->next())
		{
			priv_temp = res->getString("privilege");
		}

		if(priv_temp[0] == 'O')
		{
			privilege_flag = 0;
		}
		else if(priv_temp[0] == 'R')
		{
			privilege_flag = 1;
		}
		else
		{
			cerr << "priv:" << priv_temp << endl;
			cerr << "Error while obtaining privilege." << endl;
			privilege_flag = 2;
		}
	}
	else
	{
		stmt->execute("INSERT INTO " + table + "(username, pass_hash, privilege) "
			+ "VALUES('" + username + "', '" + password_hash + "', '" + privilege + "')");

		if(privilege == "O")
		{
			privilege_flag = 0;
		}
		else if(privilege == "R")
		{
			privilege_flag = 1;
		}
		else
		{
			privilege_flag = 2;
		}
	}

	return privilege_flag;
}

string BISGX_Database::do_executeQuery(string sentence, string cond)
{
	res = stmt->executeQuery(sentence);
	string retstr;

	while(res->next())
	{
		retstr = res->getString(cond);
	}

	return retstr;
}

string BISGX_Database::do_executeQuery_Annotation(string sentence,
	int vcf_or_list, int clinvar_flag)
{
	res = stmt->executeQuery(sentence);
	string retstr, vcf_pos;

	while(res->next())
	{
		if(res->getString("CHROM") == "")
		{
			return string("");
		}

		if(vcf_or_list == 0)
		{
			retstr += res->getString("CHROM") + string("\t");
			retstr += res->getString("POS") + string("\t");
			retstr += res->getString("ID") + string("\t");
			retstr += res->getString("REF") + string("\t");
			retstr += res->getString("ALT") + string("\t");
			retstr += res->getString("QUAL") + string("\t");
			retstr += res->getString("FILTER") + string("\t");
			retstr += res->getString("INFO");
		}
		else
		{
			retstr += "#ID\n";
			retstr += res->getString("ID") + std::string("\n\n");
			retstr += "#CHROM\n";
			retstr += res->getString("CHROM") + std::string("\n\n");
			retstr += "#POS\n";
			retstr += res->getString("POS") + std::string("\n\n");
			retstr += "#REF\n";
			retstr += res->getString("REF") + std::string("\n\n");
			retstr += "#ALT\n";
			retstr += res->getString("ALT") + std::string("\n\n");
			retstr += "#QUAL\n";
			retstr += res->getString("QUAL") + std::string("\n\n");
			retstr += "#FILTER\n";
			retstr += res->getString("FILTER") + std::string("\n\n");
			retstr += "#INFO\n";
			retstr += res->getString("INFO") + std::string("\n\n");
		}

		vcf_pos = res->getString("POS");

		if(clinvar_flag != 0)
		{
			string sentence_clinvar = "SELECT INFO FROM clinvar WHERE POS = '";
			sentence_clinvar += vcf_pos;
			sentence_clinvar += "'";

			res2 = stmt2->executeQuery(sentence_clinvar);

			std::string clinvar_info = "";

			while(res2->next())
			{
				clinvar_info = res2->getString("INFO");

				if(clinvar_info == "")
				{
					clinvar_info = "N/A";
				}

				if(vcf_or_list == 0)
				{
					retstr += "\t";
					retstr += clinvar_info;
				}
				else
				{
					retstr += "#INFO(CLINVAR)\n";
					retstr += clinvar_info + std::string("\n");
				}
			}

			if(clinvar_info == "")
			{
				if(vcf_or_list == 0)
				{
					retstr += "\tN/A";
				}
				else
				{
					retstr += "#INFO(CLINVAR)\nN/A\n";
				}
			}
		}

		retstr += "\n";
	}
	
	return retstr;
}

int BISGX_Database::do_executeQueryInt(string sentence, string cond)
{
	res = stmt->executeQuery(sentence);
	int retint;

	while(res->next())
	{
		retint = res->getInt(cond);
	}

	return retint;
}

void BISGX_Database::storeDB(string data_to_store, string datatype, int cipherlen)
{
	table = "stored_data";
	res = stmt->executeQuery("SELECT COUNT(*) FROM " + table);

	int datanum = -9999;

	while(res->next())
	{
		datanum = res->getInt("COUNT(*)");
	}

	cout << "COUNT:" << datanum << endl;

	string dataset_name = "dataset";
	dataset_name += to_string(datanum);

	
	stmt->execute("INSERT INTO " + table + "(dataname, owner, data, datatype, cipherlen)"
		+ "VALUES('" + dataset_name + "', '" + username_internal + "', '"
		+ data_to_store + "', '" + datatype + "', '" + to_string(cipherlen) + "')");
}

void BISGX_Database::setUsername(string username)
{
	username_internal = username;
}

string BISGX_Database::do_inquiryDB()
{
	res = stmt->executeQuery
		("SELECT dataname, datatype FROM stored_data");
	string inquiry_res;
	
	while(res->next())
	{
		inquiry_res += res->getString("dataname");
		inquiry_res += " ->  ";
		inquiry_res += res->getString("datatype");
		inquiry_res += "\n";
	}

	return inquiry_res;
}


void OCALL_print(const char* message)
{
	printf("%s\n", message);
	return;
}

void OCALL_print_status(sgx_status_t st)
{
	sgx_error_print(st);
	return;
}

void OCALL_print_int(int num)
{
	cout << "OCALL_INT_PRINT: " << dec<< num << endl;
	return;
}

void OCALL_dump(uint8_t *char_to_dump, int bufsize)
{
	BIO_dump_fp(stdout, (const char*)char_to_dump, bufsize);
	return;
}

void OCALL_generate_nonce(uint8_t *ivbuf, int bufsize)
{
	random_device rnd;
	mt19937 mt(rnd());
	uniform_int_distribution<> randchar(0, 255);

	for(int i = 0; i < bufsize; i++)
	{
		ivbuf[i] = (uint8_t)randchar(mt);
	}

	cout << "Generated nonce is:" << endl;
	BIO_dump_fp(stdout, (const char*)ivbuf, bufsize);
	cout << endl;

	return;
}

void OCALL_get_time(uint8_t *timebuf, int bufsize)
{
	time_t t = time(NULL);
	strftime(reinterpret_cast<char*>(timebuf), 64, "%Y/%m/%d %a %H:%M:%S", localtime(&t));
}

void OCALL_fwrite(uint8_t *buf, int buflen)
{
	ofstream ofs("sealed.txt", ios::binary | ios::trunc);
	
	ofs.write(reinterpret_cast<const char*>(buf), buflen);
}

void OCALL_fread(uint8_t *buf, int buflen)
{
	string tmp, tmp2;

	ifstream ifs("sealed2.txt", ios::binary);

	if(!ifs)
	{
		cout << "failed to open file." << endl;
	}


	ifs.read(reinterpret_cast<char*>(buf), buflen);

}

void OCALL_get_sealed_length(char *dataset_name, int *sealed_length)
{
	string dataname_str(dataset_name);

	string query = "SELECT * FROM stored_data WHERE dataname = '";
	query += dataname_str;
	query += "'";

	string cond = "cipherlen";

	*sealed_length = bdb.do_executeQueryInt(query, cond);
}

void OCALL_chrono_start()
{
	chrono_start = chrono::system_clock::now();
}

void OCALL_chrono_end()
{
	chrono_end = chrono::system_clock::now();
	double elapsed = chrono::duration_cast<chrono::milliseconds>
		(chrono_end - chrono_start).count();

	cout << endl;
	cout << "-----------------------------------------------" << endl;
	cout << "Elapsed time is: " << elapsed << "[ms]" << endl;
	cout << "-----------------------------------------------" << endl;
	cout << endl;
}

void OCALL_chrono_end_get_time(double *elapsed)
{
	chrono_end = chrono::system_clock::now();
	*elapsed = chrono::duration_cast<chrono::milliseconds>
		(chrono_end - chrono_start).count();
}

/*referred: https://ryozi.hatenadiary.jp/entry/20101203/1291380670 in 12/30/2018*/
int base64_encrypt(uint8_t *src, int srclen, uint8_t *dst, int dstlen)
{
	const char Base64char[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	int i,j;
	int calclength = (srclen/3*4) + (srclen%3?4:0);
	if(calclength > dstlen) return -1;
	
	j=0;
	for(i=0; i+2<srclen; i+=3){
		dst[j++] = Base64char[ (src[i] >> 2) & 0x3F ];
		dst[j++] = Base64char[ (src[i] << 4 | src[i+1] >> 4) & 0x3F ];
		dst[j++] = Base64char[ (src[i+1] << 2 | src[i+2] >> 6) & 0x3F ];
		dst[j++] = Base64char[ (src[i+2]) & 0x3F ];
	}
	
	if(i<srclen){
		dst[j++] = Base64char[ (src[i] >> 2) & 0x3F ];
		if(i+1<srclen){
			dst[j++] = Base64char[ (src[i] << 4 | src[i+1] >> 4) & 0x3F ];
			if(i+2<srclen){
				dst[j++] = Base64char[ (src[i+1] << 2 | src[i+2] >> 6) & 0x3F ];
			}else{
				dst[j++] = Base64char[ (src[i+1] << 2) & 0x3F ];
			}
		}else{
			dst[j++] = Base64char[ (src[i] << 4) & 0x3F ];
		}
	}
	while(j%4) dst[j++] = '=';
	
	if(j<dstlen) dst[j] = '\0';
	return j;
}

int base64_decrypt(uint8_t *src, int srclen, uint8_t *dst, int dstlen)
{
	const unsigned char Base64num[] = {
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x3E,0xFF,0xFF,0xFF,0x3F,
		0x34,0x35,0x36,0x37,0x38,0x39,0x3A,0x3B,0x3C,0x3D,0xFF,0xFF,0xFF,0x00,0xFF,0xFF,
		0xFF,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,
		0x0F,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0xFF,0xFF,0xFF,0xFF,0xFF,
		0xFF,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,
		0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F,0x30,0x31,0x32,0x33,0xFF,0xFF,0xFF,0xFF,0xFF,
		
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	};
	int calclength = (srclen/4*3);
	int i,j;
	if(calclength > dstlen || srclen % 4 != 0) return 0;
	
	j=0;
	for(i=0; i+3<srclen; i+=4){
		if((Base64num[src[i+0]]|Base64num[src[i+1]]|Base64num[src[i+2]]|Base64num[src[i+3]]) > 0x3F){
			return -1;
		}
		dst[j++] = Base64num[src[i+0]]<<2 | Base64num[src[i+1]] >> 4;
		dst[j++] = Base64num[src[i+1]]<<4 | Base64num[src[i+2]] >> 2;
		dst[j++] = Base64num[src[i+2]]<<6 | Base64num[src[i+3]];
	}
	
	if(j<dstlen) dst[j] = '\0';
	return j;
}

void OCALL_load_db(uint8_t *sealed_data, int buflen, char *dataset_name)
{
	string dataname_str(dataset_name);

	string query = "SELECT * FROM stored_data WHERE dataname = '";
	query += dataname_str;
	query += "'";

	string cond = "data";

	string str_to_load = bdb.do_executeQuery(query, cond);

	int sealedlen;
	int sealedb64len = str_to_load.length();

	uint8_t *sealedb64 = 
		reinterpret_cast<uint8_t*>(const_cast<char*>(str_to_load.c_str()));

	sealedlen = base64_decrypt(sealedb64,
		sealedb64len, sealed_data, sealedb64len);
}

int OCALL_select_annotation(char *id, char *record, 
	int vcf_or_list, int clinvar_flag)
{
	try
	{
		string id_str(id);

		string query = "SELECT * FROM vcf WHERE ID = '";
		query += id_str;
		query += "'";

		string record_str = bdb.do_executeQuery_Annotation(query, 
			vcf_or_list, clinvar_flag);

		if(record_str == "")
		{
			record_str += "WARNING: Designated annotation '";
			record_str += id_str;
			record_str += "' is not found.";
		}

		int record_len = record_str.length() + 1;

		char *temp = new char[record_len]();
		temp = (char*)record_str.c_str();

		for(int i = 0; i < record_len; i++)
		{
			record[i] = temp[i];
		}

	}
	catch(sql::SQLException &e)
	{
		cerr << "# ERR: SQLException in " << __FILE__ << " on line " << __LINE__ << endl;
		cerr << "# ERR: " << e.what() << endl;
		cerr << " (MySQL error code: " << e.getErrorCode();
		cerr << ", SQLState: " << e.getSQLState() << ")" << endl;

		return -1;
	}

	return 0;

}

void OCALL_calc_inquiryDB_size(int *inquired_size)
{
	string inquiry_res = "";

	inquiry_res = bdb.do_inquiryDB();

	*inquired_size = inquiry_res.length();
}

void OCALL_inquiryDB(uint8_t *inquiry_res, int buflen)
{
	string inquiry_res_str = "";

	inquiry_res_str = bdb.do_inquiryDB();

	uint8_t *dummy = reinterpret_cast<uint8_t*>
		(const_cast<char*>(inquiry_res_str.c_str()));


	for(int i = 0; i < strlen((char*)dummy); i++)
	{
		inquiry_res[i] = dummy[i];
	}
}


int receive_login_info(MsgIO *msgio, sgx_enclave_id_t eid, BISGX_Database *bdb, string *datatype_str)
{
	int rv;
	size_t sz;
	void **received_cipher;
	void **received_iv;
	void **received_tag;
	void **received_deflen;
	size_t cipherb64len, ivb64len, tagb64len, recvdeflen;

	rv = msgio->read((void **) &received_cipher, &sz);

	if ( rv == -1 ) {
		eprintf("system error reading secret from SP\n");
		return -1;
	} else if ( rv == 0 ) {
		eprintf("protocol error reading secret from SP\n");
		return -1;
	}

	cipherb64len = sz / 2;

	
	rv = msgio->read((void **) &received_iv, &sz);

	if(rv == -1) {
		eprintf("system error reading IV from SP\n");
		return -1;
	} else if ( rv == 0 ) {
		eprintf("protocol error reading IV from SP\n");
		return -1;
	}

	ivb64len = sz / 2;

	
	rv = msgio->read((void **) &received_tag, &sz);

	if ( rv == -1 ) {
		eprintf("system error reading MAC tag from SP\n");
		return -1;
	} else if ( rv == 0 ) {
		eprintf("protocol error reading MAC tag from SP\n");
		return -1;
	}

	tagb64len = sz / 2;

	
	rv = msgio->read((void **) &received_deflen, &sz);

	if ( rv == -1 ) {
		eprintf("system error reading default cipher length from SP\n");
		return -1;
	} else if ( rv == 0 ) {
		eprintf("protocol error reading default cipher length from SP\n");
		return -1;
	}

	recvdeflen = sz / 2;


	/*
	unsigned char *cipher_to_enclave = (unsigned char *) received_cipher;
	cout << "cipherlen uint8_t: " << (unsigned char *) received_len << endl;
	size_t cipherlen = (size_t)received_len[0];
	*/

	/*Obtain base64-ed cipher text from received pointer*/
	unsigned char *cipherb64 = (unsigned char *) received_cipher;
	//cout << "Received base64-ed cipher is: " << endl;
	//cout << cipherb64 << endl << endl;
	
	size_t cipherb64_len = strlen((char*)cipherb64);
	//cout << "Base64-ed cipher's length is: " << cipherb64_len << endl;

	/*Next, obtain base64-ed IV*/
	unsigned char *ivb64 = (unsigned char *) received_iv;
	//cout << "Received base64-ed IV is: " << endl;
	//cout << ivb64 << endl << endl;

	/*Then obtain base64-ed MAC tag*/
	unsigned char *tagb64 = (unsigned char *) received_tag;
	//cout << "Received base64-ed MAC tag is: " << endl;
	//cout << tagb64 << endl << endl;

	size_t tagb64_len = strlen((char*)tagb64);
	//cout << "Base64-ed MAC tag's length is: " << tagb64_len << endl;


	/*In addition to that, obtain base64-ed default cipher length*/
	unsigned char *deflenb64 = (unsigned char *) received_deflen;

	//cout << "Received base64-ed default cipher length is: " << endl;
	//cout << deflenb64 << endl << endl;



	int deflen, rettmp, deftaglen = 16;
	uint8_t cipherb64lentmp[32] = {'\0'}, tagb64lentmp[32] = {'\0'};
	uint8_t deflentmp[128] = {'\0'};
	uint8_t deftaglentmp[32] = {'\0'};
	uint8_t *cipher_to_enclave;
	uint8_t iv_to_enclave[12];
	uint8_t tag_to_enclave[16];

	
	/*Decrypt default cipher's length from base64*/
	rettmp = base64_decrypt(deflenb64, recvdeflen, deflentmp, 32);
	deflen = strtol((char*)deflentmp, NULL, 10);

	cout << "Decrypted default cipher length is: " << deflen << endl;
	cout << "rettmp: " << rettmp << endl;
	

	/*Decrypt cipher from base64*/
	cipher_to_enclave = new uint8_t[cipherb64len];
	int cipherlen;

	cipherlen = base64_decrypt(cipherb64, cipherb64len, cipher_to_enclave, cipherb64len);

	/*
	cout << "Cipher length is: " << cipherlen << endl;
	cout << "Cipher decoded from base64 is: " << endl;
	BIO_dump_fp(stdout, (const char*)cipher_to_enclave, cipherlen);
	*/

	/*Decrypt iv from base64*/
	int ivlen;
	uint8_t iv_tmp[32] = {'\0'};

	ivlen = base64_decrypt(ivb64, ivb64len, iv_tmp, 32);
	
	
	cout << "IV length is (must be 12): " << ivlen << endl;
	cout << "IV decoded from base64 is: " << endl;
	BIO_dump_fp(stdout, (const char*)iv_tmp, ivlen);

	for(int i = 0; i < 12; i++)
	{
		iv_to_enclave[i] = iv_tmp[i];
	}


	/*Decrypt tag from base64*/
	int taglen;
	uint8_t tag_tmp[32] = {'\0'};

	taglen = base64_decrypt(tagb64, tagb64len, tag_tmp, 32);

	cout << "Tag length is (must be 16, but maybe some offset): " << taglen << endl;
	cout << "Tag decoded from base64 is: " << endl;
	BIO_dump_fp(stdout, (const char*)tag_tmp, taglen);

	for(int i = 0; i < 16; i++)
	{
		tag_to_enclave[i] = tag_tmp[i];
	}

	cout << "Execute ECALL with passing cipher data." << endl;

	uint8_t result_cipher[1024] = {'\0'};
	size_t result_len = -9999;
	sgx_status_t retval;

	uint8_t username[32] = {'\0'};
	uint8_t password_hash[33] = {'\0'};
	uint8_t privilege[2] = {'\0'};
	uint8_t datatype[8] = {'\0'};

	cout << "Check cipher_to_enclave before pass: " << endl;
	OCALL_dump(cipher_to_enclave, cipherlen);

	sgx_status_t login_status = process_login_info(eid, &retval, g_ra_ctx, 
		cipher_to_enclave, (size_t)deflen, iv_to_enclave, tag_to_enclave, 
		result_cipher, &result_len, username, password_hash, privilege,
		datatype);

	uint8_t phash_hex[65] = {'\0'};

	/*raw binary may cause bug with SQL statement, so convert to hex string*/
	for(int i = 0; i < 32; i++)
	{
		sprintf((char*)&phash_hex[i*2], "%02x", password_hash[i]);
	}

	string username_str(reinterpret_cast<char*>(username));
	string phash_hex_str(reinterpret_cast<char*>(phash_hex));
	string privilege_str(reinterpret_cast<char*>(privilege));
	string dtstr_tmp(reinterpret_cast<char*>(datatype));

	*datatype_str = dtstr_tmp;

	bdb->setUsername(username_str);

	try
	{
		bdb->switchTable(string("userinfo"));
		int flag = bdb->do_login(username_str, phash_hex_str, privilege_str);

		return flag;
	}
	catch(sql::SQLException &e)
	{
		cerr << "# ERR: SQLException in " << __FILE__ << " on line " << __LINE__ << endl;
		cerr << "# ERR: " << e.what() << endl;
		cerr << " (MySQL error code: " << e.getErrorCode();
		cerr << ", SQLState: " << e.getSQLState() << ")" << endl;

		return 2;
	}
}


void msgio_read_error_check(int rv, string str)
{
	if(rv == -1)
	{
		string emsg = "system error reading ";
		emsg += str;
		emsg += " from ISV\n";

		eprintf(emsg.c_str());
	}
	else if(rv == 0)
	{
		string emsg = "protocol error reading ";
		emsg += str;
		emsg += " from ISV\n";

		eprintf(emsg.c_str());
	}
}

int main (int argc, char *argv[])
{
	config_t config;
	sgx_launch_token_t token= { 0 };
	sgx_status_t status;
	sgx_enclave_id_t eid= 0;
	int updated= 0;
	int sgx_support;
	uint32_t i;
	EVP_PKEY *service_public_key= NULL;
	char have_spid= 0;
	char flag_stdio= 0;

	try
	{
		bdb.initDB();
	}
	catch(sql::SQLException &e)
	{
		cerr << "# ERR: SQLException in " << __FILE__ << " on line " << __LINE__ << endl;
		cerr << "# ERR: " << e.what() << endl;
		cerr << " (MySQL error code: " << e.getErrorCode();
		cerr << ", SQLState: " << e.getSQLState() << ")" << endl;

		return EXIT_FAILURE;
	}
	
	cout << "*** INFO: ISV is running as SERVER(non-SGX term). ***" << endl;

	/* Create a logfile to capture debug output and actual msg data */
	fplog = create_logfile("client.log");
	dividerWithText(fplog, "Client Log Timestamp");

	const time_t timeT = time(NULL);
	struct tm lt, *ltp;

#ifndef _WIN32
	ltp = localtime(&timeT);
	if ( ltp == NULL ) {
		perror("localtime");
		return 1;
	}
	lt= *ltp;
#else

	localtime_s(&lt, &timeT);
#endif
	fprintf(fplog, "%4d-%02d-%02d %02d:%02d:%02d\n", 
		lt.tm_year + 1900, 
		lt.tm_mon + 1, 
		lt.tm_mday,  
		lt.tm_hour, 
		lt.tm_min, 
		lt.tm_sec);
	divider(fplog);


	memset(&config, 0, sizeof(config));
	config.mode= MODE_ATTEST;

	static struct option long_opt[] =
	{
		{"help",		no_argument,		0, 'h'},		
		{"debug",		no_argument,		0, 'd'},
		{"epid-gid",	no_argument,		0, 'e'},
		{"pse-manifest",
						no_argument,    	0, 'm'},
		{"nonce",		required_argument,	0, 'n'},
		{"nonce-file",	required_argument,	0, 'N'},
		{"rand-nonce",	no_argument,		0, 'r'},
		{"spid",		required_argument,	0, 's'},
		{"spid-file",	required_argument,	0, 'S'},
		{"linkable",	no_argument,		0, 'l'},
		{"pubkey",		optional_argument,	0, 'p'},
		{"pubkey-file",	required_argument,	0, 'P'},
		{"quote",		no_argument,		0, 'q'},
		{"verbose",		no_argument,		0, 'v'},
		{"stdio",		no_argument,		0, 'z'},
		{ 0, 0, 0, 0 }
	};

	/* Parse our options */

	while (1) {
		int c;
		int opt_index= 0;
		unsigned char keyin[64];

		c= getopt_long(argc, argv, "N:P:S:dehlmn:p:qrs:vz", long_opt,
			&opt_index);
		if ( c == -1 ) break;

		switch(c) {
		case 0:
			break;
		case 'N':
			if ( ! from_hexstring_file((unsigned char *) &config.nonce,
					optarg, 16)) {

				fprintf(stderr, "nonce must be 32-byte hex string\n");
				exit(1);
			}
			SET_OPT(config.flags, OPT_NONCE);

			break;
		case 'P':
			if ( ! key_load_file(&service_public_key, optarg, KEY_PUBLIC) ) {
				fprintf(stderr, "%s: ", optarg);
				crypto_perror("key_load_file");
				exit(1);
			} 

			if ( ! key_to_sgx_ec256(&config.pubkey, service_public_key) ) {
				fprintf(stderr, "%s: ", optarg);
				crypto_perror("key_to_sgx_ec256");
				exit(1);
			}
			SET_OPT(config.flags, OPT_PUBKEY);

			break;
		case 'S':
			if ( ! from_hexstring_file((unsigned char *) &config.spid,
					optarg, 16)) {

				fprintf(stderr, "SPID must be 32-byte hex string\n");
				exit(1);
			}
			++have_spid;

			break;
		case 'd':
			debug= 1;
			break;
		case 'e':
			config.mode= MODE_EPID;
			break;
		case 'l':
			SET_OPT(config.flags, OPT_LINK);
			break;
		case 'm':
			SET_OPT(config.flags, OPT_PSE);
			break;
		case 'n':
			if ( strlen(optarg) < 32 ) {
				fprintf(stderr, "nonce must be 32-byte hex string\n");
				exit(1);
			}
			if ( ! from_hexstring((unsigned char *) &config.nonce,
					(unsigned char *) optarg, 16) ) {

				fprintf(stderr, "nonce must be 32-byte hex string\n");
				exit(1);
			}

			SET_OPT(config.flags, OPT_NONCE);

			break;
		case 'p':
			if ( ! from_hexstring((unsigned char *) keyin,
					(unsigned char *) optarg, 64)) {

				fprintf(stderr, "key must be 128-byte hex string\n");
				exit(1);
			}

			/* Reverse the byte stream to make a little endien style value */
			for(i= 0; i< 32; ++i) config.pubkey.gx[i]= keyin[31-i];
			for(i= 0; i< 32; ++i) config.pubkey.gy[i]= keyin[63-i];

			SET_OPT(config.flags, OPT_PUBKEY);

			break;
		case 'q':
			config.mode = MODE_QUOTE;
			break;
		case 'r':
			for(i= 0; i< 2; ++i) {
				int retry= 10;
				unsigned char ok= 0;
				uint64_t *np= (uint64_t *) &config.nonce;

				while ( !ok && retry ) ok= _rdrand64_step(&np[i]);
				if ( ok == 0 ) {
					fprintf(stderr, "nonce: RDRAND underflow\n");
					exit(1);
				}
			}
			SET_OPT(config.flags, OPT_NONCE);
			break;
		case 's':
			if ( strlen(optarg) < 32 ) {
				fprintf(stderr, "SPID must be 32-byte hex string\n");
				exit(1);
			}
			if ( ! from_hexstring((unsigned char *) &config.spid,
					(unsigned char *) optarg, 16) ) {

				fprintf(stderr, "SPID must be 32-byte hex string\n");
				exit(1);
			}
			++have_spid;
			break;
		case 'v':
			verbose= 1;
			break;
		case 'z':
			flag_stdio= 1;
			break;
		case 'h':
		case '?':
		default:
			usage();
		}
	}

	argc-= optind;
	if ( argc > 1 ) usage();

	/* Remaining argument is host[:port] */

	if ( flag_stdio && argc ) usage();
	else if ( !flag_stdio && ! argc ) {
		// Default to localhost
		config.server= strdup("localhost");
		if ( config.server == NULL ) {
			perror("malloc");
			return 1;
		}
	} else if ( argc ) {
		char *cp;

		config.server= strdup(argv[optind]);
		if ( config.server == NULL ) {
			perror("malloc");
			return 1;
		}
		
		/* If there's a : then we have a port, too */
		cp= strchr(config.server, ':');
		if ( cp != NULL ) {
			*cp++= '\0';
			config.port= cp;
		}
	}

	if ( ! have_spid && config.mode != MODE_EPID ) {
		fprintf(stderr, "SPID required. Use one of --spid or --spid-file \n");
		return 1;
	}

	/* Can we run SGX? */

#ifndef SGX_HW_SIM
	sgx_support = get_sgx_support();
	if (sgx_support & SGX_SUPPORT_NO) {
		fprintf(stderr, "This system does not support Intel SGX.\n");
		return 1;
	} else {
		if (sgx_support & SGX_SUPPORT_ENABLE_REQUIRED) {
			fprintf(stderr, "Intel SGX is supported on this system but disabled in the BIOS\n");
			return 1;
		}
		else if (sgx_support & SGX_SUPPORT_REBOOT_REQUIRED) {
			fprintf(stderr, "Intel SGX will be enabled after the next reboot\n");
			return 1;
		}
		else if (!(sgx_support & SGX_SUPPORT_ENABLED)) {
			fprintf(stderr, "Intel SGX is supported on this sytem but not available for use\n");
			fprintf(stderr, "The system may lock BIOS support, or the Platform Software is not available\n");
			return 1;
		}
	} 
#endif

	/* Launch the enclave */

#ifdef _WIN32
	status = sgx_create_enclave(ENCLAVE_NAME, SGX_DEBUG_FLAG,
		&token, &updated, &eid, 0);
	if (status != SGX_SUCCESS) {
		fprintf(stderr, "sgx_create_enclave: %s: %08x\n",
			ENCLAVE_NAME, status);
		return 1;
	}
#else
	status = sgx_create_enclave_search(ENCLAVE_NAME,
		SGX_DEBUG_FLAG, &token, &updated, &eid, 0);
	if ( status != SGX_SUCCESS ) {
		fprintf(stderr, "sgx_create_enclave: %s: %08x\n",
			ENCLAVE_NAME, status);
		if ( status == SGX_ERROR_ENCLAVE_FILE_ACCESS ) 
			fprintf(stderr, "Did you forget to set LD_LIBRARY_PATH?\n");
		return 1;
	}
#endif

	if(config.server == NULL)
	{
		msgio = new MsgIO();
	}
	else
	{
		try
		{
			msgio = new MsgIO(NULL, (config.port == NULL) ?
				DEFAULT_PORT : config.port);
		}
		catch(...)
		{
			exit(1);
		}
	}

	bool isRAed = false;

	/* Are we attesting, or just spitting out a quote? */

	while(msgio->server_loop())
	{
		if ( config.mode == MODE_ATTEST ) {
			do_attestation(eid, &config);
		} else if ( config.mode == MODE_EPID || config.mode == MODE_QUOTE ) {
			do_quote(eid, &config);
		} else {
			fprintf(stderr, "Unknown operation mode.\n");
			return 1;
		}
	

		string datatype = "";

		cout << "RA completed. Receive login info from SP..." << endl;
		int login_flag = receive_login_info(msgio, eid, &bdb, &datatype);
		cout << "Receive secret data from SP... " << endl;
		
		if(datatype == "vcf")
		{
			int rv;
			size_t sz;
			void **received_vctx;
			void **received_iv_vctx;
			void **received_tag_vctx;
			void **received_deflen_vctx;
			size_t vctx_b64len, vctx_iv_b64len;
			size_t vctx_tag_b64len, vctx_deflen_b64len;

			uint8_t *uchar_vctx_b64;
			uint8_t *uchar_iv_vctx_b64;
			uint8_t *uchar_tag_vctx_b64;
			uint8_t *uchar_deflen_vctx_b64;
			uint8_t *void_to_uchar;

			rv = msgio->read_nd((void **) &received_vctx, &sz);
			vctx_b64len = sz;

			if(rv != 1)
			{
				msgio_read_error_check(rv, "secret");
				return -1;
			}

			uchar_vctx_b64 = new uint8_t[sz + 1]();
			void_to_uchar = (uint8_t*)received_vctx;

			for(int i = 0; i < sz; i++)
			{
				uchar_vctx_b64[i] = void_to_uchar[i];
			}



			rv = msgio->read_nd((void **) &received_iv_vctx, &sz);
			vctx_iv_b64len = sz;

			if(rv != 1)
			{
				msgio_read_error_check(rv, "IV");
				return -1;
			}

			uchar_iv_vctx_b64 = new uint8_t[sz + 1]();
			void_to_uchar = (uint8_t*)received_iv_vctx;

			for(int i = 0; i < sz; i++)
			{
				uchar_iv_vctx_b64[i] = void_to_uchar[i];
			}




			rv = msgio->read_nd((void **) &received_tag_vctx, &sz);
			vctx_tag_b64len = sz;

			if(rv != 1)
			{
				msgio_read_error_check(rv, "MAC tag");
				return -1;
			}

			uchar_tag_vctx_b64 = new uint8_t[sz + 1]();
			void_to_uchar = (uint8_t*)received_tag_vctx;
			
			for(int i = 0; i < sz; i++)
			{
				uchar_tag_vctx_b64[i] = void_to_uchar[i];
			}




			rv = msgio->read_nd((void **) &received_deflen_vctx, &sz);
			vctx_deflen_b64len = sz;

			if(rv != 1)
			{
				msgio_read_error_check(rv, "default cipher length");
				return -1;
			}

			uchar_deflen_vctx_b64 = new uint8_t[sz + 1]();
			void_to_uchar = (uint8_t*)received_deflen_vctx;

			for(int i = 0; i < sz; i++)
			{
				uchar_deflen_vctx_b64[i] = void_to_uchar[i];
			}

			

			cout << "IVb64:" << endl;
			cout << uchar_iv_vctx_b64 << endl;

			cout << "Tagb64:" << endl;
			cout << uchar_tag_vctx_b64 << endl;

			cout << "deflenb64:" << endl;
			cout << uchar_deflen_vctx_b64 << endl;

			cout << "vctxb64:" << endl;
			cout << uchar_vctx_b64 << endl;

			/* allocate heap excessively to avoid error with
			*  base64 function
			*/
			int vctx_deflen, rettmp;
			uint8_t *vctx_cipher;
			uint8_t *iv_vctx = new uint8_t[32]();
			uint8_t *tag_vctx = new uint8_t[32]();
			uint8_t *deflen_vctx_tmp = new uint8_t[128]();


			/* VCF context cipher length */
			rettmp = base64_decrypt(uchar_deflen_vctx_b64,
				vctx_deflen_b64len, deflen_vctx_tmp, 128);

			vctx_deflen = strtol((char*)deflen_vctx_tmp, NULL, 10);


			/* VCF context cipher */
			vctx_cipher = new uint8_t[vctx_deflen + 16]();

			rettmp = base64_decrypt(uchar_vctx_b64,
				vctx_b64len, vctx_cipher, vctx_deflen + 16);


			/* IV for VCF context cipher */
			rettmp = base64_decrypt(uchar_iv_vctx_b64, 
				vctx_iv_b64len, iv_vctx, 32);


			/* MAC tag for VCF context cipher*/
			rettmp = base64_decrypt(uchar_tag_vctx_b64,
				vctx_tag_b64len, tag_vctx, 32);


			
			cout << "deflen: " << vctx_deflen << endl;
			
			cout << "IV: " << endl;
			OCALL_dump(iv_vctx, 12);

			cout << "tag: " << endl;
			OCALL_dump(tag_vctx, 16);

			cout << "vctx cipher: " << endl;
			OCALL_dump(vctx_cipher, vctx_deflen);


			sgx_status_t retval;
			uint8_t *tar_filename = new uint8_t[16 + 1]();

			cout << "\nEnter enclave to extract given tar filename." << endl;

			sgx_status_t vst = process_extract_filename(eid, &retval, 
				g_ra_ctx, vctx_cipher, vctx_deflen, iv_vctx, tag_vctx, 
				tar_filename);


			/* create directory to store tarball */
			string mkdir_cmd = "mkdir -p encrypted_vcf/";
			mkdir_cmd += (char*)tar_filename;

			int sys_ret = system(mkdir_cmd.c_str());

			if(!WIFEXITED(sys_ret))
			{
				cerr << "Failed to create directory for tarball." << endl;
				return -1;
			}

			/*
			string tar_filename_str = "encrypted_vcf/";
			tar_filename_str += (char*)tar_filename;
			tar_filename_str += '/';
			*/
			string tar_filename_str = (char*)tar_filename;
			tar_filename_str += ".tar";

			cout << "Obtained filename: " << tar_filename_str << endl;

			ofstream tar_ofs(tar_filename_str, ios::app | ios::binary);

			if(!tar_ofs)
			{
				cerr << "Failed to open tarfile to write." << endl;
				return -1;
			}

			
			void **received_tarsize;
			uint64_t tarball_size = 0;

			rv = msgio->read_nd((void **) &received_tarsize, &sz);

			if(rv != 1)
			{
				msgio_read_error_check(rv, "tarball size");
				return -1;
			}


			tarball_size = strtol((char*)received_tarsize, NULL, 10);

			cout << "tarball size: " << tarball_size << endl;


			int round_num = tarball_size / ROUND_UNIT;

			if(tarball_size % ROUND_UNIT != 0)
			{
				round_num++;
			}


			for(int i = 0; i < round_num; i++)
			{
				void **received_tar;
				uint8_t *tar_binary;
				uint64_t tar_length;

				rv = msgio->read_nd((void**) &received_tar, &sz);

				if(rv != 1)
				{
					msgio_read_error_check(rv, "tarball");
					return -1;
				}

				tar_binary = new uint8_t[sz]();

				tar_length = base64_decrypt((uint8_t*)received_tar,
					sz, tar_binary, sz);

				
				if(tar_length >= ROUND_UNIT)
				{
					tar_ofs.write((char*)tar_binary, ROUND_UNIT);
				}
				else
				{
					tar_ofs.write((char*)tar_binary,
						tarball_size % ROUND_UNIT);
				}
	
				/*
				if(tar_length > ROUND_UNIT)
				{
					cerr << "Fatal error with file output." << endl;
					cerr << tar_length << endl;
					return -1;
				}
				*/

				if(!tar_ofs)
				{
					cerr << "Failed to write tarball." << endl;
					return -1;
				}

			}

			
			
			/* receive arrays of IV and MAC tags */
			void **received_iv_array;
			void **received_tag_array;
			int iv_array_length, tag_array_length;

			rv = msgio->read_nd((void**)&received_iv_array, &sz);

			if(rv != 1)
			{
				msgio_read_error_check(rv, "IV array");
				return -1;
			}

			iv_array_length = sz;


			rv = msgio->read_nd((void**)&received_tag_array, &sz);

			if(rv != 1)
			{
				msgio_read_error_check(rv, "MAC tag array");
				return -1;
			}

			tag_array_length = sz;



			/* extract data from tarball */
			string tar_cmd = "tar -xf " + string((char*)tar_filename);
			tar_cmd += ".tar";

			sys_ret = system(tar_cmd.c_str());

			if(!WIFEXITED(sys_ret))
			{
				cerr << "Failed to extract secret from tarball." << endl;
				return -1;
			}
			


			string rm_cmd = "rm -f " + string((char*)tar_filename);
			rm_cmd += ".tar";

			sys_ret = system(rm_cmd.c_str());

			if(!WIFEXITED(sys_ret))
			{
				cerr << "Failed to delete unnecessary tarball." << endl;
				cerr << "Please delete it manually." << endl;
			}



			/* register vcf contexts */


			/* seal session key and store */

			/* destruct heaps */
			delete(tar_filename);
			delete(vctx_cipher);
			delete(iv_vctx);
			delete(tag_vctx);
			delete(vctx_cipher);
		}
		else
		{
			int rv;
			size_t sz;
			void **received_cipher;
			void **received_iv;
			void **received_tag;
			void **received_deflen;
			size_t cipherb64len, ivb64len, tagb64len, recvdeflen;

			rv = msgio->read((void **) &received_iv, &sz);

			if(rv == -1) {
				eprintf("system error reading IV from SP\n");
				return 0;
			} else if ( rv == 0 ) {
				eprintf("protocol error reading IV from SP\n");
				return 0;
			}

			ivb64len = sz / 2;

			
			rv = msgio->read((void **) &received_tag, &sz);

			if ( rv == -1 ) {
				eprintf("system error reading MAC tag from SP\n");
				return 0;
			} else if ( rv == 0 ) {
				eprintf("protocol error reading MAC tag from SP\n");
				return 0;
			}

			tagb64len = sz / 2;

			
			rv = msgio->read((void **) &received_deflen, &sz);

			if ( rv == -1 ) {
				eprintf("system error reading default cipher length from SP\n");
				return 0;
			} else if ( rv == 0 ) {
				eprintf("protocol error reading default cipher length from SP\n");
				return 0;
			}

			recvdeflen = sz / 2;

			rv = msgio->read_nd((void **) &received_cipher, &sz);

			if ( rv == -1 ) {
				eprintf("system error reading secret from SP\n");
				return 0;
			} else if ( rv == 0 ) {
				eprintf("protocol error reading secret from SP\n");
				return 0;
			}

			cipherb64len = sz;


			/*
			unsigned char *cipher_to_enclave = (unsigned char *) received_cipher;
			cout << "cipherlen uint8_t: " << (unsigned char *) received_len << endl;
			size_t cipherlen = (size_t)received_len[0];
			*/

			/*Obtain base64-ed cipher text from received pointer*/
			unsigned char *cipherb64 = (unsigned char *) received_cipher;
			//cout << "Received base64-ed cipher is: " << endl;
			//cout << cipherb64 << endl << endl;
			
			size_t cipherb64_len = strlen((char*)cipherb64);
			cout << "Base64-ed cipher's length is: " << cipherb64_len << endl;

			/*Next, obtain base64-ed IV*/
			unsigned char *ivb64 = (unsigned char *) received_iv;
			cout << "Received base64-ed IV is: " << endl;
			cout << ivb64 << endl << endl;

			/*Then obtain base64-ed MAC tag*/
			unsigned char *tagb64 = (unsigned char *) received_tag;
			cout << "Received base64-ed MAC tag is: " << endl;
			cout << tagb64 << endl << endl;

			size_t tagb64_len = strlen((char*)tagb64);
			cout << "Base64-ed MAC tag's length is: " << tagb64_len << endl;


			/*In addition to that, obtain base64-ed default cipher length*/
			unsigned char *deflenb64 = (unsigned char *) received_deflen;

			cout << "Received base64-ed default cipher length is: " << endl;
			cout << deflenb64 << endl << endl;



			int deflen, rettmp, deftaglen = 16;
			uint8_t cipherb64lentmp[32] = {'\0'}, tagb64lentmp[32] = {'\0'};
			uint8_t deflentmp[128] = {'\0'};
			uint8_t deftaglentmp[32] = {'\0'};
			uint8_t *cipher_to_enclave;
			uint8_t iv_to_enclave[12];
			uint8_t tag_to_enclave[16];

			
			/*Decrypt default cipher's length from base64*/
			rettmp = base64_decrypt(deflenb64, recvdeflen, deflentmp, 32);
			deflen = strtol((char*)deflentmp, NULL, 10);

			cout << "Decrypted default cipher length is: " << deflen << endl;
			cout << "rettmp: " << rettmp << endl;
			

			/*Decrypt cipher from base64*/
			cipher_to_enclave = new uint8_t[cipherb64len];
			int cipherlen;

			cipherlen = base64_decrypt(cipherb64, cipherb64len, cipher_to_enclave, cipherb64len);

			//cout << "Cipher length is: " << cipherlen << endl;
			//cout << "Cipher decoded from base64 is: " << endl;
			//BIO_dump_fp(stdout, (const char*)cipher_to_enclave, cipherlen);

			/*Decrypt iv from base64*/
			int ivlen;
			uint8_t iv_tmp[32] = {'\0'};

			ivlen = base64_decrypt(ivb64, ivb64len, iv_tmp, 32);
			
			cout << "IV length is (must be 12): " << ivlen << endl;
			cout << "IV decoded from base64 is: " << endl;
			BIO_dump_fp(stdout, (const char*)iv_tmp, ivlen);

			for(int i = 0; i < 12; i++)
			{
				iv_to_enclave[i] = iv_tmp[i];
			}

			/*Decrypt tag from base64*/
			int taglen;
			uint8_t tag_tmp[32] = {'\0'};

			taglen = base64_decrypt(tagb64, tagb64len, tag_tmp, 32);

			cout << "Tag length is (must be 16, but maybe some offset): " << taglen << endl;
			cout << "Tag decoded from base64 is: " << endl;
			BIO_dump_fp(stdout, (const char*)tag_tmp, taglen);

			for(int i = 0; i < 16; i++)
			{
				tag_to_enclave[i] = tag_tmp[i];
			}

			cout << "Execute ECALL with passing cipher data." << endl;

			//uint8_t result_cipher[20000000] = {'\0'};
			uint8_t *result_cipher;
			size_t result_len = -9999;
			sgx_status_t retval, ecall_status;


			if(login_flag == 0)//Owner
			{
				size_t store_flag = 0;
				result_cipher = new uint8_t[cipherlen + 1000];

				try
				{
					OCALL_chrono_start();
					ecall_status = seal_data(eid, &retval, g_ra_ctx, cipher_to_enclave, 
					(size_t)deflen, iv_to_enclave, tag_to_enclave, result_cipher,
					cipherlen + 1000, &result_len);

					if(ecall_status != SGX_SUCCESS)
					{
						sgx_error_print(ecall_status);
						store_flag = 1;
					}

					uint8_t *b64_to_store = new uint8_t[result_len * 2];
					int b64_to_store_len;

					b64_to_store_len = base64_encrypt(result_cipher, result_len,
							b64_to_store, result_len * 2);

					//OCALL_dump(b64_to_store, b64_to_store_len);

					string string_to_store(reinterpret_cast<char*>(b64_to_store));

					bdb.storeDB(string_to_store, datatype, result_len);
		
					OCALL_chrono_end();

				}
				catch(sql::SQLException &e)
				{
					cerr << "# ERR: SQLException in " << __FILE__ << " on line " << __LINE__ << endl;
					cerr << "# ERR: " << e.what() << endl;
					cerr << " (MySQL error code: " << e.getErrorCode();
					cerr << ", SQLState: " << e.getSQLState() << ")" << endl;

					store_flag = 1;
				}

				ecall_status = encrypt_store_status(eid, &retval, g_ra_ctx, store_flag, 
					iv_to_enclave, tag_to_enclave, result_cipher, &result_len);

			}
			else if(login_flag == 1)//Researcher
			{
				result_cipher = new uint8_t[1000000];

				ecall_status = run_interpreter(eid, &retval, g_ra_ctx,
					cipher_to_enclave, (size_t)deflen, iv_to_enclave,
					tag_to_enclave, result_cipher, &result_len);
			}
			else
			{
				//return password error
			}
			
			if(ecall_status != SGX_SUCCESS)
			{
				sgx_error_print(ecall_status);
			}

			cout << "\nExited ECALL successfully. Check the returned data." << endl;
			cout << "Result from enclave: " << dec << result_len << endl << endl;

			cout << "Cipher: " << endl;
			BIO_dump_fp(stdout, (const char*)result_cipher, result_len);

			cout << "\nIV: " << endl;
			BIO_dump_fp(stdout, (const char*)iv_to_enclave, 12);

			cout << "\nTag: " << endl;
			BIO_dump_fp(stdout, (const char*)tag_to_enclave, 16);


			/*Convert result contexts to base64 format*/
			uint8_t* res_cipherb64 = new uint8_t[result_len * 2];
			uint8_t res_ivb64[64] = {'\0'};
			uint8_t res_tagb64[64] = {'\0'};
			uint8_t res_deflenb64[128] = {'\0'};
			int res_cipherb64_len, res_ivb64_len, res_tagb64_len, res_deflenb64_len;

			/*Encode result cipher*/
			res_cipherb64_len = base64_encrypt(result_cipher, result_len,
						res_cipherb64, result_len * 2);

			/*Encode result IV*/
			res_ivb64_len = base64_encrypt(iv_to_enclave, 12, res_ivb64, 64);

			/*Encode result MAC tag*/
			res_tagb64_len = base64_encrypt(tag_to_enclave, 16, res_tagb64, 64);

			/*Encode result cipher's length*/
			uint8_t *resdeflentmp = 
				const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(to_string(result_len).c_str()));

			res_deflenb64_len = 
				base64_encrypt(resdeflentmp, strlen((char*)resdeflentmp), res_deflenb64, 128);


			/*Base64 value check*/
			cout << "========================================================================" << endl;
			cout << "result cipher in base64: " << endl;
			cout << res_cipherb64 << endl;
			cout << "========================================================================" << endl;
			cout << "result IV in base64: " << endl;
			cout << res_ivb64 << endl;
			cout << "========================================================================" << endl;
			cout << "result tag in base64: " << endl;
			cout << res_tagb64 << endl;
			cout << "========================================================================" << endl;
			cout << "result cipher's length in base64" << endl;
			cout << res_deflenb64 << endl;
			cout << "========================================================================" << endl;
			cout << endl;

			/*send base64-ed result cipher to SP*/
			cout << "========================================================================" << endl;
			cout << "Send encrypted result to SP." << endl;
			
			cout << "Encrypted result to be sent is: " << endl;
			msgio->send(res_cipherb64, strlen((char*)res_cipherb64));

			cout << "Complete sending message." << endl;
			cout << "Please wait for 0.25 sec." << endl;
			cout << "========================================================================" << endl;

			usleep(250000);

			/*send base64-ed IV to SP*/
			cout << "IV to be sent is: " << endl;
			msgio->send(res_ivb64, strlen((char*)res_ivb64));

			cout << "Complete sending message." << endl;
			cout << "Please wait for 0.25 sec." << endl;
			cout << "========================================================================" << endl;
			
			usleep(250000);

			/*send base64-ed MAC tag to SP*/
			cout << "Tag to be sent is: " << endl;
			msgio->send(res_tagb64, strlen((char*)res_tagb64));

			cout << "Complete sending message." << endl;
			cout << "Please wait for 0.25 sec." << endl;
			cout << "========================================================================" << endl;

			usleep(250000);

			/*send base64-ed result cipher length to SP*/
			cout << "Result cipher's length to be sent is: " << endl;
			msgio->send(res_deflenb64, strlen((char*)res_deflenb64));

			cout << "Complete sending message." << endl;
			cout << "Please wait for 0.25 sec." << endl;
			cout << "========================================================================" << endl;
			
			cout << "Complete sending result contexts to SP." << endl << endl;
			//enclave_ra_close(eid, &g_sgxrv, g_ra_ctx);
		}
	}
	enclave_ra_close(eid, &g_sgxrv, g_ra_ctx);
     
	close_logfile(fplog);

	return 0;
}

int do_attestation (sgx_enclave_id_t eid, config_t *config)
{
	sgx_status_t status, sgxrv, pse_status;
	sgx_ra_msg1_t msg1;
	sgx_ra_msg2_t *msg2 = NULL;
	sgx_ra_msg3_t *msg3 = NULL;
	ra_msg4_t *msg4 = NULL;
	uint32_t msg0_extended_epid_group_id = 0;
	uint32_t msg3_sz;
	uint32_t flags= config->flags;
	sgx_ra_context_t ra_ctx= 0xdeadbeef;
	int rv;
	//MsgIO *msgio;
	size_t msg4sz = 0;
	int enclaveTrusted = NotTrusted; // Not Trusted
	int b_pse= OPT_ISSET(flags, OPT_PSE);

	/*
	if ( config->server == NULL ) {
		msgio = new MsgIO();
	} else {
		try {
			msgio = new MsgIO(config->server, (config->port == NULL) ?
				DEFAULT_PORT : config->port);
		}
		catch(...) {
			exit(1);
		}
	}
	*/

	/*
	 * WARNING! Normally, the public key would be hardcoded into the
	 * enclave, not passed in as a parameter. Hardcoding prevents
	 * the enclave using an unauthorized key.
	 *
	 * This is diagnostic/test application, however, so we have
	 * the flexibility of a dynamically assigned key.
	 */

	/* Executes an ECALL that runs sgx_ra_init() */

	if ( OPT_ISSET(flags, OPT_PUBKEY) ) {
		if ( debug ) fprintf(stderr, "+++ using supplied public key\n");
		status= enclave_ra_init(eid, &sgxrv, config->pubkey, b_pse,
			&ra_ctx, &pse_status);
	} else {
		if ( debug ) fprintf(stderr, "+++ using default public key\n");
		status= enclave_ra_init_def(eid, &sgxrv, b_pse, &ra_ctx,
			&pse_status);
	}

	/* Did the ECALL succeed? */
	if ( status != SGX_SUCCESS ) {
		fprintf(stderr, "enclave_ra_init: %08x\n", status);
		delete msgio;
		return 1;
	}

	/* If we asked for a PSE session, did that succeed? */
	if (b_pse) {
		if ( pse_status != SGX_SUCCESS ) {
			fprintf(stderr, "pse_session: %08x\n", sgxrv);
			delete msgio;
			return 1;
		}
	}

	/* Did sgx_ra_init() succeed? */
	if ( sgxrv != SGX_SUCCESS ) {
		fprintf(stderr, "sgx_ra_init: %08x\n", sgxrv);
		delete msgio;
		return 1;
	}

	/* Generate msg0 */

	status = sgx_get_extended_epid_group_id(&msg0_extended_epid_group_id);
	if ( status != SGX_SUCCESS ) {
		enclave_ra_close(eid, &sgxrv, ra_ctx); 
		fprintf(stderr, "sgx_get_extended_epid_group_id: %08x\n", status);
		delete msgio;
		return 1;
	}
	if ( verbose ) {
		dividerWithText(stderr, "Msg0 Details");
		dividerWithText(fplog, "Msg0 Details");
		fprintf(stderr,   "Extended Epid Group ID: ");
		fprintf(fplog,   "Extended Epid Group ID: ");
		print_hexstring(stderr, &msg0_extended_epid_group_id,
			 sizeof(uint32_t));
		print_hexstring(fplog, &msg0_extended_epid_group_id,
			 sizeof(uint32_t));
		fprintf(stderr, "\n");
		fprintf(fplog, "\n");
		divider(stderr);
		divider(fplog);
	}
 
	/* Generate msg1 */

	status= sgx_ra_get_msg1(ra_ctx, eid, sgx_ra_get_ga, &msg1);
	if ( status != SGX_SUCCESS ) {
		enclave_ra_close(eid, &sgxrv, ra_ctx);
		fprintf(stderr, "sgx_ra_get_msg1: %08x\n", status);
		fprintf(fplog, "sgx_ra_get_msg1: %08x\n", status);
		delete msgio;
		return 1;
	}

	if ( verbose ) {
		dividerWithText(stderr,"Msg1 Details");
		dividerWithText(fplog,"Msg1 Details");
		fprintf(stderr,   "msg1.g_a.gx = ");
		fprintf(fplog,   "msg1.g_a.gx = ");
		print_hexstring(stderr, msg1.g_a.gx, 32);
		print_hexstring(fplog, msg1.g_a.gx, 32);
		fprintf(stderr, "\nmsg1.g_a.gy = ");
		fprintf(fplog, "\nmsg1.g_a.gy = ");
		print_hexstring(stderr, msg1.g_a.gy, 32);
		print_hexstring(fplog, msg1.g_a.gy, 32);
		fprintf(stderr, "\nmsg1.gid    = ");
		fprintf(fplog, "\nmsg1.gid    = ");
		print_hexstring(stderr, msg1.gid, 4);
		print_hexstring(fplog, msg1.gid, 4);
		fprintf(stderr, "\n");
		fprintf(fplog, "\n");
		divider(stderr);
		divider(fplog);
	}

	/*
	 * Send msg0 and msg1 concatenated together (msg0||msg1). We do
	 * this for efficiency, to eliminate an additional round-trip
	 * between client and server. The assumption here is that most
	 * clients have the correct extended_epid_group_id so it's
	 * a waste to send msg0 separately when the probability of a
	 * rejection is astronomically small.
	 *
	 * If it /is/ rejected, then the client has only wasted a tiny
	 * amount of time generating keys that won't be used.
	 */

	dividerWithText(fplog, "Msg0||Msg1 ==> SP");
	fsend_msg_partial(fplog, &msg0_extended_epid_group_id,
		sizeof(msg0_extended_epid_group_id));
	fsend_msg(fplog, &msg1, sizeof(msg1));
	divider(fplog);

	dividerWithText(stderr, "Copy/Paste Msg0||Msg1 Below to SP");
	msgio->send_partial(&msg0_extended_epid_group_id,
		sizeof(msg0_extended_epid_group_id));
	msgio->send(&msg1, sizeof(msg1));
	divider(stderr);

	fprintf(stderr, "Waiting for msg2\n");

	/* Read msg2 
	 *
	 * msg2 is variable length b/c it includes the revocation list at
	 * the end. msg2 is malloc'd in readZ_msg do free it when done.
	 */

	rv= msgio->read((void **) &msg2, NULL);
	if ( rv == 0 ) {
		enclave_ra_close(eid, &sgxrv, ra_ctx);
		fprintf(stderr, "protocol error reading msg2\n");
		delete msgio;
		exit(1);
	} else if ( rv == -1 ) {
		enclave_ra_close(eid, &sgxrv, ra_ctx);
		fprintf(stderr, "system error occurred while reading msg2\n");
		delete msgio;
		exit(1);
	}

	if ( verbose ) {
		dividerWithText(stderr, "Msg2 Details");
		dividerWithText(fplog, "Msg2 Details (Received from SP)");
		fprintf(stderr,   "msg2.g_b.gx      = ");
		fprintf(fplog,   "msg2.g_b.gx      = ");
		print_hexstring(stderr, &msg2->g_b.gx, sizeof(msg2->g_b.gx));
		print_hexstring(fplog, &msg2->g_b.gx, sizeof(msg2->g_b.gx));
		fprintf(stderr, "\nmsg2.g_b.gy      = ");
		fprintf(fplog, "\nmsg2.g_b.gy      = ");
		print_hexstring(stderr, &msg2->g_b.gy, sizeof(msg2->g_b.gy));
		print_hexstring(fplog, &msg2->g_b.gy, sizeof(msg2->g_b.gy));
		fprintf(stderr, "\nmsg2.spid        = ");
		fprintf(fplog, "\nmsg2.spid        = ");
		print_hexstring(stderr, &msg2->spid, sizeof(msg2->spid));
		print_hexstring(fplog, &msg2->spid, sizeof(msg2->spid));
		fprintf(stderr, "\nmsg2.quote_type  = ");
		fprintf(fplog, "\nmsg2.quote_type  = ");
		print_hexstring(stderr, &msg2->quote_type, sizeof(msg2->quote_type));
		print_hexstring(fplog, &msg2->quote_type, sizeof(msg2->quote_type));
		fprintf(stderr, "\nmsg2.kdf_id      = ");
		fprintf(fplog, "\nmsg2.kdf_id      = ");
		print_hexstring(stderr, &msg2->kdf_id, sizeof(msg2->kdf_id));
		print_hexstring(fplog, &msg2->kdf_id, sizeof(msg2->kdf_id));
		fprintf(stderr, "\nmsg2.sign_ga_gb  = ");
		fprintf(fplog, "\nmsg2.sign_ga_gb  = ");
		print_hexstring(stderr, &msg2->sign_gb_ga, sizeof(msg2->sign_gb_ga));
		print_hexstring(fplog, &msg2->sign_gb_ga, sizeof(msg2->sign_gb_ga));
		fprintf(stderr, "\nmsg2.mac         = ");
		fprintf(fplog, "\nmsg2.mac         = ");
		print_hexstring(stderr, &msg2->mac, sizeof(msg2->mac));
		print_hexstring(fplog, &msg2->mac, sizeof(msg2->mac));
		fprintf(stderr, "\nmsg2.sig_rl_size = ");
		fprintf(fplog, "\nmsg2.sig_rl_size = ");
		print_hexstring(stderr, &msg2->sig_rl_size, sizeof(msg2->sig_rl_size));
		print_hexstring(fplog, &msg2->sig_rl_size, sizeof(msg2->sig_rl_size));
		fprintf(stderr, "\nmsg2.sig_rl      = ");
		fprintf(fplog, "\nmsg2.sig_rl      = ");
		print_hexstring(stderr, &msg2->sig_rl, msg2->sig_rl_size);
		print_hexstring(fplog, &msg2->sig_rl, msg2->sig_rl_size);
		fprintf(stderr, "\n");
		fprintf(fplog, "\n");
		divider(stderr);
		divider(fplog);
	}

	if ( debug ) {
		fprintf(stderr, "+++ msg2_size = %zu\n",
			sizeof(sgx_ra_msg2_t)+msg2->sig_rl_size);
		fprintf(fplog, "+++ msg2_size = %zu\n",
			sizeof(sgx_ra_msg2_t)+msg2->sig_rl_size);
	}

	/* Process Msg2, Get Msg3  */
	/* object msg3 is malloc'd by SGX SDK, so remember to free when finished */

	msg3 = NULL;

	status = sgx_ra_proc_msg2(ra_ctx, eid,
		sgx_ra_proc_msg2_trusted, sgx_ra_get_msg3_trusted, msg2, 
		sizeof(sgx_ra_msg2_t) + msg2->sig_rl_size,
	    &msg3, &msg3_sz);

	free(msg2);

	if ( status != SGX_SUCCESS ) {
		enclave_ra_close(eid, &sgxrv, ra_ctx);
		fprintf(stderr, "sgx_ra_proc_msg2: %08x\n", status);
		fprintf(fplog, "sgx_ra_proc_msg2: %08x\n", status);

		delete msgio;
		return 1;
	} 

	if ( debug ) {
		fprintf(stderr, "+++ msg3_size = %u\n", msg3_sz);
		fprintf(fplog, "+++ msg3_size = %u\n", msg3_sz);
	}
	                          
	if ( verbose ) {
		dividerWithText(stderr, "Msg3 Details");
		dividerWithText(fplog, "Msg3 Details");
		fprintf(stderr,   "msg3.mac         = ");
		fprintf(fplog,   "msg3.mac         = ");
		print_hexstring(stderr, msg3->mac, sizeof(msg3->mac));
		print_hexstring(fplog, msg3->mac, sizeof(msg3->mac));
		fprintf(stderr, "\nmsg3.g_a.gx      = ");
		fprintf(fplog, "\nmsg3.g_a.gx      = ");
		print_hexstring(stderr, msg3->g_a.gx, sizeof(msg3->g_a.gx));
		print_hexstring(fplog, msg3->g_a.gx, sizeof(msg3->g_a.gx));
		fprintf(stderr, "\nmsg3.g_a.gy      = ");
		fprintf(fplog, "\nmsg3.g_a.gy      = ");
		print_hexstring(stderr, msg3->g_a.gy, sizeof(msg3->g_a.gy));
		print_hexstring(fplog, msg3->g_a.gy, sizeof(msg3->g_a.gy));
		fprintf(stderr, "\nmsg3.ps_sec_prop.sgx_ps_sec_prop_desc = ");
		fprintf(fplog, "\nmsg3.ps_sec_prop.sgx_ps_sec_prop_desc = ");
		print_hexstring(stderr, msg3->ps_sec_prop.sgx_ps_sec_prop_desc,
			sizeof(msg3->ps_sec_prop.sgx_ps_sec_prop_desc));
		print_hexstring(fplog, msg3->ps_sec_prop.sgx_ps_sec_prop_desc,
			sizeof(msg3->ps_sec_prop.sgx_ps_sec_prop_desc));
		fprintf(fplog, "\n");
		fprintf(stderr, "\nmsg3.quote       = ");
		fprintf(fplog, "\nmsg3.quote       = ");
		print_hexstring(stderr, msg3->quote, msg3_sz-sizeof(sgx_ra_msg3_t));
		print_hexstring(fplog, msg3->quote, msg3_sz-sizeof(sgx_ra_msg3_t));
		fprintf(fplog, "\n");
		fprintf(stderr, "\n");
		fprintf(fplog, "\n");
		divider(stderr);
		divider(fplog);
	}

	dividerWithText(stderr, "Copy/Paste Msg3 Below to SP");
	msgio->send(msg3, msg3_sz);
	divider(stderr);

	dividerWithText(fplog, "Msg3 ==> SP");
	fsend_msg(fplog, msg3, msg3_sz);
	divider(fplog);

	if ( msg3 ) {
		free(msg3);
		msg3 = NULL;
	}
 
	/* Read Msg4 provided by Service Provider, then process */
        
	rv= msgio->read((void **)&msg4, &msg4sz);
	if ( rv == 0 ) {
		enclave_ra_close(eid, &sgxrv, ra_ctx);
		fprintf(stderr, "protocol error reading msg4\n");
		delete msgio;
		exit(1);
	} else if ( rv == -1 ) {
		enclave_ra_close(eid, &sgxrv, ra_ctx);
		fprintf(stderr, "system error occurred while reading msg4\n");
		delete msgio;
		exit(1);
	}

	edividerWithText("Enclave Trust Status from Service Provider");

	enclaveTrusted= msg4->status;
	if ( enclaveTrusted == Trusted ) {
		eprintf("Enclave TRUSTED\n");
	}
	else if ( enclaveTrusted == NotTrusted ) {
		eprintf("Enclave NOT TRUSTED\n");
	}
	else if ( enclaveTrusted == Trusted_ItsComplicated ) {
		// Trusted, but client may be untrusted in the future unless it
		// takes action.

		eprintf("Enclave Trust is TRUSTED and COMPLICATED. The client is out of date and\nmay not be trusted in the future depending on the service provider's  policy.\n");
	} else {
		// Not Trusted, but client may be able to take action to become
		// trusted.

		eprintf("Enclave Trust is NOT TRUSTED and COMPLICATED. The client is out of date.\n");
	}

	/* check to see if we have a PIB by comparing to empty PIB */
	sgx_platform_info_t emptyPIB;
	memset(&emptyPIB, 0, sizeof (sgx_platform_info_t));

	int retPibCmp = memcmp(&emptyPIB, (void *)(&msg4->platformInfoBlob), sizeof (sgx_platform_info_t));

	if (retPibCmp == 0 ) {
		if ( verbose ) eprintf("A Platform Info Blob (PIB) was NOT provided by the IAS\n");
	} else {
		if ( verbose ) eprintf("A Platform Info Blob (PIB) was provided by the IAS\n");

		if ( debug )  {
			eprintf("+++ PIB: " );
			print_hexstring(stderr, &msg4->platformInfoBlob, sizeof (sgx_platform_info_t));
			print_hexstring(fplog, &msg4->platformInfoBlob, sizeof (sgx_platform_info_t));
			eprintf("\n");
		}

		/* We have a PIB, so check to see if there are actions to take */
		sgx_update_info_bit_t update_info;
		sgx_status_t ret = sgx_report_attestation_status(&msg4->platformInfoBlob, 
			enclaveTrusted, &update_info);

		if ( debug )  eprintf("+++ sgx_report_attestation_status ret = 0x%04x\n", ret);

		edivider();

		/* Check to see if there is an update needed */
		if ( ret == SGX_ERROR_UPDATE_NEEDED ) {

			edividerWithText("Platform Update Required");
			eprintf("The following Platform Update(s) are required to bring this\n");
			eprintf("platform's Trusted Computing Base (TCB) back into compliance:\n\n");
			if( update_info.pswUpdate ) {
				eprintf("  * Intel SGX Platform Software needs to be updated to the latest version.\n");
			}

			if( update_info.csmeFwUpdate ) {
				eprintf("  * The Intel Management Engine Firmware Needs to be Updated.  Contact your\n");
				eprintf("    OEM for a BIOS Update.\n");
			}

			if( update_info.ucodeUpdate )  {
				eprintf("  * The CPU Microcode needs to be updated.  Contact your OEM for a platform\n");
				eprintf("    BIOS Update.\n");
			}                                           
			eprintf("\n");
			edivider();      
		}
	}

	/*
	 * If the enclave is trusted, fetch a hash of the the MK and SK from
	 * the enclave to show proof of a shared secret with the service 
	 * provider.
	 */

	if ( enclaveTrusted == Trusted ) {
		sgx_status_t key_status, sha_status;
		sgx_sha256_hash_t mkhash, skhash;

		// First the MK

		if ( debug ) eprintf("+++ fetching SHA256(MK)\n");
		status= enclave_ra_get_key_hash(eid, &sha_status, &key_status, ra_ctx,
			SGX_RA_KEY_MK, &mkhash);
		if ( debug ) eprintf("+++ ECALL enclage_ra_get_key_hash (MK) ret= 0x%04x\n",
			status);

		if ( debug ) eprintf("+++ sgx_ra_get_keys (MK) ret= 0x%04x\n", key_status);
		// Then the SK

		if ( debug ) eprintf("+++ fetching SHA256(SK)\n");
		status= enclave_ra_get_key_hash(eid, &sha_status, &key_status, ra_ctx,
			SGX_RA_KEY_SK, &skhash);
		if ( debug ) eprintf("+++ ECALL enclage_ra_get_key_hash (MK) ret= 0x%04x\n",
			status);

		if ( debug ) eprintf("+++ sgx_ra_get_keys (MK) ret= 0x%04x\n", key_status);
		if ( verbose ) {
			eprintf("SHA256(MK) = ");
			print_hexstring(stderr, mkhash, sizeof(mkhash));
			print_hexstring(fplog, mkhash, sizeof(mkhash));
			eprintf("\n");
			eprintf("SHA256(SK) = ");
			print_hexstring(stderr, skhash, sizeof(skhash));
			print_hexstring(fplog, skhash, sizeof(skhash));
			eprintf("\n");
		}
	}

	free (msg4);

	g_ra_ctx = ra_ctx;
	g_sgxrv = sgxrv;
	//enclave_ra_close(eid, &sgxrv, ra_ctx);
	//delete msgio;

	return 0;
}

/*----------------------------------------------------------------------
 * do_quote()
 *
 * Generate a quote from the enclave.
 *----------------------------------------------------------------------
 * WARNING!
 *
 * DO NOT USE THIS SUBROUTINE AS A TEMPLATE FOR IMPLEMENTING REMOTE
 * ATTESTATION. do_quote() short-circuits the RA process in order 
 * to generate an enclave quote directly!
 *
 * The high-level functions provided for remote attestation take
 * care of the low-level details of quote generation for you:
 *
 *   sgx_ra_init()
 *   sgx_ra_get_msg1
 *   sgx_ra_proc_msg2
 *
 * End developers should not normally be calling these functions
 * directly when doing remote attestation: 
 *
 *    sgx_get_ps_sec_prop()
 *    sgx_get_quote()
 *    sgx_get_quote_size()
 *    sgx_calc_quote_size()
 *    sgx_get_report()
 *    sgx_init_quote()
 *
 *----------------------------------------------------------------------
 */

int do_quote(sgx_enclave_id_t eid, config_t *config)
{
	sgx_status_t status, sgxrv;
	sgx_quote_t *quote;
	sgx_report_t report;
	sgx_report_t qe_report;
	sgx_target_info_t target_info;
	sgx_epid_group_id_t epid_gid;
	uint32_t sz= 0;
	uint32_t flags= config->flags;
	sgx_quote_sign_type_t linkable= SGX_UNLINKABLE_SIGNATURE;
	sgx_ps_cap_t ps_cap;
	char *pse_manifest = NULL;
	size_t pse_manifest_sz;
#ifdef _WIN32
	LPTSTR b64quote = NULL;
	DWORD sz_b64quote = 0;
	LPTSTR b64manifest = NULL;
	DWORD sz_b64manifest = 0;
#else
	char  *b64quote= NULL;
	char *b64manifest = NULL;
#endif

 	if (OPT_ISSET(flags, OPT_LINK)) linkable= SGX_LINKABLE_SIGNATURE;

	/* Platform services info */
	if (OPT_ISSET(flags, OPT_PSE)) {
		status = sgx_get_ps_cap(&ps_cap);
		if (status != SGX_SUCCESS) {
			fprintf(stderr, "sgx_get_ps_cap: %08x\n", status);
			return 1;
		}

		status = get_pse_manifest_size(eid, &pse_manifest_sz);
		if (status != SGX_SUCCESS) {
			fprintf(stderr, "get_pse_manifest_size: %08x\n",
				status);
			return 1;
		}

		pse_manifest = (char *) malloc(pse_manifest_sz);

		status = get_pse_manifest(eid, &sgxrv, pse_manifest, pse_manifest_sz);
		if (status != SGX_SUCCESS) {
			fprintf(stderr, "get_pse_manifest: %08x\n",
				status);
			return 1;
		}
		if (sgxrv != SGX_SUCCESS) {
			fprintf(stderr, "get_sec_prop_desc_ex: %08x\n",
				sgxrv);
			return 1;
		}
	}

	/* Get our quote */

	memset(&report, 0, sizeof(report));

	status= sgx_init_quote(&target_info, &epid_gid);
	if ( status != SGX_SUCCESS ) {
		fprintf(stderr, "sgx_init_quote: %08x\n", status);
		return 1;
	}

	/* Did they ask for just the EPID? */
	if ( config->mode == MODE_EPID ) {
		printf("%08x\n", *(uint32_t *)epid_gid);
		exit(0);
	}

	status= get_report(eid, &sgxrv, &report, &target_info);
	if ( status != SGX_SUCCESS ) {
		fprintf(stderr, "get_report: %08x\n", status);
		return 1;
	}
	if ( sgxrv != SGX_SUCCESS ) {
		fprintf(stderr, "sgx_create_report: %08x\n", sgxrv);
		return 1;
	}

	// sgx_get_quote_size() has been deprecated, but our PSW may be too old
	// so use a wrapper function.

	if (! get_quote_size(&status, &sz)) {
		fprintf(stderr, "PSW missing sgx_get_quote_size() and sgx_calc_quote_size()\n");
		return 1;
	}
	if ( status != SGX_SUCCESS ) {
		fprintf(stderr, "SGX error while getting quote size: %08x\n", status);
		return 1;
	}

	quote= (sgx_quote_t *) malloc(sz);
	if ( quote == NULL ) {
		fprintf(stderr, "out of memory\n");
		return 1;
	}

	memset(quote, 0, sz);
	status= sgx_get_quote(&report, linkable, &config->spid,
		(OPT_ISSET(flags, OPT_NONCE)) ? &config->nonce : NULL,
		NULL, 0,
		(OPT_ISSET(flags, OPT_NONCE)) ? &qe_report : NULL, 
		quote, sz);
	if ( status != SGX_SUCCESS ) {
		fprintf(stderr, "sgx_get_quote: %08x\n", status);
		return 1;
	}

	/* Print our quote */

#ifdef _WIN32
	// We could also just do ((4 * sz / 3) + 3) & ~3
	// but it's cleaner to use the API.

	if (CryptBinaryToString((BYTE *) quote, sz, CRYPT_STRING_BASE64|CRYPT_STRING_NOCRLF, NULL, &sz_b64quote) == FALSE) {
		fprintf(stderr, "CryptBinaryToString: could not get Base64 encoded quote length\n");
		return 1;
	}

	b64quote = (LPTSTR)(malloc(sz_b64quote));
	if (b64quote == NULL) {
		perror("malloc");
		return 1;
	}
	if (CryptBinaryToString((BYTE *) quote, sz, CRYPT_STRING_BASE64|CRYPT_STRING_NOCRLF, b64quote, &sz_b64quote) == FALSE) {
		fprintf(stderr, "CryptBinaryToString: could not get Base64 encoded quote length\n");
		return 1;
	}

	if (OPT_ISSET(flags, OPT_PSE)) {
		if (CryptBinaryToString((BYTE *)pse_manifest, (uint32_t)(pse_manifest_sz), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &sz_b64manifest) == FALSE) {
			fprintf(stderr, "CryptBinaryToString: could not get Base64 encoded manifest length\n");
			return 1;
		}

		b64manifest = (LPTSTR)(malloc(sz_b64manifest));
		if (b64manifest == NULL) {
			free(b64quote);
			perror("malloc");
			return 1;
		}

		if (CryptBinaryToString((BYTE *)pse_manifest, (uint32_t)(pse_manifest_sz), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, b64manifest, &sz_b64manifest) == FALSE) {
			fprintf(stderr, "CryptBinaryToString: could not get Base64 encoded manifest length\n");
			return 1;
		}
	}

#else
	b64quote= base64_encode((char *) quote, sz);
	if ( b64quote == NULL ) {
		eprintf("Could not base64 encode quote\n");
		return 1;
	}

	if (OPT_ISSET(flags, OPT_PSE)) {
		b64manifest= base64_encode((char *) pse_manifest, pse_manifest_sz);
		if ( b64manifest == NULL ) {
			free(b64quote);
			eprintf("Could not base64 encode manifest\n");
			return 1;
		}
	}
#endif

	printf("{\n");
	printf("\"isvEnclaveQuote\":\"%s\"", b64quote);
	if ( OPT_ISSET(flags, OPT_NONCE) ) {
		printf(",\n\"nonce\":\"");
		print_hexstring(stdout, &config->nonce, 16);
		printf("\"");
	}

	if (OPT_ISSET(flags, OPT_PSE)) {
		printf(",\n\"pseManifest\":\"%s\"", b64manifest);	
	}
	printf("\n}\n");

#ifdef SGX_HW_SIM
	fprintf(stderr, "WARNING! Built in h/w simulation mode. This quote will not be verifiable.\n");
#endif

	free(b64quote);
	if ( b64manifest != NULL ) free(b64manifest);

	return 0;

}

/*
 * Search for the enclave file and then try and load it.
 */

#ifndef _WIN32
sgx_status_t sgx_create_enclave_search (const char *filename, const int edebug,
	sgx_launch_token_t *token, int *updated, sgx_enclave_id_t *eid,
	sgx_misc_attribute_t *attr)
{
	struct stat sb;
	char epath[PATH_MAX];	/* includes NULL */

	/* Is filename an absolute path? */

	if ( filename[0] == '/' ) 
		return sgx_create_enclave(filename, edebug, token, updated, eid, attr);

	/* Is the enclave in the current working directory? */

	if ( stat(filename, &sb) == 0 )
		return sgx_create_enclave(filename, edebug, token, updated, eid, attr);

	/* Search the paths in LD_LBRARY_PATH */

	if ( file_in_searchpath(filename, getenv("LD_LIBRARY_PATH"), epath, PATH_MAX) )
		return sgx_create_enclave(epath, edebug, token, updated, eid, attr);
		
	/* Search the paths in DT_RUNPATH */

	if ( file_in_searchpath(filename, getenv("DT_RUNPATH"), epath, PATH_MAX) )
		return sgx_create_enclave(epath, edebug, token, updated, eid, attr);

	/* Standard system library paths */

	if ( file_in_searchpath(filename, DEF_LIB_SEARCHPATH, epath, PATH_MAX) )
		return sgx_create_enclave(epath, edebug, token, updated, eid, attr);

	/*
	 * If we've made it this far then we don't know where else to look.
	 * Just call sgx_create_enclave() which assumes the enclave is in
	 * the current working directory. This is almost guaranteed to fail,
	 * but it will insure we are consistent about the error codes that
	 * get reported to the calling function.
	 */

	return sgx_create_enclave(filename, edebug, token, updated, eid, attr);
}

int file_in_searchpath (const char *file, const char *search, char *fullpath, 
	size_t len)
{
	char *p, *str;
	size_t rem;
	struct stat sb;

	if ( search == NULL ) return 0;
	if ( strlen(search) == 0 ) return 0;

	str= strdup(search);
	if ( str == NULL ) return 0;

	p= strtok(str, ":");
	while ( p != NULL) {
		size_t lp= strlen(p);

		if ( lp ) {

			strncpy(fullpath, p, len-1);
			rem= (len-1)-lp-1;
			fullpath[len-1]= 0;

			strncat(fullpath, "/", rem);
			--rem;

			strncat(fullpath, file, rem);

			if ( stat(fullpath, &sb) == 0 ) {
				free(str);
				return 1;
			}
		}

		p= strtok(NULL, ":");
	}

	free(str);

	return 0;
}

#endif


void usage () 
{
	fprintf(stderr, "usage: client [ options ] [ host[:port] ]\n\n");
	fprintf(stderr, "Required:\n");
	fprintf(stderr, "  -N, --nonce-file=FILE    Set a nonce from a file containing a 32-byte\n");
	fprintf(stderr, "                             ASCII hex string\n");
	fprintf(stderr, "  -P, --pubkey-file=FILE   File containing the public key of the service\n");
	fprintf(stderr, "                             provider.\n");
	fprintf(stderr, "  -S, --spid-file=FILE     Set the SPID from a file containing a 32-byte\n");
	fprintf(stderr, "                             ASCII hex string\n");
	fprintf(stderr, "  -d, --debug              Show debugging information\n");
	fprintf(stderr, "  -e, --epid-gid           Get the EPID Group ID instead of performing\n");
	fprintf(stderr, "                             an attestation.\n");
	fprintf(stderr, "  -l, --linkable           Specify a linkable quote (default: unlinkable)\n");
	fprintf(stderr, "  -m, --pse-manifest       Include the PSE manifest in the quote\n");
	fprintf(stderr, "  -n, --nonce=HEXSTRING    Set a nonce from a 32-byte ASCII hex string\n");
	fprintf(stderr, "  -p, --pubkey=HEXSTRING   Specify the public key of the service provider\n");
	fprintf(stderr, "                             as an ASCII hex string instead of using the\n");
	fprintf(stderr, "                             default.\n");
	fprintf(stderr, "  -q                       Generate a quote instead of performing an\n");
	fprintf(stderr, "                             attestation.\n");
	fprintf(stderr, "  -r                       Generate a nonce using RDRAND\n");
	fprintf(stderr, "  -s, --spid=HEXSTRING     Set the SPID from a 32-byte ASCII hex string\n");
	fprintf(stderr, "  -v, --verbose            Print decoded RA messages to stderr\n");
	fprintf(stderr, "  -z                       Read from stdin and write to stdout instead\n");
	fprintf(stderr, "                             connecting to a server.\n");
	fprintf(stderr, "\nOne of --spid OR --spid-file is required for generating a quote or doing\nremote attestation.\n");
	exit(1);
}

