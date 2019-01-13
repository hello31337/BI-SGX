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



#ifndef _WIN32
#include "config.h"
#endif

#include <stdlib.h>
#include <limits.h>
#include <stdio.h>
#include <sys/stat.h>
#include <string.h>
#include <sys/types.h>
#ifdef _WIN32
#include <intrin.h>
#include <openssl/applink.c>
#include "win32/getopt.h"
#else
#include <signal.h>
#include <getopt.h>
#include <unistd.h>
#endif
#include <sgx_key_exchange.h>
#include <sgx_report.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include "json.hpp"
#include "common.h"
#include "hexutil.h"
#include "fileio.h"
#include "crypto.h"
#include "byteorder.h"
#include "msgio.h"
#include "protocol.h"
#include "base64.h"
#include "iasrequest.h"
#include "logfile.h"
#include "settings.h"

using namespace json;
using namespace std;

#include <map>
#include <string>
#include <iostream>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <random>

#ifdef _WIN32
#define strdup(x) _strdup(x)
#endif

static const unsigned char def_service_private_key[32] = {
	0x90, 0xe7, 0x6c, 0xbb, 0x2d, 0x52, 0xa1, 0xce,
	0x3b, 0x66, 0xde, 0x11, 0x43, 0x9c, 0x87, 0xec,
	0x1f, 0x86, 0x6a, 0x3b, 0x65, 0xb6, 0xae, 0xea,
	0xad, 0x57, 0x34, 0x53, 0xd1, 0x03, 0x8c, 0x01
};

typedef struct ra_session_struct {
	unsigned char g_a[64];
	unsigned char g_b[64];
	unsigned char kdk[16];
	unsigned char smk[16];
	unsigned char sk[16];
	unsigned char mk[16];
	unsigned char vk[16];
} ra_session_t;

typedef struct config_struct {
	sgx_spid_t spid;
	uint16_t quote_type;
	EVP_PKEY *service_private_key;
	char *proxy_server;
	char *ca_bundle;
	char *user_agent;
	char *cert_file;
	char *cert_key_file;
	char *cert_passwd_file;
	unsigned int proxy_port;
	char *cert_type[4];
	X509_STORE *store;
	X509 *signing_ca;
	unsigned int apiver;
	int strict_trust;
} config_t;

void usage();
#ifndef _WIN32
void cleanup_and_exit(int signo);
#endif

int derive_kdk(EVP_PKEY *Gb, unsigned char kdk[16], sgx_ec256_public_t g_a,
	config_t *config);

int process_msg01 (MsgIO *msg, IAS_Connection *ias, sgx_ra_msg1_t *msg1,
	sgx_ra_msg2_t *msg2, char **sigrl, config_t *config,
	ra_session_t *session);

int process_msg3 (MsgIO *msg, IAS_Connection *ias, sgx_ra_msg1_t *msg1,
	ra_msg4_t *msg4, config_t *config, ra_session_t *session);

int get_sigrl (IAS_Connection *ias, int version, sgx_epid_group_id_t gid,
	char **sigrl, uint32_t *msg2);

int get_attestation_report(IAS_Connection *ias, int version,
	const char *b64quote, sgx_ps_sec_prop_desc_t sec_prop, ra_msg4_t *msg4,
	int strict_trust);

int get_proxy(char **server, unsigned int *port, const char *url);

int encrypt_data_for_ISV(unsigned char *plaintext, int plaintext_len,
	unsigned char *key, unsigned char *iv, unsigned char *ciphertext, uint8_t *tag);

int base64_encrypt(uint8_t *src, int srclen, uint8_t *dst, int dstlen);

uint8_t* generate_nonce(int sz);

char debug = 0;
char verbose = 0;
/* Need a global for the signal handler */
MsgIO *msgio = NULL;

bool flag_BIOS = false;
/*Flag to ignore IAS's corrupted error message*/

int main(int argc, char *argv[])
{
	char flag_spid = 0;
	char flag_pubkey = 0;
	char flag_cert = 0;
	char flag_ca = 0;
	char flag_usage = 0;
	char flag_noproxy= 0;
	char flag_prod= 0;
	char flag_stdio= 0;
	char *sigrl = NULL;
	config_t config;
	int oops;
	IAS_Connection *ias= NULL;
	char *port= NULL;
#ifndef _WIN32
	struct sigaction sact;
#endif

	/* Command line options */

	static struct option long_opt[] =
	{
		{"ias-signing-cafile",
							required_argument,	0, 'A'},
		{"ca-bundle",		required_argument,	0, 'B'},
		{"ias-cert",		required_argument,	0, 'C'},
		{"ias-cert-passwd",
							required_argument,	0, 'E'},
		{"list-agents",		no_argument,		0, 'G'},
		{"service-key-file",
							required_argument,	0, 'K'},
		{"production",		no_argument,		0, 'P'},
		{"spid-file",		required_argument,	0, 'S'},
		{"strict-trust-mode",
							no_argument,		0, 'X'},
		{"ias-cert-key",
							required_argument,	0, 'Y'},
		{"debug",			no_argument,		0, 'd'},
		{"user-agent",		required_argument,	0, 'g'},
		{"help",			no_argument, 		0, 'h'},
		{"key",				required_argument,	0, 'k'},
		{"linkable",		no_argument,		0, 'l'},
		{"proxy",			required_argument,	0, 'p'},
		{"api-version",		required_argument,	0, 'r'},
		{"spid",			required_argument,	0, 's'},
		{"ias-cert-type",	required_argument,	0, 't'},
		{"verbose",			no_argument,		0, 'v'},
		{"no-proxy",		no_argument,		0, 'x'},
		{"stdio",			no_argument,		0, 'z'},
		{ 0, 0, 0, 0 }
	};

	cout << "*** INFO: SP is running as CLIENT(non-SGX term). ***" << endl;

	/* Create a logfile to capture debug output and actual msg data */

	fplog = create_logfile("sp.log");
	fprintf(fplog, "Server log started\n");

	/* Config defaults */

	memset(&config, 0, sizeof(config));
#ifdef _WIN32
	strncpy_s((char *)config.cert_type, 4, "PEM", 3);
#else
	strncpy((char *)config.cert_type, "PEM", 3);
#endif
	config.apiver= IAS_API_DEF_VERSION;

	/* Parse our options */

	while (1) {
		int c;
		int opt_index = 0;

		c = getopt_long(argc, argv, "A:B:C:E:GK:PS:XY:dg:hk:lp:r:s:t:vxz", long_opt, &opt_index);
		if (c == -1) break;

		switch (c) {
		case 0:
			break;
		case 'A':
			if (!cert_load_file(&config.signing_ca, optarg)) {
				crypto_perror("cert_load_file");
				eprintf("%s: could not load IAS Signing Cert CA\n", optarg);
				return 1;
			}

			config.store = cert_init_ca(config.signing_ca);
			if (config.store == NULL) {
				eprintf("%s: could not initialize certificate store\n", optarg);
				return 1;
			}
			++flag_ca;

			break;
		case 'B':
			config.ca_bundle = strdup(optarg);
			if (config.ca_bundle == NULL) {
				perror("strdup");
				return 1;
			}

			break;
		case 'C':
			config.cert_file = strdup(optarg);
			if (config.cert_file == NULL) {
				perror("strdup");
				return 1;
			}
			++flag_cert;

			break;
		case 'E':
			config.cert_passwd_file = strdup(optarg);
			if (config.cert_passwd_file == NULL) {
				perror("strdup");
				return 1;
			}
			break;
		case 'G':
			ias_list_agents(stdout);
			return 1;

                case 'P':
                        flag_prod = 1;
                        break;

		case 'S':
			if (!from_hexstring_file((unsigned char *)&config.spid, optarg, 16)) {
				eprintf("SPID must be 32-byte hex string\n");
				return 1;
			}
			++flag_spid;

			break;
		case 'K':
			if (!key_load_file(&config.service_private_key, optarg, KEY_PRIVATE)) {
				crypto_perror("key_load_file");
				eprintf("%s: could not load EC private key\n", optarg);
				return 1;
			}
			break;
		case 'X':
			config.strict_trust= 1;
			break;
		case 'Y':
			config.cert_key_file = strdup(optarg);
			if (config.cert_key_file == NULL) {
				perror("strdup");
				return 1;
			}
			break;
		case 'd':
			debug = 1;
			break;
		case 'g':
			config.user_agent= strdup(optarg);
			if ( config.user_agent == NULL ) {
				perror("malloc");
				return 1;
			}
			break;
		case 'k':
			if (!key_load(&config.service_private_key, optarg, KEY_PRIVATE)) {
				crypto_perror("key_load");
				eprintf("%s: could not load EC private key\n", optarg);
				return 1;
			}
			break;
		case 'l':
			config.quote_type = SGX_LINKABLE_SIGNATURE;
			break;
		case 'p':
			if ( flag_noproxy ) usage();
			if (!get_proxy(&config.proxy_server, &config.proxy_port, optarg)) {
				eprintf("%s: could not extract proxy info\n", optarg);
				return 1;
			}
			// Break the URL into host and port. This is a simplistic algorithm.
			break;
		case 'r':
			config.apiver= atoi(optarg);
			if ( config.apiver < IAS_MIN_VERSION || config.apiver >
				IAS_MAX_VERSION ) {

				eprintf("version must be between %d and %d\n",
					IAS_MIN_VERSION, IAS_MAX_VERSION);
				return 1;
			}
			break;
		case 's':
			if (strlen(optarg) < 32) {
				eprintf("SPID must be 32-byte hex string\n");
				return 1;
			}
			if (!from_hexstring((unsigned char *)&config.spid, (unsigned char *)optarg, 16)) {
				eprintf("SPID must be 32-byte hex string\n");
				return 1;
			}
			++flag_spid;
			break;
		case 't':
			strncpy((char *) config.cert_type, optarg, 4);
			if ( debug ) eprintf("+++ cert type set to %s\n",
				config.cert_type);
			break;
		case 'v':
			verbose = 1;
			break;
		case 'x':
			if ( config.proxy_server != NULL ) usage();
			flag_noproxy=1;
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

	/* We should have zero or one command-line argument remaining */

	argc-= optind;
	if ( argc > 1 ) usage();

	/* The remaining argument, if present, is the port number. */

	if ( flag_stdio && argc ) {
		usage();
	} else if ( argc ) {
		port= argv[optind];
	} else {
		port= strdup(DEFAULT_PORT);
		if ( port == NULL ) {
			perror("strdup");
			return 1;
		}
	}

	/* Use the default CA bundle unless one is provided */

	if ( config.ca_bundle == NULL ) {
		config.ca_bundle= strdup(DEFAULT_CA_BUNDLE);
		if ( config.ca_bundle == NULL ) {
			perror("strdup");
			return 1;
		}
		if ( debug ) eprintf("+++ Using default CA bundle %s\n",
			config.ca_bundle);
	}

	/*
	 * Use the hardcoded default key unless one is provided on the
	 * command line. Most real-world services would hardcode the
	 * key since the public half is also hardcoded into the enclave.
	 */

	if (config.service_private_key == NULL) {
		if (debug) {
			eprintf("Using default private key\n");
		}
		config.service_private_key = key_private_from_bytes(def_service_private_key);
		if (config.service_private_key == NULL) {
			crypto_perror("key_private_from_bytes");
			return 1;
		}

	}

	if (debug) {
		eprintf("+++ using private key:\n");
		PEM_write_PrivateKey(stderr, config.service_private_key, NULL,
			NULL, 0, 0, NULL);
		PEM_write_PrivateKey(fplog, config.service_private_key, NULL,
			NULL, 0, 0, NULL);
	}

	if (!flag_spid) {
		eprintf("--spid or --spid-file is required\n");
		flag_usage = 1;
	}

	if (!flag_cert) {
		eprintf("--ias-cert-file is required\n");
		flag_usage = 1;
	}

	if (!flag_ca) {
		eprintf("--ias-signing-cafile is required\n");
		flag_usage = 1;
	}

	if (flag_usage) usage();

	if (verbose) eprintf("Using cert file %s\n", config.cert_file);

	/* Initialize out support libraries */

	crypto_init();

	/* Initialize our IAS request object */

	try {
		ias = new IAS_Connection(
			(flag_prod) ? IAS_SERVER_PRODUCTION : IAS_SERVER_DEVELOPMENT,
			0
		);
	}
	catch (...) {
		oops = 1;
		eprintf("exception while creating IAS request object\n");
		return 1;
	}

	ias->client_cert(config.cert_file, (char *)config.cert_type);
	if ( config.cert_passwd_file != NULL ) {
		char *passwd;
		char *keyfile;
		off_t sz;

		if ( ! from_file(NULL, config.cert_passwd_file, &sz) ) {
			eprintf("can't load password from %s\n", 
				config.cert_passwd_file);
			return 1;
		}

		if ( sz > 0 ) {
			char *cp;

			try {
				passwd= new char[sz+1];
			}
			catch (...) {
				eprintf("out of memory\n");
				return 1;
			}

			if ( ! from_file((unsigned char *) passwd, config.cert_passwd_file,
			 	&sz) ) {

				eprintf("can't load password from %s\n", 
					config.cert_passwd_file);
				return 1;
			}
			passwd[sz]= 0;

			// Remove trailing newline or linefeed.

			cp= strchr(passwd, '\n');
			if ( cp != NULL ) *cp= 0;
			cp= strchr(passwd, '\r');
			if ( cp != NULL ) *cp= 0;

			// If a key file isn't specified, assume it's bundled with
			// the certificate.

			keyfile= (config.cert_key_file == NULL) ? config.cert_file :
				config.cert_key_file;
			if ( debug ) eprintf("+++ using cert key file %s\n", keyfile);
			ias->client_key(keyfile, passwd);

#ifdef _WIN32
			SecureZeroMemory(passwd, sz);
#else
			// -fno-builtin-memset prevents optimizing this away 
			memset(passwd, 0, sz);
#endif
		}
	} else if ( config.cert_key_file != NULL ) {
		// We have a key file but no password.
		ias->client_key(config.cert_key_file, NULL);
	}

	if ( flag_noproxy ) ias->proxy_mode(IAS_PROXY_NONE);
	else if (config.proxy_server != NULL) {
		ias->proxy_mode(IAS_PROXY_FORCE);
		ias->proxy(config.proxy_server, config.proxy_port);
	}

	if ( config.user_agent != NULL ) {
		if ( ! ias->agent(config.user_agent) ) {
			eprintf("%s: unknown user agent\n", config.user_agent);
			return 0;
		}
	}

	/* 
	 * Set the cert store for this connection. This is used for verifying 
	 * the IAS signing certificate, not the TLS connection with IAS (the 
	 * latter is handled using config.ca_bundle).
	 */
	ias->cert_store(config.store);

	/*
	 * Set the CA bundle for verifying the IAS server certificate used
	 * for the TLS session. If this isn't set, then the user agent
	 * will fall back to it's default.
	 */
	if ( strlen(config.ca_bundle) ) ias->ca_bundle(config.ca_bundle);

	/* Get our message IO object. */
	
	
	if ( flag_stdio ) {
		msgio= new MsgIO();
	} else {
		try {
			//msgio = new MsgIO(NULL, (port == NULL) ? DEFAULT_PORT : port);
			msgio= new MsgIO("localhost", (port == NULL) ? DEFAULT_PORT : port);
		}
		catch(...) {
			return 1;
		}
	}
	

	//msgio = new MsgIO();

#ifndef _WIN32
	/* 
	 * Install some rudimentary signal handlers. We just want to make 
	 * sure we gracefully shutdown the listen socket before we exit
	 * to avoid "address already in use" errors on startup.
	 */

	sigemptyset(&sact.sa_mask);
	sact.sa_flags= 0;
	sact.sa_handler= &cleanup_and_exit;

	if ( sigaction(SIGHUP, &sact, NULL) == -1 ) perror("sigaction: SIGHUP");
	if ( sigaction(SIGINT, &sact, NULL) == -1 ) perror("sigaction: SIGHUP");
	if ( sigaction(SIGTERM, &sact, NULL) == -1 ) perror("sigaction: SIGHUP");
	if ( sigaction(SIGQUIT, &sact, NULL) == -1 ) perror("sigaction: SIGHUP");
#endif

 	/* If we're running in server mode, we'll block here.  */

	//while ( msgio->server_loop() ) {
		ra_session_t session;
		sgx_ra_msg1_t msg1;
		sgx_ra_msg2_t msg2;
		ra_msg4_t msg4;

		memset(&session, 0, sizeof(ra_session_t));

		/* Read message 0 and 1, then generate message 2 */

		if ( ! process_msg01(msgio, ias, &msg1, &msg2, &sigrl, &config,
			&session) ) {

			eprintf("error processing msg1\n");
			goto disconnect;
		}

		/* Send message 2 */

		/*
	 	* sgx_ra_msg2_t is a struct with a flexible array member at the
	 	* end (defined as uint8_t sig_rl[]). We could go to all the 
	 	* trouble of building a byte array large enough to hold the
	 	* entire struct and then cast it as (sgx_ra_msg2_t) but that's
	 	* a lot of work for no gain when we can just send the fixed 
	 	* portion and the array portion by hand.
	 	*/

		dividerWithText(stderr, "Copy/Paste Msg2 Below to Client");
		dividerWithText(fplog, "Msg2 (send to Client)");

		msgio->send_partial((void *) &msg2, sizeof(sgx_ra_msg2_t));
		fsend_msg_partial(fplog, (void *) &msg2, sizeof(sgx_ra_msg2_t));

		msgio->send(&msg2.sig_rl, msg2.sig_rl_size);
		fsend_msg(fplog, &msg2.sig_rl, msg2.sig_rl_size);

		edivider();

		/* Read message 3, and generate message 4 */

		if ( ! process_msg3(msgio, ias, &msg1, &msg4, &config, &session) ) {
			eprintf("error processing msg3\n");
			goto disconnect;
		}

		//sending msg4 complete; starting data encryption with session key "SK"
		if(flag_BIOS)
		{
			cerr << "============ Remote Attestation Information ============" << endl;
			cerr << "IAS says that target enclave needs BIOS or CPU microcode update," << endl;
			cerr << "But that error message always states that error regardless of BIOS/microcode version," << endl;
			cerr << "So just ignore it and complete RA, then starting secret data." << endl;
			cerr << "========================================================" << endl;
		}

		//Load data to process
		cout << endl << "Continue processing data. Enter any key to continue: " << endl;
		getchar();
		
		//to avoid fucking compile error caused by retaded goto sentence
		{
			ifstream fin_intp;
			string intp_filename, intp_str;
			stringstream ss_intp;
		

			while(1)
			{
				cout << "Input filename to send to ISV. " << endl;
				cout << "Filename: ";
				cin >> intp_filename;

				cout << endl;

				fin_intp.open(intp_filename, ios::in);

				if(!fin_intp)
				{
					cerr << "FileOpenError: Failed to open designated file.\n" << endl;
				}
				else
				{
					cout << "Open designated file \"" << intp_filename << "\" successfully." << endl;
					break;
				}
			}

			ss_intp << fin_intp.rdbuf();
			intp_str = ss_intp.str();
			
			unsigned char *intp_plain;
			unsigned const char *dummy_plain;

			dummy_plain = reinterpret_cast<unsigned const char*>(intp_str.c_str());
			intp_plain = const_cast<unsigned char*>(dummy_plain);

			cout << "Display the content of loaded file for check: \n" << endl;
			cout << "===============================================" << endl;
			cout << intp_plain << endl;
			cout << "===============================================" << endl;

			//Start encryption
			unsigned char* sp_key = session.sk;
			unsigned char* sp_iv;
			unsigned char intp_cipher[100000]; //intp_cipher[n];
			int ciphertext_len, tag_len = 16;
			uint8_t tag[16] = {'\0'};

			cout << "Generate initialization vector." << endl;
			sp_iv = generate_nonce(12);

			ciphertext_len = encrypt_data_for_ISV(intp_plain, strlen((char*)intp_plain), sp_key, sp_iv, intp_cipher, tag);

			if(ciphertext_len == -1)
			{
				cerr << "Failed to operate encryption." << endl;
				cerr << "Abort program..." << endl;

				return -1;
			}
			
			cout << "Encrypted data successfully. Cipher text is:" << endl;
			BIO_dump_fp(stdout, (const char*)intp_cipher, ciphertext_len);

			/*convert data to base64 for sending with msgio correctly*/
			uint8_t cipherb64[150000] = {'\0'};
			int b64dst_len = 150000, b64_len;

			b64_len = base64_encrypt(intp_cipher, ciphertext_len, cipherb64, b64dst_len);

			cout << "==========================================================" << endl;
			cout << "Base64 format of cipher is: " << endl;
			cout << cipherb64 << endl << endl;
			cout << "Length of cipher text is: " << ciphertext_len << endl;
			cout << "Length of base64-ed cipher is: " << b64_len << endl << endl;
			cout << "==========================================================" << endl;

			/*Next, convert IV to base64 format*/
			uint8_t ivb64[64] = {'\0'}; //maybe sufficient with 32-size
			int ivb64dst_len = 64, ivb64_len;

			ivb64_len = base64_encrypt(sp_iv, 12, ivb64, ivb64dst_len);

			cout << "Base64 format of initialization vector is: " << endl;
			cout << ivb64 << endl << endl;
			cout << "Length of base64-ed IV is: " << ivb64_len << endl << endl;
			cout << "==========================================================" << endl;

			/*Also convert tag to base64 format*/
			uint8_t tagb64[64] = {'\0'}; //maybe sufficient with 32-size
			int tagb64dst_len = 64, tagb64_len;

			tagb64_len = base64_encrypt(tag, 16, tagb64, tagb64dst_len);

			cout << "Base64 format of tag is: " << endl;
			cout << tagb64 << endl << endl;
			cout << "Length of base64-ed tag is: " << tagb64_len << endl << endl;
			cout << "==========================================================" << endl;
			
			/*In addition to that, need to convert cipher's length to base64*/
			uint8_t deflenb64[128] = {'\0'}; 
			uint8_t *uint8tdeflen;
			int deflenb64dst_len = 32, deflenb64_len;

			uint8tdeflen = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(to_string(ciphertext_len).c_str()));

			cout << "uint8_t-ed default cipher length is: " << uint8tdeflen << endl << endl;

			deflenb64_len = base64_encrypt(uint8tdeflen, strlen((char*)uint8tdeflen), deflenb64, 32);
			cout << "Base64 format of default cipher length is: " << endl;
			cout << deflenb64 << endl << endl;
			cout << "Length of base64-ed default cipher length is: " << deflenb64_len << endl;
			cout << "==========================================================" << endl;


			/*Send base64-ed secret, its length, MAC tag and its length to ISV*/

			/*cipher*/
			cout << "==========================================================" << endl;
			cout << "Send encrypted file to ISV." << endl;

			cout << "Encrypted secret to be sent in base64 is (display again): " << endl;
			msgio->send(cipherb64, strlen((char*)cipherb64));

			cout << "Complete sending message." << endl;
			cout << "Please wait for 0.25 sec." << endl;
			cout << "==========================================================" << endl;

			usleep(250000);

			/*IV*/
			cout << "Initialization vector to be sent is: " << endl;
			msgio->send(ivb64, strlen((char*)ivb64));

			cout << "Complete sending IV." << endl;
			cout << "Please wait for 0.25 sec." << endl;
			cout << "==========================================================" << endl;

			usleep(250000);
			
			/*MAC tag*/
			cout << "Tag to be sent is: (display again)" << endl;
			msgio->send(tagb64, strlen((char*)tagb64));

			cout << "Complete sending MAC tag." << endl;
			cout << "Please wait for 0.25 sec." << endl;
			cout << "==========================================================" << endl;

			usleep(250000);

			/*default cipher length*/
			cout << "Default cipher's length to be sent is: " << endl;
			msgio->send(deflenb64, deflenb64_len);

			cout << "Complete sending default cipher length." << endl;
			cout << "==========================================================" << endl;
			
		}
		//end block to avoid retarded goto error

disconnect:
		msgio->disconnect();
	//}

	crypto_destroy();

	return 0;
}

int process_msg3 (MsgIO *msgio, IAS_Connection *ias, sgx_ra_msg1_t *msg1,
	ra_msg4_t *msg4, config_t *config, ra_session_t *session)
{
	sgx_ra_msg3_t *msg3;
	size_t blen= 0;
	size_t sz;
	int rv;
	uint32_t quote_sz;
	char *buffer= NULL;
	char *b64quote;
	sgx_mac_t vrfymac;
	sgx_quote_t *q;

	/*
	 * Read our incoming message. We're using base16 encoding/hex strings
	 * so we should end up with sizeof(msg)*2 bytes.
	 */

	fprintf(stderr, "Waiting for msg3\n");

	/*
	 * Read message 3
	 *
	 * CMACsmk(M) || M
	 *
	 * where
	 *
	 * M = ga || PS_SECURITY_PROPERTY || QUOTE
	 *
	 */

	rv= msgio->read((void **) &msg3, &sz);
	if ( rv == -1 ) {
		eprintf("system error reading msg3\n");
		return 0;
	} else if ( rv == 0 ) {
		eprintf("protocol error reading msg3\n");
		return 0;
	}
	if ( debug ) {
		eprintf("+++ read %lu bytes\n", sz);
	}

	/*
	 * The quote size will be the total msg3 size - sizeof(sgx_ra_msg3_t)
	 * since msg3.quote is a flexible array member.
	 *
	 * Total message size is sz/2 since the income message is in base16.
	 */
	quote_sz = (uint32_t)((sz / 2) - sizeof(sgx_ra_msg3_t));
	if ( debug ) {
		eprintf("+++ quote_sz= %lu bytes\n", quote_sz);
	}

	/* Make sure Ga matches msg1 */

	if ( debug ) {
		eprintf("+++ Verifying msg3.g_a matches msg1.g_a\n");
		eprintf("msg1.g_a.gx = %s\n",
			hexstring(msg3->g_a.gx, sizeof(msg1->g_a.gx)));
		eprintf("msg1.g_a.gy = %s\n",
			hexstring(&msg3->g_a.gy, sizeof(msg1->g_a.gy)));
		eprintf("msg3.g_a.gx = %s\n",
			hexstring(msg3->g_a.gx, sizeof(msg3->g_a.gx)));
		eprintf("msg3.g_a.gy = %s\n",
			hexstring(&msg3->g_a.gy, sizeof(msg3->g_a.gy)));
	}
	if ( CRYPTO_memcmp(&msg3->g_a, &msg1->g_a, sizeof(sgx_ec256_public_t)) ) {
		eprintf("msg1.g_a and mgs3.g_a keys don't match\n");
		return 0;
	}

	/* Validate the MAC of M */

	cmac128(session->smk, (unsigned char *) &msg3->g_a,
		sizeof(sgx_ra_msg3_t)-sizeof(sgx_mac_t)+quote_sz,
		(unsigned char *) vrfymac);
	if ( debug ) {
		eprintf("+++ Validating MACsmk(M)\n");
		eprintf("msg3.mac   = %s\n", hexstring(msg3->mac, sizeof(sgx_mac_t)));
		eprintf("calculated = %s\n", hexstring(vrfymac, sizeof(sgx_mac_t)));
	}
	if ( CRYPTO_memcmp(msg3->mac, vrfymac, sizeof(sgx_mac_t)) ) {
		eprintf("Failed to verify msg3 MAC\n");
		return 0;
	}

	/* Encode the report body as base64 */

	b64quote= base64_encode((char *) &msg3->quote, quote_sz);
	q= (sgx_quote_t *) msg3->quote;

	if ( verbose ) {

		edividerWithText("Msg3 Details (from Client)");
		eprintf("msg3.mac                 = %s\n",
			hexstring(&msg3->mac, sizeof(msg3->mac)));
		eprintf("msg3.g_a.gx              = %s\n",
			hexstring(msg3->g_a.gx, sizeof(msg3->g_a.gx)));
		eprintf("msg3.g_a.gy              = %s\n",
			hexstring(&msg3->g_a.gy, sizeof(msg3->g_a.gy)));
		eprintf("msg3.ps_sec_prop         = %s\n",
			hexstring(&msg3->ps_sec_prop, sizeof(msg3->ps_sec_prop)));
		eprintf("msg3.quote.version       = %s\n",
			hexstring(&q->version, sizeof(uint16_t)));
		eprintf("msg3.quote.sign_type     = %s\n",
			hexstring(&q->sign_type, sizeof(uint16_t)));
		eprintf("msg3.quote.epid_group_id = %s\n",
			hexstring(&q->epid_group_id, sizeof(sgx_epid_group_id_t)));
		eprintf("msg3.quote.qe_svn        = %s\n",
			hexstring(&q->qe_svn, sizeof(sgx_isv_svn_t)));
		eprintf("msg3.quote.pce_svn       = %s\n",
			hexstring(&q->pce_svn, sizeof(sgx_isv_svn_t)));
		eprintf("msg3.quote.xeid          = %s\n",
			hexstring(&q->xeid, sizeof(uint32_t)));
		eprintf("msg3.quote.basename      = %s\n",
			hexstring(&q->basename, sizeof(sgx_basename_t)));
		eprintf("msg3.quote.report_body   = %s\n",
			hexstring(&q->report_body, sizeof(sgx_report_body_t)));
		eprintf("msg3.quote.signature_len = %s\n",
			hexstring(&q->signature_len, sizeof(uint32_t)));
		eprintf("msg3.quote.signature     = %s\n",
			hexstring(&q->signature, q->signature_len));

		edividerWithText("Enclave Quote (base64) ==> Send to IAS");

		eputs(b64quote);

		eprintf("\n");
		edivider();
	}

	/* Verify that the EPID group ID in the quote matches the one from msg1 */

	if ( debug ) {
		eprintf("+++ Validating quote's epid_group_id against msg1\n");
		eprintf("msg1.egid = %s\n", 
			hexstring(msg1->gid, sizeof(sgx_epid_group_id_t)));
		eprintf("msg3.quote.epid_group_id = %s\n",
			hexstring(&q->epid_group_id, sizeof(sgx_epid_group_id_t)));
	}

	if ( memcmp(msg1->gid, &q->epid_group_id, sizeof(sgx_epid_group_id_t)) ) {
		eprintf("EPID GID mismatch. Attestation failed.\n");
		return 0;
	}


	if ( get_attestation_report(ias, config->apiver, b64quote,
		msg3->ps_sec_prop, msg4, config->strict_trust) ) {

		unsigned char vfy_rdata[64];
		unsigned char msg_rdata[144]; /* for Ga || Gb || VK */

		sgx_report_body_t *r= (sgx_report_body_t *) &q->report_body;

		memset(vfy_rdata, 0, 64);

		/*
		 * Verify that the first 64 bytes of the report data (inside
		 * the quote) are SHA256(Ga||Gb||VK) || 0x00[32]
		 *
		 * VK = CMACkdk( 0x01 || "VK" || 0x00 || 0x80 || 0x00 )
		 *
		 * where || denotes concatenation.
		 */

		/* Derive VK */

		cmac128(session->kdk, (unsigned char *)("\x01VK\x00\x80\x00"),
				6, session->vk);

		/* Build our plaintext */

		memcpy(msg_rdata, session->g_a, 64);
		memcpy(&msg_rdata[64], session->g_b, 64);
		memcpy(&msg_rdata[128], session->vk, 16);

		/* SHA-256 hash */

		sha256_digest(msg_rdata, 144, vfy_rdata);

		if ( verbose ) {
			edividerWithText("Enclave Report Verification");
			if ( debug ) {
				eprintf("VK                 = %s\n", 
					hexstring(session->vk, 16));
			}
			eprintf("SHA256(Ga||Gb||VK) = %s\n",
				hexstring(vfy_rdata, 32));
			eprintf("report_data[64]    = %s\n",
				hexstring(&r->report_data, 64));
		}

		if ( CRYPTO_memcmp((void *) vfy_rdata, (void *) &r->report_data,
			64) ) {

			eprintf("Report verification failed.\n");
			return 0;
		}

		/*
		 * A real service provider would validate that the enclave
		 * report is from an enclave that they recognize. Namely,
		 * that the MRSIGNER matches our signing key, and the MRENCLAVE
		 * hash matches an enclave that we compiled.
		 *
		 * Other policy decisions might include examining ISV_SVN to 
		 * prevent outdated/deprecated software from successfully
		 * attesting, and ensuring the TCB is not out of date.
		 */

		if ( verbose ) {
			edivider();

			// The enclave report is valid so we can trust the report
			// data.

			edividerWithText("Enclave Report Details");

			eprintf("cpu_svn     = %s\n",
				hexstring(&r->cpu_svn, sizeof(sgx_cpu_svn_t)));
			eprintf("misc_select = %s\n",
				hexstring(&r->misc_select, sizeof(sgx_misc_select_t)));
			eprintf("attributes  = %s\n",
				hexstring(&r->attributes, sizeof(sgx_attributes_t)));
			eprintf("mr_enclave  = %s\n",
				hexstring(&r->mr_enclave, sizeof(sgx_measurement_t)));
			eprintf("mr_signer   = %s\n",
				hexstring(&r->mr_signer, sizeof(sgx_measurement_t)));
			eprintf("isv_prod_id = %04hX\n", r->isv_prod_id);
			eprintf("isv_svn     = %04hX\n", r->isv_svn);
			eprintf("report_data = %s\n",
				hexstring(&r->report_data, sizeof(sgx_report_data_t)));
		}


		edividerWithText("Copy/Paste Msg4 Below to Client"); 

		/* Serialize the members of the Msg4 structure independently */
		/* vs. the entire structure as one send_msg() */

		msgio->send_partial(&msg4->status, sizeof(msg4->status));
		msgio->send(&msg4->platformInfoBlob, sizeof(msg4->platformInfoBlob));

		fsend_msg_partial(fplog, &msg4->status, sizeof(msg4->status));
		fsend_msg(fplog, &msg4->platformInfoBlob,
			sizeof(msg4->platformInfoBlob));
		edivider();

		/*
		 * If the enclave is trusted, derive the MK and SK. Also get
		 * SHA256 hashes of these so we can verify there's a shared
		 * secret between us and the client.
		 */

		//if ( msg4->status == Trusted ) {
		if(true){
			unsigned char hashmk[32], hashsk[32];

			if ( debug ) eprintf("+++ Deriving the MK and SK\n");
			cmac128(session->kdk, (unsigned char *)("\x01MK\x00\x80\x00"),
				6, session->mk);
			cmac128(session->kdk, (unsigned char *)("\x01SK\x00\x80\x00"),
				6, session->sk);

			sha256_digest(session->mk, 16, hashmk);
			sha256_digest(session->sk, 16, hashsk);

			if ( verbose ) {
				if ( debug ) {
					eprintf("MK         = %s\n", hexstring(session->mk, 16));
					eprintf("SK         = %s\n", hexstring(session->sk, 16));
				}
				eprintf("SHA256(MK) = %s\n", hexstring(hashmk, 32));
				eprintf("SHA256(SK) = %s\n", hexstring(hashsk, 32));
			}
		}

	} else {
		eprintf("Attestation failed\n");
		return 0;
	}

	free(b64quote);

	return 1;
}

/*
 * Read and process message 0 and message 1. These messages are sent by
 * the client concatenated together for efficiency (msg0||msg1).
 */

int process_msg01 (MsgIO *msgio, IAS_Connection *ias, sgx_ra_msg1_t *msg1,
	sgx_ra_msg2_t *msg2, char **sigrl, config_t *config, ra_session_t *session)
{
	struct msg01_struct {
		uint32_t msg0_extended_epid_group_id;
		sgx_ra_msg1_t msg1;
	} *msg01;
	size_t blen= 0;
	char *buffer= NULL;
	unsigned char digest[32], r[32], s[32], gb_ga[128];
	EVP_PKEY *Gb;
	int rv;

	memset(msg2, 0, sizeof(sgx_ra_msg2_t));

	/*
	 * Read our incoming message. We're using base16 encoding/hex strings
	 * so we should end up with sizeof(msg)*2 bytes.
	 */

	fprintf(stderr, "Waiting for msg0||msg1\n");

	rv= msgio->read((void **) &msg01, NULL);
	if ( rv == -1 ) {
		eprintf("system error reading msg0||msg1\n");
		return 0;
	} else if ( rv == 0 ) {
		eprintf("protocol error reading msg0||msg1\n");
		return 0;
	}

	if ( verbose ) {
		edividerWithText("Msg0 Details (from Client)");
		eprintf("msg0.extended_epid_group_id = %u\n",
			 msg01->msg0_extended_epid_group_id);
		edivider();
	}

	/* According to the Intel SGX Developer Reference
	 * "Currently, the only valid extended Intel(R) EPID group ID is zero. The
	 * server should verify this value is zero. If the Intel(R) EPID group ID 
	 * is not zero, the server aborts remote attestation"
	 */

	if ( msg01->msg0_extended_epid_group_id != 0 ) {
		eprintf("msg0 Extended Epid Group ID is not zero.  Exiting.\n");
		free(msg01);
		return 0;
	}

	// Pass msg1 back to the pointer in the caller func
	memcpy(msg1, &msg01->msg1, sizeof(sgx_ra_msg1_t));

	if ( verbose ) {
		edividerWithText("Msg1 Details (from Client)");
		eprintf("msg1.g_a.gx = %s\n",
			hexstring(&msg1->g_a.gx, sizeof(msg1->g_a.gx)));
		eprintf("msg1.g_a.gy = %s\n",
			hexstring(&msg1->g_a.gy, sizeof(msg1->g_a.gy)));
		eprintf("msg1.gid    = %s\n",
			hexstring( &msg1->gid, sizeof(msg1->gid)));
		edivider();
	}

	/* Generate our session key */

	if ( debug ) eprintf("+++ generating session key Gb\n");

	Gb= key_generate();
	if ( Gb == NULL ) {
		eprintf("Could not create a session key\n");
		free(msg01);
		return 0;
	}

	/*
	 * Derive the KDK from the key (Ga) in msg1 and our session key.
	 * An application would normally protect the KDK in memory to 
	 * prevent trivial inspection.
	 */

	if ( debug ) eprintf("+++ deriving KDK\n");

	if ( ! derive_kdk(Gb, session->kdk, msg1->g_a, config) ) {
		eprintf("Could not derive the KDK\n");
		free(msg01);
		return 0;
	}

	if ( debug ) eprintf("+++ KDK = %s\n", hexstring(session->kdk, 16));

	/*
 	 * Derive the SMK from the KDK 
	 * SMK = AES_CMAC(KDK, 0x01 || "SMK" || 0x00 || 0x80 || 0x00) 
	 */

	if ( debug ) eprintf("+++ deriving SMK\n");

	cmac128(session->kdk, (unsigned char *)("\x01SMK\x00\x80\x00"), 7,
		session->smk);

	if ( debug ) eprintf("+++ SMK = %s\n", hexstring(session->smk, 16));

	/*
	 * Build message 2
	 *
	 * A || CMACsmk(A) || SigRL
	 * (148 + 16 + SigRL_length bytes = 164 + SigRL_length bytes)
	 *
	 * where:
	 *
	 * A      = Gb || SPID || TYPE || KDF-ID || SigSP(Gb, Ga) 
	 *          (64 + 16 + 2 + 2 + 64 = 148 bytes)
	 * Ga     = Client enclave's session key
	 *          (32 bytes)
	 * Gb     = Service Provider's session key
	 *          (32 bytes)
	 * SPID   = The Service Provider ID, issued by Intel to the vendor
	 *          (16 bytes)
	 * TYPE   = Quote type (0= linkable, 1= linkable)
	 *          (2 bytes)
	 * KDF-ID = (0x0001= CMAC entropy extraction and key derivation)
	 *          (2 bytes)
	 * SigSP  = ECDSA signature of (Gb.x || Gb.y || Ga.x || Ga.y) as r || s
	 *          (signed with the Service Provider's private key)
	 *          (64 bytes)
	 *
	 * CMACsmk= AES-128-CMAC(A)
	 *          (16 bytes)
	 * 
	 * || denotes concatenation
	 *
	 * Note that all key components (Ga.x, etc.) are in little endian 
	 * format, meaning the byte streams need to be reversed.
	 *
	 * For SigRL, send:
	 *
	 *  SigRL_size || SigRL_contents
	 *
	 * where sigRL_size is a 32-bit uint (4 bytes). This matches the
	 * structure definition in sgx_ra_msg2_t
	 */

	key_to_sgx_ec256(&msg2->g_b, Gb);
	memcpy(&msg2->spid, &config->spid, sizeof(sgx_spid_t));
	msg2->quote_type= config->quote_type;
	msg2->kdf_id= 1;

	/* Get the sigrl */

	if ( ! get_sigrl(ias, config->apiver, msg1->gid, sigrl,
		&msg2->sig_rl_size) ) {

		eprintf("could not retrieve the sigrl\n");
		return 0;
	}

	memcpy(gb_ga, &msg2->g_b, 64);
	memcpy(session->g_b, &msg2->g_b, 64);

	memcpy(&gb_ga[64], &msg1->g_a, 64);
	memcpy(session->g_a, &msg1->g_a, 64);

	if ( debug ) eprintf("+++ GbGa = %s\n", hexstring(gb_ga, 128));

	ecdsa_sign(gb_ga, 128, config->service_private_key, r, s, digest);
	reverse_bytes(&msg2->sign_gb_ga.x, r, 32);
	reverse_bytes(&msg2->sign_gb_ga.y, s, 32);

	if ( debug ) {
		eprintf("+++ sha256(GbGa) = %s\n", hexstring(digest, 32));
		eprintf("+++ r = %s\n", hexstring(r, 32));
		eprintf("+++ s = %s\n", hexstring(s, 32));
	}

	/* The "A" component is conveniently at the start of sgx_ra_msg2_t */

	cmac128(session->smk, (unsigned char *) msg2, 148,
		(unsigned char *) &msg2->mac);

	if ( verbose ) {
		edividerWithText("Msg2 Details");
		eprintf("msg2.g_b.gx      = %s\n",
			hexstring(&msg2->g_b.gx, sizeof(msg2->g_b.gx)));
		eprintf("msg2.g_b.gy      = %s\n",
			hexstring(&msg2->g_b.gy, sizeof(msg2->g_b.gy)));
		eprintf("msg2.spid        = %s\n",
			hexstring(&msg2->spid, sizeof(msg2->spid)));
		eprintf("msg2.quote_type  = %s\n",
			hexstring(&msg2->quote_type, sizeof(msg2->quote_type)));
		eprintf("msg2.kdf_id      = %s\n",
			hexstring(&msg2->kdf_id, sizeof(msg2->kdf_id)));
		eprintf("msg2.sign_ga_gb  = %s\n",
			hexstring(&msg2->sign_gb_ga, sizeof(msg2->sign_gb_ga)));
		eprintf("msg2.mac         = %s\n",
			hexstring(&msg2->mac, sizeof(msg2->mac)));
		eprintf("msg2.sig_rl_size = %s\n",
			hexstring(&msg2->sig_rl_size, sizeof(msg2->sig_rl_size)));
		edivider();
	}

	free(msg01);

	return 1;
}

int derive_kdk(EVP_PKEY *Gb, unsigned char kdk[16], sgx_ec256_public_t g_a,
	config_t *config)
{
	unsigned char *Gab_x;
	size_t slen;
	EVP_PKEY *Ga;
	unsigned char cmackey[16];

	memset(cmackey, 0, 16);

	/*
	 * Compute the shared secret using the peer's public key and a generated
	 * public/private key.
	 */

	Ga= key_from_sgx_ec256(&g_a);
	if ( Ga == NULL ) {
		crypto_perror("key_from_sgx_ec256");
		return 0;
	}

	/* The shared secret in a DH exchange is the x-coordinate of Gab */
	Gab_x= key_shared_secret(Gb, Ga, &slen);
	if ( Gab_x == NULL ) {
		crypto_perror("key_shared_secret");
		return 0;
	}

	/* We need it in little endian order, so reverse the bytes. */
	/* We'll do this in-place. */

	if ( debug ) eprintf("+++ shared secret= %s\n", hexstring(Gab_x, slen));

	reverse_bytes(Gab_x, Gab_x, slen);

	if ( debug ) eprintf("+++ reversed     = %s\n", hexstring(Gab_x, slen));

	/* Now hash that to get our KDK (Key Definition Key) */

	/*
	 * KDK = AES_CMAC(0x00000000000000000000000000000000, secret)
	 */

	cmac128(cmackey, Gab_x, slen, kdk);

	return 1;
}

int get_sigrl (IAS_Connection *ias, int version, sgx_epid_group_id_t gid,
	char **sig_rl, uint32_t *sig_rl_size)
{
	IAS_Request *req= NULL;
	int oops= 1;
	string sigrlstr;

	try {
		oops= 0;
		req= new IAS_Request(ias, (uint16_t) version);
	}
	catch (...) {
		oops = 1;
	}

	if (oops) {
		eprintf("Exception while creating IAS request object\n");
		return 0;
	}

	if ( req->sigrl(*(uint32_t *) gid, sigrlstr) != IAS_OK ) {
		return 0;
	}

	*sig_rl= strdup(sigrlstr.c_str());
	if ( *sig_rl == NULL ) return 0;

	*sig_rl_size= (uint32_t ) sigrlstr.length();

	return 1;
}

int get_attestation_report(IAS_Connection *ias, int version,
	const char *b64quote, sgx_ps_sec_prop_desc_t secprop, ra_msg4_t *msg4,
	int strict_trust) 
{
	IAS_Request *req = NULL;
	map<string,string> payload;
	vector<string> messages;
	ias_error_t status;
	string content;

	try {
		req= new IAS_Request(ias, (uint16_t) version);
	}
	catch (...) {
		eprintf("Exception while creating IAS request object\n");
		return 0;
	}

	payload.insert(make_pair("isvEnclaveQuote", b64quote));
	
	status= req->report(payload, content, messages);
	if ( status == IAS_OK ) {
		JSON reportObj = JSON::Load(content);

		if ( verbose ) {
			edividerWithText("Report Body");
			eprintf("%s\n", content.c_str());
			edivider();
			if ( messages.size() ) {
				edividerWithText("IAS Advisories");
				for (vector<string>::const_iterator i = messages.begin();
					i != messages.end(); ++i ) {

					eprintf("%s\n", i->c_str());
				}
				edivider();
			}
		}

		if ( verbose ) {
			edividerWithText("IAS Report - JSON - Required Fields");
			if ( version >= 3 ) {
				eprintf("version               = %d\n",
					reportObj["version"].ToInt());
			}
			eprintf("id:                   = %s\n",
				reportObj["id"].ToString().c_str());
			eprintf("timestamp             = %s\n",
				reportObj["timestamp"].ToString().c_str());
			eprintf("isvEnclaveQuoteStatus = %s\n",
				reportObj["isvEnclaveQuoteStatus"].ToString().c_str());
			eprintf("isvEnclaveQuoteBody   = %s\n",
				reportObj["isvEnclaveQuoteBody"].ToString().c_str());

			edividerWithText("IAS Report - JSON - Optional Fields");

			eprintf("platformInfoBlob  = %s\n",
				reportObj["platformInfoBlob"].ToString().c_str());
			eprintf("revocationReason  = %s\n",
				reportObj["revocationReason"].ToString().c_str());
			eprintf("pseManifestStatus = %s\n",
				reportObj["pseManifestStatus"].ToString().c_str());
			eprintf("pseManifestHash   = %s\n",
				reportObj["pseManifestHash"].ToString().c_str());
			eprintf("nonce             = %s\n",
				reportObj["nonce"].ToString().c_str());
			eprintf("epidPseudonym     = %s\n",
				reportObj["epidPseudonym"].ToString().c_str());
			edivider();
		}

    /*
     * If the report returned a version number (API v3 and above), make
     * sure it matches the API version we used to fetch the report.
	 *
	 * For API v3 and up, this field MUST be in the report.
     */

	if ( reportObj.hasKey("version") ) {
		unsigned int rversion= (unsigned int) reportObj["version"].ToInt();
		if ( verbose )
			eprintf("+++ Verifying report version against API version\n");
		if ( version != rversion ) {
			eprintf("Report version %u does not match API version %u\n",
				rversion , version);
			return 0;
		}
	} else if ( version >= 3 ) {
		eprintf("attestation report version required for API version >= 3\n");
		return 0;
	}

	/*
	 * This sample's attestion policy is based on isvEnclaveQuoteStatus:
	 * 
	 *   1) if "OK" then return "Trusted"
	 *
 	 *   2) if "CONFIGURATION_NEEDED" then return
	 *       "NotTrusted_ItsComplicated" when in --strict-trust-mode
	 *        and "Trusted_ItsComplicated" otherwise
	 *
	 *   3) return "NotTrusted" for all other responses
	 *
	 * 
	 * ItsComplicated means the client is not trusted, but can 
	 * conceivable take action that will allow it to be trusted
	 * (such as a BIOS update).
 	 */

	/*
	 * Simply check to see if status is OK, else enclave considered 
	 * not trusted
	 */

	memset(msg4, 0, sizeof(ra_msg4_t));

	if ( verbose ) edividerWithText("ISV Enclave Trust Status");

	if ( !(reportObj["isvEnclaveQuoteStatus"].ToString().compare("OK"))) {
		msg4->status = Trusted;
		if ( verbose ) eprintf("Enclave TRUSTED\n");
	} else if ( !(reportObj["isvEnclaveQuoteStatus"].ToString().compare("CONFIGURATION_NEEDED"))) {
		if ( strict_trust ) {
			msg4->status = NotTrusted_ItsComplicated;
			if ( verbose ) eprintf("Enclave NOT TRUSTED and COMPLICATED - Reason: %s\n",
				reportObj["isvEnclaveQuoteStatus"].ToString().c_str());
		} else {
			if ( verbose ) eprintf("Enclave TRUSTED and COMPLICATED - Reason: %s\n",
				reportObj["isvEnclaveQuoteStatus"].ToString().c_str());
			msg4->status = Trusted_ItsComplicated;
		}
	} else if ( !(reportObj["isvEnclaveQuoteStatus"].ToString().compare("GROUP_OUT_OF_DATE"))) {
		/*THIS ERROR MUST BE IGNORED BECAUSE CORRUPTED*/
		msg4->status = NotTrusted_ItsComplicated;
		flag_BIOS = true;
		cerr << "***CAUTION: THIS ERROR MUST BE IGNORED BECAUSE CLEARLY BUGED" << endl;
		//if ( verbose ) eprintf("Enclave NOT TRUSTED and COMPLICATED - Reason: %s\n",
		if (verbose ) eprintf("IAS returned unjust error message. Please ignore this. Message: %s\n",
			reportObj["isvEnclaveQuoteStatus"].ToString().c_str());
	} else {
		msg4->status = NotTrusted;
		if ( verbose ) eprintf("Enclave NOT TRUSTED - Reason: %s\n",
			reportObj["isvEnclaveQuoteStatus"].ToString().c_str());
	}
	

	/* Check to see if a platformInfoBlob was sent back as part of the
	 * response */

	if (!reportObj["platformInfoBlob"].IsNull()) {
		if ( verbose ) eprintf("A Platform Info Blob (PIB) was provided by the IAS\n");

		/* The platformInfoBlob has two parts, a TVL Header (4 bytes),
		 * and TLV Payload (variable) */

		string pibBuff = reportObj["platformInfoBlob"].ToString();

		/* remove the TLV Header (8 base16 chars, ie. 4 bytes) from
		 * the PIB Buff. */

		pibBuff.erase(pibBuff.begin(), pibBuff.begin() + (4*2)); 

		int ret = from_hexstring ((unsigned char *)&msg4->platformInfoBlob, 
			pibBuff.c_str(), pibBuff.length());
		} else {
			if ( verbose ) eprintf("A Platform Info Blob (PIB) was NOT provided by the IAS\n");
		}
                 
		return 1;
	}

	eprintf("attestation query returned %lu: \n", status);

	switch(status) {
		case IAS_QUERY_FAILED:
			eprintf("Could not query IAS\n");
			break;
		case IAS_BADREQUEST:
			eprintf("Invalid payload\n");
			break;
		case IAS_UNAUTHORIZED:
			eprintf("Failed to authenticate or authorize request\n");
			break;
		case IAS_SERVER_ERR:
			eprintf("An internal error occurred on the IAS server\n");
			break;
		case IAS_UNAVAILABLE:
			eprintf("Service is currently not able to process the request. Try again later.\n");
			break;
		case IAS_INTERNAL_ERROR:
			eprintf("An internal error occurred while processing the IAS response\n");
			break;
		case IAS_BAD_CERTIFICATE:
			eprintf("The signing certificate could not be validated\n");
			break;
		case IAS_BAD_SIGNATURE:
			eprintf("The report signature could not be validated\n");
			break;
		default:
			if ( status >= 100 && status < 600 ) {
				eprintf("Unexpected HTTP response code\n");
			} else {
				eprintf("An unknown error occurred.\n");
			}
	}

	return 0;
}

// Break a URL into server and port. NOTE: This is a simplistic algorithm.

int get_proxy(char **server, unsigned int *port, const char *url)
{
	size_t idx1, idx2;
	string lcurl, proto, srv, sport;

	if (url == NULL) return 0;

	lcurl = string(url);
	// Make lower case for sanity
	transform(lcurl.begin(), lcurl.end(), lcurl.begin(), ::tolower);

	idx1= lcurl.find_first_of(":");
	proto = lcurl.substr(0, idx1);
	if (proto == "https") *port = 443;
	else if (proto == "http") *port = 80;
	else return 0;

	idx1 = lcurl.find_first_not_of("/", idx1 + 1);
	if (idx1 == string::npos) return 0;
	
	idx2 = lcurl.find_first_of(":", idx1);
	if (idx2 == string::npos) {
		idx2 = lcurl.find_first_of("/", idx1);
		if (idx2 == string::npos) srv = lcurl.substr(idx1);
		else srv = lcurl.substr(idx1, idx2 - idx1);
	}
	else {
		srv= lcurl.substr(idx1, idx2 - idx1);
		idx1 = idx2+1;
		idx2 = lcurl.find_first_of("/", idx1);

		if (idx2 == string::npos) sport = lcurl.substr(idx1);
		else sport = lcurl.substr(idx1, idx2 - idx1);

		try {
			*port = (unsigned int) ::stoul(sport);
		}
		catch (...) {
			return 0;
		}
	}

	try {
		*server = new char[srv.length()+1];
	}
	catch (...) {
		return 0;
	}

	memcpy(*server, srv.c_str(), srv.length());
	(*server)[srv.length()] = 0;

	return 1;
}

int encrypt_data_for_ISV(unsigned char *plaintext, int plaintext_len,
	unsigned char *key, unsigned char *iv, unsigned char *ciphertext, uint8_t* tag)
{
	EVP_CIPHER_CTX *ctx;

	int len;

	int ciphertext_len;

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new()))
	{
		ERR_print_errors_fp(stderr);
		return -1;
	}

	/* Initialise the encryption operation. IMPORTANT - ensure you use a key
	* and IV size appropriate for your cipher
	* In this example we are using 256 bit AES (i.e. a 256 bit key). The
	* IV size for *most* modes is the same as the block size. For AES this
	* is 128 bits */
	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, iv))
	{
		ERR_print_errors_fp(stderr);
		return -1;
	}

	/* Provide the message to be encrypted, and obtain the encrypted output.
	* EVP_EncryptUpdate can be called multiple times if necessary
	*/
	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
	{
		ERR_print_errors_fp(stderr);
		return -1;
	}
	ciphertext_len = len;

	/* Finalise the encryption. Further ciphertext bytes may be written at
	* this stage.
	*/
	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
	{
		ERR_print_errors_fp(stderr);
		return -1;
	}
	ciphertext_len += len;

	/*Obtain MAC tag*/
	if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
	{
		ERR_print_errors_fp(stderr);
		return -1;
	}

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
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

uint8_t* generate_nonce(int size)
{
	random_device rnd;
	mt19937 mt(rnd());
	uniform_int_distribution<> randchar(0, 255);

	uint8_t* nonce_heap = new uint8_t[size];

	for(int i = 0; i < size; i++)
	{
		nonce_heap[i] = (uint8_t)randchar(mt);
	}

	cout << "Generated nonce is: " << endl;
	BIO_dump_fp(stdout, (const char*)nonce_heap, size);
	cout << endl;

	return nonce_heap;
}

#ifndef _WIN32

/* We don't care which signal it is since we're shutting down regardless */

void cleanup_and_exit(int signo)
{
	/* Signal-safe, and we don't care if it fails or is a partial write. */

	ssize_t bytes= write(STDERR_FILENO, "\nterminating\n", 13);

	/*
	 * This destructor consists of signal-safe system calls (close,
	 * shutdown).
	 */

	delete msgio;

	exit(1);
}
#endif

#define NNL <<endl<<endl<<
#define NL <<endl<<

void usage () 
{
	cerr << "usage: sp [ options ] [ port ]" NL
"Required:" NL
"  -A, --ias-signing-cafile=FILE" NL
"                           Specify the IAS Report Signing CA file." NL
"  -C, --ias-cert-file=FILE Specify the IAS client certificate to use when" NL
"                             communicating with IAS." NNL
"One of (required):" NL
"  -S, --spid-file=FILE     Set the SPID from a file containg a 32-byte." NL
"                             ASCII hex string." NL
"  -s, --spid=HEXSTRING     Set the SPID from a 32-byte ASCII hex string." NNL
"Optional:" NL
"  -B, --ca-bundle-file=FILE" NL
"                           Use the CA certificate bundle at FILE (default:" NL
"                             " << DEFAULT_CA_BUNDLE << ")" NL
"  -E, --ias-cert-passwd=FILE" NL
"                           Use password in FILE for the IAS client" NL
"                             certificate." NL
"  -G, --list-agents        List available user agent names for --user-agent" NL
"  -K, --service-key-file=FILE" NL
"                           The private key file for the service in PEM" NL
"                             format (default: use hardcoded key). The " NL
"                             client must be given the corresponding public" NL
"                             key. Can't combine with --key." NL
"  -P, --production         Query the production IAS server instead of dev." NL
"  -X, --strict-trust-mode  Don't trust enclaves that receive a " NL
"                             CONFIGURATION_NEEDED response from IAS " NL
"                             (default: trust)" NL
"  -Y, --ias-cert-key=FILE  The private key file for the IAS client certificate." NL
"  -d, --debug              Print debug information to stderr." NL
"  -g, --user-agent=NAME    Use NAME as the user agent for contacting IAS." NL
"  -k, --key=HEXSTRING      The private key as a hex string. See --key-file" NL
"                             for notes. Can't combine with --key-file." NL
"  -l, --linkable           Request a linkable quote (default: unlinkable)." NL
"  -p, --proxy=PROXYURL     Use the proxy server at PROXYURL when contacting" NL
"                             IAS. Can't combine with --no-proxy\n" NL
"  -r, --api-version=N      Use version N of the IAS API (default: " << to_string(IAS_API_DEF_VERSION) << ")" NL
"  -t, --ias-cert-type=TYPE The client certificate type. Can be PEM (default)" NL
"                             or P12." NL
"  -v, --verbose            Be verbose. Print message structure details and the" NL
"                             results of intermediate operations to stderr." NL
"  -x, --no-proxy           Do not use a proxy (force a direct connection), " NL
"                             overriding environment." NL
"  -z  --stdio              Read from stdin and write to stdout instead of" NL
"                             running as a network server." <<endl;

	::exit(1);
}

