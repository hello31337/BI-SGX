#include "error_print.hpp"

void sgx_error_print(sgx_status_t status)
{
	std::cerr << "==================================================================================" << std::endl;
	switch(status)
	{
		std::cerr << "Error name: ";

		case 0x0000:
			std::cerr << "SGX_SUCCESS" << std::endl;
			std::cerr << "Exited SGX function successfully." << std::endl;
			break;
		
		case 0x0001:
			std::cerr << "SGX_ERROR_UNEXPECTED" << std::endl;
			std::cerr << "An unexpected error has occured." << std::endl;
			break;

		case 0x0002:
			std::cerr << "SGX_ERROR_INVALID_PARAMETER" << std::endl;
			std::cerr << "The parameter is incorrect. Please check the argument of function." << std::endl;
			break;

		case 0x0003:
			std::cerr << "SGX_ERROR_OUT_OF_MEMORY" << std::endl;
			std::cerr << "There is not enough memory available to complete this operation." << std::endl;
			break;

		case 0x0004:
			std::cerr << "SGX_ERROR_ENCLAVE_LOST" << std::endl;
			std::cerr << "The enclave is lost after power transition." << std::endl;
			break;

		case 0x0005:
			std::cerr << "SGX_ERROR_INVALID_STATE" << std::endl;
			std::cerr << "The API is invoked in incorrect order or state." << std::endl;
			break;

		case 0x0007:
			std::cerr << "SGX_ERROR_HYPERV_ENABLED" << std::endl;
			std::cerr << "Incompatible versions of Windows* 10 OS and Hyper-V* are detected." << std::endl;
			std::cerr << "In this case, you need to disable Hyper-V on the target machine." << std::endl;
			break;

		case 0x0008:
			std::cerr << "SGX_ERROR_FEATURE_NOT_SUPPORTED" << std::endl;
			std::cerr << "The feature has been deprecated and is no longer supported." << std::endl;
			break;

		case 0x1001:
			std::cerr << "SGX_ERROR_INVALID_FUNCTION" << std::endl;
			std::cerr << "The ECALL/OCALL function index is incorrect." << std::endl;
			break;

		case 0x1003:
			std::cerr << "SGX_ERROR_OUT_OF_TCS" << std::endl;
			std::cerr << "The enclave is out of Thread Control Structure." << std::endl;
			break;

		case 0x1006:
			std::cerr << "SGX_ERROR_ENCLAVE_CRASHED" << std::endl;
			std::cerr << "The enclave has crashed." << std::endl;
			break;

		case 0x1007:
			std::cerr << "SGX_ERROR_ECALL_NOT_ALLOWED" << std::endl;
			std::cerr << "ECALL is not allowed at this time. For example:" << std::endl;
			std::cerr << "- ECALL is not public." << std::endl;
			std::cerr << "- ECALL is blocked by the dynamic entry table." << std::endl;
			std::cerr << "- A nested ECALL is not allowed during global initialization." << std::endl;
			break;

		case 0x1008:
			std::cerr << "SGX_ERROR_OCALL_NOT_ALLOWED" << std::endl;
			std::cerr << "OCALL is not allowed during exception handling." << std::endl;
			break;

		case 0x2000:
			std::cerr << "SGX_ERROR_UNDEFINED_SYMBOL" << std::endl;
			std::cerr << "The enclave image has undefined symbol." << std::endl;
			break;

		case 0x2001:
			std::cerr << "SGX_ERROR_INVALID_ENCLAVE" << std::endl;
			std::cerr << "The enclave image is incorrect." << std::endl;
			break;

		case 0x2002:
			std::cerr << "SGX_ERROR_INVALID_ENCLAVE_ID" << std::endl;
			std::cerr << "The enclave ID is invalid." << std::endl;
			break;

		case 0x2003:
			std::cerr << "SGX_ERROR_INVALID_SIGNATURE" << std::endl;
			std::cerr << "The signature is invalid." << std::endl;
			break;

		case 0x2004:
			std::cerr << "SGX_ERROR_NDEBUG_ENCLAVE" << std::endl;
			std::cerr << "The enclave is signed as product enclave and cannot be created" << std::endl
					<< "as a debuggable enclave." << std::endl;
			break;

		case 0x2005:
			std::cerr << "SGX_ERROR_OUT_OF_EPC" << std::endl;
			std::cerr << "There is not enough EPC available to load the enclave" << std::endl
					<< "or one of the Architecture Enclave needed to complete" << std::endl
					<< "the operation requested." << std::endl;
			break;

		case 0x2006:
			std::cerr << "SGX_ERROR_NO_DEVICE" << std::endl;
			std::cerr << "Cannot open device." << std::endl;
			break;

		case 0x2007:
			std::cerr << "SGX_ERROR_MEMORY_MAP_CONFLICT" << std::endl;
			std::cerr << "Page mapping failed in driver." << std::endl;
			break;

		case 0x2009:
			std::cerr << "SGX_ERROR_INVALID_METADATA" << std::endl;
			std::cerr << "The metadata is incorrect." << std::endl;
			break;

		case 0x200C:
			std::cerr << "SGX_ERROR_DEVICE_BUSY" << std::endl;
			std::cerr << "Device is busy." << std::endl;
			break;

		case 0x200D:
			std::cerr << "SGX_ERROR_INVALID_VERSION" << std::endl;
			std::cerr << "Metadata version is inconsistent between uRTS and sgx_sign" << std::endl
					<< "or the uRTS is incompatible with the current platform." << std::endl;
			break;

		case 0x200E:
			std::cerr << "SGX_ERROR_MODE_INCOMPATIBLE" << std::endl;
			std::cerr << "The target enclave (32/64 bit or HS/Sim) mode is incompatible" << std::endl
					<< "with the uRTS mode." << std::endl;
			break;

		case 0x200F:
			std::cerr << "SGX_ERROR_ENCLAVE_FILE_ACCESS" << std::endl;
			std::cerr << "Cannot open enclave file." << std::endl;
			break;

		case 0x2010:
			std::cerr << "SGX_ERROR_INVALID_MISC" << std::endl;
			std::cerr << "The MiscSelect/MiscMask settings are incorrect." << std::endl;
			break;

		case 0x2012:
			std::cerr << "SGX_ERROR_MEMORY_LOCKED" << std::endl;
			std::cerr << "Attempt to change system memory that should not be modified." << std::endl;
			break;

		case 0x3001:
			std::cerr << "SGX_ERROR_MAC_MISMATCH" << std::endl;
			std::cerr << "Indicates report verification or cryptographic error." << std::endl;
			break;

		case 0x3002:
			std::cerr << "SGX_ERROR_INVALID_ATTRIBUTE" << std::endl;
			std::cerr << "The enclave is not authorized." << std::endl;
			break;

		case 0x3003:
			std::cerr << "SGX_ERROR_INVALID_CPUSVN" << std::endl;
			std::cerr << "The CPU SVN is beyond the CPU SVN value of the platform." << std::endl;
			break;

		case 0x3004:
			std::cerr << "SGX_ERROR_INVALID_ISVSVN" << std::endl;
			std::cerr << "The ISV SVN is greater than the ISV SVN value of the enclave." << std::endl;
			break;

		case 0x3005:
			std::cerr << "SGX_ERROR_INVALID_KEYNAME" << std::endl;
			std::cerr << "Unsupported key name value." << std::endl;
			break;

		case 0x4001:
			std::cerr << "SGX_ERROR_SERVICE_UNAVAILABLE" << std::endl;
			std::cerr << "AE service did not respond or the requested service is not supported." << std::endl
					<< "Probably aesmd service is corrupted, so try reinstalling Intel SGX driver." << std::endl;
			break;

		case 0x4002:
			std::cerr << "SGX_ERROR_SERVICE_TIMEOUT" << std::endl;
			std::cerr << "The request to AE service timed out." << std::endl;
			break;

		case 0x4003:
			std::cerr << "SGX_ERROR_AE_INVALID_EPIDBLOB" << std::endl;
			std::cerr << "Indicates an Intel(R) EPID blob verification error." << std::endl;
			break;

		case 0x4004:
			std::cerr << "SGX_ERROR_SERVICE_INVALID_PRIVILEDGE" << std::endl;
			std::cerr << "Enclave has no priviledge to get launch token." << std::endl;
			break;

		case 0x4005:
			std::cerr << "SGX_ERROR_EPID_MEMBER_REVOKED" << std::endl;
			std::cerr << "The Intel(R) EPID group membership has been revoked." << std::endl
					<< "The platform is not trusted. Updating platform and retrying" << std::endl
					<< "will not remedy the revocation." << std::endl;
			break;

		case 0x4006:
			std::cerr << "SGX_ERROR_UPDATE_NEEDED" << std::endl;
			std::cerr << "Intel(R) SGX needs to be updated." << std::endl;
			break;

		case 0x4007:
			std::cerr << "SGX_ERROR_NETWORK_FAILURE" << std::endl;
			std::cerr << "Network connecting or proxy setting issue is encountered." << std::endl;
			break;

		case 0x4008:
			std::cerr << "SGX_ERROR_AE_SESSION_INVALID" << std::endl;
			std::cerr << "The session is invalid or ended by AE service." << std::endl;
			break;

		case 0x400a:
			std::cerr << "SGX_ERROR_BUSY" << std::endl;
			std::cerr << "The requested service is temporarily not available." << std::endl;
			break;

		case 0x400c:
			std::cerr << "SGX_ERROR_MC_NOT_FOUND" << std::endl;
			std::cerr << "The Monotonic Counter does not exist or has been invalidated." << std::endl;
			break;

		case 0x400d:
			std::cerr << "SGX_ERROR_MC_NO_ACCESS_RIGHT" << std::endl;
			std::cerr << "The caller does not have the access right to the specified VMC." << std::endl;
			break;

		case 0x400e:
			std::cerr << "SGX_ERROR_MC_USED_UP" << std::endl;
			std::cerr << "No Monotonic Counter is available." << std::endl;
			break;

		case 0x400f:
			std::cerr << "SGX_ERROR_MC_OVER_QUOTA" << std::endl;
			std::cerr << "Monotonic Counter reached quota limit." << std::endl;
			break;

		case 0x4011:
			std::cerr << "SGX_ERROR_KDF_MISMATCH" << std::endl;
			std::cerr << "Key derivation function does not match during key exchange." << std::endl;
			break;

		case 0x4012:
			std::cerr << "SGX_ERROR_UNRECOGNIZED_PLATFORM" << std::endl;
			std::cerr << "Intel(R) EPID Provisioning failed because the platform was not recognized" << std::endl
					<< "by the back-end server." << std::endl;
			break;

		case 0x4013:
			std::cerr << "SGX_ERROR_SM_SERVICE_CLOSED" << std::endl;
			std::cerr << "The secure message service instance was closed." << std::endl;
			break;

		case 0x4014:
			std::cerr << "SGX_ERROR_SM_SERVICE_UNAVAILABLE" << std::endl;
			std::cerr << "The secure message service applet does not have an existing session." << std::endl;
			break;

		case 0x4015:
			std::cerr << "SGX_ERROR_SM_SERVICE_UNCAUGHT_EXCEPTION" << std::endl;
			std::cerr << "The secure message service instance was terminated with an uncaught exception." << std::endl;
			break;

		case 0x4016:
			std::cerr << "SGX_ERROR_SM_SERVICE_RESPONSE_OVERFLOW" << std::endl;
			std::cerr << "The response data of the service applet is too large." << std::endl;
			break;

		case 0x4017:
			std::cerr << "SGX_ERROR_SM_SERVICE_INTERNAL_ERROR" << std::endl;
			std::cerr << "The secure message service got an internal error." << std::endl;
			break;

		case 0x5002:
			std::cerr << "SGX_ERROR_NO_PRIVILEDGE" << std::endl;
			std::cerr << "You do not have enough priviledges to perform the operation." << std::endl;
			break;

		case 0x6001:
			std::cerr << "SGX_ERROR_PCL_ENCRYPTED" << std::endl;
			std::cerr << "Trying to encrypt an already encrypted enclave." << std::endl;
			break;

		case 0x6002:
			std::cerr << "SGX_ERROR_PCL_NOT_ENCRYPTED" << std::endl;
			std::cerr << "Trying to load a plain enclave using sgx_created_encrypted_enclave." << std::endl;
			break;

		case 0x6003:
			std::cerr << "SGX_ERROR_PCL_MAC_MISMATCH" << std::endl;
			std::cerr << "Section MAC result does not match build time MAC." << std::endl;
			break;

		case 0x6004:
			std::cerr << "SGX_ERROR_PCL_SHA_MISMATCH" << std::endl;
			std::cerr << "Unsealed key MAC doesn't match MAC of key hardcoded in enclave binary." << std::endl;
			break;

		case 0x6005:
			std::cerr << "SGX_ERROR_PCL_GUID_MISMATCH" << std::endl;
			std::cerr << "GUID in sealed blob doesn't match GUID hardcoded in enclave binary." << std::endl;
			break;

		case 0x7001:
			std::cerr << "SGX_ERROR_FILE_BAD_STATUS" << std::endl;
			std::cerr << "The file is in a bad status, run sgx_clearerr to try and fix it." << std::endl;
			break;

		case 0x7002:
			std::cerr << "SGX_ERROR_FILE_NO_KEY_ID" << std::endl;
			std::cerr << "The Key ID field is all zeros, cannot re-generate the encryption key." << std::endl;
			break;

		case 0x7003:
			std::cerr << "SGX_ERROR_FILE_NAME_MISMATCH" << std::endl;
			std::cerr << "The current file name is different than the original file name" << std::endl
					<< "(not allowed, substitution attack)." << std::endl;
			break;

		case 0x7004:
			std::cerr << "SGX_ERROR_FILE_NOT_SGX_FILE" << std::endl;
			std::cerr << "The file is not an Intel SGX file." << std::endl;
			break;

		case 0x7005:
			std::cerr << "SGX_ERROR_FILE_CANT_OPEN_RECOVERY_FILE" << std::endl;
			std::cerr << "A recovery file cannot be opened, so the flush operation cannot continue" << std::endl
					<< "(only used when no EXXX is returned)." << std::endl;
			break;

		case 0x7006:
			std::cerr << "SGX_ERROR_FILE_CANT_WRITE_RECOVERY_FILE" << std::endl;
			std::cerr << "A recovery file cannot be writen, so the flush operation cannot continue" << std::endl
					<< "(only used when no EXXX is returned)." << std::endl;
			break;

		case 0x7007:
			std::cerr << "SGX_ERROR_FILE_RECOVERY_NEEDED" << std::endl;
			std::cerr << "When opening the file, recovery is needed, but the recovery process failed." << std::endl;
			break;

		case 0x7008:
			std::cerr << "SGX_ERROR_FILE_FLUSH_FAILED" << std::endl;
			std::cerr << "fflush operation (to the disk) failed (only used when no EXXX is returned)." << std::endl;
			break;

		case 0x7009:
			std::cerr << "SGX_ERROR_FILE_CLOSE_FAILED" << std::endl;
			std::cerr << "fclose operation (to the disk) failed (only used when no EXXX is returned)." << std::endl;
			break;

		case 0x8001:
			std::cerr << "SGX_ERROR_IPLDR_NOTENCRYPTED" << std::endl;
			std::cerr << "sgx_create_encrypted_enclave was called, but the enclave file is not encrypted." << std::endl;
			break;

		case 0x8002:
			std::cerr << "SGX_ERROR_IPLDR_MAC_MISMATCH" << std::endl;
			std::cerr << "sgx_create_encrypted_enclave was called but there was a verification error" << std::endl
					<< "when decrypting the data." << std::endl;
			break;

		case 0x8003:
			std::cerr << "SGX_ERROR_IPLDR_ENCRYPTED" << std::endl;
			std::cerr << "sgx_create_encrypted_enclave was called, but the enclave file is encrypted." << std::endl;
			break;

		case 0xf001:
			std::cerr << "SGX_INTERNAL_ERROR_ENCLAVE_CREATE_INTERRUPTED" << std::endl;
			std::cerr << "The ioctl for enclave_create unexpectedly failed with EINTR." << std::endl;
			break;
	
		default:
			std::cerr << "Unrecognized SGX status format." << std::endl;
	}

	std::cerr << "==================================================================================" << std::endl;

	return;
}
