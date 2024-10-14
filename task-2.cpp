#ifndef __PROGTEST__
#include <cstdlib>
#include <cstdio>
#include <cctype>
#include <climits>
#include <cstdint>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <unistd.h>
#include <string>
#include <memory>
#include <vector>
#include <fstream>
#include <cassert>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/rand.h>

using namespace std;

struct crypto_config
{
	const char * m_crypto_function;
	std::unique_ptr<uint8_t[]> m_key;
	std::unique_ptr<uint8_t[]> m_IV;
	size_t m_key_len;
	size_t m_IV_len;
};

#endif /* __PROGTEST__ */

#define inputBuffer_SIZE 1024
#define outputBuffer_SIZE (inputBuffer_SIZE + EVP_MAX_BLOCK_LENGTH)

bool checkConfig(crypto_config& config, size_t cipherKeyLen, size_t cipherIVLen, bool encrypt) {
	if (config.m_key_len < cipherKeyLen || config.m_key == nullptr) {
        if (!encrypt) return false;
        config.m_key = make_unique<uint8_t[]>(cipherKeyLen);
		config.m_key_len = cipherKeyLen;
        RAND_bytes(config.m_key.get(), cipherKeyLen);
    }

	if (cipherIVLen && (config.m_IV_len < cipherIVLen || config.m_IV == nullptr)) {
        if (!encrypt) return false;
        config.m_IV = make_unique<uint8_t[]>(cipherIVLen);
		config.m_IV_len = cipherIVLen;
        RAND_bytes(config.m_IV.get(), cipherIVLen);
    }
	
	return true;
}

bool encryption(const std::string& in_filename, const std::string& out_filename, crypto_config& cfg, bool encrypt) {
	ifstream ifs(in_filename);
    ofstream ofs(out_filename);

	if (!ifs.good() || !ofs.good()) {
        cout << "Failed to open file!" << endl;
        return false;
    }

	char header[18] = {};
    ifs.read(header, 18);

    if (ifs.gcount() != 18) {
        cout << "Failed reading file header!" << endl;
        return false;
    }

    ofs.write(header, 18);
	
    if (!ofs.good())
		return false;

	OpenSSL_add_all_ciphers();
	struct crypto_config &config = cfg;
	EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
    const EVP_CIPHER * cipher = EVP_get_cipherbyname(config.m_crypto_function);

    if (!ctx || !cipher) {
		EVP_CIPHER_CTX_free(ctx);
        return false;
	}

	if (!checkConfig(config, EVP_CIPHER_key_length(cipher), EVP_CIPHER_iv_length(cipher), encrypt)) {
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}

    if (!EVP_CipherInit_ex(ctx, cipher, NULL, config.m_key.get(), config.m_IV.get(), static_cast<int>(encrypt))) {
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}

	char inputBuffer[inputBuffer_SIZE] = {};
    char outputBuffer[outputBuffer_SIZE] = {};
    int outputSize = 0;

    while (ifs.good() && ofs.good()) {
        ifs.read(inputBuffer, inputBuffer_SIZE);
        if (!EVP_CipherUpdate(ctx, reinterpret_cast<unsigned char*>(outputBuffer), &outputSize, reinterpret_cast<const unsigned char*>(inputBuffer), ifs.gcount())) {
			EVP_CIPHER_CTX_free(ctx);
            return false;
		}

        ofs.write(outputBuffer, outputSize);
		if (!ofs.good()) {
			EVP_CIPHER_CTX_free(ctx);
			return false;
		}
    }

    if (ifs.eof()) {
        if (!EVP_CipherFinal_ex(ctx, reinterpret_cast<unsigned char*>(outputBuffer), &outputSize)) {
			EVP_CIPHER_CTX_free(ctx);
            return false;
		}

        ofs.write(outputBuffer, outputSize);
		EVP_CIPHER_CTX_free(ctx);
        return ofs.good();
    }

	EVP_CIPHER_CTX_free(ctx);
    return false;
}

bool encrypt_data(const std::string& in_filename, const std::string& out_filename, crypto_config& config) {
	return encryption(in_filename, out_filename, config, true);
}

bool decrypt_data(const std::string& in_filename, const std::string& out_filename, crypto_config& config) {
    return encryption(in_filename, out_filename, config, false);
}


#ifndef __PROGTEST__
#include <filesystem>
bool compare_files ( const char * name1, const char * name2 ) {
    namespace fs = std::filesystem;
    if ( fs::file_size(name1) != fs::file_size(name2) ) {
        cout << "File size mismatch" << endl;
        return false;
    }

    ifstream ifs1 (name1);
    ifstream ifs2 (name2);
    string word;
    string word2;

    while ( ifs1 >> word && ifs2 >> word2 ) {
        if ( word != word2 ) {
            cout << "Files not equal" << endl;
            return false;
        }
    }

    return true;
}

int main ( void )
{
	crypto_config config {nullptr, nullptr, nullptr, 0, 0};

	// ECB mode
	config.m_crypto_function = "AES-128-ECB";
	config.m_key = std::make_unique<uint8_t[]>(16);
 	memset(config.m_key.get(), 0, 16);
	config.m_key_len = 16;

	assert( encrypt_data  ("homer-simpson.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "homer-simpson_enc_ecb.TGA") );

	assert( decrypt_data  ("homer-simpson_enc_ecb.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "homer-simpson.TGA") );

	assert( encrypt_data  ("UCM8.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "UCM8_enc_ecb.TGA") );

	assert( decrypt_data  ("UCM8_enc_ecb.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "UCM8.TGA") );

	assert( encrypt_data  ("image_1.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "ref_1_enc_ecb.TGA") );

	assert( encrypt_data  ("image_2.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "ref_2_enc_ecb.TGA") );

	assert( decrypt_data ("image_3_enc_ecb.TGA", "out_file.TGA", config)  &&
		    compare_files("out_file.TGA", "ref_3_dec_ecb.TGA") );

	assert( decrypt_data ("image_4_enc_ecb.TGA", "out_file.TGA", config)  &&
		    compare_files("out_file.TGA", "ref_4_dec_ecb.TGA") );

	// CBC mode
	config.m_crypto_function = "AES-128-CBC";
	config.m_IV = std::make_unique<uint8_t[]>(16);
	config.m_IV_len = 16;
	memset(config.m_IV.get(), 0, 16);

	assert( encrypt_data  ("UCM8.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "UCM8_enc_cbc.TGA") );

	assert( decrypt_data  ("UCM8_enc_cbc.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "UCM8.TGA") );

	assert( encrypt_data  ("homer-simpson.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "homer-simpson_enc_cbc.TGA") );

	assert( decrypt_data  ("homer-simpson_enc_cbc.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "homer-simpson.TGA") );

	assert( encrypt_data  ("image_1.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "ref_5_enc_cbc.TGA") );

	assert( encrypt_data  ("image_2.TGA", "out_file.TGA", config) &&
			compare_files ("out_file.TGA", "ref_6_enc_cbc.TGA") );

	assert( decrypt_data ("image_7_enc_cbc.TGA", "out_file.TGA", config)  &&
		    compare_files("out_file.TGA", "ref_7_dec_cbc.TGA") );

	assert( decrypt_data ("image_8_enc_cbc.TGA", "out_file.TGA", config)  &&
		    compare_files("out_file.TGA", "ref_8_dec_cbc.TGA") );
	return 0;
}

#endif /* _PROGTEST_ */