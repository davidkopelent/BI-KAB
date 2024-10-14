#ifndef __PROGTEST__
#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

#include <openssl/evp.h>
#include <openssl/rand.h>

using namespace std;

#endif /* __PROGTEST__ */

struct Hash {
    int m_Bits;
    string m_Hash;
    string m_Message;

    Hash(int bits)
        : m_Bits(bits)
    {}

    Hash(int bits, const string& hash, const string& message)
        : m_Bits(bits)
        , m_Hash(hash)
        , m_Message(message) 
    {}
};

class Cache {
public:
    Cache(int size) : m_Size(size) {
        for (int i = 0; i < size; i++) {
            m_Cache.push_back(Hash(i));
        }
    }

    int isCached(int bits) const {
        for (int i = bits; i < m_Size; i++) {
            if (!m_Cache[i].m_Hash.empty() && !m_Cache[i].m_Message.empty())
                return i;
        }
        return -1;
    }

    bool isInCache(int bits) const {
        return !m_Cache[bits].m_Hash.empty() && !m_Cache[bits].m_Message.empty();
    }

    void addToCache(int bits, const string& hash, const string& message) {
        if (!isInCache(bits)) {
            m_Cache[bits].m_Hash = hash;
            m_Cache[bits].m_Message = message;
        }
    }

    string getHash(size_t index) const {
        return m_Cache[index].m_Hash;
    }

    string getMessage(size_t index) const {
        return m_Cache[index].m_Message;
    }

private:
    int m_Size;
    vector<Hash> m_Cache;
};

Cache cache(512);

unsigned int customRand() {
    static unsigned int seed = 12345;
    const unsigned int a = 1664525; 
    const unsigned int c = 1013904223;
    const unsigned int m = 4294967295; 
    seed = (a * seed + c) & m; // Use bitwise AND instead of modulo
    return seed;
}

string toHex(const unsigned char* data, size_t len) {
    stringstream ss;
    ss << hex << setfill('0');
    for (size_t i = 0; i < len; ++i) {
        ss << setw(2) << static_cast<int>(data[i]);
    }
    return ss.str();
}

int countZeros(const char c) {
    switch (c) {
        case '0':
            return 4;
        case '1':
            return 3;
        case '2': case '3':
            return 2;
        case '4': case '5': case '6': case '7':
            return 1;
        default:
            return 0;
    }

    return 0;
}

bool countLeadingZeros(const unsigned char *data, size_t len, int bits, string& output)
{
    int zeros_a = 0, zeros_b = 0, leadingZeros = 0;
    static const char hex_digits[] = "0123456789abcdef";

    output.clear();
    output.reserve(len * 2);
    for (size_t i = 0; i < len; i++)
    {
        char c1 = hex_digits[data[i] >> 4];
        char c2 = hex_digits[data[i] & 15];

        if (leadingZeros < bits) {
            zeros_a = countZeros(c1);
            if (zeros_a < 4 && leadingZeros < bits)
                return false;

            leadingZeros += zeros_a;

            zeros_b = countZeros(c2);
            if (zeros_b < 4 && leadingZeros < bits)
                return false;

            leadingZeros += zeros_b;
        }

        output.push_back(c1);
        output.push_back(c2);
    }   

    return leadingZeros >= bits;
}

bool isBitsValid(int bits, const char* hashType) {
    if (bits < 0) return false;
    if (strcmp(hashType, "sha512") == 0 && bits > 512) return false;
    if (strcmp(hashType, "sha256") == 0 && bits > 256) return false;
    if (strcmp(hashType, "sha384") == 0 && bits > 384) return false;
    return true;
}

int hashFinder(int bits, string &message, string &hash, const char* hashType) {
    if (!isBitsValid(bits, hashType)) return 0;

    int check = cache.isCached(bits);
    if (check != -1) {
        hash = cache.getHash(check);
        message = cache.getMessage(check);
        return 1;
    }

    OpenSSL_add_all_digests();

    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned char message_bytes[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    int ret;

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) return 0;

    // Initialize the message digest context
    md = EVP_get_digestbyname(hashType);
    if (!md) {
        EVP_MD_CTX_free(mdctx);
        return 0;
    }

    RAND_bytes(message_bytes, sizeof(message_bytes));

    while (true) {
        ret = EVP_DigestInit_ex(mdctx, md, NULL);
        if (ret != 1) {
            EVP_MD_CTX_free(mdctx);
            return 0;
        }

        // Feed the message to the digest context
        ret = EVP_DigestUpdate(mdctx, message_bytes, sizeof(message_bytes));
        if (ret != 1) {
            EVP_MD_CTX_free(mdctx);
            return 0;
        }

        // Finalize the digest computation
        ret = EVP_DigestFinal_ex(mdctx, md_value, &md_len);
        if (ret != 1) {
            EVP_MD_CTX_free(mdctx);
            return 0;
        }

        // Check if the hash has the correct number of leading zero bits
        if (countLeadingZeros(md_value, md_len, bits, hash)) {
            message = toHex(message_bytes, sizeof(message_bytes));
            if (!cache.isInCache(bits)){
                cache.addToCache(bits, hash, message);
            }

            EVP_MD_CTX_free(mdctx);
            return 1;
        }

        if (!cache.isInCache(bits)){
            cache.addToCache(bits, toHex(md_value, md_len), toHex(message_bytes, sizeof(message_bytes)));
        }

        message_bytes[customRand() % EVP_MAX_MD_SIZE] = (customRand() % UCHAR_MAX) - '0';
    }

    EVP_MD_CTX_free(mdctx);
    return 0;
}

int findHash(int bits, string &message, string &hash) {
    return hashFinder(bits, message, hash, "sha512");
}

int findHashEx (int bits, string & message, string & hash, string_view hashType) {
    return hashFinder(bits, message, hash, hashType.data());
}

#ifndef __PROGTEST__

bool countLeadingZeros(const string& hash, int bits) {
    int leadingZeros = 0;
    
    for (char c : hash) {
        switch (c) {
            case '0':
                leadingZeros += 4;
                break;
            case '1':
                leadingZeros += 3;
                return leadingZeros >= bits;
            case '2': case '3':
                leadingZeros += 2;
                return leadingZeros >= bits;
            case '4': case '5': case '6': case '7':
                leadingZeros += 1;
                return leadingZeros >= bits;
            default:
                return leadingZeros >= bits;
        }
    }
    
    return leadingZeros >= bits;
}

int checkHash(int bits, const string &hash) {
    return countLeadingZeros(hash, bits);
}

int main (void) {
 
    return EXIT_SUCCESS;
}
#endif /* __PROGTEST__ */