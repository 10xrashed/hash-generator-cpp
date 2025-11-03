#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <openssl/sha.h>
#include <openssl/md5.h>

using namespace std;

#define RESET "\033[0m"
#define BOLD "\033[1m"
#define GREEN "\033[32m"
#define BLUE "\033[34m"
#define CYAN "\033[36m"
#define YELLOW "\033[33m"
#define MAGENTA "\033[35m"

#define BYTES_TO_HEX(data, len, result) { \
    stringstream ss; \
    ss << hex << setfill('0'); \
    for (size_t i = 0; i < len; ++i) { \
        ss << setw(2) << static_cast<int>(data[i]); \
    } \
    result = ss.str(); \
}

#define MD5_HASH(input, output) { \
    unsigned char hash[MD5_DIGEST_LENGTH]; \
    MD5(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), hash); \
    BYTES_TO_HEX(hash, MD5_DIGEST_LENGTH, output); \
}

#define SHA1_HASH(input, output) { \
    unsigned char hash[SHA_DIGEST_LENGTH]; \
    SHA1(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), hash); \
    BYTES_TO_HEX(hash, SHA_DIGEST_LENGTH, output); \
}

#define SHA256_HASH(input, output) { \
    unsigned char hash[SHA256_DIGEST_LENGTH]; \
    SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), hash); \
    BYTES_TO_HEX(hash, SHA256_DIGEST_LENGTH, output); \
}

#define SHA512_HASH(input, output) { \
    unsigned char hash[SHA512_DIGEST_LENGTH]; \
    SHA512(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), hash); \
    BYTES_TO_HEX(hash, SHA512_DIGEST_LENGTH, output); \
}

#define PRINT_LINE() cout << CYAN << string(70, '=') << RESET << endl

int main() {
    string input;
    string md5Result, sha1Result, sha256Result, sha512Result;
    
    cout << endl;
    PRINT_LINE();
    cout << BOLD << GREEN << "  CRYPTOGRAPHIC HASH CALCULATOR" << RESET << endl;
    PRINT_LINE();
    cout << endl;
    
    cout << "Enter text to hash: ";
    getline(cin, input);
    cout << endl;
    
    MD5_HASH(input, md5Result);
    SHA1_HASH(input, sha1Result);
    SHA256_HASH(input, sha256Result);
    SHA512_HASH(input, sha512Result);
    
    cout << BOLD << "Input: " << YELLOW << "\"" << input << "\"" << RESET << endl;
    cout << endl;
    
    cout << left << setw(12) << "Algorithm" << setw(10) << "Bits" << "Hash" << endl;
    cout << string(70, '-') << endl;
    
    cout << MAGENTA << left << setw(12) << "MD5" << RESET << setw(10) << 128 
         << BLUE << md5Result << RESET << endl;
    
    cout << MAGENTA << left << setw(12) << "SHA-1" << RESET << setw(10) << 160 
         << BLUE << sha1Result << RESET << endl;
    
    cout << MAGENTA << left << setw(12) << "SHA-256" << RESET << setw(10) << 256 
         << BLUE << sha256Result << RESET << endl;
    
    cout << MAGENTA << left << setw(12) << "SHA-512" << RESET << setw(10) << 512 
         << BLUE << sha512Result << RESET << endl;
    
    cout << endl;
    PRINT_LINE();
    cout << endl;
    
    return 0;
}
