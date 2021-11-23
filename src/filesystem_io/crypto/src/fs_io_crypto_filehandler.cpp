#include <cryptopp/files.h>
#include <cryptopp/default.h>

void EncryptFile(const char *in, const char *out, const char *passPhrase) {   
    try {
        CryptoPP::FileSource f(in, true, 
                               new CryptoPP::DefaultEncryptorWithMAC(
                                   passPhrase, new CryptoPP::FileSink(out)));
        exit(0);
    }
    catch(...) {
        perror("Encryption Error");
        exit(1);
    }
}

void DecryptFile(const char *in, const char *out, const char *passPhrase) {
    try {
        CryptoPP::FileSource f(in, true,
                               new CryptoPP::DefaultDecryptorWithMAC(
                                   passPhrase, new CryptoPP::FileSink(out)));
    }
    catch(...) {
        perror("Decryption Error");
        exit(1);
    }
}
