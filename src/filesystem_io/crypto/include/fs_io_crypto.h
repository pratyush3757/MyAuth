#ifndef _FS_IO_CRYPTO_H_
#define _FS_IO_CRYPTO_H_

#include <string>
#include <iostream>

void encryptFile(const std::string& clearFile, 
                 const std::string& encryptedFile, 
                 const std::string& passPhrase);

void decryptFile(const std::string& encryptedFile, 
                 const std::string& clearFile, 
                 const std::string& passPhrase);

bool aesEncryptFile(const std::string& clearFile, 
                    const std::string& encryptedFile, 
                    const std::string& passPhrase);

bool aesDecryptFile(const std::string& encryptedFile, 
                    const std::string& clearFile, 
                    const std::string& passPhrase);

void importFile(const std::string& clearFile, 
                const std::string& encryptedFile, 
                const std::string& passPhrase);

bool ImportRawFile(const std::string& clearFile,
                   const std::string& encryptedFile,
                   const std::string& passPhrase);

bool authenticatePassPhrase(const std::string& filename, const std::string& passPhrase);

#endif
