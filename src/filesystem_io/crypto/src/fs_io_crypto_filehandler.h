#ifndef _FS_IO_CRYPTO_FILEHANDLER_H_
#define _FS_IO_CRYPTO_FILEHANDLER_H_

#include "datatypes_uri.h"

#include <string>
#include <map>
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

std::map<int, Uri> runtimeEncrypt(std::map<int,Uri> uriMap, const std::string& passPhrase);

#endif
