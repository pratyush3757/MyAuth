#ifndef _CRYPTO_RUNTIME_H_
#define _CRYPTO_RUNTIME_H_

#include "datatypes_uri.h"

#include <string>
#include <map>
/*

void importFile(const std::string& clearFile, 
                const std::string& encryptedFile, 
                const std::string& passPhrase);

bool importRawFile(const std::string& clearFile,
                   const std::string& encryptedFile,
                   const std::string& passPhrase);*/

std::map<int, Uri> runtimeEncrypt(std::map<int, Uri> uriMap, const std::string& passPhrase);

Uri runtimeEncrypt(Uri uriEntry);

#endif
