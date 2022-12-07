#ifndef _CRYPTO_H_
#define _CRYPTO_H_

#include "datatypes_uri.h"

#include <string>
#include <map>

bool authenticatePassPhrase(const std::string& filename, const std::string& passPhrase);

bool encryptAndWrite(std::map<int, Uri> uriMap, const std::string& dataFile);

bool encryptAndWrite(std::map<int, Uri> uriMap, 
                     const std::string& dataFile, 
                     const std::string& passPhrase);

bool decryptAndWrite(std::map<int, Uri> uriMap, const std::string& exportFile);

std::map<int, Uri> runtimeEncrypt(std::map<int, Uri> uriMap, const std::string& passPhrase);

Uri runtimeEncrypt(Uri uriEntry);

#endif
