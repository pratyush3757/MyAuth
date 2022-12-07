#ifndef _CRYPTO_AUTHENTICATION_H_
#define _CRYPTO_AUTHENTICATION_H_

#include <string>

bool authenticatePassPhrase(const std::string& filename, const std::string& passPhrase);

#endif
