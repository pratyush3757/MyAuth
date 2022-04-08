#ifndef _FS_IO_CRYPTO_IMPORT_H_
#define _FS_IO_CRYPTO_IMPORT_H_

#include <string>

void importFile(const std::string& clearFile, 
                const std::string& encryptedFile, 
                const std::string& passPhrase);

bool importRawFile(const std::string& clearFile,
                   const std::string& encryptedFile,
                   const std::string& passPhrase);

#endif
