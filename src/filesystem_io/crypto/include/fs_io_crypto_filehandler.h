#ifndef _FS_IO_CRYPTO_FILEHANDLER_
#define _FS_IO_CRYPTO_FILEHANDLER_

void EncryptFile(const char *in, const char *out, const char *passPhrase);

void DecryptFile(const char *in, const char *out, const char *passPhrase);

#endif
