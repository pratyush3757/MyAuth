#include "gtest/gtest.h"
#include "../src/token/src/token_totp.h"

TEST(cryptoTotpRfcTests, rfcTestCaseSHA1) {
    
    std::string secretKey = "12345678901234567890";
    long long int time = 0;
    int codeDigits = 8;
    std::string hashAlgorithm = "SHA1";
    int period = 30;
    
    EXPECT_EQ("94287082",
              computeTotp(secretKey, time=59, 
                          codeDigits, hashAlgorithm, period));
    
    EXPECT_EQ("07081804",
              computeTotp(secretKey, time=1111111109, 
                          codeDigits, hashAlgorithm, period));
    
    EXPECT_EQ("14050471",
              computeTotp(secretKey, time=1111111111, 
                          codeDigits, hashAlgorithm, period));
    
    EXPECT_EQ("89005924",
              computeTotp(secretKey, time=1234567890, 
                          codeDigits, hashAlgorithm, period));
    
    EXPECT_EQ("69279037",
              computeTotp(secretKey, time=2000000000, 
                          codeDigits, hashAlgorithm, period));
    
    EXPECT_EQ("65353130",
              computeTotp(secretKey, time=20000000000, 
                          codeDigits, hashAlgorithm, period));
}

TEST(cryptoTotpRfcTests, rfcTestCaseSHA256) {
    
    std::string secretKey = "12345678901234567890"
                            "123456789012";
    long long int time = 0;
    int codeDigits = 8;
    std::string hashAlgorithm = "SHA256";
    int period = 30;
    
    EXPECT_EQ("46119246",
              computeTotp(secretKey, time=59, 
                          codeDigits, hashAlgorithm, period));
    
    EXPECT_EQ("68084774",
              computeTotp(secretKey, time=1111111109, 
                          codeDigits, hashAlgorithm, period));
    
    EXPECT_EQ("67062674",
              computeTotp(secretKey, time=1111111111, 
                          codeDigits, hashAlgorithm, period));
    
    EXPECT_EQ("91819424",
              computeTotp(secretKey, time=1234567890, 
                          codeDigits, hashAlgorithm, period));
    
    EXPECT_EQ("90698825",
              computeTotp(secretKey, time=2000000000, 
                          codeDigits, hashAlgorithm, period));
    
    EXPECT_EQ("77737706",
              computeTotp(secretKey, time=20000000000, 
                          codeDigits, hashAlgorithm, period));
}

TEST(cryptoTotpRfcTests, rfcTestCaseSHA512) {
    
    std::string secretKey = "12345678901234567890"
                            "12345678901234567890"
                            "12345678901234567890"
                            "1234";
    long long int time = 0;
    int codeDigits = 8;
    std::string hashAlgorithm = "SHA512";
    int period = 30;
    
    EXPECT_EQ("90693936",
              computeTotp(secretKey, time=59, 
                          codeDigits, hashAlgorithm, period));
    
    EXPECT_EQ("25091201",
              computeTotp(secretKey, time=1111111109, 
                          codeDigits, hashAlgorithm, period));
    
    EXPECT_EQ("99943326",
              computeTotp(secretKey, time=1111111111, 
                          codeDigits, hashAlgorithm, period));
    
    EXPECT_EQ("93441116",
              computeTotp(secretKey, time=1234567890, 
                          codeDigits, hashAlgorithm, period));
    
    EXPECT_EQ("38618901",
              computeTotp(secretKey, time=2000000000, 
                          codeDigits, hashAlgorithm, period));
    
    EXPECT_EQ("47863826",
              computeTotp(secretKey, time=20000000000, 
                          codeDigits, hashAlgorithm, period));
}
