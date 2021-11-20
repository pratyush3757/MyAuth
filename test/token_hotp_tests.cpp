#include "gtest/gtest.h"
#include "../src/token/include/token_hotp.h"

TEST(cryptoHotpRfcTests, rfcTestCase1) {
    
    std::string secretKey = "12345678901234567890";
    long long int counter = 0;
    int codeDigits = 6;
    std::string hashAlgorithm = "SHA1";
    
    EXPECT_EQ("755224",
              computeHotp(secretKey,counter=0,
                          codeDigits,
                          hashAlgorithm));
    
    EXPECT_EQ("287082",
              computeHotp(secretKey,counter=1,
                          codeDigits,
                          hashAlgorithm));
    
    EXPECT_EQ("359152",
              computeHotp(secretKey,counter=2,
                          codeDigits,
                          hashAlgorithm));
    
    EXPECT_EQ("969429",
              computeHotp(secretKey,counter=3,
                          codeDigits,
                          hashAlgorithm));
    
    EXPECT_EQ("338314",
              computeHotp(secretKey,counter=4,
                          codeDigits,
                          hashAlgorithm));
    
    EXPECT_EQ("254676",
              computeHotp(secretKey,counter=5,
                          codeDigits,
                          hashAlgorithm));
    
    EXPECT_EQ("287922",
              computeHotp(secretKey,counter=6,
                          codeDigits,
                          hashAlgorithm));
    
    EXPECT_EQ("162583",
              computeHotp(secretKey,counter=7,
                          codeDigits,
                          hashAlgorithm));
    
    EXPECT_EQ("399871",
              computeHotp(secretKey,counter=8,
                          codeDigits,
                          hashAlgorithm));
    
    EXPECT_EQ("520489",
              computeHotp(secretKey,counter=9,
                          codeDigits,
                          hashAlgorithm));
}
