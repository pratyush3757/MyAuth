#include "gtest/gtest.h"
#include "../src/token/include/token_hotp.h"

TEST(cryptoHotpRfcTests, rfcTestCase1) {
    
    std::string hmacSecretKey = "12345678901234567890";
    long long int counter = 0;
    int codeDigits = 6;
    bool addChecksum = false;
    int truncationOffset = -1;
    std::string hashAlgorithm = "SHA1";
    
    EXPECT_EQ("755224",
              computeHotp(hmacSecretKey,counter=0,
                          codeDigits,
                          false /*addChecksum*/,
                          -1 /*truncationOffset*/, "SHA1" /*hashAlgorithm*/));
    
    EXPECT_EQ("287082",
              computeHotp(hmacSecretKey,counter=1,
                          codeDigits,
                          false /*addChecksum*/,
                          -1 /*truncationOffset*/, "SHA1" /*hashAlgorithm*/));
    
    EXPECT_EQ("359152",
              computeHotp(hmacSecretKey,counter=2,
                          codeDigits,
                          false /*addChecksum*/,
                          -1 /*truncationOffset*/, "SHA1" /*hashAlgorithm*/));
    
    EXPECT_EQ("969429",
              computeHotp(hmacSecretKey,counter=3,
                          codeDigits,
                          false /*addChecksum*/,
                          -1 /*truncationOffset*/, "SHA1" /*hashAlgorithm*/));
    
    EXPECT_EQ("338314",
              computeHotp(hmacSecretKey,counter=4,
                          codeDigits,
                          false /*addChecksum*/,
                          -1 /*truncationOffset*/, "SHA1" /*hashAlgorithm*/));
    
    EXPECT_EQ("254676",
              computeHotp(hmacSecretKey,counter=5,
                          codeDigits,
                          false /*addChecksum*/,
                          -1 /*truncationOffset*/, "SHA1" /*hashAlgorithm*/));
    
    EXPECT_EQ("287922",
              computeHotp(hmacSecretKey,counter=6,
                          codeDigits,
                          false /*addChecksum*/,
                          -1 /*truncationOffset*/, "SHA1" /*hashAlgorithm*/));
    
    EXPECT_EQ("162583",
              computeHotp(hmacSecretKey,counter=7,
                          codeDigits,
                          false /*addChecksum*/,
                          -1 /*truncationOffset*/, "SHA1" /*hashAlgorithm*/));
    
    EXPECT_EQ("399871",
              computeHotp(hmacSecretKey,counter=8,
                          codeDigits,
                          false /*addChecksum*/,
                          -1 /*truncationOffset*/, "SHA1" /*hashAlgorithm*/));
    
    EXPECT_EQ("520489",
              computeHotp(hmacSecretKey,counter=9,
                          codeDigits,
                          false /*addChecksum*/,
                          -1 /*truncationOffset*/, "SHA1" /*hashAlgorithm*/));
}
