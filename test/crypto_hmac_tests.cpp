#include "gtest/gtest.h"
#include "../src/crypto/include/crypto_hmac.h"

TEST(cryptoHmacRfcTests, rfcTestCase1) {
    
    std::string hmacSecretKey;
    std::string hexEncodedMessage;
    std::string hashAlgorithm;

    hmacSecretKey = "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
                    "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"; /*0x0b repeated 16 times*/
    hexEncodedMessage = "4869205468657265"; /*Hi There*/
    
    EXPECT_EQ("9294727a3638bb1c13f48ef8158bfc9d",
              computeHmacForGivenAlgorithm(hmacSecretKey,
                                           hexEncodedMessage,
                                           hashAlgorithm = "MD5"));

    hmacSecretKey = "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
                    "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
                    "\x0b\x0b\x0b\x0b"; /*0x0b repeated 20 times*/
    
    EXPECT_EQ("b617318655057264e28bc0b6fb378c8ef146be00",
              computeHmacForGivenAlgorithm(hmacSecretKey,
                                           hexEncodedMessage,
                                           hashAlgorithm = "SHA1"));
    
    EXPECT_EQ("b0344c61d8db38535ca8afceaf0bf12b"
              "881dc200c9833da726e9376c2e32cff7",
              computeHmacForGivenAlgorithm(hmacSecretKey,
                                           hexEncodedMessage,
                                           hashAlgorithm = "SHA256"));
    
    EXPECT_EQ("87aa7cdea5ef619d4ff0b4241a1d6cb0"
              "2379f4e2ce4ec2787ad0b30545e17cde"
              "daa833b7d6b8a702038b274eaea3f4e4"
              "be9d914eeb61f1702e696c203a126854",
              computeHmacForGivenAlgorithm(hmacSecretKey,
                                           hexEncodedMessage,
                                           hashAlgorithm = "SHA512"));

}

//     Test with a key shorter than the length of the HMAC output
TEST(cryptoHmacRfcTests, rfcTestCase2) {
    
    std::string hmacSecretKey;
    std::string hexEncodedMessage;
    std::string hashAlgorithm;

    hmacSecretKey = "Jefe";
    hexEncodedMessage = "7768617420646f2079612077616e7420"
                        "666f72206e6f7468696e673f"; /*what do ya want for nothing?*/
    
    EXPECT_EQ("750c783e6ab0b503eaa86e310a5db738",
              computeHmacForGivenAlgorithm(hmacSecretKey,
                                           hexEncodedMessage,
                                           hashAlgorithm = "MD5"));

    EXPECT_EQ("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79",
              computeHmacForGivenAlgorithm(hmacSecretKey,
                                           hexEncodedMessage,
                                           hashAlgorithm = "SHA1"));
    
    EXPECT_EQ("5bdcc146bf60754e6a042426089575c7"
              "5a003f089d2739839dec58b964ec3843",
              computeHmacForGivenAlgorithm(hmacSecretKey,
                                           hexEncodedMessage,
                                           hashAlgorithm = "SHA256"));
    
    EXPECT_EQ("164b7a7bfcf819e2e395fbe73b56e0a3"
              "87bd64222e831fd610270cd7ea250554"
              "9758bf75c05a994a6d034f65f8f0e6fd"
              "caeab1a34d4a6b4b636e070a38bce737",
              computeHmacForGivenAlgorithm(hmacSecretKey,
                                           hexEncodedMessage,
                                           hashAlgorithm = "SHA512"));

}

// Test with a combined length of key and data that is larger than 64
// bytes (= block-size of SHA-224 and SHA-256).
TEST(cryptoHmacRfcTests, rfcTestCase3) {
    
    std::string hmacSecretKey;
    std::string hexEncodedMessage;
    std::string hashAlgorithm;

    hmacSecretKey = "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                    "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"; /*0xaa repeated 16 times*/
    hexEncodedMessage = "dddddddddddddddddddddddddddddddd"
                        "dddddddddddddddddddddddddddddddd"
                        "dddddddddddddddddddddddddddddddd"
                        "dddd"; /*0xdd repeated 50 times*/
    
    EXPECT_EQ("56be34521d144c88dbb8c733f0e8b3f6",
              computeHmacForGivenAlgorithm(hmacSecretKey,
                                           hexEncodedMessage,
                                           hashAlgorithm = "MD5"));

    hmacSecretKey = "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                    "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                    "\xaa\xaa\xaa\xaa"; /*0xaa repeated 20 times*/
    
    EXPECT_EQ("125d7342b9ac11cd91a39af48aa17b4f63f175d3",
              computeHmacForGivenAlgorithm(hmacSecretKey,
                                           hexEncodedMessage,
                                           hashAlgorithm = "SHA1"));
    
    EXPECT_EQ("773ea91e36800e46854db8ebd09181a7"
              "2959098b3ef8c122d9635514ced565fe",
              computeHmacForGivenAlgorithm(hmacSecretKey,
                                           hexEncodedMessage,
                                           hashAlgorithm = "SHA256"));
    
    EXPECT_EQ("fa73b0089d56a284efb0f0756c890be9"
              "b1b5dbdd8ee81a3655f83e33b2279d39"
              "bf3e848279a722c806b485a47e67c807"
              "b946a337bee8942674278859e13292fb",
              computeHmacForGivenAlgorithm(hmacSecretKey,
                                           hexEncodedMessage,
                                           hashAlgorithm = "SHA512"));

}

// Test with a combined length of key and data that is larger than 64
// bytes (= block-size of SHA-224 and SHA-256).
TEST(cryptoHmacRfcTests, rfcTestCase4) {
    
    std::string hmacSecretKey;
    std::string hexEncodedMessage;
    std::string hashAlgorithm;

    hmacSecretKey = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
                    "\x11\x12\x13\x14\x15\x16\x17\x18\x19"; /*25 bytes*/
    hexEncodedMessage = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
                        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
                        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
                        "cdcd"; /*0xcd repeated 50 times*/
    
    EXPECT_EQ("697eaf0aca3a3aea3a75164746ffaa79",
              computeHmacForGivenAlgorithm(hmacSecretKey,
                                           hexEncodedMessage,
                                           hashAlgorithm = "MD5"));

    EXPECT_EQ("4c9007f4026250c6bc8414f9bf50c86c2d7235da",
              computeHmacForGivenAlgorithm(hmacSecretKey,
                                           hexEncodedMessage,
                                           hashAlgorithm = "SHA1"));
    
    EXPECT_EQ("82558a389a443c0ea4cc819899f2083a"
              "85f0faa3e578f8077a2e3ff46729665b",
              computeHmacForGivenAlgorithm(hmacSecretKey,
                                           hexEncodedMessage,
                                           hashAlgorithm = "SHA256"));
    
    EXPECT_EQ("b0ba465637458c6990e5a8c5f61d4af7"
              "e576d97ff94b872de76f8050361ee3db"
              "a91ca5c11aa25eb4d679275cc5788063"
              "a5f19741120c4f2de2adebeb10a298dd",
              computeHmacForGivenAlgorithm(hmacSecretKey,
                                           hexEncodedMessage,
                                           hashAlgorithm = "SHA512"));

}

// Test with a truncation of output to 128 bits.
TEST(cryptoHmacRfcTests, rfcTestCase5) {
    
    std::string hmacSecretKey;
    std::string hexEncodedMessage;
    std::string hashAlgorithm;

    hmacSecretKey = "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c"
                    "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c"; /*0x0c repeated 16 times*/
    hexEncodedMessage = "546573742057697468205472756e6361"
                        "74696f6e"; /*Test With Truncation*/
    
    EXPECT_EQ("56461ef2342edc00f9bab995",  // Only Digest-96 specified by RFC
              computeHmacForGivenAlgorithm(hmacSecretKey,
                                           hexEncodedMessage,
                                           hashAlgorithm = "MD5").substr(0,24));

    hmacSecretKey = "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c"
                    "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c"
                    "\x0c\x0c\x0c\x0c"; /*0x0c repeated 20 times*/
    
    EXPECT_EQ("4c1a03424b55e07fe7f27be1", // Only Digest-96 specified by RFC
              computeHmacForGivenAlgorithm(hmacSecretKey,
                                           hexEncodedMessage,
                                           hashAlgorithm = "SHA1").substr(0,24));
    
    EXPECT_EQ("a3b6167473100ee06e0c796c2955552b",
              computeHmacForGivenAlgorithm(hmacSecretKey,
                                           hexEncodedMessage,
                                           hashAlgorithm = "SHA256").substr(0,32));
    
    EXPECT_EQ("415fad6271580a531d4179bc891d87a6",
              computeHmacForGivenAlgorithm(hmacSecretKey,
                                           hexEncodedMessage,
                                           hashAlgorithm = "SHA512").substr(0,32));

}

// Test with a key larger than 128 bytes (= block-size of SHA-384 and
// SHA-512).
TEST(cryptoHmacRfcTests, rfcTestCase6) {
    
    std::string hmacSecretKey;
    std::string hexEncodedMessage;
    std::string hashAlgorithm;

    hmacSecretKey = "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                    "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                    "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                    "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                    "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                    "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                    "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                    "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                    "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                    "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"; /*0xaa repeated 80 times*/
    hexEncodedMessage = "54657374205573696e67204c61726765"
                        "72205468616e20426c6f636b2d53697a"
                        "65204b6579202d2048617368204b6579"
                        "204669727374"; 
                        /*Test Using Larger Than Block-Size Key - Hash Key First*/
    
    EXPECT_EQ("6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd",
              computeHmacForGivenAlgorithm(hmacSecretKey,
                                           hexEncodedMessage,
                                           hashAlgorithm = "MD5"));

    EXPECT_EQ("aa4ae5e15272d00e95705637ce8a3b55ed402112",
              computeHmacForGivenAlgorithm(hmacSecretKey,
                                           hexEncodedMessage,
                                           hashAlgorithm = "SHA1"));
    
    hmacSecretKey = "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                    "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                    "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                    "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                    "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                    "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                    "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                    "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                    "\xaa\xaa\xaa"; /*0xaa repeated 131 times, 131 bytes*/
    
    EXPECT_EQ("60e431591ee0b67f0d8a26aacbf5b77f"
              "8e0bc6213728c5140546040f0ee37f54",
              computeHmacForGivenAlgorithm(hmacSecretKey,
                                           hexEncodedMessage,
                                           hashAlgorithm = "SHA256"));
    
    EXPECT_EQ("80b24263c7c1a3ebb71493c1dd7be8b4"
              "9b46d1f41b4aeec1121b013783f8f352"
              "6b56d037e05f2598bd0fd2215d6a1e52"
              "95e64f73f63f0aec8b915a985d786598",
              computeHmacForGivenAlgorithm(hmacSecretKey,
                                           hexEncodedMessage,
                                           hashAlgorithm = "SHA512"));

}

// Test with a key larger than 128 bytes (= block-size of SHA-384 and
// SHA-512).
TEST(cryptoHmacRfcTests, rfcTestCase7) {
    
    std::string hmacSecretKey;
    std::string hexEncodedMessage;
    std::string hashAlgorithm;

    hmacSecretKey = "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                    "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                    "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                    "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                    "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                    "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                    "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                    "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                    "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                    "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"; /*0xaa repeated 80 times*/
    hexEncodedMessage = "54657374205573696e67204c61726765"
                        "72205468616e20426c6f636b2d53697a"
                        "65204b657920616e64204c6172676572"
                        "205468616e204f6e6520426c6f636b2d"
                        "53697a652044617461";
    /*Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data*/
    
    EXPECT_EQ("6f630fad67cda0ee1fb1f562db3aa53e",
              computeHmacForGivenAlgorithm(hmacSecretKey,
                                           hexEncodedMessage,
                                           hashAlgorithm = "MD5"));

    EXPECT_EQ("e8e99d0f45237d786d6bbaa7965c7808bbff1a91",
              computeHmacForGivenAlgorithm(hmacSecretKey,
                                           hexEncodedMessage,
                                           hashAlgorithm = "SHA1"));
    
    hmacSecretKey = "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                    "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                    "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                    "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                    "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                    "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                    "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                    "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                    "\xaa\xaa\xaa"; /*0xaa repeated 131 times, 131 bytes*/
    hexEncodedMessage = "54686973206973206120746573742075"
                        "73696e672061206c6172676572207468"
                        "616e20626c6f636b2d73697a65206b65"
                        "7920616e642061206c61726765722074"
                        "68616e20626c6f636b2d73697a652064"
                        "6174612e20546865206b6579206e6565"
                        "647320746f2062652068617368656420"
                        "6265666f7265206265696e6720757365"
                        "642062792074686520484d414320616c"
                        "676f726974686d2e"; 
    /*"This is a test using a larger than block-size key and a larger than block-size data. "
      "The key needs to be hashed before being used by the HMAC algorithm."*/                    
    
    EXPECT_EQ("9b09ffa71b942fcb27635fbcd5b0e944"
              "bfdc63644f0713938a7f51535c3a35e2",
              computeHmacForGivenAlgorithm(hmacSecretKey,
                                           hexEncodedMessage,
                                           hashAlgorithm = "SHA256"));
    
    EXPECT_EQ("e37b6a775dc87dbaa4dfa9f96e5e3ffd"
              "debd71f8867289865df5a32d20cdc944"
              "b6022cac3c4982b10d5eeb55c3e4de15"
              "134676fb6de0446065c97440fa8c6a58",
              computeHmacForGivenAlgorithm(hmacSecretKey,
                                           hexEncodedMessage,
                                           hashAlgorithm = "SHA512"));

}
