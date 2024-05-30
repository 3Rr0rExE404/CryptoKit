#ifndef CRYPTOKIT_HPP
#define CRYPTOKIT_HPP

#include <string>
#include <iostream>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>

#include "Logger.hpp"
#include "Utils.hpp"

using namespace CryptoPP;

class CryptoKit
{
    private:
        ////config vars////
        const unsigned short                                    key_length = 4096; //(b)
        const unsigned short                                    key_pub_max = 382; //(plain strlen)
        const unsigned short                                    key_priv_max = 512; //(encrypted strlen)

        ////vars////
        Logger *log;
        RSA::PrivateKey key_priv;
        RSA::PublicKey key_pub;

        ////func////

    public:
        CryptoKit();
        ~CryptoKit();

        bool GenerateKeys();
        
        int8_t SavePublicKey(const std::string filename);
        int8_t SavePrivateKey(const std::string filename);
        int8_t LoadPublicKey(const std::string filename);
        int8_t LoadPrivateKey(const std::string filename);

        int8_t EncryptMessage(std::string source, std::string* destination);
        int8_t DecryptMessage(std::string source, std::string* destination);
        

        //first sign then encrypt
};

#endif
