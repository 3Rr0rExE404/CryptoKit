#include "CryptoKit.hpp"

CryptoKit::CryptoKit()
{
    log = new Logger("CryptoKit");
}

CryptoKit::~CryptoKit()
{

}

bool CryptoKit::GenerateKeys()
{
    try
    {
        log->info("Generating keypair...");
        AutoSeededRandomPool rng;
        InvertibleRSAFunction params;
        params.GenerateRandomWithKeySize(rng, key_length);
        key_priv = RSA::PrivateKey(params);
        key_pub = RSA::PublicKey(params);
        log->info("Success!");
        return true;
    }
    catch(const std::exception& e)
    {
        log->err("GenerateKeys() failed! " + tostr(e.what()));
        return false;
    }
            
}

int8_t CryptoKit::SavePublicKey(const std::string filename)
{
    try
    {
        ByteQueue queue;
        key_pub.DEREncodePublicKey(queue);
        FileSink file(filename.c_str());
        queue.CopyTo(file);
        file.MessageEnd();
        
        log->info("Public key exported successfully.");
        return 0;
    }
    catch(const std::exception& e)
    {
        log->err("An error occured while exporting public key!");
        return -1;
    }
}

int8_t CryptoKit::SavePrivateKey(const std::string filename)
{
    try
    {
        ByteQueue queue;
        key_priv.DEREncodePrivateKey(queue);
        FileSink file(filename.c_str());
        queue.CopyTo(file);
        file.MessageEnd();

        log->info("Private key exported successfully.");
        return 0;
    }
    catch(const std::exception& e)
    {
        log->err("An error occured while exporting private key!");
        return -1;
    }
}

int8_t CryptoKit::LoadPublicKey(const std::string filename)
{
    try
    {
        ByteQueue queue;
        FileSource file(filename.c_str(), true);
        file.TransferTo(queue);
	    queue.MessageEnd();
        key_pub.BERDecodePublicKey(queue, false, queue.MaxRetrievable());

        log->info("Public key imported successfully.");

        return 0;
    }
    catch(const std::exception& e)
    {
        log->err("An error occured while importing public key!");
        return -1;
    }
    
}

int8_t CryptoKit::LoadPrivateKey(const std::string filename)
{
    try
    {
        ByteQueue queue;
        FileSource file(filename.c_str(), true);
        file.TransferTo(queue);
	    queue.MessageEnd();
        key_priv.BERDecodePrivateKey(queue, false, queue.MaxRetrievable());

        log->info("Private key imported successfully.");

        return 0;
    }
    catch(const std::exception& e)
    {
        log->err("An error occured while importing public key!");
        return -1;
    }
    
}

int8_t CryptoKit::EncryptMessage(std::string plain, std::string* cipher)
{
    try
    {
        //string cipher;
        AutoSeededRandomPool rng;
        //RSAES_OAEP_SHA_Encryptor e(key_pub);
        RSAES<OAEP<SHA512>>::Encryptor e(key_pub);
        //key_pub_max = e.FixedMaxPlaintextLength();
        //cout << "Max enc input: " << e.FixedMaxPlaintextLength() << endl;

        StringSource ss1(plain, true,
            new PK_EncryptorFilter(rng, e,
            new StringSink(*cipher)));
        //return cipher;
        return 0;
    }
    catch(const std::exception& e)
    {
        log->err("EncryptMessage() failed! " + tostr(e.what()));
        return -1;
    }         
}

int8_t CryptoKit::DecryptMessage(std::string cipher, std::string* plain)
{
    try
    {
        //string plain;
        AutoSeededRandomPool rng;
        //RSAES_OAEP_SHA_Decryptor d(key_priv);
        RSAES<OAEP<SHA512>>::Decryptor d(key_priv);
        //key_priv_max = d.FixedCiphertextLength();
        //cout << "Max dec input: " << d.FixedCiphertextLength() << endl;

        StringSource ss2(cipher, true,
            new PK_DecryptorFilter(rng, d,
            new StringSink(*plain)));
        //return plain;
        return 0;
    }
    catch(const std::exception& e)
    {
        log->err("DecryptMessage() failed! " + tostr(e.what()));
        return -1;
    }
}

