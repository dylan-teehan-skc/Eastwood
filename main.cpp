#include <iostream>
#include <string>

// Crypto++ includes
#include <cryptopp/cryptlib.h>
#include <cryptopp/hkdf.h>
#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>

#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>
#include <cryptopp/xed25519.h>

using namespace std;
using namespace CryptoPP;

void generateKeyPair() {
    AutoSeededRandomPool rng;
    x25519 curve;
    
    SecByteBlock privateKey(curve.PrivateKeyLength());
    SecByteBlock publicKey(curve.PublicKeyLength());
    
    curve.GenerateKeyPair(rng, privateKey, publicKey);
    
    string privateKeyHex, publicKeyHex;
    
    HexEncoder privEncoder(new StringSink(privateKeyHex));
    privEncoder.Put(privateKey, privateKey.size());
    privEncoder.MessageEnd();
    
    HexEncoder pubEncoder(new StringSink(publicKeyHex));
    pubEncoder.Put(publicKey, publicKey.size());
    pubEncoder.MessageEnd();
    
    cout << "X25519 Private Key: " << privateKeyHex << endl;
    cout << "X25519 Public Key: " << publicKeyHex << endl;
}

int main(int argc, char *argv[]) {
    CryptoPP::byte password[] = "password";
    size_t plen = strlen((const char*)password);

    CryptoPP::byte salt[] = "salt";
    size_t slen = strlen((const char*)salt);

    CryptoPP::byte info[] = "HKDF key deriv";
    size_t ilen = strlen((const char*)info);

    CryptoPP::byte derived[CryptoPP::SHA1::DIGESTSIZE];

    HKDF<SHA1> hkdf;
    hkdf.DeriveKey(derived, sizeof(derived), password, plen, salt, slen, info, ilen);

    string result;
    HexEncoder encoder(new StringSink(result));

    encoder.Put(derived, sizeof(derived));
    encoder.MessageEnd();
    
    cout << "HKDF Result: " << result << endl;

    generateKeyPair();

    return 0;
}