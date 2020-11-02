//------------------------------------------------------------------------------
//
//   Copyright 2018-2020 Fetch.AI Limited
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.
//
//------------------------------------------------------------------------------

#include "combined_sigs.hpp"
#include "logging.hpp"
#include "mcl_crypto.hpp"

#include <iostream>

namespace fetch {
namespace beacon {

// Constructor for combined signature should set the string to the serialisation
// of the zero of signature element
CombinedSignature::CombinedSignature() {
    mcl::Signature sig;
    combined_signature_ = sig.ToString();
}

// Adds a signature to the saved combined signature string. Returns whether the signature
// was added or not.
bool CombinedSignature::Add(std::string const &signature) {
    // Get saved combined signature
    mcl::Signature sig;
    sig.FromString(combined_signature_);

    mcl::Signature sig_to_add;
    bool ok = sig_to_add.FromString(signature);
    if (!ok) {
        Log(LogLevel::ERROR, LOGGING_NAME, "Add can not deserialise signature "+signature);
        return false;
    }

    sig.Add(sig, sig_to_add);
    combined_signature_ = sig.ToString();
    return true;
}  

std::string CombinedSignature::Finish() const {
    return combined_signature_;
}

// Constructor for combined public key should set the string to the serialisation
// of the zero of public key element
CombinedPublicKey::CombinedPublicKey() {
    mcl::GroupPublicKey pub_key;
    combined_key_ = pub_key.ToString();
}

// Adds a signature to the saved combined public key string. Returns whether the public key
// was added or not.
bool CombinedPublicKey::Add(std::string const &public_key) {
    // Get saved combined public key
    mcl::GroupPublicKey pub_key;
    pub_key.FromString(combined_key_);

    mcl::GroupPublicKey pub_key_to_add;
    bool ok = pub_key_to_add.FromString(public_key);
    if (!ok) {
        Log(LogLevel::ERROR, LOGGING_NAME, "Add can not deserialise public key "+public_key);
        return false;
    }

    pub_key.Add(pub_key, pub_key_to_add);
    combined_key_ = pub_key.ToString();
    return true;
}  

std::string CombinedPublicKey::Finish() const {
    return combined_key_;
}
    
// GenPrivKey generates a new Bls12_381 private key
// It uses OS randomness to generate the private key.
std::string GenPrivKey() {
    mcl::PrivateKey new_key;
    new_key.Random();
    return new_key.ToString();
}

// GenPrivKeyBls hashes the secret with SHA2, and uses
// that 32 byte output to create the private key.
std::string GenPrivKeyBls(std::string const &secret) {
    mcl::PrivateKey new_key;
    new_key.setHashOf(secret);
    return new_key.ToString();
} 

// Public key from private key using specified string to hash into generator
std::string PubKeyFromPrivate(std::string const &private_key, std::string const &generator) {
    mcl::PrivateKey priv_key;
    bool ok = priv_key.FromString(private_key);
    if (!ok) {
        return "";
    }

    mcl::GroupPublicKey gen;
    mcl::SetGenerator(gen, generator);

    mcl::GroupPublicKey public_key;
    public_key.Mult(gen, priv_key);
    return public_key.ToString();
}

// Public key from private with proof of possesion, so in addition to public key it returns the signature 
// of the public key
std::pair<std::string, std::string> PubKeyFromPrivateWithPoP(std::string const &private_key, std::string const &generator) {
    mcl::PrivateKey priv_key;
    bool ok = priv_key.FromString(private_key);
    if (!ok) {
        return {"", ""};
    }

    mcl::GroupPublicKey gen;
    mcl::SetGenerator(gen, generator);

    mcl::GroupPublicKey public_key;
    public_key.Mult(gen, priv_key);
    
    mcl::Signature verify_key{mcl::Sign(public_key.ToString(), priv_key)};
    return {public_key.ToString(), verify_key.ToString()};
}

std::string Sign(std::string const &message, std::string const &private_key) {

    mcl::PrivateKey priv_key;
    bool ok = priv_key.FromString(private_key);
    if (!ok) {
        return "";
    }

    return mcl::Sign(message, priv_key).ToString();
}
bool PairingVerify(std::string const &message, std::string const &sign, std::string const &public_key, std::string const &generator) {
    mcl::Signature signature;
    mcl::GroupPublicKey pub_key;
    mcl::GroupPublicKey gen;
    bool ok_sign = signature.FromString(sign);
    bool ok_key = pub_key.FromString(public_key);
    if (!ok_sign || !ok_key) {
        return false;
    }
    mcl::SetGenerator(gen, generator);
    
    return mcl::PairingVerify(message, signature, pub_key, gen);
}
} // beacon    
} // fetch
