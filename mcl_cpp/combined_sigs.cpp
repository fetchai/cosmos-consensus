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

static const std::string COMBINED_SIG_GENERATOR  = "Fetchai Combined Signature Generator";

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
std::string PubKeyFromPrivate(std::string const &private_key) {
    mcl::PrivateKey priv_key;
    bool ok = priv_key.FromString(private_key);
    if (!ok) {
        return "";
    }

    mcl::GroupPublicKey gen;
    mcl::SetGenerator(gen, COMBINED_SIG_GENERATOR);

    mcl::GroupPublicKey public_key;
    public_key.Mult(gen, priv_key);
    return public_key.ToString();
}

// Public key from private with proof of possesion, so in addition to public key it returns the signature 
// of the public key
std::pair<std::string, std::string> PubKeyFromPrivateWithPoP(std::string const &private_key) {
    mcl::PrivateKey priv_key;
    bool ok = priv_key.FromString(private_key);
    if (!ok) {
        return {"", ""};
    }

    mcl::GroupPublicKey gen;
    mcl::SetGenerator(gen, COMBINED_SIG_GENERATOR);

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

std::string CombinePublicKeys(std::vector<std::string> const &pub_keys) {
    mcl::GroupPublicKey pub_key;
    for (auto const &key : pub_keys) {
        mcl::GroupPublicKey val_key;
        bool ok_key = val_key.FromString(key);
        if (!ok_key) {
            return "";
        }
        pub_key.Add(pub_key, val_key);
    }
    return pub_key.ToString();
}

std::string CombineSignatures(std::vector<std::string> const &sigs) {
 mcl::Signature combined_sig;
    for (auto const &sig : sigs) {
        mcl::Signature val_sig;
        bool ok_sig = val_sig.FromString(sig);
        if (!ok_sig) {
            return "";
        }
        combined_sig.Add(combined_sig, val_sig);
    }
    return combined_sig.ToString();
}

bool PairingVerify(std::string const &message, std::string const &sign, std::string const &public_key) {
    mcl::Signature signature;
    mcl::GroupPublicKey pub_key;
    mcl::GroupPublicKey gen;
    bool ok_sign = signature.FromString(sign);
    bool ok_key = pub_key.FromString(public_key);
    if (!ok_sign || !ok_key) {
        return false;
    }
    mcl::SetGenerator(gen, COMBINED_SIG_GENERATOR);
    
    return mcl::PairingVerify(message, signature, pub_key, gen);
}

bool PairingVerifyCombinedSig(std::string const &message, std::string const &sign, std::vector<std::string> const &public_key) {
    mcl::Signature signature;
    mcl::GroupPublicKey pub_key;
    mcl::GroupPublicKey gen;
    bool ok_sign = signature.FromString(sign);
     if (!ok_sign) {
        return false;
    }
    for (auto const &key : public_key) {
        mcl::GroupPublicKey val_key;
        bool ok_key = val_key.FromString(key);
        if (!ok_key) {
            return false;
        }
        pub_key.Add(pub_key, val_key);
    }
    mcl::SetGenerator(gen, COMBINED_SIG_GENERATOR);
    
    return mcl::PairingVerify(message, signature, pub_key, gen);
}
} // beacon    
} // fetch
