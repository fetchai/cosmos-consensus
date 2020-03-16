#pragma once
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


#include "mcl/bn256.hpp"

#include <unordered_map>
#include <atomic>

namespace bn = mcl::bn256;

namespace fetch {
namespace crypto {
namespace mcl {

namespace details {
struct MCLInitialiser
{
  MCLInitialiser()
  {
    bool a = true;
    a = was_initialised.exchange(a);
    if (!a)
    {
      bn::initPairing();
    }
  }
  static std::atomic<bool> was_initialised;
};
}  // namespace details

class PrivateKey : public bn::Fr {
public:
  PrivateKey() {
    clear();
  }

  explicit PrivateKey(std::string const &pk) {
    clear();
    bool set = false;
    setStr(&set, pk.data());
    assert(set);
  }

  explicit PrivateKey(uint32_t value) {
    clear();
    bn::Fr::add(*this, *this, value);
  }
};

class Signature : public bn::G1 {
public:
  Signature() {
    clear();
  }

  explicit Signature(std::string const sig) {
    clear();
    bool set = false;
    setStr(&set, sig.data());
    assert(set);
  }
};

class Generator : public bn::G2 {
public:
  Generator() {
    clear();
  }

  explicit Generator(std::string const &string_to_hash) {
    clear();
    bn::hashAndMapToG2(*this, string_to_hash);
  }
};

class PublicKey : public bn::G2 {
public:
  PublicKey() {
    clear();
  }

  explicit PublicKey(std::string const &public_key) {
    clear();
    bool set = false;
    setStr(&set, public_key.data());
    assert(set);
  }

  PublicKey(Generator const &G, PrivateKey const &p) {
    bn::G2::mul(*this, G, p);
  }
};

Signature Sign(std::string const &message, PrivateKey x_i);
bool Verify(std::string const &message, Signature const &sign, PublicKey const &public_key, Generator const &G);
Signature LagrangeInterpolation(std::unordered_map < uint64_t, Signature >
const &shares);

struct DkgKeyInformation
{
  std::string              group_public_key;
  std::vector<std::string> public_key_shares;
  std::vector<std::string> private_key_shares;
  std::string              generator;
};

DkgKeyInformation TrustedDealerGenerateKeys(uint32_t cabinet_size, uint32_t threshold);

} //namespace mcl
} //namespace crypto
} //namespace fetch