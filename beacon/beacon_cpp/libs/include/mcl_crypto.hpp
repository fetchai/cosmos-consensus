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

#include <atomic>
#include <unordered_map>

namespace bn = mcl::bn256;

namespace fetch {
namespace beacon {

using CabinetIndex = uint32_t;

namespace mcl {

namespace details {
struct MCLInitialiser
{
  MCLInitialiser()
  {
    bool a{true};
    a = was_initialised.exchange(a);
    if (!a)
    {
      bn::initPairing();
    }
  }
  static std::atomic<bool> was_initialised;
};
}  // namespace details

class PrivateKey : public bn::Fr
{
public:
  PrivateKey()
  {
    clear();
  }

  explicit PrivateKey(std::string const &pk)
  {
    FromString(pk);
  }

  explicit PrivateKey(CabinetIndex value)
  {
    clear();
    bn::Fr::add(*this, *this, value);
  }
  std::string ToString() const
  {
    return getStr();
  }
  bool FromString(std::string const &pk)
  {
    clear();
    bool set{false};
    setStr(&set, pk.data());
    return set;
  }
};

class Signature : public bn::G1
{
public:
  Signature()
  {
    clear();
  }

  explicit Signature(std::string const sig)
  {
    FromString(sig);
  }
  std::string ToString() const
  {
    return getStr();
  }
  void FromString(std::string const &sig)
  {
    clear();
    bool set{false};
    setStr(&set, sig.data());
  }
};

class Generator : public bn::G2
{
public:
  Generator()
  {
    clear();
  }

  explicit Generator(std::string const &generator)
  {
    FromString(generator);
  }
  std::string ToString() const
  {
    return getStr();
  }
  bool FromString(std::string const &gen)
  {
    clear();
    bool set{false};
    setStr(&set, gen.data());
    return set;
  }
};

class PublicKey : public bn::G2
{
public:
  PublicKey()
  {
    clear();
  }

  explicit PublicKey(std::string const &public_key)
  {
    FromString(public_key);
  }

  PublicKey(Generator const &G, PrivateKey const &p)
  {
    clear();
    bn::G2::mul(*this, G, p);
  }
  std::string ToString() const
  {
    return getStr();
  }
  bool FromString(std::string const &pk)
  {
    clear();
    bool set{false};
    setStr(&set, pk.data());
    return set;
  }
};

Signature Sign(std::string const &message, PrivateKey x_i);
bool      Verify(std::string const &message, Signature const &sign, PublicKey const &public_key,
                 Generator const &G);
Signature LagrangeInterpolation(std::unordered_map<CabinetIndex, Signature> const &shares);

struct DkgKeyInformation
{
  std::string              group_public_key;
  std::vector<std::string> public_key_shares;
  std::vector<std::string> private_key_shares;
  std::string              generator;
};

DkgKeyInformation TrustedDealerGenerateKeys(CabinetIndex cabinet_size, CabinetIndex threshold);

/**
 * Helper functions for computations used in the DKG
 */
/**
 * Vector initialisation for pointers to mcl data structures
 *
 * @tparam T Type in vector
 * @param data Vector to be initialised
 * @param i Number of columns
 */
template <typename T>
void Init(std::vector<T> &data, CabinetIndex i)
{
  data.resize(i);
}

/**
 * Matrix initialisation for pointers to mcl data structures
 *
 * @tparam T Type in matrix
 * @param data Matrix to be initialised
 * @param i Number of rows
 * @param j Number of columns
 */
template <typename T>
void Init(std::vector<std::vector<T>> &data, CabinetIndex i, CabinetIndex j)
{
  data.resize(i);
  for (auto &data_i : data)
  {
    data_i.resize(j);
  }
}
void      SetGenerator(Generator &        generator_g,
                       std::string const &string_to_hash = "Fetch.ai Elliptic Curve Generator G");
void      SetGenerators(Generator &generator_g, Generator &generator_h,
                        std::string const &string_to_hash  = "Fetch.ai Elliptic Curve Generator G",
                        std::string const &string_to_hash2 = "Fetch.ai Elliptic Curve Generator H");
PublicKey ComputeLHS(PublicKey &tmpG, Generator const &G, Generator const &H,
                     PrivateKey const &share1, PrivateKey const &share2);
PublicKey ComputeLHS(Generator const &G, Generator const &H, PrivateKey const &share1,
                     PrivateKey const &share2);
void      UpdateRHS(CabinetIndex rank, PublicKey &rhsG, std::vector<PublicKey> const &input);
PublicKey ComputeRHS(CabinetIndex rank, std::vector<PublicKey> const &input);
void      ComputeShares(PrivateKey &s_i, PrivateKey &sprime_i, std::vector<PrivateKey> const &a_i,
                        std::vector<PrivateKey> const &b_i, CabinetIndex index);
std::vector<PrivateKey> InterpolatePolynom(std::vector<PrivateKey> const &a,
                                           std::vector<PrivateKey> const &b);

}  // namespace mcl
}  // namespace beacon
}  // namespace fetch
