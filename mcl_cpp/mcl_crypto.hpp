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

#include <mcl/bls12_381.hpp>

#include <atomic>
#include <unordered_map>
#include "serialisers.hpp"

namespace bn = mcl::bls12;

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
      ::mcl::fp::Mode g_mode;
      bn::initPairing(::mcl::BLS12_381, g_mode);
    }
  }
  static std::atomic<bool> was_initialised;
};
}  // namespace details

class Signature;

class PrivateKey : public bn::Fr {
public:
  PrivateKey();
  PrivateKey(uint32_t num);

  void Random();
  void Increment();
  std::string ToString() const;
  bool FromString(const std::string &s);
  void SetZero();
  void Add(const PrivateKey &left, const PrivateKey &right);
  void Sub(const PrivateKey &left, const PrivateKey &right);
  void Mult(const PrivateKey &left, const PrivateKey &right);
  void Inv(const PrivateKey &inv);
  void Negate(const PrivateKey &neg);
  void Pow(const PrivateKey &left, uint32_t pow);
  void Div(const PrivateKey &left, const PrivateKey &right);

  // For ZKP
  void SetHashOf(const Signature &generator, const Signature &Hm, const Signature &publicKey, const Signature &sig,
                const Signature &com1, const Signature &com2);
  };

class Signature : public bn::G1 {
public:
  Signature();

  void SetZero();
  bool FromString(const std::string &s);
  void Mult(const Signature &left, const PrivateKey &right);
  void Add(const Signature &left, const Signature &right);
  void HashAndMap(const std::string &payload);
  std::string ToString() const;
};

class GroupPublicKey : public bn::G2 {
public:
  GroupPublicKey();

  void SetZero();
  bool FromString(const std::string &s);
  void Mult(const GroupPublicKey &left, const PrivateKey &right);
  void Add(const GroupPublicKey &left, const GroupPublicKey &right);
  void HashAndMap(const std::string &payload);
  std::string ToString() const;
};

/// Class for computing pairings
/// @{
class Pairing : public bn::Fp12 {
public:
  Pairing();

  void Map(const Signature &g1, const GroupPublicKey &g2);
};
/// @}

/// Class for ZKP
/// @{
class Proof : public std::pair<PrivateKey, PrivateKey> {
public:
  Proof() = default;

  std::pair<std::string, std::string> ToString() const;
  bool FromString(const std::pair<std::string, std::string> &s);
};
/// @}

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


template<class Generator>
static void SetGenerator(Generator &generator_g,
                       std::string const &string_to_hash = "Fetch.ai Elliptic Curve Generator G") {
  assert(!string_to_hash.empty());
  generator_g.SetZero();
  generator_g.HashAndMap(string_to_hash + std::string(typeid(generator_g).name()));
}

template<class Generator>
static void SetGenerators(Generator &generator_g, Generator &generator_h,
                        std::string const &string_to_hash  = "Fetch.ai Elliptic Curve Generator G",
                        std::string const &string_to_hash2 = "Fetch.ai Elliptic Curve Generator H") {
  SetGenerator(generator_g, string_to_hash);
  SetGenerator(generator_h, string_to_hash2);
}


Signature Sign(std::string const &message, PrivateKey x_i);
bool PairingVerify(const std::string &message, const mcl::Signature &sign, const mcl::GroupPublicKey &y, const mcl::GroupPublicKey &G);
Proof ComputeProof(const Signature &G, const std::string &message, const Signature &y, const Signature &sig, const PrivateKey &x);
bool VerifyProof(const Signature &y, const std::string &message, const Signature &sign, const Signature &G, const Proof &proof);
Signature LagrangeInterpolation(std::unordered_map<CabinetIndex, Signature> const &shares);
void ComputeShares(PrivateKey &s_i, PrivateKey &sprime_i, std::vector<PrivateKey> const &a_i,
                        std::vector<PrivateKey> const &b_i, CabinetIndex index);
std::vector<PrivateKey> InterpolatePolynom(std::vector<PrivateKey> const &a,
                                           std::vector<PrivateKey> const &b);

template<class VerificationKey>
VerificationKey ComputeLHS(VerificationKey &tmpG, VerificationKey const &G, VerificationKey const &H,
                     PrivateKey const &share1, PrivateKey const &share2)
{
  VerificationKey tmp2G, lhsG;
  tmpG.Mult(G, share1);
  tmp2G.Mult(H, share2);
  lhsG.Add(tmpG, tmp2G);

  return lhsG;
}

template<class VerificationKey>
VerificationKey ComputeLHS(VerificationKey const &G, VerificationKey const &H, PrivateKey const &share1,
                     PrivateKey const &share2)
{
  VerificationKey tmpG;
  return ComputeLHS(tmpG, G, H, share1, share2);
}

template<class VerificationKey>
void UpdateRHS(CabinetIndex rank, VerificationKey &rhsG, std::vector<VerificationKey> const &input)
{
  PrivateKey tmpF{uint32_t(rank + 1)};
  PrivateKey crypto_rank{uint32_t(rank + 1)};
  VerificationKey tmpG;
  assert(input.size() > 0);
  for (size_t k = 1; k < input.size(); k++) {
    tmpG.Mult(input[k], tmpF);
    rhsG.Add(rhsG, tmpG);
    tmpF.Mult(tmpF, crypto_rank); // adjust index $i$ in computation
  }
}

template<class VerificationKey>
VerificationKey ComputeRHS(CabinetIndex rank, std::vector<VerificationKey> const &input) 
{
  VerificationKey rhsG{input[0]};
  assert(!input.empty());
  UpdateRHS(rank, rhsG, input);
  return rhsG;
}

}  // namespace mcl
}  // namespace beacon
}  // namespace fetch
