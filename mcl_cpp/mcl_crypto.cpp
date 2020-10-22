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

#include "mcl_crypto.hpp"

#include <iostream>

namespace fetch {
namespace beacon {
namespace mcl {

// IOMODE 2048 corresponds to printable hex string, seems to be the most stable
// of the more compact modes. 0 is the default corresponding dec representation.
const int PRIVATE_KEY_IOMODE = 2048; // Choose 32 for more compact private key
const int EC_IOMODE = 2048; // Choose 512 for compressed public key and sigs
const size_t PRIVATE_KEY_SIZE = 64;  // If more compact then should be 32
const size_t PUBLIC_KEY_SIZE  = 192; // If compressed then should be 96
const size_t SIGNATURE_SIZE   = 96;  // If compressed then should be 48
std::atomic<bool> details::MCLInitialiser::was_initialised{false};

PrivateKey::PrivateKey() {
  clear();
}

PrivateKey::PrivateKey(uint32_t num) {
  clear();
  bn::Fr::add(*this, *this, num);
}

void PrivateKey::Random() {
  setRand();
}

void PrivateKey::Increment() {
  bn::Fr::add(*this, *this, 1);
}

std::string PrivateKey::ToString() const {
  std::string ret;
  ret.resize(PRIVATE_KEY_SIZE);
  auto n = getStr(&ret[0], PRIVATE_KEY_SIZE, PRIVATE_KEY_IOMODE);
  return ret;
}

bool PrivateKey::FromString(const std::string &s) {
  bool set{false};
  setStr(&set, s.data(), PRIVATE_KEY_IOMODE);
  return set;
}

void PrivateKey::SetZero() {
  clear();
}

void PrivateKey::Add(const PrivateKey &left, const PrivateKey &right) {
  bn::Fr::add(*this, left, right);
}

void PrivateKey::Sub(const PrivateKey &left, const PrivateKey &right) {
  bn::Fr::sub(*this, left, right);
}

void PrivateKey::Mult(const PrivateKey &left, const PrivateKey &right) {
  bn::Fr::mul(*this, left, right);
}

void PrivateKey::Inv(const PrivateKey &inv) {
  bn::Fr::inv(*this, inv);
}

void PrivateKey::Negate(const PrivateKey &neg) {
  bn::Fr::neg(*this, neg);
}

void PrivateKey::Pow(const PrivateKey &left, uint32_t pow) {
  bn::Fr::pow(*this, left, pow);
}

void PrivateKey::Div(const PrivateKey &left, const PrivateKey &right) {
  bn::Fr::div(*this, left, right);
}

void PrivateKey::SetHashOf(const Signature &generator, const Signature &Hm, const Signature &publicKey,
                                      const Signature &sig, const Signature &com1, const Signature &com2) {
  std::ostringstream os;
  os << generator << Hm << publicKey << sig << com1 << com2;
  bn::Fr::setHashOf(os.str());
}

Signature::Signature() {
  clear();
}

void Signature::SetZero() {
  clear();
}

bool Signature::FromString(const std::string &s) {
  bool set{false};
  setStr(&set, s.data(), EC_IOMODE);
  return set;
}

void Signature::Mult(const Signature &left, const PrivateKey &right) {
  bn::G1::mul(*this, left, right);
}

void Signature::Add(const Signature &left, const Signature &right) {
  bn::G1::add(*this, left, right);
}

void Signature::HashAndMap(const std::string &payload) {
  bn::Fp Hm;
  Hm.setHashOf(payload);
  bn::mapToG1(*this, Hm);
}

std::string Signature::ToString() const {
  std::string ret;
  ret.resize(SIGNATURE_SIZE);
  auto n = getStr(&ret[0], SIGNATURE_SIZE, EC_IOMODE);
  return ret;
}

GroupPublicKey::GroupPublicKey() {
  clear();
}

void GroupPublicKey::SetZero() {
  clear();
}

bool GroupPublicKey::FromString(const std::string &s) {
  bool set{false};
  setStr(&set, s.data(), EC_IOMODE);
  return set;
}

void GroupPublicKey::Mult(const GroupPublicKey &left, const PrivateKey &right) {
  bn::G2::mul(*this, left, right);
}

void GroupPublicKey::Add(const GroupPublicKey &left, const GroupPublicKey &right) {
  bn::G2::add(*this, left, right);
}

void GroupPublicKey::HashAndMap(const std::string &payload) {
  bn::hashAndMapToG2(*this, payload.data(), payload.size());
}

std::string GroupPublicKey::ToString() const {
  std::string ret;
  ret.resize(PUBLIC_KEY_SIZE);
  auto n = getStr(&ret[0], PUBLIC_KEY_SIZE, EC_IOMODE);
  return ret;
}

Pairing::Pairing() {
  clear();
}

void Pairing::Map(const Signature &g1, const GroupPublicKey &g2) {
  bn::pairing(*this, g1, g2);
}

bool Proof::FromString(const std::pair<std::string, std::string> &s) {
  return first.FromString(s.first) && second.FromString(s.second);
}

std::pair<std::string, std::string> Proof::ToString() const {
  return std::make_pair(first.ToString(), second.ToString());
}

Signature Sign(std::string const &message, PrivateKey x_i)
{
  Signature PH;
  Signature sign;
  PH.HashAndMap(message);
  sign.Mult(PH, x_i);
  return sign;
}

/**
 * Verifies a signature
 *
 * @param y The public key (can be the group public key, or public key share)
 * @param message Message that was signed
 * @param sign Signature to be verified
 * @param G Generator used in DKG
 * @return
 */
bool PairingVerify(const std::string &message, const mcl::Signature &sign, const mcl::GroupPublicKey &y, const mcl::GroupPublicKey &G) 
{
  mcl::Pairing e1, e2;
  mcl::Signature PH;
  PH.HashAndMap(message);

  e1.Map(sign, G);
  e2.Map(PH, y);
  return e1 == e2;
}

Proof ComputeProof(const Signature &G, const std::string &message, const Signature &y, const Signature &sig, const PrivateKey &x) {
  Signature PH;
  PH.HashAndMap(message);

  PrivateKey r;
  r.Random();
  Signature com1, com2;
  com1.Mult(G, r);
  com2.Mult(PH, r);

  Proof pi;
  pi.first.SetHashOf(G, PH, y, sig, com1, com2);
  PrivateKey localVar;
  localVar.Mult(x, pi.first);
  pi.second.Add(r, localVar);
  return pi;
}

bool VerifyProof(const Signature &y, const std::string &message, const Signature &sign, const Signature &G,
                     const Proof &proof) 
{
  Signature PH;
  PH.HashAndMap(message);

  Signature tmp, c1, c2;
  PrivateKey tmps;
  tmps.Negate(proof.first);
  c1.Mult(G, proof.second);
  tmp.Mult(y, tmps);
  c1.Add(c1, tmp);
  c2.Mult(PH, proof.second);
  tmp.Mult(sign, tmps);
  c2.Add(c2, tmp);

  PrivateKey ch_cmp;
  ch_cmp.SetHashOf(G, PH, y, sign, c1, c2);

  return proof.first == ch_cmp;
}

/**
 * Computes the group signature using the indices and signature shares of threshold_ + 1
 * parties
 *
 * @param shares Unordered map of indices and their corresponding signature shares
 * @return Group signature
 */
Signature LagrangeInterpolation(std::unordered_map<CabinetIndex, Signature> const &shares)
{
  assert(!shares.empty());
  if (shares.size() == 1)
  {
    return shares.begin()->second;
  }
  Signature res;

  PrivateKey a{1};
  for (auto &p : shares)
  {
    a.Mult(a, PrivateKey{uint32_t(p.first + 1)});
  }

  for (auto &p1 : shares)
  {
    PrivateKey b{static_cast<uint32_t>(p1.first + 1)};
    for (auto &p2 : shares)
    {
      if (p2.first != p1.first)
      {
        PrivateKey local_share1{static_cast<uint32_t>(p1.first)};
        PrivateKey local_share2{static_cast<uint32_t>(p2.first)};
        local_share2.Sub(local_share2, local_share1);
        b.Mult(b, local_share2);
      }
    }
    b.Inv(b);
    b.Mult(a, b);

    Signature t;
    t.Mult(p1.second, b);
    res.Add(res, t);
  }
  return res;
}

/**
 * Given two polynomials (f and f') with coefficients a_i and b_i, we compute the evaluation of
 * these polynomials at different points
 *
 * @param s_i The value of f(index)
 * @param sprime_i The value of f'(index)
 * @param a_i The vector of coefficients for f
 * @param b_i The vector of coefficients for f'
 * @param index The point at which you evaluate the polynomial
 */
void ComputeShares(PrivateKey &s_i, PrivateKey &sprime_i, std::vector<PrivateKey> const &a_i,
                   std::vector<PrivateKey> const &b_i, CabinetIndex index)
{
  PrivateKey pow{static_cast<uint32_t>(index + 1)}, tmpF;
  PrivateKey crypto_rank{static_cast<uint32_t>(index+1)};
  assert(a_i.size() == b_i.size());
  assert(!a_i.empty());
  s_i      = a_i[0];
  sprime_i = b_i[0];
  for (CabinetIndex k = 1; k < a_i.size(); k++)
  {
    tmpF.Mult(pow, b_i[k]);
    sprime_i.Add(sprime_i, tmpF);
    tmpF.Mult(pow, a_i[k]);
    s_i.Add(s_i, tmpF);
    pow.Mult(pow, crypto_rank); // adjust index $j$ in computation
  }
}

/**
 * Computes the coefficients of a polynomial
 *
 * @param a Points at which polynomial has been evaluated
 * @param b Value of the polynomial at points a
 * @return The vector of coefficients of the polynomial
 */
std::vector<PrivateKey> InterpolatePolynom(std::vector<PrivateKey> const &a,
                                           std::vector<PrivateKey> const &b)
{
  std::size_t m = a.size();
  if ((b.size() != m) || (m == 0))
  {
    throw std::invalid_argument("mcl_interpolate_polynom: bad m");
  }
  std::vector<PrivateKey> prod{a}, res(m);
  for (std::size_t k = 0; k < m; k++)
  {
    PrivateKey t1{1};
    for (auto i = static_cast<long>(k - 1); i >= 0; i--)
    {
      t1.Mult(t1, a[k]);
      t1.Add(t1, prod[static_cast<std::size_t>(i)]);
    }

    PrivateKey t2;
    for (auto i = static_cast<long>(k - 1); i >= 0; i--)
    {
      t2.Mult(t2, a[k]);
      t2.Add(t2, res[static_cast<std::size_t>(i)]);
    }
    t2.Sub(b[k], t2);
    t1.Div(t2, t1);

    for (std::size_t i = 0; i < k; i++)
    {
      t2.Mult(prod[i], t1);
      res[i].Add(res[i], t2);
    }
    res[k] = t1;
    if (k < (m - 1))
    {
      if (k == 0)
      {
        prod[0].Negate(prod[0]);
      }
      else
      {
        t1.Negate(a[k]);
        prod[k].Add(t1, prod[k - 1]);
        for (auto i = static_cast<long>(k - 1); i >= 1; i--)
        {
          t2.Mult(prod[static_cast<std::size_t>(i)], t1);
          prod[static_cast<std::size_t>(i)].Add(t2, prod[static_cast<std::size_t>(i - 1)]);
        }
        prod[0].Mult(prod[0], t1);
      }
    }
  }
  return res;
}

}  // namespace mcl
}  // namespace beacon
}  // namespace fetch
