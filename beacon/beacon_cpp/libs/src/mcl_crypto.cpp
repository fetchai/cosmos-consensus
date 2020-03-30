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

namespace fetch {
namespace beacon {
namespace mcl {

std::atomic<bool> details::MCLInitialiser::was_initialised{false};

Signature Sign(std::string const &message, PrivateKey x_i)
{
  Signature PH;
  Signature sign;
  bn::Fp    Hm;
  Hm.setHashOf(message.data(), message.size());
  bn::mapToG1(PH, Hm);
  bn::G1::mul(sign, PH, x_i);  // sign = s H(m)
  return sign;
}

bool Verify(std::string const &message, Signature const &sign, PublicKey const &public_key,
            Generator const &G)
{
  Signature PH;
  bn::Fp12  e1, e2;
  bn::Fp    Hm;
  Hm.setHashOf(message.data(), message.size());
  bn::mapToG1(PH, Hm);

  bn::pairing(e1, sign, G);
  bn::pairing(e2, PH, public_key);

  return e1 == e2;
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
    a *= bn::Fr(p.first + 1);
  }

  for (auto &p1 : shares)
  {
    auto b = static_cast<bn::Fr>(p1.first + 1);
    for (auto &p2 : shares)
    {
      if (p2.first != p1.first)
      {
        b *= static_cast<bn::Fr>(p2.first) - static_cast<bn::Fr>(p1.first);
      }
    }
    Signature t;
    bn::G1::mul(t, p1.second, a / b);
    res += t;
  }
  return res;
}

DkgKeyInformation TrustedDealerGenerateKeys(CabinetIndex cabinet_size, CabinetIndex threshold)
{
  DkgKeyInformation output;
  output.generator = "Fetch.ai Generator G";

  Generator generator{output.generator};

  // Construct polynomial of degree threshold - 1
  std::vector<PrivateKey> vec_a;
  vec_a.resize(threshold);
  for (CabinetIndex ii = 0; ii < threshold; ++ii)
  {
    vec_a[ii].setRand();
  }

  // Group secret key is polynomial evaluated at 0
  PublicKey  group_public_key;
  PrivateKey group_private_key = vec_a[0];
  bn::G2::mul(group_public_key, generator, group_private_key);
  output.group_public_key = group_public_key.getStr();

  // Generate cabinet public keys from their private key contributions
  for (CabinetIndex i = 0; i < cabinet_size; ++i)
  {
    PrivateKey pow;
    PrivateKey tmpF;
    PrivateKey private_key;
    // Private key is polynomial evaluated at index i
    private_key = vec_a[0];
    for (CabinetIndex k = 1; k < vec_a.size(); k++)
    {
      bn::Fr::pow(pow, i + 1, k);        // adjust index in computation
      bn::Fr::mul(tmpF, pow, vec_a[k]);  // j^k * a_i[k]
      bn::Fr::add(private_key, private_key, tmpF);
    }
    // Public key from private
    PublicKey public_key;
    bn::G2::mul(public_key, generator, private_key);
    output.public_key_shares.push_back(public_key.getStr());
    output.private_key_shares.push_back(private_key.getStr());
  }

  return output;
}

void SetGenerator(Generator &generator_g, std::string const &string_to_hash)
{
  assert(!string_to_hash.empty());
  bn::hashAndMapToG2(generator_g, string_to_hash);
  assert(!generator_g.isZero());
}

void SetGenerators(Generator &generator_g, Generator &generator_h,
                   std::string const &string_to_hash, std::string const &string_to_hash2)
{
  assert(!string_to_hash.empty() && !string_to_hash2.empty());
  assert(string_to_hash != string_to_hash2);
  bn::hashAndMapToG2(generator_g, string_to_hash);
  bn::hashAndMapToG2(generator_h, string_to_hash2);
  assert(!generator_g.isZero());
  assert(!generator_h.isZero());
}

/**
 * LHS and RHS functions are used for checking consistency between publicly broadcasted coefficients
 * and secret shares distributed privately
 */
PublicKey ComputeLHS(PublicKey &tmpG, Generator const &G, Generator const &H,
                     PrivateKey const &share1, PrivateKey const &share2)
{
  PublicKey tmp2G, lhsG;
  bn::G2::mul(tmpG, G, share1);
  bn::G2::mul(tmp2G, H, share2);
  bn::G2::add(lhsG, tmpG, tmp2G);

  return lhsG;
}

PublicKey ComputeLHS(Generator const &G, Generator const &H, PrivateKey const &share1,
                     PrivateKey const &share2)
{
  PublicKey tmpG;
  return ComputeLHS(tmpG, G, H, share1, share2);
}

void UpdateRHS(CabinetIndex rank, PublicKey &rhsG, std::vector<PublicKey> const &input)
{
  PrivateKey tmpF{1};
  PublicKey  tmpG;
  assert(!input.empty());
  for (CabinetIndex k = 1; k < input.size(); k++)
  {
    bn::Fr::pow(tmpF, rank + 1, k);  // adjust rank in computation
    bn::G2::mul(tmpG, input[k], tmpF);
    bn::G2::add(rhsG, rhsG, tmpG);
  }
}

PublicKey ComputeRHS(CabinetIndex rank, std::vector<PublicKey> const &input)
{
  PrivateKey tmpF;
  PublicKey  tmpG, rhsG;
  assert(!input.empty());
  // initialise rhsG
  rhsG = input[0];
  UpdateRHS(rank, rhsG, input);
  return rhsG;
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
  PrivateKey pow, tmpF;
  assert(a_i.size() == b_i.size());
  assert(!a_i.empty());
  s_i      = a_i[0];
  sprime_i = b_i[0];
  for (CabinetIndex k = 1; k < a_i.size(); k++)
  {
    bn::Fr::pow(pow, index + 1, k);  // adjust index in computation
    bn::Fr::mul(tmpF, pow, b_i[k]);  // j^k * b_i[k]
    bn::Fr::add(sprime_i, sprime_i, tmpF);
    bn::Fr::mul(tmpF, pow, a_i[k]);  // j^k * a_i[k]
    bn::Fr::add(s_i, s_i, tmpF);
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
  std::vector<PrivateKey> prod{a}, res;
  res.resize(m);
  for (std::size_t k = 0; k < m; k++)
  {
    PrivateKey t1{1};
    for (auto i = static_cast<long>(k - 1); i >= 0; i--)
    {
      bn::Fr::mul(t1, t1, a[k]);
      bn::Fr::add(t1, t1, prod[static_cast<std::size_t>(i)]);
    }

    PrivateKey t2{0};
    for (auto i = static_cast<long>(k - 1); i >= 0; i--)
    {
      bn::Fr::mul(t2, t2, a[k]);
      bn::Fr::add(t2, t2, res[static_cast<std::size_t>(i)]);
    }
    bn::Fr::inv(t1, t1);

    bn::Fr::sub(t2, b[k], t2);
    bn::Fr::mul(t1, t1, t2);

    for (std::size_t i = 0; i < k; i++)
    {
      bn::Fr::mul(t2, prod[i], t1);
      bn::Fr::add(res[i], res[i], t2);
    }
    res[k] = t1;
    if (k < (m - 1))
    {
      if (k == 0)
      {
        bn::Fr::neg(prod[0], prod[0]);
      }
      else
      {
        bn::Fr::neg(t1, a[k]);
        bn::Fr::add(prod[k], t1, prod[k - 1]);
        for (auto i = static_cast<long>(k - 1); i >= 1; i--)
        {
          bn::Fr::mul(t2, prod[static_cast<std::size_t>(i)], t1);
          bn::Fr::add(prod[static_cast<std::size_t>(i)], t2, prod[static_cast<std::size_t>(i - 1)]);
        }
        bn::Fr::mul(prod[0], prod[0], t1);
      }
    }
  }
  return res;
}

}  // namespace mcl
}  // namespace beacon
}  // namespace fetch
