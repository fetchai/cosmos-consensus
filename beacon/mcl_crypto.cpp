#include "mcl_crypto.hpp"

namespace fetch {
namespace crypto {
namespace mcl {

std::atomic<bool>  details::MCLInitialiser::was_initialised{false};

Signature Sign(std::string const &message, PrivateKey x_i) {
  Signature PH;
  Signature sign;
  bn::Fp Hm;
  Hm.setHashOf(message.data(), message.size());
  bn::mapToG1(PH, Hm);
  bn::G1::mul(sign, PH, x_i);  // sign = s H(m)
  return sign;
}

bool Verify(std::string const &message, Signature const &sign, PublicKey const &public_key, Generator const &G) {
  Signature PH;
  bn::Fp12 e1, e2;
  bn::Fp Hm;
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
Signature LagrangeInterpolation(std::unordered_map < uint64_t, Signature >
const &shares) {
assert(!shares.empty());
if (shares.size()== 1) {
return shares.begin()->second;
}
Signature res;

PrivateKey a{1};
for (auto &p: shares) {
a *=bn::Fr(p.first + 1);
}

for (auto &p1 : shares) {
auto b = static_cast<bn::Fr>(p1.first + 1);
for (auto &p2 : shares) {
if (p2.first != p1.first) {
b *= static_cast<bn::Fr>(p2.first) - static_cast<bn::Fr>(p1.first);
}
}
Signature t;
bn::G1::mul(t, p1.second, a / b);
res +=t;
}
return res;
}

DkgKeyInformation TrustedDealerGenerateKeys(uint32_t cabinet_size, uint32_t threshold)
{
  DkgKeyInformation output;
  output.generator = "Fetch.ai Generator G";

  Generator generator{output.generator};

  // Construct polynomial of degree threshold - 1
  std::vector<PrivateKey> vec_a;
  vec_a.resize(threshold);
  for (uint32_t ii = 0; ii < threshold; ++ii)
  {
    vec_a[ii].setRand();
  }

  // Group secret key is polynomial evaluated at 0
  PublicKey  group_public_key;
  PrivateKey group_private_key = vec_a[0];
  bn::G2::mul(group_public_key, generator, group_private_key);
  output.group_public_key = group_public_key.getStr();

  // Generate cabinet public keys from their private key contributions
  for (uint32_t i = 0; i < cabinet_size; ++i)
  {
    PrivateKey pow;
    PrivateKey tmpF;
    PrivateKey private_key;
    // Private key is polynomial evaluated at index i
    private_key = vec_a[0];
    for (uint32_t k = 1; k < vec_a.size(); k++)
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

}
}
}
