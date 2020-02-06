#include "entropy_generation.hpp"
#include "mcl_crypto.hpp"

#include <iostream>
#include <cassert>

using namespace fetch::crypto;

int main() {
  InitialiseMcl();
  auto dealer_keys = fetch::crypto::mcl::TrustedDealerGenerateKeys(4,3);
  std::cout << "Group Public Key: " << dealer_keys.group_public_key << std::endl;
  std::cout << "Generator: " << dealer_keys.generator << std::endl;
  assert(dealer_keys.public_key_shares.size() == dealer_keys.private_key_shares.size());
  std::cout << "(index, private key, public key)" << std::endl;
  for (uint32_t i = 0; i < dealer_keys.private_key_shares.size(); i++) {
    std::cout << i << std::endl;
    std::cout << dealer_keys.private_key_shares[i] << std::endl;
    std::cout << dealer_keys.public_key_shares[i] << std::endl;
  }
}