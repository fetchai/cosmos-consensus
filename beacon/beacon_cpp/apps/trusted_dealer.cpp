#include "aeon_exec_unit.hpp"
#include "mcl_crypto.hpp"

#include <fstream>
#include <iostream>
#include <cassert>
#include <stdlib.h>

using namespace fetch::crypto;

int main(int argc, char **argv) {
  InitialiseMcl();
  if (argc != 4) {
    std::cout << "Require arguments committee size, threshold, output directory" << std::endl;
    return 0;
  }
  std::cout << "Generating keys for committee size " << argv[1] << " and threshold " << argv[2] << std::endl;
  auto dealer_keys = fetch::crypto::mcl::TrustedDealerGenerateKeys(static_cast<uint32_t>(std::atoi(argv[1])), static_cast<uint32_t>(std::atoi(argv[2])));


 for (uint32_t i = 0; i < dealer_keys.private_key_shares.size(); i++) {
    assert(dealer_keys.public_key_shares.size() == dealer_keys.private_key_shares.size());
    std::ofstream new_file;
    new_file.open(std::string(argv[3]) + std::to_string(i) + ".txt");
    new_file << "Generator, group public key, private key, list of public key shares" << std::endl;
    new_file << dealer_keys.generator << std::endl;
    new_file << dealer_keys.group_public_key << std::endl;
    new_file << dealer_keys.private_key_shares[i] << std::endl;
    for (uint32_t j = 0; j < dealer_keys.public_key_shares.size(); j++) {
      new_file << dealer_keys.public_key_shares[j] << std::endl;
    }
    new_file.close();
 }

  return 0;
}
