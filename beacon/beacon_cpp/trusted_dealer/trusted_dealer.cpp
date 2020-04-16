#include "aeon_exec_unit.hpp"
#include "mcl_crypto.hpp"

#include <fstream>
#include <iostream>
#include <cassert>
#include <stdlib.h>

using namespace fetch::crypto;

int main(int argc, char **argv) {
  InitialiseMcl();
  if (argc != 5) {
    std::cout << "Require arguments committee size, threshold, non-validators size, output directory" << std::endl;
    return 0;
  }
  std::cout << "Generating keys for committee size " << argv[1] << " and threshold " << argv[2] << std::endl;

  auto nValidators = static_cast<uint32_t>(std::atoi(argv[1]));
  auto threshold = static_cast<uint32_t>(std::atoi(argv[2]));
  auto nNonValidators = static_cast<uint32_t>(std::atoi(argv[3]));
  auto outputDir = std::string(argv[4]);

  auto dealer_keys = fetch::crypto::mcl::TrustedDealerGenerateKeys(nValidators, threshold);

 for (uint32_t i = 0; i < nValidators; i++) {
    std::ofstream new_file;
    new_file.open(outputDir + std::to_string(i) + ".txt");
    new_file << "Generator, group public key, private key, list of public key shares" << std::endl;
    new_file << dealer_keys.generator << std::endl;
    new_file << dealer_keys.group_public_key << std::endl;
    new_file << dealer_keys.private_key_shares[i] << std::endl;
    for (uint32_t j = 0; j < dealer_keys.public_key_shares.size(); j++) {
      new_file << dealer_keys.public_key_shares[j] << std::endl;
    }
    new_file.close();
 }

 for (uint32_t k = 0; k < nNonValidators; k++) {
    std::ofstream new_file;
    new_file.open(outputDir + std::to_string(k + nValidators) + ".txt");
    new_file << "Generator, group public key, private key, list of public key shares" << std::endl;
    new_file << dealer_keys.generator << std::endl;
    new_file << dealer_keys.group_public_key << std::endl;
    new_file << std::endl;
    for (uint32_t m = 0; m < dealer_keys.public_key_shares.size(); m++) {
      new_file << dealer_keys.public_key_shares[m] << std::endl;
    }
    new_file.close();
 }
  return 0;
}
