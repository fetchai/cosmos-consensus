#include "aeon_exec_unit.hpp"
#include "mcl_crypto.hpp"

#include <fstream>
#include <iostream>
#include <cassert>
#include <stdlib.h>

using namespace fetch::beacon;

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

  auto dealer_keys = fetch::beacon::mcl::TrustedDealerGenerateKeys(nValidators, threshold);

  std::set<CabinetIndex> qual;
  for (CabinetIndex i = 0; i < nValidators; i++) {
    qual.insert(i);
  }

 for (uint32_t i = 0; i < nValidators; i++) {
    DKGKeyInformation keys{dealer_keys.private_key_shares[i], dealer_keys.public_key_shares, dealer_keys.group_public_key};
    AeonExecUnit aeon{dealer_keys.generator, keys, qual};
    aeon.WriteToFile(outputDir + std::to_string(i) + ".txt");
 }

 for (uint32_t k = 0; k < nNonValidators; k++) {
    DKGKeyInformation keys{"", dealer_keys.public_key_shares, dealer_keys.group_public_key};
    AeonExecUnit aeon{dealer_keys.generator, keys, qual};
    aeon.WriteToFile(outputDir + std::to_string(k + nValidators) + ".txt");
 }
  return 0;
}
