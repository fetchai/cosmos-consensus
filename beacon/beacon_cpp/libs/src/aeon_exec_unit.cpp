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

#include "aeon_exec_unit.hpp"
#include "mcl_crypto.hpp"
#include <fstream>

namespace fetch {
namespace crypto {

void InitialiseMcl() {
  mcl::details::MCLInitialiser();
}


AeonExecUnit::AeonExecUnit(std::string const &filename) {
   std::string line;
   std::ifstream myfile (filename);
   if (myfile.is_open())
   {
      // Ignore first line which contains description of ordering
      getline(myfile, line);

      getline(myfile, generator_);
      getline(myfile, aeon_keys_.group_public_key);
      getline(myfile, aeon_keys_.private_key);

      while (getline(myfile, line))
      {
        aeon_keys_.public_key_shares.push_back(line);
      }
      myfile.close();
    }
}

/**
 * Computes signature share of a message
 *
 * @param message Message to be signed
 * @param x_i Secret key share
 * @return Signature share
 */
AeonExecUnit::Signature AeonExecUnit::Sign(MessagePayload const &message) {
  mcl::PrivateKey x_i{aeon_keys_.private_key};

  return mcl::Sign(message, x_i).getStr();
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
bool
AeonExecUnit::Verify(MessagePayload const &message, Signature const &sign, CabinetIndex const &sender) {
  assert(sender < aeon_keys_.public_key_shares.size());
  mcl::Signature signature{sign};
  mcl::PublicKey public_key{aeon_keys_.public_key_shares[sender]};
  mcl::Generator generator{generator_};

  return mcl::Verify(message, signature, public_key, generator);
}

AeonExecUnit::Signature
AeonExecUnit::ComputeGroupSignature(std::map <int, Signature> const &shares) {
  std::unordered_map <CabinetIndex, mcl::Signature> signature_shares;
  for (auto const &share : shares) {
    assert(static_cast<CabinetIndex>(share.first) < aeon_keys_.public_key_shares.size());
    mcl::Signature sig{share.second};
    signature_shares.insert({static_cast<CabinetIndex>(share.first), sig});
  }

  mcl::Signature group_sig = mcl::LagrangeInterpolation(signature_shares);
  return group_sig.getStr();
}

bool AeonExecUnit::VerifyGroupSignature(MessagePayload const &message, Signature const &sign) {
  mcl::Signature signature{sign};
  mcl::PublicKey public_key{aeon_keys_.group_public_key};
  mcl::Generator generator{generator_};

  return mcl::Verify(message, signature, public_key, generator);
}

bool AeonExecUnit::CanSign() const {
    return !aeon_keys_.private_key.empty();
}

}  // namespace crypto
}  // namespace fetch
