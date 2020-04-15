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
namespace beacon {

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

      getline(myfile, line);
      CabinetIndex qual_size{static_cast<CabinetIndex>(std::stoul(line))};

      getline(myfile, generator_);
      getline(myfile, aeon_keys_.group_public_key);
      getline(myfile, aeon_keys_.private_key);

      for (CabinetIndex i = 0; i < qual_size; i++)
      {
        getline(myfile, line);
        aeon_keys_.public_key_shares.push_back(line);
      }

      for (CabinetIndex i = 0; i < qual_size; i++)
      {
        getline(myfile, line);
        qual_.insert(static_cast<CabinetIndex>(std::stoul(line)));
      }

      myfile.close();

      CheckKeys();
    } else {
      // AeonExecUnit can not open file
      assert(false);
    }
}

AeonExecUnit::AeonExecUnit(std::string generator, DKGKeyInformation keys, std::set<CabinetIndex> qual) 
  : aeon_keys_{std::move(keys)}
  , generator_{std::move(generator)}
  , qual_{std::move(qual)} 
  {
  assert(aeon_keys_.public_key_shares.size() == qual_.size());
  CheckKeys();
}

/**
 * Check strings from file are correct for initialising the corresponding 
 * mcl type
 * 
 * @return Whether check succeeded or failed
 */
void AeonExecUnit::CheckKeys() const {
  if (CanSign()) {
    mcl::PrivateKey temp_private_key;
    assert(temp_private_key.FromString(aeon_keys_.private_key));
  }
  mcl::PublicKey temp_group_key;
  assert(temp_group_key.FromString(aeon_keys_.group_public_key));
  for (auto i = 0; i < aeon_keys_.public_key_shares.size(); i++) {
     mcl::PublicKey temp_key_share;
     assert(temp_key_share.FromString(aeon_keys_.public_key_shares[i]));
  }
  mcl::Generator generator;
  assert(generator.FromString(generator_));
}

/**
 * Computes signature share of a message
 *
 * @param message Message to be signed
 * @param x_i Secret key share
 * @return Signature share
 */
AeonExecUnit::Signature AeonExecUnit::Sign(MessagePayload const &message) const {
  if (!CanSign()) {
     assert(CanSign());
     return Signature{};
  }
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
AeonExecUnit::Verify(MessagePayload const &message, Signature const &sign, CabinetIndex const &sender) const{
  assert(sender < aeon_keys_.public_key_shares.size());
  mcl::Signature signature{sign};
  mcl::PublicKey public_key{aeon_keys_.public_key_shares[sender]};
  mcl::Generator generator{generator_};

  return mcl::Verify(message, signature, public_key, generator);
}

AeonExecUnit::Signature
AeonExecUnit::ComputeGroupSignature(std::map <int, Signature> const &shares) const {
  std::unordered_map <CabinetIndex, mcl::Signature> signature_shares;
  for (auto const &share : shares) {
    assert(static_cast<CabinetIndex>(share.first) < aeon_keys_.public_key_shares.size());
    mcl::Signature sig{share.second};
    signature_shares.insert({static_cast<CabinetIndex>(share.first), sig});
  }

  mcl::Signature group_sig = mcl::LagrangeInterpolation(signature_shares);
  return group_sig.getStr();
}

bool AeonExecUnit::VerifyGroupSignature(MessagePayload const &message, Signature const &sign) const {
  mcl::Signature signature{sign};
  mcl::PublicKey public_key{aeon_keys_.group_public_key};
  mcl::Generator generator{generator_};

  return mcl::Verify(message, signature, public_key, generator);
}

bool AeonExecUnit::CanSign() const {
    return !aeon_keys_.private_key.empty();
}

bool AeonExecUnit::CheckIndex(CabinetIndex index) const {
  if (index >= aeon_keys_.public_key_shares.size()) {
    return false;
  }
  mcl::PrivateKey private_key{aeon_keys_.private_key};
  mcl::PublicKey public_key{aeon_keys_.public_key_shares[index]};

  auto test_message = "Test";
  auto sig = Sign(test_message);

  return Verify(test_message, sig, index);
}

bool AeonExecUnit::WriteToFile(std::string const &filename) const {
  std::ofstream new_file;
  new_file.open(filename);
  new_file << "Qual size, generator, group public key, private key, list of public key shares, qual" << std::endl;
  new_file << qual_.size() << std::endl;
  new_file << generator_ << std::endl;
  new_file << aeon_keys_.group_public_key << std::endl;
  new_file << aeon_keys_.private_key << std::endl;
  for (uint32_t j = 0; j < aeon_keys_.public_key_shares.size(); j++) {
    new_file << aeon_keys_.public_key_shares[j] << std::endl;
  }
  for (auto member : qual_) {
    new_file << member << std::endl;
  }

  new_file.close();
}

bool AeonExecUnit::InQual(CabinetIndex index) const {
  return qual_.find(index) != qual_.end();
}

}  // namespace crypto
}  // namespace fetch
