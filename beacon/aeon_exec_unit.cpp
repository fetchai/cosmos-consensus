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
#include "serialisers.hpp"
#include <fstream>

namespace fetch {
namespace beacon {

void InitialiseMcl() {
  mcl::details::MCLInitialiser();
}


BaseAeon::BaseAeon(std::string const &filename) {
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

    } else {
      // AeonExecUnit can not open file
      assert(false);
    }
}

BaseAeon::BaseAeon(std::string generator, DKGKeyInformation keys, std::set<CabinetIndex> qual) 
  : aeon_keys_{std::move(keys)}
  , generator_{std::move(generator)}
  , qual_{std::move(qual)} 
  {
}

BaseAeon::BaseAeon(DKGKeyInformation const &keys, std::vector<CabinetIndex> const &qual) 
{
  for (auto const &index : qual) {
    qual_.insert(index);
  }
  aeon_keys_ = keys;
}

bool BaseAeon::VerifyGroupSignature(MessagePayload const &message, Signature const &sign) const {
  mcl::Signature signature;
  mcl::GroupPublicKey public_key;
  mcl::GroupPublicKey generator;

  signature.FromString(sign);
  public_key.FromString(aeon_keys_.group_public_key);
  generator.FromString(generator_);
  return mcl::PairingVerify(message, signature, public_key, generator);
}

bool BaseAeon::CanSign() const {
    return !aeon_keys_.private_key.empty();
}

void BaseAeon::WriteToFile(std::string const &filename) const {
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

bool BaseAeon::InQual(CabinetIndex index) const {
  return qual_.find(index) != qual_.end();
}

std::string BaseAeon::GroupPublicKey() const {
  return aeon_keys_.group_public_key;
}

 std::string BaseAeon::PrivateKey() const {
   return aeon_keys_.private_key;
 }

std::vector<std::string> BaseAeon::PublicKeyShares() const {
  return aeon_keys_.public_key_shares;
}

std::vector<CabinetIndex> BaseAeon::Qual() const {
  return {qual_.begin(), qual_.end()};
}

std::string BaseAeon::Generator() const {
  return generator_;
}

BlsAeon::BlsAeon(std::string const &filename): BaseAeon{filename}{
   CheckKeys();
}

BlsAeon::BlsAeon(std::string const &generator, DKGKeyInformation const &keys, std::vector<CabinetIndex> const &qual)
: BaseAeon{keys, qual} {
  generator_ = generator;
  CheckKeys();
}
// Constructor used beacon manager
BlsAeon::BlsAeon(std::string generator, DKGKeyInformation keys, std::set<CabinetIndex> qual)
: BaseAeon{generator, keys, qual} {
  CheckKeys();
}

bool BlsAeon::CheckIndex(CabinetIndex index) const {
  if (index >= aeon_keys_.public_key_shares.size()) {
    return false;
  }
  mcl::PrivateKey private_key;
  mcl::GroupPublicKey public_key;

  private_key.FromString(aeon_keys_.private_key);
  public_key.FromString(aeon_keys_.public_key_shares[index]);

  auto test_message = "Test";
  auto sig = Sign(test_message, index);

  return Verify(test_message, sig, index);
}

/**
 * Check strings from file are correct for initialising the corresponding 
 * mcl type
 * 
 * @return Whether check succeeded or failed
 */
void BlsAeon::CheckKeys() const {
  if (CanSign()) {
    mcl::PrivateKey temp_private_key;
    assert(temp_private_key.FromString(aeon_keys_.private_key));
  }
  mcl::GroupPublicKey temp_group_key;
  assert(temp_group_key.FromString(aeon_keys_.group_public_key));
  for (auto i = 0; i < aeon_keys_.public_key_shares.size(); i++) {
     mcl::GroupPublicKey temp_key_share;
     assert(temp_key_share.FromString(aeon_keys_.public_key_shares[i]));
  }
  mcl::GroupPublicKey generator;
  assert(generator.FromString(generator_));
}

/**
 * Computes signature share of a message
 *
 * @param message Message to be signed
 * @param x_i Secret key share
 * @return Signature share
 */
BlsAeon::Signature BlsAeon::Sign(MessagePayload const &message, CabinetIndex) const {
  if (!CanSign()) {
     assert(CanSign());
     return Signature{};
  }
  mcl::PrivateKey x_i;
  x_i.FromString(aeon_keys_.private_key);
  return mcl::Sign(message, x_i).ToString();
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
BlsAeon::Verify(MessagePayload const &message, Signature const &sign, CabinetIndex const &sender) const{
  assert(sender < aeon_keys_.public_key_shares.size());
  mcl::Signature signature;
  mcl::GroupPublicKey public_key{};
  mcl::GroupPublicKey generator;

  signature.FromString(sign);
  public_key.FromString(aeon_keys_.public_key_shares[sender]);
  generator.FromString(generator_);
  return mcl::PairingVerify(message, signature, public_key, generator);
}

BlsAeon::Signature
BlsAeon::ComputeGroupSignature(std::map <CabinetIndex, Signature> const &shares) const {
  std::unordered_map <CabinetIndex, mcl::Signature> signature_shares;
  for (auto const &share : shares) {
    assert(share.first < aeon_keys_.public_key_shares.size());
    mcl::Signature sig;
    sig.FromString(share.second);
    signature_shares.insert({share.first, sig});
  }

  mcl::Signature group_sig = mcl::LagrangeInterpolation(signature_shares);
  return group_sig.ToString();
}

std::string BlsAeon::Name() const{
  return BLS_AEON;
}

GlowAeon::GlowAeon(std::string const &generator_strs, DKGKeyInformation const &keys, std::vector<CabinetIndex> const &qual) 
: BaseAeon{keys, qual}
{
  std::pair<std::string, std::string> generators;
  bool ok = serialisers::Deserialise(generator_strs, generators);
  assert(ok);

  generator_ = generators.first;
  generator_g1_ = generators.second;
  CheckKeys();
}

GlowAeon::GlowAeon(std::string generator, std::string generator_g1, DKGKeyInformation keys, std::set<CabinetIndex> qual)
: BaseAeon{generator, keys, qual}, generator_g1_{std::move(generator_g1)} {
  CheckKeys();
}

/**
 * Check strings from file are correct for initialising the corresponding 
 * mcl type
 * 
 * @return Whether check succeeded or failed
 */
void GlowAeon::CheckKeys() const {
  if (CanSign()) {
    mcl::PrivateKey temp_private_key;
    assert(temp_private_key.FromString(aeon_keys_.private_key));
  }
  mcl::GroupPublicKey temp_group_key;
  assert(temp_group_key.FromString(aeon_keys_.group_public_key));
  for (auto i = 0; i < aeon_keys_.public_key_shares.size(); i++) {
     mcl::Signature temp_key_share;
     assert(temp_key_share.FromString(aeon_keys_.public_key_shares[i]));
  }
  mcl::GroupPublicKey generator;
  assert(generator.FromString(generator_));

  mcl::Signature gen_g1;
  assert(gen_g1.FromString(generator_g1_));
}


bool GlowAeon::CheckIndex(CabinetIndex index) const {
  if (index >= aeon_keys_.public_key_shares.size()) {
    return false;
  }
  mcl::PrivateKey private_key;
  mcl::Signature public_key;

  private_key.FromString(aeon_keys_.private_key);
  public_key.FromString(aeon_keys_.public_key_shares[index]);

  auto test_message = "Test";
  auto sig = Sign(test_message, index);

  return Verify(test_message, sig, index);
}

/**
 * Computes signature share of a message
 *
 * @param message Message to be signed
 * @param x_i Secret key share)
 * @return Signature share
 */
GlowAeon::Signature GlowAeon::Sign(MessagePayload const &message, CabinetIndex index) const {
  if (!CanSign()) {
     assert(CanSign());
     return Signature{};
  }
  mcl::PrivateKey x_i;
  mcl::Signature generator;
  mcl::Signature public_key;
  x_i.FromString(aeon_keys_.private_key);
  generator.FromString(generator_g1_);
  public_key.FromString(aeon_keys_.public_key_shares[index]);

  mcl::Signature sig = mcl::Sign(message, x_i);
  mcl::Proof proof = mcl::ComputeProof(generator, message, public_key, sig, x_i);
  return serialisers::Serialise({sig.ToString(), proof.first.ToString(), proof.second.ToString()});
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
GlowAeon::Verify(MessagePayload const &message, Signature const &sign, CabinetIndex const &sender) const{
  assert(sender < aeon_keys_.public_key_shares.size());
  std::vector<std::string> sig_and_proof;
  if (!serialisers::Deserialise(sign, sig_and_proof) || sig_and_proof.size() != 3) {
    return false;
  }

  mcl::Signature signature;
  mcl::Proof proof;
  mcl::Signature public_key{};
  mcl::Signature generator;

  signature.FromString(sig_and_proof[0]);
  proof.FromString({sig_and_proof[1], sig_and_proof[2]});
  public_key.FromString(aeon_keys_.public_key_shares[sender]);
  generator.FromString(generator_g1_);

  return mcl::VerifyProof(public_key, message, signature, generator, proof);
}

GlowAeon::Signature
GlowAeon::ComputeGroupSignature(std::map <CabinetIndex, Signature> const &shares) const {
  std::unordered_map <CabinetIndex, mcl::Signature> signature_shares;
  for (auto const &share : shares) {
    assert(share.first < aeon_keys_.public_key_shares.size());
    std::vector<std::string> sig_and_proof;
    assert(serialisers::Deserialise(share.second, sig_and_proof));
    mcl::Signature sig;
    sig.FromString(sig_and_proof[0]);
    signature_shares.insert({share.first, sig});
  }

  mcl::Signature group_sig = mcl::LagrangeInterpolation(signature_shares);
  return group_sig.ToString();
}

std::string GlowAeon::Generator() const {
  return serialisers::Serialise(std::make_pair(generator_, generator_g1_));
}

std::string GlowAeon::Name() const {
  return GLOW_AEON;
}

}  // namespace crypto
}  // namespace fetch
