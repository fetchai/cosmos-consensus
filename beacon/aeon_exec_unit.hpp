#pragma once
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


#include <cstddef>
#include <cstdint>
#include <map>
#include <vector>
#include <string>
#include <set>

namespace fetch {
namespace beacon {

void InitialiseMcl();

struct DKGKeyInformation {
  std::string private_key;
  std::vector<std::string> public_key_shares;
  std::string group_public_key;
};

class BaseAeon {
public:
  using MessagePayload     = std::string;
  using Signature          = std::string;
  using CabinetIndex       = uint32_t;

  virtual ~BaseAeon() = default;
  virtual Signature Sign(MessagePayload const &message, CabinetIndex index) const = 0;
  virtual bool Verify(MessagePayload const &message, Signature const &sign, CabinetIndex const &sender) const = 0;
  virtual bool CheckIndex(CabinetIndex index) const = 0;
  virtual Signature ComputeGroupSignature(std::map <CabinetIndex, Signature> const &signature_shares) const = 0;

  bool VerifyGroupSignature(MessagePayload const &message, Signature const &signature) const;

  bool CanSign() const;
  void WriteToFile(std::string const &filename) const;
  bool InQual(CabinetIndex index) const;
  std::string GroupPublicKey() const;
  std::string PrivateKey() const;
  std::vector<std::string> PublicKeyShares() const;
  std::vector<CabinetIndex> Qual() const;
  virtual std::string Generator() const;
  virtual std::string Name() const;

protected:
  DKGKeyInformation aeon_keys_;
  std::string generator_;
  std::set<CabinetIndex> qual_;


  explicit BaseAeon(std::string const &filename);
  BaseAeon(DKGKeyInformation const &keys, std::vector<CabinetIndex> const &qual); 
  BaseAeon(std::string generator, DKGKeyInformation keys, std::set<CabinetIndex> qual);

  virtual void CheckKeys() const = 0;
};

class BlsAeon : public BaseAeon {
public:
  explicit BlsAeon(std::string const &filename);
  BlsAeon(std::string const &generator, DKGKeyInformation const &keys, std::vector<CabinetIndex> const &qual); 
  // Constructor used in bls dkg
  BlsAeon(std::string generator, DKGKeyInformation keys, std::set<CabinetIndex> qual);
  ~BlsAeon() = default;

  Signature Sign(MessagePayload const &message, CabinetIndex) const override;
  bool Verify(MessagePayload const &message, Signature const &sign, CabinetIndex const &sender) const override;
  Signature ComputeGroupSignature(std::map <CabinetIndex, Signature> const &signature_shares) const;
  bool CheckIndex(CabinetIndex index) const override;
  std::string Name() const override;

private:  
  void CheckKeys() const override;
};

class GlowAeon : public BaseAeon {
public:
  GlowAeon(std::string const &generator, DKGKeyInformation const &keys, std::vector<CabinetIndex> const &qual); 
 // Constructor used in glow dkg
  GlowAeon(std::string generator_, std::string generate_g1, DKGKeyInformation keys, std::set<CabinetIndex> qual);
  ~GlowAeon() = default;

  Signature Sign(MessagePayload const &message, CabinetIndex index) const override;
  bool Verify(MessagePayload const &message, Signature const &sign, CabinetIndex const &sender) const override;
  Signature ComputeGroupSignature(std::map <CabinetIndex, Signature> const &signature_shares) const;
  bool CheckIndex(CabinetIndex index) const override;
  std::string Generator() const override;
  std::string Name() const override;

private:
  std::string generator_g1_;

  void CheckKeys() const override;
};

}  // namespace crypto
}  // namespace fetch
