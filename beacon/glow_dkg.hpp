#pragma once
//------------------------------------------------------------------------------
//
//   Copyright 2019-2020 Fetch.AI Limited
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

#include "base_dkg.hpp"

namespace fetch {
namespace beacon {

class GlowDkg : public BaseDkg<mcl::Signature> {
public:
  using Base = BaseDkg<mcl::Signature>;
  using PrivateKey = Base::PrivateKey;
  using Signature = Base::Signature;
  using GroupPublicKey = Base::GroupPublicKey;
  using VerificationKey = Base::VerificationKey;
  using MessagePayload = std::string;

  GlowDkg();
  ~GlowDkg() = default;

  void NewCabinet(CabinetIndex cabinet_size, CabinetIndex threshold, CabinetIndex index) override;
  void GenerateCoefficients() override;
  std::vector<Coefficient> GetQualCoefficients() override;
  void AddQualCoefficients(CabinetIndex const &from_index, std::vector<Coefficient> const &coefficients) override;
  SharesExposedMap ComputeQualComplaints(std::set<CabinetIndex> const &coeff_received) const override;
  CabinetIndex VerifyQualComplaint(CabinetIndex const & from_index, ComplaintAnswer const &answer) override;
  bool RunReconstruction() override;
  void ComputePublicKeys() override;
  std::shared_ptr<BaseAeon> GetDkgOutput() const override;

private:
  std::vector<PrivateKey> a_i_;
  std::vector<GroupPublicKey> B_i_;

  GroupPublicKey GetGeneratorG2() const;
  VerificationKey GetGroupG() const override;
  VerificationKey GetGroupH() const override;
  PrivateKey GetZeroFr() const override;
};
} //beacon
} //fetch