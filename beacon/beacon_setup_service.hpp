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
#include "aeon_exec_unit.hpp"
#include "complaints_manager.hpp"

#include <memory>

namespace fetch {
namespace beacon {

class BeaconSetupService
{
public:
  using CabinetIndex     = uint32_t;
  using Identifier       = CabinetIndex;
  using SerialisedMsg    = std::string;
  using Share            = std::string;
  using Coefficient      = std::string;
  using SharesExposedMap = std::unordered_map<Identifier, std::pair<Share, Share>>;
#ifdef GLOW
using DkgImplemention = class GlowDkg;
using AeonExecUnit    = GlowAeon;
#else
using DkgImplemention = class BlsDkg;
using AeonExecUnit    = BlsAeon;
#endif

  BeaconSetupService(Identifier cabinet_size, CabinetIndex threshold, Identifier index);
  BeaconSetupService(BeaconSetupService const &) = delete;
  BeaconSetupService(BeaconSetupService &&)      = delete;
  ~BeaconSetupService();

  /// @name For checking state transition counters
  /// @{
  bool ReceivedAllCoefficientsAndShares() const;
  bool ReceivedAllComplaints() const;
  bool ReceivedAllComplaintAnswers() const;
  bool ReceivedAllQualCoefficients() const;
  bool ReceivedAllQualComplaints() const;
  bool ReceivedAllReconstructionShares() const;
  /// @}

  /// @name For constructing DKG messages
  /// @{
  SerialisedMsg GetCoefficients();
  SerialisedMsg GetShare(Identifier index);
  SerialisedMsg GetComplaints();
  SerialisedMsg GetComplaintAnswers();
  SerialisedMsg GetQualCoefficients();
  SerialisedMsg GetQualComplaints();
  SerialisedMsg GetReconstructionShares();
  /// @}

  /// @name Handlers for messages
  /// @{
  void OnShares(SerialisedMsg const &msg, const Identifier &from);
  void OnCoefficients(SerialisedMsg const &msg, Identifier const &from);
  void OnComplaints(SerialisedMsg const &msg, Identifier const &from);
  void OnComplaintAnswers(SerialisedMsg const &msg, Identifier const &from);
  void OnQualCoefficients(SerialisedMsg const &msg, Identifier const &from);
  void OnQualComplaints(SerialisedMsg const &msg, Identifier const &from);
  void OnReconstructionShares(SerialisedMsg const &msg, Identifier const &from);
  /// @}

  CabinetIndex            BuildQual();
  bool                    CheckQualComplaints();
  bool                    RunReconstruction();
  AeonExecUnit            ComputePublicKeys();

private:
  // Managing complaints
  ComplaintsManager       complaints_manager_;
  ComplaintAnswersManager complaint_answers_manager_;
  QualComplaintsManager   qual_complaints_manager_;

    // Members below protected by mutex
  mutable std::mutex               mutex_;
  std::unique_ptr<DkgImplemention> beacon_;

  // Counters for types of messages received
  std::set<CabinetIndex>                   shares_received_;
  std::set<CabinetIndex>                   coefficients_received_;
  std::set<CabinetIndex>                   qual_coefficients_received_;
  std::map<CabinetIndex, SharesExposedMap> reconstruction_shares_received_;
  std::set<CabinetIndex>                   valid_dkg_members_;

  /// @name Helper methods
  /// @{
  std::set<CabinetIndex> ComputeComplaints();
  void     CheckComplaintAnswers();
  uint32_t QualSize();
  /// @}
};
}  // namespace beacon
}  // namespace fetch
