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

class BeaconManager;

class BeaconSetupService
{
public:
  using CabinetIndex       = uint32_t;
  using Identifier         = CabinetIndex;
  using MessageCoefficient = std::string;
  using MessageShare       = std::string;
  using SharesExposedMap   = std::map<Identifier, std::pair<MessageShare, MessageShare>>;

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
  std::vector<MessageCoefficient>       GetCoefficients();
  std::pair<MessageShare, MessageShare> GetShare(Identifier index);
  void                                  GetComplaints(std::vector<Identifier> &complaints);
  SharesExposedMap                      GetComplaintAnswers();
  std::vector<MessageCoefficient>       GetQualCoefficients();
  SharesExposedMap                      GetQualComplaints();
  SharesExposedMap                      GetReconstructionShares();
  /// @}

  /// @name Handlers for messages
  /// @{
  void OnShares(std::pair<MessageShare, MessageShare> const &shares, const Identifier &from);
  void OnCoefficients(std::vector<MessageCoefficient> const &coefficients, Identifier const &from);
  void OnComplaints(std::vector<Identifier> const &msg, Identifier const &from);
  void OnComplaintAnswers(SharesExposedMap const &answer, Identifier const &from);
  void OnQualCoefficients(std::vector<MessageCoefficient> const &msg, Identifier const &from);
  void OnQualComplaints(SharesExposedMap const &shares_msg, Identifier const &from);
  void OnReconstructionShares(SharesExposedMap const &shares_msg, Identifier const &from);
  /// @}

  std::vector<Identifier> BuildQual();
  bool                    CheckQualComplaints();
  bool                    RunReconstruction();
  DKGKeyInformation       ComputePublicKeys();

private:
  // Managing complaints
  ComplaintsManager       complaints_manager_;
  ComplaintAnswersManager complaint_answers_manager_;
  QualComplaintsManager   qual_complaints_manager_;

  // Counters for types of messages received
  std::set<CabinetIndex>                   shares_received_;
  std::set<CabinetIndex>                   coefficients_received_;
  std::set<CabinetIndex>                   qual_coefficients_received_;
  std::map<CabinetIndex, SharesExposedMap> reconstruction_shares_received_;
  std::set<CabinetIndex>                   valid_dkg_members_;

  /// @name Helper function
  /// @{
  std::set<CabinetIndex> ComputeComplaints();
  /// @}

  // Members below protected by mutex
  mutable std::mutex             mutex_;
  std::unique_ptr<BeaconManager> beacon_;

  /// @name Helper methods
  /// @{
  void     CheckComplaintAnswers();
  uint32_t QualSize();
  /// @}
};
}  // namespace beacon
}  // namespace fetch
