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

#include "beacon_setup_service.hpp"
#include "bls_dkg.hpp"
#include "glow_dkg.hpp"
#include "logging.hpp"
#include "serialisers.hpp"
#include "set_intersection.hpp"

#include <assert.h>
#include <mutex>
#include <utility>

namespace fetch {
namespace beacon {

static constexpr char const *LOGGING_NAME = "BeaconSetupService";

BeaconSetupService::BeaconSetupService(Identifier cabinet_size, CabinetIndex threshold,
                                       Identifier index)
{
  if (index < 0 || index >= cabinet_size)
  {
    return;
  }

  beacon_ = std::make_unique<DkgImplemention>();
  beacon_->NewCabinet(cabinet_size, threshold, index);
  complaints_manager_.ResetCabinet(index, threshold);
  complaint_answers_manager_.ResetCabinet();
  qual_complaints_manager_.Reset();
  // Fill valid dkg members
  auto it = valid_dkg_members_.end();
  for (Identifier i = 0; i < cabinet_size; ++i)
  {
    it = valid_dkg_members_.insert(it, i);
  }

  beacon_->GenerateCoefficients();
}

BeaconSetupService::~BeaconSetupService() = default;

uint32_t BeaconSetupService::QualSize()
{
  // Set to 2/3n for now
  auto proposed_qual_size =
      static_cast<uint32_t>(beacon_->cabinet_size() - (beacon_->cabinet_size() / 3));
  if (proposed_qual_size <= beacon_->polynomial_degree())
  {
    proposed_qual_size = beacon_->polynomial_degree() + 1;
  }
  return proposed_qual_size;
}

bool BeaconSetupService::ReceivedAllCoefficientsAndShares() const
{
  std::lock_guard<std::mutex> lock(mutex_);
  auto intersection = (coefficients_received_ & shares_received_ & valid_dkg_members_);
  return intersection.size() == (valid_dkg_members_.size() - 1);
}

bool BeaconSetupService::ReceivedAllComplaints() const
{
  std::lock_guard<std::mutex> lock(mutex_);
  return complaints_manager_.NumComplaintsReceived(valid_dkg_members_) ==
         (valid_dkg_members_.size() - 1);
}

bool BeaconSetupService::ReceivedAllComplaintAnswers() const
{
  std::lock_guard<std::mutex> lock(mutex_);
  return complaint_answers_manager_.NumComplaintAnswersReceived(valid_dkg_members_) ==
         valid_dkg_members_.size();
}

bool BeaconSetupService::ReceivedAllQualCoefficients() const
{
  std::lock_guard<std::mutex> lock(mutex_);
  auto                        intersection = (qual_coefficients_received_ & beacon_->qual());
  return intersection.size() == (beacon_->qual().size() - 1);
}

bool BeaconSetupService::ReceivedAllQualComplaints() const
{
  std::lock_guard<std::mutex> lock(mutex_);
  return qual_complaints_manager_.NumComplaintsReceived(beacon_->qual()) ==
         (beacon_->qual().size() - 1);
}

bool BeaconSetupService::ReceivedAllReconstructionShares() const
{
  std::lock_guard<std::mutex> lock(mutex_);
  auto                        complaints_list = qual_complaints_manager_.Complaints();
  auto                        qual            = beacon_->qual();
  std::set<Identifier>        remaining_honest;
  std::set_difference(qual.begin(), qual.end(), complaints_list.begin(), complaints_list.end(),
                      std::inserter(remaining_honest, remaining_honest.begin()));

  uint16_t received_count = 0;
  for (auto const &member : remaining_honest)
  {
    if (member != beacon_->cabinet_index() &&
        reconstruction_shares_received_.find(member) != reconstruction_shares_received_.end())
    {
      received_count++;
    }
  }

  return received_count == (remaining_honest.size() - 1);
}

bool BeaconSetupService::RunReconstruction()
{
  std::lock_guard<std::mutex> lock(mutex_);
  // Process reconstruction shares. Reconstruction shares from non-qual members
  // or people in qual complaints should not be considered
  for (auto const &share : reconstruction_shares_received_)
  {
    Identifier from = share.first;
    if (qual_complaints_manager_.FindComplaint(from) || !beacon_->InQual(from))
    {
      continue;
    }
    for (auto const &elem : share.second)
    {
      // Check person who's shares are being exposed is a member of qual
      if (beacon_->InQual(elem.first))
      {
        beacon_->VerifyReconstructionShare(from, elem);
      }
    }
  }

  // Reset if reconstruction fails as this breaks the initial assumption on the
  // number of Byzantine nodes
  return beacon_->RunReconstruction();
}

BeaconSetupService::AeonExecUnit BeaconSetupService::ComputePublicKeys()
{
  std::lock_guard<std::mutex> lock(mutex_);
  beacon_->ComputePublicKeys();
  auto aeon_ptr = std::dynamic_pointer_cast<AeonExecUnit>(beacon_-> GetDkgOutput());
  assert(aeon_ptr);
  return *aeon_ptr;
}

BeaconSetupService::SerialisedMsg BeaconSetupService::GetCoefficients()
{
  std::lock_guard<std::mutex>   lock(mutex_);
  return serialisers::Serialise(beacon_->GetCoefficients());
}

BeaconSetupService::SerialisedMsg BeaconSetupService::GetShare(Identifier index)
{
  std::lock_guard<std::mutex>   lock(mutex_);
  return serialisers::Serialise(beacon_->GetOwnShares(index));
}

/**
 * Get the set of nodes we are complaining against based on the secret shares and coefficients
 * sent to use. Also increments the number of complaints a given cabinet member has received with
 * our complaints
 */
BeaconSetupService::SerialisedMsg BeaconSetupService::GetComplaints()
{
  std::lock_guard<std::mutex>   lock(mutex_);
  return serialisers::Serialise(ComputeComplaints());
}

/**
 * For a complaint by cabinet member c_i against self we broadcast the secret share
 * we sent to c_i to all cabinet members. This serves as a round of defense against
 * complaints where a member reveals the secret share they sent to c_i to everyone to
 * prove that it is consistent with the coefficients they originally broadcasted
 */
BeaconSetupService::SerialisedMsg BeaconSetupService::GetComplaintAnswers()
{
  std::lock_guard<std::mutex> lock(mutex_);
  complaints_manager_.Finish(valid_dkg_members_);
  complaint_answers_manager_.Init(complaints_manager_.Complaints());

  SharesExposedMap complaint_answer;
  for (auto const &reporter : complaints_manager_.ComplaintsAgainstSelf())
  {
    complaint_answer.insert({reporter, beacon_->GetOwnShares(reporter)});
  }
  return serialisers::Serialise(complaint_answer);
}

/**
 * Get qual coefficients after computing own secret share
 */
BeaconSetupService::SerialisedMsg BeaconSetupService::GetQualCoefficients()
{
  std::lock_guard<std::mutex> lock(mutex_);
  beacon_->ComputeSecretShare();
  return serialisers::Serialise(beacon_->GetQualCoefficients());
}

/**
 * After constructing the qualified set (qual) and receiving new qual coefficients members
 * broadcast the secret shares s_ij, sprime_ij of all members in qual who sent qual coefficients
 * which failed verification
 */
BeaconSetupService::SerialisedMsg BeaconSetupService::GetQualComplaints()
{
  std::lock_guard<std::mutex> lock(mutex_);
  // Qual complaints consist of all nodes from which we did not receive qual shares, or verification
  // of qual shares failed
  auto complaints = beacon_->ComputeQualComplaints(qual_coefficients_received_);
  // Record own complaints
  for (auto const &mem : complaints)
  {
    qual_complaints_manager_.AddComplaintAgainst(mem.first);
  }
  Log(LogLevel::DEBUG, LOGGING_NAME, "GetQualComplaints(" + std::to_string(beacon_->cabinet_index()) + 
    "): size " + std::to_string(complaints.size()));
  return serialisers::Serialise(complaints);
}

/**
 * For all members that other nodes have complained against in qual we also broadcast
 * the secret shares we received from them to all cabinet members and collect the shares broadcasted
 * by others
 */
BeaconSetupService::SerialisedMsg BeaconSetupService::GetReconstructionShares()
{
  std::lock_guard<std::mutex> lock(mutex_);

  SharesExposedMap complaint_shares;
  for (auto const &in : qual_complaints_manager_.Complaints())
  {
    beacon_->AddReconstructionShare(in);
    complaint_shares.insert({in, beacon_->GetReceivedShares(in)});
  }
  return serialisers::Serialise(complaint_shares);
  ;
}

/**
 * Handler for submit shares used for members to send individual pairs of
 * secret shares to other cabinet members
 *
 * @param from Identifier of sender
 * @param shares Pair of secret shares
 */
void BeaconSetupService::OnShares(SerialisedMsg const &msg, const Identifier &from)
{
  std::lock_guard<std::mutex> lock(mutex_);
  assert(from < beacon_->cabinet_size());

  if (shares_received_.find(from) == shares_received_.end())
  {
    std::pair<Share, Share>       shares;
    if (serialisers::Deserialise(msg, shares)) {
      beacon_->AddShares(from, shares);
    }
    shares_received_.insert(from);
  }
}

/**
 * Handler for broadcasted coefficients
 *
 * @param coefficients Coefficients
 * @param from Identifier of sender
 */
void BeaconSetupService::OnCoefficients(SerialisedMsg const &msg, Identifier const &from)
{
  std::lock_guard<std::mutex> lock(mutex_);
  assert(from < beacon_->cabinet_size());

  if (coefficients_received_.find(from) == coefficients_received_.end())
  {
    std::vector<Coefficient>      coefficients;
    if (serialisers::Deserialise(msg, coefficients)) {
      beacon_->AddCoefficients(from, coefficients);
    }
    coefficients_received_.insert(from);
  }
}

/**
 * Handler for complaints message
 *
 * @param msg List of complaints
 * @param from Identifier of sender
 */
void BeaconSetupService::OnComplaints(SerialisedMsg const &msg, Identifier const &from)
{
  std::lock_guard<std::mutex> lock(mutex_);
  assert(from < beacon_->cabinet_size());

  std::set<Identifier>          complaints;
  serialisers::Deserialise(msg, complaints);
  Log(LogLevel::DEBUG, LOGGING_NAME, "OnComplaints(" + std::to_string(from) + "->" + 
    std::to_string(beacon_->cabinet_index()) + "): size " + std::to_string(complaints.size()));
  complaints_manager_.AddComplaintsFrom(from, complaints, valid_dkg_members_);
}

/**
 * Handler for complaints answer message containing the pairs of secret shares the sender sent to
 * members that complained against the sender
 *
 * @param answer Map of exposed shares
 * @param from Identifier of sender
 */
void BeaconSetupService::OnComplaintAnswers(SerialisedMsg const &msg, Identifier const &from)
{
  std::lock_guard<std::mutex> lock(mutex_);
  assert(from < beacon_->cabinet_size());

  SharesExposedMap              answer;
  serialisers::Deserialise(msg, answer);
  Log(LogLevel::DEBUG, LOGGING_NAME, "OnComplaintsAnswer(" + std::to_string(from) + "->" +
    std::to_string(beacon_->cabinet_index()) + "): size " + std::to_string(answer.size()));
  complaint_answers_manager_.AddComplaintAnswerFrom(from, answer);
}

/**
 * Handler for qual coefficients message which contains vector of qual coefficients
 *
 * @param coefficients qual coefficients
 * @param from Identifier of sender
 */
void BeaconSetupService::OnQualCoefficients(SerialisedMsg const &msg, Identifier const &from)
{
  std::lock_guard<std::mutex> lock(mutex_);
  assert(from < beacon_->cabinet_size());

  if (qual_coefficients_received_.find(from) == qual_coefficients_received_.end())
  {
    std::vector<Coefficient>      coefficients;
    if (serialisers::Deserialise(msg, coefficients)) {
      beacon_->AddQualCoefficients(from, coefficients);
    }
    qual_coefficients_received_.insert(from);
  }
}

/**
 * Handler for qual complaints message which contains the secret shares sender received from
 * members in qual complaints
 *
 * @param shares Map of exposed shares
 * @param from Identifier of sender
 */
void BeaconSetupService::OnQualComplaints(SerialisedMsg const &msg, Identifier const &from)
{
  std::lock_guard<std::mutex> lock(mutex_);
  assert(from < beacon_->cabinet_size());

  SharesExposedMap              shares;
  serialisers::Deserialise(msg, shares);
  Log(LogLevel::DEBUG, LOGGING_NAME, "OnQualComplaints(" + std::to_string(from) + "->" + 
    std::to_string(beacon_->cabinet_index()) + "): size " + std::to_string(shares.size()));
  qual_complaints_manager_.AddComplaintsFrom(from, shares);
}

/**
 * Handler for messages containing secret shares of qual members that other qual members have
 * complained against
 *
 * @param shares Map of exposed shares
 * @param from Identifier of sender
 */
void BeaconSetupService::OnReconstructionShares(SerialisedMsg const &msg, Identifier const &from)
{
  std::lock_guard<std::mutex> lock(mutex_);
  assert(from < beacon_->cabinet_size());

  if (reconstruction_shares_received_.find(from) == reconstruction_shares_received_.end())
  {
    SharesExposedMap              shares;
    serialisers::Deserialise(msg, shares);
    Log(LogLevel::DEBUG, LOGGING_NAME, "OnReconstructionShares(" + std::to_string(from) + "->" +
      std::to_string(beacon_->cabinet_index()) + "): size " + std::to_string(shares.size()));
    reconstruction_shares_received_.insert({from, shares});
  }
}

/**
 * Computes the set of nodes who did not send both shares and coefficients, or sent
 * values failing verification
 *
 * @return Set of identifiers of nodes which misbehaved
 */
std::set<BeaconSetupService::Identifier> BeaconSetupService::ComputeComplaints()
{
  std::set<Identifier> complaints_local;

  // Add nodes who did not send both coefficients and shares to complaints
  for (auto const &member : valid_dkg_members_)
  {
    if (member == beacon_->cabinet_index())
    {
      continue;
    }
    if (coefficients_received_.find(member) == coefficients_received_.end() ||
        shares_received_.find(member) == shares_received_.end())
    {
      complaints_local.insert(member);
    }
  }

  // Add nodes whos coefficients and shares failed verification to complaints
  auto verification_fail =
      beacon_->ComputeComplaints(coefficients_received_ & shares_received_ & valid_dkg_members_);
  complaints_local.insert(verification_fail.begin(), verification_fail.end());

  for (auto const &cab : complaints_local)
  {
    complaints_manager_.AddComplaintAgainst(cab);
  }
  Log(LogLevel::DEBUG, LOGGING_NAME, "ComputeComplaints(" + std::to_string(beacon_->cabinet_index()) +
    "): size " + std::to_string(complaints_local.size()));
  return complaints_local;
}

/**
 * For all complaint answers received in defense of a complaint we check the exposed secret share
 * is consistent with the broadcasted coefficients
 *
 */
void BeaconSetupService::CheckComplaintAnswers()
{
  auto answer_messages = complaint_answers_manager_.ComplaintAnswersReceived();
  for (auto const &sender_answers : answer_messages)
  {
    Identifier from = sender_answers.first;
    assert(valid_dkg_members_.find(from) != valid_dkg_members_.end());
    std::unordered_set<Identifier> answered_complaints;
    for (auto const &share : sender_answers.second)
    {
      // Check that the claimed submitter of the complaint actually did so
      if (complaints_manager_.FindComplaint(from, share.first))
      {
        answered_complaints.insert(share.first);
        if (!beacon_->VerifyComplaintAnswer(from, share))
        {
          complaint_answers_manager_.AddComplaintAgainst(from);
        }
      }
    }

    // If not all complaints against from_id are answered then add a complaint against it
    if (answered_complaints.size() != complaints_manager_.ComplaintsCount(from))
    {
      complaint_answers_manager_.AddComplaintAgainst(from);
    }
  }
}

/**
 * Builds the set of qualified members of the cabinet.  Altogether, complaints consists of
  // 1. Nodes which received over t complaints
  // 2. Complaint answers which were false

 * @return Set of qualified members
 */
CabinetIndex BeaconSetupService::BuildQual()
{
  std::lock_guard<std::mutex> lock(mutex_);
  complaint_answers_manager_.Finish(valid_dkg_members_, beacon_->cabinet_index());
  CheckComplaintAnswers();

  beacon_->SetQual(complaint_answers_manager_.BuildQual(valid_dkg_members_));

  // There should be no members in qual that are not in valid_dkg_members
  assert((beacon_->qual() & valid_dkg_members_) == beacon_->qual());
  if (std::find(beacon_->qual().begin(), beacon_->qual().end(), beacon_->cabinet_index()) == beacon_->qual().end())
  {
    return 0;
  }
  if (beacon_->qual().size() < QualSize())
  {
    return 0;
  }
  return static_cast<CabinetIndex>(beacon_->qual().size());
}

/**
 * Checks the complaints set by qual members
 */
bool BeaconSetupService::CheckQualComplaints()
{
  std::lock_guard<std::mutex> lock(mutex_);
  qual_complaints_manager_.Finish(beacon_->qual(), beacon_->cabinet_index());

  std::set<Identifier> qual{beacon_->qual()};
  for (const auto &complaint : qual_complaints_manager_.ComplaintsReceived())
  {
    Identifier sender = complaint.first;
    for (auto const &share : complaint.second)
    {
      // Check person who's shares are being exposed is not in QUAL then don't bother with checks
      if (qual.find(share.first) != qual.end())
      {
        qual_complaints_manager_.AddComplaintAgainst(beacon_->VerifyQualComplaint(sender, share));
      }
    }
  }

  std::size_t const size = qual_complaints_manager_.ComplaintsSize();

  // Reset if complaints is over threshold as this breaks the initial assumption on the
  // number of Byzantine nodes
  if (size > beacon_->polynomial_degree())
  {
    return false;
  }
  return true;
}

bool BeaconSetupService::InQual(const Identifier &index) {
  std::lock_guard<std::mutex> lock(mutex_);
 return beacon_->InQual(index);
}


std::string BeaconSetupService::Serialize() const {
  // We only serialize the items that are relevant for reconstruction
  if(!beacon_) {
    return "";
  }

  return std::string("bss_ser:") + beacon_->Serialize();
}

void BeaconSetupService::Deserialize(std::string const &from) const {
  if (from.rfind("titi", 0) == 0) {
    Log(LogLevel::ERROR, LOGGING_NAME, std::string("Failed to deser string that did not start with correct prefix. String: ") + from);
    return;
  } else {
    Log(LogLevel::ERROR, LOGGING_NAME, std::string("aasdfasdfFailed to deser string that did not start with correct prefix. String: ") + from);
  }
}

}  // namespace beacon
}  // namespace fetch
