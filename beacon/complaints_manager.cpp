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

#include "complaints_manager.hpp"
#include "set_intersection.hpp"

#include <assert.h>
#include <cstdint>
#include <iostream>
#include <mutex>

namespace fetch {
namespace beacon {

void ComplaintsManager::ResetCabinet(Identifier const &address, uint32_t threshold)
{
  std::lock_guard<std::mutex> lock(mutex_);
  threshold_  = threshold;
  identifier_ = address;
  finished_   = false;
  complaints_counter_.clear();
  complaints_.clear();
  complaints_received_.clear();
}

void ComplaintsManager::AddComplaintAgainst(Identifier const &complaint_address)
{
  std::lock_guard<std::mutex> lock(mutex_);
  complaints_counter_[complaint_address].insert(identifier_);
}

void ComplaintsManager::AddComplaintsFrom(Identifier const &from, ComplaintsList const &complaints,
                                          Cabinet const &cabinet)
{
  std::lock_guard<std::mutex> lock(mutex_);
  // Check if we have received a complaints message from this node before and if not log that we
  // received a complaint message
  if (complaints_received_.find(from) != complaints_received_.end())
  {
    return;
  }

  // Only keep elements of complaints in cabinet
  auto cabinet_complaints = complaints & cabinet;
  complaints_received_.insert({from, cabinet_complaints});
}

void ComplaintsManager::Finish(std::set<Identifier> const &cabinet)
{
  std::lock_guard<std::mutex> lock(mutex_);

  assert(!finished_);
  assert(complaints_.empty());

  for (auto const &from : cabinet)
  {
    if (from == identifier_)
    {
      continue;
    }

    // Add miners which did not send a complaint to complaints
    if (complaints_received_.find(from) == complaints_received_.end())
    {
      complaints_.insert(from);
    }
    else
    {
      auto complaints = complaints_received_.at(from);
      for (auto const &bad_node : complaints)
      {
        if (cabinet.find(bad_node) != cabinet.end())
        {
          complaints_counter_[bad_node].insert(from);
        }
      }
    }
  }

  // All miners who have received threshold or more complaints are also disqualified
  for (auto const &member : complaints_counter_)
  {
    if (member.second.size() >= threshold_)
    {
      complaints_.insert(member.first);
    }
  }
  complaints_received_.clear();
  finished_ = true;
}

uint32_t ComplaintsManager::NumComplaintsReceived(std::set<Identifier> const &cabinet) const
{
  std::lock_guard<std::mutex> lock(mutex_);

  std::set<Identifier> complaint_senders;
  for (auto const &member : complaints_received_)
  {
    complaint_senders.insert(member.first);
  }

  auto cabinet_complaints = complaint_senders & cabinet;
  return static_cast<uint32_t>(cabinet_complaints.size());
}

std::unordered_set<ComplaintsManager::Identifier> ComplaintsManager::ComplaintsAgainstSelf() const
{
  std::lock_guard<std::mutex> lock(mutex_);
  assert(finished_);
  auto iter = complaints_counter_.find(identifier_);
  if (iter == complaints_counter_.end())
  {
    return {};
  }
  return complaints_counter_.at(identifier_);
}

bool ComplaintsManager::FindComplaint(Identifier const &complaint_address,
                                      Identifier const &complainer_address) const
{
  std::lock_guard<std::mutex> lock(mutex_);
  assert(finished_);
  auto iter = complaints_counter_.find(complaint_address);
  if (iter == complaints_counter_.end())
  {
    return false;
  }
  return (complaints_counter_.at(complaint_address).find(complainer_address) !=
          complaints_counter_.at(complaint_address).end());
}

uint32_t ComplaintsManager::ComplaintsCount(Identifier const &address) const
{
  std::lock_guard<std::mutex> lock(mutex_);
  assert(finished_);
  auto iter = complaints_counter_.find(address);
  if (iter == complaints_counter_.end())
  {
    return 0;
  }
  return static_cast<uint32_t>(complaints_counter_.at(address).size());
}

std::set<ComplaintsManager::Identifier> ComplaintsManager::Complaints() const
{
  std::lock_guard<std::mutex> lock(mutex_);
  assert(finished_);
  return complaints_;
}

void ComplaintAnswersManager::Init(ComplaintsList const &complaints)
{
  std::lock_guard<std::mutex> lock(mutex_);
  std::copy(complaints.begin(), complaints.end(), std::inserter(complaints_, complaints_.begin()));
}

void ComplaintAnswersManager::ResetCabinet()
{
  std::lock_guard<std::mutex> lock(mutex_);
  finished_ = false;
  complaints_.clear();
  complaint_answers_received_.clear();
}

void ComplaintAnswersManager::AddComplaintAgainst(Identifier const &member)
{
  std::lock_guard<std::mutex> lock(mutex_);
  complaints_.insert(member);
}

void ComplaintAnswersManager::AddComplaintAnswerFrom(Identifier const &from,
                                                     Answer const &    complaint_answer)
{
  std::lock_guard<std::mutex> lock(mutex_);
  if (complaint_answers_received_.find(from) != complaint_answers_received_.end())
  {
    return;
  }
  complaint_answers_received_.insert({from, complaint_answer});
}

void ComplaintAnswersManager::Finish(Cabinet const &cabinet, Identifier const &node_id)
{
  std::lock_guard<std::mutex> lock(mutex_);
  assert(!finished_);

  ComplaintAnswers cabinet_answers;
  // Add miners which did not send a complaint answer to complaints
  for (auto const &cab : cabinet)
  {
    if (cab == node_id)
    {
      continue;
    }
    if (complaint_answers_received_.find(cab) == complaint_answers_received_.end())
    {
      complaints_.insert(cab);
    }
    else
    {
      cabinet_answers.insert({cab, complaint_answers_received_.at(cab)});
    }
  }

  // Only keep answers from members of cabinet
  complaint_answers_received_ = cabinet_answers;
  finished_                   = true;
}

uint32_t ComplaintAnswersManager::NumComplaintAnswersReceived(Cabinet const &cabinet) const
{
  std::lock_guard<std::mutex> lock(mutex_);
  std::set<Identifier>        complaint_answer_senders;
  for (auto const &member : complaint_answers_received_)
  {
    complaint_answer_senders.insert(member.first);
  }
  auto cabinet_answers = complaint_answer_senders & cabinet;
  return static_cast<uint32_t>(cabinet_answers.size());
}

ComplaintAnswersManager::ComplaintAnswers ComplaintAnswersManager::ComplaintAnswersReceived() const
{
  std::lock_guard<std::mutex> lock(mutex_);
  assert(finished_);
  return complaint_answers_received_;
}

std::set<ComplaintAnswersManager::Identifier> ComplaintAnswersManager::BuildQual(
    Cabinet const &cabinet) const
{
  std::lock_guard<std::mutex> lock(mutex_);
  assert(finished_);
  std::set<Identifier> qual;
  std::set_difference(cabinet.begin(), cabinet.end(), complaints_.begin(), complaints_.end(),
                      std::inserter(qual, qual.begin()));
  return qual;
}

void QualComplaintsManager::Reset()
{
  std::lock_guard<std::mutex> lock(mutex_);
  finished_ = false;
  complaints_.clear();
  complaints_received_.clear();
}

void QualComplaintsManager::AddComplaintAgainst(Identifier const &id)
{
  std::lock_guard<std::mutex> lock(mutex_);
  complaints_.insert(id);
}

std::set<QualComplaintsManager::Identifier> QualComplaintsManager::Complaints() const
{
  std::lock_guard<std::mutex> lock(mutex_);
  assert(finished_);
  return complaints_;
}

void QualComplaintsManager::AddComplaintsFrom(Identifier const &      id,
                                              SharesExposedMap const &complaints)
{
  std::lock_guard<std::mutex> lock(mutex_);
  if (complaints_received_.find(id) != complaints_received_.end())
  {
    return;
  }
  complaints_received_.insert({id, complaints});
}

void QualComplaintsManager::Finish(Cabinet const &qual, Identifier const &node_id)
{
  std::lock_guard<std::mutex> lock(mutex_);
  if (!finished_)
  {
    QualComplaints qual_complaints;
    for (auto const &qualified_member : qual)
    {
      if (qualified_member == node_id)
      {
        continue;
      }
      if (complaints_received_.find(qualified_member) == complaints_received_.end())
      {
        complaints_.insert(qualified_member);
      }
      else
      {
        qual_complaints.insert({qualified_member, complaints_received_.at(qualified_member)});
      }
    }

    complaints_received_ = qual_complaints;
    finished_            = true;
  }
}

uint32_t QualComplaintsManager::NumComplaintsReceived(Cabinet const &qual) const
{
  std::lock_guard<std::mutex> lock(mutex_);
  uint32_t                    qual_complaints{0};
  for (auto const &mem : qual)
  {
    if (complaints_received_.find(mem) != complaints_received_.end())
    {
      qual_complaints++;
    }
  }
  return qual_complaints;
}

QualComplaintsManager::QualComplaints QualComplaintsManager::ComplaintsReceived() const
{
  std::lock_guard<std::mutex> lock(mutex_);
  assert(finished_);
  return complaints_received_;
}

std::size_t QualComplaintsManager::ComplaintsSize() const
{
  std::lock_guard<std::mutex> lock(mutex_);
  assert(finished_);
  return complaints_.size();
}

bool QualComplaintsManager::FindComplaint(Identifier const &id) const
{
  std::lock_guard<std::mutex> lock(mutex_);
  assert(finished_);
  return complaints_.find(id) != complaints_.end();
}

}  // namespace beacon
}  // namespace fetch
