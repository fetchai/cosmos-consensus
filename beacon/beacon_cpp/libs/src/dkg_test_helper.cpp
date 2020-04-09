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

#include "dkg_test_helper.hpp"
#include "mcl_crypto.hpp"
#include "serialisers.hpp"

namespace fetch {
namespace beacon {   
 
 void MutateShare(std::string &msg, Failure failure) 
{   
  switch (failure)
  {
  case Failure::BAD_SHARE:
  {
    std::pair<std::string, std::string> shares;  
    mcl::PrivateKey fake{2};
    mcl::PrivateKey fake2{10};
    shares = {fake.ToString(), fake2.ToString()};
    msg = serialisers::Serialise(shares);
    break;
  }
  case Failure::MESSAGES_WITH_INVALID_CRYPTO:
  {
    std::pair<std::string, std::string> shares;  
    shares = {"garbage", "garbage2"};
    msg = serialisers::Serialise(shares);
    break;
  }
  }  
}

void MutateCoefficient(std::string &msg, Failure failure) 
{
  switch (failure)
  {
  case Failure::BAD_COEFFICIENT:
  {
    std::vector<std::string> coeff;  
    mcl::PublicKey fake;
    coeff.push_back(fake.ToString());
    msg = serialisers::Serialise(coeff);
  break;
  }
  case Failure::MESSAGES_WITH_INVALID_CRYPTO:
  {
    std::vector<std::string> coeff;  
    serialisers::Deserialise(msg, coeff);
    for (auto elem : coeff) 
    {
      elem += "garbage";
    }
    msg = serialisers::Serialise(coeff);
  }
  break;
  }
}

void MutateComplaint(std::string &msg, Failure failure) 
{
  if (failure == Failure::MESSAGES_WITH_UNKNOWN_INDEX)
  {
    std::set<uint32_t> complaints;  
    serialisers::Deserialise(msg, complaints);
    complaints.insert(-1);
    msg = serialisers::Serialise(complaints);
  }
}

void InvalidIndexExposedShare(std::unordered_map<uint32_t, std::pair<std::string, std::string>> &exposed_shares) 
{
  mcl::PrivateKey fake;  
  exposed_shares[-1] = {fake.ToString(), fake.ToString()};
}

void InvalidCryptoExposedShare(std::unordered_map<uint32_t, std::pair<std::string, std::string>> &exposed_shares) 
{ 
  for (auto &elem : exposed_shares) 
  {
    elem.second = {"garbage", "garbage2"};
  }
}

void MutateComplaintAnswer(std::string &msg, Failure failure) 
{
  std::unordered_map<uint32_t, std::pair<std::string, std::string>> exposed_shares;
  serialisers::Deserialise(msg, exposed_shares);
  switch (failure)
  {
  case Failure::MESSAGES_WITH_UNKNOWN_INDEX:
    InvalidIndexExposedShare(exposed_shares);
    break;
  case Failure::MESSAGES_WITH_INVALID_CRYPTO:
    InvalidCryptoExposedShare(exposed_shares);  
    break;
  case Failure::EMPTY_COMPLAINT_ANSWER:
    exposed_shares.clear();
    break;
  }
  msg = serialisers::Serialise(exposed_shares);
}

void MutateQualCoefficient(std::string &msg, Failure failure) 
{
  switch (failure)
  {
  case Failure::BAD_QUAL_COEFFICIENT:
  {
    std::vector<std::string> coeff;  
    mcl::PublicKey fake;
    coeff.push_back(fake.ToString());
    msg = serialisers::Serialise(coeff);
    break;
  }
  case Failure::QUAL_MESSAGES_WITH_INVALID_CRYPTO:
  {
    std::vector<std::string> coeff;  
    serialisers::Deserialise(msg, coeff);
    for (auto elem : coeff) 
    {
      elem += "garbage";
    }
    msg = serialisers::Serialise(coeff);
    break;
  }
  }
}

void MutateQualComplaint(std::string &msg, Failure failure) 
{
  std::unordered_map<uint32_t, std::pair<std::string, std::string>> exposed_shares;
  serialisers::Deserialise(msg, exposed_shares);
  switch (failure)
  {
  case Failure::MESSAGES_WITH_UNKNOWN_INDEX:
    InvalidIndexExposedShare(exposed_shares);
    break;
  case Failure::QUAL_MESSAGES_WITH_INVALID_CRYPTO:
    InvalidCryptoExposedShare(exposed_shares);  
    break;
  case Failure::FALSE_QUAL_COMPLAINT:
    mcl::PrivateKey fake;  
    exposed_shares[0] = {fake.ToString(), fake.ToString()};
    break;
  }
  msg = serialisers::Serialise(exposed_shares);
}

void MutateReconstructionShare(std::string &msg, Failure failure) 
{
  std::unordered_map<uint32_t, std::pair<std::string, std::string>> exposed_shares;
  serialisers::Deserialise(msg, exposed_shares);
  switch (failure)
  {
  case Failure::MESSAGES_WITH_UNKNOWN_INDEX:
    InvalidIndexExposedShare(exposed_shares);
    break;
  case Failure::QUAL_MESSAGES_WITH_INVALID_CRYPTO:
    InvalidCryptoExposedShare(exposed_shares);  
    break;
  case Failure::WITHHOLD_RECONSTRUCTION_SHARE:
    exposed_shares.clear();
    break;
  }
  msg = serialisers::Serialise(exposed_shares);
}

std::string MutateMsg(std::string msg, DKGMessageType type, Failure failure) 
{
  switch (type) 
  {
  case DKGMessageType::SHARE:
    MutateShare(msg, failure);
    break;    
  case DKGMessageType::COEFFICIENT: 
    MutateCoefficient(msg, failure);
    break;
  case DKGMessageType::COMPLAINT:
    MutateComplaint(msg, failure);
    break;
  case DKGMessageType::COMPLAINT_ANSWER:
    MutateComplaintAnswer(msg, failure);
    break;
  case DKGMessageType::QUAL_COEFFICIENT:
    MutateQualCoefficient(msg, failure);
    break;
  case DKGMessageType::QUAL_COMPLAINT:
    MutateQualComplaint(msg, failure);
    break;
  case DKGMessageType::RECONSTRUCTION_SHARE:
    MutateReconstructionShare(msg, failure);
    break;
  default:
    assert(false);  
  }  
  return msg;
}

}  // beacon
}  // fetch