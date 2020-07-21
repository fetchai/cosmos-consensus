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

#include "aeon_exec_unit.hpp"
#include "mcl_crypto.hpp"

#include <array>
#include <unordered_map>
#include <cstdint>
#include <cstddef>
#include <iostream>
#include <mutex>
#include <memory>

namespace fetch {
namespace beacon {    

/**
 * This class implemnents defines the functions required for the DKG
 */

template<class CryptoVerificationKey>
class BaseDkg {
public:
  using PrivateKey = mcl::PrivateKey;
  using Signature = mcl::Signature;
  using GroupPublicKey = mcl::GroupPublicKey;
  using VerificationKey = CryptoVerificationKey;
  using MessagePayload = std::string;
  using CabinetIndex     = uint32_t;
  using Share            = std::string;
  using Coefficient      = std::string;
  using ComplaintAnswer  = std::pair<CabinetIndex, std::pair<Share, Share>>;
  using ExposedShare     = std::pair<CabinetIndex, std::pair<Share, Share>>;
  using SharesExposedMap = std::unordered_map<CabinetIndex, std::pair<Share, Share>>;

  virtual ~BaseDkg() = default;
  virtual VerificationKey GetGroupG() const = 0;
  virtual VerificationKey GetGroupH() const = 0;
  virtual PrivateKey GetZeroFr() const = 0;
  virtual void NewCabinet(CabinetIndex cabinet_size, CabinetIndex threshold, CabinetIndex index) = 0;
  virtual void GenerateCoefficients() = 0;
  virtual std::vector<Coefficient> GetQualCoefficients() = 0;
  virtual void AddQualCoefficients(CabinetIndex const &from_index,std::vector<Coefficient> const &coefficients) = 0;
  virtual SharesExposedMap ComputeQualComplaints(std::set<CabinetIndex> const &coeff_received) const = 0;
  virtual CabinetIndex VerifyQualComplaint(CabinetIndex const & from_index, ComplaintAnswer const &answer) = 0;
  virtual bool RunReconstruction() = 0;
  virtual void ComputePublicKeys() = 0;
  virtual std::shared_ptr<BaseAeon> GetDkgOutput() const = 0;
  
  std::vector<Coefficient> GetCoefficients()
  {
    std::vector<Coefficient> coefficients;
    for (CabinetIndex k = 0; k <= polynomial_degree_; k++)
    {
      coefficients.emplace_back(C_ik_[cabinet_index_][k].ToString());
    }
    return coefficients;
  }

  std::pair<Share, Share> GetOwnShares(CabinetIndex const &receiver_index)
  {
    std::pair<Share, Share> shares_j{s_ij_[cabinet_index_][receiver_index].ToString(),
                                   sprime_ij_[cabinet_index_][receiver_index].ToString()};
    return shares_j;
  }

  std::pair<Share, Share> GetReceivedShares(CabinetIndex const &owner)
  {
    std::pair<Share, Share> shares_j{s_ij_[owner][cabinet_index_].ToString(),
                                   sprime_ij_[owner][cabinet_index_].ToString()};
    return shares_j;
  }

  void AddShares(CabinetIndex const &from_index, std::pair<Share, Share> const &shares) {
    s_ij_[from_index][cabinet_index_].FromString(shares.first);
    sprime_ij_[from_index][cabinet_index_].FromString(shares.second);
 }

  void AddCoefficients(CabinetIndex const &from_index,
                                    std::vector<Coefficient> const &coefficients) {
    if (coefficients.size() == polynomial_degree_ + 1)
    {
      for (CabinetIndex i = 0; i <= polynomial_degree_; ++i)
      {
        C_ik_[from_index][i].FromString(coefficients[i]);
      }
    }
  }

  std::set<CabinetIndex> ComputeComplaints(std::set<CabinetIndex> const &coeff_received)
  {
    std::set<CabinetIndex> complaints;
    for (auto &i : coeff_received)
    {
      if (i != cabinet_index_)
      {
        VerificationKey rhs;
        VerificationKey lhs;
        lhs = mcl::ComputeLHS(secret_commitments_[i][cabinet_index_], GetGroupG(), GetGroupH(),
                                    s_ij_[i][cabinet_index_], sprime_ij_[i][cabinet_index_]);
        rhs = mcl::ComputeRHS(cabinet_index_, C_ik_[i]);
        if (lhs != rhs || lhs.isZero())
        {
          complaints.insert(i);
        }
      }
    }
    return complaints;
  }

  bool VerifyComplaintAnswer(CabinetIndex const &from_index, ComplaintAnswer const &answer) {
    CabinetIndex reporter_index = answer.first;
    PrivateKey s, sprime;
    VerificationKey lhsG, rhsG;

    if (s.FromString(answer.second.first) && sprime.FromString(answer.second.second)) 
    {
      rhsG = mcl::ComputeRHS(reporter_index, C_ik_[from_index]);
      lhsG = mcl::ComputeLHS(GetGroupG(), GetGroupH(), s, sprime);
      if (lhsG != rhsG || lhsG.isZero())
      {
        return false;
      }
     
      if (reporter_index == cabinet_index_) 
      {
        s_ij_[from_index][cabinet_index_] = s;
        sprime_ij_[from_index][cabinet_index_] = sprime;
        secret_commitments_[from_index][cabinet_index_].SetZero();
        secret_commitments_[from_index][cabinet_index_].Mult(GetGroupG(), s_ij_[from_index][cabinet_index_]);
      }
      return true;
    }
    return false;
  }

  void SetQual(std::set<CabinetIndex> qual)
  {
    qual_ = std::move(qual);
  }

  void ComputeSecretShare() 
  {
    secret_share_.SetZero();
    xprime_i_.SetZero();
    for (auto const &iq_index : qual_) {
      secret_share_.Add(secret_share_, s_ij_[iq_index][cabinet_index_]);
      xprime_i_.Add(xprime_i_, sprime_ij_[iq_index][cabinet_index_]);
    }
  }

  void AddReconstructionShare(CabinetIndex const &index) 
  {
    if (reconstruction_shares.find(index) == reconstruction_shares.end())
    {
      mcl::Init(reconstruction_shares[index].second, cabinet_size_);
    }
    reconstruction_shares.at(index).first.insert(cabinet_index_);
    reconstruction_shares.at(index).second[cabinet_index_] = s_ij_[index][cabinet_index_];
  }

  void VerifyReconstructionShare(CabinetIndex const &from, ExposedShare const &share) 
  {
    CabinetIndex victim_index = share.first;
    VerificationKey lhs, rhs;
    PrivateKey s, sprime;

    if (s.FromString(share.second.first) && sprime.FromString(share.second.second)) 
    {
      lhs = mcl::ComputeLHS(GetGroupG(), GetGroupH(), s, sprime);
      rhs = mcl::ComputeRHS(from, C_ik_[victim_index]);
      if (lhs == rhs && !lhs.isZero()) 
      {
        AddReconstructionShare(from, {share.first, share.second.first});
      }
    }
  }

  /// Property methods
  /// @{
  bool InQual(CabinetIndex const &index) const
  {
    return std::find(qual_.begin(), qual_.end(), index) != qual_.end();
  }
  std::set<CabinetIndex> const &qual() const
  {
    return qual_;
  }
  CabinetIndex cabinet_index() const {
    return cabinet_index_;
  }
  CabinetIndex polynomial_degree() const
  {
    return polynomial_degree_;
  }
  CabinetIndex cabinet_size() const
  {
    return cabinet_size_;
  }
  ///}

protected:
  // What the DKG should return
  PrivateKey             secret_share_;       ///< Share of group private key (x_i)
  GroupPublicKey              public_key_;         ///< Group public key (y)
  std::vector<VerificationKey> public_key_shares_;  ///< Public keys of cabinet generated by DKG (v_i)
  std::set<CabinetIndex> qual_;               ///< Set of qualified members

  CabinetIndex cabinet_size_;       ///< Size of cabinet
  CabinetIndex polynomial_degree_;  ///< Degree of polynomial in DKG
  CabinetIndex cabinet_index_;      ///< Index of our address in cabinet_

  // Temporary variables in DKG
  PrivateKey xprime_i_;
  std::vector<std::vector<PrivateKey> > s_ij_, sprime_ij_;
  std::vector<std::vector<VerificationKey>> C_ik_;
  std::vector<std::vector<VerificationKey>> A_ik_;
  std::vector<std::vector<VerificationKey>> secret_commitments_;

  std::unordered_map<CabinetIndex, std::pair<std::set<CabinetIndex>, std::vector<PrivateKey>>>
      reconstruction_shares;  ///< Map from id of node_i in complaints to a pair <parties which
  ///< exposed shares of node_i, the shares that were exposed>

  BaseDkg() = default;

  void AddReconstructionShare(CabinetIndex const &from_index,
                                           std::pair<CabinetIndex, Share> const &share) 
  {
    if (reconstruction_shares.find(share.first) == reconstruction_shares.end()) {
      mcl::Init(reconstruction_shares[share.first].second, cabinet_size_);
    }
    else if (!reconstruction_shares.at(share.first).second[from_index].isZero())
    {
      return;
    }
    PrivateKey s;
    if (s.FromString(share.second))
    {
      reconstruction_shares.at(share.first).first.insert(from_index);
      reconstruction_shares.at(share.first).second[from_index] = s;
    }
  }
};
} // beacon
} // fetch