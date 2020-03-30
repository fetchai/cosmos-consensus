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

#include "beacon_manager.hpp"
#include "mcl_crypto.hpp"

#include <mutex>
#include <type_traits>
#include <utility>

namespace fetch {
namespace beacon {
namespace {

class CurveParameters
{
private:
struct Params
{
  BeaconManager::PrivateKey zeroFr_{};

  BeaconManager::Generator group_g_{};
  BeaconManager::Generator group_h_{};
};

std::unique_ptr<Params> params_;
std::mutex mutex_;

public:
  // Construction / Destruction
  CurveParameters()                        = default;
  CurveParameters(CurveParameters const &) = delete;
  CurveParameters(CurveParameters &&)      = delete;
  ~CurveParameters()                       = default;

  BeaconManager::PrivateKey const &GetZeroFr()
  {
    EnsureInitialised();
    std::lock_guard<std::mutex> lock(mutex_);
    return params_->zeroFr_;
  }

  BeaconManager::Generator const &GetGroupG()
  {
    EnsureInitialised();
    std::lock_guard<std::mutex> lock(mutex_);
    return params_->group_g_;
  }

  BeaconManager::Generator const &GetGroupH()
  {
    EnsureInitialised();
    std::lock_guard<std::mutex> lock(mutex_);
    return params_->group_h_;
  }

  void EnsureInitialised()
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!params_)
    {
      params_ = std::make_unique<Params>();
      beacon::mcl::SetGenerators(params_->group_g_, params_->group_h_);
    }
  }

// Operators
  CurveParameters &operator=(CurveParameters const &) = delete;
  CurveParameters &operator=(CurveParameters &&) = delete;
};

CurveParameters curve_params_{};

}  // namespace

constexpr char const *LOGGING_NAME = "BeaconManager";

BeaconManager::BeaconManager()
{
  curve_params_.EnsureInitialised();
}

BeaconManager::~BeaconManager() = default;

void BeaconManager::GenerateCoefficients()
{
  std::vector<PrivateKey> a_i(polynomial_degree_ + 1, GetZeroFr());
  std::vector<PrivateKey> b_i(polynomial_degree_ + 1, GetZeroFr());
  for (CabinetIndex k = 0; k <= polynomial_degree_; k++)
  {
    a_i[k].setRand();
    b_i[k].setRand();
  }

  for (CabinetIndex k = 0; k <= polynomial_degree_; k++)
  {
    *C_ik[cabinet_index_][k] =
        beacon::mcl::ComputeLHS(*g__a_i[k], GetGroupG(), GetGroupH(), a_i[k], b_i[k]);
  }

  for (CabinetIndex l = 0; l < cabinet_size_; l++)
  {
    beacon::mcl::ComputeShares(*s_ij[cabinet_index_][l], *sprime_ij[cabinet_index_][l], a_i, b_i, l);
  }
}

std::vector<BeaconManager::Coefficient> BeaconManager::GetCoefficients()
{
  std::vector<Coefficient> coefficients;
  for (CabinetIndex k = 0; k <= polynomial_degree_; k++)
  {
    coefficients.emplace_back(C_ik[cabinet_index_][k]->ToString());
  }
  return coefficients;
}

std::pair<BeaconManager::Share, BeaconManager::Share> BeaconManager::GetOwnShares(
    CabinetIndex const &receiver_index)
{
  std::pair<Share, Share> shares_j{s_ij[cabinet_index_][receiver_index]->ToString(), sprime_ij[cabinet_index_][receiver_index]->ToString()};
  return shares_j;
}

std::pair<BeaconManager::Share, BeaconManager::Share> BeaconManager::GetReceivedShares(
    CabinetIndex const &owner)
{
  std::pair<Share, Share> shares_j{s_ij[owner][cabinet_index_]->ToString(),
                                   sprime_ij[owner][cabinet_index_]->ToString()};
  return shares_j;
}

void BeaconManager::AddCoefficients(CabinetIndex const &           from,
                                    std::vector<Coefficient> const &coefficients)
{
  if (coefficients.size() == polynomial_degree_ + 1)
  {
    for (CabinetIndex i = 0; i <= polynomial_degree_; ++i)
    {
      C_ik[from][i]->FromString(coefficients[i]);
    }
    return;
  }
}

void BeaconManager::AddShares(CabinetIndex const &from_index, std::pair<Share, Share> const &shares)
{
  s_ij[from_index][cabinet_index_]->FromString(shares.first);
  sprime_ij[from_index][cabinet_index_]->FromString(shares.second);
}

/**
 * Checks coefficients broadcasted by cabinet member c_i is consistent with the secret shares
 * received from c_i. If false then add to complaints
 *
 * @return Set of muddle addresses of nodes we complain against
 */
std::set<BeaconManager::CabinetIndex> BeaconManager::ComputeComplaints(std::set<CabinetIndex> const &coeff_received)
{
  std::set<CabinetIndex> complaints;
  for (auto &i : coeff_received)
  {
    if (i != cabinet_index_)
    {
      PublicKey rhs;
      PublicKey lhs;
      lhs = beacon::mcl::ComputeLHS(*g__s_ij[i][cabinet_index_], GetGroupG(), GetGroupH(),
                                    *s_ij[i][cabinet_index_], *sprime_ij[i][cabinet_index_]);
      rhs = beacon::mcl::ComputeRHS(cabinet_index_, C_ik[i]);
      if (lhs != rhs || lhs.isZero())
      {
        complaints.insert(i);
      }
    }
  }
  return complaints;
}

bool BeaconManager::VerifyComplaintAnswer(CabinetIndex const &from_index, ComplaintAnswer const &answer)
{
  CabinetIndex reporter_index = answer.first;
  // Verify shares received
  PrivateKey s{answer.second.first};
  PrivateKey sprime{answer.second.second};
  PublicKey  lhsG;
  PublicKey  rhsG;
  rhsG   = beacon::mcl::ComputeRHS(reporter_index, C_ik[from_index]);
  lhsG   = beacon::mcl::ComputeLHS(GetGroupG(), GetGroupH(), s, sprime);
  if (lhsG != rhsG || lhsG.isZero())
  {
    return false;
  }

  if (reporter_index == cabinet_index_)
  {
    *s_ij[from_index][cabinet_index_]      = s;
    *sprime_ij[from_index][cabinet_index_] = sprime;
    bn::G2::mul(*g__s_ij[from_index][cabinet_index_], GetGroupG(), *s_ij[from_index][cabinet_index_]);
  }
  return true;
}

void BeaconManager::SetQual(std::set<CabinetIndex> qual) {
  qual_ = std::move(qual);
}

/**
 * If in qual a member computes individual share of the secret key and further computes and
 * broadcasts qual coefficients
 */
void BeaconManager::ComputeSecretShare()
{
   PrivateKey secret_share_temp;
  for (auto const &iq_index : qual_)
  {
    bn::Fr::add(secret_share_temp, secret_share_temp, *s_ij[iq_index][cabinet_index_]);
  }
  secret_share_ = secret_share_temp.ToString();
}

std::vector<BeaconManager::Coefficient> BeaconManager::GetQualCoefficients()
{
  std::vector<Coefficient> coefficients;
  for (std::size_t k = 0; k <= polynomial_degree_; k++)
  {
    *A_ik[cabinet_index_][k] = *g__a_i[k];
    coefficients.push_back(A_ik[cabinet_index_][k]->ToString());
  }
  return coefficients;
}

void BeaconManager::AddQualCoefficients(CabinetIndex const &           from_index,
                                        std::vector<Coefficient> const &coefficients)
{
  if (coefficients.size() == polynomial_degree_ + 1)
  {
    for (CabinetIndex i = 0; i <= polynomial_degree_; ++i)
    {
      A_ik[from_index][i]->FromString(coefficients[i]);
    }
    return;
  }
}

/**
 * Checks coefficients sent by qual members and puts their address and the secret shares we received
 * from them into a complaints maps if the coefficients are not valid
 *
 * @return Map of address and pair of secret shares for each qual member we wish to complain against
 */
BeaconManager::SharesExposedMap BeaconManager::ComputeQualComplaints(std::set<CabinetIndex> const &coeff_received)
{
  SharesExposedMap qual_complaints;

  for (auto const &i : qual_)
  {
    if (i != cabinet_index_)
    {
      if (std::find(coeff_received.begin(), coeff_received.end(), i) != coeff_received.end())
      {
        PublicKey rhs;
        PublicKey lhs;
        lhs = *g__s_ij[i][cabinet_index_];
        rhs = beacon::mcl::ComputeRHS(cabinet_index_, A_ik[i]);
        if (lhs != rhs || rhs.isZero())
        {
          qual_complaints.insert({i, {s_ij[i][cabinet_index_]->ToString(), sprime_ij[i][cabinet_index_]->ToString()}});
        }
      }
      else
      {
        qual_complaints.insert({i, {s_ij[i][cabinet_index_]->ToString(), sprime_ij[i][cabinet_index_]->ToString()}});
      }
    }
  }
  return qual_complaints;
}

BeaconManager::CabinetIndex BeaconManager::VerifyQualComplaint(CabinetIndex const &  from_index,
                                                                ComplaintAnswer const &answer)
{
  CabinetIndex victim_index = answer.first;

  PublicKey  lhs;
  PublicKey  rhs;
  PrivateKey s{answer.second.first};
  PrivateKey sprime{answer.second.second};
  lhs    = beacon::mcl::ComputeLHS(GetGroupG(), GetGroupH(), s, sprime);
  rhs    = beacon::mcl::ComputeRHS(from_index, C_ik[victim_index]);
  if (lhs != rhs || lhs.isZero())
  {
    return from_index;
  }

  bn::G2::mul(lhs, GetGroupG(), s);  // G^s
  rhs = beacon::mcl::ComputeRHS(from_index, A_ik[victim_index]);
  if (lhs != rhs || rhs.isZero())
  {
   return answer.first;
  }

  return from_index;
}

/**
 * Compute group public key and individual public key shares
 */
void BeaconManager::ComputePublicKeys()
{
  PublicKey public_key_temp;  
  // For all parties in $QUAL$, set $y_i = A_{i0}
  for (auto const &it : qual_)
  {
    *y_i[it]         = *A_ik[it][0];
  }
  // Compute public key $y = \prod_{i \in QUAL} y_i \bmod p$
  for (auto const &it : qual_)
  {
    bn::G2::add(public_key_temp, public_key_temp, *y_i[it]);
  }
  // Compute public_key_shares_ $v_j = \prod_{i \in QUAL} \prod_{k=0}^t (A_{ik})^{j^k} \bmod
  // p$
  for (auto const &jt : qual_)
  {
    for (auto const &it : qual_)
    {
      bn::G2::add(*public_key_shares_[jt], *public_key_shares_[jt], *A_ik[it][0]);
      beacon::mcl::UpdateRHS(jt, *public_key_shares_[jt], A_ik[it]);
    }
  }
  public_key_ = public_key_temp.ToString();
}

void BeaconManager::AddReconstructionShare(CabinetIndex const &index)
{
  if (reconstruction_shares.find(index) == reconstruction_shares.end())
  {
    mcl::Init(reconstruction_shares[index].second, cabinet_size_);
  }
  reconstruction_shares.at(index).first.insert(cabinet_index_);
  *reconstruction_shares.at(index).second[cabinet_index_] = *s_ij[index][cabinet_index_];
}

void BeaconManager::AddReconstructionShare(CabinetIndex const &                 from_index,
                                           std::pair<CabinetIndex, Share> const &share)
{
  if (reconstruction_shares.find(share.first) == reconstruction_shares.end())
  {
    mcl::Init(reconstruction_shares[share.first].second, cabinet_size_);
  }
  else if (!reconstruction_shares.at(share.first).second[from_index]->isZero())
  {
    return;
  }
  PrivateKey s{share.second};
  reconstruction_shares.at(share.first).first.insert(from_index);
  *reconstruction_shares.at(share.first).second[from_index] = s;
}

void BeaconManager::VerifyReconstructionShare(CabinetIndex const &from, ExposedShare const &share)
{
  CabinetIndex victim_index = share.first;
  PublicKey    lhs;
  PublicKey    rhs;
  PrivateKey   s{share.second.first};
  PrivateKey   sprime{share.second.second};
  lhs    = beacon::mcl::ComputeLHS(GetGroupG(), GetGroupH(), s, sprime);
  rhs    = beacon::mcl::ComputeRHS(from, C_ik[victim_index]);

  if (lhs == rhs && !lhs.isZero())
  {
    AddReconstructionShare(from, {share.first, share.second.first});
  }
}

/**
 * Run polynomial interpolation on the exposed secret shares of other cabinet members to
 * recontruct their random polynomials
 *
 * @return Bool for whether reconstruction from shares was successful
 */
bool BeaconManager::RunReconstruction()
{
  std::vector<std::vector<PrivateKey>>a_ik;
  a_ik.resize(static_cast<CabinetIndex>(cabinet_size_));
  a_ik.resize(static_cast<CabinetIndex>(polynomial_degree_ + 1));
  for (auto const &in : reconstruction_shares)
  {
    CabinetIndex            victim_index = in.first;
    std::set<CabinetIndex>  parties{in.second.first};
    if (in.first == cabinet_index_)
    {
      // Do not run reconstruction for myself
      continue;
    }
    if (parties.size() <= polynomial_degree_)
    {
      // Do not have enough good shares to be able to do reconstruction
      return false;
    }
    std::vector<PrivateKey> points;
    std::vector<PrivateKey> shares_f;
    for (const auto &index : parties)
    {
      points.emplace_back(index + 1);  // adjust index in computation
      shares_f.push_back(*in.second.second[index]);
    }
    a_ik[victim_index] = beacon::mcl::InterpolatePolynom(points, shares_f);
    for (std::size_t k = 0; k <= polynomial_degree_; k++)
    {
      bn::G2::mul(*A_ik[victim_index][k], GetGroupG(), a_ik[victim_index][k]);
    }
  }
  return true;
}

/**
 * @brief resets the class back to a state where a new cabinet is set up.
 * @param cabinet_size is the size of the cabinet.
 * @param threshold is the threshold to be able to generate a signature.
 */
void BeaconManager::NewCabinet(CabinetIndex cabinet_size, CabinetIndex threshold, CabinetIndex index)
{
  assert(threshold > 0);
  cabinet_size_      = cabinet_size;
  polynomial_degree_ = threshold - 1;
  cabinet_index_ = index;

  Reset();
}

void BeaconManager::Reset()
{
  secret_share_ = {};
  public_key_ = {};
  beacon::mcl::Init(public_key_shares_, cabinet_size_);
  beacon::mcl::Init(y_i, cabinet_size_);
  beacon::mcl::Init(s_ij, cabinet_size_, cabinet_size_);
  beacon::mcl::Init(sprime_ij, cabinet_size_, cabinet_size_);
  beacon::mcl::Init(C_ik, cabinet_size_, polynomial_degree_ + 1);
  beacon::mcl::Init(A_ik, cabinet_size_, polynomial_degree_ + 1);
  beacon::mcl::Init(g__s_ij, cabinet_size_, cabinet_size_);
  beacon::mcl::Init(g__a_i, polynomial_degree_ + 1);

  qual_.clear();
  reconstruction_shares.clear();
}

bool BeaconManager::InQual(CabinetIndex const &index) const
{
  return std::find(qual_.begin(), qual_.end(), index) != qual_.end();
}

std::set<BeaconManager::CabinetIndex> const &BeaconManager::qual() const
{
  return qual_;
}

BeaconManager:: CabinetIndex BeaconManager::cabinet_index() const 
{
  return cabinet_index_;
}

BeaconManager::CabinetIndex BeaconManager::polynomial_degree() const
{
  return polynomial_degree_;
}

BeaconManager::CabinetIndex BeaconManager::cabinet_size() const
{
  return cabinet_size_;
}

DKGKeyInformation              BeaconManager::GetDkgOutput() const {
  auto output = DKGKeyInformation();
  output.group_public_key = public_key_;
  output.private_key = secret_share_;
  for (auto i = 0; i < public_key_shares_.size(); i++) {
    output.public_key_shares.push_back(public_key_shares_[i]->ToString());
  }
  return output;
}

BeaconManager::Generator const &BeaconManager::GetGroupG()
{
  return curve_params_.GetGroupG();
}

BeaconManager::Generator const &BeaconManager::GetGroupH()
{
  return curve_params_.GetGroupH();
}

BeaconManager::PrivateKey const &BeaconManager::GetZeroFr()
{
  return curve_params_.GetZeroFr();
}

}  // namespace dkg
}  // namespace fetch
