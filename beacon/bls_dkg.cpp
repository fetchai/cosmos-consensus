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

#include "bls_dkg.hpp"

#include <memory>
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
    BlsDkg::PrivateKey zeroFr_{};

    BlsDkg::VerificationKey group_g_{};
    BlsDkg::VerificationKey group_h_{};
  };

  std::unique_ptr<Params> params_;
  std::mutex              mutex_;

public:
  // Construction / Destruction
  CurveParameters()                        = default;
  CurveParameters(CurveParameters const &) = delete;
  CurveParameters(CurveParameters &&)      = delete;
  ~CurveParameters()                       = default;

  BlsDkg::PrivateKey const &GetZeroFr()
  {
    EnsureInitialised();
    std::lock_guard<std::mutex> lock(mutex_);
    return params_->zeroFr_;
  }

  BlsDkg::VerificationKey const &GetGroupG()
  {
    EnsureInitialised();
    std::lock_guard<std::mutex> lock(mutex_);
    return params_->group_g_;
  }

  BlsDkg::VerificationKey const &GetGroupH()
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

BlsDkg::BlsDkg()
{
  curve_params_.EnsureInitialised();
}

void BlsDkg::NewCabinet(CabinetIndex cabinet_size, CabinetIndex threshold, CabinetIndex index) {
  assert(threshold > 0);
  this->cabinet_size_      = cabinet_size;
  this->polynomial_degree_ = threshold - 1;
  this->cabinet_index_     = index;

  this->secret_share_ = {};
  this->public_key_   = {};
  mcl::Init(this->public_key_shares_, cabinet_size_);
  mcl::Init(this->s_ij_, cabinet_size_, cabinet_size_);
  mcl::Init(this->sprime_ij_, cabinet_size_, cabinet_size_);
  mcl::Init(this->C_ik_, cabinet_size_, polynomial_degree_ + 1);
  mcl::Init(this->A_ik_, cabinet_size_, polynomial_degree_ + 1);
  mcl::Init(this->g__s_ij_, cabinet_size_, cabinet_size_);
  mcl::Init(this->g__a_i_, polynomial_degree_ + 1);

  this->qual_.clear();
  this->reconstruction_shares.clear();
}

void BlsDkg::GenerateCoefficients()
{
  std::vector<PrivateKey> a_i(polynomial_degree_ + 1, GetZeroFr());
  std::vector<PrivateKey> b_i(polynomial_degree_ + 1, GetZeroFr());
  for (CabinetIndex k = 0; k <= polynomial_degree_; k++)
  {
    a_i[k].Random();
    b_i[k].Random();
  }

  for (CabinetIndex k = 0; k <= polynomial_degree_; k++)
  {
    this->C_ik_[cabinet_index_][k] =
        mcl::ComputeLHS(g__a_i_[k], GetGroupG(), GetGroupH(), a_i[k], b_i[k]);
  }

  for (CabinetIndex l = 0; l < cabinet_size_; l++)
  {
    mcl::ComputeShares(this->s_ij_[cabinet_index_][l], this->sprime_ij_[cabinet_index_][l], a_i, b_i, l);
  }
}

std::vector<BlsDkg::Coefficient> BlsDkg::GetQualCoefficients()
{
  std::vector<Coefficient> coefficients;
  for (std::size_t k = 0; k <= polynomial_degree_; k++)
  {
    this->A_ik_[cabinet_index_][k] = g__a_i_[k];
    coefficients.push_back(this->A_ik_[cabinet_index_][k].ToString());
  }
  return coefficients;
}

void BlsDkg::AddQualCoefficients(CabinetIndex const &            from_index,
                                        std::vector<Coefficient> const &coefficients)
{
  if (coefficients.size() == this->polynomial_degree_ + 1)
  {
    for (CabinetIndex i = 0; i <= this->polynomial_degree_; ++i)
    {
      this->A_ik_[from_index][i].FromString(coefficients[i]);
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
BlsDkg::SharesExposedMap BlsDkg::ComputeQualComplaints(
    std::set<CabinetIndex> const &coeff_received) const
{
  SharesExposedMap qual_complaints;

  for (auto const &i : qual_)
  {
    if (i != cabinet_index_)
    {
      if (std::find(coeff_received.begin(), coeff_received.end(), i) != coeff_received.end())
      {
        VerificationKey rhs;
        VerificationKey lhs;
        lhs = this->g__s_ij_[i][cabinet_index_];
        rhs = mcl::ComputeRHS(cabinet_index_, this->A_ik_[i]);
        if (lhs != rhs || rhs.isZero())
        {
          qual_complaints.insert(
              {i, {this->s_ij_[i][cabinet_index_].ToString(), this->sprime_ij_[i][cabinet_index_].ToString()}});
        }
      }
      else
      {
        qual_complaints.insert(
            {i, {this->s_ij_[i][cabinet_index_].ToString(), this->sprime_ij_[i][cabinet_index_].ToString()}});
      }
    }
  }
  return qual_complaints;
}

BlsDkg::CabinetIndex BlsDkg::VerifyQualComplaint(CabinetIndex const &   from_index,
                                                               ComplaintAnswer const &answer)
{
  CabinetIndex victim_index = answer.first;

  VerificationKey  lhs;
  VerificationKey  rhs;
  PrivateKey s, sprime;
  s.FromString(answer.second.first);
  sprime.FromString(answer.second.second);
  lhs = mcl::ComputeLHS(GetGroupG(), GetGroupH(), s, sprime);
  rhs = mcl::ComputeRHS(from_index, this->C_ik_[victim_index]);
  if (lhs != rhs || lhs.isZero())
  {
    return from_index;
  }

  lhs.Mult(GetGroupG(), s);  // G^s
  rhs = mcl::ComputeRHS(from_index, this->A_ik_[victim_index]);
  if (lhs != rhs || rhs.isZero())
  {
    return answer.first;
  }

  return from_index;
}

/**
 * Run polynomial interpolation on the exposed secret shares of other cabinet members to
 * recontruct their random polynomials
 *
 * @return Bool for whether reconstruction from shares was successful
 */
bool BlsDkg::RunReconstruction()
{
  std::vector<std::vector<PrivateKey>> a_ik;
  a_ik.resize(static_cast<CabinetIndex>(this->cabinet_size_));
  a_ik.resize(static_cast<CabinetIndex>(this->polynomial_degree_ + 1));
  for (auto const &in : this->reconstruction_shares)
  {
    CabinetIndex           victim_index = in.first;
    std::set<CabinetIndex> parties{in.second.first};
    if (in.first == this->cabinet_index_)
    {
      // Do not run reconstruction for myself
      continue;
    }
    if (parties.size() <= this->polynomial_degree_)
    {
      // Do not have enough good shares to be able to do reconstruction
      return false;
    }
    std::vector<PrivateKey> points;
    std::vector<PrivateKey> shares_f;
    for (const auto &index : parties)
    {
      points.emplace_back(index + 1);  // adjust index in computation
      shares_f.push_back(in.second.second[index]);
    }
    a_ik[victim_index] = mcl::InterpolatePolynom(points, shares_f);
    for (std::size_t k = 0; k <= polynomial_degree_; k++)
    {
      this->A_ik_[victim_index][k].Mult(GetGroupG(), a_ik[victim_index][k]);
    }
  }
  return true;
}

/**
 * Compute group public key and individual public key shares
 */
void BlsDkg::ComputePublicKeys()
{
  std::vector<VerificationKey> y_i;
  mcl::Init(y_i, this->cabinet_size_);
  this->public_key_.clear();
  // For all parties in $QUAL$, set $y_i = A_{i0}
  for (auto const &it : qual_)
  {
    y_i[it] = this->A_ik_[it][0];
  }
  // Compute public key $y = \prod_{i \in QUAL} y_i \bmod p$
  for (auto const &it : qual_)
  {
    this->public_key_.Add(this->public_key_, y_i[it]);
  }
  // Compute public_key_shares_ $v_j = \prod_{i \in QUAL} \prod_{k=0}^t (A_{ik})^{j^k} \bmod
  // p$
  std::vector<VerificationKey> v_coeff;
  for (size_t k = 0; k <= polynomial_degree_; k++) {
    VerificationKey tmpV;
    for (const auto &jt : qual_) {
      tmpV.Add(tmpV, this->A_ik_[jt][k]);
    }
    v_coeff.push_back(tmpV);
  }

  for (auto const &jt : qual_)
  {
      public_key_shares_[jt].Add(public_key_shares_[jt], v_coeff[0]);
      mcl::UpdateRHS(jt, public_key_shares_[jt], v_coeff);
  }
}

AeonExecUnit BlsDkg::GetDkgOutput() const
{
  assert(qual_.size() != 0);
  auto output             = DKGKeyInformation();
  output.group_public_key = public_key_.ToString();
  output.private_key      = secret_share_.ToString();
  for (auto elem : public_key_shares_)
  {
    output.public_key_shares.push_back(elem.ToString());
  }
  AeonExecUnit aeon{GetGroupG().ToString(), output, qual_};
  return aeon;
}

BlsDkg::VerificationKey const &BlsDkg::GetGroupG() const
{
  return curve_params_.GetGroupG();
}

BlsDkg::VerificationKey const &BlsDkg::GetGroupH() const
{
  return curve_params_.GetGroupH();
}

BlsDkg::PrivateKey const &BlsDkg::GetZeroFr() const
{
  return curve_params_.GetZeroFr();
}

} //beacon
} //fetch
