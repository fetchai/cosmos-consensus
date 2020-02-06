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

namespace fetch {
namespace crypto {

void InitialiseMcl();

struct DKGKeyInformation {
  std::string private_key;
  std::vector<std::string> public_key_shares;
  std::string group_public_key;
};

class EntropyGenerationInterface {
public:
  using MessagePayload     = std::string;
  using Signature          = std::string;
  using Generator          = std::string;
  using CabinetIndex       = uint64_t;

  EntropyGenerationInterface(DKGKeyInformation aeon_keys, Generator generator);

  Signature Sign(MessagePayload const &message);
  bool Verify(MessagePayload const &message, Signature const &sign, CabinetIndex const &sender);
  Signature ComputeGroupSignature(std::map <int, Signature> const &signature_shares);
  bool VerifyGroupSignature(MessagePayload const &message, Signature const &signature);

private:
  DKGKeyInformation aeon_keys_;
  Generator generator_;
};

}  // namespace crypto
}  // namespace fetch
