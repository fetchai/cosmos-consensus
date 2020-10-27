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

#include <set>
#include <string>
#include <unordered_map>
#include <vector>
//#include "base_dkg.hpp"
//#include "base_dkg.hpp"
//#include "mcl_crypto.hpp"

namespace fetch {
namespace serialisers {

std::string Serialise(std::vector<std::string> const &coeff);
std::string Serialise(std::pair<std::string, std::string> const &share);
std::string Serialise(std::set<uint32_t> const &complaints);
std::string Serialise(std::unordered_map<uint32_t, std::pair<std::string, std::string>> const &shares);
//template <typename T>
//std::string Serialise(std::vector<std::vector<::fetch::beacon::mcl::PrivateKey>> const &private_keys);

bool Deserialise(std::string const &msg, std::vector<std::string> &coeff);
bool Deserialise(std::string const &msg, std::pair<std::string, std::string> &shares);
bool Deserialise(std::string const &msg, std::set<uint32_t> &complaints);
bool Deserialise(std::string const &msg, std::unordered_map<uint32_t, std::pair<std::string, std::string>> &shares);
//template <typename T>
//bool Deserialise(std::string const &msg, std::vector<std::vector<T>> &private_keys);

}  // namespace serialisers
}  // namespace fetch
