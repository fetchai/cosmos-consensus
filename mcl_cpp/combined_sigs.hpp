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

#include "base_dkg.hpp"

#include <string>
#include <stdint.h>

namespace fetch {
namespace beacon {

std::string GenPrivKey();
std::string GenPrivKeyBls(std::string const &secret); 
std::string PubKeyFromPrivate(std::string const &private_key);
std::pair<std::string, std::string> PubKeyFromPrivateWithPoP(std::string const &private_key);
std::string Sign(std::string const &message, std::string const &private_key);
std::string CombinePublicKeys(std::vector<std::string> const &pub_keys);
std::string CombineSignatures(std::vector<std::string> const &sigs);
bool PairingVerify(std::string const &message, std::string const &sign, std::string const &public_key);
bool PairingVerifyCombinedSig(std::string const &message, std::string const &sign, std::vector<std::string> const &public_key);

} //beacon
} //fetch