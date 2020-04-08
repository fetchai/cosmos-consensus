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

#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/serialization/set.hpp>
#include <boost/serialization/string.hpp>
#include <boost/serialization/unordered_map.hpp>
#include <boost/serialization/utility.hpp>
#include <boost/serialization/vector.hpp>
#include <sstream>

namespace fetch {
namespace serialisers {

std::string Serialise(std::vector<std::string> const &coeff) {
  std::ostringstream            ss;
  boost::archive::text_oarchive oa{ss};
  oa << coeff;
  return ss.str();
}

std::string Serialise(std::pair<std::string, std::string> const &share) {
  std::ostringstream            ss;
  boost::archive::text_oarchive oa{ss};
  oa << share;
  return ss.str();
}

std::string Serialise(std::set<uint32_t> const &complaints) {
  std::ostringstream            ss;
  boost::archive::text_oarchive oa{ss};
  oa << complaints;
  return ss.str();
}

std::string Serialise(std::unordered_map<uint32_t, std::pair<std::string, std::string>> const &shares) {
  std::ostringstream            ss;
  boost::archive::text_oarchive oa{ss};
  oa << shares;
  return ss.str();
}

bool Deserialise(std::string const &msg, std::vector<std::string> &coeff) {
    std::istringstream            ss{msg};
    boost::archive::text_iarchive ia{ss};
    try {
    ia >> coeff;
    } catch (boost::archive::archive_exception ex) {
        std::cerr << "Error deserialising coefficients: " << ex.what() << std::endl;
        return false;
    }
    return true;
}

bool Deserialise(std::string const &msg, std::pair<std::string, std::string> &shares) {
    std::istringstream            ss{msg};
    boost::archive::text_iarchive ia{ss};
    try {
    ia >> shares;
    } catch (boost::archive::archive_exception ex) {
        std::cerr << "Error deserialising shares: " << ex.what() << std::endl;
        return false;
    }
    return true;
}

bool Deserialise(std::string const &msg, std::set<uint32_t> &complaints) {
    std::istringstream            ss{msg};
    boost::archive::text_iarchive ia{ss};
    try {
    ia >> complaints;
    } catch (boost::archive::archive_exception ex) {
        std::cerr << "Error deserialising complaints: " << ex.what() << std::endl;
        return false;
    }
    return true;
}

bool Deserialise(std::string const &msg, std::unordered_map<uint32_t, std::pair<std::string, std::string>> shares) {
    std::istringstream            ss{msg};
    boost::archive::text_iarchive ia{ss};
    try {
    ia >> shares;
    } catch (boost::archive::archive_exception ex) {
        std::cerr << "Error deserialising exposed shares: " << ex.what() << std::endl;
        return false;
    }
    return true;
}

}  // namespace serialisers
}  // namespace fetch