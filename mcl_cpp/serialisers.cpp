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

#include "logging.hpp"
#include "serialisers.hpp"

#include <sstream>
#include <iomanip>

namespace fetch {
namespace serialisers {
namespace {
  constexpr char const *LOGGING_NAME = "Serialisers";

  void EncodeLength(std::ostream &stream, std::size_t value) {
    stream << value;
  }

  void Encode(std::ostream &stream, std::string const &value) {
    stream << "str:";
    EncodeLength(stream, value.size());
    stream << ':' << value << ';';
  }

  void Encode(std::ostream &stream, uint32_t value) {
    stream << "u32:";
    stream << value;
    stream << ';';
  }

  char DecodeNext(std::istream &stream) {
    char const value = static_cast<char>(stream.get());

    if (stream.eof()) {
      throw std::underflow_error("unable to read complete type information");
    }

    return value;
  }

  void DecodeTerminator(std::istream &stream) {
    char const term = DecodeNext(stream);
    if (term != ';') {
      throw std::runtime_error("missing terminator");
    }
  }

  template <typename Callback>
  void DecodeItem(std::istream &stream, Callback const &cb) {
    for (;;) {
      // extract the next value from the stream
      char const value = DecodeNext(stream);

      // execute the callback
      bool const cont = cb(value);
      if (!cont) {
        break;
      }
    }
  }

  std::string DecodeType(std::istream &stream) {
    std::string type_id{};

    DecodeItem(stream, [&type_id](char value) {
      // break on the next terminator
      if (value == ':') {
        return false;
      }

      // sanity check
      bool const valid = ((value >= 'a') && (value <= 'z')) ||
                         ((value >= '0') && (value <= '9'));
      if (!valid) {
        throw std::runtime_error("invalid character for type information");
      }

      // add the character
      type_id.push_back(value);

      return true;
    });

    return type_id;
  }

  std::size_t DecodeLength(std::istream &stream) {
    std::string buffer{};

    DecodeItem(stream, [&buffer](char value) {
      // break on the next terminator
      if (value == ':') {
        return false;
      }

      // check that the value is a number
      if (!((value >= '0') && (value <= '9'))) {
        throw std::runtime_error("invalid character for length");
      }

      buffer.push_back(value);
      return true;
    });

    // decode the value
    std::size_t decoded_value{0};
    std::istringstream iss{buffer};
    iss >> decoded_value;

    return decoded_value;
  }

  std::string DecodeBytes(std::istream &stream, std::size_t len) {
    std::string buffer{};

    DecodeItem(stream, [&buffer, len](char value) {
      // break on the next terminator
      if (value == ';') {
        return false;
      }

      if (buffer.size() >= len) {
        throw std::overflow_error("extracted too many bytes from stream for string");
      }

      buffer.push_back(value);
      return true;
    });

    if (buffer.size() != len) {
      throw std::underflow_error("extracted too few bytes from stream for string");
    }

    return buffer;
  }

  std::string DecodeString(std::istream &stream) {
    std::string const type_id = DecodeType(stream);
    if (type_id != "str") {
      throw std::runtime_error("unexpected type, expected string");
    }

    // extract the length
    std::size_t length = DecodeLength(stream);

    // extract the bytes of the string
    std::string value = DecodeBytes(stream, length);

    return value;
  }

  uint32_t DecodeU32(std::istream &stream) {
    std::string const type_id = DecodeType(stream);
    if (type_id != "u32") {
      throw std::runtime_error("Unexpected type, expected u32");
    }

    std::string buffer{};
    DecodeItem(stream, [&buffer](char value) {
      // break on the next terminator
      if (value == ';') {
        return false;
      }

      if (!((value >= '0') && (value <= '9'))) {
        throw std::runtime_error("invalid character for u32");
      }

      buffer.push_back(value);
      return true;
    });

    uint32_t value{0};
    std::istringstream iss{buffer};
    iss >> value;

    return value;
  }

  std::vector<std::string> DecodeStringSequence(std::istream &stream) {
    std::vector<std::string> values{};

    std::string const type_id = DecodeType(stream);
    if (type_id != "seq") {
      throw std::runtime_error("unexpected type, expected sequence");
    }

    // decode the length of the sequence
    std::size_t const length = DecodeLength(stream);

    // reset the output container
    values.reserve(length);

    // iterate and parse the string items
    for (std::size_t i = 0; i < length; ++i) {
      values.push_back(DecodeString(stream));
    }

    // decode the terminator
    DecodeTerminator(stream);

    return values;
  }

  std::pair<std::string, std::string> DecodeStringPair(std::istream &stream) {
    std::vector<std::string> items = DecodeStringSequence(stream);

    if (items.size() != 2) {
      throw std::runtime_error("too many shares decoded from message");
    }

    // update the shares
    return {items[0], items[1]};
  }

  void CheckStreamConsumed(std::istringstream &iss) {
    iss.get(); // attempt to read more data
    if (!iss.eof()) {
      throw std::overflow_error("too much data provided to deserialisation");
    }
  }
}

std::string Serialise(std::vector<std::string> const &coeff) {
  std::ostringstream stream{};

  stream << "seq:";
  EncodeLength(stream, coeff.size());
  stream << ':';

  for (auto const &value : coeff) {
    Encode(stream, value);
  }

  stream << ';';

  return stream.str();
}

std::string Serialise(std::pair<std::string, std::string> const &share) {

  // convert the pair into the vector
  std::vector<std::string> data = {
    std::get<0>(share),
    std::get<1>(share)
  };

  return Serialise(data);
}

std::string Serialise(std::set<uint32_t> const &complaints) {
  std::ostringstream stream{};

  stream << "seq:";
  EncodeLength(stream, complaints.size());
  stream << ':';

  for (auto const &value : complaints) {
    Encode(stream, value);
  }

  stream << ';';

  return stream.str();
}

std::string Serialise(std::unordered_map<uint32_t, std::pair<std::string, std::string>> const &shares) {
  std::ostringstream stream{};

  stream << "map:";
  EncodeLength(stream, shares.size());
  stream << ":";

  for (auto const &element : shares) {
    Encode(stream, element.first);
    stream << '=' << Serialise(element.second);
  }

  stream << ';';

  return stream.str();
}

bool Deserialise(std::string const &msg, std::vector<std::string> &coeff) {
  bool success{false};

  try {
    std::istringstream stream{msg};

    // decode the string sequence
    coeff = DecodeStringSequence(stream);

    CheckStreamConsumed(stream);

    success = true;

  } catch (std::exception const &ex) {
    Log(LogLevel::ERROR, LOGGING_NAME, "Coefficients: " + std::string(ex.what()));
    coeff.clear();
  }

  return success;
}

bool Deserialise(std::string const &msg, std::pair<std::string, std::string> &shares) {
  bool success{false};

  try {
    std::istringstream stream{msg};

    // extract the shares
    shares = DecodeStringPair(stream);

    CheckStreamConsumed(stream);

    // signal great success
    success = true;

  } catch (std::exception const &ex) {
    Log(LogLevel::ERROR, LOGGING_NAME, "Shares: " + std::string(ex.what()));
    shares = {};
  }

  return success;
}

bool Deserialise(std::string const &msg, std::set<uint32_t> &complaints) {
  bool success{false};

  try {
    std::istringstream stream{msg};

    std::string const type_id = DecodeType(stream);
    if (type_id != "seq") {
      throw std::runtime_error("unexpected type, expected sequence");
    }

    // decode the length of the sequence
    std::size_t const length = DecodeLength(stream);

    // reset the output container
    complaints.clear();

    for (std::size_t i = 0; i < length; ++i) {
      complaints.insert(DecodeU32(stream));
    }

    DecodeTerminator(stream);
    CheckStreamConsumed(stream);

    success = true;

  } catch (std::exception const &ex) {
    Log(LogLevel::ERROR, LOGGING_NAME, "Complaints: " + std::string(ex.what()));
    complaints.clear();
  }

  return success;
}

bool Deserialise(std::string const &msg, std::unordered_map<uint32_t, std::pair<std::string, std::string>> &shares) {
  bool success{false};

  try {
    std::istringstream stream{msg};

    std::string const type_id = DecodeType(stream);
    if (type_id != "map") {
      throw std::runtime_error("unexpected type, expected sequence");
    }

    std::size_t const length = DecodeLength(stream);

    shares.clear();
    for (std::size_t i = 0; i < length; ++i) {

      // extract the key
      uint32_t const key = DecodeU32(stream);

      // check the sep
      char const sep = DecodeNext(stream);
      if (sep != '=') {
        throw std::runtime_error("missing map seperator");
      }

      // extract the value and update the output map
      shares[key] = DecodeStringPair(stream);
    }

    // check the terminator
    DecodeTerminator(stream);
    CheckStreamConsumed(stream);

    success = true;

  } catch (std::exception const &ex) {
    Log(LogLevel::ERROR, LOGGING_NAME, "Exposed shares: " + std::string(ex.what()));
    shares.clear();
  }

  return success;
}

}  // namespace serialisers
}  // namespace fetch