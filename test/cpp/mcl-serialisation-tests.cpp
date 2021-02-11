#define CATCH_CONFIG_MAIN  // This tells Catch to provide a main() - only do this in one cpp file
#include "catch.hpp"
#include "serialisers.hpp"

#include <sstream>


TEST_CASE( "Check encoding of vec{string}", "[serialisers]" ) {
  std::string const expected = "seq:3:str:3:foo;str:4:barr;str:5:bazzz;;";
  std::vector<std::string> const data{
    "foo",
    "barr",
    "bazzz"
  };

  std::string const encoded = fetch::serialisers::Serialise(data);
  REQUIRE( encoded == expected );

  std::vector<std::string> recovered{};
  bool const success = fetch::serialisers::Deserialise(encoded, recovered);

  REQUIRE( success );
  REQUIRE( data == recovered );
}

TEST_CASE( "Check encoding of pair{string,string}", "[serialisers]" ) {
  std::string const expected = "seq:2:str:3:foo;str:4:barr;;";
  std::pair<std::string, std::string> data{"foo", "barr"};

  std::string const encoded = fetch::serialisers::Serialise(data);
  REQUIRE( encoded == expected );

  std::pair<std::string, std::string> recovered{};
  bool const success = fetch::serialisers::Deserialise(encoded, recovered);

  REQUIRE( success );
  REQUIRE( data == recovered );
}

TEST_CASE( "Check encoding of set{u32}", "[serialisers]" ) {
  std::string const expected = "seq:5:u32:0;u32:1;u32:2;u32:5;u32:10;;";
  std::set<uint32_t> data{0, 1, 2, 5, 10};

  std::string const encoded = fetch::serialisers::Serialise(data);
  REQUIRE( encoded == expected );

  std::set<uint32_t> recovered{};
  bool const success = fetch::serialisers::Deserialise(encoded, recovered);

  REQUIRE( success );
  REQUIRE( data == recovered );
}

TEST_CASE( "Check encoding of map{u32,{string,string}}", "[serialisers]" ) {
  std::string const expected = "map:2:u32:1;=seq:2:str:3:bar;str:4:bazz;;u32:0;=seq:2:str:3:foo;str:3:bar;;;";

  std::unordered_map<uint32_t, std::pair<std::string, std::string>> data;
  data[0] = {"foo", "bar"};
  data[1] = {"bar", "bazz"};

  std::string const encoded = fetch::serialisers::Serialise(data);
  REQUIRE( encoded == expected );

  std::unordered_map<uint32_t, std::pair<std::string, std::string>> recovered{};
  bool const success = fetch::serialisers::Deserialise(encoded, recovered);

  REQUIRE( success );
  REQUIRE( data == recovered );
}
