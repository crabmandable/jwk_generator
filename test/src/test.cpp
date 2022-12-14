#include <gtest/gtest.h>
#include "jwk_generator/jwk_generator.hpp"

using namespace jwk_generator;

class Test : public ::testing::Test {
 protected:
  void SetUp() override {
  }
};

TEST_F(Test, Test1) {
    auto jwks = JwkSetGenerator<RS512, ES384>();
    std::cout << jwks << std::endl;
    std::cout << jwks.get<0>().private_to_pem() << std::endl;
    std::cout << jwks.get<0>().public_to_pem() << std::endl;
    std::cout << jwks.get<1>().private_to_pem() << std::endl;
    std::cout << jwks.get<1>().public_to_pem() << std::endl;
}

TEST_F(Test, ManyKeys) {
    auto jwks = make_jwks<ES512>(100);
    std::cout << jwks << std::endl;
}

TEST_F(Test, ManyKeysAgain) {
    std::vector<JwkGenerator<ES256>> keys;
    keys.resize(100);
    auto jwks = JwkSetSingleSpecGenerator(std::move(keys));
    std::cout << jwks << std::endl;
    for (size_t i = 0; i < keys.size(); i++) {
        std::cout << jwks[i].public_to_pem() << std::endl;
    }
}

TEST_F(Test, ES256) {
    auto jwk = JwkGenerator<ES256>();
    std::cout << jwk << std::endl;
    std::cout << jwk.private_to_pem() << std::endl;
    std::cout << jwk.public_to_pem() << std::endl;
}

TEST_F(Test, ES384) {
    auto jwk = JwkGenerator<ES384>();
    std::cout << jwk << std::endl;
    std::cout << jwk.private_to_pem() << std::endl;
    std::cout << jwk.public_to_pem() << std::endl;
}

TEST_F(Test, ES512) {
    auto jwk = JwkGenerator<ES512>();
    std::cout << jwk << std::endl;
    std::cout << jwk.private_to_pem() << std::endl;
    std::cout << jwk.public_to_pem() << std::endl;
}

TEST_F(Test, RS256) {
    auto jwk = JwkGenerator<RS256>();
    std::cout << jwk << std::endl;
    std::cout << jwk.private_to_pem() << std::endl;
    std::cout << jwk.public_to_pem() << std::endl;
}

TEST_F(Test, RS384) {
    auto jwk = JwkGenerator<RS384>();
    std::cout << jwk << std::endl;
    std::cout << jwk.private_to_pem() << std::endl;
    std::cout << jwk.public_to_pem() << std::endl;
}

TEST_F(Test, RS512) {
    auto jwk = JwkGenerator<RS512>();
    std::cout << jwk << std::endl;
    std::cout << jwk.private_to_pem() << std::endl;
    std::cout << jwk.public_to_pem() << std::endl;
}
