#include <gtest/gtest.h>
#include "jwk_generator/jwk_generator.hpp"

using namespace jwk_generator;

class Test : public ::testing::Test {
 protected:
  void SetUp() override {
  }
};

TEST_F(Test, Test1) {
    auto jwks = JwksGenerator<RSAKey<512>, ECDSAKey<384>>();
    std::cout << jwks << std::endl;
    std::cout << jwks.get<0>().private_to_pem() << std::endl;
    std::cout << jwks.get<0>().public_to_pem() << std::endl;
    std::cout << jwks.get<1>().private_to_pem() << std::endl;
    std::cout << jwks.get<1>().public_to_pem() << std::endl;
}
