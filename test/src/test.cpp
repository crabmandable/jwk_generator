#include <gtest/gtest.h>
#include "jwk_generator/jwk_generator.hpp"

using namespace jwk_generator;

class Test : public ::testing::Test {
 protected:
  void SetUp() override {
  }
};

TEST_F(Test, Test1) {
    std::cout << JwksGenerator<RSAKeySpec<512>, ECDSAKeySpec<384>>() << std::endl;
}
