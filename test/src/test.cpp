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

TEST_F(Test, ManyKeys) {
    auto jwks = make_jwks<ECDSAKey<512>>(100);
    std::cout << jwks << std::endl;
}

TEST_F(Test, ManyKeysAgain) {
    std::vector<JwkGenerator<ECDSAKey<256>>> keys;
    keys.resize(100);
    auto jwks = JwksSingleSpecGenerator(std::move(keys));
    std::cout << jwks << std::endl;
    for (size_t i = 0; i < keys.size(); i++) {
        std::cout << jwks[i].public_to_pem() << std::endl;
    }
}

TEST_F(Test, ECDSA256) {
    auto jwk = JwkGenerator<ECDSAKey<256>>();
    std::cout << jwk << std::endl;
    std::cout << jwk.private_to_pem() << std::endl;
    std::cout << jwk.public_to_pem() << std::endl;
}

TEST_F(Test, ECDSA384) {
    auto jwk = JwkGenerator<ECDSAKey<384>>();
    std::cout << jwk << std::endl;
    std::cout << jwk.private_to_pem() << std::endl;
    std::cout << jwk.public_to_pem() << std::endl;
}

TEST_F(Test, ECDSA512) {
    auto jwk = JwkGenerator<ECDSAKey<512>>();
    std::cout << jwk << std::endl;
    std::cout << jwk.private_to_pem() << std::endl;
    std::cout << jwk.public_to_pem() << std::endl;
}

TEST_F(Test, RSA256) {
    auto jwk = JwkGenerator<RSAKey<256>>();
    std::cout << jwk << std::endl;
    std::cout << jwk.private_to_pem() << std::endl;
    std::cout << jwk.public_to_pem() << std::endl;
}

TEST_F(Test, RSA384) {
    auto jwk = JwkGenerator<RSAKey<384>>();
    std::cout << jwk << std::endl;
    std::cout << jwk.private_to_pem() << std::endl;
    std::cout << jwk.public_to_pem() << std::endl;
}

TEST_F(Test, RSA512) {
    auto jwk = JwkGenerator<RSAKey<512>>();
    std::cout << jwk << std::endl;
    std::cout << jwk.private_to_pem() << std::endl;
    std::cout << jwk.public_to_pem() << std::endl;
}
