#pragma once

#include "nlohmann/json.hpp"
#include <openssl/types.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include "jwk_generator/uuid.hpp"
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include "openssl/evp.h"
#include <memory>
#include <stdint.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include "cppcodec/base64_url_unpadded.hpp"
#include "uuid.hpp"

namespace jwk_generator {
    namespace detail {
        static inline std::string OpenSSLLastError() {
            int err = ERR_get_error();
            char errStr[256];
            ERR_error_string(err, errStr);
            return std::string(errStr);
        }

        static inline const char* ECDSABitsToCurve(size_t nBits) {
            switch(nBits) {
                case 256: {
                    return SN_X9_62_prime256v1;
                }
                case 512: {
                    return SN_secp521r1;
                }
                case 384: {
                    return SN_secp384r1;
                }
            }
            throw std::runtime_error("Unsupported ecdsa algorithm");
        }
    };

    template<size_t nBits>
        struct RSAKeySpec {
            std::string kid;
            std::shared_ptr<EVP_PKEY> keyPair;
            std::string modulous;
            std::string exponent;

            RSAKeySpec() {
                using namespace detail;
                kid = detail::generate_uuid_v4();

                size_t len;
                keyPair = {EVP_RSA_gen(nBits), EVP_PKEY_free};
                if (!keyPair) {
                    throw std::runtime_error(std::string("Unable to generate rsa key: ") + OpenSSLLastError());
                }
                std::shared_ptr<BIGNUM> modBN = {BN_new(), BN_free};
                if (!modBN) {
                    throw std::runtime_error(std::string("Unable to allocate BN") + OpenSSLLastError());
                }
                BIGNUM* modTmp = modBN.get();
                if (!EVP_PKEY_get_bn_param(keyPair.get(), OSSL_PKEY_PARAM_RSA_N, &modTmp)) {
                    throw std::runtime_error(std::string("Unable to retrieve public key: ") + OpenSSLLastError());
                }

                len = BN_num_bytes(modBN.get());
                std::vector<uint8_t> modBin;
                modBin.resize(len);
                BN_bn2bin(modBN.get(), modBin.data());
                modulous = cppcodec::base64_url_unpadded::encode(modBin);

                std::shared_ptr<BIGNUM> exBN = {BN_new(), BN_free};
                if (!exBN) {
                    throw std::runtime_error(std::string("Unable to allocate BN") + OpenSSLLastError());
                }
                BIGNUM* exTmp = exBN.get();
                if (!EVP_PKEY_get_bn_param(keyPair.get(), OSSL_PKEY_PARAM_RSA_E, &exTmp)) {
                    throw std::runtime_error(std::string("Unable to retrieve public key: ") + OpenSSLLastError());
                }

                len = BN_num_bytes(exBN.get());
                std::vector<uint8_t> exBin;
                exBin.resize(len);
                BN_bn2bin(exBN.get(), exBin.data());
                exponent = cppcodec::base64_url_unpadded::encode(exBin);
            }

            void insertJson(nlohmann::json& json) const {
                json["alg"] = "RS" + std::to_string(nBits);
                json["kty"] = "RSA";
                json["kid"] = kid;
                json["e"] = exponent;
                json["n"] = modulous;
            }
        };

    template<size_t nBits>
        struct ECDSAKeySpec {
            std::string kid;
            std::shared_ptr<EVP_PKEY> keyPair;
            std::string pointX;
            std::string pointY;

            ECDSAKeySpec() {
                using namespace detail;
                kid = detail::generate_uuid_v4();

                size_t len;
                keyPair = {EVP_EC_gen(ECDSABitsToCurve(nBits)), EVP_PKEY_free};
                if (!keyPair) {
                    throw std::runtime_error(std::string("Unable to generate ec key: ") + OpenSSLLastError());
                }
                std::shared_ptr<BIGNUM> xBN = {BN_new(), BN_free};
                if (!xBN) {
                    throw std::runtime_error(std::string("Unable to allocate BN") + OpenSSLLastError());
                }
                BIGNUM* xTmp = xBN.get();
                if (!EVP_PKEY_get_bn_param(keyPair.get(), OSSL_PKEY_PARAM_EC_PUB_X, &xTmp)) {
                    throw std::runtime_error(std::string("Unable to retrieve public key: ") + OpenSSLLastError());
                }

                len = BN_num_bytes(xBN.get());
                std::vector<uint8_t> xBin;
                xBin.resize(len);
                BN_bn2bin(xBN.get(), xBin.data());
                pointX = cppcodec::base64_url_unpadded::encode(xBin);

                std::shared_ptr<BIGNUM> yBN = {BN_new(), BN_free};
                if (!yBN) {
                    throw std::runtime_error(std::string("Unable to allocate BN") + OpenSSLLastError());
                }
                BIGNUM* yTmp = yBN.get();
                if (!EVP_PKEY_get_bn_param(keyPair.get(), OSSL_PKEY_PARAM_EC_PUB_Y, &yTmp)) {
                    throw std::runtime_error(std::string("Unable to retrieve public key: ") + OpenSSLLastError());
                }

                len = BN_num_bytes(yBN.get());
                std::vector<uint8_t> yBin;
                yBin.resize(len);
                BN_bn2bin(yBN.get(), yBin.data());
                pointY = cppcodec::base64_url_unpadded::encode(yBin);
            }

            void insertJson(nlohmann::json& json) const {
                json["alg"] = "ES" + std::to_string(nBits);
                json["kid"] = kid;
                json["kty"] = "EC";
                json["x"] = pointX;
                json["y"] = pointY;
                json["crv"] = std::string("P-") + std::to_string(nBits);
            }
        };

    template <typename KeySpec>
        struct JwkGenerator {
            static nlohmann::json to_json() {
                nlohmann::json json;
                auto key = KeySpec();
                key.insertJson(json);
                return json;
            }

            operator std::string () const {
                return to_json().dump();
            }

            friend std::ostream & operator<< (std::ostream &out, const JwkGenerator& e) {
                out << std::string(e);
                return out;
            }
        };

    template <typename... KeySpec>
        struct JwksGenerator {
            static nlohmann::json to_json() {
                nlohmann::json jwks;
                jwks["keys"] = {JwkGenerator<KeySpec>().to_json()...};
                return jwks;
            }

            operator std::string () const {
                return to_json().dump();
            }

            friend std::ostream & operator<< (std::ostream &out, const JwksGenerator& e) {
                out << std::string(e);
                return out;
            }
        };

};
