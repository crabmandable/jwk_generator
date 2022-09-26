#pragma once

#include "jwk_generator/libs/json.hpp"
#include "jwk_generator/errors.hpp"

#include "openssl/evp.h"
#include <openssl/ec.h>
#include <openssl/ecdsa.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L // 3.0.0
#define JWKGEN_OPENSSL_3_0
#include <openssl/types.h>
#include <openssl/core_names.h>
#endif

namespace jwk_generator {
    template<size_t nBits>
    class ECDSAKey {
        private:
#ifdef JWKGEN_OPENSSL_3_0
        static constexpr const char* ecdsa_bit_to_curve() {
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
#else
        static constexpr int ecdsa_bit_to_curve() {
            switch(nBits) {
                case 256: {
                    return NID_X9_62_prime256v1;
                }
                case 512: {
                    return NID_secp521r1;
                }
                case 384: {
                    return NID_secp384r1;
                }
            }
            throw std::runtime_error("Unsupported ecdsa algorithm");
        }
#endif
        public:
        std::shared_ptr<EVP_PKEY> keyPair;
        std::string pointX;
        std::string pointY;

        ECDSAKey(ECDSAKey&) = delete;
        ECDSAKey& operator = (const ECDSAKey&) = delete;
        ECDSAKey(ECDSAKey&&) = default;
        ECDSAKey& operator = (ECDSAKey&&) = default;
        ECDSAKey() {
            using namespace detail;

#ifdef JWKGEN_OPENSSL_3_0
            keyPair = {EVP_EC_gen(ecdsa_bit_to_curve()), EVP_PKEY_free};
            if (!keyPair) {
                throw openssl_error("Unable to generate ec key: ");
            }
            BIGNUM* xBN = nullptr;
            if (!EVP_PKEY_get_bn_param(keyPair.get(), OSSL_PKEY_PARAM_EC_PUB_X, &xBN)) {
                throw openssl_error("Unable to extract coordinates key: ");
            }

            BIGNUM* yBN = nullptr;
            if (!EVP_PKEY_get_bn_param(keyPair.get(), OSSL_PKEY_PARAM_EC_PUB_Y, &yBN)) {
                throw openssl_error("Unable extract coordinates from key: ");
            }
#else
            // don't wrap in smart pointer because the EVP own it
            std::shared_ptr<EC_GROUP> groupShared = {EC_GROUP_new_by_curve_name(ecdsa_bit_to_curve()), EC_GROUP_free};
            const EC_GROUP* group = groupShared.get();

            EC_KEY* ec = EC_KEY_new();
            if (!EC_KEY_set_group(ec, group)) {
                EC_KEY_free(ec);
                throw openssl_error("Unable to generate ec key: ");
            }
            if (!EC_KEY_generate_key(ec)) {
                EC_KEY_free(ec);
                throw openssl_error("Unable to generate ec key: ");
            }
            keyPair = {EVP_PKEY_new(), EVP_PKEY_free};
            if (!keyPair) {
                EC_KEY_free(ec);
                throw openssl_error("Unable to generate ec key: ");
            }
            EVP_PKEY* pkey = keyPair.get();
            if (!EVP_PKEY_assign_EC_KEY(pkey, ec)) {
                throw openssl_error("Unable to generate ec key: ");
            }

            std::shared_ptr<BIGNUM> xShared = {BN_new(), BN_free};
            BIGNUM* xBN = xShared.get();
            if (!xBN) {
                throw openssl_error("Unable to allocate BN: ");
            }
            std::shared_ptr<BIGNUM> yShared = {BN_new(), BN_free};
            BIGNUM* yBN = yShared.get();
            if (!yBN) {
                throw openssl_error("Unable to allocate BN: ");
            }
            auto point = EC_KEY_get0_public_key(ec);
            if (!EC_POINT_get_affine_coordinates(group, point, xBN, yBN, NULL)) {
                throw openssl_error("Unable to extract coordinates from key: ");
            }
#endif

            size_t len = BN_num_bytes(xBN);
            std::vector<uint8_t> xBin;
            xBin.resize(len);
            BN_bn2bin(xBN, xBin.data());
            pointX = base64_url_encode(xBin);

            len = BN_num_bytes(yBN);
            std::vector<uint8_t> yBin;
            yBin.resize(len);
            BN_bn2bin(yBN, yBin.data());
            pointY = base64_url_encode(yBin);
        }

        void insert_json(nlohmann::json& json) const {
            json["alg"] = "ES" + std::to_string(nBits);
            json["kty"] = "EC";
            json["x"] = pointX;
            json["y"] = pointY;
            json["crv"] = std::string("P-") + std::to_string(nBits);
        }
    };
};
