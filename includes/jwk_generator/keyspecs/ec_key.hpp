#pragma once

#include "jwk_generator/libs/json.hpp"
#include "jwk_generator/errors.hpp"
#include "jwk_generator/openssl_wrapper.hpp"

namespace jwk_generator {
    template<size_t shaBits>
    class ECKey {
        private:
#ifdef JWKGEN_OPENSSL_3_0
        static constexpr const char* ecdsa_bit_to_curve() {
            switch(shaBits) {
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
            throw std::runtime_error("Unsupported EC algorithm");
        }
#else
        static constexpr int ecdsa_bit_to_curve() {
            switch(shaBits) {
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
            throw std::runtime_error("Unsupported EC algorithm");
        }
#endif

        static constexpr size_t bits_to_point_size() {
            switch(shaBits) {
                case 256: {
                    return 32;
                }
                case 512: {
                    return 66;
                }
                case 384: {
                    return 48;
                }
            }
            throw std::runtime_error("Unsupported EC algorithm");
        }
        public:
        static constexpr size_t pointSize = bits_to_point_size();
        openssl::EVPPKey keyPair;
        std::string pointX;
        std::string pointY;

        ECKey(const ECKey&) = delete;
        ECKey& operator = (const ECKey&) = delete;
        ECKey(ECKey&&) = default;
        ECKey& operator = (ECKey&&) = default;
        ECKey() {
            using namespace detail;

#ifdef JWKGEN_OPENSSL_3_0
            keyPair = {[]() { return EVP_EC_gen(ecdsa_bit_to_curve()); }};
            if (!keyPair) {
                throw openssl_error("Unable to generate ec key: ");
            }
            BIGNUM* xBN = nullptr;
            if (!EVP_PKEY_get_bn_param(keyPair, OSSL_PKEY_PARAM_EC_PUB_X, &xBN)) {
                throw openssl_error("Unable to extract coordinates key: ");
            }

            BIGNUM* yBN = nullptr;
            if (!EVP_PKEY_get_bn_param(keyPair, OSSL_PKEY_PARAM_EC_PUB_Y, &yBN)) {
                throw openssl_error("Unable extract coordinates from key: ");
            }
#else
            auto group = openssl::ECGroup ([]() { return EC_GROUP_new_by_curve_name(ecdsa_bit_to_curve()); });
            auto ec = openssl::ECKey::allocate();

            if (!EC_KEY_set_group(ec, group)) {
                throw openssl_error("Unable to generate ec key: ");
            }
            if (!EC_KEY_generate_key(ec)) {
                throw openssl_error("Unable to generate ec key: ");
            }
            keyPair = openssl::EVPPKey::allocate();
            if (!keyPair) {
                throw openssl_error("Unable to generate ec key: ");
            }

            // release it now as ownership transfers to the key pair
            EC_KEY* ecPtr = ec.release();
            if (!EVP_PKEY_assign_EC_KEY(keyPair, ecPtr)) {
                throw openssl_error("Unable to generate ec key: ");
            }

            openssl::BigNum xBN = openssl::BigNum::allocate();
            if (!xBN) {
                throw openssl_error("Unable to allocate BN: ");
            }
            openssl::BigNum yBN = openssl::BigNum::allocate();
            if (!yBN) {
                throw openssl_error("Unable to allocate BN: ");
            }
            auto point = EC_KEY_get0_public_key(ecPtr);
            if (!EC_POINT_get_affine_coordinates(group, point, xBN, yBN, NULL)) {
                throw openssl_error("Unable to extract coordinates from key: ");
            }
#endif

            std::vector<uint8_t> xBin;
            xBin.resize(pointSize);
            BN_bn2binpad(xBN, xBin.data(), pointSize);
            pointX = base64_url_encode(xBin);

            std::vector<uint8_t> yBin;
            yBin.resize(pointSize);
            BN_bn2binpad(yBN, yBin.data(), pointSize);
            pointY = base64_url_encode(yBin);
        }

        void insert_json(nlohmann::json& json) const {
            std::string crv = std::string("P-") + std::to_string(shaBits);
            if (shaBits == 512) {
                crv = "P-521";
            }
            json["alg"] = "ES" + std::to_string(shaBits);
            json["kty"] = "EC";
            json["x"] = pointX;
            json["y"] = pointY;
            json["crv"] = crv;
        }
    };

    using ES256 = ECKey<256>;
    using ES384 = ECKey<384>;
    using ES512 = ECKey<512>;
};
