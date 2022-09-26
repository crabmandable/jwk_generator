#pragma once

#include "jwk_generator/libs/json.hpp"
#include "jwk_generator/errors.hpp"

#include <openssl/rsa.h>
#include "openssl/evp.h"

#if OPENSSL_VERSION_NUMBER >= 0x30000000L // 3.0.0
#define JWKGEN_OPENSSL_3_0
#include <openssl/types.h>
#include <openssl/core_names.h>
#endif

namespace jwk_generator {
    template<size_t shaBits>
    struct RSAKey {
        public:
        static constexpr const size_t nBits = 2048;
        std::shared_ptr<EVP_PKEY> keyPair;
        std::string modulous;
        std::string exponent;

        RSAKey() {
            using namespace detail;

#ifdef JWKGEN_OPENSSL_3_0
            keyPair = {EVP_RSA_gen(nBits), EVP_PKEY_free};
            if (!keyPair) {
                throw openssl_error("Unable to generate rsa key: ");
            }

            BIGNUM* modBN = nullptr;
            if (!EVP_PKEY_get_bn_param(keyPair.get(), OSSL_PKEY_PARAM_RSA_N, &modBN)) {
                throw openssl_error("Unable to retrieve public key: ");
            }

            BIGNUM* exBN = nullptr;
            if (!EVP_PKEY_get_bn_param(keyPair.get(), OSSL_PKEY_PARAM_RSA_E, &exBN)) {
                throw openssl_error("Unable to retrieve public key: ");
            }
#else
            std::shared_ptr<BIGNUM> exShared = {BN_new(), BN_free};
            if (!exShared) {
                throw openssl_error("Unable to allocate BN: ");
            }
            BIGNUM* exBN = exShared.get();
            BN_set_word(exBN, 65537);

            // rsa becomes owned by the evp, so don't wrap in smart pointer
            RSA* rsa = RSA_new();
            if (!RSA_generate_key_ex(rsa, nBits, exBN, NULL)) {
                RSA_free(rsa);
                throw openssl_error("Unable to generate rsa key: ");
            }

            keyPair = {EVP_PKEY_new(), EVP_PKEY_free};
            if (!keyPair) {
                RSA_free(rsa);
                throw openssl_error("Unable to generate rsa key: ");
            }
            EVP_PKEY* pkey = keyPair.get();
            if (!EVP_PKEY_assign_RSA(pkey, rsa)) {
                throw openssl_error("Unable to generate rsa key: ");
            }
            const BIGNUM* modBN = RSA_get0_n(rsa);
#endif

            size_t len = BN_num_bytes(modBN);
            std::vector<uint8_t> modBin;
            modBin.resize(len);
            BN_bn2bin(modBN, modBin.data());
            modulous = base64_url_encode(modBin);

            len = BN_num_bytes(exBN);
            std::vector<uint8_t> exBin;
            exBin.resize(len);
            BN_bn2bin(exBN, exBin.data());
            exponent = base64_url_encode(exBin);
        }

        void insert_json(nlohmann::json& json) const {
            json["alg"] = "RS" + std::to_string(shaBits);
            json["kty"] = "RSA";
            json["e"] = exponent;
            json["n"] = modulous;
        }
    };
};
