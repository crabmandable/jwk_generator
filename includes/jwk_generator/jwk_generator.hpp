#pragma once

#include <sstream>
#include <stdexcept>
#include <string>
#include "jwk_generator/uuid.hpp"
#include <memory>
#include <tuple>
#include <stdint.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include "openssl/evp.h"

#include "jwk_generator/base64_url.hpp"
#include "jwk_generator/uuid.hpp"
#include "jwk_generator/json.hpp"

#if OPENSSL_VERSION_NUMBER >= 0x30000000L // 3.0.0
#define JWKGEN_OPENSSL_3_0
#include <openssl/types.h>
#include <openssl/core_names.h>
#endif

namespace jwk_generator {
    namespace detail {
        static inline std::string OpenSSLLastError() {
            int err = ERR_get_error();
            char errStr[256];
            ERR_error_string(err, errStr);
            return std::string(errStr);
        }

#ifdef JWKGEN_OPENSSL_3_0
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
#else
        static inline int ECDSABitsToCurve(size_t nBits) {
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
    };

    struct openssl_error: public std::runtime_error {
        openssl_error(std::string what) : std::runtime_error(what + detail::OpenSSLLastError()) {}
    };

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

        void insertJson(nlohmann::json& json) const {
            json["alg"] = "RS" + std::to_string(shaBits);
            json["kty"] = "RSA";
            json["e"] = exponent;
            json["n"] = modulous;
        }
    };

    template<size_t nBits>
    struct ECDSAKey {
        std::shared_ptr<EVP_PKEY> keyPair;
        std::string pointX;
        std::string pointY;

        ECDSAKey() {
            using namespace detail;

#ifdef JWKGEN_OPENSSL_3_0
            keyPair = {EVP_EC_gen(ECDSABitsToCurve(nBits)), EVP_PKEY_free};
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
            std::shared_ptr<EC_GROUP> groupShared = {EC_GROUP_new_by_curve_name(ECDSABitsToCurve(nBits)), EC_GROUP_free};
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

        void insertJson(nlohmann::json& json) const {
            json["alg"] = "ES" + std::to_string(nBits);
            json["kty"] = "EC";
            json["x"] = pointX;
            json["y"] = pointY;
            json["crv"] = std::string("P-") + std::to_string(nBits);
        }
    };

    template <typename KeySpec>
    class JwkGenerator {
        private:
        KeySpec key;

        std::string to_pem(std::function<int(BIO*, EVP_PKEY*)> writeKeyToBIO) {
            using namespace detail;
            auto pemKeyBIO = std::shared_ptr<BIO>(BIO_new(BIO_s_secmem()), BIO_free);
            if (!pemKeyBIO) {
                throw openssl_error("Unable to retrieve public key: ");
            }
            EVP_PKEY* tmpEVP = key.keyPair.get();
            int result = writeKeyToBIO(pemKeyBIO.get(), tmpEVP);
            if (!result) {
                throw openssl_error("Unable to convert key to pem: ");
            }
            char* buffer;
            auto len = BIO_get_mem_data(pemKeyBIO.get(), &buffer);
            if (!len) {
                throw openssl_error("Unable to retrieve key from bio: ");
            }
            std::string pem;
            pem.resize(len);
            std::memcpy(pem.data(), buffer, len);
            return pem;
        }

        public:
        std::string kid;

        JwkGenerator() {
            kid = detail::generate_uuid_v4();
        }

        std::string private_to_pem() {
            return to_pem([](auto bio, auto key) {
                return PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, 0, NULL);
            });
        }

        std::string public_to_pem() {
            return to_pem([](auto bio, auto key) {
                return PEM_write_bio_PUBKEY(bio, key);
            });
        }

        nlohmann::json to_json() const {
            nlohmann::json json;
            key.insertJson(json);
            json["kid"] = kid;
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
            std::tuple<JwkGenerator<KeySpec>...> keys;
            nlohmann::json to_json() const {
                using namespace nlohmann;
                json jwks;
                std::apply([&jwks](const auto&... jwk) {
                    jwks["keys"] = std::array<json, std::tuple_size<decltype(keys)>{}> {jwk.to_json()...};
                }, keys);
                return jwks;
            }

            template <size_t idx>
            auto get() {
                return std::get<idx>(keys);
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
