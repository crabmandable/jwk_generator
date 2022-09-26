#pragma once

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
#include <tuple>
#include <stdint.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

#include "jwk_generator/base64_url.hpp"
#include "jwk_generator/uuid.hpp"
#include "jwk_generator/json.hpp"

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

    template<size_t shaBits>
    struct RSAKey {
        std::shared_ptr<EVP_PKEY> keyPair;
        std::string modulous;
        std::string exponent;

        RSAKey() {
            using namespace detail;

            size_t len;
            keyPair = {EVP_RSA_gen(2048), EVP_PKEY_free};
            if (!keyPair) {
                throw std::runtime_error(std::string("Unable to generate rsa key: ") + OpenSSLLastError());
            }
            auto modBN = std::shared_ptr<BIGNUM>{BN_new(), BN_free};
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
            modulous = base64_url_encode(modBin);

            auto exBN = std::shared_ptr<BIGNUM>{BN_new(), BN_free};
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

            size_t len;
            keyPair = {EVP_EC_gen(ECDSABitsToCurve(nBits)), EVP_PKEY_free};
            if (!keyPair) {
                throw std::runtime_error(std::string("Unable to generate ec key: ") + OpenSSLLastError());
            }
            auto xBN = std::shared_ptr<BIGNUM>{BN_new(), BN_free};
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
            pointX = base64_url_encode(xBin);

            auto yBN = std::shared_ptr<BIGNUM>(BN_new(), BN_free);
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
                throw std::runtime_error(std::string("Unable to retrieve public key: ") + OpenSSLLastError());
            }
            EVP_PKEY* tmpEVP = key.keyPair.get();
            int result = writeKeyToBIO(pemKeyBIO.get(), tmpEVP);
            if (!result) {
                throw std::runtime_error(std::string("Unable to convert key to pem: ") + OpenSSLLastError());
            }
            char* buffer;
            auto len = BIO_get_mem_data(pemKeyBIO.get(), &buffer);
            if (!len) {
                throw std::runtime_error(std::string("Unable to retrieve key from bio: ") + OpenSSLLastError());
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
