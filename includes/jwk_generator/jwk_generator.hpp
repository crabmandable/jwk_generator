#pragma once

#include <sstream>
#include <stdexcept>
#include <string>
#include <memory>
#include <tuple>
#include <stdint.h>

#include <openssl/bio.h>
#include <openssl/pem.h>

#include "jwk_generator//libs/base64_url.hpp"
#include "jwk_generator/libs/uuid.hpp"
#include "jwk_generator/libs/json.hpp"
#include "jwk_generator/errors.hpp"
#include "jwk_generator/keyspecs/ecdsa_key.hpp"
#include "jwk_generator/keyspecs/rsa_key.hpp"

namespace jwk_generator {
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
            key.insert_json(json);
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
