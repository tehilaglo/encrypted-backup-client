/**
 * @file RSAWrapper.h
 * @brief Declares RSA public/private key wrapper classes.
 *
 * @details
 * This module provides lightweight C++ wrappers around Crypto++ RSA public and
 * private key operations. The wrappers support key serialization, encryption,
 * decryption, and public-key derivation from a private key.
 *
 * @author Tehila Cahnaman
 */

#pragma once

#include <string>

#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>

/**
 * @class RSAPublicWrapper
 * @brief Wraps a Crypto++ RSA public key.
 *
 * @details
 * This class loads serialized RSA public keys, exports public keys, and encrypts
 * plaintext using RSA-OAEP-SHA. Copying is disabled because the wrapper owns
 * cryptographic key state and a random generator.
 */
class RSAPublicWrapper
{
public:
    /** Defines the size of the cryptographic key used in specific operations */
    static const unsigned int KEYSIZE = 160;

    /** Defines the default RSA key size in bits */
    static const unsigned int BITS = 1024;

    /**
     * @brief Constructs an RSAPublicWrapper instance by loading a serialized RSA public key.
     *
     * @param key A pointer to a buffer containing the serialized RSA public key.
     * @param length The size of the key buffer in bytes. This value determines the amount of
     *               data to be read from the buffer for public key loading.
     *
     * @throws std::invalid_argument If the key buffer is null while the specified length
     *                               is greater than zero.
     */
    RSAPublicWrapper(const char* key, size_t length);

    /**
     * @brief Constructs an RSAPublicWrapper with an RSA public key provided as a string.
     *
     * @param key A string containing the serialized RSA public key to be loaded.
     */
    explicit RSAPublicWrapper(const std::string& key);

    /**
     * @brief Default destructor for the RSAPublicWrapper class.
     */
    ~RSAPublicWrapper();

    RSAPublicWrapper(const RSAPublicWrapper&) = delete;
    RSAPublicWrapper& operator=(const RSAPublicWrapper&) = delete;

    /**
     * @brief Retrieves the serialized RSA public key.
     *
     * @return A string containing the serialized RSA public key.
     */
    std::string getPublicKey() const;

    /**
     * @brief Exports the RSA public key to the provided buffer.
     *
     * @param keyout A pointer to the buffer where the public key will be written.
     *               This buffer must be pre-allocated by the caller.
     * @param length The length of the buffer in bytes. It should be large enough
     *               to accommodate the serialized key.
     *
     * @return A pointer to the same buffer provided in the `keyout` parameter.
     *
     * @throws std::invalid_argument If the `keyout` parameter is null.
     */
    char* getPublicKey(char* keyout, size_t length) const;

    /**
     * @brief Encrypts plaintext using the RSA-OAEP-SHA algorithm.
     *
     * @param plain The plaintext input to be encrypted.
     * @return A string containing the resulting ciphertext after encryption.
     */
    std::string encrypt(const std::string& plain);

    /**
     * @brief Encrypts plaintext using RSA-OAEP-SHA.
     *
     * @param plain Pointer to the plaintext buffer to be encrypted. The buffer
     * must not be null if the length is greater than 0.
     * @param length The size of the plaintext buffer in bytes.
     *
     * @return A string containing the encrypted ciphertext.
     *
     * @throws std::invalid_argument If the plaintext buffer is null while the
     * length is greater than 0.
     */
    std::string encrypt(const char* plain, size_t length);

private:

    /** Cryptographically secure random number generator */
    CryptoPP::AutoSeededRandomPool rng_;
    /** Represents the RSA public key used for cryptographic operations */
    CryptoPP::RSA::PublicKey public_key_;
};

/**
 * @class RSAPrivateWrapper
 * @brief Wraps a Crypto++ RSA private key.
 *
 * @details
 * This class generates or loads RSA private keys, exports private keys, derives
 * the matching public key, and decrypts ciphertext using RSA-OAEP-SHA. Copying
 * is disabled because the wrapper owns cryptographic key state and a random
 * generator.
 */
class RSAPrivateWrapper
{
public:

    /** Defines the key size in bits for RSA cryptographic operations */
    static const unsigned int BITS = 1024;

    /**
     * @brief Constructs a new RSA private key wrapper and generates a fresh private key.
     */
    RSAPrivateWrapper();

    /**
     * @brief Constructs an RSA private key wrapper from raw serialized key bytes.
     *
     * @param key Pointer to serialized private key data.
     * @param length Number of bytes in the serialized key.
     *
     * @throws std::invalid_argument if key is null while length is non-zero.
     */
    RSAPrivateWrapper(const char* key, size_t length);

    /**
     * @brief Constructs an RSA private key wrapper from a serialized key string.
     *
     * @param key Serialized private key.
     */
    explicit RSAPrivateWrapper(const std::string& key);

    /**
     * @brief Default destructor for the RSAPrivateWrapper class.
     */
    ~RSAPrivateWrapper();

    RSAPrivateWrapper(const RSAPrivateWrapper&) = delete;
    RSAPrivateWrapper& operator=(const RSAPrivateWrapper&) = delete;

    /**
     * @brief Serializes the RSA private key into a string.
     *
     * @return Serialized private key.
     */
    std::string getPrivateKey() const;

    /**
     * @brief Retrieves the serialized RSA private key and writes it to the specified buffer.
     *
     * @param keyout A pointer to the buffer where the serialized private key will be written.
     *               The buffer must be allocated and sized appropriately by the caller.
     * @param length The size of the provided buffer in bytes.
     *
     * @return A pointer to the same buffer passed in the `keyout` parameter, containing
     *         the serialized RSA private key.
     *
     * @throws std::invalid_argument If the `keyout` buffer is nullptr.
     */
    char* getPrivateKey(char* keyout, size_t length) const;

    /**
     * @brief Extracts the RSA public key from the current private key.
     *
     * @return A serialized string representation of the RSA public key.
     */
    std::string getPublicKey() const;

    /**
     * @brief Retrieves the RSA public key associated with the private key.
     *
     * @param keyout A pointer to the output buffer where the public key will be written.
     *               This buffer must not be null.
     * @param length The length of the output buffer in bytes. It must be large enough
     *               to accommodate the serialized public key.
     *
     * @return Returns the same pointer to the output buffer (`keyout`) after the public key
     *         has been written to it.
     *
     * @throws std::invalid_argument If `keyout` is null.
     */
    char* getPublicKey(char* keyout, size_t length) const;

    /**
     * @brief Decrypts the given ciphertext using the RSA private key.
     *
     * @param cipher The ciphertext to decrypt, provided as a binary-encoded string.
     *
     * @return The decrypted plaintext string.
     *
     * @throws std::runtime_error If decryption fails due to invalid ciphertext
     *         or cryptographic errors.
     */
    std::string decrypt(const std::string& cipher);

    /**
     * @brief Decrypts ciphertext using the RSA private key.
     *
     * @param cipher A pointer to the buffer containing the encrypted data.
     *               The buffer must not be null if the length is greater than zero.
     * @param length The size of the ciphertext buffer in bytes.
     *               Must be non-negative.
     *
     * @return A string containing the decrypted plaintext.
     *
     * @throws std::invalid_argument If the ciphertext buffer is null and the length
     *                               is greater than zero.
     */
    std::string decrypt(const char* cipher, size_t length);

    /**
     * @brief Decrypts a Base64-encoded ciphertext using the RSA private key.
     *
     * @param base64_cipher The Base64-encoded ciphertext to decrypt.
     *                      This string must represent a valid RSA-encrypted binary message in Base64 format.
     *
     * @return The decrypted plaintext as a string.
     */
    std::string decrypt_base64(const std::string& base64_cipher);

private:
    /** Cryptographic random number generator */
    CryptoPP::AutoSeededRandomPool rng_;

    /** Stores an RSA private key for cryptographic operations */
    CryptoPP::RSA::PrivateKey private_key_;
};
