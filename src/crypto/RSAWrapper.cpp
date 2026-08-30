/**
 * @file RSAWrapper.cpp
 * @brief Implements RSA encryption, decryption, and key serialization helpers.
 *
 * @details
 * This module wraps Crypto++ RSA public/private key operations used by the
 * encrypted backup client. It supports loading serialized keys, exporting keys,
 * RSA-OAEP encryption/decryption, and Base64-decoded ciphertext decryption.
 *
 * @author Tehila Cahnaman
 */

#include "crypto/RSAWrapper.h"

#include <cryptopp/base64.h>
#include <cryptopp/filters.h>
#include <stdexcept>
#include <string>

/**
 * @brief Constructs an RSAPublicWrapper instance by loading a serialized RSA public key.
 *
 * @details
 * This constructor initializes the RSAPublicWrapper instance using a provided
 * serialized RSA public key.
 *
 * @param key A pointer to a buffer containing the serialized RSA public key.
 * @param length The size of the key buffer in bytes. This value determines the amount of
 *               data to be read from the buffer for public key loading.
 *
 * @throws std::invalid_argument If the key buffer is null while the specified length
 *                               is greater than zero.
 */
RSAPublicWrapper::RSAPublicWrapper(const char* key, size_t length)
{
    if (key == nullptr && length > 0)
    {
        throw std::invalid_argument("Public key buffer cannot be null.");
    }

    CryptoPP::StringSource source(
        reinterpret_cast<const CryptoPP::byte*>(key),
        length,
        true
    );

    public_key_.Load(source);
}

/**
 * @brief Constructs an RSAPublicWrapper with an RSA public key provided as a string.
 *
 * @details
 * This constructor initializes the RSAPublicWrapper object by loading the provided
 * serialized RSA public key.
 *
 * @param key A string containing the serialized RSA public key to be loaded.
 */
RSAPublicWrapper::RSAPublicWrapper(const std::string& key)
{
    CryptoPP::StringSource source(key, true);
    public_key_.Load(source);
}

/**
 * @brief Default destructor for the RSAPublicWrapper class.
 */
RSAPublicWrapper::~RSAPublicWrapper() = default;

/**
 * @brief Retrieves the serialized RSA public key.
 *
 * @details
 * This method exports the loaded RSA public key as a serialized string.
 *
 * @return A string containing the serialized RSA public key.
 */
std::string RSAPublicWrapper::getPublicKey() const
{
    std::string key;
    CryptoPP::StringSink sink(key);

    public_key_.Save(sink);

    return key;
}

/**
 * @brief Exports the RSA public key to the provided buffer.
 *
 * @details
 * This method saves the serialized RSA public key into a user-supplied buffer.
 * The buffer must have sufficient capacity to hold the serialized key, which
 * depends on the key size used during the RSA key generation.
 *
 * @param keyout A pointer to the buffer where the public key will be written.
 *               This buffer must be pre-allocated by the caller.
 * @param length The length of the buffer in bytes. It should be large enough
 *               to accommodate the serialized key.
 * @return A pointer to the same buffer provided in the `keyout` parameter.
 * @throws std::invalid_argument If the `keyout` parameter is null.
 */
char* RSAPublicWrapper::getPublicKey(char* keyout, size_t length) const
{
    if (keyout == nullptr)
    {
        throw std::invalid_argument("Public key output buffer cannot be null.");
    }

    CryptoPP::ArraySink sink(
        reinterpret_cast<CryptoPP::byte*>(keyout),
        length
    );

    public_key_.Save(sink);

    return keyout;
}

/**
 * @brief Encrypts plaintext using the RSA-OAEP-SHA algorithm.
 *
 * @details
 * This method performs encryption on the given plaintext using an RSA public key
 * and the OAEP-SHA padding scheme. The encrypted data is returned as a string.
 *
 * @param plain The plaintext input to be encrypted.
 * @return A string containing the resulting ciphertext after encryption.
 */
std::string RSAPublicWrapper::encrypt(const std::string& plain)
{
    std::string cipher;
    CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(public_key_);

    CryptoPP::StringSource source(
        plain,
        true,
        new CryptoPP::PK_EncryptorFilter(
            rng_,
            encryptor,
            new CryptoPP::StringSink(cipher)
        )
    );

    return cipher;
}

/**
 * @brief Encrypts plaintext using RSA-OAEP-SHA.
 *
 * @details
 * This method encrypts the provided plaintext buffer using the RSA public key
 * stored in this wrapper. The encryption utilizes RSA-OAEP-SHA algorithm,
 * producing a ciphertext that can later be decrypted using the corresponding
 * private key.
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
std::string RSAPublicWrapper::encrypt(const char* plain, size_t length)
{
    if (plain == nullptr && length > 0)
    {
        throw std::invalid_argument("Plaintext buffer cannot be null.");
    }

    std::string cipher;
    CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(public_key_);

    CryptoPP::StringSource source(
        reinterpret_cast<const CryptoPP::byte*>(plain),
        length,
        true,
        new CryptoPP::PK_EncryptorFilter(
            rng_,
            encryptor,
            new CryptoPP::StringSink(cipher)
        )
    );

    return cipher;
}

/**
 * @brief Constructs a new RSA private key wrapper and generates a fresh private key.
 */
RSAPrivateWrapper::RSAPrivateWrapper()
{
    private_key_.Initialize(rng_, BITS);
}

/**
 * @brief Constructs an RSA private key wrapper from raw serialized key bytes.
 *
 * @param key Pointer to serialized private key data.
 * @param length Number of bytes in the serialized key.
 *
 * @throws std::invalid_argument if key is null while length is non-zero.
 */
RSAPrivateWrapper::RSAPrivateWrapper(const char* key, size_t length)
{
    if (key == nullptr && length > 0)
    {
        throw std::invalid_argument("Private key buffer cannot be null.");
    }

    CryptoPP::StringSource source(
        reinterpret_cast<const CryptoPP::byte*>(key),
        length,
        true
    );

    private_key_.Load(source);
}

/**
 * @brief Constructs an RSA private key wrapper from a serialized key string.
 *
 * @param key Serialized private key.
 */
RSAPrivateWrapper::RSAPrivateWrapper(const std::string& key)
{
    CryptoPP::StringSource source(key, true);
    private_key_.Load(source);
}

/**
 * @brief Default destructor for the RSAPrivateWrapper class.
 */
RSAPrivateWrapper::~RSAPrivateWrapper() = default;

/**
 * @brief Serializes the RSA private key into a string.
 *
 * @return Serialized private key.
 */
std::string RSAPrivateWrapper::getPrivateKey() const
{
    std::string key;
    CryptoPP::StringSink sink(key);

    private_key_.Save(sink);

    return key;
}

/**
 * @brief Retrieves the serialized RSA private key and writes it to the specified buffer.
 *
 * @details
 * This method exports the internal RSA private key into a provided buffer
 * using the Crypto++ library. The serialized key is written into the given
 * buffer, and the buffer must be large enough to hold the key data.
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
char* RSAPrivateWrapper::getPrivateKey(char* keyout, size_t length) const
{
    if (keyout == nullptr)
    {
        throw std::invalid_argument("Private key output buffer cannot be null.");
    }

    CryptoPP::ArraySink sink(
        reinterpret_cast<CryptoPP::byte*>(keyout),
        length
    );

    private_key_.Save(sink);

    return keyout;
}

/**
 * @brief Extracts the RSA public key from the current private key.
 *
 * @details
 * This method constructs an RSA public key from the internally stored private key
 * and serializes it into a string format.
 *
 * @return A serialized string representation of the RSA public key.
 */
std::string RSAPrivateWrapper::getPublicKey() const
{
    CryptoPP::RSAFunction public_key(private_key_);

    std::string key;
    CryptoPP::StringSink sink(key);

    public_key.Save(sink);

    return key;
}

/**
 * @brief Retrieves the RSA public key associated with the private key.
 *
 * @details
 * This method extracts the RSA public key from the associated private key and
 * writes it into the provided output buffer. The output buffer must have
 * sufficient space to hold the serialized public key. An exception is thrown
 * if the output buffer is null.
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
char* RSAPrivateWrapper::getPublicKey(char* keyout, size_t length) const
{
    if (keyout == nullptr)
    {
        throw std::invalid_argument("Public key output buffer cannot be null.");
    }

    CryptoPP::RSAFunction public_key(private_key_);

    CryptoPP::ArraySink sink(
        reinterpret_cast<CryptoPP::byte*>(keyout),
        length
    );

    public_key.Save(sink);

    return keyout;
}

/**
 * @brief Decrypts the given ciphertext using the RSA private key.
 *
 * @details
 * This method decrypts a provided ciphertext string using the RSA-OAEP-SHA
 * decryption scheme. The method expects the input to be a binary-encoded
 * ciphertext that was encrypted with the corresponding RSA public key.
 *
 * @param cipher The ciphertext to decrypt, provided as a binary-encoded string.
 *
 * @return The decrypted plaintext string.
 *
 * @throws std::runtime_error If decryption fails due to invalid ciphertext
 *         or cryptographic errors.
 */
std::string RSAPrivateWrapper::decrypt(const std::string& cipher)
{
    std::string decrypted;
    CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(private_key_);

    CryptoPP::StringSource source(
        cipher,
        true,
        new CryptoPP::PK_DecryptorFilter(
            rng_,
            decryptor,
            new CryptoPP::StringSink(decrypted)
        )
    );

    return decrypted;
}

/**
 * @brief Decrypts ciphertext using the RSA private key.
 *
 * @details
 * This method decrypts the provided ciphertext using the RSA private key
 * initialized in the RSAPrivateWrapper class. The decryption uses the
 * RSAES-OAEP-SHA algorithm and a secure random number generator (RNG). The
 * method throws an exception if the provided ciphertext buffer is null
 * and the specified length is greater than zero.
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
std::string RSAPrivateWrapper::decrypt(const char* cipher, size_t length)
{
    if (cipher == nullptr && length > 0)
    {
        throw std::invalid_argument("Ciphertext buffer cannot be null.");
    }

    std::string decrypted;
    CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(private_key_);

    CryptoPP::StringSource source(
        reinterpret_cast<const CryptoPP::byte*>(cipher),
        length,
        true,
        new CryptoPP::PK_DecryptorFilter(
            rng_,
            decryptor,
            new CryptoPP::StringSink(decrypted)
        )
    );

    return decrypted;
}

/**
 * @brief Decrypts a Base64-encoded ciphertext using the RSA private key.
 *
 * @details
 * This method first decodes the provided Base64-encoded ciphertext into its raw binary representation.
 * It then decrypts the decoded data using the RSA private key associated with this instance.
 * The result is the plaintext string corresponding to the encrypted input.
 *
 * @param base64_cipher The Base64-encoded ciphertext to decrypt.
 *                      This string must represent a valid RSA-encrypted binary message in Base64 format.
 *
 * @return The decrypted plaintext as a string.
 */
std::string RSAPrivateWrapper::decrypt_base64(const std::string& base64_cipher)
{
    std::string decoded_cipher;

    CryptoPP::StringSource source(
        base64_cipher,
        true,
        new CryptoPP::Base64Decoder(
            new CryptoPP::StringSink(decoded_cipher)
        )
    );

    return decrypt(decoded_cipher);
}
