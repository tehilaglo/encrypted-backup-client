/**
 * @file AESWrapper.cpp
 * @brief Implements AES-CBC encryption and decryption helpers.
 *
 * @details
 * This module wraps Crypto++ AES-CBC functionality for symmetric encryption.
 * Encryption generates a random IV for each message and prepends the IV to the
 * ciphertext. Decryption expects the input buffer to contain the IV followed by
 * the encrypted payload.
 *
 * @author Tehila Cahnaman
 */

#include "crypto/AESWrapper.h"

#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <stdexcept>

/**
 * @brief Generates a random symmetric key for AES encryption.
 *
 * This method fills the provided buffer with cryptographically secure random bytes,
 * suitable for use as a symmetric encryption key for AES operations. The size of
 * the key is determined by the `length` parameter, which must specify a value
 * appropriate for AES (e.g., 16, 24, or 32 bytes for AES-128, AES-192, or AES-256, respectively).
 *
 * @param buffer A pointer to a buffer where the generated key will be stored.
 *               The buffer must be allocated with enough space to hold the specified length.
 * @param length The length of the key to be generated in bytes.
 * @return A pointer to the buffer containing the generated key.
 * @throws std::invalid_argument If the provided buffer is null.
 */
unsigned char* AESWrapper::GenerateKey(unsigned char* buffer, unsigned int length)
{
    if (buffer == nullptr)
    {
        throw std::invalid_argument("AES key buffer cannot be null.");
    }

    CryptoPP::AutoSeededRandomPool rng;
    rng.GenerateBlock(buffer, length);

    return buffer;
}

/**
 * @brief Constructs an AESWrapper object and generates a default symmetric key.
 *
 * The constructor initializes the `key_` member variable by generating a random
 * symmetric encryption key with a default length (`DEFAULT_KEY_LEN`). This key
 * is used for AES encryption and decryption operations.
 *
 * @return An instance of the AESWrapper class with the generated symmetric key.
 * @throws std::invalid_argument if the key buffer is null during key generation.
 */
AESWrapper::AESWrapper()
{
    GenerateKey(key_, DEFAULT_KEY_LEN);
}

/**
 * @brief Constructs an AESWrapper instance with a specified encryption key.
 *
 * This constructor initializes the AESWrapper object with a user-provided symmetric
 * encryption key. The key is validated to ensure it is not null and matches the
 * required length, as specified by `DEFAULT_KEY_LEN`.
 *
 * @param key A pointer to the user-provided symmetric key buffer. The key must not be null.
 * @param length The length of the provided key in bytes. This must match `DEFAULT_KEY_LEN`.
 * @throws std::invalid_argument If the provided key is null.
 * @throws std::length_error If the provided key length does not match `DEFAULT_KEY_LEN`.
 */
AESWrapper::AESWrapper(const unsigned char* key, unsigned int length)
{
    if (key == nullptr)
    {
        throw std::invalid_argument("AES key cannot be null.");
    }

    if (length != DEFAULT_KEY_LEN)
    {
        throw std::length_error("AES key length must be 32 bytes.");
    }

    CryptoPP::memcpy_s(key_, DEFAULT_KEY_LEN, key, length);
}

/**
 * @brief Default destructor for the AESWrapper class.
 */
AESWrapper::~AESWrapper() = default;

/**
 * @brief Returns the raw AES key.
 *
 * @return Pointer to the internal AES key buffer.
 */
const unsigned char* AESWrapper::getKey() const
{
    return key_;
}

/**
 * @brief Encrypts plaintext using AES-CBC with a random IV.
 *
 * @param plain Pointer to plaintext data.
 * @param length Plaintext length in bytes.
 * @return Binary string containing IV followed by ciphertext.
 *
 * @throws std::invalid_argument if plain is null while length is non-zero.
 */
std::string AESWrapper::encrypt(const char* plain, unsigned int length)
{
    if (plain == nullptr && length > 0)
    {
        throw std::invalid_argument("Plaintext buffer cannot be null.");
    }

    CryptoPP::AutoSeededRandomPool rng;

    CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = {};
    rng.GenerateBlock(iv, CryptoPP::AES::BLOCKSIZE);

    CryptoPP::AES::Encryption aes_encryption(key_, DEFAULT_KEY_LEN);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbc_encryption(
        aes_encryption,
        iv
    );

    std::string cipher;

    CryptoPP::StreamTransformationFilter encryptor(
        cbc_encryption,
        new CryptoPP::StringSink(cipher)
    );

    encryptor.Put(reinterpret_cast<const CryptoPP::byte*>(plain), length);
    encryptor.MessageEnd();

    // Store IV with ciphertext so decryption can reconstruct the CBC state.
    std::string result(
        reinterpret_cast<const char*>(iv),
        CryptoPP::AES::BLOCKSIZE
    );

    result += cipher;
    return result;
}

/**
 * @brief Decrypts ciphertext using AES encryption in CBC mode.
 *
 * This method decrypts the provided ciphertext using the AES algorithm
 * in CBC mode with a predefined key. The first block of the ciphertext
 * is treated as an initialization vector (IV), and the remaining data is
 * decrypted to produce the original plaintext.
 *
 * @param cipher A pointer to the ciphertext buffer, which includes the IV as the first block.
 * @param length The length of the ciphertext buffer in bytes. It must be at least the AES block size.
 * @return A string containing the decrypted plaintext.
 * @throws std::invalid_argument If the ciphertext buffer is null.
 * @throws std::runtime_error If the ciphertext is too short to contain an IV and valid encrypted data.
 */std::string AESWrapper::decrypt(const char* cipher, unsigned int length)
{
    if (cipher == nullptr)
    {
        throw std::invalid_argument("Ciphertext buffer cannot be null.");
    }

    if (length < CryptoPP::AES::BLOCKSIZE)
    {
        throw std::runtime_error(
            "Ciphertext is too short to contain an IV and encrypted data."
        );
    }

    CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = {};
    std::memcpy(iv, cipher, CryptoPP::AES::BLOCKSIZE);

    CryptoPP::AES::Decryption aes_decryption(key_, DEFAULT_KEY_LEN);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbc_decryption(
        aes_decryption,
        iv
    );

    std::string decrypted;

    CryptoPP::StreamTransformationFilter decryptor(
        cbc_decryption,
        new CryptoPP::StringSink(decrypted)
    );

    decryptor.Put(
        reinterpret_cast<const CryptoPP::byte*>(cipher + CryptoPP::AES::BLOCKSIZE),
        length - CryptoPP::AES::BLOCKSIZE
    );

    decryptor.MessageEnd();

    return decrypted;
}
