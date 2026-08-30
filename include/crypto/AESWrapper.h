/**
 * @file AESWrapper.h
 * @brief Declares an AES encryption/decryption wrapper.
 *
 * @details
 * This module provides a small wrapper around Crypto++ AES-CBC encryption.
 * The wrapper stores a symmetric key, supports random key generation, and
 * encrypts/decrypts binary buffers using AES-CBC.
 *
 * @author Tehila Cahnaman
 */

#pragma once

#include <string>

#include "protocol/protocol_types.h"


/**
 * @brief AESWrapper class for handling AES encryption and decryption operations.
 *
 * The AESWrapper class provides methods for encrypting and decrypting data
 * using the AES (Advanced Encryption Standard) algorithm. It internally manages
 * the symmetric key used for encryption and decryption tasks.
 */
class AESWrapper
{
public:

	/**
	* @brief Default length for symmetric encryption keys in AESWrapper.
	*
	* DEFAULT_KEY_LEN defines the length of the symmetric key used for AES encryption
	* and decryption within the AESWrapper class. It is set to the value of SYMMETRIC_KEY_LEN,
	* which defaults to 32 bytes (256 bits). This length is standard for AES-256 encryption.
	*/
	static const unsigned int DEFAULT_KEY_LEN = SYMMETRIC_KEY_LEN;

	/**
	 * @brief Generates a random symmetric key for AES encryption.
	 *
	 * @param buffer A pointer to a buffer where the generated key will be stored.
	 *               The buffer must be allocated with enough space to hold the specified length.
	 *
	 * @param length The length of the key to be generated in bytes.
	 *
	 * @return A pointer to the buffer containing the generated key.
	 *
	 * @throws std::invalid_argument If the provided buffer is null.
	 */
	static unsigned char* GenerateKey(unsigned char* buffer, unsigned int length);

	/**
	 * @brief Constructs an AESWrapper object and generates a default symmetric key.
	 *
	 * @return An instance of the AESWrapper class with the generated symmetric key.
	 *
	 * @throws std::invalid_argument if the key buffer is null during key generation.
	 */
	AESWrapper();

	/**
	 * @brief Constructs an AESWrapper instance with a specified encryption key.
	 *
	 * @param key A pointer to the user-provided symmetric key buffer. The key must not be null.
	 * @param length The length of the provided key in bytes. This must match `DEFAULT_KEY_LEN`.
	 *
	 * @throws std::invalid_argument If the provided key is null.
	 * @throws std::length_error If the provided key length does not match `DEFAULT_KEY_LEN`.
	 */
	AESWrapper(const unsigned char* key, unsigned int length);

	/**
	 * @brief Default destructor for the AESWrapper class.
	 */
	~AESWrapper();

	AESWrapper(const AESWrapper&) = delete;
	AESWrapper& operator=(const AESWrapper&) = delete;

	/**
	 * Returns the encryption key currently used by the AESWrapper instance.
	 *
	 * @return A pointer to the array holding the encryption key.
	 */
	const unsigned char* getKey() const;

	/**
	 * @brief Encrypts the given plaintext using a specified key.
	 *
	 * @param plaintext The data to be encrypted.
	 * @param key The key used to perform the encryption.
	 *
	 * @return The encrypted ciphertext as a result of the operation.
	 */
	std::string encrypt(const char* plain, unsigned int length);

	/**
	 * @brief Decrypts ciphertext using AES encryption in CBC mode.
	 *
	 * @param cipher A pointer to the ciphertext buffer, which includes the IV as the first block.
	 * @param length The length of the ciphertext buffer in bytes. It must be at least the AES block size.
	 *
	 * @return A string containing the decrypted plaintext.
	 *
	 * @throws std::invalid_argument If the ciphertext buffer is null.
	 * @throws std::runtime_error If the ciphertext is too short to contain an IV and valid encrypted data.
	 */
	std::string decrypt(const char* cipher, unsigned int length);

private:
	/** Internal buffer used to store the symmetric AES encryption key */
	unsigned char key_[DEFAULT_KEY_LEN]{};
};
