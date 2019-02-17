#pragma once

#define _CRT_SECURE_NO_WARNINGS

#include <string>


class AES128 {
	/* Serves as the initial round during encryption
	* AddRoundKey is simply an XOR of a 128-bit block with the 128-bit key.
	*/
	void AddRoundKey(unsigned char * state, unsigned char * roundKey);

	/* Perform substitution to each of the 16 bytes
	* Uses S-box as lookup table
	*/
	void E_SubBytes(unsigned char * state);

	// Shift left, adds diffusion
	void E_ShiftRows(unsigned char * state);

	/* MixColumns uses mul2, mul3 look-up tables
	* Source of diffusion
	*/
	void MixColumns(unsigned char * state);

	/* Each round operates on 128 bits at a time
	* The number of rounds is defined in AESEncrypt()
	*/
	void E_Round(unsigned char * state, unsigned char * key);

	// Same as Round() except it doesn't mix columns
	void FinalRound(unsigned char * state, unsigned char * key);

	/* Used in Round() and serves as the final round during decryption
	* SubRoundKey is simply an XOR of a 128-bit block with the 128-bit key.
	* So basically does the same as AddRoundKey in the encryption
	*/
	void SubRoundKey(unsigned char * state, unsigned char * roundKey);

	/* InverseMixColumns uses mul9, mul11, mul13, mul14 look-up tables
	* Unmixes the columns by reversing the effect of MixColumns in encryption
	*/
	void InverseMixColumns(unsigned char * state);

	// Shifts rows right (rather than left) for decryption
	void D_ShiftRows(unsigned char * state);

	/* Perform substitution to each of the 16 bytes
	* Uses inverse S-box as lookup table
	*/
	void D_SubBytes(unsigned char * state);

	/* Each round operates on 128 bits at a time
	* The number of rounds is defined in AESDecrypt()
	* Not surprisingly, the steps are the encryption steps but reversed
	*/
	void D_Round(unsigned char * state, unsigned char * key);

	// Same as Round() but no InverseMixColumns
	void InitialRound(unsigned char * state, unsigned char * key);

	/* The AES encryption function
	* Organizes the confusion and diffusion steps into one function
	*/
	void AESEncrypt(unsigned char * message, unsigned char * expandedKey, unsigned char * encryptedMessage);

	/* The AES decryption function
	* Organizes all the decryption steps into one function
	*/
	void AESDecrypt(unsigned char * encryptedMessage, unsigned char * expandedKey, unsigned char * decryptedMessage);

public:
	std::string CustomEncrypter(std::string Decrypted_Data, std::string Crypt_Key);
	std::string CustomDecrypter(std::string Encrypted_Data, std::string Crypt_Key);

};