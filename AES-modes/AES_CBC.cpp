#include <cryptopp/aes.h>
#include <cryptopp/osrng.h>

#include <iostream>
#include <string>
#include <vector>
#include <cstdint>

int DEFAULT_BLOCK_SIZE = 16;

using namespace std;

class CBC_MODE{

	private:
		vector<uint8_t> hexStrToByteArr(const string& hexStr);
		string byteArrToHexStr(const vector<uint8_t> byteArr);
		string cipher_text;
		string plain_text;
		string key;

		string decryptCBC(string ct, string key);
		// cipher text (hex) -> bytes -> strip IV 
		// -> decrypt -> strip padding -> plain text
		
		string encryptCBC(string pt, string key);
		// plain text -> add padding -> select IV
		// -> xor -> encrypt -> bytes to hex
		
	public:

		CBC_MODE(bool is_coded, string text, string k);
		// is_coded shows that the text is cipher or plain
		
		string get_plain_text();
		// return plaintext
		string get_cipher_text();
		// return ciphertext
};

int main(){
	string key = "140b41b22a29beb4061bda66b6747e14";

	string ct1 = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81";
	CBC_MODE c1(1, ct1, key);
	cout << "the first answer is: " << c1.get_plain_text() << endl;
	cout << endl;

	string ct2 = "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253";
	CBC_MODE c2(1, ct2, key);
	cout << "the second answer is: " << c2.get_plain_text() << endl;
	cout << endl;

	string pt1 = "Basic CBC mode encryption needs padding.";
	CBC_MODE p1(0, pt1, key);
	cout << p1.get_cipher_text() << endl;

	string ct3 = p1.get_cipher_text();
	CBC_MODE c3(1, ct3, key);
	cout << "the plain text of the above ciphered is: " << c3.get_plain_text() << endl;
	cout << endl;

	return 0;
}

string CBC_MODE::encryptCBC(string pt, string key)
{
	// // debug
	// cout << "the plaintext size before padding: " << (pt.size()) << endl;
	// // debug

	vector<uint8_t> pt_in_bytes;
	for(char ch: pt)
		pt_in_bytes.push_back(static_cast<uint8_t>(ch));
	
	vector<uint8_t> key_in_bytes = hexStrToByteArr(key);
	
	int pad_number = DEFAULT_BLOCK_SIZE - (pt.size() % DEFAULT_BLOCK_SIZE);
	for(int i=0; i<pad_number; i++)
		pt_in_bytes.push_back(static_cast<uint8_t>(pad_number));
	
	// // debug
	// for(uint8_t byte: pt_in_bytes)
	// 	cout << static_cast<int>(byte) << " ";
	// cout << endl;
	// // debug

	// Generating random IV
	CryptoPP::AutoSeededRandomPool prng;

	CryptoPP::SecByteBlock iv(DEFAULT_BLOCK_SIZE);
	prng.GenerateBlock(iv, iv.size());


	vector<uint8_t> ct_in_bytes;

	// c[i] xor c[i-1] (IV for c[0])
	uint8_t prev_block[DEFAULT_BLOCK_SIZE];
	for(int j=0; j<DEFAULT_BLOCK_SIZE; j++)
	{
		prev_block[j] = iv[j];
		ct_in_bytes.push_back(iv[j]);
	}

	CryptoPP::AES::Encryption aesEncryption(key_in_bytes.data(), key_in_bytes.size());
	
	for(size_t i=0; i< pt_in_bytes.size(); i+=DEFAULT_BLOCK_SIZE)
	{
		uint8_t xored[DEFAULT_BLOCK_SIZE];
		uint8_t block[DEFAULT_BLOCK_SIZE];
		uint8_t encrypted[DEFAULT_BLOCK_SIZE];
		
		for(int j=0; j<DEFAULT_BLOCK_SIZE; j++)
			block[j] = pt_in_bytes[i+j];

		for(int j=0; j<DEFAULT_BLOCK_SIZE; j++)
		{
			uint8_t xor_ans = (block[j] ^ prev_block[j]);
			xored[j] = xor_ans;
		}

		aesEncryption.ProcessBlock(xored, encrypted);

		for(int j=0; j<DEFAULT_BLOCK_SIZE; j++)
		{
			ct_in_bytes.push_back(encrypted[j]);
			prev_block[j] = encrypted[j];
		}
	}
	string cipher_text = byteArrToHexStr(ct_in_bytes);
	return cipher_text;
}

string CBC_MODE::decryptCBC(string ct, string key)
{

	// cipher text (hex) -> bytes -> strip IV 
	// -> decrypt -> strip padding -> plain text

	// // debug
	// cout << "cipher text is: " << ct << endl;
	// cout << "key is: " << key << endl;
	// // debug

	vector<uint8_t> ct_in_bytes = hexStrToByteArr(ct);
	vector<uint8_t> key_in_bytes = hexStrToByteArr(key);

	// // debug
	// cout << "cipher text in bytes: ";
	// for(uint8_t byte: ct_in_bytes)
	// 	cout << static_cast<int>(byte) << " ";
	// cout << endl;

	// cout << "key in bytes: ";
	// for(uint8_t byte: key)
	// 	cout << static_cast<int>(byte) << " ";
	// cout << endl;
	// // debug

	
	// strip IV
	uint8_t IV[DEFAULT_BLOCK_SIZE];
	for (int i=0; i<DEFAULT_BLOCK_SIZE; i++){
		IV[i] = ct_in_bytes[i];
	}
	
	// // debug
	// cout << "IV in bytes: ";
	// for(uint8_t byte: IV)
	// 	cout << static_cast<int>(byte) << " ";
	// cout << endl;
	// // debug

	// decrypt
	// dec(c[i]) xor c[i-1] (IV for c0)
	vector<uint8_t> pt_vec;
	uint8_t prev_block[DEFAULT_BLOCK_SIZE];
	for(int i=DEFAULT_BLOCK_SIZE; i<ct_in_bytes.size(); i+=DEFAULT_BLOCK_SIZE)
	{
		// // debug
		// cout << endl;
		// // debug

		uint8_t block[DEFAULT_BLOCK_SIZE], decrypted[DEFAULT_BLOCK_SIZE];

		for(int j=0; j<DEFAULT_BLOCK_SIZE; j++)
			block[j] = ct_in_bytes[i+j];
		
		// // debug
		// cout << "ITERATION: " << i/DEFAULT_BLOCK_SIZE << endl
		// << "BLOCK: ";
		// for(uint8_t byte: block)
		// 	cout << static_cast<int>(byte) << " ";
		// cout << endl;
		// // debug

		// decrypted[i] = decrypt(block[i])
		CryptoPP::AES::Decryption aesDecryption(key_in_bytes.data(), key_in_bytes.size());
		aesDecryption.ProcessBlock(block, decrypted);
		
		// // debug 
		// cout << "DECRYPTION COMPLETED." << endl
		// << "decrypted: ";
		// for(uint8_t byte: decrypted)
		// 	cout << static_cast<int>(byte) << " ";
		// cout << endl;
		// // debug

		// xor c[i-1] (IV for c0)
		// if is the first block: xor IV
		if (i==DEFAULT_BLOCK_SIZE)
		{
			// // debug
			// cout << "This is the first block. xoring with IV..."  << endl;
			// // debug

			for(int j=0; j<DEFAULT_BLOCK_SIZE; j++)
			{
				int xor_ans = static_cast<int>(decrypted[j] ^ IV[j]);
				pt_vec.push_back(xor_ans);
				
				// // debug
				// cout << static_cast<int>(decrypted[j]) << " xor " << static_cast<int>(IV[j]) << " = " << xor_ans << endl;
				// // debug
			}
		}
		else{
			// // debug
			// cout << "the previous block is: ";
			// for(uint8_t byte: prev_block)
			// 	cout << static_cast<int>(byte) << " ";
			// cout << endl;
			// cout << "This is the " << i/DEFAULT_BLOCK_SIZE << " block. xoring with the last one..." << endl;
			// // debug

			for(int j=0; j<DEFAULT_BLOCK_SIZE; j++)
			{
				int xor_ans = static_cast<int>(decrypted[j] ^ prev_block[j]);
				pt_vec.push_back(xor_ans);
				
				// // debug
				// cout << static_cast<int>(decrypted[j]) << " xor " << static_cast<int>(prev_block[j])
				// << " = " << xor_ans << endl;
				// // debug
			}
		}
		for(int j=0; j<DEFAULT_BLOCK_SIZE; j++)
			prev_block[j] = block[j];
	}

	// // debug
	// for(uint8_t byte: pt_vec)
	// 	cout << static_cast<char>(byte);
	// cout << endl;
	// // debug

	int padd_num = static_cast<int>(pt_vec.back());

	// // debug
	// cout << "padd number: " << padd_num << endl;
	// // debug

	for (int i=0; i<padd_num; i++)
		pt_vec.pop_back();

	
	string plain_text = "";
	for (uint8_t byte: pt_vec)
		plain_text += static_cast<char>(byte);

	// // debug
	// cout << "plain text size after remove padding is: " << plain_text.size() << endl;
	// // debug

	return plain_text;
}


vector<uint8_t> CBC_MODE::hexStrToByteArr(const string& hexStr)
{
	vector<uint8_t> byteArr;
	for (size_t i=0; i<hexStr.length(); i+=2)
	{
		string byteStr = hexStr.substr(i,2);

		uint8_t byteVal = static_cast<uint8_t>(stoi(byteStr, nullptr, 16));
		byteArr.push_back(byteVal);
	}

	return byteArr;
}

string CBC_MODE::byteArrToHexStr(const vector<uint8_t> byteArr)
{
	// // debug
	// for(uint8_t byte: byteArr)
	// 	cout << static_cast<int>(byte) << ' ';
	// cout << endl;
	// // debug
	
	string hexStr = "";
	const char hexDigits[] = {"0123456789abcdef"};
	for (uint8_t byte: byteArr)
	{
		hexStr += hexDigits[byte / 16];
		hexStr += hexDigits[byte % 16];
	}
	return hexStr;
}

CBC_MODE::CBC_MODE(bool is_coded, string text, string k)
{
	key = k;
	if(is_coded){
		cipher_text = text;
		plain_text = decryptCBC(cipher_text, key);
	}
	else
	{
		plain_text = text;
		cipher_text = encryptCBC(plain_text, key);
	}
}

string CBC_MODE::get_plain_text()
{
	return plain_text;
}
string CBC_MODE::get_cipher_text()
{
	return cipher_text;
}