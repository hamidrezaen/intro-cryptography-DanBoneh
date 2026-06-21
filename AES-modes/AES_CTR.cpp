#include <cryptopp/aes.h>
#include <cryptopp/osrng.h>

#include <iostream>
#include <string>
#include <vector>
#include <cstdint>
using namespace std;

int DEFAULT_BLOCK_SIZE = 16;

class AES_CTR{
    private:
        string cipher_text, plain_text, key;
        vector<uint8_t> hexStrToByteArr(const string& hexStr);
        uint8_t* addOne(uint8_t* arr);

        string decryptCTR(string cipher_text, string key);
        // hex ct/key -> byte ct/key -> split IV
        // F(k,IV+i) -> xor with c[i]

    public:
        AES_CTR(bool is_encoded, string text, string key);
        string get_cipher_text();
        string get_plain_text();
};

int main(){
    string key = "36f18357be4dbd77f050515c73fcf9f2";
    
    string ct1 = "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329";
    AES_CTR c1(1, ct1, key);
    cout << "the first plain text is: "
    << c1.get_plain_text() << endl
    << endl;

    string ct2 = "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451";
    AES_CTR c2(1, ct2, key);
    cout << "the second plain text is: " 
    << c2.get_plain_text() << endl
    << endl;
}

AES_CTR::AES_CTR(bool is_encoded, string text, string key)
{
	this->key = key;
	if(is_encoded){
		cipher_text = text;
		plain_text = decryptCTR(cipher_text, key);
	}
	else
	{
		plain_text = text;
		// cipher_text = encryptCTR(plain_text, key);
	}
}

string AES_CTR::decryptCTR(string cipher_text, string key)
{
    vector<uint8_t> ct_in_bytes = hexStrToByteArr(cipher_text);
    vector<uint8_t> key_in_bytes = hexStrToByteArr(key);

    uint8_t IV[DEFAULT_BLOCK_SIZE];
    for(int i=0; i<16; i++)
        IV[i] = ct_in_bytes[i];
    
    // //debug
    // cout << "The cipher text is: ";
    // for(uint8_t byte: ct_in_bytes)
    //     cout << static_cast<int>(byte) << " ";
    // cout << endl;

    // cout << "The IV is: ";
    // for(uint8_t byte: IV)
    //     cout << static_cast<int>(byte) << " ";
    // cout << endl;   
    // // debug

    vector<uint8_t> pt_in_bytes;
    CryptoPP::AES::Encryption aesEncryption(key_in_bytes.data(), key_in_bytes.size());
    for(int i=DEFAULT_BLOCK_SIZE; i<ct_in_bytes.size(); i+=DEFAULT_BLOCK_SIZE)
    {
        uint8_t block[DEFAULT_BLOCK_SIZE], prf_out[DEFAULT_BLOCK_SIZE];
        
        int j = 0;
        while(j < DEFAULT_BLOCK_SIZE && i+j < ct_in_bytes.size())
            block[j++] = ct_in_bytes[i+j];
        
        aesEncryption.ProcessBlock(IV, prf_out); 

        int filled = j;
        for(int j=0; j < filled; j++)
			{
				int xor_ans = static_cast<int>(block[j] ^ prf_out[j]);
				pt_in_bytes.push_back(xor_ans);
            }
        addOne(IV);
    }
    
    // // debug
    // for(uint8_t byte: pt_in_bytes)
    //     cout << static_cast<char>(byte);
    // cout << endl;
    // // debug

    string plain_text = "";
    for(uint8_t byte:pt_in_bytes)
        plain_text += static_cast<char>(byte);
    return plain_text;
}

vector<uint8_t> AES_CTR::hexStrToByteArr(const string& hexStr)
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

uint8_t* AES_CTR::addOne(uint8_t* arr)
{
    int i = DEFAULT_BLOCK_SIZE - 1;
    while(arr[i] == 255)
        arr[i--]=0;
    arr[i] += 1;
    return arr;
}

string AES_CTR::get_plain_text(){ return plain_text; }
string AES_CTR::get_cipher_text(){ return cipher_text; }