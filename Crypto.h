#ifndef CRYPTO_HEAD_FILE
#define CRYPTO_HEAD_FILE

#pragma once
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/md5.h>
#include <string.h>  
#include <iostream>
using namespace std;

//////////////////////////////////////////////////////////////////////////////////
namespace Crypto {
	static const int SHA_oid_ints[6] = {1, 3, 14, 3, 2, 26};
	static const int SHA256_oid_ints[9] = {2, 16, 840, 1, 101, 3, 4, 2, 1};
	static const int SHA384_oid_ints[9] = {2, 16, 840, 1, 101, 3, 4, 2, 2};
	static const int SHA512_oid_ints[9] = {2, 16, 840, 1, 101, 3, 4, 2, 3};

	class DerValue {
	public:
		static const unsigned char tag_OctetString = 0x04;
		static const unsigned char tag_Null = 0x05;
		static const unsigned char tag_ObjectId = 0x06;
		static const unsigned char tag_Sequence = 0x30;
	};//DerValue
	class DerOutputStream {
		friend class ObjectIdentifier;
	public:
		unsigned char* buf;
		int count;
		DerOutputStream() {
			buf = new unsigned char[33];
			count = 0;
		}
		void putLength(int len)
		{
			if (len < 128) {
				write((byte)len);

			} else if (len < (1 << 8)) {
				write((byte)0x081);
				write((byte)len);

			} else if (len < (1 << 16)) {
				write((byte)0x082);
				write((byte)(len >> 8));
				write((byte)len);

			} else if (len < (1 << 24)) {
				write((byte)0x083);
				write((byte)(len >> 16));
				write((byte)(len >> 8));
				write((byte)len);

			} else {
				write((byte)0x084);
				write((byte)(len >> 24));
				write((byte)(len >> 16));
				write((byte)(len >> 8));
				write((byte)len);
			}
		}

		void write(int b) {
			int newcount = count + 1;
			if (newcount > sizeof(buf)) {
				unsigned char* src = buf;
				int size = newcount;
				buf = new unsigned char[size];
				memcpy(buf, src, sizeof(src));
				delete src;
			}
			buf[count] = (char)b;
			count = newcount;
		}
		void write(unsigned char b[], int off, int len) {
			if ((off < 0) || (off > sizeof(b)) || (len < 0) ||
				((off + len) > sizeof(b)) || ((off + len) < 0)) {
				throw "长度不对";
			} else if (len == 0) {
				return;
			}
			int newcount = count + len;
			if (newcount > sizeof(buf)) {
				unsigned char* src = buf;
				int size = newcount;
				buf = new unsigned char[size];
				memcpy(buf, src, sizeof(src));
				delete src;
			}
			memcpy(buf+count, b+off, len);			
			count = newcount;
		}
		void reset() {
			count = 0;
		}
		unsigned char* tocharArray() {
			return buf;
		}
		//void putOID(ObjectIdentifier oid){
		//	oid.encode(this);
		//}
		void putOctetString(unsigned char octets[]) {
			write(DerValue::tag_OctetString, octets);
		}
		void putNull(){
			write(DerValue::tag_Null);
			putLength(0);
		}
		void write(char tag, DerOutputStream out) {
			write(tag);
			putLength(out.count);
			write(out.buf, 0, out.count);
		}
		void write(char tag, unsigned char buf[]) {
			write(tag);
			putLength(sizeof(buf));
			write(buf, 0, sizeof(buf));
		}		
	};//DerOutputStream
	class ObjectIdentifier {
	public:
		static const int maxFirstComponent = 2;
		static const int maxSecondComponent = 39;

		const int*         components;
		int         componentLen;
		ObjectIdentifier(){}
		ObjectIdentifier(int* _components, bool dummy) {
			components = _components;
			componentLen = sizeof(components)/sizeof(components[0]);
		}
		ObjectIdentifier (const int values[])
		{
			checkValidOid(values, sizeof(values)/sizeof(values[0]));
			components = values;
			componentLen = sizeof(values)/sizeof(values[0]);
		}
		void checkValidOid(const int values[], int len){
			if (values == NULL || len < 2) {
				printf("ObjectIdentifier() -- Must be at least two oid components \n");
			}

			for (int i=0; i<len; i++) {
				if (values[i] < 0) {
					printf("ObjectIdentifier() -- oid component # must be non-negative \n");
				}
			}

			if (values[0] > maxFirstComponent) {
				printf("ObjectIdentifier() -- First oid component is invalid \n");
			}

			if (values[0] < 2 && values[1] > maxSecondComponent) {
				printf("ObjectIdentifier() -- Second oid component is invalid \n");
			}
		}
		void encode (DerOutputStream out)
		{
			DerOutputStream chars;
			int i;

			// According to ISO X.660, when the 1st component is 0 or 1, the 2nd
			// component is restricted to be less than or equal to 39, thus make
			// it small enough to be encoded into one single char.
			if (components[0] < 2) {
				chars.write ((components [0] * 40) + components [1]);
			} else {
				putComponent(chars, (components [0] * 40) + components [1]);
			}
			for (i = 2; i < componentLen; i++)
				putComponent (chars, components [i]);

			/*
			 * Now that we've constructed the component, encode
			 * it in the stream we were given.
			 */
			out.write (DerValue::tag_ObjectId, chars);
		}
		static void putComponent (DerOutputStream out, int val)
		{
			int     i;
			// TODO: val must be <128*128*128*128 here, otherwise, 4 chars is not
			// enough to hold it. Will address this later.
			char    buf [4];

			for (i = 0; i < 4; i++) {
				buf [i] = (char) (val & 0x07f);
				val = val >> 7;
				if (val == 0)
					break;
			}
			for ( ; i > 0; --i)
				out.write (buf [i] | 0x080);
			out.write (buf [0]);
		}
		static ObjectIdentifier newInternal(int values[]) {
			return ObjectIdentifier(values, true);
		}
	};//ObjectIdentifier
	class AlgorithmId {
	public:
		ObjectIdentifier algid;
		AlgorithmId(ObjectIdentifier& oid) {
			algid = oid;
		}
		void encode(DerOutputStream out){
			derEncode(out);
		}
		void derEncode (DerOutputStream out){
			DerOutputStream chars;
			algid.encode(out);
			chars.putNull();
			DerOutputStream tmp;			
			tmp.write(DerValue.tag_Sequence, chars);
			out.write(tmp.tocharArray(), 0, tmp.count);
		}				
	};//AlgorithmId
	
	static const ObjectIdentifier SHA_oid = *new ObjectIdentifier(Crypto::SHA_oid_ints);
	static const ObjectIdentifier SHA256_oid = *new ObjectIdentifier(Crypto::SHA256_oid_ints);
	static const ObjectIdentifier SHA384_oid = *new ObjectIdentifier(Crypto::SHA384_oid_ints);
	static const ObjectIdentifier SHA512_oid = *new ObjectIdentifier(Crypto::SHA512_oid_ints);

	class Util {
		friend class ObjectIdentifier;
		friend class DerOutputStream;
		friend class AlgorithmId;
		friend class DerValue;
	public:
		static unsigned char* encodeSignature(ObjectIdentifier oid, unsigned char* digest){
			DerOutputStream out;
			AlgorithmId agId(oid);
			agId.encode(out);
			out.putOctetString(digest);
			DerOutputStream seq;
			seq.write(DerValue.tag_Sequence, out);			
			return seq.tocharArray();
		}
		
		static std::string sha256_rsa_encrypt(const std::string &srcStr, const std::string &priKey)  
		{  
			// 调用sha256哈希    
			unsigned char mdStr[33] = {0};  
			SHA256((const unsigned char *)srcStr.c_str(), srcStr.length(), mdStr);  
		  
			// 哈希后的字符串    
			std::string encodedStr = std::string((const char *)mdStr);  
			//// 哈希后的十六进制串 32字节    
			//char buf[65] = {0};  
			//char tmp[3] = {0};  
			//for (int i = 0; i < 32; i++)  
			//{  
			//	sprintf(tmp, "%02x", mdStr[i]);  
			//	strcat(buf, tmp);  
			//}  
			//buf[32] = '\0'; // 后面都是0，从32字节截断    
			//encodedHexStr = std::string(buf);
			unsigned char* pStr = encodeSignature(Crypto::SHA256_oid, (unsigned char*)encodedStr.c_str());
			std::string strRet;  
			RSA *rsa = RSA_new();  
			BIO *keybio = BIO_new_mem_buf((unsigned char *)priKey.c_str(), -1);  			
			rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);  
		  
			int len = RSA_size(rsa);  
			char *encryptedText = (char *)malloc(len + 1);  
			memset(encryptedText, 0, len + 1);  
		  
			// 加密函数 			
			int ret = RSA_private_encrypt(lstrlenA((LPCSTR)pStr), (const unsigned char*)pStr, (unsigned char*)encryptedText, rsa, RSA_PKCS1_PADDING);  
			if (ret >= 0)  
				strRet = std::string(encryptedText, ret);  
		  
			// 释放内存  
			free(encryptedText);  
			BIO_free_all(keybio);  
			RSA_free(rsa);  
		  
			return strRet;  
		}
		static void sha256(const std::string &srcStr, std::string &encodedStr, std::string &encodedHexStr)  
		{  
			// 调用sha256哈希    
			unsigned char mdStr[33] = {0};  
			SHA256((const unsigned char *)srcStr.c_str(), srcStr.length(), mdStr);  
		  
			// 哈希后的字符串    
			encodedStr = std::string((const char *)mdStr);  
			// 哈希后的十六进制串 32字节    
			char buf[65] = {0};  
			char tmp[3] = {0};  
			for (int i = 0; i < 32; i++)  
			{  
				sprintf(tmp, "%02x", mdStr[i]);  
				strcat(buf, tmp);  
			}  
			buf[32] = '\0'; // 后面都是0，从32字节截断    
			encodedHexStr = std::string(buf);  
		}
		#define KEY_LENGTH  2048               // 密钥长度  
		#define PUB_KEY_FILE "pubkey.pem"    // 公钥路径  
		#define PRI_KEY_FILE "prikey.pem"    // 私钥路径
		static void generateRSAKey(std::string strKey[2])  
		{  
			// 公私密钥对    
			size_t pri_len;  
			size_t pub_len;  
			char *pri_key = NULL;  
			char *pub_key = NULL;  
		  
			// 生成密钥对    
			RSA *keypair = RSA_generate_key(KEY_LENGTH, RSA_3, NULL, NULL);  
		  
			BIO *pri = BIO_new(BIO_s_mem());  
			BIO *pub = BIO_new(BIO_s_mem());  
		  
			PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);  
			PEM_write_bio_RSAPublicKey(pub, keypair);  
		  
			// 获取长度    
			pri_len = BIO_pending(pri);  
			pub_len = BIO_pending(pub);  
		  
			// 密钥对读取到字符串    
			pri_key = (char *)malloc(pri_len + 1);  
			pub_key = (char *)malloc(pub_len + 1);  
		  
			BIO_read(pri, pri_key, pri_len);  
			BIO_read(pub, pub_key, pub_len);  
		  
			pri_key[pri_len] = '\0';  
			pub_key[pub_len] = '\0';  
		  
			// 存储密钥对    
			strKey[0] = pub_key;  
			strKey[1] = pri_key;  
		  
			// 存储到磁盘（这种方式存储的是begin rsa public key/ begin rsa private key开头的）  
			FILE *pubFile = fopen(PUB_KEY_FILE, "w");  
			if (pubFile == NULL)  
			{  
				assert(false);  
				return;  
			}  
			fputs(pub_key, pubFile);  
			fclose(pubFile);  
		  
			FILE *priFile = fopen(PRI_KEY_FILE, "w");  
			if (priFile == NULL)  
			{  
				assert(false);  
				return;  
			}  
			fputs(pri_key, priFile);  
			fclose(priFile);  
		  
			// 内存释放  
			RSA_free(keypair);  
			BIO_free_all(pub);  
			BIO_free_all(pri);  
		  
			free(pri_key);  
			free(pub_key);  
		}
		// 公钥加密    
		static std::string rsa_pub_encrypt(const std::string &clearText, const std::string &pubKey)  
		{  
			std::string strRet;  
			RSA *rsa = NULL;  
			BIO *keybio = BIO_new_mem_buf((unsigned char *)pubKey.c_str(), -1);  
			// 此处有三种方法  
			// 1, 读取内存里生成的密钥对，再从内存生成rsa  
			// 2, 读取磁盘里生成的密钥对文本文件，在从内存生成rsa  
			// 3，直接从读取文件指针生成rsa   
			rsa = PEM_read_bio_RSAPublicKey(keybio, &rsa, NULL, NULL);  
		  
			int len = RSA_size(rsa);  
			char *encryptedText = (char *)malloc(len + 1);  
			memset(encryptedText, 0, len + 1);  
		  
			// 加密函数 			
			int ret = RSA_public_encrypt(clearText.length(), (const unsigned char*)clearText.c_str(), (unsigned char*)encryptedText, rsa, RSA_PKCS1_PADDING);  
			if (ret >= 0)  
				strRet = std::string(encryptedText, ret);  
		  
			// 释放内存  
			free(encryptedText);  
			BIO_free_all(keybio);  
			RSA_free(rsa);  
		  
			return strRet;  
		}  
		 
		static std::string rsa_pri_encrypt(const std::string &clearText, const std::string &priKey)  
		{  
			std::string strRet;  
			RSA *rsa = RSA_new();  
			BIO *keybio = BIO_new_mem_buf((unsigned char *)priKey.c_str(), -1);  
			// 此处有三种方法  
			// 1, 读取内存里生成的密钥对，再从内存生成rsa  
			// 2, 读取磁盘里生成的密钥对文本文件，在从内存生成rsa  
			// 3，直接从读取文件指针生成rsa  			 
			rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);  
		  
			int len = RSA_size(rsa);  
			char *encryptedText = (char *)malloc(len + 1);  
			memset(encryptedText, 0, len + 1);  
		  
			// 加密函数 			
			int ret = RSA_private_encrypt(clearText.length(), (const unsigned char*)clearText.c_str(), (unsigned char*)encryptedText, rsa, RSA_PKCS1_PADDING);  
			if (ret >= 0)  
				strRet = std::string(encryptedText, ret);  
		  
			// 释放内存  
			free(encryptedText);  
			BIO_free_all(keybio);  
			RSA_free(rsa);  
		  
			return strRet;  
		} 
		// 私钥解密    
		static std::string rsa_pri_decrypt(const std::string &cipherText, const std::string &priKey)  
		{  
			std::string strRet;  
			RSA *rsa = RSA_new();  
			BIO *keybio;  
			keybio = BIO_new_mem_buf((unsigned char *)priKey.c_str(), -1);  
		  
			// 此处有三种方法  
			// 1, 读取内存里生成的密钥对，再从内存生成rsa  
			// 2, 读取磁盘里生成的密钥对文本文件，在从内存生成rsa  
			// 3，直接从读取文件指针生成rsa  
			rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);  
		  
			int len = RSA_size(rsa);  
			char *decryptedText = (char *)malloc(len + 1);  
			memset(decryptedText, 0, len + 1);  
		  
			// 解密函数  
			int ret = RSA_private_decrypt(cipherText.length(), (const unsigned char*)cipherText.c_str(), (unsigned char*)decryptedText, rsa, RSA_PKCS1_PADDING);  
			if (ret >= 0)  
				strRet = std::string(decryptedText, ret);  
		  
			// 释放内存  
			free(decryptedText);  
			BIO_free_all(keybio);  
			RSA_free(rsa);  
		  
			return strRet;  
		}  
		static int hmacEncode(const char * algo,  
			const char * key, unsigned int key_length,  
			const char * input, unsigned int input_length,  
			unsigned char * &output, unsigned int &output_length){
			const EVP_MD * engine = NULL;  
			if(lstrcmpA("sha512", algo) == 0) {  
					engine = EVP_sha512();  
			}  
			else if(lstrcmpA("sha256", algo) == 0) {  
					engine = EVP_sha256();  
			}  
			else if(lstrcmpA("sha1", algo) == 0) {  
					engine = EVP_sha1();  
			}  
			else if(lstrcmpA("md5", algo) == 0) {  
					engine = EVP_md5();  
			}  
			else if(lstrcmpA("sha224", algo) == 0) {  
					engine = EVP_sha224();  
			}  
			else if(lstrcmpA("sha384", algo) == 0) {  
					engine = EVP_sha384();  
			}  
			else if(lstrcmpA("sha", algo) == 0) {  
					engine = EVP_sha();  
			}  
			//else if(lstrcmpA("md2", algo) == 0) {  
			//		engine = EVP_md2();  
			//}  
			else {  
					cout << "Algorithm " << algo << " is not supported by this program!" << endl;  
					return -1;  
			}  
	  
			output = (unsigned char*)malloc(EVP_MAX_MD_SIZE);  
	  
			HMAC_CTX ctx;  
			HMAC_CTX_init(&ctx);  
			HMAC_Init_ex(&ctx, key, strlen(key), engine, NULL);  
			HMAC_Update(&ctx, (unsigned char*)input, strlen(input));        // input is OK; &input is WRONG !!!  
	  
			HMAC_Final(&ctx, output, &output_length);  
			HMAC_CTX_cleanup(&ctx);  
	  
			return 0;  
		}
		static std::string base64Encode(std::string src, bool with_new_line=false)  
		{  
			const char* input=src.c_str();
			int length=src.size();
			BIO * bmem = NULL;  
			BIO * b64 = NULL;  
			BUF_MEM * bptr = NULL;  
		  
			b64 = BIO_new(BIO_f_base64());  
			if(!with_new_line) {  
				BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);  
			}  
			bmem = BIO_new(BIO_s_mem());  
			b64 = BIO_push(b64, bmem);  
			BIO_write(b64, input, length);  
			BIO_flush(b64);  
			BIO_get_mem_ptr(b64, &bptr);  
		  
			char * buff = (char *)malloc(bptr->length + 1);  
			memcpy(buff, bptr->data, bptr->length);  
			buff[bptr->length] = 0;  
		  
			BIO_free_all(b64);  
		  
			return string(buff);  
		}  
		  
		static std::string base64Decode(std::string src, bool with_new_line=false)  
		{  
			const char* input=src.c_str();
			int length=src.size();
			BIO * b64 = NULL;  
			BIO * bmem = NULL;  
			char * buffer = (char *)malloc(length);  
			memset(buffer, 0, length);  
		  
			b64 = BIO_new(BIO_f_base64());  
			if(!with_new_line) {  
				BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);  
			}  
			bmem = BIO_new_mem_buf(input, length);  
			bmem = BIO_push(b64, bmem);  
			BIO_read(bmem, buffer, length);  
		  
			BIO_free_all(bmem);  
		  
			return string(buffer);  
		}
		static void md5(const std::string &srcStr, std::string &encodedStr, std::string &encodedHexStr)  
		{  
			// 调用md5哈希    
			unsigned char mdStr[33] = {0};  
			MD5((const unsigned char *)srcStr.c_str(), srcStr.length(), mdStr);  
		  
			// 哈希后的字符串    
			encodedStr = std::string((const char *)mdStr);  
			// 哈希后的十六进制串 32字节    
			char buf[65] = {0};  
			char tmp[3] = {0};  
			for (int i = 0; i < 32; i++)  
			{  
				sprintf(tmp, "%02x", mdStr[i]);  
				strcat(buf, tmp);  
			}  
			buf[32] = '\0'; // 后面都是0，从32字节截断    
			encodedHexStr = std::string(buf);  
		}
	};//Util

}
//////////////////////////////////////////////////////////////////////////////////

#endif