#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/sm4.h>
#include <gmssl/rand.h>


int main(void)
{
	SM4_KEY sm4_key;
	unsigned char key[16];
	unsigned char iv[16];
	unsigned char aad[20];
	unsigned char mbuf[64] = {
		0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,
		0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,
		0x31,0x32,0x33,0x34,
	};
	unsigned char cbuf[64] = {0};
	unsigned char pbuf[64] = {0};
	unsigned char tag[16];
	int i;

	rand_bytes(key, sizeof(key));
	rand_bytes(iv, sizeof(iv));

	printf("key: ");
	for (i = 0; i < sizeof(key); i++) {
		printf("%02X", key[i]);
	}
	printf("\n");

	printf("iv: ");
	for (i = 0; i < sizeof(iv); i++) {
		printf("%02X", iv[i]);
	}
	printf("\n");

	sm4_set_encrypt_key(&sm4_key, key);

	printf("sm4 gcm encrypt\n");

	printf("auth-only data: ");
	for (i = 0; i < sizeof(aad); i++) {
		printf("%02X", aad[i]);
	}
	printf("\n");

	printf("plaintext: ");
	for (i = 0; i < sizeof(mbuf); i++) {
		printf("%02X", mbuf[i]);
	}
	printf("\n");

	sm4_gcm_encrypt(&sm4_key, iv, sizeof(iv), aad, sizeof(aad), mbuf, sizeof(mbuf), cbuf, sizeof(tag), tag);

	printf("ciphertext: ");
	for (i = 0; i < sizeof(cbuf); i++) {
		printf("%02X", cbuf[i]);
	}
	printf("\n");

	printf("mac-tag: ");
	for (i = 0; i < sizeof(tag); i++) {
		printf("%02X", tag[i]);
	}
	printf("\n");

	if (sm4_gcm_decrypt(&sm4_key, iv, sizeof(iv), aad, sizeof(aad), cbuf, sizeof(mbuf), tag, sizeof(tag), pbuf) != 1) {
		fprintf(stderr, "sm4 gcm decrypt failed\n");
		return 1;
	}

	printf("decrypted: ");
	for (i = 0; i < sizeof(pbuf); i++) {
		printf("%02X", pbuf[i]);
	}
	printf("\n");

	return 0;
}
