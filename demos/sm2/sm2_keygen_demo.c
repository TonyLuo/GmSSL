#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/sm2.h>

int main(void)
{
	SM2_KEY sm2_key;

	if (sm2_key_generate(&sm2_key) != 1) {
		fprintf(stderr, "error\n");
		return 1;
	}

	sm2_key_print(stdout, 0, 0, "SM2PrivateKey", &sm2_key);
	sm2_public_key_print(stdout, 0, 0, "SM2PublicKey", &sm2_key);

	return 0;
}
