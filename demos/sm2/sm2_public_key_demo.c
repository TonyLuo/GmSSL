#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/mem.h>
#include <gmssl/sm2.h>


int main(void)
{
	SM2_KEY sm2_key;
	char *password = "123456";

	printf("Read SM2 private key file (PEM) from stdin ...\n");
	if (sm2_private_key_info_decrypt_from_pem(&sm2_key, password, stdin) != 1) {
		fprintf(stderr, "error\n");
		return 1;
	}

	// openssl ec -pubin -in sm2pub.pem -text
	sm2_public_key_info_to_pem(&sm2_key, stdout);

	gmssl_secure_clear(&sm2_key, sizeof(sm2_key));
	return 0;
}
