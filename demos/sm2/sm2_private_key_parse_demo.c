#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/mem.h>
#include <gmssl/sm2.h>


int main(void)
{
	SM2_KEY sm2_key;
	char *password = "123456";
	unsigned char buf[512];
	unsigned char *p;
	size_t len;

	printf("Read SM2 private key file (PEM) from stdin ...\n");
	if (sm2_private_key_info_decrypt_from_pem(&sm2_key, password, stdin) != 1) {
		fprintf(stderr, "error\n");
		return 1;
	}

	p = buf;
	len = 0;
	if (sm2_private_key_to_der(&sm2_key, &p, &len) != 1) {
		fprintf(stderr, "error\n");
		return 1;
	}
	fwrite(buf, 1, len, stdout);

	gmssl_secure_clear(&sm2_key, sizeof(sm2_key));
	return 0;
}
