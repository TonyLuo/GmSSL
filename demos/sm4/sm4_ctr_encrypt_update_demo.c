#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/sm4.h>
#include <gmssl/rand.h>


int main(void)
{
	SM4_CTR_CTX cbc_ctx;
	unsigned char key[16] = {
		0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,
		0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,
	};
	unsigned char ctr[16] = {
		0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,
		0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,
	};
	unsigned char inbuf[1024];
	unsigned char outbuf[1024 + 32];
	ssize_t inlen;
	size_t outlen;

	if (sm4_ctr_encrypt_init(&cbc_ctx, key, ctr) != 1) {
		fprintf(stderr, "%s %d: error\n", __FILE__, __LINE__);
		return 1;
	}
	while ((inlen = fread(inbuf, 1, sizeof(inbuf), stdin)) > 0) {
		if (sm4_ctr_encrypt_update(&cbc_ctx, inbuf, inlen, outbuf, &outlen) != 1) {
			fprintf(stderr, "%s %d: error\n", __FILE__, __LINE__);
			return 1;
		}
		fwrite(outbuf, 1, outlen, stdout);
	}
	if (sm4_ctr_encrypt_finish(&cbc_ctx, outbuf, &outlen) != 1) {
		fprintf(stderr, "%s %d: error\n", __FILE__, __LINE__);
		return 1;
	}
	fwrite(outbuf, 1, outlen, stdout);

	return 0;
}
