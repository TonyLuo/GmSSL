#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#ifndef OPENSSL_NO_CMAC
#include <openssl/cmac.h>
#endif
#ifndef OPENSSL_NO_SM2
#include <openssl/sm2.h>
#endif
#include <openssl/x509.h>
#include <openssl/stack.h>
#include <openssl/crypto.h>
#include <openssl/safestack.h>
#include "../e_os.h"
#include "gmssl_err.h"
#include "gmssl_err.c"
#include "org_gmssl_SDF.h"

// //三未信安
#include "swsds.h"

#define GMSSL_JNI_VERSION "GmSSL-JNI API/1.1 2017-09-01"

void *pDeviceHandle;  //设备句柄
void *pSessionHandle; //会话句柄
// SGD_HANDLE pDeviceHandle; //设备句柄
// SGD_HANDLE pSessionHandle; //会话句柄
static void initSDF(void)
{
	printf("-----initSDF-----\n");
	int rc = SDF_OpenDevice(&pDeviceHandle);
	if (rc)
	{
		printf("-----SDF_OpenDevice failed rc:%d [%s %d]-----\n", rc, __func__, __LINE__);
	}
	else
	{
		rc = SDF_OpenSession(pDeviceHandle, &pSessionHandle);
		if (rc)
		{
			printf("------SDF_OpenSession failed. rc:%d [%s %d]------\n", rc, __func__, __LINE__);
		}
		else
		{
			printf("-------SDF_OpenSession success. rc:%d [%s %d]-----\n", rc, __func__, __LINE__);
		}
	}
}
static void releaseSDF(void)
{
	printf("-----releaseSDF-----\n");
	int rc = SDF_CloseSession(pSessionHandle);
	if (rc)
	{
		printf("-----SDF_CloseSession failed rc:%d [%s %d]-----\n", rc, __func__, __LINE__);
	}

	rc = SDF_CloseDevice(pDeviceHandle);
	if (rc)
	{
		printf("------SDF_CloseDevice failed. rc:%d [%s %d]------\n", rc, __func__, __LINE__);
	}
	else
	{
		printf("-------SDF_CloseDevice success. rc:%d [%s %d]-----\n", rc, __func__, __LINE__);
	}
}

/**
 * @brief convert char to hex
 *
 * @param str
 * @param len
 * @return char*
 */
static char *Char2Hex(char *str, int len)
{
	char *hex = (char *)malloc(len * 2 + 1);
	char *p = hex;
	int i;
	for (i = 0; i < len; i++)
	{
		sprintf(p, "%02x", (unsigned char)str[i]);
		p += 2;
	}
	*p = 0;
	return hex;
}
/**
 * @brief convert hex to char
 *
 * @param str
 * @param len
 * @return char*
 */
static char *Hex2Char(char *str, int len){
	char *hex = (char *)malloc(len / 2 + 1);
	char *p = hex;
	int i;
	for (i = 0; i < len; i += 2)
	{
		sprintf(p, "%c", (char)strtoul(str + i, NULL, 16));
		p++;
	}
	*p = 0;
	return hex;
}


JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
	(void)ERR_load_JNI_strings();
	initSDF();

	return JNI_VERSION_1_2;
}

JNIEXPORT void JNICALL JNI_OnUnload(JavaVM *vm, void *reserved)
{
	ERR_unload_JNI_strings();
	releaseSDF();
}

JNIEXPORT jobject JNICALL Java_org_gmssl_SDF_getDeviceInfo(JNIEnv *env, jobject thisObject)
{

	DEVICEINFO pstDeviceInfo;
	memset(&pstDeviceInfo, 0, sizeof(DEVICEINFO));
	SGD_RV rc = SDF_GetDeviceInfo(pSessionHandle, &pstDeviceInfo);
	if (rc)
	{
		printf("SDF_GetDeviceInfo failed. rc:%d [%s %d]\n", rc, __func__, __LINE__);
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_GENERATERANDOM, ERR_R_INTERNAL_ERROR);
		return NULL;
	}

	// Create the object of the class
	jclass deviceInfoClass = (*env)->FindClass(env, "org/gmssl/SDF$DeviceInfo");
	jobject deviceInfo = (*env)->AllocObject(env, deviceInfoClass);

	// Get the  fields to be set

	// https://docs.oracle.com/javase/7/docs/technotes/guides/jni/spec/types.html

	jfieldID issuerName = (*env)->GetFieldID(env, deviceInfoClass, "issuerName", "Ljava/lang/String;");
	jfieldID deviceName = (*env)->GetFieldID(env, deviceInfoClass, "deviceName", "Ljava/lang/String;");
	jfieldID deviceSerial = (*env)->GetFieldID(env, deviceInfoClass, "deviceSerial", "Ljava/lang/String;");

	jfieldID deviceVersion = (*env)->GetFieldID(env, deviceInfoClass, "deviceVersion", "I");
	jfieldID standardVersion = (*env)->GetFieldID(env, deviceInfoClass, "standardVersion", "I");
	jfieldID symAlgAbility = (*env)->GetFieldID(env, deviceInfoClass, "symAlgAbility", "I");
	jfieldID hashAlgAbility = (*env)->GetFieldID(env, deviceInfoClass, "hashAlgAbility", "I");
	jfieldID bufferSize = (*env)->GetFieldID(env, deviceInfoClass, "bufferSize", "I");
	(*env)->SetObjectField(env, deviceInfo, issuerName, (*env)->NewStringUTF(env, (const char *)&(pstDeviceInfo.IssuerName)));
	(*env)->SetObjectField(env, deviceInfo, deviceName, (*env)->NewStringUTF(env, (const char *)&(pstDeviceInfo.DeviceName)));
	(*env)->SetObjectField(env, deviceInfo, deviceSerial, (*env)->NewStringUTF(env, (const char *)&(pstDeviceInfo.DeviceSerial)));
	(*env)->SetIntField(env, deviceInfo, deviceVersion, (jint)pstDeviceInfo.DeviceVersion);
	(*env)->SetIntField(env, deviceInfo, standardVersion, (jint)pstDeviceInfo.StandardVersion);
	(*env)->SetIntField(env, deviceInfo, symAlgAbility, (jint)pstDeviceInfo.SymAlgAbility);
	(*env)->SetIntField(env, deviceInfo, hashAlgAbility, (jint)pstDeviceInfo.HashAlgAbility);
	(*env)->SetIntField(env, deviceInfo, bufferSize, (jint)pstDeviceInfo.BufferSize);

	// TODO set array filed
	//  jfieldID asymAlgAbility = (*env)->GetFieldID(env, deviceInfoClass, "asymAlgAbility", "[I");
	//  (*env)->SetIntField(env, deviceInfo, asymAlgAbility, pstDeviceInfo.AsymAlgAbility);

	return deviceInfo;
}

JNIEXPORT jbyteArray JNICALL Java_org_gmssl_SDF_generateRandom(JNIEnv *env, jobject this, jint outlen)
{
	printf("-----SDF_GenerateRandom  [%s %d]-----\n", __func__, __LINE__);

	jbyteArray ret = NULL;
	jbyte *outbuf = NULL;

	if (outlen <= 0 || outlen >= INT_MAX)
	{
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_GENERATERANDOM, JNI_R_INVALID_LENGTH);
		return NULL;
	}

	if (!(outbuf = OPENSSL_malloc(outlen)))
	{
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_GENERATERANDOM, ERR_R_MALLOC_FAILURE);
		goto end;
	}

	int r = SDF_GenerateRandom(pSessionHandle, outlen, (unsigned char *)outbuf);
	printf("-----SDF_GenerateRandom r:%d [%s %d]-----\n", r, __func__, __LINE__);

	if (r)
	{
		printf("-----SDF_GenerateRandom failed. r:%d [%s %d]-----\n", r, __func__, __LINE__);
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_GENERATERANDOM, JNI_R_GMSSL_RNG_ERROR);
		goto end;
	}

	if (!(ret = (*env)->NewByteArray(env, outlen)))
	{
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_GENERATERANDOM, JNI_R_JNI_MALLOC_FAILURE);
		goto end;
	}
	

	(*env)->SetByteArrayRegion(env, ret, 0, outlen, (jbyte *)outbuf);

end:
	OPENSSL_free(outbuf);
	return ret;
}

JNIEXPORT jobject JNICALL Java_org_gmssl_SDF_generateKeyPair_1RSA(JNIEnv *env, jobject thisObject, jint keyBits)
{

	if (keyBits <= 0 || keyBits >= INT_MAX)
	{
		JNIerr(JNI_F_JAVA_ORG_GMSSL_GMSSL_GENERATERANDOM, JNI_R_INVALID_LENGTH);
		return NULL;
	}
	RSArefPublicKey pucPublicKey;
	memset(&pucPublicKey, 0, sizeof(RSArefPublicKey));
	RSArefPrivateKey pucPrivateKey;
	memset(&pucPrivateKey, 0, sizeof(RSArefPrivateKey));
	SGD_RV rc = SDF_GenerateKeyPair_RSA(pSessionHandle, keyBits, &pucPublicKey, &pucPrivateKey);
	if (rc)
	{
		printf("SDF_GenerateKeyPair_RSA failed. rc:%d [%s %d]\n", rc, __func__, __LINE__);
	}
	else
	{
		printf("-----SDF_GenerateKeyPair_RSA success. [%s %d]-----\n", __func__, __LINE__);
	}

	// Create the object of the class
	jclass publicKeyClass = (*env)->FindClass(env, "org/gmssl/SDF$RSArefPublicKey");
	jobject publicKey = (*env)->AllocObject(env, publicKeyClass);
	// Get the  fields to be set
	jfieldID bits = (*env)->GetFieldID(env, publicKeyClass, "bits", "I");
	(*env)->SetIntField(env, publicKey, bits, (jint)pucPublicKey.bits);

	jfieldID m = (*env)->GetFieldID(env, publicKeyClass, "m", "Ljava/lang/String;");
	(*env)->SetObjectField(env, publicKey, m, (*env)->NewStringUTF(env, (const char *)&(pucPublicKey.m)));

	jfieldID e = (*env)->GetFieldID(env, publicKeyClass, "e", "Ljava/lang/String;");
	(*env)->SetObjectField(env, publicKey, e, (*env)->NewStringUTF(env, (const char *)&(pucPublicKey.e)));

	jclass privateKeyClass = (*env)->FindClass(env, "org/gmssl/SDF$RSArefPrivateKey");
	jobject privateKey = (*env)->AllocObject(env, privateKeyClass);

	bits = (*env)->GetFieldID(env, privateKeyClass, "bits", "I");
	(*env)->SetIntField(env, privateKey, bits, (jint)pucPrivateKey.bits);

	m = (*env)->GetFieldID(env, privateKeyClass, "m", "Ljava/lang/String;");
	(*env)->SetObjectField(env, privateKey, m, (*env)->NewStringUTF(env, (const char *)&(pucPrivateKey.m)));
	e = (*env)->GetFieldID(env, privateKeyClass, "e", "Ljava/lang/String;");
	(*env)->SetObjectField(env, privateKey, e, (*env)->NewStringUTF(env, (const char *)&(pucPrivateKey.e)));
	jfieldID d = (*env)->GetFieldID(env, privateKeyClass, "d", "Ljava/lang/String;");
	(*env)->SetObjectField(env, privateKey, d, (*env)->NewStringUTF(env, (const char *)&(pucPrivateKey.d)));
	jfieldID p = (*env)->GetFieldID(env, privateKeyClass, "p", "Ljava/lang/String;");
	(*env)->SetObjectField(env, privateKey, p, (*env)->NewStringUTF(env, (const char *)&(pucPrivateKey.prime[0])));

	jfieldID q = (*env)->GetFieldID(env, privateKeyClass, "q", "Ljava/lang/String;");
	(*env)->SetObjectField(env, privateKey, q, (*env)->NewStringUTF(env, (const char *)&(pucPrivateKey.prime[1])));

	jfieldID dp = (*env)->GetFieldID(env, privateKeyClass, "dp", "Ljava/lang/String;");
	(*env)->SetObjectField(env, privateKey, dp, (*env)->NewStringUTF(env, (const char *)&(pucPrivateKey.pexp[0])));

	jfieldID dq = (*env)->GetFieldID(env, privateKeyClass, "dq", "Ljava/lang/String;");
	(*env)->SetObjectField(env, privateKey, dq, (*env)->NewStringUTF(env, (const char *)&(pucPrivateKey.pexp[1])));

	jfieldID coef = (*env)->GetFieldID(env, privateKeyClass, "coef", "Ljava/lang/String;");
	(*env)->SetObjectField(env, privateKey, coef, (*env)->NewStringUTF(env, (const char *)&(pucPrivateKey.coef)));

	jclass keyPairClass = (*env)->FindClass(env, "org/gmssl/SDF$KeyPair");
	jobject keyPair = (*env)->AllocObject(env, keyPairClass);
	jfieldID publicKeyField = (*env)->GetFieldID(env, keyPairClass, "publicKey", "Lorg/gmssl/SDF$RSArefPublicKey;");
	(*env)->SetObjectField(env, keyPair, publicKeyField, publicKey);
	jfieldID privateKeyField = (*env)->GetFieldID(env, keyPairClass, "privateKey", "Lorg/gmssl/SDF$RSArefPrivateKey;");
	(*env)->SetObjectField(env, keyPair, privateKeyField, privateKey);
	return keyPair;
}

/*
 * Class:     org_gmssl_SDF
 * Method:    generateKeyPair_ECC
 * Signature: (IILorg/gmssl/SDF/ECCrefPublicKey;Lorg/gmssl/SDF/ECCrefPrivateKey;)I
 */
JNIEXPORT jobject JNICALL Java_org_gmssl_SDF_generateKeyPair_1ECC(JNIEnv *env, jobject thisObject, jint algId, jint keyBits)
{
	unsigned int uiAlgID = algId;
	unsigned int uiKeyBits = keyBits;
	ECCrefPublicKey pucPublicKey;
	memset(&pucPublicKey, 0, sizeof(ECCrefPublicKey));
	ECCrefPrivateKey pucPrivateKey;
	memset(&pucPrivateKey, 0, sizeof(ECCrefPrivateKey));

	// pucPublicKey.bits = 32; //
	// pucPrivateKey.bits = 32;
	// printf("pucPublicKey.bits:%d [%s %d]", pucPublicKey.bits, __func__, __LINE__);
	int rc = SDF_GenerateKeyPair_ECC(pSessionHandle, uiAlgID, uiKeyBits, &pucPublicKey, &pucPrivateKey);
	if (rc)
	{
		printf("SDF_GenerateKeyPair_ECC failed rc:%d [%s %d]\n", rc, __func__, __LINE__);
		return NULL;
	}
	else
	{
		printf("-----SDF_GenerateKeyPair_ECC success. [%s %d]-----\n", __func__, __LINE__);
	}
	// Create the object of the class
	jclass publicKeyClass = (*env)->FindClass(env, "org/gmssl/SDF$ECCrefPublicKey");
	jobject publicKey = (*env)->AllocObject(env, publicKeyClass);
	// Get the  fields to be set
	jfieldID bits = (*env)->GetFieldID(env, publicKeyClass, "bits", "I");
	(*env)->SetIntField(env, publicKey, bits, (jint)pucPublicKey.bits);
	jfieldID x = (*env)->GetFieldID(env, publicKeyClass, "x", "Ljava/lang/String;");
	(*env)->SetObjectField(env, publicKey, x, (*env)->NewStringUTF(env, Char2Hex((char *)pucPublicKey.x, ECCref_MAX_LEN)));
	jfieldID y = (*env)->GetFieldID(env, publicKeyClass, "y", "Ljava/lang/String;");
	(*env)->SetObjectField(env, publicKey, y, (*env)->NewStringUTF(env, Char2Hex((char *)pucPublicKey.y, ECCref_MAX_LEN)));

	jclass privateKeyClass = (*env)->FindClass(env, "org/gmssl/SDF$ECCrefPrivateKey");
	jobject privateKey = (*env)->AllocObject(env, privateKeyClass);
	// Get the  fields to be set
	bits = (*env)->GetFieldID(env, privateKeyClass, "bits", "I");
	(*env)->SetIntField(env, privateKey, bits, (jint)pucPrivateKey.bits);
	jfieldID K = (*env)->GetFieldID(env, privateKeyClass, "K", "Ljava/lang/String;");
	(*env)->SetObjectField(env, privateKey, K, (*env)->NewStringUTF(env, Char2Hex((char *)pucPrivateKey.D, ECCref_MAX_LEN)));

	jclass keyPairClass = (*env)->FindClass(env, "org/gmssl/SDF$KeyPair");
	jobject keyPair = (*env)->AllocObject(env, keyPairClass);
	jfieldID publicKeyField = (*env)->GetFieldID(env, keyPairClass, "publicKey", "Ljava/lang/Object;");
	(*env)->SetObjectField(env, keyPair, publicKeyField, publicKey);
	jfieldID privateKeyField = (*env)->GetFieldID(env, keyPairClass, "privateKey", "Ljava/lang/Object;");
	(*env)->SetObjectField(env, keyPair, privateKeyField, privateKey);

	return keyPair;
}
