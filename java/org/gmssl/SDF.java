package org.gmssl;

public class SDF {

	/* 设备信息 */
	// typedef struct DeviceInfo_st{
	// unsigned char IssuerName[40];
	// unsigned char DeviceName[16];
	// unsigned char DeviceSerial[16];
	// unsigned int DeviceVersion;
	// unsigned int StandardVersion;
	// unsigned int AsymAlgAbility[2];
	// unsigned int SymAlgAbility;
	// unsigned int HashAlgAbility;
	// unsigned int BufferSize;
	// } DEVICEINFO;
	static class DeviceInfo {
		public DeviceInfo(){}
		public String issuerName; // 设备生成厂家名称
		public String deviceName; // 设备型号
		public String deviceSerial; // 设备序列号
		public int deviceVersion;
		public int standardVersion;
		public int[] asymAlgAbility;
		public int symAlgAbility;
		public int hashAlgAbility;
		public int bufferSize;
	}
	static class KeyPair{
		public KeyPair(){}
		public Object publicKey;
		public Object privateKey;
	}

	/* RSA密钥 */

	// typedef struct RSArefPrivateKey_st
	// {
	// unsigned int bits;
	// unsigned char m[RSAref_MAX_LEN];
	// unsigned char e[RSAref_MAX_LEN];
	// unsigned char d[RSAref_MAX_LEN];
	// unsigned char prime[2][RSAref_MAX_PLEN];
	// unsigned char pexp[2][RSAref_MAX_PLEN];
	// unsigned char coef[RSAref_MAX_PLEN];
	// } RSArefPrivateKey;

	// typedef struct RSArefPublicKey_st
	// {
	// unsigned int bits;
	// unsigned char m[RSAref_MAX_LEN];
	// unsigned char e[RSAref_MAX_LEN];
	// } RSArefPublicKey;
	static class RSArefPublicKey {
		public int bits; // 密钥位长
		public String m; // 公钥模
		public String e; // 公钥指数

	}

	
	static class RSArefPrivateKey {
		
		public int bits; // 密钥位长
		public String m; // 公钥模
		public String e; // 公钥指数
		public String d; // 私钥指数
		// public String[] prime; // 公钥素数 p 和q
		// public String[] pexp; // 公钥素数指数 Dp 和Dq
		public String p; 
		public String q; 
		public String dp; 
		public String dq; 
		public String coef; // 公钥素数乘积，系数i

	}

	/* ECC密钥 */

	// // typedef struct ECCrefPublicKey_st
	// // {
	// // unsigned int bits;
	// // unsigned char x[ECCref_MAX_LEN];
	// // unsigned char y[ECCref_MAX_LEN];
	// // } ECCrefPublicKey;

	// // typedef struct ECCrefPrivateKey_st
	// // {
	// // unsigned int bits;
	// // unsigned char D[ECCref_MAX_LEN];
	// // } ECCrefPrivateKey;
	static class ECCrefPublicKey {
		
		
		public int bits; // 密钥位长
		public String x; // 公钥x坐标
		public String y; // 公钥y坐标
	}

	
	static class ECCrefPrivateKey {
	
		public int bits; // 密钥位长
		public String K; // 私钥，SDF标准为K，三未信安定义私钥为D，为了兼容标准，这里定义为K
	}

	// /*ECC 密文*/
	// typedef struct ECCCipher_st
	// {
	// unsigned int clength; //C的有效长度
	// unsigned char x[ECCref_MAX_LEN];
	// unsigned char y[ECCref_MAX_LEN];
	// unsigned char C[ECCref_MAX_CIPHER_LEN];
	// unsigned char M[ECCref_MAX_LEN];
	// } ECCCipher;
	static class ECCCipher {
		public int L; // 密文长度,SDF标准为L，三未信安定义clength，为了兼容标准，这里定义为L
		public String x; // 公钥x坐标
		public String y; // 公钥y坐标
		public String C; // 密文
		public String M; // 明文
	}

	/* ECC 签名 */
	// typedef struct ECCSignature_st
	// {
	// unsigned char r[ECCref_MAX_LEN];
	// unsigned char s[ECCref_MAX_LEN];
	// } ECCSignature;
	class ECCSignature {
		public String r; // 签名r值
		public String s; //	签名s值
	}

	/* 设备管理类函数 */
	public native DeviceInfo getDeviceInfo();

	/**
	 * 
	 * @param length 长度
	 * @return 0：成功，其他：失败
	 */
	public native byte[] generateRandom(int length);

	/* 密钥管理类函数 */

	/**
	 *  生成RSA密钥对
	 * @param keyBits 密钥长度，单位bit，可以是1024、2048、3072、4096、etc.
	 * @param publicKey RSA公钥,如果为空，则生成一个新的公钥，并返回。
	 * @param privateKey RSA私钥,如果为空，则生成一个新的私钥，并返回。
	 * @return 0：成功，其他：失败
	 *
	 */
	public native KeyPair generateKeyPair_RSA(int keyBits);

	// SGD_RV SDF_GenerateKeyPair_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiAlgID,SGD_UINT32  uiKeyBits, ECCrefPublicKey *pucPublicKey, ECCrefPrivateKey *pucPrivateKey);

	/**
	 * 生成ECC密钥对
	 * @param algId 指定算法标识 SGD_SM2 – SM2 密码算法 SGD_SM2_1 – SM2 签名算法 SGD_SM2_2 – SM2 密钥交换 协议SGD_SM2_3 – SM2 加密算法
	 * @param keyBits 指定密钥模长，只支持 256bit（32 字节）
	 * @param publicKey ECC公钥，如果为空，则生成一个新的公钥，并返回。
	 * @param privateKey ECC私钥，如果为空，则生成一个新的私钥，并返回。
	 * @return 0：成功，其他：失败
	 */
	public native KeyPair generateKeyPair_ECC(int algId, int keyBits);
	public static void main(String[] args) {
		final SDF sdf = new SDF();

		DeviceInfo deviceInfo = sdf.getDeviceInfo();
		System.out.println("DeviceInfo: issureName=" + deviceInfo.issuerName + ",deviceName=" + deviceInfo.deviceName
				+ ",deviceSerial=" + deviceInfo.deviceSerial + ",deviceVersion=" + deviceInfo.deviceVersion
				+ ",standardVersion=" + deviceInfo.standardVersion + ",asymAlgAbility=" + deviceInfo.asymAlgAbility
				+ ",symAlgAbility=" + deviceInfo.symAlgAbility + ",hashAlgAbility=" + deviceInfo.hashAlgAbility
				+ ",bufferSize=" + deviceInfo.bufferSize);

		byte[] data = sdf.generateRandom(10);
		for (int i = 0; i < data.length; i++) {
			System.out.printf("%02X", data[i]);
		}
		System.out.println("");


		// RSArefPublicKey publicKey = null;
		// RSArefPrivateKey privateKey = null;
		// int keyBits = 256;
		// KeyPair result = sdf.generateKeyPair_RSA(keyBits);
		// System.out.println("generateKeyPair_RSA result=" + result);

		
		int keyBits = 256;
		int algId = 0;
		KeyPair keyPair = sdf.generateKeyPair_ECC(algId, keyBits);
		ECCrefPublicKey eccPublicKey = (ECCrefPublicKey) keyPair.publicKey;
		ECCrefPrivateKey eccPrivateKey = (ECCrefPrivateKey)keyPair.privateKey;
		// System.out.println("generateKeyPair_ECC result=" + result);
		System.out.println("eccPublicKey.bits=" + eccPublicKey.bits + ",eccPublicKey.x=" + eccPublicKey.x + ",eccPublicKey.y=" + eccPublicKey.y);
		System.out.println("eccPrivateKey.bits=" + eccPrivateKey.bits + ",eccPrivateKey.K=" + eccPrivateKey.K);
		
		

	}

	static {
		// System.loadLibrary("gmssljni");
		// System.load("/Users/tony/unicom/git/GmSSL/java/libsdfjni.so");
		System.load("/data/GmSSL/GmSSL-master/java/libsdfjni.so");

	}
}
