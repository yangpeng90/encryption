package com.peng.yang;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

/**
 * AES对称加密算法
 * @author 杨鹏
 *
 */

/*
 * 基本实现和DES类似，只不过在实现该算法的时候，设置密钥长度大于128会出现错误：Illegal key size or default parameters，
 * 这是因为美国的出口限制，Sun通过权限文件（local_policy.jar、US_export_policy.jar）做了相应限制，Oracle在其官方网站上
 * 提供了无政策限制权限文件（Unlimited Strength Jurisdiction Policy Files），我们只需要将其部署在JRE环境中，就可以解决
 * 限制问题
 * JDK8的无政策限制权限文件（http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html）
 * 将下载的local_policy.jar和US_export_policy.jar替换JDK的JRE环境中，或者是JRE环境中上述两个jar文件即可
 * 非对称的ELGamal加密算法算法也有该问题，解决方法相同
 */
public class AESutils {
	
	
	/*
		算法/模式/填充                16字节加密后数据长度        不满16字节加密后长度
		
		AES/CBC/NoPadding             16                                  不支持
		
		AES/CBC/PKCS5Padding          32                   16
		
		AES/CBC/ISO10126Padding       32                   16
		
		AES/CFB/NoPadding             16                              原始数据长度
		
		AES/CFB/PKCS5Padding          32                   16
		
		AES/CFB/ISO10126Padding       32                   16
		
		AES/ECB/NoPadding             16                                  不支持
		
		AES/ECB/PKCS5Padding          32                   16
		
		AES/ECB/ISO10126Padding       32                   16
		
		AES/OFB/NoPadding             16                              原始数据长度
		
		AES/OFB/PKCS5Padding          32                   16
		
		AES/OFB/ISO10126Padding       32                   16
		
		AES/PCBC/NoPadding            16                              不支持
		
		AES/PCBC/PKCS5Padding         32                   16
		
		AES/PCBC/ISO10126Padding      32                   16
		
		看上面的列表可以知道AES加密后要么16要么32位(前提是大于16字节)
		有些模式是不支持对于不满16字节字符串的加密,见上面列表最后一列 (不支持)
		如果不满16字节且支持加密的模式,一定是有填充量的,就是不满16的字节用一个默认值来填充,直到它满16位后再加密.
	 */
	
	/**
	 * 
	 * @param contentBytes 要加密的字节数组
	 * @param secret 密钥
	 * @param paddingMode 填充模式
	 * @param charset 指定编码集
	 * @return 加密后的字节数组
	 */
	public static byte[] encryptArrToArr(byte[] contentBytes, String secret, String paddingMode,
			String charset) {
		byte[] result = null;
		try {
			KeyGenerator kgen = KeyGenerator.getInstance("AES");
			kgen.init(128, new SecureRandom(secret.getBytes(charset)));
			SecretKey secretKey = kgen.generateKey();
			byte[] encoded = secretKey.getEncoded();
			SecretKeySpec key = new SecretKeySpec(encoded, "AES");

			Cipher cipher = null;
			if (paddingMode != null) {
				cipher = Cipher.getInstance(paddingMode);
			} else {
				cipher = Cipher.getInstance("AES/ECB/PKCS5padding");// 默认填充方式
			}

			cipher.init(Cipher.ENCRYPT_MODE, key);
			result = cipher.doFinal(contentBytes);

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
		if (result == null || result.length ==0) {
			throw new RuntimeException(
					"These is not encryption result exception");
		}
		return result;
	}
	
	/**
	 * 
	 * @param contentBytes 要加密的字符串
	 * @param secret 密钥
	 * @param paddingMode 填充模式
	 * @param charset 指定字符集
	 * @return 加密后的字节数组
	 */
	public static byte[] encryptStrToArr(String content, String secret,
			String paddingMode, String charset) {
		try {
			return encryptArrToArr(content.getBytes(charset), secret, paddingMode, charset);
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}
	}
	
	
	/**
	 * 
	 * @param in 加密的字节输入流
	 * @param secret 密钥
	 * @param paddingMode 填充模式
 	 * @param charset 密钥编码
	 * @return 解密的字节输出流
	 * @throws IOException
	 */
	public static InputStream decryptInputStream(InputStream in, String secret,
			String paddingMode, String charset) throws IOException {
		
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		
		byte[] bytes = new byte[1024];
		int len = 0;
		while((len = in.read(bytes)) != -1) {
			bos.write(bytes, 0, len);
		}
		in.close();
		bos.close();
		// 获取加密信息，即AES加密后base64编码数组
		byte[] encryptArray = bos.toByteArray();
		// base解码
		encryptArray = Base64.decodeBase64(encryptArray);
		
		// 解密数组
		byte[] decryptArray = decryptArrToArr(encryptArray, secret, paddingMode, charset);
		return new ByteArrayInputStream(decryptArray);
	}
	
	/**
	 * 
	 * @param contentBytes 要解密的字节数组
	 * @param secret 密钥
	 * @param paddingMode 填充模式
	 * @param charset 指定字符集
	 * @return 解密后的字节数组
	 */
	public static byte[] decryptArrToArr(byte[] contentBytes, String secret,
			String paddingMode, String charset) {
		byte[] result = null;
		try {
			KeyGenerator kgen = KeyGenerator.getInstance("AES");
			kgen.init(128, new SecureRandom(secret.getBytes(charset)));
			SecretKey secretKey = kgen.generateKey();
			byte[] encoded = secretKey.getEncoded();
			SecretKeySpec key = new SecretKeySpec(encoded, "AES");
			
			Cipher cipher = null;
			if (paddingMode != null) {
				cipher = Cipher.getInstance(paddingMode);
			} else {
				cipher = Cipher.getInstance("AES/ECB/PKCS5padding");// 默认填充方式
			}
			
			cipher.init(Cipher.DECRYPT_MODE, key);// 初始化
			result = cipher.doFinal(contentBytes);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
		
		if (result == null || result.length ==0) {
			throw new RuntimeException(
					"These is not decryption result exception");
		}
		return result;
	}
	
	/**
	 * 
	 * @param contentBytes 要解密的字节数组
	 * @param secret 密钥
	 * @param paddingMode 填充模式
	 * @param charset 指定字符集
	 * @return 解密后的字符串
	 */
	public static String decryptArrToStr(byte[] contentBytes, String secret,
			String paddingMode, String charset) {
		try {
			return new String(decryptArrToArr(contentBytes, secret, paddingMode, charset), charset);
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}
	}
}
