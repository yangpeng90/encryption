package com.peng.yang;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

/**
 * MD5摘要算法
 * 128位摘要信息
 * @author 杨鹏
 *
 */
/*
 * toByteArray
 * toHexString
 * toBaseString
 */
public class MD5Utils {
	
	// 用-和_替换+和/
	public static String toBase64UrlSafeString(String str, String charset) {
		byte[] md5bs = toByteArray(str, charset);
		md5bs = Base64.encodeBase64URLSafe(md5bs);
		return new String(md5bs);
	}
	
	// 先将字符串生成默认编码的字节数组，然后进行MD5算法生成加密字节数组，转换为Base64编码的字符串
	public static String toBase64String(String str) {
		byte[]bs = Base64.encodeBase64(toByteArray(str));
		return new String(bs);
	}
	
	// 先将字符串生成制定编码的字节数组，然后进行MD5算法生成加密字节数组，转换为Base64编码的字符串
	public static String toBase64String(String str, String charset) {
		byte[]bs = Base64.encodeBase64(toByteArray(str, charset));
		try {
			return new String(bs, charset);
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}
	}
	
	// 先将字符串生成默认编码的字节数组，然后进行MD5算法生成加密字节数组，转换为16进制字符串
	public static String toHexString(String str) {
		return Hex.encodeHexString(toByteArray(str));
	}
	
	// 先将字符串生成制定编码的字节数组，然后进行MD5算法生成加密字节数组，转换为16进制字符串
	public static String toHexString(String str, String charset) {
		return Hex.encodeHexString(toByteArray(str, charset));
	}
	
	// 平台默认字符集获取字符串的字节编码数组
	public static byte[] toByteArray(String str) {

		try {
			byte[] bytes = str.getBytes();
			MessageDigest md5 = MessageDigest.getInstance("MD5");
			return md5.digest(bytes);
		} catch (NoSuchAlgorithmException e1) {
			throw new RuntimeException(e1);
		}
		
	}

	// 因为要获取字符串的字节编码数组，所以要指定编码
	public static byte[] toByteArray(String str, String charset) {
		
		try {
			byte[] bytes = str.getBytes(charset);
			MessageDigest md5 = MessageDigest.getInstance("MD5");
			return md5.digest(bytes);
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		} catch (NoSuchAlgorithmException e1) {
			throw new RuntimeException(e1);
		}
		
	}
}
