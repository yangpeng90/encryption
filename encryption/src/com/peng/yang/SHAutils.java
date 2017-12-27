package com.peng.yang;

import java.io.UnsupportedEncodingException;

import org.apache.commons.codec.digest.DigestUtils;

/**
 * 安全散列算法
 * 固定长度摘要信息
 * @author 杨鹏
 *
 */
public class SHAutils {

	public static String sha512HexStr(String str) {
		return DigestUtils.sha512Hex(str.getBytes());
	}

	// SHA-512
	public static String sha512HexStr(String str, String charset) {
		try {
			return DigestUtils.sha512Hex(str.getBytes(charset));
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}
	}

	public static String sha256HexStr(String str) {
		return DigestUtils.sha256Hex(str.getBytes());
	}

	// SHA-256
	public static String sha256HexStr(String str, String charset) {
		try {
			return DigestUtils.sha256Hex(str.getBytes(charset));
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}
	}

	public static String sha1HexStr(String str) {
		return DigestUtils.sha1Hex(str.getBytes());
	}

	// SHA-1
	// charset为字符串转换为字节数组的编码
	public static String sha1HexStr(String str, String charset) {
		try {
			return DigestUtils.sha1Hex(str.getBytes(charset));
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}
	}
	
	public static byte[] sha512(String s, String charset) {
		try {
			return DigestUtils.sha512(s.getBytes(charset));
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}
	}
	public static byte[] sha256(String s, String charset) {
		try {
			return DigestUtils.sha256(s.getBytes(charset));
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}
	}
	public static byte[] sha1(String s, String charset) {
		try {
			return DigestUtils.sha1(s.getBytes(charset));
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}
	}
	
	public static byte[] sha512(String s) {
		return DigestUtils.sha512(s.getBytes());
	}
	public static byte[] sha256(String s) {
		return DigestUtils.sha256(s.getBytes());
	}
	public static byte[] sha1(String s) {
		return DigestUtils.sha1(s.getBytes());
	}
}
