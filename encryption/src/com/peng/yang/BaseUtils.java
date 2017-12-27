package com.peng.yang;

import org.apache.commons.codec.binary.Base64;

public class BaseUtils {

	// 由于base64编码是ASCII的子集，解码不需要指定字符集
	public static String decode(String base64Str) {
		return new String(Base64.decodeBase64(base64Str));
	}
	
}
