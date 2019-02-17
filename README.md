# 128-bit AES PKCS7

## 개요
128비트 AES에 대한 이해도를 향상시키기 위해 C++로 작성된 프로그램입니다.
AES-128-ECB입니다!

## 설명

- aes128.cpp - 	CustomDecrypter(암호화된 문자열, 암호키), CustomEncrypter(암호화할 문자열, 암호키);
- aes.h - 메인 프로그램 파일에 사용하기 위한 구조 및 키 확장 기능을 제공합니다.

## 암호키
128비트 AES인 만큼 암호키는 16자리까지 읽을 수 있으며 이상적인 길이 또한 16자리 입니다.
16자리가 되지 않아도 괜찮습니다! PKCS7 PADDING을 자동으로 수행하니까요!

## 사용 방법
Base64함수에 대해 의존성을 띄고 있으므로, Base64함수를 만들어 사용하거나 해당부분을 주석처리후 사용하면 됩니다!

	#include "aes128.h"
	
	int main(){
		AES128 aes128;
		aes128.CustomEncrypter("https://syudal.tistory.com", "syudaltistorycom");
	}
