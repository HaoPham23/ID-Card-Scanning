import 'package:dmrtd/extensions.dart';
import 'package:encrypt/encrypt.dart';
import 'dart:typed_data';

void main() {
  final plainText = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit';
  final key = Key(Uint8List.fromList([
    0x89,
    0xDE,
    0xD1,
    0xB2,
    0x66,
    0x24,
    0xEC,
    0x1E,
    0x63,
    0x4C,
    0x19,
    0x89,
    0x30,
    0x28,
    0x49,
    0xDD
  ]));
  print(Uint8List.fromList([
    0x89,
    0xDE,
    0xD1,
    0xB2,
    0x66,
    0x24,
    0xEC,
    0x1E,
    0x63,
    0x4C,
    0x19,
    0x89,
    0x30,
    0x28,
    0x49,
    0xDD
  ]).hex());
  // final key = Key.fromSecureRandom(16);
  final iv = IV(Uint8List.fromList(List.filled(16, 0)));
  print(Uint8List.fromList(List.filled(16, 0)).hex());
  // final iv = IV.fromSecureRandom(16);
  final encryptedNonceTest = Encrypted(Uint8List.fromList([
    0x95,
    0xA3,
    0xA0,
    0x16,
    0x52,
    0x2E,
    0xE9,
    0x8D,
    0x01,
    0xE7,
    0x6C,
    0xB6,
    0xB9,
    0x8B,
    0x42,
    0xC3
  ]));
  final encrypter = Encrypter(AES(key, mode: AESMode.cbc, padding: null));
  final decryptedNonce =
      Uint8List.fromList(encrypter.decryptBytes(encryptedNonceTest, iv: iv));
  print('DECRYPTED NONCE:       ${decryptedNonce.hex()}');
}
