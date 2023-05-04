// Created by Hao, 02/05/2023
import 'dart:typed_data';
import 'iso7816/smcipher.dart';
import '../crypto/des.dart';
import '../crypto/iso9797.dart';
import 'package:encrypt/encrypt.dart';
import "package:pointycastle/export.dart" as pc;

// ignore: camel_case_types
class PACE_SMCipher implements SMCipher {
  Uint8List encKey;
  Uint8List macKey;

  PACE_SMCipher(this.encKey, this.macKey);

  @override
  Uint8List encrypt(Uint8List data, [IV? iv]) {
    final key = Key(encKey);
    final encrypter = Encrypter(AES(key, mode: AESMode.cbc, padding: null));
    return encrypter.encryptBytes(data, iv: iv).bytes;
  }


  @override
  Uint8List decrypt(Uint8List edata, [IV? iv]) {
    final key = Key(encKey);
    final encrypter = Encrypter(AES(key, mode: AESMode.cbc, padding: null));
    return Uint8List.fromList(encrypter.decryptBytes(Encrypted(edata), iv: iv));
  }

  @override
  Uint8List mac(Uint8List data) {
    final cmac = pc.CMac(pc.AESEngine(), 64);
    cmac.init(pc.KeyParameter(macKey));
    return cmac.process(data);
  }
}