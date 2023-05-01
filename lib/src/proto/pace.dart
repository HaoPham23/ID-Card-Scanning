//  Created by Hao Pham, 27/04/2023
import 'dart:ffi';
import 'dart:typed_data';
import 'package:collection/collection.dart';
import 'package:convert/convert.dart';
import 'package:dmrtd/dmrtd.dart';
import 'package:dmrtd/extensions.dart';
import 'package:logging/logging.dart';
import 'package:meta/meta.dart';
import 'package:encrypt/encrypt.dart';
import '../crypto/des.dart';
import '../crypto/iso9797.dart';
import '../crypto/kdf.dart';
import '../crypto/crypto_utils.dart';
import '../types/pair.dart';

import 'iso7816/icc.dart';
import 'dba_keys.dart';
import 'mrtd_sm.dart';
import 'ssc.dart';

class PACEError implements Exception {
  final String message;
  PACEError(this.message);
  @override
  String toString() => message;
}

class PACE {
  static final _log = Logger("pace");

  static Future<void> initSession(
      {required PACEKeys keys,
      required Map securityInfos,
      required ICC icc}) async {
    final paceOID = securityInfos['PACEInfo']['paceOID'];
    final parameterSpec = securityInfos['PACEInfo']['parameterSpec'];
    final mappingType = securityInfos['PACEInfo']['mappingType'];
    final agreementAlg = securityInfos['PACEInfo']['agreementAlg'];
    final cipherAlg = securityInfos['PACEInfo']['cipherAlg'];
    final digestAlg = securityInfos['PACEInfo']['digestAlg'];
    final keyLength = securityInfos['PACEInfo']['keyLength'];
    // paceKeyType = PACEHandler.MRZ_PACE_KEY_REFERENCE
    final paceKeyType = 0x01;
    final paceKey = keys.encKey;
    _log.info("doPACE - input parameters");
    _log.info("paceOID - $paceOID");
    _log.info("parameterSpec - $parameterSpec");
    _log.info("mappingType - $mappingType");
    _log.info("agreementAlg - $agreementAlg");
    _log.info("cipherAlg - $cipherAlg");
    _log.info("digestAlg - $digestAlg");
    _log.info("keyLength - $keyLength");
    _log.info("paceKey - ${paceKey.hex()}");
    final _ =
        await icc.sendMSESetATMutualAuth(oid: paceOID, keyType: paceKeyType);

// let decryptedNonce = try await self.doStep1()
// let ephemeralParams = try await self.doStep2(passportNonce: decryptedNonce)
// let (ephemeralKeyPair, passportPublicKey) = try await self.doStep3KeyExchange(ephemeralParams: ephemeralParams)
// let (encKey, macKey) = try await self.doStep4KeyAgreement( pcdKeyPair: ephemeralKeyPair, passportPublicKey: passportPublicKey)
// try self.paceCompleted( ksEnc: encKey, ksMac: macKey )
// Log.debug("PACE SUCCESSFUL" )
    final decryptedNonce = await doStep1(icc: icc, paceKey: paceKey);
    _log.debug("Decrypted Nonce - ${decryptedNonce.hex()}");
    // final ephemeralParams = await doStep2(icc: icc);
    // throw Exception("PACE Failed!");
    throw Exception("PACE Failed");
  }

  static Future<Uint8List> doStep1(
      {required ICC icc, required Uint8List paceKey}) async {
    _log.debug("Doing PACE step 1");
    final response = await icc.sendGeneralAuthenticate(
        data: Uint8List.fromList([]), isLast: false);
    final data = response.data;
    _log.debug("Encrypted nonce - ${data!.sublist(4).hex()}");

    final encryptedNonce = Encrypted(data!.sublist(4)); // Nhap, sua sau
    final key = Key(paceKey);
    final iv = IV(Uint8List.fromList(List.filled(16, 0)));
    final encrypter = Encrypter(AES(key, mode: AESMode.cbc, padding: null));
    final decryptedNonce = Uint8List.fromList(encrypter.decryptBytes(
      encryptedNonce,
      iv: iv,
    ));
    return decryptedNonce;
  }
}
