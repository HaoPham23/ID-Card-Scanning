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
import 'package:elliptic/elliptic.dart';
import 'package:elliptic/ecdh.dart';
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
    final EllipticCurve brainpoolP256r1 = EllipticCurve(
      'brainpoolP256r1',
      256, // bitSize
      BigInt.parse(
          'a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377',
          radix: 16), // p
      BigInt.parse(
          '7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9',
          radix: 16), //a
      BigInt.parse(
          '26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6',
          radix: 16), //b
      BigInt.zero, //S
      AffinePoint.fromXY(
        BigInt.parse(
            '8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262',
            radix: 16),
        BigInt.parse(
            '547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997',
            radix: 16),
      ), // G
      BigInt.parse(
          'a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7',
          radix: 16), //N
      01, // h
    );
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

    final decryptedNonce = await doStep1(icc: icc, paceKey: paceKey);
    _log.debug("Decrypted Nonce - ${decryptedNonce.hex()}");

    final ephemeralParams = await doStep2(
        icc: icc, decryptedNonce: decryptedNonce, ec: brainpoolP256r1);

    final terminalKeyPairsAndICCPubKey =
        await doStep3KeyExchange(icc: icc, ephemeralParams: ephemeralParams);


    // throw Exception("PACE Failed!");
    throw "PACE Failed";
  }

  static Future<Uint8List> doStep1(
      {required ICC icc, required Uint8List paceKey}) async {
    _log.debug("Doing PACE step 1");
    final response = await icc.sendGeneralAuthenticate(
        data: Uint8List.fromList([0x7c, 0x00]), isLast: false);
    final data = response.data;
    _log.debug("Encrypted nonce - ${data!.sublist(4).hex()}");

    final encryptedNonce = Encrypted(data.sublist(4)); // Nhap, sua sau
    final key = Key(paceKey);
    final iv = IV(Uint8List.fromList(List.filled(16, 0)));
    final encrypter = Encrypter(AES(key, mode: AESMode.cbc, padding: null));
    final decryptedNonce = Uint8List.fromList(encrypter.decryptBytes(
      encryptedNonce,
      iv: iv,
    ));
    return decryptedNonce;
  }

  static Future<EllipticCurve> doStep2(
      {required ICC icc,
      required Uint8List decryptedNonce,
      required EllipticCurve ec}) async {
    _log.debug("Doing PACE step 2");
    // Create Private and Public key on brainpoolp256r1
    final mappingKey = ec.generatePrivateKey();
    _log.debug("private mapping key - ${mappingKey.D}");
    var pcdMappingEncodedPublicKey = mappingKey.publicKey;
    _log.debug("public mapping key - ${pcdMappingEncodedPublicKey.toHex()}");
    _log.debug("x = ${pcdMappingEncodedPublicKey.X.toRadixString(16)}");
    _log.debug("y = ${pcdMappingEncodedPublicKey.Y.toRadixString(16)}");
    // Send to ICC
    _log.debug("Sending public mapping key to passport..");
    final step2Data = [0x7c, 0x43, 0x81, 0x41] +
        hex.decode(pcdMappingEncodedPublicKey.toHex());
    final response = await icc.sendGeneralAuthenticate(
        data: Uint8List.fromList(step2Data), isLast: false);
    // Receive ICC Pubkey
    final data = response.data;
    _log.debug("Received passports public mapping key");
    final piccMappingEncodedPublicKey =
        PublicKey.fromHex(ec, hex.encode(data!.sublist(4)));
    _log.debug("   ICC public mapping key:");
    _log.debug("      x = ${piccMappingEncodedPublicKey.X.toRadixString(16)}");
    _log.debug("      y = ${piccMappingEncodedPublicKey.Y.toRadixString(16)}");

    // Create ephemeralParams
    var ephemeralParams = doECDHMappingAgreement(
        mappingKey: mappingKey,
        piccMappingEncodedPublicKey: piccMappingEncodedPublicKey,
        nonce: decryptedNonce);
    return ephemeralParams;
  }

  static Future<Map> doStep3KeyExchange(
      {required ICC icc, required EllipticCurve ephemeralParams}) async {
    _log.debug("Doing PACE Step3 - Key Exchange");
    var terminalKeyPairsAndICCPubKey = {};
    final terminalPrivateKey = ephemeralParams.generatePrivateKey();
    terminalKeyPairsAndICCPubKey['ephemeralKeyPair'] = terminalPrivateKey;
    _log.debug("Generated Ephemeral key pair");

    _log.debug("ephemeral private key - ${terminalPrivateKey.D}");
    var terminalPublicKey = terminalPrivateKey.publicKey;
    _log.debug("ephemeral public key - ${terminalPublicKey.toHex()}");
    _log.debug("  x = ${terminalPublicKey.X.toRadixString(16)}");
    _log.debug("  y = ${terminalPublicKey.Y.toRadixString(16)}");
    // Send to ICC
    _log.debug("Sending ephemeral public key to passport..");
    final step3Data = [0x7c, 0x43, 0x83, 0x41] +
        hex.decode(terminalPublicKey.toHex());
    final response = await icc.sendGeneralAuthenticate(
        data: Uint8List.fromList(step3Data), isLast: false);
    // Receive ICC Pubkey
    final data = response.data;
    _log.debug("Received passports ephemeral public key");
    final iccPublicKey =
        PublicKey.fromHex(ephemeralParams, hex.encode(data!.sublist(4)));
    _log.debug("   ICC ephemeral public key:");
    _log.debug("      x = ${iccPublicKey.X.toRadixString(16)}");
    _log.debug("      y = ${iccPublicKey.Y.toRadixString(16)}");
    terminalKeyPairsAndICCPubKey['passportPublicKey'] = iccPublicKey;
    return terminalKeyPairsAndICCPubKey;
  }

  static EllipticCurve doECDHMappingAgreement(
      {required PrivateKey mappingKey,
      required PublicKey piccMappingEncodedPublicKey,
      required Uint8List nonce}) {
    _log.debug("Doing ECDH Mapping agreement");
    final ec = mappingKey.curve;
    final H = ec.scalarMul(piccMappingEncodedPublicKey, mappingKey.bytes);
    final G_hat = ec.add(ec.scalarBaseMul(nonce), H);
    _log.debug(
        "New Generator G^ = (0x${G_hat.X.toRadixString(16)}, 0x${G_hat.Y.toRadixString(16)})");
    final EllipticCurve ephemeralParams = EllipticCurve(
      'brainpoolP256r1',
      256, // bitSize
      BigInt.parse(
          'a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377',
          radix: 16), // p
      BigInt.parse(
          '7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9',
          radix: 16), //a
      BigInt.parse(
          '26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6',
          radix: 16), //b
      BigInt.zero, //S
      G_hat, // G
      BigInt.parse(
          'a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7',
          radix: 16), //N
      01, // h
    );
    return ephemeralParams;
  }
}
