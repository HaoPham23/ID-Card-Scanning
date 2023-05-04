import 'package:convert/convert.dart';
import 'package:dmrtd/extensions.dart';
import 'package:elliptic/elliptic.dart';
import 'package:elliptic/ecdh.dart';
import 'dart:convert';
import 'dart:typed_data';
import '../crypto/kdf.dart';
import 'package:encrypt/encrypt.dart';
import 'package:crypto/crypto.dart';
import '../crypto/iso9797.dart';
import "package:pointycastle/export.dart" as pc;
import 'pace_keys.dart';

Uint8List doStep1({required Uint8List paceKey}) {
  print("Doing PACE step 1");
  final data = Uint8List.fromList(
      hex.decode("7C12801095A3A016522EE98D01E76CB6B98B42C3"));
  print("Encrypted nonce - ${data.sublist(4).hex()}");
  print("Expected:       - 95A3A016522EE98D01E76CB6B98B42C3");
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

EllipticCurve doStep2(
    {required Uint8List decryptedNonce, required EllipticCurve ec}) {
  print("Doing PACE step 2");
  // Create Private and Public key on brainpoolp256r1
  final mappingKey = PrivateKey.fromHex(
      ec, "7F4EF07B9EA82FD78AD689B38D0BC78CF21F249D953BC46F4C6E19259C010F99");
  print("private mapping key - ${mappingKey.D}");
  var pcdMappingEncodedPublicKey = mappingKey.publicKey;
  print("public mapping key - ${pcdMappingEncodedPublicKey.toHex()}");
  print("x =       ${pcdMappingEncodedPublicKey.X.toRadixString(16)}");
  print(
      "Expected: 7ACF3EFC982EC45565A4B155129EFBC74650DCBFA6362D896FC70262E0C2CC5E");
  print("y =       ${pcdMappingEncodedPublicKey.Y.toRadixString(16)}");
  print(
      "Expected: 544552DCB6725218799115B55C9BAA6D9F6BC3A9618E70C25AF71777A9C4922D");
  // Send to ICC
  print("Sending public mapping key to passport..");
  final step2Data =
      [0x7c, 0x43, 0x81, 0x41] + hex.decode(pcdMappingEncodedPublicKey.toHex());
  print("T>C:      ${Uint8List.fromList(step2Data).hex()}");
  print(
      "Expected: 7C438141047ACF3EFC982EC45565A4B155129EFBC74650DCBFA6362D896FC70262E0C2CC5E544552DCB6725218799115B55C9BAA6D9F6BC3A9618E70C25AF71777A9C4922D");
  final response = Uint8List.fromList(hex.decode(
      "7C43824104824FBA91C9CBE26BEF53A0EBE7342A3BF178CEA9F45DE0B70AA601651FBA3F5730D8C879AAA9C9F73991E61B58F4D52EB87A0A0C709A49DC63719363CCD13C54"));
  // // Receive ICC Pubkey
  final data = response;
  print("Received passports public mapping key");
  final piccMappingEncodedPublicKey =
      PublicKey.fromHex(ec, hex.encode(data.sublist(4)));
  print("   ICC public mapping key:");
  print("      x = ${piccMappingEncodedPublicKey.X.toRadixString(16)}");
  print(
      "Expected: 824FBA91C9CBE26BEF53A0EBE7342A3BF178CEA9F45DE0B70AA601651FBA3F57");
  print("      y = ${piccMappingEncodedPublicKey.Y.toRadixString(16)}");
  print(
      "Expected: 30D8C879AAA9C9F73991E61B58F4D52EB87A0A0C709A49DC63719363CCD13C54");

  // Create ephemeralParams
  var ephemeralParams = doECDHMappingAgreement(
      mappingKey: mappingKey,
      piccMappingEncodedPublicKey: piccMappingEncodedPublicKey,
      nonce: decryptedNonce);
  return ephemeralParams;
}

EllipticCurve doECDHMappingAgreement(
    {required PrivateKey mappingKey,
    required PublicKey piccMappingEncodedPublicKey,
    required Uint8List nonce}) {
  print("Doing ECDH Mapping agreement");
  final ec = mappingKey.curve;
  final H = ec.scalarMul(piccMappingEncodedPublicKey, mappingKey.bytes);
  final G_hat = ec.add(ec.scalarBaseMul(nonce), H);
  print(
      "G^ =      (0x${G_hat.X.toRadixString(16)}, 0x${G_hat.Y.toRadixString(16)})");
  print(
      "Expected: (0x8CED63C91426D4F0EB1435E7CB1D74A46723A0AF21C89634F65A9AE87A9265E2, 0x8C879506743F8611AC33645C5B985C80B5F09A0B83407C1B6A4D857AE76FE522)");
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

Map doStep3KeyExchange({required EllipticCurve ephemeralParams}) {
  print("Doing PACE Step3 - Key Exchange");
  var terminalKeyPairsAndICCPubKey = {};
  final terminalPrivateKey = PrivateKey.fromHex(ephemeralParams,
      "A73FB703AC1436A18E0CFA5ABB3F7BEC7A070E7A6788486BEE230C4A22762595");
  print("Generated Ephemeral key pair");

  print("ephemeral private key - ${terminalPrivateKey.D}");
  var terminalPublicKey = terminalPrivateKey.publicKey;
  print("ephemeral public key - ${terminalPublicKey.toHex()}");
  print("  x =     ${terminalPublicKey.X.toRadixString(16)}");
  print(
      "Expected: 2DB7A64C0355044EC9DF190514C625CBA2CEA48754887122F3A5EF0D5EDD301C");
  print("  y =     ${terminalPublicKey.Y.toRadixString(16)}");
  print(
      "Expected: 3556F3B3B186DF10B857B58F6A7EB80F20BA5DC7BE1D43D9BF850149FBB36462");
  // Send to ICC
  print("Sending ephemeral public key to passport..");
  final step3Data =
      [0x7c, 0x43, 0x83, 0x41] + hex.decode(terminalPublicKey.toHex());
  print("step3Data = ${Uint8List.fromList(step3Data).hex()}");
  print(
      "Expected:   7C438341042DB7A64C0355044EC9DF190514C625CBA2CEA48754887122F3A5EF0D5EDD301C3556F3B3B186DF10B857B58F6A7EB80F20BA5DC7BE1D43D9BF850149FBB36462");
  final response = Uint8List.fromList(hex.decode(
      "7C438441049E880F842905B8B3181F7AF7CAA9F0EFB743847F44A306D2D28C1D9EC65DF6DB7764B22277A2EDDC3C265A9F018F9CB852E111B768B326904B59A0193776F094"));
  // Receive ICC Pubkey
  final data = response;
  print("Received passports ephemeral public key");
  final iccPublicKey =
      PublicKey.fromHex(ephemeralParams, hex.encode(data.sublist(4)));
  print("   ICC ephemeral public key:");
  print("      x = ${iccPublicKey.X.toRadixString(16)}");
  print(
      "Expected: 9E880F842905B8B3181F7AF7CAA9F0EFB743847F44A306D2D28C1D9EC65DF6DB");
  print("      y = ${iccPublicKey.Y.toRadixString(16)}");
  print(
      "Expected  7764B22277A2EDDC3C265A9F018F9CB852E111B768B326904B59A0193776F094");

  terminalKeyPairsAndICCPubKey['ephemeralKeyPair'] = terminalPrivateKey;
  terminalKeyPairsAndICCPubKey['passportPublicKey'] = iccPublicKey;
  return terminalKeyPairsAndICCPubKey;
}

Map doStep4KeyAgreement(
    {required PrivateKey ephemeralKeyPair,
    required PublicKey passportPublicKey,
    required Uint8List oid}) {
  print("Doing PACE Step4 Key Agreement...");
  print("Computing shared secret...");
  final keySeed = Uint8List.fromList(
      hex.decode(computeSecretHex(ephemeralKeyPair, passportPublicKey)));
  print("Shared secret - ${keySeed.hex()}");
  print(
      "Expected:       28768D20701247DAE81804C9E780EDE582A9996DB4A315020B2733197DB84925");
  print("Deriving ksEnc and ksMac keys from shared secret");
  final encKey = DeriveKey.aes128(keySeed);
  final macKey = DeriveKey.cmac128(keySeed);
  print("KSenc =    ${hex.encode(encKey)}");
  print("Expected:  F5F0E35C0D7161EE6724EE513A0D9A7F");
  print("KSmac =    ${hex.encode(macKey)}");
  print("Expected:  FE251C7858B356B24514B3BD5F4297D1");
  var encKey_macKey = {};
  encKey_macKey['encKey'] = encKey;
  encKey_macKey['macKey'] = macKey;

  // Step 4 - generate authentication token
  print("Generating authentication token");
  final pcdAuthToken =
      generateAuthenticationToken(passportPublicKey, macKey, oid);

  print("  authentication token - ${hex.encode(pcdAuthToken)}");
  print("Expected:                C2B0BD78D94BA866");
  print("Sending auth token to passport");
  final step4Data = [0x7c, 0x0a, 0x85, 0x08] + pcdAuthToken;
  print("Step4Data:  ${Uint8List.fromList(step4Data).hex()}");
  print("Expected:   7C0A8508C2B0BD78D94BA866");
  // final response = await icc.sendGeneralAuthenticate(
  //     data: Uint8List.fromList(step4Data), isLast: true);
  // final data = response.data;
  // print("Received ${response.data!.hex()}");
  return encKey_macKey;
}

Uint8List generateAuthenticationToken(
    PublicKey pubkey, Uint8List macKey, Uint8List oid) {
  var authData = Uint8List.fromList([0x7f, 0x49, 0x4f] +
      [0x06, 0x0a] +
      oid.sublist(1) +
      [0x86, 0x41] +
      hex.decode(pubkey.toHex()));
  print("authData = ${authData.hex()}");
  print(
      "Expected:  7F494F060A04007F000702020402028641049E880F842905B8B3181F7AF7CAA9F0EFB743847F44A306D2D28C1D9EC65DF6DB7764B22277A2EDDC3C265A9F018F9CB852E111B768B326904B59A0193776F094");
  final cmac = pc.CMac(pc.AESEngine(), 64);
  // var macKey_test = Uint8List.fromList(hex.decode('fe251c7858b356b24514b3bd5f4297d1'));
  // cmac.init(pc.KeyParameter(macKey_test));
  cmac.init(pc.KeyParameter(macKey));
  final authToken = cmac.process(authData);
  return authToken;
}

void testPACE() {
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
  // Test PaceKey
  final keys =
      PACEKeys("T22000129", DateTime(1964, 8, 12), DateTime(2010, 10, 31));
  final paceKey = keys.encKey;
  print("Pacekey : ${paceKey.hex()}");
  print("Expected: 89DED1B26624EC1E634C1989302849DD");
  // Test Step1
  final decryptedNonce = doStep1(paceKey: paceKey);
  print("Decrypted nonce: ${decryptedNonce.hex()}");
  print("Expected       : 3F00C4D39D153F2B2A214A078D899B22");
  // Test Step2
  final ephemeralParams =
      doStep2(decryptedNonce: decryptedNonce, ec: brainpoolP256r1);
  // Test Step3
  final terminalKeyPairsAndICCPubKey =
      doStep3KeyExchange(ephemeralParams: ephemeralParams);
  final ephemeralKeyPair = terminalKeyPairsAndICCPubKey["ephemeralKeyPair"];
  final passportPublicKey = terminalKeyPairsAndICCPubKey['passportPublicKey'];
  //Test Step4
  final paceOID = Uint8List.fromList([0, 4, 0, 127, 0, 7, 2, 2, 4, 2, 2]);
  final encKey_macKey = doStep4KeyAgreement(
      ephemeralKeyPair: ephemeralKeyPair,
      passportPublicKey: passportPublicKey,
      oid: paceOID);
  final encKey = encKey_macKey["encKey"];
  final macKey = encKey_macKey["macKey"];
}

void main() {
  final EllipticCurve ec = EllipticCurve(
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

  // final mappingKey = PrivateKey.fromHex(
  //     ec, '7F4EF07B9EA82FD78AD689B38D0BC78CF21F249D953BC46F4C6E19259C010F99');
  // final piccMappingEncodedPrivateKey = PrivateKey.fromHex(
  //     ec, '498FF49756F2DC1587840041839A85982BE7761D14715FB091EFA7BCE9058560');
  // final piccMappingEncodedPublicKey = piccMappingEncodedPrivateKey.publicKey;
  // final H = ec.scalarMul(piccMappingEncodedPublicKey, mappingKey.bytes);
  // final nonce = hex.decode('3F00C4D39D153F2B2A214A078D899B22');
  // final G_hat = ec.add(ec.scalarBaseMul(nonce), H);
  // final EllipticCurve ephemeralParams = EllipticCurve(
  //   'brainpoolP256r1',
  //   256, // bitSize
  //   BigInt.parse(
  //       'a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377',
  //       radix: 16), // p
  //   BigInt.parse(
  //       '7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9',
  //       radix: 16), //a
  //   BigInt.parse(
  //       '26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6',
  //       radix: 16), //b
  //   BigInt.zero, //S
  //   G_hat, // G
  //   BigInt.parse(
  //       'a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7',
  //       radix: 16), //N
  //   01, // h
  // );

  // final new_terminalPrivKey = PrivateKey.fromHex(ephemeralParams,
  //     'A73FB703AC1436A18E0CFA5ABB3F7BEC7A070E7A6788486BEE230C4A22762595');
  // final new_piccPrivKey = PrivateKey.fromHex(ephemeralParams,
  //     '107CF58696EF6155053340FD633392BA81909DF7B9706F226F32086C7AFF974A');

  // final new_terminalPubKey = new_terminalPrivKey.publicKey;
  // final new_piccPubKey = new_piccPrivKey.publicKey;
  // final keySeed = Uint8List.fromList(
  //     hex.decode(computeSecretHex(new_terminalPrivKey, new_piccPubKey)));
  // final KSenc = DeriveKey.aes128(keySeed);
  // final KSmac = DeriveKey.cmac128(keySeed);
  // print(hex.encode(KSenc));
  // print(hex.encode(KSmac));
  // final tagOld =
  //     '7F494F060A04007F000702020402028641049E880F842905B8B3181F7AF7CAA9F0EFB743847F44A306D2D28C1D9EC65DF6DB7764B22277A2EDDC3C265A9F018F9CB852E111B768B326904B59A0193776F094';
  // var tagList = Uint8List.fromList(
  //     hex.decode("7F494F060A04007F000702020402028641") +
  //         hex.decode(new_piccPubKey.toHex()));
  // // final tagList = Uint8List.fromList(hex.decode(tag));
  // var tagList2 = Uint8List.fromList(
  //     hex.decode("7F494F060A04007F000702020402028641") +
  //         hex.decode(new_piccPubKey.toHex()));
  // final cmac = pc.CMac(pc.AESEngine(), 64);
  // cmac.init(pc.KeyParameter(KSmac));
  // final t = cmac.process(tagList);
  // final t2 = cmac.process(tagList2);
  // print(hex.encode(t));
  // print(hex.encode(t2));
  // print(new_piccPubKey.toHex());
  // print(hex.encode(tagList));
  testPACE();
}
