import 'package:flutter/foundation.dart';
import 'package:flutter/cupertino.dart';
import 'dart:typed_data';

import 'package:dmrtd/dmrtd.dart';
import 'package:dmrtd/extensions.dart';
import 'package:intl/intl.dart';
import 'package:logging/logging.dart';
import 'package:crypto/crypto.dart';

import 'package:pkcs7/pkcs7.dart';
import 'package:pointycastle/pointycastle.dart';
import 'package:pointycastle/src/utils.dart';
// import 'package:pointycastle/src/asn1.dart';

import 'package:ecdsa/ecdsa.dart' as ecdsa;
import 'package:elliptic/elliptic.dart' as ecc;

import 'package:mrtdeg/curves.dart';

class Mrz {
  String id;
  DateTime birthday;
  DateTime expiry;

  Mrz(this.id, this.birthday, this.expiry);

  @override
  String toString() {
    return 'Mrz{$id, $birthday, $expiry}';
  }
}

class MrtdData {
  EfCardAccess? cardAccess;
  EfCardSecurity? cardSecurity;
  EfCOM? com;
  EfSOD? sod;
  EfDG1? dg1;
  EfDG2? dg2;
  EfDG3? dg3;
  EfDG4? dg4;
  EfDG5? dg5;
  EfDG6? dg6;
  EfDG7? dg7;
  EfDG8? dg8;
  EfDG9? dg9;
  EfDG10? dg10;
  EfDG11? dg11;
  EfDG12? dg12;
  EfDG13? dg13;
  EfDG14? dg14;
  EfDG15? dg15;
  EfDG16? dg16;
  Uint8List? aaSig;
  Uint8List? authData;
}

final Map<DgTag, String> dgTagToString = {
  EfDG1.TAG: 'EF.DG1',
  EfDG2.TAG: 'EF.DG2',
  EfDG3.TAG: 'EF.DG3',
  EfDG4.TAG: 'EF.DG4',
  EfDG5.TAG: 'EF.DG5',
  EfDG6.TAG: 'EF.DG6',
  EfDG7.TAG: 'EF.DG7',
  EfDG8.TAG: 'EF.DG8',
  EfDG9.TAG: 'EF.DG9',
  EfDG10.TAG: 'EF.DG10',
  EfDG11.TAG: 'EF.DG11',
  EfDG12.TAG: 'EF.DG12',
  EfDG13.TAG: 'EF.DG13',
  EfDG14.TAG: 'EF.DG14',
  EfDG15.TAG: 'EF.DG15',
  EfDG16.TAG: 'EF.DG16'
};

String formatEfCom(final EfCOM efCom) {
  var str = "version: ${efCom.version}\n"
      "unicode version: ${efCom.unicodeVersion}\n"
      "DG tags:";

  for (final t in efCom.dgTags) {
    try {
      str += " ${dgTagToString[t]!}";
    } catch (e) {
      str += " 0x${t.value.toRadixString(16)}";
    }
  }
  return str;
}

String formatMRZ(final MRZ mrz) {
  return "MRZ\n"
          "  version: ${mrz.version}\n" +
      "  doc code: ${mrz.documentCode}\n" +
      "  doc No.: ${mrz.documentNumber}\n" +
      "  country: ${mrz.country}\n" +
      "  nationality: ${mrz.nationality}\n" +
      "  name: ${mrz.firstName}\n" +
      "  surname: ${mrz.lastName}\n" +
      "  gender: ${mrz.gender}\n" +
      "  date of birth: ${DateFormat.yMd().format(mrz.dateOfBirth)}\n" +
      "  date of expiry: ${DateFormat.yMd().format(mrz.dateOfExpiry)}\n" +
      "  add. data: ${mrz.optionalData}\n" +
      "  add. data: ${mrz.optionalData2}";
}

Map getSecurityInfos(final EfCardAccess? ca) {
  var p = ASN1Parser(ca!.toBytes().sublist(2));
  var tbsCertificate = (p.nextObject() as ASN1Sequence).elements!;
  var signatureAlgorithm = (p.nextObject() as ASN1Sequence).elements!;
  var signature = (p.nextObject() as ASN1Sequence).elements!;
  var res = {};
  res['tbsCertificate'] = {};
  res['caAlgorithmIdentifier'] = {};
  res['PACEInfo'] = {};
  res['PACEInfo']['paceOID'] =
      (signature[0] as ASN1ObjectIdentifier).objectIdentifier;
  res['PACEInfo']['parameterSpec'] = 'brainpoolp256r1';
  res['PACEInfo']['mappingType'] = 'GM';
  res['PACEInfo']['agreementAlg'] = 'ECDH';
  res['PACEInfo']['cipherAlg'] = 'AES';
  res['PACEInfo']['digestAlg'] = 'SHA-1';
  res['PACEInfo']['keyLength'] = 128;

  return res;
}

String formatCardAccess(final EfCardAccess ca) {
  var p = ASN1Parser(ca.toBytes().sublist(2));

  // var values = (p.nextObject()! as ASN1Sequence).elements!;
  var log = Logger("CardAccess");

  var s = "";
  var tbsCertificate = (p.nextObject() as ASN1Sequence).elements!;
  var signatureAlgorithm = (p.nextObject() as ASN1Sequence).elements!;
  var signature = (p.nextObject() as ASN1Sequence).elements!;
  s += "\nTo Be Signed Certificate\n";
  s +=
      "  serialNumber: ${(tbsCertificate[0] as ASN1ObjectIdentifier).objectIdentifierAsString} (bsiTA)\n";
  s += "  signature: ${(tbsCertificate[1] as ASN1Integer).integer}\n";

  s += "\nChip Authentication Algorithm Identifier\n";
  s +=
      "  algorithm: ${(signatureAlgorithm[0] as ASN1ObjectIdentifier).objectIdentifierAsString} (bsiCA_ECDH_AES_CBC_CMAC_128)\n";
  s += "  parameters: ${(signatureAlgorithm[1] as ASN1Integer).integer}\n";

  s += "\nPACEinfo\n";
  s +=
      " Algorithm: ${(signature[0] as ASN1ObjectIdentifier).objectIdentifierAsString} (bsiPACE_ECDH_GM_AES_CBC_CMAC_128)\n";
  s += " Version: ${(signature[1] as ASN1Integer).integer}\n";
  s +=
      " PACEParameters: ${(signature[2] as ASN1Integer).integer} (Brainpool P256r1)\n";
  return s;
}

String formatDG13(final EfDG13 dg13) {
  var p = ASN1Parser(dg13.toBytes().sublist(4));
  var values =
      ((p.nextObject()! as ASN1Sequence).elements![2] as ASN1Set).elements!;
  var log = Logger("dg13");

  var s = "";
  for (var value in values) {
    var v = (value as ASN1Sequence).elements!;
    if (v.length <= 1) {
      continue;
    }

    var id = (v[0] as ASN1Integer).integer!.toInt() - 1;
    if (id == 12) {
      for (var i = 1; i < v.length; i++) {
        var name = (v[i]! as ASN1Sequence).elements![0];
        s += "parent $i: ${(name as ASN1UTF8String).utf8StringValue}\n";
      }
      continue;
    }

    var label_map = [
      "document id",
      "full name",
      "birthday",
      "gender",
      "nationality",
      "ethnicity",
      "belief",
      "hometown",
      "permanant address",
      "identify features",
      "document issue date",
      "document expiry date",
      "",
      "",
      "other1",
      "other2",
    ];
    var tmp = v[1];
    if (tmp is ASN1PrintableString) {
      s += "${label_map[id]}: ${(tmp as ASN1PrintableString).stringValue}\n";
      log.info("dg13 ${(tmp as ASN1PrintableString).stringValue}");
    } else if (tmp is ASN1UTF8String) {
      s += "${label_map[id]}: ${(tmp as ASN1UTF8String).utf8StringValue}\n";
      log.info("dg13 ${(tmp as ASN1UTF8String).utf8StringValue}");
    }
  }
  return s;
}

String formatDG15(final EfDG15 dg15) {
  var str = "EF.DG15:\n"
      "  AAPublicKey\n"
      "    type: ";

  final rawSubPubKey = dg15.aaPublicKey.rawSubjectPublicKey();
  if (dg15.aaPublicKey.type == AAPublicKeyType.RSA) {
    final tvSubPubKey = TLV.fromBytes(rawSubPubKey);
    var rawSeq = tvSubPubKey.value;
    if (rawSeq[0] == 0x00) {
      rawSeq = rawSeq.sublist(1);
    }

    final tvKeySeq = TLV.fromBytes(rawSeq);
    final tvModule = TLV.decode(tvKeySeq.value);
    final tvExp = TLV.decode(tvKeySeq.value.sublist(tvModule.encodedLen));

    str += "RSA\n"
        "    exponent: ${tvExp.value.hex()}\n"
        "    modulus: ${tvModule.value.hex()}";
  } else {
    str += "EC\n    SubjectPublicKey: ${rawSubPubKey.hex()}";
  }
  return str;
}

String formatProgressMsg(String message, int percentProgress) {
  final p = (percentProgress / 20).round();
  final full = "🟢 " * p;
  final empty = "⚪️ " * (5 - p);
  return message + "\n\n" + full + empty;
}

Image formatDG2(EfDG2 dg2) {
  var dg2_data = TLV.decode(dg2.toBytes()); // 75
  var template_wrapper = TLV.decode(dg2_data.value); // 7f61

  var instance_no = TLV.decode(template_wrapper.value); // 02
  var template = TLV
      .decode(template_wrapper.value.sublist(instance_no.encodedLen)); // 7f60

  var header = TLV.decode(template.value); // a1
  var biometric_data =
      TLV.decode(template.value.sublist(header.encodedLen)); // 5f2e

  var raw_data = biometric_data.value;
  var picture = raw_data.sublist(46);
  return Image.memory(picture);
}

bool verify_active_auth(EfDG15 dg15, Uint8List signature, Uint8List m2) {
  var log = Logger("auth");

  final rawSubPubKey = dg15.aaPublicKey.rawSubjectPublicKey();
  final tvSubPubKey = TLV.fromBytes(rawSubPubKey);
  var rawSeq = tvSubPubKey.value;
  if (rawSeq[0] == 0x00) {
    rawSeq = rawSeq.sublist(1);
  }

  final tvKeySeq = TLV.fromBytes(rawSeq);
  final tvModulus = TLV.decode(tvKeySeq.value);
  final tvExp = TLV.decode(tvKeySeq.value.sublist(tvModulus.encodedLen));

  final n = decodeBigInt(tvModulus.value);
  log.info("n $n");

  final signature_raw = decodeBigIntWithSign(1, signature);
  log.info("s $signature_raw");
  final message_decrypted = signature_raw.modPow(BigInt.from(65537), n);
  log.info("msg $message_decrypted");
  final message_raw = encodeBigInt(message_decrypted);

  final t = message_raw[message_raw.length - 1] == 0xbc ? 1 : 2;
  final hashlen;
  if (t == 1) {
    hashlen = 160;
  } else {
    switch (message_raw[message_raw.length - 2]) {
      case 0x34:
        hashlen = 256;
        break;
      case 0x35:
        hashlen = 512;
        break;
      case 0x36:
        hashlen = 384;
        break;
      case 0x38:
        hashlen = 224;
        break;
      default:
        hashlen = 0;
        break;
    }
  }

  final k = n.bitLength;
  final m1_len = ((k - hashlen - 8 * t - 4) - 4);

  // bits 01 default bit
  // bit 1 partial recovery
  // bit 1 end of padding
  // k - hash_len - m1_len - 8t - 4 bits padding
  final pad = (2 + 1 + 1 + k - hashlen - m1_len - 8 * t - 4);

  final m1_len_bytes = m1_len ~/ 8;
  final pad_bytes = pad ~/ 8;
  final hash_len_bytes = hashlen ~/ 8;

  final message_end = pad_bytes + m1_len_bytes;
  final hash_end = message_end + hash_len_bytes;

  final m1 = message_raw.sublist(pad_bytes, message_end);
  final hash = message_raw.sublist(message_end, hash_end.toInt());

  log.info("m1 $m1");
  log.info("hash $hash");

  return listEquals(hash, sha1.convert([...m1, ...m2]).bytes);
}

bool verify_sod(MrtdData mrtd) {
  var log = Logger("sod");
  var verify_result = true;

  final sod = mrtd.sod!;
  final dg1 = mrtd.dg1!;
  final dg2 = mrtd.dg2!;
  // final dg3 = mrtd.dg3!;
  final dg13 = mrtd.dg13!;
  final dg14 = mrtd.dg14!;
  final dg15 = mrtd.dg15!;

  log.info("DG1 raw ${dg1.toBytes().length}");
  log.info("DG2 raw ${dg2.toBytes().length}");
  log.info("DG13 raw ${dg13.toBytes().length}");
  log.info("DG14 raw ${dg14.toBytes().length}");
  log.info("DG15 raw ${dg15.toBytes().length}");
  log.info("SOD raw ${mrtd.sod!.toBytes().length}");
  log.info("COM raw ${mrtd.com!.toBytes().length}");

  // check hash digests
  final dg1_digest = sha256.convert(dg1.toBytes());
  final dg2_digest = sha256.convert(dg2.toBytes());
  // final dg3_digest = sha256.convert(dg3.toBytes());
  final dg13_digest = sha256.convert(dg13.toBytes());
  final dg14_digest = sha256.convert(dg14.toBytes());
  final dg15_digest = sha256.convert(dg15.toBytes());

  log.info("sha256(dg1)=$dg1_digest");
  log.info("sha256(dg2)=$dg2_digest");
  // log.info("sha256(dg3)=$dg3_digest");
  log.info("sha256(dg13)=$dg13_digest");
  log.info("sha256(dg14)=$dg14_digest");
  log.info("sha256(dg15)=$dg15_digest");

  final datagroup_digests = {
    1: dg1_digest,
    2: dg2_digest,
    13: dg13_digest,
    14: dg14_digest,
    15: dg15_digest,
  };

  log.info("digest map $datagroup_digests");

  final sod_pkcs7_raw = sod.toBytes().sublist(4);
  final sod_pkcs7 = Pkcs7(ASN1Sequence.fromBytes(sod_pkcs7_raw));
  // skip 4 bytes implicit + 4 bytes octetstring
  final encapsulatedContent = sod_pkcs7.encapsulatedContent!.sublist(8);
  final dg_digest = sha256.convert(encapsulatedContent);
  log.info("sha256(dg)=$dg_digest");

  final digest_list =
      ASN1Sequence.fromBytes(encapsulatedContent).elements![2] as ASN1Sequence;
  for (var digest_item in digest_list.elements!) {
    final item = (digest_item as ASN1Sequence).elements!;
    final dg_number = (item[0] as ASN1Integer).integer!.toInt();
    final dg_digest = item[1].valueBytes!;

    // fingerprint date can't be fetched
    if (dg_number == 3) {
      continue;
    }

    final calculated_digest = datagroup_digests[dg_number]!;
    final matched = listEquals(calculated_digest.bytes, dg_digest);
    verify_result &= matched;
  }

  final signer = sod_pkcs7.signerInfo.first;
  final signer_asn1 = signer.asn1;
  final message = signer_asn1.elements![3];
  final sign_message_body = message.valueBytes!;
  final sign_message = Uint8List.fromList(
      [0x31, message.valueByteLength!, ...sign_message_body]);

  // check if message['message digest'] == dg_digest
  // lazy decode so just check if atleast 1 field content is equal
  final message_decoded = ASN1Set.fromBytes(sign_message);
  var is_digest_correct = false;
  for (var item in message_decoded.elements!) {
    var wrapper = item as ASN1Sequence;
    var nested_item = wrapper.elements![1] as ASN1Set;
    var value = nested_item.valueBytes!.sublist(2); // skip 2 bytes tag,length
    is_digest_correct |= listEquals(value, dg_digest.bytes);
  }
  verify_result &= is_digest_correct;
  log.info("digest correct? $is_digest_correct");

  final sign_digest = sha256.convert(sign_message);
  final sign_digest_number = decodeBigInt(sign_digest.bytes);
  log.info("sha256(sign message)=$sign_digest");

  final signature_raw = ASN1Sequence.fromBytes(signer.signature);
  final r_raw = signature_raw.elements![0] as ASN1Integer;
  final s_raw = signature_raw.elements![1] as ASN1Integer;

  final r = r_raw.integer;
  final s = s_raw.integer;
  log.info("signature $r $s");

  final certificate = sod_pkcs7.certificates.first;
  final pubkey_raw = certificate.publicKeyBytes.sublist(1); // skip 04

  final pub_x = decodeBigInt(pubkey_raw.sublist(0, pubkey_raw.length ~/ 2));
  final pub_y = decodeBigInt(pubkey_raw.sublist(pubkey_raw.length ~/ 2));
  log.info("cert pubkey $pub_x $pub_y");

  log.info("cert signature ${certificate.signatureValue}");
  final cert_signature_raw =
      ASN1Sequence.fromBytes(certificate.signatureValue.sublist(1));
  final cert_r_raw = cert_signature_raw.elements![0] as ASN1Integer;
  final cert_s_raw = cert_signature_raw.elements![1] as ASN1Integer;
  final cert_r = cert_r_raw.integer;
  final cert_s = cert_s_raw.integer;
  log.info("cert signature $cert_r $cert_s");

  final tbs_cert_data = certificate.asn1.elements![0].encodedBytes;
  final cert_digest = sha384.convert(tbs_cert_data!);
  final cert_digest_number = decodeBigInt(cert_digest.bytes);
  log.info("cert digest $cert_digest");

  // verify signed data with brainpoolP384r1
  // verify_ecdsa(sign_digest_number, (r, s), (pub_x, pub_y));

  final cert_pubkey = ecc.PublicKey(brainpoolP384r1, pub_x, pub_y);
  final verified_signeddata = ecdsa.verify(
      cert_pubkey, sign_digest.bytes, ecdsa.Signature.fromRS(r!, s!));

  // verify certificate with found pubkey

  final ca_pub_x = BigInt.parse(
      "5705586746797687392276527904990313555022905475611271258729414636068323857880334000957361424951661974682935706611888");
  final ca_pub_y = BigInt.parse(
      "7821704373206592378644977211567592118672246135776362491204878202396889655625917188376232816427307041739256606332695");
  final ca_pubkey = ecc.PublicKey(nist384r1, ca_pub_x, ca_pub_y);
  final verified_cert = ecdsa.verify(
      ca_pubkey, cert_digest.bytes, ecdsa.Signature.fromRS(cert_r!, cert_s!));

  log.info("signed data verified? $verified_signeddata");
  log.info("certificate verified? $verified_cert");

  verify_result &= verified_signeddata;
  verify_result &= verified_cert;
  return verify_result;
}
