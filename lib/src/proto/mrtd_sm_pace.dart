// Created by Hao Pham, 04/05/2023

import 'dart:typed_data';
import 'package:collection/collection.dart';
import 'package:dmrtd/extensions.dart';
import 'package:logging/logging.dart';
import 'package:meta/meta.dart';
import 'package:encrypt/encrypt.dart';
import 'ssc.dart';
import 'iso7816/command_apdu.dart';
import 'iso7816/iso7816.dart';
import 'iso7816/response_apdu.dart';
import 'iso7816/sm.dart';
import '../lds/tlv.dart';
import 'pace_smcipher.dart';

const blockSize = 16;

/// Class defines secure messaging protocol as specified in ICAO 9303 p11.
class MrtdSMPACE extends SecureMessaging {
  final _log = Logger("mrtd.sm");
  final Uint8List encKey;
  final Uint8List macKey;
  static final bool Function(List<dynamic>, List<dynamic>) _eq =
      const ListEquality().equals;
  final PACE_SMCipher paceCipher;
  SSC _ssc;
  set ssc(final SSC ssc) => _ssc = ssc;

  MrtdSMPACE(this.paceCipher, this._ssc, this.encKey, this.macKey)
      : super(paceCipher);

  @override
  CommandAPDU protect(final CommandAPDU cmd) {
    _log.debug("Protecting APDU");
    _log.verbose("  header=${cmd.rawHeader().hex()}");
    _log.sdVerbose("  data=${cmd.data?.hex()}");
    _log.verbose("  Le=${cmd.ne}");

    final pcmd = maskCmd(cmd);
    _log.verbose("masked APDU header=${pcmd.rawHeader().hex()}");

    final dataDO = generateDataDO(pcmd);
    _log.verbose("Generated data DO=${dataDO.hex()}");

    final do97 = SecureMessaging.do97(pcmd.ne);
    _log.verbose("Generated data DO97=${do97.hex()}");

    final M = generateM(cmd: pcmd, dataDO: dataDO, do97: do97);
    _log.verbose("Generated M=${M.hex()}");

    final N = generateN(M: M);
    _log.verbose("Generated N=${N.hex()}");
    _log.verbose("  used SSC=${_ssc.toBytes().hex()}");

    final CC = paceCipher.mac(N);
    final do8E = SecureMessaging.do8E(CC);
    _log.verbose("Calculated CC=${CC.hex()}");
    _log.verbose("Generated data DO8E=${do8E.hex()}");

    pcmd.data = Uint8List.fromList(dataDO + do97 + do8E);
    pcmd.ne = 256; // serialized as 0x00
    return pcmd;
  }

  @override
  ResponseAPDU unprotect(ResponseAPDU rapdu) {
    if (rapdu.status == StatusWord.smDataMissing ||
        rapdu.status == StatusWord.smDataInvalid ||
        (rapdu.data?.isEmpty ?? true)) {
      //RAPDU should have data
      return rapdu;
    }

    _log.debug("Unprotecting RAPDU: $rapdu");
    final tvDataDO = parseDataDOFromRAPDU(rapdu);
    final do99 = parseDO99FromRAPDU(rapdu, (tvDataDO?.encodedLen ?? 0));
    final do8EStart = (tvDataDO?.encodedLen ?? 0) + do99.encodedLen;
    final do8E = parseDO8EFromRAPDU(rapdu, do8EStart);
    final K = generateK(data: rapdu.data!.sublist(0, do8EStart));
    final CC = paceCipher.mac(K);

    _log.verbose("Generated K=${K.hex()}");
    _log.verbose("  used SSC=${_ssc.toBytes().hex()}");
    _log.verbose("APDU CC=${do8E.value.hex()}");
    _log.verbose("Calculated CC=${CC.hex()}");
    if (!_eq(CC, do8E.value)) {
      throw SMError("Invalid MAC of response APDU");
    }

    final data = decryptDataDO(tvDataDO);
    return ResponseAPDU(StatusWord.fromBytes(do99.value), data);
  }

  @visibleForTesting
  Uint8List? decryptDataDO(final DecodedTV? dtv) {
    _log.verbose("Decrypting data=${dtv?.value.hex()}");
    if (dtv == null || dtv.value.isEmpty) {
      return null;
    }

    final tag = dtv.tag.value;
    if (tag != SecureMessaging.tagDO85 && tag != SecureMessaging.tagDO87) {
      throw SMError(
          "Can't decrypt invalid data DO with tag=$tag value=${dtv.value.hex()}");
    }

    final bool isDO87 = tag == SecureMessaging.tagDO87;
    final bool padded =
        !isDO87 || dtv.value[0] == 0x01; // Defined in ISO/IEC 7816-4 part 5
    final iv = genIV();
    var data = paceCipher.decrypt(dtv.value.sublist(isDO87 ? 1 : 0), iv);
    _log.sdVerbose("Decrypted data=${data.hex()}");
    _log.sdVerbose("Decrypted data is padded: $padded");
    if (padded) {
      data = unpad(data);
      _log.sdVerbose("Unpadded data=${data.hex()}");
    }
    return data;
  }

  @visibleForTesting
  Uint8List generateDataDO(final CommandAPDU cmd) {
    _ssc.increment();
    var dataDO = Uint8List(0);
    if (cmd.data != null && cmd.data!.isNotEmpty) {
      final iv = genIV();
      final edata = paceCipher.encrypt(pad(cmd.data!), iv);
      if (cmd.ins == ISO7816_INS.READ_BINARY_EXT) {
        dataDO = SecureMessaging.do85(edata);
      } else {
        dataDO = SecureMessaging.do87(edata, dataIsPadded: true);
      }
    }
    return dataDO;
  }

  @visibleForTesting
  Uint8List generateK({required final Uint8List data}) {
    _ssc.increment();
    final paddedSSC = paddingSSC();
    final upK = Uint8List.fromList(paddedSSC + data);
    return pad(upK);
  }

  @visibleForTesting
  Uint8List generateM(
      {required final CommandAPDU cmd,
      required final Uint8List dataDO,
      required final Uint8List do97}) {
    final rawHeader = pad(cmd.rawHeader());
    return Uint8List.fromList(rawHeader + dataDO + do97);
  }

  @visibleForTesting
  Uint8List generateN({required final Uint8List M}) {
    final paddedSSC = paddingSSC();
    final upN = Uint8List.fromList(paddedSSC + M);
    return pad(upN);
  }

  @visibleForTesting
  CommandAPDU maskCmd(final CommandAPDU cmd) {
    CommandAPDU mcmd = cmd;
    mcmd.cla |= ISO7816_CLA.SM_HEADER_AUTHN;
    return mcmd;
  }

  /// Returns decoded data from DO85 or DO87 if they are present in [rapdu].
  @visibleForTesting
  DecodedTV? parseDataDOFromRAPDU(final ResponseAPDU rapdu) {
    if (rapdu.data == null ||
        rapdu.data!.isEmpty ||
        (rapdu.data![0] != SecureMessaging.tagDO85 &&
            rapdu.data![0] != SecureMessaging.tagDO87)) {
      return null;
    }

    final DO = TLV.decode(rapdu.data!);
    return DO;
  }

  @visibleForTesting
  DecodedTV parseDO8EFromRAPDU(final ResponseAPDU rapdu, int offset) {
    if (rapdu.data == null ||
        rapdu.data!.isEmpty ||
        rapdu.data![offset] != SecureMessaging.tagDO8E) {
      throw SMError("Missing DO'8E' in response APDU or invalid offset");
    }
    return TLV.decode(rapdu.data!.sublist(offset));
  }

  @visibleForTesting
  DecodedTV parseDO99FromRAPDU(final ResponseAPDU rapdu, int offset) {
    if (rapdu.data == null ||
        rapdu.data!.isEmpty ||
        rapdu.data![offset] != SecureMessaging.tagDO99) {
      throw SMError("Missing DO'99' in response APDU or invalid offset");
    }
    return TLV.decode(rapdu.data!.sublist(offset));
  }

  Uint8List pad(Uint8List data) {
    final Uint8List padBlock =
        Uint8List.fromList([0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    final padSize = blockSize - (data.length % blockSize);
    return Uint8List.fromList(data + padBlock.sublist(0, padSize));
  }

  Uint8List unpad(Uint8List data) {
    var i = data.length - 1;
    while (data[i] == 0x00) {
      i -= 1;
    }
    if (data[i] == 0x80) {
      return data.sublist(0, i);
    }
    return data;
  }

  Uint8List paddingSSC() {
    return Uint8List.fromList(Uint8List(8) + _ssc.toBytes());
  }

  IV genIV() {
    final ivEncrypter =
        Encrypter(AES(Key(encKey), mode: AESMode.ecb, padding: null));
    final paddedSSC = paddingSSC();
    final nullIV = IV(Uint8List(16));
    final iv = IV(ivEncrypter.encryptBytes(paddedSSC, iv: nullIV).bytes);
    return iv;
  }
}
