import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:dmrtd/extensions.dart';
import 'package:logging/logging.dart';
import 'package:meta/meta.dart';

import '../crypto/des.dart';
import '../crypto/iso9797.dart';
import '../crypto/kdf.dart';
import '../crypto/crypto_utils.dart';
import '../types/pair.dart';

import 'iso7816/icc.dart';
import 'bac_smcipher.dart';
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
  // static final bool Function(List<dynamic>, List<dynamic>) _eq  = const ListEquality().equals;

  // Specified in section 4.4.1 of ICAO 9303 p11 doc
  static const nonceLen =  8;                        // Challenge is 8 bytes
  static const kLen     = 16;                        // Key length 16 bytes
  static const sLen     = (2 * nonceLen) + kLen;     // S length
  static const rLen     = sLen;                      // R length
  static const eLen     = sLen;                      // Encrypted cryptogram S length 32 bytes
  static const macLen   = ISO9797.macAlg3_DigestLen; // 8 bytes

}