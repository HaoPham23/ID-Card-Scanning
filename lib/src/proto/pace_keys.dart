//  Created by Hao Pham, 27/04/2023
import 'dart:typed_data';
import 'package:crypto/crypto.dart';

import '../crypto/kdf.dart';
import '../lds/mrz.dart';
import '../extension/datetime_apis.dart';
import '../extension/string_apis.dart';

/// Class defines PACE Keys as specified in section 9.7.3 of doc ICAO 9303 p11
/// which are used to establish secure messaging session via PACE protocol.
class PACEKeys {
  late String _mrtdNum;
  late String _dob;
  late String _doe;

  /// Constructs [PACEKeys] using passport number [mrtdNumber],
  /// passport owner's [dateOfBirth] and passport [dateOfExpiry].
  PACEKeys(String mrtdNumber, DateTime dateOfBirth, DateTime dateOfExpiry) {
    _mrtdNum = mrtdNumber;
    _dob = dateOfBirth.formatYYMMDD();
    _doe = dateOfExpiry.formatYYMMDD();
  }

  /// Constructs [PACEKeys] from [mrz].
  factory PACEKeys.fromMRZ(MRZ mrz) {
    return PACEKeys(mrz.documentNumber, mrz.dateOfBirth, mrz.dateOfExpiry);
  }

  /// Returns encryption key [Kenc] to be used in PACE protocol. (K_pi)
  Uint8List get encKey {
    return DeriveKey.aes128(keySeed, paceMode: true);
  }

  /// Returns Kseed as specified in Section 9.7.3
  /// to the Part 11 of doc ICAO 9303 p11
  Uint8List get keySeed {
    final paddedMrtdNum = _mrtdNum.padRight(9, '<');
    final cdn = MRZ.calculateCheckDigit(paddedMrtdNum);
    final cdb = MRZ.calculateCheckDigit(_dob);
    final cde = MRZ.calculateCheckDigit(_doe);
    final hash = sha1.convert("$paddedMrtdNum$cdn$_dob$cdb$_doe$cde".codeUnits);
    final kSeed = hash.bytes as Uint8List?;
    return kSeed!;
  }

  /// Returns passport number used for calculating key seed.
  String get mrtdNumber => _mrtdNum;

  /// Returns passport owner's date of birth used for calculating key seed.
  DateTime get dateOfBirth => _dob.parseDateYYMMDD();

  /// Returns passport date of expiry used for calculating key seed.
  DateTime get dateOfExpiry => _doe.parseDateYYMMDD();
}
