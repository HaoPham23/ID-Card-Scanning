//  Created by Hao Pham, 27/04/2023
import 'dart:typed_data';
import 'dart:convert';
import 'package:convert/convert.dart';
import 'package:crypto/crypto.dart';
import '../crypto/kdf.dart';

/// Class defines PACE Keys as specified in section 9.7.3 of doc ICAO 9303 p11
/// which are used to establish secure messaging session via PACE protocol.
class PACEKeys {
  late String _mrtdNum;
  late String _dob;
  late String _doe;
  Uint8List? _cachedSeed;

  /// Constructs [PACEKeys] using passport number [mrtdNumber],
  /// passport owner's [dateOfBirth] and passport [dateOfExpiry].
  PACEKeys(String mrtdNumber, String dateOfBirth, String dateOfExpiry) {
    _mrtdNum = mrtdNumber;
    _dob = dateOfBirth;
    _doe = dateOfExpiry;
  }

  /// Returns encryption key [Kenc] to be used in PACE protocol. (K_pi)
  Uint8List get encKey {
    return DeriveKey.aes128(keySeed, paceMode: true);
  }

  Uint8List get keySeed {
    final hash = sha1.convert("$_mrtdNum$_dob$_doe".codeUnits);
    final kSeed = hash.bytes as Uint8List?;
    return kSeed!;
  }
}

void main() {
  final testKey = PACEKeys("T220001293", "6408125", "1010318");
  print(hex.encode(testKey.keySeed));
  print(hex.encode(testKey.encKey));
}
