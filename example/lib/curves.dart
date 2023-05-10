import 'package:elliptic/elliptic.dart';

late EllipticCurve brainpoolP384r1 = EllipticCurve(
  'brainpoolP384r1',
  384, // bitSize
  BigInt.parse(
      '8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53',
      radix: 16), // p
  BigInt.parse(
      '7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826',
      radix: 16), //a
  BigInt.parse(
      '4a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696fa504c11',
      radix: 16), //b
  BigInt.zero, //S
  AffinePoint.fromXY(
    BigInt.parse(
        '1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e',
        radix: 16),
    BigInt.parse(
        '8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c5315',
        radix: 16),
  ), // G
  BigInt.parse(
      '8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565',
      radix: 16), //N
  01, // h
);

late EllipticCurve nist384r1 = EllipticCurve(
  'nist384r1',
  384, // bitSize
  BigInt.parse(
      'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff',
      radix: 16), // p
  BigInt.parse(
      'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc',
      radix: 16), //a
  BigInt.parse(
      'b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef',
      radix: 16), //b
  BigInt.zero, //S
  AffinePoint.fromXY(
    BigInt.parse(
        'aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7',
        radix: 16),
    BigInt.parse(
        '3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f',
        radix: 16),
  ), // G
  BigInt.parse(
      'ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973',
      radix: 16), //N
  01, // h
);
