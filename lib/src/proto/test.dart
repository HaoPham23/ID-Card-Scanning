import 'package:convert/convert.dart';
import 'package:elliptic/elliptic.dart';
import 'package:elliptic/ecdh.dart';
import 'dart:convert';

void main() {
  // use elliptic curves
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
  // var priv = ec.generatePrivateKey();
  // var pub = priv.publicKey;
  // print('privateKey: 0x$priv');
  // print('publicKey: 0x$pub');

  // use ecdh
  final mappingKey = PrivateKey.fromHex(
      ec, '7F4EF07B9EA82FD78AD689B38D0BC78CF21F249D953BC46F4C6E19259C010F99');
  final piccMappingEncodedPrivateKey = PrivateKey.fromHex(
      ec, '498FF49756F2DC1587840041839A85982BE7761D14715FB091EFA7BCE9058560');
  final piccMappingEncodedPublicKey = piccMappingEncodedPrivateKey.publicKey;
  final H = ec.scalarMul(piccMappingEncodedPublicKey, mappingKey.bytes);
  final nonce = hex.decode('3F00C4D39D153F2B2A214A078D899B22');
  final G_hat = ec.add(ec.scalarBaseMul(nonce), H);
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
  final new_piccPrivKey = PrivateKey.fromHex(ephemeralParams,
      'A73FB703AC1436A18E0CFA5ABB3F7BEC7A070E7A6788486BEE230C4A22762595');
  final new_piccPubKey = new_piccPrivKey.publicKey;
  print(new_piccPubKey.X.toRadixString(16));
  print(new_piccPubKey.Y.toRadixString(16));
}
