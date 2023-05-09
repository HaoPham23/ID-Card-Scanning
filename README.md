## Dart library for ICAO Machine Readable Travel Documents standard - Biometric Passport
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![test](https://github.com/ZeroPass/dmrtd/actions/workflows/test.yml/badge.svg?branch=master)](https://github.com/ZeroPass/dmrtd/actions/workflows/test.yml)

DMRTD is dart implementation of [ICAO 9303](https://www.icao.int/publications/pages/publication.aspx?docnum=9303) standard.
Library provide APIs to send commands to and read data from MRTD.

## Key features
* BAC session key establishment
* PACE session key establishment
* Reading all elementary files from MRTD e.g. EF.SOD, EF.DG1, EF.DG15 ...  
  *Note: most of files can't be fully parsed yet*
* Executing `Active Authentication` on MRTD
* Basic implementation of ICC ISO7816-4 smart card standard
* Implementation of ISO 9797 Algorithm 3 MAC and padding scheme

## Library structure
dmrtd.dart - public passport API  
extensions.dart - exposes library's dart [extensions](lib/src/extension)  
internal.dart - exposes internal components of the library such as MrtdApi, ICC and crypto

## Usage
1. Connect to a mobile phone via USB cable
1. Go to example folder: `cd example`
2. Install the app to your phone by: `flutter run`

## Other documentation
* [ICAO 9303 Specifications Common to all MRTDs](https://www.icao.int/publications/Documents/9303_p3_cons_en.pdf)
* [ICAO 9303 Specifications for Machine Readable Passports (MRPs) and other TD3 Size MRTDs](https://www.icao.int/publications/Documents/9303_p4_cons_en.pdf)
* [ICAO 9303 eMRTD logical data structure](https://www.icao.int/publications/Documents/9303_p10_cons_en.pdf)
* [ICAO 9303 Security mechanisms for MRTDs](https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf)
