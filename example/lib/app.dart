import 'dart:io';
import 'dart:convert';
import 'dart:core';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/cupertino.dart';
import 'package:flutter_platform_widgets/flutter_platform_widgets.dart';
import 'package:logging/logging.dart';

import 'package:collection/collection.dart';

// import 'package:flutter_scalable_ocr/flutter_scalable_ocr.dart';
import 'package:image_picker/image_picker.dart';
import 'package:google_mlkit_text_recognition/google_mlkit_text_recognition.dart';

import 'package:mrtdeg/mrtd.dart';
import 'package:mrtdeg/scannfc.dart';

class App extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return PlatformApp(
        localizationsDelegates: [
          DefaultMaterialLocalizations.delegate,
          DefaultCupertinoLocalizations.delegate,
          DefaultWidgetsLocalizations.delegate,
        ],
        material: (_, __) => MaterialAppData(),
        cupertino: (_, __) => CupertinoAppData(),
        home: HomePage());
  }
}

bool verify_hash_digit(int hash, String content) {
  int mapvalue(v) {
    if (v < 59 && v > 48) {
      return v - 48;
    } else if (v < 90 && v > 65) {
      return v - 65 + 10;
    } else {
      return 0;
    }
  }

  final calculated_hash =
      content.codeUnits.foldIndexed(0, (int idx, int acc, int ele) {
    final weights = [7, 3, 1];
    final weight = weights[idx % weights.length];
    return acc + weight * mapvalue(ele);
  });

  return calculated_hash % 10 == hash;
}

Mrz? mrz_parse(String line1, String line2, String line3) {
  final log = Logger("mrzparse");
  if (!line1.startsWith("IDVNM")) {
    return null;
  }

  // IDVNM <9digit> <checkdigit> <optional>
  // we can assume all are numbers and this replacement doesn't break the assumption
  line1 = line1.replaceAll('O', '0');
  final m1 = RegExp(r"(\d{9})(\d)").firstMatch(line1.substring(5, 5 + 10));

  // birthday <checkdigit>
  // same as above, letters are M F VNM only
  line2 = line2.replaceAll('O', '0');

  final m2 =
      RegExp(r"(\d{2})(\d{2})(\d{2})(\d)").firstMatch(line2.substring(0, 7));

  // expirydate <checkdigit>
  final m3 =
      RegExp(r"(\d{2})(\d{2})(\d{2})(\d)").firstMatch(line2.substring(8, 15));

  if (m1 == null || m2 == null || m3 == null) {
    return null;
  }

  final id = m1.group(1)!;
  final id_hash = int.parse(m1.group(2)!);

  final birth_year = m2.group(1)!;
  final birth_month = m2.group(2)!;
  final birth_date = m2.group(3)!;
  final birth_hash = int.parse(m2.group(4)!);

  final expiry_year = m3.group(1)!;
  final expiry_month = m3.group(2)!;
  final expiry_date = m3.group(3)!;
  final expiry_hash = int.parse(m3.group(4)!);

  final v1 = verify_hash_digit(id_hash, id);
  final v2 = verify_hash_digit(birth_hash, line2.substring(0, 6));
  final v3 = verify_hash_digit(expiry_hash, line2.substring(8, 14));

  if (!(v1 && v2 && v3)) {
    return null;
  }

  final now = new DateTime.now();
  var birth_year_number = int.parse(birth_year)!;
  if (birth_year_number < now.year) {
    birth_year_number += 2000;
  } else {
    birth_year_number += 1900;
  }
  return Mrz(
      id,
      DateTime(
          birth_year_number, int.parse(birth_month)!, int.parse(birth_date)!),
      DateTime(2000 + int.parse(expiry_year)!, int.parse(expiry_month)!,
          int.parse(expiry_date)!));
}

class HomePageScan extends StatefulWidget {
  @override
  State<HomePageScan> createState() => _HomePageScanState();
}

class HomePageTypein extends StatefulWidget {
  @override
  State<HomePageTypein> createState() => _HomePageTypeinState();
}

class _HomePageScanState extends State<HomePageScan> {
  final log = Logger("homepage");
  List<XFile>? _imageFileList;

  final TextRecognizer _textRecognizer =
      TextRecognizer(script: TextRecognitionScript.latin);

  void _setImageFileListFromFile(XFile? value) {
    _imageFileList = value == null ? null : <XFile>[value];
  }

  dynamic _pickImageError;

  String? _retrieveDataError;

  final ImagePicker _picker = ImagePicker();
  final TextEditingController maxWidthController = TextEditingController();
  final TextEditingController maxHeightController = TextEditingController();
  final TextEditingController qualityController = TextEditingController();

  Future<void> _onImageButtonPressed(ImageSource source,
      {BuildContext? context, bool isMultiImage = false}) async {
    try {
      final XFile? pickedFile = await _picker.pickImage(
        source: source,
        maxWidth: null,
        maxHeight: null,
        imageQuality: null,
      );
      setState(() {
        _setImageFileListFromFile(pickedFile);
      });

      final recognizedText = await _textRecognizer
          .processImage(InputImage.fromFilePath(pickedFile!.path));

      LineSplitter ls = new LineSplitter();
      List<String> lines = ls.convert(recognizedText.text);
      var start_line = 0;
      for (var line in lines) {
        if (line.startsWith("IDVNM")) {
          break;
        }
        start_line += 1;
      }

      if (lines.length <= start_line + 2) {}
      final a = lines[start_line].replaceAll(" ", "");
      final b = lines[start_line + 1].replaceAll(" ", "");
      final c = lines[start_line + 2].replaceAll(" ", "");

      if (!(a.length == 30 && b.length == 30 && c.length == 30)) {
        return;
      }

      log.info("$a, $b, $c");

      // this is pain
      final mrz = mrz_parse(a, b, c);
      if (mrz == null) {
        return;
      }

      log.info("mrz ${mrz.toString()}");

      Navigator.push(
        context!,
        MaterialPageRoute(builder: (context) => ScanIdCard(mrz: mrz!)),
      );
    } catch (e) {
      setState(() {
        _pickImageError = e;
      });
    }
    /* await _displayPickImageDialog(context!,
        (double? maxWidth, double? maxHeight, int? quality) async {
      try {
        final XFile? pickedFile = await _picker.pickImage(
          source: source,
          maxWidth: maxWidth,
          maxHeight: maxHeight,
          imageQuality: quality,
        );
        setState(() {
          _setImageFileListFromFile(pickedFile);
        });
      } catch (e) {
        setState(() {
          _pickImageError = e;
        });
      }
    }); */
  }

  @override
  void deactivate() {
    super.deactivate();
  }

  @override
  void dispose() {
    maxWidthController.dispose();
    maxHeightController.dispose();
    qualityController.dispose();
    super.dispose();
  }

  Widget _previewImages() {
    final Text? retrieveError = _getRetrieveErrorWidget();
    if (retrieveError != null) {
      return retrieveError;
    }
    if (_imageFileList != null) {
      return Semantics(
        label: 'image_picker_example_picked_images',
        child: ListView.builder(
          key: UniqueKey(),
          itemBuilder: (BuildContext context, int index) {
            // Why network for web?
            // See https://pub.dev/packages/image_picker#getting-ready-for-the-web-platform
            return Semantics(
              label: 'image_picker_example_picked_image',
              child: Image.file(File(_imageFileList![index].path)),
            );
          },
          itemCount: _imageFileList!.length,
        ),
      );
    } else if (_pickImageError != null) {
      return Text(
        'Pick image error: $_pickImageError',
        textAlign: TextAlign.center,
      );
    } else {
      return const Text(
        'You have not yet picked an image.',
        textAlign: TextAlign.center,
      );
    }
  }

  Widget _handlePreview() {
    return _previewImages();
  }

  Future<void> retrieveLostData() async {
    final LostDataResponse response = await _picker.retrieveLostData();
    if (response.isEmpty) {
      return;
    }
    if (response.file != null) {
      setState(() {
        if (response.files == null) {
          _setImageFileListFromFile(response.file);
        } else {
          _imageFileList = response.files;
        }
      });
    } else {
      _retrieveDataError = response.exception!.code;
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text("BShield ID card verifier"),
      ),
      body: Center(
        child: defaultTargetPlatform == TargetPlatform.android
            ? FutureBuilder<void>(
                future: retrieveLostData(),
                builder: (BuildContext context, AsyncSnapshot<void> snapshot) {
                  switch (snapshot.connectionState) {
                    case ConnectionState.none:
                    case ConnectionState.waiting:
                      return const Text(
                        'You have not yet picked an image.',
                        textAlign: TextAlign.center,
                      );
                    case ConnectionState.done:
                      return _handlePreview();
                    case ConnectionState.active:
                      if (snapshot.hasError) {
                        return Text(
                          'Pick image/video error: ${snapshot.error}}',
                          textAlign: TextAlign.center,
                        );
                      } else {
                        return const Text(
                          'You have not yet picked an image.',
                          textAlign: TextAlign.center,
                        );
                      }
                  }
                },
              )
            : _handlePreview(),
      ),
      floatingActionButton: Column(
        mainAxisAlignment: MainAxisAlignment.end,
        children: <Widget>[
          Semantics(
            label: 'image_pick',
            child: FloatingActionButton(
              onPressed: () {
                _onImageButtonPressed(ImageSource.gallery, context: context);
              },
              heroTag: 'image0',
              tooltip: 'Pick Image from gallery',
              child: const Icon(Icons.photo),
            ),
          ),
          Padding(
            padding: const EdgeInsets.only(top: 16.0),
            child: FloatingActionButton(
              onPressed: () {
                _onImageButtonPressed(ImageSource.camera, context: context);
              },
              heroTag: 'image2',
              tooltip: 'Take a Photo',
              child: const Icon(Icons.camera_alt),
            ),
          ),
        ],
      ),
    );
  }

  // @override
  // Widget build1(BuildContext context) {
  //   return Scaffold(
  //       appBar: AppBar(
  //         title: Text("Hao ID card verifier"),
  //       ),
  //       body: Center(
  //           child: ScanIdCard(
  //               mrz: Mrz("203011953", DateTime(2003, 5, 16),
  //                   DateTime(2028, 5, 16)))));
  // }

  Text? _getRetrieveErrorWidget() {
    if (_retrieveDataError != null) {
      final Text result = Text(_retrieveDataError!);
      _retrieveDataError = null;
      return result;
    }
    return null;
  }

  Future<void> _displayPickImageDialog(
      BuildContext context, OnPickImageCallback onPick) async {
    return showDialog(
        context: context,
        builder: (BuildContext context) {
          return AlertDialog(
            title: const Text('Add optional parameters'),
            content: Column(
              children: <Widget>[
                TextField(
                  controller: maxWidthController,
                  keyboardType:
                      const TextInputType.numberWithOptions(decimal: true),
                  decoration: const InputDecoration(
                      hintText: 'Enter maxWidth if desired'),
                ),
                TextField(
                  controller: maxHeightController,
                  keyboardType:
                      const TextInputType.numberWithOptions(decimal: true),
                  decoration: const InputDecoration(
                      hintText: 'Enter maxHeight if desired'),
                ),
                TextField(
                  controller: qualityController,
                  keyboardType: TextInputType.number,
                  decoration: const InputDecoration(
                      hintText: 'Enter quality if desired'),
                ),
              ],
            ),
            actions: <Widget>[
              TextButton(
                child: const Text('CANCEL'),
                onPressed: () {
                  Navigator.of(context).pop();
                },
              ),
              TextButton(
                  child: const Text('PICK'),
                  onPressed: () {
                    final double? width = maxWidthController.text.isNotEmpty
                        ? double.parse(maxWidthController.text)
                        : null;
                    final double? height = maxHeightController.text.isNotEmpty
                        ? double.parse(maxHeightController.text)
                        : null;
                    final int? quality = qualityController.text.isNotEmpty
                        ? int.parse(qualityController.text)
                        : null;
                    onPick(width, height, quality);
                    Navigator.of(context).pop();
                  }),
            ],
          );
        });
  }
}

class _HomePageTypeinState extends State<HomePageTypein> {
  final log = Logger("homepage");

  final TextEditingController maxWidthController = TextEditingController();
  final TextEditingController maxHeightController = TextEditingController();
  final TextEditingController qualityController = TextEditingController();

  @override
  void deactivate() {
    super.deactivate();
  }

  @override
  void dispose() {
    maxWidthController.dispose();
    maxHeightController.dispose();
    qualityController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final TextEditingController controller1 =
        TextEditingController(text: "083203011953");
    final TextEditingController controller2 =
        TextEditingController(text: "16052003");
    final TextEditingController controller3 =
        TextEditingController(text: "16052028");
    return Scaffold(
        appBar: AppBar(
          title: Text("BShield ID card verifier"),
        ),
        body: Padding(
          padding: EdgeInsets.all(15),
          child: Column(
            children: <Widget>[
              TextField(
                keyboardType: TextInputType.number,
                controller: controller1,
                decoration: InputDecoration(
                  hintText: 'ID Numbers',
                ),
              ),
              TextField(
                keyboardType: TextInputType.number,
                controller: controller2,
                decoration: InputDecoration(
                  hintText: 'Date of Birth (ddmmyyyy)',
                ),
              ),
              TextField(
                keyboardType: TextInputType.number,
                controller: controller3,
                decoration: InputDecoration(
                  hintText: 'Date of Expiry (ddmmyyyy)',
                ),
              ),
              SizedBox(height: 16.0),
              ElevatedButton(
                style: ElevatedButton.styleFrom(
                  backgroundColor: Colors.green,
                  foregroundColor: Colors.white,
                  shadowColor: Colors.greenAccent,
                  elevation: 3,
                  shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(32.0)),
                  minimumSize: Size(100, 40), //////// HERE
                ),
                onPressed: () {
                  _handleSubmitted(
                      controller1.text, controller2.text, controller3.text);
                },
                child: Text('Go!'),
              )
            ],
          ),
        ));
  }

  void _handleSubmitted(String id, String birthday, String exday) {
    String shortenId = id.substring(id.length - 9);
    print(shortenId);
    int birthdayDay = int.parse(birthday.substring(0, 2));
    int birthdayMonth = int.parse(birthday.substring(2, 4));
    int birthdayYear = int.parse(birthday.substring(4));
    int expDay = int.parse(exday.substring(0, 2));
    int expMonth = int.parse(exday.substring(2, 4));
    int expYear = int.parse(exday.substring(4));
    print(birthdayDay);
    print(birthdayMonth);
    print(birthdayYear);

    print(expDay);
    print(expMonth);
    print(expYear);
    Navigator.push(
      context,
      MaterialPageRoute(
          builder: (context) => ScanIdCard(
              mrz: Mrz(
                  shortenId,
                  DateTime(birthdayYear, birthdayMonth, birthdayDay),
                  DateTime(expYear, expMonth, expDay)))),
    );
  }
}

typedef OnPickImageCallback = void Function(
    double? maxWidth, double? maxHeight, int? quality);

class HomePage extends StatefulWidget {
  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text('Scan or Type'),
      ),
      body: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          ElevatedButton(
            child: Text('Scan'),
            onPressed: () {
              Navigator.push(
                context,
                MaterialPageRoute(builder: (context) => HomePageScan()),
              );
            },
          ),
          ElevatedButton(
            child: Text('Type in'),
            onPressed: () {
              Navigator.push(
                context,
                MaterialPageRoute(builder: (context) => HomePageTypein()),
              );
            },
          ),
        ],
      ),
    );
  }
}
