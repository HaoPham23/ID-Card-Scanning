import 'package:flutter/material.dart';
import 'package:logging/logging.dart';

import 'package:mrtdeg/app.dart';
import 'package:mrtdeg/mrtd.dart';
import 'package:mrtdeg/scannfc.dart';

void main() {
  Logger.root.level = Level.ALL;
  Logger.root.onRecord.listen((record) {
    print('LOGGER: ${record.time}: ${record.message}');
  });

  runApp(App());
}
