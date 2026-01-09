// lib/main.dart (FULL REPLACE)
// Terrindo Attendance Mobile - Check In/Out + Monthly Records + Leave Request + Profile
//
// Fixes:
// ✅ Records time now shown in LOCAL timezone (device) instead of UTC
// ✅ Month picker on Records page styled black/orange (same vibe as date picker)
// ✅ NEW: Approval tab for roles: manager, general_manager, hrd (and admin)
//
// Required pubspec.yaml deps (example):
// dependencies:
//   flutter:
//     sdk: flutter
//   dio: ^5.7.0
//   cookie_jar: ^4.0.8
//   dio_cookie_manager: ^3.1.1
//   shared_preferences: ^2.3.2
//   geolocator: ^13.0.2
//   intl: ^0.19.0
//   image_picker: ^1.1.2
//
// Assets:
// flutter:
//   assets:
//     - assets/logo.png

import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:dio/dio.dart';
import 'package:cookie_jar/cookie_jar.dart';
import 'package:dio_cookie_manager/dio_cookie_manager.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:geolocator/geolocator.dart';
import 'package:intl/intl.dart';
import 'package:image_picker/image_picker.dart';

void main() => runApp(const App());

// Terrindo-ish palette (UNCHANGED)
const Color kTbrOrange = Color(0xFFF28C28);
const Color kTbrNavy = Color(0xFF0B2A4A);
const Color kTbrCard = Color(0xFF102F52);

ThemeData _appTheme() {
  return ThemeData(
    brightness: Brightness.dark,
    primaryColor: kTbrOrange,
    scaffoldBackgroundColor: kTbrNavy,
    cardColor: kTbrCard,
    appBarTheme: const AppBarTheme(
      backgroundColor: kTbrNavy,
      foregroundColor: Colors.white,
      elevation: 0,
    ),
    colorScheme: const ColorScheme.dark(
      primary: kTbrOrange,
      onPrimary: Colors.black,
      secondary: kTbrOrange,
      surface: kTbrCard,
    ),
    filledButtonTheme: FilledButtonThemeData(
      style: FilledButton.styleFrom(
        backgroundColor: kTbrOrange,
        foregroundColor: Colors.black,
        padding: const EdgeInsets.symmetric(vertical: 16),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
      ),
    ),
    outlinedButtonTheme: OutlinedButtonThemeData(
      style: OutlinedButton.styleFrom(
        padding: const EdgeInsets.symmetric(vertical: 14),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
        side: BorderSide(color: Colors.white.withOpacity(0.25)),
        foregroundColor: Colors.white,
      ),
    ),
    inputDecorationTheme: InputDecorationTheme(
      filled: true,
      fillColor: Colors.white.withOpacity(0.06),
      border: OutlineInputBorder(borderRadius: BorderRadius.circular(14), borderSide: BorderSide.none),
      enabledBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(14), borderSide: BorderSide.none),
      focusedBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(14),
        borderSide: const BorderSide(color: kTbrOrange, width: 1.2),
      ),
      labelStyle: const TextStyle(color: Colors.white70),
      hintStyle: const TextStyle(color: Colors.white54),
    ),
  );
}

// ---------- Face Capture (Selfie -> DataURL base64) ----------
// Uses image_picker to open the native camera UI (front camera preferred).
Future<String> captureSelfieDataUrl({int quality = 85}) async {
  final picker = ImagePicker();
  final XFile? file = await picker.pickImage(
    source: ImageSource.camera,
    preferredCameraDevice: CameraDevice.front,
    imageQuality: quality, // 0-100
    maxWidth: 720,
    maxHeight: 720,
  );
  if (file == null) {
    throw Exception("Cancelled");
  }
  final Uint8List bytes = await file.readAsBytes();
  return "data:image/jpeg;base64,${base64Encode(bytes)}";
}

// ---------- API client ----------
class Api {
  final String baseUrl;
  late final Dio dio;
  final CookieJar jar = CookieJar();

  Api(this.baseUrl) {
    dio = Dio(
      BaseOptions(
        baseUrl: baseUrl,
        connectTimeout: const Duration(seconds: 12),
        receiveTimeout: const Duration(seconds: 12),
        headers: {'Content-Type': 'application/json'},
        validateStatus: (s) => s != null && s >= 200 && s < 600,
      ),
    );
    dio.interceptors.add(CookieManager(jar));
  }

  Map<String, dynamic> _json(Response res) {
    if (res.data is Map<String, dynamic>) return res.data as Map<String, dynamic>;
    if (res.data is String) {
      final s = (res.data as String).trimLeft();
      if (s.startsWith('<!doctype html') || s.startsWith('<html')) {
        throw Exception("Server returned HTML (endpoint missing/unauthorized).");
      }
      return jsonDecode(res.data as String) as Map<String, dynamic>;
    }
    return Map<String, dynamic>.from(res.data as dynamic);
  }

  Future<void> login(String email, String password) async {
    final res = await dio.post(
      '/api/login',
      data: jsonEncode({"email": email, "password": password}),
    );
    final j = _json(res);
    if (res.statusCode != 200 || j["ok"] != true) {
      throw Exception(j["error"] ?? "Login failed");
    }
  }

  Future<void> logout() async {
    final res = await dio.post('/api/logout');
    final j = _json(res);
    if (res.statusCode != 200 || j["ok"] != true) {
      throw Exception(j["error"] ?? "Logout failed");
    }
  }

  Future<Map<String, dynamic>> me() async {
    final res = await dio.get('/api/me');
    final j = _json(res);
    if (res.statusCode != 200 || j["ok"] != true) {
      throw Exception(j["error"] ?? "Unauthorized");
    }
    return j;
  }

  Future<Map<String, dynamic>> checkAttendance({
    required String action, // check_in / check_out
    double? lat,
    double? lon,
    String? faceToken,
  }) async {
    final res = await dio.post(
      '/api/attendance/check',
      data: jsonEncode({
        "action": action,
        "lat": lat,
        "lon": lon,
        if (faceToken != null && faceToken.isNotEmpty) "face_token": faceToken,
      }),
    );
    final j = _json(res);
    if (res.statusCode != 200 || j["ok"] != true) {
      throw Exception(j["error"] ?? "Request failed");
    }
    return j;
  }

  Future<List<Map<String, dynamic>>> myAttendance({String? start, String? end}) async {
    final res = await dio.get('/api/attendance/my', queryParameters: {
      if (start != null && start.isNotEmpty) "start": start,
      if (end != null && end.isNotEmpty) "end": end,
    });
    final j = _json(res);
    if (res.statusCode != 200 || j["ok"] != true) {
      throw Exception(j["error"] ?? "Load failed");
    }
    final rows = (j["rows"] as List).cast<dynamic>();
    return rows.map((e) => Map<String, dynamic>.from(e as Map)).toList();
  }

  Future<void> requestLeave({
    required String type, // leave/sick/wfh
    required String startDate, // YYYY-MM-DD
    required String endDate, // YYYY-MM-DD
    required String reason,
  }) async {
    final res = await dio.post(
      '/api/leave/request',
      data: jsonEncode({"type": type, "start_date": startDate, "end_date": endDate, "reason": reason}),
    );
    final j = _json(res);
    if (res.statusCode != 200 || j["ok"] != true) {
      throw Exception(j["error"] ?? "Submit failed");
    }
  }

  Future<List<Map<String, dynamic>>> myLeave() async {
    final res = await dio.get('/api/leave/my');
    final j = _json(res);
    if (res.statusCode != 200 || j["ok"] != true) {
      throw Exception(j["error"] ?? "Load failed");
    }
    final rows = (j["rows"] as List).cast<dynamic>();
    return rows.map((e) => Map<String, dynamic>.from(e as Map)).toList();
  }

  Future<void> changePassword({required String oldPw, required String newPw}) async {
    final res = await dio.post(
      '/api/profile/change_password',
      data: jsonEncode({"old_password": oldPw, "new_password": newPw}),
    );
    final j = _json(res);
    if (res.statusCode != 200 || j["ok"] != true) {
      throw Exception(j["error"] ?? "Update failed");
    }
  }


  Future<void> updateProfile({
    required String phone,
    required String address,
    required String birthDate, // YYYY-MM-DD (optional)
    required String ktpNumber,
  }) async {
    final res = await dio.post(
      '/api/profile/update',
      data: jsonEncode({
        "phone": phone,
        "address": address,
        "birth_date": birthDate,
        "ktp_number": ktpNumber,
      }),
    );
    final j = _json(res);
    if (res.statusCode != 200 || j["ok"] != true) {
      throw Exception(j["error"] ?? "Profile update failed");
    }
  }

  // ---- NEW: approvals API ----
  Future<List<Map<String, dynamic>>> approvalsList() async {
    final res = await dio.get('/api/leave/approvals');
    final j = _json(res);
    if (res.statusCode != 200 || j["ok"] != true) {
      throw Exception(j["error"] ?? "Load approvals failed");
    }
    final rows = (j["rows"] as List).cast<dynamic>();
    return rows.map((e) => Map<String, dynamic>.from(e as Map)).toList();
  }

  Future<void> approveLeave(int id) async {
    final res = await dio.post('/api/leave/$id/approve');
    final j = _json(res);
    if (res.statusCode != 200 || j["ok"] != true) {
      throw Exception(j["error"] ?? "Approve failed");
    }
  }

  Future<void> rejectLeave(int id) async {
    final res = await dio.post('/api/leave/$id/reject');
    final j = _json(res);
    if (res.statusCode != 200 || j["ok"] != true) {
      throw Exception(j["error"] ?? "Reject failed");
    }
  }

  // ---- NEW: announcements API ----
  Future<List<Map<String, dynamic>>> announcementsActive() async {
    final res = await dio.get('/api/announcements/active');
    final j = _json(res);
    if (res.statusCode != 200 || j["ok"] != true) {
      throw Exception(j["error"] ?? "Load announcements failed");
    }
    final rows = (j["rows"] as List).cast<dynamic>();
    return rows.map((e) => Map<String, dynamic>.from(e as Map)).toList();
  }

  // ---- NEW: Face Recognition API (OpenCV backend) ----
  Future<void> faceEnroll(String imageDataUrl) async {
    final res = await dio.post(
      '/api/face/enroll',
      data: jsonEncode({"image": imageDataUrl}),
    );
    final j = _json(res);
    if (res.statusCode != 200 || j["ok"] != true) {
      throw Exception(j["error"] ?? "Face enroll failed");
    }
  }

  Future<String> faceVerify({required String imageDataUrl, required String action}) async {
    final res = await dio.post(
      '/api/face/verify',
      data: jsonEncode({"image": imageDataUrl, "action": action}),
    );
    final j = _json(res);
    if (res.statusCode != 200 || j["ok"] != true) {
      throw Exception(j["error"] ?? "Face verify failed");
    }
    final token = (j["token"] ?? "").toString();
    if (token.isEmpty) throw Exception("Face token missing");
    return token;
  }
}

// ---------- App ----------
class App extends StatelessWidget {
  const App({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Terrindo Attendance',
      debugShowCheckedModeBanner: false,
      theme: _appTheme(),
      home: const Boot(),
    );
  }
}

class Boot extends StatefulWidget {
  const Boot({super.key});
  @override
  State<Boot> createState() => _BootState();
}

class _BootState extends State<Boot> {
  bool loading = true;
  String baseUrl = "http://192.168.0.113:5000";

  Future<void> _load() async {
    final sp = await SharedPreferences.getInstance();
    baseUrl = sp.getString('base_url') ?? baseUrl;
    setState(() => loading = false);
  }

  @override
  void initState() {
    super.initState();
    _load();
  }

  @override
  Widget build(BuildContext context) {
    if (loading) return const Scaffold(body: Center(child: CircularProgressIndicator()));
    return LoginPage(baseUrl: baseUrl);
  }
}

// ---------- Login ----------
class LoginPage extends StatefulWidget {
  final String baseUrl;
  const LoginPage({super.key, required this.baseUrl});

  @override
  State<LoginPage> createState() => _LoginPageState();
}

class _LoginPageState extends State<LoginPage> {
  late String baseUrl;
  final email = TextEditingController();
  final pass = TextEditingController();
  bool busy = false;
  String msg = "";

  @override
  void initState() {
    super.initState();
    baseUrl = widget.baseUrl;
  }

  Future<void> _saveBaseUrl(String v) async {
    final sp = await SharedPreferences.getInstance();
    await sp.setString('base_url', v.trim());
  }

  Future<void> _editBaseUrl() async {
    final c = TextEditingController(text: baseUrl);
    await showDialog(
      context: context,
      builder: (_) => AlertDialog(
        backgroundColor: Colors.black,
        title: const Text("Server URL", style: TextStyle(color: kTbrOrange)),
        content: TextField(
          controller: c,
          decoration: const InputDecoration(
            labelText: "Base URL",
            hintText: "http://192.168.0.113:5000",
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text("Cancel", style: TextStyle(color: Colors.white70)),
          ),
          FilledButton(
            onPressed: () async {
              final v = c.text.trim();
              if (v.isEmpty) return;
              await _saveBaseUrl(v);
              setState(() => baseUrl = v);
              if (context.mounted) Navigator.pop(context);
            },
            child: const Text("Save"),
          ),
        ],
      ),
    );
  }

  Future<void> _login() async {
    setState(() {
      busy = true;
      msg = "";
    });
    try {
      final api = Api(baseUrl);
      await api.login(email.text.trim(), pass.text);
      if (!mounted) return;
      Navigator.pushReplacement(context, MaterialPageRoute(builder: (_) => HomeShell(api: api, baseUrl: baseUrl)));
    } catch (e) {
      setState(() => msg = "$e");
    } finally {
      setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: Center(
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 420),
            child: Padding(
              padding: const EdgeInsets.all(18),
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Row(
                    children: [
                      const Spacer(),
                      IconButton(
                        onPressed: _editBaseUrl,
                        icon: const Icon(Icons.settings),
                        tooltip: "Server URL",
                      ),
                    ],
                  ),
                  const SizedBox(height: 8),
                  Image.asset('assets/logo.png', height: 110),
                  const SizedBox(height: 16),
                  const Text("Attendance", style: TextStyle(fontSize: 22, fontWeight: FontWeight.bold)),
                  const SizedBox(height: 16),
                  TextField(controller: email, keyboardType: TextInputType.emailAddress, decoration: const InputDecoration(labelText: "Email/Username")),
                  const SizedBox(height: 10),
                  TextField(controller: pass, obscureText: true, decoration: const InputDecoration(labelText: "Password")),
                  const SizedBox(height: 14),
                  SizedBox(
                    width: double.infinity,
                    child: FilledButton(
                      onPressed: busy ? null : _login,
                      child: busy ? const SizedBox(height: 18, width: 18, child: CircularProgressIndicator(strokeWidth: 2)) : const Text("Login"),
                    ),
                  ),
                  if (msg.isNotEmpty) ...[
                    const SizedBox(height: 10),
                    Text(msg, style: const TextStyle(color: Colors.redAccent)),
                  ],
                  const SizedBox(height: 10),
                  Text(baseUrl, style: TextStyle(color: Colors.white.withOpacity(0.55), fontSize: 12)),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

// ---------- Home Shell ----------
class HomeShell extends StatefulWidget {
  final Api api;
  final String baseUrl;
  const HomeShell({super.key, required this.api, required this.baseUrl});

  @override
  State<HomeShell> createState() => _HomeShellState();
}

class _HomeShellState extends State<HomeShell> {
  int idx = 0;
  bool roleLoading = true;
  String role = "staff"; // default
  bool canApprove = false;

  bool _isApproverRole(String r) {
    final rr = r.toLowerCase();
    return rr == "manager" || rr == "general_manager" || rr == "hrd" || rr == "admin";
  }

  Future<void> _loadRole() async {
    try {
      final me = await widget.api.me();
      final user = (me["user"] as Map<String, dynamic>?);
      final r = (user?["role"] ?? "staff").toString();
      setState(() {
        role = r;
        canApprove = _isApproverRole(r);
        roleLoading = false;
        // if current idx points to a removed page, reset
        if (!canApprove && idx == 3) idx = 0;
      });
    } catch (_) {
      // if /api/me fails, still keep default layout
      setState(() => roleLoading = false);
    }
  }

  @override
  void initState() {
    super.initState();
    _loadRole();
  }

  @override
  Widget build(BuildContext context) {
    // Pages list (style untouched, only add Approval page conditionally)
    final pages = <Widget>[
      HomePage(api: widget.api),
      MonthlyRecordsPage(api: widget.api),
      LeavePage(api: widget.api),
      if (canApprove) ApprovalPage(api: widget.api),
      ProfilePage(api: widget.api, baseUrl: widget.baseUrl),
    ];

    final titles = <String>[
      "Home",
      "Records",
      "Leave",
      if (canApprove) "Approval",
      "Profile",
    ];

    final items = <BottomNavigationBarItem>[
      const BottomNavigationBarItem(icon: Icon(Icons.fingerprint), label: "Home"),
      const BottomNavigationBarItem(icon: Icon(Icons.calendar_month), label: "Records"),
      const BottomNavigationBarItem(icon: Icon(Icons.assignment), label: "Leave"),
      if (canApprove) const BottomNavigationBarItem(icon: Icon(Icons.fact_check), label: "Approval"),
      const BottomNavigationBarItem(icon: Icon(Icons.person), label: "Profile"),
    ];

    return Scaffold(
      appBar: AppBar(
        title: Text(titles[idx]),
        actions: [
          if (roleLoading)
            const Padding(
              padding: EdgeInsets.only(right: 14),
              child: Center(child: SizedBox(height: 18, width: 18, child: CircularProgressIndicator(strokeWidth: 2))),
            )
          else
            Padding(
              padding: const EdgeInsets.only(right: 14),
              child: Center(
                child: Text(
                  role.toUpperCase(),
                  style: TextStyle(color: Colors.white.withOpacity(0.75), fontSize: 12, fontWeight: FontWeight.w700),
                ),
              ),
            ),
        ],
      ),
      body: pages[idx],
      bottomNavigationBar: BottomNavigationBar(
        currentIndex: idx,
        onTap: (i) => setState(() => idx = i),
        backgroundColor: kTbrCard,
        selectedItemColor: kTbrOrange,
        unselectedItemColor: Colors.white70,
        type: BottomNavigationBarType.fixed,
        items: items,
      ),
    );
  }
}

// ---------- Home (Check In/Out) ----------
class HomePage extends StatefulWidget {
  final Api api;
  const HomePage({super.key, required this.api});

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  bool busy = false;
  String msg = "";
  String lastAction = "";
  String lastTime = "";

  // --- Announcements (NEW) ---
  bool annBusy = true;
  String annErr = "";
  List<Map<String, dynamic>> annRows = [];



  Future<void> _loadAnnouncements() async {
    setState(() {
      annBusy = true;
      annErr = "";
      annRows = [];
    });
    try {
      final rows = await widget.api.announcementsActive();
      setState(() {
        annRows = rows;
        annBusy = false;
      });
    } catch (e) {
      setState(() {
        annErr = "$e";
        annBusy = false;
      });
    }
  }

  @override
  void initState() {
    super.initState();
    _loadAnnouncements();
  }

  Future<Position?> _getPos() async {
    final enabled = await Geolocator.isLocationServiceEnabled();
    if (!enabled) return null;

    LocationPermission perm = await Geolocator.checkPermission();
    if (perm == LocationPermission.denied) perm = await Geolocator.requestPermission();
    if (perm == LocationPermission.deniedForever || perm == LocationPermission.denied) return null;

    return Geolocator.getCurrentPosition(desiredAccuracy: LocationAccuracy.high);
  }

  Future<void> _do(String action) async {
    setState(() {
      busy = true;
      msg = "";
      lastAction = "";
      lastTime = "";
    });
    try {
      final pos = await _getPos();
      // 1) Face verify (selfie) -> get face_token
      final img = await captureSelfieDataUrl();
      final token = await widget.api.faceVerify(imageDataUrl: img, action: action);

      // 2) Attendance check with face_token
      final j = await widget.api.checkAttendance(
        action: action,
        lat: pos?.latitude,
        lon: pos?.longitude,
        faceToken: token,
      );

      // Backend returns ISO string; show in local time on device
      final raw = (j["time"] ?? "").toString();
      final show = raw.isEmpty ? "" : DateFormat("yyyy-MM-dd HH:mm:ss").format(DateTime.parse(raw).toLocal());

      setState(() {
        lastAction = (j["message"] ?? "").toString();
        lastTime = show;
        msg = "OK";
      });
    } catch (e) {
      setState(() => msg = "$e");
    } finally {
      setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return SafeArea(
      child: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text("Check In / Check Out", style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
                  const SizedBox(height: 10),
                  Row(
                    children: [
                      Expanded(
                        child: FilledButton.icon(
                          onPressed: busy ? null : () => _do("check_in"),
                          icon: const Icon(Icons.login),
                          label: const Text("Check In"),
                        ),
                      ),
                      const SizedBox(width: 12),
                      Expanded(
                        child: OutlinedButton.icon(
                          onPressed: busy ? null : () => _do("check_out"),
                          icon: const Icon(Icons.logout),
                          label: const Text("Check Out"),
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 12),
                  if (busy) const LinearProgressIndicator(minHeight: 4),
                  if (lastAction.isNotEmpty) ...[
                    const SizedBox(height: 10),
                    Text(lastAction, style: const TextStyle(color: kTbrOrange, fontWeight: FontWeight.w700)),
                    if (lastTime.isNotEmpty) Text(lastTime, style: const TextStyle(color: Colors.white70)),
                  ],
                  if (msg.isNotEmpty && msg != "OK") ...[
                    const SizedBox(height: 10),
                    Text(msg, style: const TextStyle(color: Colors.redAccent)),
                  ],
                  const SizedBox(height: 6),
                  Text(
                    "Tip: pastikan GPS aktif dan izin lokasi diberikan.",
                    style: TextStyle(color: Colors.white.withOpacity(0.55), fontSize: 12),
                  )
                ],
              ),
            ),
          ),

          const SizedBox(height: 12),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      const Expanded(
                        child: Text("Announcements", style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
                      ),
                      IconButton(
                        onPressed: annBusy ? null : _loadAnnouncements,
                        icon: const Icon(Icons.refresh, size: 20),
                        tooltip: "Refresh",
                      ),
                    ],
                  ),
                  const SizedBox(height: 8),
                  if (annBusy) const LinearProgressIndicator(minHeight: 4),
                  if (!annBusy && annErr.isNotEmpty) ...[
                    const SizedBox(height: 10),
                    Text(annErr, style: const TextStyle(color: Colors.redAccent)),
                  ],
                  if (!annBusy && annErr.isEmpty && annRows.isEmpty) ...[
                    const SizedBox(height: 6),
                    Text("No announcements.", style: TextStyle(color: Colors.white70)),
                  ],
                  for (final a in annRows) ...[
                    const SizedBox(height: 10),
                    Container(
                      padding: const EdgeInsets.all(12),
                      decoration: BoxDecoration(
                        color: Colors.black.withOpacity(0.18),
                        borderRadius: BorderRadius.circular(14),
                        border: Border.all(color: Colors.white.withOpacity(0.10)),
                      ),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Row(
                            children: [
                              Expanded(
                                child: Text(
                                  (a["title"] ?? "-").toString(),
                                  style: const TextStyle(fontWeight: FontWeight.w800),
                                ),
                              ),
                              _AnnouncementPill(level: (a["level"] ?? "info").toString()),
                            ],
                          ),
                          const SizedBox(height: 6),
                          Text(
                            (a["body"] ?? "").toString(),
                            style: TextStyle(color: Colors.white.withOpacity(0.82)),
                          ),
                        ],
                      ),
                    ),
                  ],
                  const SizedBox(height: 6),
                  Text(
                    "Info dari admin (berita duka, libur, cuti bersama, dll).",
                    style: TextStyle(color: Colors.white70, fontSize: 12),
                  )
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}


class _AnnouncementPill extends StatelessWidget {
  final String level;
  const _AnnouncementPill({required this.level});

  @override
  Widget build(BuildContext context) {
    final lv = level.toLowerCase();
    Color bg = Colors.white.withOpacity(0.10);
    String text = "INFO";

    if (lv == "danger") {
      bg = Colors.redAccent.withOpacity(0.18);
      text = "IMPORTANT";
    } else if (lv == "warning") {
      bg = kTbrOrange.withOpacity(0.18);
      text = "NOTICE";
    }

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
      decoration: BoxDecoration(
        color: bg,
        borderRadius: BorderRadius.circular(999),
        border: Border.all(color: Colors.white.withOpacity(0.12)),
      ),
      child: Text(
        text,
        style: const TextStyle(fontSize: 11, fontWeight: FontWeight.w900, letterSpacing: 0.4),
      ),
    );
  }
}


// ---------- Leave Page ----------
class LeavePage extends StatefulWidget {
  final Api api;
  const LeavePage({super.key, required this.api});

  @override
  State<LeavePage> createState() => _LeavePageState();
}

class _LeavePageState extends State<LeavePage> {
  bool busy = false;
  String msg = "";
  String type = "leave";
  DateTime? start;
  DateTime? end;
  final reason = TextEditingController();
  List<Map<String, dynamic>> myReq = [];

  static String _fmtDate(DateTime? d) => d == null ? "" : DateFormat("yyyy-MM-dd").format(d);

  ThemeData _pickerTheme() {
    return ThemeData.dark().copyWith(
      colorScheme: const ColorScheme.dark(
        primary: kTbrOrange,
        onPrimary: Colors.black,
        surface: Colors.black,
        onSurface: Colors.white,
      ),
      dialogBackgroundColor: Colors.black,
    );
  }

  Future<void> _load() async {
    try {
      final rows = await widget.api.myLeave();
      setState(() => myReq = rows);
    } catch (e) {
      setState(() => msg = "Load failed: $e");
    }
  }

  Future<void> _pickStart() async {
    final now = DateTime.now();
    final d = await showDatePicker(
      context: context,
      firstDate: DateTime(now.year - 1, 1, 1),
      lastDate: DateTime(now.year + 2, 12, 31),
      initialDate: start ?? now,
      builder: (context, child) => Theme(data: _pickerTheme(), child: child!),
    );
    if (d != null) setState(() => start = d);
  }

  Future<void> _pickEnd() async {
    final base = start ?? DateTime.now();
    final d = await showDatePicker(
      context: context,
      firstDate: DateTime(base.year - 1, 1, 1),
      lastDate: DateTime(base.year + 2, 12, 31),
      initialDate: end ?? base,
      builder: (context, child) => Theme(data: _pickerTheme(), child: child!),
    );
    if (d != null) setState(() => end = d);
  }

  Future<void> _submit() async {
    if (start == null || end == null) {
      setState(() => msg = "Start/End date wajib dipilih.");
      return;
    }
    if (end!.isBefore(start!)) {
      setState(() => msg = "End date harus >= start date.");
      return;
    }
    setState(() {
      busy = true;
      msg = "";
    });
    try {
      await widget.api.requestLeave(
        type: type,
        startDate: _fmtDate(start),
        endDate: _fmtDate(end),
        reason: reason.text.trim(),
      );
      reason.clear();
      setState(() {
        start = null;
        end = null;
        msg = "Request submitted.";
      });
      await _load();
    } catch (e) {
      setState(() => msg = "$e");
    } finally {
      setState(() => busy = false);
    }
  }

  @override
  void initState() {
    super.initState();
    _load();
  }

  @override
  Widget build(BuildContext context) {
    return SafeArea(
      child: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text("Leave Request", style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
                  const SizedBox(height: 12),
                  DropdownButtonFormField<String>(
                    value: type,
                    items: const [
                      DropdownMenuItem(value: "leave", child: Text("Leave")),
                      DropdownMenuItem(value: "sick", child: Text("Sick")),
                      DropdownMenuItem(value: "wfh", child: Text("WFH")),
                      DropdownMenuItem(value: "on_site", child: Text("On Site Duty")),
                      DropdownMenuItem(value: "late_work", child: Text("Late")),
                      DropdownMenuItem(value: "early_finish", child: Text("Go home early")),
                    ],
                    onChanged: busy ? null : (v) => setState(() => type = v ?? "leave"),
                    decoration: const InputDecoration(labelText: "Type"),
                  ),
                  const SizedBox(height: 10),
                  Row(
                    children: [
                      Expanded(
                        child: OutlinedButton(
                          onPressed: busy ? null : _pickStart,
                          child: Text("Start: ${_fmtDate(start).isEmpty ? '-' : _fmtDate(start)}"),
                        ),
                      ),
                      const SizedBox(width: 12),
                      Expanded(
                        child: OutlinedButton(
                          onPressed: busy ? null : _pickEnd,
                          child: Text("End: ${_fmtDate(end).isEmpty ? '-' : _fmtDate(end)}"),
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 10),
                  TextField(controller: reason, minLines: 2, maxLines: 4, decoration: const InputDecoration(labelText: "Reason (optional)")),
                  const SizedBox(height: 12),
                  SizedBox(
                    width: double.infinity,
                    child: FilledButton.icon(
                      onPressed: busy ? null : _submit,
                      icon: const Icon(Icons.send),
                      label: const Text("Submit"),
                    ),
                  ),
                  if (busy) ...[
                    const SizedBox(height: 10),
                    const LinearProgressIndicator(minHeight: 4),
                  ],
                  if (msg.isNotEmpty) ...[
                    const SizedBox(height: 10),
                    Text(msg, style: TextStyle(color: msg == "Request submitted." ? kTbrOrange : Colors.redAccent)),
                  ],
                ],
              ),
            ),
          ),
          const SizedBox(height: 14),
          const Text("My Requests", style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold)),
          const SizedBox(height: 8),
          if (myReq.isEmpty)
            Text("No requests.", style: TextStyle(color: Colors.white.withOpacity(0.6))),
          for (final r in myReq)
            Card(
              child: ListTile(
                title: Text("${(r["type"] ?? "").toString().toUpperCase()} — ${r["status"] ?? ""}"),
                subtitle: Text("${r["start_date"] ?? ""} → ${r["end_date"] ?? ""}\n${r["reason"] ?? ""}".trim()),
              ),
            ),
        ],
      ),
    );
  }
}

// ---------- Approval Page (NEW, style follows existing cards/buttons) ----------
class ApprovalPage extends StatefulWidget {
  final Api api;
  const ApprovalPage({super.key, required this.api});

  @override
  State<ApprovalPage> createState() => _ApprovalPageState();
}

class _ApprovalPageState extends State<ApprovalPage> {
  bool busy = true;
  String msg = "";
  List<Map<String, dynamic>> rows = [];

  Future<void> _load() async {
    setState(() {
      busy = true;
      msg = "";
    });
    try {
      rows = await widget.api.approvalsList();
    } catch (e) {
      msg = "$e";
    } finally {
      setState(() => busy = false);
    }
  }

  Future<void> _approve(int id) async {
    setState(() => busy = true);
    try {
      await widget.api.approveLeave(id);
      await _load();
    } catch (e) {
      setState(() {
        busy = false;
        msg = "$e";
      });
    }
  }

  Future<void> _reject(int id) async {
    setState(() => busy = true);
    try {
      await widget.api.rejectLeave(id);
      await _load();
    } catch (e) {
      setState(() {
        busy = false;
        msg = "$e";
      });
    }
  }

  @override
  void initState() {
    super.initState();
    _load();
  }

  @override
  Widget build(BuildContext context) {
    return SafeArea(
      child: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Row(
            children: [
              const Expanded(
                child: Text("Pending Approvals", style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold)),
              ),
              IconButton(
                onPressed: busy ? null : _load,
                icon: const Icon(Icons.refresh),
                tooltip: "Refresh",
              ),
            ],
          ),
          const SizedBox(height: 8),
          if (busy) const LinearProgressIndicator(minHeight: 4),
          if (msg.isNotEmpty) ...[
            const SizedBox(height: 10),
            Text(msg, style: const TextStyle(color: Colors.redAccent)),
          ],
          const SizedBox(height: 10),
          if (!busy && rows.isEmpty)
            Text("No pending approvals.", style: TextStyle(color: Colors.white.withOpacity(0.6))),
          for (final r in rows)
            Card(
              child: Padding(
                padding: const EdgeInsets.all(14),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      "${(r["employee_name"] ?? r["employee"] ?? "-")} — ${(r["type"] ?? "").toString().toUpperCase()}",
                      style: const TextStyle(fontWeight: FontWeight.w800),
                    ),
                    const SizedBox(height: 6),
                    Text(
                      "${r["start_date"] ?? ""} → ${r["end_date"] ?? ""}",
                      style: TextStyle(color: Colors.white.withOpacity(0.75)),
                    ),
                    if ((r["dept"] ?? "").toString().isNotEmpty) ...[
                      const SizedBox(height: 6),
                      Text("Dept: ${r["dept"]}", style: TextStyle(color: Colors.white.withOpacity(0.65), fontSize: 12)),
                    ],
                    if ((r["reason"] ?? "").toString().trim().isNotEmpty) ...[
                      const SizedBox(height: 8),
                      Text((r["reason"] ?? "").toString().trim(), style: TextStyle(color: Colors.white.withOpacity(0.75))),
                    ],
                    const SizedBox(height: 12),
                    Row(
                      children: [
                        Expanded(
                          child: OutlinedButton.icon(
                            onPressed: busy ? null : () => _reject((r["id"] as num).toInt()),
                            icon: const Icon(Icons.close),
                            label: const Text("Reject"),
                          ),
                        ),
                        const SizedBox(width: 12),
                        Expanded(
                          child: FilledButton.icon(
                            onPressed: busy ? null : () => _approve((r["id"] as num).toInt()),
                            icon: const Icon(Icons.check),
                            label: const Text("Approve"),
                          ),
                        ),
                      ],
                    ),
                  ],
                ),
              ),
            ),
        ],
      ),
    );
  }
}

// ---------- Monthly Records ----------
class MonthlyRecordsPage extends StatefulWidget {
  final Api api;
  const MonthlyRecordsPage({super.key, required this.api});

  @override
  State<MonthlyRecordsPage> createState() => _MonthlyRecordsPageState();
}

class _MonthlyRecordsPageState extends State<MonthlyRecordsPage> {
  bool busy = true;
  String msg = "";
  DateTime month = DateTime(DateTime.now().year, DateTime.now().month, 1);

  // Map by YYYY-MM-DD
  Map<String, Map<String, dynamic>> recByDate = {};

  static const List<String> idDays = ["Senin", "Selasa", "Rabu", "Kamis", "Jumat", "Sabtu", "Minggu"];
  static const List<String> idMonths = [
    "Januari","Februari","Maret","April","Mei","Juni","Juli","Agustus","September","Oktober","November","Desember"
  ];

  @override
  void initState() {
    super.initState();
    _loadMonth();
  }

  String _ymd(DateTime d) => DateFormat("yyyy-MM-dd").format(d);

  // ✅ FIX: show local time (device timezone) to avoid UTC on Records
  String _hmFromIso(String s) {
    if (s.trim().isEmpty) return "";
    final dt = DateTime.parse(s).toLocal();
    return "${dt.hour.toString().padLeft(2, '0')}:${dt.minute.toString().padLeft(2, '0')}";
  }

  bool _isLate(String checkIn) {
    if (checkIn.trim().isEmpty) return false;
    try {
      final dt = DateTime.parse(checkIn.replaceFirst(" ", "T")).toLocal();
      // default late threshold (09:15). If backend already sets status=late, we also show it.
      const lateHour = 9;
      const lateMinute = 15;
      final cmp = DateTime(dt.year, dt.month, dt.day, lateHour, lateMinute);
      return dt.isAfter(cmp);
    } catch (_) {
      return false;
    }
  }

  ThemeData _dialogTheme() {
    return ThemeData.dark().copyWith(
      dialogBackgroundColor: Colors.black,
      colorScheme: const ColorScheme.dark(
        primary: kTbrOrange,
        onPrimary: Colors.black,
        surface: Colors.black,
        onSurface: Colors.white,
      ),
    );
  }

  Future<void> _pickMonth() async {
    final now = DateTime.now();
    int y = month.year;
    int m = month.month;

    await showDialog(
      context: context,
      builder: (ctx) {
        return Theme(
          data: _dialogTheme(),
          child: AlertDialog(
            backgroundColor: Colors.black,
            title: const Text("Pilih Bulan", style: TextStyle(color: kTbrOrange)),
            content: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                DropdownButtonFormField<int>(
                  value: y,
                  dropdownColor: Colors.black,
                  iconEnabledColor: kTbrOrange,
                  decoration: const InputDecoration(labelText: "Tahun"),
                  items: List.generate(7, (i) {
                    final yy = now.year - 3 + i;
                    return DropdownMenuItem(value: yy, child: Text("$yy"));
                  }),
                  onChanged: (v) => y = v ?? y,
                ),
                const SizedBox(height: 10),
                DropdownButtonFormField<int>(
                  value: m,
                  dropdownColor: Colors.black,
                  iconEnabledColor: kTbrOrange,
                  decoration: const InputDecoration(labelText: "Bulan"),
                  items: List.generate(12, (i) {
                    final mm = i + 1;
                    return DropdownMenuItem(value: mm, child: Text(idMonths[i]));
                  }),
                  onChanged: (v) => m = v ?? m,
                ),
              ],
            ),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(ctx),
                child: const Text("Cancel", style: TextStyle(color: Colors.white70)),
              ),
              FilledButton(
                onPressed: () {
                  setState(() => month = DateTime(y, m, 1));
                  Navigator.pop(ctx);
                  _loadMonth();
                },
                child: const Text("Apply"),
              ),
            ],
          ),
        );
      },
    );
  }

  Future<void> _loadMonth() async {
    setState(() {
      busy = true;
      msg = "";
    });
    try {
      final start = DateTime(month.year, month.month, 1);
      final end = DateTime(month.year, month.month + 1, 0);
      final rows = await widget.api.myAttendance(start: _ymd(start), end: _ymd(end));

      final map = <String, Map<String, dynamic>>{};
      for (final r in rows) {
        final d = (r["date"] ?? "").toString();
        if (d.isNotEmpty) map[d] = r;
      }
      setState(() => recByDate = map);
    } catch (e) {
      setState(() => msg = "Load failed: $e");
    } finally {
      setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final titleMonth = "${idMonths[month.month - 1]} ${month.year}";
    final daysInMonth = DateTime(month.year, month.month + 1, 0).day;
    final startDay = DateTime(month.year, month.month, 1);

    return SafeArea(
      child: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Row(
            children: [
              Expanded(
                child: GestureDetector(
                  onTap: _pickMonth,
                  child: Container(
                    padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 14),
                    decoration: BoxDecoration(
                      color: Colors.black.withOpacity(0.35),
                      borderRadius: BorderRadius.circular(14),
                      border: Border.all(color: kTbrOrange.withOpacity(0.55)),
                    ),
                    child: Row(
                      children: [
                        const Icon(Icons.date_range, color: kTbrOrange),
                        const SizedBox(width: 10),
                        Text(titleMonth, style: const TextStyle(fontSize: 16, fontWeight: FontWeight.w700)),
                        const Spacer(),
                        const Icon(Icons.expand_more, color: Colors.white70),
                      ],
                    ),
                  ),
                ),
              ),
              const SizedBox(width: 10),
              IconButton(
                onPressed: busy ? null : _loadMonth,
                icon: const Icon(Icons.refresh),
                tooltip: "Refresh",
              ),
            ],
          ),
          const SizedBox(height: 12),
          if (busy) const LinearProgressIndicator(minHeight: 4),
          if (msg.isNotEmpty) ...[
            const SizedBox(height: 10),
            Text(msg, style: const TextStyle(color: Colors.redAccent)),
          ],
          const SizedBox(height: 10),
          for (int d = 1; d <= daysInMonth; d++)
            _DayRow(
              day: d,
              date: DateTime(month.year, month.month, d),
              dayName: idDays[(startDay.add(Duration(days: d - 1)).weekday + 6) % 7],
              record: recByDate[_ymd(DateTime(month.year, month.month, d))],
              hmFromIso: _hmFromIso,
              isLate: _isLate,
            ),
          const SizedBox(height: 16),
        ],
      ),
    );
  }
}

class _DayRow extends StatelessWidget {
  final int day;
  final DateTime date;
  final String dayName;
  final Map<String, dynamic>? record;
  final String Function(String) hmFromIso;
  final bool Function(String) isLate;

  const _DayRow({
    required this.day,
    required this.date,
    required this.dayName,
    required this.record,
    required this.hmFromIso,
    required this.isLate,
  });

  Color _statusColor(String status) {
    switch (status) {
      case "present":
        return Colors.greenAccent;
      case "late":
        return kTbrOrange;
      case "late_work":
        return kTbrOrange;
      case "early_finish":
        return kTbrOrange;
      case "absent":
        return Colors.redAccent;
      case "leave":
        return Colors.redAccent;
      case "sick":
        return Colors.redAccent;
      case "wfh":
        return Colors.lightBlueAccent;
      case "on_site":
        return Colors.cyanAccent;
      default:
        return Colors.white70;
    }
  }

  @override
  Widget build(BuildContext context) {
    final rec = record;
    final status = (rec?["status"] ?? "").toString();
    final note = (rec?["note"] ?? "").toString();
    final ci = (rec?["check_in"] ?? "").toString();
    final co = (rec?["check_out"] ?? "").toString();

    final ciHm = ci.isEmpty ? "-" : hmFromIso(ci);
    final coHm = co.isEmpty ? "-" : hmFromIso(co);

    final has = rec != null;
    final lateFlag = has && (status == "late" || isLate(ci));

    return Card(
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
        child: Row(
          children: [
            Container(
              width: 46,
              height: 46,
              alignment: Alignment.center,
              decoration: BoxDecoration(
                color: Colors.black.withOpacity(0.25),
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: Colors.white.withOpacity(0.12)),
              ),
              child: Text(day.toString().padLeft(2, "0"), style: const TextStyle(fontSize: 16, fontWeight: FontWeight.bold)),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Text(dayName, style: TextStyle(color: Colors.white.withOpacity(0.85), fontWeight: FontWeight.w700)),
                      const SizedBox(width: 8),
                      if (has)
                        Container(
                          padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                          decoration: BoxDecoration(
                            color: _statusColor(status).withOpacity(0.18),
                            borderRadius: BorderRadius.circular(999),
                            border: Border.all(color: _statusColor(status).withOpacity(0.45)),
                          ),
                          child: Text(
                            status.isEmpty ? "-" : status.toUpperCase(),
                            style: TextStyle(fontSize: 11, color: _statusColor(status), fontWeight: FontWeight.w800),
                          ),
                        ),
                      if (lateFlag) ...[
                        const SizedBox(width: 8),
                        const Icon(Icons.warning_amber_rounded, size: 16, color: kTbrOrange),
                      ],
                    ],
                  ),
                  const SizedBox(height: 6),
                  Row(
                    children: [
                      const Icon(Icons.login, size: 16, color: Colors.white70),
                      const SizedBox(width: 6),
                      Text(ciHm, style: const TextStyle(fontWeight: FontWeight.w700)),
                      const SizedBox(width: 14),
                      const Icon(Icons.logout, size: 16, color: Colors.white70),
                      const SizedBox(width: 6),
                      Text(coHm, style: const TextStyle(fontWeight: FontWeight.w700)),
                    ],
                  ),
                  if (note.isNotEmpty) ...[
                    const SizedBox(height: 6),
                    Text(note, style: TextStyle(color: Colors.white.withOpacity(0.6), fontSize: 12)),
                  ],
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

// ---------- Profile ----------
class ProfilePage extends StatefulWidget {
  final Api api;
  final String baseUrl;
  const ProfilePage({super.key, required this.api, required this.baseUrl});

  @override
  State<ProfilePage> createState() => _ProfilePageState();
}

class _ProfilePageState extends State<ProfilePage> {
  bool busy = true;
  String msg = "";
  Map<String, dynamic>? me;

  final oldPw = TextEditingController();
  final newPw = TextEditingController();

  // --- Edit Profile (NEW) ---
  final pfPhone = TextEditingController();
  final pfAddress = TextEditingController();
  final pfBirthDate = TextEditingController(); // YYYY-MM-DD
  final pfKtp = TextEditingController();

  Future<void> _load() async {
    setState(() {
      busy = true;
      msg = "";
    });
    try {
      me = await widget.api.me();

      // fill edit profile form from employee (same as mobile_app.html)
      final emp = me?["employee"] as Map<String, dynamic>?;
      pfPhone.text = (emp?["phone"] ?? "").toString();
      pfAddress.text = (emp?["address"] ?? "").toString();
      pfBirthDate.text = (emp?["birth_date"] ?? "").toString();
      pfKtp.text = (emp?["ktp_number"] ?? "").toString();
    } catch (e) {
      msg = "$e";
    } finally {
      setState(() => busy = false);
    }
  }

  @override
  void dispose() {
    oldPw.dispose();
    newPw.dispose();
    pfPhone.dispose();
    pfAddress.dispose();
    pfBirthDate.dispose();
    pfKtp.dispose();
    super.dispose();
  }

  Future<void> _changePw() async {
    final o = oldPw.text.trim();
    final n = newPw.text.trim();
    if (o.isEmpty || n.isEmpty) {
      setState(() => msg = "Old/New password wajib diisi.");
      return;
    }
    setState(() {
      busy = true;
      msg = "";
    });
    try {
      await widget.api.changePassword(oldPw: o, newPw: n);
      oldPw.clear();
      newPw.clear();
      setState(() => msg = "Password updated.");
    } catch (e) {
      setState(() => msg = "$e");
    } finally {
      setState(() => busy = false);
    }
  }



  ThemeData _pickerTheme() {
    return ThemeData.dark().copyWith(
      colorScheme: const ColorScheme.dark(
        primary: kTbrOrange,
        onPrimary: Colors.black,
        surface: Colors.black,
        onSurface: Colors.white,
      ),
      dialogBackgroundColor: Colors.black,
    );
  }

  Future<void> _pickBirthDate() async {
    final now = DateTime.now();
    DateTime initial = now;
    if (pfBirthDate.text.trim().isNotEmpty) {
      try {
        initial = DateTime.parse(pfBirthDate.text.trim());
      } catch (_) {}
    }
    final d = await showDatePicker(
      context: context,
      firstDate: DateTime(now.year - 80, 1, 1),
      lastDate: DateTime(now.year + 1, 12, 31),
      initialDate: initial,
      builder: (context, child) => Theme(data: _pickerTheme(), child: child!),
    );
    if (d != null) {
      pfBirthDate.text = DateFormat("yyyy-MM-dd").format(d);
      setState(() {}); // refresh UI
    }
  }

  Future<void> _saveProfile() async {
    setState(() {
      busy = true;
      msg = "";
    });
    try {
      await widget.api.updateProfile(
        phone: pfPhone.text.trim(),
        address: pfAddress.text.trim(),
        birthDate: pfBirthDate.text.trim(),
        ktpNumber: pfKtp.text.trim(),
      );

      // reload profile info
      await _load();

      setState(() => msg = "Profile updated.");
    } catch (e) {
      setState(() => msg = "$e");
    } finally {
      setState(() => busy = false);
    }
  }

  Future<void> _enrollFace() async {
    setState(() {
      busy = true;
      msg = "";
    });
    try {
      final img = await captureSelfieDataUrl();
      await widget.api.faceEnroll(img);
      setState(() => msg = "Face enrolled successfully.");
    } catch (e) {
      setState(() => msg = "$e");
    } finally {
      setState(() => busy = false);
    }
  }

  Future<void> _logout() async {
    setState(() {
      busy = true;
      msg = "";
    });
    try {
      await widget.api.logout();
      if (!mounted) return;
      Navigator.pushAndRemoveUntil(
        context,
        MaterialPageRoute(builder: (_) => LoginPage(baseUrl: widget.baseUrl)),
        (route) => false,
      );
    } catch (e) {
      setState(() => msg = "$e");
    } finally {
      setState(() => busy = false);
    }
  }

  @override
  void initState() {
    super.initState();
    _load();
  }

  @override
  Widget build(BuildContext context) {
    final user = me?["user"] as Map<String, dynamic>?;
    final emp = me?["employee"] as Map<String, dynamic>?;

    return SafeArea(
      child: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          if (busy) const LinearProgressIndicator(minHeight: 4),
          if (msg.isNotEmpty) ...[
            const SizedBox(height: 10),
            Text(
              msg,
              style: TextStyle(
                color: (msg == "Password updated." || msg == "Profile updated." || msg == "Face enrolled successfully.")
                    ? kTbrOrange
                    : Colors.redAccent,
              ),
            ),
          ],
          const SizedBox(height: 10),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text("My Profile", style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
                  const SizedBox(height: 10),
                  _kv("Name", (user?["name"] ?? "-").toString()),
                  _kv("Email", (user?["email"] ?? "-").toString()),
                  _kv("Role", (user?["role"] ?? "-").toString()),
                  const SizedBox(height: 10),
                  if (emp != null) ...[
                    const Divider(),
                    _kv("Employee Code", (emp["code"] ?? "-").toString()),
                    _kv("Employee Name", (emp["name"] ?? "-").toString()),
                    _kv("Dept", (emp["dept"] ?? "-").toString()),
                  ],
                ],
              ),
            ),
          ),
          const SizedBox(height: 14),
          // --- Face Enrollment (NEW) ---
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text("Face Enrollment", style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold)),
                  const SizedBox(height: 8),
                  Text(
                    "Daftarkan wajah 1x agar bisa check-in/out dengan verifikasi.",
                    style: TextStyle(color: Colors.white.withOpacity(0.65), fontSize: 12),
                  ),
                  const SizedBox(height: 12),
                  SizedBox(
                    width: double.infinity,
                    child: FilledButton.icon(
                      onPressed: busy ? null : _enrollFace,
                      icon: const Icon(Icons.face),
                      label: const Text("Enroll Face"),
                    ),
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 14),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text("Change Password", style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold)),
                  const SizedBox(height: 10),
                  TextField(controller: oldPw, obscureText: true, decoration: const InputDecoration(labelText: "Old password")),
                  const SizedBox(height: 10),
                  TextField(controller: newPw, obscureText: true, decoration: const InputDecoration(labelText: "New password (min 6 chars)")),
                  const SizedBox(height: 12),
                  SizedBox(
                    width: double.infinity,
                    child: FilledButton.icon(
                      onPressed: busy ? null : _changePw,
                      icon: const Icon(Icons.lock_reset),
                      label: const Text("Update"),
                    ),
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 14),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text("Edit Profile", style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold)),
                  const SizedBox(height: 10),
                  TextField(controller: pfPhone, decoration: const InputDecoration(labelText: "Nomor HP", hintText: "08xxxxxxxxxx")),
                  const SizedBox(height: 10),
                  TextField(controller: pfAddress, decoration: const InputDecoration(labelText: "Alamat", hintText: "Alamat lengkap")),
                  const SizedBox(height: 10),
                  Row(
                    children: [
                      Expanded(
                        child: TextField(
                          controller: pfBirthDate,
                          readOnly: true,
                          onTap: busy ? null : _pickBirthDate,
                          decoration: const InputDecoration(labelText: "Tanggal Lahir"),
                        ),
                      ),
                      const SizedBox(width: 12),
                      Expanded(
                        child: TextField(
                          controller: pfKtp,
                          decoration: const InputDecoration(labelText: "Nomor KTP", hintText: "16 digit (opsional)"),
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 12),
                  SizedBox(
                    width: double.infinity,
                    child: FilledButton.icon(
                      onPressed: busy ? null : _saveProfile,
                      icon: const Icon(Icons.save),
                      label: const Text("Save"),
                    ),
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 14),
          SizedBox(
            width: double.infinity,
            child: FilledButton.icon(
              onPressed: busy ? null : _logout,
              icon: const Icon(Icons.logout),
              label: const Text("Logout"),
            ),
          ),
        ],
      ),
    );
  }

  Widget _kv(String k, String v) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 6),
      child: Row(
        children: [
          SizedBox(width: 120, child: Text(k, style: TextStyle(color: Colors.white.withOpacity(0.6)))),
          Expanded(child: Text(v, style: const TextStyle(fontWeight: FontWeight.w700))),
        ],
      ),
    );
  }
}
