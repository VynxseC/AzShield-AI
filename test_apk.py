import zipfile

manifest_mock = """
<manifest package="az.kapital.security.update.trojan">
    <uses-permission android:name="android.permission.RECEIVE_SMS" />
    <uses-permission android:name="android.permission.READ_SMS" />
    <uses-permission android:name="android.permission.BIND_ACCESSIBILITY_SERVICE" />
    <uses-permission android:name="android.permission.REQUEST_INSTALL_PACKAGES" />
    <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW" />
</manifest>
"""

dex_mock = """
Lcom/az/bankstealer/SmsInterceptor;
Landroid/telephony/SmsManager;->sendTextMessage
Ldalvik/system/DexClassLoader;
https://api.telegram.org/bot849201944:AAFakeDemoC2ServerToken/sendMessage
"""

with zipfile.ZipFile("Kapital_Tehlukesizlik_Yenilemesi.apk", "w") as apk:
    apk.writestr("AndroidManifest.xml", manifest_mock)
    apk.writestr("classes.dex", dex_mock)

print("Hazırdır! 'Kapital_Tehlukesizlik_Yenilemesi.apk' yaradıldı.")