"""Build a signed APK using Android SDK tools and a JDK, without Gradle."""
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parent
SDK = Path(os.environ.get('ANDROID_HOME', Path.home() / 'AppData/Local/Android/Sdk'))
JAVA = Path(shutil.which('java') or 'java').resolve().parent
TOOLS = SDK / 'build-tools/36.0.0'
ANDROID = SDK / 'platforms/android-37.0/android.jar'
BUILD = ROOT / 'build'
SIGNING = ROOT / '.signing'


def run(*args):
    subprocess.run([str(x) for x in args], check=True, cwd=ROOT)


def main():
    BUILD.mkdir(exist_ok=True)
    SIGNING.mkdir(exist_ok=True)
    classes = BUILD / 'classes'
    dex = BUILD / 'dex'
    classes.mkdir(exist_ok=True)
    dex.mkdir(exist_ok=True)
    run(TOOLS / 'aapt2.exe', 'compile', '--dir', ROOT / 'res', '-o', BUILD / 'resources.zip')
    run(TOOLS / 'aapt2.exe', 'link', '-o', BUILD / 'resources.apk', '--manifest', ROOT / 'AndroidManifest.xml', '-I', ANDROID, BUILD / 'resources.zip')
    sources = sorted((ROOT / 'src').rglob('*.java'))
    boot = str(ANDROID) + os.pathsep + str(TOOLS / 'core-lambda-stubs.jar')
    run(JAVA / 'javac.exe', '-encoding', 'UTF-8', '-source', '8', '-target', '8', '-bootclasspath', boot, '-d', classes, *sources)
    run(JAVA / 'java.exe', '-cp', TOOLS / 'lib/d8.jar', 'com.android.tools.r8.D8', '--min-api', '23', '--lib', ANDROID, '--output', dex, *sorted(classes.rglob('*.class')))
    unsigned = BUILD / 'unsigned.apk'
    shutil.copyfile(BUILD / 'resources.apk', unsigned)
    with zipfile.ZipFile(unsigned, 'a', compression=zipfile.ZIP_DEFLATED) as apk:
        apk.write(dex / 'classes.dex', 'classes.dex')
    run(TOOLS / 'zipalign.exe', '-f', '-p', '4', unsigned, BUILD / 'aligned.apk')
    password = SIGNING / 'password.txt'
    keystore = SIGNING / 'hazee-key.jks'
    if not password.exists():
        password.write_text(secrets.token_urlsafe(36), encoding='utf-8')
    if not keystore.exists():
        run(JAVA / 'keytool.exe', '-genkeypair', '-keystore', keystore, '-storetype', 'JKS', '-alias', 'hazee-key', '-keyalg', 'RSA', '-keysize', '3072', '-validity', '10000', '-storepass:file', password, '-keypass:file', password, '-dname', 'CN=Hazee Key, OU=Android, O=Hazee')
    output = BUILD / 'Hazee-Key-1.0.apk'
    run(JAVA / 'java.exe', '-jar', TOOLS / 'lib/apksigner.jar', 'sign', '--ks', keystore, '--ks-key-alias', 'hazee-key', '--ks-pass', 'file:' + str(password), '--out', output, BUILD / 'aligned.apk')
    run(JAVA / 'java.exe', '-jar', TOOLS / 'lib/apksigner.jar', 'verify', '--verbose', output)
    print('APK:', output)


if __name__ == '__main__':
    main()
