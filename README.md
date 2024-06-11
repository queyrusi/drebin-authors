# drebin-authors

Python 3 port with adjustments for [Michael Spreitzenbarth's](https://www.dropbox.com/scl/fi/glssfbxh1pfotqrvnooxh/feature-extractor.tar.gz?e=5&file_subpath=%2Ffeature-extractor&rlkey=gx9v48scttwgm72eloloil08e) (Drebin co-author) feature extractor.

## Setup
**Prepare `ssdeep` install:**
```bash
sudo apt-get update
sudo apt-get install ssdeep libfuzzy-dev
export LDFLAGS="-L/usr/local/lib"
export CPPFLAGS="-I/usr/local/include"
```


**Install `aapt`:**
```bash
sudo apt-get install -y android-sdk
export ANDROID_HOME=/usr/lib/android-sdk
export PATH=$PATH:$ANDROID_HOME/platform-tools:$ANDROID_HOME/tools
source ~/.bashrc
sdkmanager "build-tools;30.0.3"
```


then run

```bash
pip3 install -r requirements.txt
```

## Usage
```bash
python3 drebin.py <APK-PATH> <WORKING-DIR>
```
Results saved inside working dir.
