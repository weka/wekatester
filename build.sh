pyinstaller --onefile wekatester.py

TARGET=tarball/wekatester
mkdir -p $TARGET
cp dist/wekatester $TARGET
cp fio $TARGET
cp -r fio-jobfiles $TARGET
cd tarball
tar cvzf ../wekatester.tar wekatester

