cd src/Dll;
make;

cd ../../;

cd src/Panel;
make;

cd ../../;

mv src/Dll/bin/CrimsonEDR.dll .
mv src/Panel/bin/CrimsonEDRPanel.exe .

cd src/Dll;
make clean;

cd ../../;

cd src/Panel;
make clean;

cd ../../;

cp src/ioc.json .;