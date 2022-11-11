m1 = 210455
m2 = 146077

space compression factor c = space using list / space using RBF
number of ips = 10000
each ip = 13 bytes
1 byte = 8 bits

c1 = 8 * 13 * 10000 / 210455
c1 = 4.9416

c2 = 8 * 13 * 10000 / 146077
c2 = 7.1195

m1 = 210455
m2 = 146077
c1 = 4.9416
c2 = 7.1195


*****************************************************************************************
Instructions
*****************************************************************************************
Run the first file RBFGen.cpp using statement:


>> g++ RBFGen.cpp -o rbfexecutable.exe 
>> ./rbfexecutable.exe

Then enter the M value to be inserted.

Run the second file which is in the same folder IPCheck.cpp using statement:


>>g++ IPCheck.cpp -o ipchecker.exe
>> ./ipchecker.exe

Then enter the M value which was used before to generate the RBF.
Enter the IP Address to check.


