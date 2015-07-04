UTEID: kge227; ryt96;
FIRSTNAME: Kevin; Roger
LASTNAME: Esswein; Tang
CSACCOUNT: kesswein; rtang96
EMAIL: kesswein@utexas.edu; roger.tang.utexas.edu

[Program 4]
[Description]
The program is put into the AES.java file. The program creates an encryption by using a 256 bit key to encrypt multiple 128 bit plaintexts. By cycling through the main four steps of byte substitution, shift row, mix columns and round table, the encryption is securely safe from an attacker. Roger wrote most of the functions, where as Kevin's contribution was limited to the inverse functions and some of the read functions.

[Finish]
We finished all of the assignment.

[Test Cases]
[Input of test 1]
java AES e key plaintext
java AES d key plaintext.enc

plaintext
00112233445566778899AABBCCDDEEFF
key
0000000000000000000000000000000000000000000000000000000000000000

[Output of test 1]
6.938647180632501E-7 MB/s

plaintext.enc
1C060F4C9E7EA8D6CA961A2D64C05C18
plaintext.enc.dec
00112233445566778899AABBCCDDEEFF

[Input of test 2]
plaintext
00112233445566778899AABBCCDDEEFF
00112233445566778899AABBCCDDEEFF
key
0000000000000000000000000000000000000000000000000000000000000000

[Output of test 2]
1.1652974421721145E-6 MB/s

plaintext.enc
1C060F4C9E7EA8D6CA961A2D64C05C18
1C060F4C9E7EA8D6CA961A2D64C05C18

plaintext.enc.dec
00112233445566778899AABBCCDDEEFF
00112233445566778899AABBCCDDEEFF

[Input of test 3]
plaintext
000000000000000
key
0000000000000000000000000000000000000000000000000000000000000000

[Output of test 3]
3.676335428844528E-7 MB/s

plaintext.enc
DC95C078A2408989AD48A21492842087
plaintext.enc.dec
00000000000000000000000000000000

[Input of test 3]
plaintext
36B299247633979676E1B4433F241641EC36277712167F000B
key
4785692759023895031750326843905673910539267490325934758930547345

[Output of test 4]
6.415705647424896E-7 MB/s

plaintext.enc
8F8D1BFE4742F0A135CDE7851A62C56E
plaintext.enc.dec
36B299247633979676E1B4433F241641
