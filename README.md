# Brutelock

Brutelock is a free and opensource password cracking software written in python 3.
It allows users to efficiently crack hashed passwords.
It supports all of the hashing algorithms listed below:
-

- **SHA1**
- **SHA224**
- **SHA256**
- **SHA384**
- **SHA512**
- **BLAKE2b**
- **BLAKE2s**
- **SHA3 224**
- **SHA3 256**
- **SHA3 384**
- **SHA3 512**
- **MD5**

## Importing and Exporting

You can import and export passwords in both .txt and .json format.
Importing passwords from a .json file requires the data to be in a list datatype.
you specify these with the "-f <file>" for the hashed password file, and "-out <file>" at the end for the output file.
-

## Wordlist

Brutelock also supports wordlist attacks also known as dictionary attacks.
you can use a wordlist with "--wordlist <file>"
the wordlist can be in both .json and .txt files. if the filetype is .json, the data will need to be in list datatype
-

## Additional settings

Brutelock has a lot more features including:
-

- **Setting for minimal password length (--ml <number>)**
- **Setting for what characters the password can contain (--charpool <number>)**
- **Setting for maximum cracks the program should do before exiting (--max <number>)**

## Installation

```
git clone https://github.com/GilbertEnevoldsen/Brutelock.git
```
