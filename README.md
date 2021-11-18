# Brutelock

Brutelock is a free and opensource password cracking software written in python 3.
It allows users to efficiently crack hashed passwords.
It supports all of the hashing algorithms listed below:
-

- *SHA1*
- *SHA224*
- *SHA256*
- *SHA384*
- *SHA512*
- *BLAKE2b*
- *BLAKE2s*
- *SHA3 224*
- *SHA3 256*
- *SHA3 384*
- *SHA3 512*
- *MD5*

## Importing and Exporting

You can import and export passwords in both .txt and .json format.
Importing passwords from a .json file requires the data to be in a list datatype.
you specify these with the "-f <file>" for the hashed password file, and "-out <file>" at the end for the output file.


## Wordlist

Brutelock also supports wordlist attacks also known as dictionary attacks.
you can use a wordlist with "--wordlist <file>"
the wordlist can be in both .json and .txt files. if the filetype is .json, the data will need to be in list datatype


## Additional settings

Brutelock has a lot more features including:


- *Setting for minimal password length (--ml <number>)*
- *Setting for what characters the password can contain (--charpool <number>)*
- *Setting for maximum cracks the program should do before exiting (--max <number>)*

## Installation

```
git clone https://github.com/GilbertEnevoldsen/Brutelock.git
```

## Usage
```
Usage: [-help / --help HELP] [-m METHOD] [-f PASSWORD FILE] [--ml MINIMUM LENGTH]
       [--charpool CHARACTER POOL] [--wordlist WORDLIST] [--max MAX CRACKS] [-out OUTPUT FILE]
          
Arguments:
  -help, --help     shows this message
  -m                what hashing method to use
                    sha1, sha224, sha256, sha384, sha512,
                    blake2b, blake2s, sha3_224, sha3_256,
                    sha3_384, sha3_512, md5
  -f                the file with the passwords
                    (supports both .json in list format and .txt)
  --ml              the minimum length to guess passwords for
  --charpool        what characters that passwords can contain
                    1, lowercase
                    2, lowercase and digits
                    3, lowercase and uppercase
                    4, lowercase and uppercase and digits
                    5, lowercase and uppercase and digits and special characters
  --wordlist        a wordlist with passwords that
                    brutelock will try before it tries
                    standard bruteforcing
  --max             stops after MAX amount of passwords
                    has been cracked
  -out              what file to save cracked passwords
                    to (supports both .json as a list of
                    objects and .txt), you need to put
                    this argument at the end of the
                    command
```
