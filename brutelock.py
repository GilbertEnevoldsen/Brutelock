# Brutelock: Advanced Password Cracker
# ------------------------------------
#
# Python script for cracking hashed passwords

import itertools

import hashlib

import string

import json

import time

import sys

# -help/--help command

if '-help' in sys.argv or '--help' in sys.argv:
    
    print("""
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
          """)
    
    exit()

print("""
  ____             _       _            _    
 |  _ \           | |     | |          | |   
 | |_) |_ __ _   _| |_ ___| | ___   ___| | __
 |  _ <| '__| | | | __/ _ \ |/ _ \ / __| |/ /
 | |_) | |  | |_| | ||  __/ | (_) | (__|   < 
 |____/|_|   \__,_|\__\___|_|\___/ \___|_|\_\ v1.0.0

Advanced Password Cracker
Github : https://github.com/GilbertEnevoldsen

Initializing brutelock - v1.0.0 with python 3.x
""")

# Getting system arguments and configuring the settings

if '-m' in sys.argv:

    hashing = sys.argv[sys.argv.index('-m') + 1].lower()

    if hashing != 'sha1' and hashing != 'sha224' and  hashing != 'sha256' and  hashing != 'sha384' and  hashing != 'sha512' and  hashing != 'blake2b' and  hashing != 'blake2s' and hashing != 'sha3_224' and hashing != 'sha3_256' and hashing != 'sha3_384' and hashing != 'sha3_512' and hashing != 'md5':
    
        raise ValueError('invalid hashing method specified\n(sha1 / sha224 / sha256 / sha384 / sha512 / blake2b / blake2s / sha3_224 / sha3_256 / sha3_384 / sha3_512 / md5)')

else:

    raise ValueError('no hashing method specified (-m <method>)')

if '-f' in sys.argv:

    hashed_password_file = sys.argv[sys.argv.index('-f') + 1].lower()

else:

    raise ValueError('no password file specified (-f <file>)')

if '--ml' in sys.argv:

    minimum_password_length = int(sys.argv[sys.argv.index('--ml') + 1])

else:

    minimum_password_length = 1

character_pool = 4

if '--charpool' in sys.argv:

    character_pool = int(sys.argv[sys.argv.index('--charpool') + 1])

    if character_pool < 1 or character_pool > 5:

        raise ValueError('invalid character pool (--charpool <number>)\n(1. lowercase / 2. lowercase and digits / 3. lowercase and uppercase / 4. lowercase and uppercase and digits / 5. lowercase and uppercase and digits and special characters)')

if '--max' in sys.argv:

    max_cracks = int(sys.argv[sys.argv.index('--max') + 1])

wordlist_file = ''    

if '--wordlist' in sys.argv:

    wordlist_file = sys.argv[sys.argv.index('--wordlist') + 1]

if '-out' == sys.argv[-2]:

    save_file = sys.argv[-1]

else:

    raise ValueError('invalid save file (end: -out <file>)')

# Loading files (Password list / Word list)
# Configuring loading dependinng on filetype (.txt / .json)

print('\n[+] Loading neccesary files...')

print(f'\n - Password File : {hashed_password_file} : LOADING', end='\r')

if hashed_password_file.split('.')[-1] == 'json':

    with open(hashed_password_file, 'r') as file:
        file = file.read()
        hashed_list = json.loads(file)

else:

    with open(hashed_password_file) as file:
        hashed_list = file.read().split('\n')

print(f' - Password File : {hashed_password_file} : DONE   ')

wordlist = []

if wordlist_file != '':

    print(f' - Wordlist File : {wordlist_file} : LOADING', end='\r')

    if wordlist_file.split('.')[-1] == 'json':
        with open(wordlist_file, 'r') as file:
            file = file.read()
            wordlist = json.loads(file)
    else:

        with open(wordlist_file, 'r') as file:
            wordlist = file.read().split('\n')

    print(f' - Wordlist File : {wordlist_file} : DONE   ')

# Displaying config information

hashing_methods = {
    "sha1": "SHA1",
    "sha224": "SHA224",
    "sha256": "SHA256",
    "sha384": "SHA384",
    "sha512": "SHA512",
    "blake2b": "BLAKE2b",
    "blake2s": "BLAKE2s",
    "sha3-224": "SHA3-224",
    "sha3-256": "SHA3-256",
    "sha3-384": "SHA3-384",
    "sha3-512": "SHA3-512",
    "md5": "MD5"
}

character_pools = {
    "1": "low",
    "2": "low:dig",
    "3": "low:upp",
    "4": "low:upp:dig",
    "5": "low:upp:dig:spe"
}

print('\n')
print(f'| Passwords.........: /{hashed_password_file}')
print(f'| Hashes............: {len(hashed_list)} hashes, {len("".join(hashed_list))} bytes')
print(f'| HashingMethod.....: {hashing} : {hashing_methods[str(hashing)]}')
print(f'| CharacterPool.....: {character_pool} : {character_pools[str(character_pool)]}')
print(f'| MinimumLength.....: {minimum_password_length}')

if wordlist_file != '':

    print(f'| Wordlist..........: /{wordlist_file}')
    print(f'| Words.............: {len(wordlist)} words, {len("".join(wordlist))} bytes')

else:

    print(f'| Wordlist..........: - / - / -')
    print(f'| Words.............: - / - / -')

# Creating function for wordlist brute forcing

def wordlist_function(method):
    
    global_time_start = time.time()
    
    time_start =  time.time()
    
    times = []

    try:

        if len(cracked_list) == len(hashed_list) or len(cracked_list) >= max_cracks:

            return

    except:
        
        if len(cracked_list) == len(hashed_list):

            return

    for plain_word_index in range(len(wordlist)):

        # Hashing depending on the configured method

        if method == 'sha1': hashed_attempt = hashlib.sha1(bytes(wordlist[plain_word_index], 'utf-8')).hexdigest()
        elif method == 'sha224': hashed_attempt = hashlib.sha224(bytes(wordlist[plain_word_index], 'utf-8')).hexdigest()
        elif method == 'sha256': hashed_attempt = hashlib.sha256(bytes(wordlist[plain_word_index], 'utf-8')).hexdigest()
        elif method == 'sha384': hashed_attempt = hashlib.sha384(bytes(wordlist[plain_word_index], 'utf-8')).hexdigest()
        elif method == 'sha512': hashed_attempt = hashlib.sha512(bytes(wordlist[plain_word_index], 'utf-8')).hexdigest()
        elif method == 'blake2b': hashed_attempt = hashlib.blake2b(bytes(wordlist[plain_word_index], 'utf-8')).hexdigest()
        elif method == 'blake2s': hashed_attempt = hashlib.blake2s(bytes(wordlist[plain_word_index], 'utf-8')).hexdigest()
        elif method == 'sha3_224': hashed_attempt = hashlib.sha3_224(bytes(wordlist[plain_word_index], 'utf-8')).hexdigest()
        elif method == 'sha3_256': hashed_attempt = hashlib.sha3_256(bytes(wordlist[plain_word_index], 'utf-8')).hexdigest()
        elif method == 'sha3_384': hashed_attempt = hashlib.sha3_384(bytes(wordlist[plain_word_index], 'utf-8')).hexdigest()
        elif method == 'sha3_512': hashed_attempt = hashlib.sha3_512(bytes(wordlist[plain_word_index], 'utf-8')).hexdigest()
        elif method == 'md5': hashed_attempt = hashlib.md5(bytes(wordlist[plain_word_index], 'utf-8')).hexdigest()
        
        times.append(time.time() - time_start)
            
        time_start =  time.time()
        
        if len(times) > 1000:
            
            times.pop(0)

        if len(wordlist[plain_word_index]) > 32:
    
            print(f'Iterating words ~ time {round(time.time() - global_time_start)}s : avg time per/1000 i ({round(sum(times), 2)}s) : status: {round(plain_word_index / len(wordlist) * 100)}% - testing hash for plain ({"".join(wordlist[plain_word_index][0:31])})', end='\r')

        else:

            print(f'Iterating words ~ time {round(time.time() - global_time_start)}s : avg time per/1000 i ({round(sum(times), 2)}s) : status: {round(plain_word_index / len(wordlist) * 100)}% - testing hash for plain ({"".join(wordlist[plain_word_index])})                                ', end='\r')

        for hashed_password in hashed_list:

            if hashed_attempt == hashed_password and wordlist[plain_word_index] not in cracked_list:

                print(f'{hashed_attempt}:{wordlist[plain_word_index]} - {round(time.time() - global_time_start)}s                                                                                                                                                      ')

                # Writing cracked passwords to file
                
                if save_file.split('.')[-1] == 'json':

                    nfile = False

                    try:

                        with open(save_file, 'r') as f:
                            f_data = f.read()
                            if len(f_data) == 0:
                                nfile = True

                    except:

                        nfile = True

                    if nfile == False:

                        with open(save_file, 'w') as f:
                            f.write(f_data[0:len(f_data)-2])

                    cracked_list.append(wordlist[plain_word_index])

                    with open(save_file, 'a') as f:

                        if nfile == True:

                            f.write('[\n' + json.dumps({"plain": wordlist[plain_word_index], "hash": hashed_attempt, "method": method}) + '\n]')

                        else:

                            f.write(',\n' + json.dumps({"plain": wordlist[plain_word_index], "hash": hashed_attempt, "method": method}) + '\n]')

                    try:

                        if len(cracked_list) == len(hashed_list) or len(cracked_list) >= max_cracks:

                            return

                    except:
                        
                        if len(cracked_list) == len(hashed_list):

                            return

                else:

                    with open(save_file, 'a') as f:

                        f.write(f'{hashed_attempt}:{"".join(wordlist[plain_word_index])}\n')

                    try:

                        if len(cracked_list) == len(hashed_list) or len(cracked_list) >= max_cracks:

                            return

                    except:
                        
                        if len(cracked_list) == len(hashed_list):

                            return

# Creating function for bruteforcing

def bruteforce(method, min_length=1, max_length=64):
    
    global_time_start = time.time()
    
    time_start =  time.time()
    
    times = []

    try:

        if len(cracked_list) == len(hashed_list) or len(cracked_list) >= max_cracks:

            return

    except:
        
        if len(cracked_list) == len(hashed_list):

            return

    # Creadting configured character pool

    if character_pool == 1: chars = string.ascii_lowercase
    if character_pool == 2: chars = string.ascii_lowercase + string.digits
    if character_pool == 3: chars = string.ascii_letters
    if character_pool == 4: chars = string.ascii_letters + string.digits
    if character_pool == 5: chars = string.ascii_letters + string.digits + """ .,:;-_=+*~^'"()[]{}<>/\|!¤£$&?#%@"""

    for password_length in range(min_length, max_length):

        for plain in itertools.product(chars, repeat=password_length):

            # Hashing depending on the configured method

            if method == 'sha1': hashed_attempt = hashlib.sha1(bytes(''.join(plain), 'utf-8')).hexdigest()
            elif method == 'sha224': hashed_attempt = hashlib.sha224(bytes(''.join(plain), 'utf-8')).hexdigest()
            elif method == 'sha256': hashed_attempt = hashlib.sha256(bytes(''.join(plain), 'utf-8')).hexdigest()
            elif method == 'sha384': hashed_attempt = hashlib.sha384(bytes(''.join(plain), 'utf-8')).hexdigest()
            elif method == 'sha512': hashed_attempt = hashlib.sha512(bytes(''.join(plain), 'utf-8')).hexdigest()
            elif method == 'blake2b': hashed_attempt = hashlib.blake2b(bytes(''.join(plain), 'utf-8')).hexdigest()
            elif method == 'blake2s': hashed_attempt = hashlib.blake2s(bytes(''.join(plain), 'utf-8')).hexdigest()
            elif method == 'sha3_224': hashed_attempt = hashlib.sha3_224(bytes(''.join(plain), 'utf-8')).hexdigest()
            elif method == 'sha3_256': hashed_attempt = hashlib.sha3_256(bytes(''.join(plain), 'utf-8')).hexdigest()
            elif method == 'sha3_384': hashed_attempt = hashlib.sha3_384(bytes(''.join(plain), 'utf-8')).hexdigest()
            elif method == 'sha3_512': hashed_attempt = hashlib.sha3_512(bytes(''.join(plain), 'utf-8')).hexdigest()
            elif method == 'md5': hashed_attempt = hashlib.md5(bytes(plain, 'utf-8')).hexdigest()
            
            times.append(time.time() - time_start)
            
            time_start =  time.time()
            
            if len(times) > 1000:
                
                times.pop(0)

            print(f'Iterating ~ time {round(time.time() - global_time_start)}s : avg time p/1000 i ({round(sum(times), 2)}s) - testing hash for plain ({"".join(plain)})          ', end='\r')

            for hashed_password in hashed_list:

                if hashed_attempt == hashed_password and "".join(plain) not in cracked_list:

                    print(f'{hashed_attempt}:{"".join(plain)} - {round(time.time() - global_time_start)}s                                                                                                                                                      ')

                    # Writing cracked passwords to file

                    if save_file.split('.')[-1] == 'json':

                        nfile = False

                        try:

                            with open(save_file, 'r') as f:
                                f_data = f.read()
                                if len(f_data) == 0:
                                    nfile = True
                        except:

                            nfile = True

                        if nfile == False:

                            with open(save_file, 'w') as f:
                                f.write(f_data[0:len(f_data)-2])

                        cracked_list.append(plain)

                        with open(save_file, 'a') as f:

                            if nfile == True:

                                f.write('[\n' + json.dumps({"plain": ''.join(plain), "hash": hashed_attempt, "method": method}) + '\n]')
                            else:

                                f.write(',\n' + json.dumps({"plain": ''.join(plain), "hash": hashed_attempt, "method": method}) + '\n]')

                        try:

                            if len(cracked_list) == len(hashed_list) or len(cracked_list) >= max_cracks:

                                return

                        except:
                            
                            if len(cracked_list) == len(hashed_list):

                                return
                        
                    else:
    
                        with open(save_file, 'a') as f:

                            f.write(f'{hashed_attempt}:{"".join(plain)}\n')

                        try:

                            if len(cracked_list) == len(hashed_list) or len(cracked_list) >= max_cracks:

                                return

                        except:
                            
                            if len(cracked_list) == len(hashed_list):

                                return

# Running

cracked_list = []

print()

if len(wordlist) != 0:

    print(f'\n[+] Iterating through wordlist <{wordlist_file}> ~ :\n')

    wordlist_function(hashing)
    print('                                                                                                                                                                                                        ')

print(f'\n[+] Brute forcing every combination ~ :\n')

bruteforce(hashing, int(minimum_password_length))