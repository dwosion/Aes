#!/usr/bin/python3   
#Input format:
#   plain text: abcdef0123456789
#   cipher text: fc 8b e6 a8 05 db 08 24 c1 11 04 6d 75 76 f8 17
#   cipher key: 0123456789abcdef
#Output format:
#   plain text: a b c d e f 0 1 2 3 4 5 6 7 8 9
#   cipher test: fc 8b e6 a8 05 db 08 24 c1 11 04 6d 75 76 f8 17 

import Aes

while True:   
    operation = input('Please choose cihper(c) or decipher(d): ')
    if operation == 'c':
        while True:
            plainText = input('Enter the plaintext string: ')
            if len(plainText) != 16:
                print("The length of the string is not 16 ({})".format(len(plainText)))
                continue
            else:
                while True:
                    keyLength = input('Enter the key length(16, 24, 32): ')
                    if keyLength == "16":
                        while True:
                            cipherKey = input('Enter the cipher key: ')
                            if len(cipherKey) != 16:
                                print('The length of cipher key is not 16({})'.format(len(cipherKey)))
                                continue
                            else:
                                aesCipher = Aes.AesCore('128', list(plainText), list(cipherKey))
                                resCiText = aesCipher.Cipher()
                                aesCipher.FormatPrint('Cipher text', resCiText)
                                exit(0)
                    elif keyLength == "24":
                        while True:
                            cipherKey = input('Enter the cipher key: ')                   
                            if len(cipherKey) != 24:
                                print('The length of cipher key is not 24({})'.format(len(cipherKey)))
                                continue
                            else:
                                aesCipher = Aes.AesCore('192', list(plainText), list(cipherKey))
                                resCiText = aesCipher.Cipher()
                                aesCipher.FormatPrint('Cipher text', resCiText)
                                exit()
                    elif keyLength == "32":
                        while True:
                            cipherKey = input('Enter the cipher key: ')                   
                            if len(cipherKey) != 32:
                                print('The length of cipher key is not 32({})'.format(len(cipherKey)))
                                continue
                            else:
                                aesCipher = Aes.AesCore('256', list(plainText), list(cipherKey))
                                resCiText = aesCipher.Cipher()
                                aesCipher.FormatPrint('Cipher text', resCiText)
                                exit()
                    else:
                        print('The key length is not available.')
                        continue
    elif operation == 'd':
        while True:
            cipherTextString = input('Enter the cipher text string: ')
            cipherText = cipherTextString.split()
            if len(cipherText) != 16:
                print("The length of the string is not 16 ({})".format(len(cipherText)))
                continue
            else:
                while True:
                    keyLength = input('Enter the key length(16, 24, 32): ')
                    if keyLength == "16":
                        while True:
                            cipherKey = input('Enter the cipher key: ')
                            if len(cipherKey) != 16:
                                print('The length of cipher key is not 16({})'.format(len(cipherKey)))
                                continue
                            else:
                                aesDecipher = Aes.AesCore('128', cipherText, list(cipherKey))
                                resDeciText = aesDecipher.InvCipher()
                                print("Plain text: {}".format(resDeciText))
                                exit(0)
                    elif keyLength == "24":
                        while True:
                            cipherKey = input('Enter the cipher key: ')                   
                            if len(cipherKey) != 24:
                                print('The length of cipher key is not 24({})'.format(len(cipherKey)))
                                continue
                            else:
                                aesDecipher = Aes.AesCore('192', cipherText, list(cipherKey))
                                resDeciText = aesDecipher.InvCipher()
                                print("Plain text: {}".format(resDeciText))
                                exit()
                    elif keyLength == "32":
                        while True:
                            cipherKey = input('Enter the cipher key: ')                   
                            if len(cipherKey) != 32:
                                print('The length of cipher key is not 32({})'.format(len(cipherKey)))
                                continue
                            else:
                                aesDecipher = Aes.AesCore('256', cipherText, list(cipherKey))
                                resDeciText = aesDecipher.InvCipher()
                                print("Plain text: {}".format(resDeciText))
                                exit()
                    else:
                        print('The key length is not available.')
                        continue
    else:
        print("Please input 'c' or 'd'!")
        continue    


