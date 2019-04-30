# Aes
1. Introduction
This is a simple python implementation of AES(Advanced Encryption Standard). This implementation follows the thought of the standard pressed by the NIST. For more information of the details about the algorithm, please refer to the wiki or the NIST.FIPS.197.
2. Functions
The file, 'Aes.py', defines a class called AesCore, which contaions all the attributes and methods. The data type of list in python is used to represent the state array and key word. The organization of the nested lists is indexed by column. The initialization of this class needs three input arguments, which are numBit, userText and keyWord. The numBit is responsible for choosing aes-128, aes-192 or aes-256. The usetText means the plain text that is to be ciphered or the cipher text that is to be deciphered. The keyWord is the cipher key used in the cipher or decipher process. The main methods of the class are the Cipher and InvCipher functions. There is also a main function for testing the algorithm, especially for the keyExpansion, the cipher and the decipher modules. The main function reproduces all the testing results of the NIST.FIPS.197.

The file, 'Test.py', is an application of the defined class. It takes inputs from the users according to the printed words and outputs the corresponding results.
3. Others
This implementaion is written for understanding the coputimg process of the Aes algorithm, so the code is a bit rough and there is no 
additional optimization skills. The objective is for unserstanding the paragraph of 'Advanced FPGA Design: Architecture, Implementaion, and Optimization', which was written by Steve Kilts. There are definitely many differences between software implemention and hardware designs for the same algorithm.
