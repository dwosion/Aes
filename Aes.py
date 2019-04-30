#!/usr/bin/python3
#-*-coding:utf-8-*-

"""
The MIT License (MIT)

Copyright (c) 2019 Dwosion

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Author: Dwosion <dwosion@hotmail.com>

"""

class AesCore(object):
    """ Aescore class realizes the cipher and the decipher functions. 
        
        This class is capable of aes-128,
        aes-192 and aes-256. It has three inputs, bitNum, keyWord and userText. All of them are in 
        a list of string style. However, those method operations need an ascii sytle. Thus, a transformation must be
        needed before theoperations for both the text and the key.

        Args:
            bitNum: 128, 192, 256
            userText: ['a'*16]' for cipher, or ['0a'*16] for 
            keyWord: ['a'*16]
        Returns:
            Cipher(): A list of cipher text in the form of number, [109,245, ...].
            InvCipher(): A string of plain text, '0 1 2 3 4 ...' 
    """

    # S-box for the subsitution values of the byte
    SBox = ((0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,),
            (0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,),
            (0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,),
            (0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,),
            (0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52 ,0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,),
            (0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,),
            (0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,),
            (0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,),
            (0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,),
            (0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,),
            (0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,),
            (0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,),
            (0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,),
            (0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,),
            (0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,),
            (0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,))
    
    #Inverse S-box valuse for the subsitution of the byte
    InvSBox = ((0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,),
               (0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,),
               (0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,),
               (0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,),
               (0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,),
               (0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,),
               (0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,),
               (0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,),
               (0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,),
               (0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,),
               (0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,),
               (0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,),
               (0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,),
               (0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,),
               (0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,),
               (0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,))
    

    def __init__(self, bitNum, userText, keyWord):
        """Initialize input arguments.

           Args:
               bitNum: Select the key length of the aes from aes-128, aes-192, aes-256.
               userText: The plaintext or the ciphertext with the length of 16 (16*8 bits).
               keyWord: The cipher key with the length of 16 (16*8 bits). 
        """
        self.bitNum = bitNum
        aesList = {'128' : {'numNk' : 4, 'numNb' : 4, 'numNr' : 10},
                   '192' : {'numNk' : 6, 'numNb' : 4, 'numNr' : 12},
                   '256' : {'numNk' : 8, 'numNb' : 4, 'numNr' : 14}}        
        self.Nk = aesList[self.bitNum]['numNk']  # The word number of the key
        self.Nb = aesList[self.bitNum]['numNb']  # The block number of the text
        self.Nr = aesList[self.bitNum]['numNr']  # The round number of the cipher
        self.userText = userText
        self.keyWord = keyWord


    def StringToAscii(self, stringList):
        """ List transformation from string to ascii.

            This function transform the type of elements in a list from string to ascii.

            Args:
                stringList: A list consists of string with the list length of 16.

            Returns:
                asciiList: A list consistd of ascii with the list length of 16. 
        """

        asciiList = [0]*len(stringList)
        for i in range(len(stringList)):
            asciiList[i] = ord(stringList[i])
        return asciiList

    
    def AsciiToString(self, asciiList):
        """ List transformation from string to ascii.

            This function transform the type of elements in a list from string to ascii.

            Args:
                stringList: A list consists of string with the list length of 16.

            Returns:
                asciiList: A list consistd of ascii with the list length of 16. 
        """ 
        stringList = [0]*len(asciiList)
        for i in range(len(asciiList)):
            stringList[i] = chr(asciiList[i])
        return stringList

    def StringToNumber(self, stringList):
        """Transform a character to number('a'-> 10)."""
        numberList = [0]*len(stringList)
        for i in range(len(stringList)):
            numberList[i] = int(stringList[i], 16)
        return numberList


    def ListToArray(self, stateList):
        """ Transform  a list to an array.

            The list has 16 elements. And the the size of the array is 4*Nb(eg. 4*4). The convertion 
            is applied indexed by column first.

            Args: 
                stateList: A List of bytes with the length of 16.
            
            Returns:
                stateArray: An array of bytes in 4*4.        

        """
        stateArray = [[0]*4 for i in range(self.Nb)]
        for i in range(self.Nb):
            for j in range(4):
                stateArray[i][j] = stateList[4*i+j]
        return stateArray

    
    def ArrayToList(self, stateArray):
        """ Transform  an array to a list.

            The list has 16 elements. And the the size of the array is 4*Nb(eg. 4*4). The convertion 
            is applied indexed by column first.

            Args:
                stateArray: An array of bytes in 4*4.

            Returns:  
                stateList: A List of bytes with the length of 16.
        """
        stateList = [0]*4*self.Nb
        for i in range(self.Nb):
            for j in range(4):
                stateList[4*i+j] = stateArray[i][j]
        return stateList


    def SubWord(self, aWord):
        """ Key word subsitition using the sbox.

            The key word is has four bytes, and each byte applies the sbox substiturion.
            
            Args:
                aWord: A key word represented as a list of four bytes of the key schedule.
            
            Returns:
                aWord: A key word represented as a list after sbox word subsitution of four bytes.
        """
        for i in range(4):
            rowNum = (aWord[i] & 0xf0) >> 4
            colNum = aWord[i] & 0x0f
            aWord[i] = self.SBox[rowNum][colNum]
        return aWord


    def RotWord(self, aWord):
        """ A key word of the key schedule is represented as a list of four bytes. The function 
            implements a circular left shift for each byte.
        """
        aWord = aWord[1:]+aWord[:1]
        return aWord


    def XMul(self, aByte):
        """ A binary polynomial multiplies with the polynomial x.

            This function implement the  polynomial multiplication with the polynomial x (also as 
            {0x02}).

            Args:
                aByte: A byte which represents the polynomial.
            
            Returns:
                aByte: A byte which is the result of the multipication.
        """
        aByte = aByte & 0Xff  # Restricted to a byte
        bitFlag = (aByte & 0X80)
        if bitFlag:
            aByte = (aByte << 1) ^ 0x1b
            return aByte & 0xff
        else:
            return aByte << 1 & 0xff


    def XMulRec(self, n):
        """ A recursive implementation of xmul.
            
            This function is on the basis of {x^i, 0x00, 0x00, 0x00}.

            Args:
                n: The number of recursion, that is x^i.
            
            Returns:
                aByte: The value of x^i.
        """
        if n == 1:
            return 0x02
        else:
            return self.XMul(self.XMulRec(n-1))


    def RConGen(self):
        """This function generate the round const for the key scedule process."""
        RoundCon = [[0]*4 for i in range(self.Nr)]
        for i in range(0, self.Nr):
            if i == 0:
                RoundCon[i][0] = 0x01
            else:
                RoundCon[i][0] = self.XMulRec(i)

        for i in range(0, self.Nr-1):
            for j in range(1, 3):
                RoundCon[i][j] = 0x00
        return RoundCon


    def KeyExpansion(self):
        """ KeyExpansion performs a routine to generate a key schedule.

            The process of aes-128 and aes-192 is same, but that of aes-256 is a bit
            different. The key expansion is executed in the word fashion.

            Returns:
                keySchedule: The key schedule with the length of Nb*(Nr+1). Every element 
                is a list consisting of four terms (eg. bytes) to express a word.
        """
        keySchedule = [[0]*4 for i in range(self.Nb*(self.Nr+1))]
        RoundCon = self.RConGen()
        keyWordAscii = self.StringToAscii(self.keyWord).copy()    #For application
        #keyWordAscii = self.keyWord.copy()                       #For test
        for i in range(self.Nk):
            keySchedule[i] = [keyWordAscii[4*i], keyWordAscii[4*i+1], keyWordAscii[4*i+2], keyWordAscii[4*i+3]]

        for i in range(self.Nk, self.Nb*(self.Nr+1)):
            tempWord = keySchedule[i-1].copy()
            if (i%self.Nk == 0):
                tempWord = self.SubWord(self.RotWord(tempWord))
                for j in range(4):
                    tempWord[j] = tempWord[j] ^ RoundCon[i//self.Nk-1][j]
            elif(self.Nk > 6 and i%self.Nk == 4):
                tempWord = self.SubWord(tempWord)               
            for k in range(4):
                keySchedule[i][k] = (keySchedule[i-self.Nk][k]) ^ tempWord[k]
        return keySchedule        


    def AddRoundKey(self, stateArray, fWord):
        """ Each column of the state array applies XOR with the corresponding round key

            Every stateArray correspons to four words of the key schudule. The argument, 
            fword, is a list of four words of the key scedule.        
        """
        for i in range(self.Nb):
            for j in range(4):
                stateArray[i][j] = stateArray[i][j] ^ fWord[i][j]
        return


    def SubBytes(self, stateArray):
        """The SubBytes implemements the subsitution on each byte of the state array using sbox."""
        for i in range(4):
            for j in range(self.Nb):
                rowNum = (stateArray[i][j] & 0xf0) >> 4
                colNum = (stateArray[i][j] & 0x0f)
                stateArray[i][j] = self.SBox[rowNum][colNum]
        return


    def InvSubBytes(self, stateArray):
        """The InvShiftBytes implements the substittion on each byte of the state array using InvSBox."""
        for i in range(4):
            for j in range(self.Nb):
                rowNum = (stateArray[i][j] & 0xf0) >> 4
                colNum = (stateArray[i][j] & 0x0f)
                stateArray[i][j] = self.InvSBox[rowNum][colNum]
        return

    def ArrayTrans(self,anArray):
        """The array indexed by column is transformed to an array indexed by row"""
        numRow = len(anArray)
        numCol = len(anArray[0])
        resArray = [[0]*numCol for i in range(numRow)]
        for i in range(numRow):
            for j in range(numCol):
                resArray[j][i] = anArray[i][j]
        return resArray
        

    def ShiftRows(self,stateArray):
        """The ShiftRows implements the cyclical shift of the rows of state."""
        resArray = self.ArrayTrans(stateArray)
        for (i, j) in ((0, 0), (1, 1), (2, 2), (3, 3)):
            resArray[i] = resArray[i][j:] + resArray[i][:j] 
        stateArray.clear()
        stateArray.extend(self.ArrayTrans(resArray)[i] for i in range(4)) 
        return    
         


    def InvShiftRows(self, stateArray):
        """The InvShiftRows implements the cyclical shift of the rows of state."""
        resArray = self.ArrayTrans(stateArray)
        for (i, j) in ((0, 0), (1, 1), (2, 2), (3, 3)):
            resArray[i] = resArray[i][-j:] + resArray[i][:-j]
        stateArray.clear()
        stateArray.extend(self.ArrayTrans(resArray)[i] for i in range(4)) 
        return
      

    def ByteMul(self, firstByte, secondByte):
        """Define the function that the binay polynomial multiplication with another one."""
        resByte = 0x00
        for i in range(8):
            bitFlag = secondByte & 0x01
            if bitFlag:
                tempByte = firstByte
                for j in range(i):
                    tempByte = self.XMul(tempByte)
                resByte = resByte ^ tempByte
            secondByte = secondByte >> 1
        return resByte


    def MixColumns(self, stateArray):
        """Multiply the sate array with the predfined mixcolumns matrix on the basis of the polynomials over GF(2^8)."""
        tempArray = self.ArrayTrans(stateArray)
        for i in range(self.Nb):
            stateArray[0][i] = self.ByteMul(tempArray[0][i], 0x02) ^ self.ByteMul(tempArray[1][i], 0x03) ^ tempArray[2][i] ^ tempArray[3][i]
            stateArray[1][i] = tempArray[0][i] ^ self.ByteMul(tempArray[1][i], 0x02) ^ self.ByteMul(tempArray[2][i], 0x03) ^ tempArray[3][i]
            stateArray[2][i] = tempArray[0][i] ^ tempArray[1][i] ^ self.ByteMul(tempArray[2][i], 0x02) ^ self.ByteMul(tempArray[3][i], 0x03)
            stateArray[3][i] = self.ByteMul(tempArray[0][i], 0x03) ^ tempArray[1][i] ^ tempArray[2][i] ^ self.ByteMul(tempArray[3][i], 0x02)
        stateArray[:] =self.ArrayTrans(stateArray)[:]
        return
        


    def InvMixColumns(self, stateArray):
        """Multiply the state array with the predifine inverse mixcolumns matrix on the basis of the polynomials over GF(2^8)."""
        tempArray = self.ArrayTrans(stateArray)
        for i in range(self.Nb):
            stateArray[0][i] = self.ByteMul(tempArray[0][i], 0x0e) ^ self.ByteMul(tempArray[1][i], 0x0b) ^ self.ByteMul(tempArray[2][i], 0x0d) ^ self.ByteMul(tempArray[3][i], 0x09)
            stateArray[1][i] = self.ByteMul(tempArray[0][i], 0x09) ^ self.ByteMul(tempArray[1][i], 0x0e) ^ self.ByteMul(tempArray[2][i], 0x0b) ^ self.ByteMul(tempArray[3][i], 0x0d)
            stateArray[2][i] = self.ByteMul(tempArray[0][i], 0x0d) ^ self.ByteMul(tempArray[1][i], 0x09) ^ self.ByteMul(tempArray[2][i], 0x0e) ^ self.ByteMul(tempArray[3][i], 0x0b)
            stateArray[3][i] = self.ByteMul(tempArray[0][i], 0x0b) ^ self.ByteMul(tempArray[1][i], 0x0d) ^ self.ByteMul(tempArray[2][i], 0x09) ^ self.ByteMul(tempArray[3][i], 0x0e)
        stateArray[:] =self.ArrayTrans(stateArray)[:]
        return   

    
    def FormatPrint(self, aStringName, aList):
        """A list of decimal number is printed  in hexdecimal."""
        aCharList = ' '.join(list(format(x, '02x') for x in aList))
        print("{}: {}".format(aStringName, aCharList), end='\n')
    
    def ArrayPrint(self, anArrayName, anArray):
        """Print a nested number list of (array) in a list form."""
        arrayOut = []
        for i in range(self.Nb):
            arrayOut.extend(anArray[i])
        self.FormatPrint(anArrayName, arrayOut)
    
    def Cipher(self):
        """ The Cipher process consists of four subprocesses, which are subbytes, shifirows, 
            mixcolumns and addroundkeys. In this case, it accepts string usertext and returns 
            the cipher text in the hexdecimal style.
        """ 
        keySchedule = self.KeyExpansion()
        """
        for i in range(self.Nr+1):
            keyOut = []
            for j in range(self.Nb):
                keyOut.extend(keySchedule[i*4+j]) 
            self.FormatPrint("keySchedule[{}]".format(i), keyOut)
        """ 
                
        asciiList = self.StringToAscii(self.userText)   #For application
        stateArray = self.ListToArray(asciiList)        #For application
        #stateArray = self.ListToArray(self.userText)   #For test
        #self.ArrayPrint("stateArrayInput[00]", stateArray)
        self.AddRoundKey(stateArray, keySchedule[0:self.Nb])
        #self.ArrayPrint("stateArrayStart[00]", stateArray)

        for i in range(1, self.Nr):
            self.SubBytes(stateArray)
            #self.ArrayPrint("stateArrayS_Box[{:02}]".format(i), stateArray)
            self.ShiftRows(stateArray)
            #self.ArrayPrint("stateArrayS_Row[{:02}]".format(i), stateArray)
            self.MixColumns(stateArray)
            #self.ArrayPrint("stateArrayM_Col[{:02}]".format(i), stateArray)
            self.AddRoundKey(stateArray, keySchedule[i*self.Nb:(i+1)*self.Nb])
            #self.ArrayPrint("stateArrayStart[{:02}]".format(i+1), stateArray)
        self.SubBytes(stateArray)
        #self.ArrayPrint("stateArrayS_Box[{}]".format(self.Nr), stateArray)
        self.ShiftRows(stateArray)
        #self.ArrayPrint("stateArrayS_Row[{}]".format(self.Nr), stateArray)
        self.AddRoundKey(stateArray, keySchedule[self.Nr*self.Nb:(self.Nr+1)*self.Nb])
        #self.ArrayPrint("stateArrayOutput[{}]".format(self.Nr), stateArray)
        stateList = self.ArrayToList(stateArray)
        return stateList   
        

    def InvCipher(self):
        """ This inverse cipher process is implemented in reverse order of the cipher. In this case, it 
            accepts the hexdecimal userText and the string.
        """
        keySchedule = self.KeyExpansion()
        #stateArray = self.ListToArray(self.userText)                       #For test
        stateArray = self.ListToArray(self.StringToNumber(self.userText))   #For application
        #self.ArrayPrint("InverseStateArrayInput[00]", stateArray)
        self.AddRoundKey(stateArray, keySchedule[self.Nr*self.Nb:(self.Nr+1)*self.Nb])
        #self.ArrayPrint("InverseStateArrayStart[00]", stateArray)

        for i in range(self.Nr-1, 0, -1):
            self.InvShiftRows(stateArray)
            #self.ArrayPrint("InverseStateArrayS_Row[{:02}]".format(self.Nr-i), stateArray)
            self.InvSubBytes(stateArray)
            #self.ArrayPrint("InverseStateArrayS_Box[{:02}]".format(self.Nr-i), stateArray)
            self.AddRoundKey(stateArray, keySchedule[i*self.Nb:(i+1)*self.Nb])
            #self.ArrayPrint("InverseStateArrayS_Add[{:02}]".format(self.Nr-i), stateArray)
            self.InvMixColumns(stateArray)
            #self.ArrayPrint("InverseStateArrayStart[{:02}]".format(self.Nr-i+1), stateArray)
        
        self.InvShiftRows(stateArray)
        #self.ArrayPrint("InverseStateArrayS_Row[{}]".format(self.Nr), stateArray)
        self.InvSubBytes(stateArray)
        #self.ArrayPrint("InverseStateArrayS_Box[{}]".format(self.Nr), stateArray)
        self.AddRoundKey(stateArray, keySchedule[0:self.Nb])
        #self.ArrayPrint("InverseStateArrayOutput", stateArray)

        stateList = self.ArrayToList(stateArray)
        stringList = ' '.join(self.AsciiToString(stateList))  #For application
        return stringList                                     #For application
        #return stateList                                       #For test

def main():

    #This section is for testing KeyExpansion. In this case, the StringToAscii in KeyExpansion needs to be  
    # annotated first.
    testKey_128 = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]
    testKey_192 = [0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
                   0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b]
    testKey_256 = [0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                   0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4]
    testText_All = [0]*16

    keyTest_128 = AesCore('128', testText_All, testKey_128)
    print("KeyExpansion Test for 128-bit key", end='\n')
    keyTest_128.FormatPrint("Cipher Key", testKey_128)    
    keySche_128 = keyTest_128.KeyExpansion()
    print("The result of KeyExpansion:", end='\n')
    for i in range(len(keySche_128)):
        keyTest_128.FormatPrint("KeySchedule[{:02}]".format(i),keySche_128[i])
    
    keyTest_192 = AesCore('192', testText_All, testKey_192)
    print("KeyExpansion Test for 192-bit key", end='\n')
    keyTest_192.FormatPrint("Cipher Key", testKey_192)    
    keySche_192 = keyTest_192.KeyExpansion()
    print("The result of KeyExpansion:", end='\n')
    for i in range(len(keySche_192)):
        keyTest_192.FormatPrint("KeySchedule[{:02}]".format(i),keySche_192[i])

    keyTest_256 = AesCore('256', testText_All, testKey_256)
    print("KeyExpansion Test for 256-bit key", end='\n')
    keyTest_256.FormatPrint("Cipher Key", testKey_256)    
    keySche_256 = keyTest_256.KeyExpansion()
    print("The result of KeyExpansion:", end='\n')
    for i in range(len(keySche_256)):
        keyTest_256.FormatPrint("KeySchedule[{:02}]".format(i),keySche_256[i])

    #Cipher using Aes-128
    plainText_128 = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
    cipherKey_128 = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]
    
    #Cipher using Aes-192
    plainText_192 = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
    cipherKey_192 = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17]

    #Cipher using Aes-256
    plainText_256 = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
    cipherKey_256 = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f]
    
    #This section is for testing cipher and decipher. In this case, the StringToAscii and 
    # AsciiToString in Cipher and decipher needs to be annotated first.
    aes_128 = AesCore('128', plainText_128, cipherKey_128)
    print("Aes-128:", end='\n')
    aes_128.FormatPrint("Plain Text", plainText_128)
    aes_128.FormatPrint("Cipher Key", cipherKey_128)
    print("Begin Cipher ...", end='\n')
    cipherText_128 = aes_128.Cipher()
    aes_128.FormatPrint("Cipher Text", cipherText_128)
    print("Begin DeCipher ...", end='\n')
    recAes_128 = AesCore('128', cipherText_128, cipherKey_128)
    recPlainText_128 = recAes_128.InvCipher()
    aes_128.FormatPrint("Recoveried Plain Text", recPlainText_128)

    aes_192 = AesCore('192', plainText_192, cipherKey_192)
    print("Aes-192:", end='\n')
    aes_192.FormatPrint("Plain Text", plainText_192)
    aes_192.FormatPrint("Cipher Key", cipherKey_192)
    print("Begin Cipher ...", end='\n')
    cipherText_192 = aes_192.Cipher()
    aes_192.FormatPrint("Cipher Text", cipherText_192)
    print("Begin DeCipher ...", end='\n')
    recAes_192 = AesCore('192', cipherText_192, cipherKey_192)
    recPlainText_192 = recAes_192.InvCipher()
    aes_192.FormatPrint("Recoveried Plain Text", recPlainText_192)

    aes_256 = AesCore('256', plainText_256, cipherKey_256)
    print("Aes-256:", end='\n')
    aes_256.FormatPrint("Plain Text", plainText_256)
    aes_256.FormatPrint("Cipher Key", cipherKey_256)
    print("Begin Cipher ...", end='\n')
    cipherText_256 = aes_256.Cipher()
    aes_256.FormatPrint("Cipher Text", cipherText_256)
    print("Begin DeCipher ...", end='\n')
    recAes_256 = AesCore('256', cipherText_256, cipherKey_256)
    recPlainText_256 = recAes_256.InvCipher()
    aes_256.FormatPrint("Recoveried Plain Text", recPlainText_256)


if __name__ ==  '__main__':
    main()
    
        

        

