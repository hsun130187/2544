
import argparse
import os
import time
import socket
import sys
import binascii
from aes import AESCipher
from Crypto.PublicKey import RSA
from Crypto.Util.number import *
'''def calC1bytes(c):

    # change long int to hex number,c1 bytes as AES key
    c1 = (c * (2 ** (b * e)) % n)
    c1bytes = long_to_bytes(c1)
    return c1bytes'''

#c1 = (InAesK * (2 ** (b * e)) % n)
#c1bytes = long_to_bytes(c1)
#encryptedKey = key.encrypt(c1bytes, 32)[0]
#GuessAESKeybin = "1"+"".zfill(255)
#if hex(int(GuessAESKeybin, 2))[-1:]=='L':
	#MyguessAESKey = binascii.a2b_hex(hex(int(GuessAESKeybin, 2))[2:-1].zfill(64))
#else:
	#MyguessAESKey = binascii.a2b_hex(hex(int(GuessAESKeybin, 2))[2:].zfill(64))

#aes = AESCipher(MyguessAESKey)
#msg = ""

def istrue(b,aesbin,n,e):
    # Send data
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect the socket to the port where the server is listening
    server_address = (args.ipaddress, int(args.port))
    sock.connect(server_address)
    sock.settimeout(2)
    c1 = (InAesK * (2 ** (b * e)) % n)
    c1bytes = long_to_bytes(c1)
    if hex(int(aesbin, 2))[-1:]=='L':
            AESKey = binascii.a2b_hex(hex(int(aesbin, 2))[2:-1].zfill(64))
    else:
            AESKey = binascii.a2b_hex(hex(int(aesbin, 2))[2:].zfill(64))
    aes = AESCipher(AESKey)
    try:
        message = aes.encrypt('THis is my test message')
    except ValueError:
        print("Client with port {} failed.".format(args.port),
              file=sys.stderr)
        exit(1)
    msg = c1bytes + message
    # msg: AES key encrypted by the public key of RSA
    #      + message encrypted by the AES key

    if args.verbose is True:
        print('Sending: {}'.format(message.hex()))
    sock.sendall(msg)

    # Look for the response
    amount_received = 0
    amount_expected = len(message)

    if amount_expected % 16 != 0:
        amount_expected += (16 - (len(message) % 16))

    answer = b''
    if amount_expected > amount_received:
        while amount_received < amount_expected:
            try:
                data = sock.recv(MESSAGE_LENGTH)
            except socket.timeout as e:
                err = e.args[0]

                if err == 'timed out':
                    print('Connection timed out, waiting for retry',
                          file=sys.stderr)
                    time.sleep(1)
                    continue
                else:
                    print('Another issue: {}'.format(e),
                          file=sys.stderr)
                    break
            except socket.error as e:
                print('Socket error: {}'.format(e),
                      file=sys.stderr)
                break
            amount_received += len(data)
            answer += data
    sock.close()
    print('Received: {}'.format(aes.decrypt(answer)))
    try:
        temp=aes.decrypt(answer).decode("utf-8")
    except UnicodeDecodeError as e:
        return False
    result = ''.join(temp.split())
    if result=="THISISMYTESTMESSAGE":
            return True
    else:
            return False
MESSAGE_LENGTH=15
'''ciphertext1=""" 3e ee 74 54 c8 58 e6 c7  0b d8 7b 21 7d 33 fc ed   
  62 e2 6b 89 d1 10 26 d5  1f 51 49 71 98 97 3c ca   
  d2 9e 11 fe c1 8e 93 ec  c4 64 ce 40 86 e0 c4 8e   
  12 c0 6e ed 63 60 30 c3  38 e7 22 03 4d 2a 47 72  
  c1 0b d4 30 f7 0f b7 aa  dd 1a f2 d0 aa e3 4a 89   
  b9 a7 7d 4c 7e 03 74 55  a0 66 c4 bd ac f7 bb fd   
  15 d1 d4 16 01 72 41 8b  55 07 d5 cc fc 3b 31 4d   
  36 3f 76 a2 40 31 ed ed  9b 58 89 22 ba c3 15 45   
  e2 39 92 f7 e6 45 a1 c7  85 30 ef e0 e8 c3 55 95   
  d8 0e 57 71 00 2f 3a b5  7a 2e b9 f3 99 7c 0c d2   
  96 f7 66 89 a2 f5 5b 09  f6 21 be ec 79 1c 3a 65  
  2d 68 de b0 82 29 44 00  da cd d3 9a cc 0d 31 da   
  ae 36 30 63 e4 87 b3 57  25 68 a7 ba 40 8e bd 6f   
  cc 56 63 a1 d3 14 63 5a  53 e1 53 aa 7f f5 c3 c8   
  67 8c 3d e4 27 11 35 4f  8b b1 a2 98 ec fc 29 03   
  21 64 34 aa b9 62 95 c0  bb 79 0d b5 52 24 e8 95   
  ab c8 d2 6c c4 2a 96 ce  f5 55 1c a5 b3 5e ee cc   
  08 01 ac c3 c0 e3 28 15  f7 6a c6 5c d0 34 34 91   
  b0 40 09 f9 44 95 ae 16  65 19 fa 48 55 34 e5 09   
  2a a2 a1 70 e8 04 da ac  ef 71 dd f6 f9 aa 4c 6c   
  8e fa e8 f1 e9 4f 6f e1  c2 53 59 32 3f 7c 79 d2   
  75 7e a0 4d c2 1f 41 63  b3 6f 8b d3 9d 16 d2 c9   
  3f 8c 06 87 51 3c 8b 92  ca 8e 57 19 36 d8 be 91   
  0c 10 62 4f db 19 63 ba  46 1c ce 70 f6 78 29 a3   
  9a 1d 2d 98 83 96 b7 9a  1d f0 cb a0 6d 7b b5 b1   
  9e ef ca 20 19 eb 19 a7  82 72 33 28 c0 44 00 cf   
  69 73 44 b3 b8 33 e0 5d  f8 7d df 7b 5d 2c a7 38   
  34 ab d1 b6 d6 96 f8 d8  8f 5c 3b c5 b8 21 7d 44 """  
'''
ciphertext1="""a6 b0 75 72 6c f2 bc 73  54 70 c4 94 2b c1 50 e0
  c2 5e c0 12 f4 31 a5 80  ed 3a 27 4e 89 66 e0 79 
  02 3f 2f 93 65 10 e5 b4  4b 99 2f 7b 28 dc bd 72   
  05 93 2c f6 15 a4 65 c0  07 aa 13 2b 60 9f db 13   
  8f a4 d4 37 ac 9a 0b 9c  a8 38 22 08 11 8c 24 b5   
  fb 66 75 f0 5b f9 a9 91  55 cb c5 b6 11 a4 7d b9   
  70 5e 1e 40 17 5f 42 ef  fe a3 ac 73 46 de d7 5d   
  00 85 53 98 60 6d a5 46  25 86 d5 2c 0d 9f 5c da   
  7d 37 29 19 0c c4 f0 87  ed 27 12 e7 1d 0e 50 05   
  02 ad 87 58 70 b3 61 ec  0b a7 ca e7 1c 29 6c 90   
  19 c1 8e 99 38 6d 5b ed  92 40 68 85 e2 0e ed fb   
  90 10 5f fb 91 75 25 7c  ca 26 e1 53 1b 8a 9e 7b   
  32 07 dd da 77 99 e2 13  4f 1f 1b 10 9c 54 4c cf   
  14 bb 52 7e 8b a3 28 53  29 2f 8a 8d 50 9a 30 81   
  b1 f5 d8 a8 43 da c3 5f  f6 07 32 25 f6 a5 35 bc   
  77 5c 01 d8 06 23 e2 51  22 fb c8 f1 a7 22 12 73  
  d9 93 a1 b1 b0 8a f7 34  00 bb 0e ee 37 21 a7 f8   
  05 13 23 28 8a 6e ce 06  4d aa 76 28 5c ab 4e 7d   
  16 b8 49 87 cc 04 7b b9  56 59 73 af 4b dd 0e 4d"""

#print(ciphertext1)
#print(c)


# Handle command-line arguments
parser = argparse.ArgumentParser()
parser.add_argument("-ip", "--ipaddress",
                    help='ip address where the server is running',
                    default='127.0.0.1',  # Defaults to loopback
                    required=True)
parser.add_argument("-p", "--port",
                    help='port where the server is listening on',
                    required=True)
parser.add_argument("-f", "--publickey",
                    help='name of public key',
                    default='serverPublicKey',
                    required=False)
parser.add_argument("-v", "--verbose",
                    help="print out extra info to stdout",
                    default='True',
                    required=False)

args = parser.parse_args()

### Create a TCP/IP socket
##sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
##
### Connect the socket to the port where the server is listening
##server_address = (args.ipaddress, int(args.port))
##sock.connect(server_address)
##sock.settimeout(2)


# load server's public key
serverPublicKeyFileName = args.publickey
key = ""
with open(serverPublicKeyFileName, 'r') as f:
    key = RSA.importKey(f.read())
    n=key.n
    e=key.e
MESSAGE_LENGTH = 15

ciphertext1 = ''.join(ciphertext1.split())
AESkey = ciphertext1[:512]
InAesK = int(AESkey,16)   
AESKeybinb255 = "1"+"".zfill(255)
AESKeybin = AESKeybinb255
   
            
for i in range(1,256):
	b=255-i
	#(print 'b = %s' % b)
	AESKeybin0="0"+AESKeybin[:-1]
	AESKeybin1="1"+AESKeybin[:-1]
	bool0=istrue(b,AESKeybin0,n,e)
	time.sleep(7)
	if bool0:
		AESKeybin=AESKeybin0
	else:
		bool1=istrue(b,AESKeybin1,n,e)
		time.sleep(7)
		if bool1:
			AESKeybin=AESKeybin1
		else:
			print ('Error!')
			break
	print ("AESKeybin = %s" % AESKeybin)            
    
encrypted_message=ciphertext1[512:]
int_encrypted_message = int(encrypted_message,16)
messageBytes = long_to_bytes(int_encrypted_message)
if hex(int(AESKeybin, 2))[-1:]=='L':
	AESKey = binascii.a2b_hex(hex(int(AESKeybin, 2))[2:-1].zfill(64))
else:
	AESKey = binascii.a2b_hex(hex(int(AESKeybin, 2))[2:].zfill(64))

#get plaintext
aes = AESCipher(AESKey)
plaintext = aes.decrypt(messageBytes).decode()
print (plaintext)

