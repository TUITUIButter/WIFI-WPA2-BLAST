import threading
import hmac
from _winapi import ExitProcess
from binascii import b2a_hex, a2b_hex
from hashlib import pbkdf2_hmac

ssid = 'Coherer'
ANonce = '3e8e967dacd960324cac5b6aa721235bf57b949771c867989f49d04ed47c6933'
SNonce = 'cdf405ceb9d889ef3dec42609828fae546b7add7baecbb1a394eac5214b1d386'
apMac = '000c4182b255'
cliMac = '000d9382363a'
A = ''
b = ''


def MakeAB():
    A = "Pairwise key expansion"
    B = min(apMac, cliMac) + max(apMac, cliMac) + min(ANonce, SNonce) + max(ANonce, SNonce)
    return A, B


def PRF(key, A, B):
    # Number of bytes in the PTK
    nByte = 64
    i = 0
    R = b''
    # Each iteration produces 160-bit value and 512 bits are required
    while i <= ((nByte * 8 + 159) / 160):
        hmacsha1 = hmac.new(key, A.encode() + chr(0x00).encode() + a2b_hex(B) + chr(i).encode(), 'sha1')
        R = R + hmacsha1.digest()
        i += 1
    return R[0:nByte]


def MIC(ptk):
    # The entire 802.1x frame with the MIC field set to all zeros
    data2 = a2b_hex(
        "0203007502010a00100000000000000000cdf405ceb9d889ef3dec42609828fae546b7add7baecbb1a394eac5214b1d"
        "386000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000001630140100000fac020100000fac040100000fac020000")
    hmacFunc = 'sha1'
    mic = hmac.new(ptk[0:16], data2, hmacFunc).digest()[:16]
    return mic


def main(begin, end):
    f = open("pwd-dictionary.txt", "r")
    for pwd in f.readlines()[begin:end]:
        pwd = pwd[:-1]
        # pwd = 'Induction'

        pmk = pbkdf2_hmac('sha1', pwd.encode('ascii'), ssid.encode('ascii'), 4096, 32)

        ptk = PRF(pmk, A, B)

        mic = MIC(ptk)

        # pmkStr = b2a_hex(pmk).decode()
        # print('ptk: ' + pmkStr)
        # print('ptk: ' + b2a_hex(ptk).decode())
        # print('mic: ' + b2a_hex(mic).decode())
        # print('')

        if b2a_hex(mic).decode() == 'a462a7029ad5ba30b6af0df391988e45':
            print("-----------Success:" + pwd, flush=True)
            ExitProcess(1)
            break
    f.close()


if __name__ == '__main__':
    A, B = MakeAB()
    # main(0, 10)
    threadList = []
    for i in range(10):
        thread = threading.Thread(target=main, args=(i*700000, (i+1)*700000))
        threadList.append(thread)
        thread.start()
    for i in range(10):
        threadList[i].join()

