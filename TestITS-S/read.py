import sys

def readfile(filename):
    f = open(filename, 'rb')
    count = 0
    while (byte := f.read(1)):
        sys.stdout.write ("{0} ".format(hex(ord(byte))))
        count += 1

    print ("count = {0}".format(count))
    print()



readfile('CTL.coer')
readfile('CTL102941Data.coer')
readfile('innerCTL.coer')
