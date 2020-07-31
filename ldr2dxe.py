#!/usr/bin/python
# -*- coding: iso-8859-15 -*-

# LDR to DXE "deflate"
#
# This tool tries to parse the content of a Blackfin loader format file
# to the original "elf" (also called DXE for blackfin) file.

# DXE header format:
# 4 * 4 Bytes (4 processor words, 32 bit, little endian)
# first word: "Block code" contains the identifier, checksum and flags
# 	[0]:  HDRsign is always 10101101 ==> 0xAD 
#	[1]:  HDRchk is header checksum
#	[2]:  Flag field: FINAL | FIRST | INDIRECT | IGNORE | INIT | CALLBACK | QUICKBOOT | FILL
#	[3]:  UNUSED | UNUSED | SAVE | AUX | DMA CODE
#
# second word: Target address
# third word:  Byte count
# fourth word: Argument

import ctypes
import sys
import struct
import binascii

c_uint8 = ctypes.c_uint8

class Flags_bits(ctypes.BigEndianStructure): #using big endian here because I'm lazy
    _fields_ = [
            ("final", c_uint8, 1),
            ("first", c_uint8, 1),
            ("indirect", c_uint8, 1),
            ("ignore", c_uint8, 1),
            ("init", c_uint8, 1),
            ("callback", c_uint8, 1),
            ("quickboot", c_uint8, 1),
            ("fill", c_uint8, 1),
        ]

class Flags(ctypes.Union):
    _fields_ = [("b", Flags_bits),
            ("asbyte", c_uint8)]

if __name__ == "__main__":
	if len(sys.argv) < 3:
		print "Usage: ", sys.argv[0], " <input ldr file> <output elf file>"
		exit(1)
	infilename = sys.argv[1]
	outfilename = sys.argv[2]
	infile = open(infilename, "rb") # TODO: try/catch for file open
	flags = Flags()
	outfile = None

	# main parsing loop: 1) check next header 2) parse flags 3) append content to outfile
	block=1
	dxe=0
	for header in iter(lambda: infile.read(4)[::-1], ""):
		# read the first 4 Bytes of the in file in reverse order
		# because LDR is little endian
		target_bytes = infile.read(4)[::-1] # TODO: check for each read if EOF and exit with error message "infile ended abruptly"
		bytecount_bytes = infile.read(4)
		bytecount = struct.unpack('i', bytecount_bytes)[0]
		argument_bytes = infile.read(4)
		#check if the header is still a valid LDR header
		if(header[0] != '\xAD'):
			print "The infile doesn't look like an DXE Part, one of the Header identifiers is not 0xAD"
			exit(1)
		flags.asbyte = ord(header[2])

		# check the first header flags. Should be "first" AND ("ignore" OR "Final")
		if block == 1 and flags.b.first != 1:
			print "The infile doesn't look like an DXE Part, the flags in the first Header don't contain the 'first' bit"
			exit(1)

		if (flags.b.first == 1):
			# check if the Target address of the first block is the default start address (0xFFA00000)
			if(target_bytes != '\xFF\xA0\x00\x00'):
				print "The infile doesn't look like an DXE part, the target address of the first block is not 0xFFA00000"
				exit(1)
			# check if the byte count of the first block is 0 (should be)
			if(bytecount != 0):
				print "The infile doesn't look like an LDR file, the bytecount of the first block is not 0"
				exit(1)
			# last header part of the first block is the start offset of the next DXE
			nextDXE = struct.unpack('i', argument_bytes)[0]
			print '[working] The infile looks like an DXE part. First Block OK, next DXE is at %X' % nextDXE
			# open the outfile
			if outfile != None:
				outfile.close()
			dxe += 1
			block = 1
			outfile = open('DXE' + str(dxe) + '_' + outfilename, "wb") # TODO: try/catch for file open
			# write ELF file header
			outfile.write('\x7F\x45\x4C\x46\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x6A\x00\x01\x00\x00\x00')
		# if(flags.b.fill == 1):
		# 	for _ in range(bytecount):
		# 		outfile.write(argument_bytes)
		# else:
		# 	buffer = infile.read(bytecount)
		# 	outfile.write(buffer)
		outfile.write(header)
		outfile.write(target_bytes)
		outfile.write(bytecount_bytes)
		outfile.write(argument_bytes)
		if bytecount > 0 and flags.b.fill == 0:
			buffer = infile.read(bytecount)
			outfile.write(buffer)

		print("[written] block {} with {} ({}) bytes, target {}, flags {} (final: {}, first: {}, indirect: {}, ignore: {}, init: {}, callback: {}, quickboot: {}, fill: {}), arg {}".format(block, bytecount, hex(bytecount), binascii.hexlify(bytearray(target_bytes)), hex(flags.asbyte), flags.b.final, flags.b.first, flags.b.indirect, flags.b.ignore, flags.b.init, flags.b.callback, flags.b.quickboot, flags.b.fill, binascii.hexlify(bytearray(argument_bytes))))
		block = block + 1
	outfile.close()
	infile.close()
		
		
