#!/usr/bin/python

import sys
import subprocess
import os
import tempfile
import random
import time

x64_regs = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']

def genRegState( ):
    state = []

    for i in range(14):
        state.append(random.randint(0, 0xffffffffffffffff))

    return state
        
def selectReg( ):
    return random.choice(x64_regs)

def selectRegConstant( ):
    z = random.randint(0, 0xffff) & 1

    if z:
        return random.choice(x64_regs)
    else:
        return hex(random.randint(0, 0x7fffffff)).rstrip('L')

def mov( ):
    return '\tmov %s, %s\n' %( selectReg(), selectRegConstant())

## xchg
def xchg( ):
    return '\txchg %s, %s\n' %(selectReg(), selectReg())

## add
def add():
    return '\tadd %s, %s\n' %(selectReg(), selectRegConstant())

## adc
def adc():
    return '\tadc %s, %s\n' %(selectReg(), selectRegConstant())

## sub
def sub():
    return '\tsub %s, %s\n' %(selectReg(), selectRegConstant())

def sbb():
    return '\tsbb %s, %s\n' %(selectReg(), selectRegConstant())

def inc():
    return '\tinc %s\n' %(selectReg())

def dec():
    return '\tdec %s\n' %(selectReg())

def neg():
    return '\tneg %s\n' %(selectReg())

def andm():
    return '\tand %s, %s\n' %(selectReg(), selectRegConstant())

def xorm():
    return '\txor %s, %s\n' %(selectReg(), selectRegConstant())

def orm():
    return '\tor %s, %s\n' %(selectReg(), selectRegConstant())

def notm():
    return '\tnot %s\n' %(selectReg())

def nop():
    return '\tnop\n'

def shld():
    z = random.randint(0, 0xffff) & 1

    if z:
        imm = 'cl'
    else:
        imm = hex(random.randint(1,16)).rstrip('L')

    return '\tshld %s, %s, %s\n' %(selectReg(), selectReg(), imm)

def shrd():
    z = random.randint(0, 0xffff) & 1

    if z:
        imm = 'cl'
    else:
        imm = hex(random.randint(1,16)).rstrip('L')

    return '\tshrd %s, %s, %s\n' %(selectReg(), selectReg(), imm)

def shift():
    z = random.randint(0, 0xffff) & 1

    if z:
        imm = 'cl'
    else:
        imm = hex(random.randint(1,16)).rstrip('L')

    return '\t%s %s, %s\n' %(random.choice(['sal', 'shl', 'sar', 'shr', 'ror', 'rol', 'rcr', 'rcl']), selectReg(), imm)
  
def mul():
    return '\tmul %s\n' %(selectReg())

def bswap():
    return '\tbswap %s\n' %(selectReg())
 
## imul
def imul():
    z = random.randint(0, 100) & 1

    if z:
        return '\timul %s\n' %(selectReg())

    return '\timul %s, %s\n' %(selectReg(), selectRegConstant())
 
def push():
    global pushes

    pushes += 1

    return '\tpush %s\n' %(selectRegConstant())

def pop():
    global pushes

    if pushes == 0:
        return ''

    pushes -= 1

    return '\tpop %s\n' %(selectReg())

def ret ():
    return '\tret\n'

#bsf
#bsr
#bt
#btc
#btr
#bts
#cmovcc
#xadd

def badFormat():
    sys.stdout.write('****Improperly formatted solution\n')
    sys.stdout.flush()
    sys.exit(0)

def checkData( code ):
    state = genRegState()

    sys.stdout.write('****Initial Register State****\n')
    sys.stdout.write('rax=%s\n' %(hex(state[0]).rstrip('L')))
    sys.stdout.write('rbx=%s\n' %(hex(state[1]).rstrip('L')))
    sys.stdout.write('rcx=%s\n' %(hex(state[2]).rstrip('L')))
    sys.stdout.write('rdx=%s\n' %(hex(state[3]).rstrip('L')))
    sys.stdout.write('rsi=%s\n' %(hex(state[4]).rstrip('L')))
    sys.stdout.write('rdi=%s\n' %(hex(state[5]).rstrip('L')))
    sys.stdout.write('r8=%s\n' %(hex(state[6]).rstrip('L')))
    sys.stdout.write('r9=%s\n' %(hex(state[7]).rstrip('L')))
    sys.stdout.write('r10=%s\n' %(hex(state[8]).rstrip('L')))
    sys.stdout.write('r11=%s\n' %(hex(state[9]).rstrip('L')))
    sys.stdout.write('r12=%s\n' %(hex(state[10]).rstrip('L')))
    sys.stdout.write('r13=%s\n' %(hex(state[11]).rstrip('L')))
    sys.stdout.write('r14=%s\n' %(hex(state[12]).rstrip('L')))
    sys.stdout.write('r15=%s\n' %(hex(state[13]).rstrip('L')))
    sys.stdout.flush()

    ex = []
    ex.append("/home/hj/defcon/catwestern/catwestern64")
    
    for x in state:
        ex.append( hex(x)[2:].rstrip('L'))

    f = tempfile.NamedTemporaryFile(delete=False)
    f.write(code)
    f.close()

    z = subprocess.call( ["nasm", "-f", "bin", f.name, '-o', f.name + '.bin'] )

    ex.append( f.name + '.bin' )

    os.unlink( f.name )

    z = subprocess.check_output( ex )

    solution = {}
    zl = z.split('\n')

    for ll in zl:
        if ll == '':
            continue

        rg = ll.split('=')
	solution[rg[0]] = int(rg[1])

    z = open( f.name + '.bin', 'rb')
    sc = z.read()
    z.close()
    os.unlink(f.name + '.bin')

    sys.stdout.write('****Send Solution In The Same Format****\n')
    sys.stdout.write('About to send %d bytes: \n' %len(sc))
    sys.stdout.write( sc )
    sys.stdout.flush()

    submission = {}
    try:

        for i in range(14):
            line = sys.stdin.readline()

            rg = line.split('=')

            if len(rg) != 2:
                badFormat()
            if rg[0] not in [ 'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']:
                badFormat()

            if rg[0] in submission:
                badFormat()

            submission[rg[0]] = int(rg[1], 16)	
    except:
        badFormat()

    for ss in submission:
        if ss not in solution:
            badFormat()

        if submission[ss] != solution[ss]:
            badSolution()

<<<<<<< HEAD
    f = open('/home/hj/defcon/catwestern/flag', 'rb')
=======
    f = open('./flag', 'rb')
>>>>>>> d3dfe6f4cdbd9e3b73de712ea06ae17884b60d25
    flag = f.read()
    f.close()

    sys.stdout.write('The flag is: %s' %(flag))
    return

def badSolution():
    sys.stdout.write('****Invalid Solution****\n')
    sys.stdout.flush()
    sys.exit(0)

if __name__ == '__main__':
    global pushes

    d = 'BITS 64\n\nstart:\n'

    pushes = 0

    for i in range(20):
        d += random.choice( [ mov, add, xchg, adc, sub, inc, dec, neg, andm, xorm, orm, notm, nop, shrd, shld, sbb, shift, mul, bswap, imul, push, pop] )()

    while pushes:
        d += pop()

    d += ret()

    checkData(d)
    sys.stdout.flush()

