import sys, os

SMT = """
(define-fun MAT0POS ((t (_ BitVec 32)) (v (_ BitVec 32))) (_ BitVec 32)
	(bvxor v (bvlshr v t))
)

(define-fun MAT0NEG ((t (_ BitVec 32)) (v (_ BitVec 32))) (_ BitVec 32)
	(bvxor v (bvshl v t))
)

(define-fun MAT3NEG ((t (_ BitVec 32)) (v (_ BitVec 32))) (_ BitVec 32)
	(bvshl v t)
)

(define-fun MAT4NEG ((t (_ BitVec 32)) (b (_ BitVec 32)) (v (_ BitVec 32))) (_ BitVec 32)
	(bvxor v (bvand (bvshl v t) b))
)

(define-fun z1 ((a (_ BitVec 32)) (b (_ BitVec 32))) (_ BitVec 32)
	(bvxor (MAT0NEG #x00000010 a) (MAT0NEG #x0000000f b))
)
(define-fun z2 ((a (_ BitVec 32))) (_ BitVec 32)
	(MAT0POS #x0000000b a)
)

(define-fun newV1 ((s0 (_ BitVec 32)) (M1 (_ BitVec 32)) (M2 (_ BitVec 32))) (_ BitVec 32)
   (bvxor (z1 s0 M1) (z2 M2))
)

(define-fun newV0 ((s0 (_ BitVec 32)) (M1 (_ BitVec 32)) (M2 (_ BitVec 32)) (s1 (_ BitVec 32)) (s2 (_ BitVec 32))) (_ BitVec 32)
   (bvxor (MAT0NEG #x00000002 s0) (bvxor (MAT0NEG #x00000012 (z1 s2 M1)) (bvxor (MAT3NEG #x0000001c (z2 M2)) (MAT4NEG #x00000005 #xda442d24 s1))))
)
"""

print SMT

TempValues = sys.argv[1].split(",")
StartValues = []
for i in xrange(0, len(TempValues)):
	StartValues.append(int(TempValues[i], 16))


TempValues = sys.argv[2].split(",")
Values = []
for i in xrange(0, len(TempValues)):
	Values.append(int(TempValues[i], 16))

State = "(declare-const STATE%d_%d (_ BitVec 32))"
for i in xrange(0, 16):
	print State % (i, 0)

	if i < len(StartValues):
		print "(assert (= (bvand STATE%d_%d #xfffffff0) #x%08x))" % (i, 0, StartValues[len(StartValues)-1-i] & 0xfffffff0)

PerLineEntry = """
(declare-const STATE%s (_ BitVec 32))
(declare-const STATE%s (_ BitVec 32))
(assert (= STATE%s (newV1 STATE%s STATE%s STATE%s)))
(assert (= STATE%s (newV0 STATE%s STATE%s STATE%s STATE%s STATE%s)))
(assert (= (bvand STATE%s #xfffffff0) #x%08x))
"""

CurStateIDs = [0]*16
CurState = 0

for i in xrange(0, len(Values)):
	State0 = "%d_%d" % (CurState, CurStateIDs[CurState])
	#CurStateIDs[CurState] += 1
	#State0New = "%d_%d" % (CurState, CurStateIDs[CurState])

	NewV1 = 10
	CurStateIDs[(CurState+NewV1) % 16] += 1
	State0New = "%d_%d" % ((CurState+NewV1) % 16, CurStateIDs[(CurState+NewV1) % 16])

	State31 = "%d_%d" % ((CurState + 15) % 16, CurStateIDs[(CurState+15) % 16])
	CurStateIDs[(CurState+15) % 16] += 1
	State31New = "%d_%d" % ((CurState + 15) % 16, CurStateIDs[(CurState+15) % 16])

	M1 = "%d_%d" % ((CurState + 13) % 16, CurStateIDs[(CurState+13) % 16])
	M2 = "%d_%d" % ((CurState + 9) % 16, CurStateIDs[(CurState+9) % 16])

	print PerLineEntry % (State0New, State31New, State0New, State0, M1, M2, State31New, State31, M1, M2, State0New, State0, State31New, Values[i] & 0xfffffff0)
	CurState = (CurState + 15) % 16

print "(check-sat)\n(get-model)\n"
