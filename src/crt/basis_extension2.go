package crt

import (
	"math/bits"
	"unsafe"

	"github.com/tuneinsight/lattigo/v5/ring"
	"github.com/tuneinsight/lattigo/v5/utils/bignum"
)

// BasisExtender stores the necessary parameters for RNS basis extension.
// The used algorithm is from https://eprint.iacr.org/2018/117.pdf.
type BasisExtender struct {
	ringQ                *ring.Ring
	ringP                *ring.Ring
	constantsQtoP        []ModUpConstants
	constantsPtoQ        []ModUpConstants
	modDownConstantsPtoQ [][]uint64
	modDownConstantsQtoP [][]uint64

	buffQ ring.Poly
	buffP ring.Poly
}

func genmodDownConstants(ringQ, ringP *ring.Ring) (constants [][]uint64) {

	constants = make([][]uint64, ringP.ModuliChainLength())

	for j, SubRingP := range ringP.SubRings {

		pj := SubRingP.Modulus

		constants[j] = make([]uint64, ringQ.ModuliChainLength())

		for i, SubRingQ := range ringQ.SubRings {

			qi := SubRingQ.Modulus

			constants[j][i] = ring.ModExp(pj, qi-2, qi)
			constants[j][i] = ring.MForm(constants[j][i], qi, SubRingQ.BRedConstant)

			if j > 0 {
				constants[j][i] = ring.MRed(constants[j][i], constants[j-1][i], qi, SubRingQ.MRedConstant)
			}
		}
	}

	return
}

// NewBasisExtender creates a new BasisExtender, enabling RNS basis extension from Q to P and P to Q.
func NewBasisExtender(ringQ, ringP *ring.Ring) (be *BasisExtender) {

	be = new(BasisExtender)

	be.ringQ = ringQ
	be.ringP = ringP

	Q := ringQ.ModuliChain()
	P := ringP.ModuliChain()

	be.constantsQtoP = make([]ModUpConstants, ringQ.ModuliChainLength())
	for i := range Q {
		be.constantsQtoP[i] = GenModUpConstants(Q[:i+1], P)
	}

	be.constantsPtoQ = make([]ModUpConstants, ringP.ModuliChainLength())
	for i := range P {
		be.constantsPtoQ[i] = GenModUpConstants(P[:i+1], Q)
	}

	be.modDownConstantsPtoQ = genmodDownConstants(ringQ, ringP)
	be.modDownConstantsQtoP = genmodDownConstants(ringP, ringQ)

	be.buffQ = ringQ.NewPoly()
	be.buffP = ringP.NewPoly()

	return
}

// ModUpConstants stores the necessary parameters for RNS basis extension.
type ModUpConstants struct {
	// Parameters for basis extension from Q to P
	// (Q/Qi)^-1) (mod each Qi) (in Montgomery form)
	qoverqiinvqi []uint64
	// Q/qi (mod each Pj) (in Montgomery form)
	qoverqimodp [][]uint64
	// Q*v (mod each Pj) for v in [1,...,k] where k is the number of Pj moduli
	vtimesqmodp [][]uint64
}

// GenModUpConstants generates the ModUpConstants for basis extension from Q to P and P to Q.
func GenModUpConstants(Q, P []uint64) ModUpConstants {

	bredQ := make([][]uint64, len(Q))
	mredQ := make([]uint64, len(Q))
	bredP := make([][]uint64, len(P))
	mredP := make([]uint64, len(P))

	for i := range Q {
		bredQ[i] = ring.BRedConstant(Q[i])
		mredQ[i] = ring.MRedConstant(Q[i])
	}

	for i := range P {
		bredP[i] = ring.BRedConstant(P[i])
		mredP[i] = ring.MRedConstant(P[i])
	}

	qoverqiinvqi := make([]uint64, len(Q))
	qoverqimodp := make([][]uint64, len(P))

	for i := range P {
		qoverqimodp[i] = make([]uint64, len(Q))
	}

	var qiStar uint64
	for i, qi := range Q {

		qiStar = ring.MForm(1, qi, bredQ[i])

		for j := 0; j < len(Q); j++ {
			if j != i {
				qiStar = ring.MRed(qiStar, ring.MForm(Q[j], qi, bredQ[i]), qi, mredQ[i])
			}
		}

		// (Q/Qi)^-1) * r (mod Qi) (in Montgomery form)
		qoverqiinvqi[i] = ring.ModexpMontgomery(qiStar, int(qi-2), qi, mredQ[i], bredQ[i])

		for j, pj := range P {
			// (Q/qi * r) (mod Pj) (in Montgomery form)
			qiStar = 1
			for u := 0; u < len(Q); u++ {
				if u != i {
					qiStar = ring.MRed(qiStar, ring.MForm(Q[u], pj, bredP[j]), pj, mredP[j])
				}
			}

			qoverqimodp[j][i] = ring.MForm(qiStar, pj, bredP[j])
		}
	}

	vtimesqmodp := make([][]uint64, len(P))
	var QmodPi uint64
	for j, pj := range P {
		vtimesqmodp[j] = make([]uint64, len(Q)+1)
		// Correction Term (v*Q) mod each Pj

		QmodPi = 1
		for _, qi := range Q {
			QmodPi = ring.MRed(QmodPi, ring.MForm(qi, pj, bredP[j]), pj, mredP[j])
		}

		v := pj - QmodPi
		vtimesqmodp[j][0] = 0
		for i := 1; i < len(Q)+1; i++ {
			vtimesqmodp[j][i] = ring.CRed(vtimesqmodp[j][i-1]+v, pj)
		}
	}

	return ModUpConstants{qoverqiinvqi: qoverqiinvqi, qoverqimodp: qoverqimodp, vtimesqmodp: vtimesqmodp}
}

// ShallowCopy creates a shallow copy of this basis extender in which the read-only data-structures are
// shared with the receiver.
func (be *BasisExtender) ShallowCopy() *BasisExtender {
	if be == nil {
		return nil
	}
	return &BasisExtender{
		ringQ:                be.ringQ,
		ringP:                be.ringP,
		constantsQtoP:        be.constantsQtoP,
		constantsPtoQ:        be.constantsPtoQ,
		modDownConstantsQtoP: be.modDownConstantsQtoP,
		modDownConstantsPtoQ: be.modDownConstantsPtoQ,

		buffQ: be.ringQ.NewPoly(),
		buffP: be.ringP.NewPoly(),
	}
}

// ModUpQtoP extends the RNS basis of a polynomial from Q to QP.
// Given a polynomial with coefficients in basis {Q0,Q1....Qlevel},
// it extends its basis from {Q0,Q1....Qlevel} to {Q0,Q1....Qlevel,P0,P1...Pj}
func (be *BasisExtender) ModUpQtoP(levelQ, levelP int, polQ, polP ring.Poly) {

	ringQ := be.ringQ.AtLevel(levelQ)
	ringP := be.ringP.AtLevel(levelP)
	buffQ := be.buffQ

	QHalf := bignum.NewInt(ringQ.ModulusAtLevel[levelQ])
	QHalf.Rsh(QHalf, 1)

	ringQ.AddScalarBigint(polQ, QHalf, buffQ)
	ModUpExact(buffQ.Coeffs[:levelQ+1], polP.Coeffs[:levelP+1], be.ringQ, be.ringP, be.constantsQtoP[levelQ])
	ringP.SubScalarBigint(polP, QHalf, polP)
}

// ModUpPtoQ extends the RNS basis of a polynomial from P to PQ.
// Given a polynomial with coefficients in basis {P0,P1....Plevel},
// it extends its basis from {P0,P1....Plevel} to {Q0,Q1...Qj}
func (be *BasisExtender) ModUpPtoQ(levelP, levelQ int, polP, polQ ring.Poly) {

	ringQ := be.ringQ.AtLevel(levelQ)
	ringP := be.ringP.AtLevel(levelP)
	buffP := be.buffP

	PHalf := bignum.NewInt(ringP.ModulusAtLevel[levelP])
	PHalf.Rsh(PHalf, 1)

	ringP.AddScalarBigint(polP, PHalf, buffP)
	ModUpExact(buffP.Coeffs[:levelP+1], polQ.Coeffs[:levelQ+1], be.ringP, be.ringQ, be.constantsPtoQ[levelP])
	ringQ.SubScalarBigint(polQ, PHalf, polQ)
}

// ModDownQPtoQ reduces the basis of a polynomial.
// Given a polynomial with coefficients in basis {Q0,Q1....Qlevel} and {P0,P1...Pj},
// it reduces its basis from {Q0,Q1....Qlevel} and {P0,P1...Pj} to {Q0,Q1....Qlevel}
// and does a rounded integer division of the result by P.
func (be *BasisExtender) ModDownQPtoQ(levelQ, levelP int, p1Q, p1P, p2Q ring.Poly) {

	ringQ := be.ringQ.AtLevel(levelQ)
	modDownConstants := be.modDownConstantsPtoQ[levelP]
	buffQ := be.buffQ

	be.ModUpPtoQ(levelP, levelQ, p1P, buffQ)

	for i, s := range ringQ.SubRings[:levelQ+1] {
		s.SubThenMulScalarMontgomeryTwoModulus(buffQ.Coeffs[i], p1Q.Coeffs[i], s.Modulus-modDownConstants[i], p2Q.Coeffs[i])
	}
}

// ModDownQPtoQNTT reduces the basis of a polynomial.
// Given a polynomial with coefficients in basis {Q0,Q1....Qi} and {P0,P1...Pj},
// it reduces its basis from {Q0,Q1....Qi} and {P0,P1...Pj} to {Q0,Q1....Qi}
// and does a rounded integer division of the result by P.
// Inputs must be in the NTT domain.
func (be *BasisExtender) ModDownQPtoQNTT(levelQ, levelP int, p1Q, p1P, p2Q ring.Poly) {

	ringQ := be.ringQ.AtLevel(levelQ)
	ringP := be.ringP.AtLevel(levelP)
	modDownConstants := be.modDownConstantsPtoQ[levelP]
	buffP := be.buffP
	buffQ := be.buffQ

	ringP.INTTLazy(p1P, buffP)
	be.ModUpPtoQ(levelP, levelQ, buffP, buffQ)
	ringQ.NTTLazy(buffQ, buffQ)

	// Finally, for each level of p1 (and the buffer since they now share the same basis) we compute p2 = (P^-1) * (p1 - buff) mod Q
	for i, s := range ringQ.SubRings[:levelQ+1] {
		// Then for each coefficient we compute (P^-1) * (p1[i][j] - buff[i][j]) mod qi
		s.SubThenMulScalarMontgomeryTwoModulus(buffQ.Coeffs[i], p1Q.Coeffs[i], s.Modulus-modDownConstants[i], p2Q.Coeffs[i])
	}
}

// ModDownQPtoP reduces the basis of a polynomial.
// Given a polynomial with coefficients in basis {Q0,Q1....QlevelQ} and {P0,P1...PlevelP},
// it reduces its basis from {Q0,Q1....QlevelQ} and {P0,P1...PlevelP} to {P0,P1...PlevelP}
// and does a floored integer division of the result by Q.
func (be *BasisExtender) ModDownQPtoP(levelQ, levelP int, p1Q, p1P, p2P ring.Poly) {

	ringP := be.ringP.AtLevel(levelP)
	modDownConstants := be.modDownConstantsQtoP[levelQ]
	buffP := be.buffP

	be.ModUpQtoP(levelQ, levelP, p1Q, buffP)

	// Finally, for each level of p1 (and buff since they now share the same basis) we compute p2 = (P^-1) * (p1 - buff) mod Q
	for i, s := range ringP.SubRings[:levelP+1] {
		// Then, for each coefficient we compute (P^-1) * (p1[i][j] - buff[i][j]) mod qi
		s.SubThenMulScalarMontgomeryTwoModulus(buffP.Coeffs[i], p1P.Coeffs[i], s.Modulus-modDownConstants[i], p2P.Coeffs[i])
	}
	// In total we do len(P) + len(Q) NTT, which is optimal (linear in the number of moduli of P and Q)
}

// ModUpExact takes p1 mod Q and switches its basis to P, returning the result on p2.
// Caution: values are not centered and returned values are in [0, 2P-1].
func ModUpExact(p1, p2 [][]uint64, ringQ, ringP *ring.Ring, MUC ModUpConstants) {

	var v, rlo, rhi [8]uint64
	var y0, y1, y2, y3, y4, y5, y6, y7 [32]uint64

	levelQ := len(p1) - 1
	levelP := len(p2) - 1

	Q := ringQ.ModuliChain()
	mredQ := ringQ.MRedConstants()

	P := ringP.ModuliChain()
	mredP := ringP.MRedConstants()

	vtimesqmodp := MUC.vtimesqmodp
	qoverqiinvqi := MUC.qoverqiinvqi
	qoverqimodp := MUC.qoverqimodp

	// We loop over each coefficient and apply the basis extension
	for x := 0; x < len(p1[0]); x = x + 8 {
		reconstructRNS(0, levelQ+1, x, p1, &v, &y0, &y1, &y2, &y3, &y4, &y5, &y6, &y7, Q, mredQ, qoverqiinvqi)
		for j := 0; j < levelP+1; j++ {
			/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p2[j])%8 != 0*/
			multSum(levelQ, (*[8]uint64)(unsafe.Pointer(&p2[j][x])), &rlo, &rhi, &v, &y0, &y1, &y2, &y3, &y4, &y5, &y6, &y7, P[j], mredP[j], vtimesqmodp[j], qoverqimodp[j])
		}
	}
}

func reconstructRNS(start, end, x int, p [][]uint64, v *[8]uint64, y0, y1, y2, y3, y4, y5, y6, y7 *[32]uint64, Q, QInv, QbMont []uint64) {

	var vi [8]float64
	var qi, qiInv, qoverqiinvqi uint64
	var qif float64

	for i, j := start, 0; i < end; i, j = i+1, j+1 {

		qoverqiinvqi = QbMont[i]
		qi = Q[i]
		qiInv = QInv[i]
		qif = float64(qi)

		/* #nosec G103 -- behavior and consequences well understood, possible buffer overflow if len(p[i])%8 != 0 */
		pTmp := (*[8]uint64)(unsafe.Pointer(&p[i][x]))

		y0[j] = ring.MRed(pTmp[0], qoverqiinvqi, qi, qiInv)
		y1[j] = ring.MRed(pTmp[1], qoverqiinvqi, qi, qiInv)
		y2[j] = ring.MRed(pTmp[2], qoverqiinvqi, qi, qiInv)
		y3[j] = ring.MRed(pTmp[3], qoverqiinvqi, qi, qiInv)
		y4[j] = ring.MRed(pTmp[4], qoverqiinvqi, qi, qiInv)
		y5[j] = ring.MRed(pTmp[5], qoverqiinvqi, qi, qiInv)
		y6[j] = ring.MRed(pTmp[6], qoverqiinvqi, qi, qiInv)
		y7[j] = ring.MRed(pTmp[7], qoverqiinvqi, qi, qiInv)

		// Computation of the correction term v * Q%pi
		vi[0] += float64(y0[j]) / qif
		vi[1] += float64(y1[j]) / qif
		vi[2] += float64(y2[j]) / qif
		vi[3] += float64(y3[j]) / qif
		vi[4] += float64(y4[j]) / qif
		vi[5] += float64(y5[j]) / qif
		vi[6] += float64(y6[j]) / qif
		vi[7] += float64(y7[j]) / qif
	}

	v[0] = uint64(vi[0])
	v[1] = uint64(vi[1])
	v[2] = uint64(vi[2])
	v[3] = uint64(vi[3])
	v[4] = uint64(vi[4])
	v[5] = uint64(vi[5])
	v[6] = uint64(vi[6])
	v[7] = uint64(vi[7])
}

// Caution, returns the values in [0, 2q-1]
func multSum(level int, res, rlo, rhi, v *[8]uint64, y0, y1, y2, y3, y4, y5, y6, y7 *[32]uint64, q, qInv uint64, vtimesqmodp, qoverqimodp []uint64) {

	var mhi, mlo, c, hhi, qqip uint64

	qqip = qoverqimodp[0]

	rhi[0], rlo[0] = bits.Mul64(y0[0], qqip)
	rhi[1], rlo[1] = bits.Mul64(y1[0], qqip)
	rhi[2], rlo[2] = bits.Mul64(y2[0], qqip)
	rhi[3], rlo[3] = bits.Mul64(y3[0], qqip)
	rhi[4], rlo[4] = bits.Mul64(y4[0], qqip)
	rhi[5], rlo[5] = bits.Mul64(y5[0], qqip)
	rhi[6], rlo[6] = bits.Mul64(y6[0], qqip)
	rhi[7], rlo[7] = bits.Mul64(y7[0], qqip)

	// Accumulates the sum on uint128 and does a lazy montgomery reduction at the end
	for i := 1; i < level+1; i++ {

		qqip = qoverqimodp[i]

		mhi, mlo = bits.Mul64(y0[i], qqip)
		rlo[0], c = bits.Add64(rlo[0], mlo, 0)
		rhi[0] += mhi + c

		mhi, mlo = bits.Mul64(y1[i], qqip)
		rlo[1], c = bits.Add64(rlo[1], mlo, 0)
		rhi[1] += mhi + c

		mhi, mlo = bits.Mul64(y2[i], qqip)
		rlo[2], c = bits.Add64(rlo[2], mlo, 0)
		rhi[2] += mhi + c

		mhi, mlo = bits.Mul64(y3[i], qqip)
		rlo[3], c = bits.Add64(rlo[3], mlo, 0)
		rhi[3] += mhi + c

		mhi, mlo = bits.Mul64(y4[i], qqip)
		rlo[4], c = bits.Add64(rlo[4], mlo, 0)
		rhi[4] += mhi + c

		mhi, mlo = bits.Mul64(y5[i], qqip)
		rlo[5], c = bits.Add64(rlo[5], mlo, 0)
		rhi[5] += mhi + c

		mhi, mlo = bits.Mul64(y6[i], qqip)
		rlo[6], c = bits.Add64(rlo[6], mlo, 0)
		rhi[6] += mhi + c

		mhi, mlo = bits.Mul64(y7[i], qqip)
		rlo[7], c = bits.Add64(rlo[7], mlo, 0)
		rhi[7] += mhi + c
	}

	hhi, _ = bits.Mul64(rlo[0]*qInv, q)
	res[0] = rhi[0] - hhi + q + vtimesqmodp[v[0]]

	hhi, _ = bits.Mul64(rlo[1]*qInv, q)
	res[1] = rhi[1] - hhi + q + vtimesqmodp[v[1]]

	hhi, _ = bits.Mul64(rlo[2]*qInv, q)
	res[2] = rhi[2] - hhi + q + vtimesqmodp[v[2]]

	hhi, _ = bits.Mul64(rlo[3]*qInv, q)
	res[3] = rhi[3] - hhi + q + vtimesqmodp[v[3]]

	hhi, _ = bits.Mul64(rlo[4]*qInv, q)
	res[4] = rhi[4] - hhi + q + vtimesqmodp[v[4]]

	hhi, _ = bits.Mul64(rlo[5]*qInv, q)
	res[5] = rhi[5] - hhi + q + vtimesqmodp[v[5]]

	hhi, _ = bits.Mul64(rlo[6]*qInv, q)
	res[6] = rhi[6] - hhi + q + vtimesqmodp[v[6]]

	hhi, _ = bits.Mul64(rlo[7]*qInv, q)
	res[7] = rhi[7] - hhi + q + vtimesqmodp[v[7]]
}
