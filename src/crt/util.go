package crt

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/tuneinsight/lattigo/v5/ring"
)

func CRTUint64(residues, moduli []uint64) (*big.Int, *big.Int, error) {
	if len(residues) != len(moduli) {
		return nil, nil, errors.New("길이가 다릅니다")
	}
	if len(residues) == 0 {
		return nil, nil, errors.New("빈 입력")
	}

	// M = 전체 moduli 곱
	M := big.NewInt(1)
	for i, m := range moduli {
		if m == 0 {
			return nil, nil, fmt.Errorf("moduli[%d]는 0이 될 수 없음", i)
		}
		M.Mul(M, new(big.Int).SetUint64(m))
	}

	result := big.NewInt(0)

	for i := 0; i < len(moduli); i++ {
		ai := new(big.Int).SetUint64(residues[i])
		mi := new(big.Int).SetUint64(moduli[i])

		// ai = ai mod mi (안전하게 정규화)
		ai.Mod(ai, mi)

		// Mi = M / mi
		Mi := new(big.Int).Div(new(big.Int).Set(M), mi)

		// inv = Mi^{-1} mod mi
		inv := new(big.Int).ModInverse(Mi, mi)
		if inv == nil {
			return nil, nil, fmt.Errorf("moduli[%d]에서 역원이 없음 (서로소 아님)", i)
		}

		// term = ai * Mi * inv
		term := new(big.Int).Mul(ai, Mi)
		term.Mul(term, inv)

		result.Add(result, term)
	}

	// result ∈ [0, M)
	result.Mod(result, M)
	MHalf := new(big.Int).Rsh(M, uint(1))
	// MHalf = MHalf.Sub(MHalf, result)
	if result.Cmp(MHalf) == 1 {
		result = result.Sub(result, M)
	}

	return result, M, nil
}

// Computes:
// Q_A * [Qhat_B^{-1} mod Q_B]
func ComputeValue(q []uint64, blockA, blockB []int) (*big.Int, error) {
	n := len(q)

	usedB := make(map[int]bool, len(blockB))
	for _, i := range blockB {
		usedB[i] = true
	}

	QA := productByIndices(q, blockA)
	QB := productByIndices(q, blockB)

	compB := complementIndices(n, usedB)
	QhatB := productByIndices(q, compB)

	inv := new(big.Int).ModInverse(QhatB, QB)
	if inv == nil {
		return nil, fmt.Errorf("mod inverse does not exist")
	}
	result := new(big.Int).Mul(QA, inv)
	return result, nil
}

// Computes:
// Qhat_A * [Qhat_A^{-1} mod Q_A]
func ComputeValue2(q []uint64, blockA []int) (*big.Int, error) {
	n := len(q)

	usedA := make(map[int]bool, len(blockA))
	for _, i := range blockA {
		usedA[i] = true
	}

	QA := productByIndices(q, blockA)

	compA := complementIndices(n, usedA)
	QhatA := productByIndices(q, compA)

	inv := new(big.Int).ModInverse(QhatA, QA)
	if inv == nil {
		return nil, fmt.Errorf("mod inverse does not exist")
	}
	result := new(big.Int).Mul(QhatA, inv)
	return result, nil
}

func CheckPolyValue(poly ring.Poly, ringQ *ring.Ring) {
	polytemp := *poly.CopyNew()
	ringQ.INTT(polytemp, polytemp)
	ringQ.IMForm(polytemp, polytemp)
	fmt.Println("//////")
	for i := range polytemp.Coeffs {
		qHalf := int64(ringQ.ModuliChain()[i] >> 1)
		for j := range polytemp.Coeffs[i] {
			val := int64(polytemp.Coeffs[i][j])
			if val > qHalf {
				val -= int64(ringQ.ModuliChain()[i])
			}
			fmt.Print(val, ",")
		}
		fmt.Println()
	}
	fmt.Println("//////")
}

func productByIndices(q []uint64, indices []int) *big.Int {
	res := big.NewInt(1)
	for _, i := range indices {
		res.Mul(res, new(big.Int).SetUint64(q[i]))
	}
	return res
}

func complementIndices(n int, excluded map[int]bool) []int {
	out := make([]int, 0, n-len(excluded))
	for i := 0; i < n; i++ {
		if !excluded[i] {
			out = append(out, i)
		}
	}
	return out
}
