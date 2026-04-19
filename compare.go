package main

import (
	"crypto/rand"
	"math/big"
	"time"
)

// GenerateRandomBitVariable: r = sum(2^i * r_i)를 만족하는 랜덤 변수와 비트 쉐어를 생성
func (s *SecretSharingScheme) GenerateRandomBitVariable(parties []*Party, bitLen, varIdx int) {
	numCoeffs := s.Degree + 1
	numParties := s.NumParties

	// 1. 공간 안전 확보
	for p := 0; p < numParties; p++ {
		for len(parties[p].InputShares) <= varIdx {
			parties[p].InputShares = append(parties[p].InputShares, nil)
		}
		for len(parties[p].BitShares) <= varIdx {
			parties[p].BitShares = append(parties[p].BitShares, nil)
		}
		parties[p].BitShares[varIdx] = make([]BitShares, bitLen)
	}

	// 2. 계수별 랜덤 비트 생성 및 다항식 조립
	totalPoly := make([]*big.Int, numCoeffs)
	for j := 0; j < numCoeffs; j++ {
		totalPoly[j] = big.NewInt(0)
	}

	for i := 0; i < bitLen; i++ {
		bitPoly := make([]*big.Int, numCoeffs)
		for j := 0; j < numCoeffs; j++ {
			b, _ := rand.Int(rand.Reader, big.NewInt(2))
			bitPoly[j] = b

			term := new(big.Int).Lsh(b, uint(i))
			totalPoly[j].Add(totalPoly[j], term).Mod(totalPoly[j], s.Modulus)
		}

		// 비트 다항식 공유 및 저장
		shares := s.Share(bitPoly)
		for p := 0; p < numParties; p++ {
			parties[p].BitShares[varIdx][i] = BitShares{Shares: shares[p]}
		}
	}

	// 전체 다항식 r 공유 및 저장
	totalShares := s.Share(totalPoly)
	for p := 0; p < numParties; p++ {
		parties[p].InputShares[varIdx] = totalShares[p]
	}
}

// BitAND: 모든 참여자의 다항식 쉐어 x, y에 대해 계수별 논리곱(AND) 수행
func (s *SecretSharingScheme) BitAND(parties []*Party, xAll, yAll [][]AdditiveShare, tripleIdx int) [][]AdditiveShare {
	numParties := s.NumParties
	numCoeffs := s.Degree + 1

	dSharesAll := make([][]AdditiveShare, numParties)
	eSharesAll := make([][]AdditiveShare, numParties)

	for i := 0; i < numParties; i++ {
		dSharesAll[i] = make([]AdditiveShare, numCoeffs)
		eSharesAll[i] = make([]AdditiveShare, numCoeffs)
		triple := parties[i].BeaverTriple[tripleIdx]

		for j := 0; j < numCoeffs; j++ {
			dV := new(big.Int).Sub(xAll[i][j].Value, triple[0][j].Value)
			eV := new(big.Int).Sub(yAll[i][j].Value, triple[1][j].Value)
			dSharesAll[i][j] = AdditiveShare{Value: dV.Mod(dV, s.Modulus), Modulus: s.Modulus}
			eSharesAll[i][j] = AdditiveShare{Value: eV.Mod(eV, s.Modulus), Modulus: s.Modulus}
		}
	}

	opened := s.OpenMultiple(dSharesAll, eSharesAll)
	dPlain, ePlain := opened[0], opened[1]

	resAll := make([][]AdditiveShare, numParties)
	for i := 0; i < numParties; i++ {
		triple := parties[i].BeaverTriple[tripleIdx]
		resAll[i] = s.ComputeFinalShare(i, dPlain, ePlain, triple)
	}
	return resAll
}

// ComparePublic: 비밀 공유된 xIdx와 공개된 상수 배열 publicVals의 크기를 비교 (x < c)
func (s *SecretSharingScheme) ComparePublic(parties []*Party, xIdx int, publicVals []*big.Int, bitLen, resultIdx, tmpRandIdx int) []*Party {
	numParties := s.NumParties
	numCoeffs := s.Degree + 1

	// 1. 랜덤 마스킹 변수 r 생성 (tmpRandIdx 위치에 저장)
	s.GenerateRandomBitVariable(parties, bitLen, tmpRandIdx)

	// 2. [d] = [x] + [r] 계산 및 공개(Open)
	dSharesAll := make([][]AdditiveShare, numParties)
	for i := 0; i < numParties; i++ {
		dSharesAll[i] = make([]AdditiveShare, numCoeffs)
		for j := 0; j < numCoeffs; j++ {
			sum := new(big.Int).Add(parties[i].InputShares[xIdx][j].Value, parties[i].InputShares[tmpRandIdx][j].Value)
			dSharesAll[i][j] = AdditiveShare{Value: sum.Mod(sum, s.Modulus), Modulus: s.Modulus}
		}
	}
	dPlain := s.Open(dSharesAll)

	// 3. 비교 상태 변수 초기화 (ltPrev = 0)
	ltPrev := make([][]AdditiveShare, numParties)
	for p := 0; p < numParties; p++ {
		ltPrev[p] = make([]AdditiveShare, numCoeffs)
		for j := 0; j < numCoeffs; j++ {
			ltPrev[p][j] = AdditiveShare{Value: big.NewInt(0), Modulus: s.Modulus}
		}
	}

	// 4. c' = d - c 계산 및 상수 배열 저장
	cPrimeVals := make([]*big.Int, numCoeffs)
	for j := 0; j < numCoeffs; j++ {
		cPrimeVals[j] = new(big.Int).Sub(dPlain[j], publicVals[j])
	}

	// 5. LSB부터 MSB까지 1비트씩 순차 비교 (c' < r 인지 확인)
	tripleIdx := 0
	for i := 0; i < bitLen; i++ {
		// r의 i번째 비트 추출
		riAll := make([][]AdditiveShare, numParties)
		for p := 0; p < numParties; p++ {
			riAll[p] = parties[p].BitShares[tmpRandIdx][i].Shares
		}

		// [and_res] = [r_i] & [lt_prev] (비트당 1개의 트리플 소모)
		andRes := s.BitAND(parties, riAll, ltPrev, tripleIdx)
		tripleIdx++

		// 다음 상태(ltNext) 계산 (로컬 연산)
		ltNext := make([][]AdditiveShare, numParties)
		for p := 0; p < numParties; p++ {
			ltNext[p] = make([]AdditiveShare, numCoeffs)
			for j := 0; j < numCoeffs; j++ {
				// c'가 음수이거나 범위를 넘어가면 비트 연산 생략 (나중에 일괄 처리)
				if cPrimeVals[j].Sign() < 0 || cPrimeVals[j].BitLen() > bitLen {
					ltNext[p][j] = ltPrev[p][j] // 더미 데이터 유지
					continue
				}

				cBit := cPrimeVals[j].Bit(i)
				if cBit == 0 {
					// cBit == 0: lt_next = r_i + lt_prev - and_res
					v := new(big.Int).Add(riAll[p][j].Value, ltPrev[p][j].Value)
					v.Sub(v, andRes[p][j].Value)
					ltNext[p][j] = AdditiveShare{Value: v.Mod(v, s.Modulus), Modulus: s.Modulus}
				} else {
					// cBit == 1: lt_next = and_res
					ltNext[p][j] = AdditiveShare{Value: new(big.Int).Set(andRes[p][j].Value), Modulus: s.Modulus}
				}
			}
		}
		ltPrev = ltNext
	}

	// 6. 경계 조건(Boundary Conditions) 후처리 및 결과 저장
	for p := 0; p < numParties; p++ {
		for len(parties[p].InputShares) <= resultIdx {
			parties[p].InputShares = append(parties[p].InputShares, nil)
		}

		finalRes := make([]AdditiveShare, numCoeffs)
		for j := 0; j < numCoeffs; j++ {
			if cPrimeVals[j].Sign() < 0 {
				// d < c 이면, x <= d < c 이므로 항상 x < c (결과 1)
				val := big.NewInt(0)
				if p == 0 {
					val.SetInt64(1)
				}
				finalRes[j] = AdditiveShare{Value: val, Modulus: s.Modulus}
			} else if cPrimeVals[j].BitLen() > bitLen {
				// d - c >= 2^bitLen 이면, x > c 이므로 항상 거짓 (결과 0)
				finalRes[j] = AdditiveShare{Value: big.NewInt(0), Modulus: s.Modulus}
			} else {
				// 일반적인 경우 회로 결과값 적용
				finalRes[j] = ltPrev[p][j]
			}
		}
		parties[p].InputShares[resultIdx] = finalRes
	}

	return parties
}

// AndPairBatch: BitANDBatch의 입력 인자 구조체
type AndPairBatch struct {
	X [][]AdditiveShare
	Y [][]AdditiveShare
}

// BitANDBatch: 여러 개의 (X, Y) 쌍을 단 1회의 통신 라운드로 일괄 계산
func (s *SecretSharingScheme) BitANDBatch(parties []*Party, pairs []AndPairBatch, startTripleIdx int) [][][]AdditiveShare {
	numParties := s.NumParties
	numCoeffs := s.Degree + 1
	numPairs := len(pairs)

	dSharesAll := make([][][]AdditiveShare, numPairs)
	eSharesAll := make([][][]AdditiveShare, numPairs)

	// 1. Local Masking (모든 쌍에 대해 수행)
	for k := 0; k < numPairs; k++ {
		dSharesAll[k] = make([][]AdditiveShare, numParties)
		eSharesAll[k] = make([][]AdditiveShare, numParties)
		//tripleIdx := startTripleIdx + k

		for i := 0; i < numParties; i++ {
			t := time.Now()
			dSharesAll[k][i] = make([]AdditiveShare, numCoeffs)
			eSharesAll[k][i] = make([]AdditiveShare, numCoeffs)
			triple := parties[i].BeaverTriple[0]

			for j := 0; j < numCoeffs; j++ {
				dV := new(big.Int).Sub(pairs[k].X[i][j].Value, triple[0][j].Value)
				eV := new(big.Int).Sub(pairs[k].Y[i][j].Value, triple[1][j].Value)
				dSharesAll[k][i][j] = AdditiveShare{Value: dV.Mod(dV, s.Modulus), Modulus: s.Modulus}
				eSharesAll[k][i][j] = AdditiveShare{Value: eV.Mod(eV, s.Modulus), Modulus: s.Modulus}
			}
			parties[i].LocalTime += time.Since(t)
		}
	}

	// 2. OpenMultiple (단 1번의 통신 라운드 발생)
	var openArgs [][][]AdditiveShare
	for k := 0; k < numPairs; k++ {
		openArgs = append(openArgs, dSharesAll[k], eSharesAll[k])
	}
	opened := s.OpenMultiple(openArgs...)

	// 3. Final Computation
	results := make([][][]AdditiveShare, numPairs)
	for k := 0; k < numPairs; k++ {
		dPlain := opened[2*k]
		ePlain := opened[2*k+1]
		//tripleIdx := startTripleIdx + k

		resAll := make([][]AdditiveShare, numParties)
		for i := 0; i < numParties; i++ {
			t := time.Now()
			triple := parties[i].BeaverTriple[0]
			resAll[i] = s.ComputeFinalShare(i, dPlain, ePlain, triple)
			parties[i].LocalTime += time.Since(t)
		}
		results[k] = resAll
	}

	return results
}

type CompareNode struct {
	G [][]AdditiveShare // [Party][Coefficient]
	P [][]AdditiveShare
}

// ComparePublicTree: 공개 상수와의 비교를 이진 트리 기반으로 최적화 (X >= C 일 때 1 반환)
func (s *SecretSharingScheme) ComparePublicTree(parties []*Party, xIdx int, publicVals []*big.Int, bitLen, resultIdx, tmpRandIdx int) []*Party {
	numParties := s.NumParties
	numCoeffs := s.Degree + 1

	// 1. 랜덤 마스킹 및 Open (1라운드)
	s.GenerateRandomBitVariable(parties, bitLen, tmpRandIdx)
	dSharesAll := make([][]AdditiveShare, numParties)
	for i := 0; i < numParties; i++ {
		t := time.Now()
		dSharesAll[i] = make([]AdditiveShare, numCoeffs)
		for j := 0; j < numCoeffs; j++ {
			sum := new(big.Int).Add(parties[i].InputShares[xIdx][j].Value, parties[i].InputShares[tmpRandIdx][j].Value)
			dSharesAll[i][j] = AdditiveShare{Value: sum.Mod(sum, s.Modulus), Modulus: s.Modulus}
		}
		parties[i].LocalTime += time.Since(t)
	}
	dPlain := s.Open(dSharesAll)

	// 2. c' = d - c 계산
	cPrimeVals := make([]*big.Int, numCoeffs)
	for j := 0; j < numCoeffs; j++ {
		cPrimeVals[j] = new(big.Int).Sub(dPlain[j], publicVals[j])
	}

	// 3. Level 0 단말 노드 초기화
	var nodes []CompareNode
	for bit := 0; bit < bitLen; bit++ {
		G_bit := make([][]AdditiveShare, numParties)
		P_bit := make([][]AdditiveShare, numParties)

		for p := 0; p < numParties; p++ {
			t := time.Now()
			G_bit[p] = make([]AdditiveShare, numCoeffs)
			P_bit[p] = make([]AdditiveShare, numCoeffs)

			for j := 0; j < numCoeffs; j++ {
				if cPrimeVals[j].Sign() < 0 || cPrimeVals[j].BitLen() > bitLen {
					G_bit[p][j] = AdditiveShare{Value: big.NewInt(0), Modulus: s.Modulus}
					P_bit[p][j] = AdditiveShare{Value: big.NewInt(0), Modulus: s.Modulus}
					continue
				}

				cBit := cPrimeVals[j].Bit(bit)
				r_ij := parties[p].BitShares[tmpRandIdx][bit].Shares[j].Value

				if cBit == 0 {
					G_bit[p][j] = AdditiveShare{Value: new(big.Int).Set(r_ij), Modulus: s.Modulus}
					pVal := new(big.Int).Sub(big.NewInt(0), r_ij)
					if p == 0 {
						pVal.Add(pVal, big.NewInt(1))
					}
					P_bit[p][j] = AdditiveShare{Value: pVal.Mod(pVal, s.Modulus), Modulus: s.Modulus}
				} else {
					G_bit[p][j] = AdditiveShare{Value: big.NewInt(0), Modulus: s.Modulus}
					P_bit[p][j] = AdditiveShare{Value: new(big.Int).Set(r_ij), Modulus: s.Modulus}
				}
			}
			parties[p].LocalTime += time.Since(t)
		}
		nodes = append(nodes, CompareNode{G: G_bit, P: P_bit})
	}

	// 4. 이진 트리 축소 (O(log bitLen) 라운드)
	tripleIdx := 0
	for len(nodes) > 1 {
		numPairs := len(nodes) / 2
		var batchPairs []AndPairBatch

		for m := 0; m < numPairs; m++ {
			L := nodes[2*m+1]
			R := nodes[2*m]
			batchPairs = append(batchPairs, AndPairBatch{X: L.P, Y: R.G})
			batchPairs = append(batchPairs, AndPairBatch{X: L.P, Y: R.P})
		}

		TripleCount += 1
		mulResults := s.BitANDBatch(parties, batchPairs, tripleIdx)
		tripleIdx += len(batchPairs)

		var nextNodes []CompareNode
		for m := 0; m < numPairs; m++ {
			L := nodes[2*m+1]
			termPG := mulResults[2*m]
			termPP := mulResults[2*m+1]

			G_new := make([][]AdditiveShare, numParties)
			for p := 0; p < numParties; p++ {
				t := time.Now()
				G_new[p] = make([]AdditiveShare, numCoeffs)
				for j := 0; j < numCoeffs; j++ {
					v := new(big.Int).Add(L.G[p][j].Value, termPG[p][j].Value)
					G_new[p][j] = AdditiveShare{Value: v.Mod(v, s.Modulus), Modulus: s.Modulus}
				}
				parties[p].LocalTime += time.Since(t)
			}
			nextNodes = append(nextNodes, CompareNode{G: G_new, P: termPP})
		}

		if len(nodes)%2 != 0 {
			nextNodes = append(nextNodes, nodes[len(nodes)-1])
		}
		nodes = nextNodes
	}

	// 🚀 5. 최종 결과 산출 및 반전 (X >= C 조건 적용)
	for p := 0; p < numParties; p++ {
		t := time.Now()
		for len(parties[p].InputShares) <= resultIdx {
			parties[p].InputShares = append(parties[p].InputShares, nil)
		}

		finalRes := make([]AdditiveShare, numCoeffs)
		for j := 0; j < numCoeffs; j++ {
			if cPrimeVals[j].Sign() < 0 {
				// d < c 이면, X < C 가 확실함. 따라서 X >= C 는 거짓(0)
				finalRes[j] = AdditiveShare{Value: big.NewInt(0), Modulus: s.Modulus}
			} else if cPrimeVals[j].BitLen() > bitLen {
				// d - c >= 2^bitLen 이면, X > C 가 확실함. 따라서 X >= C 는 참(1)
				val := big.NewInt(0)
				if p == 0 {
					val.SetInt64(1)
				}
				finalRes[j] = AdditiveShare{Value: val, Modulus: s.Modulus}
			} else {
				// 일반적인 경우: nodes[0].G 는 (X < C) 일 때 1이 됨.
				// 따라서 1 - G 를 계산하여 (X >= C) 로 반전시킴!
				v := new(big.Int).Sub(big.NewInt(0), nodes[0].G[p][j].Value) // -G
				if p == 0 {
					v.Add(v, big.NewInt(1)) // Party 0이 상수 1을 더해 1 - G 로 만듦
				}
				finalRes[j] = AdditiveShare{Value: v.Mod(v, s.Modulus), Modulus: s.Modulus}
			}
		}
		parties[p].InputShares[resultIdx] = finalRes
		parties[p].LocalTime += time.Since(t)
	}

	return parties
}
