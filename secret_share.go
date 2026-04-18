package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	mathRand "math/rand" // 별칭(Alias)을 부여하여 이름 충돌 방지
	"sync"
	"tifs/src/crt"
	"time"
)

type AdditiveShare struct {
	Value   *big.Int // uint64에서 *big.Int로 변경
	Modulus *big.Int
}

// BitShares: 특정 비트 자릿수의 계수별 쉐어들을 담음
type BitShares struct {
	Shares []AdditiveShare // [Coefficient Index]
}

type Party struct {
	ID           int
	InputShares  [][]AdditiveShare   // [Variable ID][Coefficient]
	BitShares    [][]BitShares       // [Variable ID][Bit Index][Coefficient]
	BeaverTriple [][][]AdditiveShare // [Triple ID][ABC(0:a, 1:b, 2:c)][Coefficient]
}
type SecretSharingScheme struct {
	Modulus             *big.Int
	NumParties          int
	Degree              int
	CommunicationRounds int
	TotalCommBytes      uint64
}

func NewSecretSharingScheme(modulus *big.Int, n int, deg int) *SecretSharingScheme {
	return &SecretSharingScheme{
		Modulus:    modulus,
		NumParties: n,
		Degree:     deg,
	}
}

// Share: 다항식을 n개의 쉐어로 분할
func (s *SecretSharingScheme) Share(poly []*big.Int) [][]AdditiveShare {
	numCoeffs := s.Degree + 1
	shares := make([][]AdditiveShare, s.NumParties)
	for i := range shares {
		shares[i] = make([]AdditiveShare, numCoeffs)
	}

	var wg sync.WaitGroup

	// 각 계수(j)에 대해 병렬로 고루틴을 실행합니다.
	for j := 0; j < numCoeffs; j++ {
		wg.Add(1) // 대기해야 할 고루틴 개수 추가

		// 💡 주의: for 루프 변수 j를 고루틴 내부로 안전하게 전달하기 위해 익명 함수의 인자로 넘깁니다.
		go func(j int) {
			defer wg.Done() // 함수가 종료될 때 WaitGroup 감소

			// 🚀 핵심: 고루틴마다 '독립적인' 난수 생성기를 만듭니다.
			// 동시에 실행되더라도 시드값이 겹치지 않도록 j를 더해줍니다.
			seed := time.Now().UnixNano() + int64(j)
			localRng := mathRand.New(mathRand.NewSource(seed))

			coeff := poly[j]
			sum := big.NewInt(0)

			for i := 0; i < s.NumParties-1; i++ {
				// 내부 루프마다 난수 생성기를 만들지 않고, 고루틴별로 만들어둔 localRng를 재사용합니다. (속도 대폭 향상)
				r := new(big.Int).Rand(localRng, s.Modulus)

				// 배열(shares)의 서로 다른 인덱스[j]에 접근하므로 동시성 충돌(Race Condition)이 발생하지 않습니다.
				shares[i][j] = AdditiveShare{Value: new(big.Int).Set(r), Modulus: s.Modulus}
				sum.Add(sum, r).Mod(sum, s.Modulus)
			}

			last := new(big.Int).Sub(coeff, sum)
			last.Mod(last, s.Modulus)
			shares[s.NumParties-1][j] = AdditiveShare{Value: last, Modulus: s.Modulus}

		}(j) // 익명 함수 호출 및 j 값 복사 전달
	}

	// 모든 고루틴의 작업이 끝날 때까지 메인 스레드를 블로킹(대기)합니다.
	wg.Wait()

	return shares
}

// Share_special: 첫 번째 참여자에게 0을 할당하는 특수 분할
func (s *SecretSharingScheme) ShareAuthority(poly []*big.Int) [][]AdditiveShare {
	numCoeffs := s.Degree + 1
	shares := make([][]AdditiveShare, s.NumParties)
	for i := range shares {
		shares[i] = make([]AdditiveShare, numCoeffs)
	}

	for j := 0; j < numCoeffs; j++ {
		coeff := poly[j]
		sum := big.NewInt(0)

		// Party 0 gets 0
		shares[0][j] = AdditiveShare{Value: big.NewInt(0), Modulus: s.Modulus}

		for i := 1; i < s.NumParties-1; i++ {
			r, _ := rand.Int(rand.Reader, s.Modulus)
			shares[i][j] = AdditiveShare{Value: new(big.Int).Set(r), Modulus: s.Modulus}
			sum.Add(sum, r).Mod(sum, s.Modulus)
		}

		last := new(big.Int).Sub(coeff, sum)
		last.Mod(last, s.Modulus)
		shares[s.NumParties-1][j] = AdditiveShare{Value: last, Modulus: s.Modulus}
	}
	return shares
}

// Share_special: 첫 번째 참여자에게 0을 할당하는 특수 분할
func (s *SecretSharingScheme) ShareSever(poly []*big.Int) [][]AdditiveShare {
	numCoeffs := s.Degree + 1
	shares := make([][]AdditiveShare, s.NumParties)
	for i := range shares {
		shares[i] = make([]AdditiveShare, numCoeffs)
	}

	for j := 0; j < numCoeffs; j++ {
		coeff := poly[j]
		sum := big.NewInt(0)

		// Party 0 gets poly
		shares[0][j] = AdditiveShare{Value: coeff, Modulus: s.Modulus}
		r := big.NewInt(0)
		for i := 1; i < s.NumParties; i++ {
			shares[i][j] = AdditiveShare{Value: new(big.Int).Set(r), Modulus: s.Modulus}
			sum.Add(sum, r).Mod(sum, s.Modulus)
		}
	}
	return shares
}

// Open: 다항식 복원
func (s *SecretSharingScheme) Open(allShares [][]AdditiveShare) []*big.Int {
	numCoeffs := s.Degree + 1
	s.CommunicationRounds++
	// *big.Int의 대략적인 크기를 측정 (Modulus 비트 수 기준)
	byteSize := uint64((s.Modulus.BitLen() + 7) / 8)
	s.TotalCommBytes += uint64(s.NumParties*numCoeffs) * byteSize

	reconstructedPoly := make([]*big.Int, numCoeffs)
	for j := 0; j < numCoeffs; j++ {
		sum := big.NewInt(0)
		for i := 0; i < s.NumParties; i++ {
			sum.Add(sum, allShares[i][j].Value).Mod(sum, s.Modulus)
		}
		reconstructedPoly[j] = new(big.Int).Set(sum)
	}
	return reconstructedPoly
}

// OpenMultiple: 여러 다항식 동시 복원
func (s *SecretSharingScheme) OpenMultiple(allSets ...[][]AdditiveShare) [][]*big.Int {
	if len(allSets) == 0 {
		return nil
	}
	numCoeffs := s.Degree + 1
	numSets := len(allSets)
	s.CommunicationRounds++
	byteSize := uint64((s.Modulus.BitLen() + 7) / 8)
	s.TotalCommBytes += uint64(s.NumParties*numCoeffs*numSets) * byteSize

	results := make([][]*big.Int, numSets)
	for k, set := range allSets {
		reconstructedPoly := make([]*big.Int, numCoeffs)
		for j := 0; j < numCoeffs; j++ {
			sum := big.NewInt(0)
			for i := 0; i < s.NumParties; i++ {
				sum.Add(sum, set[i][j].Value).Mod(sum, s.Modulus)
			}
			reconstructedPoly[j] = new(big.Int).Set(sum)
		}
		results[k] = reconstructedPoly
	}
	return results
}

// GenerateBeaverTriples: 트리플 생성
func (s *SecretSharingScheme) GenerateBeaverTriples(count int) [][][][]AdditiveShare {
	numCoeffs := s.Degree + 1
	allPartiesTriples := make([][][][]AdditiveShare, s.NumParties)
	for p := 0; p < s.NumParties; p++ {
		allPartiesTriples[p] = make([][][]AdditiveShare, count)
		for t := 0; t < count; t++ {
			allPartiesTriples[p][t] = make([][]AdditiveShare, 3)
		}
	}

	for t := 0; t < count; t++ {
		polyA := make([]*big.Int, numCoeffs)
		polyB := make([]*big.Int, numCoeffs)
		polyC := make([]*big.Int, numCoeffs)

		for j := 0; j < numCoeffs; j++ {
			a, _ := rand.Int(rand.Reader, s.Modulus)
			b, _ := rand.Int(rand.Reader, s.Modulus)
			c := new(big.Int).Mul(a, b)
			c.Mod(c, s.Modulus)
			polyA[j], polyB[j], polyC[j] = a, b, c
		}

		sharesA := s.Share(polyA)
		sharesB := s.Share(polyB)
		sharesC := s.Share(polyC)

		for p := 0; p < s.NumParties; p++ {
			allPartiesTriples[p][t][0] = sharesA[p]
			allPartiesTriples[p][t][1] = sharesB[p]
			allPartiesTriples[p][t][2] = sharesC[p]
		}
	}
	return allPartiesTriples
}

// Add: 두 다항식 쉐어를 로컬에서 더함 (통신 발생 안 함)
// shares1, shares2: 더하고자 하는 두 다항식의 계수 쉐어 슬라이스
func (s *SecretSharingScheme) AddLocal(shares1, shares2 []AdditiveShare) []AdditiveShare {
	numCoeffs := s.Degree + 1
	result := make([]AdditiveShare, numCoeffs)

	for j := 0; j < numCoeffs; j++ {
		// 두 쉐어의 값을 더함: res = (val1 + val2) mod Modulus
		val := new(big.Int).Add(shares1[j].Value, shares2[j].Value)

		result[j] = AdditiveShare{
			Value:   val.Mod(val, s.Modulus),
			Modulus: s.Modulus,
		}
	}

	return result
}

// Add: 모든 참여자의 특정 인덱스 쉐어들을 더하고 지정된 resultIdx에 결과를 저장
func (s *SecretSharingScheme) Add(parties []*Party, xIdx, yIdx, resultIdx int) []*Party {
	for i := 0; i < s.NumParties; i++ {
		// 로컬 덧셈 수행
		res := s.AddLocal(parties[i].InputShares[xIdx], parties[i].InputShares[yIdx])

		// 지정된 resultIdx까지 공간 확보
		for len(parties[i].InputShares) <= resultIdx {
			parties[i].InputShares = append(parties[i].InputShares, nil)
		}

		// 해당 인덱스에 결과 저장
		parties[i].InputShares[resultIdx] = res
	}
	return parties
}

// AddPublic: 비밀 쉐어(xIdx)에 공개 상수 다항식(publicVals)을 더하여 resultIdx에 저장 (0 Round 로컬 연산)
// 연산식: [res] = [x] + publicVals
func (s *SecretSharingScheme) AddPublic(parties []*Party, xIdx int, publicVals []*big.Int, resultIdx int) []*Party {
	numParties := s.NumParties
	numCoeffs := s.Degree + 1

	// 💡 안정성 검증 로직 (Panic 방지)
	if len(publicVals) != numCoeffs {
		panic("AddPublic 오류: publicVals의 길이가 다항식 계수 개수와 일치하지 않습니다.")
	}
	if len(parties[0].InputShares) <= xIdx {
		panic("AddPublic 오류: xIdx가 유효한 범위를 벗어났습니다.")
	}

	for i := 0; i < numParties; i++ {
		res := make([]AdditiveShare, numCoeffs)
		for j := 0; j < numCoeffs; j++ {
			// 원본 쉐어 값을 안전하게 복사 (포인터 오염 방지)
			val := new(big.Int).Set(parties[i].InputShares[xIdx][j].Value)

			// 🚀 핵심: 오직 Party 0만 공개 상수를 더합니다.
			// (나머지 Party는 원본 쉐어 값을 그대로 유지)
			if i == 0 {
				val.Add(val, publicVals[j])
			}

			// 모듈러 연산 후 저장
			res[j] = AdditiveShare{Value: val.Mod(val, s.Modulus), Modulus: s.Modulus}
		}

		// resultIdx 공간 안전하게 확보
		for len(parties[i].InputShares) <= resultIdx {
			parties[i].InputShares = append(parties[i].InputShares, nil)
		}

		// 해당 인덱스에 결과 저장
		parties[i].InputShares[resultIdx] = res
	}

	return parties
}

// SubLocal: 두 다항식 쉐어를 로컬에서 뺌 (통신 발생 안 함)
// shares1, shares2: 빼고자 하는 두 다항식의 계수 쉐어 슬라이스 (shares1 - shares2)
func (s *SecretSharingScheme) SubLocal(shares1, shares2 []AdditiveShare) []AdditiveShare {
	numCoeffs := s.Degree + 1
	result := make([]AdditiveShare, numCoeffs)

	for j := 0; j < numCoeffs; j++ {
		// 두 쉐어의 값을 뺌: res = (val1 - val2) mod Modulus
		val := new(big.Int).Sub(shares1[j].Value, shares2[j].Value)

		result[j] = AdditiveShare{
			// big.Int.Mod는 음수를 자동으로 양수 합동값으로 변환해줍니다.
			Value:   val.Mod(val, s.Modulus),
			Modulus: s.Modulus,
		}
	}

	return result
}

// Sub: 모든 참여자의 특정 인덱스 쉐어들을 빼고 지정된 resultIdx에 결과를 저장
// xIdx 요소에서 yIdx 요소를 뺍니다. (xIdx - yIdx)
func (s *SecretSharingScheme) Sub(parties []*Party, xIdx, yIdx, resultIdx int) []*Party {
	for i := 0; i < s.NumParties; i++ {
		// 로컬 뺄셈 수행
		res := s.SubLocal(parties[i].InputShares[xIdx], parties[i].InputShares[yIdx])

		// 지정된 resultIdx까지 공간 확보
		for len(parties[i].InputShares) <= resultIdx {
			parties[i].InputShares = append(parties[i].InputShares, nil)
		}

		// 해당 인덱스에 결과 저장
		parties[i].InputShares[resultIdx] = res
	}
	return parties
}

// MultiplyLocal: 로컬 마스킹
func (s *SecretSharingScheme) MultiplyLocal(p *Party, xIdx, yIdx, tripleIdx int) ([]AdditiveShare, []AdditiveShare) {
	xShares := p.InputShares[xIdx]
	yShares := p.InputShares[yIdx]
	triple := p.BeaverTriple[tripleIdx]

	numCoeffs := len(xShares)
	dShares := make([]AdditiveShare, numCoeffs)
	eShares := make([]AdditiveShare, numCoeffs)

	for j := 0; j < numCoeffs; j++ {
		dVal := new(big.Int).Sub(xShares[j].Value, triple[0][j].Value)
		eVal := new(big.Int).Sub(yShares[j].Value, triple[1][j].Value)

		dShares[j] = AdditiveShare{Value: dVal.Mod(dVal, s.Modulus), Modulus: s.Modulus}
		eShares[j] = AdditiveShare{Value: eVal.Mod(eVal, s.Modulus), Modulus: s.Modulus}
	}
	return dShares, eShares
}

// ComputeFinalShare: 최종 선형 결합
func (s *SecretSharingScheme) ComputeFinalShare(partyID int, d, e []*big.Int, triple [][]AdditiveShare) []AdditiveShare {
	numCoeffs := s.Degree + 1
	zShares := make([]AdditiveShare, numCoeffs)

	for j := 0; j < numCoeffs; j++ {
		res := big.NewInt(0)
		if partyID == 0 {
			res.Mul(d[j], e[j])
		}

		termDb := new(big.Int).Mul(d[j], triple[1][j].Value)
		termEa := new(big.Int).Mul(e[j], triple[0][j].Value)
		termC := triple[2][j].Value

		res.Add(res, termDb).Add(res, termEa).Add(res, termC)
		res.Mod(res, s.Modulus)

		zShares[j] = AdditiveShare{Value: new(big.Int).Set(res), Modulus: s.Modulus}
	}
	return zShares
}

// Multiply: Beaver Triple을 사용하여 곱셈을 수행하고 지정된 resultIdx에 결과를 저장
func (s *SecretSharingScheme) Multiply(parties []*Party, xIdx, yIdx, tripleIdx, resultIdx int) []*Party {
	numParties := s.NumParties
	dSharesAll := make([][]AdditiveShare, numParties)
	eSharesAll := make([][]AdditiveShare, numParties)

	// 1. Local Masking
	for i := 0; i < numParties; i++ {
		dSharesAll[i], eSharesAll[i] = s.MultiplyLocal(parties[i], xIdx, yIdx, tripleIdx)
	}

	// 2. Open (1 Round)
	openedValues := s.OpenMultiple(dSharesAll, eSharesAll)
	dPlain, ePlain := openedValues[0], openedValues[1]

	// 3. Final Computation & State Update
	for i := 0; i < numParties; i++ {
		triple := parties[i].BeaverTriple[tripleIdx]
		res := s.ComputeFinalShare(i, dPlain, ePlain, triple)

		// 지정된 resultIdx까지 공간 확보
		for len(parties[i].InputShares) <= resultIdx {
			parties[i].InputShares = append(parties[i].InputShares, nil)
		}

		// 해당 인덱스에 결과 저장
		parties[i].InputShares[resultIdx] = res
	}
	return parties
}

// MultiplyPublic: 비밀 쉐어(xIdx)와 공개 상수(publicVals)를 곱하여 resultIdx에 저장 (로컬 연산)
// 연산식: [res] = [x] * publicVals
func (s *SecretSharingScheme) MultiplyPublic(parties []*Party, xIdx int, publicVals []*big.Int, resultIdx int) []*Party {
	numParties := s.NumParties
	numCoeffs := s.Degree + 1

	// 💡 안정성 검증 로직 (Panic 방지)
	if len(publicVals) != numCoeffs {
		panic("MultiplyPublic 오류: publicVals의 길이가 다항식 계수 개수와 일치하지 않습니다.")
	}
	if len(parties[0].InputShares) <= xIdx {
		panic("MultiplyPublic 오류: xIdx가 유효한 범위를 벗어났습니다.")
	}

	for i := 0; i < numParties; i++ {
		res := make([]AdditiveShare, numCoeffs)
		for j := 0; j < numCoeffs; j++ {
			// [x] * publicVal 계산 (로컬 스칼라 곱셈)
			// 각각의 참여자가 자신이 가진 쉐어에 공개 상수를 곱하기만 하면 됩니다.
			val := new(big.Int).Mul(parties[i].InputShares[xIdx][j].Value, publicVals[j])

			res[j] = AdditiveShare{Value: val.Mod(val, s.Modulus), Modulus: s.Modulus}
		}

		// resultIdx 공간 안전하게 확보
		for len(parties[i].InputShares) <= resultIdx {
			parties[i].InputShares = append(parties[i].InputShares, nil)
		}

		// 해당 인덱스에 결과 저장
		parties[i].InputShares[resultIdx] = res
	}

	return parties
}

// Add: 두 다항식 쉐어를 로컬에서 더함 (통신 발생 안 함)
// shares1, shares2: 더하고자 하는 두 다항식의 계수 쉐어 슬라이스
func (s *SecretSharingScheme) ModLocal(shares1 []AdditiveShare, mod *big.Int) []AdditiveShare {
	numCoeffs := s.Degree + 1
	result := make([]AdditiveShare, numCoeffs)

	for j := 0; j < numCoeffs; j++ {
		// 두 쉐어의 값을 더함: res = (val1 + val2) mod Modulus
		val := new(big.Int).Mod(shares1[j].Value, mod)

		result[j] = AdditiveShare{
			Value:   val.Mod(val, s.Modulus),
			Modulus: s.Modulus,
		}
	}
	//fmt.Println(mod, s.Modulus)

	return result
}

// Add: 모든 참여자의 특정 인덱스 쉐어들을 더하고 지정된 resultIdx에 결과를 저장
func (s *SecretSharingScheme) Mod(parties []*Party, xIdx int, mod *big.Int, resultIdx int) []*Party {
	for i := 0; i < s.NumParties; i++ {
		// 로컬 덧셈 수행
		res := s.ModLocal(parties[i].InputShares[xIdx], mod)

		// 지정된 resultIdx까지 공간 확보
		for len(parties[i].InputShares) <= resultIdx {
			parties[i].InputShares = append(parties[i].InputShares, nil)
		}

		// 해당 인덱스에 결과 저장
		parties[i].InputShares[resultIdx] = res
	}
	return parties
}

// ConditionalSubPublic: condIdx의 쉐어(0 또는 1)가 1일 때만 xIdx에서 공개 상수 publicVals를 뺌
// 연산식: [res] = [x] - [cond] * publicVals
func (s *SecretSharingScheme) ConditionalSubPublic(parties []*Party, xIdx int, publicVals []*big.Int, condIdx, resultIdx int) []*Party {
	numParties := s.NumParties
	numCoeffs := s.Degree + 1

	for i := 0; i < numParties; i++ {
		res := make([]AdditiveShare, numCoeffs)
		for j := 0; j < numCoeffs; j++ {
			// 1. [cond] * publicVal 계산 (로컬 스칼라 곱셈)
			term := new(big.Int).Mul(parties[i].InputShares[condIdx][j].Value, publicVals[j])

			// 2. [x] - term 계산
			val := new(big.Int).Sub(parties[i].InputShares[xIdx][j].Value, term)

			res[j] = AdditiveShare{Value: val.Mod(val, s.Modulus), Modulus: s.Modulus}
		}

		// resultIdx에 결과 저장
		for len(parties[i].InputShares) <= resultIdx {
			parties[i].InputShares = append(parties[i].InputShares, nil)
		}
		parties[i].InputShares[resultIdx] = res
	}

	return parties
}

// Helper: 전체 모듈러스 Q 계산
func computeQ(modulus []*big.Int) (*big.Int, error) {
	if len(modulus) == 0 {
		return nil, fmt.Errorf("modulus slice is empty")
	}
	Q := big.NewInt(1)
	for i, m := range modulus {
		if m.Sign() <= 0 {
			return nil, fmt.Errorf("invalid modulus at index %d", i)
		}
		Q.Mul(Q, m)
	}
	return Q, nil
}

// findPrimitiveRootCRT: 여러 소수 모듈러스에 대해 각각 원시 거듭제곱근을 찾고 CRT로 병합
// findPrimitiveRootCRT: 여러 소수 모듈러스에 대해 각각 원시 거듭제곱근을 찾고 CRT로 병합 (결정론적 탐색)
func findPrimitiveRootCRT(moduli []*big.Int, rootDegree int) (*big.Int, error) {
	var psiResidues []*big.Int
	degreeBig := big.NewInt(int64(rootDegree)) // Negacyclic의 경우 2N

	// 1. 각각의 작은 소수 q_i 에 대해 원시 거듭제곱근 psi_i 를 찾음
	for i, q := range moduli {
		qMinus1 := new(big.Int).Sub(q, big.NewInt(1))

		// q_i 가 1 (mod 2N) 을 만족하는지 확인 (NTT-friendly 조건)
		if new(big.Int).Mod(qMinus1, degreeBig).Sign() != 0 {
			return nil, fmt.Errorf("moduli[%d]는 %d-th NTT를 지원하지 않습니다 (1 mod 2N 아님)", i, rootDegree)
		}

		power := new(big.Int).Div(qMinus1, degreeBig)
		found := false

		// 🚀 핵심 수정: rand 대신 a=2 부터 순차 탐색하여 매번 '동일한' 루트를 찾도록 강제함
		for a_int := int64(2); a_int < 10000; a_int++ {
			a := big.NewInt(a_int)

			// psi_i = a^((q-1)/2N) mod q
			psi_i := new(big.Int).Exp(a, power, q)

			if psi_i.Cmp(big.NewInt(1)) == 0 {
				continue
			}

			// psi_i^(N) != 1 인지 확인
			halfDegree := big.NewInt(int64(rootDegree / 2))
			check := new(big.Int).Exp(psi_i, halfDegree, q)
			if check.Cmp(big.NewInt(1)) == 0 {
				continue
			}

			psiResidues = append(psiResidues, psi_i)
			found = true
			break
		}

		if !found {
			return nil, fmt.Errorf("moduli[%d]에서 원시 거듭제곱근 탐색 실패", i)
		}
	}

	// 2. CRTBigInt를 사용하여 병합
	psiQ, _, err := crt.CRTBigInt(psiResidues, moduli) // 패키지명(crt)은 환경에 맞게 수정하세요
	if err != nil {
		return nil, fmt.Errorf("CRT 병합 실패: %v", err)
	}

	// 🚀 안전 장치: CRT 결과가 음수 대역으로 나왔을 경우 엄격한 양수 모듈러 대역 [0, Q-1]로 올림
	Q := big.NewInt(1)
	for _, m := range moduli {
		Q.Mul(Q, m)
	}
	psiQ.Mod(psiQ, Q)
	if psiQ.Sign() < 0 {
		psiQ.Add(psiQ, Q)
	}

	return psiQ, nil
}

// LocalNTT: 다항식 쉐어에 대해 로컬 NTT 수행 (0 Round)
func (s *SecretSharingScheme) LocalNTT(parties []*Party, xIdx int, modulus []*big.Int, N int, returnIdx int) ([][]AdditiveShare, error) {
	Q, err := computeQ(modulus)
	if err != nil {
		return nil, err
	}

	omega, err := findPrimitiveRootCRT(modulus, N)
	if err != nil {
		return nil, err
	}

	// 최적화: omega의 거듭제곱 미리 계산
	omegaPowers := make([]*big.Int, N)
	omegaPowers[0] = big.NewInt(1)
	for i := 1; i < N; i++ {
		omegaPowers[i] = new(big.Int).Mul(omegaPowers[i-1], omega)
		omegaPowers[i].Mod(omegaPowers[i], Q)
	}

	numParties := s.NumParties
	allRes := make([][]AdditiveShare, numParties)

	for i := 0; i < numParties; i++ {
		if len(parties[i].InputShares) <= xIdx || len(parties[i].InputShares[xIdx]) < N {
			return nil, fmt.Errorf("Party %d: xIdx 데이터가 부족합니다 (기대 길이: %d)", i, N)
		}

		shares := parties[i].InputShares[xIdx]
		res := make([]AdditiveShare, N)

		// 순진한(Naive) O(N^2) 행렬-벡터 곱셈 적용
		// (실제 대규모 N에서는 비트 리버설을 포함한 Cooley-Tukey O(N log N) 구조로 교체 가능)
		for k := 0; k < N; k++ {
			sum := big.NewInt(0)
			for j := 0; j < N; j++ {
				powIdx := (j * k) % N
				term := new(big.Int).Mul(shares[j].Value, omegaPowers[powIdx])
				sum.Add(sum, term)
			}
			res[k] = AdditiveShare{Value: sum.Mod(sum, Q), Modulus: Q} // Modulus를 Q로 업데이트
		}

		// returnIdx 공간 확보 및 결과 할당
		for len(parties[i].InputShares) <= returnIdx {
			parties[i].InputShares = append(parties[i].InputShares, nil)
		}
		parties[i].InputShares[returnIdx] = res
		allRes[i] = res
	}

	return allRes, nil
}

// LocalINTT: 다항식 쉐어에 대해 로컬 역 NTT(INTT) 수행 (0 Round)
func (s *SecretSharingScheme) LocalINTT(parties []*Party, xIdx int, modulus []*big.Int, N int, returnIdx int) ([][]AdditiveShare, error) {
	Q, err := computeQ(modulus)
	if err != nil {
		return nil, err
	}

	omega, err := findPrimitiveRootCRT(modulus, N)
	if err != nil {
		return nil, err
	}

	// INTT 필요 요소: omega^-1 과 N^-1 계산
	omegaInv := new(big.Int).ModInverse(omega, Q)
	NBig := big.NewInt(int64(N))
	NInv := new(big.Int).ModInverse(NBig, Q)
	if omegaInv == nil || NInv == nil {
		return nil, fmt.Errorf("역원 계산 실패 (Q가 소수가 아닐 수 있습니다)")
	}

	// 최적화: omegaInv의 거듭제곱 미리 계산
	omegaInvPowers := make([]*big.Int, N)
	omegaInvPowers[0] = big.NewInt(1)
	for i := 1; i < N; i++ {
		omegaInvPowers[i] = new(big.Int).Mul(omegaInvPowers[i-1], omegaInv)
		omegaInvPowers[i].Mod(omegaInvPowers[i], Q)
	}

	numParties := s.NumParties
	allRes := make([][]AdditiveShare, numParties)

	for i := 0; i < numParties; i++ {
		if len(parties[i].InputShares) <= xIdx || len(parties[i].InputShares[xIdx]) < N {
			return nil, fmt.Errorf("Party %d: xIdx 데이터가 부족합니다", i)
		}

		shares := parties[i].InputShares[xIdx]
		res := make([]AdditiveShare, N)

		for j := 0; j < N; j++ {
			sum := big.NewInt(0)
			for k := 0; k < N; k++ {
				powIdx := (j * k) % N
				term := new(big.Int).Mul(shares[k].Value, omegaInvPowers[powIdx])
				sum.Add(sum, term)
			}
			// 결과에 N^-1 을 곱함
			sum.Mul(sum, NInv)
			res[j] = AdditiveShare{Value: sum.Mod(sum, Q), Modulus: Q}
		}

		for len(parties[i].InputShares) <= returnIdx {
			parties[i].InputShares = append(parties[i].InputShares, nil)
		}
		parties[i].InputShares[returnIdx] = res
		allRes[i] = res
	}

	return allRes, nil
}

// (computeQ, findPrimitiveRoot, reverseBits 헬퍼 함수는 이전 코드와 동일하게 사용)

// 비트 반전(Bit Reversal) 헬퍼 함수
func reverseBits(x uint32, bitLen int) uint32 {
	var res uint32
	for i := 0; i < bitLen; i++ {
		if (x & (1 << i)) != 0 {
			res |= 1 << (bitLen - 1 - i)
		}
	}
	return res
}

// LocalNegacyclicNTT: Z_Q[x]/(x^N + 1) 환에 대한 O(N log N) 고속 로컬 수론적 변환
func (s *SecretSharingScheme) LocalNegacyclicNTT(parties []*Party, xIdx int, modulus []*big.Int, N int, returnIdx int) ([][]AdditiveShare, error) {
	logN := 0
	for (1 << logN) < N {
		logN++
	}
	if (1 << logN) != N {
		return nil, fmt.Errorf("NTT를 위해 N은 2의 거듭제곱이어야 합니다")
	}

	Q, err := computeQ(modulus)
	if err != nil {
		return nil, err
	}

	// 🚀 핵심: Negacyclic NTT는 N번째가 아닌 2N번째 원시 거듭제곱근(psi)이 필요합니다.
	psi, err := findPrimitiveRootCRT(modulus, 2*N)
	if err != nil {
		return nil, fmt.Errorf("2N번째 원시 거듭제곱근 psi를 찾을 수 없습니다: %v", err)
	}

	// omega = psi^2 mod Q (기존 N번째 거듭제곱근 역할)
	omega := new(big.Int).Mul(psi, psi)
	omega.Mod(omega, Q)

	// 최적화: psi의 거듭제곱을 미리 계산하여 읽기 전용으로 공유
	psiPowers := make([]*big.Int, N)
	psiPowers[0] = big.NewInt(1)
	for i := 1; i < N; i++ {
		psiPowers[i] = new(big.Int).Mul(psiPowers[i-1], psi)
		psiPowers[i].Mod(psiPowers[i], Q)
	}

	numParties := s.NumParties
	allRes := make([][]AdditiveShare, numParties)
	var wg sync.WaitGroup

	for i := 0; i < numParties; i++ {
		wg.Add(1)
		go func(pIdx int) {
			defer wg.Done()

			shares := parties[pIdx].InputShares[xIdx]
			res := make([]AdditiveShare, N)

			// 1. Pre-multiplication & Bit-Reversal 병합 (O(N))
			for k := 0; k < N; k++ {
				rev := reverseBits(uint32(k), logN)

				// u = shares[k] * psi^k mod Q
				u := new(big.Int).Mul(shares[k].Value, psiPowers[k])
				u.Mod(u, Q)

				res[rev] = AdditiveShare{Value: u, Modulus: Q}
			}

			// 2. 표준 Cooley-Tukey 나비 연산 (O(N log N), omega 사용)
			for length := 2; length <= N; length <<= 1 {
				halfLen := length / 2
				exp := big.NewInt(int64(N / length))
				omegaLen := new(big.Int).Exp(omega, exp, Q)

				for start := 0; start < N; start += length {
					w := big.NewInt(1)
					for j := 0; j < halfLen; j++ {
						u := new(big.Int).Set(res[start+j].Value)
						v := new(big.Int).Mul(res[start+j+halfLen].Value, w)
						v.Mod(v, Q)

						res[start+j].Value.Add(u, v).Mod(res[start+j].Value, Q)
						res[start+j+halfLen].Value.Sub(u, v).Mod(res[start+j+halfLen].Value, Q)

						w.Mul(w, omegaLen).Mod(w, Q)
					}
				}
			}

			// 결과 저장
			for len(parties[pIdx].InputShares) <= returnIdx {
				parties[pIdx].InputShares = append(parties[pIdx].InputShares, nil)
			}
			parties[pIdx].InputShares[returnIdx] = res
			allRes[pIdx] = res

		}(i)
	}

	wg.Wait()
	return allRes, nil
}

// LocalNegacyclicINTT: Z_Q[x]/(x^N + 1) 환에 대한 O(N log N) 고속 로컬 역 수론적 변환
func (s *SecretSharingScheme) LocalNegacyclicINTT(parties []*Party, xIdx int, modulus []*big.Int, N int, returnIdx int) ([][]AdditiveShare, error) {
	logN := 0
	for (1 << logN) < N {
		logN++
	}

	Q, err := computeQ(modulus)
	if err != nil {
		return nil, err
	}

	psi, err := findPrimitiveRootCRT(modulus, 2*N)
	if err != nil {
		return nil, err
	}
	omega := new(big.Int).Mul(psi, psi)
	omega.Mod(omega, Q)

	// INTT 필요 요소: psi^-1, omega^-1, N^-1
	psiInv := new(big.Int).ModInverse(psi, Q)
	omegaInv := new(big.Int).ModInverse(omega, Q)
	NInv := new(big.Int).ModInverse(big.NewInt(int64(N)), Q)
	if psiInv == nil || omegaInv == nil || NInv == nil {
		return nil, fmt.Errorf("역원 계산 실패")
	}

	// 최적화: psiInv의 거듭제곱 미리 계산
	psiInvPowers := make([]*big.Int, N)
	psiInvPowers[0] = big.NewInt(1)
	for i := 1; i < N; i++ {
		psiInvPowers[i] = new(big.Int).Mul(psiInvPowers[i-1], psiInv)
		psiInvPowers[i].Mod(psiInvPowers[i], Q)
	}

	numParties := s.NumParties
	allRes := make([][]AdditiveShare, numParties)
	var wg sync.WaitGroup

	for i := 0; i < numParties; i++ {
		wg.Add(1)
		go func(pIdx int) {
			defer wg.Done()

			shares := parties[pIdx].InputShares[xIdx]
			res := make([]AdditiveShare, N)

			// 1. Bit-Reversal Permutation
			for k := 0; k < N; k++ {
				rev := reverseBits(uint32(k), logN)
				res[rev] = AdditiveShare{
					Value:   new(big.Int).Set(shares[k].Value),
					Modulus: Q,
				}
			}

			// 2. 나비 연산 (omegaInv 사용)
			for length := 2; length <= N; length <<= 1 {
				halfLen := length / 2
				exp := big.NewInt(int64(N / length))
				omegaInvLen := new(big.Int).Exp(omegaInv, exp, Q)

				for start := 0; start < N; start += length {
					w := big.NewInt(1)
					for j := 0; j < halfLen; j++ {
						u := new(big.Int).Set(res[start+j].Value)
						v := new(big.Int).Mul(res[start+j+halfLen].Value, w)
						v.Mod(v, Q)

						res[start+j].Value.Add(u, v).Mod(res[start+j].Value, Q)
						res[start+j+halfLen].Value.Sub(u, v).Mod(res[start+j+halfLen].Value, Q)

						w.Mul(w, omegaInvLen).Mod(w, Q)
					}
				}
			}

			// 3. Post-multiplication & N^-1 스케일링 병합 (O(N))
			for k := 0; k < N; k++ {
				// res[k] = res[k] * NInv * psiInv^k mod Q
				res[k].Value.Mul(res[k].Value, NInv)
				res[k].Value.Mod(res[k].Value, Q)
				res[k].Value.Mul(res[k].Value, psiInvPowers[k])
				res[k].Value.Mod(res[k].Value, Q)
			}

			for len(parties[pIdx].InputShares) <= returnIdx {
				parties[pIdx].InputShares = append(parties[pIdx].InputShares, nil)
			}
			parties[pIdx].InputShares[returnIdx] = res
			allRes[pIdx] = res

		}(i)
	}

	wg.Wait()
	return allRes, nil
}

// GenerateRandomFieldShare: 무작위 비밀 난수 [r]을 생성
func (s *SecretSharingScheme) GenerateRandomFieldShare(parties []*Party, targetIdx int) {
	numCoeffs := s.Degree + 1

	for i := 0; i < s.NumParties; i++ {
		rng := mathRand.New(mathRand.NewSource(time.Now().UnixNano() + int64(i*1000)))
		res := make([]AdditiveShare, numCoeffs)

		for j := 0; j < numCoeffs; j++ {
			// 🚀 GCD 연산 없이 그냥 0이 아닌 난수만 빠르게 뽑습니다.
			r := big.NewInt(0)
			for r.Sign() == 0 {
				r.Rand(rng, s.Modulus)
			}
			res[j] = AdditiveShare{Value: new(big.Int).Set(r), Modulus: s.Modulus}
		}

		for len(parties[i].InputShares) <= targetIdx {
			parties[i].InputShares = append(parties[i].InputShares, nil)
		}
		parties[i].InputShares[targetIdx] = res
	}
}

// Inverse: 마스킹 기법을 사용하여 비밀 쉐어 [x]의 역원 [x^-1]을 계산
func (s *SecretSharingScheme) Inverse(parties []*Party, xIdx, rIdx, tripleIdx, resultIdx int) []*Party {
	numParties := s.NumParties
	numCoeffs := s.Degree + 1

	// 1. 마스킹 곱셈 수행: [m] = [x] * [r] (1 Round & 1 Triple 소모)
	// 기존에 작성된 Multiply 함수를 사용하여 결과를 잠시 resultIdx에 저장합니다.
	s.Multiply(parties, xIdx, rIdx, tripleIdx, resultIdx)

	// 2. 마스킹된 값 m을 모든 참여자에게 공개 (Open) (1 Round)
	mSharesAll := make([][]AdditiveShare, numParties)
	for i := 0; i < numParties; i++ {
		mSharesAll[i] = parties[i].InputShares[resultIdx]
	}
	mPlain := s.Open(mSharesAll)

	// 3. 로컬 역원 계산 및 마스킹 해제: [res] = m^-1 * [r] (0 Round)
	for i := 0; i < numParties; i++ {
		res := make([]AdditiveShare, numCoeffs)

		for j := 0; j < numCoeffs; j++ {
			// 공개된 상수 m 의 역원 m^-1 mod Q 계산
			mInv := new(big.Int).ModInverse(mPlain[j], s.Modulus)
			if mInv == nil {
				panic(fmt.Sprintf("Inverse 오류: 계수 %d에서 역원이 존재하지 않습니다 (x 또는 r이 0이거나 Q와 서로소가 아님)", j))
			}

			// [x^-1] = m^-1 * [r_i]
			val := new(big.Int).Mul(mInv, parties[i].InputShares[rIdx][j].Value)
			res[j] = AdditiveShare{Value: val.Mod(val, s.Modulus), Modulus: s.Modulus}
		}

		// 최종 결과 [x^-1] 덮어쓰기
		parties[i].InputShares[resultIdx] = res
	}

	return parties
}
