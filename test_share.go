package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

func Test_share() {
	// 1. 환경 설정
	// 1. q 리스트 (big.Int 슬라이스) 정의
	q := []*big.Int{
		new(big.Int).SetUint64(281474976317441),
		new(big.Int).SetUint64(1099512938497),
		new(big.Int).SetUint64(1099510054913),
		new(big.Int).SetUint64(1099507695617),
		new(big.Int).SetUint64(1099515691009),
		new(big.Int).SetUint64(1099516870657),
		new(big.Int).SetUint64(1099506515969),
		new(big.Int).SetUint64(1099504549889),
		new(big.Int).SetUint64(1099503894529),
		new(big.Int).SetUint64(1099503370241),
		new(big.Int).SetUint64(281474975662081),
		new(big.Int).SetUint64(281474978414593),
	}

	// 2. 모든 값을 곱한 결과물 계산 (PQ)
	PQ := big.NewInt(1) // 1로 초기화
	for _, val := range q {
		PQ.Mul(PQ, val)
	}

	// 3. 결과 확인
	fmt.Printf("모든 q의 곱 (PQ) 비트 길이: %d bits\n", PQ.BitLen())
	fmt.Printf("PQ 값: %s\n", PQ.String())

	modulus := PQ
	numParties := 8
	degree := 65536
	scheme := NewSecretSharingScheme(modulus, numParties, degree)

	// 2. Party 초기화
	parties := make([]*Party, numParties)
	for i := 0; i < numParties; i++ {
		parties[i] = &Party{ID: i}
	}

	// 3. Offline 단계: Beaver Triple 생성 및 분배
	triples := scheme.GenerateBeaverTriples(1)
	for i := 0; i < numParties; i++ {
		parties[i].BeaverTriple = triples[i]
	}

	// 4. 입력값 준비 및 비밀 공유 (Sharing)
	numCoeffs := degree + 1
	valX := make([]*big.Int, numCoeffs)
	valY := make([]*big.Int, numCoeffs)
	valZ := make([]*big.Int, numCoeffs)

	for j := 0; j < numCoeffs; j++ {
		x, _ := rand.Int(rand.Reader, scheme.Modulus)
		y, _ := rand.Int(rand.Reader, scheme.Modulus)
		z, _ := rand.Int(rand.Reader, scheme.Modulus)
		valX[j] = x
		valY[j] = y
		valZ[j] = z
	}

	sharesX := scheme.ShareSever(valX)     // Index 0에 저장될 쉐어
	sharesY := scheme.ShareAuthority(valY) // Index 1에 저장될 쉐어
	sharesZ := scheme.ShareAuthority(valZ) // Index 1에 저장될 쉐어

	for i := 0; i < numParties; i++ {
		// 초기 InputShares 구성: [0]: X의 쉐어, [1]: Y의 쉐어
		parties[i].InputShares = [][]AdditiveShare{sharesX[i], sharesY[i], sharesZ[i]}
	}

	fmt.Printf("--- 연산 시작 (상태 업데이트 방식, Parties: %d) ---\n", numParties)

	// 5. 온라인 단계: Multiply 호출
	// 내부적으로 각 참여자의 InputShares에 결과값이 append됨.
	// 결과값은 이제 Index 2에 위치하게 됩니다.
	scheme.Multiply(parties, 0, 1, 0, 0)
	scheme.Add(parties, 0, 2, 0)

	// 6. 결과 복원 (Open) 및 검증
	// 모든 참여자의 InputShares[2] (곱셈 결과)를 수집하여 Open 호출
	resultIdx := 0
	allResultShares := make([][]AdditiveShare, numParties)
	for i := 0; i < numParties; i++ {
		allResultShares[i] = parties[i].InputShares[resultIdx]
	}

	finalResult := scheme.Open(allResultShares)

	// isVerbose: 상세 출력 여부 (true: 전체 출력, false: 패스/실패 여부만 확인)
	isVerbose := false
	allPassed := true

	fmt.Println("\n--- 결과 검증 ---")
	for i := 0; i < numCoeffs; i++ {
		// 1. 기대값 계산 (Expected = valX * valY mod M)
		expected := new(big.Int).Mul(valX[i], valY[i])
		expected.Mod(expected, modulus)
		expected = new(big.Int).Add(expected, valZ[i])
		expected.Mod(expected, modulus)

		if isVerbose {
			// 상세 출력 모드
			fmt.Printf("계수 [%d] 연산 결과: %s (기대값: %s)\n", i, finalResult[i].String(), expected.String())
		} else {
			// 자동 판별 모드: (Result - Expected) mod M == 0 인지 확인
			diff := new(big.Int).Sub(finalResult[i], expected)
			diff.Mod(diff, modulus)

			if diff.Cmp(big.NewInt(0)) == 0 {
				//fmt.Printf("계수 [%d]: PASS\n", i)
			} else {
				fmt.Printf("계수 [%d]: FAIL (결과: %s, 기대값: %s)\n", i, finalResult[i].String(), expected.String())
				allPassed = false
				break // 하나라도 실패하면 중단
			}
		}
	}

	if !isVerbose && allPassed {
		fmt.Println("\n결과: 모든 연산이 정확하게 수행되었습니다. (SUCCESS)")
	} else if !allPassed {
		fmt.Println("\n결과: 연산 오류가 발견되었습니다. (FAILED)")
	}

	// 7. 통신 통계 출력
	fmt.Println("\n--- 통신 통계 (Communication Metrics) ---")
	fmt.Printf("총 통신 라운드: %d rounds\n", scheme.CommunicationRounds)
	fmt.Printf("총 통신량: %d bytes\n", scheme.TotalCommBytes)
}

func Test_ComparePublic_Workflow() {
	// 1. 환경 설정 (570비트급 PQ)
	qValues := []string{
		"281474976317441", "1099512938497", "1099510054913",
		"1099507695617", "1099515691009", "1099516870657",
		"1099506515969", "1099504549889", "1099503894529",
		"1099503370241", "281474975662081", "281474978414593",
	}
	PQ := big.NewInt(1)
	for _, v := range qValues {
		val, _ := new(big.Int).SetString(v, 10)
		PQ.Mul(PQ, val)
	}

	numParties := 3
	degree := 15 // 16개의 계수 (SIMD 병렬 처리)
	scheme := NewSecretSharingScheme(PQ, numParties, degree)

	// 2. 참여자 초기화
	parties := make([]*Party, numParties)
	for i := 0; i < numParties; i++ {
		parties[i] = &Party{
			ID:          i,
			InputShares: make([][]AdditiveShare, 0),
			BitShares:   make([][]BitShares, 0),
		}
	}

	// 3. 오프라인 단계: 트리플 생성
	// 공개 비교는 비트당 1개의 트리플만 소모하므로 128비트 기준 128개 이상이면 충분합니다.
	// (비밀-비밀 비교의 5배 효율성)
	triples := scheme.GenerateBeaverTriples(200)
	for i := 0; i < numParties; i++ {
		parties[i].BeaverTriple = triples[i]
	}

	// 4. 입력 데이터 준비 (비밀 X와 공개 상수 C)
	numCoeffs := degree + 1
	valX := make([]*big.Int, numCoeffs)
	publicVals := make([]*big.Int, numCoeffs)

	for j := 0; j < numCoeffs; j++ {
		// x는 랜덤, c는 x보다 크거나 작도록 임의 설정
		x, _ := rand.Int(rand.Reader, PQ)
		c, _ := rand.Int(rand.Reader, PQ)
		valX[j] = x
		publicVals[j] = c
	}

	// X 값 쉐어링 (Index 0에 저장)
	sharesX := scheme.ShareSever(valX)
	for i := 0; i < numParties; i++ {
		parties[i].InputShares = [][]AdditiveShare{sharesX[i]}
	}

	fmt.Printf("--- 연산 시작 (공개 값 비교 [X < C], Degree: %d) ---\n", degree)

	// 5. 온라인 단계: 공개 비교 연산 수행
	// xIdx: 0, publicVals, bitLen: 128, resultIdx: 1, tmpRandIdx: 2
	scheme.ComparePublic(parties, 0, publicVals, 128, 1, 2)

	// 6. 결과 복원 및 검증
	resultIdx := 1
	allResultShares := make([][]AdditiveShare, numParties)
	for i := 0; i < numParties; i++ {
		allResultShares[i] = parties[i].InputShares[resultIdx]
	}
	finalResult := scheme.Open(allResultShares)

	isVerbose := false
	allPassed := true

	fmt.Println("\n--- 결과 검증 ---")
	for i := 0; i < numCoeffs; i++ {
		// 계수별 기대값 계산: valX[i] < publicVals[i] 이면 1, 아니면 0
		expected := big.NewInt(0)
		if valX[i].Cmp(publicVals[i]) < 0 {
			expected.SetInt64(1)
		}

		// (Result - Expected) mod PQ == 0 인지 확인
		diff := new(big.Int).Sub(finalResult[i], expected)
		diff.Mod(diff, PQ)

		if diff.Cmp(big.NewInt(0)) != 0 {
			fmt.Printf("[계수 %d] FAIL - 결과: %s, 기대값: %s\n", i, finalResult[i].String(), expected.String())
			allPassed = false
		} else if isVerbose {
			fmt.Printf("[계수 %d] PASS - 결과: %s\n", i, finalResult[i].String())
		}
	}

	if allPassed {
		fmt.Println("결과: 모든 계수의 공개 비교 연산이 정확하게 수행되었습니다. (SUCCESS)")
	} else {
		fmt.Println("결과: 일부 계수에서 연산 오류가 발생했습니다. (FAILED)")
	}

	// 7. 통신 통계 출력
	fmt.Println("\n--- 통신 통계 (Communication Metrics) ---")
	fmt.Printf("총 통신 라운드: %d rounds\n", scheme.CommunicationRounds)
	fmt.Printf("총 통신량: %d bytes\n", scheme.TotalCommBytes)
}

func Test_ComparePublicTree_Workflow() {
	// 1. 환경 설정 (570비트급 PQ)
	qValues := []string{
		"281474976317441", "1099512938497", "1099510054913",
		"1099507695617", "1099515691009", "1099516870657",
		"1099506515969", "1099504549889", "1099503894529",
		"1099503370241", "281474975662081", "281474978414593",
	}
	PQ := big.NewInt(1)
	for _, v := range qValues {
		val, _ := new(big.Int).SetString(v, 10)
		PQ.Mul(PQ, val)
	}

	numParties := 3
	degree := 15 // 16개의 계수 (SIMD 병렬 처리)
	scheme := NewSecretSharingScheme(PQ, numParties, degree)

	// 2. 참여자 초기화
	parties := make([]*Party, numParties)
	for i := 0; i < numParties; i++ {
		parties[i] = &Party{
			ID:          i,
			InputShares: make([][]AdditiveShare, 0),
			BitShares:   make([][]BitShares, 0),
		}
	}

	// 3. 오프라인 단계: 트리플 생성
	// 이진 트리 방식은 라운드를 획기적으로 줄이는 대신, 각 계층마다 병렬 곱셈이 발생하므로
	// 선형 방식보다 더 많은 트리플을 소모합니다. 128비트 기준 약 256개의 트리플이 필요합니다.
	// 여유롭게 500개를 생성합니다.
	triples := scheme.GenerateBeaverTriples(500)
	for i := 0; i < numParties; i++ {
		parties[i].BeaverTriple = triples[i]
	}

	// 4. 입력 데이터 준비 (비밀 X와 공개 상수 C)
	numCoeffs := degree + 1
	valX := make([]*big.Int, numCoeffs)
	publicVals := make([]*big.Int, numCoeffs)

	for j := 0; j < numCoeffs; j++ {
		// x는 랜덤, c는 x보다 크거나 작도록 임의 설정
		x, _ := rand.Int(rand.Reader, PQ)
		c, _ := rand.Int(rand.Reader, PQ)
		valX[j] = x
		publicVals[j] = c
	}

	// X 값 쉐어링 (Index 0에 저장)
	sharesX := scheme.ShareSever(valX)
	for i := 0; i < numParties; i++ {
		parties[i].InputShares = [][]AdditiveShare{sharesX[i]}
	}

	fmt.Printf("--- 연산 시작 (이진 트리 기반 공개 값 비교 [X < C], Degree: %d) ---\n", degree)

	// 5. 온라인 단계: 이진 트리 기반 공개 비교 연산 수행
	// xIdx: 0, publicVals, bitLen: 128, resultIdx: 1, tmpRandIdx: 2
	scheme.ComparePublicTree(parties, 0, publicVals, 128, 1, 2)

	// 6. 결과 복원 및 검증
	resultIdx := 1
	allResultShares := make([][]AdditiveShare, numParties)
	for i := 0; i < numParties; i++ {
		allResultShares[i] = parties[i].InputShares[resultIdx]
	}
	finalResult := scheme.Open(allResultShares)

	isVerbose := false
	allPassed := true

	fmt.Println("\n--- 결과 검증 ---")
	for i := 0; i < numCoeffs; i++ {
		// 계수별 기대값 계산: valX[i] < publicVals[i] 이면 1, 아니면 0
		expected := big.NewInt(0)
		if valX[i].Cmp(publicVals[i]) < 0 {
			expected.SetInt64(1)
		}

		// (Result - Expected) mod PQ == 0 인지 확인
		diff := new(big.Int).Sub(finalResult[i], expected)
		diff.Mod(diff, PQ)

		if diff.Cmp(big.NewInt(0)) != 0 {
			fmt.Printf("[계수 %d] FAIL - 결과: %s, 기대값: %s\n", i, finalResult[i].String(), expected.String())
			allPassed = false
		} else if isVerbose {
			fmt.Printf("[계수 %d] PASS - 결과: %s\n", i, finalResult[i].String())
		}
	}

	if allPassed {
		fmt.Println("결과: 모든 계수의 공개 비교 연산(Tree)이 정확하게 수행되었습니다. (SUCCESS)")
	} else {
		fmt.Println("결과: 일부 계수에서 연산 오류가 발생했습니다. (FAILED)")
	}

	// 7. 통신 통계 출력
	fmt.Println("\n--- 통신 통계 (Communication Metrics) ---")
	fmt.Printf("총 통신 라운드: %d rounds\n", scheme.CommunicationRounds)
	fmt.Printf("총 통신량: %d bytes\n", scheme.TotalCommBytes)
}
