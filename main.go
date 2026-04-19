package main

import (
	"bufio"
	"fmt"
	"math"
	"math/big"
	"math/cmplx"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"tifs/src/crt"
	"tifs/src/galois"

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he/hefloat"
	"github.com/tuneinsight/lattigo/v5/ring"
	"github.com/tuneinsight/lattigo/v5/ring/ringqp"
	"github.com/tuneinsight/lattigo/v5/utils/bignum"
	"github.com/tuneinsight/lattigo/v5/utils/sampling"
)

type PublicSideContext struct {
	params    hefloat.Parameters
	pk        *rlwe.PublicKey
	authPK    *rlwe.PublicKey
	evaluator *hefloat.Evaluator
	encryptor *rlwe.Encryptor
	encoder   *hefloat.Encoder
	conjKey   *rlwe.GaloisKey
}

type ClientSideContext struct {
	sk        *rlwe.SecretKey
	decryptor *rlwe.Decryptor
}

type AuthSideContext struct {
	sk *rlwe.SecretKey
}

func GenConjKeyWithAuth(pubctx PublicSideContext, cltx ClientSideContext) *rlwe.GaloisKey {
	kgen := rlwe.NewKeyGenerator(pubctx.params)
	return galois.GenGaloisKeyNew(kgen, pubctx.params.GaloisElementForComplexConjugation(), cltx.sk, pubctx.authPK.Value)
}

func BeginProtocol(paramsliteral hefloat.ParametersLiteral) (PublicSideContext, ClientSideContext, AuthSideContext) {
	var pubCTX PublicSideContext
	var authCTX AuthSideContext
	var clientCTX ClientSideContext

	params, err := hefloat.NewParametersFromLiteral(paramsliteral)
	if err != nil {
		panic(err)
	}
	fmt.Println("ckks parameter init end")
	fmt.Println("Params QP")
	fmt.Println(params.Q())
	fmt.Println(params.P())

	pubCTX.params = params

	kgen := rlwe.NewKeyGenerator(params)
	fmt.Println("Authority Side")
	{
		authCTX.sk = kgen.GenSecretKeyNew()
		pubCTX.authPK = kgen.GenPublicKeyNew(authCTX.sk)
	}
	fmt.Println("Authority Side End")

	fmt.Println("Client Side")
	{
		sk := kgen.GenSecretKeyNew()
		pk := kgen.GenPublicKeyNew(sk)
		rlk := kgen.GenRelinearizationKeyNew(sk)
		clientCTX.sk = sk

		// generate keys - Rotating key
		rotidx := []int{0, 1, 2}
		galEls := make([]uint64, len(rotidx))
		for i, x := range rotidx {
			galEls[i] = params.GaloisElement(x)
		}
		rtk := make([]*rlwe.GaloisKey, len(galEls))
		var wg sync.WaitGroup
		wg.Add(len(galEls))
		for i := range galEls {
			i := i

			go func() {
				defer wg.Done()
				kgen_ := rlwe.NewKeyGenerator(params)
				rtk[i] = kgen_.GenGaloisKeyNew(galEls[i], sk)
			}()
		}
		wg.Wait()

		//generate -er
		encryptor := rlwe.NewEncryptor(params, pk)
		decryptor := rlwe.NewDecryptor(params, sk)
		encoder := hefloat.NewEncoder(params)
		pubCTX.pk = pk
		pubCTX.encryptor = encryptor
		pubCTX.encoder = encoder

		pubCTX.conjKey = GenConjKeyWithAuth(pubCTX, clientCTX)
		rtk = append(rtk, pubCTX.conjKey)
		evk := rlwe.NewMemEvaluationKeySet(rlk, rtk...)
		evaluator := hefloat.NewEvaluator(params, evk)
		pubCTX.evaluator = evaluator
		clientCTX.decryptor = decryptor
	}
	fmt.Println("Client Side End")

	return pubCTX, clientCTX, authCTX
}

func SecRes(pubCTX PublicSideContext, authCTX AuthSideContext, num int) *rlwe.SecretKey {

	//debug := false

	fmt.Printf("Setup Start!")

	params := pubCTX.params
	gk := pubCTX.conjKey
	skAuth := authCTX.sk
	ringQP := params.RingQP()

	moduli := make([]uint64, len(params.Q())+len(params.P()))
	copy(moduli, ringQP.RingQ.ModuliChain())
	copy(moduli[len(params.Q()):], ringQP.RingP.ModuliChain())
	PQ := big.NewInt(1)
	// moduli의 모든 원소를 순회하며 곱셈 수행
	for _, v := range moduli {
		// uint64 타입인 v를 *big.Int 타입으로 변환
		val := new(big.Int).SetUint64(v)

		// PQ = PQ * val
		PQ.Mul(PQ, val)
	}

	numParties := num
	degree := 65535 // 16개의 계수 (SIMD 병렬 처리)
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

	fmt.Printf("Gen BeaverTriples... ")
	triples := scheme.GenerateBeaverTriples(1)
	for i := 0; i < numParties; i++ {
		parties[i].BeaverTriple = triples[i]
	}
	fmt.Println(" Done!")

	//numCoeffs := degree + 1

	b0 := *gk.Value[0][0][0].CopyNew()
	b1 := *gk.Value[1][0][0].CopyNew()
	sk_auth := *skAuth.Value.CopyNew()

	ringQP.IMForm(b0, b0)
	ringQP.IMForm(b1, b1)
	ringQP.IMForm(sk_auth, sk_auth)

	fmt.Printf("Gen b0 shares... ")
	coef := make([]uint64, len(moduli))
	b0polysBigint := make([]*big.Int, params.N())
	for j := range params.N() {
		for k := range b0.Q.Coeffs {
			coef[k] = b0.Q.Coeffs[k][j]
		}
		for k := range b0.P.Coeffs {
			coef[len(params.Q())+k] = b0.P.Coeffs[k][j]
		}

		b0polysBigint[j], _, _ = crt.CRTUint64(coef, moduli)
	}

	sharesb0 := scheme.ShareSever(b0polysBigint)
	fmt.Println(" Done!")

	fmt.Printf("Gen b1 shares... ")
	coef = make([]uint64, len(moduli))
	b1polysBigint := make([]*big.Int, params.N())
	for j := range params.N() {
		for k := range b1.Q.Coeffs {
			coef[k] = b1.Q.Coeffs[k][j]
		}
		for k := range b1.P.Coeffs {
			coef[len(params.Q())+k] = b1.P.Coeffs[k][j]
		}

		b1polysBigint[j], _, _ = crt.CRTUint64(coef, moduli)
	}

	sharesb1 := scheme.ShareSever(b1polysBigint)
	fmt.Println(" Done!")

	fmt.Printf("Gen sk_auth shares... ")
	coef = make([]uint64, len(moduli))
	skpolysBigint := make([]*big.Int, params.N())
	for j := range params.N() {
		for k := range sk_auth.Q.Coeffs {
			coef[k] = sk_auth.Q.Coeffs[k][j]
		}
		for k := range sk_auth.P.Coeffs {
			coef[len(params.Q())+k] = sk_auth.P.Coeffs[k][j]
		}

		skpolysBigint[j], _, _ = crt.CRTUint64(coef, moduli)
	}

	sharessk := scheme.ShareAuthority(skpolysBigint)

	for i := 0; i < numParties; i++ {
		// 초기 InputShares 구성: [0]: X의 쉐어, [1]: Y의 쉐어
		parties[i].InputShares = [][]AdditiveShare{sharesb0[i], sharesb1[i], sharessk[i]}
	}
	fmt.Println(" Done!")

	fmt.Printf("Step 1...")
	scheme.Multiply(parties, 1, 2, 0, 2)
	scheme.Add(parties, 0, 2, 0)

	PQ_big := params.Q()
	for _, v := range params.P() {
		PQ_big = append(PQ_big, v)
	}
	PQ_big_big := make([]*big.Int, len(PQ_big))
	for i := 0; i < len(PQ_big_big); i++ {
		PQ_big_big[i] = new(big.Int).SetUint64(PQ_big[i])
	}

	// ######## step 1. b0 + b1 * skAuth ######

	b0 = *gk.Value[0][0][0].CopyNew()
	b1 = *gk.Value[1][0][0].CopyNew()
	sk_auth = *skAuth.Value.CopyNew()

	ringQP.MulCoeffsMontgomery(b1, skAuth.Value, b1)
	ringQP.Add(b0, b1, b0)
	ringQP.Reduce(b0, b0)
	ringQP.IMForm(b0, b0)
	//ringQP.INTT(b0, b0)

	fmt.Println(" Done!")

	//PrintDebug(scheme, parties, numParties, params, PQ, b0, 0)
	//fmt.Println(Q_, P_)

	fmt.Printf("Step 2... ")
	var perLevel int
	{
		temp := float64(len(params.Q())) / float64(len(gk.Value))
		perLevel = int(math.Ceil(temp))
	}

	Q0Q1level := perLevel * 2
	fmt.Println("Q0Q1Level", Q0Q1level)
	Q_ := params.Q()

	Q_ = params.Q()
	P_ := Q_[Q0Q1level:]
	for _, v := range params.P() {
		P_ = append(P_, v)
	}
	Q_ = Q_[:Q0Q1level]
	Q0Q1 := big.NewInt(1)
	Pbig := big.NewInt(1)
	for _, v := range Q_ {
		// uint64 타입인 v를 *big.Int 타입으로 변환
		val := new(big.Int).SetUint64(v)

		// PQ = PQ * val
		Q0Q1.Mul(Q0Q1, val)
	}

	//P_mod := new(big.Int).ModInverse(new(big.Int).Mod(Pbig, Q0Q1), Q0Q1)
	//fmt.Println(Pbig)
	//fmt.Println(Q_)
	//fmt.Println(P_)
	for _, v := range P_ {
		// uint64 타입인 v를 *big.Int 타입으로 변환
		val := new(big.Int).SetUint64(v)

		// PQ = PQ * val
		Pbig.Mul(Pbig, val)
	}

	P_mod := new(big.Int).ModInverse(new(big.Int).Mod(Pbig, Q0Q1), Q0Q1)
	fmt.Println("Q0Q1 : ", Q0Q1)
	fmt.Println("P inv : ", P_mod)

	N := params.N()
	// Q_ : Q0Q1, P_ : Q2...Qdnum P
	Q_ = params.Q()
	P_ = Q_[Q0Q1level:]
	for _, v := range params.P() {
		P_ = append(P_, v)
	}
	Q_ = Q_[:Q0Q1level]
	ringQ_, _ := ring.NewRing(N, Q_)
	ringP_, _ := ring.NewRing(N, P_)
	be := crt.NewBasisExtender(ringQ_, ringP_)
	PHalf := bignum.NewInt(ringP_.ModulusAtLevel[ringP_.Level()])
	PHalf.Rsh(PHalf, 1)

	publicVals := make([]*big.Int, params.N())
	for j := 0; j < params.N(); j++ {
		// x는 랜덤, c는 x보다 크거나 작도록 임의 설정
		c := PHalf
		publicVals[j] = c
	}

	scheme.LocalNegacyclicINTT(parties, 0, PQ_big_big, params.N(), 0, moduli)
	scheme.AddPublic(parties, 0, publicVals, 0)

	scheme.Mod(parties, 0, Pbig, 1)
	//fmt.Println(Pbig)

	publicVals = make([]*big.Int, params.N())
	for j := 0; j < params.N(); j++ {
		// x는 랜덤, c는 x보다 크거나 작도록 임의 설정
		c := Pbig
		publicVals[j] = c
	}

	//lognum := int(math.Floor(math.Log2(float64(num)))) + 1
	for i := 0; i < num-1; i++ {
		fmt.Printf("compare... ")
		scheme.ComparePublicTree(parties, 1, publicVals, Pbig.BitLen(), 2, 3)
		fmt.Println(" Done!")
		fmt.Printf("conditonal sub... ")
		scheme.ConditionalSubPublic(parties, 1, publicVals, 2, 1)
		fmt.Println(" Done!")
	}

	//PrintDebug(scheme, parties, numParties, params, PQ, b0, 1)
	scheme.Sub(parties, 0, 1, 0)

	scheme.Modulus = Q0Q1
	scheme.Mod(parties, 0, Q0Q1, 0)
	//fmt.Println(Q0Q1, parties[0].InputShares[0][0].Modulus)

	for j := 0; j < params.N(); j++ {
		// x는 랜덤, c는 x보다 크거나 작도록 임의 설정
		c := P_mod
		publicVals[j] = c
	}
	scheme.MultiplyPublic(parties, 0, publicVals, 0)
	//scheme.Mod(parties, 0, Q0Q1, 0)
	Q_big := make([]*big.Int, len(Q_))
	for i := 0; i < len(Q_big); i++ {
		Q_big[i] = new(big.Int).SetUint64(Q_[i])
	}

	//scheme.LocalNegacyclicNTT(parties, 0, Q_big, params.N(), 0, moduli)

	// publicVals = make([]*big.Int, params.N())
	// for j := 0; j < params.N(); j++ {
	// 	// x는 랜덤, c는 x보다 크거나 작도록 임의 설정
	// 	c := new(big.Int).Mod(PHalf.Neg(PHalf), Q0Q1)
	// 	publicVals[j] = c
	// }
	// scheme.AddPublic(parties, 0, publicVals, 0)

	// ######## step 2. ModDown ######

	//polQ_ : b0 mod Q0Q1, polP_ : b0 mod P
	polQ_ := ringQ_.NewPoly()
	polP_ := ringP_.NewPoly()
	polres := ringQ_.NewPoly()
	for i, v := range b0.Q.Coeffs[:Q0Q1level] {
		copy(polQ_.Coeffs[i], v)
	}
	for i, v := range b0.Q.Coeffs[Q0Q1level:] {
		copy(polP_.Coeffs[i], v)
	}
	for i, v := range polP_.Coeffs[len(params.Q())-Q0Q1level:] {
		copy(v, b0.P.Coeffs[i])
	}
	be.ModDownQPtoQNTT(polQ_.Level(), polP_.Level(), polQ_, polP_, polres)
	//ringQ_.INTT(polres, polres)
	//ringQ_.IMForm(polres, polres)

	PrintDebugQ0Q1(scheme, parties, numParties, params, Q0Q1, polres, 0)
	// 6. 결과 복원 (Open) 및 검증

	// scheme.GenerateRandomFieldShare(parties, 4)
	// scheme.Inverse(parties, 0, 4, 0, 0)
	//scheme.LocalNegacyclicNTT(parties, 0, Q_big, params.N(), 0)

	Q := params.Q()
	blockA := make([]int, perLevel)
	blockB := make([]int, perLevel)
	for i := range perLevel {
		blockA[i] = i
		blockB[i] = i + perLevel
	}

	// t0 = Q1[Q0hat]^-1, t1 = Q0[Q1hat]^-1
	t0, _ := crt.ComputeValue(Q, blockB, blockA)
	t1, _ := crt.ComputeValue(Q, blockA, blockB)

	for j := 0; j < params.N(); j++ {
		// x는 랜덤, c는 x보다 크거나 작도록 임의 설정
		c := t1
		publicVals[j] = c
	}

	for i := 0; i < numParties; i++ {
		// 초기 InputShares 구성: [0]: X의 쉐어, [1]: Y의 쉐어
		parties[i].InputShares[1] = sharessk[i]
	}

	scheme.MultiplyPublic(parties, 1, publicVals, 1)

	for j := 0; j < params.N(); j++ {
		// x는 랜덤, c는 x보다 크거나 작도록 임의 설정
		c := t0
		publicVals[j] = c
	}

	scheme.AddPublic(parties, 1, publicVals, 1)

	//scheme.LocalNegacyclicNTT(parties, 1, Q_big, params.N(), 1)

	polskAuth := ringQ_.NewPoly()
	for i, v := range skAuth.Value.Q.Coeffs[:Q0Q1level] {
		copy(polskAuth.Coeffs[i], v)
	}

	// ######## step 3. compute Q1[Q0hat]^-1 + Q0[Q1hat]^-1 * skAuth ######
	Q = params.Q()
	blockA = make([]int, perLevel)
	blockB = make([]int, perLevel)
	for i := range perLevel {
		blockA[i] = i
		blockB[i] = i + perLevel
	}

	// t0 = Q1[Q0hat]^-1, t1 = Q0[Q1hat]^-1
	t0, _ = crt.ComputeValue(Q, blockB, blockA)
	t1, _ = crt.ComputeValue(Q, blockA, blockB)

	ringQ_.MulScalarBigint(polskAuth, t1, polskAuth)
	ringQ_.IMForm(polskAuth, polskAuth)
	ringQ_.AddScalarBigint(polskAuth, t0, polskAuth)
	ringQ_.MForm(polskAuth, polskAuth)
	ringQ_.Reduce(polskAuth, polskAuth)
	//ringQ_.IMForm(polskAuth, polskAuth)

	// ######## step 4. compute inverse of Q1[Q0hat]^-1 + Q0[Q1hat]^-1 * skAuth ######
	coef = make([]uint64, len(ringQ_.ModuliChain()))
	for j := range N {
		for i := range polskAuth.Coeffs {
			coef[i] = polskAuth.Coeffs[i][j]
		}
		ringQ_.Inverse(coef)
		for i := range polskAuth.Coeffs {
			polskAuth.Coeffs[i][j] = coef[i]
		}
	}

	ringQ_.MulCoeffsMontgomery(polskAuth, polres, polres)
	//ringQ_.INTT(polres, polres)

	scheme.GenerateRandomFieldShare(parties, 4)

	//fmt.Println("mod : ", parties[0].InputShares[1][0].Modulus)
	scheme.Modulus = Q0Q1
	//fmt.Println("mod : ", parties[0].InputShares[1][0].Modulus)
	PrintDebugQ0Q1(scheme, parties, numParties, params, Q0Q1, polres, 0)
	scheme.Inverse(parties, 1, 4, 0, 1)
	//fmt.Println("mod : ", parties[0].InputShares[1][0].Modulus)
	//ringQ_.IMForm(polskAuth, polskAuth)
	//PrintDebugQ0Q1(scheme, parties, numParties, params, Q0Q1, polskAuth, 1)

	scheme.Multiply(parties, 0, 1, 0, 0)
	//scheme.LocalNegacyclicINTT(parties, 0, Q_big, params.N(), 0, moduli)
	PrintDebugQ0Q1(scheme, parties, numParties, params, Q0Q1, polres, 0)
	fmt.Println(" Done!")

	// ######## step 5. ModUp(make poly to Secret Key Object) ######
	polresP := ringP_.NewPoly()
	be.ModUpQtoP(ringQ_.Level(), ringP_.Level(), polres, polresP)

	keygen := rlwe.NewKeyGenerator(pubCTX.params)
	sk := keygen.GenSecretKeyNew()

	for i, v := range polres.Coeffs[:Q0Q1level] {
		copy(sk.Value.Q.Coeffs[i], v)
	}
	for i, v := range polresP.Coeffs[:len(Q)-Q0Q1level] {
		copy(sk.Value.Q.Coeffs[Q0Q1level+i], v)
	}
	for i, v := range polresP.Coeffs[len(Q)-Q0Q1level:] {
		copy(sk.Value.P.Coeffs[i], v)
	}

	ringQP.MForm(sk.Value, sk.Value)
	ringQP.NTT(sk.Value, sk.Value)
	// ringQ_.MForm(polres, polres)
	// return polres
	return sk
}

var TripleCount int

func main() {
	//CPU full power
	runtime.GOMAXPROCS(runtime.NumCPU())

	TripleCount = 0
	//Test_share()
	//Test_ComparePublic_Workflow()
	//Test_ComparePublicTree_Workflow()

	//return

	// Moduli 생성 관련은 moduli_test.go에 따로 분리
	modulipath := "moduli.txt"
	Q, P := LoadModuliFromTXT(modulipath)

	//ckks parameter init
	SchemeParams := hefloat.ParametersLiteral{
		LogN:            16,
		Q:               Q,
		P:               P,
		LogDefaultScale: 40,
	}
	pubCTX, clientCTX, authCTX := BeginProtocol(SchemeParams)
	params := pubCTX.params
	encoder := pubCTX.encoder
	encryptor := pubCTX.encryptor
	// evaluator := pubCTX.evaluator

	// TODO : SK shares 만들기
	//party 개수, hyperparameter는 이거밖에 없음
	partyNum := 2
	fmt.Println("client sk share 생성")

	// 각 party SK Share의 CRT representation과 BigInt representation
	// 첫번째 인덱스는 무조건 각 party의 인덱스를 말함
	// CRT representation은 ringQ, ringP의 계수로 나눠서 저장하는 형태입니다. (ringQ의 계수는 Q0Q1, ringP의 계수는 Q2...Qdnum P)
	// BigInt representation은 CRT representation을 CRT로 합쳐서 하나의 big.Int로 표현한 형태입니다. (계수마다 하나의 big.Int)
	polysCRT := make([]ringqp.Poly, partyNum)
	polysBigint := make([][]*big.Int, partyNum)

	ringQP := params.RingQP()
	moduli := make([]uint64, len(params.Q())+len(params.P()))
	copy(moduli, ringQP.RingQ.ModuliChain())
	copy(moduli[len(params.Q()):], ringQP.RingP.ModuliChain())
	// ######## step 1. SK share (sk_auth = sum_{1<= i <= n} sk_{auth,i}) ######
	{
		// 각 party의 SK share를 CRT representation으로 만듭니다. (마지막 party는 sk_auth - sum_{1<= i <n} sk_{auth,i})
		for i := range partyNum - 1 {
			polysCRT[i] = ringQP.NewPoly()
			for j := range polysCRT[i].Q.Coeffs {
				for k := range polysCRT[i].Q.Coeffs[j] {
					polysCRT[i].Q.Coeffs[j][k] = sampling.RandUint64() % ringQP.RingQ.ModuliChain()[j]
				}
			}

			for j := range polysCRT[i].P.Coeffs {
				for k := range polysCRT[i].P.Coeffs[j] {
					polysCRT[i].P.Coeffs[j][k] = sampling.RandUint64() % ringQP.RingP.ModuliChain()[j]
				}
			}
		}

		polysCRT[partyNum-1] = *authCTX.sk.Value.CopyNew()
		for i := range partyNum - 1 {
			ringQP.Sub(polysCRT[partyNum-1], polysCRT[i], polysCRT[partyNum-1])
			ringQP.Reduce(polysCRT[partyNum-1], polysCRT[partyNum-1])
		}

		// Normal form (Mform, NTTform 둘다 아님)으로 저장합니다. 굳이 필요없으면 주석 처리해도 됩니다. 다만, verification check할 때 비교대상도 Normal form으로 만들어야 합니다.
		for i := range partyNum {
			ringQP.IMForm(polysCRT[i], polysCRT[i])
			//ringQP.INTT(polysCRT[i], polysCRT[i])
		}
		// coefficient form에서 CRT merge

		coef := make([]uint64, len(moduli))
		for i := range partyNum {
			polysBigint[i] = make([]*big.Int, params.N())
			for j := range params.N() {
				for k := range polysCRT[i].Q.Coeffs {
					coef[k] = polysCRT[i].Q.Coeffs[k][j]
				}
				for k := range polysCRT[i].P.Coeffs {
					coef[len(params.Q())+k] = polysCRT[i].P.Coeffs[k][j]
				}

				polysBigint[i][j], _, _ = crt.CRTUint64(coef, moduli)
			}
		}
	}

	// ######## sk share verification check (SUM == sk_auth??) ######
	{
		polystemp := make([]*big.Int, params.N())
		for i := range polystemp {
			polystemp[i] = big.NewInt(0)
		}

		coef := make([]uint64, len(moduli))
		polyCRT := ringQP.NewPoly()
		for i := range params.N() {
			for j := range partyNum {
				polystemp[i] = new(big.Int).Add(polystemp[i], polysBigint[j][i])
			}
			copy(coef, ringQP.RingQ.NewRNSScalarFromBigint(polystemp[i]))
			copy(coef[len(params.Q()):], ringQP.RingP.NewRNSScalarFromBigint(polystemp[i]))

			for j := range polyCRT.Q.Coeffs {
				polyCRT.Q.Coeffs[j][i] = coef[j]
			}
			for j := range polyCRT.P.Coeffs {
				polyCRT.P.Coeffs[j][i] = coef[len(params.Q())+j]
			}
		}
		sktemp := *authCTX.sk.Value.CopyNew()
		// Normal form으로 만들어서 비교합니다. (위에 주석 처리했다면 여기도 주석처리해야 verification check 통과할 수 있습니다.)
		ringQP.IMForm(sktemp, sktemp)
		//ringQP.INTT(sktemp, sktemp)

		isOK := true
		for i := range sktemp.Q.Coeffs {
			for j := range sktemp.Q.Coeffs[i] {
				if sktemp.Q.Coeffs[i][j] != polyCRT.Q.Coeffs[i][j] {
					isOK = false
					break
				}
			}
		}
		for i := range sktemp.P.Coeffs {
			for j := range sktemp.P.Coeffs[i] {
				if sktemp.P.Coeffs[i][j] != polyCRT.P.Coeffs[i][j] {
					isOK = false
					break
				}
			}
		}

		if isOK {
			fmt.Println("SK share 생성 성공")
		} else {
			fmt.Println("SK share 생성 실패")
		}
		fmt.Println()
	}
	// TODO End

	skNew := SecRes(pubCTX, authCTX, partyNum)

	fmt.Println("키 직접 비교")
	{
		isOk := true
		for i := range skNew.Value.Q.Coeffs {
			for j := range skNew.Value.Q.Coeffs[i] {
				if skNew.Value.Q.Coeffs[i][j] != clientCTX.sk.Value.Q.Coeffs[i][j] {
					isOk = false
					break
				}
			}
		}
		if isOk {
			fmt.Println("SK 복구 성공")
		} else {
			fmt.Println("SK 복구 실패")
		}
	}

	fmt.Println("값 비교")
	{
		values := make([]complex128, params.MaxSlots())
		for i := range values {
			values[i] = sampling.RandComplex128(-1, 1)
		}
		pt := hefloat.NewPlaintext(params, params.MaxLevel())
		encoder.Encode(values, pt)
		ct, _ := encryptor.EncryptNew(pt)

		values_OriginSK := make([]complex128, params.MaxSlots())
		if err := encoder.Decode(pt, values_OriginSK); err != nil {
			panic(err)
		}

		// ringQ := params.RingQ()
		// pt.Resize(0, 0)
		// ringQ.AtLevel(0).MulCoeffsMontgomery(ct.Value[1], sk.Value.Q, pt.Value)
		// ringQ.AtLevel(0).Add(ct.Value[0], pt.Value, pt.Value)
		decryptor_New := rlwe.NewDecryptor(params, skNew)
		pt = decryptor_New.DecryptNew(ct)

		values_NewSK := make([]complex128, params.MaxSlots())
		if err := encoder.Decode(pt, values_NewSK); err != nil {
			panic(err)
		}

		maxerr := float64(0)
		for i := range values_NewSK {
			err := cmplx.Abs(values_NewSK[i] - values_OriginSK[i])
			if err > maxerr {
				maxerr = err
			}
		}

		fmt.Println("Compare With Decrypt By Origin SK vs New SK")
		fmt.Println("max-bit-precision", -math.Log2(maxerr))
	}

}

// filename 경로에 q, p를 저장합니다
func SaveModuliToTXT(filename string, q, p []uint64) {
	f, _ := os.Create(filename)
	defer f.Close()

	qStr := uint64SliceToString(q)
	pStr := uint64SliceToString(p)

	fmt.Fprintf(f, "q=%s\np=%s\n", qStr, pStr)
}

// filename 경로에서 q, p를 읽어옵니다
func LoadModuliFromTXT(filename string) (q, p []uint64) {
	f, _ := os.Open(filename)
	defer f.Close()

	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		switch {
		case strings.HasPrefix(line, "q="):
			q = parseUint64Slice(strings.TrimPrefix(line, "q="))

		case strings.HasPrefix(line, "p="):
			p = parseUint64Slice(strings.TrimPrefix(line, "p="))
		}
	}

	return q, p
}

func uint64SliceToString(nums []uint64) string {
	if len(nums) == 0 {
		return ""
	}

	parts := make([]string, len(nums))
	for i, v := range nums {
		parts[i] = strconv.FormatUint(v, 10)
	}
	return strings.Join(parts, ",")
}

func parseUint64Slice(s string) []uint64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return []uint64{}
	}

	parts := strings.Split(s, ",")
	res := make([]uint64, len(parts))

	for i, part := range parts {
		v, _ := strconv.ParseUint(strings.TrimSpace(part), 10, 64)
		res[i] = v
	}

	return res
}
