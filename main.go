package main

import (
	"fmt"
	"math"
	"math/cmplx"
	"runtime"
	"sync"
	"tifs/src/crt"
	"tifs/src/galois"

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he/hefloat"
	"github.com/tuneinsight/lattigo/v5/ring"
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

func SecRes(pubCTX PublicSideContext, authCTX AuthSideContext) *rlwe.SecretKey {
	params := pubCTX.params
	gk := pubCTX.conjKey
	skAuth := authCTX.sk
	ringqp := params.RingQP()

	b0 := *gk.Value[0][0][0].CopyNew()
	b1 := *gk.Value[1][0][0].CopyNew()
	var perLevel int
	{
		temp := float64(len(params.Q())) / float64(len(gk.Value))
		perLevel = int(math.Ceil(temp))
	}
	Q0Q1level := perLevel * 2

	ringqp.MulCoeffsMontgomery(b1, skAuth.Value, b1)
	ringqp.Add(b0, b1, b0)
	ringqp.Reduce(b0, b0)
	ringqp.IMForm(b0, b0)

	N := params.N()
	Q_ := params.Q()
	P_ := Q_[Q0Q1level:]
	for _, v := range params.P() {
		P_ = append(P_, v)
	}
	Q_ = Q_[:Q0Q1level]

	ringQ_, _ := ring.NewRing(N, Q_)
	ringP_, _ := ring.NewRing(N, P_)
	be := crt.NewBasisExtender(ringQ_, ringP_)

	polQ_ := ringQ_.NewPoly()
	polres := ringQ_.NewPoly()
	polP_ := ringP_.NewPoly()
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

	polskAuth := ringQ_.NewPoly()
	for i, v := range skAuth.Value.Q.Coeffs[:4] {
		copy(polskAuth.Coeffs[i], v)
	}

	Q := params.Q()
	blockA := make([]int, perLevel)
	blockB := make([]int, perLevel)
	for i := range perLevel {
		blockA[i] = i
		blockB[i] = i + perLevel
	}

	t1, _ := crt.ComputeValue(Q, blockA, blockB)
	t0, _ := crt.ComputeValue(Q, blockB, blockA)

	ringQ_.MulScalarBigint(polskAuth, t1, polskAuth)
	ringQ_.IMForm(polskAuth, polskAuth)
	ringQ_.AddScalarBigint(polskAuth, t0, polskAuth)
	ringQ_.MForm(polskAuth, polskAuth)
	ringQ_.Reduce(polskAuth, polskAuth)

	coef := make([]uint64, len(ringQ_.ModuliChain()))
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
	ringQ_.INTT(polres, polres)

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

	ringqp.MForm(sk.Value, sk.Value)
	ringqp.NTT(sk.Value, sk.Value)
	// ringQ_.MForm(polres, polres)
	// return polres
	return sk
}

func main() {
	//CPU full power
	runtime.GOMAXPROCS(runtime.NumCPU())
	//ckks parameter init
	SchemeParams := hefloat.ParametersLiteral{
		LogN:            16,
		LogQ:            []int{48, 40, 40, 40, 40, 40, 40, 40, 40, 40},
		LogP:            []int{48, 48},
		LogDefaultScale: 40,
	}
	pubCTX, clientCTX, authCTX := BeginProtocol(SchemeParams)
	params := pubCTX.params
	encoder := pubCTX.encoder
	encryptor := pubCTX.encryptor
	// evaluator := pubCTX.evaluator
	skNew := SecRes(pubCTX, authCTX)

	fmt.Println("키 직접 비교")
	{
		isOk := true
		for i := range skNew.Value.Q.Coeffs {
			for j := range skNew.Value.Q.Coeffs {
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
