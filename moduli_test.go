package main

import (
	"fmt"
	"math/big"
	"math/cmplx"
	"runtime"
	"sync"
	"testing"
	"tifs/src/crt"

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he/hefloat"
	"github.com/tuneinsight/lattigo/v5/utils/sampling"
)

func Test_MakeModuli(t *testing.T) {
	logN := 16
	logQ := []int{48, 40, 40, 40, 40, 40, 40, 40, 40, 40}
	logP := []int{48, 48}
	filename := "moduli.txt"

	q, p, _ := rlwe.GenModuli(logN+1, logQ, logP)
	fmt.Println("Q:", q)
	fmt.Println("P:", p)
	fmt.Println()

	SaveModuliToTXT(filename, q, p)

	q_, p_ := LoadModuliFromTXT(filename)
	fmt.Println("Q:", q_)
	fmt.Println("P:", p_)
}

func Test_Decrypt(t *testing.T) {
	//CPU full power
	runtime.GOMAXPROCS(runtime.NumCPU())

	TripleCount = 0
	modulipath := "moduli.txt"
	Q, P := LoadModuliFromTXT(modulipath)

	//ckks parameter init
	SchemeParams := hefloat.ParametersLiteral{
		LogN:            16,
		Q:               Q,
		P:               P,
		LogDefaultScale: 40,
	}
	params, err := hefloat.NewParametersFromLiteral(SchemeParams)
	if err != nil {
		panic(err)
	}
	kgen := rlwe.NewKeyGenerator(params)
	sk := kgen.GenSecretKeyNew()
	pk := kgen.GenPublicKeyNew(sk)
	rlk := kgen.GenRelinearizationKeyNew(sk)

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
	evk := rlwe.NewMemEvaluationKeySet(rlk, rtk...)
	evaluator := hefloat.NewEvaluator(params, evk)

	_, _, _, _ = encoder, encryptor, evaluator, decryptor

	values := make([]complex128, params.MaxSlots())
	for i := range values {
		values[i] = sampling.RandComplex128(-1, 1)
	}
	pt := hefloat.NewPlaintext(params, params.MaxLevel())
	encoder.Encode(values, pt)
	ct, _ := encryptor.EncryptNew(pt)

	//[degree][N]
	fmt.Println("CT : CRT -> BIGINT")
	ctbigint := make([][]*big.Int, 2)
	for i := range ctbigint {
		ctbigint[i] = make([]*big.Int, params.N())
	}
	{
		ctLevel := ct.Level()
		moduli := params.Q()[:ctLevel+1]
		coefs := make([]uint64, ctLevel+1)
		for d := range 2 {
			for i := range params.N() {
				for j := range ctLevel + 1 {
					coefs[j] = ct.Value[d].Coeffs[j][i]
				}
				ctbigint[d][i], _, _ = crt.CRTUint64(coefs, moduli)
			}
		}
	}
	ptbigint := make([]*big.Int, params.N())
	skbigint := make([]*big.Int, params.N())

	{

		fmt.Println("SK : CRT -> BIGINT")
		ctLevel := ct.Level()
		moduli := params.Q()[:ctLevel+1]
		coefs := make([]uint64, ctLevel+1)
		var M *big.Int
		sktemp := sk.CopyNew()
		params.RingQP().IMForm(sktemp.Value, sktemp.Value)
		for i := range params.N() {
			for j := range ctLevel + 1 {
				coefs[j] = sktemp.Value.Q.Coeffs[j][i]
			}
			skbigint[i], M, _ = crt.CRTUint64(coefs, moduli)
		}

		fmt.Println("Decrypt")
		for i := range params.N() {
			ptbigint[i] = big.NewInt(0)
			ptbigint[i].Mul(ctbigint[1][i], skbigint[i])
			ptbigint[i].Add(ctbigint[0][i], ptbigint[i])
			ptbigint[i].Mod(ptbigint[i], M)
		}
	}

	//make pt : bigint -> CRT
	ptres := hefloat.NewPlaintext(params, ct.Level())
	{
		ringQ := params.RingQ().AtLevel(ct.Level())
		for i := range params.N() {
			rns := ringQ.NewRNSScalarFromBigint(ptbigint[i])
			for j := range ct.Level() + 1 {
				ptres.Value.Coeffs[j][i] = rns[j]
			}
		}
	}

	valueRes := make([]complex128, params.MaxSlots())
	encoder.Decode(ptres, valueRes)

	maxErr := 0.0
	for i := range params.MaxSlots() {
		abserr := cmplx.Abs(values[i] - valueRes[i])
		if abserr > maxErr {
			maxErr = abserr
		}
	}
	fmt.Println(maxErr)
}
