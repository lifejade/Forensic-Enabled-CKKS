package galois

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he/hefloat"
	"github.com/tuneinsight/lattigo/v5/ring"
	"github.com/tuneinsight/lattigo/v5/ring/ringqp"
	"github.com/tuneinsight/lattigo/v5/utils"
	"github.com/tuneinsight/lattigo/v5/utils/sampling"
)

func Automorphism(eval *hefloat.Evaluator, ctIn *rlwe.Ciphertext, galEl uint64, evk *rlwe.GaloisKey, opOut *rlwe.Ciphertext) (err error) {

	if ctIn.Degree() != 1 || opOut.Degree() != 1 {
		return fmt.Errorf("cannot apply Automorphism: input and output Ciphertext must be of degree 1")
	}

	if galEl == 1 {
		if opOut != ctIn {
			opOut.Copy(ctIn)
		}
		return
	}

	level := utils.Min(ctIn.Level(), opOut.Level())

	opOut.Resize(opOut.Degree(), level)

	ringQ := eval.GetRLWEParameters().RingQ().AtLevel(level)

	ctTmp := &rlwe.Ciphertext{Element: rlwe.Element[ring.Poly]{Value: []ring.Poly{eval.BuffQP[0].Q, eval.BuffQP[1].Q}}}
	ctTmp.MetaData = ctIn.MetaData

	eval.GadgetProduct(level, ctIn.Value[1], &evk.GadgetCiphertext, ctTmp)

	ringQ.Add(ctTmp.Value[0], ctIn.Value[0], ctTmp.Value[0])

	if ctIn.IsNTT {
		ringQ.AutomorphismNTTWithIndex(ctTmp.Value[0], eval.AutomorphismIndex(galEl), opOut.Value[0])
		ringQ.AutomorphismNTTWithIndex(ctTmp.Value[1], eval.AutomorphismIndex(galEl), opOut.Value[1])
	} else {
		ringQ.Automorphism(ctTmp.Value[0], galEl, opOut.Value[0])
		ringQ.Automorphism(ctTmp.Value[1], galEl, opOut.Value[1])
	}

	*opOut.MetaData = *ctIn.MetaData

	return
}

// GenGaloisKeyNew generates a new GaloisKey, enabling the automorphism X^{i} -> X^{i * galEl}.
func GenGaloisKeyNew(kgen *rlwe.KeyGenerator, galEl uint64, sk *rlwe.SecretKey, polys []ringqp.Poly, evkParams ...rlwe.EvaluationKeyParameters) (gk *rlwe.GaloisKey) {
	levelQ, levelP, BaseTwoDecomposition := rlwe.ResolveEvaluationKeyParameters(*kgen.GetRLWEParameters(), evkParams)
	gk = &rlwe.GaloisKey{
		EvaluationKey: rlwe.EvaluationKey{GadgetCiphertext: *rlwe.NewGadgetCiphertext(kgen.GetRLWEParameters(), 1, levelQ, levelP, BaseTwoDecomposition)},
		NthRoot:       kgen.GetRLWEParameters().RingQ().NthRoot(),
	}

	GenGaloisKey(kgen, galEl, sk, gk, polys)
	return
}

// GenGaloisKey generates a GaloisKey, enabling the automorphism X^{i} -> X^{i * galEl}.
func GenGaloisKey(kgen *rlwe.KeyGenerator, galEl uint64, sk *rlwe.SecretKey, gk *rlwe.GaloisKey, polys []ringqp.Poly) {

	skIn := sk.Value

	ringQP := kgen.GetRLWEParameters().RingQP().AtLevel(gk.LevelQ(), gk.LevelP())

	ringQ := ringQP.RingQ
	ringP := ringQP.RingP
	skOut := ringQP.NewPoly()

	// We encrypt [-a * pi_{k^-1}(sk) + sk, a]
	// This enables to first apply the gadget product, re-encrypting
	// a ciphetext from sk to pi_{k^-1}(sk) and then we apply pi_{k}
	// on the ciphertext.
	galElInv := kgen.GetRLWEParameters().ModInvGaloisElement(galEl)

	index, err := ring.AutomorphismNTTIndex(ringQ.N(), ringQ.NthRoot(), galElInv)

	// Sanity check, this error should not happen unless the
	// evaluator's buffer thave been improperly tempered with.
	if err != nil {
		panic(err)
	}

	ringQ.AutomorphismNTTWithIndex(skIn.Q, index, skOut.Q)

	if ringP != nil {
		ringP.AutomorphismNTTWithIndex(skIn.P, index, skOut.P)
	}

	genEvaluationKey(kgen, skIn.Q, skOut, &gk.EvaluationKey, polys)

	gk.GaloisElement = galEl
	gk.NthRoot = ringQ.NthRoot()
}

func genEvaluationKey(kgen *rlwe.KeyGenerator, skIn ring.Poly, skOut ringqp.Poly, evk *rlwe.EvaluationKey, polys []ringqp.Poly) {

	enc := kgen.WithKey(&rlwe.SecretKey{Value: skOut})
	buffQ := kgen.GetRLWEParameters().RingQ().NewPoly()

	// Samples an encryption of zero for each element of the EvaluationKey.
	for i := 0; i < len(evk.Value); i++ {
		if i <= 1 {
			for j := 0; j < len(evk.Value[i]); j++ {
				encryptZero(rlwe.Element[ringqp.Poly]{MetaData: &rlwe.MetaData{CiphertextMetaData: rlwe.CiphertextMetaData{IsNTT: true, IsMontgomery: true}}, Value: []ringqp.Poly(evk.Value[i][j])}, polys[i], &rlwe.SecretKey{Value: skOut}, *kgen.GetRLWEParameters())
			}
		} else {
			for j := 0; j < len(evk.Value[i]); j++ {
				if err := enc.EncryptZero(rlwe.Element[ringqp.Poly]{MetaData: &rlwe.MetaData{CiphertextMetaData: rlwe.CiphertextMetaData{IsNTT: true, IsMontgomery: true}}, Value: []ringqp.Poly(evk.Value[i][j])}); err != nil {
					// Sanity check, this error should not happen.
					panic(err)
				}
			}
		}
	}

	// Adds the plaintext (input-key) to the EvaluationKey.
	if err := AddPolyTimesGadgetVectorToGadgetCiphertext(skIn, []rlwe.GadgetCiphertext{evk.GadgetCiphertext}, *kgen.GetRLWEParameters().RingQP(), buffQ); err != nil {
		// Sanity check, this error should not happen.
		panic(err)
	}
}

func encryptZero(ct interface{}, c1 ringqp.Poly, sk *rlwe.SecretKey, params rlwe.Parameters) {
	switch ct := ct.(type) {
	case rlwe.Element[ringqp.Poly]:

		// var c1 ringqp.Poly
		c0 := ct.Value[0]
		ct.Value[1] = *c1.CopyNew()

		levelQ := ct.Level()
		prng, _ := sampling.NewPRNG()
		xeSampler, _ := ring.NewSampler(prng, params.RingQ(), params.Xe(), false)

		levelQ, levelP := ct.LevelQ(), ct.LevelP()
		ringQP := params.RingQP().AtLevel(levelQ, levelP)

		xeSampler.AtLevel(levelQ).Read(c0.Q)
		if levelP != -1 {
			ringQP.ExtendBasisSmallNormAndCenter(c0.Q, levelP, c0.Q, c0.P)
		}

		ringQP.NTT(c0, c0)
		// ct[1] is assumed to be sampled in of the Montgomery domain,
		// thus -as will also be in the Montgomery domain (s is by default), therefore 'e'
		// must be switched to the Montgomery domain.
		ringQP.MForm(c0, c0)

		// (-a*sk + e, a)
		ringQP.MulCoeffsMontgomeryThenSub(c1, sk.Value, c0)
	}
}
func AddPolyTimesGadgetVectorToGadgetCiphertext(pt ring.Poly, cts []rlwe.GadgetCiphertext, ringQP ringqp.Ring, buff ring.Poly) (err error) {
	levelQ := cts[0].LevelQ()
	levelP := cts[0].LevelP()

	ringQ := ringQP.RingQ.AtLevel(levelQ)

	if len(cts) > 2 {
		return fmt.Errorf("cannot AddPolyTimesGadgetVectorToGadgetCiphertext: len(cts) should be <= 2")
	}

	if levelP != -1 {
		ringQ.MulScalarBigint(pt, ringQP.RingP.AtLevel(levelP).Modulus(), buff) // P * pt
	} else {
		levelP = 0
		buff.CopyLvl(levelQ, pt) // 1 * pt
	}

	BaseRNSDecompositionVectorSize := len(cts[0].Value)

	BaseTwoDecompositionVectorSize := make([]int, len(cts[0].Value))
	for i := range BaseTwoDecompositionVectorSize {
		BaseTwoDecompositionVectorSize[i] = len(cts[0].Value[i])
	}

	N := ringQ.N()

	var index int
	for j := 0; j < utils.MaxSlice(BaseTwoDecompositionVectorSize); j++ {

		for i := 0; i < BaseRNSDecompositionVectorSize; i++ {

			if j < BaseTwoDecompositionVectorSize[i] {

				// e + (m * P * w^2j) * (q_star * q_tild) mod QP
				//
				// q_prod = prod(q[i*#Pi+j])
				// q_star = Q/qprod
				// q_tild = q_star^-1 mod q_prod
				//
				// Therefore : (pt * P * w^2j) * (q_star * q_tild) = pt*P*w^2j mod q[i*#Pi+j], else 0
				for k := 0; k < levelP+1; k++ {

					index = i*(levelP+1) + k

					// Handle cases where #pj does not divide #qi
					if index >= levelQ+1 {
						break
					}

					qi := ringQ.SubRings[index].Modulus
					p0tmp := buff.Coeffs[index]

					for u, ct := range cts {
						p1tmp := ct.Value[i][j][u].Q.Coeffs[index]
						for w := 0; w < N; w++ {
							p1tmp[w] = ring.CRed(p1tmp[w]+p0tmp[w], qi)
						}
					}

				}
			}
		}

		// w^2j
		ringQ.MulScalar(buff, 1<<cts[0].BaseTwoDecomposition, buff)
	}

	return
}
