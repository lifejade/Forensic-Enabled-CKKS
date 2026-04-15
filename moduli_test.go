package main

import (
	"fmt"
	"testing"

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
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
