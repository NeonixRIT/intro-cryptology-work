package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"time"
)

func squareExponentiation(a int, b int, n int) int {
	r := 1
	for b > 0 {
		if b%2 == 1 {
			r = (r * a) % n
		}
		a = (a * a) % n
		b /= 2
	}
	return r
}

func isPrimeFromSlice(n *big.Int, primes []*big.Int) bool {
	for _, p := range primes {
		tempN1 := new(big.Int)
		tempN1.Set(n)
		tempN2 := new(big.Int)
		tempN2.Set(n)
		if tempN1.Mod(tempN1, p).Cmp(big.NewInt(0)) == 0 && p.Exp(p, big.NewInt(2), nil).Cmp(tempN2) <= 0 {
			return false
		}
	}
	return true
}

func isPrimeDefault(n int) bool {
	if n <= 1 {
		return false
	}
	if n == 2 || n == 3 {
		return true
	}
	if n%2 == 0 {
		return false
	}
	for i := 3; i*i <= n; i += 2 {
		if n%i == 0 {
			return false
		}
	}
	return true
}

func isPrimeMiller(n *big.Int, k int) bool {
	if n.Cmp(big.NewInt(1)) <= 0 {
		return false
	}
	if n.Cmp(big.NewInt(3)) <= 0 {
		return true
	}
	if n.Bit(0) == 0 {
		return false
	}

	// Write n-1 as 2^r * d
	d := new(big.Int).Sub(n, big.NewInt(1))
	r := 0
	for d.Bit(0) == 0 {
		r++
		d.Rsh(d, 1)
	}

	// Perform k rounds of testing
	for i := 0; i < k; i++ {
		a, _ := rand.Int(rand.Reader, new(big.Int).Sub(n, big.NewInt(4)))
		a.Add(a, big.NewInt(2))
		x := new(big.Int).Exp(a, d, n)
		if x.Cmp(big.NewInt(1)) == 0 || x.Cmp(new(big.Int).Sub(n, big.NewInt(1))) == 0 {
			continue
		}
		for j := 0; j < r-1; j++ {
			x.Exp(x, big.NewInt(2), n)
			if x.Cmp(new(big.Int).Sub(n, big.NewInt(1))) == 0 {
				break
			}
		}
		if x.Cmp(new(big.Int).Sub(n, big.NewInt(1))) != 0 {
			return false
		}
	}

	return true
}

func isPrime(n *big.Int) bool {
	return isPrimeMiller(n, 20)
}

func generatePrimeNumber(minBits int) *big.Int {
	min := big.NewInt(2)
	min = min.Exp(min, big.NewInt(int64(minBits-1)), nil)
	max := big.NewInt(2)
	max = max.Exp(max, big.NewInt(int64(minBits)), nil)
	for {
		tempMax := new(big.Int)
		tempMax.Set(max)
		n, _ := rand.Int(rand.Reader, tempMax.Sub(tempMax, min))
		n.Add(n, min)
		if isPrime(n) {
			return n
		}
	}
}

func main() {
	for {
		fmt.Printf("Generating prime number (Miller)... ")
		start := time.Now()
		num := generatePrimeNumber(2048)
		duration := time.Since(start)
		fmt.Println(num)
		fmt.Printf("\tbits: %v\n", num.BitLen())
		fmt.Printf("\ttime: %v\n\n\n", duration)
	}

	// fmt.Printf("Generating prime number (Miller)... ")
	// start = time.Now()
	// num, _ = rand.Prime(rand.Reader, 2048)
	// duration = time.Since(start)
	// fmt.Println(num)
	// fmt.Printf("\tbits: %v\n", num.BitLen())
	// fmt.Printf("\ttime: %v\n\n", duration)
}
