// Copyright (c) 2020, Google Inc.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

package main

import (
	"crypto/elliptic"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"
)

func main() {
	if err := writeP256NistzTable("p256-nistz-table.h"); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing p256-nistz-table.h: %s\n", err)
		os.Exit(1)
	}

	if err := writeP256Table("p256_table.h"); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing p256_table.h: %s\n", err)
		os.Exit(1)
	}

	if err := writeP384Table("p384_table.h"); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing p384_table.h: %s\n", err)
		os.Exit(1)
	}

	if err := writeP521Table("p521_table.h"); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing p521_table.h: %s\n", err)
		os.Exit(1)
	}
}

func writeP256NistzTable(path string) error {
	curve := elliptic.P256()
	tables := make([][][2]*big.Int, 0, 37)
	for shift := 0; shift < 256; shift += 7 {
		row := makeMultiples(curve, 64, shift)
		tables = append(tables, row)
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	const fileHeader = `/*
 * Copyright 2014-2016 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2015, Intel Inc.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

// This is the precomputed constant time access table for the code in
// p256-nistz.c, for the default generator. The table consists of 37
// subtables, each subtable contains 64 affine points. The affine points are
// encoded as eight uint64's, four for the x coordinate and four for the y.
// Both values are in little-endian order. There are 37 tables because a
// signed, 6-bit wNAF form of the scalar is used and ceil(256/(6 + 1)) = 37.
// Within each table there are 64 values because the 6-bit wNAF value can take
// 64 values, ignoring the sign bit, which is implemented by performing a
// negation of the affine point when required. We would like to align it to 2MB
// in order to increase the chances of using a large page but that appears to
// lead to invalid ELF files being produced.

// This file is generated by make_tables.go.

static const alignas(4096) PRECOMP256_ROW ecp_nistz256_precomputed[37] = `
	if _, err := f.WriteString(fileHeader); err != nil {
		return err
	}
	if err := writeTables(f, curve, tables, true, 4, writeBNMont, nil); err != nil {
		return err
	}
	if _, err := f.WriteString(";\n"); err != nil {
		return err
	}

	return nil
}

func writeP256Table(path string) error {
	curve := elliptic.P256()
	tables := [][][2]*big.Int{
		makeComb(curve, 64, 4, 0),
		makeComb(curve, 64, 4, 32),
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	const fileHeader = `/* Copyright (c) 2020, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

// This file is generated by make_tables.go.

// Base point pre computation
// --------------------------
//
// Two different sorts of precomputed tables are used in the following code.
// Each contain various points on the curve, where each point is three field
// elements (x, y, z).
//
// For the base point table, z is usually 1 (0 for the point at infinity).
// This table has 2 * 16 elements, starting with the following:
// index | bits    | point
// ------+---------+------------------------------
//     0 | 0 0 0 0 | 0G
//     1 | 0 0 0 1 | 1G
//     2 | 0 0 1 0 | 2^64G
//     3 | 0 0 1 1 | (2^64 + 1)G
//     4 | 0 1 0 0 | 2^128G
//     5 | 0 1 0 1 | (2^128 + 1)G
//     6 | 0 1 1 0 | (2^128 + 2^64)G
//     7 | 0 1 1 1 | (2^128 + 2^64 + 1)G
//     8 | 1 0 0 0 | 2^192G
//     9 | 1 0 0 1 | (2^192 + 1)G
//    10 | 1 0 1 0 | (2^192 + 2^64)G
//    11 | 1 0 1 1 | (2^192 + 2^64 + 1)G
//    12 | 1 1 0 0 | (2^192 + 2^128)G
//    13 | 1 1 0 1 | (2^192 + 2^128 + 1)G
//    14 | 1 1 1 0 | (2^192 + 2^128 + 2^64)G
//    15 | 1 1 1 1 | (2^192 + 2^128 + 2^64 + 1)G
// followed by a copy of this with each element multiplied by 2^32.
//
// The reason for this is so that we can clock bits into four different
// locations when doing simple scalar multiplies against the base point,
// and then another four locations using the second 16 elements.
//
// Tables for other points have table[i] = iG for i in 0 .. 16.

// fiat_p256_g_pre_comp is the table of precomputed base points
#if defined(BORINGSSL_NISTP256_64BIT)
static const fiat_p256_felem fiat_p256_g_pre_comp[2][15][2] = `
	if _, err := f.WriteString(fileHeader); err != nil {
		return err
	}
	if err := writeTables(f, curve, tables, true, 4, writeU64Mont, nil); err != nil {
		return err
	}
	if _, err := f.WriteString(";\n#else\nstatic const fiat_p256_felem fiat_p256_g_pre_comp[2][15][2] = "); err != nil {
		return err
	}
	if err := writeTables(f, curve, tables, true, 4, writeU32Mont, nil); err != nil {
		return err
	}
	if _, err := f.WriteString(";\n#endif\n"); err != nil {
		return err
	}

	return nil
}

func writeP384Table(path string) error {

	win_size := 5 // window size for the comb multiplication
	pts_per_subtable := (1 << win_size) >> 1 // we keep only the odd multiples
	num_subtables := int(math.Ceil(float64(384) / float64(win_size * 4))) // we use comb mul with step 4

	curve := elliptic.P384()
	tables := make([][][2]*big.Int, 0, num_subtables)
	for i := 0; i < num_subtables; i += 1 {
		row := makeOddMultiples(curve, pts_per_subtable, i*win_size*4)
		tables = append(tables, row)
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	const fileHeader = `/*
------------------------------------------------------------------------------------
 Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
 SPDX-License-Identifier: Apache-2.0 OR ISC
------------------------------------------------------------------------------------
*/

// This file is generated by make_tables.go.

// P-384 base point pre computation
// --------------------------------
//
// Based on windows size equal to 5, the precomputed table for the base point G
// of P-384, |p384_g_pre_comp|, consists of 20 sub-tables, each holding 16
// points. A point is represented by a pair of field elements (x, y).
//
// The j-th point of the i-th sub-table is:
//     p384_g_pre_comp[i][j] = [(2j + 1)2^{20i}]G.
// The table is populated with such points for i in [0, 19] and j in [0, 15];
// and used in mul_base and mul_public functions in |p384.c| for computing
// a scalar product with the Comb method (see the functions for details).
//
// The table and its usage in scalar multiplications are adapted from
// ECCKiila project (https://arxiv.org/abs/2007.11481). The table generation
// is based on the generation method in:
// https://gitlab.com/nisec/ecckiila/-/blob/master/main.py#L296

#if defined(P384_USE_64BIT_LIMBS_FELEM)`

	table_def_str := fmt.Sprintf("static const p384_felem p384_g_pre_comp[%d][%d][2] = ", num_subtables, pts_per_subtable)

	if _, err := f.WriteString(fileHeader + "\n" + table_def_str); err != nil {
		return err
	}
	if err := writeTables(f, curve, tables, true, 4, writeU64Mont, nil); err != nil {
		return err
	}
	if _, err := f.WriteString(";\n#else\n" + table_def_str); err != nil {
		return err
	}
	if err := writeTables(f, curve, tables, true, 4, writeU32Mont, nil); err != nil {
		return err
	}
	if _, err := f.WriteString(";\n#endif\n"); err != nil {
		return err
	}

	return nil
}

func writeP521Table(path string) error {

	win_size := 5 // window size for the comb multiplication
	pts_per_subtable := (1 << win_size) >> 1 // we keep only the odd multiples
	num_subtables := int(math.Ceil(float64(521) / float64(win_size * 4))) // we use comb mul with step 4

	curve := elliptic.P521()
	tables := make([][][2]*big.Int, 0, num_subtables)
	for i := 0; i < num_subtables; i += 1 {
		row := makeOddMultiples(curve, pts_per_subtable, i*win_size*4)
		tables = append(tables, row)
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	const fileHeader = `/*
------------------------------------------------------------------------------------
 Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
 SPDX-License-Identifier: Apache-2.0 OR ISC
------------------------------------------------------------------------------------
*/

// This file is generated by make_tables.go.

// P-521 base point pre computation
// --------------------------------
//
// Based on windows size equal to 5, the precomputed table for the base point G
// of P-521, |p521_g_pre_comp|, consists of 27 sub-tables, each holding 16
// points. A point is represented by a pair of field elements (x, y).
//
// The j-th point of the i-th sub-table is:
//     p521_g_pre_comp[i][j] = [(2j + 1)2^{20i}]G.
// The table is populated with such points for i in [0, 26] and j in [0, 15];
// and used in mul_base and mul_public functions in |p521.c| for computing
// a scalar product with the Comb method (see the functions for details).
//
// The table and its usage in scalar multiplications are adapted from
// ECCKiila project (https://arxiv.org/abs/2007.11481). The table generation
// is based on the generation method in:
// https://gitlab.com/nisec/ecckiila/-/blob/master/main.py#L296

#if defined(P521_USE_S2N_BIGNUM_FIELD_ARITH)`

	table_def_str := fmt.Sprintf("static const p521_felem p521_g_pre_comp[%d][%d][2] = ", num_subtables, pts_per_subtable)

	if _, err := f.WriteString(fileHeader + "\n" + table_def_str); err != nil {
		return err
	}
	if err := writeTables(f, curve, tables, true, 4, writeU64, nil); err != nil {
		return err
	}
	if _, err := f.WriteString(";\n#else\n#if defined(P521_USE_64BIT_LIMBS_FELEM)\n" + table_def_str); err != nil {
		return err
	}
	// P-521 Fiat-crypto implementation for 64-bit systems represents a field
	// element by an array of 58-bit digits stored in 64-bit containers.
	if err := writeTables(f, curve, tables, true, 4, writeU58, nil); err != nil {
		return err
	}
	if _, err := f.WriteString(";\n#else\n" + table_def_str); err != nil {
		return err
	}
	// P-521 Fiat-crypto implementation for 32-bit systems represents a field
	// element by an array of digits where digits have bit-size as listed below.
	var bitSizes = [...]uint {28, 27, 28, 27, 28, 27, 27, 28, 27, 28, 27, 28, 27, 27, 28, 27, 28, 27, 27}
	if err := writeTables(f, curve, tables, true, 4, writeU32Custom, bitSizes[:]); err != nil {
		return err
	}
	if _, err := f.WriteString(";\n#endif\n#endif\n"); err != nil {
		return err
	}

	return nil
}

// makeMultiples returns a table of the first n multiples of 2^shift * G,
// starting from 1 * 2^shift * G.
func makeMultiples(curve elliptic.Curve, n, shift int) [][2]*big.Int {
	ret := make([][2]*big.Int, n)
	x, y := curve.Params().Gx, curve.Params().Gy
	for j := 0; j < shift; j++ {
		x, y = curve.Double(x, y)
	}
	ret[1-1] = [2]*big.Int{x, y}
	for i := 2; i <= n; i++ {
		if i&1 == 0 {
			x, y := curve.Double(ret[i/2-1][0], ret[i/2-1][1])
			ret[i-1] = [2]*big.Int{x, y}
		} else {
			x, y := curve.Add(ret[i-1-1][0], ret[i-1-1][1], ret[1-1][0], ret[1-1][1])
			ret[i-1] = [2]*big.Int{x, y}
		}
	}
	return ret
}

// makeOddMultiples returns a table of the first n odd multiples of 2^shift * G
// starting from 1 * 2^shift * G.
func makeOddMultiples(curve elliptic.Curve, n, shift int) [][2]*big.Int {
	ret := make([][2]*big.Int, n)
	x, y := curve.Params().Gx, curve.Params().Gy
	cnt := 0
	for j := 0; j < shift; j++ {
		x, y = curve.Double(x, y)
		cnt++
	}

	ret[0] = [2]*big.Int{x, y}
	x2, y2 := curve.Double(x, y)

	for i := 1; i < n; i++ {
		x, y := curve.Add(ret[i-1][0], ret[i-1][1], x2, y2)
		ret[i] =[2]*big.Int{x, y}
	}

	return ret
}

// makeComb returns a table of 2^size - 1 points. The i-1th entry is k*G.
// If i is represented in binary by b0*2^0 + b1*2^1 + ... bn*2^n, k is
// b0*2^(shift + 0*stride) + b1*2^(shift + 1*stride) + ... + bn*2^(shift + n*stride).
// The entry for i = 0 is omitted because it is always the point at infinity.
func makeComb(curve elliptic.Curve, stride, size, shift int) [][2]*big.Int {
	ret := make([][2]*big.Int, 1<<size-1)
	x, y := curve.Params().Gx, curve.Params().Gy
	for j := 0; j < shift; j++ {
		x, y = curve.Double(x, y)
	}
	ret[1<<0-1] = [2]*big.Int{x, y}
	for i := 1; i < size; i++ {
		// Entry 2^i is entry 2^(i-1) doubled stride times.
		x, y = ret[1<<(i-1)-1][0], ret[1<<(i-1)-1][1]
		for j := 0; j < stride; j++ {
			x, y = curve.Double(x, y)
		}
		ret[1<<i-1] = [2]*big.Int{x, y}
		// The remaining entries with MSB 2^i are computed by adding entry 2^i
		// to the corresponding previous entry.
		for j := 1; j < 1<<i; j++ {
			x, y = curve.Add(ret[1<<i-1][0], ret[1<<i-1][1], ret[j-1][0], ret[j-1][1])
			ret[1<<i+j-1] = [2]*big.Int{x, y}
		}
	}
	return ret
}

// toMontgomery sets n to be n×R mod p, where R is the Montgomery factor.
func toMontgomery(curve elliptic.Curve, n *big.Int) *big.Int {
	params := curve.Params()
	// R is the bit width of p, rounded up to word size.
	rounded64 := 64 * ((params.BitSize + 63) / 64)
	rounded32 := 32 * ((params.BitSize + 31) / 32)
	if rounded64 != rounded32 {
		panic(fmt.Sprintf("Montgomery form for %s is inconsistent between 32-bit and 64-bit", params.Name))
	}
	R := new(big.Int).SetInt64(1)
	R.Lsh(R, uint(rounded64))

	ret := new(big.Int).Mul(n, R)
	ret.Mod(ret, params.P)
	return ret
}

func bigIntToU64s(curve elliptic.Curve, n *big.Int) []uint64 {
	words := (curve.Params().BitSize + 63) / 64
	ret := make([]uint64, words)
	bytes := n.Bytes()
	for i, b := range bytes {
		i = len(bytes) - i - 1
		ret[i/8] |= uint64(b) << (8 * (i % 8))
	}
	return ret
}

// Convert big int to an array of 58-bit digits.
// This is needed for P-521 Fiat-crypto implementation in third_party/fiat/p521_64.h.
func bigIntToU58s(curve elliptic.Curve, n *big.Int) []uint64 {
	words := (curve.Params().BitSize + 57) / 58
	ret := make([]uint64, words)
	mask := big.NewInt((1 << 58) - 1)
	tmp := new(big.Int).Set(n)
	for i := 0; i < words; i++ {
		ret[i] = new(big.Int).And(tmp, mask).Uint64()
		tmp.Rsh(tmp, 58)
	}
	return ret
}

// Convert big int to an array of digits where each digit
// has bit-size as specified in the input bitSizes array
// This is needed for P-521 Fiat-crypto implementation in third_party/fiat/p521_32.h.
func bigIntToUCustom(curve elliptic.Curve, n *big.Int, bitSizes []uint) []uint64 {
	words := len(bitSizes)
	ret := make([]uint64, words)
	tmp := new(big.Int).Set(n)
	for i, bits := range bitSizes {
		mask := big.NewInt((1 << bits) - 1)
		ret[i] = new(big.Int).And(tmp, mask).Uint64()
		tmp.Rsh(tmp, bits)
	}
	return ret
}

func bigIntToU32s(curve elliptic.Curve, n *big.Int) []uint64 {
	words := (curve.Params().BitSize + 31) / 32
	ret := make([]uint64, words)
	bytes := n.Bytes()
	for i, b := range bytes {
		i = len(bytes) - i - 1
		ret[i/4] |= uint64(b) << (8 * (i % 4))
	}
	return ret
}

func writeIndent(w io.Writer, indent int) error {
	for i := 0; i < indent; i++ {
		if _, err := io.WriteString(w, " "); err != nil {
			return err
		}
	}
	return nil
}

func writeWords(w io.Writer, words []uint64, wrap, indent int, format func(uint64) string) error {
	if _, err := io.WriteString(w, "{"); err != nil {
		return err
	}
	for i, word := range words {
		if i > 0 {
			if i%wrap == 0 {
				if _, err := io.WriteString(w, ",\n"); err != nil {
					return err
				}
				if err := writeIndent(w, indent+1); err != nil {
					return err
				}
			} else {
				if _, err := io.WriteString(w, ", "); err != nil {
					return err
				}
			}
		}
		if _, err := io.WriteString(w, format(word)); err != nil {
			return err
		}
	}
	if _, err := io.WriteString(w, "}"); err != nil {
		return err
	}
	return nil
}

func writeBNMont(w io.Writer, curve elliptic.Curve, n *big.Int, indent int, bitSizes []uint) error {
	n = toMontgomery(curve, n)
	return writeWords(w, bigIntToU64s(curve, n), 2, indent, func(word uint64) string {
		return fmt.Sprintf("TOBN(0x%08x, 0x%08x)", uint32(word>>32), uint32(word))
	})
}

func writeU64Mont(w io.Writer, curve elliptic.Curve, n *big.Int, indent int, bitSizes []uint) error {
	n = toMontgomery(curve, n)
	return writeWords(w, bigIntToU64s(curve, n), 3, indent, func(word uint64) string {
		return fmt.Sprintf("0x%016x", word)
	})
}

func writeU32Mont(w io.Writer, curve elliptic.Curve, n *big.Int, indent int, bitSizes []uint) error {
	n = toMontgomery(curve, n)
	return writeWords(w, bigIntToU32s(curve, n), 6, indent, func(word uint64) string {
		if word >= 1<<32 {
			panic(fmt.Sprintf("word too large: 0x%x", word))
		}
		return fmt.Sprintf("0x%08x", word)
	})
}

func writeU64(w io.Writer, curve elliptic.Curve, n *big.Int, indent int, bitSizes []uint) error {
	return writeWords(w, bigIntToU64s(curve, n), 3, indent, func(word uint64) string {
		return fmt.Sprintf("0x%016x", word)
	})
}

// This is needed for P-521 Fiat-crypto implementation.
func writeU58(w io.Writer, curve elliptic.Curve, n *big.Int, indent int, bitSizes []uint) error {
	return writeWords(w, bigIntToU58s(curve, n), 3, indent, func(word uint64) string {
		return fmt.Sprintf("0x%016x", word)
	})
}

// Write a big int to an array of digits where each digit
// has bit-size as specified in the input bitSizes array
// This is needed for P-521 Fiat-crypto implementation.
func writeU32Custom(w io.Writer, curve elliptic.Curve, n *big.Int, indent int, bitSizes []uint) error {
	return writeWords(w, bigIntToUCustom(curve, n, bitSizes), 3, indent, func(word uint64) string {
		return fmt.Sprintf("0x%08x", word)
	})
}

func writeU32(w io.Writer, curve elliptic.Curve, n *big.Int, indent int, bitSizes []uint) error {
	return writeWords(w, bigIntToU32s(curve, n), 6, indent, func(word uint64) string {
		if word >= 1<<32 {
			panic(fmt.Sprintf("word too large: 0x%x", word))
		}
		return fmt.Sprintf("0x%08x", word)
	})
}

type writeBigIntFunc func(w io.Writer, curve elliptic.Curve, n *big.Int, indent int, bitSizes []uint) error

func writeTable(w io.Writer, curve elliptic.Curve, table [][2]*big.Int, isRoot bool, indent int, writeBigInt writeBigIntFunc, writeBigIntBitSizes []uint) error {
	if _, err := io.WriteString(w, "{"); err != nil {
		return err
	}
	if isRoot {
		if _, err := io.WriteString(w, "\n"); err != nil {
			return err
		}
		if err := writeIndent(w, indent); err != nil {
			return err
		}
	} else {
		indent++
	}
	for i, point := range table {
		if i != 0 {
			if _, err := io.WriteString(w, ",\n"); err != nil {
				return err
			}
			if err := writeIndent(w, indent); err != nil {
				return err
			}
		}
		if _, err := io.WriteString(w, "{"); err != nil {
			return err
		}
		if err := writeBigInt(w, curve, point[0], indent+1, writeBigIntBitSizes); err != nil {
			return err
		}
		if _, err := io.WriteString(w, ",\n"); err != nil {
			return err
		}
		if err := writeIndent(w, indent+1); err != nil {
			return err
		}
		if err := writeBigInt(w, curve, point[1], indent+1, writeBigIntBitSizes); err != nil {
			return err
		}
		if _, err := io.WriteString(w, "}"); err != nil {
			return err
		}
	}
	if _, err := io.WriteString(w, "}"); err != nil {
		return err
	}
	return nil
}

func writeTables(w io.Writer, curve elliptic.Curve, tables [][][2]*big.Int, isRoot bool, indent int, writeBigInt writeBigIntFunc, writeBigIntBitSizes []uint) error {
	if _, err := io.WriteString(w, "{"); err != nil {
		return err
	}
	if isRoot {
		if _, err := io.WriteString(w, "\n"); err != nil {
			return err
		}
		if err := writeIndent(w, indent); err != nil {
			return err
		}
	} else {
		indent++
	}
	for i, table := range tables {
		if i != 0 {
			if _, err := io.WriteString(w, ",\n"); err != nil {
				return err
			}
			if err := writeIndent(w, indent); err != nil {
				return err
			}
		}
		if err := writeTable(w, curve, table, false, indent, writeBigInt, writeBigIntBitSizes); err != nil {
			return err
		}
	}
	if _, err := io.WriteString(w, "}"); err != nil {
		return err
	}
	return nil
}

