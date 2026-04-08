#! /usr/bin/env perl
# Copyright 2020-2022 The OpenSSL Project Authors. All Rights Reserved.
#
# Written by Xiaokang Qian <xiaokang.qian@arm.com> for the OpenSSL project,
# derived from https://github.com/ARM-software/AArch64cryptolib, original
# author Samuel Lee <Samuel.Lee@arm.com>. 
#
# SPDX-License-Identifier: Apache-2.0


$flavour = shift;
$output  = shift;

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}arm-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../../perlasm/arm-xlate.pl" and -f $xlate) or
die "can't locate arm-xlate.pl";

open OUT,"| \"$^X\" \"$xlate\" $flavour \"$output\"";
*STDOUT=*OUT;

die "only for 64 bit" if $flavour !~ /64/;

$code=<<___;
#include "openssl/arm_arch.h"

#if __ARM_MAX_ARCH__>=8
.text
___
$code.=".arch   armv8.2-a+crypto\n";

$input_ptr="x0";  #argument block
$bit_length="x1";
$byte_length="x9";
$output_ptr="x2";
$current_tag="x3";
$Htable="x6";
$counter="x16";
$constant_temp="x15";
$modulo_constant="x10";
$cc="x11";
{

my ($end_input_ptr,$main_end_input_ptr)=map("x$_",(4..5));
my ($temp0_x,$temp1_x)=map("x$_",(7..8));
my ($temp2_x,$temp3_x)=map("x$_",(13..14));
my ($ctr0b,$ctr1b,$ctr2b,$ctr3b,$ctr4b,$ctr5b,$ctr6b,$ctr7b,$res0b,$res1b,$res2b,$res3b,$res4b,$res5b,$res6b,$res7b)=map("v$_.16b",(0..15));
my ($ctr0,$ctr1,$ctr2,$ctr3,$ctr4,$ctr5,$ctr6,$ctr7,$res0,$res1,$res2,$res3,$res4,$res5,$res6,$res7)=map("v$_",(0..15));
my ($ctr0d,$ctr1d,$ctr2d,$ctr3d,$ctr4d,$ctr5d,$ctr6d,$ctr7d)=map("d$_",(0..7));
my ($ctr0q,$ctr1q,$ctr2q,$ctr3q,$ctr4q,$ctr5q,$ctr6q,$ctr7q)=map("q$_",(0..7));
my ($res0q,$res1q,$res2q,$res3q,$res4q,$res5q,$res6q,$res7q)=map("q$_",(8..15));

my ($ctr_t0,$ctr_t1,$ctr_t2,$ctr_t3,$ctr_t4,$ctr_t5,$ctr_t6,$ctr_t7)=map("v$_",(8..15));
my ($ctr_t0b,$ctr_t1b,$ctr_t2b,$ctr_t3b,$ctr_t4b,$ctr_t5b,$ctr_t6b,$ctr_t7b)=map("v$_.16b",(8..15));
my ($ctr_t0q,$ctr_t1q,$ctr_t2q,$ctr_t3q,$ctr_t4q,$ctr_t5q,$ctr_t6q,$ctr_t7q)=map("q$_",(8..15));

my ($acc_hb,$acc_mb,$acc_lb)=map("v$_.16b",(17..19));
my ($acc_h,$acc_m,$acc_l)=map("v$_",(17..19));

my ($h1,$h12k,$h2,$h3,$h34k,$h4)=map("v$_",(20..25));
my ($h5,$h56k,$h6,$h7,$h78k,$h8)=map("v$_",(20..25));
my ($h1q,$h12kq,$h2q,$h3q,$h34kq,$h4q)=map("q$_",(20..25));
my ($h5q,$h56kq,$h6q,$h7q,$h78kq,$h8q)=map("q$_",(20..25));

my $t0="v16";
my $t0d="d16";

my $t1="v29";
my $t2=$res1;
my $t3=$t1;

my $t4=$res0;
my $t5=$res2;
my $t6=$t0;

my $t7=$res3;
my $t8=$res4;
my $t9=$res5;

my $t10=$res6;
my $t11="v21";
my $t12=$t1;

my $rtmp_ctr="v30";
my $rtmp_ctrq="q30";
my $rctr_inc="v31";
my $rctr_incd="d31";

my $mod_constantd=$t0d;
my $mod_constant=$t0;

my ($rk0,$rk1,$rk2)=map("v$_.16b",(26..28));
my ($rk3,$rk4,$rk5)=map("v$_.16b",(26..28));
my ($rk6,$rk7,$rk8)=map("v$_.16b",(26..28));
my ($rk9,$rk10,$rk11)=map("v$_.16b",(26..28));
my ($rk12,$rk13,$rk14)=map("v$_.16b",(26..28));
my ($rk0q,$rk1q,$rk2q)=map("q$_",(26..28));
my ($rk3q,$rk4q,$rk5q)=map("q$_",(26..28));
my ($rk6q,$rk7q,$rk8q)=map("q$_",(26..28));
my ($rk9q,$rk10q,$rk11q)=map("q$_",(26..28));
my ($rk12q,$rk13q,$rk14q)=map("q$_",(26..28));
my $rk2q1="v28.1q";
my $rk3q1="v26.1q";
my $rk4v="v27";
{
#########################################################################################
# size_t aesv8_gcm_8x_dec_256(const uint8_t *in,
#                             size_t len,
#                             uint8_t *out,
#                             uint64_t *Xi,
#                             uint8_t ivec[16],
#                             const AES_KEY *key,
#                             const void *Htable);
#
$code.=<<___;
.global aesv8_gcm_8x_dec_256
.type   aesv8_gcm_8x_dec_256,%function
.align  4
aesv8_gcm_8x_dec_256:
	AARCH64_VALID_CALL_TARGET
	cbz	x1, .L256_dec_ret
	stp	d8, d9, [sp, #-80]!
	lsr	$byte_length, $bit_length, #3
	mov	$counter, x4
	mov	$cc, x5
	stp	d10, d11, [sp, #16]
	stp	d12, d13, [sp, #32]
	stp	d14, d15, [sp, #48]
	mov	x5, #0xc200000000000000
	stp	x5, xzr, [sp, #64]
	add	$modulo_constant, sp, #64

	ld1	{ $ctr0b}, [$counter]					@ CTR block 0

	mov	$constant_temp, #0x100000000			@ set up counter increment
	movi	$rctr_inc.16b, #0x0
	mov	$rctr_inc.d[1], $constant_temp
	mov	$main_end_input_ptr, $byte_length

	sub	$main_end_input_ptr, $main_end_input_ptr, #1		@ byte_len - 1

	rev32	$rtmp_ctr.16b, $ctr0.16b				@ set up reversed counter

	add	$rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s		@ CTR block 0

	rev32	$ctr1.16b, $rtmp_ctr.16b				@ CTR block 1
	add	$rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s		@ CTR block 1

	rev32	$ctr2.16b, $rtmp_ctr.16b				@ CTR block 2
	add	$rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s		@ CTR block 2
	ldp	$rk0q, $rk1q, [$cc, #0]				  	@ load rk0, rk1

	rev32	$ctr3.16b, $rtmp_ctr.16b				@ CTR block 3
	add	$rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s		@ CTR block 3

	rev32	$ctr4.16b, $rtmp_ctr.16b				@ CTR block 4
	add	$rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s		@ CTR block 4

	aese	$ctr0b, $rk0  \n  aesmc	$ctr0b, $ctr0b			@ AES block 0 - round 0

	rev32	$ctr5.16b, $rtmp_ctr.16b				@ CTR block 5
	add	$rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s		@ CTR block 5

	aese	$ctr1b, $rk0  \n  aesmc	$ctr1b, $ctr1b			@ AES block 1 - round 0
	aese	$ctr2b, $rk0  \n  aesmc	$ctr2b, $ctr2b			@ AES block 2 - round 0

	rev32	$ctr6.16b, $rtmp_ctr.16b				@ CTR block 6
	add	$rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s		@ CTR block 6

	rev32	$ctr7.16b, $rtmp_ctr.16b				@ CTR block 7
	aese	$ctr4b, $rk0  \n  aesmc	$ctr4b, $ctr4b			@ AES block 4 - round 0

	aese	$ctr6b, $rk0  \n  aesmc	$ctr6b, $ctr6b		        @ AES block 6 - round 0
	aese	$ctr5b, $rk0  \n  aesmc	$ctr5b, $ctr5b			@ AES block 5 - round 0

	aese	$ctr3b, $rk0  \n  aesmc	$ctr3b, $ctr3b			@ AES block 3 - round 0
	aese	$ctr7b, $rk0  \n  aesmc	$ctr7b, $ctr7b		        @ AES block 7 - round 0
	ldp	$rk2q, $rk3q, [$cc, #32]				@ load rk2, rk3

	aese	$ctr6b, $rk1  \n  aesmc	$ctr6b, $ctr6b		        @ AES block 6 - round 1
	aese	$ctr4b, $rk1  \n  aesmc	$ctr4b, $ctr4b		        @ AES block 4 - round 1
	aese	$ctr0b, $rk1  \n  aesmc	$ctr0b, $ctr0b		        @ AES block 0 - round 1

	aese	$ctr5b, $rk1  \n  aesmc	$ctr5b, $ctr5b			@ AES block 5 - round 1
	aese	$ctr7b, $rk1  \n  aesmc	$ctr7b, $ctr7b			@ AES block 7 - round 1
	aese	$ctr1b, $rk1  \n  aesmc	$ctr1b, $ctr1b			@ AES block 1 - round 1

	aese	$ctr2b, $rk1  \n  aesmc	$ctr2b, $ctr2b			@ AES block 2 - round 1
	aese	$ctr3b, $rk1  \n  aesmc	$ctr3b, $ctr3b			@ AES block 3 - round 1

	aese	$ctr3b, $rk2  \n  aesmc	$ctr3b, $ctr3b			@ AES block 3 - round 2
	aese	$ctr2b, $rk2  \n  aesmc	$ctr2b, $ctr2b			@ AES block 2 - round 2
	aese	$ctr6b, $rk2  \n  aesmc	$ctr6b, $ctr6b			@ AES block 6 - round 2

	aese	$ctr1b, $rk2  \n  aesmc	$ctr1b, $ctr1b			@ AES block 1 - round 2
	aese	$ctr7b, $rk2  \n  aesmc	$ctr7b, $ctr7b			@ AES block 7 - round 2
	aese	$ctr5b, $rk2  \n  aesmc	$ctr5b, $ctr5b			@ AES block 5 - round 2

	aese	$ctr0b, $rk2  \n  aesmc	$ctr0b, $ctr0b			@ AES block 0 - round 2
	aese	$ctr4b, $rk2  \n  aesmc	$ctr4b, $ctr4b			@ AES block 4 - round 2
	ldp	$rk4q, $rk5q, [$cc, #64]				@ load rk4, rk5

	aese	$ctr1b, $rk3  \n  aesmc	$ctr1b, $ctr1b			@ AES block 1 - round 3
	aese	$ctr2b, $rk3  \n  aesmc	$ctr2b, $ctr2b			@ AES block 2 - round 3

	aese	$ctr3b, $rk3  \n  aesmc	$ctr3b, $ctr3b			@ AES block 3 - round 3
	aese	$ctr4b, $rk3  \n  aesmc	$ctr4b, $ctr4b			@ AES block 4 - round 3

	aese	$ctr5b, $rk3  \n  aesmc	$ctr5b, $ctr5b			@ AES block 5 - round 3
	aese	$ctr7b, $rk3  \n  aesmc	$ctr7b, $ctr7b			@ AES block 7 - round 3
	aese	$ctr0b, $rk3  \n  aesmc	$ctr0b, $ctr0b			@ AES block 0 - round 3

	aese	$ctr6b, $rk3  \n  aesmc	$ctr6b, $ctr6b			@ AES block 6 - round 3

	aese	$ctr7b, $rk4  \n  aesmc	$ctr7b, $ctr7b			@ AES block 7 - round 4
	aese	$ctr3b, $rk4  \n  aesmc	$ctr3b, $ctr3b			@ AES block 3 - round 4

	aese	$ctr6b, $rk4  \n  aesmc	$ctr6b, $ctr6b			@ AES block 6 - round 4
	aese	$ctr2b, $rk4  \n  aesmc	$ctr2b, $ctr2b			@ AES block 2 - round 4
	aese	$ctr0b, $rk4  \n  aesmc	$ctr0b, $ctr0b			@ AES block 0 - round 4

	aese	$ctr4b, $rk4  \n  aesmc	$ctr4b, $ctr4b			@ AES block 4 - round 4
	aese	$ctr1b, $rk4  \n  aesmc	$ctr1b, $ctr1b			@ AES block 1 - round 4
	aese	$ctr5b, $rk4  \n  aesmc	$ctr5b, $ctr5b			@ AES block 5 - round 4

	aese	$ctr0b, $rk5  \n  aesmc	$ctr0b, $ctr0b			@ AES block 0 - round 5
	aese	$ctr6b, $rk5  \n  aesmc	$ctr6b, $ctr6b			@ AES block 6 - round 5

	ldp	$rk6q, $rk7q, [$cc, #96]				@ load rk6, rk7
	aese	$ctr4b, $rk5  \n  aesmc	$ctr4b, $ctr4b			@ AES block 4 - round 5
	aese	$ctr7b, $rk5  \n  aesmc	$ctr7b, $ctr7b			@ AES block 7 - round 5

	aese	$ctr5b, $rk5  \n  aesmc	$ctr5b, $ctr5b			@ AES block 5 - round 5

	aese	$ctr2b, $rk5  \n  aesmc	$ctr2b, $ctr2b			@ AES block 2 - round 5
	aese	$ctr3b, $rk5  \n  aesmc	$ctr3b, $ctr3b			@ AES block 3 - round 5

	aese	$ctr1b, $rk5  \n  aesmc	$ctr1b, $ctr1b			@ AES block 1 - round 5

	aese	$ctr4b, $rk6  \n  aesmc	$ctr4b, $ctr4b			@ AES block 4 - round 6
	aese	$ctr3b, $rk6  \n  aesmc	$ctr3b, $ctr3b			@ AES block 3 - round 6
	aese	$ctr7b, $rk6  \n  aesmc	$ctr7b, $ctr7b			@ AES block 7 - round 6

	aese	$ctr6b, $rk6  \n  aesmc	$ctr6b, $ctr6b			@ AES block 6 - round 6
	aese	$ctr0b, $rk6  \n  aesmc	$ctr0b, $ctr0b			@ AES block 0 - round 6
	aese	$ctr5b, $rk6  \n  aesmc	$ctr5b, $ctr5b			@ AES block 5 - round 6

	aese	$ctr2b, $rk6  \n  aesmc	$ctr2b, $ctr2b			@ AES block 2 - round 6
	aese	$ctr1b, $rk6  \n  aesmc	$ctr1b, $ctr1b			@ AES block 1 - round 6
	ldp	$rk8q, $rk9q, [$cc, #128]				@ load rk8, rk9

	aese	$ctr5b, $rk7  \n  aesmc	$ctr5b, $ctr5b			@ AES block 5 - round 7
	aese	$ctr0b, $rk7  \n  aesmc	$ctr0b, $ctr0b			@ AES block 0 - round 7

	aese	$ctr3b, $rk7  \n  aesmc	$ctr3b, $ctr3b			@ AES block 3 - round 7
	aese	$ctr2b, $rk7  \n  aesmc	$ctr2b, $ctr2b			@ AES block 2 - round 7
	aese	$ctr7b, $rk7  \n  aesmc	$ctr7b, $ctr7b			@ AES block 7 - round 7

	aese	$ctr4b, $rk7  \n  aesmc	$ctr4b, $ctr4b			@ AES block 4 - round 7
	aese	$ctr1b, $rk7  \n  aesmc	$ctr1b, $ctr1b			@ AES block 1 - round 7
	aese	$ctr6b, $rk7  \n  aesmc	$ctr6b, $ctr6b			@ AES block 6 - round 7

	and	$main_end_input_ptr, $main_end_input_ptr, #0xffffffffffffff80 @ number of bytes to be processed in main loop (at least 1 byte must be handled by tail)
	aese	$ctr7b, $rk8  \n  aesmc	$ctr7b, $ctr7b			@ AES block 7 - round 8
	aese	$ctr5b, $rk8  \n  aesmc	$ctr5b, $ctr5b			@ AES block 5 - round 8

	aese	$ctr0b, $rk8  \n  aesmc	$ctr0b, $ctr0b			@ AES block 0 - round 8
	aese	$ctr1b, $rk8  \n  aesmc	$ctr1b, $ctr1b			@ AES block 1 - round 8
	aese	$ctr2b, $rk8  \n  aesmc	$ctr2b, $ctr2b			@ AES block 2 - round 8

	aese	$ctr4b, $rk8  \n  aesmc	$ctr4b, $ctr4b			@ AES block 4 - round 8
	aese	$ctr3b, $rk8  \n  aesmc	$ctr3b, $ctr3b			@ AES block 3 - round 8
	aese	$ctr6b, $rk8  \n  aesmc	$ctr6b, $ctr6b			@ AES block 6 - round 8

	aese	$ctr2b, $rk9  \n  aesmc	$ctr2b, $ctr2b			@ AES block 2 - round 9

	ld1	{ $acc_lb}, [$current_tag]
	ext	$acc_lb, $acc_lb, $acc_lb, #8
	rev64	$acc_lb, $acc_lb
	ldp	$rk10q, $rk11q, [$cc, #160]				@ load rk10, rk11
	add	$end_input_ptr, $input_ptr, $bit_length, lsr #3 @ end_input_ptr
	add	$main_end_input_ptr, $main_end_input_ptr, $input_ptr

	aese	$ctr3b, $rk9  \n  aesmc	$ctr3b, $ctr3b			@ AES block 3 - round 9
	aese	$ctr6b, $rk9  \n  aesmc	$ctr6b, $ctr6b			@ AES block 6 - round 9

	aese	$ctr4b, $rk9  \n  aesmc	$ctr4b, $ctr4b			@ AES block 4 - round 9
	aese	$ctr5b, $rk9  \n  aesmc	$ctr5b, $ctr5b			@ AES block 5 - round 9

	aese	$ctr7b, $rk9  \n  aesmc	$ctr7b, $ctr7b			@ AES block 7 - round 9

	aese	$ctr0b, $rk9  \n  aesmc	$ctr0b, $ctr0b			@ AES block 0 - round 9
	aese	$ctr1b, $rk9  \n  aesmc	$ctr1b, $ctr1b			@ AES block 1 - round 9

	aese	$ctr4b, $rk10 \n  aesmc	$ctr4b, $ctr4b			@ AES block 4 - round 10
	aese	$ctr7b, $rk10 \n  aesmc	$ctr7b, $ctr7b			@ AES block 7 - round 10
	aese	$ctr5b, $rk10 \n  aesmc	$ctr5b, $ctr5b			@ AES block 5 - round 10

	aese	$ctr1b, $rk10 \n  aesmc	$ctr1b, $ctr1b			@ AES block 1 - round 10
	aese	$ctr2b, $rk10 \n  aesmc	$ctr2b, $ctr2b			@ AES block 2 - round 10
	aese	$ctr0b, $rk10 \n  aesmc	$ctr0b, $ctr0b			@ AES block 0 - round 10

	aese	$ctr6b, $rk10 \n  aesmc	$ctr6b, $ctr6b			@ AES block 6 - round 10
	aese	$ctr3b, $rk10 \n  aesmc	$ctr3b, $ctr3b			@ AES block 3 - round 10
	ldp	$rk12q, $rk13q, [$cc, #192]				@ load rk12, rk13

	aese	$ctr0b, $rk11 \n  aesmc	$ctr0b, $ctr0b			@ AES block 0 - round 11
	add	$rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s @ CTR block 7

	aese	$ctr7b, $rk11 \n  aesmc	$ctr7b, $ctr7b			@ AES block 7 - round 11
	aese	$ctr3b, $rk11 \n  aesmc	$ctr3b, $ctr3b			@ AES block 3 - round 11
	aese	$ctr1b, $rk11 \n  aesmc	$ctr1b, $ctr1b			@ AES block 1 - round 11

	aese	$ctr5b, $rk11 \n  aesmc	$ctr5b, $ctr5b			@ AES block 5 - round 11
	aese	$ctr4b, $rk11 \n  aesmc	$ctr4b, $ctr4b			@ AES block 4 - round 11
	aese	$ctr2b, $rk11 \n  aesmc	$ctr2b, $ctr2b			@ AES block 2 - round 11

	aese	$ctr6b, $rk11 \n  aesmc	$ctr6b, $ctr6b			@ AES block 6 - round 11
	ldr	$rk14q, [$cc, #224]					@ load rk14

	aese	$ctr1b, $rk12 \n  aesmc	$ctr1b, $ctr1b			@ AES block 1 - round 12
	aese	$ctr4b, $rk12 \n  aesmc	$ctr4b, $ctr4b			@ AES block 4 - round 12
	aese	$ctr5b, $rk12 \n  aesmc	$ctr5b, $ctr5b			@ AES block 5 - round 12

	cmp	$input_ptr, $main_end_input_ptr				@ check if we have <= 8 blocks
	aese	$ctr3b, $rk12 \n  aesmc	$ctr3b, $ctr3b			@ AES block 3 - round 12
	aese	$ctr2b, $rk12 \n  aesmc	$ctr2b, $ctr2b			@ AES block 2 - round 12

	aese	$ctr6b, $rk12 \n  aesmc	$ctr6b, $ctr6b			@ AES block 6 - round 12
	aese	$ctr0b, $rk12 \n  aesmc	$ctr0b, $ctr0b			@ AES block 0 - round 12
	aese	$ctr7b, $rk12 \n  aesmc	$ctr7b, $ctr7b			@ AES block 7 - round 12

	aese	$ctr5b, $rk13						@ AES block 5 - round 13
	aese	$ctr1b, $rk13						@ AES block 1 - round 13
	aese	$ctr2b, $rk13						@ AES block 2 - round 13

	aese	$ctr0b, $rk13						@ AES block 0 - round 13
	aese	$ctr4b, $rk13						@ AES block 4 - round 13
	aese	$ctr6b, $rk13						@ AES block 6 - round 13

	aese	$ctr3b, $rk13						@ AES block 3 - round 13
	aese	$ctr7b, $rk13						@ AES block 7 - round 13
	b.ge	.L256_dec_tail						@ handle tail

	ldp	$res0q, $res1q, [$input_ptr], #32			@ AES block 0, 1 - load ciphertext

	ldp	$res2q, $res3q, [$input_ptr], #32			@ AES block 2, 3 - load ciphertext

	ldp	$res4q, $res5q, [$input_ptr], #32			@ AES block 4, 5 - load ciphertext

	ldp	$res6q, $res7q, [$input_ptr], #32			@ AES block 6, 7 - load ciphertext
	cmp	$input_ptr, $main_end_input_ptr				@ check if we have <= 8 blocks

	eor3	$ctr1b, $res1b, $ctr1b, $rk14				@ AES block 1 - result
	eor3	$ctr0b, $res0b, $ctr0b, $rk14				@ AES block 0 - result
	stp	$ctr0q, $ctr1q, [$output_ptr], #32			@ AES block 0, 1 - store result

	rev32	$ctr0.16b, $rtmp_ctr.16b				@ CTR block 8
	add	$rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s		@ CTR block 8
	eor3	$ctr3b, $res3b, $ctr3b, $rk14				@ AES block 3 - result

	eor3	$ctr5b, $res5b, $ctr5b, $rk14				@ AES block 5 - result

	eor3	$ctr4b, $res4b, $ctr4b, $rk14				@ AES block 4 - result
	rev32	$ctr1.16b, $rtmp_ctr.16b				@ CTR block 9
	add	$rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s		@ CTR block 9

	eor3	$ctr2b, $res2b, $ctr2b, $rk14				@ AES block 2 - result
	stp	$ctr2q, $ctr3q, [$output_ptr], #32			@ AES block 2, 3 - store result

	rev32	$ctr2.16b, $rtmp_ctr.16b				@ CTR block 10
	add	$rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s		@ CTR block 10

	eor3	$ctr6b, $res6b, $ctr6b, $rk14				@ AES block 6 - result

	rev32	$ctr3.16b, $rtmp_ctr.16b				@ CTR block 11
	add	$rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s		@ CTR block 11
	stp	$ctr4q, $ctr5q, [$output_ptr], #32			@ AES block 4, 5 - store result

	eor3	$ctr7b, $res7b, $ctr7b, $rk14				@ AES block 7 - result
	stp	$ctr6q, $ctr7q, [$output_ptr], #32			@ AES block 6, 7 - store result

	rev32	$ctr4.16b, $rtmp_ctr.16b				@ CTR block 12
	add	$rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s		@ CTR block 12
	b.ge	.L256_dec_prepretail					@ do prepretail

.L256_dec_main_loop:							@ main loop start
	rev32	$ctr5.16b, $rtmp_ctr.16b				@ CTR block 8k+13
	ldp	$rk0q, $rk1q, [$cc, #0]					@ load rk0, rk1
	add	$rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s		@ CTR block 8k+13

	rev64	$res1b, $res1b						@ GHASH block 8k+1
	ldr	$h7q, [$Htable, #144]				@ load h7l | h7h
	ldr	$h8q, [$Htable, #176]				@ load h8l | h8h

	rev32	$ctr6.16b, $rtmp_ctr.16b				@ CTR block 8k+14
	add	$rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s		@ CTR block 8k+14
	rev64	$res0b, $res0b						@ GHASH block 8k

	ext	$acc_lb, $acc_lb, $acc_lb, #8				@ PRE 0
	rev64	$res4b, $res4b						@ GHASH block 8k+4
	rev64	$res3b, $res3b						@ GHASH block 8k+3

	rev32	$ctr7.16b, $rtmp_ctr.16b				@ CTR block 8k+15
	rev64	$res7b, $res7b						@ GHASH block 8k+7

	aese	$ctr3b, $rk0  \n  aesmc	$ctr3b, $ctr3b			@ AES block 8k+11 - round 0
	aese	$ctr6b, $rk0  \n  aesmc	$ctr6b, $ctr6b			@ AES block 8k+14 - round 0
	aese	$ctr2b, $rk0  \n  aesmc	$ctr2b, $ctr2b			@ AES block 8k+10 - round 0

	aese	$ctr7b, $rk0  \n  aesmc	$ctr7b, $ctr7b			@ AES block 8k+15 - round 0
	aese	$ctr0b, $rk0  \n  aesmc	$ctr0b, $ctr0b			@ AES block 8k+8 - round 0
	aese	$ctr5b, $rk0  \n  aesmc	$ctr5b, $ctr5b			@ AES block 8k+13 - round 0

	aese	$ctr4b, $rk0  \n  aesmc	$ctr4b, $ctr4b			@ AES block 8k+12 - round 0
	aese	$ctr1b, $rk0  \n  aesmc	$ctr1b, $ctr1b			@ AES block 8k+9 - round 0
	ldp	$rk2q, $rk3q, [$cc, #32]				@ load rk2, rk3

	eor	$res0b, $res0b, $acc_lb					@ PRE 1
	ldr	$h5q, [$Htable, #96]				@ load h5l | h5h
	ldr	$h6q, [$Htable, #128]				@ load h6l | h6h
	aese	$ctr6b, $rk1  \n  aesmc	$ctr6b, $ctr6b			@ AES block 8k+14 - round 1

	aese	$ctr4b, $rk1  \n  aesmc	$ctr4b, $ctr4b			@ AES block 8k+12 - round 1
	rev64	$res2b, $res2b						@ GHASH block 8k+2
	aese	$ctr3b, $rk1  \n  aesmc	$ctr3b, $ctr3b			@ AES block 8k+11 - round 1

	aese	$ctr0b, $rk1  \n  aesmc	$ctr0b, $ctr0b			@ AES block 8k+8 - round 1
	aese	$ctr5b, $rk1  \n  aesmc	$ctr5b, $ctr5b			@ AES block 8k+13 - round 1
	aese	$ctr2b, $rk1  \n  aesmc	$ctr2b, $ctr2b			@ AES block 8k+10 - round 1

	trn1	$acc_m.2d, $res1.2d, $res0.2d				@ GHASH block 8k, 8k+1 - mid
	aese	$ctr7b, $rk1  \n  aesmc	$ctr7b, $ctr7b			@ AES block 8k+15 - round 1
	aese	$ctr1b, $rk1  \n  aesmc	$ctr1b, $ctr1b			@ AES block 8k+9 - round 1

	aese	$ctr4b, $rk2  \n  aesmc	$ctr4b, $ctr4b			@ AES block 8k+12 - round 2
	aese	$ctr0b, $rk2  \n  aesmc	$ctr0b, $ctr0b			@ AES block 8k+8 - round 2
	aese	$ctr3b, $rk2  \n  aesmc	$ctr3b, $ctr3b			@ AES block 8k+11 - round 2

	aese	$ctr6b, $rk2  \n  aesmc	$ctr6b, $ctr6b			@ AES block 8k+14 - round 2
	aese	$ctr7b, $rk2  \n  aesmc	$ctr7b, $ctr7b			@ AES block 8k+15 - round 2
	pmull	$acc_l.1q, $res0.1d, $h8.1d				@ GHASH block 8k - low

	aese	$ctr5b, $rk2  \n  aesmc	$ctr5b, $ctr5b			@ AES block 8k+13 - round 2
	aese	$ctr2b, $rk2  \n  aesmc	$ctr2b, $ctr2b			@ AES block 8k+10 - round 2
	aese	$ctr1b, $rk2  \n  aesmc	$ctr1b, $ctr1b			@ AES block 8k+9 - round 2

	ldp	$rk4q, $rk5q, [$cc, #64]				@ load rk4, rk5
	pmull2  $t1.1q, $res2.2d, $h6.2d				@ GHASH block 8k+2 - high
	aese	$ctr3b, $rk3  \n  aesmc	$ctr3b, $ctr3b			@ AES block 8k+11 - round 3

	aese	$ctr0b, $rk3  \n  aesmc	$ctr0b, $ctr0b			@ AES block 8k+8 - round 3
	pmull2  $t0.1q, $res1.2d, $h7.2d				@ GHASH block 8k+1 - high
	pmull	$h7.1q, $res1.1d, $h7.1d				@ GHASH block 8k+1 - low

	aese	$ctr5b, $rk3  \n  aesmc	$ctr5b, $ctr5b			@ AES block 8k+13 - round 3
	aese	$ctr6b, $rk3  \n  aesmc	$ctr6b, $ctr6b			@ AES block 8k+14 - round 3
	pmull2  $acc_h.1q, $res0.2d, $h8.2d				@ GHASH block 8k - high

	aese	$ctr4b, $rk3  \n  aesmc	$ctr4b, $ctr4b			@ AES block 8k+12 - round 3
	aese	$ctr1b, $rk3  \n  aesmc	$ctr1b, $ctr1b			@ AES block 8k+9 - round 3
	trn2	$res0.2d, $res1.2d, $res0.2d				@ GHASH block 8k, 8k+1 - mid

	pmull2  $t2.1q, $res3.2d, $h5.2d				@ GHASH block 8k+3 - high
	aese	$ctr2b, $rk3  \n  aesmc	$ctr2b, $ctr2b			@ AES block 8k+10 - round 3
	eor	$acc_hb, $acc_hb, $t0.16b				@ GHASH block 8k+1 - high

	aese	$ctr5b, $rk4  \n  aesmc	$ctr5b, $ctr5b			@ AES block 8k+13 - round 4
	aese	$ctr7b, $rk3  \n  aesmc	$ctr7b, $ctr7b			@ AES block 8k+15 - round 3
	aese	$ctr3b, $rk4  \n  aesmc	$ctr3b, $ctr3b			@ AES block 8k+11 - round 4

	aese	$ctr2b, $rk4  \n  aesmc	$ctr2b, $ctr2b			@ AES block 8k+10 - round 4
	aese	$ctr0b, $rk4  \n  aesmc	$ctr0b, $ctr0b			@ AES block 8k+8 - round 4
	aese	$ctr1b, $rk4  \n  aesmc	$ctr1b, $ctr1b			@ AES block 8k+9 - round 4

	aese	$ctr6b, $rk4  \n  aesmc	$ctr6b, $ctr6b			@ AES block 8k+14 - round 4
	aese	$ctr7b, $rk4  \n  aesmc	$ctr7b, $ctr7b			@ AES block 8k+15 - round 4
	aese	$ctr4b, $rk4  \n  aesmc	$ctr4b, $ctr4b			@ AES block 8k+12 - round 4

	ldr	$h56kq, [$Htable, #112]				@ load h6k | h5k
	ldr	$h78kq, [$Htable, #160]				@ load h8k | h7k
	eor	$res0.16b, $res0.16b, $acc_m.16b			@ GHASH block 8k, 8k+1 - mid
	pmull	$h6.1q, $res2.1d, $h6.1d				@ GHASH block 8k+2 - low

	ldp	$rk6q, $rk7q, [$cc, #96]				@ load rk6, rk7
	aese	$ctr5b, $rk5  \n  aesmc	$ctr5b, $ctr5b			@ AES block 8k+13 - round 5
	eor	$acc_lb, $acc_lb, $h7.16b				@ GHASH block 8k+1 - low

	aese	$ctr0b, $rk5  \n  aesmc	$ctr0b, $ctr0b			@ AES block 8k+8 - round 5
	aese	$ctr3b, $rk5  \n  aesmc	$ctr3b, $ctr3b			@ AES block 8k+11 - round 5
	aese	$ctr7b, $rk5  \n  aesmc	$ctr7b, $ctr7b			@ AES block 8k+15 - round 5

	aese	$ctr1b, $rk5  \n  aesmc	$ctr1b, $ctr1b			@ AES block 8k+9 - round 5
	aese	$ctr2b, $rk5  \n  aesmc	$ctr2b, $ctr2b			@ AES block 8k+10 - round 5
	aese	$ctr6b, $rk5  \n  aesmc	$ctr6b, $ctr6b			@ AES block 8k+14 - round 5

	eor3	$acc_hb, $acc_hb, $t1.16b, $t2.16b			@ GHASH block 8k+2, 8k+3 - high
	trn1	$t3.2d, $res3.2d, $res2.2d				@ GHASH block 8k+2, 8k+3 - mid
	rev64	$res5b, $res5b						@ GHASH block 8k+5

	pmull2  $acc_m.1q, $res0.2d, $h78k.2d				@ GHASH block 8k	- mid
	pmull	$h78k.1q, $res0.1d, $h78k.1d				@ GHASH block 8k+1 - mid
	trn2	$res2.2d, $res3.2d, $res2.2d				@ GHASH block 8k+2, 8k+3 - mid

	aese	$ctr3b, $rk6  \n  aesmc	$ctr3b, $ctr3b			@ AES block 8k+11 - round 6
	aese	$ctr0b, $rk6  \n  aesmc	$ctr0b, $ctr0b			@ AES block 8k+8 - round 6
	aese	$ctr4b, $rk5  \n  aesmc	$ctr4b, $ctr4b			@ AES block 8k+12 - round 5

	trn1	$t6.2d, $res5.2d, $res4.2d				@ GHASH block 8k+4, 8k+5 - mid
	aese	$ctr1b, $rk6  \n  aesmc	$ctr1b, $ctr1b			@ AES block 8k+9 - round 6
	aese	$ctr6b, $rk6  \n  aesmc	$ctr6b, $ctr6b			@ AES block 8k+14 - round 6

	eor	$res2.16b, $res2.16b, $t3.16b				@ GHASH block 8k+2, 8k+3 - mid
	pmull	$h5.1q, $res3.1d, $h5.1d				@ GHASH block 8k+3 - low
	aese	$ctr4b, $rk6  \n  aesmc	$ctr4b, $ctr4b			@ AES block 8k+12 - round 6

	aese	$ctr2b, $rk6  \n  aesmc	$ctr2b, $ctr2b			@ AES block 8k+10 - round 6
	aese	$ctr5b, $rk6  \n  aesmc	$ctr5b, $ctr5b			@ AES block 8k+13 - round 6
	aese	$ctr7b, $rk6  \n  aesmc	$ctr7b, $ctr7b			@ AES block 8k+15 - round 6

	pmull2  $t3.1q, $res2.2d, $h56k.2d				@ GHASH block 8k+2 - mid
	pmull	$h56k.1q, $res2.1d, $h56k.1d				@ GHASH block 8k+3 - mid
	eor3	$acc_lb, $acc_lb, $h6.16b, $h5.16b			@ GHASH block 8k+2, 8k+3 - low

	ldr	$h3q, [$Htable, #48]				@ load h3l | h3h
	ldr	$h4q, [$Htable, #80]				@ load h4l | h4h
	rev64	$res6b, $res6b						@ GHASH block 8k+6
	eor	$acc_mb, $acc_mb, $h78k.16b				@ GHASH block 8k+1 - mid

	aese	$ctr2b, $rk7  \n  aesmc	$ctr2b, $ctr2b			@ AES block 8k+10 - round 7
	aese	$ctr5b, $rk7  \n  aesmc	$ctr5b, $ctr5b			@ AES block 8k+13 - round 7
	ldp	$rk8q, $rk9q, [$cc, #128]				@ load rk8, rk9

	ldr	$h1q, [$Htable]				@ load h1l | h1h
	ldr	$h2q, [$Htable, #32]				@ load h2l | h2h
	eor3	$acc_mb, $acc_mb, $h56k.16b, $t3.16b			@ GHASH block 8k+2, 8k+3 - mid
	aese	$ctr7b, $rk7  \n  aesmc	$ctr7b, $ctr7b			@ AES block 8k+15 - round 7

	aese	$ctr1b, $rk7  \n  aesmc	$ctr1b, $ctr1b			@ AES block 8k+9 - round 7
	aese	$ctr3b, $rk7  \n  aesmc	$ctr3b, $ctr3b			@ AES block 8k+11 - round 7
	aese	$ctr6b, $rk7  \n  aesmc	$ctr6b, $ctr6b			@ AES block 8k+14 - round 7

	ldr	$h12kq, [$Htable, #16]				@ load h2k | h1k
	ldr	$h34kq, [$Htable, #64]				@ load h4k | h3k
	aese	$ctr0b, $rk7  \n  aesmc	$ctr0b, $ctr0b			@ AES block 8k+8 - round 7
	aese	$ctr4b, $rk7  \n  aesmc	$ctr4b, $ctr4b			@ AES block 8k+12 - round 7

	pmull2  $t4.1q, $res4.2d, $h4.2d				@ GHASH block 8k+4 - high
	pmull	$h4.1q, $res4.1d, $h4.1d				@ GHASH block 8k+4 - low
	trn2	$res4.2d, $res5.2d, $res4.2d				@ GHASH block 8k+4, 8k+5 - mid

	aese	$ctr5b, $rk8  \n  aesmc	$ctr5b, $ctr5b			@ AES block 8k+13 - round 8
	pmull2  $t5.1q, $res5.2d, $h3.2d				@ GHASH block 8k+5 - high
	aese	$ctr2b, $rk8  \n  aesmc	$ctr2b, $ctr2b			@ AES block 8k+10 - round 8

	aese	$ctr6b, $rk8  \n  aesmc	$ctr6b, $ctr6b			@ AES block 8k+14 - round 8
	pmull	$h3.1q, $res5.1d, $h3.1d				@ GHASH block 8k+5 - low
	aese	$ctr1b, $rk8  \n  aesmc	$ctr1b, $ctr1b			@ AES block 8k+9 - round 8

	aese	$ctr4b, $rk8  \n  aesmc	$ctr4b, $ctr4b			@ AES block 8k+12 - round 8
	aese	$ctr0b, $rk8  \n  aesmc	$ctr0b, $ctr0b			@ AES block 8k+8 - round 8
	pmull2  $t7.1q, $res6.2d, $h2.2d				@ GHASH block 8k+6 - high

	trn1	$t9.2d, $res7.2d, $res6.2d				@ GHASH block 8k+6, 8k+7 - mid
	aese	$ctr3b, $rk8  \n  aesmc	$ctr3b, $ctr3b			@ AES block 8k+11 - round 8
	aese	$ctr7b, $rk8  \n  aesmc	$ctr7b, $ctr7b			@ AES block 8k+15 - round 8

	ldp	$rk10q, $rk11q, [$cc, #160]				@ load rk10, rk11
	pmull	$h2.1q, $res6.1d, $h2.1d				@ GHASH block 8k+6 - low
	trn2	$res6.2d, $res7.2d, $res6.2d				@ GHASH block 8k+6, 8k+7 - mid

	add	$rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s		@ CTR block 8k+15
	eor3	$acc_hb, $acc_hb, $t4.16b, $t5.16b			@ GHASH block 8k+4, 8k+5 - high
	aese	$ctr3b, $rk9  \n  aesmc	$ctr3b, $ctr3b			@ AES block 8k+11 - round 9

	aese	$ctr6b, $rk9  \n  aesmc	$ctr6b, $ctr6b			@ AES block 8k+14 - round 9
	eor	$res6.16b, $res6.16b, $t9.16b				@ GHASH block 8k+6, 8k+7 - mid
	aese	$ctr5b, $rk9  \n  aesmc	$ctr5b, $ctr5b			@ AES block 8k+13 - round 9

	ldp	$res0q, $res1q, [$input_ptr], #32			@ AES block 8k+8, 8k+9 - load ciphertext
	eor	$res4.16b, $res4.16b, $t6.16b				@ GHASH block 8k+4, 8k+5 - mid
	aese	$ctr7b, $rk9  \n  aesmc	$ctr7b, $ctr7b			@ AES block 8k+15 - round 9

	pmull2  $t9.1q, $res6.2d, $h12k.2d				@ GHASH block 8k+6 - mid
	aese	$ctr2b, $rk9  \n  aesmc	$ctr2b, $ctr2b			@ AES block 8k+10 - round 9
	aese	$ctr1b, $rk9  \n  aesmc	$ctr1b, $ctr1b			@ AES block 8k+9 - round 9

	pmull2  $t6.1q, $res4.2d, $h34k.2d				@ GHASH block 8k+4 - mid
	pmull	$h34k.1q, $res4.1d, $h34k.1d				@ GHASH block 8k+5 - mid
	pmull2  $t8.1q, $res7.2d, $h1.2d				@ GHASH block 8k+7 - high

	pmull	$h1.1q, $res7.1d, $h1.1d				@ GHASH block 8k+7 - low
	aese	$ctr3b, $rk10 \n  aesmc	$ctr3b, $ctr3b			@ AES block 8k+11 - round 10
	aese	$ctr6b, $rk10 \n  aesmc	$ctr6b, $ctr6b			@ AES block 8k+14 - round 10

	pmull	$h12k.1q, $res6.1d, $h12k.1d				@ GHASH block 8k+7 - mid
	aese	$ctr0b, $rk9  \n  aesmc	$ctr0b, $ctr0b			@ AES block 8k+8 - round 9
	eor3	$acc_lb, $acc_lb, $h4.16b, $h3.16b			@ GHASH block 8k+4, 8k+5 - low

	aese	$ctr4b, $rk9  \n  aesmc	$ctr4b, $ctr4b			@ AES block 8k+12 - round 9
	eor3	$acc_mb, $acc_mb, $h34k.16b, $t6.16b			@ GHASH block 8k+4, 8k+5 - mid
	eor3	$acc_hb, $acc_hb, $t7.16b, $t8.16b			@ GHASH block 8k+6, 8k+7 - high

	aese	$ctr2b, $rk10 \n  aesmc	$ctr2b, $ctr2b			@ AES block 8k+10 - round 10
	aese	$ctr5b, $rk10 \n  aesmc	$ctr5b, $ctr5b			@ AES block 8k+13 - round 10
	aese	$ctr7b, $rk10 \n  aesmc	$ctr7b, $ctr7b			@ AES block 8k+15 - round 10

	aese	$ctr1b, $rk10 \n  aesmc	$ctr1b, $ctr1b			@ AES block 8k+9 - round 10
	aese	$ctr0b, $rk10 \n  aesmc	$ctr0b, $ctr0b			@ AES block 8k+8 - round 10
	aese	$ctr4b, $rk10 \n  aesmc	$ctr4b, $ctr4b			@ AES block 8k+12 - round 10

	eor3	$acc_lb, $acc_lb, $h2.16b, $h1.16b			@ GHASH block 8k+6, 8k+7 - low
	rev32	$h1.16b, $rtmp_ctr.16b					@ CTR block 8k+16
	ldr	$mod_constantd, [$modulo_constant]			@ MODULO - load modulo constant

	add	$rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s		@ CTR block 8k+16
	aese	$ctr1b, $rk11 \n  aesmc	$ctr1b, $ctr1b			@ AES block 8k+9 - round 11
	ldp	$rk12q, $rk13q, [$cc, #192]				@ load rk12, rk13

	aese	$ctr0b, $rk11 \n  aesmc	$ctr0b, $ctr0b			@ AES block 8k+8 - round 11
	aese	$ctr6b, $rk11 \n  aesmc	$ctr6b, $ctr6b			@ AES block 8k+14 - round 11

	eor3	$acc_mb, $acc_mb, $h12k.16b, $t9.16b			@ GHASH block 8k+6, 8k+7 - mid
	rev32	$h2.16b, $rtmp_ctr.16b					@ CTR block 8k+17
	aese	$ctr2b, $rk11 \n  aesmc	$ctr2b, $ctr2b			@ AES block 8k+10 - round 11

	ldp	$res2q, $res3q, [$input_ptr], #32			@ AES block 8k+10, 8k+11 - load ciphertext
	aese	$ctr7b, $rk11 \n  aesmc	$ctr7b, $ctr7b			@ AES block 8k+15 - round 11
	ext	$t11.16b, $acc_hb, $acc_hb, #8				 @ MODULO - other top alignment

	aese	$ctr5b, $rk11 \n  aesmc	$ctr5b, $ctr5b			@ AES block 8k+13 - round 11
	add	$rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s		@ CTR block 8k+17
	aese	$ctr3b, $rk11 \n  aesmc	$ctr3b, $ctr3b			@ AES block 8k+11 - round 11

	aese	$ctr2b, $rk12 \n  aesmc	$ctr2b, $ctr2b			@ AES block 8k+10 - round 12
	aese	$ctr7b, $rk12 \n  aesmc	$ctr7b, $ctr7b			@ AES block 8k+15 - round 12
	aese	$ctr6b, $rk12 \n  aesmc	$ctr6b, $ctr6b			@ AES block 8k+14 - round 12

	rev32	$h3.16b, $rtmp_ctr.16b					@ CTR block 8k+18
	add	$rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s		@ CTR block 8k+18
	pmull	$t12.1q, $acc_h.1d, $mod_constant.1d			@ MODULO - top 64b align with mid

	eor3	$acc_mb, $acc_mb, $acc_hb, $acc_lb		 	@ MODULO - karatsuba tidy up
	aese	$ctr1b, $rk12 \n  aesmc	$ctr1b, $ctr1b			@ AES block 8k+9 - round 12
	aese	$ctr4b, $rk11 \n  aesmc	$ctr4b, $ctr4b			@ AES block 8k+12 - round 11

	ldr	$rk14q, [$cc, #224]					@ load rk14
	aese	$ctr5b, $rk12 \n  aesmc	$ctr5b, $ctr5b			@ AES block 8k+13 - round 12
	aese	$ctr3b, $rk12 \n  aesmc	$ctr3b, $ctr3b			@ AES block 8k+11 - round 12

	eor3	$acc_mb, $acc_mb, $t12.16b, $t11.16b			@ MODULO - fold into mid
	aese	$ctr0b, $rk12 \n  aesmc	$ctr0b, $ctr0b			@ AES block 8k+8 - round 12
	aese	$ctr4b, $rk12 \n  aesmc	$ctr4b, $ctr4b			@ AES block 8k+12 - round 12

	ldp	$res4q, $res5q, [$input_ptr], #32			@ AES block 8k+12, 8k+13 - load ciphertext
	aese	$ctr1b, $rk13						@ AES block 8k+9 - round 13
	aese	$ctr2b, $rk13						@ AES block 8k+10 - round 13

	ldp	$res6q, $res7q, [$input_ptr], #32			@ AES block 8k+14, 8k+15 - load ciphertext
	aese	$ctr0b, $rk13						@ AES block 8k+8 - round 13
	aese	$ctr5b, $rk13						@ AES block 8k+13 - round 13

	rev32	$h4.16b, $rtmp_ctr.16b					@ CTR block 8k+19
	eor3	$ctr2b, $res2b, $ctr2b, $rk14				@ AES block 8k+10 - result
	eor3	$ctr1b, $res1b, $ctr1b, $rk14				@ AES block 8k+9 - result

	ext	$t11.16b, $acc_mb, $acc_mb, #8				@ MODULO - other mid alignment
	aese	$ctr7b, $rk13						@ AES block 8k+15 - round 13

	add	$rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s		@ CTR block 8k+19
	pmull	$acc_h.1q, $acc_m.1d, $mod_constant.1d			@ MODULO - mid 64b align with low
	aese	$ctr4b, $rk13						@ AES block 8k+12 - round 13

	eor3	$ctr5b, $res5b, $ctr5b, $rk14				@ AES block 8k+13 - result
	eor3	$ctr0b, $res0b, $ctr0b, $rk14				@ AES block 8k+8 - result
	aese	$ctr3b, $rk13						@ AES block 8k+11 - round 13

	stp	$ctr0q, $ctr1q, [$output_ptr], #32			@ AES block 8k+8, 8k+9 - store result
	mov	$ctr0.16b, $h1.16b					@ CTR block 8k+16
	eor3	$ctr4b, $res4b, $ctr4b, $rk14				@ AES block 8k+12 - result

	eor3	$acc_lb, $acc_lb, $t11.16b, $acc_hb		 	@ MODULO - fold into low
	eor3	$ctr3b, $res3b, $ctr3b, $rk14				@ AES block 8k+11 - result
	stp	$ctr2q, $ctr3q, [$output_ptr], #32			@ AES block 8k+10, 8k+11 - store result

	mov	$ctr3.16b, $h4.16b					@ CTR block 8k+19
	mov	$ctr2.16b, $h3.16b					@ CTR block 8k+18
	aese	$ctr6b, $rk13						@ AES block 8k+14 - round 13

	mov	$ctr1.16b, $h2.16b					@ CTR block 8k+17
	stp	$ctr4q, $ctr5q, [$output_ptr], #32			@ AES block 8k+12, 8k+13 - store result
	eor3	$ctr7b, $res7b, $ctr7b, $rk14				@ AES block 8k+15 - result

	eor3	$ctr6b, $res6b, $ctr6b, $rk14				@ AES block 8k+14 - result
	rev32	$ctr4.16b, $rtmp_ctr.16b				@ CTR block 8k+20
	add	$rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s		@ CTR block 8k+20

	cmp	$input_ptr, $main_end_input_ptr				@ LOOP CONTROL
	stp	$ctr6q, $ctr7q, [$output_ptr], #32			@ AES block 8k+14, 8k+15 - store result
	b.lt	.L256_dec_main_loop

.L256_dec_prepretail:							@ PREPRETAIL
	ldp	$rk0q, $rk1q, [$cc, #0]					@ load rk0, rk1
	rev32	$ctr5.16b, $rtmp_ctr.16b				@ CTR block 8k+13
	add	$rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s		@ CTR block 8k+13

	rev64	$res4b, $res4b						@ GHASH block 8k+4
	ldr	$h56kq, [$Htable, #112]				@ load h6k | h5k
	ldr	$h78kq, [$Htable, #160]				@ load h8k | h7k

	rev32	$ctr6.16b, $rtmp_ctr.16b				@ CTR block 8k+14
	rev64	$res0b, $res0b						@ GHASH block 8k
	add	$rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s		@ CTR block 8k+14

	ext	$acc_lb, $acc_lb, $acc_lb, #8				@ PRE 0
	ldr	$h7q, [$Htable, #144]				@ load h7l | h7h
	ldr	$h8q, [$Htable, #176]				@ load h8l | h8h
	rev64	$res1b, $res1b						@ GHASH block 8k+1

	rev32	$ctr7.16b, $rtmp_ctr.16b				@ CTR block 8k+15
	rev64	$res2b, $res2b						@ GHASH block 8k+2
	ldr	$h5q, [$Htable, #96]				@ load h5l | h5h
	ldr	$h6q, [$Htable, #128]				@ load h6l | h6h

	aese	$ctr0b, $rk0  \n  aesmc	$ctr0b, $ctr0b			@ AES block 8k+8 - round 0
	aese	$ctr1b, $rk0  \n  aesmc	$ctr1b, $ctr1b			@ AES block 8k+9 - round 0
	aese	$ctr4b, $rk0  \n  aesmc	$ctr4b, $ctr4b			@ AES block 8k+12 - round 0

	aese	$ctr3b, $rk0  \n  aesmc	$ctr3b, $ctr3b			@ AES block 8k+11 - round 0
	aese	$ctr5b, $rk0  \n  aesmc	$ctr5b, $ctr5b			@ AES block 8k+13 - round 0
	aese	$ctr6b, $rk0  \n  aesmc	$ctr6b, $ctr6b			@ AES block 8k+14 - round 0

	aese	$ctr4b, $rk1  \n  aesmc	$ctr4b, $ctr4b			@ AES block 8k+12 - round 1
	aese	$ctr7b, $rk0  \n  aesmc	$ctr7b, $ctr7b			@ AES block 8k+15 - round 0
	aese	$ctr2b, $rk0  \n  aesmc	$ctr2b, $ctr2b			@ AES block 8k+10 - round 0

	ldp	$rk2q, $rk3q, [$cc, #32]				@ load rk2, rk3
	aese	$ctr0b, $rk1  \n  aesmc	$ctr0b, $ctr0b			@ AES block 8k+8 - round 1
	eor	$res0b, $res0b, $acc_lb					@ PRE 1

	aese	$ctr7b, $rk1  \n  aesmc	$ctr7b, $ctr7b			@ AES block 8k+15 - round 1
	aese	$ctr6b, $rk1  \n  aesmc	$ctr6b, $ctr6b			@ AES block 8k+14 - round 1
	aese	$ctr2b, $rk1  \n  aesmc	$ctr2b, $ctr2b			@ AES block 8k+10 - round 1

	aese	$ctr3b, $rk1  \n  aesmc	$ctr3b, $ctr3b			@ AES block 8k+11 - round 1
	aese	$ctr1b, $rk1  \n  aesmc	$ctr1b, $ctr1b			@ AES block 8k+9 - round 1
	aese	$ctr5b, $rk1  \n  aesmc	$ctr5b, $ctr5b			@ AES block 8k+13 - round 1

	pmull2  $t0.1q, $res1.2d, $h7.2d				@ GHASH block 8k+1 - high
	trn1	$acc_m.2d, $res1.2d, $res0.2d				@ GHASH block 8k, 8k+1 - mid
	pmull	$acc_l.1q, $res0.1d, $h8.1d				@ GHASH block 8k - low

	rev64	$res3b, $res3b						@ GHASH block 8k+3
	pmull	$h7.1q, $res1.1d, $h7.1d				@ GHASH block 8k+1 - low

	aese	$ctr5b, $rk2  \n  aesmc	$ctr5b, $ctr5b			@ AES block 8k+13 - round 2
	aese	$ctr7b, $rk2  \n  aesmc	$ctr7b, $ctr7b			@ AES block 8k+15 - round 2
	aese	$ctr1b, $rk2  \n  aesmc	$ctr1b, $ctr1b			@ AES block 8k+9 - round 2

	aese	$ctr3b, $rk2  \n  aesmc	$ctr3b, $ctr3b			@ AES block 8k+11 - round 2
	aese	$ctr6b, $rk2  \n  aesmc	$ctr6b, $ctr6b			@ AES block 8k+14 - round 2
	pmull2  $acc_h.1q, $res0.2d, $h8.2d				@ GHASH block 8k - high

	aese	$ctr0b, $rk2  \n  aesmc	$ctr0b, $ctr0b			@ AES block 8k+8 - round 2
	aese	$ctr7b, $rk3  \n  aesmc	$ctr7b, $ctr7b			@ AES block 8k+15 - round 3

	aese	$ctr5b, $rk3  \n  aesmc	$ctr5b, $ctr5b			@ AES block 8k+13 - round 3
	rev64	$res6b, $res6b						@ GHASH block 8k+6

	aese	$ctr0b, $rk3  \n  aesmc	$ctr0b, $ctr0b			@ AES block 8k+8 - round 3
	aese	$ctr2b, $rk2  \n  aesmc	$ctr2b, $ctr2b			@ AES block 8k+10 - round 2
	aese	$ctr6b, $rk3  \n  aesmc	$ctr6b, $ctr6b			@ AES block 8k+14 - round 3

	pmull2  $t1.1q, $res2.2d, $h6.2d				@ GHASH block 8k+2 - high
	trn2	$res0.2d, $res1.2d, $res0.2d				@ GHASH block 8k, 8k+1 - mid
	aese	$ctr4b, $rk2  \n  aesmc	$ctr4b, $ctr4b			@ AES block 8k+12 - round 2

	ldp	$rk4q, $rk5q, [$cc, #64]				@ load rk4, rk5
	aese	$ctr1b, $rk3  \n  aesmc	$ctr1b, $ctr1b			@ AES block 8k+9 - round 3
	pmull2  $t2.1q, $res3.2d, $h5.2d				@ GHASH block 8k+3 - high

	aese	$ctr2b, $rk3  \n  aesmc	$ctr2b, $ctr2b			@ AES block 8k+10 - round 3
	eor	$acc_hb, $acc_hb, $t0.16b				@ GHASH block 8k+1 - high
	eor	$res0.16b, $res0.16b, $acc_m.16b			@ GHASH block 8k, 8k+1 - mid

	aese	$ctr4b, $rk3  \n  aesmc	$ctr4b, $ctr4b			@ AES block 8k+12 - round 3
	pmull	$h6.1q, $res2.1d, $h6.1d				@ GHASH block 8k+2 - low
	aese	$ctr3b, $rk3  \n  aesmc	$ctr3b, $ctr3b			@ AES block 8k+11 - round 3

	eor3	$acc_hb, $acc_hb, $t1.16b, $t2.16b			@ GHASH block 8k+2, 8k+3 - high
	trn1	$t3.2d, $res3.2d, $res2.2d				@ GHASH block 8k+2, 8k+3 - mid
	trn2	$res2.2d, $res3.2d, $res2.2d				@ GHASH block 8k+2, 8k+3 - mid

	pmull2  $acc_m.1q, $res0.2d, $h78k.2d				@ GHASH block 8k	- mid
	pmull	$h5.1q, $res3.1d, $h5.1d				@ GHASH block 8k+3 - low
	eor	$acc_lb, $acc_lb, $h7.16b				@ GHASH block 8k+1 - low

	pmull	$h78k.1q, $res0.1d, $h78k.1d				@ GHASH block 8k+1 - mid
	aese	$ctr5b, $rk4  \n  aesmc	$ctr5b, $ctr5b			@ AES block 8k+13 - round 4
	aese	$ctr0b, $rk4  \n  aesmc	$ctr0b, $ctr0b			@ AES block 8k+8 - round 4

	eor3	$acc_lb, $acc_lb, $h6.16b, $h5.16b			@ GHASH block 8k+2, 8k+3 - low
	ldr	$h1q, [$Htable]				@ load h1l | h1h
	ldr	$h2q, [$Htable, #32]				@ load h2l | h2h
	aese	$ctr7b, $rk4  \n  aesmc	$ctr7b, $ctr7b			@ AES block 8k+15 - round 4

	aese	$ctr2b, $rk4  \n  aesmc	$ctr2b, $ctr2b			@ AES block 8k+10 - round 4
	aese	$ctr6b, $rk4  \n  aesmc	$ctr6b, $ctr6b			@ AES block 8k+14 - round 4
	eor	$acc_mb, $acc_mb, $h78k.16b				@ GHASH block 8k+1 - mid

	eor	$res2.16b, $res2.16b, $t3.16b				@ GHASH block 8k+2, 8k+3 - mid
	aese	$ctr7b, $rk5  \n  aesmc	$ctr7b, $ctr7b			@ AES block 8k+15 - round 5
	aese	$ctr1b, $rk4  \n  aesmc	$ctr1b, $ctr1b			@ AES block 8k+9 - round 4

	aese	$ctr2b, $rk5  \n  aesmc	$ctr2b, $ctr2b			@ AES block 8k+10 - round 5
	aese	$ctr3b, $rk4  \n  aesmc	$ctr3b, $ctr3b			@ AES block 8k+11 - round 4
	aese	$ctr4b, $rk4  \n  aesmc	$ctr4b, $ctr4b			@ AES block 8k+12 - round 4

	aese	$ctr1b, $rk5  \n  aesmc	$ctr1b, $ctr1b			@ AES block 8k+9 - round 5
	pmull2  $t3.1q, $res2.2d, $h56k.2d				@ GHASH block 8k+2 - mid
	aese	$ctr6b, $rk5  \n  aesmc	$ctr6b, $ctr6b			@ AES block 8k+14 - round 5

	aese	$ctr4b, $rk5  \n  aesmc	$ctr4b, $ctr4b			@ AES block 8k+12 - round 5
	aese	$ctr3b, $rk5  \n  aesmc	$ctr3b, $ctr3b			@ AES block 8k+11 - round 5
	pmull	$h56k.1q, $res2.1d, $h56k.1d				@ GHASH block 8k+3 - mid

	aese	$ctr0b, $rk5  \n  aesmc	$ctr0b, $ctr0b			@ AES block 8k+8 - round 5
	aese	$ctr5b, $rk5  \n  aesmc	$ctr5b, $ctr5b			@ AES block 8k+13 - round 5
	ldp	$rk6q, $rk7q, [$cc, #96]				@ load rk6, rk7

	ldr	$h3q, [$Htable, #48]				@ load h3l | h3h
	ldr	$h4q, [$Htable, #80]				@ load h4l | h4h
	rev64	$res7b, $res7b						@ GHASH block 8k+7
	rev64	$res5b, $res5b						@ GHASH block 8k+5

	eor3	$acc_mb, $acc_mb, $h56k.16b, $t3.16b			@ GHASH block 8k+2, 8k+3 - mid

	trn1	$t6.2d, $res5.2d, $res4.2d				@ GHASH block 8k+4, 8k+5 - mid

	aese	$ctr0b, $rk6  \n  aesmc	$ctr0b, $ctr0b			@ AES block 8k+8 - round 6
	ldr	$h12kq, [$Htable, #16]				@ load h2k | h1k
	ldr	$h34kq, [$Htable, #64]				@ load h4k | h3k
	aese	$ctr6b, $rk6  \n  aesmc	$ctr6b, $ctr6b			@ AES block 8k+14 - round 6

	aese	$ctr5b, $rk6  \n  aesmc	$ctr5b, $ctr5b			@ AES block 8k+13 - round 6
	aese	$ctr7b, $rk6  \n  aesmc	$ctr7b, $ctr7b			@ AES block 8k+15 - round 6

	pmull2  $t4.1q, $res4.2d, $h4.2d				@ GHASH block 8k+4 - high
	pmull2  $t5.1q, $res5.2d, $h3.2d				@ GHASH block 8k+5 - high
	pmull	$h4.1q, $res4.1d, $h4.1d				@ GHASH block 8k+4 - low

	trn2	$res4.2d, $res5.2d, $res4.2d				@ GHASH block 8k+4, 8k+5 - mid
	pmull	$h3.1q, $res5.1d, $h3.1d				@ GHASH block 8k+5 - low
	trn1	$t9.2d, $res7.2d, $res6.2d				@ GHASH block 8k+6, 8k+7 - mid

	aese	$ctr7b, $rk7  \n  aesmc	$ctr7b, $ctr7b			@ AES block 8k+15 - round 7
	pmull2  $t7.1q, $res6.2d, $h2.2d				@ GHASH block 8k+6 - high
	aese	$ctr1b, $rk6  \n  aesmc	$ctr1b, $ctr1b			@ AES block 8k+9 - round 6

	aese	$ctr2b, $rk6  \n  aesmc	$ctr2b, $ctr2b			@ AES block 8k+10 - round 6
	aese	$ctr3b, $rk6  \n  aesmc	$ctr3b, $ctr3b			@ AES block 8k+11 - round 6
	aese	$ctr4b, $rk6  \n  aesmc	$ctr4b, $ctr4b			@ AES block 8k+12 - round 6

	ldp	$rk8q, $rk9q, [$cc, #128]				@ load rk8, rk9
	pmull	$h2.1q, $res6.1d, $h2.1d				@ GHASH block 8k+6 - low
	aese	$ctr5b, $rk7  \n  aesmc	$ctr5b, $ctr5b			@ AES block 8k+13 - round 7

	aese	$ctr1b, $rk7  \n  aesmc	$ctr1b, $ctr1b			@ AES block 8k+9 - round 7
	aese	$ctr4b, $rk7  \n  aesmc	$ctr4b, $ctr4b			@ AES block 8k+12 - round 7

	aese	$ctr6b, $rk7  \n  aesmc	$ctr6b, $ctr6b			@ AES block 8k+14 - round 7
	aese	$ctr2b, $rk7  \n  aesmc	$ctr2b, $ctr2b			@ AES block 8k+10 - round 7
	eor3	$acc_hb, $acc_hb, $t4.16b, $t5.16b			@ GHASH block 8k+4, 8k+5 - high

	aese	$ctr0b, $rk7  \n  aesmc	$ctr0b, $ctr0b			@ AES block 8k+8 - round 7
	trn2	$res6.2d, $res7.2d, $res6.2d				@ GHASH block 8k+6, 8k+7 - mid
	aese	$ctr3b, $rk7  \n  aesmc	$ctr3b, $ctr3b			@ AES block 8k+11 - round 7

	aese	$ctr0b, $rk8  \n  aesmc	$ctr0b, $ctr0b			@ AES block 8k+8 - round 8
	aese	$ctr7b, $rk8  \n  aesmc	$ctr7b, $ctr7b			@ AES block 8k+15 - round 8
	aese	$ctr4b, $rk8  \n  aesmc	$ctr4b, $ctr4b			@ AES block 8k+12 - round 8

	aese	$ctr1b, $rk8  \n  aesmc	$ctr1b, $ctr1b			@ AES block 8k+9 - round 8
	aese	$ctr5b, $rk8  \n  aesmc	$ctr5b, $ctr5b			@ AES block 8k+13 - round 8
	aese	$ctr6b, $rk8  \n  aesmc	$ctr6b, $ctr6b			@ AES block 8k+14 - round 8

	aese	$ctr3b, $rk8  \n  aesmc	$ctr3b, $ctr3b			@ AES block 8k+11 - round 8
	aese	$ctr4b, $rk9  \n  aesmc	$ctr4b, $ctr4b			@ AES block 8k+12 - round 9
	eor	$res4.16b, $res4.16b, $t6.16b				@ GHASH block 8k+4, 8k+5 - mid

	aese	$ctr0b, $rk9  \n  aesmc	$ctr0b, $ctr0b			@ AES block 8k+8 - round 9
	aese	$ctr1b, $rk9  \n  aesmc	$ctr1b, $ctr1b			@ AES block 8k+9 - round 9
	eor	$res6.16b, $res6.16b, $t9.16b				@ GHASH block 8k+6, 8k+7 - mid

	aese	$ctr6b, $rk9  \n  aesmc	$ctr6b, $ctr6b			@ AES block 8k+14 - round 9
	aese	$ctr7b, $rk9  \n  aesmc	$ctr7b, $ctr7b			@ AES block 8k+15 - round 9
	pmull2  $t6.1q, $res4.2d, $h34k.2d				@ GHASH block 8k+4 - mid

	aese	$ctr2b, $rk8  \n  aesmc	$ctr2b, $ctr2b			@ AES block 8k+10 - round 8
	pmull	$h34k.1q, $res4.1d, $h34k.1d				@ GHASH block 8k+5 - mid
	pmull2  $t8.1q, $res7.2d, $h1.2d				@ GHASH block 8k+7 - high

	pmull2  $t9.1q, $res6.2d, $h12k.2d				@ GHASH block 8k+6 - mid
	pmull	$h12k.1q, $res6.1d, $h12k.1d				@ GHASH block 8k+7 - mid
	pmull	$h1.1q, $res7.1d, $h1.1d				@ GHASH block 8k+7 - low

	ldp	$rk10q, $rk11q, [$cc, #160]				@ load rk10, rk11
	eor3	$acc_lb, $acc_lb, $h4.16b, $h3.16b			@ GHASH block 8k+4, 8k+5 - low
	eor3	$acc_mb, $acc_mb, $h34k.16b, $t6.16b			@ GHASH block 8k+4, 8k+5 - mid

	aese	$ctr2b, $rk9  \n  aesmc	$ctr2b, $ctr2b			@ AES block 8k+10 - round 9
	aese	$ctr3b, $rk9  \n  aesmc	$ctr3b, $ctr3b			@ AES block 8k+11 - round 9
	aese	$ctr5b, $rk9  \n  aesmc	$ctr5b, $ctr5b			@ AES block 8k+13 - round 9

	eor3	$acc_hb, $acc_hb, $t7.16b, $t8.16b			@ GHASH block 8k+6, 8k+7 - high
	eor3	$acc_lb, $acc_lb, $h2.16b, $h1.16b			@ GHASH block 8k+6, 8k+7 - low
	ldr	$mod_constantd, [$modulo_constant]			@ MODULO - load modulo constant

	eor3	$acc_mb, $acc_mb, $h12k.16b, $t9.16b			@ GHASH block 8k+6, 8k+7 - mid

	aese	$ctr4b, $rk10 \n  aesmc	$ctr4b, $ctr4b			@ AES block 8k+12 - round 10
	aese	$ctr6b, $rk10 \n  aesmc	$ctr6b, $ctr6b			@ AES block 8k+14 - round 10
	aese	$ctr5b, $rk10 \n  aesmc	$ctr5b, $ctr5b			@ AES block 8k+13 - round 10

	aese	$ctr0b, $rk10 \n  aesmc	$ctr0b, $ctr0b			@ AES block 8k+8 - round 10
	aese	$ctr2b, $rk10 \n  aesmc	$ctr2b, $ctr2b			@ AES block 8k+10 - round 10
	aese	$ctr3b, $rk10 \n  aesmc	$ctr3b, $ctr3b			@ AES block 8k+11 - round 10

	eor3	$acc_mb, $acc_mb, $acc_hb, $acc_lb		 	@ MODULO - karatsuba tidy up

	aese	$ctr7b, $rk10 \n  aesmc	$ctr7b, $ctr7b			@ AES block 8k+15 - round 10
	aese	$ctr1b, $rk10 \n  aesmc	$ctr1b, $ctr1b			@ AES block 8k+9 - round 10
	ldp	$rk12q, $rk13q, [$cc, #192]				@ load rk12, rk13

	ext	$t11.16b, $acc_hb, $acc_hb, #8				@ MODULO - other top alignment

	aese	$ctr2b, $rk11 \n  aesmc	$ctr2b, $ctr2b			@ AES block 8k+10 - round 11
	aese	$ctr1b, $rk11 \n  aesmc	$ctr1b, $ctr1b			@ AES block 8k+9 - round 11
	aese	$ctr0b, $rk11 \n  aesmc	$ctr0b, $ctr0b			@ AES block 8k+8 - round 11

	pmull	$t12.1q, $acc_h.1d, $mod_constant.1d			@ MODULO - top 64b align with mid
	aese	$ctr3b, $rk11 \n  aesmc	$ctr3b, $ctr3b			@ AES block 8k+11 - round 11

	aese	$ctr7b, $rk11 \n  aesmc	$ctr7b, $ctr7b			@ AES block 8k+15 - round 11
	aese	$ctr6b, $rk11 \n  aesmc	$ctr6b, $ctr6b			@ AES block 8k+14 - round 11
	aese	$ctr4b, $rk11 \n  aesmc	$ctr4b, $ctr4b			@ AES block 8k+12 - round 11

	aese	$ctr5b, $rk11 \n  aesmc	$ctr5b, $ctr5b			@ AES block 8k+13 - round 11
	aese	$ctr3b, $rk12 \n  aesmc	$ctr3b, $ctr3b			@ AES block 8k+11 - round 12

	eor3	$acc_mb, $acc_mb, $t12.16b, $t11.16b			@ MODULO - fold into mid

	aese	$ctr3b, $rk13						@ AES block 8k+11 - round 13
	aese	$ctr2b, $rk12 \n  aesmc	$ctr2b, $ctr2b			@ AES block 8k+10 - round 12
	aese	$ctr6b, $rk12 \n  aesmc	$ctr6b, $ctr6b			@ AES block 8k+14 - round 12

	pmull	$acc_h.1q, $acc_m.1d, $mod_constant.1d			@ MODULO - mid 64b align with low
	aese	$ctr4b, $rk12 \n  aesmc	$ctr4b, $ctr4b			@ AES block 8k+12 - round 12
	aese	$ctr7b, $rk12 \n  aesmc	$ctr7b, $ctr7b			@ AES block 8k+15 - round 12

	aese	$ctr0b, $rk12 \n  aesmc	$ctr0b, $ctr0b			@ AES block 8k+8 - round 12
	ldr	$rk14q, [$cc, #224]					@ load rk14
	aese	$ctr1b, $rk12 \n  aesmc	$ctr1b, $ctr1b	        	@ AES block 8k+9 - round 12

	aese	$ctr4b, $rk13						@ AES block 8k+12 - round 13
	ext	$t11.16b, $acc_mb, $acc_mb, #8			 	@ MODULO - other mid alignment
	aese	$ctr5b, $rk12 \n  aesmc	$ctr5b, $ctr5b			@ AES block 8k+13 - round 12

	aese	$ctr6b, $rk13						@ AES block 8k+14 - round 13
	aese	$ctr2b, $rk13						@ AES block 8k+10 - round 13
	aese	$ctr1b, $rk13						@ AES block 8k+9 - round 13

	aese	$ctr5b, $rk13						@ AES block 8k+13 - round 13
	eor3	$acc_lb, $acc_lb, $t11.16b, $acc_hb		 	@ MODULO - fold into low
	add	$rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s		@ CTR block 8k+15

	aese	$ctr7b, $rk13						@ AES block 8k+15 - round 13
	aese	$ctr0b, $rk13						@ AES block 8k+8 - round 13
.L256_dec_tail:								@ TAIL

	ext	$t0.16b, $acc_lb, $acc_lb, #8				@ prepare final partial tag
	sub	$main_end_input_ptr, $end_input_ptr, $input_ptr		@ main_end_input_ptr is number of bytes left to process
	cmp	$main_end_input_ptr, #112

	ldr	$res1q, [$input_ptr], #16				@ AES block 8k+8 - load ciphertext

	ldp	$h78kq, $h8q, [$Htable, #160]			@ load h8k | h7k
	mov	$t1.16b, $rk14

	ldp	$h5q, $h56kq, [$Htable, #96]			@ load h5l | h5h

	eor3	$res4b, $res1b, $ctr0b, $t1.16b				@ AES block 8k+8 - result
	ldp	$h6q, $h7q, [$Htable, #128]			@ load h6l | h6h
	b.gt	.L256_dec_blocks_more_than_7

	mov	$ctr7b, $ctr6b
	sub	$rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s
	mov	$ctr6b, $ctr5b

	mov	$ctr5b, $ctr4b
	mov	$ctr4b, $ctr3b
	movi	$acc_l.8b, #0

	movi	$acc_h.8b, #0
	movi	$acc_m.8b, #0
	mov	$ctr3b, $ctr2b

	cmp	$main_end_input_ptr, #96
	mov	$ctr2b, $ctr1b
	b.gt	.L256_dec_blocks_more_than_6

	mov	$ctr7b, $ctr6b
	mov	$ctr6b, $ctr5b

	mov	$ctr5b, $ctr4b
	cmp	$main_end_input_ptr, #80
	sub	$rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s

	mov	$ctr4b, $ctr3b
	mov	$ctr3b, $ctr1b
	b.gt	.L256_dec_blocks_more_than_5

	cmp	$main_end_input_ptr, #64
	mov	$ctr7b, $ctr6b
	sub	$rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s

	mov	$ctr6b, $ctr5b

	mov	$ctr5b, $ctr4b
	mov	$ctr4b, $ctr1b
	b.gt	.L256_dec_blocks_more_than_4

	sub	$rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s
	mov	$ctr7b, $ctr6b
	cmp	$main_end_input_ptr, #48

	mov	$ctr6b, $ctr5b
	mov	$ctr5b, $ctr1b
	b.gt	.L256_dec_blocks_more_than_3

	ldr	$h34kq, [$Htable, #64]				@ load h4k | h3k
	sub	$rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s
	mov	$ctr7b, $ctr6b

	cmp	$main_end_input_ptr, #32
	mov	$ctr6b, $ctr1b
	b.gt	.L256_dec_blocks_more_than_2

	sub	$rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s

	mov	$ctr7b, $ctr1b
	cmp	$main_end_input_ptr, #16
	b.gt	.L256_dec_blocks_more_than_1

	sub	$rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s
	ldr	$h12kq, [$Htable, #16]				@ load h2k | h1k
	b	 .L256_dec_blocks_less_than_1
.L256_dec_blocks_more_than_7:						@ blocks left >  7
	rev64	$res0b, $res1b						@ GHASH final-7 block
	ldr	$res1q, [$input_ptr], #16				@ AES final-6 block - load ciphertext
	st1	{ $res4b}, [$output_ptr], #16				@ AES final-7 block  - store result

	ins	$acc_m.d[0], $h78k.d[1]					@ GHASH final-7 block - mid

	eor	$res0b, $res0b, $t0.16b					@ feed in partial tag

	ins	$rk4v.d[0], $res0.d[1]					@ GHASH final-7 block - mid
	eor3	$res4b, $res1b, $ctr1b, $t1.16b				@ AES final-6 block - result

	pmull2  $acc_h.1q, $res0.2d, $h8.2d				@ GHASH final-7 block - high

	eor	$rk4v.8b, $rk4v.8b, $res0.8b				@ GHASH final-7 block - mid
	movi	$t0.8b, #0						@ supress further partial tag feed in

	pmull	$acc_l.1q, $res0.1d, $h8.1d				@ GHASH final-7 block - low
	pmull	$acc_m.1q, $rk4v.1d, $acc_m.1d			 	@ GHASH final-7 block - mid
.L256_dec_blocks_more_than_6:						@ blocks left >  6

	rev64	$res0b, $res1b						@ GHASH final-6 block

	eor	$res0b, $res0b, $t0.16b					@ feed in partial tag
	ldr	$res1q, [$input_ptr], #16				@ AES final-5 block - load ciphertext
	movi	$t0.8b, #0						@ supress further partial tag feed in

	ins	$rk4v.d[0], $res0.d[1]					@ GHASH final-6 block - mid
	st1	{ $res4b}, [$output_ptr], #16				@ AES final-6 block - store result
	pmull2  $rk2q1, $res0.2d, $h7.2d				@ GHASH final-6 block - high

	pmull	$rk3q1, $res0.1d, $h7.1d				@ GHASH final-6 block - low

	eor3	$res4b, $res1b, $ctr2b, $t1.16b				@ AES final-5 block - result
	eor	$acc_lb, $acc_lb, $rk3					@ GHASH final-6 block - low
	eor	$rk4v.8b, $rk4v.8b, $res0.8b				@ GHASH final-6 block - mid

	pmull	$rk4v.1q, $rk4v.1d, $h78k.1d				@ GHASH final-6 block - mid

	eor	$acc_mb, $acc_mb, $rk4v.16b				@ GHASH final-6 block - mid
	eor	$acc_hb, $acc_hb, $rk2					@ GHASH final-6 block - high
.L256_dec_blocks_more_than_5:						@ blocks left >  5

	rev64	$res0b, $res1b						@ GHASH final-5 block

	eor	$res0b, $res0b, $t0.16b					@ feed in partial tag

	pmull2  $rk2q1, $res0.2d, $h6.2d				@ GHASH final-5 block - high
	ins	$rk4v.d[0], $res0.d[1]					@ GHASH final-5 block - mid

	ldr	$res1q, [$input_ptr], #16				@ AES final-4 block - load ciphertext

	eor	$rk4v.8b, $rk4v.8b, $res0.8b				@ GHASH final-5 block - mid
	st1	{ $res4b}, [$output_ptr], #16			  	@ AES final-5 block - store result

	pmull	$rk3q1, $res0.1d, $h6.1d				@ GHASH final-5 block - low
	ins	$rk4v.d[1], $rk4v.d[0]					@ GHASH final-5 block - mid

	pmull2  $rk4v.1q, $rk4v.2d, $h56k.2d				@ GHASH final-5 block - mid

	eor	$acc_hb, $acc_hb, $rk2					@ GHASH final-5 block - high
	eor3	$res4b, $res1b, $ctr3b, $t1.16b				@ AES final-4 block - result
	eor	$acc_lb, $acc_lb, $rk3					@ GHASH final-5 block - low

	eor	$acc_mb, $acc_mb, $rk4v.16b				@ GHASH final-5 block - mid
	movi	$t0.8b, #0						@ supress further partial tag feed in
.L256_dec_blocks_more_than_4:						@ blocks left >  4

	rev64	$res0b, $res1b						@ GHASH final-4 block

	eor	$res0b, $res0b, $t0.16b					@ feed in partial tag

	ins	$rk4v.d[0], $res0.d[1]					@ GHASH final-4 block - mid
	ldr	$res1q, [$input_ptr], #16				@ AES final-3 block - load ciphertext

	movi	$t0.8b, #0						@ supress further partial tag feed in

	pmull	$rk3q1, $res0.1d, $h5.1d				@ GHASH final-4 block - low
	pmull2  $rk2q1, $res0.2d, $h5.2d				@ GHASH final-4 block - high

	eor	$rk4v.8b, $rk4v.8b, $res0.8b				@ GHASH final-4 block - mid

	eor	$acc_hb, $acc_hb, $rk2					@ GHASH final-4 block - high

	pmull	$rk4v.1q, $rk4v.1d, $h56k.1d				@ GHASH final-4 block - mid

	eor	$acc_lb, $acc_lb, $rk3					@ GHASH final-4 block - low
	st1	{ $res4b}, [$output_ptr], #16			 	@ AES final-4 block - store result

	eor	$acc_mb, $acc_mb, $rk4v.16b				@ GHASH final-4 block - mid
	eor3	$res4b, $res1b, $ctr4b, $t1.16b				@ AES final-3 block - result
.L256_dec_blocks_more_than_3:						@ blocks left >  3

	ldr	$h4q, [$Htable, #80]				@ load h4l | h4h
	rev64	$res0b, $res1b						@ GHASH final-3 block

	eor	$res0b, $res0b, $t0.16b					@ feed in partial tag
	ldr	$res1q, [$input_ptr], #16				@ AES final-2 block - load ciphertext
	ldr	$h34kq, [$Htable, #64]				@ load h4k | h3k

	ins	$rk4v.d[0], $res0.d[1]					@ GHASH final-3 block - mid
	st1	{ $res4b}, [$output_ptr], #16			 	@ AES final-3 block - store result

	eor3	$res4b, $res1b, $ctr5b, $t1.16b				@ AES final-2 block - result

	eor	$rk4v.8b, $rk4v.8b, $res0.8b				@ GHASH final-3 block - mid

	ins	$rk4v.d[1], $rk4v.d[0]					@ GHASH final-3 block - mid
	pmull	$rk3q1, $res0.1d, $h4.1d				@ GHASH final-3 block - low
	pmull2  $rk2q1, $res0.2d, $h4.2d				@ GHASH final-3 block - high

	movi	$t0.8b, #0						@ supress further partial tag feed in
	pmull2  $rk4v.1q, $rk4v.2d, $h34k.2d				@ GHASH final-3 block - mid
	eor	$acc_lb, $acc_lb, $rk3					@ GHASH final-3 block - low

	eor	$acc_hb, $acc_hb, $rk2					@ GHASH final-3 block - high

	eor	$acc_mb, $acc_mb, $rk4v.16b				@ GHASH final-3 block - mid
.L256_dec_blocks_more_than_2:						@ blocks left >  2

	rev64	$res0b, $res1b						@ GHASH final-2 block

	ldr	$h3q, [$Htable, #48]				@ load h3l | h3h
	ldr	$res1q, [$input_ptr], #16				@ AES final-1 block - load ciphertext

	eor	$res0b, $res0b, $t0.16b					@ feed in partial tag

	ins	$rk4v.d[0], $res0.d[1]					@ GHASH final-2 block - mid

	pmull	$rk3q1, $res0.1d, $h3.1d				@ GHASH final-2 block - low
	st1	{ $res4b}, [$output_ptr], #16			  	@ AES final-2 block - store result
	eor3	$res4b, $res1b, $ctr6b, $t1.16b				@ AES final-1 block - result

	eor	$rk4v.8b, $rk4v.8b, $res0.8b				@ GHASH final-2 block - mid
	eor	$acc_lb, $acc_lb, $rk3					@ GHASH final-2 block - low
	movi	$t0.8b, #0						@ supress further partial tag feed in

	pmull	$rk4v.1q, $rk4v.1d, $h34k.1d				@ GHASH final-2 block - mid
	pmull2  $rk2q1, $res0.2d, $h3.2d				@ GHASH final-2 block - high

	eor	$acc_mb, $acc_mb, $rk4v.16b				@ GHASH final-2 block - mid
	eor	$acc_hb, $acc_hb, $rk2					@ GHASH final-2 block - high
.L256_dec_blocks_more_than_1:						@ blocks left >  1

	rev64	$res0b, $res1b						@ GHASH final-1 block

	eor	$res0b, $res0b, $t0.16b					@ feed in partial tag

	ins	$rk4v.d[0], $res0.d[1]					@ GHASH final-1 block - mid
	ldr	$h2q, [$Htable, #32]				@ load h2l | h2h

	eor	$rk4v.8b, $rk4v.8b, $res0.8b				@ GHASH final-1 block - mid
	ldr	$res1q, [$input_ptr], #16				@ AES final block - load ciphertext
	st1	{ $res4b}, [$output_ptr], #16			 	@ AES final-1 block - store result

	ldr	$h12kq, [$Htable, #16]				@ load h2k | h1k
	pmull	$rk3q1, $res0.1d, $h2.1d				@ GHASH final-1 block - low

	ins	$rk4v.d[1], $rk4v.d[0]					@ GHASH final-1 block - mid

	eor	$acc_lb, $acc_lb, $rk3					@ GHASH final-1 block - low

	eor3	$res4b, $res1b, $ctr7b, $t1.16b				@ AES final block - result
	pmull2  $rk2q1, $res0.2d, $h2.2d				@ GHASH final-1 block - high

	pmull2  $rk4v.1q, $rk4v.2d, $h12k.2d				@ GHASH final-1 block - mid

	movi	$t0.8b, #0						@ supress further partial tag feed in
	eor	$acc_hb, $acc_hb, $rk2					@ GHASH final-1 block - high

	eor	$acc_mb, $acc_mb, $rk4v.16b				@ GHASH final-1 block - mid
.L256_dec_blocks_less_than_1:						@ blocks left <= 1

	ld1	{ $rk0}, [$output_ptr]					@ load existing bytes where the possibly partial last block is to be stored
	mvn	$temp0_x, xzr						@ temp0_x = 0xffffffffffffffff
	and	$bit_length, $bit_length, #127				@ bit_length %= 128

	sub	$bit_length, $bit_length, #128				@ bit_length -= 128
	rev32	$rtmp_ctr.16b, $rtmp_ctr.16b
	str	$rtmp_ctrq, [$counter]					@ store the updated counter

	neg	$bit_length, $bit_length				@ bit_length = 128 - #bits in input (in range [1,128])

	and	$bit_length, $bit_length, #127			 	@ bit_length %= 128

	lsr	$temp0_x, $temp0_x, $bit_length				@ temp0_x is mask for top 64b of last block
	cmp	$bit_length, #64
	mvn	$temp1_x, xzr						@ temp1_x = 0xffffffffffffffff

	csel	$temp3_x, $temp0_x, xzr, lt
	csel	$temp2_x, $temp1_x, $temp0_x, lt

	mov	$ctr0.d[0], $temp2_x					@ ctr0b is mask for last block
	mov	$ctr0.d[1], $temp3_x

	and	$res1b, $res1b, $ctr0b					@ possibly partial last block has zeroes in highest bits
	ldr	$h1q, [$Htable]				@ load h1l | h1h
	bif	$res4b, $rk0, $ctr0b					@ insert existing bytes in top end of result before storing

	rev64	$res0b, $res1b						@ GHASH final block

	eor	$res0b, $res0b, $t0.16b					@ feed in partial tag

	ins	$t0.d[0], $res0.d[1]					@ GHASH final block - mid
	pmull2  $rk2q1, $res0.2d, $h1.2d				@ GHASH final block - high

	eor	$t0.8b, $t0.8b, $res0.8b				@ GHASH final block - mid

	pmull	$rk3q1, $res0.1d, $h1.1d				@ GHASH final block - low
	eor	$acc_hb, $acc_hb, $rk2					@ GHASH final block - high

	pmull	$t0.1q, $t0.1d, $h12k.1d				@ GHASH final block - mid

	eor	$acc_mb, $acc_mb, $t0.16b				@ GHASH final block - mid
	ldr	$mod_constantd, [$modulo_constant]			@ MODULO - load modulo constant
	eor	$acc_lb, $acc_lb, $rk3					@ GHASH final block - low

	pmull	$t11.1q, $acc_h.1d, $mod_constant.1d		 	@ MODULO - top 64b align with mid
	eor	$t10.16b, $acc_hb, $acc_lb				@ MODULO - karatsuba tidy up

	ext	$acc_hb, $acc_hb, $acc_hb, #8				@ MODULO - other top alignment
	st1	{ $res4b}, [$output_ptr]				@ store all 16B

	eor	$acc_mb, $acc_mb, $t10.16b				@ MODULO - karatsuba tidy up

	eor	$t11.16b, $acc_hb, $t11.16b				@ MODULO - fold into mid
	eor	$acc_mb, $acc_mb, $t11.16b				@ MODULO - fold into mid

	pmull	$acc_h.1q, $acc_m.1d, $mod_constant.1d			@ MODULO - mid 64b align with low

	ext	$acc_mb, $acc_mb, $acc_mb, #8				@ MODULO - other mid alignment
	eor	$acc_lb, $acc_lb, $acc_hb				@ MODULO - fold into low

	eor	$acc_lb, $acc_lb, $acc_mb				@ MODULO - fold into low
	ext	$acc_lb, $acc_lb, $acc_lb, #8
	rev64	$acc_lb, $acc_lb
	st1	{ $acc_l.16b }, [$current_tag]
	mov	x0, $byte_length

        ldp     d10, d11, [sp, #16]
	ldp     d12, d13, [sp, #32]
	ldp     d14, d15, [sp, #48]
	ldp     d8, d9, [sp], #80
	ret

.L256_dec_ret:
	mov w0, #0x0
	ret
.size aesv8_gcm_8x_dec_256,.-aesv8_gcm_8x_dec_256
___
}
}

$code.=<<___;
.asciz  "AES GCM module for ARMv8, SPDX BSD-3-Clause by <xiaokang.qian\@arm.com>"
.align  2
#endif
___

{
    my  %opcode = (
    "rax1"    => 0xce608c00,    "eor3"    => 0xce000000,
    "bcax"    => 0xce200000,    "xar"    => 0xce800000    );

    sub unsha3 {
         my ($mnemonic,$arg)=@_;

         $arg =~ m/[qv]([0-9]+)[^,]*,\s*[qv]([0-9]+)[^,]*(?:,\s*[qv]([0-9]+)[^,]*(?:,\s*[qv#]([0-9\-]+))?)?/
         &&
         sprintf ".inst\t0x%08x\t//%s %s",
            $opcode{$mnemonic}|$1|($2<<5)|($3<<16)|(eval($4)<<10),
            $mnemonic,$arg;
    }
    sub unvmov {
        my $arg=shift;

        $arg =~ m/q([0-9]+)#(lo|hi),\s*q([0-9]+)#(lo|hi)/o &&
        sprintf "ins    v%d.d[%d],v%d.d[%d]",$1<8?$1:$1+8,($2 eq "lo")?0:1,
                             $3<8?$3:$3+8,($4 eq "lo")?0:1;
    }

     foreach(split("\n",$code)) {
        s/@\s/\/\//o;               # old->new style commentary
        s/\`([^\`]*)\`/eval($1)/ge;

        m/\bld1r\b/ and s/\.16b/.2d/g    or
        s/\b(eor3|rax1|xar|bcax)\s+(v.*)/unsha3($1,$2)/ge;
        print $_,"\n";
     }
}
