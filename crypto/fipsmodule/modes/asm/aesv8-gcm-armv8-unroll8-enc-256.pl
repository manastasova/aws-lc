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
$round_keys_ptr="x11";
{

my ($end_input_ptr,$main_end_input_ptr)=map("x$_",(4..5));
my ($temp0_x,$temp1_x)=map("x$_",(7..8));
my ($temp2_x,$temp3_x)=map("x$_",(13..14));
my ($enc_ctr_0b,$enc_ctr_1b,$enc_ctr_2b,$enc_ctr_3b,$enc_ctr_4b,$enc_ctr_5b,$enc_ctr_6b,$enc_ctr_7b,$ct_0b,$ct_1b,$ct_2b,$ct_3b,$ct_4b,$ct_5b,$ct_6b,$ct_7b)=map("v$_.16b",(0..15));
my ($enc_ctr_0,$enc_ctr_1,$enc_ctr_2,$enc_ctr_3,$enc_ctr_4,$enc_ctr_5,$enc_ctr_6,$enc_ctr_7,$ct_0,$ct_1,$ct_2,$ct_3,$ct_4,$ct_5,$ct_6,$ct_7)=map("v$_",(0..15));
my ($enc_ctr_0d,$enc_ctr_1d,$enc_ctr_2d,$enc_ctr_3d,$enc_ctr_4d,$enc_ctr_5d,$enc_ctr_6d,$enc_ctr_7d)=map("d$_",(0..7));
my ($enc_ctr_0q,$enc_ctr_1q,$enc_ctr_2q,$enc_ctr_3q,$enc_ctr_4q,$enc_ctr_5q,$enc_ctr_6q,$enc_ctr_7q)=map("q$_",(0..7));
# Counter aliases (same registers as enc_ctr_*, used before AES encryption)
my ($ctr_0b,$ctr_1b,$ctr_2b,$ctr_3b,$ctr_4b,$ctr_5b,$ctr_6b,$ctr_7b)=map("v$_.16b",(0..7));
my ($ctr_0,$ctr_1,$ctr_2,$ctr_3,$ctr_4,$ctr_5,$ctr_6,$ctr_7)=map("v$_",(0..7));
my ($ctr_0q,$ctr_1q,$ctr_2q,$ctr_3q,$ctr_4q,$ctr_5q,$ctr_6q,$ctr_7q)=map("q$_",(0..7));
my ($ct_0q,$ct_1q,$ct_2q,$ct_3q,$ct_4q,$ct_5q,$ct_6q,$ct_7q)=map("q$_",(8..15));

my ($pt_0,$pt_1,$pt_2,$pt_3,$pt_4,$pt_5,$pt_6,$pt_7)=map("v$_",(8..15));
my ($pt_0b,$pt_1b,$pt_2b,$pt_3b,$pt_4b,$pt_5b,$pt_6b,$pt_7b)=map("v$_.16b",(8..15));
my ($pt_0q,$pt_1q,$pt_2q,$pt_3q,$pt_4q,$pt_5q,$pt_6q,$pt_7q)=map("q$_",(8..15));

my ($acc_hb,$acc_mb,$acc_lb)=map("v$_.16b",(17..19));
my ($acc_h,$acc_m,$acc_l)=map("v$_",(17..19));

my ($h1,$h12k,$h2,$h3,$h34k,$h4)=map("v$_",(20..25));
my ($h5,$h56k,$h6,$h7,$h78k,$h8)=map("v$_",(20..25));
my ($h1q,$h12kq,$h2q,$h3q,$h34kq,$h4q)=map("q$_",(20..25));
my ($h5q,$h56kq,$h6q,$h7q,$h78kq,$h8q)=map("q$_",(20..25));

my $t0="v16";
my $t0d="d16";

my $t1="v29";
my $t2=$ct_1;
my $t3=$t1;

my $t4=$ct_0;
my $t5=$ct_2;
my $t6=$t0;

my $t7=$ct_3;
my $t8=$ct_4;
my $t9=$ct_5;

my $t10=$ct_6;
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
#########################################################################################
# size_t aesv8_gcm_8x_enc_256(const uint8_t *in,
#                             size_t len,
#                             uint8_t *out,
#                             uint64_t *Xi,
#                             uint8_t ivec[16],
#                             const AES_KEY *key,
#                             const void *Htable);
#
$code.=<<___;
.macro aesenmc, dst, key // @slothy:no-unfold=true
        aese    \\dst, \\key
        aesmc   \\dst, \\dst
.endm

.global aesv8_gcm_8x_enc_256
.type   aesv8_gcm_8x_enc_256,%function
.align  4
aesv8_gcm_8x_enc_256:
        AARCH64_VALID_CALL_TARGET
        cbz     x1, .L256_enc_ret
        stp     d8, d9, [sp, #-80]!
        stp     d10, d11, [sp, #16]
        stp     d12, d13, [sp, #32]
        stp     d14, d15, [sp, #48]
        
        lsr     $byte_length, $bit_length, #3
        mov     $counter, x4
        mov     $round_keys_ptr, x5
        
        mov     x5, #0xc200000000000000
        stp     x5, xzr, [sp, #64]
        add     $modulo_constant, sp, #64

        ld1     { $ctr_0b}, [$counter]                                   @ load initial counter (big-endian)

        mov     $main_end_input_ptr, $byte_length

        mov     $constant_temp, #0x100000000                             @ rctr_inc = [0, 0, 0, 1] — adds 1 to the counter lane only
        movi    $rctr_inc.16b, #0x0
        mov     $rctr_inc.d[1], $constant_temp

        and     $main_end_input_ptr, $main_end_input_ptr, #0xffffffffffffff80 @ number of bytes to be processed in main loop (multiple of 128)

        add     $main_end_input_ptr, $main_end_input_ptr, $input_ptr

        rev32   $rtmp_ctr.16b, $ctr_0.16b                                @ byte-reverse counter into LE accumulator

        add     $rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s                 @ increment LE counter (counter+1)
        rev32   $ctr_1.16b, $rtmp_ctr.16b                                @ snapshot counter+1 as BE for AES -> ctr_1

        add     $rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s                 @ increment LE counter (counter+2)
        rev32   $ctr_2.16b, $rtmp_ctr.16b                                @ snapshot counter+2 as BE for AES -> ctr_2

        add     $rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s                 @ increment LE counter (counter+3)
        rev32   $ctr_3.16b, $rtmp_ctr.16b                                @ snapshot counter+3 as BE for AES -> ctr_3

        add     $rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s                 @ increment LE counter (counter+4)
        rev32   $ctr_4.16b, $rtmp_ctr.16b                                @ snapshot counter+4 as BE for AES -> ctr_4

        add     $rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s                 @ increment LE counter (counter+5)
        rev32   $ctr_5.16b, $rtmp_ctr.16b                                @ snapshot counter+5 as BE for AES -> ctr_5

        add     $rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s                 @ increment LE counter (counter+6)
        rev32   $ctr_6.16b, $rtmp_ctr.16b                                @ snapshot counter+6 as BE for AES -> ctr_6
        ldp     $rk0q, $rk1q, [$round_keys_ptr, #0]                      @ load rk0, rk1

        add     $rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s                 @ increment LE counter (counter+7)
        rev32   $ctr_7.16b, $rtmp_ctr.16b                                @ snapshot counter+7 as BE for AES -> ctr_7

        aesenmc $enc_ctr_0b, $rk0 @ AES block 0 - round 0
        aesenmc $enc_ctr_1b, $rk0 @ AES block 1 - round 0
        aesenmc $enc_ctr_2b, $rk0 @ AES block 2 - round 0

        aesenmc $enc_ctr_3b, $rk0 @ AES block 3 - round 0
        aesenmc $enc_ctr_4b, $rk0 @ AES block 4 - round 0
        aesenmc $enc_ctr_5b, $rk0 @ AES block 5 - round 0

        aesenmc $enc_ctr_6b, $rk0 @ AES block 6 - round 0
        aesenmc $enc_ctr_7b, $rk0 @ AES block 7 - round 0
        ldp     $rk2q, $rk3q, [$round_keys_ptr, #32]                     @ load rk2, rk3

        aesenmc $enc_ctr_0b, $rk1 @ AES block 0 - round 1
        aesenmc $enc_ctr_1b, $rk1 @ AES block 1 - round 1
        aesenmc $enc_ctr_2b, $rk1 @ AES block 2 - round 1

        aesenmc $enc_ctr_3b, $rk1 @ AES block 3 - round 1
        aesenmc $enc_ctr_4b, $rk1 @ AES block 4 - round 1
        aesenmc $enc_ctr_5b, $rk1 @ AES block 5 - round 1

        aesenmc $enc_ctr_6b, $rk1 @ AES block 6 - round 1
        aesenmc $enc_ctr_7b, $rk1 @ AES block 7 - round 1

        aesenmc $enc_ctr_0b, $rk2 @ AES block 0 - round 2
        aesenmc $enc_ctr_1b, $rk2 @ AES block 1 - round 2
        aesenmc $enc_ctr_2b, $rk2 @ AES block 2 - round 2

        aesenmc $enc_ctr_3b, $rk2 @ AES block 3 - round 2
        aesenmc $enc_ctr_4b, $rk2 @ AES block 4 - round 2
        aesenmc $enc_ctr_5b, $rk2 @ AES block 5 - round 2

        aesenmc $enc_ctr_6b, $rk2 @ AES block 6 - round 2
        aesenmc $enc_ctr_7b, $rk2 @ AES block 7 - round 2

        aesenmc $enc_ctr_0b, $rk3 @ AES block 0 - round 3
        aesenmc $enc_ctr_1b, $rk3 @ AES block 1 - round 3
        aesenmc $enc_ctr_2b, $rk3 @ AES block 2 - round 3

        aesenmc $enc_ctr_3b, $rk3 @ AES block 3 - round 3
        aesenmc $enc_ctr_4b, $rk3 @ AES block 4 - round 3
        aesenmc $enc_ctr_5b, $rk3 @ AES block 5 - round 3

        aesenmc $enc_ctr_6b, $rk3 @ AES block 6 - round 3
        aesenmc $enc_ctr_7b, $rk3 @ AES block 7 - round 3

        ldp     $rk4q, $rk5q, [$round_keys_ptr, #64]                     @ load rk4, rk5

        aesenmc $enc_ctr_0b, $rk4 @ AES block 0 - round 4
        aesenmc $enc_ctr_1b, $rk4 @ AES block 1 - round 4
        aesenmc $enc_ctr_2b, $rk4 @ AES block 2 - round 4

        aesenmc $enc_ctr_3b, $rk4 @ AES block 3 - round 4
        aesenmc $enc_ctr_4b, $rk4 @ AES block 4 - round 4
        aesenmc $enc_ctr_5b, $rk4 @ AES block 5 - round 4

        aesenmc $enc_ctr_6b, $rk4 @ AES block 6 - round 4
        aesenmc $enc_ctr_7b, $rk4 @ AES block 7 - round 4

        aesenmc $enc_ctr_0b, $rk5 @ AES block 0 - round 5
        aesenmc $enc_ctr_1b, $rk5 @ AES block 1 - round 5
        aesenmc $enc_ctr_2b, $rk5 @ AES block 2 - round 5

        aesenmc $enc_ctr_3b, $rk5 @ AES block 3 - round 5
        aesenmc $enc_ctr_4b, $rk5 @ AES block 4 - round 5
        aesenmc $enc_ctr_5b, $rk5 @ AES block 5 - round 5

        aesenmc $enc_ctr_6b, $rk5 @ AES block 6 - round 5
        aesenmc $enc_ctr_7b, $rk5 @ AES block 7 - round 5

        ldp     $rk6q, $rk7q, [$round_keys_ptr, #96]                     @ load rk6, rk7

        aesenmc $enc_ctr_0b, $rk6 @ AES block 0 - round 6
        aesenmc $enc_ctr_1b, $rk6 @ AES block 1 - round 6
        aesenmc $enc_ctr_2b, $rk6 @ AES block 2 - round 6

        aesenmc $enc_ctr_3b, $rk6 @ AES block 3 - round 6
        aesenmc $enc_ctr_4b, $rk6 @ AES block 4 - round 6
        aesenmc $enc_ctr_5b, $rk6 @ AES block 5 - round 6

        aesenmc $enc_ctr_6b, $rk6 @ AES block 6 - round 6
        aesenmc $enc_ctr_7b, $rk6 @ AES block 7 - round 6

        aesenmc $enc_ctr_0b, $rk7 @ AES block 0 - round 7
        aesenmc $enc_ctr_1b, $rk7 @ AES block 1 - round 7
        aesenmc $enc_ctr_2b, $rk7 @ AES block 2 - round 7

        aesenmc $enc_ctr_3b, $rk7 @ AES block 3 - round 7
        aesenmc $enc_ctr_4b, $rk7 @ AES block 4 - round 7
        aesenmc $enc_ctr_5b, $rk7 @ AES block 5 - round 7

        aesenmc $enc_ctr_6b, $rk7 @ AES block 6 - round 7
        aesenmc $enc_ctr_7b, $rk7 @ AES block 7 - round 7

        ldp     $rk8q, $rk9q, [$round_keys_ptr, #128]                    @ load rk8, rk9

        aesenmc $enc_ctr_0b, $rk8 @ AES block 0 - round 8
        aesenmc $enc_ctr_1b, $rk8 @ AES block 1 - round 8
        aesenmc $enc_ctr_2b, $rk8 @ AES block 2 - round 8

        aesenmc $enc_ctr_3b, $rk8 @ AES block 3 - round 8
        aesenmc $enc_ctr_4b, $rk8 @ AES block 4 - round 8
        aesenmc $enc_ctr_5b, $rk8 @ AES block 5 - round 8

        aesenmc $enc_ctr_6b, $rk8 @ AES block 6 - round 8
        aesenmc $enc_ctr_7b, $rk8 @ AES block 7 - round 8

        ld1     { $acc_lb}, [$current_tag]
        ext     $acc_lb, $acc_lb, $acc_lb, #8
        rev64   $acc_lb, $acc_lb
        ldp     $rk10q, $rk11q, [$round_keys_ptr, #160]                  @ load rk10, rk11

        aesenmc $enc_ctr_0b, $rk9 @ AES block 0 - round 9
        aesenmc $enc_ctr_1b, $rk9 @ AES block 1 - round 9
        aesenmc $enc_ctr_2b, $rk9 @ AES block 2 - round 9

        aesenmc $enc_ctr_3b, $rk9 @ AES block 3 - round 9
        aesenmc $enc_ctr_4b, $rk9 @ AES block 4 - round 9
        aesenmc $enc_ctr_5b, $rk9 @ AES block 5 - round 9

        aesenmc $enc_ctr_6b, $rk9 @ AES block 6 - round 9
        aesenmc $enc_ctr_7b, $rk9 @ AES block 7 - round 9

        aesenmc $enc_ctr_0b, $rk10 @ AES block 0 - round 10
        aesenmc $enc_ctr_1b, $rk10 @ AES block 1 - round 10
        aesenmc $enc_ctr_2b, $rk10 @ AES block 2 - round 10

        aesenmc $enc_ctr_3b, $rk10 @ AES block 3 - round 10
        aesenmc $enc_ctr_4b, $rk10 @ AES block 4 - round 10
        aesenmc $enc_ctr_5b, $rk10 @ AES block 5 - round 10

        aesenmc $enc_ctr_6b, $rk10 @ AES block 6 - round 10
        aesenmc $enc_ctr_7b, $rk10 @ AES block 7 - round 10

        aesenmc $enc_ctr_0b, $rk11 @ AES block 0 - round 11
        aesenmc $enc_ctr_1b, $rk11 @ AES block 1 - round 11
        aesenmc $enc_ctr_2b, $rk11 @ AES block 2 - round 11

        aesenmc $enc_ctr_3b, $rk11 @ AES block 3 - round 11
        aesenmc $enc_ctr_4b, $rk11 @ AES block 4 - round 11
        aesenmc $enc_ctr_5b, $rk11 @ AES block 5 - round 11

        aesenmc $enc_ctr_6b, $rk11 @ AES block 6 - round 11
        aesenmc $enc_ctr_7b, $rk11 @ AES block 7 - round 11

        ldp     $rk12q, $rk13q, [$round_keys_ptr, #192]                  @ load rk12, rk13
        add     $rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s                 @ increment LE counter
        ldr     $rk14q, [$round_keys_ptr, #224]                          @ load rk14

        aesenmc $enc_ctr_0b, $rk12 @ AES block 0 - round 12
        aesenmc $enc_ctr_1b, $rk12 @ AES block 1 - round 12
        aesenmc $enc_ctr_2b, $rk12 @ AES block 2 - round 12

        aesenmc $enc_ctr_3b, $rk12 @ AES block 3 - round 12
        aesenmc $enc_ctr_4b, $rk12 @ AES block 4 - round 12
        aesenmc $enc_ctr_5b, $rk12 @ AES block 5 - round 12

        aesenmc $enc_ctr_6b, $rk12 @ AES block 6 - round 12
        aesenmc $enc_ctr_7b, $rk12 @ AES block 7 - round 12

        aese    $enc_ctr_0b, $rk13                                       @ AES block 0 - round 13
        aese    $enc_ctr_1b, $rk13                                       @ AES block 1 - round 13
        aese    $enc_ctr_2b, $rk13                                       @ AES block 2 - round 13

        aese    $enc_ctr_3b, $rk13                                       @ AES block 3 - round 13
        aese    $enc_ctr_4b, $rk13                                       @ AES block 4 - round 13
        aese    $enc_ctr_5b, $rk13                                       @ AES block 5 - round 13

        aese    $enc_ctr_6b, $rk13                                       @ AES block 6 - round 13
        aese    $enc_ctr_7b, $rk13                                       @ AES block 7 - round 13

        add     $end_input_ptr, $input_ptr, $bit_length, lsr #3          @ end_input_ptr
        cmp     $input_ptr, $main_end_input_ptr                          @ check if we have <= 8 blocks
        b.ge    .L256_enc_tail                                           @ handle tail



        ldp     $pt_0q, $pt_1q, [$input_ptr], #32                        @ AES block 0, 1 - load plaintext

        ldp     $pt_2q, $pt_3q, [$input_ptr], #32                        @ AES block 2, 3 - load plaintext

        eor3    $ct_0b, $pt_0b, $enc_ctr_0b, $rk14                       @ AES block 0 - result
        rev32   $ctr_0.16b, $rtmp_ctr.16b                                @ snapshot LE counter as BE for AES -> ctr_0
        add     $rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s                 @ increment LE counter

        eor3    $ct_1b, $pt_1b, $enc_ctr_1b, $rk14                       @ AES block 1 - result
        eor3    $ct_3b, $pt_3b, $enc_ctr_3b, $rk14                       @ AES block 3 - result

        rev32   $ctr_1.16b, $rtmp_ctr.16b                                @ snapshot LE counter as BE for AES -> ctr_1
        add     $rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s                 @ increment LE counter
        ldp     $pt_4q, $pt_5q, [$input_ptr], #32                        @ AES block 4, 5 - load plaintext

        ldp     $pt_6q, $pt_7q, [$input_ptr], #32                        @ AES block 6, 7 - load plaintext
        eor3    $ct_2b, $pt_2b, $enc_ctr_2b, $rk14                       @ AES block 2 - result
        cmp     $input_ptr, $main_end_input_ptr                          @ check if we have <= 8 blocks

        rev32   $ctr_2.16b, $rtmp_ctr.16b                                @ snapshot LE counter as BE for AES -> ctr_2
        add     $rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s                 @ increment LE counter
        stp     $ct_0q, $ct_1q, [$output_ptr], #32                       @ AES block 0, 1 - store result

        stp     $ct_2q, $ct_3q, [$output_ptr], #32                       @ AES block 2, 3 - store result

        rev32   $ctr_3.16b, $rtmp_ctr.16b                                @ snapshot LE counter as BE for AES -> ctr_3
        add     $rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s                 @ increment LE counter

        eor3    $ct_4b, $pt_4b, $enc_ctr_4b, $rk14                       @ AES block 4 - result

        eor3    $ct_7b, $pt_7b, $enc_ctr_7b, $rk14                       @ AES block 7 - result
        eor3    $ct_6b, $pt_6b, $enc_ctr_6b, $rk14                       @ AES block 6 - result
        eor3    $ct_5b, $pt_5b, $enc_ctr_5b, $rk14                       @ AES block 5 - result

        stp     $ct_4q, $ct_5q, [$output_ptr], #32                       @ AES block 4, 5 - store result
        rev32   $ctr_4.16b, $rtmp_ctr.16b                                @ snapshot LE counter as BE for AES -> ctr_4

        stp     $ct_6q, $ct_7q, [$output_ptr], #32                       @ AES block 6, 7 - store result
        add     $rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s                 @ increment LE counter
        b.ge    .L256_enc_prepretail                                     @ do prepretail

.L256_enc_main_loop:							@ main loop start
        ldp     $rk0q, $rk1q, [$round_keys_ptr, #0]                      @ load rk0, rk1

        rev32   $ctr_5.16b, $rtmp_ctr.16b                                @ snapshot LE counter as BE for AES -> ctr_5
        add     $rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s                 @ increment LE counter
        ldr     $h56kq, [$Htable, #112]                                  @ load h6k | h5k
        ldr     $h78kq, [$Htable, #160]                                  @ load h8k | h7k

        rev64   $ct_3b, $ct_3b                                           @ GHASH block 8k+3
        ldr     $h5q, [$Htable, #96]                                     @ load h5l | h5h
        ldr     $h6q, [$Htable, #128]                                    @ load h6l | h6h
        rev64   $ct_1b, $ct_1b                                           @ GHASH block 8k+1

        rev32   $ctr_6.16b, $rtmp_ctr.16b                                @ snapshot LE counter as BE for AES -> ctr_6
        add     $rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s                 @ increment LE counter
        rev64   $ct_0b, $ct_0b                                           @ GHASH block 8k

        rev64   $ct_4b, $ct_4b                                           @ GHASH block 8k+4
        ext     $acc_lb, $acc_lb, $acc_lb, #8                            @ PRE 0
        ldr     $h7q, [$Htable, #144]                                    @ load h7l | h7h
        ldr     $h8q, [$Htable, #176]                                    @ load h8l | h8h

        aesenmc $enc_ctr_3b, $rk0 @ AES block 8k+11 - round 0
        aesenmc $enc_ctr_5b, $rk0 @ AES block 8k+13 - round 0
        rev32   $ctr_7.16b, $rtmp_ctr.16b                                @ snapshot LE counter as BE for AES -> ctr_7

        aesenmc $enc_ctr_0b, $rk0 @ AES block 8k+8 - round 0
        aesenmc $enc_ctr_1b, $rk0 @ AES block 8k+9 - round 0
        aesenmc $enc_ctr_2b, $rk0 @ AES block 8k+10 - round 0

        aesenmc $enc_ctr_4b, $rk0 @ AES block 8k+12 - round 0
        aesenmc $enc_ctr_6b, $rk0 @ AES block 8k+14 - round 0
        aesenmc $enc_ctr_7b, $rk0 @ AES block 8k+15 - round 0

        ldp     $rk2q, $rk3q, [$round_keys_ptr, #32]                     @ load rk2, rk3
        eor     $ct_0b, $ct_0b, $acc_lb                                  @ PRE 1
        aesenmc $enc_ctr_0b, $rk1 @ AES block 8k+8 - round 1
        aesenmc $enc_ctr_1b, $rk1 @ AES block 8k+9 - round 1
        aesenmc $enc_ctr_2b, $rk1 @ AES block 8k+10 - round 1

        aesenmc $enc_ctr_3b, $rk1 @ AES block 8k+11 - round 1
        aesenmc $enc_ctr_4b, $rk1 @ AES block 8k+12 - round 1
        aesenmc $enc_ctr_5b, $rk1 @ AES block 8k+13 - round 1

        aesenmc $enc_ctr_6b, $rk1 @ AES block 8k+14 - round 1

        pmull2  $acc_h.1q, $ct_0.2d, $h8.2d                              @ GHASH block 8k - high
        pmull   $acc_l.1q, $ct_0.1d, $h8.1d                              @ GHASH block 8k - low
        pmull2  $t0.1q, $ct_1.2d, $h7.2d                                 @ GHASH block 8k+1 - high

        trn1    $acc_m.2d, $ct_1.2d, $ct_0.2d                            @ GHASH block 8k, 8k+1 - mid
        trn2    $ct_0.2d, $ct_1.2d, $ct_0.2d                             @ GHASH block 8k, 8k+1 - mid
        aesenmc $enc_ctr_7b, $rk1 @ AES block 8k+15 - round 1

        aesenmc $enc_ctr_1b, $rk2 @ AES block 8k+9 - round 2
        aesenmc $enc_ctr_2b, $rk2 @ AES block 8k+10 - round 2
        aesenmc $enc_ctr_5b, $rk2 @ AES block 8k+13 - round 2

        aesenmc $enc_ctr_6b, $rk2 @ AES block 8k+14 - round 2
        pmull   $h7.1q, $ct_1.1d, $h7.1d                                 @ GHASH block 8k+1 - low
        aesenmc $enc_ctr_4b, $rk2 @ AES block 8k+12 - round 2

        aesenmc $enc_ctr_5b, $rk3 @ AES block 8k+13 - round 3
        aesenmc $enc_ctr_6b, $rk3 @ AES block 8k+14 - round 3
        aesenmc $enc_ctr_0b, $rk2 @ AES block 8k+8 - round 2

        aesenmc $enc_ctr_1b, $rk3 @ AES block 8k+9 - round 3
        aesenmc $enc_ctr_3b, $rk2 @ AES block 8k+11 - round 2
        aesenmc $enc_ctr_7b, $rk2 @ AES block 8k+15 - round 2

        aesenmc $enc_ctr_4b, $rk3 @ AES block 8k+12 - round 3
        rev64   $ct_6b, $ct_6b                                           @ GHASH block 8k+6
        pmull2  $t2.1q, $ct_3.2d, $h5.2d                                 @ GHASH block 8k+3 - high

        aesenmc $enc_ctr_3b, $rk3 @ AES block 8k+11 - round 3
        ldp     $rk4q, $rk5q, [$round_keys_ptr, #64]                     @ load rk4, rk5
        rev64   $ct_2b, $ct_2b                                           @ GHASH block 8k+2

        aesenmc $enc_ctr_0b, $rk3 @ AES block 8k+8 - round 3
        aesenmc $enc_ctr_2b, $rk3 @ AES block 8k+10 - round 3
        aesenmc $enc_ctr_7b, $rk3 @ AES block 8k+15 - round 3

        eor     $acc_hb, $acc_hb, $t0.16b                                @ GHASH block 8k+1 - high
        pmull2  $t1.1q, $ct_2.2d, $h6.2d                                 @ GHASH block 8k+2 - high
        rev64   $ct_5b, $ct_5b                                           @ GHASH block 8k+5

        pmull   $h5.1q, $ct_3.1d, $h5.1d                                 @ GHASH block 8k+3 - low
        eor     $acc_lb, $acc_lb, $h7.16b                                @ GHASH block 8k+1 - low
        ldr     $h3q, [$Htable, #48]                                     @ load h3l | h3h
        ldr     $h4q, [$Htable, #80]                                     @ load h4l | h4h

        trn1    $t6.2d, $ct_5.2d, $ct_4.2d                               @ GHASH block 8k+4, 8k+5 - mid
        eor3    $acc_hb, $acc_hb, $t1.16b, $t2.16b                       @ GHASH block 8k+2, 8k+3 - high
        pmull   $h6.1q, $ct_2.1d, $h6.1d                                 @ GHASH block 8k+2 - low

        aesenmc $enc_ctr_1b, $rk4 @ AES block 8k+9 - round 4
        aesenmc $enc_ctr_2b, $rk4 @ AES block 8k+10 - round 4
        aesenmc $enc_ctr_3b, $rk4 @ AES block 8k+11 - round 4

        aesenmc $enc_ctr_4b, $rk4 @ AES block 8k+12 - round 4
        aesenmc $enc_ctr_5b, $rk4 @ AES block 8k+13 - round 4
        aesenmc $enc_ctr_7b, $rk4 @ AES block 8k+15 - round 4

        trn1    $t3.2d, $ct_3.2d, $ct_2.2d                               @ GHASH block 8k+2, 8k+3 - mid
        aesenmc $enc_ctr_0b, $rk4 @ AES block 8k+8 - round 4
        aesenmc $enc_ctr_6b, $rk4 @ AES block 8k+14 - round 4

        trn2    $ct_2.2d, $ct_3.2d, $ct_2.2d                             @ GHASH block 8k+2, 8k+3 - mid
        eor     $ct_0.16b, $ct_0.16b, $acc_m.16b                         @ GHASH block 8k, 8k+1 - mid
        ldp     $rk6q, $rk7q, [$round_keys_ptr, #96]                     @ load rk6, rk7

        aesenmc $enc_ctr_4b, $rk5 @ AES block 8k+12 - round 5
        aesenmc $enc_ctr_5b, $rk5 @ AES block 8k+13 - round 5
        aesenmc $enc_ctr_7b, $rk5 @ AES block 8k+15 - round 5

        eor     $ct_2.16b, $ct_2.16b, $t3.16b                            @ GHASH block 8k+2, 8k+3 - mid
        aesenmc $enc_ctr_2b, $rk5 @ AES block 8k+10 - round 5
        rev64   $ct_7b, $ct_7b                                           @ GHASH block 8k+7

        aesenmc $enc_ctr_1b, $rk5 @ AES block 8k+9 - round 5
        aesenmc $enc_ctr_3b, $rk5 @ AES block 8k+11 - round 5
        aesenmc $enc_ctr_6b, $rk5 @ AES block 8k+14 - round 5

        pmull2  $t3.1q, $ct_2.2d, $h56k.2d                               @ GHASH block 8k+2 - mid
        pmull2  $acc_m.1q, $ct_0.2d, $h78k.2d                            @ GHASH block 8k	- mid
        aesenmc $enc_ctr_0b, $rk5 @ AES block 8k+8 - round 5

        pmull   $h78k.1q, $ct_0.1d, $h78k.1d                             @ GHASH block 8k+1 - mid
        aesenmc $enc_ctr_1b, $rk6 @ AES block 8k+9 - round 6
        aesenmc $enc_ctr_2b, $rk6 @ AES block 8k+10 - round 6
        aesenmc $enc_ctr_4b, $rk6 @ AES block 8k+12 - round 6

        aesenmc $enc_ctr_6b, $rk6 @ AES block 8k+14 - round 6
        aesenmc $enc_ctr_7b, $rk6 @ AES block 8k+15 - round 6

        eor     $acc_mb, $acc_mb, $h78k.16b                              @ GHASH block 8k+1 - mid
        pmull   $h56k.1q, $ct_2.1d, $h56k.1d                             @ GHASH block 8k+3 - mid
        aesenmc $enc_ctr_5b, $rk6 @ AES block 8k+13 - round 6

        eor3    $acc_lb, $acc_lb, $h6.16b, $h5.16b                       @ GHASH block 8k+2, 8k+3 - low
        aesenmc $enc_ctr_0b, $rk6 @ AES block 8k+8 - round 6
        aesenmc $enc_ctr_3b, $rk6 @ AES block 8k+11 - round 6

        ldp     $rk8q, $rk9q, [$round_keys_ptr, #128]                    @ load rk8, rk9
        pmull2  $t4.1q, $ct_4.2d, $h4.2d                                 @ GHASH block 8k+4 - high
        aesenmc $enc_ctr_5b, $rk7 @ AES block 8k+13 - round 7

        ldr     $h1q, [$Htable]                                          @ load h1l | h1h
        ldr     $h2q, [$Htable, #32]                                     @ load h2l | h2h
        aesenmc $enc_ctr_2b, $rk7 @ AES block 8k+10 - round 7
        eor3    $acc_mb, $acc_mb, $h56k.16b, $t3.16b                     @ GHASH block 8k+2, 8k+3 - mid

        ldr     $h12kq, [$Htable, #16]                                   @ load h2k | h1k
        ldr     $h34kq, [$Htable, #64]                                   @ load h4k | h3k
        aesenmc $enc_ctr_0b, $rk7 @ AES block 8k+8 - round 7
        aesenmc $enc_ctr_3b, $rk7 @ AES block 8k+11 - round 7
        aesenmc $enc_ctr_6b, $rk7 @ AES block 8k+14 - round 7

        aesenmc $enc_ctr_7b, $rk7 @ AES block 8k+15 - round 7
        pmull   $h4.1q, $ct_4.1d, $h4.1d                                 @ GHASH block 8k+4 - low

        trn2    $ct_4.2d, $ct_5.2d, $ct_4.2d                             @ GHASH block 8k+4, 8k+5 - mid
        aesenmc $enc_ctr_1b, $rk7 @ AES block 8k+9 - round 7
        aesenmc $enc_ctr_4b, $rk7 @ AES block 8k+12 - round 7

        pmull2  $t5.1q, $ct_5.2d, $h3.2d                                 @ GHASH block 8k+5 - high
        aesenmc $enc_ctr_0b, $rk8 @ AES block 8k+8 - round 8
        aesenmc $enc_ctr_7b, $rk8 @ AES block 8k+15 - round 8

        pmull   $h3.1q, $ct_5.1d, $h3.1d                                 @ GHASH block 8k+5 - low
        trn1    $t9.2d, $ct_7.2d, $ct_6.2d                               @ GHASH block 8k+6, 8k+7 - mid
        eor     $ct_4.16b, $ct_4.16b, $t6.16b                            @ GHASH block 8k+4, 8k+5 - mid

        aesenmc $enc_ctr_3b, $rk8 @ AES block 8k+11 - round 8
        aesenmc $enc_ctr_0b, $rk9 @ AES block 8k+8 - round 9
        aesenmc $enc_ctr_1b, $rk8 @ AES block 8k+9 - round 8

        pmull2  $t6.1q, $ct_4.2d, $h34k.2d                               @ GHASH block 8k+4 - mid
        pmull   $h34k.1q, $ct_4.1d, $h34k.1d                             @ GHASH block 8k+5 - mid
        aesenmc $enc_ctr_2b, $rk8 @ AES block 8k+10 - round 8
        aesenmc $enc_ctr_5b, $rk8 @ AES block 8k+13 - round 8
        pmull2  $t7.1q, $ct_6.2d, $h2.2d                                 @ GHASH block 8k+6 - high
        pmull   $h2.1q, $ct_6.1d, $h2.1d                                 @ GHASH block 8k+6 - low

        aesenmc $enc_ctr_6b, $rk8 @ AES block 8k+14 - round 8
        trn2    $ct_6.2d, $ct_7.2d, $ct_6.2d                             @ GHASH block 8k+6, 8k+7 - mid
        aesenmc $enc_ctr_4b, $rk8 @ AES block 8k+12 - round 8

        eor3    $acc_mb, $acc_mb, $h34k.16b, $t6.16b                     @ GHASH block 8k+4, 8k+5 - mid
        aesenmc $enc_ctr_5b, $rk9 @ AES block 8k+13 - round 9
        aesenmc $enc_ctr_7b, $rk9 @ AES block 8k+15 - round 9

        eor     $ct_6.16b, $ct_6.16b, $t9.16b                            @ GHASH block 8k+6, 8k+7 - mid
        aesenmc $enc_ctr_4b, $rk9 @ AES block 8k+12 - round 9
        aesenmc $enc_ctr_6b, $rk9 @ AES block 8k+14 - round 9

        ldp     $rk10q, $rk11q, [$round_keys_ptr, #160]                  @ load rk10, rk11
        aesenmc $enc_ctr_2b, $rk9 @ AES block 8k+10 - round 9
        aesenmc $enc_ctr_3b, $rk9 @ AES block 8k+11 - round 9

        pmull2  $t8.1q, $ct_7.2d, $h1.2d                                 @ GHASH block 8k+7 - high
        eor3    $acc_lb, $acc_lb, $h4.16b, $h3.16b                       @ GHASH block 8k+4, 8k+5 - low
        pmull   $h1.1q, $ct_7.1d, $h1.1d                                 @ GHASH block 8k+7 - low

        ldr     $mod_constantd, [$modulo_constant]                       @ MODULO - load modulo constant
        pmull2  $t9.1q, $ct_6.2d, $h12k.2d                               @ GHASH block 8k+6 - mid
        pmull   $h12k.1q, $ct_6.1d, $h12k.1d                             @ GHASH block 8k+7 - mid

        aesenmc $enc_ctr_1b, $rk9 @ AES block 8k+9 - round 9

        eor3    $acc_mb, $acc_mb, $h12k.16b, $t9.16b                     @ GHASH block 8k+6, 8k+7 - mid
        eor3    $acc_lb, $acc_lb, $h2.16b, $h1.16b                       @ GHASH block 8k+6, 8k+7 - low
        eor3    $acc_hb, $acc_hb, $t4.16b, $t5.16b                       @ GHASH block 8k+4, 8k+5 - high

        aesenmc $enc_ctr_0b, $rk10 @ AES block 8k+8 - round 10
        aesenmc $enc_ctr_2b, $rk10 @ AES block 8k+10 - round 10
        aesenmc $enc_ctr_3b, $rk10 @ AES block 8k+11 - round 10

        aesenmc $enc_ctr_4b, $rk10 @ AES block 8k+12 - round 10
        aesenmc $enc_ctr_5b, $rk10 @ AES block 8k+13 - round 10
        add     $rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s                 @ increment LE counter

        aesenmc $enc_ctr_1b, $rk10 @ AES block 8k+9 - round 10
        aesenmc $enc_ctr_6b, $rk10 @ AES block 8k+14 - round 10
        aesenmc $enc_ctr_7b, $rk10 @ AES block 8k+15 - round 10

        eor3    $acc_hb, $acc_hb, $t7.16b, $t8.16b                       @ GHASH block 8k+6, 8k+7 - high

        ldp     $rk12q, $rk13q, [$round_keys_ptr, #192]                  @ load rk12, rk13
        rev32   $h1.16b, $rtmp_ctr.16b                                   @ snapshot LE counter as BE -> h1 (temp storage for ctr)

        ext     $t11.16b, $acc_hb, $acc_hb, #8                           @ MODULO - other top alignment
        ldp     $pt_0q, $pt_1q, [$input_ptr], #32                        @ AES block 8k+8, 8k+9 - load plaintext
        aesenmc $enc_ctr_2b, $rk11 @ AES block 8k+10 - round 11
        aesenmc $enc_ctr_6b, $rk11 @ AES block 8k+14 - round 11
        add     $rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s                 @ increment LE counter
        aesenmc $enc_ctr_0b, $rk11 @ AES block 8k+8 - round 11
        aesenmc $enc_ctr_3b, $rk11 @ AES block 8k+11 - round 11
        aesenmc $enc_ctr_7b, $rk11 @ AES block 8k+15 - round 11

        pmull   $t12.1q, $acc_h.1d, $mod_constant.1d                     @ MODULO - top 64b align with mid
        aesenmc $enc_ctr_1b, $rk11 @ AES block 8k+9 - round 11

        aesenmc $enc_ctr_7b, $rk12 @ AES block 8k+15 - round 12
        aesenmc $enc_ctr_5b, $rk11 @ AES block 8k+13 - round 11

        aesenmc $enc_ctr_3b, $rk12 @ AES block 8k+11 - round 12
        aesenmc $enc_ctr_6b, $rk12 @ AES block 8k+14 - round 12
        rev32   $h2.16b, $rtmp_ctr.16b                                   @ snapshot LE counter as BE -> h2 (temp storage for ctr)

        add     $rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s                 @ increment LE counter
        aesenmc $enc_ctr_4b, $rk11 @ AES block 8k+12 - round 11
        eor3    $acc_mb, $acc_mb, $acc_hb, $acc_lb                       @ MODULO - karatsuba tidy up

        aesenmc $enc_ctr_5b, $rk12 @ AES block 8k+13 - round 12
        ldr     $rk14q, [$round_keys_ptr, #224]                          @ load rk14
        aese    $enc_ctr_7b, $rk13                                       @ AES block 8k+15 - round 13

        ldp     $pt_2q, $pt_3q, [$input_ptr], #32                        @ AES block 8k+10, 8k+11 - load plaintext
        aesenmc $enc_ctr_2b, $rk12 @ AES block 8k+10 - round 12
        aesenmc $enc_ctr_4b, $rk12 @ AES block 8k+12 - round 12

        eor3    $acc_mb, $acc_mb, $t12.16b, $t11.16b                     @ MODULO - fold into mid
        aesenmc $enc_ctr_1b, $rk12 @ AES block 8k+9 - round 12
        ldp     $pt_4q, $pt_5q, [$input_ptr], #32                        @ AES block 4, 5 - load plaintext

        ldp     $pt_6q, $pt_7q, [$input_ptr], #32                        @ AES block 6, 7 - load plaintext
        aese    $enc_ctr_2b, $rk13                                       @ AES block 8k+10 - round 13
        aese    $enc_ctr_4b, $rk13                                       @ AES block 8k+12 - round 13

        rev32   $h3.16b, $rtmp_ctr.16b                                   @ snapshot LE counter as BE -> h3 (temp storage for ctr)
        add     $rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s                 @ increment LE counter
        aese    $enc_ctr_5b, $rk13                                       @ AES block 8k+13 - round 13

        aesenmc $enc_ctr_0b, $rk12 @ AES block 8k+8 - round 12
        aese    $enc_ctr_3b, $rk13                                       @ AES block 8k+11 - round 13
        cmp     $input_ptr, $main_end_input_ptr                          @ LOOP CONTROL

        eor3    $ct_2b, $pt_2b, $enc_ctr_2b, $rk14                       @ AES block 8k+10 - result
        rev32   $h4.16b, $rtmp_ctr.16b                                   @ snapshot LE counter as BE -> h4 (temp storage for ctr)
        add     $rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s                 @ increment LE counter

        aese    $enc_ctr_0b, $rk13                                       @ AES block 8k+8 - round 13
        aese    $enc_ctr_6b, $rk13                                       @ AES block 8k+14 - round 13
        eor3    $ct_5b, $pt_5b, $enc_ctr_5b, $rk14                       @ AES block 5 - result

        ext     $t11.16b, $acc_mb, $acc_mb, #8                           @ MODULO - other mid alignment
        pmull   $acc_h.1q, $acc_m.1d, $mod_constant.1d                   @ MODULO - mid 64b align with low
        aese    $enc_ctr_1b, $rk13                                       @ AES block 8k+9 - round 13

        eor3    $ct_4b, $pt_4b, $enc_ctr_4b, $rk14                       @ AES block 4 - result
        rev32   $ctr_4.16b, $rtmp_ctr.16b                                @ snapshot LE counter as BE for AES -> ctr_4
        eor3    $ct_3b, $pt_3b, $enc_ctr_3b, $rk14                       @ AES block 8k+11 - result

        mov     $ctr_3.16b, $h4.16b                                      @ copy prepared BE counter from h4 -> ctr_3
        eor3    $ct_1b, $pt_1b, $enc_ctr_1b, $rk14                       @ AES block 8k+9 - result
        eor3    $ct_0b, $pt_0b, $enc_ctr_0b, $rk14                       @ AES block 8k+8 - result

        add     $rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s                 @ increment LE counter
        stp     $ct_0q, $ct_1q, [$output_ptr], #32                       @ AES block 8k+8, 8k+9 - store result
        mov     $ctr_2.16b, $h3.16b                                      @ copy prepared BE counter from h3 -> ctr_2

        eor3    $ct_7b, $pt_7b, $enc_ctr_7b, $rk14                       @ AES block 7 - result
        eor3    $acc_lb, $acc_lb, $t11.16b, $acc_hb                      @ MODULO - fold into low
        stp     $ct_2q, $ct_3q, [$output_ptr], #32                       @ AES block 8k+10, 8k+11 - store result

        eor3    $ct_6b, $pt_6b, $enc_ctr_6b, $rk14                       @ AES block 6 - result
        mov     $ctr_1.16b, $h2.16b                                      @ copy prepared BE counter from h2 -> ctr_1
        stp     $ct_4q, $ct_5q, [$output_ptr], #32                       @ AES block 4, 5 - store result

        stp     $ct_6q, $ct_7q, [$output_ptr], #32                       @ AES block 6, 7 - store result
        mov     $ctr_0.16b, $h1.16b                                      @ copy prepared BE counter from h1 -> ctr_0
        b.lt    .L256_enc_main_loop

.L256_enc_prepretail:							@ PREPRETAIL
        rev32   $ctr_5.16b, $rtmp_ctr.16b                                @ snapshot LE counter as BE for AES -> ctr_5
        ldp     $rk0q, $rk1q, [$round_keys_ptr, #0]                      @ load rk0, rk1
        add     $rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s                 @ increment LE counter

        rev64   $ct_2b, $ct_2b                                           @ GHASH block 8k+2

        rev32   $ctr_6.16b, $rtmp_ctr.16b                                @ snapshot LE counter as BE for AES -> ctr_6
        add     $rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s                 @ increment LE counter

        rev64   $ct_5b, $ct_5b                                           @ GHASH block 8k+5
        ldr     $h56kq, [$Htable, #112]                                  @ load h6k | h5k
        ldr     $h78kq, [$Htable, #160]                                  @ load h8k | h7k

        rev32   $ctr_7.16b, $rtmp_ctr.16b                                @ snapshot LE counter as BE for AES -> ctr_7

        aesenmc $enc_ctr_0b, $rk0 @ AES block 8k+8 - round 0
        aesenmc $enc_ctr_1b, $rk0 @ AES block 8k+9 - round 0
        aesenmc $enc_ctr_2b, $rk0 @ AES block 8k+10 - round 0

        aesenmc $enc_ctr_3b, $rk0 @ AES block 8k+11 - round 0
        aesenmc $enc_ctr_4b, $rk0 @ AES block 8k+12 - round 0
        aesenmc $enc_ctr_5b, $rk0 @ AES block 8k+13 - round 0

        aesenmc $enc_ctr_6b, $rk0 @ AES block 8k+14 - round 0
        aesenmc $enc_ctr_7b, $rk0 @ AES block 8k+15 - round 0

        ext     $acc_lb, $acc_lb, $acc_lb, #8                            @ PRE 0
        rev64   $ct_0b, $ct_0b                                           @ GHASH block 8k
        aesenmc $enc_ctr_1b, $rk1 @ AES block 8k+9 - round 1

        rev64   $ct_1b, $ct_1b                                           @ GHASH block 8k+1
        ldp     $rk2q, $rk3q, [$round_keys_ptr, #32]                     @ load rk2, rk3
        aesenmc $enc_ctr_3b, $rk1 @ AES block 8k+11 - round 1

        ldr     $h7q, [$Htable, #144]                                    @ load h7l | h7h
        ldr     $h8q, [$Htable, #176]                                    @ load h8l | h8h
        aesenmc $enc_ctr_2b, $rk1 @ AES block 8k+10 - round 1

        ldr     $h5q, [$Htable, #96]                                     @ load h5l | h5h
        ldr     $h6q, [$Htable, #128]                                    @ load h6l | h6h
        aesenmc $enc_ctr_0b, $rk1 @ AES block 8k+8 - round 1
        aesenmc $enc_ctr_4b, $rk1 @ AES block 8k+12 - round 1
        aesenmc $enc_ctr_5b, $rk1 @ AES block 8k+13 - round 1
        eor     $ct_0b, $ct_0b, $acc_lb                                  @ PRE 1

        rev64   $ct_3b, $ct_3b                                           @ GHASH block 8k+3
        aesenmc $enc_ctr_6b, $rk1 @ AES block 8k+14 - round 1

        aesenmc $enc_ctr_1b, $rk2 @ AES block 8k+9 - round 2
        aesenmc $enc_ctr_2b, $rk2 @ AES block 8k+10 - round 2
        aesenmc $enc_ctr_7b, $rk1 @ AES block 8k+15 - round 1

        aesenmc $enc_ctr_0b, $rk2 @ AES block 8k+8 - round 2
        aesenmc $enc_ctr_3b, $rk2 @ AES block 8k+11 - round 2
        aesenmc $enc_ctr_4b, $rk2 @ AES block 8k+12 - round 2

        aesenmc $enc_ctr_5b, $rk2 @ AES block 8k+13 - round 2
        aesenmc $enc_ctr_6b, $rk2 @ AES block 8k+14 - round 2
        aesenmc $enc_ctr_7b, $rk2 @ AES block 8k+15 - round 2

        ldp     $rk4q, $rk5q, [$round_keys_ptr, #64]                     @ load rk4, rk5
        trn1    $acc_m.2d, $ct_1.2d, $ct_0.2d                            @ GHASH block 8k, 8k+1 - mid
        pmull2  $acc_h.1q, $ct_0.2d, $h8.2d                              @ GHASH block 8k - high

        rev64   $ct_6b, $ct_6b                                           @ GHASH block 8k+6
        aesenmc $enc_ctr_4b, $rk3 @ AES block 8k+12 - round 3
        pmull2  $t0.1q, $ct_1.2d, $h7.2d                                 @ GHASH block 8k+1 - high

        aesenmc $enc_ctr_7b, $rk3 @ AES block 8k+15 - round 3
        pmull   $acc_l.1q, $ct_0.1d, $h8.1d                              @ GHASH block 8k - low
        trn2    $ct_0.2d, $ct_1.2d, $ct_0.2d                             @ GHASH block 8k, 8k+1 - mid

        pmull2  $t1.1q, $ct_2.2d, $h6.2d                                 @ GHASH block 8k+2 - high
        aesenmc $enc_ctr_2b, $rk3 @ AES block 8k+10 - round 3
        aesenmc $enc_ctr_3b, $rk3 @ AES block 8k+11 - round 3
        aesenmc $enc_ctr_6b, $rk3 @ AES block 8k+14 - round 3
        eor     $acc_hb, $acc_hb, $t0.16b                                @ GHASH block 8k+1 - high

        pmull   $h7.1q, $ct_1.1d, $h7.1d                                 @ GHASH block 8k+1 - low
        pmull2  $t2.1q, $ct_3.2d, $h5.2d                                 @ GHASH block 8k+3 - high
        aesenmc $enc_ctr_0b, $rk3 @ AES block 8k+8 - round 3
        aesenmc $enc_ctr_1b, $rk3 @ AES block 8k+9 - round 3
        eor     $ct_0.16b, $ct_0.16b, $acc_m.16b                         @ GHASH block 8k, 8k+1 - mid
        aesenmc $enc_ctr_5b, $rk3 @ AES block 8k+13 - round 3

        pmull   $h6.1q, $ct_2.1d, $h6.1d                                 @ GHASH block 8k+2 - low
        aesenmc $enc_ctr_0b, $rk4 @ AES block 8k+8 - round 4
        aesenmc $enc_ctr_1b, $rk4 @ AES block 8k+9 - round 4
        aesenmc $enc_ctr_2b, $rk4 @ AES block 8k+10 - round 4

        aesenmc $enc_ctr_4b, $rk4 @ AES block 8k+12 - round 4
        aesenmc $enc_ctr_6b, $rk4 @ AES block 8k+14 - round 4

        aesenmc $enc_ctr_6b, $rk5 @ AES block 8k+14 - round 5
        pmull2  $acc_m.1q, $ct_0.2d, $h78k.2d                            @ GHASH block 8k	- mid
        eor3    $acc_hb, $acc_hb, $t1.16b, $t2.16b                       @ GHASH block 8k+2, 8k+3 - high

        aesenmc $enc_ctr_7b, $rk4 @ AES block 8k+15 - round 4
        trn1    $t3.2d, $ct_3.2d, $ct_2.2d                               @ GHASH block 8k+2, 8k+3 - mid
        trn2    $ct_2.2d, $ct_3.2d, $ct_2.2d                             @ GHASH block 8k+2, 8k+3 - mid

        aesenmc $enc_ctr_5b, $rk4 @ AES block 8k+13 - round 4
        eor     $acc_lb, $acc_lb, $h7.16b                                @ GHASH block 8k+1 - low
        aesenmc $enc_ctr_3b, $rk4 @ AES block 8k+11 - round 4

        pmull   $h5.1q, $ct_3.1d, $h5.1d                                 @ GHASH block 8k+3 - low
        pmull   $h78k.1q, $ct_0.1d, $h78k.1d                             @ GHASH block 8k+1 - mid
        eor     $ct_2.16b, $ct_2.16b, $t3.16b                            @ GHASH block 8k+2, 8k+3 - mid

        rev64   $ct_4b, $ct_4b                                           @ GHASH block 8k+4
        aesenmc $enc_ctr_0b, $rk5 @ AES block 8k+8 - round 5
        aesenmc $enc_ctr_1b, $rk5 @ AES block 8k+9 - round 5
        aesenmc $enc_ctr_4b, $rk5 @ AES block 8k+12 - round 5

        aesenmc $enc_ctr_7b, $rk5 @ AES block 8k+15 - round 5
        ldp     $rk6q, $rk7q, [$round_keys_ptr, #96]                     @ load rk6, rk7

        ldr     $h3q, [$Htable, #48]                                     @ load h3l | h3h
        ldr     $h4q, [$Htable, #80]                                     @ load h4l | h4h
        pmull2  $t3.1q, $ct_2.2d, $h56k.2d                               @ GHASH block 8k+2 - mid
        pmull   $h56k.1q, $ct_2.1d, $h56k.1d                             @ GHASH block 8k+3 - mid

        eor3    $acc_lb, $acc_lb, $h6.16b, $h5.16b                       @ GHASH block 8k+2, 8k+3 - low
        eor     $acc_mb, $acc_mb, $h78k.16b                              @ GHASH block 8k+1 - mid

        aesenmc $enc_ctr_5b, $rk5 @ AES block 8k+13 - round 5
        rev64   $ct_7b, $ct_7b                                           @ GHASH block 8k+7
        trn1    $t6.2d, $ct_5.2d, $ct_4.2d                               @ GHASH block 8k+4, 8k+5 - mid

        aesenmc $enc_ctr_2b, $rk5 @ AES block 8k+10 - round 5
        aesenmc $enc_ctr_3b, $rk5 @ AES block 8k+11 - round 5
        eor3    $acc_mb, $acc_mb, $h56k.16b, $t3.16b                     @ GHASH block 8k+2, 8k+3 - mid

        aesenmc $enc_ctr_4b, $rk6 @ AES block 8k+12 - round 6
        aesenmc $enc_ctr_6b, $rk6 @ AES block 8k+14 - round 6
        aesenmc $enc_ctr_7b, $rk6 @ AES block 8k+15 - round 6

        ldr     $h12kq, [$Htable, #16]                                   @ load h2k | h1k
        ldr     $h34kq, [$Htable, #64]                                   @ load h4k | h3k
        aesenmc $enc_ctr_0b, $rk6 @ AES block 8k+8 - round 6
        aesenmc $enc_ctr_1b, $rk6 @ AES block 8k+9 - round 6
        aesenmc $enc_ctr_2b, $rk6 @ AES block 8k+10 - round 6

        aesenmc $enc_ctr_3b, $rk6 @ AES block 8k+11 - round 6
        aesenmc $enc_ctr_5b, $rk6 @ AES block 8k+13 - round 6

        pmull2  $t4.1q, $ct_4.2d, $h4.2d                                 @ GHASH block 8k+4 - high
        pmull   $h4.1q, $ct_4.1d, $h4.1d                                 @ GHASH block 8k+4 - low
        ldr     $h1q, [$Htable]                                          @ load h1l | h1h
        ldr     $h2q, [$Htable, #32]                                     @ load h2l | h2h

        ldp     $rk8q, $rk9q, [$round_keys_ptr, #128]                    @ load rk8, rk9
        aesenmc $enc_ctr_1b, $rk7 @ AES block 8k+9 - round 7
        aesenmc $enc_ctr_4b, $rk7 @ AES block 8k+12 - round 7

        pmull2  $t5.1q, $ct_5.2d, $h3.2d                                 @ GHASH block 8k+5 - high
        trn2    $ct_4.2d, $ct_5.2d, $ct_4.2d                             @ GHASH block 8k+4, 8k+5 - mid

        aesenmc $enc_ctr_5b, $rk7 @ AES block 8k+13 - round 7
        aesenmc $enc_ctr_6b, $rk7 @ AES block 8k+14 - round 7
        pmull   $h3.1q, $ct_5.1d, $h3.1d                                 @ GHASH block 8k+5 - low

        aesenmc $enc_ctr_3b, $rk7 @ AES block 8k+11 - round 7
        aesenmc $enc_ctr_7b, $rk7 @ AES block 8k+15 - round 7
        eor     $ct_4.16b, $ct_4.16b, $t6.16b                            @ GHASH block 8k+4, 8k+5 - mid

        pmull2  $t7.1q, $ct_6.2d, $h2.2d                                 @ GHASH block 8k+6 - high
        pmull   $h2.1q, $ct_6.1d, $h2.1d                                 @ GHASH block 8k+6 - low
        aesenmc $enc_ctr_2b, $rk7 @ AES block 8k+10 - round 7

        trn1    $t9.2d, $ct_7.2d, $ct_6.2d                               @ GHASH block 8k+6, 8k+7 - mid
        trn2    $ct_6.2d, $ct_7.2d, $ct_6.2d                             @ GHASH block 8k+6, 8k+7 - mid
        aesenmc $enc_ctr_0b, $rk7 @ AES block 8k+8 - round 7

        aesenmc $enc_ctr_7b, $rk8 @ AES block 8k+15 - round 8
        eor3    $acc_lb, $acc_lb, $h4.16b, $h3.16b                       @ GHASH block 8k+4, 8k+5 - low
        aesenmc $enc_ctr_2b, $rk8 @ AES block 8k+10 - round 8
        aesenmc $enc_ctr_3b, $rk8 @ AES block 8k+11 - round 8
        aesenmc $enc_ctr_4b, $rk8 @ AES block 8k+12 - round 8

        aesenmc $enc_ctr_5b, $rk8 @ AES block 8k+13 - round 8
        aesenmc $enc_ctr_6b, $rk8 @ AES block 8k+14 - round 8
        eor     $ct_6.16b, $ct_6.16b, $t9.16b                            @ GHASH block 8k+6, 8k+7 - mid
        aesenmc $enc_ctr_0b, $rk8 @ AES block 8k+8 - round 8

        pmull2  $t6.1q, $ct_4.2d, $h34k.2d                               @ GHASH block 8k+4 - mid
        pmull   $h34k.1q, $ct_4.1d, $h34k.1d                             @ GHASH block 8k+5 - mid
        aesenmc $enc_ctr_1b, $rk8 @ AES block 8k+9 - round 8

        pmull2  $t8.1q, $ct_7.2d, $h1.2d                                 @ GHASH block 8k+7 - high
        pmull2  $t9.1q, $ct_6.2d, $h12k.2d                               @ GHASH block 8k+6 - mid
        pmull   $h12k.1q, $ct_6.1d, $h12k.1d                             @ GHASH block 8k+7 - mid

        pmull   $h1.1q, $ct_7.1d, $h1.1d                                 @ GHASH block 8k+7 - low
        eor3    $acc_mb, $acc_mb, $h34k.16b, $t6.16b                     @ GHASH block 8k+4, 8k+5 - mid
        eor3    $acc_hb, $acc_hb, $t4.16b, $t5.16b                       @ GHASH block 8k+4, 8k+5 - high

        ldp     $rk10q, $rk11q, [$round_keys_ptr, #160]                  @ load rk10, rk11
        aesenmc $enc_ctr_0b, $rk9 @ AES block 8k+8 - round 9
        aesenmc $enc_ctr_1b, $rk9 @ AES block 8k+9 - round 9

        eor3    $acc_hb, $acc_hb, $t7.16b, $t8.16b                       @ GHASH block 8k+6, 8k+7 - high
        eor3    $acc_mb, $acc_mb, $h12k.16b, $t9.16b                     @ GHASH block 8k+6, 8k+7 - mid
        ldr     $mod_constantd, [$modulo_constant]                       @ MODULO - load modulo constant

        eor3    $acc_lb, $acc_lb, $h2.16b, $h1.16b                       @ GHASH block 8k+6, 8k+7 - low

        aesenmc $enc_ctr_2b, $rk9 @ AES block 8k+10 - round 9
        aesenmc $enc_ctr_3b, $rk9 @ AES block 8k+11 - round 9
        aesenmc $enc_ctr_5b, $rk9 @ AES block 8k+13 - round 9

        aesenmc $enc_ctr_6b, $rk9 @ AES block 8k+14 - round 9
        aesenmc $enc_ctr_7b, $rk9 @ AES block 8k+15 - round 9

        aesenmc $enc_ctr_1b, $rk10 @ AES block 8k+9 - round 10
        aesenmc $enc_ctr_5b, $rk10 @ AES block 8k+13 - round 10
        aesenmc $enc_ctr_4b, $rk9 @ AES block 8k+12 - round 9

        aesenmc $enc_ctr_0b, $rk10 @ AES block 8k+8 - round 10
        aesenmc $enc_ctr_2b, $rk10 @ AES block 8k+10 - round 10
        aesenmc $enc_ctr_3b, $rk10 @ AES block 8k+11 - round 10

        aesenmc $enc_ctr_4b, $rk10 @ AES block 8k+12 - round 10
        aesenmc $enc_ctr_6b, $rk10 @ AES block 8k+14 - round 10
        aesenmc $enc_ctr_7b, $rk10 @ AES block 8k+15 - round 10

        pmull   $t12.1q, $acc_h.1d, $mod_constant.1d                     @ MODULO - top 64b align with mid
        eor3    $acc_mb, $acc_mb, $acc_hb, $acc_lb                       @ MODULO - karatsuba tidy up
        aesenmc $enc_ctr_7b, $rk11 @ AES block 8k+15 - round 11

        ldp     $rk12q, $rk13q, [$round_keys_ptr, #192]                  @ load rk12, rk13
        ext     $t11.16b, $acc_hb, $acc_hb, #8                           @ MODULO - other top alignment
        aesenmc $enc_ctr_2b, $rk11 @ AES block 8k+10 - round 11

        eor3    $acc_mb, $acc_mb, $t12.16b, $t11.16b                     @ MODULO - fold into mid
        aesenmc $enc_ctr_0b, $rk11 @ AES block 8k+8 - round 11
        aesenmc $enc_ctr_1b, $rk11 @ AES block 8k+9 - round 11
        aesenmc $enc_ctr_4b, $rk11 @ AES block 8k+12 - round 11

        aesenmc $enc_ctr_5b, $rk11 @ AES block 8k+13 - round 11
        aesenmc $enc_ctr_6b, $rk11 @ AES block 8k+14 - round 11

        pmull   $acc_h.1q, $acc_m.1d, $mod_constant.1d                   @ MODULO - mid 64b align with low
        aesenmc $enc_ctr_3b, $rk11 @ AES block 8k+11 - round 11
        ldr     $rk14q, [$round_keys_ptr, #224]                          @ load rk14

        aesenmc $enc_ctr_0b, $rk12 @ AES block 8k+8 - round 12
        aesenmc $enc_ctr_1b, $rk12 @ AES block 8k+9 - round 12
        aesenmc $enc_ctr_2b, $rk12 @ AES block 8k+10 - round 12

        aesenmc $enc_ctr_5b, $rk12 @ AES block 8k+13 - round 12
        aesenmc $enc_ctr_6b, $rk12 @ AES block 8k+14 - round 12
        ext     $t11.16b, $acc_mb, $acc_mb, #8                           @ MODULO - other mid alignment

        aesenmc $enc_ctr_4b, $rk12 @ AES block 8k+12 - round 12
        add     $rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s                 @ increment LE counter

        aesenmc $enc_ctr_3b, $rk12 @ AES block 8k+11 - round 12
        aesenmc $enc_ctr_7b, $rk12 @ AES block 8k+15 - round 12
        aese    $enc_ctr_0b, $rk13                                       @ AES block 8k+8 - round 13

        eor3    $acc_lb, $acc_lb, $t11.16b, $acc_hb                      @ MODULO - fold into low
        aese    $enc_ctr_1b, $rk13                                       @ AES block 8k+9 - round 13
        aese    $enc_ctr_2b, $rk13                                       @ AES block 8k+10 - round 13
        aese    $enc_ctr_3b, $rk13                                       @ AES block 8k+11 - round 13

        aese    $enc_ctr_4b, $rk13                                       @ AES block 8k+12 - round 13
        aese    $enc_ctr_5b, $rk13                                       @ AES block 8k+13 - round 13
        aese    $enc_ctr_6b, $rk13                                       @ AES block 8k+14 - round 13

        aese    $enc_ctr_7b, $rk13                                       @ AES block 8k+15 - round 13
.L256_enc_tail:								@ TAIL

        ldp     $h78kq, $h8q, [$Htable, #160]                            @ load h8l | h8h
        sub     $main_end_input_ptr, $end_input_ptr, $input_ptr          @ main_end_input_ptr is number of bytes left to process
        cbz     $main_end_input_ptr, .L256_enc_blocks_none               @ no remaining blocks, skip to tag store

        ldr     $pt_0q, [$input_ptr], #16                                @ AES block 8k+8 - load plaintext

        ldp     $h5q, $h56kq, [$Htable, #96]                             @ load h5l | h5h

        ext     $t0.16b, $acc_lb, $acc_lb, #8                            @ prepare final partial tag
        ldp     $h6q, $h7q, [$Htable, #128]                              @ load h6l | h6h
        mov     $t1.16b, $rk14

        cmp     $main_end_input_ptr, #112
        eor3    $ct_1b, $pt_0b, $enc_ctr_0b, $t1.16b                     @ AES block 8k+8 - result
        b.gt    .L256_enc_blocks_more_than_7

        movi    $acc_l.8b, #0
        mov     $enc_ctr_7b, $enc_ctr_6b
        movi    $acc_h.8b, #0

        mov     $enc_ctr_6b, $enc_ctr_5b
        mov     $enc_ctr_5b, $enc_ctr_4b
        mov     $enc_ctr_4b, $enc_ctr_3b

        mov     $enc_ctr_3b, $enc_ctr_2b
        sub     $rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s
        mov     $enc_ctr_2b, $enc_ctr_1b

        movi    $acc_m.8b, #0
        cmp     $main_end_input_ptr, #96
        b.gt    .L256_enc_blocks_more_than_6

        mov     $enc_ctr_7b, $enc_ctr_6b
        mov     $enc_ctr_6b, $enc_ctr_5b
        cmp     $main_end_input_ptr, #80

        mov     $enc_ctr_5b, $enc_ctr_4b
        mov     $enc_ctr_4b, $enc_ctr_3b
        mov     $enc_ctr_3b, $enc_ctr_1b

        sub     $rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s
        b.gt    .L256_enc_blocks_more_than_5

        mov     $enc_ctr_7b, $enc_ctr_6b
        sub     $rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s

        mov     $enc_ctr_6b, $enc_ctr_5b
        mov     $enc_ctr_5b, $enc_ctr_4b

        cmp     $main_end_input_ptr, #64
        mov     $enc_ctr_4b, $enc_ctr_1b
        b.gt    .L256_enc_blocks_more_than_4

        cmp     $main_end_input_ptr, #48
        mov     $enc_ctr_7b, $enc_ctr_6b
        mov     $enc_ctr_6b, $enc_ctr_5b

        mov     $enc_ctr_5b, $enc_ctr_1b
        sub     $rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s
        b.gt    .L256_enc_blocks_more_than_3

        cmp     $main_end_input_ptr, #32
        mov     $enc_ctr_7b, $enc_ctr_6b
        ldr     $h34kq, [$Htable, #64]                                   @ load h4k | h3k

        mov     $enc_ctr_6b, $enc_ctr_1b
        sub     $rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s
        b.gt    .L256_enc_blocks_more_than_2

        mov     $enc_ctr_7b, $enc_ctr_1b

        sub     $rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s
        cmp     $main_end_input_ptr, #16
        b.gt    .L256_enc_blocks_more_than_1

        sub     $rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s
        ldr     $h12kq, [$Htable, #16]                                   @ load h2k | h1k
        b        .L256_enc_blocks_less_than_1
.L256_enc_blocks_more_than_7:						@ blocks left >  7
        st1     { $ct_1b}, [$output_ptr], #16                            @ AES final-7 block  - store result

        rev64   $ct_0b, $ct_1b                                           @ GHASH final-7 block

        eor     $ct_0b, $ct_0b, $t0.16b                                  @ feed in partial tag

        ldr     $pt_1q, [$input_ptr], #16                                @ AES final-6 block - load plaintext

        pmull2  $acc_h.1q, $ct_0.2d, $h8.2d                              @ GHASH final-7 block - high
        ins     $rk4v.d[0], $ct_0.d[1]                                   @ GHASH final-7 block - mid
        ins     $acc_m.d[0], $h78k.d[1]                                  @ GHASH final-7 block - mid

        movi    $t0.8b, #0                                               @ supress further partial tag feed in

        eor     $rk4v.8b, $rk4v.8b, $ct_0.8b                             @ GHASH final-7 block - mid
        eor3    $ct_1b, $pt_1b, $enc_ctr_1b, $t1.16b                     @ AES final-6 block - result

        pmull   $acc_m.1q, $rk4v.1d, $acc_m.1d                           @ GHASH final-7 block - mid
        pmull   $acc_l.1q, $ct_0.1d, $h8.1d                              @ GHASH final-7 block - low
.L256_enc_blocks_more_than_6:						@ blocks left >  6

        st1     { $ct_1b}, [$output_ptr], #16                            @ AES final-6 block - store result

        rev64   $ct_0b, $ct_1b                                           @ GHASH final-6 block

        eor     $ct_0b, $ct_0b, $t0.16b                                  @ feed in partial tag

        pmull   $rk3q1, $ct_0.1d, $h7.1d                                 @ GHASH final-6 block - low
        ins     $rk4v.d[0], $ct_0.d[1]                                   @ GHASH final-6 block - mid
        pmull2  $rk2q1, $ct_0.2d, $h7.2d                                 @ GHASH final-6 block - high

        ldr     $pt_1q, [$input_ptr], #16                                @ AES final-5 block - load plaintext

        eor     $acc_lb, $acc_lb, $rk3                                   @ GHASH final-6 block - low

        eor     $rk4v.8b, $rk4v.8b, $ct_0.8b                             @ GHASH final-6 block - mid

        pmull   $rk4v.1q, $rk4v.1d, $h78k.1d                             @ GHASH final-6 block - mid
        eor3    $ct_1b, $pt_1b, $enc_ctr_2b, $t1.16b                     @ AES final-5 block - result

        movi    $t0.8b, #0                                               @ supress further partial tag feed in

        eor     $acc_mb, $acc_mb, $rk4v.16b                              @ GHASH final-6 block - mid
        eor     $acc_hb, $acc_hb, $rk2                                   @ GHASH final-6 block - high
.L256_enc_blocks_more_than_5:						@ blocks left >  5

        st1     { $ct_1b}, [$output_ptr], #16                            @ AES final-5 block - store result

        rev64   $ct_0b, $ct_1b                                           @ GHASH final-5 block

        eor     $ct_0b, $ct_0b, $t0.16b                                  @ feed in partial tag

        ins     $rk4v.d[0], $ct_0.d[1]                                   @ GHASH final-5 block - mid

        pmull2  $rk2q1, $ct_0.2d, $h6.2d                                 @ GHASH final-5 block - high

        eor     $acc_hb, $acc_hb, $rk2                                   @ GHASH final-5 block - high
        eor     $rk4v.8b, $rk4v.8b, $ct_0.8b                             @ GHASH final-5 block - mid

        ins     $rk4v.d[1], $rk4v.d[0]                                   @ GHASH final-5 block - mid

        ldr     $pt_1q, [$input_ptr], #16                                @ AES final-4 block - load plaintext
        pmull   $rk3q1, $ct_0.1d, $h6.1d                                 @ GHASH final-5 block - low

        pmull2  $rk4v.1q, $rk4v.2d, $h56k.2d                             @ GHASH final-5 block - mid
        movi    $t0.8b, #0                                               @ supress further partial tag feed in
        eor     $acc_lb, $acc_lb, $rk3                                   @ GHASH final-5 block - low

        eor     $acc_mb, $acc_mb, $rk4v.16b                              @ GHASH final-5 block - mid
        eor3    $ct_1b, $pt_1b, $enc_ctr_3b, $t1.16b                     @ AES final-4 block - result
.L256_enc_blocks_more_than_4:						@ blocks left >  4

        st1     { $ct_1b}, [$output_ptr], #16                            @ AES final-4 block - store result

        rev64   $ct_0b, $ct_1b                                           @ GHASH final-4 block

        ldr     $pt_1q, [$input_ptr], #16                                @ AES final-3 block - load plaintext

        eor     $ct_0b, $ct_0b, $t0.16b                                  @ feed in partial tag

        ins     $rk4v.d[0], $ct_0.d[1]                                   @ GHASH final-4 block - mid
        pmull2  $rk2q1, $ct_0.2d, $h5.2d                                 @ GHASH final-4 block - high

        eor3    $ct_1b, $pt_1b, $enc_ctr_4b, $t1.16b                     @ AES final-3 block - result
        pmull   $rk3q1, $ct_0.1d, $h5.1d                                 @ GHASH final-4 block - low

        eor     $rk4v.8b, $rk4v.8b, $ct_0.8b                             @ GHASH final-4 block - mid
        eor     $acc_lb, $acc_lb, $rk3                                   @ GHASH final-4 block - low

        pmull   $rk4v.1q, $rk4v.1d, $h56k.1d                             @ GHASH final-4 block - mid

        movi    $t0.8b, #0                                               @ supress further partial tag feed in

        eor     $acc_mb, $acc_mb, $rk4v.16b                              @ GHASH final-4 block - mid
        eor     $acc_hb, $acc_hb, $rk2                                   @ GHASH final-4 block - high
.L256_enc_blocks_more_than_3:						@ blocks left >  3

        st1     { $ct_1b}, [$output_ptr], #16                            @ AES final-3 block - store result

        ldr     $h4q, [$Htable, #80]                                     @ load h4l | h4h
        rev64   $ct_0b, $ct_1b                                           @ GHASH final-3 block

        eor     $ct_0b, $ct_0b, $t0.16b                                  @ feed in partial tag

        ins     $rk4v.d[0], $ct_0.d[1]                                   @ GHASH final-3 block - mid
        pmull2  $rk2q1, $ct_0.2d, $h4.2d                                 @ GHASH final-3 block - high

        eor     $acc_hb, $acc_hb, $rk2                                   @ GHASH final-3 block - high
        eor     $rk4v.8b, $rk4v.8b, $ct_0.8b                             @ GHASH final-3 block - mid
        ldr     $h34kq, [$Htable, #64]                                   @ load h4k | h3k

        ins     $rk4v.d[1], $rk4v.d[0]                                   @ GHASH final-3 block - mid
        ldr     $pt_1q, [$input_ptr], #16                                @ AES final-2 block - load plaintext

        pmull2  $rk4v.1q, $rk4v.2d, $h34k.2d                             @ GHASH final-3 block - mid
        pmull   $rk3q1, $ct_0.1d, $h4.1d                                 @ GHASH final-3 block - low

        eor3    $ct_1b, $pt_1b, $enc_ctr_5b, $t1.16b                     @ AES final-2 block - result
        movi    $t0.8b, #0                                               @ supress further partial tag feed in

        eor     $acc_mb, $acc_mb, $rk4v.16b                              @ GHASH final-3 block - mid
        eor     $acc_lb, $acc_lb, $rk3                                   @ GHASH final-3 block - low
.L256_enc_blocks_more_than_2:						@ blocks left >  2

        ldr     $h3q, [$Htable, #48]                                     @ load h3l | h3h

        st1     { $ct_1b}, [$output_ptr], #16                            @ AES final-2 block - store result

        rev64   $ct_0b, $ct_1b                                           @ GHASH final-2 block
        ldr     $pt_1q, [$input_ptr], #16                                @ AES final-1 block - load plaintext

        eor     $ct_0b, $ct_0b, $t0.16b                                  @ feed in partial tag

        ins     $rk4v.d[0], $ct_0.d[1]                                   @ GHASH final-2 block - mid

        movi    $t0.8b, #0                                               @ supress further partial tag feed in

        pmull2  $rk2q1, $ct_0.2d, $h3.2d                                 @ GHASH final-2 block - high
        eor3    $ct_1b, $pt_1b, $enc_ctr_6b, $t1.16b                     @ AES final-1 block - result

        eor     $rk4v.8b, $rk4v.8b, $ct_0.8b                             @ GHASH final-2 block - mid

        eor     $acc_hb, $acc_hb, $rk2                                   @ GHASH final-2 block - high

        pmull   $rk4v.1q, $rk4v.1d, $h34k.1d                             @ GHASH final-2 block - mid
        pmull   $rk3q1, $ct_0.1d, $h3.1d                                 @ GHASH final-2 block - low

        eor     $acc_mb, $acc_mb, $rk4v.16b                              @ GHASH final-2 block - mid
        eor     $acc_lb, $acc_lb, $rk3                                   @ GHASH final-2 block - low
.L256_enc_blocks_more_than_1:						@ blocks left >  1

        st1     { $ct_1b}, [$output_ptr], #16                            @ AES final-1 block - store result

        ldr     $h2q, [$Htable, #32]                                     @ load h2l | h2h
        rev64   $ct_0b, $ct_1b                                           @ GHASH final-1 block
        ldr     $pt_1q, [$input_ptr], #16                                @ AES final block - load plaintext

        eor     $ct_0b, $ct_0b, $t0.16b                                  @ feed in partial tag
        movi    $t0.8b, #0                                               @ supress further partial tag feed in

        ins     $rk4v.d[0], $ct_0.d[1]                                   @ GHASH final-1 block - mid
        pmull2  $rk2q1, $ct_0.2d, $h2.2d                                 @ GHASH final-1 block - high

        eor3    $ct_1b, $pt_1b, $enc_ctr_7b, $t1.16b                     @ AES final block - result
        eor     $acc_hb, $acc_hb, $rk2                                   @ GHASH final-1 block - high

        pmull   $rk3q1, $ct_0.1d, $h2.1d                                 @ GHASH final-1 block - low
        eor     $rk4v.8b, $rk4v.8b, $ct_0.8b                             @ GHASH final-1 block - mid

        ldr     $h12kq, [$Htable, #16]                                   @ load h2k | h1k

        eor     $acc_lb, $acc_lb, $rk3                                   @ GHASH final-1 block - low
        ins     $rk4v.d[1], $rk4v.d[0]                                   @ GHASH final-1 block - mid

        pmull2  $rk4v.1q, $rk4v.2d, $h12k.2d                             @ GHASH final-1 block - mid

        eor     $acc_mb, $acc_mb, $rk4v.16b                              @ GHASH final-1 block - mid
.L256_enc_blocks_less_than_1:						@ blocks left <= 1

        and     $bit_length, $bit_length, #127                           @ bit_length %= 128

        sub     $bit_length, $bit_length, #128                           @ bit_length -= 128

        neg     $bit_length, $bit_length                                 @ bit_length = 128 - #bits in input (in range [1,128])

        mvn     $temp0_x, xzr                                            @ temp0_x = 0xffffffffffffffff
        and     $bit_length, $bit_length, #127                           @ bit_length %= 128

        lsr     $temp0_x, $temp0_x, $bit_length                          @ temp0_x is mask for top 64b of last block
        cmp     $bit_length, #64
        mvn     $temp1_x, xzr                                            @ temp1_x = 0xffffffffffffffff

        csel    $temp3_x, $temp0_x, xzr, lt
        csel    $temp2_x, $temp1_x, $temp0_x, lt

        mov     $enc_ctr_0.d[0], $temp2_x                                @ enc_ctr_0b is mask for last block
        ldr     $h1q, [$Htable]                                          @ load h1l | h1h

        ld1     { $rk0}, [$output_ptr]                                   @ load existing bytes where the possibly partial last block is to be stored
        mov     $enc_ctr_0.d[1], $temp3_x

        and     $ct_1b, $ct_1b, $enc_ctr_0b                              @ possibly partial last block has zeroes in highest bits

        rev64   $ct_0b, $ct_1b                                           @ GHASH final block

        rev32   $rtmp_ctr.16b, $rtmp_ctr.16b                             @ convert LE counter back to BE for storage
        bif     $ct_1b, $rk0, $enc_ctr_0b                                @ insert existing bytes in top end of result before storing
        str     $rtmp_ctrq, [$counter]                                   @ store the updated counter

        eor     $ct_0b, $ct_0b, $t0.16b                                  @ feed in partial tag
        st1     { $ct_1b}, [$output_ptr]                                 @ store all 16B

        ins     $t0.d[0], $ct_0.d[1]                                     @ GHASH final block - mid
        pmull2  $rk2q1, $ct_0.2d, $h1.2d                                 @ GHASH final block - high
        pmull   $rk3q1, $ct_0.1d, $h1.1d                                 @ GHASH final block - low

        eor     $acc_hb, $acc_hb, $rk2                                   @ GHASH final block - high
        eor     $acc_lb, $acc_lb, $rk3                                   @ GHASH final block - low

        eor     $t0.8b, $t0.8b, $ct_0.8b                                 @ GHASH final block - mid

        pmull   $t0.1q, $t0.1d, $h12k.1d                                 @ GHASH final block - mid

        eor     $acc_mb, $acc_mb, $t0.16b                                @ GHASH final block - mid
        ldr     $mod_constantd, [$modulo_constant]                       @ MODULO - load modulo constant

        ext     $t11.16b, $acc_hb, $acc_hb, #8                           @ MODULO - other top alignment

        eor3    $acc_mb, $acc_mb, $acc_hb, $acc_lb                       @ MODULO - karatsuba tidy up
        pmull   $t12.1q, $acc_h.1d, $mod_constant.1d                     @ MODULO - top 64b align with mid

        eor3    $acc_mb, $acc_mb, $t12.16b, $t11.16b                     @ MODULO - fold into mid

        pmull   $acc_h.1q, $acc_m.1d, $mod_constant.1d                   @ MODULO - mid 64b align with low
        ext     $t11.16b, $acc_mb, $acc_mb, #8                           @ MODULO - other mid alignment

        eor3    $acc_lb, $acc_lb, $acc_hb, $t11.16b                      @ MODULO - fold into low
                ext     $acc_lb, $acc_lb, $acc_lb, #8
        rev64   $acc_lb, $acc_lb
        st1     { $acc_l.16b }, [$current_tag]
        mov     x0, $byte_length                                         @ return sizes

        ldp     d10, d11, [sp, #16]
        ldp     d12, d13, [sp, #32]
        ldp     d14, d15, [sp, #48]
        ldp     d8, d9, [sp], #80
        ret

.L256_enc_blocks_none:								@ ZERO TAIL BLOCKS
        sub     $rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s
        sub     $rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s
        sub     $rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s
        sub     $rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s
        sub     $rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s
        sub     $rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s
        sub     $rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s
        sub     $rtmp_ctr.4s, $rtmp_ctr.4s, $rctr_inc.4s

        rev32   $rtmp_ctr.16b, $rtmp_ctr.16b                             @ convert LE counter back to BE for storage
        str     $rtmp_ctrq, [$counter]                                   @ store the updated counter

        ext     $acc_lb, $acc_lb, $acc_lb, #8
        rev64   $acc_lb, $acc_lb
        st1     { $acc_l.16b }, [$current_tag]
        mov     x0, $byte_length                                         @ return sizes

        ldp     d10, d11, [sp, #16]
        ldp     d12, d13, [sp, #32]
        ldp     d14, d15, [sp, #48]
        ldp     d8, d9, [sp], #80
        ret

.L256_enc_ret:
        mov w0, #0x0
        ret
.size aesv8_gcm_8x_enc_256,.-aesv8_gcm_8x_enc_256
___
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
