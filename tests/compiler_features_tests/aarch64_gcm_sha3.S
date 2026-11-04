// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

// Match the architecture directive and SHA3 instruction used by the 8x kernels.
.text
.arch armv8.2-a+crypto+sha3
eor3 v0.16b, v1.16b, v2.16b, v3.16b
ret
