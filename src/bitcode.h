/*
 * Copyright (c) 2016 Lonelycoder AB
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#pragma once

#define ATTR_KIND_BY_VAL  3

#define TYPE_CODE_NUMENTRY     1
#define TYPE_CODE_VOID         2
#define TYPE_CODE_FLOAT        3
#define TYPE_CODE_DOUBLE       4
#define TYPE_CODE_LABEL        5
#define TYPE_CODE_OPAQUE       6
#define TYPE_CODE_INTEGER      7
#define TYPE_CODE_POINTER      8
#define TYPE_CODE_ARRAY        11
#define TYPE_CODE_VECTOR       12
#define TYPE_CODE_METADATA     16
#define TYPE_CODE_STRUCT_NAME  19
#define TYPE_CODE_STRUCT_NAMED 20
#define TYPE_CODE_STRUCT_ANON  18
#define TYPE_CODE_FUNCTION     21


#define CST_CODE_SETTYPE         1
#define CST_CODE_NULL            2
#define CST_CODE_UNDEF           3
#define CST_CODE_INTEGER         4
#define CST_CODE_FLOAT           6
#define CST_CODE_AGGREGATE       7
#define CST_CODE_STRING          8
#define CST_CODE_CSTRING         9
#define CST_CODE_CE_BINOP        10
#define CST_CODE_CE_CAST         11
#define CST_CODE_CE_GEP          12
#define CST_CODE_CE_CMP          17
#define CST_CODE_INLINEASM_OLD   18
#define CST_CODE_CE_INBOUNDS_GEP 20
#define CST_CODE_BLOCKADDRESS    21
#define CST_CODE_DATA            22
#define CST_CODE_INLINEASM       23

#define CAST_TRUNC    0
#define CAST_ZEXT     1
#define CAST_SEXT     2
#define CAST_FPTOUI   3
#define CAST_FPTOSI   4
#define CAST_UITOFP   5
#define CAST_SITOFP   6
#define CAST_FPTRUNC  7
#define CAST_FPEXT    8
#define CAST_PTRTOINT 9
#define CAST_INTTOPTR 10
#define CAST_BITCAST  11

#define BINOP_ADD   0
#define BINOP_SUB   1
#define BINOP_MUL   2
#define BINOP_UDIV  3
#define BINOP_SDIV  4
#define BINOP_UREM  5
#define BINOP_SREM  6
#define BINOP_SHL   7
#define BINOP_LSHR  8
#define BINOP_ASHR  9
#define BINOP_AND  10
#define BINOP_OR   11
#define BINOP_XOR  12
#define BINOP_ROL  13
#define BINOP_ROR  14


#define ICMP_EQ    32
#define ICMP_NE    33
#define ICMP_UGT   34
#define ICMP_UGE   35
#define ICMP_ULT   36
#define ICMP_ULE   37
#define ICMP_SGT   38
#define ICMP_SGE   39
#define ICMP_SLT   40
#define ICMP_SLE   41

#define FUNC_CODE_DECLAREBLOCKS          1
#define FUNC_CODE_INST_BINOP             2
#define FUNC_CODE_INST_CAST              3
#define FUNC_CODE_INST_GEP_OLD           4
#define FUNC_CODE_INST_RET              10
#define FUNC_CODE_INST_BR               11
#define FUNC_CODE_INST_SWITCH           12
#define FUNC_CODE_INST_INVOKE           13
#define FUNC_CODE_INST_UNREACHABLE      15
#define FUNC_CODE_INST_PHI              16
#define FUNC_CODE_INST_ALLOCA           19
#define FUNC_CODE_INST_LOAD             20
#define FUNC_CODE_INST_VAARG            23
#define FUNC_CODE_INST_STORE_OLD        24
#define FUNC_CODE_INST_EXTRACTVAL       26
#define FUNC_CODE_INST_INSERTVAL        27
#define FUNC_CODE_INST_CMP2             28
#define FUNC_CODE_INST_VSELECT          29
#define FUNC_CODE_INST_INBOUNDS_GEP_OLD 30
#define FUNC_CODE_INST_CALL             34
#define FUNC_CODE_INST_RESUME           39
#define FUNC_CODE_INST_LANDINGPAD_OLD   40
#define FUNC_CODE_INST_LOADATOMIC       41
#define FUNC_CODE_INST_STOREATOMIC_OLD  42
#define FUNC_CODE_INST_GEP              43
#define FUNC_CODE_INST_STORE            44
#define FUNC_CODE_INST_STOREATOMIC      45
#define FUNC_CODE_INST_LANDINGPAD       47


#define FCMP_FALSE  0
#define FCMP_OEQ    1
#define FCMP_OGT    2
#define FCMP_OGE    3
#define FCMP_OLT    4
#define FCMP_OLE    5
#define FCMP_ONE    6
#define FCMP_ORD    7
#define FCMP_UNO    8
#define FCMP_UEQ    9
#define FCMP_UGT   10
#define FCMP_UGE   11
#define FCMP_ULT   12
#define FCMP_ULE   13
#define FCMP_UNE   14
#define FCMP_TRUE  15

#define MODULE_CODE_VERSION    1
#define MODULE_CODE_TRIPLE     2
#define MODULE_CODE_DATALAYOUT 3
#define MODULE_CODE_GLOBALVAR  7
#define MODULE_CODE_FUNCTION   8
#define MODULE_CODE_ALIAS      9
#define MODULE_CODE_COMDAT     12
#define MODULE_CODE_VSTOFFSET  13
#define MODULE_CODE_METADATA_VALUES_UNUSED 15
#define MODULE_CODE_SOURCE_FILENAME 16

#define BITCODE_BLOCKINFO       0
#define BITCODE_MODULE          8
#define BITCODE_PARAMATTR       9
#define BITCODE_PARAMATTR_GROUP 10
#define BITCODE_CONSTANTS       11
#define BITCODE_FUNCTION        12
#define BITCODE_IDENTIFICATION_BLOCK_ID 13
#define BITCODE_VALUE_SYMTAB    14
#define BITCODE_METADATA        15
#define BITCODE_METADATA_ATTACHMENT 16
#define BITCODE_TYPES_NEW 17
#define BITCODE_USELIST 18
#define BITCODE_OPERAND_BUNDLE_TAGS_BLOCK_ID 21
#define BITCODE_METADATA_KIND_BLOCK_ID 22





