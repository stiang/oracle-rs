//! Data types negotiation message
//!
//! The DataTypes message is sent after the Protocol message to establish
//! the data type representations that will be used during the session.
//!
//! This message sends the client's compile and runtime capabilities along
//! with a list of supported data types. The list must include ALL TTC
//! (Two-Task Common) protocol types, not just SQL types.

use bytes::Bytes;

use crate::buffer::{ReadBuffer, WriteBuffer};
use crate::capabilities::Capabilities;
use crate::constants::{charset, encoding, MessageType, PacketType, PACKET_HEADER_SIZE};
use crate::error::Result;
use crate::packet::PacketHeader;

/// A data type definition for negotiation
#[derive(Debug, Clone, Copy)]
pub struct DataTypeDefinition {
    /// The data type code
    pub data_type: u16,
    /// The converted data type code
    pub conv_data_type: u16,
    /// The representation mode
    pub representation: u16,
}

// Oracle SQL type numbers
const ORA_TYPE_NUM_VARCHAR: u16 = 1;
const ORA_TYPE_NUM_NUMBER: u16 = 2;
const ORA_TYPE_NUM_BINARY_INTEGER: u16 = 3;
const ORA_TYPE_NUM_LONG: u16 = 8;
const ORA_TYPE_NUM_ROWID: u16 = 11;
const ORA_TYPE_NUM_DATE: u16 = 12;
const ORA_TYPE_NUM_RAW: u16 = 23;
const ORA_TYPE_NUM_LONG_RAW: u16 = 24;
const ORA_TYPE_NUM_CHAR: u16 = 96;
const ORA_TYPE_NUM_BINARY_FLOAT: u16 = 100;
const ORA_TYPE_NUM_BINARY_DOUBLE: u16 = 101;
const ORA_TYPE_NUM_CURSOR: u16 = 102;
const ORA_TYPE_NUM_OBJECT: u16 = 109;
const ORA_TYPE_NUM_CLOB: u16 = 112;
const ORA_TYPE_NUM_BLOB: u16 = 113;
const ORA_TYPE_NUM_BFILE: u16 = 114;
const ORA_TYPE_NUM_JSON: u16 = 119;
const ORA_TYPE_NUM_VECTOR: u16 = 127;
const ORA_TYPE_NUM_TIMESTAMP: u16 = 180;
const ORA_TYPE_NUM_TIMESTAMP_TZ: u16 = 181;
const ORA_TYPE_NUM_INTERVAL_YM: u16 = 182;
const ORA_TYPE_NUM_INTERVAL_DS: u16 = 183;
const ORA_TYPE_NUM_UROWID: u16 = 208;
const ORA_TYPE_NUM_TIMESTAMP_LTZ: u16 = 231;
const ORA_TYPE_NUM_BOOLEAN: u16 = 252;

// TTC internal data types (not associated with actual database data)
const TNS_DATA_TYPE_FLOAT: u16 = 4;
const TNS_DATA_TYPE_STR: u16 = 5;
const TNS_DATA_TYPE_VNU: u16 = 6;
const TNS_DATA_TYPE_PDN: u16 = 7;
const TNS_DATA_TYPE_VCS: u16 = 9;
const TNS_DATA_TYPE_TIDDEF: u16 = 10;
const TNS_DATA_TYPE_VBI: u16 = 15;
const TNS_DATA_TYPE_UB2: u16 = 25;
const TNS_DATA_TYPE_UB4: u16 = 26;
const TNS_DATA_TYPE_SB1: u16 = 27;
const TNS_DATA_TYPE_SB2: u16 = 28;
const TNS_DATA_TYPE_SB4: u16 = 29;
const TNS_DATA_TYPE_SWORD: u16 = 30;
const TNS_DATA_TYPE_UWORD: u16 = 31;
const TNS_DATA_TYPE_PTRB: u16 = 32;
const TNS_DATA_TYPE_PTRW: u16 = 33;
const TNS_DATA_TYPE_OER8: u16 = 34 + 256;
const TNS_DATA_TYPE_FUN: u16 = 35 + 256;
const TNS_DATA_TYPE_AUA: u16 = 36 + 256;
const TNS_DATA_TYPE_RXH7: u16 = 37 + 256;
const TNS_DATA_TYPE_NA6: u16 = 38 + 256;
const TNS_DATA_TYPE_OAC9: u16 = 39;
const TNS_DATA_TYPE_AMS: u16 = 40;
const TNS_DATA_TYPE_BRN: u16 = 41;
const TNS_DATA_TYPE_BRP: u16 = 42 + 256;
const TNS_DATA_TYPE_BRV: u16 = 43 + 256;
const TNS_DATA_TYPE_KVA: u16 = 44 + 256;
const TNS_DATA_TYPE_CLS: u16 = 45 + 256;
const TNS_DATA_TYPE_CUI: u16 = 46 + 256;
const TNS_DATA_TYPE_DFN: u16 = 47 + 256;
const TNS_DATA_TYPE_DQR: u16 = 48 + 256;
const TNS_DATA_TYPE_DSC: u16 = 49 + 256;
const TNS_DATA_TYPE_EXE: u16 = 50 + 256;
const TNS_DATA_TYPE_FCH: u16 = 51 + 256;
const TNS_DATA_TYPE_GBV: u16 = 52 + 256;
const TNS_DATA_TYPE_GEM: u16 = 53 + 256;
const TNS_DATA_TYPE_GIV: u16 = 54 + 256;
const TNS_DATA_TYPE_OKG: u16 = 55 + 256;
const TNS_DATA_TYPE_HMI: u16 = 56 + 256;
const TNS_DATA_TYPE_INO: u16 = 57 + 256;
const TNS_DATA_TYPE_LNF: u16 = 59 + 256;
const TNS_DATA_TYPE_ONT: u16 = 60 + 256;
const TNS_DATA_TYPE_OPE: u16 = 61 + 256;
const TNS_DATA_TYPE_OSQ: u16 = 62 + 256;
const TNS_DATA_TYPE_SFE: u16 = 63 + 256;
const TNS_DATA_TYPE_SPF: u16 = 64 + 256;
const TNS_DATA_TYPE_VSN: u16 = 65 + 256;
const TNS_DATA_TYPE_UD7: u16 = 66 + 256;
const TNS_DATA_TYPE_DSA: u16 = 67 + 256;
const TNS_DATA_TYPE_UIN: u16 = 68;
const TNS_DATA_TYPE_PIN: u16 = 71 + 256;
const TNS_DATA_TYPE_PFN: u16 = 72 + 256;
const TNS_DATA_TYPE_PPT: u16 = 73 + 256;
const TNS_DATA_TYPE_STO: u16 = 75 + 256;
const TNS_DATA_TYPE_ARC: u16 = 77 + 256;
const TNS_DATA_TYPE_MRS: u16 = 78 + 256;
const TNS_DATA_TYPE_MRT: u16 = 79 + 256;
const TNS_DATA_TYPE_MRG: u16 = 80 + 256;
const TNS_DATA_TYPE_MRR: u16 = 81 + 256;
const TNS_DATA_TYPE_MRC: u16 = 82 + 256;
const TNS_DATA_TYPE_VER: u16 = 83 + 256;
const TNS_DATA_TYPE_LON2: u16 = 84 + 256;
const TNS_DATA_TYPE_INO2: u16 = 85 + 256;
const TNS_DATA_TYPE_ALL: u16 = 86 + 256;
const TNS_DATA_TYPE_UDB: u16 = 87 + 256;
const TNS_DATA_TYPE_AQI: u16 = 88 + 256;
const TNS_DATA_TYPE_ULB: u16 = 89 + 256;
const TNS_DATA_TYPE_ULD: u16 = 90 + 256;
const TNS_DATA_TYPE_SLS: u16 = 91;
const TNS_DATA_TYPE_SID: u16 = 92 + 256;
const TNS_DATA_TYPE_NA7: u16 = 93 + 256;
const TNS_DATA_TYPE_LVC: u16 = 94;
const TNS_DATA_TYPE_LVB: u16 = 95;
const TNS_DATA_TYPE_AVC: u16 = 97;
const TNS_DATA_TYPE_AL7: u16 = 98 + 256;
const TNS_DATA_TYPE_K2RPC: u16 = 99 + 256;
const TNS_DATA_TYPE_RDD: u16 = 104;
const TNS_DATA_TYPE_XDP: u16 = 103 + 256;
const TNS_DATA_TYPE_OSL: u16 = 106;
const TNS_DATA_TYPE_OKO8: u16 = 107 + 256;
const TNS_DATA_TYPE_EXT_NAMED: u16 = 108;
const TNS_DATA_TYPE_EXT_REF: u16 = 110;
const TNS_DATA_TYPE_INT_REF: u16 = 111;
const TNS_DATA_TYPE_CFILE: u16 = 115;
const TNS_DATA_TYPE_RSET: u16 = 116;
const TNS_DATA_TYPE_CWD: u16 = 117;
const TNS_DATA_TYPE_OAC122: u16 = 120;
const TNS_DATA_TYPE_UD12: u16 = 124 + 256;
const TNS_DATA_TYPE_AL8: u16 = 125 + 256;
const TNS_DATA_TYPE_LFOP: u16 = 126 + 256;
const TNS_DATA_TYPE_FCRT: u16 = 127 + 256;
const TNS_DATA_TYPE_DNY: u16 = 128 + 256;
const TNS_DATA_TYPE_OPR: u16 = 129 + 256;
const TNS_DATA_TYPE_PLS: u16 = 130 + 256;
const TNS_DATA_TYPE_XID: u16 = 131 + 256;
const TNS_DATA_TYPE_TXN: u16 = 132 + 256;
const TNS_DATA_TYPE_DCB: u16 = 133 + 256;
const TNS_DATA_TYPE_CCA: u16 = 134 + 256;
const TNS_DATA_TYPE_WRN: u16 = 135 + 256;
const TNS_DATA_TYPE_TLH: u16 = 137 + 256;
const TNS_DATA_TYPE_TOH: u16 = 138 + 256;
const TNS_DATA_TYPE_FOI: u16 = 139 + 256;
const TNS_DATA_TYPE_SID2: u16 = 140 + 256;
const TNS_DATA_TYPE_TCH: u16 = 141 + 256;
const TNS_DATA_TYPE_PII: u16 = 142 + 256;
const TNS_DATA_TYPE_PFI: u16 = 143 + 256;
const TNS_DATA_TYPE_PPU: u16 = 144 + 256;
const TNS_DATA_TYPE_PTE: u16 = 145 + 256;
const TNS_DATA_TYPE_CLV: u16 = 146;
const TNS_DATA_TYPE_RXH8: u16 = 148 + 256;
const TNS_DATA_TYPE_N12: u16 = 149 + 256;
const TNS_DATA_TYPE_AUTH: u16 = 150 + 256;
const TNS_DATA_TYPE_KVAL: u16 = 151 + 256;
const TNS_DATA_TYPE_DTR: u16 = 152;
const TNS_DATA_TYPE_DUN: u16 = 153;
const TNS_DATA_TYPE_DOP: u16 = 154;
const TNS_DATA_TYPE_VST: u16 = 155;
const TNS_DATA_TYPE_ODT: u16 = 156;
const TNS_DATA_TYPE_FGI: u16 = 157 + 256;
const TNS_DATA_TYPE_DSY: u16 = 158 + 256;
const TNS_DATA_TYPE_DSYR8: u16 = 159 + 256;
const TNS_DATA_TYPE_DSYH8: u16 = 160 + 256;
const TNS_DATA_TYPE_DSYL: u16 = 161 + 256;
const TNS_DATA_TYPE_DSYT8: u16 = 162 + 256;
const TNS_DATA_TYPE_DSYV8: u16 = 163 + 256;
const TNS_DATA_TYPE_DSYP: u16 = 164 + 256;
const TNS_DATA_TYPE_DSYF: u16 = 165 + 256;
const TNS_DATA_TYPE_DSYK: u16 = 166 + 256;
const TNS_DATA_TYPE_DSYY: u16 = 167 + 256;
const TNS_DATA_TYPE_DSYQ: u16 = 168 + 256;
const TNS_DATA_TYPE_DSYC: u16 = 169 + 256;
const TNS_DATA_TYPE_DSYA: u16 = 170 + 256;
const TNS_DATA_TYPE_OT8: u16 = 171 + 256;
const TNS_DATA_TYPE_DOL: u16 = 172;
const TNS_DATA_TYPE_DSYTY: u16 = 173 + 256;
const TNS_DATA_TYPE_AQE: u16 = 174 + 256;
const TNS_DATA_TYPE_KV: u16 = 175 + 256;
const TNS_DATA_TYPE_AQD: u16 = 176 + 256;
const TNS_DATA_TYPE_AQ8: u16 = 177 + 256;
const TNS_DATA_TYPE_TIME: u16 = 178;
const TNS_DATA_TYPE_TIME_TZ: u16 = 179;
const TNS_DATA_TYPE_EDATE: u16 = 184;
const TNS_DATA_TYPE_ETIME: u16 = 185;
const TNS_DATA_TYPE_ETTZ: u16 = 186;
const TNS_DATA_TYPE_ESTAMP: u16 = 187;
const TNS_DATA_TYPE_ESTZ: u16 = 188;
const TNS_DATA_TYPE_EIYM: u16 = 189;
const TNS_DATA_TYPE_EIDS: u16 = 190;
const TNS_DATA_TYPE_RFS: u16 = 193 + 256;
const TNS_DATA_TYPE_RXH10: u16 = 194 + 256;
const TNS_DATA_TYPE_DCLOB: u16 = 195;
const TNS_DATA_TYPE_DBLOB: u16 = 196;
const TNS_DATA_TYPE_DBFILE: u16 = 197;
const TNS_DATA_TYPE_DJSON: u16 = 198;
const TNS_DATA_TYPE_KPN: u16 = 198 + 256;
const TNS_DATA_TYPE_KPDNR: u16 = 199 + 256;
const TNS_DATA_TYPE_DSYD: u16 = 200 + 256;
const TNS_DATA_TYPE_DSYS: u16 = 201 + 256;
const TNS_DATA_TYPE_DSYR: u16 = 202 + 256;
const TNS_DATA_TYPE_DSYH: u16 = 203 + 256;
const TNS_DATA_TYPE_DSYT: u16 = 204 + 256;
const TNS_DATA_TYPE_DSYV: u16 = 205 + 256;
const TNS_DATA_TYPE_AQM: u16 = 206 + 256;
const TNS_DATA_TYPE_OER11: u16 = 207 + 256;
const TNS_DATA_TYPE_AQL: u16 = 210 + 256;
const TNS_DATA_TYPE_OTC: u16 = 211 + 256;
const TNS_DATA_TYPE_KFNO: u16 = 212 + 256;
const TNS_DATA_TYPE_KFNP: u16 = 213 + 256;
const TNS_DATA_TYPE_KGT8: u16 = 214 + 256;
const TNS_DATA_TYPE_RASB4: u16 = 215 + 256;
const TNS_DATA_TYPE_RAUB2: u16 = 216 + 256;
const TNS_DATA_TYPE_RAUB1: u16 = 217 + 256;
const TNS_DATA_TYPE_RATXT: u16 = 218 + 256;
const TNS_DATA_TYPE_RSSB4: u16 = 219 + 256;
const TNS_DATA_TYPE_RSUB2: u16 = 220 + 256;
const TNS_DATA_TYPE_RSUB1: u16 = 221 + 256;
const TNS_DATA_TYPE_RSTXT: u16 = 222 + 256;
const TNS_DATA_TYPE_RIDL: u16 = 223 + 256;
const TNS_DATA_TYPE_GLRDD: u16 = 224 + 256;
const TNS_DATA_TYPE_GLRDG: u16 = 225 + 256;
const TNS_DATA_TYPE_GLRDC: u16 = 226 + 256;
const TNS_DATA_TYPE_OKO: u16 = 227 + 256;
const TNS_DATA_TYPE_DPP: u16 = 228 + 256;
const TNS_DATA_TYPE_DPLS: u16 = 229 + 256;
const TNS_DATA_TYPE_DPMOP: u16 = 230 + 256;
const TNS_DATA_TYPE_ESITZ: u16 = 232;
const TNS_DATA_TYPE_UB8: u16 = 233;
const TNS_DATA_TYPE_STAT: u16 = 234 + 256;
const TNS_DATA_TYPE_RFX: u16 = 235 + 256;
const TNS_DATA_TYPE_FAL: u16 = 236 + 256;
const TNS_DATA_TYPE_CKV: u16 = 237 + 256;
const TNS_DATA_TYPE_DRCX: u16 = 238 + 256;
const TNS_DATA_TYPE_KGH: u16 = 239 + 256;
const TNS_DATA_TYPE_AQO: u16 = 240 + 256;
const TNS_DATA_TYPE_PNTY: u16 = 241;
const TNS_DATA_TYPE_OKGT: u16 = 242 + 256;
const TNS_DATA_TYPE_KPFC: u16 = 243 + 256;
const TNS_DATA_TYPE_FE2: u16 = 244 + 256;
const TNS_DATA_TYPE_SPFP: u16 = 245 + 256;
const TNS_DATA_TYPE_DPULS: u16 = 246 + 256;
const TNS_DATA_TYPE_AQA: u16 = 253 + 256;
const TNS_DATA_TYPE_KPBF: u16 = 254 + 256;
const TNS_DATA_TYPE_TSM: u16 = 513;
const TNS_DATA_TYPE_MSS: u16 = 514;
const TNS_DATA_TYPE_KPC: u16 = 516;
const TNS_DATA_TYPE_CRS: u16 = 517;
const TNS_DATA_TYPE_KKS: u16 = 518;
const TNS_DATA_TYPE_KSP: u16 = 519;
const TNS_DATA_TYPE_KSPTOP: u16 = 520;
const TNS_DATA_TYPE_KSPVAL: u16 = 521;
const TNS_DATA_TYPE_PSS: u16 = 522;
const TNS_DATA_TYPE_NLS: u16 = 523;
const TNS_DATA_TYPE_ALS: u16 = 524;
const TNS_DATA_TYPE_KSDEVTVAL: u16 = 525;
const TNS_DATA_TYPE_KSDEVTTOP: u16 = 526;
const TNS_DATA_TYPE_KPSPP: u16 = 527;
const TNS_DATA_TYPE_KOL: u16 = 528;
const TNS_DATA_TYPE_LST: u16 = 529;
const TNS_DATA_TYPE_ACX: u16 = 530;
const TNS_DATA_TYPE_SCS: u16 = 531;
const TNS_DATA_TYPE_RXH: u16 = 532;
const TNS_DATA_TYPE_KPDNS: u16 = 533;
const TNS_DATA_TYPE_KPDCN: u16 = 534;
const TNS_DATA_TYPE_KPNNS: u16 = 535;
const TNS_DATA_TYPE_KPNCN: u16 = 536;
const TNS_DATA_TYPE_KPS: u16 = 537;
const TNS_DATA_TYPE_APINF: u16 = 538;
const TNS_DATA_TYPE_TEN: u16 = 539;
const TNS_DATA_TYPE_XSSCS: u16 = 540;
const TNS_DATA_TYPE_XSSSO: u16 = 541;
const TNS_DATA_TYPE_XSSAO: u16 = 542;
const TNS_DATA_TYPE_KSRPC: u16 = 543;
const TNS_DATA_TYPE_KVL: u16 = 560;
const TNS_DATA_TYPE_SESSGET: u16 = 563;
const TNS_DATA_TYPE_SESSREL: u16 = 564;
const TNS_DATA_TYPE_XSSDEF: u16 = 565;
const TNS_DATA_TYPE_PDQCINV: u16 = 572;
const TNS_DATA_TYPE_PDQIDC: u16 = 573;
const TNS_DATA_TYPE_KPDQCSTA: u16 = 574;
const TNS_DATA_TYPE_KPRS: u16 = 575;
const TNS_DATA_TYPE_KPDQIDC: u16 = 576;
const TNS_DATA_TYPE_RTSTRM: u16 = 578;
const TNS_DATA_TYPE_SESSRET: u16 = 579;
const TNS_DATA_TYPE_SCN6: u16 = 580;
const TNS_DATA_TYPE_KECPA: u16 = 581;
const TNS_DATA_TYPE_KECPP: u16 = 582;
const TNS_DATA_TYPE_SXA: u16 = 583;
const TNS_DATA_TYPE_KVARR: u16 = 584;
const TNS_DATA_TYPE_KPNGN: u16 = 585;
const TNS_DATA_TYPE_XSNSOP: u16 = 590;
const TNS_DATA_TYPE_XSATTR: u16 = 591;
const TNS_DATA_TYPE_XSNS: u16 = 592;
const TNS_DATA_TYPE_TXT: u16 = 593;
const TNS_DATA_TYPE_XSSESSNS: u16 = 594;
const TNS_DATA_TYPE_XSATTOP: u16 = 595;
const TNS_DATA_TYPE_XSCREOP: u16 = 596;
const TNS_DATA_TYPE_XSDETOP: u16 = 597;
const TNS_DATA_TYPE_XSDESOP: u16 = 598;
const TNS_DATA_TYPE_XSSETSP: u16 = 599;
const TNS_DATA_TYPE_XSSIDP: u16 = 600;
const TNS_DATA_TYPE_XSPRIN: u16 = 601;
const TNS_DATA_TYPE_XSKVL: u16 = 602;
const TNS_DATA_TYPE_XSSSDEF2: u16 = 603;
const TNS_DATA_TYPE_XSNSOP2: u16 = 604;
const TNS_DATA_TYPE_XSNS2: u16 = 605;
const TNS_DATA_TYPE_IMPLRES: u16 = 611;
const TNS_DATA_TYPE_OER19: u16 = 612;
const TNS_DATA_TYPE_UB1ARRAY: u16 = 613;
const TNS_DATA_TYPE_SESSSTATE: u16 = 614;
const TNS_DATA_TYPE_AC_REPLAY: u16 = 615;
const TNS_DATA_TYPE_AC_CONT: u16 = 616;
const TNS_DATA_TYPE_KPDNREQ: u16 = 622;
const TNS_DATA_TYPE_KPDNRNF: u16 = 623;
const TNS_DATA_TYPE_KPNGNC: u16 = 624;
const TNS_DATA_TYPE_KPNRI: u16 = 625;
const TNS_DATA_TYPE_AQENQ: u16 = 626;
const TNS_DATA_TYPE_AQDEQ: u16 = 627;
const TNS_DATA_TYPE_AQJMS: u16 = 628;
const TNS_DATA_TYPE_KPDNRPAY: u16 = 629;
const TNS_DATA_TYPE_KPDNRACK: u16 = 630;
const TNS_DATA_TYPE_KPDNRMP: u16 = 631;
const TNS_DATA_TYPE_KPDNRDQ: u16 = 632;
const TNS_DATA_TYPE_CHUNKINFO: u16 = 636;
const TNS_DATA_TYPE_SCN: u16 = 637;
const TNS_DATA_TYPE_SCN8: u16 = 638;
const TNS_DATA_TYPE_UD21: u16 = 639;
const TNS_DATA_TYPE_TNP: u16 = 640;
const TNS_DATA_TYPE_OAC: u16 = 646;
const TNS_DATA_TYPE_SESSSIGN: u16 = 647;
const TNS_DATA_TYPE_OER: u16 = 652;
const TNS_DATA_TYPE_PLEND: u16 = 660;
const TNS_DATA_TYPE_PLBGN: u16 = 661;
const TNS_DATA_TYPE_UDS: u16 = 663;
const TNS_DATA_TYPE_PLOP: u16 = 665;

// Type representations
const TNS_TYPE_REP_UNIVERSAL: u16 = 1;
const TNS_TYPE_REP_ORACLE: u16 = 10;

/// Complete TTC data types list for protocol negotiation.
/// This list must include ALL protocol types, not just SQL types.
/// Ported from python-oracledb's data_types.pyx DATA_TYPES array.
pub static DATA_TYPES: &[DataTypeDefinition] = &[
    // SQL types
    DataTypeDefinition { data_type: ORA_TYPE_NUM_VARCHAR, conv_data_type: ORA_TYPE_NUM_VARCHAR, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: ORA_TYPE_NUM_NUMBER, conv_data_type: ORA_TYPE_NUM_NUMBER, representation: TNS_TYPE_REP_ORACLE },
    DataTypeDefinition { data_type: ORA_TYPE_NUM_LONG, conv_data_type: ORA_TYPE_NUM_LONG, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: ORA_TYPE_NUM_DATE, conv_data_type: ORA_TYPE_NUM_DATE, representation: TNS_TYPE_REP_ORACLE },
    DataTypeDefinition { data_type: ORA_TYPE_NUM_RAW, conv_data_type: ORA_TYPE_NUM_RAW, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: ORA_TYPE_NUM_LONG_RAW, conv_data_type: ORA_TYPE_NUM_LONG_RAW, representation: TNS_TYPE_REP_UNIVERSAL },
    // Internal types for protocol encoding
    DataTypeDefinition { data_type: TNS_DATA_TYPE_UB2, conv_data_type: TNS_DATA_TYPE_UB2, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_UB4, conv_data_type: TNS_DATA_TYPE_UB4, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_SB1, conv_data_type: TNS_DATA_TYPE_SB1, representation: TNS_TYPE_REP_ORACLE },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_SB2, conv_data_type: TNS_DATA_TYPE_SB2, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_SB4, conv_data_type: TNS_DATA_TYPE_SB4, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_SWORD, conv_data_type: TNS_DATA_TYPE_SWORD, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_UWORD, conv_data_type: TNS_DATA_TYPE_UWORD, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_PTRB, conv_data_type: TNS_DATA_TYPE_PTRB, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_PTRW, conv_data_type: TNS_DATA_TYPE_PTRW, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_TIDDEF, conv_data_type: TNS_DATA_TYPE_TIDDEF, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: ORA_TYPE_NUM_ROWID, conv_data_type: ORA_TYPE_NUM_ROWID, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_AMS, conv_data_type: TNS_DATA_TYPE_AMS, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_BRN, conv_data_type: TNS_DATA_TYPE_BRN, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_CWD, conv_data_type: TNS_DATA_TYPE_CWD, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_OAC122, conv_data_type: TNS_DATA_TYPE_OAC122, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_OER8, conv_data_type: TNS_DATA_TYPE_OER8, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_FUN, conv_data_type: TNS_DATA_TYPE_FUN, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_AUA, conv_data_type: TNS_DATA_TYPE_AUA, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_RXH7, conv_data_type: TNS_DATA_TYPE_RXH7, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_NA6, conv_data_type: TNS_DATA_TYPE_NA6, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_BRP, conv_data_type: TNS_DATA_TYPE_BRP, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_BRV, conv_data_type: TNS_DATA_TYPE_BRV, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_KVA, conv_data_type: TNS_DATA_TYPE_KVA, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_CLS, conv_data_type: TNS_DATA_TYPE_CLS, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_CUI, conv_data_type: TNS_DATA_TYPE_CUI, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_DFN, conv_data_type: TNS_DATA_TYPE_DFN, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_DQR, conv_data_type: TNS_DATA_TYPE_DQR, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_DSC, conv_data_type: TNS_DATA_TYPE_DSC, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_EXE, conv_data_type: TNS_DATA_TYPE_EXE, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_FCH, conv_data_type: TNS_DATA_TYPE_FCH, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_GBV, conv_data_type: TNS_DATA_TYPE_GBV, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_GEM, conv_data_type: TNS_DATA_TYPE_GEM, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_GIV, conv_data_type: TNS_DATA_TYPE_GIV, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_OKG, conv_data_type: TNS_DATA_TYPE_OKG, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_HMI, conv_data_type: TNS_DATA_TYPE_HMI, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_INO, conv_data_type: TNS_DATA_TYPE_INO, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_LNF, conv_data_type: TNS_DATA_TYPE_LNF, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_ONT, conv_data_type: TNS_DATA_TYPE_ONT, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_OPE, conv_data_type: TNS_DATA_TYPE_OPE, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_OSQ, conv_data_type: TNS_DATA_TYPE_OSQ, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_SFE, conv_data_type: TNS_DATA_TYPE_SFE, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_SPF, conv_data_type: TNS_DATA_TYPE_SPF, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_VSN, conv_data_type: TNS_DATA_TYPE_VSN, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_UD7, conv_data_type: TNS_DATA_TYPE_UD7, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_DSA, conv_data_type: TNS_DATA_TYPE_DSA, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_PIN, conv_data_type: TNS_DATA_TYPE_PIN, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_PFN, conv_data_type: TNS_DATA_TYPE_PFN, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_PPT, conv_data_type: TNS_DATA_TYPE_PPT, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_STO, conv_data_type: TNS_DATA_TYPE_STO, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_ARC, conv_data_type: TNS_DATA_TYPE_ARC, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_MRS, conv_data_type: TNS_DATA_TYPE_MRS, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_MRT, conv_data_type: TNS_DATA_TYPE_MRT, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_MRG, conv_data_type: TNS_DATA_TYPE_MRG, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_MRR, conv_data_type: TNS_DATA_TYPE_MRR, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_MRC, conv_data_type: TNS_DATA_TYPE_MRC, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_VER, conv_data_type: TNS_DATA_TYPE_VER, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_LON2, conv_data_type: TNS_DATA_TYPE_LON2, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_INO2, conv_data_type: TNS_DATA_TYPE_INO2, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_ALL, conv_data_type: TNS_DATA_TYPE_ALL, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_UDB, conv_data_type: TNS_DATA_TYPE_UDB, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_AQI, conv_data_type: TNS_DATA_TYPE_AQI, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_ULB, conv_data_type: TNS_DATA_TYPE_ULB, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_ULD, conv_data_type: TNS_DATA_TYPE_ULD, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_SID, conv_data_type: TNS_DATA_TYPE_SID, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_NA7, conv_data_type: TNS_DATA_TYPE_NA7, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_AL7, conv_data_type: TNS_DATA_TYPE_AL7, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_K2RPC, conv_data_type: TNS_DATA_TYPE_K2RPC, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_XDP, conv_data_type: TNS_DATA_TYPE_XDP, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_OKO8, conv_data_type: TNS_DATA_TYPE_OKO8, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_UD12, conv_data_type: TNS_DATA_TYPE_UD12, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_AL8, conv_data_type: TNS_DATA_TYPE_AL8, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_LFOP, conv_data_type: TNS_DATA_TYPE_LFOP, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_FCRT, conv_data_type: TNS_DATA_TYPE_FCRT, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_DNY, conv_data_type: TNS_DATA_TYPE_DNY, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_OPR, conv_data_type: TNS_DATA_TYPE_OPR, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_PLS, conv_data_type: TNS_DATA_TYPE_PLS, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_XID, conv_data_type: TNS_DATA_TYPE_XID, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_TXN, conv_data_type: TNS_DATA_TYPE_TXN, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_DCB, conv_data_type: TNS_DATA_TYPE_DCB, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_CCA, conv_data_type: TNS_DATA_TYPE_CCA, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_WRN, conv_data_type: TNS_DATA_TYPE_WRN, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_TLH, conv_data_type: TNS_DATA_TYPE_TLH, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_TOH, conv_data_type: TNS_DATA_TYPE_TOH, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_FOI, conv_data_type: TNS_DATA_TYPE_FOI, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_SID2, conv_data_type: TNS_DATA_TYPE_SID2, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_TCH, conv_data_type: TNS_DATA_TYPE_TCH, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_PII, conv_data_type: TNS_DATA_TYPE_PII, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_PFI, conv_data_type: TNS_DATA_TYPE_PFI, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_PPU, conv_data_type: TNS_DATA_TYPE_PPU, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_PTE, conv_data_type: TNS_DATA_TYPE_PTE, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_RXH8, conv_data_type: TNS_DATA_TYPE_RXH8, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_N12, conv_data_type: TNS_DATA_TYPE_N12, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_AUTH, conv_data_type: TNS_DATA_TYPE_AUTH, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_KVAL, conv_data_type: TNS_DATA_TYPE_KVAL, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_FGI, conv_data_type: TNS_DATA_TYPE_FGI, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_DSY, conv_data_type: TNS_DATA_TYPE_DSY, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_DSYR8, conv_data_type: TNS_DATA_TYPE_DSYR8, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_DSYH8, conv_data_type: TNS_DATA_TYPE_DSYH8, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_DSYL, conv_data_type: TNS_DATA_TYPE_DSYL, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_DSYT8, conv_data_type: TNS_DATA_TYPE_DSYT8, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_DSYV8, conv_data_type: TNS_DATA_TYPE_DSYV8, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_DSYP, conv_data_type: TNS_DATA_TYPE_DSYP, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_DSYF, conv_data_type: TNS_DATA_TYPE_DSYF, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_DSYK, conv_data_type: TNS_DATA_TYPE_DSYK, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_DSYY, conv_data_type: TNS_DATA_TYPE_DSYY, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_DSYQ, conv_data_type: TNS_DATA_TYPE_DSYQ, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_DSYC, conv_data_type: TNS_DATA_TYPE_DSYC, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_DSYA, conv_data_type: TNS_DATA_TYPE_DSYA, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_OT8, conv_data_type: TNS_DATA_TYPE_OT8, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_DSYTY, conv_data_type: TNS_DATA_TYPE_DSYTY, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_AQE, conv_data_type: TNS_DATA_TYPE_AQE, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_KV, conv_data_type: TNS_DATA_TYPE_KV, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_AQD, conv_data_type: TNS_DATA_TYPE_AQD, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_AQ8, conv_data_type: TNS_DATA_TYPE_AQ8, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_RFS, conv_data_type: TNS_DATA_TYPE_RFS, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_RXH10, conv_data_type: TNS_DATA_TYPE_RXH10, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_KPN, conv_data_type: TNS_DATA_TYPE_KPN, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_KPDNR, conv_data_type: TNS_DATA_TYPE_KPDNR, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_DSYD, conv_data_type: TNS_DATA_TYPE_DSYD, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_DSYS, conv_data_type: TNS_DATA_TYPE_DSYS, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_DSYR, conv_data_type: TNS_DATA_TYPE_DSYR, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_DSYH, conv_data_type: TNS_DATA_TYPE_DSYH, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_DSYT, conv_data_type: TNS_DATA_TYPE_DSYT, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_DSYV, conv_data_type: TNS_DATA_TYPE_DSYV, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_AQM, conv_data_type: TNS_DATA_TYPE_AQM, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_OER11, conv_data_type: TNS_DATA_TYPE_OER11, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_AQL, conv_data_type: TNS_DATA_TYPE_AQL, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_OTC, conv_data_type: TNS_DATA_TYPE_OTC, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_KFNO, conv_data_type: TNS_DATA_TYPE_KFNO, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_KFNP, conv_data_type: TNS_DATA_TYPE_KFNP, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_KGT8, conv_data_type: TNS_DATA_TYPE_KGT8, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_RASB4, conv_data_type: TNS_DATA_TYPE_RASB4, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_RAUB2, conv_data_type: TNS_DATA_TYPE_RAUB2, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_RAUB1, conv_data_type: TNS_DATA_TYPE_RAUB1, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_RATXT, conv_data_type: TNS_DATA_TYPE_RATXT, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_RSSB4, conv_data_type: TNS_DATA_TYPE_RSSB4, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_RSUB2, conv_data_type: TNS_DATA_TYPE_RSUB2, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_RSUB1, conv_data_type: TNS_DATA_TYPE_RSUB1, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_RSTXT, conv_data_type: TNS_DATA_TYPE_RSTXT, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_RIDL, conv_data_type: TNS_DATA_TYPE_RIDL, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_GLRDD, conv_data_type: TNS_DATA_TYPE_GLRDD, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_GLRDG, conv_data_type: TNS_DATA_TYPE_GLRDG, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_GLRDC, conv_data_type: TNS_DATA_TYPE_GLRDC, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_OKO, conv_data_type: TNS_DATA_TYPE_OKO, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_DPP, conv_data_type: TNS_DATA_TYPE_DPP, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_DPLS, conv_data_type: TNS_DATA_TYPE_DPLS, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_DPMOP, conv_data_type: TNS_DATA_TYPE_DPMOP, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_STAT, conv_data_type: TNS_DATA_TYPE_STAT, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_RFX, conv_data_type: TNS_DATA_TYPE_RFX, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_FAL, conv_data_type: TNS_DATA_TYPE_FAL, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_CKV, conv_data_type: TNS_DATA_TYPE_CKV, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_DRCX, conv_data_type: TNS_DATA_TYPE_DRCX, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_KGH, conv_data_type: TNS_DATA_TYPE_KGH, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_AQO, conv_data_type: TNS_DATA_TYPE_AQO, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_OKGT, conv_data_type: TNS_DATA_TYPE_OKGT, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_KPFC, conv_data_type: TNS_DATA_TYPE_KPFC, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_FE2, conv_data_type: TNS_DATA_TYPE_FE2, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_SPFP, conv_data_type: TNS_DATA_TYPE_SPFP, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_DPULS, conv_data_type: TNS_DATA_TYPE_DPULS, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_AQA, conv_data_type: TNS_DATA_TYPE_AQA, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_KPBF, conv_data_type: TNS_DATA_TYPE_KPBF, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_TSM, conv_data_type: TNS_DATA_TYPE_TSM, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_MSS, conv_data_type: TNS_DATA_TYPE_MSS, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_KPC, conv_data_type: TNS_DATA_TYPE_KPC, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_CRS, conv_data_type: TNS_DATA_TYPE_CRS, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_KKS, conv_data_type: TNS_DATA_TYPE_KKS, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_KSP, conv_data_type: TNS_DATA_TYPE_KSP, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_KSPTOP, conv_data_type: TNS_DATA_TYPE_KSPTOP, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_KSPVAL, conv_data_type: TNS_DATA_TYPE_KSPVAL, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_PSS, conv_data_type: TNS_DATA_TYPE_PSS, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_NLS, conv_data_type: TNS_DATA_TYPE_NLS, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_ALS, conv_data_type: TNS_DATA_TYPE_ALS, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_KSDEVTVAL, conv_data_type: TNS_DATA_TYPE_KSDEVTVAL, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_KSDEVTTOP, conv_data_type: TNS_DATA_TYPE_KSDEVTTOP, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_KPSPP, conv_data_type: TNS_DATA_TYPE_KPSPP, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_KOL, conv_data_type: TNS_DATA_TYPE_KOL, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_LST, conv_data_type: TNS_DATA_TYPE_LST, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_ACX, conv_data_type: TNS_DATA_TYPE_ACX, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_SCS, conv_data_type: TNS_DATA_TYPE_SCS, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_RXH, conv_data_type: TNS_DATA_TYPE_RXH, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_KPDNS, conv_data_type: TNS_DATA_TYPE_KPDNS, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_KPDCN, conv_data_type: TNS_DATA_TYPE_KPDCN, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_KPNNS, conv_data_type: TNS_DATA_TYPE_KPNNS, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_KPNCN, conv_data_type: TNS_DATA_TYPE_KPNCN, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_KPS, conv_data_type: TNS_DATA_TYPE_KPS, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_APINF, conv_data_type: TNS_DATA_TYPE_APINF, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_TEN, conv_data_type: TNS_DATA_TYPE_TEN, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_XSSCS, conv_data_type: TNS_DATA_TYPE_XSSCS, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_XSSSO, conv_data_type: TNS_DATA_TYPE_XSSSO, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_XSSAO, conv_data_type: TNS_DATA_TYPE_XSSAO, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_KSRPC, conv_data_type: TNS_DATA_TYPE_KSRPC, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_KVL, conv_data_type: TNS_DATA_TYPE_KVL, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_XSSDEF, conv_data_type: TNS_DATA_TYPE_XSSDEF, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_PDQCINV, conv_data_type: TNS_DATA_TYPE_PDQCINV, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_PDQIDC, conv_data_type: TNS_DATA_TYPE_PDQIDC, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_KPDQCSTA, conv_data_type: TNS_DATA_TYPE_KPDQCSTA, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_KPRS, conv_data_type: TNS_DATA_TYPE_KPRS, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_KPDQIDC, conv_data_type: TNS_DATA_TYPE_KPDQIDC, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_RTSTRM, conv_data_type: TNS_DATA_TYPE_RTSTRM, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_SESSGET, conv_data_type: TNS_DATA_TYPE_SESSGET, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_SESSREL, conv_data_type: TNS_DATA_TYPE_SESSREL, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_SESSRET, conv_data_type: TNS_DATA_TYPE_SESSRET, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_SCN6, conv_data_type: TNS_DATA_TYPE_SCN6, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_KECPA, conv_data_type: TNS_DATA_TYPE_KECPA, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_KECPP, conv_data_type: TNS_DATA_TYPE_KECPP, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_SXA, conv_data_type: TNS_DATA_TYPE_SXA, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_KVARR, conv_data_type: TNS_DATA_TYPE_KVARR, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_KPNGN, conv_data_type: TNS_DATA_TYPE_KPNGN, representation: TNS_TYPE_REP_UNIVERSAL },
    // Converted types
    DataTypeDefinition { data_type: ORA_TYPE_NUM_BINARY_INTEGER, conv_data_type: ORA_TYPE_NUM_NUMBER, representation: TNS_TYPE_REP_ORACLE },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_FLOAT, conv_data_type: ORA_TYPE_NUM_NUMBER, representation: TNS_TYPE_REP_ORACLE },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_STR, conv_data_type: ORA_TYPE_NUM_VARCHAR, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_VNU, conv_data_type: ORA_TYPE_NUM_NUMBER, representation: TNS_TYPE_REP_ORACLE },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_PDN, conv_data_type: ORA_TYPE_NUM_NUMBER, representation: TNS_TYPE_REP_ORACLE },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_VCS, conv_data_type: ORA_TYPE_NUM_VARCHAR, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_VBI, conv_data_type: ORA_TYPE_NUM_VARCHAR, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_OAC9, conv_data_type: TNS_DATA_TYPE_OAC9, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_UIN, conv_data_type: ORA_TYPE_NUM_NUMBER, representation: TNS_TYPE_REP_ORACLE },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_SLS, conv_data_type: ORA_TYPE_NUM_NUMBER, representation: TNS_TYPE_REP_ORACLE },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_LVC, conv_data_type: ORA_TYPE_NUM_VARCHAR, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_LVB, conv_data_type: ORA_TYPE_NUM_RAW, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: ORA_TYPE_NUM_CHAR, conv_data_type: ORA_TYPE_NUM_CHAR, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_AVC, conv_data_type: ORA_TYPE_NUM_CHAR, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: ORA_TYPE_NUM_BINARY_FLOAT, conv_data_type: ORA_TYPE_NUM_BINARY_FLOAT, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: ORA_TYPE_NUM_BINARY_DOUBLE, conv_data_type: ORA_TYPE_NUM_BINARY_DOUBLE, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: ORA_TYPE_NUM_CURSOR, conv_data_type: ORA_TYPE_NUM_CURSOR, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_RDD, conv_data_type: ORA_TYPE_NUM_ROWID, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_OSL, conv_data_type: TNS_DATA_TYPE_OSL, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_EXT_NAMED, conv_data_type: ORA_TYPE_NUM_OBJECT, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: ORA_TYPE_NUM_OBJECT, conv_data_type: ORA_TYPE_NUM_OBJECT, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_EXT_REF, conv_data_type: TNS_DATA_TYPE_INT_REF, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_INT_REF, conv_data_type: TNS_DATA_TYPE_INT_REF, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: ORA_TYPE_NUM_CLOB, conv_data_type: ORA_TYPE_NUM_CLOB, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: ORA_TYPE_NUM_BLOB, conv_data_type: ORA_TYPE_NUM_BLOB, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: ORA_TYPE_NUM_BFILE, conv_data_type: ORA_TYPE_NUM_BFILE, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_CFILE, conv_data_type: TNS_DATA_TYPE_CFILE, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_RSET, conv_data_type: ORA_TYPE_NUM_CURSOR, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: ORA_TYPE_NUM_JSON, conv_data_type: ORA_TYPE_NUM_JSON, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_DJSON, conv_data_type: TNS_DATA_TYPE_DJSON, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_CLV, conv_data_type: TNS_DATA_TYPE_CLV, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_DTR, conv_data_type: ORA_TYPE_NUM_NUMBER, representation: TNS_TYPE_REP_ORACLE },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_DUN, conv_data_type: ORA_TYPE_NUM_NUMBER, representation: TNS_TYPE_REP_ORACLE },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_DOP, conv_data_type: ORA_TYPE_NUM_NUMBER, representation: TNS_TYPE_REP_ORACLE },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_VST, conv_data_type: ORA_TYPE_NUM_VARCHAR, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_ODT, conv_data_type: ORA_TYPE_NUM_DATE, representation: TNS_TYPE_REP_ORACLE },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_DOL, conv_data_type: ORA_TYPE_NUM_NUMBER, representation: TNS_TYPE_REP_ORACLE },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_TIME, conv_data_type: TNS_DATA_TYPE_TIME, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_TIME_TZ, conv_data_type: TNS_DATA_TYPE_TIME_TZ, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: ORA_TYPE_NUM_TIMESTAMP, conv_data_type: ORA_TYPE_NUM_TIMESTAMP, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: ORA_TYPE_NUM_TIMESTAMP_TZ, conv_data_type: ORA_TYPE_NUM_TIMESTAMP_TZ, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: ORA_TYPE_NUM_INTERVAL_YM, conv_data_type: ORA_TYPE_NUM_INTERVAL_YM, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: ORA_TYPE_NUM_INTERVAL_DS, conv_data_type: ORA_TYPE_NUM_INTERVAL_DS, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_EDATE, conv_data_type: ORA_TYPE_NUM_DATE, representation: TNS_TYPE_REP_ORACLE },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_ETIME, conv_data_type: TNS_DATA_TYPE_ETIME, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_ETTZ, conv_data_type: TNS_DATA_TYPE_ETTZ, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_ESTAMP, conv_data_type: TNS_DATA_TYPE_ESTAMP, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_ESTZ, conv_data_type: TNS_DATA_TYPE_ESTZ, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_EIYM, conv_data_type: TNS_DATA_TYPE_EIYM, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_EIDS, conv_data_type: TNS_DATA_TYPE_EIDS, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_DCLOB, conv_data_type: ORA_TYPE_NUM_CLOB, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_DBLOB, conv_data_type: ORA_TYPE_NUM_BLOB, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_DBFILE, conv_data_type: ORA_TYPE_NUM_BFILE, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: ORA_TYPE_NUM_UROWID, conv_data_type: ORA_TYPE_NUM_UROWID, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: ORA_TYPE_NUM_TIMESTAMP_LTZ, conv_data_type: ORA_TYPE_NUM_TIMESTAMP_LTZ, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_ESITZ, conv_data_type: ORA_TYPE_NUM_TIMESTAMP_LTZ, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_UB8, conv_data_type: TNS_DATA_TYPE_UB8, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_PNTY, conv_data_type: ORA_TYPE_NUM_OBJECT, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: ORA_TYPE_NUM_BOOLEAN, conv_data_type: ORA_TYPE_NUM_BOOLEAN, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_XSNSOP, conv_data_type: TNS_DATA_TYPE_XSNSOP, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_XSATTR, conv_data_type: TNS_DATA_TYPE_XSATTR, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_XSNS, conv_data_type: TNS_DATA_TYPE_XSNS, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_UB1ARRAY, conv_data_type: TNS_DATA_TYPE_UB1ARRAY, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_SESSSTATE, conv_data_type: TNS_DATA_TYPE_SESSSTATE, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_AC_REPLAY, conv_data_type: TNS_DATA_TYPE_AC_REPLAY, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_AC_CONT, conv_data_type: TNS_DATA_TYPE_AC_CONT, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_IMPLRES, conv_data_type: TNS_DATA_TYPE_IMPLRES, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_OER19, conv_data_type: TNS_DATA_TYPE_OER19, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_TXT, conv_data_type: TNS_DATA_TYPE_TXT, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_XSSESSNS, conv_data_type: TNS_DATA_TYPE_XSSESSNS, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_XSATTOP, conv_data_type: TNS_DATA_TYPE_XSATTOP, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_XSCREOP, conv_data_type: TNS_DATA_TYPE_XSCREOP, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_XSDETOP, conv_data_type: TNS_DATA_TYPE_XSDETOP, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_XSDESOP, conv_data_type: TNS_DATA_TYPE_XSDESOP, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_XSSETSP, conv_data_type: TNS_DATA_TYPE_XSSETSP, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_XSSIDP, conv_data_type: TNS_DATA_TYPE_XSSIDP, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_XSPRIN, conv_data_type: TNS_DATA_TYPE_XSPRIN, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_XSKVL, conv_data_type: TNS_DATA_TYPE_XSKVL, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_XSSSDEF2, conv_data_type: TNS_DATA_TYPE_XSSSDEF2, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_XSNSOP2, conv_data_type: TNS_DATA_TYPE_XSNSOP2, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_XSNS2, conv_data_type: TNS_DATA_TYPE_XSNS2, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_KPDNREQ, conv_data_type: TNS_DATA_TYPE_KPDNREQ, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_KPDNRNF, conv_data_type: TNS_DATA_TYPE_KPDNRNF, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_KPNGNC, conv_data_type: TNS_DATA_TYPE_KPNGNC, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_KPNRI, conv_data_type: TNS_DATA_TYPE_KPNRI, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_AQENQ, conv_data_type: TNS_DATA_TYPE_AQENQ, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_AQDEQ, conv_data_type: TNS_DATA_TYPE_AQDEQ, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_AQJMS, conv_data_type: TNS_DATA_TYPE_AQJMS, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_KPDNRPAY, conv_data_type: TNS_DATA_TYPE_KPDNRPAY, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_KPDNRACK, conv_data_type: TNS_DATA_TYPE_KPDNRACK, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_KPDNRMP, conv_data_type: TNS_DATA_TYPE_KPDNRMP, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_KPDNRDQ, conv_data_type: TNS_DATA_TYPE_KPDNRDQ, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_SCN, conv_data_type: TNS_DATA_TYPE_SCN, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_SCN8, conv_data_type: TNS_DATA_TYPE_SCN8, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_CHUNKINFO, conv_data_type: TNS_DATA_TYPE_CHUNKINFO, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_UD21, conv_data_type: TNS_DATA_TYPE_UD21, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_UDS, conv_data_type: TNS_DATA_TYPE_UDS, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_TNP, conv_data_type: TNS_DATA_TYPE_TNP, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_OER, conv_data_type: TNS_DATA_TYPE_OER, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_OAC, conv_data_type: TNS_DATA_TYPE_OAC, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_SESSSIGN, conv_data_type: TNS_DATA_TYPE_SESSSIGN, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: ORA_TYPE_NUM_VECTOR, conv_data_type: ORA_TYPE_NUM_VECTOR, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_PLEND, conv_data_type: TNS_DATA_TYPE_PLEND, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_PLBGN, conv_data_type: TNS_DATA_TYPE_PLBGN, representation: TNS_TYPE_REP_UNIVERSAL },
    DataTypeDefinition { data_type: TNS_DATA_TYPE_PLOP, conv_data_type: TNS_DATA_TYPE_PLOP, representation: TNS_TYPE_REP_UNIVERSAL },
];

/// Data types negotiation message
#[derive(Debug)]
pub struct DataTypesMessage {
    _private: (),
}

impl DataTypesMessage {
    /// Create a new DataTypes message
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Build the DataTypes request packet
    pub fn build_request(&self, caps: &Capabilities, large_sdu: bool) -> Result<Bytes> {
        let mut buf = WriteBuffer::with_capacity(4096);

        // Reserve space for packet header
        buf.write_zeros(PACKET_HEADER_SIZE)?;

        // Data flags (2 bytes)
        buf.write_u16_be(0)?;

        // Message type
        buf.write_u8(MessageType::DataTypes as u8)?;

        // Character set IDs (little-endian)
        buf.write_u16_le(charset::UTF8)?;
        buf.write_u16_le(charset::UTF8)?;

        // Encoding flags
        buf.write_u8(encoding::MULTI_BYTE | encoding::CONV_LENGTH)?;

        // Compile capabilities (length-prefixed)
        buf.write_bytes_with_length(Some(&caps.compile_caps))?;

        // Runtime capabilities (length-prefixed)
        buf.write_bytes_with_length(Some(&caps.runtime_caps))?;

        // Data type definitions
        for dt in DATA_TYPES {
            buf.write_u16_be(dt.data_type)?;
            buf.write_u16_be(dt.conv_data_type)?;
            buf.write_u16_be(dt.representation)?;
            buf.write_u16_be(0)?; // Reserved
        }

        // Terminator
        buf.write_u16_be(0)?;

        // Calculate total length and write header
        let total_len = buf.len() as u32;
        let header = PacketHeader::new(PacketType::Data, total_len);
        let mut header_buf = WriteBuffer::with_capacity(PACKET_HEADER_SIZE);
        header.write(&mut header_buf, large_sdu)?;

        // Patch the header at the beginning
        let mut result = buf.into_inner();
        result[..PACKET_HEADER_SIZE].copy_from_slice(header_buf.as_slice());

        Ok(result.freeze())
    }

    /// Parse the DataTypes response
    ///
    /// The server echoes back the data types, which we just skip through.
    pub fn parse_response(&self, payload: &[u8]) -> Result<()> {
        let mut buf = ReadBuffer::from_slice(payload);

        // Skip data flags (2 bytes)
        buf.skip(2)?;

        // The response contains the same data type format
        // We just need to verify it's valid by reading through it
        loop {
            let data_type = buf.read_u16_be()?;
            if data_type == 0 {
                break;
            }

            // Read conv_data_type
            let conv_data_type = buf.read_u16_be()?;
            if conv_data_type != 0 {
                // Skip representation and reserved
                buf.skip(4)?;
            }
        }

        Ok(())
    }
}

impl Default for DataTypesMessage {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_types_count() {
        // Verify we have approximately the expected number of data types
        assert!(DATA_TYPES.len() > 200, "Expected 200+ data types, got {}", DATA_TYPES.len());
    }

    #[test]
    fn test_build_data_types_request() {
        let caps = Capabilities::new();
        let msg = DataTypesMessage::new();
        let packet = msg.build_request(&caps, false).unwrap();

        // Check header
        assert!(packet.len() > PACKET_HEADER_SIZE);
        assert_eq!(packet[4], PacketType::Data as u8);

        // Check message type
        assert_eq!(packet[PACKET_HEADER_SIZE + 2], MessageType::DataTypes as u8);

        // Check charset IDs (little-endian)
        let charset1 = u16::from_le_bytes([
            packet[PACKET_HEADER_SIZE + 3],
            packet[PACKET_HEADER_SIZE + 4],
        ]);
        assert_eq!(charset1, charset::UTF8);
    }

    #[test]
    fn test_critical_internal_types_present() {
        // Verify critical internal types are in the list
        let has_ub2 = DATA_TYPES.iter().any(|dt| dt.data_type == TNS_DATA_TYPE_UB2);
        let has_ub4 = DATA_TYPES.iter().any(|dt| dt.data_type == TNS_DATA_TYPE_UB4);
        let has_ub8 = DATA_TYPES.iter().any(|dt| dt.data_type == TNS_DATA_TYPE_UB8);
        let has_auth = DATA_TYPES.iter().any(|dt| dt.data_type == TNS_DATA_TYPE_AUTH);

        assert!(has_ub2, "UB2 type must be present");
        assert!(has_ub4, "UB4 type must be present");
        assert!(has_ub8, "UB8 type must be present");
        assert!(has_auth, "AUTH type must be present");
    }

    #[test]
    fn test_parse_data_types_response() {
        // Build a minimal response
        let mut payload = Vec::new();

        // Data flags
        payload.extend_from_slice(&[0x00, 0x00]);

        // A single data type followed by terminator
        payload.extend_from_slice(&1u16.to_be_bytes()); // data_type
        payload.extend_from_slice(&1u16.to_be_bytes()); // conv_data_type
        payload.extend_from_slice(&1u16.to_be_bytes()); // representation
        payload.extend_from_slice(&0u16.to_be_bytes()); // reserved

        // Terminator
        payload.extend_from_slice(&0u16.to_be_bytes());

        let msg = DataTypesMessage::new();
        let result = msg.parse_response(&payload);
        assert!(result.is_ok());
    }
}
