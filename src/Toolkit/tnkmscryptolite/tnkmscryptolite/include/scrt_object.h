#ifndef __SCRT_OBJECT_H__
#define __SCRT_OBJECT_H__

/*
!Notation! 
SN : Short Name, 축약형 이름 
LN : Long Name, RFC, PKCS등의 표준 문서에 나타있는 이름
NID : Numeric ID 
OBJ : Object ID, 일반적으로 Length and Value로 표현됨

CertLib에서 사용되는 알고리즘에 대한 ID도 추가적으로 정의할 필요가 있음(예:PBE.... 등)
*/

#define SN_undef			 "UNDEF"
#define LN_undef			 "undefined"
#define NID_undef			 0
#define OBJ_undef			 0L

/* Hash Algorithm ID */
#define SN_sha256			 "SHA256"
#define LN_sha256			 "sha256"
#define NID_sha256			 105
#define OBJ_sha256			 9L,96L,134L,72L,1L,101L,3L,4L,2L,1L

#define SN_sha512			 "SHA512"
#define LN_sha512			 "sha512"
#define NID_sha512			 107
#define OBJ_sha512			 9L,96L,134L,72L,1L,101L,3L,4L,2L,3L

#define SN_lsh256			 "LSH256"
#define LN_lsh256			 "lsh256"
#define NID_lsh256			 110
#define OBJ_lsh256			 

#define SN_lsh512			 "LSH512"
#define LN_lsh512			 "lsh512"
#define NID_lsh512			 112
#define OBJ_lsh512			 

/* Block Cipher Algorithm ID */

#define SN_seed_ecb		     "SEED-ECB"
#define LN_seed_ecb			 "seed-ecb"
#define NID_seed_ecb		 701

#define SN_seed_cbc			 "SEED-CBC"
#define LN_seed_cbc			 "seed-cbc"
#define NID_seed_cbc		 702

#define SN_seed_cfb64		 "SEED-CFB"
#define LN_seed_cfb64		 "seed-cfb"
#define NID_seed_cfb64		 703

#define SN_seed_ofb64		 "SEED-OFB"
#define LN_seed_ofb64		 "seed-ofb"
#define NID_seed_ofb64		 704

#define SN_seed_cfb128		 "SEED-CFB128"
#define LN_seed_cfb128		 "seed-cfb128"
#define NID_seed_cfb128		 705

#define SN_seed_ctr128		"SEED-CTR"
#define LN_seed_ctr128		"seed-ctr"
#define NID_seed_ctr128		706

#define SN_seed256_ecb		"SEED-256-ECB"
#define LN_seed256_ecb		"seed-256-ecb"
#define NID_seed256_ecb		707

#define SN_seed256_cbc		"SEED-256-CBC"
#define LN_seed256_cbc		"seed-256-cbc"
#define NID_seed256_cbc		708

#define SN_seed256_cfb64	"SEED-256-CFB"
#define LN_seed256_cfb64	"seed-256-cfb"
#define NID_seed256_cfb64	709

#define SN_seed256_ofb64	"SEED-256-OFB"
#define LN_seed256_ofb64	"seed-256-ofb"
#define NID_seed256_ofb64	710

#define SN_seed256_cfb128	"SEED-256-CFB128"
#define LN_seed256_cfb128	"seed-256-cfb128"
#define NID_seed256_cfb128	711

#define SN_seed256_ctr128	"SEED-256-CTR"
#define LN_seed256_ctr128	"seed-256-ctr"
#define NID_seed256_ctr128	712

#define SN_aes_128_ecb		 "AES-128-ECB"
#define LN_aes_128_ecb		 "aes-128-ecb"
#define NID_aes_128_ecb		 1300

#define SN_aes_192_ecb		 "AES-192-ECB"
#define LN_aes_192_ecb		 "aes-192-ecb"
#define NID_aes_192_ecb		 1301

#define SN_aes_256_ecb		 "AES-256-ECB"
#define LN_aes_256_ecb		 "aes-256-ecb"
#define NID_aes_256_ecb		 1302

#define SN_aes_128_cbc		 "AES-128-CBC"
#define LN_aes_128_cbc		 "aes-128-cbc"
#define NID_aes_128_cbc		 1303

#define SN_aes_192_cbc		 "AES-192-CBC"
#define LN_aes_192_cbc		 "aes-192-cbc"
#define NID_aes_192_cbc		 1304

#define SN_aes_256_cbc		 "AES-256-CBC"
#define LN_aes_256_cbc		 "aes-256-cbc"
#define NID_aes_256_cbc		 1305

#define SN_aes_128_cfb128	 "AES-128-CFB"
#define LN_aes_128_cfb128	 "aes-128-cfb"
#define NID_aes_128_cfb128	 1306

#define SN_aes_192_cfb128	 "AES-192-CFB"
#define LN_aes_192_cfb128	 "aes-192-cfb"
#define NID_aes_192_cfb128	 1307

#define SN_aes_256_cfb128	 "AES-256-CFB"
#define LN_aes_256_cfb128	 "aes-256-cfb"
#define NID_aes_256_cfb128	 1308

#define SN_aes_128_ofb128	 "AES-128-OFB"
#define LN_aes_128_ofb128	 "aes-128-ofb"
#define NID_aes_128_ofb128	 1309

#define SN_aes_192_ofb128	 "AES-192-OFB"
#define LN_aes_192_ofb128	 "aes-192-ofb"
#define NID_aes_192_ofb128	 1310

#define SN_aes_256_ofb128	 "AES-256-OFB"
#define LN_aes_256_ofb128	 "aes-256-ofb"
#define NID_aes_256_ofb128	 1311

#define SN_aes_128_ctr128	 "AES-128-CTR"
#define LN_aes_128_ctr128	 "aes-128-ctr"
#define NID_aes_128_ctr128	 1312

#define SN_aes_192_ctr128	 "AES-192-CTR"
#define LN_aes_192_ctr128	 "aes-192-ctr"
#define NID_aes_192_ctr128	 1313

#define SN_aes_256_ctr128	 "AES-256-CTR"
#define LN_aes_256_ctr128	 "aes-256-ctr"
#define NID_aes_256_ctr128	 1314

#define SN_aes_128_cfb1	     "AES-128-CFB1"
#define LN_aes_128_cfb1	     "aes-128-cfb1"
#define NID_aes_128_cfb1	 1315

#define SN_aes_192_cfb1	     "AES-192-CFB1"
#define LN_aes_192_cfb1	     "aes-192-cfb1"
#define NID_aes_192_cfb1	 1316

#define SN_aes_256_cfb1	     "AES-256-CFB1"
#define LN_aes_256_cfb1	     "aes-256-cfb1"
#define NID_aes_256_cfb1	 1317

#define SN_aes_128_cfb8	     "AES-128-CFB8"
#define LN_aes_128_cfb8	     "aes-128-cfb8"
#define NID_aes_128_cfb8	 1318

#define SN_aes_192_cfb8	     "AES-192-CFB8"
#define LN_aes_192_cfb8	     "aes-192-cfb8"
#define NID_aes_192_cfb8	 1319

#define SN_aes_256_cfb8	     "AES-256-CFB8"
#define LN_aes_256_cfb8	     "aes-256-cfb8"
#define NID_aes_256_cfb8	 1320

#define SN_aria_128_ecb		 "ARIA-128-ECB"
#define LN_aria_128_ecb		 "aria-128-ecb"
#define NID_aria_128_ecb	 1401

#define SN_aria_192_ecb		 "ARIA-192-ECB"
#define LN_aria_192_ecb		 "aria-192-ecb"
#define NID_aria_192_ecb	 1402

#define SN_aria_256_ecb		 "ARIA-256-ECB"
#define LN_aria_256_ecb		 "aria-256-ecb"
#define NID_aria_256_ecb	 1403

#define SN_aria_128_cbc		 "ARIA-128-CBC"
#define LN_aria_128_cbc		 "aria-128-cbc"
#define NID_aria_128_cbc	 1404

#define SN_aria_192_cbc		 "ARIA-192-CBC"
#define LN_aria_192_cbc		 "aria-192-cbc"
#define NID_aria_192_cbc	 1405

#define SN_aria_256_cbc		 "ARIA-256-CBC"
#define LN_aria_256_cbc		 "aria-256-cbc"
#define NID_aria_256_cbc	 1406

#define SN_aria_128_cfb128	 "ARIA-128-CFB128"
#define LN_aria_128_cfb128	 "aria-128-cfb128"
#define NID_aria_128_cfb128	 1407

#define SN_aria_192_cfb128	 "ARIA-192-CFB128"
#define LN_aria_192_cfb128	 "aria-192-cfb128"
#define NID_aria_192_cfb128	 1408

#define SN_aria_256_cfb128	 "ARIA-256-CFB128"
#define LN_aria_256_cfb128	 "aria-256-cfb128"
#define NID_aria_256_cfb128	 1409

#define SN_aria_128_ofb128	 "ARIA-128-OFB128"
#define LN_aria_128_ofb128	 "aria-128-ofb128"
#define NID_aria_128_ofb128	 1410

#define SN_aria_192_ofb128	 "ARIA-192-OFB128"
#define LN_aria_192_ofb128	 "aria-192-ofb128"
#define NID_aria_192_ofb128	 1411

#define SN_aria_256_ofb128	 "ARIA-256-OFB128"
#define LN_aria_256_ofb128	 "aria-256-ofb128"
#define NID_aria_256_ofb128	 1412

#define SN_aria_128_ctr128	 "ARIA-128-CTR128"
#define LN_aria_128_ctr128	 "aria-128-ctr128"
#define NID_aria_128_ctr128	 1413

#define SN_aria_192_ctr128	 "ARIA-192-CTR-128"
#define LN_aria_192_ctr128	 "aria-192-ctr-128"
#define NID_aria_192_ctr128	 1414

#define SN_aria_256_ctr128	 "ARIA-256-CTR-128"
#define LN_aria_256_ctr128	 "aria-256-ctr-128"
#define NID_aria_256_ctr128	 1415

#define SN_lea_128_ecb		 "LEA-128-ECB"
#define LN_lea_128_ecb		 "lea-128-ecb"
#define NID_lea_128_ecb	 1501

#define SN_lea_192_ecb		 "LEA-192-ECB"
#define LN_lea_192_ecb		 "lea-192-ecb"
#define NID_lea_192_ecb	 1502

#define SN_lea_256_ecb		 "LEA-256-ECB"
#define LN_lea_256_ecb		 "lea-256-ecb"
#define NID_lea_256_ecb	 1503

#define SN_lea_128_cbc		 "LEA-128-CBC"
#define LN_lea_128_cbc		 "lea-128-cbc"
#define NID_lea_128_cbc	 1504

#define SN_lea_192_cbc		 "LEA-192-CBC"
#define LN_lea_192_cbc		 "lea-192-cbc"
#define NID_lea_192_cbc	 1505

#define SN_lea_256_cbc		 "LEA-256-CBC"
#define LN_lea_256_cbc		 "lea-256-cbc"
#define NID_lea_256_cbc	 1506

#define SN_lea_128_cfb128	 "LEA-128-CFB128"
#define LN_lea_128_cfb128	 "lea-128-cfb128"
#define NID_lea_128_cfb128	 1507

#define SN_lea_192_cfb128	 "LEA-192-CFB128"
#define LN_lea_192_cfb128	 "lea-192-cfb128"
#define NID_lea_192_cfb128	 1508

#define SN_lea_256_cfb128	 "LEA-256-CFB128"
#define LN_lea_256_cfb128	 "lea-256-cfb128"
#define NID_lea_256_cfb128	 1509

#define SN_lea_128_ofb128	 "LEA-128-OFB128"
#define LN_lea_128_ofb128	 "lea-128-ofb128"
#define NID_lea_128_ofb128	 1510

#define SN_lea_192_ofb128	 "LEA-192-OFB128"
#define LN_lea_192_ofb128	 "lea-192-ofb128"
#define NID_lea_192_ofb128	 1511

#define SN_lea_256_ofb128	 "LEA-256-OFB128"
#define LN_lea_256_ofb128	 "lea-256-ofb128"
#define NID_lea_256_ofb128	 1512

#define SN_lea_128_ctr128	 "LEA-128-CTR128"
#define LN_lea_128_ctr128	 "lea-128-ctr128"
#define NID_lea_128_ctr128	 1513

#define SN_lea_192_ctr128	 "LEA-192-CTR-128"
#define LN_lea_192_ctr128	 "lea-192-ctr-128"
#define NID_lea_192_ctr128	 1514

#define SN_lea_256_ctr128	 "LEA-256-CTR-128"
#define LN_lea_256_ctr128	 "lea-256-ctr-128"
#define NID_lea_256_ctr128	 1515

/* Public Key Encryption Algorithm ID */

/*Public Signature Algorithm ID */
#define SN_has160WithRSAEncryption	    "RSA-HAS160"
#define LN_has160WithRSAEncryption	    "has160WithRSAEncryption"
#define NID_has160WithRSAEncryption	    901

#define SN_has160WithDSAEncryption		"DSA-HAS160"
#define LN_has160WithDSAEncryption		"has160WithDSAEncryption"
#define NID_has160WithDSAEncryption		902

#define SN_has160WithKCDSAEncryption	"KCDSA-HAS160"
#define LN_has160WithKCDSAEncryption	"has160WithKCDSAEncryption"
#define NID_has160WithKCDSAEncryption	903

#define SN_sha1WithRSAEncryption	    "RSA-SHA1"
#define LN_sha1WithRSAEncryption	    "sha1WithRSAEncryption"
#define NID_sha1WithRSAEncryption	    904
#define OBJ_sha1WithRSAEncryption	    OBJ_pkcs,1L,5L

#define SN_sha1WithDSAEncryption		"DSA-SHA1"
#define LN_sha1WithDSAEncryption		"sha1WithDSAEncryption"
#define NID_sha1WithDSAEncryption		905

#define SN_sha1WithKCDSAEncryption		"KCDSA-SHA1"
#define LN_sha1WithKCDSAEncryption		"sha1WithKCDSAEncryption"
#define NID_sha1WithKCDSAEncryption		906

#define SN_md5WithRSAEncryption		    "RSA-MD5"
#define LN_md5WithRSAEncryption		    "md5WithRSAEncryption"
#define NID_md5WithRSAEncryption	    907
#define OBJ_md5WithRSAEncryption	    OBJ_pkcs,1L,4L

#define SN_ripemd160WithRSA		        "RSA-RIPEMD160"
#define LN_ripemd160WithRSA		        "ripemd160WithRSA"
#define NID_ripemd160WithRSA		    908
#define OBJ_ripemd160WithRSA	    	1L,3L,36L,3L,3L,1L,2L

#define SN_sha256WithRSAEncryption	    "RSA-SHA256"
#define LN_sha256WithRSAEncryption	    "sha256WithRSAEncryption"
#define NID_sha256WithRSAEncryption	    909
#define OBJ_sha256WithRSAEncryption	    OBJ_pkcs,1L,11L

#define SN_sha384WithRSAEncryption	    "RSA-SHA384"
#define LN_sha384WithRSAEncryption	    "sha384WithRSAEncryption"
#define NID_sha384WithRSAEncryption	    910
#define OBJ_sha384WithRSAEncryption	    OBJ_pkcs,1L,12L

#define SN_sha512WithRSAEncryption	    "RSA-SHA512"
#define LN_sha512WithRSAEncryption	    "sha512WithRSAEncryption"
#define NID_sha512WithRSAEncryption	    911
#define OBJ_sha512WithRSAEncryption	    OBJ_pkcs,1L,13L

#define SN_sha224WithRSAEncryption	    "RSA-SHA224"
#define LN_sha224WithRSAEncryption	    "sha224WithRSAEncryption"
#define NID_sha224WithRSAEncryption	    912
#define OBJ_sha224WithRSAEncryption	    OBJ_pkcs,1L,14L

#define SN_sha224WithKCDSAEncryption	"KCDSA-SHA224"
#define LN_sha224WithKCDSAEncryption	"sha224WithKCDSAEncryption"
#define NID_sha224WithKCDSAEncryption	913

#define SN_sha256WithKCDSAEncryption	"KCDSA-SHA256"
#define LN_sha256WithKCDSAEncryption	"sha256WithKCDSAEncryption"
#define NID_sha256WithKCDSAEncryption	914

#define NID_sha224WithRSA_PSS_Encryption	915
#define NID_sha256WithRSA_PSS_Encryption	916
#define NID_sha384WithRSA_PSS_Encryption	917
#define NID_sha512WithRSA_PSS_Encryption	918
#define NID_sha224WithRSA_OAEP_Encryption	919
#define NID_sha256WithRSA_OAEP_Encryption	920
#define NID_sha1WithRSA_OAEP_Encryption		921
#define NID_sha1WithRSA_PSS_Encryption		922

#define SN_lsh256WithRSAEncryption	    "RSA-LSH256"
#define LN_lsh256WithRSAEncryption	    "lsh256WithRSAEncryption"
#define NID_lsh256WithRSAEncryption	    931
#define OBJ_lsh256WithRSAEncryption	    

#define SN_lsh512WithRSAEncryption	    "RSA-LSH512"
#define LN_lsh512WithRSAEncryption	    "lsh512WithRSAEncryption"
#define NID_lsh512WithRSAEncryption	    933
#define OBJ_lsh512WithRSAEncryption	  

/* Password Based Encryption Algorithm ID */
#define SN_pbeWithMD5AndDES_CBC 	    "PBE-MD5-DESCBC"
#define LN_pbeWithMD5AndDES_CBC 	    "pbeWithMD5AndDES_CBC"
#define NID_pbeWithMD5AndDES_CBC 	    1001

#define SN_pbeWithSHA1AndDES_CBC 	    "PBE-SHA1-DESCBC"
#define LN_pbeWithSHA1AndDES_CBC 	    "pbeWithSHA1AndDES_CBC"
#define NID_pbeWithSHA1AndDES_CBC 	    1002

#define SN_pbeWithSHA1And3DES_CBC 	    "PBE-SHA1-3DESCBC"
#define LN_pbeWithSHA1And3DES_CBC 	    "pbeWithSHAAnd2_KeyTripleDES_CBC"
#define NID_pbeWithSHA1And2Key3DES_CBC 	 1003

#define SN_pbeWithSHA1AndSEED_CBC 	    "PBE-SHA1-SEEDCBC"
#define LN_pbeWithSHA1AndSEED_CBC 	    "pbeWithSHA1AndSEED_CBC"
#define NID_pbeWithSHA1And3Key3DES_CBC 	 1004

#define SN_pbeWithHAS160And3DES_CBC     "PBE-HAS160-3DESCBC"
#define LN_pbeWithHAS160And3DES_CBC     "pbeWithHAS160And3DES_CBC"
#define NID_pbeWithHAS160And3DES_CBC    1005

#define SN_pbeWithSHA1AndSEED_CBC 	    "PBE-SHA1-SEEDCBC"
#define LN_pbeWithSHA1AndSEED_CBC 	    "pbeWithSHA1AndSEED_CBC"
#define NID_pbeWithSHA1AndSEED_CBC 	    1006

#define SN_pbeWithHAS160AndSEED_CBC     "PBE-HAS160-SEEDCBC"
#define LN_pbeWithHAS160AndSEED_CBC 	"pbeWithHAS160AndSEED_CBC"
#define NID_pbeWithHAS160AndSEED_CBC    1007

#define NID_pbewithSHAAnd40BitRC2_CBC   1008
#define NID_pbeWithSHAAnd128BitRC2_CBC  1009
#define NID_pbeWithSHAAnd40BitRC4       1010
#define NID_pbeWithSHAAnd128BitRC4      1011

/* ocsp nid*/
#define NID_ocsp_Nonce						1012
#define NID_ocsp_CrlRef						1013
#define	NID_ocsp_AcceptableResponseType		1014	
#define	NID_ocsp_ArchiveCutoff				1015	
#define	NID_ocsp_ServiceLocator				1016	
#define	NID_ocsp_AccessMethod_ocsp			1017	
#define NID_ocsp_OCSPSigning				1018	
#define NID_ocsp_OCSP						1019	
#define NID_ocsp_Basic						1020	
#define	NID_ocsp_AccessMethod_ldap			1021	

/* CMS NID */
#define NID_cms_signingtime					1090
#define	NID_cms_contenttype					1091
#define	NID_cms_messagedigest				1092

/* HMAC Algorithm ID */
#define SN_hMACWithSHA1          	    "HMAC-SHA1"
#define LN_hMACWithSHA1         	    "hMAC_SHA1"
#define NID_hMACWithSHA1        	    1101
#define NID_ID_DATA						1102

#endif