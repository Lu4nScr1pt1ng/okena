; bcrypt in `auth basic users=FILE`: lines as htpasswd -B writes them,
; `name:$2y$10$...` ($2a$, $2b$, $2y$), checked by a process of its own,
; okena-bcrypt, never by a worker: a check costs tens of milliseconds of CPU
; (that is the point of bcrypt), which would stop a worker's loop for every
; connection it holds.
;
; A worker that gets such a name and its password looks for them in a table
; shared with okena-bcrypt, by the SHA-256 of `name:password` (and the user's
; line): a yes is kept 5 minutes, a no 10 seconds. Not there: the question
; goes on a ring okena-bcrypt reads (woken by a futex), and the request is
; held (fault_hold) 2 ms at a time until the answer is in the table, 8
; seconds at most (then 503, as when the ring is full: a flood of wrong
; passwords costs one core, not the workers, and gets 503s). Asked twice at
; once, the second waits for the first's answer.
;
; The table and the ring are one shared mapping, made before the workers
; fork, under one spinlock held for a lookup at most. A reload counts a new
; generation: okena-bcrypt starts again with the new plan, and what the old
; generation asked or knew is not believed by the new one.

BY_LOCK		:= 0			; d
BY_HEAD		:= 4			; d: the workers' (requests put)
BY_TAIL		:= 8			; d: okena-bcrypt's (taken)
BY_WAKE		:= 12			; d: the futex okena-bcrypt sleeps on
BY_GEN		:= 16			; d
BY_RING		:= 64
BY_RN		:= 256			; requests waiting, at most
YQ_KEY		:= 0			; 32
YQ_SLOT		:= 32			; d: the user's line (g_auth_tab's index)
YQ_PLEN		:= 36			; d: 72 at most (bcrypt reads no more)
YQ_GEN		:= 40			; d
YQ_PW		:= 48			; 72
YQ_SIZE		:= 128
BY_CACHE	:= BY_RING + BY_RN * YQ_SIZE
BY_N		:= 8192			; answers kept
BY_PROBE	:= 16
YE_KEY		:= 0			; 32
YE_STATE	:= 32			; d: YS_*
YE_T		:= 36			; d: seconds (monotonic)
YE_GEN		:= 40			; d
YE_SIZE		:= 48
BY_SIZE		:= BY_CACHE + BY_N * YE_SIZE
YS_OK		:= 1
YS_BAD		:= 2
YS_ASKED	:= 3
BY_OK_S		:= 300			; a yes, kept
BY_BAD_S	:= 10			; a no
BY_ASK_S	:= 15			; a question not answered: asked again after
BY_HOLD_US	:= 2000
BY_WAIT_MS	:= 8000			; (cost 16 takes some 4 s alone)
AT_BCRYPT	:= 0x100		; AT_SLEN: bcrypt, | its cost
BF_P		:= 0
BF_S		:= 72
FUTEX_WAIT_	:= 0
FUTEX_WAKE_	:= 1

bss
	align 8
	g_bc_shm	dq ?			; the shared mapping, 0 none
	g_bc_gen	dd ?			; this process's generation
	g_bc_pid	dd ?
	g_plan_bcrypt	dd ?			; some users file has bcrypt lines
	g_bc_key:	rb 32
	align 8
	g_bf		rd 18 + 1024		; okena-bcrypt: Blowfish's state
	g_bc_kw		rd 18			; the key, as words
	g_bc_sw		rd 18			; the salt, as a key
	g_bc_s4		rd 4			; the salt
	g_bc_ct		rd 6
	g_bc_kb:	rb 80
	g_bcq:		rb YQ_SIZE		; the request being answered
end bss

rodata
	align 4
	; "OrpheanBeholderScryDoubt", big-endian words
	bc_magic	dd 0x4F727068,0x65616E42,0x65686F6C,0x64657253,0x63727944,0x6F756274
	align 8
	ts_bc_wait	dq 1, 0
	bc_name		db 'okena-bcrypt',0
end rodata

rodata
	align 4
	; Blowfish's first state: pi's fractional part in hex (P, then the S-boxes)
	bf_pi	dd 0x243F6A88,0x85A308D3,0x13198A2E,0x03707344,0xA4093822,0x299F31D0,0x082EFA98,0xEC4E6C89
		dd 0x452821E6,0x38D01377,0xBE5466CF,0x34E90C6C,0xC0AC29B7,0xC97C50DD,0x3F84D5B5,0xB5470917
		dd 0x9216D5D9,0x8979FB1B,0xD1310BA6,0x98DFB5AC,0x2FFD72DB,0xD01ADFB7,0xB8E1AFED,0x6A267E96
		dd 0xBA7C9045,0xF12C7F99,0x24A19947,0xB3916CF7,0x0801F2E2,0x858EFC16,0x636920D8,0x71574E69
		dd 0xA458FEA3,0xF4933D7E,0x0D95748F,0x728EB658,0x718BCD58,0x82154AEE,0x7B54A41D,0xC25A59B5
		dd 0x9C30D539,0x2AF26013,0xC5D1B023,0x286085F0,0xCA417918,0xB8DB38EF,0x8E79DCB0,0x603A180E
		dd 0x6C9E0E8B,0xB01E8A3E,0xD71577C1,0xBD314B27,0x78AF2FDA,0x55605C60,0xE65525F3,0xAA55AB94
		dd 0x57489862,0x63E81440,0x55CA396A,0x2AAB10B6,0xB4CC5C34,0x1141E8CE,0xA15486AF,0x7C72E993
		dd 0xB3EE1411,0x636FBC2A,0x2BA9C55D,0x741831F6,0xCE5C3E16,0x9B87931E,0xAFD6BA33,0x6C24CF5C
		dd 0x7A325381,0x28958677,0x3B8F4898,0x6B4BB9AF,0xC4BFE81B,0x66282193,0x61D809CC,0xFB21A991
		dd 0x487CAC60,0x5DEC8032,0xEF845D5D,0xE98575B1,0xDC262302,0xEB651B88,0x23893E81,0xD396ACC5
		dd 0x0F6D6FF3,0x83F44239,0x2E0B4482,0xA4842004,0x69C8F04A,0x9E1F9B5E,0x21C66842,0xF6E96C9A
		dd 0x670C9C61,0xABD388F0,0x6A51A0D2,0xD8542F68,0x960FA728,0xAB5133A3,0x6EEF0B6C,0x137A3BE4
		dd 0xBA3BF050,0x7EFB2A98,0xA1F1651D,0x39AF0176,0x66CA593E,0x82430E88,0x8CEE8619,0x456F9FB4
		dd 0x7D84A5C3,0x3B8B5EBE,0xE06F75D8,0x85C12073,0x401A449F,0x56C16AA6,0x4ED3AA62,0x363F7706
		dd 0x1BFEDF72,0x429B023D,0x37D0D724,0xD00A1248,0xDB0FEAD3,0x49F1C09B,0x075372C9,0x80991B7B
		dd 0x25D479D8,0xF6E8DEF7,0xE3FE501A,0xB6794C3B,0x976CE0BD,0x04C006BA,0xC1A94FB6,0x409F60C4
		dd 0x5E5C9EC2,0x196A2463,0x68FB6FAF,0x3E6C53B5,0x1339B2EB,0x3B52EC6F,0x6DFC511F,0x9B30952C
		dd 0xCC814544,0xAF5EBD09,0xBEE3D004,0xDE334AFD,0x660F2807,0x192E4BB3,0xC0CBA857,0x45C8740F
		dd 0xD20B5F39,0xB9D3FBDB,0x5579C0BD,0x1A60320A,0xD6A100C6,0x402C7279,0x679F25FE,0xFB1FA3CC
		dd 0x8EA5E9F8,0xDB3222F8,0x3C7516DF,0xFD616B15,0x2F501EC8,0xAD0552AB,0x323DB5FA,0xFD238760
		dd 0x53317B48,0x3E00DF82,0x9E5C57BB,0xCA6F8CA0,0x1A87562E,0xDF1769DB,0xD542A8F6,0x287EFFC3
		dd 0xAC6732C6,0x8C4F5573,0x695B27B0,0xBBCA58C8,0xE1FFA35D,0xB8F011A0,0x10FA3D98,0xFD2183B8
		dd 0x4AFCB56C,0x2DD1D35B,0x9A53E479,0xB6F84565,0xD28E49BC,0x4BFB9790,0xE1DDF2DA,0xA4CB7E33
		dd 0x62FB1341,0xCEE4C6E8,0xEF20CADA,0x36774C01,0xD07E9EFE,0x2BF11FB4,0x95DBDA4D,0xAE909198
		dd 0xEAAD8E71,0x6B93D5A0,0xD08ED1D0,0xAFC725E0,0x8E3C5B2F,0x8E7594B7,0x8FF6E2FB,0xF2122B64
		dd 0x8888B812,0x900DF01C,0x4FAD5EA0,0x688FC31C,0xD1CFF191,0xB3A8C1AD,0x2F2F2218,0xBE0E1777
		dd 0xEA752DFE,0x8B021FA1,0xE5A0CC0F,0xB56F74E8,0x18ACF3D6,0xCE89E299,0xB4A84FE0,0xFD13E0B7
		dd 0x7CC43B81,0xD2ADA8D9,0x165FA266,0x80957705,0x93CC7314,0x211A1477,0xE6AD2065,0x77B5FA86
		dd 0xC75442F5,0xFB9D35CF,0xEBCDAF0C,0x7B3E89A0,0xD6411BD3,0xAE1E7E49,0x00250E2D,0x2071B35E
		dd 0x226800BB,0x57B8E0AF,0x2464369B,0xF009B91E,0x5563911D,0x59DFA6AA,0x78C14389,0xD95A537F
		dd 0x207D5BA2,0x02E5B9C5,0x83260376,0x6295CFA9,0x11C81968,0x4E734A41,0xB3472DCA,0x7B14A94A
		dd 0x1B510052,0x9A532915,0xD60F573F,0xBC9BC6E4,0x2B60A476,0x81E67400,0x08BA6FB5,0x571BE91F
		dd 0xF296EC6B,0x2A0DD915,0xB6636521,0xE7B9F9B6,0xFF34052E,0xC5855664,0x53B02D5D,0xA99F8FA1
		dd 0x08BA4799,0x6E85076A,0x4B7A70E9,0xB5B32944,0xDB75092E,0xC4192623,0xAD6EA6B0,0x49A7DF7D
		dd 0x9CEE60B8,0x8FEDB266,0xECAA8C71,0x699A17FF,0x5664526C,0xC2B19EE1,0x193602A5,0x75094C29
		dd 0xA0591340,0xE4183A3E,0x3F54989A,0x5B429D65,0x6B8FE4D6,0x99F73FD6,0xA1D29C07,0xEFE830F5
		dd 0x4D2D38E6,0xF0255DC1,0x4CDD2086,0x8470EB26,0x6382E9C6,0x021ECC5E,0x09686B3F,0x3EBAEFC9
		dd 0x3C971814,0x6B6A70A1,0x687F3584,0x52A0E286,0xB79C5305,0xAA500737,0x3E07841C,0x7FDEAE5C
		dd 0x8E7D44EC,0x5716F2B8,0xB03ADA37,0xF0500C0D,0xF01C1F04,0x0200B3FF,0xAE0CF51A,0x3CB574B2
		dd 0x25837A58,0xDC0921BD,0xD19113F9,0x7CA92FF6,0x94324773,0x22F54701,0x3AE5E581,0x37C2DADC
		dd 0xC8B57634,0x9AF3DDA7,0xA9446146,0x0FD0030E,0xECC8C73E,0xA4751E41,0xE238CD99,0x3BEA0E2F
		dd 0x3280BBA1,0x183EB331,0x4E548B38,0x4F6DB908,0x6F420D03,0xF60A04BF,0x2CB81290,0x24977C79
		dd 0x5679B072,0xBCAF89AF,0xDE9A771F,0xD9930810,0xB38BAE12,0xDCCF3F2E,0x5512721F,0x2E6B7124
		dd 0x501ADDE6,0x9F84CD87,0x7A584718,0x7408DA17,0xBC9F9ABC,0xE94B7D8C,0xEC7AEC3A,0xDB851DFA
		dd 0x63094366,0xC464C3D2,0xEF1C1847,0x3215D908,0xDD433B37,0x24C2BA16,0x12A14D43,0x2A65C451
		dd 0x50940002,0x133AE4DD,0x71DFF89E,0x10314E55,0x81AC77D6,0x5F11199B,0x043556F1,0xD7A3C76B
		dd 0x3C11183B,0x5924A509,0xF28FE6ED,0x97F1FBFA,0x9EBABF2C,0x1E153C6E,0x86E34570,0xEAE96FB1
		dd 0x860E5E0A,0x5A3E2AB3,0x771FE71C,0x4E3D06FA,0x2965DCB9,0x99E71D0F,0x803E89D6,0x5266C825
		dd 0x2E4CC978,0x9C10B36A,0xC6150EBA,0x94E2EA78,0xA5FC3C53,0x1E0A2DF4,0xF2F74EA7,0x361D2B3D
		dd 0x1939260F,0x19C27960,0x5223A708,0xF71312B6,0xEBADFE6E,0xEAC31F66,0xE3BC4595,0xA67BC883
		dd 0xB17F37D1,0x018CFF28,0xC332DDEF,0xBE6C5AA5,0x65582185,0x68AB9802,0xEECEA50F,0xDB2F953B
		dd 0x2AEF7DAD,0x5B6E2F84,0x1521B628,0x29076170,0xECDD4775,0x619F1510,0x13CCA830,0xEB61BD96
		dd 0x0334FE1E,0xAA0363CF,0xB5735C90,0x4C70A239,0xD59E9E0B,0xCBAADE14,0xEECC86BC,0x60622CA7
		dd 0x9CAB5CAB,0xB2F3846E,0x648B1EAF,0x19BDF0CA,0xA02369B9,0x655ABB50,0x40685A32,0x3C2AB4B3
		dd 0x319EE9D5,0xC021B8F7,0x9B540B19,0x875FA099,0x95F7997E,0x623D7DA8,0xF837889A,0x97E32D77
		dd 0x11ED935F,0x16681281,0x0E358829,0xC7E61FD6,0x96DEDFA1,0x7858BA99,0x57F584A5,0x1B227263
		dd 0x9B83C3FF,0x1AC24696,0xCDB30AEB,0x532E3054,0x8FD948E4,0x6DBC3128,0x58EBF2EF,0x34C6FFEA
		dd 0xFE28ED61,0xEE7C3C73,0x5D4A14D9,0xE864B7E3,0x42105D14,0x203E13E0,0x45EEE2B6,0xA3AAABEA
		dd 0xDB6C4F15,0xFACB4FD0,0xC742F442,0xEF6ABBB5,0x654F3B1D,0x41CD2105,0xD81E799E,0x86854DC7
		dd 0xE44B476A,0x3D816250,0xCF62A1F2,0x5B8D2646,0xFC8883A0,0xC1C7B6A3,0x7F1524C3,0x69CB7492
		dd 0x47848A0B,0x5692B285,0x095BBF00,0xAD19489D,0x1462B174,0x23820E00,0x58428D2A,0x0C55F5EA
		dd 0x1DADF43E,0x233F7061,0x3372F092,0x8D937E41,0xD65FECF1,0x6C223BDB,0x7CDE3759,0xCBEE7460
		dd 0x4085F2A7,0xCE77326E,0xA6078084,0x19F8509E,0xE8EFD855,0x61D99735,0xA969A7AA,0xC50C06C2
		dd 0x5A04ABFC,0x800BCADC,0x9E447A2E,0xC3453484,0xFDD56705,0x0E1E9EC9,0xDB73DBD3,0x105588CD
		dd 0x675FDA79,0xE3674340,0xC5C43465,0x713E38D8,0x3D28F89E,0xF16DFF20,0x153E21E7,0x8FB03D4A
		dd 0xE6E39F2B,0xDB83ADF7,0xE93D5A68,0x948140F7,0xF64C261C,0x94692934,0x411520F7,0x7602D4F7
		dd 0xBCF46B2E,0xD4A20068,0xD4082471,0x3320F46A,0x43B7D4B7,0x500061AF,0x1E39F62E,0x97244546
		dd 0x14214F74,0xBF8B8840,0x4D95FC1D,0x96B591AF,0x70F4DDD3,0x66A02F45,0xBFBC09EC,0x03BD9785
		dd 0x7FAC6DD0,0x31CB8504,0x96EB27B3,0x55FD3941,0xDA2547E6,0xABCA0A9A,0x28507825,0x530429F4
		dd 0x0A2C86DA,0xE9B66DFB,0x68DC1462,0xD7486900,0x680EC0A4,0x27A18DEE,0x4F3FFEA2,0xE887AD8C
		dd 0xB58CE006,0x7AF4D6B6,0xAACE1E7C,0xD3375FEC,0xCE78A399,0x406B2A42,0x20FE9E35,0xD9F385B9
		dd 0xEE39D7AB,0x3B124E8B,0x1DC9FAF7,0x4B6D1856,0x26A36631,0xEAE397B2,0x3A6EFA74,0xDD5B4332
		dd 0x6841E7F7,0xCA7820FB,0xFB0AF54E,0xD8FEB397,0x454056AC,0xBA489527,0x55533A3A,0x20838D87
		dd 0xFE6BA9B7,0xD096954B,0x55A867BC,0xA1159A58,0xCCA92963,0x99E1DB33,0xA62A4A56,0x3F3125F9
		dd 0x5EF47E1C,0x9029317C,0xFDF8E802,0x04272F70,0x80BB155C,0x05282CE3,0x95C11548,0xE4C66D22
		dd 0x48C1133F,0xC70F86DC,0x07F9C9EE,0x41041F0F,0x404779A4,0x5D886E17,0x325F51EB,0xD59BC0D1
		dd 0xF2BCC18F,0x41113564,0x257B7834,0x602A9C60,0xDFF8E8A3,0x1F636C1B,0x0E12B4C2,0x02E1329E
		dd 0xAF664FD1,0xCAD18115,0x6B2395E0,0x333E92E1,0x3B240B62,0xEEBEB922,0x85B2A20E,0xE6BA0D99
		dd 0xDE720C8C,0x2DA2F728,0xD0127845,0x95B794FD,0x647D0862,0xE7CCF5F0,0x5449A36F,0x877D48FA
		dd 0xC39DFD27,0xF33E8D1E,0x0A476341,0x992EFF74,0x3A6F6EAB,0xF4F8FD37,0xA812DC60,0xA1EBDDF8
		dd 0x991BE14C,0xDB6E6B0D,0xC67B5510,0x6D672C37,0x2765D43B,0xDCD0E804,0xF1290DC7,0xCC00FFA3
		dd 0xB5390F92,0x690FED0B,0x667B9FFB,0xCEDB7D9C,0xA091CF0B,0xD9155EA3,0xBB132F88,0x515BAD24
		dd 0x7B9479BF,0x763BD6EB,0x37392EB3,0xCC115979,0x8026E297,0xF42E312D,0x6842ADA7,0xC66A2B3B
		dd 0x12754CCC,0x782EF11C,0x6A124237,0xB79251E7,0x06A1BBE6,0x4BFB6350,0x1A6B1018,0x11CAEDFA
		dd 0x3D25BDD8,0xE2E1C3C9,0x44421659,0x0A121386,0xD90CEC6E,0xD5ABEA2A,0x64AF674E,0xDA86A85F
		dd 0xBEBFE988,0x64E4C3FE,0x9DBC8057,0xF0F7C086,0x60787BF8,0x6003604D,0xD1FD8346,0xF6381FB0
		dd 0x7745AE04,0xD736FCCC,0x83426B33,0xF01EAB71,0xB0804187,0x3C005E5F,0x77A057BE,0xBDE8AE24
		dd 0x55464299,0xBF582E61,0x4E58F48F,0xF2DDFDA2,0xF474EF38,0x8789BDC2,0x5366F9C3,0xC8B38E74
		dd 0xB475F255,0x46FCD9B9,0x7AEB2661,0x8B1DDF84,0x846A0E79,0x915F95E2,0x466E598E,0x20B45770
		dd 0x8CD55591,0xC902DE4C,0xB90BACE1,0xBB8205D0,0x11A86248,0x7574A99E,0xB77F19B6,0xE0A9DC09
		dd 0x662D09A1,0xC4324633,0xE85A1F02,0x09F0BE8C,0x4A99A025,0x1D6EFE10,0x1AB93D1D,0x0BA5A4DF
		dd 0xA186F20F,0x2868F169,0xDCB7DA83,0x573906FE,0xA1E2CE9B,0x4FCD7F52,0x50115E01,0xA70683FA
		dd 0xA002B5C4,0x0DE6D027,0x9AF88C27,0x773F8641,0xC3604C06,0x61A806B5,0xF0177A28,0xC0F586E0
		dd 0x006058AA,0x30DC7D62,0x11E69ED7,0x2338EA63,0x53C2DD94,0xC2C21634,0xBBCBEE56,0x90BCB6DE
		dd 0xEBFC7DA1,0xCE591D76,0x6F05E409,0x4B7C0188,0x39720A3D,0x7C927C24,0x86E3725F,0x724D9DB9
		dd 0x1AC15BB4,0xD39EB8FC,0xED545578,0x08FCA5B5,0xD83D7CD3,0x4DAD0FC4,0x1E50EF5E,0xB161E6F8
		dd 0xA28514D9,0x6C51133C,0x6FD5C7E7,0x56E14EC4,0x362ABFCE,0xDDC6C837,0xD79A3234,0x92638212
		dd 0x670EFA8E,0x406000E0,0x3A39CE37,0xD3FAF5CF,0xABC27737,0x5AC52D1B,0x5CB0679E,0x4FA33742
		dd 0xD3822740,0x99BC9BBE,0xD5118E9D,0xBF0F7315,0xD62D1C7E,0xC700C47B,0xB78C1B6B,0x21A19045
		dd 0xB26EB1BE,0x6A366EB4,0x5748AB2F,0xBC946E79,0xC6A376D2,0x6549C2C8,0x530FF8EE,0x468DDE7D
		dd 0xD5730A1D,0x4CD04DC6,0x2939BBDB,0xA9BA4650,0xAC9526E8,0xBE5EE304,0xA1FAD5F0,0x6A2D519A
		dd 0x63EF8CE2,0x9A86EE22,0xC089C2B8,0x43242EF6,0xA51E03AA,0x9CF2D0A4,0x83C061BA,0x9BE96A4D
		dd 0x8FE51550,0xBA645BD6,0x2826A2F9,0xA73A3AE1,0x4BA99586,0xEF5562E9,0xC72FEFD3,0xF752F7DA
		dd 0x3F046F69,0x77FA0A59,0x80E4A915,0x87B08601,0x9B09E6AD,0x3B3EE593,0xE990FD5A,0x9E34D797
		dd 0x2CF0B7D9,0x022B8B51,0x96D5AC3A,0x017DA67D,0xD1CF3ED6,0x7C7D2D28,0x1F9F25CF,0xADF2B89B
		dd 0x5AD6B472,0x5A88F54C,0xE029AC71,0xE019A5E6,0x47B0ACFD,0xED93FA9B,0xE8D3C48D,0x283B57CC
		dd 0xF8D56629,0x79132E28,0x785F0191,0xED756055,0xF7960E44,0xE3D35E8C,0x15056DD4,0x88F46DBA
		dd 0x03A16125,0x0564F0BD,0xC3EB9E15,0x3C9057A2,0x97271AEC,0xA93A072A,0x1B3F6D9B,0x1E6321F5
		dd 0xF59C66FB,0x26DCF319,0x7533D928,0xB155FDF5,0x03563482,0x8ABA3CBB,0x28517711,0xC20AD9F8
		dd 0xABCC5167,0xCCAD925F,0x4DE81751,0x3830DC8E,0x379D5862,0x9320F991,0xEA7A90C2,0xFB3E7BCE
		dd 0x5121CE64,0x774FBE32,0xA8B6E37E,0xC3293D46,0x48DE5369,0x6413E680,0xA2AE0810,0xDD6DB224
		dd 0x69852DFD,0x09072166,0xB39A460A,0x6445C0DD,0x586CDECF,0x1C20C8AE,0x5BBEF7DD,0x1B588D40
		dd 0xCCD2017F,0x6BB4E3BB,0xDDA26A7E,0x3A59FF45,0x3E350A44,0xBCB4CDD5,0x72EACEA8,0xFA6484BB
		dd 0x8D6612AE,0xBF3C6F47,0xD29BE463,0x542F5D9E,0xAEC2771B,0xF64E6370,0x740E0D8D,0xE75B1357
		dd 0xF8721671,0xAF537D5D,0x4040CB08,0x4EB4E2CC,0x34D2466A,0x0115AF84,0xE1B00428,0x95983A1D
		dd 0x06B89FB4,0xCE6EA048,0x6F3F3B82,0x3520AB82,0x011A1D4B,0x277227F8,0x611560B1,0xE7933FDC
		dd 0xBB3A792B,0x344525BD,0xA08839E1,0x51CE794B,0x2F32C9B7,0xA01FBAC9,0xE01CC87E,0xBCC7D1F6
		dd 0xCF0111C3,0xA1E8AAC7,0x1A908749,0xD44FBD9A,0xD0DADECB,0xD50ADA38,0x0339C32A,0xC6913667
		dd 0x8DF9317C,0xE0B12B4F,0xF79E59B7,0x43F5BB3A,0xF2D519FF,0x27D9459C,0xBF97222C,0x15E6FC2A
		dd 0x0F91FC71,0x9B941525,0xFAE59361,0xCEB69CEB,0xC2A86459,0x12BAA8D1,0xB6C1075E,0xE3056A0C
		dd 0x10D25065,0xCB03A442,0xE0EC6E0E,0x1698DB3B,0x4C98A0BE,0x3278E964,0x9F1F9532,0xE0D392DF
		dd 0xD3A0342B,0x8971F21E,0x1B0A7441,0x4BA3348C,0xC5BE7120,0xC37632D8,0xDF359F8D,0x9B992F2E
		dd 0xE60B6F47,0x0FE3F11D,0xE54CDA54,0x1EDAD891,0xCE6279CF,0xCD3E7E6F,0x1618B166,0xFD2C1D05
		dd 0x848FD2C5,0xF6FB2299,0xF523F357,0xA6327623,0x93A83531,0x56CCCD02,0xACF08162,0x5A75EBB5
		dd 0x6E163697,0x88D273CC,0xDE966292,0x81B949D0,0x4C50901B,0x71C65614,0xE6C6C7BD,0x327A140A
		dd 0x45E1D006,0xC3F27B9A,0xC9AA53FD,0x62A80F00,0xBB25BFE2,0x35BDD2F6,0x71126905,0xB2040222
		dd 0xB6CBCF7C,0xCD769C2B,0x53113EC0,0x1640E3D3,0x38ABBD60,0x2547ADF0,0xBA38209C,0xF746CE76
		dd 0x77AFA1C5,0x20756060,0x85CBFE4E,0x8AE88DD8,0x7AAAF9B0,0x4CF9AA7E,0x1948C25C,0x02FB8A8C
		dd 0x01C36AE4,0xD6EBE1F9,0x90D4F869,0xA65CDEA0,0x3F09252D,0xC208E69F,0xB74E6132,0xCE77E25B
		dd 0x578FDFE3,0x3AC372E6
end rodata

; ------------------------------------------------------------ the users file

; rsi = after `name:`, rdx = the line's end, r8 = its slot: CF when the rest is
; not a bcrypt hash ($2a$, $2b$, $2y$, cost 4 to 16, 53 bytes of salt and hash)
; and nothing is kept; otherwise its salt, hash and cost are in the slot.
bc_line:
	mov	rcx,rdx
	sub	rcx,rsi
	cmp	rcx,60
	jne	.no
	cmp	word [rsi],'$2'
	jne	.no
	mov	al,[rsi+2]
	cmp	al,'a'
	je	@f
	cmp	al,'b'
	je	@f
	cmp	al,'y'
	jne	.no
@@:
	cmp	byte [rsi+3],'$'
	jne	.no
	cmp	byte [rsi+6],'$'
	jne	.no
	movzx	eax,byte [rsi+4]
	sub	eax,'0'
	cmp	eax,9
	ja	.no
	imul	eax,eax,10
	movzx	ecx,byte [rsi+5]
	sub	ecx,'0'
	cmp	ecx,9
	ja	.no
	add	eax,ecx
	cmp	eax,4
	jb	.bad_cost
	cmp	eax,16
	ja	.bad_cost
	or	eax,AT_BCRYPT
	push	rax
	push	rsi
	lea	rsi,[rsi+7]
	mov	ecx,22
	lea	rdi,[r8+AT_SALT]
	call	bc_b64
	pop	rsi
	jc	.no_pop
	push	rsi
	lea	rsi,[rsi+29]
	mov	ecx,31
	lea	rdi,[r8+AT_HASH]
	call	bc_b64
	pop	rsi
	jc	.no_pop
	pop	rax
	mov	[r8+AT_SLEN],eax
	mov	dword [g_plan_bcrypt],1
	clc
	ret
.no_pop:
	pop	rax
.no:
	stc
	ret
.bad_cost:
	call	log_begin
	out_lit 'auth basic: a bcrypt line',39,'s cost is from 04 to 16 (each step doubles the time a check takes)'
	call	log_end
	mov	edi,EXIT_CONFIG
	jmp	exit_process

; rsi/ecx = bcrypt's base64 (./A-Za-z0-9, no padding), rdi = out: the bytes
; whole (22 -> 16, 31 -> 23). CF on a byte not of it.
bc_b64:
	xor	edx,edx				; the bits
	xor	r9d,r9d				; how many
.c:
	test	ecx,ecx
	jz	.done
	movzx	eax,byte [rsi]
	inc	rsi
	dec	ecx
	cmp	al,'.'
	je	.dot
	cmp	al,'/'
	je	.slash
	cmp	al,'A'
	jb	.digit
	cmp	al,'Z'
	jbe	.upper
	cmp	al,'a'
	jb	.bad
	cmp	al,'z'
	ja	.bad
	sub	eax,'a' - 28
	jmp	.v
.upper:
	sub	eax,'A' - 2
	jmp	.v
.digit:
	cmp	al,'0'
	jb	.bad
	cmp	al,'9'
	ja	.bad
	sub	eax,'0' - 54
	jmp	.v
.dot:
	xor	eax,eax
	jmp	.v
.slash:
	mov	eax,1
.v:
	shl	edx,6
	or	edx,eax
	add	r9d,6
	cmp	r9d,8
	jb	.c
	sub	r9d,8
	mov	eax,edx
	push	rcx
	mov	ecx,r9d
	shr	eax,cl
	pop	rcx
	mov	[rdi],al
	inc	rdi
	jmp	.c
.done:
	clc
	ret
.bad:
	stc
	ret

; ------------------------------------------------------------ the supervisor

; The shared mapping (once), a new generation (each start and reload)
bc_init:
	cmp	dword [g_plan_bcrypt],0
	je	.out
	cmp	qword [g_bc_shm],0
	jne	.gen
	xor	edi,edi
	mov	esi,BY_SIZE
	mov	edx,PROT_READ or PROT_WRITE
	mov	r10d,MAP_SHARED or MAP_ANONYMOUS or MAP_NORESERVE
	mov	r8,-1
	xor	r9d,r9d
	mov	eax,SYS_mmap
	syscall
	cmp	rax,-4096
	ja	.out
	mov	[g_bc_shm],rax
.gen:
	inc	dword [g_bc_gen]
	mov	rax,[g_bc_shm]
	mov	ecx,[g_bc_gen]
	mov	[rax+BY_GEN],ecx
.out:
	ret

spawn_bcrypt:
	cmp	dword [g_plan_bcrypt],0
	je	.none
	cmp	qword [g_bc_shm],0
	je	.none
	mov	eax,SYS_fork
	syscall
	test	rax,rax
	jz	bcrypt_main
	js	.none
	mov	[g_bc_pid],eax
.none:
	ret

; a reload: okena-bcrypt again, with the new plan
bc_reload:
	mov	edi,[g_bc_pid]
	test	edi,edi
	jz	@f
	mov	dword [g_bc_pid],0
	mov	esi,SIGKILL
	mov	eax,SYS_kill
	syscall
@@:
	call	bc_init
	jmp	spawn_bcrypt

; ------------------------------------------------------------ the workers

macro bc_lock
	local spin, got
spin:
	mov	eax,1
	xchg	eax,[r10+BY_LOCK]
	test	eax,eax
	jz	got
	pause
	jmp	spin
got:
end macro

; r9 = a bcrypt user's slot, r8/rdx = the password (g_au_dec holds
; `name:password`), r15 = record, ebx = session: eax = YS_OK, YS_BAD, 3 held
; (g_fa_mode FA_HELD), 4 not to be had (503). Keeps rbx, r9, r12-r15.
bc_check:
	mov	r10,[g_bc_shm]
	test	r10,r10
	jz	.fail
	push	r9
	push	r8
	push	rdx
	; the key
	lea	rax,[g_au_dec]
	sub	r8,rax
	add	rdx,r8
	lea	rsi,[g_au_dec]
	lea	rdi,[g_bc_key]
	call	sha256
	mov	r9,[rsp+16]
	mov	rax,r9
	lea	rcx,[g_auth_tab]
	sub	rax,rcx
	shr	rax,7				; (AT_SIZE)
	inc	eax
	xor	[g_bc_key],eax
	pop	rdx
	pop	r8
	mov	r11,rdx				; (the password's length, kept)
	mov	r10,[g_bc_shm]
	push	r12
	push	r13
	push	r14
	push	r15
	; seconds now
	mov	rax,[g_now_ms]
	xor	edx,edx
	mov	ecx,1000
	div	rcx
	mov	r13d,eax
	bc_lock
	mov	eax,[g_bc_key]
	and	eax,BY_N - 1
	mov	r14d,eax			; where it starts
	xor	r12,r12				; a place for it: a free one, else the stalest
	mov	r15d,-1				; (the stalest's age)
	xor	ecx,ecx
.probe:
	lea	eax,[r14+rcx]
	and	eax,BY_N - 1
	imul	rax,rax,YE_SIZE
	lea	rdi,[r10+BY_CACHE+rax]
	mov	eax,[rdi+YE_STATE]
	test	eax,eax
	jz	.free
	mov	edx,[g_bc_gen]
	cmp	[rdi+YE_GEN],edx
	jne	.stale
	; this one?
	push	rcx
	push	rdi
	lea	rsi,[g_bc_key]
	mov	ecx,32
	repe	cmpsb
	pop	rdi
	pop	rcx
	jne	.other
	; known: its answer, while it holds
	mov	edx,r13d
	sub	edx,[rdi+YE_T]
	mov	eax,[rdi+YE_STATE]
	cmp	eax,YS_OK
	jne	@f
	cmp	edx,BY_OK_S
	jb	.answer
	jmp	.again
@@:
	cmp	eax,YS_BAD
	jne	@f
	cmp	edx,BY_BAD_S
	jb	.answer
	jmp	.again
@@:
	cmp	edx,BY_ASK_S
	jb	.unlock_hold			; asked: its answer comes
.again:
	mov	r12,rdi				; (asked again, here)
	jmp	.ask
.other:
	mov	edx,r13d			; its age, for a place when none is free
	sub	edx,[rdi+YE_T]
	cmp	dword [rdi+YE_STATE],YS_ASKED
	je	.next				; (not one being asked)
	cmp	r15d,-1
	je	.older
	cmp	edx,r15d
	jbe	.next
.older:
	test	r12,r12
	jz	@f
	cmp	dword [r12+YE_STATE],0
	je	.next				; (a free one is better)
@@:
	mov	r12,rdi
	mov	r15d,edx
	jmp	.next
.stale:
	mov	r15d,-2				; another generation's: as good as free
.free:
	test	r12,r12
	jz	@f
	cmp	dword [r12+YE_STATE],0
	je	.next
@@:
	mov	r12,rdi
.next:
	inc	ecx
	cmp	ecx,BY_PROBE
	jb	.probe
	test	r12,r12
	jz	.unlock_fail			; (all being asked)
.ask:
	; a question on the ring
	mov	eax,[r10+BY_HEAD]
	sub	eax,[r10+BY_TAIL]
	cmp	eax,BY_RN
	jae	.unlock_fail
	mov	eax,[r10+BY_HEAD]
	and	eax,BY_RN - 1
	imul	rax,rax,YQ_SIZE
	lea	rdi,[r10+BY_RING+rax]
	push	rdi
	lea	rsi,[g_bc_key]
	mov	ecx,32
	rep	movsb
	pop	rdi
	mov	rax,r9
	lea	rcx,[g_auth_tab]
	sub	rax,rcx
	shr	rax,7
	mov	[rdi+YQ_SLOT],eax
	mov	ecx,72
	cmp	r11,rcx
	cmovb	ecx,r11d
	mov	[rdi+YQ_PLEN],ecx
	mov	eax,[g_bc_gen]
	mov	[rdi+YQ_GEN],eax
	lea	rdi,[rdi+YQ_PW]
	mov	rsi,r8
	rep	movsb
	inc	dword [r10+BY_HEAD]
	; its place in the table: asked
	mov	rdi,r12
	lea	rsi,[g_bc_key]
	mov	ecx,32
	rep	movsb
	mov	dword [r12+YE_STATE],YS_ASKED
	mov	[r12+YE_T],r13d
	mov	eax,[g_bc_gen]
	mov	[r12+YE_GEN],eax
	inc	dword [r10+BY_WAKE]
	mov	dword [r10+BY_LOCK],0
	lea	rdi,[r10+BY_WAKE]
	mov	esi,FUTEX_WAKE_
	mov	edx,1
	xor	r10d,r10d
	mov	eax,SYS_futex
	syscall
	jmp	.hold
.answer:
	mov	dword [r10+BY_LOCK],0
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	r9
	push	rax
	call	bc_held_done
	pop	rax
	ret
.unlock_fail:
	mov	dword [r10+BY_LOCK],0
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	r9
	jmp	.fail
.unlock_hold:
	mov	dword [r10+BY_LOCK],0
.hold:
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	r9
	; held 2 ms at a time, 2 s in all
	mov	rax,[r15+H_BUF]
	mov	ecx,dword [r15+H_LT0]
	cmp	[rax+HB_FGEN],ecx
	je	@f
	mov	[rax+HB_FGEN],ecx		; (this exchange's first hold)
	mov	rcx,[g_now_ms]
	add	rcx,BY_WAIT_MS
	mov	[rax+HB_FDUE],rcx
@@:
	mov	rcx,[g_now_ms]
	cmp	rcx,[rax+HB_FDUE]
	ja	.fail
	cmp	dword [g_fd_n],FD_MAX
	jae	.fail
	push	r9
	mov	eax,BY_HOLD_US
	call	fault_hold
	pop	r9
	mov	dword [g_fa_mode],FA_HELD
	mov	eax,3
	ret
.fail:
	call	bc_held_done
	mov	dword [g_fa_mode],FR_FAIL
	mov	eax,4
	ret

; r15: an exchange that was held is decided: what holding it marked, undone
; (its faults and limits are still to come, as forward auth's)
bc_held_done:
	mov	rax,[r15+H_BUF]
	mov	ecx,dword [r15+H_LT0]
	cmp	[rax+HB_FGEN],ecx
	jne	.out
	mov	dword [rax+HB_FGEN],0
	and	dword [r15+H_FLAGS],not HX_FAULTED
.out:
	ret

; ------------------------------------------------------------ okena-bcrypt

; Never returns.
bcrypt_main:
	mov	dword [g_is_worker],0
	mov	edi,PR_SET_PDEATHSIG
	mov	esi,SIGKILL
	mov	eax,SYS_prctl
	syscall
	mov	eax,SYS_getppid
	syscall
	cmp	eax,[g_sup_pid]
	je	@f
	xor	edi,edi
	jmp	exit_process
@@:
	mov	edi,PR_SET_NAME
	lea	rsi,[bc_name]
	mov	eax,SYS_prctl
	syscall
	call	helper_close_sockets
	call	priv_drop
	call	ll_confine_none
	seccomp_for filter_bcrypt
	mov	r15,[g_bc_shm]
.loop:
	mov	r10,r15
	bc_lock
	mov	eax,[r15+BY_TAIL]
	cmp	eax,[r15+BY_HEAD]
	jne	.take
	mov	edx,[r15+BY_WAKE]		; nothing: asleep until a worker asks
	mov	dword [r15+BY_LOCK],0
	lea	rdi,[r15+BY_WAKE]
	mov	esi,FUTEX_WAIT_
	lea	r10,[ts_bc_wait]
	mov	eax,SYS_futex
	syscall
	jmp	.loop
.take:
	and	eax,BY_RN - 1
	imul	rax,rax,YQ_SIZE
	lea	rsi,[r15+BY_RING+rax]
	lea	rdi,[g_bcq]
	mov	ecx,YQ_SIZE
	rep	movsb
	inc	dword [r15+BY_TAIL]
	mov	dword [r15+BY_LOCK],0
	; its answer
	xor	r14d,r14d			; 0: none (another generation's, or no such line)
	mov	eax,[g_bcq+YQ_GEN]
	cmp	eax,[g_bc_gen]
	jne	.answered
	mov	eax,[g_bcq+YQ_SLOT]
	cmp	eax,AT_N
	jae	.answered
	shl	rax,7
	lea	r12,[g_auth_tab+rax]
	mov	eax,[r12+AT_SLEN]
	test	eax,AT_BCRYPT
	jz	.answered
	call	bc_verify
	mov	r14d,YS_BAD
	test	eax,eax
	jz	.answered
	mov	r14d,YS_OK
.answered:
	sub	rsp,16				; seconds now
	mov	edi,CLOCK_MONOTONIC
	mov	rsi,rsp
	mov	eax,SYS_clock_gettime
	syscall
	mov	r13,[rsp]
	add	rsp,16
	mov	r10,r15
	bc_lock
	mov	eax,dword [g_bcq+YQ_KEY]
	and	eax,BY_N - 1
	mov	r12d,eax
	xor	ecx,ecx
.find:
	lea	eax,[r12+rcx]
	and	eax,BY_N - 1
	imul	rax,rax,YE_SIZE
	lea	rdi,[r15+BY_CACHE+rax]
	cmp	dword [rdi+YE_STATE],YS_ASKED
	jne	.find_next
	mov	eax,[g_bcq+YQ_GEN]
	cmp	[rdi+YE_GEN],eax
	jne	.find_next
	push	rcx
	push	rdi
	lea	rsi,[g_bcq+YQ_KEY]
	mov	ecx,32
	repe	cmpsb
	pop	rdi
	pop	rcx
	jne	.find_next
	mov	[rdi+YE_STATE],r14d		; (0: the place is free again)
	mov	[rdi+YE_T],r13d
	jmp	.found
.find_next:
	inc	ecx
	cmp	ecx,BY_PROBE
	jb	.find
.found:
	mov	dword [r15+BY_LOCK],0
	jmp	.loop

; r12 = the user's slot, g_bcq = the request: eax = 1 when the password is
; the one bcrypt's hash was made of
bc_verify:
	push	rbx
	push	r12
	push	r13
	push	r14
	; the key: the password and its NUL (72 bytes at most read)
	mov	ecx,[g_bcq+YQ_PLEN]
	lea	rsi,[g_bcq+YQ_PW]
	lea	rdi,[g_bc_kb]
	push	rcx
	rep	movsb
	mov	byte [rdi],0
	pop	rcx
	inc	ecx
	lea	rsi,[g_bc_kb]
	lea	rdi,[g_bc_kw]
	mov	edx,18
	call	bc_words
	lea	rsi,[r12+AT_SALT]
	mov	ecx,16
	lea	rdi,[g_bc_sw]
	mov	edx,18
	call	bc_words
	lea	rsi,[r12+AT_SALT]
	mov	ecx,16
	lea	rdi,[g_bc_s4]
	mov	edx,4
	call	bc_words
	; Blowfish from pi, then eksblowfish's setup
	lea	rdi,[g_bf]
	lea	rsi,[bf_pi]
	mov	ecx,18 + 1024
	rep	movsd
	lea	rbx,[g_bf]
	push	r12
	lea	r12,[g_bc_kw]
	lea	r13,[g_bc_s4]
	call	bf_expand
	pop	rax
	mov	ecx,[rax+AT_SLEN]
	and	ecx,0xFF			; the cost
	mov	r14d,1
	shl	r14d,cl
	push	rax
.round:
	lea	r12,[g_bc_kw]
	xor	r13d,r13d
	call	bf_expand
	lea	r12,[g_bc_sw]
	xor	r13d,r13d
	call	bf_expand
	dec	r14d
	jnz	.round
	pop	r12
	; "OrpheanBeholderScryDoubt", 64 times
	lea	rdi,[g_bc_ct]
	lea	rsi,[bc_magic]
	mov	ecx,6
	rep	movsd
	mov	r14d,64
.enc:
	xor	r13d,r13d
.pair:
	mov	eax,[g_bc_ct+r13*4]
	mov	edx,[g_bc_ct+r13*4+4]
	call	bf_encrypt
	mov	[g_bc_ct+r13*4],eax
	mov	[g_bc_ct+r13*4+4],edx
	add	r13d,2
	cmp	r13d,6
	jb	.pair
	dec	r14d
	jnz	.enc
	; its 23 bytes, big-endian, against the hash: all compared
	xor	edx,edx				; the differences
	xor	ecx,ecx
.cmp:
	mov	eax,ecx
	shr	eax,2
	mov	eax,[g_bc_ct+rax*4]
	bswap	eax
	mov	r8d,ecx
	and	r8d,3
	push	rcx
	lea	ecx,[r8*8]
	shr	eax,cl
	pop	rcx
	xor	al,[r12+AT_HASH+rcx]
	or	dl,al
	inc	ecx
	cmp	ecx,23
	jb	.cmp
	xor	eax,eax
	test	dl,dl
	setz	al
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

; rsi/ecx = bytes, rdi = out, edx = words: them as big-endian words, the
; bytes taken round again as needed (bcrypt's stream2word)
bc_words:
	xor	r8d,r8d				; where in the bytes
.word:
	xor	eax,eax
	mov	r9d,4
.byte:
	shl	eax,8
	mov	al,[rsi+r8]
	inc	r8d
	cmp	r8d,ecx
	jb	@f
	xor	r8d,r8d
@@:
	dec	r9d
	jnz	.byte
	mov	[rdi],eax
	add	rdi,4
	dec	edx
	jnz	.word
	ret

; rbx = Blowfish's state, r12 = 18 key words, r13 = the salt's 4 words (0:
; none): the key mixed into P, then P and the S-boxes encrypted anew
; (with the salt mixed in, when there is one)
bf_expand:
	xor	ecx,ecx
@@:
	mov	eax,[r12+rcx*4]
	xor	[rbx+BF_P+rcx*4],eax
	inc	ecx
	cmp	ecx,18
	jb	@b
	xor	eax,eax
	xor	edx,edx
	xor	r9d,r9d
	mov	r10,rbx				; P, then the S-boxes after it
	mov	r11d,(18 + 1024) / 2
.pair:
	test	r13,r13
	jz	@f
	xor	eax,[r13+r9*4]
	xor	edx,[r13+r9*4+4]
	xor	r9d,2
@@:
	call	bf_encrypt
	mov	[r10],eax
	mov	[r10+4],edx
	add	r10,8
	dec	r11d
	jnz	.pair
	ret

; Blowfish's F of s32, into r8d (rbx = the state)
macro bf_f s32, s8h, s8l
	mov	ecx,s32
	shr	ecx,24
	mov	r8d,[rbx+BF_S+rcx*4]
	mov	ecx,s32
	shr	ecx,16
	movzx	ecx,cl
	add	r8d,[rbx+BF_S+1024+rcx*4]
	movzx	ecx,s8h
	xor	r8d,[rbx+BF_S+2048+rcx*4]
	movzx	ecx,s8l
	add	r8d,[rbx+BF_S+3072+rcx*4]
end macro

; eax = L, edx = R: encrypted (rbx = the state). Uses ecx, r8.
bf_encrypt:
	repeat 8, i:0
		xor	eax,[rbx+BF_P+i*8]
		bf_f	eax, ah, al
		xor	edx,r8d
		xor	edx,[rbx+BF_P+i*8+4]
		bf_f	edx, dh, dl
		xor	eax,r8d
	end repeat
	xor	eax,[rbx+BF_P+64]
	xor	edx,[rbx+BF_P+68]
	xchg	eax,edx
	ret
