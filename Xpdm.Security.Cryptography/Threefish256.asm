permute00 equ 14
permute01 equ 16
permute10 equ 52
permute11 equ 57
permute20 equ 23
permute21 equ 40
permute30 equ  5
permute31 equ 37
permute40 equ 25
permute41 equ 33
permute50 equ 46
permute51 equ 12
permute60 equ 58
permute61 equ 22
permute70 equ 32
permute71 equ 32

%define bA xmm0
%define bB xmm1
%define bTemp xmm2
%define rotL xmm3
%define rotR xmm4
%define bCount xmm5
%define bInc xmm6
%define bSixFour xmm7

%define memA ebp-0x58
%define memBin ebp-0x78
%define memBout ebp-0x68
%define k0 ebp-0x98
%define k1 ebp-0xa8
%define k2 ebp-0xb8
%define k3 ebp-0xc8
%define k4 ebp-0xd8
%define t0h ebp-0xe8
%define t0l ebp-0xf8
%define t1h ebp-0x108
%define t1l ebp-0x118
%define t2h ebp-0x128
%define t2l ebp-0x138

%define permute(x,y) permute %+ x %+ y

%macro pinsrwy 2

	pinsrw %1,%2,0x4

%endmacro

%macro swapxy 1

	pshufd %1,%1,0x4e

%endmacro

%macro xyzwtoyxwz 1

	pshufd %1,%1,0xb1

%endmacro

%macro subkey 1

  %assign kA %1 % 5
  %assign kB (%1 + 1) % 5
  %assign th %1 % 3
  %assign tl (%1 + 1) % 3

	; Subkey %1
	paddq bA,[k %+ kA]
	paddq bA,[t %+ tl %+ l]
	paddq bB,bCount
	paddq bB,[k %+ kB]
	paddq bB,[t %+ th %+ h]
	paddq bCount,bInc

%endmacro

%macro unkey 1

  %assign kA %1 % 5
  %assign kB (%1 + 1) % 5
  %assign th %1 % 3
  %assign tl (%1 + 1) % 3

	; Subkey %1
	psubq bA,[k %+ kA]
	psubq bA,[t %+ tl %+ l]
	psubq bB,bCount
	psubq bB,[k %+ kB]
	psubq bB,[t %+ th %+ h]
	psubq bCount,bInc

%endmacro

%macro round 1

  %assign pX %1 % 8

	; Round %1
	paddq bB,bA
  %if pX = 7
        ; Short-cut for <32, 32> rotate
	; Invalid if these rotation constants change
	xyzwtoyxwz bA
  %else
	mov eax,permute(pX,0)
	movd rotL,eax
	mov eax,permute(pX,1)
	pinsrwy rotL,eax
	movaps rotR,bSixFour
	psubq rotR,rotL
	movaps bTemp,bA
	psllq bTemp,rotL
	psrlq bA,rotR
	por bA,bTemp
  %endif
	pxor bA,bB
	swapxy bB

%endmacro

%macro unround 1

  %assign pX %1 % 8

	; Round %1
	swapxy bB
	pxor bA,bB
  %if pX = 7
        ; Short-cut for <32, 32> rotate
	; Invalid if these rotation constants change
	xyzwtoyxwz bA
  %else
	mov eax,permute(pX,0)
	movd rotL,eax
	mov eax,permute(pX,1)
	pinsrwy rotL,eax
	movaps rotR,bSixFour
	psubq rotR,rotL
	movaps bTemp,bA
	psrlq bTemp,rotL
	psllq bA,rotR
	por bA,bTemp
  %endif
	psubq bB,bA

%endmacro

encrypt:

	movaps bA,[memA]
	movaps bTemp,[memBin]
	movaps bB,bA
	punpckhqdq bA,bTemp
	punpcklqdq bB,bTemp
	movaps bTemp,bA

	; Put <0,1> into xmm6, xmm5 is subkey counter
	mov eax,1
	movd bInc,eax
	pxor bCount,bCount

	mov eax,64
	movd bSixFour,eax
	pshufd bSixFour,bSixFour,0x44

	subkey 0x00
		round 0x00
		round 0x01
		round 0x02
		round 0x03
	subkey 0x01
		round 0x04
		round 0x05
		round 0x06
		round 0x07
	subkey 0x02
		round 0x08
		round 0x09
		round 0x0a
		round 0x0b
	subkey 0x03
		round 0x0c
		round 0x0d
		round 0x0e
		round 0x0f
	subkey 0x04
		round 0x10
		round 0x11
		round 0x12
		round 0x13
	subkey 0x05
		round 0x14
		round 0x15
		round 0x16
		round 0x17
	subkey 0x06
		round 0x18
		round 0x19
		round 0x1a
		round 0x1b
	subkey 0x07
		round 0x1c
		round 0x1d
		round 0x1e
		round 0x1f
	subkey 0x08
		round 0x20
		round 0x21
		round 0x22
		round 0x23
	subkey 0x09
		round 0x24
		round 0x25
		round 0x26
		round 0x27
	subkey 0x0a
		round 0x28
		round 0x29
		round 0x2a
		round 0x2b
	subkey 0x0b
		round 0x2c
		round 0x2d
		round 0x2e
		round 0x2f
	subkey 0x0c
		round 0x30
		round 0x31
		round 0x32
		round 0x33
	subkey 0x0d
		round 0x34
		round 0x35
		round 0x36
		round 0x37
	subkey 0x0e
		round 0x38
		round 0x39
		round 0x3a
		round 0x3b
	subkey 0x0f
		round 0x3c
		round 0x3d
		round 0x3e
		round 0x3f
	subkey 0x10
		round 0x40
		round 0x41
		round 0x42
		round 0x43
	subkey 0x11
		round 0x44
		round 0x45
		round 0x46
		round 0x47
	subkey 0x12

	movaps [memA],bA
	movaps [memBout],bB
	jmp 0x2229
	times 0x100 nop

; encrypt 0x1db80
; start   0x1dfc0            0x0     0x160
; stop    0x21307  (0x3347)  0x1065  0x11c5 (0x1065)  ((0x22e2))
; decrypt 0x214b0
; start   0x218fd            0x1165  0x12c5
; stop    0x24c7b  (0x337e)  0x21cf  0x232f (0x106a)  ((0x2314))
; next    0x24e30

decrypt:
	movaps bA,[memA]
	movaps bTemp,[memBin]
	movaps bB,bA
	punpckhqdq bA,bTemp
	punpcklqdq bB,bTemp
	movaps bTemp,bA

	; Put <0,1> into xmm6, xmm5 is subkey counter
	mov eax,1
	movd bInc,eax
	mov eax,18
	movd bCount,eax

	mov eax,64
	movd bSixFour,eax
	pshufd bSixFour,bSixFour,0x44

	subkey 0x12
		round 0x47
		round 0x46
		round 0x45
		round 0x44
	subkey 0x11
		round 0x43
		round 0x42
		round 0x41
		round 0x40
	subkey 0x10
		round 0x3f
		round 0x3e
		round 0x3d
		round 0x3c
	subkey 0x0f
		round 0x3b
		round 0x3a
		round 0x39
		round 0x38
	subkey 0x0e
		round 0x37
		round 0x36
		round 0x35
		round 0x34
	subkey 0x0d
		round 0x33
		round 0x32
		round 0x31
		round 0x30
	subkey 0x0c
		round 0x2f
		round 0x2e
		round 0x2d
		round 0x2c
	subkey 0x0b
		round 0x2b
		round 0x2a
		round 0x29
		round 0x28
	subkey 0x0a
		round 0x27
		round 0x26
		round 0x25
		round 0x24
	subkey 0x09
		round 0x23
		round 0x22
		round 0x21
		round 0x20
	subkey 0x08
		round 0x1f
		round 0x1e
		round 0x1d
		round 0x1c
	subkey 0x07
		round 0x1b
		round 0x1a
		round 0x19
		round 0x18
	subkey 0x06
		round 0x17
		round 0x16
		round 0x15
		round 0x14
	subkey 0x05
		round 0x13
		round 0x12
		round 0x11
		round 0x10
	subkey 0x04
		round 0x0f
		round 0x0e
		round 0x0d
		round 0x0c
	subkey 0x03
		round 0x0b
		round 0x0a
		round 0x09
		round 0x08
	subkey 0x02
		round 0x07
		round 0x06
		round 0x05
		round 0x04
	subkey 0x01
		round 0x03
		round 0x02
		round 0x01
		round 0x00
	subkey 0x00

	movaps [memA],bA
	movaps [memBout],bB
	jmp 0x2257
	times 0x100 nop

