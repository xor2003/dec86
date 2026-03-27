
                .686p
                .mmx
                .model large

; ===========================================================================

; Segment type: Pure data
DATA            segment para stack 'DATA' use16
                assume cs:DATA
msg             db 'Welcome to the snake game!!',0
                                        ; DATA XREF: main+F\u2193o
                                        ; main+30\u2193o
instructions    db 0Ah                  ; DATA XREF: main+19\u2193o
                db 0Dh,'Use a, s, d and w to control your snake',0Ah
                db 0Dh,'Use q anytime to quit',0Dh,0Ah
                db 'Press any key to continue$'
aThanksForPlayi db 'Thanks for playing! hope you enjoyed',0
                                        ; DATA XREF: main+7C\u2193o
gameovermsg     db 'OOPS!! your snake died! :P ',0
                                        ; DATA XREF: main+63\u2193o
scoremsg        db 'Score: ',0          ; DATA XREF: draw\u2193o
head            db '^'                  ; DATA XREF: draw+1A\u2193o
                                        ; keyboardfunctions+D\u2193r ...
                db 0Ah
                db 0Ah
body            db '*'                  ; DATA XREF: shiftsnake+80\u2193o
                db  0Ah
                db 0Bh
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
                db    0
segmentcount    db 1                    ; DATA XREF: draw+10\u2193r
                                        ; shiftsnake:loc_10371\u2193r ...
fruitactive     db 1                    ; DATA XREF: fruitgeneration:loc_101AB\u2193r
                                        ; draw+3C\u2193w ...
fruitx          db 8                    ; DATA XREF: fruitgeneration+4\u2193r
                                        ; fruitgeneration+33\u2193w ...
fruity          db 8                    ; DATA XREF: fruitgeneration\u2193r
                                        ; fruitgeneration+20\u2193w ...
gameover        db 0                    ; DATA XREF: main+3D\u2193r
                                        ; shiftsnake:loc_1036C\u2193w
quit            db 0                    ; DATA XREF: main+47\u2193r
                                        ; keyboardfunctions:loc_102F1\u2193w
delaytime       db 5                    ; DATA XREF: main+5B\u2193w
                                        ; main+74\u2193w ...
                db 0
                db    0
                db    0
                db    0
                db    0
DATA            ends

; ===========================================================================

; Segment type: Pure code
seg001          segment byte public 'CODE' use16
                assume cs:seg001
                assume es:nothing, ss:DATA, ds:nothing, fs:nothing, gs:nothing

; =============== S U B R O U T I N E =======================================

; Attributes: noreturn

; int __cdecl main(int argc, const char **argv, const char **envp)
                public main
main            proc near

argc            = dword ptr  2
argv            = dword ptr  6
envp            = dword ptr  0Ah

                mov     ax, seg DATA
                mov     ds, ax
                assume ds:DATA
                mov     ax, 0B800h
                mov     es, ax
                assume es:nothing
                mov     ax, 3
                int     10h             ; - VIDEO - SET VIDEO MODE
                                        ; AL = mode
                mov     dx, 0
                mov     ah, 9
                int     21h             ; DOS - PRINT STRING
                                        ; DS:DX -> string terminated by "$"
                mov     ah, 7
                int     21h             ; DOS - DIRECT STDIN INPUT, NO ECHO
                mov     ax, 3
                int     10h             ; - VIDEO - SET VIDEO MODE
                                        ; AL = mode
                mov     ax, 4C00h
                int     21h             ; DOS - 2+ - QUIT WITH EXIT CODE (EXIT)
main            endp                    ; AL = exit code


delay           proc near               ; CODE XREF: main:loc_1012D\u2191p
                                        ; main+6A\u2191p ...
                mov     ah, 0
                int     1Ah             ; CLOCK - GET TIME OF DAY
                                        ; Return: CX:DX = clock count
                                        ; AL = 00h if clock was read or written (via AH=0,1) since the previous
                                        ; midnight
                                        ; Otherwise, AL > 0
                mov     bx, dx

loc_10198:                              ; CODE XREF: delay+E\u2193j
                int     1Ah
                sub     dx, bx
                jl      short loc_10198
                retn
delay           endp


; =============== S U B R O U T I N E =======================================


fruitgeneration proc near               ; CODE XREF: main+4E\u2191p
                mov     ch, fruity
                mov     cl, fruitx

loc_101AB:                              ; CODE XREF: fruitgeneration+47\u2193j
                                        ; fruitgeneration+4E\u2193j ...
                cmp     fruitactive, 1
                jz      short locret_10221
                mov     ah, 0
                int     1Ah             ; CLOCK - GET TIME OF DAY
                                        ; Return: CX:DX = clock count
                                        ; AL = 00h if clock was read or written (via AH=0,1) since the previous
                                        ; midnight
                                        ; Otherwise, AL > 0
                push    dx
                mov     ax, dx
                xor     dx, dx
                xor     bh, bh
                mov     bl, 15
                dec     bl
                div     bx
                mov     fruity, dl
                inc     fruity
                pop     ax
                mov     bl, 40
                dec     dl
                xor     bh, bh
                xor     dx, dx
                div     bx
                mov     fruitx, dl
                inc     fruitx
                cmp     fruitx, cl
                jnz     short loc_101EC
                cmp     fruity, ch
                jnz     short loc_101EC
                jmp     short loc_101AB
; ---------------------------------------------------------------------------

loc_101EC:                              ; CODE XREF: fruitgeneration+3F\u2191j
                                        ; fruitgeneration+45\u2191j
                mov     al, fruitx
                ror     al, 1
                jb      short loc_101AB
                add     fruity, 2
                add     fruitx, 0
                mov     dh, fruity
                mov     dl, fruitx
                call    readcharat
                cmp     bl, '*'
                jz      short loc_101AB
                cmp     bl, '^'
                jz      short loc_101AB
                cmp     bl, '<'
                jz      short loc_101AB
                cmp     bl, '>'
                jz      short loc_101AB
                cmp     bl, 'v'
                jz      short loc_101AB

locret_10221:                           ; CODE XREF: fruitgeneration+D\u2191j
                retn
fruitgeneration endp


; =============== S U B R O U T I N E =======================================


dispdigit       proc near               ; CODE XREF: dispnum+10\u2193p
                add     dl, 30h ; '0'
                mov     ah, 2
                int     21h             ; DOS - DISPLAY OUTPUT
                                        ; DL = character to send to standard output
                retn
dispdigit       endp


; =============== S U B R O U T I N E =======================================


dispnum         proc near               ; CODE XREF: dispnum+C\u2193p
                                        ; draw+17\u2193p
                test    ax, ax
                jz      short loc_1023E
                xor     dx, dx
                mov     bx, 10
                div     bx
                push    dx
                call    dispnum
                pop     dx
                call    dispdigit
                retn
; ---------------------------------------------------------------------------

loc_1023E:                              ; CODE XREF: dispnum+2\u2191j
                mov     ah, 2
                retn
dispnum         endp


; =============== S U B R O U T I N E =======================================


setcursorpos    proc near               ; CODE XREF: draw+D\u2193p
                mov     ah, 2
                push    bx
                mov     bh, 0
                int     10h             ; - VIDEO - SET CURSOR POSITION
                                        ; DH,DL = row, column (0,0 = upper left)
                                        ; BH = page number
                pop     bx
                retn
setcursorpos    endp


; =============== S U B R O U T I N E =======================================


draw            proc near               ; CODE XREF: main+51\u2191p
                lea     bx, scoremsg    ; "Score: "
                mov     dx, 109h
                call    writestringat
                add     dx, 7
                call    setcursorpos
                mov     al, segmentcount
                dec     al
                xor     ah, ah
                call    dispnum
                lea     si, head

loc_10268:                              ; CODE XREF: draw+2D\u2193j
                mov     bl, [si]
                test    bl, bl
                jz      short loc_10279
                mov     dx, [si+1]
                call    writecharat
                add     si, 3
                jmp     short loc_10268
; ---------------------------------------------------------------------------

loc_10279:                              ; CODE XREF: draw+22\u2191j
                mov     bl, 'F'
                mov     dh, fruity
                mov     dl, fruitx
                call    writecharat
                mov     fruitactive, 1
                retn
draw            endp


; =============== S U B R O U T I N E =======================================


readchar        proc near               ; CODE XREF: keyboardfunctions\u2193p
                mov     ah, 1
                int     16h             ; KEYBOARD - CHECK BUFFER, DO NOT CLEAR
                                        ; Return: ZF clear if character in buffer
                                        ; AH = scan code, AL = character
                                        ; ZF set if no character in buffer
                jnz     short loc_10295
                xor     dl, dl
                retn
; ---------------------------------------------------------------------------

loc_10295:                              ; CODE XREF: readchar+4\u2191j
                mov     ah, 0
                int     16h             ; KEYBOARD - READ CHAR FROM BUFFER, WAIT IF EMPTY
                                        ; Return: AH = scan code, AL = character
                mov     dl, al
                retn
readchar        endp


; =============== S U B R O U T I N E =======================================


keyboardfunctions proc near             ; CODE XREF: main+44\u2191p
                call    readchar
                cmp     dl, 0
                jz      short loc_102EB
                cmp     dl, 'w'
                jnz     short loc_102B6
                cmp     head, 'v'
                jz      short loc_102EB
                mov     head, '^'
                retn
; ---------------------------------------------------------------------------

loc_102B6:                              ; CODE XREF: keyboardfunctions+B\u2191j
                cmp     dl, 's'
                jnz     short loc_102C8
                cmp     head, '^'
                jz      short loc_102EB
                mov     head, 'v'
                retn
; ---------------------------------------------------------------------------

loc_102C8:                              ; CODE XREF: keyboardfunctions+1D\u2191j
                cmp     dl, 'a'
                jnz     short loc_102DA
                cmp     head, '>'
                jz      short loc_102EB
                mov     head, '<'
                retn
; ---------------------------------------------------------------------------

loc_102DA:                              ; CODE XREF: keyboardfunctions+2F\u2191j
                cmp     dl, 'd'
                jnz     short loc_102EB
                cmp     head, '<'
                jz      short loc_102EB
                mov     head, '>'

loc_102EB:                              ; CODE XREF: keyboardfunctions+6\u2191j
                                        ; keyboardfunctions+12\u2191j ...
                cmp     dl, 'q'
                jz      short loc_102F1
                retn
; ---------------------------------------------------------------------------

loc_102F1:                              ; CODE XREF: keyboardfunctions+52\u2191j
                inc     quit
                retn
keyboardfunctions endp


; =============== S U B R O U T I N E =======================================


shiftsnake      proc near               ; CODE XREF: main+3A\u2191p
                mov     bx, offset head
                xor     ax, ax
                mov     al, [bx]
                push    ax
                inc     bx
                mov     ax, [bx]
                inc     bx
                inc     bx
                xor     cx, cx

loc_10305:                              ; CODE XREF: shiftsnake+1F\u2193j
                mov     si, [bx]
                test    [bx], si
                jz      short loc_10317
                inc     cx
                inc     bx
                mov     dx, [bx]
                mov     [bx], ax
                mov     ax, dx
                inc     bx
                inc     bx
                jmp     short loc_10305
; ---------------------------------------------------------------------------

loc_10317:                              ; CODE XREF: shiftsnake+13\u2191j
                pop     ax
                push    dx
                lea     bx, head
                inc     bx
                mov     dx, [bx]
                cmp     al, '<'
                jnz     short loc_1032A
                dec     dl
                dec     dl
                jmp     short loc_1033E
; ---------------------------------------------------------------------------

loc_1032A:                              ; CODE XREF: shiftsnake+2C\u2191j
                cmp     al, 3Eh ; '>'
                jnz     short loc_10334
                inc     dl
                inc     dl
                jmp     short loc_1033E
; ---------------------------------------------------------------------------

loc_10334:                              ; CODE XREF: shiftsnake+36\u2191j
                cmp     al, '^'
                jnz     short loc_1033C
                dec     dh
                jmp     short loc_1033E
; ---------------------------------------------------------------------------

loc_1033C:                              ; CODE XREF: shiftsnake+40\u2191j
                inc     dh

loc_1033E:                              ; CODE XREF: shiftsnake+32\u2191j
                                        ; shiftsnake+3C\u2191j ...
                mov     [bx], dx
                call    readcharat
                cmp     bl, 'F'
                jz      short loc_10371
                mov     cx, dx
                pop     dx
                cmp     bl, '*'
                jz      short loc_1036C
                mov     bl, 0
                call    writecharat
                mov     dx, cx
                cmp     dh, 2
                jz      short loc_1036C
                cmp     dh, 11h
                jz      short loc_1036C
                cmp     dl, 0
                jz      short loc_1036C
                cmp     dl, 28h ; '('
                jz      short loc_1036C
                retn
; ---------------------------------------------------------------------------

loc_1036C:                              ; CODE XREF: shiftsnake+58\u2191j
                                        ; shiftsnake+64\u2191j ...
                inc     gameover
                retn
; ---------------------------------------------------------------------------

loc_10371:                              ; CODE XREF: shiftsnake+50\u2191j
                mov     al, segmentcount
                xor     ah, ah
                lea     bx, body
                mov     cx, 3
                mul     cx
                pop     dx
                add     bx, ax
                mov     byte ptr [bx], '*'
                mov     [bx+1], dx
                inc     segmentcount
                mov     dh, fruity
                mov     dl, fruitx
                mov     bl, 0
                call    writecharat
                mov     fruitactive, 0
                retn
shiftsnake      endp


; =============== S U B R O U T I N E =======================================


printbox        proc near               ; CODE XREF: main+2A\u2191p
                mov     dh, 2
                mov     dl, 0
                mov     cx, 28h ; '('
                mov     bl, '*'

loc_103A8:                              ; CODE XREF: printbox+E\u2193j
                call    writecharat
                inc     dl
                loop    loc_103A8
                mov     cx, 0Fh

loc_103B2:                              ; CODE XREF: printbox+18\u2193j
                call    writecharat
                inc     dh
                loop    loc_103B2
                mov     cx, 28h ; '('

loc_103BC:                              ; CODE XREF: printbox+22\u2193j
                call    writecharat
                dec     dl
                loop    loc_103BC
                mov     cx, 0Fh

loc_103C6:                              ; CODE XREF: printbox+2C\u2193j
                call    writecharat
                dec     dh
                loop    loc_103C6
                retn
printbox        endp


; =============== S U B R O U T I N E =======================================


writecharat     proc near               ; CODE XREF: draw+27\u2191p
                                        ; draw+39\u2191p ...
                push    dx
                mov     ax, dx
                and     ax, 0FF00h
                shr     ax, 1
                shr     ax, 1
                shr     ax, 1
                shr     ax, 1
                shr     ax, 1
                shr     ax, 1
                shr     ax, 1
                shr     ax, 1
                push    bx
                mov     bh, 0A0h ; ' '
                mul     bh
                pop     bx
                and     dx, 0FFh
                shl     dx, 1
                add     ax, dx
                mov     di, ax
                mov     es:[di], bl
                pop     dx
                retn
writecharat     endp


; =============== S U B R O U T I N E =======================================


readcharat      proc near               ; CODE XREF: fruitgeneration+62\u2191p
                                        ; shiftsnake+4A\u2191p
                push    dx
                mov     ax, dx
                and     ax, 0FF00h
                shr     ax, 1
                shr     ax, 1
                shr     ax, 1
                shr     ax, 1
                shr     ax, 1
                shr     ax, 1
                shr     ax, 1
                shr     ax, 1
                push    bx
                mov     bh, 0A0h ; ' '
                mul     bh
                pop     bx
                and     dx, 0FFh
                shl     dx, 1
                add     ax, dx
                mov     di, ax
                mov     bl, es:[di]
                pop     dx
                retn
readcharat      endp


; =============== S U B R O U T I N E =======================================


writestringat   proc near               ; CODE XREF: main+16\u2191p
                                        ; main+37\u2191p ...
                push    dx
                mov     ax, dx
                and     ax, 0FF00h
                shr     ax, 1
                shr     ax, 1
                shr     ax, 1
                shr     ax, 1
                shr     ax, 1
                shr     ax, 1
                shr     ax, 1
                shr     ax, 1
                push    bx
                mov     bh, 0A0h ; ' '
                mul     bh
                pop     bx
                and     dx, 0FFh
                shl     dx, 1
                add     ax, dx
                mov     di, ax

loc_1044A:                              ; CODE XREF: writestringat+32\u2193j
                mov     al, [bx]
                test    al, al
                jz      short loc_10458
                mov     es:[di], al
                inc     di
                inc     di
                inc     bx
                jmp     short loc_1044A
; ---------------------------------------------------------------------------

loc_10458:                              ; CODE XREF: writestringat+2A\u2191j
                pop     dx
                retn
writestringat   endp

seg001          ends


                end main
