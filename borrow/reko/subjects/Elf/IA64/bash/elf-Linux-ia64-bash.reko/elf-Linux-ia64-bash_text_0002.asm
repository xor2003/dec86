;;; Segment .text (400000000001C480)

l400000000003CE20:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000028E40; }
	{ nop.m	0x0; adds	r1,0x0,r107; nop.i	0x0 }
	{ ld4	r14,[r70]; nop.m	0x0; br.cond.sptk.few	40000000000384A0 }
400000000003CE50 11 00 00 00 01 00 00 00 00 02 00 00 78 99 FE 58 ............x..X
400000000003CE60 10 00 00 00 01 00 10 00 AC 01 42 00 D0 CD FF 48 ..........B....H
400000000003CE70 11 00 00 00 01 00 00 00 00 02 00 00 58 99 FE 58 ............X..X
400000000003CE80 10 00 00 00 01 00 10 00 AC 01 42 00 F0 CC FF 48 ..........B....H
400000000003CE90 11 00 00 00 01 00 00 00 00 02 00 00 38 99 FE 58 ............8..X
400000000003CEA0 11 00 00 00 01 00 10 00 AC 01 42 00 10 CE FF 48 ..........B....H

l400000000003CEB0:
	{ addl	r108,-28,r1; nop.m	0x0; addl	r32,2,r0; }
	{ ld8	r108,[r108]; nop.i	0x0; br.call.sptk.many	b0,yyerror; }
	{ nop.m	0x0; adds	r1,0x0,r107; br.cond.sptk.few	4000000000038330 }

l400000000003CEE0:
	{ nop.m	0x0; adds	r32,0x0,r0; br.cond.sptk.few	4000000000038330; }

l400000000003CEF0:
	{ adds	r35,0x0,r41; addl	r32,1,r0; br.cond.sptk.few	4000000000038330 }
400000000003CF00 08 00 00 00 01 00 00 01 84 30 20 20 05 48 41 00 .........0  .HA.
400000000003CF10 0A 00 3C 54 98 11 00 80 38 30 23 E0 91 02 4C 80 ..<T....80#...L.
400000000003CF20 09 80 A4 00 10 20 00 00 00 02 00 C0 01 60 01 84 ..... .......`..
400000000003CF30 11 78 00 1E 05 20 00 01 40 0A 40 00 30 B1 FF 48 .x... ..@.@.0..H
400000000003CF40 08 00 00 00 01 00 00 01 84 30 20 20 05 48 41 00 .........0  .HA.
400000000003CF50 0A 00 3C 54 98 11 00 80 38 30 23 E0 91 02 4C 80 ..<T....80#...L.
400000000003CF60 09 80 A4 00 10 20 00 00 00 02 00 C0 01 60 01 84 ..... .......`..
400000000003CF70 11 78 00 1E 05 20 00 01 40 0A 40 00 F0 B0 FF 48 .x... ..@.@....H
400000000003CF80 09 78 00 42 18 10 00 00 00 02 00 20 05 48 41 00 .x.B....... .HA.
400000000003CF90 09 00 3C 1C 98 11 00 00 00 02 00 C0 01 0E FD 8C ..<.............
400000000003CFA0 09 00 00 00 01 00 E0 00 38 30 20 00 00 00 04 00 ........80 .....
400000000003CFB0 11 60 03 1C 18 10 00 00 00 02 00 00 18 7E 00 50 .`...........~.P
400000000003CFC0 08 88 10 10 00 21 F0 48 01 26 40 00 92 02 40 80 .....!.H.&@...@.
400000000003CFD0 09 08 00 D6 00 21 00 40 A8 30 23 C0 01 60 01 84 .....!.@.0#..`..
400000000003CFE0 09 90 00 22 10 10 F0 00 3C 0A 40 00 02 80 14 80 ..."....<.@.....
400000000003CFF0 09 00 00 00 01 00 20 99 4A 1C 40 00 00 00 04 00 ...... .J.@.....
400000000003D000 10 00 48 22 90 11 00 00 00 02 00 00 60 B0 FF 48 ..H"........`..H
400000000003D010 10 00 00 00 01 00 90 02 A4 20 00 00 00 00 00 20 ......... ..... 
400000000003D020 09 90 00 42 18 10 00 78 A8 30 23 C0 01 60 01 84 ...B...x.0#..`..
400000000003D030 08 00 00 00 01 00 F0 48 01 26 40 00 92 02 40 80 .......H.&@...@.
400000000003D040 09 00 00 00 01 00 00 90 44 30 23 00 00 00 04 00 ........D0#.....
400000000003D050 11 78 00 1E 05 20 00 01 40 0A 40 00 10 B0 FF 48 .x... ..@.@....H
400000000003D060 09 78 00 42 18 10 C0 E6 F6 FF 4F 20 05 48 41 00 .x.B......O .HA.
400000000003D070 08 00 00 00 01 00 00 78 38 30 23 00 00 00 04 00 .......x80#.....
400000000003D080 19 60 03 D8 18 10 00 00 00 02 00 00 48 7D 00 50 .`..........H}.P
400000000003D090 08 88 10 10 00 21 F0 48 01 26 40 00 92 02 40 80 .....!.H.&@...@.
400000000003D0A0 09 08 00 D6 00 21 00 40 A8 30 23 C0 01 60 01 84 .....!.@.0#..`..
400000000003D0B0 09 90 00 22 10 10 F0 00 3C 0A 40 00 02 80 14 80 ..."....<.@.....
400000000003D0C0 09 00 00 00 01 00 20 99 4A 1C 40 00 00 00 04 00 ...... .J.@.....
400000000003D0D0 10 00 48 22 90 11 00 00 00 02 00 00 90 AF FF 48 ..H"...........H
400000000003D0E0 01 00 20 1C 98 11 90 02 A4 20 00 C0 CD 07 00 90 .. ...... ......
400000000003D0F0 08 00 00 00 01 00 C0 06 A0 31 20 00 00 00 04 00 .........1 .....
400000000003D100 19 68 03 42 18 10 00 00 00 02 00 00 88 5D 00 50 .h.B.........].P
400000000003D110 08 78 A4 00 13 20 00 49 01 20 40 00 00 00 04 00 .x... .I. @.....
400000000003D120 09 08 00 D6 00 21 00 40 A8 30 23 C0 01 60 01 84 .....!.@.0#..`..
400000000003D130 11 78 00 1E 05 20 00 01 40 0A 40 00 30 AF FF 48 .x... ..@.@.0..H
400000000003D140 09 78 04 00 00 24 E0 A0 04 68 48 00 04 00 00 84 .x...$...hH.....
400000000003D150 10 00 3C 1C 90 11 00 00 00 02 00 00 E0 B1 FF 48 ..<............H
400000000003D160 08 00 00 00 01 00 F0 00 18 21 20 20 05 48 41 00 .........!  .HA.
400000000003D170 0A 70 00 A0 10 10 60 70 3C 0E 71 00 92 02 40 80 .p....`p<.q...@.
400000000003D180 19 78 A4 00 13 20 E0 00 B0 00 42 03 A0 05 00 43 .x... ....B....C
400000000003D190 11 78 00 1E 05 20 00 01 40 0A 40 00 D0 AE FF 48 .x... ..@.@....H
400000000003D1A0 08 00 00 00 01 00 F0 00 18 21 20 20 05 48 41 00 .........!  .HA.
400000000003D1B0 0A 70 00 A0 10 10 60 70 3C 0E 71 00 92 02 40 80 .p....`p<.q...@.
400000000003D1C0 19 78 A4 00 13 20 E0 00 B0 00 42 03 30 02 00 43 .x... ....B.0..C
400000000003D1D0 11 78 00 1E 05 20 00 01 40 0A 40 00 90 AE FF 48 .x... ..@.@....H
400000000003D1E0 08 00 00 00 01 00 F0 00 18 21 20 20 05 48 41 00 .........!  .HA.
400000000003D1F0 0A 70 00 A0 10 10 60 70 3C 0E 71 00 92 02 40 80 .p....`p<.q...@.
400000000003D200 19 78 A4 00 13 20 E0 00 B0 00 42 03 F0 01 00 43 .x... ....B....C
400000000003D210 10 78 00 1E 05 20 00 01 40 0A 40 00 50 AE FF 48 .x... ..@.@.P..H
400000000003D220 11 00 00 00 01 00 00 00 00 02 00 00 A8 7E 00 50 .............~.P
400000000003D230 08 00 00 00 01 00 E0 00 24 21 20 20 00 58 03 84 ........$!  .X..
400000000003D240 09 00 00 00 01 00 00 40 A8 30 23 00 00 00 04 00 .......@.0#.....
400000000003D250 10 00 00 00 01 00 60 00 38 0E 73 03 E0 C9 FF 4A ......`.8.s....J
400000000003D260 10 00 00 00 01 00 00 00 00 02 00 00 F0 FB FF 48 ...............H
400000000003D270 11 00 00 00 01 00 90 02 A4 20 00 00 58 95 FE 58 ......... ..X..X
400000000003D280 08 78 A4 00 13 20 00 00 00 02 00 00 92 02 40 80 .x... ........@.
400000000003D290 09 08 00 D6 00 21 00 00 00 02 00 C0 01 60 01 84 .....!.......`..
400000000003D2A0 10 78 00 1E 05 20 00 01 40 0A 40 00 C0 AD FF 48 .x... ..@.@....H
400000000003D2B0 11 00 00 00 01 00 90 02 A4 20 00 00 18 7E 00 50 ......... ...~.P
400000000003D2C0 08 78 A4 00 13 20 00 49 01 20 40 00 00 00 04 00 .x... .I. @.....
400000000003D2D0 09 08 00 D6 00 21 00 40 A8 30 23 C0 01 60 01 84 .....!.@.0#..`..
400000000003D2E0 10 78 00 1E 05 20 00 01 40 0A 40 00 80 AD FF 48 .x... ..@.@....H
400000000003D2F0 11 00 00 00 01 00 90 02 A4 20 00 00 D8 7D 00 50 ......... ...}.P
400000000003D300 08 78 A4 00 13 20 00 49 01 20 40 00 00 00 04 00 .x... .I. @.....
400000000003D310 09 08 00 D6 00 21 00 40 A8 30 23 C0 01 60 01 84 .....!.@.0#..`..
400000000003D320 10 78 00 1E 05 20 00 01 40 0A 40 00 40 AD FF 48 .x... ..@.@.@..H
400000000003D330 11 00 00 00 01 00 90 02 A4 20 00 00 98 7D 00 50 ......... ...}.P
400000000003D340 08 78 A4 00 13 20 00 49 01 20 40 00 00 00 04 00 .x... .I. @.....
400000000003D350 09 08 00 D6 00 21 00 40 A8 30 23 C0 01 60 01 84 .....!.@.0#..`..
400000000003D360 10 78 00 1E 05 20 00 01 40 0A 40 00 00 AD FF 48 .x... ..@.@....H
400000000003D370 09 70 00 42 18 10 C0 E6 F6 FF 4F 20 05 48 41 00 .p.B......O .HA.
400000000003D380 08 00 00 00 01 00 00 70 3C 30 23 00 00 00 04 00 .......p<0#.....
400000000003D390 19 60 03 D8 18 10 00 00 00 02 00 00 38 7A 00 50 .`..........8z.P
400000000003D3A0 08 88 10 10 00 21 F0 48 01 26 40 00 92 02 40 80 .....!.H.&@...@.
400000000003D3B0 09 08 00 D6 00 21 00 40 A8 30 23 C0 01 60 01 84 .....!.@.0#..`..
400000000003D3C0 09 90 00 22 10 10 F0 00 3C 0A 40 00 02 80 14 80 ..."....<.@.....
400000000003D3D0 09 00 00 00 01 00 20 99 4A 1C 40 00 00 00 04 00 ...... .J.@.....
400000000003D3E0 10 00 48 22 90 11 00 00 00 02 00 00 80 AC FF 48 ..H"...........H
400000000003D3F0 09 70 10 02 B0 24 10 01 88 30 20 00 00 00 04 00 .p...$...0 .....
400000000003D400 09 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000003D410 08 80 10 02 33 24 F0 80 38 00 42 C0 01 71 00 84 ....3$..8.B..q..
400000000003D420 0B 00 01 00 00 21 00 00 00 02 00 00 00 00 04 00 .....!..........
400000000003D430 09 00 44 20 98 11 00 01 3C 30 20 E0 C1 0D CC 90 ..D ....<0 .....
400000000003D440 09 00 00 1E 90 11 10 F9 43 7E 46 E0 01 0C D0 90 ........C~F.....
400000000003D450 08 00 00 00 01 00 20 01 3C 20 20 E0 41 0C D0 90 ...... .<  .A...
400000000003D460 0B 88 00 22 00 10 F0 00 3C 20 20 20 02 88 50 00 ..."....<   ..P.
400000000003D470 03 78 48 1E 05 20 70 50 44 0C F3 E3 11 78 00 84 .xH.. pPD....x..
400000000003D480 03 00 00 00 01 00 F0 00 3C 2C 00 00 02 79 14 80 ........<,...y..
400000000003D490 10 00 40 1C 98 11 00 00 00 02 00 00 A0 AE FF 48 ..@............H
400000000003D4A0 08 00 00 00 01 00 E0 00 84 30 20 20 05 48 41 00 .........0  .HA.
400000000003D4B0 0A 00 3C 54 98 11 00 70 40 30 23 E0 91 02 4C 80 ..<T...p@0#...L.
400000000003D4C0 09 80 A4 00 10 20 00 00 00 02 00 C0 01 60 01 84 ..... .......`..
400000000003D4D0 10 78 00 1E 05 20 00 01 40 0A 40 00 90 AB FF 48 .x... ..@.@....H
400000000003D4E0 09 70 00 42 18 10 00 00 00 02 00 20 05 48 41 00 .p.B....... .HA.
400000000003D4F0 09 00 38 1E 98 11 00 00 00 02 00 C0 01 0E FD 8C ..8.............
400000000003D500 09 00 00 00 01 00 E0 00 38 30 20 00 00 00 04 00 ........80 .....
400000000003D510 11 60 03 1C 18 10 00 00 00 02 00 00 B8 78 00 50 .`...........x.P
400000000003D520 08 88 10 10 00 21 F0 48 01 26 40 00 92 02 40 80 .....!.H.&@...@.
400000000003D530 09 08 00 D6 00 21 00 40 A8 30 23 C0 01 60 01 84 .....!.@.0#..`..
400000000003D540 09 90 00 22 10 10 F0 00 3C 0A 40 00 02 80 14 80 ..."....<.@.....
400000000003D550 09 00 00 00 01 00 20 99 4A 1C 40 00 00 00 04 00 ...... .J.@.....
400000000003D560 10 00 48 22 90 11 00 00 00 02 00 00 00 AB FF 48 ..H"...........H
400000000003D570 01 00 20 44 98 11 90 02 A4 20 00 C0 CD 07 00 90 .. D..... ......
400000000003D580 08 00 00 00 01 00 C0 06 A0 31 20 00 00 00 04 00 .........1 .....
400000000003D590 19 68 03 42 18 10 00 00 00 02 00 00 F8 58 00 50 .h.B.........X.P
400000000003D5A0 08 78 A4 00 13 20 00 49 01 20 40 00 00 00 04 00 .x... .I. @.....
400000000003D5B0 09 08 00 D6 00 21 00 40 A8 30 23 C0 01 60 01 84 .....!.@.0#..`..
400000000003D5C0 10 78 00 1E 05 20 00 01 40 0A 40 00 A0 AA FF 48 .x... ..@.@....H
400000000003D5D0 08 70 90 FB AC 27 D0 66 F6 FF 4F 00 00 00 04 00 .p...'.f..O.....
400000000003D5E0 09 60 03 00 00 21 E0 2E 00 00 48 00 04 00 00 84 .`...!....H.....
400000000003D5F0 09 70 00 1C 18 10 D0 06 B4 31 20 00 00 00 04 00 .p.......1 .....
400000000003D600 11 10 01 1C 18 10 00 00 00 02 00 00 68 D5 FD 58 ............h..X
400000000003D610 08 08 00 D6 00 21 00 00 00 02 00 80 0D 10 01 84 .....!..........
400000000003D620 03 68 07 00 00 24 E0 06 20 00 42 C0 81 0F C8 90 .h...$.. .B.....
400000000003D630 0B 00 00 00 01 00 F0 06 38 20 20 00 00 00 04 00 ........8  .....
400000000003D640 0B 30 00 DE 87 F9 F1 E6 F5 FF 4F 00 00 00 04 00 .0........O.....
400000000003D650 CB 78 13 FB FF E7 F1 06 BC 31 20 00 00 00 04 00 .x.......1 .....
400000000003D660 D1 78 03 DE 18 10 00 00 00 02 00 00 E8 E9 FD 58 .x.............X
400000000003D670 08 00 00 00 01 00 10 00 AC 01 42 C0 A1 00 00 90 ..........B.....
400000000003D680 0B 78 00 42 10 10 00 21 05 8C 48 E0 11 78 00 84 .x.B...!..H..x..
400000000003D690 09 00 00 00 01 00 00 78 84 20 23 00 00 00 04 00 .......x. #.....
400000000003D6A0 09 00 38 20 90 11 00 00 00 02 00 00 42 0D D0 90 ..8 ........B...
400000000003D6B0 09 00 38 20 90 11 00 00 00 02 00 C0 C1 09 D0 90 ..8 ............
400000000003D6C0 11 00 00 1C 98 11 00 00 00 02 00 00 88 B7 FE 58 ...............X
400000000003D6D0 10 00 00 00 01 00 10 00 AC 01 42 00 60 AC FF 48 ..........B.`..H
400000000003D6E0 08 00 00 00 01 00 E0 00 84 30 20 20 05 48 41 00 .........0  .HA.
400000000003D6F0 0A 00 3C 54 98 11 00 70 40 30 23 E0 91 02 4C 80 ..<T...p@0#...L.
400000000003D700 09 80 A4 00 10 20 00 00 00 02 00 C0 01 60 01 84 ..... .......`..
400000000003D710 10 78 00 1E 05 20 00 01 40 0A 40 00 50 A9 FF 48 .x... ..@.@.P..H
400000000003D720 09 70 10 02 B0 24 10 01 84 30 20 00 00 00 04 00 .p...$...0 .....
400000000003D730 11 00 00 00 01 00 00 00 00 02 00 00 E0 FC FF 48 ...............H

;; parse_string_to_word_list: 400000000003D740
;;   Called from:
;;     40000000000BF38C (in expand_compound_array_assignment)
parse_string_to_word_list proc
	{ alloc	r55,ar.pfs,0x1C,0x0,0x1A; addl	r43,6116,r1; addl	r42,9156,r1 }
	{ addl	r39,8952,r1; addl	r41,7376,r1; adds	r56,0x0,r1; }
	{ nop.m	0x0; addl	r40,6680,r1; mov	r57,pr }
	{ adds	r35,0x0,r0; nop.m	0x0; addl	r36,304,r0; }
	{ nop.m	0x0; mov	r54,b6; nop.i	0x0 }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ ld4	r48,[r43]; nop.m	0x0; tnat.z	p16,p17,r33 }
	{ ld4	r47,[r42]; nop.m	0x0; br.call.sptk.many	b0,bash_history_disable; }
	{ adds	r1,0x0,r56; nop.m	0x0; addl	r58,1,r0 }
	{ ld4	r50,[r39]; ld4	r52,[r41]; nop.i	0x0; }
	{ addl	r46,6648,r1; addl	r44,6828,r1; addl	r45,6740,r1 }
	{ ld4	r51,[r40]; ld4	r53,[r46]; nop.i	0x0 }
	{ ld4	r49,[r44]; nop.m	0x0; br.call.sptk.many	b0,push_stream; }
	{ addl	r14,281,r0; adds	r1,0x0,r56; adds	r58,0x0,r32 }
	{ st4	[r0],r39; st4	[r0],r40; adds	r59,0x0,r34; }
	{ nop.m	0x0; st4	[r14],r45; nop.i	0x0 }
	{ st4	[r0],r41; nop.m	0x0; br.call.sptk.many	b0,with_input_from_string; }
	{ adds	r1,0x0,r56; nop.m	0x0; (p17) addl	r16,270336,r0; }

l400000000003D860:
	{ (p17) addl	r14,8944,r1; addl	r38,22532,r1; addl	r37,22572,r1; }

l400000000003D866:
	{ Invalid; (p18) nop; break.i	0x80000 }
	{ break.m	0x4000; nop; break.i	0x80000 }
	{ break.m	0x4000; (p19) dep	r16,r38,r0,35,3; (p52) nop }

l400000000003D896:
	{ nop; (p07) dep.z	r16,0xF,49,1; (p04) nop }

l400000000003D8A0:
	{ (p17) st4	[r15],r14; nop.m	0x0; nop.i	0x0; }

l400000000003D8A6:
	{ break.m	0x4000; nop; break.i	0x80000 }
	{ break.m	0x4000; nop; break.i	0x80000 }

l400000000003D8C0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn4000000000030880; }

l400000000003D8C2:
	{ break.m	0x20; addl	r32,0,r0; Invalid }
	{ Invalid; (p04) cmp.eq.unc	p02,p01,r33,r124; nop }

l400000000003D8E0:
	{ cmp4.eq	p07,p06,0xA,r8; nop.m	0x0; adds	r14,0xFFFFFFFFFFFFFEE7,r8 }
	{ adds	r59,0x0,r35; nop.m	0x0; (p07) br.cond.dpnt.few	400000000003DA60; }

l400000000003D900:
	{ cmp4.ltu	p07,p06,0x1,r14; nop.i	0x0; (p07) br.cond.dpnt.few	400000000003DAB0; }

l400000000003D910:
	{ ld8	r58,[r37]; nop.i	0x0; br.call.sptk.many	b0,make_word_list; }
	{ adds	r1,0x0,r56; adds	r35,0x0,r8; br.call.sptk.many	b0,fn4000000000030880; }
	{ adds	r1,0x0,r56; cmp4.eq	p07,p06,r36,r8; (p06) br.cond.dptk.few	400000000003D8E0; }

l400000000003D940:
	{ nop.m	0x0; addl	r36,9916,r1; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000003D960:
	{ nop.m	0x0; addl	r14,10,r0; nop.i	0x0; }
	{ st4	[r14],r45; nop.i	0x0; br.call.sptk.many	b0,pop_stream; }
	{ nop.m	0x0; adds	r1,0x0,r56; (p17) addl	r16,-270337,r0 }

l400000000003D990:
	{ st4	[r48],r43; st4	[r47],r42; cmp.eq	p07,p06,r36,r35; }
	{ (p17) addl	r14,8944,r1; st4	[r52],r41; nop.i	0x0 }

l400000000003D9A6:
	{ mf.a; nop; nop }
	{ break.m	0x4000; nop; nop }
	{ mf.a; shrp	r0,r0,r1,0; (p52) tbit.z	p03,p04,r3,0x20 }

l400000000003D9D6:
	{ Invalid; Invalid; Invalid }

l400000000003D9DC:
	{ srlz.d; Invalid; mov	pr,r32,0x0 }

l400000000003D9E6:
	{ chk.a.nc	f0,3FFFFFFFFF03E1E6; nop; (p32) nop }

l400000000003D9F0:
	{ cmp.eq	p06,p07,0x0,r35; adds	r58,0x0,r35; (p06) br.cond.dpnt.few	400000000003DA40; }

l400000000003DA00:
	{ nop.m	0x0; ld8	r14,[r35]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000003DA40; }

l400000000003DA20:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,list_reverse; }
	{ nop.m	0x0; adds	r1,0x0,r56; adds	r35,0x0,r8; }

l400000000003DA40:
	{ adds	r8,0x0,r35; mov	pr,r57,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r55; }
	{ nop.m	0x0; mov.spnt	b0,r54,400000000003DA50; br.ret	b0 }

l400000000003DA60:
	{ ld8	r14,[r38]; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	400000000003D8C0 }

l400000000003DA90:
	{ nop.m	0x0; addl	r36,9916,r1; nop.i	0x0; }
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000003D960; }

l400000000003DAB0:
	{ ld4	r14,[r46]; addl	r36,8996,r1; adds	r58,0x0,r0; }
	{ nop.m	0x0; nop.m	0x0; add	r14,r53,r14; }
	{ adds	r14,0xFFFFFFFFFFFFFFFF,r14; ld4	r37,[r36]; nop.i	0x0 }
	{ st4	[r14],r46; st4	[r8],r36; br.call.sptk.many	b0,yyerror; }
	{ adds	r1,0x0,r56; cmp.eq	p06,p07,0x0,r35; nop.i	0x0 }
	{ adds	r58,0x0,r35; st4	[r37],r36; (p06) br.cond.dpnt.few	400000000003DC30; }

l400000000003DB10:
	{ nop.m	0x0; addl	r35,9916,r1; nop.i	0x0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,dispose_words; }
	{ addl	r14,10,r0; adds	r1,0x0,r56; adds	r36,0x0,r35; }
	{ st4	[r14],r45; nop.i	0x0; br.call.sptk.many	b0,pop_stream; }
	{ nop.m	0x0; adds	r1,0x0,r56; (p17) addl	r16,-270337,r0 }

l400000000003DB60:
	{ st4	[r48],r43; st4	[r47],r42; cmp.eq	p07,p06,r36,r35; }
	{ (p17) addl	r14,8944,r1; st4	[r52],r41; nop.i	0x0 }

l400000000003DB76:
	{ mf.a; nop; nop }
	{ break.m	0x4000; nop; nop }
	{ mf.a; shrp	r0,r0,r1,0; (p52) tbit.z	p03,p04,r3,0x20 }

l400000000003DBA6:
	{ Invalid; Invalid; Invalid }

l400000000003DBAC:
	{ srlz.d; Invalid; mov	pr,r32,0x0 }

l400000000003DBB6:
	{ chk.a.nc	r0,3FFFFFFFFF03E3B6; nop; (p32) nop }

l400000000003DBC0:
	{ addl	r14,6512,r1; addl	r15,9044,r1; addl	r16,1,r0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ ld4	r14,[r14]; st4	[r16],r15; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; addl	r14,6456,r1; (p06) br.cond.spnt.few	400000000003DC20; }

l400000000003DC00:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	400000000003DC50 }

l400000000003DC20:
	{ nop.m	0x0; addl	r58,2,r0; br.call.sptk.many	b0,jump_to_top_level }

l400000000003DC30:
	{ addl	r35,9916,r1; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; adds	r36,0x0,r35; br.cond.sptk.few	400000000003D960 }

l400000000003DC50:
	{ nop.m	0x0; addl	r58,1,r0; br.call.sptk.many	b0,jump_to_top_level; }
	{ nop.m	0x0; break.f	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

;; save_parser_state: 400000000003DC80
;;   Called from:
;;     400000000003DC7C (in parse_string_to_word_list)
;;     400000000003E22C (in execute_variable_command)
;;     400000000003E6FC (in xparse_dolparen)
;;     40000000000E619C (in gen_compspec_completions)
save_parser_state proc
	{ alloc	r35,ar.pfs,0x6,0x0,0x5; nop.m	0x0; mov	r34,b2 }
	{ adds	r36,0x0,r1; cmp.eq	p07,p06,0x0,r32; (p07) br.cond.dpnt.few	400000000003DEA0 }

l400000000003DCA0:
	{ addl	r14,8944,r1; nop.m	0x0; adds	r33,0x0,r32; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ st4	[r33],r8,8; nop.i	0x0; br.call.sptk.many	b0,save_token_state; }
	{ adds	r1,0x0,r36; adds	r26,0x1C,r32; adds	r24,0x20,r32 }
	{ adds	r22,0x28,r32; adds	r20,0x30,r32; adds	r18,0x34,r32; }
	{ nop.m	0x0; addl	r14,6828,r1; adds	r16,0x38,r32 }
	{ st8	[r8],r33; ld4	r27,[r14]; addl	r14,6620,r1; }
	{ nop.m	0x0; ld4	r25,[r14]; addl	r14,6684,r1 }
	{ st4	[r27],r26; ld8	r23,[r14]; addl	r14,8952,r1 }
	{ st4	[r25],r24; nop.m	0x0; nop.i	0x0 }
	{ st8	[r23],r22; ld4	r21,[r14]; addl	r14,6116,r1; }
	{ nop.m	0x0; st4	[r21],r20; nop.i	0x0; }
	{ ld4	r19,[r14]; nop.m	0x0; addl	r14,9156,r1; }
	{ nop.m	0x0; st4	[r19],r18; nop.i	0x0; }
	{ ld4	r17,[r14]; nop.m	0x0; addl	r14,9044,r1; }
	{ nop.m	0x0; st4	[r17],r16; nop.i	0x0; }
	{ ld4	r15,[r14]; nop.m	0x0; adds	r14,0x3C,r32; }
	{ st4	[r15],r14; nop.i	0x0; br.call.sptk.many	b0,save_pipestatus_array; }
	{ adds	r1,0x0,r36; adds	r26,0x48,r32; adds	r27,0x40,r32 }
	{ adds	r25,0x50,r32; adds	r24,0x58,r32; adds	r23,0x5C,r32; }
	{ addl	r18,8396,r1; addl	r15,6804,r1; mov.i	ar.pfs,r35 }
	{ addl	r14,6800,r1; st8	[r8],r27; adds	r22,0x10,r32; }
	{ nop.m	0x0; adds	r8,0x0,r32; mov.spnt	b0,r34,400000000003DE00 }
	{ ld8	r17,[r15]; st8	[r0],r15; nop.i	0x0; }
	{ ld4	r16,[r14]; st8	[r17],r22; nop.i	0x0 }
	{ st4	[r0],r14; ld8	r21,[r18]; addl	r18,8388,r1; }
	{ nop.m	0x0; st8	[r21],r26; adds	r21,0x18,r32; }
	{ st4	[r16],r21; ld8	r20,[r18]; addl	r18,6680,r1; }
	{ nop.m	0x0; ld4	r19,[r18]; addl	r18,7376,r1 }
	{ st8	[r20],r25; nop.m	0x0; nop.i	0x0 }
	{ st4	[r19],r24; ld4	r18,[r18]; nop.i	0x0; }
	{ st4	[r18],r23; nop.i	0x0; br.ret	b0; }

l400000000003DEA0:
	{ addl	r37,96,r0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r32,0x0,r8; cmp.eq	p06,p07,0x0,r8; nop.b	0x0 }
	{ adds	r1,0x0,r36; mov.i	ar.pfs,r35; (p07) br.cond.dpnt.few	400000000003DCA0; }

l400000000003DED0:
	{ adds	r8,0x0,r32; mov.spnt	b0,r34,400000000003DED0; br.ret	b0; }
400000000003DEE0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000003DEF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; restore_parser_state: 400000000003DF00
;;   Called from:
;;     400000000003E32C (in execute_variable_command)
;;     400000000003E44C (in execute_variable_command)
;;     400000000003E78C (in xparse_dolparen)
;;     40000000000E626C (in gen_compspec_completions)
restore_parser_state proc
	{ alloc	r35,ar.pfs,0x6,0x0,0x5; adds	r14,0x0,r32; mov	r34,b2 }
	{ cmp.eq	p06,p07,0x0,r32; adds	r36,0x0,r1; (p06) br.cond.dpnt.few	400000000003E1D0; }

l400000000003DF20:
	{ ld4	r15,[r14],8; nop.m	0x0; addl	r33,6804,r1; }
	{ ld8	r37,[r14]; nop.m	0x0; addl	r14,8944,r1; }
	{ nop.m	0x0; adds	r16,0x8,r37; cmp.eq	p06,p07,0x0,r37; }
	{ st4	[r15],r14; nop.m	0x0; adds	r14,0x0,r37 }
	{ adds	r15,0xC,r37; nop.m	0x0; (p06) br.cond.dpnt.few	400000000003DFF0; }

l400000000003DF70:
	{ ld4	r18,[r14],4; ld4	r17,[r16]; nop.i	0x0; }
	{ nop.m	0x0; ld4	r16,[r14]; addl	r14,6740,r1 }
	{ ld4	r15,[r15]; st4	[r18],r14; addl	r14,6736,r1; }
	{ st4	[r17],r14; nop.m	0x0; addl	r14,6732,r1; }
	{ st4	[r16],r14; nop.m	0x0; addl	r14,8996,r1; }
	{ nop.m	0x0; nop.i	0x0; nop.i	0x0 }
	{ st4	[r15],r14; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r36; nop.m	0x0; nop.i	0x0 }

l400000000003DFF0:
	{ adds	r20,0x1C,r32; adds	r19,0x20,r32; adds	r18,0x28,r32 }
	{ adds	r17,0x30,r32; adds	r16,0x34,r32; adds	r15,0x38,r32; }
	{ adds	r14,0x3C,r32; ld4	r21,[r20]; nop.i	0x0 }
	{ ld4	r20,[r19]; ld8	r19,[r18]; nop.i	0x0 }
	{ ld4	r18,[r17]; ld4	r17,[r16]; nop.i	0x0 }
	{ ld4	r16,[r15]; ld4	r15,[r14]; adds	r14,0x40,r32; }
	{ ld8	r37,[r14]; nop.m	0x0; addl	r14,6828,r1; }
	{ st4	[r21],r14; nop.m	0x0; addl	r14,6620,r1; }
	{ st4	[r20],r14; nop.m	0x0; addl	r14,6684,r1; }
	{ st8	[r19],r14; nop.m	0x0; addl	r14,8952,r1; }
	{ nop.m	0x0; st4	[r18],r14; addl	r14,6116,r1; }
	{ nop.m	0x0; st4	[r17],r14; addl	r14,9156,r1; }
	{ nop.m	0x0; st4	[r16],r14; addl	r14,9044,r1; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ st4	[r15],r14; nop.i	0x0; br.call.sptk.many	b0,restore_pipestatus_array; }
	{ adds	r1,0x0,r36; adds	r17,0x48,r32; adds	r16,0x50,r32 }
	{ adds	r15,0x58,r32; ld8	r37,[r33]; adds	r14,0x5C,r32; }
	{ nop.m	0x0; ld8	r18,[r17]; cmp.eq	p06,p07,0x0,r37 }
	{ nop.m	0x0; ld8	r17,[r16]; nop.i	0x0; }
	{ ld4	r16,[r15]; ld4	r15,[r14]; addl	r14,8396,r1; }
	{ nop.m	0x0; st8	[r18],r14; addl	r14,8388,r1; }
	{ nop.m	0x0; st8	[r17],r14; addl	r14,6680,r1; }
	{ st4	[r16],r14; nop.m	0x0; addl	r14,7376,r1; }
	{ nop.m	0x0; st4	[r15],r14; nop.i	0x0 }
	{ nop.b	0x0; (p06) br.cond.dpnt.few	400000000003E190; br.call.sptk.many	b0,fn400000000001A7E0; }

l400000000003E17C:
	{ (p51) nop; invala; break.b	0x1000 }
	{ cmp.lt	p00,p09,r1,r0; zxt1	r4,r64; break.i	0x1000 }

l400000000003E190:
	{ adds	r14,0x10,r32; nop.m	0x0; adds	r32,0x18,r32; }
	{ ld8	r14,[r14]; ld4	r15,[r32]; nop.i	0x0; }
	{ st8	[r14],r33; addl	r14,6800,r1; nop.i	0x0; }
	{ st4	[r15],r14; nop.m	0x0; nop.i	0x0 }

l400000000003E1D0:
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r34,400000000003E1E0; br.ret	b0; }
400000000003E1F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; execute_variable_command: 400000000003E200
;;   Called from:
;;     400000000002362C (in parse_command)
execute_variable_command proc
	{ alloc	r36,ar.pfs,0x9,0x0,0x6; adds	r12,0xFFFFFFFFFFFFFFA0,r12; mov	r35,b3 }
	{ nop.m	0x0; adds	r37,0x0,r1; nop.i	0x0; }
	{ adds	r38,0x10,r12; nop.i	0x0; br.call.sptk.many	b0,save_parser_state; }
	{ adds	r1,0x0,r37; addl	r38,-20,r1; nop.i	0x0; }
	{ ld8	r38,[r38]; nop.i	0x0; br.call.sptk.many	b0,get_string_value; }
	{ cmp.eq	p06,p07,0x0,r8; adds	r1,0x0,r37; nop.i	0x0 }
	{ adds	r34,0x0,r8; adds	r38,0x0,r8; (p06) br.cond.dpnt.few	400000000003E3E0; }

l400000000003E270:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r37; adds	r38,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r39,0x0,r34; nop.m	0x0; adds	r1,0x0,r37 }
	{ adds	r38,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r37; nop.m	0x0; adds	r34,0x0,r8 }
	{ adds	r38,0x0,r32; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r37; adds	r38,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r37; nop.m	0x0; adds	r38,0x0,r8 }
	{ adds	r39,0x0,r32; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r39,0x0,r33; addl	r40,5,r0; nop.i	0x0 }
	{ adds	r1,0x0,r37; adds	r38,0x0,r8; br.call.sptk.many	b0,parse_and_execute; }
	{ adds	r1,0x0,r37; adds	r38,0x10,r12; br.call.sptk.many	b0,restore_parser_state; }
	{ adds	r1,0x0,r37; adds	r39,0x0,r34; adds	r40,0x0,r0; }
	{ nop.m	0x0; addl	r38,-20,r1; nop.i	0x0; }
	{ ld8	r38,[r38]; nop.i	0x0; br.call.sptk.many	b0,bind_variable; }
	{ cmp.eq	p06,p07,0x0,r34; nop.m	0x0; adds	r1,0x0,r37 }
	{ adds	r38,0x0,r34; nop.m	0x0; (p06) br.cond.spnt.few	400000000003E3A0; }

l400000000003E380:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r37; nop.m	0x0; nop.i	0x0; }

l400000000003E3A0:
	{ addl	r14,6728,r1; ld4	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0xA,r15; nop.i	0x0; }
	{ (p07) st4	[r0],r14; mov.i	ar.pfs,r36; mov.spnt	b0,r35,400000000003E3C0 }

l400000000003E3C6:
	{ break.m	0xAA024; nop; break.i	0x80000 }
	{ Invalid; (p34) nop; (p32) nop }

l400000000003E3E0:
	{ adds	r38,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r37; adds	r38,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r37; nop.m	0x0; adds	r39,0x0,r32 }
	{ adds	r38,0x0,r8; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r39,0x0,r33; adds	r1,0x0,r37; nop.i	0x0 }
	{ addl	r40,5,r0; adds	r38,0x0,r8; br.call.sptk.many	b0,parse_and_execute; }
	{ adds	r1,0x0,r37; adds	r38,0x10,r12; br.call.sptk.many	b0,restore_parser_state; }
	{ adds	r1,0x0,r37; adds	r39,0x0,r0; adds	r40,0x0,r0; }
	{ nop.m	0x0; addl	r38,-20,r1; nop.i	0x0; }
	{ ld8	r38,[r38]; nop.i	0x0; br.call.sptk.many	b0,bind_variable; }
	{ adds	r1,0x0,r37; addl	r14,6728,r1; nop.i	0x0; }
	{ ld4	r15,[r14]; cmp4.eq	p07,p06,0xA,r15; nop.i	0x0; }
	{ (p07) st4	[r0],r14; mov.i	ar.pfs,r36; mov.spnt	b0,r35,400000000003E4A0 }

l400000000003E4A6:
	{ break.m	0xAA024; nop; break.i	0x80000 }
	{ Invalid; (p34) nop; Invalid }

;; save_input_line_state: 400000000003E4C0
;;   Called from:
;;     400000000003E70C (in xparse_dolparen)
save_input_line_state proc
	{ alloc	r34,ar.pfs,0x5,0x0,0x4; nop.m	0x0; mov	r33,b1 }
	{ adds	r35,0x0,r1; cmp.eq	p07,p06,0x0,r32; (p07) br.cond.dpnt.few	400000000003E570 }

l400000000003E4E0:
	{ addl	r18,6788,r1; adds	r14,0x0,r32; addl	r15,6824,r1 }
	{ addl	r16,6720,r1; addl	r17,6724,r1; adds	r23,0x10,r32; }
	{ ld8	r22,[r18]; adds	r32,0x8,r32; nop.b	0x0 }
	{ st8	[r0],r18; ld4	r21,[r15]; mov.i	ar.pfs,r34; }
	{ ld4	r20,[r16]; st8	[r14],r12,12; nop.b	0x0 }
	{ st4	[r0],r16; ld4	r19,[r17]; mov.spnt	b0,r33,400000000003E530; }
	{ st4	[r21],r14; st4	[r20],r23; nop.i	0x0; }
	{ st4	[r19],r32; st4	[r0],r17; nop.i	0x0; }
	{ st4	[r0],r15; nop.i	0x0; br.ret	b0; }

l400000000003E570:
	{ addl	r36,24,r0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ nop.m	0x0; mov.i	ar.pfs,r34; nop.b	0x0 }
	{ adds	r32,0x0,r8; cmp.eq	p07,p06,0x0,r8; adds	r8,0x0,r0; }
	{ nop.m	0x0; mov.spnt	b0,r33,400000000003E5A0; adds	r1,0x0,r35 }
	{ nop.b	0x0; (p06) br.cond.spnt.few	400000000003E4E0; br.ret	b0; }

l400000000003E5BC:
	{ ldf8	f0,[r0]; (p36) nop; (p04) dep	r33,r32,r13,62,3 }

;; restore_input_line_state: 400000000003E5C0
;;   Called from:
;;     400000000003E7AC (in xparse_dolparen)
restore_input_line_state proc
	{ alloc	r35,ar.pfs,0x6,0x0,0x5; addl	r33,6788,r1; mov	r34,b2 }
	{ adds	r36,0x0,r1; ld8	r37,[r33]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r37; nop.i	0x0; (p06) br.cond.dpnt.few	400000000003E610; }

l400000000003E5F0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r36; nop.m	0x0; nop.i	0x0 }

l400000000003E610:
	{ adds	r14,0x0,r32; adds	r16,0x10,r32; nop.b	0x0 }
	{ adds	r32,0x8,r32; nop.m	0x0; mov.spnt	b0,r34,400000000003E620; }
	{ nop.m	0x0; ld8	r15,[r14],12; mov.i	ar.pfs,r35 }
	{ ld4	r18,[r16]; ld4	r17,[r14]; addl	r14,6720,r1 }
	{ st8	[r15],r33; ld4	r16,[r32]; nop.i	0x0; }
	{ st4	[r18],r14; nop.m	0x0; addl	r14,6824,r1; }
	{ st4	[r17],r14; nop.m	0x0; addl	r14,6724,r1; }
	{ nop.m	0x0; st4	[r16],r14; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x1,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn40000000000253C0; }
400000000003E6A0 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
400000000003E6B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; xparse_dolparen: 400000000003E6C0
;;   Called from:
;;     400000000008B68C (in extract_command_subst)
xparse_dolparen proc
	{ alloc	r39,ar.pfs,0xE,0x0,0xA; adds	r12,0xFFFFFFFFFFFFFF80,r12; tbit.z	p06,p07,r35,0x6 }
	{ adds	r40,0x0,r1; nop.i	0x0; mov	r38,b6 }
	{ (p06) addl	r37,13,r0; adds	r42,0x10,r12; adds	r36,0x88,r12; }

l400000000003E6E6:
	{ Invalid; (p18) cmp4.eq.or.andcm	p08,p02,r12,r1; (p17) nop }

l400000000003E6F6:
	{ (p20) break.m	0xCA080; (p32) nop; (p16) nop.b	0x28000 }
	{ Invalid; (p32) nop; (p16) nop }
	{ Invalid; (p08) nop; nop }
	{ Invalid; (p21) nop; (p32) brp.ret.sptk	b4,400000000003E756 }
	{ add	r0,r0,r1; (p21) nop; break.i	0x80000 }
	{ (p21) fwb; nop; (p48) br.call.sptk.few	b3,b0 }
	{ Invalid; (p08) nop; break.b	0x80000 }
	{ mf.a; nop; nop }
	{ break.m	0x4000; (p32) nop; (p32) nop }
	{ Invalid; (p32) nop; (p16) nop.b	0x28000 }
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ Invalid; (p32) nop; (p16) nop }
	{ (p07) fwb; nop; (p32) nop }
	{ Invalid; (p08) nop; (p16) nop }
	{ break.m	0x4000; nop; nop }
	{ break.m	0x4000; Invalid; (p32) nop }
	{ Invalid; (p03) cmp.eq.or	p00,p51,0x12,r7; (p33) cmp.eq	p04,p13,0x32,r0 }

l400000000003E806:
	{ mf.a; (p03) nop; add	r0,r0,r0; }

l400000000003E80C:
	{ (p20) rsm	0x3CC390; mov	pr,r0,0x2000; (p16) rfi }

l400000000003E81C:
	{ (p02) cmp.eq	p00,p17,r64,r33; czx1.r	r2,r97; break.b	0x1000 }

l400000000003E820:
	{ cmp4.eq	p07,p06,0xA,r16; nop.i	0x0; (p06) br.cond.dpnt.few	400000000003E860; }

l400000000003E830:
	{ nop.m	0x0; adds	r15,0x1,r14; nop.i	0x0; }
	{ st8	[r15],r36; nop.i	0x0; br.cloop.sptk.few	400000000003E8F0; }

l400000000003E850:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000003E860:
	{ nop.m	0x0; sub	r44,r15,r33; tbit.z	p07,p06,r35,0x0 }
	{ sub	r32,r15,r32,0x1; addl	r42,1,r0; adds	r43,0x0,r0; }
	{ st4	[r32],r34; (p06) adds	r8,0x0,r0; (p06) br.cond.dpnt.few	400000000003E8C0; }

l400000000003E88C:
	{ (p02) invala; cmp.eq	p00,p00,r32,r0; mov	pr,r75,0xE600 }

l400000000003E890:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r44; (p06) br.cond.dptk.few	400000000003E940 }

l400000000003E8A0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r40; st1	[r0],r8; nop.i	0x0 }

l400000000003E8C0:
	{ nop.m	0x0; mov.i	ar.pfs,r39; nop.i	0x0; }
	{ nop.m	0x0; mov.i	LC,r41; mov.spnt	b0,r38,400000000003E8D0 }
	{ nop.m	0x0; adds	r12,0x80,r12; br.ret	b0 }

l400000000003E8F0:
	{ ld1	r16,[r14],-1; nop.m	0x0; sxt1	r16,r16; }
	{ cmp4.eq	p06,p07,0xA,r16; nop.i	0x0; (p07) br.cond.dpnt.few	400000000003E860; }

l400000000003E910:
	{ nop.m	0x0; adds	r15,0x1,r14; nop.i	0x0; }
	{ st8	[r15],r36; nop.i	0x0; br.cloop.sptk.few	400000000003E8F0 }

l400000000003E930:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000003E860 }

l400000000003E940:
	{ adds	r42,0x0,r33; adds	r44,0xFFFFFFFFFFFFFFFF,r44; br.call.sptk.many	b0,substring; }
	{ adds	r1,0x0,r40; mov.i	ar.pfs,r39; mov.i	LC,r41; }
	{ nop.m	0x0; mov.spnt	b0,r38,400000000003E960; nop.i	0x0 }
	{ adds	r12,0x80,r12; nop.m	0x0; br.ret	b0; }

;; fn400000000003E980: 400000000003E980
;;   Called from:
;;     400000000004210C (in group_member)
;;     400000000004231C (in get_group_list)
;;     400000000004255C (in get_group_array)
fn400000000003E980 proc
	{ alloc	r37,ar.pfs,0xA,0x0,0x8; addl	r34,6908,r1; mov	r39,LC }
	{ adds	r38,0x0,r1; addl	r33,6892,r1; addl	r35,6900,r1; }
	{ ld4	r14,[r34]; nop.m	0x0; mov	r36,b4; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	400000000003ED10 }

l400000000003E9C0:
	{ ld4	r14,[r34]; st4	[r0],r33; nop.i	0x0 }
	{ ld8	r40,[r35]; nop.m	0x0; sxt4	r41,r14; }
	{ shladd	r41,r41,0x2,r0; nop.i	0x0; br.call.sptk.many	b0,xrealloc; }
	{ nop.m	0x0; ld4	r34,[r34]; adds	r1,0x0,r38 }
	{ adds	r32,0x0,r8; st8	[r8],r35; adds	r41,0x0,r8; }
	{ adds	r40,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BE60; }
	{ adds	r1,0x0,r38; st4	[r8],r33; cmp4.eq	p07,p06,0x0,r8 }
	{ nop.m	0x0; nop.m	0x0; (p06) br.cond.dptk.few	400000000003ECE0; }

l400000000003EA40:
	{ nop.m	0x0; addl	r19,-22276,r1; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ adds	r14,0x8,r19; addl	r15,1,r0; nop.i	0x0 }
	{ addl	r8,1,r0; ld4	r20,[r14]; nop.i	0x0 }
	{ st4	[r15],r33; st4	[r20],r32; nop.i	0x0 }

l400000000003EA90:
	{ adds	r17,0xFFFFFFFFFFFFFFFF,r8; adds	r15,0x8,r19; cmp4.lt	p09,p08,0x0,r8 }
	{ adds	r14,0x0,r0; adds	r16,0x4,r32; addp4	r17,r17,r0 }
	{ ld4	r15,[r15]; adds	r14,0x1,r14; mov.i	LC,r17 }
	{ cmp4.eq	p06,p07,r20,r15; nop.m	0x0; (p06) br.cond.dpnt.few	400000000003EC90; }

l400000000003EAD0:
	{ nop.m	0x0; (p09) mov.i	LC,r17; (p08) mov.i	LC,0x0; }

l400000000003EADC:
	{ Invalid; break.i	0x1000; nop }

l400000000003EAE0:
	{ nop.m	0x0; nop.i	0x0; br.cloop.sptk.few	400000000003ECB0; }

l400000000003EAF0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000003EB00:
	{ cmp4.eq	p06,p07,r8,r14; adds	r17,0xFFFFFFFFFFFFFFFF,r8; sxt4	r15,r8 }
	{ adds	r16,0xFFFFFFFFFFFFFFF8,r32; nop.m	0x0; (p07) br.cond.dpnt.few	400000000003ED40; }

l400000000003EB20:
	{ nop.m	0x0; cmp4.lt	p06,p07,r14,r34; (p07) br.cond.dptk.few	400000000003ED40; }

l400000000003EB30:
	{ cmp4.lt	p06,p07,0x0,r8; addp4	r17,r17,r0; nop.i	0x0 }
	{ adds	r14,0xFFFFFFFFFFFFFFFF,r15; shladd	r15,r15,0x2,r16; (p07) br.cond.dpnt.few	400000000003EB80; }

l400000000003EB50:
	{ (p06) shladd	r17,r17,0x2,r0; (p06) shladd	r14,r14,0x2,r32; (p06) sub	r17,r15,r17; }

l400000000003EB56:
	{ Invalid; (p08) nop; nop; }

l400000000003EB5C:
	{ Invalid; Invalid; Invalid }

l400000000003EB60:
	{ ld4	r16,[r14],-4; adds	r15,0x8,r14; cmp.eq	p07,p06,r17,r14; }
	{ st4	[r16],r15; nop.i	0x0; (p06) br.cond.dptk.few	400000000003EB60 }

l400000000003EB80:
	{ adds	r14,0x8,r19; nop.m	0x0; adds	r8,0x1,r8; }
	{ nop.m	0x0; ld4	r20,[r14]; adds	r14,0x8,r19 }
	{ st4	[r8],r33; ld4.a	r15,[r14]; nop.i	0x0 }
	{ st4	[r20],r32; ld4.c.clr	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,r15,r20; (p06) br.cond.dpnt.few	400000000003EC90; }

l400000000003EBD0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000003EBE0:
	{ ld4	r16,[r33]; nop.m	0x0; adds	r14,0x4,r32; }
	{ adds	r18,0xFFFFFFFFFFFFFFFF,r16; cmp4.lt	p07,p06,0x0,r16; (p06) br.cond.dpnt.few	400000000003EC90; }

l400000000003EC00:
	{ nop.m	0x0; addp4	r18,r18,r0; nop.i	0x0; }
	{ shladd	r18,r18,0x2,r32; nop.i	0x0; adds	r18,0x4,r18; }

l400000000003EC20:
	{ adds	r16,0x0,r14; nop.m	0x0; cmp.eq	p07,p06,r18,r14 }
	{ adds	r14,0x4,r14; nop.m	0x0; (p07) br.cond.dpnt.few	400000000003EC90; }

l400000000003EC40:
	{ nop.m	0x0; ld4	r17,[r16]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,r17,r15; (p07) br.cond.dptk.few	400000000003EC20 }

l400000000003EC60:
	{ adds	r19,0x8,r19; st4	[r20],r16; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r19]; nop.i	0x0; }
	{ st4	[r14],r32; nop.m	0x0; nop.i	0x0 }

l400000000003EC90:
	{ nop.m	0x0; mov.i	ar.pfs,r37; mov.i	LC,r39; }
	{ nop.m	0x0; mov.spnt	b0,r36,400000000003ECA0; br.ret	b0 }

l400000000003ECB0:
	{ ld4	r17,[r16],4; nop.m	0x0; adds	r14,0x1,r14; }
	{ cmp4.eq	p06,p07,r15,r17; (p06) br.cond.dpnt.few	400000000003EBE0; br.cloop.sptk.few	400000000003ECB0 }

l400000000003ECCC:
	{ Invalid; break.i	0x1000; break.b	0x1000 }

l400000000003ECD0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000003EB00; }

l400000000003ECE0:
	{ addl	r19,-22276,r1; nop.m	0x0; cmp4.lt	p07,p06,0x0,r8; }
	{ nop.m	0x0; nop.i	0x0; (p06) br.cond.dpnt.few	400000000003ED40; }

l400000000003ED00:
	{ ld4	r20,[r32]; nop.i	0x0; br.cond.sptk.few	400000000003EA90 }

l400000000003ED10:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,getmaxgroups; }
	{ nop.m	0x0; adds	r1,0x0,r38; nop.i	0x0 }
	{ st4	[r8],r34; nop.m	0x0; br.cond.sptk.few	400000000003E9C0 }

l400000000003ED40:
	{ adds	r14,0x8,r19; ld4	r20,[r32]; nop.i	0x0; }
	{ nop.m	0x0; ld4	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,r15,r20; (p07) br.cond.dptk.few	400000000003EBE0 }

l400000000003ED70:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000003EC90; }
400000000003ED80 08 18 1D 0A 80 05 E0 00 80 00 20 40 04 00 C4 00 .......... @....
400000000003ED90 0B 20 01 02 00 21 00 00 00 02 00 C0 01 70 50 00 . ...!.......pP.
400000000003EDA0 11 38 AC 1C 86 39 00 00 00 02 80 03 60 01 00 43 .8...9......`..C
400000000003EDB0 11 38 B4 1C 86 39 E0 80 3A 7E C6 03 E0 00 00 43 .8...9..:~.....C
400000000003EDC0 01 00 00 00 01 00 E0 00 38 20 00 00 00 00 04 00 ........8 ......
400000000003EDD0 10 00 00 00 01 00 70 48 38 0C EB 03 A0 00 00 43 ......pH8......C
400000000003EDE0 11 28 01 40 00 21 00 00 00 02 00 00 A8 4D 0C 50 .(.@.!.......M.P
400000000003EDF0 09 00 00 00 01 00 10 00 90 00 42 20 04 40 00 84 ..........B .@..
400000000003EE00 11 30 00 42 07 39 50 02 84 00 42 03 70 00 00 41 .0.B.9P...B.p..A
400000000003EE10 11 00 00 00 01 00 00 00 00 02 00 00 B8 C8 FD 58 ...............X
400000000003EE20 11 08 00 48 00 21 50 0A 20 00 42 00 A8 9E 0A 50 ...H.!P. .B....P
400000000003EE30 08 08 00 48 00 21 00 00 00 02 00 A0 04 40 00 84 ...H.!.......@..
400000000003EE40 19 30 01 42 00 21 00 00 00 02 00 00 48 C3 FD 58 .0.B.!......H..X
400000000003EE50 09 08 00 48 00 21 00 00 00 02 00 00 30 02 AA 00 ...H.!......0...
400000000003EE60 10 00 00 00 01 00 00 10 05 80 03 80 08 00 84 00 ................
400000000003EE70 09 40 00 00 00 21 00 00 00 02 00 00 30 02 AA 00 .@...!......0...
400000000003EE80 10 00 00 00 01 00 00 10 05 80 03 80 08 00 84 00 ................
400000000003EE90 0B 70 04 40 00 21 F0 00 38 00 20 00 00 00 04 00 .p.@.!..8. .....
400000000003EEA0 01 00 00 00 01 00 F0 00 3C 28 00 00 00 00 04 00 ........<(......
400000000003EEB0 10 00 00 00 01 00 70 00 3C 0C F3 03 B0 00 00 43 ......p.<......C
400000000003EEC0 0B 70 00 1C 00 10 E0 80 3A 7E 46 00 00 00 04 00 .p......:~F.....
400000000003EED0 01 00 00 00 01 00 E0 00 38 20 00 00 00 00 04 00 ........8 ......
400000000003EEE0 10 00 00 00 01 00 70 48 38 0C 6B 03 00 FF FF 4A ......pH8.k....J
400000000003EEF0 10 00 00 00 01 00 00 00 00 02 00 00 80 FF FF 48 ...............H
400000000003EF00 0B 70 04 40 00 21 F0 00 38 00 20 00 00 00 04 00 .p.@.!..8. .....
400000000003EF10 01 00 00 00 01 00 F0 00 3C 28 00 00 00 00 04 00 ........<(......
400000000003EF20 10 00 00 00 01 00 70 00 3C 0C 73 03 A0 FF FF 4A ......p.<.s....J
400000000003EF30 09 00 00 00 01 00 50 22 F7 A7 4F 00 00 00 04 00 ......P"..O.....
400000000003EF40 11 28 01 4A 18 10 00 00 00 02 00 00 88 41 02 50 .(.J.........A.P
400000000003EF50 11 08 00 48 00 21 10 02 20 00 42 00 B0 FE FF 48 ...H.!.. .B....H
400000000003EF60 09 00 00 00 01 00 50 62 F7 A7 4F 00 00 00 04 00 ......Pb..O.....
400000000003EF70 11 28 01 4A 18 10 00 00 00 02 00 00 58 41 02 50 .(.J........XA.P
400000000003EF80 11 08 00 48 00 21 10 02 20 00 42 00 80 FE FF 48 ...H.!.. .B....H
400000000003EF90 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000003EFA0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000003EFB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; posix_initialize: 400000000003EFC0
;;   Called from:
;;     40000000000628DC (in sv_strict_posix)
posix_initialize proc
	{ cmp4.eq	p06,p07,0x0,r32; nop.m	0x0; addl	r14,1,r0; }
	{ (p07) addl	r15,6680,r1; (p06) addl	r14,6512,r1; (p06) addl	r16,1,r0; }

l400000000003EFD6:
	{ (p07) chk.a.clr	r112,3FFFFFFFFF257FE6; (p08) nop; break.i	0x80000; }

l400000000003EFDC:
	{ nop; break.b	0x1000; break.b	0x1000 }

l400000000003EFE0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ (p07) st4	[r14],r15; nop.m	0x0; (p07) addl	r15,6264,r1; }

l400000000003EFF6:
	{ addp4	r0,0xFFFFFFFFFFFFE000,r1; (p07) nop; add	r0,r0,r32 }

l400000000003F000:
	{ nop.m	0x0; (p06) ld4	r15,[r14]; (p06) addl	r14,6260,r1; }

l400000000003F00C:
	{ (p58) nop; mov	pr,r32,0x0; (p32) cmp4.ne.or.andcm	p35,p40,r3,r100; }

l400000000003F010:
	{ nop.m	0x0; (p07) st4	[r14],r15; (p07) addl	r15,5856,r1 }

l400000000003F01C:
	{ (p48) nop; break.i	0x1000; break.i	0x1000; }

l400000000003F020:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; (p06) st4	[r16],r14; (p06) addl	r14,6680,r1; }

l400000000003F03C:
	{ Invalid; Invalid; cmp4.eq.and	p00,p32,r32,r0; }

l400000000003F040:
	{ (p07) st4	[r14],r15; nop.m	0x0; (p07) addl	r14,6260,r1; }

l400000000003F046:
	{ chk.a.nc	f0,3FFFFFFFFF03F846; (p07) nop; break.i	0x80000 }

l400000000003F050:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; (p07) st4	[r0],r14; nop.i	0x0; }

l400000000003F06C:
	{ Invalid; Invalid; add	r0,r32,r0 }

l400000000003F076:
	{ break.m	0x4000; (p34) break.i	0x84000; break.i	0x80000 }

;; string_to_rlimtype: 400000000003F080
;;   Called from:
;;     4000000000110D2C (in ulimit_builtin)
string_to_rlimtype proc
	{ nop.m	0x0; mov	r2,LC; nop.i	0x0 }
	{ cmp.eq	p08,p09,0x0,r32; adds	r15,0x1,r32; (p08) br.cond.dpnt.few	400000000003F0F0; }

l400000000003F0A0:
	{ ld1	r14,[r32]; sub	r16,r0,r15; sxt1	r14,r14; }
	{ cmp4.eq	p07,p06,0x9,r14; cmp4.eq	p10,p11,0x0,r14; mov.i	LC,r16 }
	{ nop.m	0x0; nop.m	0x0; (p10) br.cond.dpnt.few	400000000003F280; }

l400000000003F0D0:
	{ nop.m	0x0; cmp4.eq.or.andcm	p07,p06,0x20,r14; (p06) br.cond.dpnt.few	400000000003F130; }

l400000000003F0E0:
	{ nop.m	0x0; adds	r32,0x0,r15; br.cloop.sptk.few	400000000003F100; }

l400000000003F0F0:
	{ adds	r8,0x0,r0; mov.i	LC,r2; br.ret	b0 }

l400000000003F100:
	{ ld1	r14,[r15],1; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x20,r14; cmp4.eq	p08,p09,0x0,r14; (p08) br.cond.dpnt.few	400000000003F270; }

l400000000003F120:
	{ nop.m	0x0; cmp4.eq.or.andcm	p06,p07,0x9,r14; (p06) br.cond.dptk.few	400000000003F0E0; }

l400000000003F130:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x2D,r14; nop.i	0x0; }
	{ (p07) adds	r17,0x0,r0; (p06) addl	r17,1,r0; cmp4.eq.or.andcm	p06,p07,0x2B,r14; }

l400000000003F146:
	{ Invalid; (p03) cmp4.eq.or.andcm	p43,p51,r14,r71; Invalid; }

l400000000003F14C:
	{ Invalid; (p01) nop; (p02) nop }

l400000000003F156:
	{ (p08) chk.a.clr	f0,3FFFFFFFFF0BF156; Invalid; nop.b	0x20028; }

l400000000003F15C:
	{ Invalid; zxt1	r0,r64; break.i	0x1000 }

l400000000003F160:
	{ adds	r32,0x1,r32; nop.i	0x0; cmp.eq	p08,p09,0x0,r32 }

l400000000003F170:
	{ adds	r16,0x1,r32; adds	r8,0x0,r0; (p08) br.cond.spnt.few	400000000003F290; }

l400000000003F180:
	{ ld1	r14,[r32]; sub	r15,r0,r16; shladd	r8,r8,0x2,r8; }
	{ nop.m	0x0; sxt1	r14,r14; mov.i	LC,r15 }
	{ adds	r15,0xFFFFFFFFFFFFFFD0,r14; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	400000000003F290; }

l400000000003F1B0:
	{ nop.m	0x0; zxt1	r14,r15; sxt4	r15,r15; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x9,r14; shladd	r8,r8,0x1,r15 }
	{ nop.b	0x0; (p06) br.cond.dpnt.few	400000000003F290; br.cloop.sptk.few	400000000003F200; }

l400000000003F1DC:
	{ (p01) cmp.lt	p00,p02,r0,r32; czx1.r	r32,r97; br.cond	b0 }

l400000000003F1E0:
	{ cmp4.eq	p06,p07,0x0,r17; nop.i	0x0; (p07) sub	r8,r0,r8 }

l400000000003F1F0:
	{ nop.m	0x0; mov.i	LC,r2; br.ret	b0 }

l400000000003F200:
	{ ld1	r14,[r16],1; nop.m	0x0; sxt1	r14,r14; }
	{ adds	r15,0xFFFFFFFFFFFFFFD0,r14; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	400000000003F1E0; }

l400000000003F220:
	{ nop.m	0x0; zxt1	r14,r15; sxt4	r15,r15; }
	{ cmp4.ltu	p07,p06,0x9,r14; nop.i	0x0; (p07) br.cond.dpnt.few	400000000003F1E0; }

l400000000003F240:
	{ nop.m	0x0; shladd	r8,r8,0x2,r8; nop.i	0x0; }
	{ nop.m	0x0; shladd	r8,r8,0x1,r15; br.cloop.sptk.few	400000000003F200 }

l400000000003F260:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000003F1E0 }

l400000000003F270:
	{ cmp.eq	p08,p09,0x0,r32; nop.m	0x0; nop.i	0x0 }

l400000000003F280:
	{ nop.m	0x0; adds	r17,0x0,r0; br.cond.sptk.few	400000000003F170; }

l400000000003F290:
	{ adds	r8,0x0,r0; nop.m	0x0; cmp4.eq	p06,p07,0x0,r17; }
	{ nop.m	0x0; (p07) sub	r8,r0,r8; br.cond.sptk.few	400000000003F1F0; }

l400000000003F2AC:
	{ (p58) nop; break.i	0x1000; break.b	0x1000 }
400000000003F2B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; print_rlimtype: 400000000003F2C0
;;   Called from:
;;     400000000010FDBC (in fn400000000010FC40)
print_rlimtype proc
	{ alloc	r35,ar.pfs,0x9,0x0,0x5; adds	r12,0xFFFFFFFFFFFFFFE0,r12; mov	r34,b2 }
	{ nop.m	0x0; adds	r36,0x0,r1; nop.i	0x0; }
	{ nop.m	0x0; movl	r14,0x800CCCCCCCCCCCCD }
	{ adds	r15,0x23,r12; setf.sig	f6,r14; adds	r14,0x24,r12 }
	{ nop.m	0x0; st1	[r0],r14; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000003F320:
	{ setf.sig	f7,r32; nop.m	0x0; adds	r39,0x0,r15; }
	{ nop.m	0x0; nop.m	0x0; xma.hu	f7,f7,f6,f0; }
	{ nop.m	0x0; getf.sig	r14,f7; nop.i	0x0; }
	{ nop.m	0x0; extr	r14,r14,3,61; shladd	r16,r14,0x2,r14; }
	{ shladd	r16,r16,0x1,r0; sub	r16,r32,r16; adds	r32,0x0,r14; }
	{ adds	r14,0x30,r16; nop.m	0x0; cmp.eq	p07,p06,0x0,r32; }
	{ st1	[r15],r127,-1; nop.i	0x0; (p06) br.cond.dptk.few	400000000003F320 }

l400000000003F390:
	{ cmp4.eq	p06,p07,0x0,r33; addl	r38,-5628,r1; addl	r37,1,r0; }
	{ (p07) addl	r40,-5644,r1; ld8	r38,[r38]; nop.i	0x0; }

l400000000003F3A6:
	{ (p19) fwb; addl	r0,49152,r1; (p01) cmp4.eq.or.andcm	p10,p52,0x3F,r127 }

l400000000003F3B6:
	{ (p20) fwb; nop; (p01) nop; }

l400000000003F3BC:
	{ Invalid; Invalid; break.i	0x1000 }

l400000000003F3C6:
	{ break.m	0x4000; Invalid; (p16) nop }
	{ break.m	0xAA023; nop; break.i	0x80000 }
	{ Invalid; (p34) nop; break.i	0x80000 }
400000000003F3F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; all_digits: 400000000003F400
;;   Called from:
;;     4000000000062A9C (in sv_ignoreeof)
;;     40000000000DE73C (in fn40000000000DE580)
;;     40000000000EFC6C (in get_job_spec)
;;     400000000010E41C (in trap_builtin)
;;     4000000000110CFC (in ulimit_builtin)
all_digits proc
	{ ld1	r14,[r32]; adds	r32,0x1,r32; sxt1	r14,r14; }
	{ adds	r15,0xFFFFFFFFFFFFFFD0,r14; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	400000000003F460; }

l400000000003F420:
	{ nop.m	0x0; zxt1	r15,r15; nop.i	0x0; }
	{ cmp4.ltu	p06,p07,0x9,r15; nop.i	0x0; (p06) br.cond.dpnt.few	400000000003F470; }

l400000000003F440:
	{ ld1	r14,[r32],1; nop.m	0x0; sxt1	r14,r14; }
	{ adds	r15,0xFFFFFFFFFFFFFFD0,r14; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	400000000003F420 }

l400000000003F460:
	{ nop.m	0x0; addl	r8,1,r0; br.ret	b0; }

l400000000003F470:
	{ nop.m	0x0; adds	r8,0x0,r0; br.ret	b0; }

;; legal_number: 400000000003F480
;;   Called from:
;;     400000000003236C (in fn4000000000030880)
;;     400000000004116C (in trim_pathname)
;;     4000000000062D5C (in sv_funcnest)
;;     40000000000639CC (in sv_histsize)
;;     40000000000692BC (in adjust_shell_level)
;;     400000000006AD0C (in pop_args)
;;     400000000006CADC (in initialize_shell_variables)
;;     40000000000AB2DC (in time_to_check_mail)
;;     40000000000AD4BC (in decode_signal)
;;     40000000000B593C (in binary_test)
;;     40000000000B596C (in binary_test)
;;     40000000000B756C (in fn40000000000B7400)
;;     40000000000C59CC (in brace_expand)
;;     40000000000DF4DC (in fn40000000000DE580)
;;     40000000000EAFEC (in caller_builtin)
;;     40000000000EED8C (in get_numeric_arg)
;;     40000000000EF02C (in get_exitstat)
;;     40000000000EFE4C (in display_signal_list)
;;     40000000000F94BC (in fc_builtin)
;;     40000000000FE4FC (in history_builtin)
;;     40000000000FF9BC (in disown_builtin)
;;     40000000001002BC (in kill_builtin)
;;     4000000000101DEC (in dirs_builtin)
;;     40000000001020CC (in dirs_builtin)
;;     4000000000102B4C (in popd_builtin)
;;     4000000000102BFC (in popd_builtin)
;;     40000000001032BC (in pushd_builtin)
;;     4000000000103B3C (in pushd_builtin)
;;     4000000000103C0C (in get_dirstack_from_string)
;;     400000000011201C (in wait_builtin)
;;     400000000011AB9C (in internal_getopt)
legal_number proc
	{ alloc	r36,ar.pfs,0xB,0x0,0x7; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r38,pr }
	{ cmp.eq	p16,p17,0x0,r33; adds	r37,0x0,r1; mov	r35,b3 }
	{ (p17) st8	[r0],r33; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B840; }

l400000000003F4A6:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ Invalid; (p19) nop; nop }
	{ Invalid; (p20) nop; (p32) nop }
	{ break.m	0x4000; (p32) nop; (p32) nop }
	{ Invalid; nop; nop }
	{ chk.a.nc	f0,3FFFFFFFFF03FCF6; nop; break.i	0x80000 }

l400000000003F500:
	{ nop.m	0x0; ld8	r14,[r15]; nop.i	0x0; }
	{ cmp.eq	p06,p07,r32,r14; adds	r15,0x1,r14; (p06) br.cond.dpnt.few	400000000003F600; }

l400000000003F520:
	{ nop.m	0x0; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p07,p06,0x20,r14; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p07,p06,0x9,r14; (p06) br.cond.dpnt.few	400000000003F5A0; }

l400000000003F550:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000003F560:
	{ adds	r14,0x10,r12; st8	[r15],r14; nop.i	0x0; }
	{ nop.m	0x0; ld1	r14,[r15],1; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x20,r14; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p06,p07,0x9,r14; (p06) br.cond.dptk.few	400000000003F560; }

l400000000003F5A0:
	{ cmp.eq	p06,p07,0x0,r32; cmp4.eq	p09,p08,0x0,r14; (p06) br.cond.dpnt.few	400000000003F600; }

l400000000003F5B0:
	{ ld1	r15,[r32]; nop.m	0x0; sxt1	r15,r15; }
	{ cmp4.eq	p06,p07,0x0,r15; (p06) br.cond.dpnt.few	400000000003F600; (p08) br.cond.dpnt.few	400000000003F600; }

l400000000003F5CC:
	{ (p02) nop; Invalid; (p17) cmp.eq	p00,p18,r0,r0 }

l400000000003F5D0:
	{ (p17) st8	[r8],r33; addl	r8,1,r0; mov	pr,r38,0xFFFFFFFFFFFFFFFE; }

l400000000003F5D6:
	{ Invalid; Invalid; break.i	0x80000 }
	{ break.m	0xAA024; nop; break.i	0x80000 }
	{ Invalid; Invalid; nop }

l400000000003F600:
	{ adds	r8,0x0,r0; mov	pr,r38,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,400000000003F610; nop.i	0x0 }
	{ adds	r12,0x10,r12; nop.m	0x0; br.ret	b0; }
400000000003F630 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; legal_identifier: 400000000003F640
;;   Called from:
;;     40000000000347EC (in fn4000000000030880)
;;     400000000003F90C (in check_identifier)
;;     400000000006BF3C (in initialize_shell_variables)
;;     40000000000BFD1C (in valid_array_reference)
;;     40000000000F0F9C (in fn40000000000F0900)
;;     4000000000100DFC (in mapfile_builtin)
;;     400000000010191C (in mapfile_builtin)
;;     400000000010541C (in read_builtin)
;;     40000000001075BC (in read_builtin)
;;     400000000010777C (in read_builtin)
;;     400000000010A6EC (in unset_builtin)
;;     400000000010AA7C (in unset_builtin)
;;     400000000010C10C (in set_or_show_attributes)
;;     400000000010C1FC (in set_or_show_attributes)
;;     40000000001124AC (in fn4000000000112480)
;;     4000000000116AEC (in printf_builtin)
legal_identifier proc
	{ alloc	r35,ar.pfs,0x5,0x0,0x5; mov	r34,b2; nop.i	0x0 }
	{ cmp.eq	p06,p07,0x0,r32; adds	r36,0x0,r1; (p06) br.cond.dpnt.few	400000000003F740; }

l400000000003F660:
	{ nop.m	0x0; ld1	r33,[r32]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r33; nop.i	0x0; (p06) br.cond.dpnt.few	400000000003F740; }

l400000000003F680:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C3C0; }
	{ nop.m	0x0; ld8	r16,[r8]; zxt1	r14,r33 }
	{ adds	r15,0x1,r32; adds	r1,0x0,r36; adds	r32,0x2,r32; }
	{ shladd	r14,r14,0x1,r16; nop.m	0x0; cmp4.eq	p08,p09,0x5F,r33; }
	{ nop.m	0x0; ld2	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r14,0xA; (p07) br.cond.dptk.few	400000000003F7B0 }

l400000000003F6E0:
	{ nop.m	0x0; ld1	r14,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	400000000003F790; }

l400000000003F700:
	{ nop.m	0x0; zxt1	r15,r14; cmp4.eq	p08,p09,0x5F,r14; }
	{ shladd	r15,r15,0x1,r16; ld2	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r15,0x3; (p06) br.cond.dptk.few	400000000003F770 }

l400000000003F730:
	{ nop.m	0x0; nop.i	0x0; (p08) br.cond.dpnt.few	400000000003F770 }

l400000000003F740:
	{ adds	r8,0x0,r0; nop.m	0x0; nop.i	0x0 }

l400000000003F750:
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r34,400000000003F760; br.ret	b0 }

l400000000003F770:
	{ nop.m	0x0; ld1	r14,[r32],1; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	400000000003F700 }

l400000000003F790:
	{ addl	r8,1,r0; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,400000000003F7A0; br.ret	b0 }

l400000000003F7B0:
	{ adds	r8,0x0,r0; (p08) br.cond.dpnt.few	400000000003F6E0; br.cond.sptk.few	400000000003F750; }

l400000000003F7BC:
	{ (p61) ldf8	f127,[r36]; (p04) cmp.lt	p34,p02,r1,r96; (p01) dep	r2,r8,r64,62,1 }

;; check_identifier: 400000000003F7C0
check_identifier proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x5; adds	r14,0x8,r32; mov	r34,b2 }
	{ adds	r36,0x0,r1; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; and	r14,0x3,r14; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000003F880; }

l400000000003F800:
	{ ld8	r37,[r32]; adds	r15,0x1,r37; nop.i	0x0; }
	{ ld1	r14,[r37]; nop.m	0x0; sxt1	r14,r14; }
	{ adds	r16,0xFFFFFFFFFFFFFFD0,r14; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	400000000003F880; }

l400000000003F830:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000003F840:
	{ nop.m	0x0; zxt1	r16,r16; nop.i	0x0; }
	{ cmp4.ltu	p06,p07,0x9,r16; nop.i	0x0; (p06) br.cond.dpnt.few	400000000003F8F0; }

l400000000003F860:
	{ ld1	r14,[r15],1; nop.m	0x0; sxt1	r14,r14; }
	{ adds	r16,0xFFFFFFFFFFFFFFD0,r14; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	400000000003F840 }

l400000000003F880:
	{ addl	r38,-5620,r1; addl	r39,5,r0; adds	r37,0x0,r0; }
	{ ld8	r38,[r38]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r36; nop.m	0x0; adds	r37,0x0,r8 }
	{ ld8	r38,[r32]; nop.m	0x0; br.call.sptk.many	b0,internal_error; }
	{ nop.m	0x0; adds	r1,0x0,r36; adds	r8,0x0,r0 }

l400000000003F8D0:
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r34,400000000003F8E0; br.ret	b0 }

l400000000003F8F0:
	{ addl	r8,1,r0; cmp4.eq	p07,p06,0x0,r33; (p07) br.cond.dptk.few	400000000003F8D0; }

l400000000003F900:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,legal_identifier; }
	{ cmp4.eq	p07,p06,0x0,r8; adds	r1,0x0,r36; mov.i	ar.pfs,r35 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	400000000003F880; }

l400000000003F930:
	{ (p06) addl	r8,1,r0; mov.spnt	b0,r34,400000000003F930; br.ret	b0; }

l400000000003F936:
	{ Invalid; (p34) nop; (p32) nop }

;; legal_alias_name: 400000000003F940
;;   Called from:
;;     40000000000E952C (in alias_builtin)
legal_alias_name proc
	{ ld1	r14,[r32]; addl	r16,-18556,r1; adds	r32,0x1,r32; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; zxt1	r15,r14; (p06) br.cond.dpnt.few	400000000003FA90; }

l400000000003F970:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ shladd	r15,r15,0x2,r16; ld4	r17,[r15]; addl	r15,1026,r0; }
	{ and	r15,r15,r17; nop.m	0x0; addl	r17,1026,r0; }
	{ cmp4.eq	p07,p06,0x0,r15; nop.i	0x0; (p06) br.cond.dpnt.few	400000000003FA80; }

l400000000003F9B0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x24,r14; nop.i	0x0; }
	{ cmp4.eq.or.andcm	p06,p07,0x3C,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000003FA80; }

l400000000003F9D0:
	{ cmp4.eq	p06,p07,0x3E,r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000003FA80; }

l400000000003F9E0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x2F,r14; (p06) br.cond.dpnt.few	400000000003FA80; }

l400000000003F9F0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000003FA00:
	{ ld1	r14,[r32],1; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; zxt1	r15,r14; cmp4.eq	p09,p08,0x0,r14 }
	{ cmp4.eq	p06,p07,0x24,r14; cmp4.eq	p10,p11,0x3E,r14; (p09) br.cond.dpnt.few	400000000003FA90; }

l400000000003FA30:
	{ shladd	r15,r15,0x2,r16; cmp4.eq.or.andcm	p06,p07,0x3C,r14; cmp4.eq	p12,p13,0x2F,r14; }
	{ nop.m	0x0; ld4	r15,[r15]; nop.i	0x0; }
	{ and	r15,r17,r15; nop.i	0x0; cmp4.eq	p09,p08,0x0,r15 }
	{ (p08) br.cond.dpnt.few	400000000003FA80; (p06) br.cond.dpnt.few	400000000003FA80; (p10) br.cond.dpnt.few	400000000003FA80; }

l400000000003FA66:
	{ nop; nop; break.i	0x80000; }

l400000000003FA6C:
	{ (p01) invala; break.i	0x1000; Invalid }

l400000000003FA70:
	{ nop.m	0x0; nop.i	0x0; (p13) br.cond.dptk.few	400000000003FA00 }

l400000000003FA80:
	{ nop.m	0x0; adds	r8,0x0,r0; br.ret	b0; }

l400000000003FA90:
	{ nop.m	0x0; addl	r8,1,r0; br.ret	b0; }
400000000003FAA0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000003FAB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; assignment: 400000000003FAC0
;;   Called from:
;;     4000000000032A4C (in fn4000000000030880)
;;     4000000000032A4C (in fn4000000000030880)
;;     4000000000065F6C (in add_or_supercede_exported_var)
;;     400000000006E12C (in assign_in_env)
;;     400000000009915C (in fn4000000000099100)
;;     40000000000A7D4C (in fn40000000000A7940)
;;     40000000000A848C (in fn40000000000A7940)
;;     40000000000F0EAC (in fn40000000000F0900)
;;     400000000010C0EC (in set_or_show_attributes)
;;     400000000012940C (in putenv)
assignment proc
	{ alloc	r36,ar.pfs,0x9,0x0,0x6; adds	r37,0x0,r1; nop.b	0x0 }
	{ ld1	r34,[r32]; nop.m	0x0; mov	r35,b3; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C3C0; }
	{ nop.m	0x0; zxt1	r14,r34; nop.i	0x0 }
	{ ld8	r17,[r8]; adds	r1,0x0,r37; shladd	r14,r14,0x1,r17; }
	{ nop.m	0x0; ld2	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r14,0xA; (p06) br.cond.dptk.few	400000000003FB60; }

l400000000003FB30:
	{ cmp4.eq	p06,p07,0x5F,r34; nop.i	0x0; (p06) br.cond.dpnt.few	400000000003FB90; }

l400000000003FB40:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r33; nop.i	0x0; }
	{ nop.m	0x0; cmp4.ne.or.andcm	p06,p07,0x5B,r34; (p06) br.cond.dpnt.few	400000000003FC00; }

l400000000003FB60:
	{ cmp4.eq	p07,p06,0x0,r34; nop.i	0x0; (p07) br.cond.dpnt.few	400000000003FC00; }

l400000000003FB70:
	{ cmp4.eq	p06,p07,0x3D,r34; nop.i	0x0; (p06) br.cond.dpnt.few	400000000003FC00; }

l400000000003FB80:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x5B,r34; (p06) br.cond.dpnt.few	400000000003FDA0 }

l400000000003FB90:
	{ nop.m	0x0; adds	r16,0x1,r32; addl	r14,1,r0 }
	{ nop.m	0x0; adds	r18,0x0,r0; adds	r19,0x56,r17; }

l400000000003FBB0:
	{ nop.m	0x0; zxt1	r15,r34; nop.i	0x0 }
	{ cmp4.eq	p07,p06,0x2B,r34; cmp4.eq	p08,p09,0x5F,r34; (p07) br.cond.dpnt.few	400000000003FC30; }

l400000000003FBD0:
	{ shladd	r15,r15,0x1,r17; ld2	r15,[r15]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r15,0x3; (p06) br.cond.dptk.few	400000000003FC80 }

l400000000003FBF0:
	{ nop.m	0x0; nop.i	0x0; (p08) br.cond.dpnt.few	400000000003FC80 }

l400000000003FC00:
	{ adds	r8,0x0,r0; nop.m	0x0; nop.i	0x0 }

l400000000003FC10:
	{ nop.m	0x0; mov.i	ar.pfs,r36; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r35,400000000003FC20; br.ret	b0 }

l400000000003FC30:
	{ add	r18,r32,r18,0x1; ld1	r15,[r18]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x3D,r15; nop.i	0x0; (p07) br.cond.dpnt.few	400000000003FDB0; }

l400000000003FC60:
	{ nop.m	0x0; ld2	r15,[r19]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r15,0x3; (p07) br.cond.dptk.few	400000000003FC00; }

l400000000003FC80:
	{ ld1	r34,[r16],1; nop.m	0x0; adds	r15,0x1,r14 }
	{ adds	r8,0x0,r14; nop.m	0x0; adds	r18,0x0,r14; }
	{ cmp4.eq	p07,p06,0x0,r34; adds	r14,0x0,r15; (p07) br.cond.dpnt.few	400000000003FC00; }

l400000000003FCB0:
	{ cmp4.eq	p06,p07,0x3D,r34; nop.i	0x0; (p06) br.cond.dpnt.few	400000000003FC10; }

l400000000003FCC0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x5B,r34; (p06) br.cond.dptk.few	400000000003FBB0 }

l400000000003FCD0:
	{ adds	r39,0x0,r8; nop.m	0x0; adds	r38,0x0,r32 }
	{ adds	r40,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,skipsubscript; }
	{ nop.m	0x0; sxt4	r14,r8; adds	r1,0x0,r37; }
	{ nop.m	0x0; add	r14,r32,r14; nop.i	0x0; }
	{ ld1	r14,[r14]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x5D,r14; (p07) br.cond.dptk.few	400000000003FC00 }

l400000000003FD30:
	{ adds	r15,0x1,r8; nop.m	0x0; sxt4	r14,r15; }
	{ add	r32,r32,r14; ld1	r14,[r32]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x2B,r14; nop.i	0x0; (p07) br.cond.dpnt.few	400000000003FDD0; }

l400000000003FD70:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x3D,r14; (p07) br.cond.dptk.few	400000000003FC00 }

l400000000003FD80:
	{ adds	r8,0x0,r15; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,400000000003FD90; br.ret	b0 }

l400000000003FDA0:
	{ nop.m	0x0; adds	r8,0x0,r0; br.cond.sptk.few	400000000003FCD0; }

l400000000003FDB0:
	{ adds	r8,0x0,r14; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,400000000003FDC0; br.ret	b0 }

l400000000003FDD0:
	{ adds	r32,0x1,r32; ld1	r14,[r32]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p07,p06,0x3D,r14; }
	{ (p07) adds	r8,0x2,r8; nop.i	0x0; (p07) br.cond.dpnt.few	400000000003FC10; }

l400000000003FDF6:
	{ chk.a.nc	f0,3FFFFFFFFF0405F6; nop; break.i	0x80000 }

l400000000003FE00:
	{ nop.m	0x0; adds	r8,0x0,r0; br.cond.sptk.few	400000000003FC10; }
400000000003FE10 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000003FE20 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000003FE30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; sh_unset_nodelay_mode: 400000000003FE40
;;   Called from:
;;     400000000001F65C (in main)
;;     400000000001F99C (in main)
;;     40000000000B047C (in getc_with_restart)
sh_unset_nodelay_mode proc
	{ alloc	r34,ar.pfs,0x7,0x0,0x4; nop.m	0x0; mov	r33,b1 }
	{ adds	r35,0x0,r1; nop.m	0x0; adds	r36,0x0,r32; }
	{ addl	r37,3,r0; adds	r38,0x0,r0; br.call.sptk.many	b0,fn400000000001B7E0; }
	{ adds	r14,0x0,r8; adds	r1,0x0,r35; nop.b	0x0 }
	{ adds	r8,0x0,r0; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ cmp4.lt	p06,p07,r14,r0; mov.spnt	b0,r33,400000000003FE90; (p06) br.cond.dpnt.few	400000000003FF00; }

l400000000003FEA0:
	{ nop.m	0x0; tbit.z	p06,p07,r14,0xB; nop.i	0x0 }
	{ nop.b	0x0; (p07) br.cond.dpnt.few	400000000003FEC0; br.ret	b0 }

l400000000003FEBC:
	{ cmp.lt	p00,p09,r33,r0; (p52) shladd	r31,r127,0x4,r123; (p04) nop }

l400000000003FEC0:
	{ addl	r38,-2049,r0; adds	r36,0x0,r32; addl	r37,4,r0; }
	{ and	r38,r38,r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B7E0; }
	{ adds	r1,0x0,r35; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,400000000003FEF0; br.ret	b0 }

l400000000003FF00:
	{ addl	r8,-1,r0; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,400000000003FF10; br.ret	b0; }
400000000003FF20 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000003FF30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; sh_validfd: 400000000003FF40
;;   Called from:
;;     40000000000478AC (in xtrace_set)
;;     40000000000627AC (in sv_xtracefd)
sh_validfd proc
	{ alloc	r34,ar.pfs,0x7,0x0,0x4; nop.m	0x0; mov	r33,b1 }
	{ adds	r35,0x0,r1; nop.m	0x0; adds	r36,0x0,r32; }
	{ addl	r37,1,r0; adds	r38,0x0,r0; br.call.sptk.many	b0,fn400000000001B7E0; }
	{ andcm	r8,0xFFFFFFFFFFFFFFFF,r8; adds	r1,0x0,r35; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; extr.u	r8,r8,31,1; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r33,400000000003FF90; br.ret	b0; }
400000000003FFA0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000003FFB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fd_ispipe: 400000000003FFC0
fd_ispipe proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x5; mov	r34,b2; adds	r36,0x0,r1; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B840; }
	{ adds	r1,0x0,r36; adds	r33,0x0,r8; adds	r37,0x0,r32 }
	{ adds	r38,0x0,r0; st4	[r0],r8; addl	r39,1,r0; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AA20; }
	{ adds	r14,0x0,r0; cmp.lt	p07,p06,r8,r0; nop.b	0x0 }
	{ adds	r1,0x0,r36; mov.i	ar.pfs,r35; (p07) br.cond.dpnt.few	4000000000040040; }

l4000000000040030:
	{ adds	r8,0x0,r14; mov.spnt	b0,r34,4000000000040030; br.ret	b0 }

l4000000000040040:
	{ ld4	r14,[r33]; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ cmp4.eq	p06,p07,0x1D,r14; mov.spnt	b0,r34,4000000000040050; (p06) addl	r14,1,r0; }

l4000000000040060:
	{ nop.m	0x0; (p07) adds	r14,0x0,r0; nop.i	0x0; }

l400000000004006C:
	{ Invalid; break.i	0x1000; (p01) shladd	r64,r3,0x1,r64 }
	{ nop; (p20) ldfe.nt1	f97,[r96]; Invalid }

;; check_dev_tty: 4000000000040080
;;   Called from:
;;     400000000001C9FC (in main)
check_dev_tty proc
	{ alloc	r33,ar.pfs,0x5,0x0,0x3; addl	r35,-5612,r1; nop.b	0x0 }
	{ adds	r34,0x0,r1; mov	r32,b0; addl	r36,2050,r0 }
	{ ld8	r35,[r35]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B4E0; }
	{ cmp4.lt	p07,p06,r8,r0; nop.m	0x0; adds	r1,0x0,r34 }
	{ adds	r35,0x0,r8; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000040110; }

l40000000000400D0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C340; }
	{ adds	r1,0x0,r34; nop.m	0x0; nop.i	0x0 }

l40000000000400F0:
	{ nop.m	0x0; mov.i	ar.pfs,r33; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r32,4000000000040100; br.ret	b0 }

l4000000000040110:
	{ addl	r14,-10356,r1; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r35,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BBC0; }
	{ adds	r1,0x0,r34; adds	r35,0x0,r8; br.call.sptk.many	b0,fn400000000001B600; }
	{ cmp.eq	p06,p07,0x0,r8; adds	r1,0x0,r34; nop.i	0x0 }
	{ addl	r36,2050,r0; adds	r35,0x0,r8; (p06) br.cond.dpnt.few	40000000000400F0; }

l4000000000040160:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B4E0; }
	{ adds	r1,0x0,r34; adds	r35,0x0,r8; br.call.sptk.many	b0,fn400000000001C340; }
	{ nop.m	0x0; adds	r1,0x0,r34; br.cond.sptk.few	40000000000400F0; }
4000000000040190 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000401A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000401B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; same_file: 40000000000401C0
;;   Called from:
;;     4000000000068CDC (in set_pwd)
;;     4000000000068E8C (in set_pwd)
;;     40000000000A9ABC (in phash_search)
;;     40000000000B581C (in fn40000000000B5690)
;;     40000000000DCA0C (in fn40000000000DC640)
;;     40000000000ECA0C (in pwd_builtin)
same_file proc
	{ alloc	r37,ar.pfs,0xA,0x0,0x7; adds	r12,0xFFFFFFFFFFFFFEE0,r12; nop.b	0x0 }
	{ cmp.eq	p07,p06,0x0,r34; mov	r36,b4; adds	r38,0x0,r1; }
	{ nop.m	0x0; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000040290; }

l40000000000401F0:
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r35; (p07) br.cond.dpnt.few	40000000000402E0 }

l4000000000040200:
	{ ld8	r15,[r34]; ld8	r14,[r35]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r14,r15; (p07) br.cond.dpnt.few	4000000000040240 }

l4000000000040220:
	{ adds	r8,0x0,r0; mov.i	ar.pfs,r37; mov.spnt	b0,r36,4000000000040220 }
	{ nop.m	0x0; adds	r12,0x120,r12; br.ret	b0 }

l4000000000040240:
	{ adds	r34,0x8,r34; nop.m	0x0; adds	r35,0x8,r35; }
	{ ld8	r8,[r34]; ld8	r14,[r35]; nop.i	0x0; }
	{ cmp.eq	p06,p07,r14,r8; (p06) addl	r8,1,r0; nop.i	0x0; }

l400000000004026C:
	{ Invalid; zxt1	r0,r64; (p16) break.i	0x2A809 }

l4000000000040276:
	{ break.m	0xAA025; nop; break.i	0x80000 }
	{ Invalid; (p34) nop; (p48) nop }

l4000000000040290:
	{ addl	r39,1,r0; nop.m	0x0; adds	r40,0x0,r32 }
	{ adds	r41,0xA0,r12; nop.m	0x0; br.call.sptk.many	b0,fn400000000001AFE0; }
	{ cmp4.eq	p06,p07,0x0,r8; adds	r1,0x0,r38; (p07) br.cond.dpnt.few	4000000000040220; }

l40000000000402C0:
	{ (p06) adds	r34,0xA0,r12; cmp.eq	p07,p06,0x0,r35; (p06) br.cond.dptk.few	4000000000040200; }

l40000000000402C6:
	{ (p03) chk.a.clr	r0,3FFFFFFFFFCC34F6; nop; break.b	0x80000 }

l40000000000402D0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000402E0:
	{ addl	r39,1,r0; adds	r40,0x0,r33; nop.i	0x0 }
	{ adds	r41,0x10,r12; adds	r35,0x10,r12; br.call.sptk.many	b0,fn400000000001AFE0; }
	{ adds	r1,0x0,r38; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dpnt.few	4000000000040220; }

l4000000000040310:
	{ ld8	r15,[r34]; ld8	r14,[r35]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,r14,r15; (p06) br.cond.dptk.few	4000000000040220 }

l4000000000040330:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000040240; }

;; move_to_high_fd: 4000000000040340
;;   Called from:
;;     400000000001FF7C (in main)
;;     4000000000020D2C (in main)
;;     400000000004071C (in sh_openpipe)
;;     400000000004074C (in sh_openpipe)
;;     400000000007F4FC (in initialize_job_control)
;;     400000000007FB0C (in initialize_job_control)
;;     40000000000A281C (in fn40000000000A1400)
move_to_high_fd proc
	{ alloc	r37,ar.pfs,0xC,0x0,0x9; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r39,pr }
	{ cmp4.lt	p07,p06,0x13,r34; nop.m	0x0; adds	r38,0x0,r1; }
	{ addl	r14,1,r0; (p07) adds	r34,0xFFFFFFFFFFFFFFFF,r34; mov	r40,LC; }

l400000000004036C:
	{ invala; break.x	0x8000031000; }
	{ (p13) nop; czx1.r	r32,r100; (p02) cmp.lt.unc	p31,p17,r104,r79 }

l4000000000040380:
	{ cmp4.eq	p17,p16,0x0,r33; adds	r16,0xFFFFFFFFFFFFFFFC,r34; zxt1	r14,r14 }
	{ adds	r17,0xFFFFFFFFFFFFFFFF,r34; addp4	r16,r16,r0; (p16) addl	r15,1,r0 }

l40000000000403A0:
	{ cmp4.lt	p09,p08,0x2,r17; (p17) adds	r15,0x0,r0; mov.i	LC,r16; }

l40000000000403AC:
	{ (p08) cmp.eq.unc	p01,p09,r42,r0; zxt1	r67,r3; Invalid }
	{ (p08) cmp.lt.unc	p01,p17,r42,r0; Invalid; mov	pr,r80,0x40 }

l40000000000403C0:
	{ cmp4.eq	p06,p07,0x0,r15; (p08) mov.i	LC,0x0; (p06) br.cond.dpnt.few	4000000000040470; }

l40000000000403CC:
	{ (p05) nop; break.i	0x1000; break.b	0x1000 }

l40000000000403D0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000403E0:
	{ adds	r41,0x0,r34; nop.m	0x0; addl	r42,1,r0 }
	{ adds	r43,0x10,r12; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B7E0; }
	{ adds	r1,0x0,r38; cmp4.eq	p06,p07,0xFFFFFFFFFFFFFFFF,r8; (p06) br.cond.dpnt.few	4000000000040460; }

l4000000000040410:
	{ nop.m	0x0; adds	r34,0xFFFFFFFFFFFFFFFF,r34; br.cloop.sptk.few	40000000000403E0 }

l4000000000040420:
	{ adds	r35,0x0,r32; nop.m	0x0; nop.i	0x0; }

l4000000000040430:
	{ adds	r8,0x0,r35; mov	pr,r39,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; mov.i	LC,r40; mov.spnt	b0,r36,4000000000040440 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l4000000000040460:
	{ addl	r14,1,r0; nop.m	0x0; nop.i	0x0 }

l4000000000040470:
	{ cmp4.eq	p07,p06,r34,r32; adds	r41,0x0,r32; adds	r42,0x0,r34; }
	{ nop.m	0x0; tbit.z.or.andcm	p07,p06,r14,0x0; (p07) br.cond.dpnt.few	4000000000040420; }

l4000000000040490:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AE60; }
	{ adds	r1,0x0,r38; adds	r35,0x0,r8; cmp4.eq	p06,p07,0xFFFFFFFFFFFFFFFF,r8 }
	{ nop.b	0x0; (p06) br.cond.dpnt.few	4000000000040420; (p16) br.cond.dptk.few	4000000000040590 }

l40000000000404BC:
	{ Invalid; nop; zxt1	r0,r64 }

l40000000000404C0:
	{ nop.m	0x0; adds	r41,0x0,r32; br.call.sptk.many	b0,fn400000000001C340; }
	{ adds	r1,0x0,r38; nop.m	0x0; nop.i	0x0 }

l40000000000404E0:
	{ adds	r8,0x0,r35; mov	pr,r39,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; mov.i	LC,r40; mov.spnt	b0,r36,40000000000404F0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

l4000000000040510:
	{ addl	r34,255,r0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B420; }
	{ addl	r14,1,r0; cmp4.lt	p07,p06,0x0,r8; adds	r1,0x0,r38; }
	{ (p06) addl	r14,1,r0; (p06) addl	r34,19,r0; (p06) br.cond.dpnt.few	4000000000040380; }

l4000000000040536:
	{ (p17) chk.a.clr	r19,3FFFFFFFFF240536; nop; break.i	0x80000; }

l400000000004053C:
	{ (p50) nop; cmp.eq	p00,p00,r32,r0; (p01) nop }

l4000000000040540:
	{ nop.m	0x0; addl	r15,256,r0; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r15,r8; (p06) br.cond.dptk.few	4000000000040380 }

l4000000000040560:
	{ adds	r34,0xFFFFFFFFFFFFFFFF,r8; cmp4.lt	p06,p07,0x3,r34; nop.i	0x0; }
	{ nop.m	0x0; (p06) addl	r14,1,r0; nop.i	0x0; }

l400000000004057C:
	{ Invalid; cmp4.eq.and	p00,p32,r32,r0; zxt1	r0,r64 }

l400000000004058C:
	{ (p48) cmp.lt.unc	p63,p11,r63,r36; (p01) cmp.lt	p57,p19,r31,r107; Invalid }

l4000000000040590:
	{ addl	r14,-10652,r1; ld8	r14,[r14]; nop.i	0x0; }
	{ ld8	r41,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BBC0; }
	{ cmp4.eq	p07,p06,r32,r8; nop.m	0x0; adds	r1,0x0,r38 }
	{ adds	r41,0x0,r32; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000040430; }

l40000000000405D0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C340; }
	{ nop.m	0x0; adds	r1,0x0,r38; br.cond.sptk.few	40000000000404E0; }
40000000000405F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; check_binary_file: 4000000000040600
;;   Called from:
;;     400000000001FEFC (in main)
;;     400000000005051C (in shell_execve)
;;     40000000000F58EC (in fn40000000000F4180)
check_binary_file proc
	{ nop.m	0x0; mov	r2,LC; nop.i	0x0 }
	{ cmp4.lt	p07,p06,0x0,r33; adds	r15,0xFFFFFFFFFFFFFFFF,r33; (p06) br.cond.dpnt.few	4000000000040670; }

l4000000000040620:
	{ ld1	r14,[r32]; addp4	r15,r15,r0; adds	r32,0x1,r32; }
	{ cmp4.eq	p06,p07,0xA,r14; mov.i	LC,r15; (p06) br.cond.dpnt.few	4000000000040670; }

l4000000000040640:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	40000000000406B0; }

l4000000000040650:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000040660:
	{ nop.m	0x0; nop.i	0x0; br.cloop.sptk.few	4000000000040680; }

l4000000000040670:
	{ adds	r8,0x0,r0; mov.i	LC,r2; br.ret	b0 }

l4000000000040680:
	{ nop.m	0x0; ld1	r14,[r32],1; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0xA,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000040670; }

l40000000000406A0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	4000000000040660 }

l40000000000406B0:
	{ addl	r8,1,r0; mov.i	LC,r2; br.ret	b0; }

;; sh_openpipe: 40000000000406C0
sh_openpipe proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x5; mov	r34,b2; nop.b	0x0 }
	{ adds	r36,0x0,r1; adds	r33,0x0,r32; adds	r37,0x0,r32; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BB40; }
	{ adds	r14,0x0,r8; cmp4.lt	p06,p07,r8,r0; adds	r1,0x0,r36 }
	{ addl	r38,1,r0; addl	r39,64,r0; (p06) br.cond.dpnt.few	4000000000040770; }

l4000000000040710:
	{ ld4	r37,[r32]; nop.i	0x0; br.call.sptk.many	b0,move_to_high_fd; }
	{ st4	[r33],r4,4; nop.m	0x0; adds	r1,0x0,r36 }
	{ addl	r38,1,r0; nop.m	0x0; addl	r39,64,r0; }
	{ ld4	r37,[r33]; nop.i	0x0; br.call.sptk.many	b0,move_to_high_fd; }
	{ adds	r1,0x0,r36; nop.m	0x0; adds	r14,0x0,r0 }
	{ st4	[r8],r33; nop.m	0x0; nop.i	0x0; }

l4000000000040770:
	{ adds	r8,0x0,r14; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,4000000000040780; br.ret	b0; }
4000000000040790 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000407A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000407B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; sh_closepipe: 40000000000407C0
;;   Called from:
;;     400000000007B2A6 (in start_pipeline)
;;     4000000000082F8C (in make_child)
;;     4000000000082F8C (in make_child)
;;     400000000008315C (in make_child)
;;     40000000000834AC (in stop_pipeline)
;;     400000000008510C (in without_job_control)
;;     40000000000853AC (in close_pgrp_pipe)
sh_closepipe proc
	{ alloc	r35,ar.pfs,0x6,0x0,0x5; ld4	r37,[r32]; nop.b	0x0 }
	{ adds	r36,0x0,r1; mov	r34,b2; adds	r33,0x4,r32; }
	{ cmp4.lt	p06,p07,r37,r0; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000040810; }

l40000000000407F0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C340; }
	{ adds	r1,0x0,r36; nop.m	0x0; nop.i	0x0 }

l4000000000040810:
	{ nop.m	0x0; ld4	r37,[r33]; nop.i	0x0; }
	{ cmp4.lt	p06,p07,r37,r0; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000040850; }

l4000000000040830:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C340; }
	{ adds	r1,0x0,r36; nop.m	0x0; nop.i	0x0 }

l4000000000040850:
	{ addl	r14,-1,r0; adds	r8,0x0,r0; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; st4	[r14],r33; mov.spnt	b0,r34,4000000000040860 }
	{ nop.m	0x0; st4	[r14],r32; br.ret	b0; }

;; file_exists: 4000000000040880
;;   Called from:
;;     40000000000C7C4C (in load_history)
;;     40000000000C838C (in maybe_save_shell_history)
file_exists proc
	{ alloc	r34,ar.pfs,0x7,0x0,0x4; adds	r12,0xFFFFFFFFFFFFFF70,r12; mov	r33,b1 }
	{ adds	r35,0x0,r1; nop.m	0x0; adds	r37,0x0,r32; }
	{ addl	r36,1,r0; adds	r38,0x10,r12; br.call.sptk.many	b0,fn400000000001AFE0; }
	{ cmp4.eq	p06,p07,0x0,r8; adds	r1,0x0,r35; (p06) addl	r8,1,r0; }

l40000000000408C0:
	{ (p07) adds	r8,0x0,r0; mov.i	ar.pfs,r34; mov.spnt	b0,r33,40000000000408C0 }

l40000000000408C6:
	{ break.m	0xAA022; nop; break.i	0x80000 }
	{ Invalid; (p34) nop; break.i	0x80000 }
40000000000408E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000408F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; file_isdir: 4000000000040900
;;   Called from:
;;     40000000000409EC (in file_iswdir)
;;     400000000005026C (in shell_execve)
;;     40000000000CA64C (in fn40000000000CA600)
;;     40000000000F855C (in exec_builtin)
file_isdir proc
	{ alloc	r34,ar.pfs,0x7,0x0,0x4; adds	r12,0xFFFFFFFFFFFFFF70,r12; mov	r33,b1 }
	{ adds	r35,0x0,r1; nop.m	0x0; adds	r37,0x0,r32; }
	{ addl	r36,1,r0; adds	r38,0x10,r12; br.call.sptk.many	b0,fn400000000001AFE0; }
	{ nop.m	0x0; adds	r1,0x0,r35; adds	r14,0x0,r0 }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	4000000000040980; }

l4000000000040950:
	{ adds	r14,0x28,r12; ld4	r15,[r14]; addl	r14,61440,r0; }
	{ and	r14,r14,r15; addl	r15,16384,r0; cmp4.eq	p06,p07,r15,r14; }
	{ (p06) addl	r14,1,r0; nop.i	0x0; (p07) adds	r14,0x0,r0; }

l4000000000040976:
	{ chk.a.nc	f0,3FFFFFFFFF041176; Invalid; nop }

l4000000000040980:
	{ adds	r8,0x0,r14; mov.i	ar.pfs,r34; mov.spnt	b0,r33,4000000000040980 }
	{ nop.m	0x0; adds	r12,0x90,r12; br.ret	b0; }
40000000000409A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000409B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; file_iswdir: 40000000000409C0
;;   Called from:
;;     400000000012E2CC (in fn400000000012E200)
;;     400000000012E39C (in fn400000000012E200)
;;     400000000012E3FC (in fn400000000012E200)
;;     400000000012E42C (in fn400000000012E200)
;;     400000000012E45C (in fn400000000012E200)
file_iswdir proc
	{ alloc	r34,ar.pfs,0x6,0x0,0x4; nop.m	0x0; mov	r33,b1 }
	{ adds	r35,0x0,r1; nop.m	0x0; adds	r36,0x0,r32; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,file_isdir; }
	{ adds	r14,0x0,r0; cmp4.eq	p06,p07,0x0,r8; nop.b	0x0 }
	{ adds	r1,0x0,r35; mov.i	ar.pfs,r34; (p07) br.cond.dpnt.few	4000000000040A20; }

l4000000000040A10:
	{ adds	r8,0x0,r14; mov.spnt	b0,r33,4000000000040A10; br.ret	b0; }

l4000000000040A20:
	{ adds	r36,0x0,r32; addl	r37,2,r0; br.call.sptk.many	b0,sh_eaccess; }
	{ cmp4.eq	p06,p07,0x0,r8; adds	r1,0x0,r35; mov.i	ar.pfs,r34; }
	{ (p06) addl	r8,1,r0; mov.spnt	b0,r33,4000000000040A40; (p07) adds	r8,0x0,r0; }

l4000000000040A46:
	{ chk.a.nc	f33,3FFFFFFFFF120A56; (p04) nop; break.i	0x80000 }

l4000000000040A50:
	{ nop.m	0x0; adds	r14,0x0,r8; nop.i	0x0; }
	{ nop.m	0x0; adds	r8,0x0,r14; br.ret	b0; }
4000000000040A70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; dot_or_dotdot: 4000000000040A80
;;   Called from:
;;     40000000000CD89C (in command_word_completion_function)
dot_or_dotdot proc
	{ cmp.eq	p06,p07,0x0,r32; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000040AB0; }

l4000000000040A90:
	{ ld1	r14,[r32]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2E,r14; (p07) br.cond.dpnt.few	4000000000040AC0 }

l4000000000040AB0:
	{ nop.m	0x0; adds	r8,0x0,r0; br.ret	b0 }

l4000000000040AC0:
	{ adds	r14,0x1,r32; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x2F,r14; }
	{ cmp4.eq.or.andcm	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000040B40; }

l4000000000040AF0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x2E,r14; (p07) br.cond.dptk.few	4000000000040AB0 }

l4000000000040B00:
	{ adds	r32,0x2,r32; ld1	r14,[r32]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x2F,r14; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p06,p07,0x0,r14; (p07) br.cond.dptk.few	4000000000040AB0; }

l4000000000040B30:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000040B40:
	{ nop.m	0x0; addl	r8,1,r0; br.ret	b0; }
4000000000040B50 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000040B60 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000040B70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; absolute_pathname: 4000000000040B80
;;   Called from:
;;     40000000000CC3BC (in command_word_completion_function)
;;     40000000000D70DC (in bash_default_completion)
;;     40000000000D74EC (in bash_default_completion)
;;     40000000000EC00C (in cd_builtin)
;;     400000000010D06C (in source_builtin)
absolute_pathname proc
	{ cmp.eq	p06,p07,0x0,r32; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000040BD0; }

l4000000000040B90:
	{ ld1	r14,[r32]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000040BD0; }

l4000000000040BB0:
	{ cmp4.eq	p06,p07,0x2F,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000040C60; }

l4000000000040BC0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x2E,r14; (p06) br.cond.dpnt.few	4000000000040BE0 }

l4000000000040BD0:
	{ nop.m	0x0; adds	r8,0x0,r0; br.ret	b0 }

l4000000000040BE0:
	{ adds	r14,0x1,r32; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x2F,r14; }
	{ cmp4.eq.or.andcm	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000040C60; }

l4000000000040C10:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2E,r14; (p06) br.cond.dptk.few	4000000000040BD0 }

l4000000000040C20:
	{ adds	r32,0x2,r32; ld1	r14,[r32]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x2F,r14; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p06,p07,0x0,r14; (p07) br.cond.dptk.few	4000000000040BD0; }

l4000000000040C50:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000040C60:
	{ nop.m	0x0; addl	r8,1,r0; br.ret	b0; }
4000000000040C70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; absolute_program: 4000000000040C80
;;   Called from:
;;     4000000000020FBC (in main)
;;     40000000000CC87C (in command_word_completion_function)
;;     40000000000CCCCC (in command_word_completion_function)
;;     40000000000CCEFC (in command_word_completion_function)
;;     40000000000CD74C (in command_word_completion_function)
;;     40000000000D70FC (in bash_default_completion)
;;     40000000000D750C (in bash_default_completion)
;;     40000000000DCBAC (in fn40000000000DCB80)
;;     40000000000DD2CC (in search_for_command)
;;     40000000000DD38C (in search_for_command)
;;     40000000000DD4AC (in search_for_command)
;;     40000000000DD73C (in user_command_matches)
;;     40000000000F7E2C (in exec_builtin)
;;     40000000000F7E2C (in exec_builtin)
;;     40000000000FBA0C (in hash_builtin)
;;     400000000010E9FC (in describe_command)
;;     400000000010E9FC (in describe_command)
absolute_program proc
	{ alloc	r34,ar.pfs,0x6,0x0,0x4; nop.m	0x0; mov	r33,b1 }
	{ adds	r35,0x0,r1; nop.m	0x0; adds	r36,0x0,r32; }
	{ addl	r37,47,r0; nop.i	0x0; br.call.sptk.many	b0,mbschr; }
	{ cmp.eq	p07,p06,0x0,r8; adds	r1,0x0,r35; mov.i	ar.pfs,r34; }
	{ (p06) addl	r8,1,r0; nop.m	0x0; mov.spnt	b0,r33,4000000000040CC0; }

l4000000000040CC6:
	{ break.m	0x4000; nop; cmp.lt	p00,p00,r0,r32 }
	{ Invalid; (p34) nop; break.i	0x80000; }

l4000000000040CDC:
	{ nop; break.m	0x1000; break.i	0x1000 }
4000000000040CE0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000040CF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; make_absolute: 4000000000040D00
;;   Called from:
;;     400000000006DCAC (in initialize_shell_variables)
;;     40000000000EB35C (in fn40000000000EB300)
;;     40000000000EB6DC (in fn40000000000EB300)
make_absolute proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x5; adds	r36,0x0,r1; mov	r34,b2 }
	{ cmp.eq	p06,p07,0x0,r33; adds	r37,0x0,r33; (p06) br.cond.dpnt.few	4000000000040D80; }

l4000000000040D20:
	{ ld1	r14,[r32]; adds	r39,0x0,r0; adds	r38,0x0,r32; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x2F,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000040D80; }

l4000000000040D50:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,sh_makepath; }
	{ adds	r1,0x0,r36; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,4000000000040D70; br.ret	b0; }

l4000000000040D80:
	{ adds	r37,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r36; adds	r37,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r36; nop.m	0x0; adds	r37,0x0,r8 }
	{ adds	r38,0x0,r32; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r36; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,4000000000040DD0; br.ret	b0; }
4000000000040DE0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000040DF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; base_pathname: 4000000000040E00
;;   Called from:
;;     400000000001D21C (in main)
;;     400000000002263C (in shell_is_restricted)
;;     400000000002272C (in maybe_make_restricted)
;;     40000000000707EC (in get_name_for_error)
base_pathname proc
	{ alloc	r34,ar.pfs,0x6,0x0,0x4; ld1	r14,[r32]; nop.b	0x0 }
	{ adds	r35,0x0,r1; adds	r36,0x0,r32; mov	r33,b1; }
	{ nop.m	0x0; sxt1	r14,r14; addl	r37,47,r0; }
	{ cmp4.eq	p07,p06,0x2F,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000040E80; }

l4000000000040E40:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BEA0; }
	{ cmp.eq	p06,p07,0x0,r8; adds	r1,0x0,r35; (p07) adds	r32,0x1,r8; }

l4000000000040E60:
	{ adds	r8,0x0,r32; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,4000000000040E70; br.ret	b0 }

l4000000000040E80:
	{ adds	r14,0x1,r32; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000040E60; }

l4000000000040EB0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BEA0; }
	{ cmp.eq	p06,p07,0x0,r8; nop.m	0x0; adds	r1,0x0,r35; }
	{ nop.m	0x0; (p07) adds	r32,0x1,r8; br.cond.sptk.few	4000000000040E60; }

l4000000000040EDC:
	{ (p60) nop; break.i	0x1000; break.b	0x1000 }
4000000000040EE0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000040EF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; polite_directory_format: 4000000000040F00
;;   Called from:
;;     4000000000078AAC (in fn40000000000780C0)
;;     4000000000079C8C (in fn4000000000079240)
;;     4000000000079D8C (in fn4000000000079240)
;;     400000000008235C (in start_job)
;;     40000000001023FC (in dirs_builtin)
;;     400000000010249C (in dirs_builtin)
;;     400000000010279C (in dirs_builtin)
;;     40000000001027EC (in dirs_builtin)
;;     400000000010283C (in dirs_builtin)
;;     400000000010288C (in dirs_builtin)
;;     4000000000103F4C (in get_directory_stack)
;;     4000000000103FEC (in get_directory_stack)
polite_directory_format proc
	{ alloc	r36,ar.pfs,0x9,0x0,0x6; addl	r38,-5604,r1; mov	r35,b3 }
	{ nop.m	0x0; adds	r37,0x0,r1; nop.i	0x0; }
	{ ld8	r38,[r38]; nop.i	0x0; br.call.sptk.many	b0,get_string_value; }
	{ cmp.eq	p06,p07,0x0,r8; adds	r1,0x0,r37; nop.i	0x0 }
	{ adds	r33,0x0,r8; adds	r38,0x0,r8; (p06) br.cond.dpnt.few	4000000000040FE0; }

l4000000000040F50:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ cmp4.lt	p07,p06,0x1,r8; sxt4	r34,r8; adds	r1,0x0,r37 }
	{ adds	r39,0x0,r32; adds	r38,0x0,r33; (p06) br.cond.dpnt.few	4000000000040FE0; }

l4000000000040F80:
	{ adds	r40,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C020; }
	{ add	r39,r32,r34; nop.m	0x0; adds	r1,0x0,r37 }
	{ cmp4.eq	p07,p06,0x0,r8; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000040FE0; }

l4000000000040FB0:
	{ nop.m	0x0; ld1	r14,[r39]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p07,p06,0x2F,r14; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	4000000000041000 }

l4000000000040FE0:
	{ adds	r8,0x0,r32; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,4000000000040FF0; br.ret	b0 }

l4000000000041000:
	{ addl	r14,5724,r1; nop.m	0x0; addl	r40,4094,r0; }
	{ nop.m	0x0; ld8	r33,[r14]; nop.i	0x0; }
	{ adds	r38,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B920; }
	{ adds	r14,0xFFFFFFFFFFFFFFFF,r33; addl	r15,126,r0; nop.b	0x0 }
	{ adds	r33,0xFFE,r33; adds	r1,0x0,r37; mov.i	ar.pfs,r36; }
	{ adds	r32,0x0,r14; st1	[r15],r14; nop.b	0x0 }
	{ st1	[r0],r33; nop.m	0x0; mov.spnt	b0,r35,4000000000041060; }
	{ nop.m	0x0; adds	r8,0x0,r32; br.ret	b0; }

;; trim_pathname: 4000000000041080
trim_pathname proc
	{ alloc	r36,ar.pfs,0xA,0x0,0x7; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r35,b3 }
	{ cmp.eq	p07,p06,0x0,r32; adds	r37,0x0,r1; adds	r39,0x0,r32; }
	{ nop.m	0x0; mov	r38,LC; nop.i	0x0 }
	{ nop.b	0x0; (p07) br.cond.dpnt.few	40000000000410E0; br.call.sptk.many	b0,fn400000000001B6C0; }

l40000000000410BC:
	{ (p48) nop; nop; brp.sptk	b1,40000000000412BC }
	{ nop; nop }
	{ Invalid; zxt1	r0,r64; break.i	0x2A809 }

l40000000000410E0:
	{ adds	r8,0x0,r32; mov.i	ar.pfs,r36; mov.i	LC,r38; }
	{ nop.m	0x0; mov.spnt	b0,r35,40000000000410F0; nop.i	0x0 }
	{ adds	r12,0x10,r12; nop.m	0x0; br.ret	b0 }

l4000000000041110:
	{ nop.m	0x0; addl	r39,-5596,r1; nop.i	0x0; }
	{ ld8	r39,[r39]; nop.i	0x0; br.call.sptk.many	b0,get_string_value; }
	{ adds	r1,0x0,r37; cmp.eq	p06,p07,0x0,r8; (p06) br.cond.dpnt.few	40000000000410E0; }

l4000000000041140:
	{ ld1	r14,[r8]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000410E0 }

l4000000000041160:
	{ adds	r39,0x0,r8; adds	r40,0x10,r12; br.call.sptk.many	b0,legal_number; }
	{ adds	r14,0x10,r12; adds	r1,0x0,r37; cmp4.eq	p06,p07,0x0,r8 }
	{ adds	r18,0x0,r32; adds	r16,0x0,r0; (p06) br.cond.dpnt.few	40000000000410E0; }

l4000000000041190:
	{ ld8	r17,[r14]; nop.m	0x0; adds	r19,0x1,r18; }
	{ cmp.lt	p07,p06,0x0,r17; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000410E0; }

l40000000000411B0:
	{ ld1	r14,[r32]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x7E,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000413E0; }

l40000000000411D0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	40000000000410E0 }

l40000000000411E0:
	{ adds	r15,0x0,r19; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000041200:
	{ cmp4.eq	p07,p06,0x2F,r14; ld1	r14,[r15],1; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; (p07) adds	r16,0x1,r16; }

l4000000000041220:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	4000000000041200 }

l4000000000041230:
	{ nop.m	0x0; sxt4	r33,r33; sxt4	r16,r16; }
	{ add	r33,r32,r33; nop.m	0x0; cmp.lt	p06,p07,r16,r17 }
	{ adds	r16,0x0,r17; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000410E0; }

l4000000000041260:
	{ ld1	r14,[r33]; nop.m	0x0; adds	r40,0xFFFFFFFFFFFFFFFF,r33; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x2F,r14; }
	{ (p06) adds	r40,0x0,r33; nop.i	0x0; adds	r14,0x0,r40 }

l4000000000041286:
	{ break.m	0x4000; (p07) nop; (p48) nop }
	{ (p03) chk.a.clr	r18,3FFFFFFFFFA44516; mov	pr,0x430000B; break.b	0x80000 }

l40000000000412A0:
	{ nop.m	0x0; mov.i	LC,r15; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000412C0:
	{ adds	r40,0x0,r14; nop.m	0x0; adds	r14,0xFFFFFFFFFFFFFFFF,r14; }
	{ nop.m	0x0; ld1	r15,[r40]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; cmp4.eq	p07,p06,0x2F,r15; }
	{ (p07) adds	r16,0xFFFFFFFFFFFFFFFF,r16; (p07) adds	r17,0x0,r16; cmp.eq	p07,p06,0x0,r16 }

l40000000000412F6:
	{ Invalid; (p03) nop; Invalid; }

l40000000000412FC:
	{ rsm	0x3C8310; mov	pr,r0,0x2000; (p32) nop }

l400000000004130C:
	{ (p62) nop; zxt1	r64,r64; break.i	0x1000 }

l4000000000041310:
	{ adds	r40,0x0,r14; nop.m	0x0; nop.i	0x0 }

l4000000000041320:
	{ nop.m	0x0; adds	r14,0x10,r12; nop.i	0x0; }
	{ st8	[r17],r14; nop.m	0x0; nop.i	0x0 }

l4000000000041340:
	{ cmp.eq	p06,p07,r18,r40; sub	r14,r40,r18; (p06) br.cond.dpnt.few	40000000000410E0; }

l4000000000041350:
	{ nop.m	0x0; cmp4.lt	p07,p06,0x3,r14; (p06) br.cond.dptk.few	40000000000410E0 }

l4000000000041360:
	{ addl	r15,46,r0; adds	r14,0x0,r18; sub	r33,r33,r40 }
	{ adds	r34,0x3,r18; st1	[r14],r2,2; sxt4	r33,r33 }
	{ st1	[r15],r19; adds	r39,0x0,r34; adds	r41,0x0,r33 }
	{ st1	[r15],r14; add	r33,r34,r33; br.call.sptk.many	b0,fn400000000001A8A0; }
	{ adds	r8,0x0,r32; adds	r1,0x0,r37; nop.b	0x0 }
	{ st1	[r0],r33; mov.i	ar.pfs,r36; mov.i	LC,r38; }
	{ nop.m	0x0; mov.spnt	b0,r35,40000000000413C0; nop.i	0x0 }
	{ adds	r12,0x10,r12; nop.m	0x0; br.ret	b0 }

l40000000000413E0:
	{ adds	r16,0x0,r32; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000041400:
	{ adds	r14,0x1,r16; ld1	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r15,r15; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r15; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000410E0; }

l4000000000041430:
	{ cmp4.eq	p07,p06,0x2F,r15; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000041450; }

l4000000000041440:
	{ nop.m	0x0; adds	r16,0x0,r14; br.cond.sptk.few	4000000000041400; }

l4000000000041450:
	{ adds	r16,0x2,r16; nop.m	0x0; adds	r18,0x1,r14; }
	{ ld1	r14,[r16]; adds	r19,0x1,r18; adds	r16,0x0,r0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	40000000000411E0 }

l4000000000041490:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000410E0; }
40000000000414A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000414B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; extract_colon_unit: 40000000000414C0
;;   Called from:
;;     40000000000636AC (in sv_history_control)
;;     400000000006373C (in sv_history_control)
;;     40000000000AB82C (in remember_mail_dates)
;;     40000000000AB92C (in remember_mail_dates)
;;     40000000000CDE4C (in command_word_completion_function)
;;     40000000000DC32C (in fn40000000000DC300)
;;     40000000000EC0CC (in cd_builtin)
;;     4000000000109AFC (in parse_shellopts)
;;     4000000000109B5C (in parse_shellopts)
;;     4000000000114CCC (in parse_bashopts)
;;     4000000000114D6C (in parse_bashopts)
extract_colon_unit proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x5; cmp.eq	p06,p07,0x0,r32; mov	r34,b2 }
	{ adds	r36,0x0,r1; adds	r37,0x0,r32; (p06) br.cond.dpnt.few	4000000000041650; }

l40000000000414E0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ ld4	r38,[r33]; adds	r1,0x0,r36; adds	r16,0x0,r32; }
	{ cmp4.lt	p07,p06,r38,r8; nop.m	0x0; sxt4	r14,r38; }
	{ (p06) adds	r32,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000041650; }

l4000000000041516:
	{ chk.a.nc	r0,3FFFFFFFFF041D16; nop; break.i	0x80000 }

l4000000000041520:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r38; (p07) br.cond.dptk.few	4000000000041670 }

l4000000000041530:
	{ add	r16,r32,r14; ld1	r14,[r16]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p07,p06,0x3A,r14; }
	{ nop.m	0x0; (p07) adds	r38,0x1,r38; nop.i	0x0; }

l400000000004155C:
	{ break.m	0x80; mov	pr,r32,0x0; (p02) nop }
	{ cmp.eq	p38,p11,r22,r0; (p04) mov	pr,r9,0x8480; zxt1	r8,r0 }

l400000000004157C:
	{ cmp4.eq.and	p00,p43,r1,r0; Invalid; cmp4.eq.and	p00,p32,r32,r0 }

l4000000000041586:
	{ chk.a.nc	f0,3FFFFFFFFF041D86; (p07) cmp4.ltu	p00,p00,0xE,r20; (p49) nop }

l4000000000041596:
	{ Invalid; cmp4.lt	p00,p00,0x0,r1; (p49) nop.b	0x3; }

l400000000004159C:
	{ cmp4.eq.or.andcm	p00,p35,r1,r0; (p01) cmp.eq	p00,p16,r0,r64; cmp4.ne.and	p00,p28,r67,r97 }

l40000000000415A6:
	{ (p03) chk.a.clr	r0,3FFFFFFFFFD04686; (p07) cmp4.eq.or	p01,p08,0x0,r0; (p33) nop.b	0x3 }

l40000000000415B0:
	{ (p07) adds	r14,0x0,r0; and	r15,r15,r14; add	r14,r32,r17,0x1; }

l40000000000415B6:
	{ Invalid; (p07) nop; break.b	0x80000 }
	{ (p03) chk.a.clr	r0,3FFFFFFFFFD04EB6; nop; break.i	0x80000 }

l40000000000415D0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000415E0:
	{ adds	r16,0x0,r14; ld1	r15,[r14],1; adds	r39,0x1,r39; }
	{ nop.m	0x0; sxt1	r15,r15; cmp4.eq	p07,p06,0x0,r15; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p07,p06,0x3A,r15; (p06) br.cond.dptk.few	40000000000415E0; }

l4000000000041610:
	{ cmp4.eq	p07,p06,r39,r38; st4	[r39],r33; adds	r37,0x0,r32 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000416E0; }

l4000000000041630:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,substring; }
	{ nop.m	0x0; adds	r1,0x0,r36; adds	r32,0x0,r8; }

l4000000000041650:
	{ adds	r8,0x0,r32; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,4000000000041660; br.ret	b0 }

l4000000000041670:
	{ ld1	r14,[r32]; sxt4	r17,r38; adds	r39,0x0,r38; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p07,p06,0x3A,r14; }
	{ (p06) addl	r15,1,r0; (p07) adds	r15,0x0,r0; cmp4.eq	p07,p06,0x0,r14; }

l4000000000041696:
	{ Invalid; (p03) nop; Invalid; }

l400000000004169C:
	{ nop; cmp4.eq.and	p00,p00,r32,r0; zxt4	r0,r0 }

l40000000000416AC:
	{ cmp4.eq.and	p00,p43,r1,r0; (p01) cmp.eq	p00,p16,r0,r64; (p49) cmp.lt.unc	p03,p16,r3,r3 }

l40000000000416B6:
	{ Invalid; (p07) nop; break.b	0x80000 }
	{ (p03) chk.a.clr	f0,3FFFFFFFFFD04FB6; nop; nop }

l40000000000416D0:
	{ st4	[r38],r33; nop.m	0x0; nop.i	0x0; }

l40000000000416E0:
	{ ld1	r14,[r16]; adds	r38,0x1,r38; addl	r37,1,r0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ (p07) st4	[r38],r33; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }

l4000000000041706:
	{ break.m	0x4000; (p32) nop; nop }
	{ mf.a; nop; (p16) nop }
	{ break.m	0x4000; nop; nop }
	{ Invalid; (p34) nop; Invalid }

;; tilde_initialize: 4000000000041740
;;   Called from:
;;     40000000000D6ADC (in bashline_reset)
tilde_initialize proc
	{ alloc	r37,ar.pfs,0x8,0x0,0x7; addl	r14,6852,r1; mov	r36,b4 }
	{ addl	r17,-10468,r1; addl	r18,-5564,r1; adds	r38,0x0,r1; }
	{ nop.m	0x0; ld4	r15,[r14]; mov.i	ar.pfs,r37 }
	{ nop.m	0x0; ld8	r17,[r17]; nop.i	0x0; }
	{ adds	r16,0x1,r15; ld8	r18,[r18]; nop.b	0x0 }
	{ cmp4.eq	p07,p06,0x0,r15; nop.m	0x0; mov.spnt	b0,r36,4000000000041790; }
	{ st8	[r18],r17; st4	[r16],r14; nop.i	0x0 }
	{ nop.b	0x0; (p07) br.cond.dpnt.few	40000000000417C0; br.ret	b0 }

l40000000000417BC:
	{ nop; (p04) invala.e	f43; cmp.eq	p00,p00,r32,r0 }

l40000000000417C0:
	{ addl	r33,-5588,r1; nop.m	0x0; addl	r39,3,r0; }
	{ ld8	r33,[r33]; nop.i	0x0; br.call.sptk.many	b0,strvec_create; }
	{ adds	r1,0x0,r38; adds	r14,0x0,r8; adds	r15,0x10,r8 }
	{ addl	r39,2,r0; addl	r34,-5580,r1; addl	r35,6860,r1 }
	{ st8	[r14],r8,8; st8	[r0],r15; addl	r32,-5572,r1; }
	{ nop.m	0x0; ld8	r34,[r34]; nop.i	0x0 }
	{ st8	[r8],r35; ld8	r32,[r32]; nop.i	0x0; }
	{ st8	[r34],r14; nop.i	0x0; br.call.sptk.many	b0,strvec_create; }
	{ adds	r14,0x0,r8; nop.m	0x0; adds	r1,0x0,r38 }
	{ ld8	r15,[r35]; nop.m	0x0; addl	r39,3,r0; }
	{ st8	[r14],r8,8; nop.m	0x0; addl	r16,6868,r1; }
	{ nop.m	0x0; st8	[r0],r14; addl	r14,-10412,r1 }
	{ st8	[r8],r16; ld8	r14,[r14]; nop.i	0x0; }
	{ st8	[r15],r14; nop.i	0x0; br.call.sptk.many	b0,strvec_create; }
	{ adds	r14,0x0,r8; adds	r1,0x0,r38; adds	r15,0x10,r8 }
	{ addl	r39,2,r0; st8	[r14],r8,8; addl	r16,6876,r1 }
	{ st8	[r0],r15; st8	[r33],r14; addl	r14,-10124,r1 }
	{ st8	[r8],r16; ld8	r14,[r14]; nop.i	0x0; }
	{ st8	[r8],r14; nop.i	0x0; br.call.sptk.many	b0,strvec_create; }
	{ adds	r1,0x0,r38; adds	r14,0x0,r8; mov.i	ar.pfs,r37; }
	{ st8	[r14],r8,8; addl	r15,6884,r1; mov.spnt	b0,r36,4000000000041900; }
	{ nop.m	0x0; st8	[r8],r15; nop.i	0x0 }
	{ st8	[r0],r14; nop.m	0x0; br.ret	b0; }
4000000000041930 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; bash_tilde_find_word: 4000000000041940
;;   Called from:
;;     40000000000A344C (in fn40000000000A1400)
bash_tilde_find_word proc
	{ alloc	r39,ar.pfs,0xC,0x0,0x9; ld1	r14,[r32]; mov	r38,b6 }
	{ adds	r15,0x0,r32; cmp4.eq	p12,p13,0x0,r33; adds	r40,0x0,r1; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p09,p08,0x2F,r14 }
	{ cmp4.eq	p11,p10,0x0,r14; cmp4.eq	p06,p07,0x5C,r14; cmp4.eq	p14,p15,0x22,r14; }
	{ (p08) addl	r17,1,r0; (p10) addl	r16,1,r0; cmp4.eq.or.andcm	p06,p07,0x27,r14; }

l4000000000041986:
	{ Invalid; (p03) dep	r39,r14,r71,32,4; (p18) cmp.eq.or.andcm	p04,p00,r0,r0 }

l400000000004198C:
	{ (p19) nop; Invalid; (p02) epc }

l4000000000041996:
	{ Invalid; (p08) nop; break.i	0x80000 }

l400000000004199C:
	{ (p08) nop; break.i	0x1000; czx1.r	r0,r98 }
	{ chk.a.nc	r0,40000000006019BC; mov	pr,r0,0x430C; mov.sptk	b2,r0,4000000000041DDC }

l40000000000419B6:
	{ nop; nop; break.i	0x80000; }

l40000000000419BC:
	{ (p04) invala; break.i	0x1000; Invalid }

l40000000000419C0:
	{ nop.m	0x0; nop.i	0x0; (p12) br.cond.dptk.few	40000000000419E0 }

l40000000000419D0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x3A,r14; (p07) br.cond.dpnt.few	4000000000041AB0 }

l40000000000419E0:
	{ adds	r15,0x1,r15; ld1	r14,[r15]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x0,r14; cmp4.eq	p08,p09,0x5C,r14; cmp4.eq	p11,p10,0x22,r14; }
	{ cmp4.eq.or.andcm	p07,p06,0x2F,r14; nop.m	0x0; cmp4.eq.or.andcm	p08,p09,0x27,r14 }
	{ (p07) br.cond.dpnt.few	4000000000041AB0; (p08) br.cond.dpnt.few	4000000000041A30; (p10) br.cond.dptk.few	40000000000419C0 }

l4000000000041A26:
	{ nop; nop; (p16) nop }

l4000000000041A2C:
	{ (p61) nop; zxt1	r0,r64; break.i	0x1000 }

l4000000000041A30:
	{ adds	r41,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r40; adds	r41,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r41,0x0,r8 }
	{ adds	r42,0x0,r32; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ cmp.eq	p06,p07,0x0,r34; adds	r35,0x0,r8; nop.b	0x0 }
	{ adds	r1,0x0,r40; nop.m	0x0; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; adds	r8,0x0,r35; nop.b	0x0 }
	{ (p07) st4	[r0],r34; mov.spnt	b0,r38,4000000000041AA0; br.ret	b0 }

l4000000000041AA6:
	{ Invalid; (p34) nop; nop }

l4000000000041AB0:
	{ sub	r36,r15,r32; adds	r41,0x1,r36; sxt4	r37,r36; }
	{ nop.m	0x0; sxt4	r41,r41; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r40; adds	r35,0x0,r8; adds	r43,0x0,r37 }
	{ adds	r41,0x0,r8; adds	r42,0x0,r32; br.call.sptk.many	b0,fn400000000001B920; }
	{ add	r37,r35,r37; cmp.eq	p06,p07,0x0,r34; adds	r1,0x0,r40; }
	{ st1	[r0],r37; (p07) st4	[r36],r34; nop.i	0x0 }

l4000000000041B0C:
	{ nop; zxt1	r96,r64; break.i	0x1000 }

l4000000000041B10:
	{ adds	r8,0x0,r35; nop.m	0x0; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.spnt	b0,r38,4000000000041B20; br.ret	b0; }

l4000000000041B30:
	{ adds	r37,0x0,r0; nop.m	0x0; addl	r41,1,r0 }
	{ adds	r36,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r40; adds	r35,0x0,r8; adds	r43,0x0,r37 }
	{ adds	r41,0x0,r8; adds	r42,0x0,r32; br.call.sptk.many	b0,fn400000000001B920; }
	{ add	r37,r35,r37; cmp.eq	p06,p07,0x0,r34; adds	r1,0x0,r40; }
	{ nop.m	0x0; st1	[r0],r37; nop.i	0x0 }
	{ (p07) st4	[r36],r34; nop.m	0x0; br.cond.sptk.few	4000000000041B10; }

l4000000000041B96:
	{ break.m	0x4000; nop; break.i	0x80000 }
4000000000041BA0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000041BB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; bash_tilde_expand: 4000000000041BC0
;;   Called from:
;;     4000000000041FAC (in full_pathname)
;;     400000000006C8BC (in initialize_shell_variables)
;;     40000000000A34CC (in fn40000000000A1400)
;;     40000000000CA62C (in fn40000000000CA600)
;;     40000000000CAE8C (in fn40000000000CAD40)
;;     40000000000CB0BC (in fn40000000000CAD40)
;;     40000000000CB21C (in fn40000000000CAD40)
;;     40000000000CDC5C (in command_word_completion_function)
;;     40000000000CE0CC (in command_word_completion_function)
;;     40000000000DC9CC (in fn40000000000DC640)
;;     40000000000F5BEC (in maybe_execute_file)
;;     400000000012CD4C (in sh_makepath)
bash_tilde_expand proc
	{ alloc	r39,ar.pfs,0xB,0x0,0x9; addl	r34,7672,r1; mov	r38,b6 }
	{ addl	r35,7668,r1; adds	r40,0x0,r1; cmp4.eq	p06,p07,0x0,r33; }
	{ nop.m	0x0; nop.m	0x0; addl	r14,1,r0 }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0; }
	{ ld4	r36,[r34]; st4	[r14],r34; nop.i	0x0 }
	{ ld4	r37,[r35]; st4	[r14],r35; (p06) br.cond.dptk.few	4000000000041CF0 }

l4000000000041C20:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x2,r33; nop.i	0x0; }
	{ (p07) addl	r14,6868,r1; (p07) ld8	r16,[r14]; (p07) addl	r14,6884,r1; }

l4000000000041C36:
	{ (p08) chk.a.nc	f0,3FFFFFFFFF84DD16; (p07) cmp4.ne.or	p36,p08,r1,r53; (p49) nop; }

l4000000000041C3C:
	{ (p50) cmp4.eq.or.andcm	p01,p41,r53,r72; Invalid; cmp4.eq.and	p00,p32,r32,r0; }

l4000000000041C40:
	{ (p07) ld8	r15,[r14]; nop.m	0x0; (p07) addl	r14,-10412,r1; }

l4000000000041C46:
	{ chk.a.nc	f0,3FFFFFFFFF042446; (p07) cmp4.ne.or	p20,p15,0x7D,r46; (p33) addl	r3,832,r3 }

l4000000000041C50:
	{ (p07) ld8	r14,[r14]; (p06) addl	r14,6860,r1; nop.i	0x0; }

l4000000000041C56:
	{ Invalid; cmp4.ltu	p00,p00,r0,r1; (p01) addl	r0,13124,r3; }

l4000000000041C5C:
	{ Invalid; cmp4.ne.or.andcm	p04,p08,r3,r102; (p01) cmp4.ne.and	p00,p40,r3,r6 }

l4000000000041C66:
	{ (p07) chk.a.nc	f0,3FFFFFFFFF84DD46; (p07) addl	r116,845821,r0; Invalid; }

l4000000000041C6C:
	{ (p58) cmp4.ne.and	p61,p11,r48,r79; (p01) cmp4.eq.and	p53,p51,r95,r107; Invalid; }

l4000000000041C70:
	{ (p06) addl	r14,-10412,r1; (p07) ld8	r14,[r14]; nop.i	0x0; }

l4000000000041C76:
	{ (p07) fwb; addl	r0,49152,r1; (p33) nop; }

l4000000000041C7C:
	{ cmp4.eq.and	p00,p11,r1,r0; Invalid; Invalid }

l4000000000041C86:
	{ mf.a; nop; (p32) nop }
	{ break.m	0x4000; (p07) nop; break.i	0x80000 }
	{ (p03) chk.a.clr	f126,3FFFFFFFFFD04D86; nop; (p16) nop.b	0x2000A }

l4000000000041CB0:
	{ adds	r41,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BFA0; }
	{ adds	r1,0x0,r40; st4	[r36],r34; nop.b	0x0 }
	{ st4	[r37],r35; nop.m	0x0; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.spnt	b0,r38,4000000000041CE0; br.ret	b0 }

l4000000000041CF0:
	{ addl	r14,-10412,r1; ld8	r14,[r14]; nop.i	0x0; }
	{ st8	[r0],r14; ld1	r14,[r32]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x7E,r14; (p06) br.cond.dptk.few	4000000000041CB0 }

l4000000000041D30:
	{ adds	r15,0x1,r32; nop.m	0x0; addl	r17,1,r0 }
	{ nop.m	0x0; movl	r18,0x21; }

l4000000000041D50:
	{ ld1	r14,[r15],1; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.m	0x0; cmp4.eq	p09,p08,0x3A,r14; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p06,p07,0x2F,r14; (p06) br.cond.dptk.few	4000000000041CB0 }

l4000000000041D80:
	{ adds	r14,0xFFFFFFFFFFFFFFDE,r14; nop.i	0x0; (p09) br.cond.dpnt.few	4000000000041CB0; }

l4000000000041D90:
	{ nop.m	0x0; sxt1	r16,r14; zxt1	r14,r14; }
	{ nop.m	0x0; shl	r16,r17,r16; nop.i	0x0 }
	{ cmp4.ltu	p06,p07,0x3A,r14; nop.m	0x0; (p06) br.cond.dptk.few	4000000000041D50; }

l4000000000041DC0:
	{ nop.m	0x0; and	r16,r18,r16; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r16; (p07) br.cond.dptk.few	4000000000041D50 }

l4000000000041DE0:
	{ adds	r41,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r40; adds	r41,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r41,0x0,r8 }
	{ adds	r42,0x0,r32; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r40; st4	[r36],r34; nop.b	0x0 }
	{ st4	[r37],r35; nop.m	0x0; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.spnt	b0,r38,4000000000041E40; br.ret	b0; }
4000000000041E50 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000041E60 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000041E70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; full_pathname: 4000000000041E80
;;   Called from:
;;     400000000006C47C (in initialize_shell_variables)
;;     40000000000AAEFC (in fn40000000000AAEC0)
;;     40000000000F7E7C (in exec_builtin)
full_pathname proc
	{ alloc	r36,ar.pfs,0x9,0x0,0x6; ld1	r14,[r32]; nop.b	0x0 }
	{ adds	r37,0x0,r1; mov	r35,b3; adds	r38,0x0,r32; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ cmp4.eq	p07,p06,0x7E,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000041FA0; }

l4000000000041EC0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r37; adds	r38,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r37; nop.m	0x0; adds	r38,0x0,r8 }
	{ adds	r39,0x0,r32; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ nop.m	0x0; adds	r1,0x0,r37; adds	r33,0x0,r8; }

l4000000000041F10:
	{ ld1	r14,[r33]; nop.m	0x0; adds	r39,0x0,r33 }
	{ addl	r40,6,r0; adds	r38,0x0,r0; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x2F,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000041F80; }

l4000000000041F40:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,sh_makepath; }
	{ adds	r1,0x0,r37; nop.m	0x0; adds	r34,0x0,r8 }
	{ adds	r38,0x0,r33; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r37; adds	r33,0x0,r34; }

l4000000000041F80:
	{ adds	r8,0x0,r33; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,4000000000041F90; br.ret	b0; }

l4000000000041FA0:
	{ adds	r39,0x0,r0; nop.i	0x0; br.call.sptk.many	b0,bash_tilde_expand; }
	{ adds	r1,0x0,r37; adds	r33,0x0,r8; br.cond.sptk.few	4000000000041F10; }

;; group_member: 4000000000041FC0
;;   Called from:
;;     400000000012B6AC (in sh_eaccess)
group_member proc
	{ alloc	r35,ar.pfs,0x6,0x0,0x6; addl	r14,-22276,r1; mov	r37,LC }
	{ addl	r33,6892,r1; nop.m	0x0; adds	r36,0x0,r1; }
	{ nop.m	0x0; mov	r34,b2; adds	r15,0x8,r14 }
	{ adds	r14,0xC,r14; ld4	r15,[r15]; nop.i	0x0; }
	{ cmp4.eq	p07,p06,r32,r15; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000420E0; }

l4000000000042010:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,r32,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000420E0; }

l4000000000042030:
	{ nop.m	0x0; ld4	r14,[r33]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	4000000000042100; }

l4000000000042050:
	{ adds	r16,0xFFFFFFFFFFFFFFFF,r14; nop.m	0x0; cmp4.lt	p07,p06,0x0,r14 }
	{ addl	r14,6900,r1; nop.m	0x0; (p06) br.cond.dpnt.few	40000000000420C0; }

l4000000000042070:
	{ ld8	r15,[r14]; nop.m	0x0; addp4	r16,r16,r0; }
	{ nop.m	0x0; adds	r14,0x4,r15; mov.i	LC,r16; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000420A0:
	{ ld4	r16,[r15]; adds	r15,0x0,r14; adds	r14,0x4,r14; }
	{ cmp4.eq	p06,p07,r32,r16; (p06) br.cond.dpnt.few	40000000000420E0; br.cloop.sptk.few	40000000000420A0 }

l40000000000420BC:
	{ Invalid; zxt1	r0,r64; (p48) break.b	0x2A808 }

l40000000000420C0:
	{ adds	r8,0x0,r0; mov.i	ar.pfs,r35; mov.i	LC,r37; }
	{ nop.m	0x0; mov.spnt	b0,r34,40000000000420D0; br.ret	b0 }

l40000000000420E0:
	{ addl	r8,1,r0; mov.i	ar.pfs,r35; mov.i	LC,r37; }
	{ nop.m	0x0; mov.spnt	b0,r34,40000000000420F0; br.ret	b0; }

l4000000000042100:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000003E980; }
	{ nop.m	0x0; adds	r1,0x0,r36; nop.i	0x0 }
	{ ld4	r14,[r33]; nop.m	0x0; br.cond.sptk.few	4000000000042050; }
4000000000042130 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; get_group_list: 4000000000042140
get_group_list proc
	{ alloc	r40,ar.pfs,0xB,0x0,0xA; adds	r12,0xFFFFFFFFFFFFFFF0,r12; nop.b	0x0 }
	{ addl	r34,6916,r1; addl	r14,6892,r1; mov	r39,b7; }
	{ ld8	r8,[r34]; adds	r41,0x0,r1; cmp.eq	p08,p09,0x0,r32; }
	{ cmp.eq	p06,p07,0x0,r8; (p06) br.cond.dpnt.few	40000000000421C0; (p08) br.cond.dpnt.few	40000000000421A0; }

l400000000004217C:
	{ (p01) nop; cmp.lt	p00,p00,r32,r0; (p01) rfi }

l4000000000042180:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ st4	[r14],r32; nop.m	0x0; nop.i	0x0 }

l40000000000421A0:
	{ nop.m	0x0; mov.i	ar.pfs,r40; mov.spnt	b0,r39,40000000000421A0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l40000000000421C0:
	{ addl	r37,6892,r1; adds	r33,0x0,r0; adds	r35,0x0,r0 }
	{ addl	r38,6900,r1; ld4	r14,[r37]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	4000000000042300; }

l40000000000421F0:
	{ cmp4.lt	p06,p07,0x0,r14; adds	r42,0x0,r14; (p07) br.cond.dpnt.few	40000000000422D0; }

l4000000000042200:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,strvec_create; }
	{ nop.m	0x0; ld4	r14,[r37]; adds	r1,0x0,r41 }
	{ nop.m	0x0; st8	[r8],r34; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p07,p06,0x0,r14; (p06) br.cond.dpnt.few	40000000000422A0; }

l4000000000042240:
	{ ld8	r14,[r38]; shladd	r36,r33,0x1,r8; adds	r35,0x1,r35; }
	{ add	r14,r14,r33; nop.m	0x0; adds	r33,0x4,r33; }
	{ ld4	r42,[r14]; nop.i	0x0; br.call.sptk.many	b0,itos; }
	{ ld4	r14,[r37]; st8	[r8],r36; adds	r1,0x0,r41 }
	{ nop.m	0x0; ld8	r8,[r34]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p07,p06,r35,r14; (p07) br.cond.dptk.few	4000000000042240; }

l40000000000422A0:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r32; nop.i	0x0; }
	{ (p07) st4	[r14],r32; mov.i	ar.pfs,r40; mov.spnt	b0,r39,40000000000422B0 }

l40000000000422B6:
	{ break.m	0xAA028; nop; break.i	0x80000 }
	{ Invalid; (p34) nop; break.i	0x80000 }

l40000000000422D0:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r32; nop.i	0x0; }
	{ (p07) st4	[r0],r32; mov.i	ar.pfs,r40; mov.spnt	b0,r39,40000000000422E0 }

l40000000000422E6:
	{ break.m	0xAA028; nop; break.i	0x80000 }
	{ Invalid; (p34) nop; break.i	0x80000 }

l4000000000042300:
	{ nop.m	0x0; adds	r14,0x10,r12; nop.i	0x0; }
	{ st8	[r8],r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000003E980; }
	{ nop.m	0x0; adds	r15,0x10,r12; adds	r1,0x0,r41 }
	{ nop.m	0x0; ld4	r14,[r37]; nop.i	0x0; }
	{ ld8	r8,[r15]; nop.i	0x0; br.cond.sptk.few	40000000000421F0; }
4000000000042350 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000042360 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000042370 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; get_group_array: 4000000000042380
get_group_array proc
	{ alloc	r36,ar.pfs,0x8,0x0,0x7; adds	r12,0xFFFFFFFFFFFFFFF0,r12; nop.b	0x0 }
	{ addl	r33,6924,r1; addl	r14,6892,r1; mov	r38,LC; }
	{ ld8	r8,[r33]; nop.m	0x0; mov	r35,b3 }
	{ adds	r37,0x0,r1; nop.m	0x0; cmp.eq	p08,p09,0x0,r32; }
	{ cmp.eq	p06,p07,0x0,r8; (p06) br.cond.dpnt.few	4000000000042420; (p08) br.cond.dpnt.few	40000000000423F0; }

l40000000000423CC:
	{ (p01) nop; cmp.lt	p00,p00,r32,r0; (p01) rfi }

l40000000000423D0:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ st4	[r14],r32; nop.m	0x0; nop.i	0x0 }

l40000000000423F0:
	{ nop.m	0x0; mov.i	ar.pfs,r36; nop.i	0x0; }
	{ nop.m	0x0; mov.i	LC,r38; mov.spnt	b0,r35,4000000000042400 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l4000000000042420:
	{ addl	r34,6892,r1; ld4	r14,[r34]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p07) br.cond.dpnt.few	4000000000042540; }

l4000000000042440:
	{ cmp4.lt	p06,p07,0x0,r14; sxt4	r39,r14; (p07) br.cond.dpnt.few	4000000000042510; }

l4000000000042450:
	{ shladd	r39,r39,0x2,r0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ ld4	r18,[r34]; nop.m	0x0; adds	r1,0x0,r37 }
	{ adds	r16,0x0,r8; st8	[r8],r33; nop.i	0x0; }
	{ cmp4.lt	p06,p07,0x0,r18; adds	r14,0xFFFFFFFFFFFFFFFF,r18; (p07) br.cond.dpnt.few	40000000000424E0; }

l4000000000042490:
	{ (p06) addl	r15,6900,r1; nop.m	0x0; (p06) addp4	r17,r14,r0; }

l4000000000042496:
	{ adds	r0,0xFFFFFFFFFFFFE000,r1; Invalid; (p49) addl	r3,864,r3 }

l40000000000424A0:
	{ (p06) ld8	r15,[r15]; (p06) mov.i	LC,r17; (p06) adds	r14,0x4,r15; }

l40000000000424A6:
	{ chk.a.nc	r17,3FFFFFFFFF0578B6; (p07) nop; break.i	0x80000; }

l40000000000424AC:
	{ (p02) nop; break.i	0x1000; break.i	0x1000; }

l40000000000424B0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000424C0:
	{ ld4	r17,[r15]; adds	r15,0x0,r14; adds	r14,0x4,r14; }
	{ st4	[r16],r4,4; nop.i	0x0; br.cloop.sptk.few	40000000000424C0 }

l40000000000424E0:
	{ cmp.eq	p07,p06,0x0,r32; (p06) st4	[r18],r32; mov.i	ar.pfs,r36; }

l40000000000424EC:
	{ Invalid; break.i	0x1000; (p32) break.i	0x2A829 }
	{ (p17) nop; add	r0,r32,r0; Invalid }
	{ cmp.lt	p00,p11,r33,r0; Invalid; Invalid }

l4000000000042510:
	{ cmp.eq	p06,p07,0x0,r32; (p07) st4	[r0],r32; mov.i	ar.pfs,r36; }

l400000000004251C:
	{ Invalid; break.i	0x1000; (p32) break.i	0x2A829 }
	{ (p17) nop; add	r0,r32,r0; Invalid }
	{ nop; cmp.lt	p00,p00,r32,r0; zxt1	r4,r64 }

l4000000000042540:
	{ nop.m	0x0; adds	r14,0x10,r12; nop.i	0x0; }
	{ st8	[r8],r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000003E980; }
	{ nop.m	0x0; adds	r15,0x10,r12; adds	r1,0x0,r37 }
	{ nop.m	0x0; ld4	r14,[r34]; nop.i	0x0; }
	{ ld8	r8,[r15]; nop.i	0x0; br.cond.sptk.few	4000000000042440; }
4000000000042590 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
40000000000425A0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
40000000000425B0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; cmd_init: 40000000000425C0
cmd_init proc
	{ alloc	r34,ar.pfs,0x5,0x0,0x4; mov	r33,b1; adds	r35,0x0,r1; }
	{ addl	r36,480,r0; addl	r32,60,r0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r35; addl	r36,480,r0; addl	r15,14044,r1; }
	{ nop.m	0x0; adds	r14,0x0,r15; adds	r15,0xC,r15; }
	{ st8	[r14],r8,8; st4	[r0],r15; nop.i	0x0; }
	{ st4	[r32],r14; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r35; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ addl	r15,14028,r1; nop.m	0x0; mov.spnt	b0,r33,4000000000042630; }
	{ nop.m	0x0; adds	r14,0x0,r15; adds	r15,0xC,r15; }
	{ st8	[r14],r8,8; st4	[r0],r15; nop.i	0x0; }
	{ st4	[r32],r14; nop.i	0x0; br.ret	b0; }
4000000000042670 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; alloc_word_desc: 4000000000042680
;;   Called from:
;;     40000000000364FC (in fn4000000000030880)
;;     400000000003660C (in fn4000000000030880)
;;     400000000004279C (in make_bare_word)
;;     40000000000929BC (in list_string)
;;     400000000009320C (in list_string)
;;     40000000000947EC (in command_substitute)
;;     400000000009543C (in command_substitute)
;;     400000000009A32C (in fn400000000009A180)
;;     400000000009DAAC (in fn400000000009A180)
;;     400000000009DD3C (in fn400000000009A180)
;;     400000000009E17C (in fn400000000009A180)
;;     40000000000A423C (in fn40000000000A1400)
;;     40000000000A5D2C (in fn40000000000A5B80)
;;     40000000000A62CC (in fn40000000000A5B80)
alloc_word_desc proc
	{ alloc	r33,ar.pfs,0x4,0x0,0x3; addl	r16,14044,r1; mov	r32,b0 }
	{ adds	r34,0x0,r1; nop.m	0x0; mov.i	ar.pfs,r33; }
	{ adds	r15,0xC,r16; nop.m	0x0; mov.spnt	b0,r32,40000000000426A0; }
	{ nop.m	0x0; ld4	r14,[r15]; nop.i	0x0; }
	{ adds	r17,0xFFFFFFFFFFFFFFFF,r14; cmp4.lt	p07,p06,0x0,r14; (p06) br.cond.dpnt.few	4000000000042720; }

l40000000000426D0:
	{ nop.m	0x0; ld8	r14,[r16]; sxt4	r16,r17 }
	{ st4	[r17],r15; shladd	r14,r16,0x3,r14; nop.i	0x0; }
	{ nop.m	0x0; ld8	r8,[r14]; nop.i	0x0; }
	{ adds	r14,0x8,r8; nop.i	0x0; nop.i	0x0 }
	{ st8	[r0],r8; st4	[r0],r14; br.ret	b0; }

l4000000000042720:
	{ addl	r35,16,r0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r14,0x8,r8; adds	r1,0x0,r34; nop.b	0x0 }
	{ st8	[r0],r8; nop.m	0x0; mov.i	ar.pfs,r33; }
	{ st4	[r0],r14; mov.spnt	b0,r32,4000000000042750; br.ret	b0; }
4000000000042760 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000042770 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; make_bare_word: 4000000000042780
;;   Called from:
;;     4000000000042B6C (in make_word)
;;     400000000006EFEC (in copy_word)
;;     400000000008FB2C (in list_rest_of_args)
;;     400000000008FBBC (in list_rest_of_args)
;;     40000000000A36AC (in fn40000000000A1400)
;;     40000000000A3B9C (in fn40000000000A1400)
;;     40000000000A40CC (in fn40000000000A1400)
;;     40000000000A5B1C (in expand_prompt_string)
;;     40000000000A890C (in fn40000000000A7940)
;;     40000000000BC61C (in array_to_word_list)
;;     40000000000BC7AC (in array_keys_to_word_list)
;;     40000000000C226C (in fn40000000000C2180)
;;     40000000000C3C0C (in assoc_to_string)
;;     40000000000DE7AC (in fn40000000000DE580)
;;     400000000011D25C (in complete_builtin)
;;     400000000011D2DC (in complete_builtin)
;;     400000000011E6FC (in compopt_builtin)
;;     4000000000130AEC (in strvec_to_word_list)
;;     4000000000130BAC (in strvec_to_word_list)
make_bare_word proc
	{ alloc	r35,ar.pfs,0x7,0x0,0x5; mov	r34,b2; adds	r36,0x0,r1; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,alloc_word_desc; }
	{ ld1	r14,[r32]; nop.m	0x0; adds	r33,0x0,r8 }
	{ adds	r1,0x0,r36; addl	r37,1,r0; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000042810; }

l40000000000427D0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r36; st8	[r8],r33; mov.i	ar.pfs,r35 }
	{ st1	[r0],r8; nop.m	0x0; adds	r8,0x0,r33; }
	{ nop.m	0x0; mov.spnt	b0,r34,4000000000042800; br.ret	b0; }

l4000000000042810:
	{ adds	r37,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r36; adds	r37,0x1,r8; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r36; nop.m	0x0; adds	r37,0x0,r8 }
	{ adds	r38,0x0,r32; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r36; st8	[r8],r33; mov.i	ar.pfs,r35 }
	{ nop.m	0x0; adds	r8,0x0,r33; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r34,4000000000042870; br.ret	b0; }

;; make_word_flags: 4000000000042880
;;   Called from:
;;     4000000000042B9C (in make_word)
make_word_flags proc
	{ alloc	r42,ar.pfs,0x10,0x0,0xC; adds	r12,0xFFFFFFFFFFFFFFF0,r12; nop.b	0x0 }
	{ addl	r39,-9996,r1; adds	r43,0x0,r1; mov	r41,b1; }
	{ adds	r40,0x18,r12; ld8	r39,[r39]; nop.i	0x0 }
	{ adds	r44,0x0,r33; adds	r35,0x0,r0; adds	r37,0x8,r32; }
	{ st8	[r0],r40; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ nop.m	0x0; adds	r1,0x0,r43; adds	r38,0x0,r8; }

l40000000000428E0:
	{ nop.m	0x0; sxt4	r34,r35; nop.i	0x0; }
	{ nop.m	0x0; cmp.ltu	p06,p07,r34,r38; (p07) br.cond.dpnt.few	40000000000429F0 }

l4000000000042900:
	{ add	r36,r33,r34; ld1	r14,[r36]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x24,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000042AE0; }

l4000000000042930:
	{ nop.m	0x0; cmp4.lt	p06,p07,0x24,r14; (p06) br.cond.dptk.few	4000000000042A80; }

l4000000000042940:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x22,r14; (p06) br.cond.dpnt.few	4000000000042AA0 }

l4000000000042950:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x0,r43; cmp.ltu	p07,p06,0x1,r8; (p06) br.cond.dpnt.few	4000000000042AD0 }

l4000000000042970:
	{ ld1	r14,[r36]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; extr.u	r16,r14,5,3; and	r15,0x1F,r14; }
	{ shladd	r14,r16,0x2,r39; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; shr.u	r14,r14,r15; tbit.z	p07,p06,r14,0x0 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000042A10; }

l40000000000429C0:
	{ (p06) addl	r14,1,r0; nop.m	0x0; nop.i	0x0; }

l40000000000429C6:
	{ break.m	0x4000; nop; (p48) nop }

l40000000000429D0:
	{ add	r35,r14,r35; nop.m	0x0; sxt4	r34,r35; }
	{ nop.m	0x0; cmp.ltu	p06,p07,r34,r38; (p06) br.cond.dptk.few	4000000000042900 }

l40000000000429F0:
	{ adds	r8,0x0,r32; mov.i	ar.pfs,r42; mov.spnt	b0,r41,40000000000429F0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }

l4000000000042A10:
	{ ld8	r14,[r40]; adds	r15,0x10,r12; adds	r44,0x0,r0 }
	{ adds	r45,0x0,r36; sub	r46,r38,r34; adds	r47,0x0,r40; }
	{ st8	[r14],r15; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0A0; }
	{ adds	r14,0x2,r8; adds	r15,0x10,r12; adds	r1,0x0,r43; }
	{ cmp.ltu	p06,p07,0x1,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000042B00; }

l4000000000042A60:
	{ ld8	r14,[r15]; nop.m	0x0; adds	r35,0x1,r35; }
	{ st8	[r14],r40; nop.i	0x0; br.cond.sptk.few	40000000000428E0 }

l4000000000042A80:
	{ cmp4.eq	p06,p07,0x27,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000042AA0; }

l4000000000042A90:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x60,r14; (p07) br.cond.dptk.few	4000000000042950 }

l4000000000042AA0:
	{ ld4	r14,[r37]; or	r14,0x2,r14; nop.i	0x0; }
	{ st4	[r14],r37; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r1,0x0,r43; cmp.ltu	p07,p06,0x1,r8; (p07) br.cond.dptk.few	4000000000042970 }

l4000000000042AD0:
	{ nop.m	0x0; adds	r35,0x1,r35; br.cond.sptk.few	40000000000428E0 }

l4000000000042AE0:
	{ ld4	r14,[r37]; or	r14,0x1,r14; nop.i	0x0; }
	{ st4	[r14],r37; nop.i	0x0; br.cond.sptk.few	4000000000042950 }

l4000000000042B00:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r8; nop.i	0x0; }
	{ (p07) adds	r14,0x0,r8; nop.i	0x0; (p07) br.cond.spnt.few	40000000000429D0; }

l4000000000042B16:
	{ chk.a.nc	f0,3FFFFFFFFF043316; nop; break.i	0x80000 }

l4000000000042B20:
	{ nop.m	0x0; adds	r35,0x1,r35; br.cond.sptk.few	40000000000428E0; }
4000000000042B30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; make_word: 4000000000042B40
;;   Called from:
;;     4000000000021F2C (in fn4000000000021EC0)
;;     4000000000036D1C (in fn4000000000036A40)
;;     4000000000042BFC (in make_word_from_token)
;;     4000000000042D8C (in fn4000000000042D40)
;;     400000000008E1BC (in split_at_delims)
;;     400000000008E5BC (in split_at_delims)
;;     400000000008E71C (in split_at_delims)
;;     400000000009313C (in list_string)
;;     400000000009313C (in list_string)
;;     40000000000A7AEC (in fn40000000000A7940)
;;     40000000000A846C (in fn40000000000A7940)
;;     40000000000A84EC (in fn40000000000A7940)
;;     40000000000C1C5C (in fn40000000000C14C0)
;;     40000000000C20BC (in array_keys)
;;     40000000000E376C (in fn40000000000E3740)
;;     40000000000E381C (in fn40000000000E3740)
;;     40000000000E395C (in fn40000000000E3740)
;;     40000000000E399C (in fn40000000000E3740)
;;     40000000000E39FC (in fn40000000000E3740)
;;     40000000000E3A6C (in fn40000000000E3740)
;;     40000000001019EC (in fn40000000001019C0)
;;     4000000000101A2C (in fn40000000001019C0)
;;     4000000000103F5C (in get_directory_stack)
;;     400000000010402C (in get_directory_stack)
;;     400000000010409C (in get_directory_stack)
;;     400000000010413C (in get_directory_stack)
;;     400000000010C25C (in set_or_show_attributes)
;;     40000000001142EC (in shopt_setopt)
make_word proc
	{ alloc	r35,ar.pfs,0x6,0x0,0x5; mov	r34,b2; nop.b	0x0 }
	{ adds	r36,0x0,r1; adds	r37,0x0,r32; adds	r33,0x0,r32; }
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,make_bare_word; }
	{ adds	r1,0x0,r36; adds	r32,0x0,r8; mov.spnt	b0,r34,4000000000042B70; }
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	make_word_flags; }
4000000000042BA0 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
4000000000042BB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; make_word_from_token: 4000000000042BC0
;;   Called from:
;;     4000000000036FCC (in fn4000000000036A40)
make_word_from_token proc
	{ alloc	r34,ar.pfs,0x5,0x0,0x4; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r33,b1 }
	{ adds	r35,0x0,r1; adds	r14,0x10,r12; nop.i	0x0; }
	{ adds	r36,0x0,r14; st1	[r14],r1,1; nop.i	0x0; }
	{ st1	[r0],r14; nop.i	0x0; br.call.sptk.many	b0,make_word; }
	{ adds	r1,0x0,r35; mov.i	ar.pfs,r34; mov.spnt	b0,r33,4000000000042C00 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0; }
4000000000042C20 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000042C30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; make_word_list: 4000000000042C40
;;   Called from:
;;     4000000000021F4C (in fn4000000000021EC0)
;;     4000000000033A0C (in fn4000000000030880)
;;     400000000003652C (in fn4000000000030880)
;;     400000000003D91C (in parse_string_to_word_list)
;;     4000000000042DDC (in fn4000000000042D40)
;;     4000000000043F4C (in make_simple_command)
;;     400000000006F23C (in copy_word_list)
;;     400000000008E1DC (in split_at_delims)
;;     400000000008E5DC (in split_at_delims)
;;     400000000008E73C (in split_at_delims)
;;     400000000008FB4C (in list_rest_of_args)
;;     400000000008FBDC (in list_rest_of_args)
;;     4000000000092A3C (in list_string)
;;     400000000009315C (in list_string)
;;     400000000009315C (in list_string)
;;     400000000009328C (in list_string)
;;     40000000000A380C (in fn40000000000A1400)
;;     40000000000A3BDC (in fn40000000000A1400)
;;     40000000000A44BC (in fn40000000000A1400)
;;     40000000000A5B3C (in expand_prompt_string)
;;     40000000000A7B4C (in fn40000000000A7940)
;;     40000000000A84CC (in fn40000000000A7940)
;;     40000000000A850C (in fn40000000000A7940)
;;     40000000000A894C (in fn40000000000A7940)
;;     40000000000A8A3C (in fn40000000000A7940)
;;     40000000000BC63C (in array_to_word_list)
;;     40000000000BC7CC (in array_keys_to_word_list)
;;     40000000000C1C7C (in fn40000000000C14C0)
;;     40000000000C20DC (in array_keys)
;;     40000000000C228C (in fn40000000000C2180)
;;     40000000000C3C2C (in assoc_to_string)
;;     40000000000DE44C (in redirection_expand)
;;     40000000000E378C (in fn40000000000E3740)
;;     40000000000E37FC (in fn40000000000E3740)
;;     40000000000E383C (in fn40000000000E3740)
;;     40000000000E390C (in fn40000000000E3740)
;;     40000000000E397C (in fn40000000000E3740)
;;     40000000000E39BC (in fn40000000000E3740)
;;     40000000000E3A1C (in fn40000000000E3740)
;;     4000000000101A0C (in fn40000000001019C0)
;;     4000000000101A4C (in fn40000000001019C0)
;;     4000000000103F7C (in get_directory_stack)
;;     400000000010404C (in get_directory_stack)
;;     40000000001040BC (in get_directory_stack)
;;     400000000010415C (in get_directory_stack)
;;     400000000010C27C (in set_or_show_attributes)
;;     400000000011430C (in shopt_setopt)
;;     400000000011D27C (in complete_builtin)
;;     400000000011D2FC (in complete_builtin)
;;     400000000011E71C (in compopt_builtin)
;;     4000000000130B0C (in strvec_to_word_list)
;;     4000000000130BFC (in strvec_to_word_list)
make_word_list proc
	{ alloc	r35,ar.pfs,0x6,0x0,0x5; addl	r15,14028,r1; mov	r34,b2 }
	{ adds	r36,0x0,r1; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ adds	r16,0xC,r15; nop.m	0x0; mov.spnt	b0,r34,4000000000042C60; }
	{ nop.m	0x0; ld4	r14,[r16]; nop.i	0x0; }
	{ adds	r17,0xFFFFFFFFFFFFFFFF,r14; cmp4.lt	p07,p06,0x0,r14; (p06) br.cond.dpnt.few	4000000000042CE0; }

l4000000000042C90:
	{ nop.m	0x0; ld8	r14,[r15]; sxt4	r15,r17 }
	{ st4	[r17],r16; shladd	r14,r15,0x3,r14; nop.i	0x0; }
	{ nop.m	0x0; ld8	r8,[r14]; nop.i	0x0; }
	{ adds	r14,0x8,r8; nop.i	0x0; nop.i	0x0 }
	{ st8	[r33],r8; st8	[r32],r14; br.ret	b0; }

l4000000000042CE0:
	{ addl	r37,16,r0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r14,0x8,r8; adds	r1,0x0,r36; nop.b	0x0 }
	{ st8	[r33],r8; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ st8	[r32],r14; mov.spnt	b0,r34,4000000000042D10; br.ret	b0; }
4000000000042D20 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000042D30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn4000000000042D40: 4000000000042D40
;;   Called from:
;;     400000000004339C (in make_arith_for_command)
;;     400000000004339C (in make_arith_for_command)
;;     40000000000433BC (in make_arith_for_command)
;;     40000000000433EC (in make_arith_for_command)
;;     400000000004353C (in make_arith_for_command)
;;     40000000000435BC (in make_arith_for_command)
;;     400000000004361C (in make_arith_for_command)
fn4000000000042D40 proc
	{ alloc	r35,ar.pfs,0x6,0x0,0x5; mov	r34,b2; cmp.eq	p06,p07,0x0,r32 }
	{ adds	r36,0x0,r1; adds	r37,0x0,r32; (p06) br.cond.dpnt.few	4000000000042DE0; }

l4000000000042D60:
	{ ld1	r14,[r32]; adds	r33,0x0,r0; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000042DE0; }

l4000000000042D80:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,make_word; }
	{ adds	r14,0x8,r8; addl	r16,524338,r0; nop.b	0x0 }
	{ adds	r1,0x0,r36; adds	r32,0x0,r8; mov.spnt	b0,r34,4000000000042DA0; }
	{ ld4	r15,[r14]; mov.i	ar.pfs,r35; or	r15,r16,r15; }
	{ nop.m	0x0; st4	[r15],r14; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	make_word_list }

l4000000000042DE0:
	{ adds	r8,0x0,r0; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,4000000000042DF0; br.ret	b0; }

;; make_command: 4000000000042E00
;;   Called from:
;;     4000000000042EFC (in command_connect)
;;     4000000000042FDC (in make_for_command)
;;     400000000004309C (in make_select_command)
;;     400000000004334C (in make_arith_for_command)
;;     400000000004359C (in make_arith_for_command)
;;     40000000000436EC (in make_group_command)
;;     40000000000437EC (in make_case_command)
;;     400000000004397C (in make_if_command)
;;     4000000000043A3C (in make_while_command)
;;     4000000000043AFC (in make_until_command)
;;     4000000000044CBC (in make_function_def)
;;     4000000000044D7C (in make_subshell_command)
;;     4000000000044EAC (in make_coproc_command)
make_command proc
	{ alloc	r35,ar.pfs,0x6,0x0,0x5; mov	r34,b2; adds	r36,0x0,r1; }
	{ addl	r37,32,r0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r14,0x0,r8; adds	r16,0x4,r8; nop.b	0x0 }
	{ adds	r15,0x10,r8; adds	r1,0x0,r36; mov.i	ar.pfs,r35; }
	{ st4	[r14],r24,24; st4	[r0],r16; mov.spnt	b0,r34,4000000000042E40; }
	{ st8	[r33],r14; st4	[r0],r33; nop.i	0x0; }
	{ st8	[r0],r15; nop.i	0x0; br.ret	b0; }
4000000000042E70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; command_connect: 4000000000042E80
;;   Called from:
;;     4000000000045176 (in connect_async_list)
;;     400000000004529C (in connect_async_list)
;;     40000000000452DC (in connect_async_list)
command_connect proc
	{ alloc	r38,ar.pfs,0x9,0x0,0x8; mov	r37,b5; nop.b	0x0 }
	{ adds	r39,0x0,r1; adds	r36,0x0,r32; adds	r35,0x0,r33; }
	{ addl	r40,32,r0; addl	r32,6,r0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r39; adds	r17,0x18,r8; mov.spnt	b0,r37,4000000000042EB0 }
	{ adds	r16,0x8,r8; adds	r15,0x10,r8; adds	r33,0x0,r8; }
	{ st4	[r34],r17; st8	[r36],r16; mov.i	ar.pfs,r38; }
	{ nop.m	0x0; st8	[r35],r15; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x3,0x0,0x0; nop.i	0x0; br.cond.sptk.many	make_command; }
4000000000042F00 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
4000000000042F10 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000042F20 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000042F30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; make_for_command: 4000000000042F40
make_for_command proc
	{ alloc	r39,ar.pfs,0xA,0x0,0x9; mov	r38,b6; nop.b	0x0 }
	{ adds	r40,0x0,r1; adds	r37,0x0,r32; adds	r36,0x0,r33; }
	{ addl	r41,32,r0; adds	r32,0x0,r0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r15,0x0,r8; adds	r18,0x4,r8; adds	r17,0x10,r8 }
	{ adds	r16,0x18,r8; adds	r1,0x0,r40; adds	r33,0x0,r8; }
	{ nop.m	0x0; st4	[r15],r8,8; mov.spnt	b0,r38,4000000000042F90 }
	{ nop.m	0x0; st4	[r35],r18; nop.i	0x0; }
	{ st8	[r37],r15; st8	[r36],r17; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; st8	[r34],r16; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x4,0x0,0x0; nop.i	0x0; br.cond.sptk.many	make_command; }
4000000000042FE0 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
4000000000042FF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; make_select_command: 4000000000043000
make_select_command proc
	{ alloc	r39,ar.pfs,0xA,0x0,0x9; mov	r38,b6; nop.b	0x0 }
	{ adds	r40,0x0,r1; adds	r37,0x0,r32; adds	r36,0x0,r33; }
	{ addl	r41,32,r0; addl	r32,5,r0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r15,0x0,r8; adds	r18,0x4,r8; adds	r17,0x10,r8 }
	{ adds	r16,0x18,r8; adds	r1,0x0,r40; adds	r33,0x0,r8; }
	{ nop.m	0x0; st4	[r15],r8,8; mov.spnt	b0,r38,4000000000043050 }
	{ nop.m	0x0; st4	[r35],r18; nop.i	0x0; }
	{ st8	[r37],r15; st8	[r36],r17; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; st8	[r34],r16; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x4,0x0,0x0; nop.i	0x0; br.cond.sptk.many	make_command; }
40000000000430A0 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
40000000000430B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; make_arith_for_command: 40000000000430C0
make_arith_for_command proc
	{ alloc	r44,ar.pfs,0x11,0x0,0xE; adds	r41,0x8,r32; mov	r43,b3 }
	{ adds	r45,0x0,r1; nop.m	0x0; adds	r42,0x0,r33; }
	{ nop.m	0x0; ld8	r14,[r41]; adds	r36,0x0,r0 }
	{ adds	r38,0x0,r0; adds	r39,0x0,r0; adds	r40,0x0,r0; }
	{ ld8	r46,[r14]; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000043120:
	{ ld1	r14,[r46]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p09,p08,0x3B,r14; cmp4.eq	p11,p10,0x0,r14; cmp4.eq	p06,p07,0x20,r14; }
	{ (p08) addl	r17,1,r0; (p10) addl	r15,1,r0; cmp4.eq.or.andcm	p06,p07,0x9,r14; }

l4000000000043146:
	{ Invalid; (p03) br.call.dpnt.few	b1,4000000000D26A26; (p18) nop.b	0x4 }

l400000000004314C:
	{ (p04) nop; zxt1	r0,r64; Invalid }

l4000000000043156:
	{ addl	r0,49152,r1; (p07) nop; break.i	0x80000 }

l4000000000043160:
	{ nop.m	0x0; and	r15,r15,r17; (p06) br.cond.dptk.few	40000000000433D0; }

l4000000000043170:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r15; (p06) br.cond.dpnt.few	4000000000043400; }

l4000000000043180:
	{ adds	r15,0x1,r46; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l40000000000431A0:
	{ ld1	r14,[r15]; adds	r35,0x0,r15; adds	r15,0x1,r15; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p07,p06,0x0,r14; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p07,p06,0x3B,r14; (p06) br.cond.dptk.few	40000000000431A0; }

l40000000000431D0:
	{ adds	r37,0x0,r0; cmp.ltu	p07,p06,r46,r35; (p07) br.cond.dpnt.few	4000000000043350 }

l40000000000431E0:
	{ nop.m	0x0; adds	r36,0x1,r36; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x2,r36; (p06) br.cond.dpnt.few	4000000000043390; }

l4000000000043200:
	{ cmp4.eq	p06,p07,0x3,r36; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000433E0; }

l4000000000043210:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x1,r36; (p06) br.cond.dpnt.few	40000000000433B0; }

l4000000000043220:
	{ cmp.eq	p06,p07,0x0,r37; adds	r46,0x0,r37; (p06) br.cond.dpnt.few	4000000000043250; }

l4000000000043230:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r45; nop.m	0x0; nop.i	0x0 }

l4000000000043250:
	{ ld1	r14,[r35]; adds	r46,0x1,r35; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dptk.few	4000000000043120; }

l4000000000043270:
	{ cmp4.eq	p06,p07,0x3,r36; addl	r46,40,r0; (p07) br.cond.dpnt.few	4000000000043410; }

l4000000000043280:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r14,0x0,r8; adds	r33,0x0,r8; cmp.eq	p07,p06,0x0,r40 }
	{ adds	r1,0x0,r45; st4	[r14],r4,4; nop.i	0x0; }
	{ st4	[r34],r14; adds	r14,0x8,r33; (p07) br.cond.dpnt.few	4000000000043600; }

l40000000000432C0:
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r39; nop.i	0x0 }
	{ st8	[r40],r14; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000435A0; }

l40000000000432E0:
	{ adds	r14,0x10,r33; nop.m	0x0; cmp.eq	p07,p06,0x0,r38; }
	{ st8	[r39],r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000043520 }

l4000000000043300:
	{ adds	r15,0x18,r33; nop.m	0x0; adds	r14,0x20,r33 }
	{ adds	r46,0x0,r32; addl	r32,12,r0; nop.i	0x0 }
	{ st8	[r38],r15; st8	[r42],r14; br.call.sptk.many	b0,dispose_words; }
	{ adds	r1,0x0,r45; mov.spnt	b0,r43,4000000000043330; mov.i	ar.pfs,r44; }
	{ alloc	r2,ar.pfs,0x3,0x0,0x0; nop.i	0x0; br.cond.sptk.many	make_command; }

l4000000000043350:
	{ adds	r47,0x0,r0; nop.m	0x0; adds	r36,0x1,r36 }
	{ sub	r48,r35,r46; nop.m	0x0; br.call.sptk.many	b0,substring; }
	{ nop.m	0x0; adds	r1,0x0,r45; adds	r37,0x0,r8 }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x2,r36; (p07) br.cond.dptk.few	4000000000043200; }

l4000000000043390:
	{ adds	r46,0x0,r37; nop.i	0x0; br.call.sptk.many	b0,fn4000000000042D40; }
	{ adds	r1,0x0,r45; adds	r39,0x0,r8; br.cond.sptk.few	4000000000043220 }

l40000000000433B0:
	{ adds	r46,0x0,r37; nop.i	0x0; br.call.sptk.many	b0,fn4000000000042D40; }
	{ adds	r1,0x0,r45; adds	r40,0x0,r8; br.cond.sptk.few	4000000000043220 }

l40000000000433D0:
	{ nop.m	0x0; adds	r46,0x1,r46; br.cond.sptk.few	4000000000043120; }

l40000000000433E0:
	{ adds	r46,0x0,r37; nop.i	0x0; br.call.sptk.many	b0,fn4000000000042D40; }
	{ adds	r1,0x0,r45; adds	r38,0x0,r8; br.cond.sptk.few	4000000000043220 }

l4000000000043400:
	{ adds	r35,0x0,r46; adds	r37,0x0,r0; br.cond.sptk.few	40000000000431E0 }

l4000000000043410:
	{ cmp4.lt	p06,p07,0x2,r36; addl	r48,5,r0; adds	r46,0x0,r0; }
	{ (p07) addl	r47,-9564,r1; (p06) addl	r47,-9556,r1; nop.i	0x0; }

l4000000000043426:
	{ Invalid; nop; Invalid; }

l400000000004342C:
	{ nop; cmp4.eq.or.andcm	p00,p32,r32,r0; Invalid }

l400000000004343C:
	{ cmp4.eq.or.andcm	p00,p17,r1,r0; Invalid; break.i	0x1000 }

l4000000000043446:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ break.m	0x4000; (p23) nop; (p48) nop }
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ Invalid; (p24) nop; break.i	0x80000 }
	{ Invalid; nop; (p48) br.call.sptk.few	b3,b0 }
	{ break.m	0x4000; (p32) nop; (p32) nop }
	{ add	r0,r0,r1; nop; (p48) nop }
	{ break.m	0x4000; (p23) nop; nop }
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ Invalid; nop; nop.b	0x2 }
	{ break.m	0x4000; nop; (p32) nop }
	{ break.m	0x4000; nop; break.i	0x80000 }
	{ break.m	0x4000; nop; nop }
	{ break.m	0x4000; (p34) nop; break.i	0x80000 }

l4000000000043520:
	{ nop.m	0x0; addl	r46,-9540,r1; nop.i	0x0; }
	{ ld8	r46,[r46]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000042D40; }
	{ adds	r15,0x18,r33; adds	r38,0x0,r8; adds	r14,0x20,r33 }
	{ adds	r1,0x0,r45; adds	r46,0x0,r32; addl	r32,12,r0; }
	{ nop.m	0x0; st8	[r38],r15; nop.i	0x0 }
	{ st8	[r42],r14; nop.m	0x0; br.call.sptk.many	b0,dispose_words; }
	{ adds	r1,0x0,r45; mov.spnt	b0,r43,4000000000043580; mov.i	ar.pfs,r44; }
	{ alloc	r2,ar.pfs,0x3,0x0,0x0; nop.i	0x0; br.cond.sptk.many	make_command }

l40000000000435A0:
	{ nop.m	0x0; addl	r46,-9540,r1; nop.i	0x0; }
	{ ld8	r46,[r46]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000042D40; }
	{ adds	r14,0x10,r33; nop.m	0x0; adds	r39,0x0,r8 }
	{ adds	r1,0x0,r45; nop.m	0x0; cmp.eq	p07,p06,0x0,r38; }
	{ st8	[r39],r14; nop.i	0x0; (p06) br.cond.dptk.few	4000000000043300 }

l40000000000435F0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000043520 }

l4000000000043600:
	{ nop.m	0x0; addl	r46,-9540,r1; nop.i	0x0; }
	{ ld8	r46,[r46]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000042D40; }
	{ adds	r14,0x8,r33; nop.m	0x0; adds	r40,0x0,r8 }
	{ adds	r1,0x0,r45; nop.m	0x0; cmp.eq	p07,p06,0x0,r39; }
	{ st8	[r40],r14; nop.i	0x0; (p06) br.cond.dptk.few	40000000000432E0 }

l4000000000043650:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000435A0; }
4000000000043660 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000043670 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; make_group_command: 4000000000043680
make_group_command proc
	{ alloc	r36,ar.pfs,0x7,0x0,0x6; nop.m	0x0; mov	r35,b3 }
	{ adds	r37,0x0,r1; nop.m	0x0; adds	r34,0x0,r32; }
	{ addl	r38,16,r0; addl	r32,9,r0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r37; adds	r14,0x8,r8; nop.b	0x0 }
	{ adds	r33,0x0,r8; nop.m	0x0; mov.spnt	b0,r35,40000000000436C0; }
	{ st8	[r34],r14; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	make_command; }
40000000000436F0 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................

;; make_case_command: 4000000000043700
make_case_command proc
	{ alloc	r39,ar.pfs,0xA,0x0,0x9; mov	r38,b6; nop.b	0x0 }
	{ adds	r40,0x0,r1; adds	r35,0x0,r33; adds	r37,0x0,r32; }
	{ addl	r41,24,r0; addl	r32,1,r0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r14,0x0,r8; adds	r15,0x8,r8; adds	r1,0x0,r40 }
	{ adds	r36,0x0,r8; cmp.eq	p06,p07,0x0,r33; adds	r41,0x0,r33; }
	{ nop.m	0x0; st4	[r14],r4,4; adds	r33,0x0,r8 }
	{ nop.m	0x0; st8	[r37],r15; nop.i	0x0; }
	{ st4	[r34],r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000437C0; }

l4000000000043780:
	{ nop.m	0x0; ld8	r14,[r35]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000437C0; }

l40000000000437A0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,list_reverse; }
	{ nop.m	0x0; adds	r1,0x0,r40; adds	r35,0x0,r8 }

l40000000000437C0:
	{ adds	r36,0x10,r36; nop.m	0x0; mov.spnt	b0,r38,40000000000437C0; }
	{ st8	[r35],r36; nop.m	0x0; mov.i	ar.pfs,r39; }
	{ alloc	r2,ar.pfs,0x3,0x0,0x0; nop.i	0x0; br.cond.sptk.many	make_command; }
40000000000437F0 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................

;; make_pattern_list: 4000000000043800
make_pattern_list proc
	{ alloc	r36,ar.pfs,0x7,0x0,0x6; mov	r35,b3; adds	r37,0x0,r1; }
	{ addl	r38,32,r0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r37; adds	r34,0x0,r8; nop.i	0x0 }
	{ cmp.eq	p06,p07,0x0,r32; adds	r38,0x0,r32; (p06) br.cond.dpnt.few	4000000000043880; }

l4000000000043840:
	{ nop.m	0x0; ld8	r14,[r32]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000043880; }

l4000000000043860:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,list_reverse; }
	{ nop.m	0x0; adds	r1,0x0,r37; adds	r32,0x0,r8 }

l4000000000043880:
	{ adds	r14,0x0,r34; adds	r16,0x8,r34; nop.b	0x0 }
	{ adds	r15,0x10,r34; adds	r8,0x0,r34; mov.i	ar.pfs,r36; }
	{ st8	[r14],r24,24; st8	[r32],r16; mov.spnt	b0,r35,40000000000438A0; }
	{ nop.m	0x0; st8	[r33],r15; nop.i	0x0 }
	{ st4	[r0],r14; nop.m	0x0; br.ret	b0; }
40000000000438D0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000438E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000438F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; make_if_command: 4000000000043900
make_if_command proc
	{ alloc	r38,ar.pfs,0x9,0x0,0x8; mov	r37,b5; nop.b	0x0 }
	{ adds	r39,0x0,r1; adds	r35,0x0,r32; adds	r36,0x0,r33; }
	{ addl	r40,32,r0; addl	r32,3,r0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r15,0x0,r8; adds	r17,0x10,r8; mov.spnt	b0,r37,4000000000043930 }
	{ adds	r16,0x18,r8; adds	r1,0x0,r39; adds	r33,0x0,r8; }
	{ st4	[r15],r8,8; st8	[r36],r17; mov.i	ar.pfs,r38; }
	{ st8	[r35],r15; st8	[r34],r16; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x3,0x0,0x0; nop.i	0x0; br.cond.sptk.many	make_command; }
4000000000043980 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
4000000000043990 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000439A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000439B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; make_while_command: 40000000000439C0
make_while_command proc
	{ alloc	r37,ar.pfs,0x8,0x0,0x7; mov	r36,b4; nop.b	0x0 }
	{ adds	r38,0x0,r1; adds	r34,0x0,r32; adds	r35,0x0,r33; }
	{ addl	r39,24,r0; addl	r32,2,r0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r14,0x0,r8; adds	r16,0x10,r8; nop.b	0x0 }
	{ adds	r1,0x0,r38; adds	r33,0x0,r8; mov.spnt	b0,r36,4000000000043A00; }
	{ st4	[r14],r8,8; st8	[r35],r16; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; st8	[r34],r14; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	make_command; }
4000000000043A40 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
4000000000043A50 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000043A60 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000043A70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; make_until_command: 4000000000043A80
make_until_command proc
	{ alloc	r37,ar.pfs,0x8,0x0,0x7; mov	r36,b4; nop.b	0x0 }
	{ adds	r38,0x0,r1; adds	r34,0x0,r32; adds	r35,0x0,r33; }
	{ addl	r39,24,r0; addl	r32,8,r0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r14,0x0,r8; adds	r16,0x10,r8; nop.b	0x0 }
	{ adds	r1,0x0,r38; adds	r33,0x0,r8; mov.spnt	b0,r36,4000000000043AC0; }
	{ st4	[r14],r8,8; st8	[r35],r16; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; st8	[r34],r14; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	make_command; }
4000000000043B00 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
4000000000043B10 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000043B20 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000043B30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; make_arith_command: 4000000000043B40
make_arith_command proc
	{ alloc	r35,ar.pfs,0x6,0x0,0x5; mov	r34,b2; adds	r36,0x0,r1; }
	{ addl	r37,32,r0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r36; nop.m	0x0; adds	r33,0x0,r8 }
	{ addl	r37,16,r0; nop.m	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r18,0x18,r33; adds	r16,0x0,r8; mov.i	ar.pfs,r35 }
	{ adds	r1,0x0,r36; adds	r14,0x0,r33; adds	r8,0x0,r33; }
	{ nop.m	0x0; st8	[r16],r18; adds	r15,0x0,r16 }
	{ adds	r17,0x8,r16; addl	r16,6648,r1; adds	r33,0x4,r33; }
	{ nop.m	0x0; st8	[r32],r17; mov.spnt	b0,r34,4000000000043BC0; }
	{ ld4	r16,[r16]; st4	[r15],r4,4; nop.i	0x0; }
	{ nop.m	0x0; st4	[r16],r15; addl	r15,10,r0 }
	{ st4	[r0],r33; st4	[r14],r16,16; nop.i	0x0; }
	{ st8	[r0],r14; nop.i	0x0; br.ret	b0; }
4000000000043C10 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000043C20 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000043C30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; make_cond_node: 4000000000043C40
;;   Called from:
;;     4000000000036C7C (in fn4000000000036A40)
;;     4000000000036D3C (in fn4000000000036A40)
;;     4000000000036DBC (in fn4000000000036A40)
;;     400000000003708C (in fn4000000000036A40)
;;     40000000000370AC (in fn4000000000036A40)
;;     400000000003717C (in fn4000000000036A40)
;;     400000000003719C (in fn4000000000036A40)
;;     4000000000037A0C (in fn4000000000037980)
;;     4000000000037ACC (in fn4000000000037A40)
make_cond_node proc
	{ alloc	r37,ar.pfs,0x8,0x0,0x7; mov	r36,b4; adds	r38,0x0,r1; }
	{ addl	r39,40,r0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r38; adds	r15,0x0,r8; adds	r19,0x8,r8 }
	{ adds	r18,0x10,r8; adds	r17,0x18,r8; adds	r14,0x20,r8; }
	{ addl	r16,6648,r1; st4	[r15],r4,4; nop.b	0x0 }
	{ st4	[r32],r19; nop.m	0x0; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; st8	[r33],r18; nop.b	0x0 }
	{ st8	[r34],r17; nop.m	0x0; mov.spnt	b0,r36,4000000000043CB0; }
	{ st8	[r35],r14; ld4	r16,[r16]; nop.i	0x0; }
	{ st4	[r16],r15; nop.i	0x0; br.ret	b0; }
4000000000043CE0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000043CF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; make_cond_command: 4000000000043D00
;;   Called from:
;;     400000000003578C (in fn4000000000030880)
make_cond_command proc
	{ alloc	r34,ar.pfs,0x5,0x0,0x4; mov	r33,b1; adds	r35,0x0,r1; }
	{ addl	r36,32,r0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r14,0x0,r8; addl	r17,11,r0; adds	r15,0x4,r8 }
	{ cmp.eq	p06,p07,0x0,r32; adds	r18,0x4,r32; adds	r16,0x18,r8; }
	{ st4	[r14],r16,16; st4	[r0],r15; nop.b	0x0 }
	{ (p06) adds	r15,0x0,r0; adds	r1,0x0,r35; mov.i	ar.pfs,r34; }

l4000000000043D56:
	{ Invalid; nop; br.call.spnt.few	b0,b0 }
	{ Invalid; nop; nop }
	{ break.m	0x4000; nop; cmp.lt	p00,p00,r0,r32 }
	{ (p07) fwb; nop; br.call.spnt.many	b0,b3; }

l4000000000043D8C:
	{ Invalid; Invalid; add	r0,r32,r0 }
	{ nop; break.m	0x1000; break.i	0x1000 }
4000000000043DA0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000043DB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; make_bare_simple_command: 4000000000043DC0
;;   Called from:
;;     400000000004408C (in make_simple_command)
;;     40000000000ED0FC (in command_builtin)
;;     40000000000FF3AC (in jobs_builtin)
make_bare_simple_command proc
	{ alloc	r34,ar.pfs,0x5,0x0,0x4; mov	r33,b1; adds	r35,0x0,r1; }
	{ addl	r36,32,r0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r35; nop.m	0x0; adds	r32,0x0,r8 }
	{ addl	r36,24,r0; nop.m	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r18,0x18,r32; adds	r14,0x0,r8; mov.i	ar.pfs,r34 }
	{ adds	r1,0x0,r35; adds	r15,0x0,r32; adds	r8,0x0,r32; }
	{ st8	[r14],r18; addl	r18,6648,r1; mov.spnt	b0,r33,4000000000043E20 }
	{ adds	r16,0x0,r14; adds	r17,0x8,r14; adds	r14,0x10,r14; }
	{ nop.m	0x0; st8	[r0],r14; nop.i	0x0 }
	{ addl	r14,4,r0; st8	[r0],r17; adds	r32,0x4,r32; }
	{ ld4	r18,[r18]; st4	[r16],r4,4; nop.i	0x0; }
	{ st4	[r18],r16; st4	[r15],r16,16; nop.i	0x0; }
	{ nop.m	0x0; st8	[r0],r15; nop.i	0x0 }
	{ st4	[r0],r32; nop.m	0x0; br.ret	b0; }
4000000000043EA0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000043EB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; make_simple_command: 4000000000043EC0
make_simple_command proc
	{ alloc	r38,ar.pfs,0xA,0x0,0x8; adds	r12,0xFFFFFFFFFFFFFFF0,r12; mov	r37,b5 }
	{ adds	r39,0x0,r1; adds	r35,0x0,r32; adds	r36,0x0,r33; }
	{ adds	r14,0x10,r12; nop.m	0x0; cmp.eq	p07,p06,0x0,r34; }
	{ nop.m	0x0; st8	[r14],r8,8; nop.i	0x0; }
	{ st8	[r33],r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000044080 }

l4000000000043F10:
	{ adds	r14,0x18,r34; nop.m	0x0; cmp.eq	p06,p07,0x0,r35 }
	{ adds	r40,0x0,r35; nop.m	0x0; (p06) br.cond.dpnt.few	4000000000043FC0; }

l4000000000043F30:
	{ ld8	r35,[r14]; adds	r35,0x8,r35; nop.i	0x0; }
	{ ld8	r41,[r35]; nop.i	0x0; br.call.sptk.many	b0,make_word_list; }
	{ nop.m	0x0; adds	r1,0x0,r39; addl	r16,-524289,r0 }
	{ st8	[r8],r35; addl	r14,8944,r1; nop.i	0x0; }
	{ nop.m	0x0; ld4	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; and	r15,r16,r15; nop.i	0x0; }
	{ st4	[r15],r14; nop.m	0x0; nop.i	0x0 }

l4000000000043FA0:
	{ adds	r8,0x0,r34; mov.i	ar.pfs,r38; mov.spnt	b0,r37,4000000000043FA0 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l4000000000043FC0:
	{ cmp.eq	p06,p07,0x0,r36; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000043FA0; }

l4000000000043FD0:
	{ (p07) adds	r15,0x0,r36; ld8	r14,[r15]; nop.i	0x0; }

l4000000000043FD6:
	{ (p07) fwb; nop; break.i	0x80000 }
	{ (p03) chk.a.clr	f0,3FFFFFFFFFCC70C6; nop; break.b	0x80000 }

l4000000000043FF0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000044000:
	{ adds	r15,0x0,r14; ld8	r14,[r15]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	4000000000044000 }

l4000000000044020:
	{ adds	r14,0x18,r34; nop.m	0x0; adds	r8,0x0,r34; }
	{ ld8	r14,[r14]; adds	r14,0x10,r14; nop.i	0x0; }
	{ nop.m	0x0; ld8	r16,[r14]; nop.i	0x0; }
	{ st8	[r16],r15; st8	[r36],r14; mov.i	ar.pfs,r38; }
	{ nop.m	0x0; mov.spnt	b0,r37,4000000000044060; nop.i	0x0 }
	{ adds	r12,0x10,r12; nop.m	0x0; br.ret	b0; }

l4000000000044080:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,make_bare_simple_command; }
	{ adds	r1,0x0,r39; addl	r16,524288,r0; adds	r34,0x0,r8; }
	{ addl	r14,8944,r1; nop.m	0x0; nop.i	0x0; }
	{ ld4	r15,[r14]; or	r15,r16,r15; nop.i	0x0; }
	{ st4	[r15],r14; nop.i	0x0; br.cond.sptk.few	4000000000043F10; }
40000000000440D0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000440E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000440F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; make_here_document: 4000000000044100
;;   Called from:
;;     400000000002686C (in gather_here_documents)
make_here_document proc
	{ alloc	r48,ar.pfs,0x16,0x0,0x13; adds	r34,0x18,r32; mov	r50,pr }
	{ adds	r46,0x20,r32; adds	r49,0x0,r1; addl	r36,6648,r1; }
	{ ld4	r14,[r34]; addl	r41,7376,r1; mov	r47,b7 }
	{ addl	r45,-10652,r1; adds	r52,0x0,r0; adds	r37,0x0,r0; }
	{ cmp4.eq	p07,p06,0x4,r14; cmp4.eq	p09,p08,0x8,r14; cmp4.eq	p16,p17,0x8,r14 }
	{ nop.m	0x0; adds	r38,0x0,r0; adds	r40,0x0,r0; }
	{ (p06) addl	r15,1,r0; nop.m	0x0; (p08) addl	r14,1,r0 }

l4000000000044166:
	{ Invalid; (p07) nop; break.i	0x80000 }

l4000000000044170:
	{ nop.m	0x0; ld8	r45,[r45]; nop.i	0x0; }
	{ (p07) adds	r15,0x0,r0; (p09) adds	r14,0x0,r0; and	r14,r14,r15; }

l4000000000044186:
	{ Invalid; (p07) nop; (p32) nop }

l400000000004418C:
	{ (p07) cmp.lt	p15,p17,r12,r64; czx1.r	r64,r97; mov	pr,r32,0x0; }
	{ (p41) nop; cmp.lt	p00,p00,r32,r0; (p01) rfi }

l40000000000441A0:
	{ nop.m	0x0; ld8	r14,[r46]; nop.i	0x0; }
	{ ld8	r51,[r14]; nop.i	0x0; br.call.sptk.many	b0,string_quote_removal; }
	{ cmp.eq	p06,p07,0x0,r8; adds	r1,0x0,r49; nop.i	0x0 }
	{ adds	r43,0x0,r8; adds	r51,0x0,r8; (p06) br.cond.dpnt.few	4000000000044720; }

l40000000000441E0:
	{ adds	r32,0x28,r32; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ ld8	r14,[r46]; adds	r1,0x0,r49; sxt4	r44,r8 }
	{ nop.m	0x0; cmp4.eq	p18,p19,0x0,r8; nop.i	0x0; }
	{ ld8	r51,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; ld8	r14,[r46]; adds	r1,0x0,r49 }
	{ st8	[r43],r32; adds	r14,0x8,r14; nop.i	0x0; }
	{ ld4	r42,[r14]; nop.m	0x0; tbit.z	p06,p07,r42,0x1; }
	{ (p06) addl	r42,1,r0; nop.i	0x0; (p07) adds	r42,0x0,r0; }

l4000000000044256:
	{ chk.a.nc	f0,3FFFFFFFFF044A56; (p21) nop; (p48) nop }

l4000000000044260:
	{ adds	r51,0x0,r42; nop.i	0x0; br.call.sptk.many	b0,read_secondary_line; }
	{ nop.m	0x0; adds	r35,0x0,r8; adds	r1,0x0,r49 }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r8; (p07) br.cond.dpnt.few	4000000000044400 }

l4000000000044290:
	{ ld4	r15,[r36]; ld4	r14,[r41]; nop.i	0x0; }
	{ adds	r15,0x1,r15; nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; }
	{ st4	[r15],r36; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000444C0; }

l40000000000442C0:
	{ nop.m	0x0; ld1	r34,[r35]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r34,r34; (p16) br.cond.dpnt.few	4000000000044500; }

l40000000000442E0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r34; (p06) br.cond.dpnt.few	4000000000044260 }

l40000000000442F0:
	{ nop.m	0x0; nop.i	0x0; (p18) br.cond.dptk.few	4000000000044600 }

l4000000000044300:
	{ ld1	r14,[r43]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r14,r34; (p07) br.cond.dpnt.few	40000000000445D0 }

l4000000000044320:
	{ adds	r51,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ cmp4.eq	p08,p09,0x0,r37; nop.m	0x0; add	r39,r8,r38 }
	{ adds	r1,0x0,r49; nop.m	0x0; adds	r34,0x0,r8; }
	{ nop.m	0x0; cmp4.lt	p06,p07,r39,r37; (p06) br.cond.dptk.few	40000000000443A0 }

l4000000000044360:
	{ add	r37,r37,r8; adds	r51,0x0,r40; (p09) shladd	r37,r37,0x1,r0; }

l4000000000044370:
	{ nop.m	0x0; (p08) adds	r37,0x2,r8; nop.i	0x0; }

l400000000004437C:
	{ Invalid; add	r0,r32,r0; (p06) break.i	0x164A0 }
	{ (p20) nop; nop; zxt1	r32,r64 }
	{ invala; break.x	0x80000164C0; }

l40000000000443A0:
	{ nop.m	0x0; sxt4	r51,r38; nop.b	0x0 }
	{ adds	r52,0x0,r35; adds	r38,0x0,r39; sxt4	r53,r34; }
	{ add	r51,r40,r51; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A8A0; }
	{ adds	r1,0x0,r49; adds	r51,0x0,r42; br.call.sptk.many	b0,read_secondary_line; }
	{ nop.m	0x0; adds	r1,0x0,r49; adds	r35,0x0,r8 }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	4000000000044290; }

l4000000000044400:
	{ addl	r52,-9524,r1; adds	r51,0x0,r0; addl	r53,5,r0; }
	{ ld8	r52,[r52]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r49; adds	r51,0x0,r8; nop.i	0x0 }
	{ adds	r52,0x0,r33; adds	r53,0x0,r43; br.call.sptk.many	b0,internal_warning; }
	{ adds	r1,0x0,r49; nop.m	0x0; nop.i	0x0 }

l4000000000044450:
	{ nop.m	0x0; sxt4	r38,r38; cmp.eq	p06,p07,0x0,r40 }
	{ nop.m	0x0; nop.m	0x0; (p06) br.cond.spnt.few	4000000000044750; }

l4000000000044470:
	{ ld8.a	r14,[r46]; nop.m	0x0; add	r38,r40,r38; }
	{ st1	[r0],r38; ld8.c.clr	r14,[r46]; nop.i	0x0 }
	{ nop.m	0x0; st8	[r40],r14; nop.i	0x0 }

l40000000000444A0:
	{ nop.m	0x0; mov	pr,r50,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r48; }
	{ nop.m	0x0; mov.spnt	b0,r47,40000000000444B0; br.ret	b0; }

l40000000000444C0:
	{ nop.m	0x0; adds	r51,0x0,r35; nop.i	0x0 }
	{ ld8	r52,[r45]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001C260; }
	{ ld1	r34,[r35]; nop.m	0x0; adds	r1,0x0,r49; }
	{ nop.m	0x0; sxt1	r34,r34; (p17) br.cond.dptk.few	40000000000442E0; }

l4000000000044500:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r34; (p06) br.cond.dptk.few	4000000000044260 }

l4000000000044510:
	{ nop.m	0x0; nop.i	0x0; (p18) br.cond.dptk.few	4000000000044680 }

l4000000000044520:
	{ ld1	r14,[r43]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r14,r34; (p07) br.cond.dpnt.few	4000000000044640; }

l4000000000044540:
	{ adds	r14,0x1,r35; cmp4.eq	p07,p06,0x9,r34; (p06) br.cond.dpnt.few	40000000000442F0; }

l4000000000044550:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000044560:
	{ adds	r35,0x0,r14; ld1	r34,[r14],1; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r34,r34; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x9,r34; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000442E0; }

l4000000000044590:
	{ adds	r35,0x0,r14; ld1	r34,[r14],1; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r34,r34; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x9,r34; (p06) br.cond.dptk.few	4000000000044560 }

l40000000000445C0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000442E0 }

l40000000000445D0:
	{ adds	r52,0x0,r43; nop.m	0x0; adds	r53,0x0,r44 }
	{ adds	r51,0x0,r35; nop.m	0x0; br.call.sptk.many	b0,fn400000000001C020; }
	{ adds	r1,0x0,r49; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	4000000000044320; }

l4000000000044600:
	{ add	r14,r35,r44; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0xA,r14; (p07) br.cond.dptk.few	4000000000044320 }

l4000000000044630:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000044450 }

l4000000000044640:
	{ adds	r51,0x0,r35; nop.m	0x0; adds	r52,0x0,r43 }
	{ adds	r53,0x0,r44; nop.m	0x0; br.call.sptk.many	b0,fn400000000001C020; }
	{ adds	r1,0x0,r49; cmp4.eq	p07,p06,0x0,r8; (p06) br.cond.dptk.few	4000000000044540; }

l4000000000044670:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000044680:
	{ add	r14,r35,r44; ld1	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0xA,r14; (p07) br.cond.dptk.few	4000000000044540 }

l40000000000446B0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000044450 }

l40000000000446C0:
	{ addl	r52,-9532,r1; addl	r53,5,r0; adds	r51,0x0,r0; }
	{ ld8	r52,[r52]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r49; nop.m	0x0; adds	r51,0x0,r8 }
	{ ld4	r52,[r34]; nop.m	0x0; br.call.sptk.many	b0,internal_error; }
	{ adds	r1,0x0,r49; mov	pr,r50,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r48; }
	{ nop.m	0x0; mov.spnt	b0,r47,4000000000044710; br.ret	b0; }

l4000000000044720:
	{ addl	r51,1,r0; adds	r32,0x28,r32; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r49; st8	[r8],r32; nop.i	0x0 }
	{ st1	[r0],r8; nop.m	0x0; nop.i	0x0 }

l4000000000044750:
	{ addl	r51,1,r0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ ld8.a	r14,[r46]; st1	[r0],r8; adds	r40,0x0,r8 }
	{ adds	r1,0x0,r49; ld8.c.clr	r14,[r46]; nop.i	0x0; }
	{ st8	[r40],r14; nop.i	0x0; br.cond.sptk.few	40000000000444A0; }
4000000000044790 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000447A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000447B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; make_redirection: 40000000000447C0
;;   Called from:
;;     40000000000DE7DC (in fn40000000000DE580)
;;     40000000000DF24C (in fn40000000000DE580)
;;     40000000000DF58C (in fn40000000000DE580)
;;     40000000000DFCBC (in fn40000000000DE580)
;;     40000000000E093C (in fn40000000000DE580)
;;     40000000000E096C (in fn40000000000DE580)
make_redirection proc
	{ alloc	r41,ar.pfs,0xE,0x0,0xB; adds	r12,0xFFFFFFFFFFFFFFF0,r12; nop.b	0x0 }
	{ adds	r42,0x0,r1; nop.m	0x0; mov	r40,b0; }
	{ addl	r43,48,r0; nop.i	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r38,0x20,r8; adds	r37,0x18,r8; adds	r14,0x14,r8 }
	{ adds	r16,0x8,r8; adds	r15,0x10,r8; adds	r1,0x0,r42; }
	{ adds	r36,0x0,r8; nop.m	0x0; cmp4.ltu	p06,p07,0x13,r33 }
	{ st8	[r32],r16; st8	[r34],r38; nop.i	0x0; }
	{ st4	[r33],r37; st4	[r0],r14; nop.i	0x0; }
	{ nop.m	0x0; st4	[r35],r15; nop.i	0x0 }
	{ st8	[r0],r8; nop.m	0x0; (p07) br.cond.dptk.few	40000000000448B0 }

l4000000000044860:
	{ addl	r44,-9516,r1; addl	r45,5,r0; adds	r43,0x0,r0; }
	{ ld8	r44,[r44]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r42; nop.m	0x0; adds	r43,0x0,r8 }
	{ adds	r44,0x0,r33; nop.m	0x0; br.call.sptk.many	b0,programming_error; }
	{ nop.m	0x0; adds	r1,0x0,r42; br.call.sptk.many	b0,fn400000000001C1A0; }

l40000000000448B0:
	{ addl	r15,-9492,r1; nop.m	0x0; addp4	r16,r33,r0; }
	{ ld8	r15,[r15]; shladd	r15,r16,0x3,r15; nop.i	0x0; }
	{ ld8	r16,[r15]; add	r15,r15,r16; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b6,r15,40000000000448E0; br.cond	b6; }
40000000000448F0 09 00 00 00 01 00 70 02 88 30 20 00 00 00 04 00 ......p..0 .....
4000000000044900 11 58 01 4E 00 21 00 00 00 02 00 00 C8 6D FD 58 .X.N.!.......m.X
4000000000044910 03 40 FC 11 3F 23 10 00 A8 00 42 C0 01 40 58 00 .@..?#....B..@X.
4000000000044920 0B 38 9D 1C 00 20 E0 00 9C 00 20 00 00 00 04 00 .8... .... .....
4000000000044930 01 00 00 00 01 00 E0 00 38 28 00 00 00 00 04 00 ........8(......
4000000000044940 10 00 00 00 01 00 70 68 39 0C 73 03 E0 00 00 42 ......ph9.s....B
4000000000044950 09 00 00 00 01 00 00 00 9C 00 23 00 00 00 04 00 ..........#.....
4000000000044960 11 58 01 44 18 10 00 00 00 02 00 00 A8 AA FF 58 .X.D...........X
4000000000044970 10 08 00 54 00 21 60 00 20 0E 73 03 60 01 00 42 ...T.!`. .s.`..B
4000000000044980 11 58 01 44 18 10 C0 82 30 00 42 00 08 AB FF 58 .X.D....0.B....X
4000000000044990 10 08 00 54 00 21 60 00 20 0E 73 03 40 01 00 42 ...T.!`. .s.@..B
40000000000449A0 0B 78 40 18 00 21 E0 00 3C 30 20 00 00 00 04 00 .x@..!..<0 .....
40000000000449B0 01 00 00 00 01 00 F0 00 38 2C 00 00 00 00 04 00 ........8,......
40000000000449C0 10 00 00 00 01 00 70 78 38 0C 70 03 10 01 00 42 ......px8.p....B
40000000000449D0 11 58 01 44 00 21 00 00 00 02 00 00 F8 6C 00 50 .X.D.!.......l.P
40000000000449E0 09 38 34 42 86 39 F0 80 30 00 42 20 00 50 01 84 .84B.9..0.B .P..
40000000000449F0 C9 08 41 00 00 24 E0 00 3C 30 20 00 00 00 04 00 ..A..$..<0 .....
4000000000044A00 08 00 00 00 01 C0 11 7A 00 00 48 00 00 00 04 00 .......z..H.....
4000000000044A10 0B 00 38 4C 90 11 00 08 95 20 23 00 00 00 04 00 ..8L..... #.....
4000000000044A20 02 40 00 48 00 21 00 48 01 55 00 00 80 0A 00 07 .@.H.!.H.U......
4000000000044A30 18 00 00 00 01 00 C0 80 30 00 42 80 08 00 84 00 ........0.B.....
4000000000044A40 09 78 04 01 08 24 00 00 00 02 00 00 01 20 01 84 .x...$....... ..
4000000000044A50 02 00 3C 1C 90 11 00 48 01 55 00 00 80 0A 00 07 ..<....H.U......
4000000000044A60 18 00 00 00 01 00 C0 80 30 00 42 80 08 00 84 00 ........0.B.....
4000000000044A70 09 78 08 01 00 24 00 00 00 02 00 00 01 20 01 84 .x...$....... ..
4000000000044A80 02 00 3C 1C 90 11 00 48 01 55 00 00 80 0A 00 07 ..<....H.U......
4000000000044A90 18 00 00 00 01 00 C0 80 30 00 42 80 08 00 84 00 ........0.B.....
4000000000044AA0 09 78 04 01 04 24 00 00 00 02 00 00 01 20 01 84 .x...$....... ..
4000000000044AB0 02 00 3C 1C 90 11 00 48 01 55 00 00 80 0A 00 07 ..<....H.U......
4000000000044AC0 18 00 00 00 01 00 C0 80 30 00 42 80 08 00 84 00 ........0.B.....
4000000000044AD0 03 38 34 42 86 39 80 00 90 00 42 23 24 01 00 90 .84B.9....B#$...
4000000000044AE0 09 00 00 00 01 C0 11 8A 00 00 48 00 00 00 04 00 ..........H.....
4000000000044AF0 02 00 84 4A 90 11 00 48 01 55 00 00 80 0A 00 07 ...J...H.U......
4000000000044B00 19 00 00 00 01 00 C0 80 30 00 42 80 08 00 84 00 ........0.B.....
4000000000044B10 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000044B20 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000044B30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; make_function_def: 4000000000044B40
make_function_def proc
	{ alloc	r40,ar.pfs,0xC,0x0,0xA; nop.m	0x0; mov	r39,b7 }
	{ adds	r41,0x0,r1; nop.m	0x0; adds	r38,0x0,r32; }
	{ addl	r42,32,r0; addl	r32,7,r0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r41; adds	r37,0x0,r8; adds	r14,0x8,r33 }
	{ adds	r15,0x4,r8; adds	r17,0x10,r8; adds	r16,0x8,r8; }
	{ nop.m	0x0; st4	[r37],r24,24; addl	r42,-9508,r1 }
	{ adds	r36,0x0,r8; st8	[r33],r17; adds	r33,0x0,r8; }
	{ st4	[r34],r15; st8	[r38],r16; nop.i	0x0 }
	{ ld8	r42,[r42]; st4	[r35],r14; nop.i	0x0 }
	{ st8	[r0],r37; nop.m	0x0; br.call.sptk.many	b0,find_variable; }
	{ adds	r14,0x28,r8; adds	r1,0x0,r41; nop.i	0x0 }
	{ cmp.eq	p06,p07,0x0,r8; adds	r15,0x8,r8; (p06) br.cond.dpnt.few	4000000000044C80; }

l4000000000044C00:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x2; (p06) br.cond.dptk.few	4000000000044C80 }

l4000000000044C20:
	{ ld8	r14,[r15]; adds	r43,0x0,r0; adds	r15,0x10,r14 }
	{ cmp.eq	p06,p07,0x0,r14; adds	r42,0x0,r14; (p06) br.cond.spnt.few	4000000000044C80; }

l4000000000044C40:
	{ nop.m	0x0; ld4	r14,[r15]; nop.i	0x0; }
	{ cmp4.lt	p07,p06,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000044C80; }

l4000000000044C60:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,array_reference; }
	{ adds	r1,0x0,r41; st8	[r8],r37; nop.i	0x0 }

l4000000000044C80:
	{ ld8	r42,[r38]; adds	r43,0x0,r36; br.call.sptk.many	b0,bind_function_def; }
	{ nop.m	0x0; adds	r1,0x0,r41; mov.spnt	b0,r39,4000000000044C90 }
	{ st8	[r0],r37; nop.m	0x0; mov.i	ar.pfs,r40; }
	{ alloc	r2,ar.pfs,0x4,0x0,0x0; nop.i	0x0; br.cond.sptk.many	make_command; }
4000000000044CC0 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
4000000000044CD0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000044CE0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000044CF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; make_subshell_command: 4000000000044D00
make_subshell_command proc
	{ alloc	r36,ar.pfs,0x7,0x0,0x6; nop.m	0x0; mov	r35,b3 }
	{ adds	r37,0x0,r1; nop.m	0x0; adds	r34,0x0,r32; }
	{ addl	r38,16,r0; addl	r32,13,r0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r15,0x8,r8; adds	r1,0x0,r37; nop.b	0x0 }
	{ adds	r33,0x0,r8; nop.m	0x0; mov.spnt	b0,r35,4000000000044D40; }
	{ st8	[r34],r15; addl	r15,1,r0; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; st4	[r15],r8; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	make_command; }
4000000000044D80 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
4000000000044D90 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000044DA0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000044DB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; make_coproc_command: 4000000000044DC0
make_coproc_command proc
	{ alloc	r38,ar.pfs,0xA,0x0,0x8; mov	r37,b5; nop.b	0x0 }
	{ adds	r39,0x0,r1; adds	r35,0x0,r32; adds	r36,0x0,r33; }
	{ addl	r40,24,r0; addl	r32,14,r0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r39; nop.m	0x0; adds	r34,0x0,r8 }
	{ adds	r40,0x0,r35; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r39; nop.m	0x0; adds	r40,0x1,r8 }
	{ adds	r33,0x0,r34; nop.m	0x0; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r39; nop.m	0x0; adds	r40,0x0,r8 }
	{ adds	r41,0x0,r35; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r14,0x10,r34; adds	r15,0x8,r34; nop.b	0x0 }
	{ adds	r1,0x0,r39; nop.m	0x0; mov.spnt	b0,r37,4000000000044E60; }
	{ st8	[r36],r14; addl	r14,4097,r0; nop.b	0x0 }
	{ st8	[r8],r15; nop.m	0x0; mov.i	ar.pfs,r38; }
	{ nop.m	0x0; st4	[r14],r34; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	make_command; }
4000000000044EB0 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................

;; clean_simple_command: 4000000000044EC0
clean_simple_command proc
	{ alloc	r37,ar.pfs,0xB,0x0,0x7; ld4	r41,[r32]; nop.b	0x0 }
	{ adds	r35,0x18,r32; adds	r38,0x0,r1; mov	r36,b4; }
	{ cmp4.eq	p06,p07,0x4,r41; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000045030; }

l4000000000044EF0:
	{ ld8	r33,[r35]; adds	r34,0x8,r33; nop.i	0x0; }
	{ nop.m	0x0; ld8	r39,[r34]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r39; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000044F70; }

l4000000000044F20:
	{ nop.m	0x0; ld8	r14,[r39]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000044F70; }

l4000000000044F40:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,list_reverse; }
	{ adds	r1,0x0,r38; nop.m	0x0; adds	r39,0x0,r8 }
	{ ld8	r33,[r35]; nop.m	0x0; nop.i	0x0; }

l4000000000044F70:
	{ adds	r33,0x10,r33; st8	[r39],r34; nop.i	0x0; }
	{ nop.m	0x0; ld8	r39,[r33]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r39; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000044FE0; }

l4000000000044FA0:
	{ nop.m	0x0; ld8	r14,[r39]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000044FE0; }

l4000000000044FC0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,list_reverse; }
	{ nop.m	0x0; adds	r1,0x0,r38; adds	r39,0x0,r8; }

l4000000000044FE0:
	{ addl	r14,8944,r1; addl	r16,-524289,r0; nop.b	0x0 }
	{ adds	r8,0x0,r32; st8	[r39],r33; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; nop.m	0x0; mov.spnt	b0,r36,4000000000045000; }
	{ ld4	r15,[r14]; and	r15,r16,r15; nop.i	0x0; }
	{ st4	[r15],r14; nop.i	0x0; br.ret	b0 }

l4000000000045030:
	{ addl	r39,-9500,r1; addl	r40,1,r0; adds	r42,0x0,r0; }
	{ ld8	r39,[r39]; nop.i	0x0; br.call.sptk.many	b0,command_error; }
	{ adds	r1,0x0,r38; addl	r16,-524289,r0; nop.b	0x0 }
	{ adds	r8,0x0,r32; nop.m	0x0; mov.i	ar.pfs,r37; }
	{ addl	r14,8944,r1; nop.m	0x0; mov.spnt	b0,r36,4000000000045070; }
	{ nop.m	0x0; ld4	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; and	r15,r16,r15; nop.i	0x0; }
	{ st4	[r15],r14; nop.i	0x0; br.ret	b0; }
40000000000450B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; connect_async_list: 40000000000450C0
connect_async_list proc
	{ alloc	r38,ar.pfs,0xB,0x0,0x8; adds	r14,0x18,r32; nop.b	0x0 }
	{ adds	r16,0x4,r32; mov	r37,b5; adds	r39,0x0,r1; }
	{ ld8	r14,[r14]; adds	r35,0x0,r32; adds	r41,0x0,r33 }
	{ adds	r42,0x0,r34; adds	r15,0x10,r14; adds	r14,0x18,r14; }
	{ nop.m	0x0; ld8	r15,[r15]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r15; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000045160; }

l4000000000045120:
	{ nop.m	0x0; ld4	r16,[r16]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p07,p06,r16,0x0; (p06) br.cond.dpnt.few	4000000000045160; }

l4000000000045140:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x3B,r14; (p07) br.cond.dpnt.few	4000000000045180 }

l4000000000045160:
	{ nop.m	0x0; mov.spnt	b0,r37,4000000000045160; mov.i	ar.pfs,r38; }
	{ alloc	r2,ar.pfs,0x3,0x0,0x0; nop.i	0x0; br.cond.sptk.many	command_connect }

l4000000000045180:
	{ nop.m	0x0; movl	r17,0x1FFFFFFFF }
	{ ld8	r14,[r15]; adds	r16,0x18,r15; and	r14,r17,r14; }
	{ cmp.eq	p07,p06,0x6,r14; nop.i	0x0; (p06) br.cond.dpnt.few	40000000000452D0; }

l40000000000451B0:
	{ ld8	r14,[r16]; adds	r16,0x18,r14; adds	r14,0x10,r14; }
	{ nop.m	0x0; ld4	r16,[r16]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x3B,r16; nop.i	0x0; (p07) br.cond.dpnt.few	40000000000452D0; }

l40000000000451E0:
	{ ld8	r40,[r14]; adds	r16,0x18,r40; nop.i	0x0; }
	{ ld8	r14,[r40]; and	r14,r17,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x6,r14; (p06) br.cond.dpnt.few	4000000000045290; }

l4000000000045210:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000045220:
	{ ld8	r14,[r16]; adds	r16,0x18,r14; adds	r14,0x10,r14; }
	{ nop.m	0x0; ld4	r16,[r16]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x3B,r16; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000045290; }

l4000000000045250:
	{ adds	r15,0x0,r40; ld8	r40,[r14]; nop.i	0x0; }
	{ adds	r16,0x18,r40; ld8	r14,[r40]; nop.i	0x0; }
	{ nop.m	0x0; and	r14,r17,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x6,r14; (p07) br.cond.dptk.few	4000000000045220 }

l4000000000045290:
	{ adds	r36,0x0,r15; nop.i	0x0; br.call.sptk.many	b0,command_connect; }
	{ adds	r14,0x18,r36; adds	r1,0x0,r39; mov.i	ar.pfs,r38; }
	{ ld8	r14,[r14]; mov.spnt	b0,r37,40000000000452B0; adds	r14,0x10,r14; }
	{ st8	[r8],r14; adds	r8,0x0,r35; br.ret	b0; }

l40000000000452D0:
	{ adds	r36,0x0,r35; adds	r40,0x0,r15; br.call.sptk.many	b0,command_connect; }
	{ adds	r14,0x18,r36; adds	r1,0x0,r39; mov.i	ar.pfs,r38; }
	{ ld8	r14,[r14]; mov.spnt	b0,r37,40000000000452F0; adds	r14,0x10,r14; }
	{ st8	[r8],r14; adds	r8,0x0,r35; br.ret	b0; }
4000000000045310 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
4000000000045320 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
4000000000045330 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........
4000000000045340 0B 70 20 03 36 24 00 00 38 20 23 C0 01 0C D8 90 .p .6$..8 #.....
4000000000045350 09 00 00 1C 90 11 00 00 00 02 00 C0 41 0C D8 90 ............A...
4000000000045360 09 00 00 1C 90 11 00 00 00 02 00 C0 41 0B D8 90 ............A...
4000000000045370 11 00 00 1C 98 11 00 00 00 02 00 80 08 00 84 00 ................

;; fn4000000000045380: 4000000000045380
;;   Called from:
;;     400000000004550C (in fn4000000000045480)
;;     40000000000455AC (in fn4000000000045480)
;;     40000000000457EC (in fn4000000000045480)
fn4000000000045380 proc
	{ alloc	r35,ar.pfs,0x7,0x0,0x5; addl	r33,6948,r1; mov	r34,b2 }
	{ addl	r15,6940,r1; addl	r14,6944,r1; adds	r36,0x0,r1; }
	{ ld8	r37,[r33]; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ cmp.eq	p07,p06,0x0,r37; mov.spnt	b0,r34,40000000000453B0; (p07) br.cond.dpnt.few	4000000000045430; }

l40000000000453C0:
	{ ld4	r16,[r15]; ld4	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; add	r32,r32,r16; nop.i	0x0; }
	{ cmp4.lt	p06,p07,r32,r15; (p07) br.cond.dpnt.few	40000000000453F0; br.ret	b0 }

l40000000000453EC:
	{ Invalid; (p04) cmp.lt	p00,p16,r40,r64; zxt2	r0,r11 }

l40000000000453F0:
	{ adds	r32,0x80,r32; and	r38,0xFFFFFFFFFFFFFF80,r32; nop.i	0x0; }
	{ st4	[r38],r14; sxt4	r38,r38; br.call.sptk.many	b0,xrealloc; }
	{ adds	r1,0x0,r36; st8	[r8],r33; mov.i	ar.pfs,r35; }
	{ nop.m	0x0; mov.spnt	b0,r34,4000000000045420; br.ret	b0 }

l4000000000045430:
	{ adds	r32,0x3F,r32; and	r37,0xFFFFFFFFFFFFFFC0,r32; nop.i	0x0; }
	{ st4	[r37],r14; sxt4	r37,r37; br.call.sptk.many	b0,xmalloc; }
	{ adds	r1,0x0,r36; st8	[r8],r33; mov.i	ar.pfs,r35; }
	{ addl	r14,6940,r1; nop.m	0x0; mov.spnt	b0,r34,4000000000045460; }
	{ st4	[r0],r14; nop.i	0x0; br.ret	b0; }

;; fn4000000000045480: 4000000000045480
;;   Called from:
;;     4000000000045A6C (in fn4000000000045A00)
;;     4000000000045C5C (in fn4000000000045B80)
;;     4000000000045C9C (in fn4000000000045B80)
;;     4000000000045CBC (in fn4000000000045B80)
;;     4000000000045D0C (in fn4000000000045B80)
;;     4000000000045D5C (in fn4000000000045B80)
;;     4000000000045DAC (in fn4000000000045B80)
;;     4000000000045DEC (in fn4000000000045B80)
;;     4000000000045E6C (in fn4000000000045B80)
;;     4000000000045EDC (in fn4000000000045B80)
;;     4000000000045EFC (in fn4000000000045B80)
;;     4000000000045F9C (in fn4000000000045B80)
;;     40000000000460AC (in fn4000000000045FC0)
;;     40000000000461AC (in fn4000000000046180)
;;     400000000004624C (in fn4000000000046180)
;;     40000000000471AC (in fn40000000000470C0)
;;     400000000004729C (in fn40000000000470C0)
;;     40000000000472EC (in fn40000000000470C0)
;;     400000000004890C (in print_for_command_head)
;;     4000000000048ACC (in print_select_command_head)
;;     4000000000048C7C (in print_case_command_head)
;;     4000000000048DEC (in print_arith_command)
;;     4000000000048E3C (in print_arith_command)
;;     4000000000048EBC (in print_cond_command)
;;     4000000000048EEC (in print_cond_command)
;;     40000000000495AC (in print_simple_command)
;;     400000000004971C (in fn4000000000049600)
;;     40000000000497CC (in fn4000000000049600)
;;     400000000004981C (in fn4000000000049600)
;;     400000000004985C (in fn4000000000049600)
;;     400000000004ABFC (in fn4000000000049600)
;;     400000000004B25C (in named_function_string)
;;     400000000004B2BC (in named_function_string)
;;     400000000004B30C (in named_function_string)
;;     400000000004B46C (in named_function_string)
;;     400000000004B48C (in named_function_string)
;;     400000000004B4EC (in named_function_string)
;;     400000000004B53C (in named_function_string)
fn4000000000045480 proc
	{ alloc	r50,ar.pfs,0x1A,0x0,0x15; adds	r16,0x8,r12; adds	r17,0x0,r12 }
	{ adds	r12,0xFFFFFFFFFFFFFFB0,r12; addl	r46,6940,r1; addl	r47,6948,r1; }
	{ mov.m	r52,UNAT; st8.spill	[r16],r112,-16; mov	r49,b1 }
	{ adds	r51,0x0,r1; adds	r53,0x0,r32; adds	r41,0x1C,r12; }
	{ st8.spill	[r17],r112,-16; st8.spill	[r16],r112,-16; adds	r40,0x0,r32 }
	{ adds	r48,0x28,r12; st8.spill	[r17],r112,-16; nop.i	0x0 }
	{ st8.spill	[r16],r112,-16; st8.spill	[r34],r17; nop.i	0x0 }
	{ st8.spill	[r33],r16; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r51; adds	r53,0x1,r8; br.call.sptk.many	b0,fn4000000000045380; }
	{ adds	r14,0x1D,r12; adds	r1,0x0,r51; cmp.eq	p07,p06,0x0,r32; }
	{ st1	[r0],r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000045640; }

l4000000000045530:
	{ nop.m	0x0; ld1	r14,[r32]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; cmp4.eq	p06,p07,0x0,r14; }
	{ (p06) addl	r46,6940,r1; (p06) addl	r47,6948,r1; (p06) br.cond.dpnt.few	4000000000045640; }

l4000000000045556:
	{ (p23) chk.a.clr	r36,3FFFFFFFFF260566; nop; (p32) nop.b	0x2802A; }

l400000000004555C:
	{ (p07) ld4	r0,[r33]; (p21) cmp.eq	p00,p16,r10,r64; (p16) nop }

l4000000000045560:
	{ adds	r42,0x1,r40; cmp4.eq	p07,p06,0x25,r14; (p07) br.cond.dpnt.few	4000000000045680 }

l4000000000045570:
	{ st1	[r14],r41; nop.m	0x0; nop.i	0x0 }

l4000000000045580:
	{ nop.m	0x0; addl	r45,1,r0; addl	r53,2,r0 }
	{ nop.m	0x0; addl	r44,1,r0; adds	r43,0x0,r41; }

l40000000000455A0:
	{ adds	r40,0x0,r42; nop.i	0x0; br.call.sptk.many	b0,fn4000000000045380; }
	{ ld4	r15,[r46]; adds	r1,0x0,r51; adds	r54,0x0,r43 }
	{ adds	r55,0x0,r45; ld8	r14,[r47]; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r53,r15; nop.i	0x0; }
	{ add	r53,r14,r53; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A8A0; }
	{ ld4	r14,[r46]; adds	r1,0x0,r51; cmp.eq	p06,p07,0x0,r42; }
	{ nop.m	0x0; add	r44,r14,r44; nop.i	0x0; }
	{ st4	[r44],r46; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000045640 }

l4000000000045620:
	{ ld1	r14,[r40]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	4000000000045560 }

l4000000000045640:
	{ ld4	r14,[r46]; ld8	r15,[r47]; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r14,r14; add	r14,r15,r14; }
	{ st1	[r0],r14; mov.i	ar.pfs,r50; mov.spnt	b0,r49,4000000000045660 }
	{ mov.m	UNAT,r52; adds	r12,0x50,r12; br.ret	b0 }

l4000000000045680:
	{ ld1	r43,[r42]; nop.m	0x0; sxt1	r43,r43; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r43; (p07) br.cond.dptk.few	4000000000045570; }

l40000000000456A0:
	{ cmp4.eq	p06,p07,0x64,r43; adds	r40,0x2,r40; (p06) br.cond.dpnt.few	40000000000458C0; }

l40000000000456B0:
	{ nop.m	0x0; cmp4.lt	p06,p07,0x64,r43; (p06) br.cond.dptk.few	4000000000045750; }

l40000000000456C0:
	{ cmp4.eq	p06,p07,0x25,r43; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000045870; }

l40000000000456D0:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x63,r43; (p06) br.cond.dpnt.few	40000000000458A0 }

l40000000000456E0:
	{ addl	r54,-5516,r1; addl	r55,5,r0; adds	r53,0x0,r0; }
	{ ld8	r54,[r54]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r51; nop.m	0x0; adds	r53,0x0,r8 }
	{ adds	r54,0x0,r43; nop.m	0x0; br.call.sptk.many	b0,programming_error; }
	{ ld1	r14,[r40]; adds	r1,0x0,r51; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dptk.few	4000000000045560 }

l4000000000045740:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000045640; }

l4000000000045750:
	{ nop.m	0x0; cmp4.eq	p06,p07,0x73,r43; (p07) br.cond.dptk.few	40000000000456E0 }

l4000000000045760:
	{ ld8	r43,[r48]; nop.m	0x0; adds	r48,0x8,r48; }
	{ adds	r53,0x0,r43; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ cmp.eq	p07,p06,0x0,r43; adds	r44,0x0,r8; adds	r1,0x0,r51; }
	{ (p06) addl	r14,1,r0; (p07) adds	r14,0x0,r0; cmp4.eq	p07,p06,0x0,r44; }

l4000000000045796:
	{ Invalid; Invalid; (p49) nop; }

l400000000004579C:
	{ cmp4.eq.or.andcm	p44,p03,r6,r115; (p17) dep	r0,r0,r0,62,3; (p05) cmp4.ne.or.andcm	p00,p48,r3,r64 }

l40000000000457A6:
	{ Invalid; (p07) nop; break.i	0x80000 }

l40000000000457B0:
	{ nop.m	0x0; and	r14,r42,r15; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.sptk.few	4000000000045620 }

l40000000000457D0:
	{ adds	r53,0x1,r44; nop.m	0x0; sxt4	r45,r44 }
	{ adds	r42,0x0,r40; nop.m	0x0; br.call.sptk.many	b0,fn4000000000045380; }
	{ ld4	r15,[r46]; adds	r1,0x0,r51; adds	r54,0x0,r43 }
	{ adds	r55,0x0,r45; ld8	r14,[r47]; adds	r40,0x0,r42; }
	{ nop.m	0x0; sxt4	r53,r15; nop.i	0x0; }
	{ add	r53,r14,r53; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A8A0; }
	{ ld4	r14,[r46]; adds	r1,0x0,r51; cmp.eq	p06,p07,0x0,r42; }
	{ nop.m	0x0; add	r44,r14,r44; nop.i	0x0; }
	{ st4	[r44],r46; nop.i	0x0; (p07) br.cond.dptk.few	4000000000045620 }

l4000000000045860:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000045640 }

l4000000000045870:
	{ st1	[r14],r41; adds	r42,0x0,r40; addl	r45,1,r0 }
	{ addl	r53,2,r0; addl	r44,1,r0; adds	r43,0x0,r41; }
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000455A0 }

l40000000000458A0:
	{ ld4	r14,[r48]; adds	r42,0x0,r40; adds	r48,0x8,r48; }
	{ st1	[r14],r41; nop.i	0x0; br.cond.sptk.few	4000000000045580 }

l40000000000458C0:
	{ ld4	r53,[r48]; nop.m	0x0; adds	r48,0x8,r48 }
	{ adds	r54,0x10,r12; nop.m	0x0; addl	r55,12,r0; }
	{ cmp4.lt	p07,p06,r53,r0; sxt4	r53,r53; (p07) br.cond.dpnt.few	4000000000045980; }

l40000000000458F0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,inttostr; }
	{ cmp.eq	p07,p06,0x0,r8; adds	r43,0x0,r8; adds	r1,0x0,r51; }
	{ (p06) addl	r14,1,r0; adds	r53,0x0,r43; (p07) adds	r14,0x0,r0; }

l4000000000045916:
	{ (p26) chk.a.clr	f0,3FFFFFFFFF0C5BC6; (p07) nop; (p32) nop.b	0xE00A }

l4000000000045920:
	{ adds	r42,0x0,r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ nop.m	0x0; adds	r1,0x0,r51; adds	r44,0x0,r8; }

l4000000000045940:
	{ cmp4.eq	p07,p06,0x0,r44; (p06) addl	r15,1,r0; nop.i	0x0; }

l400000000004594C:
	{ cmp4.eq.or.andcm	p00,p43,r1,r0; (p01) cmp.lt	p00,p16,r0,r64; zxt1	r106,r3 }

l4000000000045956:
	{ Invalid; nop; break.i	0x80000 }
	{ (p03) chk.a.clr	r0,3FFFFFFFFFD09246; nop; break.i	0x80000 }

l4000000000045970:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000457D0 }

l4000000000045980:
	{ adds	r53,0x10,r12; addl	r56,-5524,r1; addl	r54,1,r0 }
	{ addl	r55,12,r0; addl	r57,-1,r0; addl	r42,1,r0; }
	{ ld8	r56,[r56]; adds	r43,0x0,r53; br.call.sptk.many	b0,fn400000000001C440; }
	{ adds	r1,0x0,r51; adds	r53,0x0,r43; br.call.sptk.many	b0,fn400000000001B6C0; }
	{ adds	r1,0x0,r51; adds	r44,0x0,r8; br.cond.sptk.few	4000000000045940; }
40000000000459D0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000459E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000459F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn4000000000045A00: 4000000000045A00
;;   Called from:
;;     400000000004893C (in print_for_command_head)
;;     4000000000048AFC (in print_select_command_head)
;;     4000000000048E1C (in print_arith_command)
;;     400000000004957C (in print_simple_command)
fn4000000000045A00 proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x5; adds	r36,0x0,r1; mov	r34,b2 }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r32; (p07) br.cond.dpnt.few	4000000000045A90; }

l4000000000045A20:
	{ ld8	r39,[r32]; adds	r14,0x8,r32; addl	r37,-5500,r1; }
	{ cmp.eq	p07,p06,0x0,r39; ld8	r14,[r14]; nop.i	0x0 }
	{ ld8	r37,[r37]; (p07) addl	r39,-5508,r1; nop.i	0x0; }

l4000000000045A4C:
	{ cmp4.eq.or.andcm	p00,p09,r1,r0; (p04) cmp.lt	p32,p16,r8,r64; Invalid }

l4000000000045A56:
	{ (p19) fwb; cmp4.eq	p00,p00,r0,r1; (p49) nop }

l4000000000045A66:
	{ break.m	0x4000; (p32) nop; nop }
	{ add	r0,r0,r1; nop; break.i	0x80000 }
	{ (p03) chk.a.clr	r0,3FFFFFFFFFCC8C86; mov	pr,0x4AFFFFA; break.b	0x80000 }

l4000000000045A90:
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r34,4000000000045AA0; br.ret	b0; }
4000000000045AB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000045AC0 09 80 04 02 80 05 E0 E0 04 6C 48 00 C4 E8 57 9F .........lH...W.
4000000000045AD0 09 70 00 1C 10 10 00 02 80 30 20 00 00 00 04 00 .p.......0 .....
4000000000045AE0 08 38 00 1C 86 31 00 00 00 02 00 E0 01 70 58 00 .8...1.......pX.
4000000000045AF0 19 70 90 02 36 24 00 00 00 02 00 03 50 00 00 43 .p..6$......P..C
4000000000045B00 0B 70 00 1C 18 10 F0 70 3C 00 40 00 00 00 04 00 .p.....p<.@.....
4000000000045B10 0B 78 FC 1F 3F 23 E0 00 3C 00 20 00 00 00 04 00 .x..?#..<. .....
4000000000045B20 03 00 00 00 01 00 E0 00 38 28 00 C0 60 72 1C E6 ........8(..`r..
4000000000045B30 11 00 00 00 01 00 60 50 38 8E 73 83 08 00 84 03 ......`P8.s.....
4000000000045B40 11 10 04 00 80 05 00 00 00 02 00 00 48 F9 FF 48 ............H..H
4000000000045B50 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
4000000000045B60 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000045B70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn4000000000045B80: 4000000000045B80
;;   Called from:
;;     4000000000045C3C (in fn4000000000045B80)
;;     4000000000045D8C (in fn4000000000045B80)
;;     4000000000045DCC (in fn4000000000045B80)
;;     4000000000045E4C (in fn4000000000045B80)
;;     4000000000048ECC (in print_cond_command)
fn4000000000045B80 proc
	{ alloc	r35,ar.pfs,0x7,0x0,0x5; ld4	r14,[r32]; mov	r34,b2 }
	{ nop.m	0x0; adds	r36,0x0,r1; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x2; (p07) br.cond.dpnt.few	4000000000045CF0; }

l4000000000045BB0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000045BC0:
	{ adds	r14,0x8,r32; nop.m	0x0; adds	r15,0x18,r32; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x6,r14; (p07) br.cond.dpnt.few	4000000000045D40; }

l4000000000045BF0:
	{ cmp4.eq	p07,p06,0x1,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000045DB0; }

l4000000000045C00:
	{ cmp4.eq	p07,p06,0x2,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000045E30; }

l4000000000045C10:
	{ cmp4.eq	p07,p06,0x3,r14; nop.i	0x0; (p07) br.cond.dpnt.few	4000000000045EB0; }

l4000000000045C20:
	{ cmp4.eq	p07,p06,0x4,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000045F40; }

l4000000000045C30:
	{ ld8	r37,[r15]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000045B80; }
	{ adds	r1,0x0,r36; addl	r37,-5436,r1; nop.i	0x0; }
	{ ld8	r37,[r37]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000045480; }
	{ adds	r14,0x10,r32; adds	r1,0x0,r36; adds	r32,0x20,r32; }
	{ ld8	r14,[r14]; nop.m	0x0; addl	r37,-5444,r1; }
	{ nop.m	0x0; ld8	r37,[r37]; nop.i	0x0; }
	{ ld8	r38,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000045480; }
	{ adds	r1,0x0,r36; addl	r37,-5436,r1; nop.i	0x0; }
	{ ld8	r37,[r37]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000045480; }
	{ ld8	r32,[r32]; nop.m	0x0; adds	r1,0x0,r36; }
	{ nop.m	0x0; ld4	r14,[r32]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x2; (p06) br.cond.dptk.few	4000000000045BC0 }

l4000000000045CF0:
	{ nop.m	0x0; addl	r37,-5484,r1; nop.i	0x0; }
	{ ld8	r37,[r37]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000045480; }
	{ adds	r14,0x8,r32; adds	r1,0x0,r36; adds	r15,0x18,r32; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x6,r14; (p06) br.cond.dptk.few	4000000000045BF0 }

l4000000000045D40:
	{ nop.m	0x0; addl	r37,-5476,r1; nop.i	0x0; }
	{ ld8	r37,[r37]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000045480; }
	{ adds	r1,0x0,r36; nop.m	0x0; adds	r14,0x18,r32; }
	{ addl	r32,-5468,r1; ld8	r37,[r14]; nop.i	0x0; }
	{ ld8	r32,[r32]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000045B80; }
	{ adds	r1,0x0,r36; mov.spnt	b0,r34,4000000000045D90; mov.i	ar.pfs,r35; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn4000000000045480 }

l4000000000045DB0:
	{ adds	r14,0x18,r32; nop.m	0x0; adds	r32,0x20,r32; }
	{ ld8	r37,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000045B80; }
	{ adds	r1,0x0,r36; addl	r37,-5460,r1; nop.i	0x0; }
	{ ld8	r37,[r37]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000045480; }
	{ ld8	r32,[r32]; nop.m	0x0; adds	r1,0x0,r36; }
	{ nop.m	0x0; ld4	r14,[r32]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x2; (p06) br.cond.dptk.few	4000000000045BC0 }

l4000000000045E20:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000045CF0 }

l4000000000045E30:
	{ adds	r14,0x18,r32; nop.m	0x0; adds	r32,0x20,r32; }
	{ ld8	r37,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000045B80; }
	{ adds	r1,0x0,r36; addl	r37,-5452,r1; nop.i	0x0; }
	{ ld8	r37,[r37]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000045480; }
	{ ld8	r32,[r32]; nop.m	0x0; adds	r1,0x0,r36; }
	{ nop.m	0x0; ld4	r14,[r32]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x2; (p06) br.cond.dptk.few	4000000000045BC0 }

l4000000000045EA0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000045CF0 }

l4000000000045EB0:
	{ adds	r14,0x10,r32; addl	r37,-5444,r1; adds	r32,0x18,r32; }
	{ ld8	r14,[r14]; ld8	r37,[r37]; nop.i	0x0; }
	{ ld8	r38,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000045480; }
	{ adds	r1,0x0,r36; addl	r37,-5436,r1; nop.i	0x0; }
	{ ld8	r37,[r37]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000045480; }
	{ ld8	r32,[r32]; nop.m	0x0; adds	r1,0x0,r36; }
	{ nop.m	0x0; ld4	r14,[r32]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x2; (p06) br.cond.dptk.few	4000000000045BC0 }

l4000000000045F30:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000045CF0; }

l4000000000045F40:
	{ cmp4.eq	p07,p06,0x5,r14; mov.i	ar.pfs,r35; (p07) br.cond.dpnt.few	4000000000045F60; }

l4000000000045F50:
	{ nop.m	0x0; mov.spnt	b0,r34,4000000000045F50; br.ret	b0; }

l4000000000045F60:
	{ adds	r14,0x10,r32; addl	r32,-5444,r1; mov.spnt	b0,r34,4000000000045F60; }
	{ nop.m	0x0; ld8	r14,[r14]; mov.i	ar.pfs,r35 }
	{ ld8	r32,[r32]; ld8	r33,[r14]; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn4000000000045480; }
4000000000045FA0 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
4000000000045FB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn4000000000045FC0: 4000000000045FC0
;;   Called from:
;;     40000000000461CC (in fn4000000000046180)
;;     40000000000498AC (in fn4000000000049600)
fn4000000000045FC0 proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x6; addl	r16,6988,r1; nop.b	0x0 }
	{ addl	r33,6996,r1; mov	r37,LC; adds	r36,0x0,r1; }
	{ ld4	r15,[r16]; nop.m	0x0; mov	r34,b2; }
	{ adds	r14,0x0,r15; cmp4.lt	p06,p07,r32,r15; (p07) br.cond.dptk.few	40000000000460B0; }

l4000000000046000:
	{ adds	r14,0xFFFFFFFFFFFFFFFF,r32; cmp4.lt	p07,p06,0x0,r32; addl	r16,32,r0; }
	{ (p06) adds	r14,0x0,r0; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000046070; }

l4000000000046016:
	{ chk.a.nc	r0,3FFFFFFFFF046816; nop; (p48) nop }

l4000000000046020:
	{ ld8	r15,[r33]; nop.m	0x0; addp4	r17,r14,r0; }
	{ adds	r14,0x1,r15; nop.m	0x0; mov.i	LC,r17; }
	{ st1	[r16],r15; adds	r15,0x0,r14; br.cloop.sptk.few	4000000000046130; }

l4000000000046050:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000046060:
	{ nop.m	0x0; sxt4	r14,r32; nop.i	0x0 }

l4000000000046070:
	{ ld8	r32,[r33]; nop.m	0x0; mov.spnt	b0,r34,4000000000046070; }
	{ add	r14,r32,r14; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ st1	[r0],r14; nop.m	0x0; mov.i	LC,r37; }
	{ alloc	r2,ar.pfs,0x1,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn4000000000045480 }

l40000000000460B0:
	{ nop.m	0x0; adds	r14,0x10,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.lt	p07,p06,r32,r14; (p06) br.cond.dptk.few	40000000000460B0 }

l40000000000460D0:
	{ sub	r39,r32,r15; adds	r15,0x10,r15; addl	r33,6996,r1; }
	{ nop.m	0x0; extr	r39,r39,4,28; nop.i	0x0 }
	{ ld8	r38,[r33]; shladd	r39,r39,0x4,r15; nop.i	0x0; }
	{ st4	[r39],r16; sxt4	r39,r39; br.call.sptk.many	b0,xrealloc; }
	{ nop.m	0x0; adds	r1,0x0,r36; nop.i	0x0 }
	{ st8	[r8],r33; nop.m	0x0; br.cond.sptk.few	4000000000046000 }

l4000000000046130:
	{ adds	r14,0x1,r14; st1	[r16],r15; nop.i	0x0; }
	{ nop.m	0x0; adds	r15,0x0,r14; br.cloop.sptk.few	4000000000046130 }

l4000000000046150:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000046060; }
4000000000046160 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000046170 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn4000000000046180: 4000000000046180
;;   Called from:
;;     400000000004B3AC (in named_function_string)
;;     400000000004B5FC (in named_function_string)
;;     400000000004B5FC (in named_function_string)
fn4000000000046180 proc
	{ alloc	r35,ar.pfs,0x6,0x0,0x5; addl	r37,-5428,r1; mov	r34,b2 }
	{ adds	r36,0x0,r1; nop.m	0x0; adds	r33,0x0,r32; }
	{ ld8	r37,[r37]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000045480; }
	{ adds	r1,0x0,r36; addl	r14,6976,r1; nop.i	0x0; }
	{ ld4	r37,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000045FC0; }
	{ adds	r1,0x0,r36; cmp.eq	p06,p07,0x0,r32; (p06) br.cond.dpnt.few	4000000000046200; }

l40000000000461E0:
	{ ld1	r14,[r32]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	4000000000046220 }

l4000000000046200:
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r34,4000000000046210; br.ret	b0; }

l4000000000046220:
	{ addl	r32,-5444,r1; nop.m	0x0; mov.spnt	b0,r34,4000000000046220; }
	{ ld8	r32,[r32]; nop.m	0x0; mov.i	ar.pfs,r35; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn4000000000045480; }
4000000000046250 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
4000000000046260 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000046270 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000046280 18 30 2D 10 80 05 F0 C0 80 00 42 00 00 00 00 20 .0-.......B.... 
4000000000046290 09 70 40 40 00 21 00 41 80 00 42 A0 04 00 C4 00 .p@@.!.A..B.....
40000000000462A0 08 20 01 1E 10 10 70 02 04 00 42 60 04 00 01 84 . ....p...B`....
40000000000462B0 0B 70 00 1C 10 10 80 40 90 12 73 C0 00 70 1C 50 .p.....@..s..p.P
40000000000462C0 09 00 00 00 01 00 42 0A 00 00 48 00 00 00 04 00 ......B...H.....
40000000000462D0 31 21 01 00 00 21 00 00 00 02 80 03 80 01 00 43 1!...!.........C
40000000000462E0 09 00 00 00 01 00 90 02 40 20 20 00 00 00 04 00 ........@  .....
40000000000462F0 11 00 00 00 01 00 60 00 A4 0E F3 03 80 00 00 43 ......`........C
4000000000046300 08 70 80 46 00 21 60 00 90 0E 73 00 C4 EE 57 9F .p.F.!`...s...W.
4000000000046310 0A 78 A0 46 00 21 E0 00 38 30 A0 23 44 ED 57 9F .x.F.!..80.#D.W.
4000000000046320 0B 00 01 40 18 10 E0 40 38 00 42 23 C4 EF 53 9F ...@...@8.B#..S.
4000000000046330 09 70 00 1C 10 D0 11 02 84 30 20 00 00 00 04 00 .p.......0 .....
4000000000046340 D0 08 01 42 18 10 60 10 38 0E A8 03 B0 00 00 43 ...B..`.8......C
4000000000046350 03 10 01 1E 18 10 00 28 05 80 03 00 60 02 AA 00 .......(....`...
4000000000046360 10 10 0C 00 80 05 00 00 00 02 00 00 28 F1 FF 48 ............(..H
4000000000046370 09 00 00 00 01 00 80 22 F7 AB 4F 00 00 00 04 00 ......."..O.....
4000000000046380 11 40 01 50 18 10 00 00 00 02 00 00 08 F1 FF 58 .@.P...........X
4000000000046390 08 70 80 46 00 21 60 00 90 0E 73 20 00 38 01 84 .p.F.!`...s .8..
40000000000463A0 0A 78 A0 46 00 21 E0 00 38 30 20 23 C4 EF 53 9F .x.F.!..80 #..S.
40000000000463B0 0A 00 B1 FB D5 27 E0 40 38 00 C2 23 44 ED 57 9F .....'.@8..#D.W.
40000000000463C0 09 00 00 00 01 00 00 02 80 30 20 00 00 00 04 00 .........0 .....
40000000000463D0 09 70 00 1C 10 90 11 02 84 30 20 00 00 00 04 00 .p.......0 .....
40000000000463E0 F0 08 01 42 18 10 60 10 38 0E 28 03 70 FF FF 4A ...B..`.8.(.p..J
40000000000463F0 11 40 01 1E 18 10 00 00 00 02 00 00 18 B0 0E 50 .@.............P
4000000000046400 08 08 00 4E 00 21 30 02 20 00 42 40 05 40 00 84 ...N.!0. .B@.@..
4000000000046410 19 40 01 40 00 21 90 02 84 00 42 00 78 F0 FF 58 .@.@.!....B.x..X
4000000000046420 11 08 00 4E 00 21 80 02 8C 00 42 00 C8 43 FD 58 ...N.!....B..C.X
4000000000046430 09 08 00 4E 00 21 00 00 00 02 00 00 60 02 AA 00 ...N.!......`...
4000000000046440 10 00 00 00 01 00 00 28 05 80 03 80 08 00 84 00 .......(........
4000000000046450 09 70 00 20 18 10 00 00 00 02 00 00 C5 ED 57 9F .p. ..........W.
4000000000046460 09 00 00 00 01 00 80 02 A0 30 20 00 00 00 04 00 .........0 .....
4000000000046470 11 48 01 1C 18 10 00 00 00 02 00 00 18 F0 FF 58 .H.............X
4000000000046480 11 00 00 00 01 00 10 00 9C 00 42 00 80 FE FF 48 ..........B....H
4000000000046490 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000464A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000464B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn40000000000464C0: 40000000000464C0
;;   Called from:
;;     400000000004716C (in fn40000000000470C0)
;;     40000000000472CC (in fn40000000000470C0)
;;     400000000004736C (in fn40000000000470C0)
fn40000000000464C0 proc
	{ alloc	r39,ar.pfs,0xB,0x0,0x9; adds	r15,0x18,r32; nop.b	0x0 }
	{ adds	r36,0x20,r32; adds	r14,0x8,r32; mov	r38,b6; }
	{ ld4	r16,[r15]; adds	r40,0x0,r1; adds	r35,0x0,r32 }
	{ ld8	r37,[r36]; ld4	r34,[r36]; cmp4.ltu	p06,p07,0x13,r16 }
	{ nop.m	0x0; ld8	r17,[r14]; nop.i	0x0; }
	{ ld4	r33,[r14]; nop.i	0x0; (p07) br.cond.dptk.few	4000000000046540 }

l4000000000046520:
	{ nop.m	0x0; mov.i	ar.pfs,r39; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r38,4000000000046530; br.ret	b0 }

l4000000000046540:
	{ addl	r14,-4780,r1; ld8	r14,[r14]; nop.i	0x0; }
	{ shladd	r14,r16,0x3,r14; ld8	r15,[r14]; nop.i	0x0; }
	{ nop.m	0x0; add	r14,r14,r15; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b6,r14,4000000000046570; br.cond	b6; }
4000000000046580 0B 18 41 40 00 21 E0 00 8C 20 20 00 00 00 04 00 ..A@.!...  .....
4000000000046590 10 00 00 00 01 00 60 00 38 0E 28 03 80 08 00 42 ......`.8.(....B
40000000000465A0 08 00 71 FA D7 27 10 02 44 30 20 00 60 0A 00 07 ..q..'..D0 .`...
40000000000465B0 0B 10 01 4A 18 10 00 02 80 30 20 00 70 02 AA 00 ...J.....0 .p...
40000000000465C0 10 10 0C 00 80 05 00 00 00 02 00 00 C8 EE FF 48 ...............H
40000000000465D0 09 00 11 FB D7 27 10 02 94 30 20 00 60 0A 00 07 .....'...0 .`...
40000000000465E0 09 00 01 40 18 10 00 00 00 02 00 00 70 02 AA 00 ...@........p...
40000000000465F0 10 10 0C 00 80 05 00 00 00 02 00 00 98 EE FF 48 ...............H
4000000000046600 09 18 41 40 00 21 90 22 F7 AB 4F 40 05 08 01 84 ..A@.!."..O@....
4000000000046610 09 00 00 00 01 00 E0 00 8C 20 20 00 00 00 04 00 .........  .....
4000000000046620 11 00 00 00 01 00 60 00 38 0E A8 03 10 09 00 43 ......`.8......C
4000000000046630 11 30 04 42 87 39 00 00 00 02 00 03 30 00 00 43 .0.B.9......0..C
4000000000046640 13 48 01 52 18 10 00 24 F7 7F 2C 00 00 00 00 20 .H.R...$..,.... 
4000000000046650 09 08 00 50 00 21 00 00 00 02 00 00 00 00 04 00 ...P.!..........
4000000000046660 09 00 00 00 01 00 00 E2 F7 AB 4F 00 00 00 04 00 ..........O.....
4000000000046670 08 00 01 40 18 10 00 00 00 02 00 00 00 00 04 00 ...@............
4000000000046680 03 08 01 4A 18 10 00 30 05 80 03 00 70 02 AA 00 ...J...0....p...
4000000000046690 10 10 0C 00 80 05 00 00 00 02 00 00 F8 ED FF 48 ...............H
40000000000466A0 09 18 41 40 00 21 00 00 00 02 00 00 44 EF 57 9F ..A@.!......D.W.
40000000000466B0 09 00 00 00 01 00 E0 00 8C 20 20 00 00 00 04 00 .........  .....
40000000000466C0 11 00 00 00 01 00 60 00 38 0E A8 03 30 08 00 43 ......`.8...0..C
40000000000466D0 11 00 00 00 01 00 60 00 84 0E F3 03 80 09 00 43 ......`........C
40000000000466E0 08 00 01 40 18 10 00 00 00 02 00 00 00 00 04 00 ...@............
40000000000466F0 03 08 01 4A 18 10 00 30 05 80 03 00 70 02 AA 00 ...J...0....p...
4000000000046700 10 10 0C 00 80 05 00 00 00 02 00 00 88 ED FF 48 ...............H
4000000000046710 09 00 11 FA D6 27 00 00 00 02 00 00 60 0A 00 07 .....'......`...
4000000000046720 09 00 01 40 18 10 00 00 00 02 00 00 70 02 AA 00 ...@........p...
4000000000046730 10 10 0C 00 80 05 00 00 00 02 00 00 58 ED FF 48 ............X..H
4000000000046740 09 18 41 40 00 21 90 22 F7 AB 4F 40 05 08 01 84 ..A@.!."..O@....
4000000000046750 09 00 00 00 01 00 E0 00 8C 20 20 00 00 00 04 00 .........  .....
4000000000046760 11 00 00 00 01 00 60 00 38 0E A8 03 50 07 00 43 ......`.8...P..C
4000000000046770 11 30 04 42 87 39 00 00 00 02 00 03 30 00 00 43 .0.B.9......0..C
4000000000046780 13 48 01 52 18 10 00 84 F6 7F 2C 00 00 00 00 20 .H.R......,.... 
4000000000046790 09 08 00 50 00 21 00 00 00 02 00 00 00 00 04 00 ...P.!..........
40000000000467A0 09 00 00 00 01 00 00 A2 F4 AD 4F 00 00 00 04 00 ..........O.....
40000000000467B0 08 00 01 40 18 10 00 00 00 02 00 00 00 00 04 00 ...@............
40000000000467C0 03 08 01 4A 18 10 00 30 05 80 03 00 70 02 AA 00 ...J...0....p...
40000000000467D0 10 10 0C 00 80 05 00 00 00 02 00 00 B8 EC FF 48 ...............H
40000000000467E0 09 48 01 40 00 21 00 22 F4 AB 4F 60 84 1A 01 84 .H.@.!."..O`....
40000000000467F0 11 00 01 40 18 10 00 00 00 02 00 00 98 FA FF 58 ...@...........X
4000000000046800 0B 08 00 50 00 21 90 62 F6 AB 4F 00 00 00 04 00 ...P.!.b..O.....
4000000000046810 11 48 01 52 18 10 00 00 00 02 00 00 78 EC FF 58 .H.R........x..X
4000000000046820 08 70 00 48 18 10 10 00 A0 00 42 00 60 0A 00 07 .p.H......B.`...
4000000000046830 0B 10 01 46 18 10 00 00 00 02 00 00 70 02 AA 00 ...F........p...
4000000000046840 09 00 00 00 01 00 10 02 38 30 20 00 00 00 04 00 ........80 .....
4000000000046850 10 10 0C 00 80 05 00 00 00 02 00 00 38 EC FF 48 ............8..H
4000000000046860 09 18 41 40 00 21 00 00 00 02 00 00 44 EA 5B 9F ..A@.!......D.[.
4000000000046870 09 00 00 00 01 00 E0 00 8C 20 20 00 00 00 04 00 .........  .....
4000000000046880 11 00 00 00 01 00 60 00 38 0E A8 03 30 07 00 43 ......`.8...0..C
4000000000046890 11 00 00 00 01 00 60 00 84 0E F3 03 70 07 00 43 ......`.....p..C
40000000000468A0 08 00 01 40 18 10 00 00 00 02 00 00 00 00 04 00 ...@............
40000000000468B0 03 08 01 4A 18 10 00 30 05 80 03 00 70 02 AA 00 ...J...0....p...
40000000000468C0 10 10 0C 00 80 05 00 00 00 02 00 00 C8 EB FF 48 ...............H
40000000000468D0 0B 18 41 40 00 21 E0 00 8C 20 20 00 00 00 04 00 ..A@.!...  .....
40000000000468E0 10 00 00 00 01 00 60 00 38 0E 28 03 40 04 00 42 ......`.8.(.@..B
40000000000468F0 09 00 B1 FA D6 27 10 02 44 30 20 00 60 0A 00 07 .....'..D0 .`...
4000000000046900 09 00 01 40 18 10 00 00 00 02 00 00 70 02 AA 00 ...@........p...
4000000000046910 10 10 0C 00 80 05 00 00 00 02 00 00 78 EB FF 48 ............x..H
4000000000046920 0B 18 41 40 00 21 E0 00 8C 20 20 00 00 00 04 00 ..A@.!...  .....
4000000000046930 10 00 00 00 01 00 60 00 38 0E 28 03 C0 03 00 42 ......`.8.(....B
4000000000046940 09 00 F1 FA D6 27 10 02 44 30 20 00 60 0A 00 07 .....'..D0 .`...
4000000000046950 09 00 01 40 18 10 00 00 00 02 00 00 70 02 AA 00 ...@........p...
4000000000046960 10 10 0C 00 80 05 00 00 00 02 00 00 28 EB FF 48 ............(..H
4000000000046970 0B 18 41 40 00 21 E0 00 8C 20 20 00 00 00 04 00 ..A@.!...  .....
4000000000046980 10 00 00 00 01 00 60 00 38 0E 28 03 40 03 00 42 ......`.8.(.@..B
4000000000046990 09 00 B1 FA D7 27 10 02 44 30 20 00 60 0A 00 07 .....'..D0 .`...
40000000000469A0 09 00 01 40 18 10 00 00 00 02 00 00 70 02 AA 00 ...@........p...
40000000000469B0 10 10 0C 00 80 05 00 00 00 02 00 00 D8 EA FF 48 ...............H
40000000000469C0 09 00 F1 FA D7 27 10 02 94 30 20 00 60 0A 00 07 .....'...0 .`...
40000000000469D0 09 00 01 40 18 10 00 00 00 02 00 00 70 02 AA 00 ...@........p...
40000000000469E0 10 10 0C 00 80 05 00 00 00 02 00 00 A8 EA FF 48 ...............H
40000000000469F0 09 18 41 40 00 21 90 22 F7 AB 4F 40 05 08 01 84 ..A@.!."..O@....
4000000000046A00 09 00 00 00 01 00 E0 00 8C 20 20 00 00 00 04 00 .........  .....
4000000000046A10 11 00 00 00 01 00 60 00 38 0E A8 03 60 05 00 43 ......`.8...`..C
4000000000046A20 11 30 04 42 87 39 00 00 00 02 00 03 30 00 00 43 .0.B.9......0..C
4000000000046A30 13 48 01 52 18 10 00 2C F5 7F 2C 00 00 00 00 20 .H.R...,..,.... 
4000000000046A40 09 08 00 50 00 21 00 00 00 02 00 00 00 00 04 00 ...P.!..........
4000000000046A50 09 00 00 00 01 00 00 E2 F4 AD 4F 00 00 00 04 00 ..........O.....
4000000000046A60 08 00 01 40 18 10 00 00 00 02 00 00 00 00 04 00 ...@............
4000000000046A70 03 08 01 4A 18 10 00 30 05 80 03 00 70 02 AA 00 ...J...0....p...
4000000000046A80 10 10 0C 00 80 05 00 00 00 02 00 00 08 EA FF 48 ...............H
4000000000046A90 09 18 41 40 00 21 90 22 F7 AB 4F 40 05 08 01 84 ..A@.!."..O@....
4000000000046AA0 09 00 00 00 01 00 E0 00 8C 20 20 00 00 00 04 00 .........  .....
4000000000046AB0 11 00 00 00 01 00 60 00 38 0E A8 03 C0 03 00 43 ......`.8......C
4000000000046AC0 11 30 04 42 87 39 00 00 00 02 00 03 30 00 00 43 .0.B.9......0..C
4000000000046AD0 13 48 01 52 18 10 00 DC F4 7F 2C 00 00 00 00 20 .H.R......,.... 
4000000000046AE0 09 08 00 50 00 21 00 00 00 02 00 00 00 00 04 00 ...P.!..........
4000000000046AF0 09 00 00 00 01 00 00 62 F4 AD 4F 00 00 00 04 00 .......b..O.....
4000000000046B00 08 00 01 40 18 10 00 00 00 02 00 00 00 00 04 00 ...@............
4000000000046B10 03 08 01 4A 18 10 00 30 05 80 03 00 70 02 AA 00 ...J...0....p...
4000000000046B20 10 10 0C 00 80 05 00 00 00 02 00 00 68 E9 FF 48 ............h..H
4000000000046B30 0B 18 41 40 00 21 E0 00 8C 20 20 00 00 00 04 00 ..A@.!...  .....
4000000000046B40 10 00 00 00 01 00 60 00 38 0E 28 03 A0 02 00 42 ......`.8.(....B
4000000000046B50 08 00 31 FB D6 27 10 02 44 30 20 00 60 0A 00 07 ..1..'..D0 .`...
4000000000046B60 0B 10 01 4A 18 10 00 02 80 30 20 00 70 02 AA 00 ...J.....0 .p...
4000000000046B70 10 10 0C 00 80 05 00 00 00 02 00 00 18 E9 FF 48 ...............H
4000000000046B80 0B 18 41 40 00 21 E0 00 8C 20 20 00 00 00 04 00 ..A@.!...  .....
4000000000046B90 10 00 00 00 01 00 60 00 38 0E 28 03 20 02 00 42 ......`.8.(. ..B
4000000000046BA0 08 00 71 FB D6 27 10 02 44 30 20 00 60 0A 00 07 ..q..'..D0 .`...
4000000000046BB0 0B 10 01 4A 18 10 00 02 80 30 20 00 70 02 AA 00 ...J.....0 .p...
4000000000046BC0 10 10 0C 00 80 05 00 00 00 02 00 00 C8 E8 FF 48 ...............H
4000000000046BD0 0B 18 41 40 00 21 E0 00 8C 20 20 00 00 00 04 00 ..A@.!...  .....
4000000000046BE0 10 00 00 00 01 00 60 00 38 0E 28 03 A0 01 00 42 ......`.8.(....B
4000000000046BF0 09 00 B1 FB D6 27 10 02 44 30 20 00 60 0A 00 07 .....'..D0 .`...
4000000000046C00 09 00 01 40 18 10 00 00 00 02 00 00 70 02 AA 00 ...@........p...
4000000000046C10 10 10 0C 00 80 05 00 00 00 02 00 00 78 E8 FF 48 ............x..H
4000000000046C20 0B 18 41 40 00 21 E0 00 8C 20 20 00 00 00 04 00 ..A@.!...  .....
4000000000046C30 10 00 00 00 01 00 60 00 38 0E 28 03 20 01 00 42 ......`.8.(. ..B
4000000000046C40 09 00 F1 FB D6 27 10 02 44 30 20 00 60 0A 00 07 .....'..D0 .`...
4000000000046C50 09 00 01 40 18 10 00 00 00 02 00 00 70 02 AA 00 ...@........p...
4000000000046C60 10 10 0C 00 80 05 00 00 00 02 00 00 28 E8 FF 48 ............(..H
4000000000046C70 0B 18 41 40 00 21 E0 00 8C 20 20 00 00 00 04 00 ..A@.!...  .....
4000000000046C80 10 00 00 00 01 00 60 00 38 0E 28 03 C0 01 00 42 ......`.8.(....B
4000000000046C90 08 00 31 FA D7 27 10 02 44 30 20 00 60 0A 00 07 ..1..'..D0 .`...
4000000000046CA0 0B 10 01 4A 18 10 00 02 80 30 20 00 70 02 AA 00 ...J.....0 .p...
4000000000046CB0 10 10 0C 00 80 05 00 00 00 02 00 00 D8 E7 FF 48 ...............H
4000000000046CC0 09 00 D1 FA D7 27 00 00 00 02 00 00 60 0A 00 07 .....'......`...
4000000000046CD0 09 00 01 40 18 10 00 00 00 02 00 00 70 02 AA 00 ...@........p...
4000000000046CE0 10 10 0C 00 80 05 00 00 00 02 00 00 A8 E7 FF 48 ...............H
4000000000046CF0 09 00 11 FB D6 27 00 00 00 02 00 00 60 0A 00 07 .....'......`...
4000000000046D00 09 00 01 40 18 10 00 00 00 02 00 00 70 02 AA 00 ...@........p...
4000000000046D10 10 10 0C 00 80 05 00 00 00 02 00 00 78 E7 FF 48 ............x..H
4000000000046D20 09 00 D1 FA D6 27 00 00 00 02 00 00 60 0A 00 07 .....'......`...
4000000000046D30 09 00 01 40 18 10 00 00 00 02 00 00 70 02 AA 00 ...@........p...
4000000000046D40 10 10 0C 00 80 05 00 00 00 02 00 00 48 E7 FF 48 ............H..H
4000000000046D50 09 00 11 FA D7 27 00 00 00 02 00 00 60 0A 00 07 .....'......`...
4000000000046D60 09 00 01 40 18 10 00 00 00 02 00 00 70 02 AA 00 ...@........p...
4000000000046D70 10 10 0C 00 80 05 00 00 00 02 00 00 18 E7 FF 48 ...............H
4000000000046D80 09 00 D1 FB D6 27 00 00 00 02 00 00 60 0A 00 07 .....'......`...
4000000000046D90 09 00 01 40 18 10 00 00 00 02 00 00 70 02 AA 00 ...@........p...
4000000000046DA0 10 10 0C 00 80 05 00 00 00 02 00 00 E8 E6 FF 48 ...............H
4000000000046DB0 09 00 91 FB D6 27 20 02 94 30 20 00 60 0A 00 07 .....' ..0 .`...
4000000000046DC0 09 00 01 40 18 10 00 00 00 02 00 00 70 02 AA 00 ...@........p...
4000000000046DD0 10 10 0C 00 80 05 00 00 00 02 00 00 B8 E6 FF 48 ...............H
4000000000046DE0 09 00 51 FB D6 27 20 02 94 30 20 00 60 0A 00 07 ..Q..' ..0 .`...
4000000000046DF0 09 00 01 40 18 10 00 00 00 02 00 00 70 02 AA 00 ...@........p...
4000000000046E00 10 10 0C 00 80 05 00 00 00 02 00 00 88 E6 FF 48 ...............H
4000000000046E10 09 00 91 FA D7 27 20 02 94 30 20 00 60 0A 00 07 .....' ..0 .`...
4000000000046E20 09 00 01 40 18 10 00 00 00 02 00 00 70 02 AA 00 ...@........p...
4000000000046E30 10 10 0C 00 80 05 00 00 00 02 00 00 58 E6 FF 48 ............X..H
4000000000046E40 09 00 51 FA D7 27 20 02 94 30 20 00 60 0A 00 07 ..Q..' ..0 .`...
4000000000046E50 09 00 01 40 18 10 00 00 00 02 00 00 70 02 AA 00 ...@........p...
4000000000046E60 10 10 0C 00 80 05 00 00 00 02 00 00 28 E6 FF 48 ............(..H
4000000000046E70 09 48 71 FB D5 27 A0 02 44 30 20 00 00 00 04 00 .Hq..'..D0 .....
4000000000046E80 11 48 01 52 18 10 00 00 00 02 00 00 08 E6 FF 58 .H.R...........X
4000000000046E90 0B 08 00 50 00 21 00 62 F4 AD 4F 00 00 00 04 00 ...P.!.b..O.....
4000000000046EA0 10 00 01 40 18 10 00 00 00 02 00 00 70 FC FF 48 ...@........p..H
4000000000046EB0 09 48 71 FB D5 27 A0 02 44 30 20 00 00 00 04 00 .Hq..'..D0 .....
4000000000046EC0 11 48 01 52 18 10 00 00 00 02 00 00 C8 E5 FF 58 .H.R...........X
4000000000046ED0 0B 08 00 50 00 21 00 A2 F4 AD 4F 00 00 00 04 00 ...P.!....O.....
4000000000046EE0 10 00 01 40 18 10 00 00 00 02 00 00 E0 F8 FF 48 ...@...........H
4000000000046EF0 09 48 71 FB D5 27 A0 02 44 30 20 00 00 00 04 00 .Hq..'..D0 .....
4000000000046F00 11 48 01 52 18 10 00 00 00 02 00 00 88 E5 FF 58 .H.R...........X
4000000000046F10 0B 08 00 50 00 21 00 A2 F7 AB 4F 00 00 00 04 00 ...P.!....O.....
4000000000046F20 10 00 01 40 18 10 00 00 00 02 00 00 D0 F7 FF 48 ...@...........H
4000000000046F30 09 48 71 FB D5 27 A0 02 44 30 20 00 00 00 04 00 .Hq..'..D0 .....
4000000000046F40 11 48 01 52 18 10 00 00 00 02 00 00 48 E5 FF 58 .H.R........H..X
4000000000046F50 0B 08 00 50 00 21 00 E2 F7 AB 4F 00 00 00 04 00 ...P.!....O.....
4000000000046F60 10 00 01 40 18 10 00 00 00 02 00 00 20 F7 FF 48 ...@........ ..H
4000000000046F70 09 48 71 FB D5 27 A0 02 44 30 20 00 00 00 04 00 .Hq..'..D0 .....
4000000000046F80 11 48 01 52 18 10 00 00 00 02 00 00 08 E5 FF 58 .H.R...........X
4000000000046F90 0B 08 00 50 00 21 00 E2 F4 AD 4F 00 00 00 04 00 ...P.!....O.....
4000000000046FA0 10 00 01 40 18 10 00 00 00 02 00 00 D0 FA FF 48 ...@...........H
4000000000046FB0 09 48 71 FB D5 27 A0 02 44 30 20 00 00 00 04 00 .Hq..'..D0 .....
4000000000046FC0 11 48 01 52 18 10 00 00 00 02 00 00 C8 E4 FF 58 .H.R...........X
4000000000046FD0 09 08 00 50 00 21 50 02 90 30 20 00 00 00 04 00 ...P.!P..0 .....
4000000000046FE0 09 00 00 00 01 00 00 22 F5 AD 4F 00 00 00 04 00 ......."..O.....
4000000000046FF0 10 00 01 40 18 10 00 00 00 02 00 00 C0 F8 FF 48 ...@...........H
4000000000047000 09 48 91 FB D5 27 00 00 00 02 00 40 05 08 01 84 .H...'.....@....
4000000000047010 11 48 01 52 18 10 00 00 00 02 00 00 78 E4 FF 58 .H.R........x..X
4000000000047020 09 08 00 50 00 21 50 02 90 30 20 00 00 00 04 00 ...P.!P..0 .....
4000000000047030 09 00 00 00 01 00 00 22 F5 AD 4F 00 00 00 04 00 ......."..O.....
4000000000047040 10 00 01 40 18 10 00 00 00 02 00 00 70 F8 FF 48 ...@........p..H
4000000000047050 09 48 91 FB D5 27 00 00 00 02 00 40 05 08 01 84 .H...'.....@....
4000000000047060 11 48 01 52 18 10 00 00 00 02 00 00 28 E4 FF 58 .H.R........(..X
4000000000047070 0B 08 00 50 00 21 00 A2 F7 AB 4F 00 00 00 04 00 ...P.!....O.....
4000000000047080 11 00 01 40 18 10 00 00 00 02 00 00 70 F6 FF 48 ...@........p..H
4000000000047090 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000470A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000470B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn40000000000470C0: 40000000000470C0
;;   Called from:
;;     40000000000495DC (in print_simple_command)
;;     400000000004973C (in fn4000000000049600)
;;     400000000004B60C (in named_function_string)
;;     400000000004B60C (in named_function_string)
fn40000000000470C0 proc
	{ alloc	r40,ar.pfs,0xC,0x0,0xB; adds	r35,0x18,r32; mov	r42,pr }
	{ addl	r37,6956,r1; cmp.eq	p07,p06,0x0,r32; adds	r43,0x0,r32; }
	{ adds	r41,0x0,r1; st4	[r0],r37; mov	r39,b7 }
	{ adds	r36,0x0,r0; adds	r34,0x0,r0; (p07) br.cond.dpnt.few	4000000000047340; }

l4000000000047100:
	{ ld4	r33,[r35]; cmp.eq	p16,p17,r0,r0; addl	r38,10,r0; }
	{ cmp4.eq	p07,p06,0x8,r33; nop.m	0x0; cmp4.eq	p09,p08,0xE,r33; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p07,p06,0x4,r33; (p07) br.cond.dpnt.few	40000000000471E0 }

l4000000000047130:
	{ nop.m	0x0; adds	r14,0x8,r32; (p08) br.cond.dptk.few	4000000000047160; }

l4000000000047140:
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x1,r14; (p07) br.cond.dpnt.few	4000000000047360 }

l4000000000047160:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn40000000000464C0; }
	{ adds	r1,0x0,r41; nop.m	0x0; nop.i	0x0; }

l4000000000047180:
	{ addl	r43,-5436,r1; ld8	r32,[r32]; nop.i	0x0; }
	{ ld8	r43,[r43]; cmp.eq	p06,p07,0x0,r32; (p06) br.cond.dpnt.few	4000000000047240 }

l40000000000471A0:
	{ adds	r35,0x18,r32; nop.i	0x0; br.call.sptk.many	b0,fn4000000000045480; }
	{ ld4	r33,[r35]; adds	r1,0x0,r41; adds	r43,0x0,r32; }
	{ cmp4.eq	p07,p06,0x8,r33; nop.m	0x0; cmp4.eq	p09,p08,0xE,r33; }
	{ nop.m	0x0; cmp4.eq.or.andcm	p07,p06,0x4,r33; (p06) br.cond.dptk.few	4000000000047130 }

l40000000000471E0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,copy_redirect; }
	{ nop.m	0x0; adds	r1,0x0,r41; nop.i	0x0 }
	{ st8	[r0],r8; nop.m	0x0; (p16) br.cond.dpnt.few	4000000000047390; }

l4000000000047210:
	{ st8	[r8],r36; addl	r43,-5436,r1; adds	r36,0x0,r8; }
	{ ld8	r32,[r32]; ld8	r43,[r43]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r32; (p07) br.cond.dptk.few	40000000000471A0 }

l4000000000047240:
	{ addl	r14,6980,r1; nop.m	0x0; addl	r43,-5436,r1 }
	{ adds	r33,0x0,r34; nop.m	0x0; (p16) br.cond.dpnt.few	4000000000047340; }

l4000000000047260:
	{ ld4	r14,[r14]; ld8	r43,[r43]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; (p07) addl	r14,6964,r1; nop.i	0x0; }

l400000000004727C:
	{ nop; mov	pr,r32,0x0; Invalid }

l400000000004728C:
	{ rsm	0x200080; mov	pr,r0,0x2000; Invalid }

l400000000004729C:
	{ (p15) nop; invala; break.b	0x1000 }
	{ nop; break.i	0x1000; break.i	0x1000 }
	{ ldfps	f0,f1,[r0]; zxt1	r64,r64; break.i	0x1000 }

l40000000000472C0:
	{ adds	r43,0x0,r34; nop.i	0x0; br.call.sptk.many	b0,fn40000000000464C0; }
	{ adds	r1,0x0,r41; addl	r43,-5428,r1; nop.i	0x0; }
	{ ld8	r43,[r43]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000045480; }
	{ ld8	r34,[r34]; nop.m	0x0; adds	r1,0x0,r41; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r34; (p06) br.cond.dptk.few	40000000000472C0 }

l4000000000047310:
	{ addl	r14,1,r0; adds	r43,0x0,r33; nop.i	0x0 }
	{ st4	[r14],r37; nop.m	0x0; br.call.sptk.many	b0,dispose_redirects; }
	{ adds	r1,0x0,r41; nop.m	0x0; nop.i	0x0 }

l4000000000047340:
	{ nop.m	0x0; mov	pr,r42,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r40; }
	{ nop.m	0x0; mov.spnt	b0,r39,4000000000047350; br.ret	b0; }

l4000000000047360:
	{ st4	[r38],r35; adds	r43,0x0,r32; br.call.sptk.many	b0,fn40000000000464C0; }
	{ nop.m	0x0; adds	r1,0x0,r41; nop.i	0x0 }
	{ st4	[r33],r35; nop.m	0x0; br.cond.sptk.few	4000000000047180 }

l4000000000047390:
	{ nop.m	0x0; adds	r36,0x0,r8; adds	r34,0x0,r8 }
	{ nop.m	0x0; cmp.eq	p16,p17,0x0,r8; br.cond.sptk.few	4000000000047180; }
40000000000473B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; fn40000000000473C0: 40000000000473C0
;;   Called from:
;;     400000000004782C (in print_word_list)
fn40000000000473C0 proc
	{ alloc	r41,ar.pfs,0x10,0x0,0xC; adds	r16,0x8,r12; adds	r17,0x0,r12 }
	{ adds	r12,0xFFFFFFFFFFFFFFC0,r12; addl	r14,-10260,r1; addl	r46,-5500,r1; }
	{ mov.m	r43,UNAT; st8.spill	[r16],r112,-16; mov	r40,b0 }
	{ ld8	r14,[r14]; adds	r42,0x0,r1; addl	r45,1,r0; }
	{ st8.spill	[r17],r112,-16; st8.spill	[r16],r112,-16; adds	r47,0x18,r12 }
	{ nop.m	0x0; ld8	r46,[r46]; nop.i	0x0; }
	{ st8.spill	[r17],r112,-16; st8.spill	[r16],r112,-16; nop.i	0x0; }
	{ st8.spill	[r34],r17; st8.spill	[r33],r16; nop.i	0x0; }
	{ ld8	r44,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A560; }
	{ nop.m	0x0; adds	r1,0x0,r42; mov.i	ar.pfs,r41 }
	{ mov.m	UNAT,r43; nop.i	0x0; mov.spnt	b0,r40,4000000000047460 }
	{ nop.m	0x0; adds	r12,0x40,r12; br.ret	b0; }
4000000000047480 08 20 25 0C 80 05 20 A2 05 6C 48 60 04 00 C4 00 . %... ..lH`....
4000000000047490 0B 28 01 02 00 21 10 02 88 30 20 00 00 00 04 00 .(...!...0 .....
40000000000474A0 11 00 00 00 01 00 70 00 84 0C F2 03 70 00 00 43 ......p.....p..C
40000000000474B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000474C0 09 00 00 00 01 00 60 22 F6 AB 4F 00 00 00 04 00 ......`"..O.....
40000000000474D0 11 30 01 4C 18 10 00 00 00 02 00 00 B8 DF FF 58 .0.L...........X
40000000000474E0 11 08 00 4A 00 21 60 02 84 00 42 00 A8 ED FF 58 ...J.!`...B....X
40000000000474F0 09 08 01 42 18 10 00 00 00 02 00 20 00 28 01 84 ...B....... .(..
4000000000047500 10 00 00 00 01 00 70 00 84 0C 72 03 C0 FF FF 4A ......p...r....J
4000000000047510 0B 70 00 40 00 10 00 00 00 02 00 C0 01 70 50 00 .p.@.........pP.
4000000000047520 11 00 00 00 01 00 70 00 38 0C F3 03 50 00 00 42 ......p.8...P..B
4000000000047530 08 78 04 40 00 21 70 D8 39 0C 73 00 00 00 04 00 .x.@.!p.9.s.....
4000000000047540 19 30 F1 FA D5 27 70 02 80 00 C2 03 E0 01 00 43 .0...'p........C
4000000000047550 13 30 01 4C 18 10 00 9C EF 7F 2C 00 00 00 00 20 .0.L......,.... 
4000000000047560 09 08 00 4A 00 21 00 00 00 02 00 00 00 00 04 00 ...J.!..........
4000000000047570 02 70 00 44 18 10 60 62 F6 AB 4F C0 00 70 1C E4 .p.D..`b..O..p..
4000000000047580 19 30 01 4C 18 10 00 00 00 02 00 03 80 01 00 43 .0.L...........C
4000000000047590 11 00 00 00 01 00 00 00 00 02 00 00 F8 DE FF 58 ...............X
40000000000475A0 0B 08 00 4A 00 21 E0 A0 05 6C 48 00 00 00 04 00 ...J.!...lH.....
40000000000475B0 09 00 00 00 01 00 10 02 38 30 20 00 00 00 04 00 ........80 .....
40000000000475C0 11 00 00 00 01 00 60 00 84 0E 72 03 40 01 00 41 ......`...r.@..A
40000000000475D0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
40000000000475E0 09 70 80 42 00 21 F0 40 85 00 42 C0 44 E8 57 9F .p.B.!.@..B.D.W.
40000000000475F0 09 70 00 1C 18 10 60 02 98 30 20 00 00 00 04 00 .p....`..0 .....
4000000000047600 09 00 00 00 01 00 80 02 3C 30 20 00 00 00 04 00 ........<0 .....
4000000000047610 11 38 01 1C 18 10 00 00 00 02 00 00 78 DE FF 58 .8..........x..X
4000000000047620 0B 08 00 4A 00 21 60 62 F6 AB 4F 00 00 00 04 00 ...J.!`b..O.....
4000000000047630 11 30 01 4C 18 10 00 00 00 02 00 00 58 DE FF 58 .0.L........X..X
4000000000047640 09 08 01 42 18 10 00 00 00 02 00 20 00 28 01 84 ...B....... .(..
4000000000047650 10 00 00 00 01 00 70 00 84 0C 72 03 90 FF FF 4A ......p...r....J
4000000000047660 09 00 00 00 01 00 E0 00 88 30 20 00 00 00 04 00 .........0 .....
4000000000047670 11 30 00 1C 07 39 00 00 00 02 00 03 90 00 00 41 .0...9.........A
4000000000047680 0B 78 00 40 00 10 00 00 00 02 00 E0 01 78 50 00 .x.@.........xP.
4000000000047690 11 00 00 00 01 00 60 00 3C 0E 73 03 40 00 00 42 ......`.<.s.@..B
40000000000476A0 09 30 11 FB D5 27 70 D8 3D 0C 73 00 14 00 01 84 .0...'p.=.s.....
40000000000476B0 13 30 01 4C 18 D0 01 60 00 80 21 00 D8 DD FF 58 .0.L...`..!....X
40000000000476C0 09 08 00 4A 00 21 E0 00 88 30 20 00 00 00 04 00 ...J.!...0 .....
40000000000476D0 11 30 01 1C 00 21 00 00 00 02 00 00 38 47 00 50 .0...!......8G.P
40000000000476E0 02 08 00 4A 00 21 F0 08 00 00 48 C0 C1 0A D8 90 ...J.!....H.....
40000000000476F0 0A 00 00 00 01 00 00 78 38 20 23 00 00 00 04 00 .......x8 #.....
4000000000047700 09 00 00 44 98 11 00 00 00 02 00 00 40 02 AA 00 ...D........@...
4000000000047710 10 00 00 00 01 00 00 18 05 80 03 80 08 00 84 00 ................
4000000000047720 0B 70 00 1E 00 10 00 00 00 02 00 C0 01 70 50 00 .p...........pP.
4000000000047730 10 00 00 00 01 00 60 00 38 0E 73 03 40 FE FF 4A ......`.8.s.@..J
4000000000047740 09 30 F1 FA D5 27 00 00 00 02 00 E0 04 00 01 84 .0...'..........
4000000000047750 11 30 01 4C 18 10 00 00 00 02 00 00 38 DD FF 58 .0.L........8..X
4000000000047760 10 00 00 00 01 00 10 00 94 00 42 00 10 FE FF 48 ..........B....H
4000000000047770 0B 78 00 40 00 10 00 00 00 02 00 E0 01 78 50 00 .x.@.........xP.
4000000000047780 10 00 00 00 01 00 60 00 3C 0E 73 03 50 FF FF 4A ......`.<.s.P..J
4000000000047790 11 00 00 00 01 00 00 00 00 02 00 00 F8 DC FF 58 ...............X
40000000000477A0 08 00 00 00 01 00 10 00 94 00 42 00 00 00 04 00 ..........B.....
40000000000477B0 19 70 00 44 18 10 00 00 00 02 00 00 20 FF FF 48 .p.D........ ..H

;; print_word_list: 40000000000477C0
;;   Called from:
;;     40000000000FC4AC (in help_builtin)
;;     40000000000FC4AC (in help_builtin)
print_word_list proc
	{ alloc	r35,ar.pfs,0x8,0x0,0x5; adds	r36,0x0,r1; mov	r34,b2 }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r32; (p07) br.cond.dpnt.few	4000000000047850; }

l40000000000477E0:
	{ ld8	r39,[r32]; adds	r14,0x8,r32; addl	r37,-5500,r1; }
	{ cmp.eq	p07,p06,0x0,r39; ld8	r14,[r14]; nop.i	0x0 }
	{ ld8	r37,[r37]; (p07) addl	r39,-5508,r1; nop.i	0x0; }

l400000000004780C:
	{ cmp4.eq.or.andcm	p00,p09,r1,r0; (p04) cmp.lt	p32,p16,r8,r64; Invalid }

l4000000000047816:
	{ (p19) fwb; cmp4.eq	p00,p00,r0,r1; (p49) nop }

l4000000000047826:
	{ break.m	0x4000; (p32) nop; nop }
	{ add	r0,r0,r1; nop; break.i	0x80000 }
	{ (p03) chk.a.clr	r0,3FFFFFFFFFCCAA46; mov	pr,0x4AFFFFA; break.b	0x80000 }

l4000000000047850:
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r34,4000000000047860; br.ret	b0; }
4000000000047870 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; xtrace_set: 4000000000047880
;;   Called from:
;;     4000000000047ABC (in xtrace_init)
;;     400000000006280C (in sv_xtracefd)
xtrace_set proc
	{ alloc	r36,ar.pfs,0x9,0x0,0x6; cmp4.lt	p06,p07,r32,r0; mov	r35,b3 }
	{ adds	r37,0x0,r1; adds	r38,0x0,r32; (p06) br.cond.dpnt.few	4000000000047A10; }

l40000000000478A0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,sh_validfd; }
	{ cmp4.eq	p07,p06,0x0,r8; nop.m	0x0; adds	r1,0x0,r37 }
	{ adds	r38,0x0,r33; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000479B0; }

l40000000000478D0:
	{ cmp.eq	p06,p07,0x0,r33; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000047A20; }

l40000000000478E0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BBC0; }
	{ adds	r1,0x0,r37; cmp4.eq	p07,p06,r32,r8; nop.i	0x0 }
	{ addl	r40,5,r0; adds	r38,0x0,r0; (p07) br.cond.dpnt.few	4000000000047980; }

l4000000000047910:
	{ nop.m	0x0; addl	r39,-5156,r1; nop.i	0x0; }
	{ ld8	r39,[r39]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r37; nop.m	0x0; adds	r34,0x0,r8 }
	{ adds	r38,0x0,r33; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BBC0; }
	{ adds	r1,0x0,r37; adds	r38,0x0,r34; nop.i	0x0 }
	{ adds	r39,0x0,r32; adds	r40,0x0,r8; br.call.sptk.many	b0,internal_warning; }
	{ adds	r1,0x0,r37; nop.m	0x0; nop.i	0x0; }

l4000000000047980:
	{ addl	r14,5740,r1; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ st4	[r32],r14; addl	r14,6932,r1; mov.spnt	b0,r35,4000000000047990; }
	{ st8	[r33],r14; nop.i	0x0; br.ret	b0 }

l40000000000479B0:
	{ addl	r39,-5172,r1; addl	r40,5,r0; adds	r38,0x0,r0; }
	{ ld8	r39,[r39]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r37; nop.m	0x0; adds	r38,0x0,r8 }
	{ adds	r39,0x0,r32; nop.m	0x0; br.call.sptk.many	b0,internal_error; }
	{ adds	r1,0x0,r37; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,4000000000047A00; br.ret	b0 }

l4000000000047A10:
	{ nop.m	0x0; cmp.eq	p06,p07,0x0,r33; (p07) br.cond.dptk.few	4000000000047980 }

l4000000000047A20:
	{ addl	r39,-5164,r1; addl	r40,5,r0; adds	r38,0x0,r0; }
	{ ld8	r39,[r39]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001AB60; }
	{ adds	r1,0x0,r37; adds	r38,0x0,r8; br.call.sptk.many	b0,internal_error; }
	{ adds	r1,0x0,r37; nop.m	0x0; mov.i	ar.pfs,r36; }
	{ nop.m	0x0; mov.spnt	b0,r35,4000000000047A60; br.ret	b0; }
4000000000047A70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; xtrace_init: 4000000000047A80
;;   Called from:
;;     400000000001C9DC (in main)
xtrace_init proc
	{ alloc	r16,ar.pfs,0x2,0x0,0x2; nop.m	0x0; addl	r14,-10652,r1; }
	{ ld8	r14,[r14]; nop.m	0x0; addl	r32,-1,r0; }
	{ nop.m	0x0; ld8	r33,[r14]; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	xtrace_set; }
4000000000047AC0 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
4000000000047AD0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000047AE0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000047AF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; xtrace_reset: 4000000000047B00
;;   Called from:
;;     4000000000047C6C (in xtrace_fdchk)
;;     400000000006269C (in sv_xtracefd)
xtrace_reset proc
	{ alloc	r35,ar.pfs,0x6,0x0,0x5; addl	r33,5740,r1; nop.b	0x0 }
	{ addl	r32,6932,r1; mov	r34,b2; adds	r36,0x0,r1; }
	{ nop.m	0x0; ld4	r37,[r33]; nop.i	0x0; }
	{ cmp4.lt	p06,p07,r37,r0; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000047BA0; }

l4000000000047B40:
	{ nop.m	0x0; ld8	r14,[r32]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000047BE0; }

l4000000000047B60:
	{ adds	r37,0x0,r14; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A680; }
	{ nop.m	0x0; adds	r1,0x0,r36; nop.i	0x0 }
	{ ld8	r37,[r32]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BE40; }
	{ adds	r1,0x0,r36; nop.m	0x0; nop.i	0x0; }

l4000000000047BA0:
	{ addl	r14,-10652,r1; addl	r15,-1,r0; mov.i	ar.pfs,r35; }
	{ ld8	r14,[r14]; st4	[r15],r33; mov.spnt	b0,r34,4000000000047BB0; }
	{ nop.m	0x0; ld8	r14,[r14]; nop.i	0x0; }
	{ st8	[r14],r32; nop.i	0x0; br.ret	b0; }

l4000000000047BE0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C340; }
	{ adds	r1,0x0,r36; addl	r15,-1,r0; mov.i	ar.pfs,r35; }
	{ addl	r14,-10652,r1; st4	[r15],r33; mov.spnt	b0,r34,4000000000047C00; }
	{ ld8	r14,[r14]; ld8	r14,[r14]; nop.i	0x0; }
	{ st8	[r14],r32; nop.i	0x0; br.ret	b0; }
4000000000047C30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; xtrace_fdchk: 4000000000047C40
xtrace_fdchk proc
	{ addl	r14,5740,r1; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,r14,r32; (p06) br.ret	b0; }

l4000000000047C60:
	{ alloc	r2,ar.pfs,0x1,0x0,0x0; nop.i	0x0; br.cond.sptk.many	xtrace_reset; }
4000000000047C70 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................

;; indirection_level_string: 4000000000047C80
;;   Called from:
;;     40000000000482BC (in xtrace_print_assignment)
;;     40000000000487CC (in xtrace_print_word_list)
;;     40000000000489CC (in xtrace_print_for_command_head)
;;     4000000000048B8C (in xtrace_print_select_command_head)
;;     4000000000048D1C (in xtrace_print_case_command_head)
;;     4000000000048F5C (in xtrace_print_cond_term)
;;     40000000000493DC (in xtrace_print_arith_cmd)
indirection_level_string proc
	{ alloc	r40,ar.pfs,0x10,0x0,0xC; adds	r12,0xFFFFFFFFFFFFFFE0,r12; mov	r42,pr }
	{ addl	r33,14060,r1; addl	r44,-5148,r1; adds	r41,0x0,r1; }
	{ nop.m	0x0; nop.m	0x0; mov	r39,b7 }
	{ ld8	r44,[r44]; nop.m	0x0; mov	r43,LC; }
	{ st1	[r0],r33; nop.i	0x0; br.call.sptk.many	b0,get_string_value; }
	{ adds	r1,0x0,r41; nop.m	0x0; cmp.eq	p07,p06,0x0,r8 }
	{ adds	r32,0x0,r8; nop.m	0x0; (p07) br.cond.dpnt.few	4000000000047D10; }

l4000000000047CF0:
	{ ld1	r14,[r8]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	4000000000047D50 }

l4000000000047D10:
	{ addl	r8,14060,r1; nop.m	0x0; mov	pr,r42,0xFFFFFFFFFFFFFFFE; }
	{ nop.m	0x0; mov.i	ar.pfs,r40; nop.i	0x0; }
	{ nop.m	0x0; mov.i	LC,r43; mov.spnt	b0,r39,4000000000047D30 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0; }

l4000000000047D50:
	{ addl	r45,43,r0; addl	r44,120,r0; br.call.sptk.many	b0,change_flag; }
	{ adds	r1,0x0,r41; adds	r44,0x0,r32; br.call.sptk.many	b0,decode_prompt_string; }
	{ adds	r1,0x0,r41; adds	r35,0x0,r8; nop.i	0x0 }
	{ addl	r44,120,r0; addl	r45,45,r0; br.call.sptk.many	b0,change_flag; }
	{ adds	r1,0x0,r41; cmp.eq	p06,p07,0x0,r35; (p06) br.cond.dpnt.few	4000000000047D10; }

l4000000000047DA0:
	{ ld1	r14,[r35]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000047D10 }

l4000000000047DC0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ adds	r44,0x0,r35; nop.m	0x0; adds	r45,0x0,r8 }
	{ adds	r1,0x0,r41; nop.m	0x0; br.call.sptk.many	b0,fn400000000001BB20; }
	{ adds	r1,0x0,r41; adds	r32,0x0,r8; br.call.sptk.many	b0,fn400000000001B0C0; }
	{ cmp.ltu	p06,p07,0x1,r8; adds	r1,0x0,r41; (p07) br.cond.dpnt.few	4000000000048090; }

l4000000000047E10:
	{ adds	r44,0x0,r35; sxt4	r45,r32; br.call.sptk.many	b0,fn400000000001AF80; }
	{ adds	r14,0x2,r8; cmp4.ltu	p07,p06,0x1,r8; adds	r1,0x0,r41 }
	{ adds	r36,0x0,r8; sxt4	r46,r8; (p06) br.cond.spnt.few	4000000000048090; }

l4000000000047E40:
	{ cmp4.ltu	p07,p06,0x1,r14; addl	r47,17,r0; (p06) br.cond.dpnt.few	4000000000048090; }

l4000000000047E50:
	{ adds	r44,0x10,r12; adds	r45,0x0,r35; br.call.sptk.many	b0,fn400000000001B480; }
	{ adds	r14,0x10,r12; nop.m	0x0; adds	r1,0x0,r41; }
	{ ld1	r38,[r14]; nop.i	0x0; sxt1	r38,r38; }

l4000000000047E80:
	{ addl	r14,6484,r1; cmp4.eq	p06,p07,0x0,r38; adds	r32,0x0,r0 }
	{ cmp4.eq	p17,p16,0x1,r36; addl	r34,14060,r1; (p06) br.cond.dpnt.few	4000000000048130; }

l4000000000047EA0:
	{ nop.m	0x0; sxt4	r37,r36; (p16) adds	r45,0x10,r12; }

l4000000000047EB0:
	{ (p16) adds	r46,0x0,r37; ld4	r14,[r14]; nop.i	0x0; }

l4000000000047EB6:
	{ (p07) fwb; nop; (p48) nop }
	{ (p07) chk.a.clr	r127,3FFFFFFFFF1E77A6; nop; (p32) nop }

l4000000000047ED0:
	{ addp4	r14,r14,r0; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; mov.i	LC,r14; sxt4	r14,r32 }
	{ (p16) adds	r44,0x0,r34; add	r32,r32,r36; nop.b	0x0; }

l4000000000047EF6:
	{ Invalid; nop; dep	r0,r0,r32,63,1 }
	{ Invalid; (p04) nop }

l4000000000047F0C:
	{ srlz.i; Invalid; break.i	0x101000 }

l4000000000047F16:
	{ nop; (p32) nop; break.i	0x80000 }

l4000000000047F20:
	{ nop.m	0x0; (p16) adds	r1,0x0,r41; br.cloop.sptk.few	40000000000480D0; }

l4000000000047F2C:
	{ (p13) nop; break.i	0x1000; break.b	0x1000 }

l4000000000047F30:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000047F40:
	{ nop.m	0x0; sxt4	r15,r36; nop.b	0x0 }
	{ ld1	r14,[r35]; sub	r16,0x62,r32; cmp4.lt	p06,p07,0x62,r32; }
	{ add	r17,r35,r15; nop.m	0x0; sxt1	r14,r14 }
	{ addp4	r16,r16,r0; nop.m	0x0; add	r15,r35,r15,0x1; }
	{ cmp4.eq	p08,p09,0x0,r14; mov.i	LC,r16; (p08) br.cond.dpnt.few	4000000000048020; }

l4000000000047F90:
	{ ld1	r14,[r17]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p08,p09,0x0,r14; (p08) br.cond.dpnt.few	4000000000048020; (p06) br.cond.dpnt.few	4000000000048020; }

l4000000000047FAC:
	{ (p04) nop; break.i	0x1000; break.i	0x1000 }

l4000000000047FB0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000047FC0:
	{ nop.m	0x0; sxt4	r16,r32; adds	r32,0x1,r32; }
	{ add	r16,r33,r16; st1	[r14],r16; nop.i	0x0; }
	{ ld1	r14,[r35]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000048020; }

l4000000000048000:
	{ ld1	r14,[r15],1; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	4000000000048020; br.cloop.sptk.few	4000000000047FC0 }

l400000000004801C:
	{ (p61) nop.m	0x91FFF; break.i	0x1000; Invalid }

l4000000000048020:
	{ nop.m	0x0; sxt4	r32,r32; adds	r44,0x0,r35; }
	{ nop.m	0x0; add	r33,r33,r32; nop.i	0x0; }
	{ st1	[r0],r33; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r41; addl	r8,14060,r1; nop.i	0x0; }
	{ nop.m	0x0; mov	pr,r42,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r40; }
	{ nop.m	0x0; mov.i	LC,r43; mov.spnt	b0,r39,4000000000048070 }
	{ nop.m	0x0; adds	r12,0x20,r12; br.ret	b0; }

l4000000000048090:
	{ ld1	r38,[r35]; adds	r14,0x10,r12; addl	r36,1,r0; }
	{ nop.m	0x0; sxt1	r38,r38; nop.i	0x0; }
	{ nop.m	0x0; st1	[r14],r1,1; nop.i	0x0; }
	{ st1	[r0],r14; nop.i	0x0; br.cond.sptk.few	4000000000047E80 }

l40000000000480D0:
	{ cmp4.lt	p07,p06,0x62,r32; sxt4	r14,r32; add	r34,r34,r37 }
	{ (p16) adds	r45,0x10,r12; (p16) adds	r46,0x0,r37; (p07) br.cond.dpnt.few	4000000000047F40; }

l40000000000480E6:
	{ (p23) chk.a.clr	f0,3FFFFFFFFF0C8336; (p36) nop }

l40000000000480EC:
	{ (p51) cmp.le.and	p63,p41,r0,r37; (p17) shladd	r72,r3,0x1,r0; zxt1	r64,r64 }

l40000000000480F0:
	{ (p17) add	r14,r33,r14; (p16) adds	r44,0x0,r34; add	r32,r32,r36; }

l40000000000480F6:
	{ Invalid; (p04) nop }

l40000000000480FC:
	{ (p16) srlz.i; break.x	0x8C00E4C101000 }

l4000000000048106:
	{ nop; (p32) nop; break.i	0x80000 }

l4000000000048110:
	{ nop.m	0x0; (p16) adds	r1,0x0,r41; br.cloop.sptk.few	40000000000480D0 }

l400000000004811C:
	{ (p62) invala; break.i	0x1000; break.i	0x1000 }

l4000000000048120:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000047F40 }

l4000000000048130:
	{ nop.m	0x0; adds	r32,0x0,r0; br.cond.sptk.few	4000000000047F40; }

;; xtrace_print_assignment: 4000000000048140
;;   Called from:
;;     400000000006E5CC (in assign_in_env)
;;     40000000000992AC (in fn4000000000099100)
;;     400000000009966C (in fn4000000000099100)
xtrace_print_assignment proc
	{ alloc	r39,ar.pfs,0xE,0x0,0x9; addl	r36,6932,r1; mov	r38,b6 }
	{ adds	r40,0x0,r1; ld8	r37,[r36]; nop.i	0x0; }
	{ cmp.eq	p07,p06,0x0,r37; (p07) addl	r14,-10652,r1; nop.i	0x0; }

l400000000004816C:
	{ cmp4.eq.and	p00,p43,r1,r0; (p01) nop; (p04) cmp.lt.unc	p00,p08,r3,r6 }

l4000000000048176:
	{ (p18) fwb; (p03) nop; br.call.spnt.few	b0,b1; }

l400000000004817C:
	{ invala; Invalid; mov	pr,r32,0x0 }
	{ (p09) cmp.lt	p00,p11,r64,r33; Invalid; Invalid }

l4000000000048190:
	{ ld1	r14,[r33]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000048230; }

l40000000000481B0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r34; (p07) br.cond.dpnt.few	40000000000482F0 }

l40000000000481C0:
	{ addl	r43,-5140,r1; ld8	r41,[r36]; addl	r42,1,r0 }
	{ adds	r44,0x0,r32; adds	r45,0x0,r33; nop.i	0x0 }
	{ ld8	r43,[r43]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001C040; }
	{ adds	r1,0x0,r40; nop.m	0x0; nop.i	0x0 }

l4000000000048200:
	{ ld8	r41,[r36]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A680; }
	{ adds	r1,0x0,r40; nop.m	0x0; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.spnt	b0,r38,4000000000048220; br.ret	b0 }

l4000000000048230:
	{ cmp4.eq	p06,p07,0x0,r34; addl	r43,-5132,r1; addl	r42,1,r0 }
	{ adds	r44,0x0,r32; adds	r45,0x0,r33; (p07) br.cond.dpnt.few	40000000000481C0; }

l4000000000048250:
	{ nop.m	0x0; ld8	r41,[r36]; nop.i	0x0 }
	{ ld8	r43,[r43]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001C040; }
	{ nop.m	0x0; adds	r1,0x0,r40; nop.i	0x0 }
	{ ld8	r41,[r36]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A680; }
	{ adds	r1,0x0,r40; nop.m	0x0; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.spnt	b0,r38,40000000000482A0; br.ret	b0; }

l40000000000482B0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,indirection_level_string; }
	{ adds	r1,0x0,r40; nop.m	0x0; adds	r41,0x0,r8 }
	{ adds	r42,0x0,r37; nop.m	0x0; br.call.sptk.many	b0,fn400000000001C260; }
	{ nop.m	0x0; adds	r1,0x0,r40; br.cond.sptk.few	4000000000048190 }

l40000000000482F0:
	{ adds	r41,0x0,r33; nop.i	0x0; br.call.sptk.many	b0,sh_contains_shell_metas; }
	{ nop.m	0x0; adds	r1,0x0,r40; adds	r41,0x0,r33 }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	40000000000483F0 }

l4000000000048320:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,sh_single_quote; }
	{ nop.m	0x0; adds	r1,0x0,r40; adds	r37,0x0,r8; }

l4000000000048340:
	{ addl	r43,-5132,r1; addl	r42,1,r0; adds	r44,0x0,r32 }
	{ adds	r45,0x0,r37; ld8	r41,[r36]; nop.i	0x0; }
	{ ld8	r43,[r43]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C040; }
	{ cmp.eq	p07,p06,r37,r33; nop.m	0x0; adds	r1,0x0,r40 }
	{ adds	r41,0x0,r37; nop.m	0x0; (p07) br.cond.spnt.few	4000000000048200; }

l4000000000048390:
	{ cmp.eq	p06,p07,0x0,r37; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000048200; }

l40000000000483A0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ nop.m	0x0; adds	r1,0x0,r40; nop.i	0x0 }
	{ ld8	r41,[r36]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A680; }
	{ adds	r1,0x0,r40; nop.m	0x0; mov.i	ar.pfs,r39; }
	{ nop.m	0x0; mov.spnt	b0,r38,40000000000483E0; br.ret	b0; }

l40000000000483F0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,ansic_shouldquote; }
	{ cmp4.eq	p06,p07,0x0,r8; nop.m	0x0; adds	r1,0x0,r40; }
	{ nop.m	0x0; (p06) adds	r37,0x0,r33; (p06) br.cond.dptk.few	4000000000048340 }

l400000000004841C:
	{ (p57) nop; zxt1	r32,r64; br.cond.sptk.few	400000000004861C }

l4000000000048420:
	{ adds	r41,0x0,r33; nop.m	0x0; adds	r42,0x0,r0 }
	{ adds	r43,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,ansic_quote; }
	{ adds	r1,0x0,r40; adds	r37,0x0,r8; br.cond.sptk.few	4000000000048340; }
4000000000048450 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000048460 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000048470 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; xtrace_print_word_list: 4000000000048480
;;   Called from:
;;     4000000000048A6C (in xtrace_print_for_command_head)
;;     4000000000048C28 (in xtrace_print_select_command_head)
xtrace_print_word_list proc
	{ alloc	r38,ar.pfs,0xD,0x0,0x8; addl	r36,6932,r1; mov	r37,b5 }
	{ cmp4.eq	p06,p07,0x0,r33; adds	r39,0x0,r1; adds	r34,0x0,r32; }
	{ ld8	r35,[r36]; cmp.eq	p09,p08,0x0,r35; nop.i	0x0; }
	{ (p09) addl	r14,-10652,r1; (p09) ld8	r14,[r14]; nop.i	0x0; }

l40000000000484B6:
	{ (p07) fwb; nop; dep	r0,r0,r32,63,1 }

l40000000000484BC:
	{ nop; nop; Invalid }

l40000000000484CC:
	{ Invalid; Invalid; mov	pr,r32,0x0 }
	{ Invalid; cmp.eq	p00,p00,r32,r0; nop }

l40000000000484E0:
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r32; (p07) br.cond.dpnt.few	40000000000485C0; }

l40000000000484F0:
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l4000000000048500:
	{ adds	r14,0x8,r34; addl	r42,-5124,r1; addl	r41,1,r0; }
	{ ld8	r14,[r14]; ld8	r42,[r42]; nop.i	0x0; }
	{ nop.m	0x0; ld8	r35,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r35; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000048560; }

l4000000000048540:
	{ ld1	r14,[r35]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0x0,r14; (p06) br.cond.dpnt.few	4000000000048610 }

l4000000000048560:
	{ ld8	r43,[r34]; ld8	r40,[r36]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r43; (p07) addl	r43,-5436,r1; nop.i	0x0; }

l400000000004857C:
	{ nop; (p05) nop; Invalid }

l4000000000048586:
	{ (p21) fwb; nop; (p49) br.call.sptk.few	b2,b0; }

l400000000004858C:
	{ nop; Invalid; break.i	0x1000 }

l4000000000048596:
	{ break.m	0x4000; (p32) nop; (p32) nop }
	{ add	r0,r0,r1; nop; break.i	0x80000 }
	{ (p03) chk.a.clr	r0,3FFFFFFFFFCCB7D6; nop; (p16) br.call.sptk.few	b2,b0 }

l40000000000485C0:
	{ ld8	r41,[r36]; addl	r40,10,r0; br.call.sptk.many	b0,fn400000000001BD80; }
	{ nop.m	0x0; adds	r1,0x0,r39; nop.i	0x0 }
	{ ld8	r40,[r36]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A680; }
	{ adds	r1,0x0,r39; nop.m	0x0; mov.i	ar.pfs,r38; }
	{ nop.m	0x0; mov.spnt	b0,r37,4000000000048600; br.ret	b0; }

l4000000000048610:
	{ adds	r40,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,sh_contains_shell_metas; }
	{ nop.m	0x0; adds	r40,0x0,r35; adds	r1,0x0,r39 }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r8; (p06) br.cond.dptk.few	4000000000048710 }

l4000000000048640:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,sh_single_quote; }
	{ ld8	r44,[r34]; adds	r1,0x0,r39; adds	r35,0x0,r8 }
	{ addl	r41,1,r0; ld8	r40,[r36]; adds	r43,0x0,r8; }
	{ cmp.eq	p06,p07,0x0,r44; nop.m	0x0; addl	r42,-5500,r1; }
	{ (p07) addl	r44,-5436,r1; ld8	r42,[r42]; nop.i	0x0; }

l4000000000048686:
	{ (p21) fwb; addl	r0,49152,r1; (p01) cmp4.eq.or.andcm	p11,p53,0x3F,r31 }

l4000000000048696:
	{ (p22) fwb; nop; (p01) nop; }

l400000000004869C:
	{ pshladd2	r0,r1,1,r0; Invalid; break.i	0x1000 }

l40000000000486A6:
	{ break.m	0x4000; (p32) nop; break.i	0x80000 }
	{ Invalid; (p20) nop; break.b	0x80000 }
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ break.m	0x4000; nop; break.i	0x80000 }

l40000000000486E0:
	{ nop.m	0x0; ld8	r34,[r34]; nop.i	0x0; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r34; (p06) br.cond.dptk.few	4000000000048500 }

l4000000000048700:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000485C0 }

l4000000000048710:
	{ adds	r40,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,ansic_shouldquote; }
	{ adds	r1,0x0,r39; cmp4.eq	p06,p07,0x0,r8; nop.i	0x0 }
	{ addl	r41,1,r0; adds	r43,0x0,r35; (p07) br.cond.dpnt.few	4000000000048810; }

l4000000000048740:
	{ nop.m	0x0; ld8	r44,[r34]; addl	r42,-5500,r1 }
	{ ld8	r40,[r36]; nop.i	0x0; cmp.eq	p06,p07,0x0,r44 }
	{ ld8	r42,[r42]; (p07) addl	r44,-5436,r1; nop.i	0x0; }

l400000000004876C:
	{ pavg2.raz	r0,r1,r0; (p05) nop; Invalid }

l4000000000048776:
	{ (p22) fwb; nop; (p01) nop; }

l400000000004877C:
	{ pshladd2	r0,r1,1,r0; Invalid; break.i	0x1000 }

l4000000000048786:
	{ break.m	0x4000; (p32) nop; (p32) nop }
	{ add	r0,r0,r1; nop; break.i	0x80000 }
	{ (p03) chk.a.clr	r0,3FFFFFFFFFCCB9C6; nop; break.b	0x80000 }

l40000000000487B0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000485C0 }

l40000000000487C0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,indirection_level_string; }
	{ adds	r1,0x0,r39; nop.m	0x0; adds	r40,0x0,r8 }
	{ adds	r41,0x0,r35; nop.m	0x0; br.call.sptk.many	b0,fn400000000001C260; }
	{ adds	r1,0x0,r39; cmp.eq	p07,p06,0x0,r32; (p06) br.cond.dptk.few	4000000000048500 }

l4000000000048800:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000485C0 }

l4000000000048810:
	{ adds	r40,0x0,r35; nop.m	0x0; adds	r41,0x0,r0 }
	{ adds	r42,0x0,r0; nop.m	0x0; br.call.sptk.many	b0,ansic_quote; }
	{ ld8	r44,[r34]; adds	r1,0x0,r39; adds	r35,0x0,r8 }
	{ addl	r41,1,r0; ld8	r40,[r36]; adds	r43,0x0,r8; }
	{ cmp.eq	p06,p07,0x0,r44; nop.m	0x0; addl	r42,-5500,r1; }
	{ (p07) addl	r44,-5436,r1; ld8	r42,[r42]; nop.i	0x0; }

l4000000000048866:
	{ (p21) fwb; addl	r0,49152,r1; (p01) cmp4.eq.or.andcm	p11,p53,0x3F,r31 }

l4000000000048876:
	{ (p22) fwb; nop; (p01) nop; }

l400000000004887C:
	{ pshladd2	r0,r1,1,r0; Invalid; break.i	0x1000 }

l4000000000048886:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ Invalid; (p32) nop; break.i	0x80000 }
	{ Invalid; nop; break.b	0x80000 }
40000000000488B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; print_for_command_head: 40000000000488C0
print_for_command_head proc
	{ alloc	r35,ar.pfs,0x7,0x0,0x5; adds	r14,0x8,r32; mov	r34,b2 }
	{ addl	r37,-5116,r1; addl	r33,-5436,r1; adds	r36,0x0,r1; }
	{ nop.m	0x0; ld8	r14,[r14]; adds	r32,0x10,r32 }
	{ ld8	r37,[r37]; ld8	r33,[r33]; nop.i	0x0; }
	{ ld8	r38,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000045480; }
	{ adds	r1,0x0,r36; ld8	r32,[r32]; mov.spnt	b0,r34,4000000000048910; }
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn4000000000045A00; }
4000000000048940 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
4000000000048950 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000048960 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000048970 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; xtrace_print_for_command_head: 4000000000048980
xtrace_print_for_command_head proc
	{ alloc	r37,ar.pfs,0xB,0x0,0x7; addl	r35,6932,r1; mov	r36,b4 }
	{ adds	r38,0x0,r1; ld8	r34,[r35]; adds	r33,0x0,r0; }
	{ cmp.eq	p07,p06,0x0,r34; (p07) addl	r14,-10652,r1; nop.i	0x0; }

l40000000000489AC:
	{ cmp4.eq.and	p00,p43,r1,r0; (p01) dep	r64,r3,r6,49,9; Invalid }

l40000000000489B6:
	{ (p17) fwb; nop; nop; }

l40000000000489BC:
	{ Invalid; Invalid; break.i	0x1000 }
	{ (p22) nop; invala; break.i	0x1000 }
	{ cmp.eq	p34,p25,r0,r66; break.x	0x10800800801000; }
	{ (p04) nop; cmp.lt	p00,p00,r32,r0; (p01) nop }
	{ cmp.eq	p38,p09,r0,r66; Invalid; zxt4	r0,r0 }
	{ (p08) cmp.lt	p32,p09,r0,r66; nop }
	{ (p02) nop; (p05) nop; }
	{ cmpxchg4.acq	r0,[r0],r1; Invalid; break.i	0x1000 }
	{ (p48) nop; invala; (p04) rfi }
	{ (p18) nop.m	0xE001; break.i	0x1000; (p16) break.i	0x2A809 }
	{ cmpxchg4.acq	r0,[r0],r1; Invalid; break.i	0x1000 }
	{ Invalid; break.m	0x1000; break.i	0x0 }
4000000000048A70 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................

;; print_select_command_head: 4000000000048A80
print_select_command_head proc
	{ alloc	r35,ar.pfs,0x7,0x0,0x5; adds	r14,0x8,r32; mov	r34,b2 }
	{ addl	r37,-5108,r1; addl	r33,-5436,r1; adds	r36,0x0,r1; }
	{ nop.m	0x0; ld8	r14,[r14]; adds	r32,0x10,r32 }
	{ ld8	r37,[r37]; ld8	r33,[r33]; nop.i	0x0; }
	{ ld8	r38,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000045480; }
	{ adds	r1,0x0,r36; ld8	r32,[r32]; mov.spnt	b0,r34,4000000000048AD0; }
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn4000000000045A00; }
4000000000048B00 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
4000000000048B10 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000048B20 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000048B30 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; xtrace_print_select_command_head: 4000000000048B40
xtrace_print_select_command_head proc
	{ alloc	r37,ar.pfs,0xB,0x0,0x7; addl	r35,6932,r1; mov	r36,b4 }
	{ adds	r38,0x0,r1; ld8	r34,[r35]; adds	r33,0x0,r0; }
	{ cmp.eq	p07,p06,0x0,r34; (p07) addl	r14,-10652,r1; nop.i	0x0; }

l4000000000048B6C:
	{ cmp4.eq.and	p00,p43,r1,r0; (p01) dep	r64,r3,r6,49,9; Invalid }

l4000000000048B76:
	{ (p17) fwb; nop; nop; }

l4000000000048B7C:
	{ Invalid; Invalid; break.i	0x1000 }
	{ (p08) nop; invala; break.i	0x1000 }
	{ cmp.eq	p34,p25,r0,r66; break.x	0x10800800801000; }
	{ (p54) nop; cmp.lt	p00,p00,r32,r0; (p01) nop }
	{ cmp.eq	p38,p09,r0,r66; Invalid; zxt4	r0,r0 }
	{ (p08) cmp.lt	p32,p09,r0,r66; nop }
	{ (p06) nop; (p05) nop; }
	{ cmpxchg4.acq	r0,[r0],r1; Invalid; break.i	0x1000 }
	{ (p34) nop; invala; (p04) rfi }
	{ (p18) nop.m	0xE001; break.i	0x1000; (p16) break.i	0x2A809 }
	{ cmpxchg4.acq	r0,[r0],r1; Invalid; break.i	0x1000 }
	{ Invalid; break.m	0x1000; break.i	0x0 }
4000000000048C30 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................

;; print_case_command_head: 4000000000048C40
print_case_command_head proc
	{ alloc	r16,ar.pfs,0x2,0x0,0x2; adds	r14,0x8,r32; addl	r32,-5100,r1; }
	{ ld8	r14,[r14]; ld8	r32,[r32]; nop.i	0x0; }
	{ nop.m	0x0; ld8	r33,[r14]; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x2,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn4000000000045480; }
4000000000048C80 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
4000000000048C90 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000048CA0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000048CB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; xtrace_print_case_command_head: 4000000000048CC0
xtrace_print_case_command_head proc
	{ alloc	r36,ar.pfs,0xA,0x0,0x6; addl	r34,6932,r1; mov	r35,b3 }
	{ adds	r37,0x0,r1; nop.m	0x0; adds	r32,0x8,r32; }
	{ ld8	r33,[r34]; cmp.eq	p07,p06,0x0,r33; nop.i	0x0; }
	{ (p07) addl	r14,-10652,r1; (p07) ld8	r14,[r14]; nop.i	0x0; }

l4000000000048CF6:
	{ (p07) fwb; nop; cmp.lt	p00,p00,r0,r32; }

l4000000000048CFC:
	{ nop; nop; Invalid }

l4000000000048D0C:
	{ Invalid; Invalid; break.i	0x1000 }
	{ (p59) nop; invala; Invalid }
	{ cmp.lt	p33,p25,r0,r66; break.x	0x10800800801000 }
	{ (p41) nop; cmp.lt	p32,p16,r9,r64; Invalid }
	{ Invalid; Invalid; Invalid }
	{ nop; break.i	0x1000; Invalid }
	{ nop; Invalid; break.i	0x1000 }
	{ (p22) nop; invala; break.b	0x1000 }
	{ Invalid; break.i	0x1000; (p48) add	r40,r0,r112 }
	{ nop; break.m	0x1000; break.i	0x1000 }
4000000000048DA0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000048DB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; print_arith_command: 4000000000048DC0
print_arith_command proc
	{ alloc	r34,ar.pfs,0x6,0x0,0x4; addl	r36,-5084,r1; mov	r33,b1 }
	{ nop.m	0x0; adds	r35,0x0,r1; nop.i	0x0; }
	{ ld8	r36,[r36]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000045480; }
	{ adds	r1,0x0,r35; nop.m	0x0; adds	r36,0x0,r32; }
	{ addl	r37,-5436,r1; addl	r32,-5076,r1; nop.i	0x0 }
	{ ld8	r37,[r37]; ld8	r32,[r32]; br.call.sptk.many	b0,fn4000000000045A00; }
	{ adds	r1,0x0,r35; mov.spnt	b0,r33,4000000000048E20; mov.i	ar.pfs,r34; }
	{ alloc	r2,ar.pfs,0x1,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn4000000000045480; }
4000000000048E40 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
4000000000048E50 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000048E60 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000048E70 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; print_cond_command: 4000000000048E80
print_cond_command proc
	{ alloc	r35,ar.pfs,0x6,0x0,0x5; adds	r33,0x0,r32; mov	r34,b2 }
	{ addl	r37,-5068,r1; addl	r32,-5060,r1; adds	r36,0x0,r1; }
	{ nop.m	0x0; ld8	r37,[r37]; nop.i	0x0 }
	{ ld8	r32,[r32]; nop.m	0x0; br.call.sptk.many	b0,fn4000000000045480; }
	{ adds	r1,0x0,r36; adds	r37,0x0,r33; br.call.sptk.many	b0,fn4000000000045B80; }
	{ adds	r1,0x0,r36; mov.spnt	b0,r34,4000000000048ED0; mov.i	ar.pfs,r35; }
	{ alloc	r2,ar.pfs,0x1,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn4000000000045480; }
4000000000048EF0 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................

;; xtrace_print_cond_term: 4000000000048F00
xtrace_print_cond_term proc
	{ alloc	r40,ar.pfs,0xE,0x0,0xA; addl	r37,6932,r1; nop.b	0x0 }
	{ adds	r41,0x0,r1; nop.m	0x0; mov	r39,b7; }
	{ ld8	r38,[r37]; cmp.eq	p07,p06,0x0,r38; nop.i	0x0; }
	{ (p07) addl	r14,-10652,r1; (p07) ld8	r14,[r14]; nop.i	0x0; }

l4000000000048F36:
	{ (p07) fwb; cmp.lt	p00,p00,0x0,r1; (p33) nop; }

l4000000000048F3C:
	{ cmp4.eq.and	p00,p34,r1,r0; (p04) cmp.lt.unc	p00,p08,r3,r6; zxt4	r39,r13 }

l4000000000048F46:
	{ Invalid; nop; nop }
	{ mf.a; (p32) nop; (p16) nop }
	{ break.m	0x4000; (p21) nop; (p48) nop }
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ add	r0,r0,r1; (p21) mov.sptk	b1,r0,4000000000049386; (p16) nop }
	{ Invalid; (p21) nop; (p32) nop }
	{ break.m	0x4000; (p32) nop; (p32) nop }
	{ chk.a.clr	f0,3FFFFFFFFF0C9246; nop; break.b	0x80000 }

l4000000000048FC0:
	{ nop.m	0x0; cmp4.eq	p07,p06,0x3,r32; (p07) br.cond.dpnt.few	40000000000491E0; }

l4000000000048FD0:
	{ cmp4.eq	p07,p06,0x4,r32; addl	r42,-5028,r1; nop.i	0x0 }
	{ addl	r43,1,r0; addl	r44,4,r0; (p07) br.cond.dpnt.few	4000000000049050; }

l4000000000048FF0:
	{ nop.m	0x0; ld8	r45,[r37]; nop.i	0x0 }
	{ ld8	r42,[r42]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001B000; }
	{ nop.m	0x0; adds	r1,0x0,r41; nop.i	0x0 }
	{ ld8	r42,[r37]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A680; }
	{ adds	r1,0x0,r41; nop.m	0x0; mov.i	ar.pfs,r40; }
	{ nop.m	0x0; mov.spnt	b0,r39,4000000000049040; br.ret	b0 }

l4000000000049050:
	{ ld8	r43,[r37]; cmp.eq	p07,p06,0x0,r35; (p07) br.cond.dpnt.few	4000000000049310; }

l4000000000049060:
	{ ld1	r14,[r35]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	4000000000049310 }

l4000000000049080:
	{ adds	r42,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C260; }
	{ adds	r1,0x0,r41; nop.m	0x0; addl	r43,1,r0 }
	{ ld8	r42,[r37]; ld8	r45,[r34]; nop.i	0x0; }
	{ nop.m	0x0; addl	r44,-5036,r1; nop.i	0x0; }
	{ ld8	r44,[r44]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C040; }
	{ adds	r1,0x0,r41; ld8	r43,[r37]; cmp.eq	p07,p06,0x0,r36 }
	{ nop.m	0x0; nop.m	0x0; (p07) br.cond.dpnt.few	40000000000492E0; }

l40000000000490F0:
	{ ld1	r14,[r36]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p06) br.cond.dptk.few	40000000000492E0 }

l4000000000049110:
	{ nop.m	0x0; adds	r42,0x0,r36; br.call.sptk.many	b0,fn400000000001C260; }
	{ adds	r1,0x0,r41; nop.m	0x0; nop.i	0x0; }

l4000000000049130:
	{ addl	r42,-5028,r1; nop.m	0x0; addl	r43,1,r0 }
	{ ld8	r45,[r37]; nop.m	0x0; addl	r44,4,r0; }
	{ ld8	r42,[r42]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B000; }
	{ nop.m	0x0; adds	r1,0x0,r41; nop.i	0x0 }
	{ ld8	r42,[r37]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A680; }
	{ adds	r1,0x0,r41; nop.m	0x0; mov.i	ar.pfs,r40; }
	{ nop.m	0x0; mov.spnt	b0,r39,4000000000049190; br.ret	b0 }

l40000000000491A0:
	{ addl	r42,-5484,r1; nop.m	0x0; addl	r14,6932,r1 }
	{ addl	r43,1,r0; addl	r44,2,r0; nop.i	0x0 }
	{ ld8	r42,[r42]; ld8	r45,[r14]; br.call.sptk.many	b0,fn400000000001B000; }
	{ adds	r1,0x0,r41; cmp4.eq	p07,p06,0x3,r32; (p06) br.cond.dptk.few	4000000000048FD0; }

l40000000000491E0:
	{ addl	r44,-5044,r1; ld8	r42,[r37]; addl	r43,1,r0 }
	{ nop.m	0x0; ld8	r45,[r34]; nop.i	0x0; }
	{ ld8	r44,[r44]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C040; }
	{ adds	r1,0x0,r41; ld8	r43,[r37]; nop.i	0x0 }
	{ cmp.eq	p07,p06,0x0,r35; adds	r42,0x0,r35; (p07) br.cond.dpnt.few	4000000000049330; }

l4000000000049230:
	{ ld1	r14,[r35]; nop.m	0x0; sxt1	r14,r14; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000049330; }

l4000000000049250:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C260; }
	{ adds	r1,0x0,r41; nop.m	0x0; nop.i	0x0; }

l4000000000049270:
	{ addl	r42,-5028,r1; nop.m	0x0; addl	r43,1,r0 }
	{ ld8	r45,[r37]; nop.m	0x0; addl	r44,4,r0; }
	{ ld8	r42,[r42]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B000; }
	{ nop.m	0x0; adds	r1,0x0,r41; nop.i	0x0 }
	{ ld8	r42,[r37]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A680; }
	{ adds	r1,0x0,r41; nop.m	0x0; mov.i	ar.pfs,r40; }
	{ nop.m	0x0; mov.spnt	b0,r39,40000000000492D0; br.ret	b0 }

l40000000000492E0:
	{ addl	r36,-5052,r1; ld8	r36,[r36]; nop.i	0x0; }
	{ adds	r42,0x0,r36; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C260; }
	{ nop.m	0x0; adds	r1,0x0,r41; br.cond.sptk.few	4000000000049130; }

l4000000000049310:
	{ nop.m	0x0; addl	r35,-5052,r1; nop.i	0x0; }
	{ ld8	r35,[r35]; nop.i	0x0; br.cond.sptk.few	4000000000049080; }

l4000000000049330:
	{ addl	r35,-5052,r1; ld8	r35,[r35]; nop.i	0x0; }
	{ adds	r42,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,fn400000000001C260; }
	{ nop.m	0x0; adds	r1,0x0,r41; br.cond.sptk.few	4000000000049270; }
4000000000049360 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
4000000000049370 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; xtrace_print_arith_cmd: 4000000000049380
xtrace_print_arith_cmd proc
	{ alloc	r37,ar.pfs,0xC,0x0,0x7; addl	r34,6932,r1; nop.b	0x0 }
	{ adds	r38,0x0,r1; mov	r36,b4; adds	r33,0x0,r32; }
	{ ld8	r35,[r34]; cmp.eq	p07,p06,0x0,r35; nop.i	0x0; }
	{ (p07) addl	r14,-10652,r1; (p07) ld8	r14,[r14]; nop.i	0x0; }

l40000000000493B6:
	{ (p07) fwb; nop; cmp.lt	p00,p00,r0,r32; }

l40000000000493BC:
	{ nop; nop; Invalid }

l40000000000493CC:
	{ Invalid; Invalid; break.i	0x1000 }
	{ (p05) nop; invala; Invalid }
	{ nop; break.x	0x10802300A01000 }
	{ (p51) nop; invala; break.b	0x1000 }
	{ Invalid; Invalid; Invalid }
	{ (p50) cmp.eq.unc	p61,p17,r88,r79; break.x	0x80C2700801000 }
	{ (p31) nop; cmp.eq.unc	p00,p16,r9,r64; mov	pr,r72,0xE400 }
	{ (p05) ldf8	f0,[r33]; (p05) cmp.lt	p32,p08,r8,r6; (p01) nop }

l4000000000049440:
	{ ld8	r43,[r33]; adds	r14,0x8,r33; addl	r41,-5500,r1 }
	{ addl	r40,1,r0; ld8	r39,[r34]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r43; ld8	r14,[r14]; nop.i	0x0 }
	{ ld8	r41,[r41]; (p07) addl	r43,-5436,r1; nop.i	0x0; }

l400000000004947C:
	{ nop; (p05) dep	r63,r31,r117,62,4; Invalid }

l4000000000049486:
	{ (p21) fwb; nop; cmp.lt	p00,p00,r0,r32 }
	{ (p21) fwb; nop; (p49) br.call.sptk.few	b2,b0; }

l400000000004949C:
	{ nop; Invalid; break.i	0x1000 }

l40000000000494A6:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ add	r0,r0,r1; nop; break.i	0x80000 }
	{ (p03) chk.a.clr	r0,3FFFFFFFFFCCC6D6; nop; (p48) nop }

l40000000000494D0:
	{ addl	r39,-5012,r1; nop.m	0x0; addl	r40,1,r0 }
	{ ld8	r42,[r34]; nop.m	0x0; addl	r41,4,r0; }
	{ ld8	r39,[r39]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B000; }
	{ nop.m	0x0; adds	r1,0x0,r38; nop.i	0x0 }
	{ ld8	r39,[r34]; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A680; }
	{ adds	r1,0x0,r38; nop.m	0x0; mov.i	ar.pfs,r37; }
	{ nop.m	0x0; mov.spnt	b0,r36,4000000000049530; br.ret	b0; }

;; print_simple_command: 4000000000049540
print_simple_command proc
	{ alloc	r35,ar.pfs,0x7,0x0,0x5; adds	r33,0x10,r32; mov	r34,b2 }
	{ addl	r38,-5436,r1; adds	r32,0x8,r32; adds	r36,0x0,r1; }
	{ nop.m	0x0; ld8	r38,[r38]; nop.i	0x0 }
	{ ld8	r37,[r32]; nop.m	0x0; br.call.sptk.many	b0,fn4000000000045A00; }
	{ adds	r1,0x0,r36; ld8	r14,[r33]; nop.i	0x0; }
	{ addl	r37,-5436,r1; cmp.eq	p06,p07,0x0,r14; (p06) br.cond.dpnt.few	40000000000495E0; }

l40000000000495A0:
	{ ld8	r37,[r37]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000045480; }
	{ adds	r1,0x0,r36; ld8	r32,[r33]; mov.spnt	b0,r34,40000000000495B0; }
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ alloc	r2,ar.pfs,0x1,0x0,0x0; nop.i	0x0; br.cond.sptk.many	fn40000000000470C0 }

l40000000000495E0:
	{ nop.m	0x0; mov.i	ar.pfs,r35; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r34,40000000000495F0; br.ret	b0; }

;; fn4000000000049600: 4000000000049600
;;   Called from:
;;     400000000004B10C (in make_command_string)
;;     400000000004B34C (in named_function_string)
;;     400000000004B5AC (in named_function_string)
;;     400000000004B5AC (in named_function_string)
fn4000000000049600 proc
	{ alloc	r40,ar.pfs,0xE,0x0,0xA; adds	r12,0xFFFFFFFFFFFFFFF0,r12; nop.b	0x0 }
	{ addl	r34,6972,r1; mov	r39,b7; adds	r41,0x0,r1; }
	{ cmp.eq	p07,p06,0x0,r32; adds	r33,0x4,r32; (p07) br.cond.dpnt.few	400000000004ABE0; }

l4000000000049630:
	{ nop.m	0x0; ld4	r14,[r34]; nop.i	0x0; }
	{ cmp4.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000049890; }

l4000000000049650:
	{ nop.m	0x0; (p07) adds	r14,0xFFFFFFFFFFFFFFFF,r14; nop.i	0x0; }

l400000000004965C:
	{ Invalid; (p32) cmp.lt.unc	p03,p08,r8,r100; Invalid }

l4000000000049666:
	{ (p07) fwb; nop; break.i	0x80000 }
	{ (p03) chk.a.nc	f14,3FFFFFFFFFA4CF56; nop; break.i	0x80000 }

l4000000000049680:
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x2; (p07) br.cond.dpnt.few	40000000000497B0 }

l4000000000049690:
	{ nop.m	0x0; ld4	r44,[r32]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0xE,r44; (p07) br.cond.dptk.few	4000000000049770 }

l40000000000496B0:
	{ addl	r42,-4804,r1; addl	r43,1,r0; adds	r45,0x0,r0; }
	{ ld8	r42,[r42]; br.call.sptk.many	b0,command_error; nop.b	0x0; }
	{ adds	r1,0x0,r41; nop.m	0x0; nop.i	0x0; }
	{ adds	r32,0x10,r32; nop.m	0x0; addl	r42,-5436,r1; }
	{ nop.m	0x0; ld8	r14,[r32]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r14; nop.i	0x0; (p06) br.cond.dpnt.few	4000000000049750; }

l4000000000049710:
	{ ld8	r42,[r42]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000045480; }
	{ nop.m	0x0; adds	r1,0x0,r41; nop.i	0x0 }
	{ ld8	r42,[r32]; nop.m	0x0; br.call.sptk.many	b0,fn40000000000470C0; }
	{ adds	r1,0x0,r41; nop.m	0x0; nop.i	0x0 }

l4000000000049750:
	{ nop.m	0x0; mov.i	ar.pfs,r40; mov.spnt	b0,r39,4000000000049750 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }

l4000000000049770:
	{ addl	r14,-4772,r1; nop.m	0x0; addp4	r44,r44,r0; }
	{ ld8	r14,[r14]; shladd	r44,r44,0x3,r14; nop.i	0x0; }
	{ ld8	r14,[r44]; add	r44,r44,r14; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b6,r44,40000000000497A0; br.cond	b6; }

l40000000000497B0:
	{ nop.m	0x0; addl	r42,-5484,r1; nop.i	0x0; }
	{ ld8	r42,[r42]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000045480; }
	{ ld4	r44,[r32]; nop.m	0x0; adds	r1,0x0,r41; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0xE,r44; (p06) br.cond.dptk.few	40000000000496B0 }

l40000000000497F0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000049770 }

l4000000000049800:
	{ nop.m	0x0; addl	r42,-5004,r1; nop.i	0x0; }
	{ ld8	r42,[r42]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000045480; }
	{ ld4	r14,[r33]; nop.m	0x0; adds	r1,0x0,r41; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x8; (p06) br.cond.dptk.few	4000000000049680 }

l4000000000049840:
	{ nop.m	0x0; addl	r42,-4996,r1; nop.i	0x0; }
	{ ld8	r42,[r42]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000045480; }
	{ ld4	r14,[r33]; nop.m	0x0; adds	r1,0x0,r41; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x2; (p06) br.cond.dptk.few	4000000000049690 }

l4000000000049880:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	40000000000497B0 }

l4000000000049890:
	{ addl	r14,6976,r1; nop.m	0x0; adds	r33,0x4,r32; }
	{ ld4	r42,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000045FC0; }
	{ ld4	r14,[r33]; nop.m	0x0; adds	r1,0x0,r41; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x7; (p06) br.cond.dptk.few	4000000000049680 }

l40000000000498D0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	4000000000049800 }
40000000000498E0 09 00 00 00 01 00 A0 E2 F4 AB 4F 00 00 00 04 00 ..........O.....
40000000000498F0 11 50 01 54 18 10 00 00 00 02 00 00 98 BB FF 58 .P.T...........X
4000000000049900 09 78 60 40 00 21 E0 00 88 20 20 20 00 48 01 84 .x`@.!...   .H..
4000000000049910 09 78 00 1E 18 10 00 00 00 02 00 C0 11 70 00 84 .x...........p..
4000000000049920 09 78 20 1E 00 21 00 70 88 20 23 00 00 00 04 00 .x ..!.p. #.....
4000000000049930 11 50 01 1E 18 10 00 00 00 02 00 00 D8 FC FF 58 .P.............X
4000000000049940 0B 08 00 52 00 21 E0 A0 05 6C 48 40 C5 EF 53 9F ...R.!...lH@..S.
4000000000049950 09 00 00 00 01 00 E0 00 38 30 20 00 00 00 04 00 ........80 .....
4000000000049960 11 30 00 1C 07 39 00 00 00 02 00 03 30 00 00 43 .0...9......0..C
4000000000049970 13 50 01 54 18 10 00 8C ED 7F 2C 00 00 00 00 20 .P.T......,.... 
4000000000049980 09 08 00 52 00 21 00 00 00 02 00 00 00 00 04 00 ...R.!..........
4000000000049990 09 00 00 00 01 00 A0 22 F5 AB 4F 00 00 00 04 00 ......."..O.....
40000000000499A0 11 50 01 54 18 10 00 00 00 02 00 00 E8 BA FF 58 .P.T...........X
40000000000499B0 11 00 00 00 01 00 10 00 A4 00 42 00 30 FD FF 48 ..........B.0..H
40000000000499C0 09 70 60 40 00 21 10 02 06 6C 48 60 04 0F B0 90 .p`@.!...lH`....
40000000000499D0 09 00 00 00 01 00 20 02 38 30 20 00 00 00 04 00 ...... .80 .....
40000000000499E0 11 50 01 44 00 21 20 C2 88 00 42 00 E8 EE FF 58 .P.D.! ...B....X
40000000000499F0 0B 08 00 52 00 21 A0 62 F4 AB 4F 00 00 00 04 00 ...R.!.b..O.....
4000000000049A00 11 50 01 54 18 10 00 00 00 02 00 00 88 BA FF 58 .P.T...........X
4000000000049A10 0B 08 00 52 00 21 A0 22 F4 B3 4F 00 00 00 04 00 ...R.!."..O.....
4000000000049A20 11 50 01 54 18 10 00 00 00 02 00 00 68 C7 FF 58 .P.T........h..X
4000000000049A30 08 08 00 52 00 21 F0 00 84 20 20 00 00 00 04 00 ...R.!...  .....
4000000000049A40 09 70 00 46 10 10 00 00 00 02 00 00 00 00 04 00 .p.F............
4000000000049A50 09 70 3C 1C 00 20 A0 02 88 30 20 00 00 00 04 00 .p<.. ...0 .....
4000000000049A60 11 00 38 42 90 11 00 00 00 02 00 00 A8 FB FF 58 ..8B...........X
4000000000049A70 0B 08 00 52 00 21 E0 A0 05 6C 48 40 C5 EF 53 9F ...R.!...lH@..S.
4000000000049A80 09 00 00 00 01 00 E0 00 38 30 20 00 00 00 04 00 ........80 .....
4000000000049A90 11 30 00 1C 07 39 00 00 00 02 00 03 30 00 00 43 .0...9......0..C
4000000000049AA0 13 50 01 54 18 10 00 F4 EC 7F 2C 00 00 00 00 20 .P.T......,.... 
4000000000049AB0 08 08 00 52 00 21 00 00 00 02 00 00 00 00 04 00 ...R.!..........
4000000000049AC0 11 00 00 00 01 00 00 00 00 02 00 00 08 C0 FF 58 ...............X
4000000000049AD0 08 08 00 52 00 21 E0 00 84 20 20 00 00 00 04 00 ...R.!...  .....
4000000000049AE0 0B 78 00 46 10 10 A0 62 F4 B3 4F C0 E1 78 14 80 .x.F...b..O..x..
4000000000049AF0 08 00 00 00 01 00 A0 02 A8 30 20 00 00 00 04 00 .........0 .....
4000000000049B00 19 00 38 42 90 11 00 00 00 02 00 00 88 C6 FF 58 ..8B...........X
4000000000049B10 11 00 00 00 01 00 10 00 A4 00 42 00 D0 FB FF 48 ..........B....H
4000000000049B20 09 08 61 40 00 21 00 00 00 02 00 40 45 EB 6B 9F ..a@.!.....@E.k.
4000000000049B30 09 70 00 42 18 10 A0 02 A8 30 20 00 00 00 04 00 .p.B.....0 .....
4000000000049B40 09 00 00 00 01 00 E0 40 38 00 42 00 00 00 04 00 .......@8.B.....
4000000000049B50 11 58 01 1C 18 10 00 00 00 02 00 00 38 B9 FF 58 .X..........8..X
4000000000049B60 08 00 00 00 01 00 E0 00 88 20 20 20 00 48 01 84 .........   .H..
4000000000049B70 0B 78 00 42 18 10 E0 08 38 00 42 E0 01 79 00 84 .x.B....8.B..y..
4000000000049B80 08 00 00 00 01 00 00 70 88 20 23 00 00 00 04 00 .......p. #.....
4000000000049B90 19 50 01 1E 18 10 00 00 00 02 00 00 78 FA FF 58 .P..........x..X
4000000000049BA0 10 00 00 00 01 00 10 00 A4 00 42 00 40 FB FF 48 ..........B.@..H
4000000000049BB0 09 00 00 00 01 00 E0 C0 80 00 42 00 00 00 04 00 ..........B.....
4000000000049BC0 11 50 01 1C 18 10 00 00 00 02 00 00 88 F9 FF 58 .P.............X
4000000000049BD0 11 00 00 00 01 00 10 00 A4 00 42 00 10 FB FF 48 ..........B....H
4000000000049BE0 08 70 60 40 00 21 00 00 00 02 00 40 45 EE 67 9F .p`@.!.....@E.g.
4000000000049BF0 02 08 01 03 36 24 30 82 07 58 48 00 00 00 04 00 ....6$0..XH.....
4000000000049C00 19 28 01 1C 18 10 A0 02 A8 30 20 00 88 B8 FF 58 .(.......0 ....X
4000000000049C10 09 70 00 44 10 10 F0 40 94 00 42 20 00 48 01 84 .p.D...@..B .H..
4000000000049C20 09 70 04 1C 00 21 A0 02 3C 30 20 80 44 0B D8 90 .p...!..<0 .D...
4000000000049C30 11 00 38 44 90 11 00 00 00 02 00 00 D8 F9 FF 58 ..8D...........X
4000000000049C40 11 08 00 52 00 21 00 00 00 02 00 00 88 BE FF 58 ...R.!.........X
4000000000049C50 0B 08 00 52 00 21 A0 62 F7 B3 4F 00 00 00 04 00 ...R.!.b..O.....
4000000000049C60 11 50 01 54 18 10 00 00 00 02 00 00 28 B8 FF 58 .P.T........(..X
4000000000049C70 08 78 00 42 10 10 00 00 00 02 00 00 02 29 01 84 .x.B.........)..
4000000000049C80 09 08 00 52 00 21 E0 00 8C 20 20 00 00 00 04 00 ...R.!...  .....
4000000000049C90 09 70 3C 1C 00 20 A0 02 40 30 20 00 00 00 04 00 .p<.. ..@0 .....
4000000000049CA0 11 00 38 42 90 11 00 00 00 02 00 00 68 F9 FF 58 ..8B........h..X
4000000000049CB0 09 08 00 52 00 21 E0 00 90 30 20 00 00 00 04 00 ...R.!...0 .....
4000000000049CC0 11 30 00 1C 07 39 A0 E2 F7 A9 4F 03 30 00 00 43 .0...9....O.0..C
4000000000049CD0 13 50 01 54 18 10 00 DC EB 7F 2C 00 00 00 00 20 .P.T......,.... 
4000000000049CE0 09 08 00 52 00 21 00 00 00 02 00 00 00 00 04 00 ...R.!..........
4000000000049CF0 08 78 00 42 10 10 50 C2 94 00 42 40 04 0C D8 90 .x.B..P...B@....
4000000000049D00 02 70 00 46 10 10 00 00 00 02 00 E0 F1 70 14 80 .p.F.........p..
4000000000049D10 0A 70 00 4A 18 10 00 00 00 02 00 C0 00 70 1C E4 .p.J.........p..
4000000000049D20 19 00 00 00 01 00 00 78 84 20 23 03 F0 00 00 43 .......x. #....C
4000000000049D30 11 00 00 00 01 00 00 00 00 02 00 00 98 BD FF 58 ...............X
4000000000049D40 0B 08 00 52 00 21 A0 A2 F7 B3 4F 00 00 00 04 00 ...R.!....O.....
4000000000049D50 11 50 01 54 18 10 00 00 00 02 00 00 38 C4 FF 58 .P.T........8..X
4000000000049D60 08 08 00 52 00 21 E0 00 88 20 20 00 00 00 04 00 ...R.!...  .....
4000000000049D70 0B 50 01 4A 18 10 F0 80 07 58 48 00 00 00 04 00 .P.J.....XH.....
4000000000049D80 0B 78 00 1E 10 10 E0 70 3C 00 40 00 00 00 04 00 .x.....p<.@.....
4000000000049D90 11 00 38 44 90 11 00 00 00 02 00 00 78 F8 FF 58 ..8D........x..X
4000000000049DA0 09 08 00 52 00 21 E0 00 90 30 20 00 00 00 04 00 ...R.!...0 .....
4000000000049DB0 11 30 00 1C 07 39 A0 E2 F7 A9 4F 03 30 00 00 43 .0...9....O.0..C
4000000000049DC0 13 50 01 54 18 10 00 64 EB 7F 2C 00 00 00 00 20 .P.T...d..,.... 
4000000000049DD0 08 08 00 52 00 21 00 00 00 02 00 00 00 00 04 00 ...R.!..........
4000000000049DE0 09 70 00 42 10 10 F0 00 8C 20 20 00 00 00 04 00 .p.B.....  .....
4000000000049DF0 09 00 00 00 01 00 E0 70 3C 0A 40 00 00 00 04 00 .......p<.@.....
4000000000049E00 08 00 38 42 90 11 00 00 00 02 00 00 00 00 04 00 ..8B............
4000000000049E10 11 00 00 00 01 00 00 00 00 02 00 00 B8 BC FF 58 ...............X
4000000000049E20 0B 08 00 52 00 21 A0 E2 F7 B3 4F 00 00 00 04 00 ...R.!....O.....
4000000000049E30 11 50 01 54 18 10 00 00 00 02 00 00 58 C3 FF 58 .P.T........X..X
4000000000049E40 11 00 00 00 01 00 10 00 A4 00 42 00 A0 F8 FF 48 ..........B....H
4000000000049E50 02 70 60 40 00 21 B0 A2 F6 B3 4F 00 00 00 04 00 .p`@.!....O.....
4000000000049E60 19 58 01 56 18 10 A0 02 38 30 20 00 68 10 00 50 .X.V....80 .h..P
4000000000049E70 10 00 00 00 01 00 10 00 A4 00 42 00 70 F8 FF 48 ..........B.p..H
4000000000049E80 0B 70 60 40 00 21 10 02 38 30 20 00 00 00 04 00 .p`@.!..80 .....
4000000000049E90 11 50 01 42 00 21 10 82 84 00 42 00 B8 ED FF 58 .P.B.!....B....X
4000000000049EA0 09 08 00 52 00 21 20 02 84 30 20 00 00 00 04 00 ...R.! ..0 .....
4000000000049EB0 08 18 C1 03 2C 24 10 02 06 6C 48 00 00 00 04 00 ....,$...lH.....
4000000000049EC0 19 30 00 44 07 39 40 A2 05 6C 48 03 10 02 00 43 .0.D.9@..lH....C
4000000000049ED0 09 78 00 42 10 10 E0 00 8C 20 20 00 00 00 04 00 .x.B.....  .....
4000000000049EE0 09 00 00 00 01 00 E0 78 38 00 40 00 00 00 04 00 .......x8.@.....
4000000000049EF0 09 00 38 42 90 11 00 00 00 02 00 00 00 00 04 00 ..8B............
4000000000049F00 09 00 00 00 01 00 A0 E2 F7 A9 4F 00 00 00 04 00 ..........O.....
4000000000049F10 11 50 01 54 18 10 00 00 00 02 00 00 78 C2 FF 58 .P.T........x..X
4000000000049F20 09 08 00 52 00 21 00 00 00 02 00 C0 81 10 01 84 ...R.!..........
4000000000049F30 09 58 91 FA D9 27 A0 02 38 30 20 00 00 00 04 00 .X...'..80 .....
4000000000049F40 11 58 01 56 18 10 00 00 00 02 00 00 C8 BA FF 58 .X.V...........X
4000000000049F50 0B 08 00 52 00 21 A0 62 F5 B3 4F 00 00 00 04 00 ...R.!.b..O.....
4000000000049F60 11 50 01 54 18 10 00 00 00 02 00 00 28 B5 FF 58 .P.T........(..X
4000000000049F70 08 78 00 42 10 10 00 00 00 02 00 00 02 11 01 84 .x.B............
4000000000049F80 09 08 00 52 00 21 E0 00 8C 20 20 00 00 00 04 00 ...R.!...  .....
4000000000049F90 09 70 3C 1C 00 20 A0 02 40 30 20 00 00 00 04 00 .p<.. ..@0 .....
4000000000049FA0 11 00 38 42 90 11 00 00 00 02 00 00 68 F6 FF 58 ..8B........h..X
4000000000049FB0 08 00 00 00 01 00 F0 00 84 20 20 20 00 48 01 84 .........   .H..
4000000000049FC0 09 00 00 00 01 00 E0 00 8C 20 20 00 00 00 04 00 .........  .....
4000000000049FD0 09 78 3C 1C 05 20 E0 00 90 30 20 00 00 00 04 00 .x<.. ...0 .....
4000000000049FE0 11 00 3C 42 90 11 60 00 38 0E 72 03 40 00 00 43 ..<B..`.8.r.@..C
4000000000049FF0 02 50 F1 FB D4 27 00 00 00 02 00 00 00 00 04 00 .P...'..........
400000000004A000 19 50 01 54 18 10 00 00 00 02 00 00 88 D4 FF 58 .P.T...........X
400000000004A010 08 08 00 52 00 21 00 00 00 02 00 00 00 00 04 00 ...R.!..........
400000000004A020 0B 70 60 44 00 21 E0 00 38 20 20 00 00 00 04 00 .p`D.!..8  .....
400000000004A030 11 00 00 00 01 00 60 00 38 0E A8 03 80 0B 00 43 ......`.8......C
400000000004A040 03 00 00 00 01 00 60 10 38 0E A8 43 C5 EB 67 9F ......`.8..C..g.
400000000004A050 CB 50 11 FB D9 E7 A1 02 A8 30 20 00 00 00 04 00 .P.......0 .....
400000000004A060 D3 50 01 54 18 10 00 94 E0 7F 2C 00 00 00 00 20 .P.T......,.... 
400000000004A070 08 08 00 52 00 21 00 00 00 02 00 00 00 00 04 00 ...R.!..........
400000000004A080 09 00 00 00 01 00 20 02 88 30 20 00 00 00 04 00 ...... ..0 .....
400000000004A090 10 00 00 00 01 00 70 00 88 0C 72 03 70 FE FF 4A ......p...r.p..J
400000000004A0A0 09 70 00 42 10 10 F0 00 8C 20 20 00 00 00 04 00 .p.B.....  .....
400000000004A0B0 09 00 00 00 01 00 E0 70 3C 0A 40 00 00 00 04 00 .......p<.@.....
400000000004A0C0 08 00 38 42 90 11 00 00 00 02 00 00 00 00 04 00 ..8B............
400000000004A0D0 09 00 00 00 01 00 A0 62 F6 B3 4F 00 00 00 04 00 .......b..O.....
400000000004A0E0 11 50 01 54 18 10 00 00 00 02 00 00 A8 C0 FF 58 .P.T...........X
400000000004A0F0 11 00 00 00 01 00 10 00 A4 00 42 00 F0 F5 FF 48 ..........B....H
400000000004A100 08 70 60 40 00 21 00 00 00 02 00 40 45 E9 67 9F .p`@.!.....@E.g.
400000000004A110 02 08 01 03 36 24 30 82 07 58 48 00 00 00 04 00 ....6$0..XH.....
400000000004A120 19 10 01 1C 18 10 A0 02 A8 30 20 00 68 B3 FF 58 .........0 .h..X
400000000004A130 09 08 00 52 00 21 00 00 00 02 00 C0 81 10 01 84 ...R.!..........
400000000004A140 09 58 11 FB D5 27 A0 02 38 30 20 00 00 00 04 00 .X...'..80 .....
400000000004A150 11 58 01 56 18 10 00 00 00 02 00 00 B8 B8 FF 58 .X.V...........X
400000000004A160 0B 08 00 52 00 21 A0 E2 F4 B3 4F 00 00 00 04 00 ...R.!....O.....
400000000004A170 11 50 01 54 18 10 00 00 00 02 00 00 18 B3 FF 58 .P.T...........X
400000000004A180 09 08 00 52 00 21 00 00 00 02 00 C0 01 11 01 84 ...R.!..........
400000000004A190 09 58 11 FB D5 27 A0 02 38 30 20 00 00 00 04 00 .X...'..80 .....
400000000004A1A0 11 58 01 56 18 10 00 00 00 02 00 00 68 B8 FF 58 .X.V........h..X
400000000004A1B0 0B 08 00 52 00 21 A0 E2 F4 B3 4F 00 00 00 04 00 ...R.!....O.....
400000000004A1C0 11 50 01 54 18 10 00 00 00 02 00 00 C8 B2 FF 58 .P.T...........X
400000000004A1D0 09 08 00 52 00 21 E0 C0 88 00 42 40 04 12 01 84 ...R.!....B@....
400000000004A1E0 09 58 11 FB D5 27 A0 02 38 30 20 00 00 00 04 00 .X...'..80 .....
400000000004A1F0 11 58 01 56 18 10 00 00 00 02 00 00 18 B8 FF 58 .X.V...........X
400000000004A200 0B 08 00 52 00 21 A0 62 F5 B1 4F 00 00 00 04 00 ...R.!.b..O.....
400000000004A210 11 50 01 54 18 10 00 00 00 02 00 00 78 B2 FF 58 .P.T........x..X
400000000004A220 0B 08 00 52 00 21 A0 22 F4 B3 4F 00 00 00 04 00 ...R.!."..O.....
400000000004A230 11 50 01 54 18 10 00 00 00 02 00 00 58 BF FF 58 .P.T........X..X
400000000004A240 08 00 00 00 01 00 10 00 A4 00 42 00 00 00 04 00 ..........B.....
400000000004A250 19 78 00 42 10 10 E0 00 8C 20 20 00 00 F8 FF 48 .x.B.....  ....H
400000000004A260 02 70 60 40 00 21 B0 E2 F6 B3 4F 00 00 00 04 00 .p`@.!....O.....
400000000004A270 19 58 01 56 18 10 A0 02 38 30 20 00 58 0C 00 50 .X.V....80 .X..P
400000000004A280 11 00 00 00 01 00 10 00 A4 00 42 00 60 F4 FF 48 ..........B.`..H
400000000004A290 08 70 60 40 00 21 A0 62 F4 B5 4F 00 00 00 04 00 .p`@.!.b..O.....
400000000004A2A0 09 08 01 03 36 24 20 42 06 6C 48 80 04 0F B0 90 ....6$ B.lH.....
400000000004A2B0 09 18 01 1C 18 10 A0 02 A8 30 20 00 00 00 04 00 .........0 .....
400000000004A2C0 09 70 20 46 00 21 00 00 00 02 00 60 04 19 01 84 .p F.!.....`....
400000000004A2D0 09 00 00 00 01 00 E0 00 38 30 20 00 00 00 04 00 ........80 .....
400000000004A2E0 11 58 01 1C 18 10 00 00 00 02 00 00 A8 B1 FF 58 .X.............X
400000000004A2F0 03 08 00 52 00 21 B0 02 00 00 42 40 45 EE 53 9F ...R.!....B@E.S.
400000000004A300 11 50 01 54 18 10 00 00 00 02 00 00 08 7D 06 50 .P.T.........}.P
400000000004A310 08 00 00 00 01 00 10 00 A4 00 42 00 00 00 04 00 ..........B.....
400000000004A320 19 50 01 42 10 10 00 00 00 02 00 00 A8 BC FF 58 .P.B...........X
400000000004A330 0B 08 00 52 00 21 A0 A2 F4 B5 4F 00 00 00 04 00 ...R.!....O.....
400000000004A340 11 50 01 54 18 10 00 00 00 02 00 00 48 B1 FF 58 .P.T........H..X
400000000004A350 08 00 00 00 01 00 F0 00 84 20 20 20 00 48 01 84 .........   .H..
400000000004A360 0A 80 00 44 10 10 E0 00 90 20 20 00 12 80 00 84 ...D.....  .....
400000000004A370 09 00 00 00 01 00 A0 02 8C 30 20 00 00 00 04 00 .........0 .....
400000000004A380 09 70 3C 1C 00 20 00 80 88 20 23 00 00 00 04 00 .p<.. ... #.....
400000000004A390 11 00 38 42 90 11 00 00 00 02 00 00 38 53 02 50 ..8B........8S.P
400000000004A3A0 08 70 00 10 10 10 00 00 00 02 00 20 00 48 01 84 .p......... .H..
400000000004A3B0 09 18 01 10 00 21 00 00 00 02 00 40 05 40 00 84 .....!.....@.@..
400000000004A3C0 11 38 24 1C 86 39 00 00 00 02 80 03 20 06 00 43 .8$..9...... ..C
400000000004A3D0 11 00 00 00 01 00 00 00 00 02 00 00 38 F2 FF 58 ............8..X
400000000004A3E0 11 08 00 52 00 21 00 00 00 02 00 00 28 7D 06 50 ...R.!......(}.P
400000000004A3F0 08 00 00 00 01 00 E0 00 84 20 20 20 00 48 01 84 .........   .H..
400000000004A400 0B 78 00 44 10 10 00 01 90 20 20 E0 F1 7F FC 8C .x.D.....  .....
400000000004A410 08 70 38 20 05 20 00 78 88 20 23 00 00 00 04 00 .p8 . .x. #.....
400000000004A420 0A 00 00 00 01 00 00 70 84 20 23 00 00 00 04 00 .......p. #.....
400000000004A430 09 00 00 00 01 00 A0 22 F5 B5 4F 00 00 00 04 00 ......."..O.....
400000000004A440 11 50 01 54 18 10 00 00 00 02 00 00 48 BD FF 58 .P.T........H..X
400000000004A450 11 08 00 52 00 21 A0 02 8C 00 42 00 78 1B 00 50 ...R.!....B.x..P
400000000004A460 11 00 00 00 01 00 10 00 A4 00 42 00 80 F2 FF 48 ..........B....H
400000000004A470 08 08 11 03 36 24 00 00 00 02 00 60 84 01 01 84 ....6$.....`....
400000000004A480 09 80 00 44 10 10 00 00 00 02 00 A0 C4 0B D8 90 ...D............
400000000004A490 08 00 00 00 01 00 F0 00 84 20 20 00 12 80 00 84 .........  .....
400000000004A4A0 0A 70 00 46 18 10 E0 40 38 00 42 E0 11 78 00 84 .p.F...@8.B..x..
400000000004A4B0 0A 00 40 44 90 11 A0 02 38 30 20 00 00 00 04 00 ..@D....80 .....
400000000004A4C0 19 00 3C 42 90 11 00 00 00 02 00 00 48 F1 FF 58 ..<B........H..X
400000000004A4D0 03 70 00 46 18 10 10 00 A4 00 42 C0 81 71 00 84 .p.F......B..q..
400000000004A4E0 09 00 00 00 01 00 E0 00 38 20 20 00 00 00 04 00 ........8  .....
400000000004A4F0 11 30 F0 1D 87 39 00 00 00 02 00 03 10 04 00 43 .0...9.........C
400000000004A500 11 00 00 00 01 00 60 E0 3B 0E 63 03 C0 07 00 42 ......`.;.c....B
400000000004A510 11 30 98 1C 87 39 00 00 00 02 00 03 F0 03 00 43 .0...9.........C
400000000004A520 10 00 00 00 01 00 60 D8 39 0E 73 03 B0 05 00 43 ......`.9.s....C
400000000004A530 09 58 11 FA DA 27 A0 02 00 00 42 80 55 00 00 90 .X...'....B.U...
400000000004A540 11 58 01 56 18 10 00 00 00 02 00 00 28 06 FD 58 .X.V........(..X
400000000004A550 09 70 00 46 18 10 10 00 A4 00 42 40 05 40 00 84 .p.F......B@.@..
400000000004A560 09 70 60 1C 00 21 00 00 00 02 00 80 44 0B D8 90 .p`..!......D...
400000000004A570 11 58 01 1C 10 10 00 00 00 02 00 00 18 AF FF 58 .X.............X
400000000004A580 02 70 00 46 18 10 10 00 A4 00 42 C0 01 71 00 84 .p.F......B..q..
400000000004A590 0B 00 00 00 01 00 A0 02 38 30 20 00 00 00 04 00 ........80 .....
400000000004A5A0 11 00 00 00 01 00 00 00 00 02 00 00 68 F0 FF 58 ............h..X
400000000004A5B0 09 08 00 52 00 21 E0 00 90 30 20 00 00 00 04 00 ...R.!...0 .....
400000000004A5C0 11 30 00 1C 07 39 A0 E2 F7 A9 4F 03 30 00 00 43 .0...9....O.0..C
400000000004A5D0 13 50 01 54 18 10 00 5C E7 7F 2C 00 00 00 00 20 .P.T...\..,.... 
400000000004A5E0 08 08 00 52 00 21 00 00 00 02 00 00 00 00 04 00 ...R.!..........
400000000004A5F0 0B 70 00 42 10 10 E0 F8 3B 7E 46 00 00 00 04 00 .p.B....;~F.....
400000000004A600 10 00 38 42 90 11 00 00 00 02 00 00 E0 F0 FF 48 ..8B...........H
400000000004A610 09 70 60 40 00 21 10 02 06 6C 48 60 04 0F B0 90 .p`@.!...lH`....
400000000004A620 09 00 00 00 01 00 20 02 38 30 20 00 00 00 04 00 ...... .80 .....
400000000004A630 11 50 01 44 00 21 20 C2 88 00 42 00 58 E4 FF 58 .P.D.! ...B.X..X
400000000004A640 0B 08 00 52 00 21 A0 62 F4 AB 4F 00 00 00 04 00 ...R.!.b..O.....
400000000004A650 11 50 01 54 18 10 00 00 00 02 00 00 38 AE FF 58 .P.T........8..X
400000000004A660 0B 08 00 52 00 21 A0 22 F4 B3 4F 00 00 00 04 00 ...R.!."..O.....
400000000004A670 11 50 01 54 18 10 00 00 00 02 00 00 18 BB FF 58 .P.T...........X
400000000004A680 08 00 00 00 01 00 10 00 A4 00 42 00 00 00 04 00 ..........B.....
400000000004A690 19 78 00 42 10 10 E0 00 8C 20 20 00 C0 F3 FF 48 .x.B.....  ....H
400000000004A6A0 0B 70 60 40 00 21 E0 00 38 30 20 00 00 00 04 00 .p`@.!..80 .....
400000000004A6B0 09 00 00 00 01 00 E0 40 38 00 42 00 00 00 04 00 .......@8.B.....
400000000004A6C0 11 50 01 1C 18 10 00 00 00 02 00 00 08 E7 FF 58 .P.............X
400000000004A6D0 11 00 00 00 01 00 10 00 A4 00 42 00 10 F0 FF 48 ..........B....H
400000000004A6E0 08 08 71 03 36 24 00 00 00 02 00 40 C5 EA 6B 9F ..q.6$.....@..k.
400000000004A6F0 09 78 60 40 00 21 00 00 00 02 00 A0 84 0C D8 90 .x`@.!..........
400000000004A700 09 70 00 42 10 10 30 02 3C 30 20 00 00 00 04 00 .p.B..0.<0 .....
400000000004A710 09 70 04 1C 00 21 A0 02 A8 30 20 00 00 00 04 00 .p...!...0 .....
400000000004A720 11 00 38 42 90 11 00 00 00 02 00 00 68 AD FF 58 ..8B........h..X
400000000004A730 09 70 00 4A 10 10 00 00 00 02 00 20 00 48 01 84 .p.J....... .H..
400000000004A740 11 38 00 1C 86 39 00 00 00 02 00 03 60 01 00 43 .8...9......`..C
400000000004A750 03 70 00 44 10 10 00 00 00 02 00 C0 11 70 00 84 .p.D.........p..
400000000004A760 08 00 38 44 90 11 00 00 00 02 00 00 00 00 04 00 ..8D............
400000000004A770 09 00 00 00 01 00 30 42 8C 00 42 00 00 00 04 00 ......0B..B.....
400000000004A780 11 50 01 46 18 10 00 00 00 02 00 00 88 EE FF 58 .P.F...........X
400000000004A790 0B 08 00 52 00 21 E0 A0 05 6C 48 40 C5 EF 53 9F ...R.!...lH@..S.
400000000004A7A0 09 00 00 00 01 00 E0 00 38 30 20 00 00 00 04 00 ........80 .....
400000000004A7B0 11 30 00 1C 07 39 00 00 00 02 00 03 30 00 00 43 .0...9......0..C
400000000004A7C0 13 50 01 54 18 10 00 64 E6 7F 2C 00 00 00 00 20 .P.T...d..,.... 
400000000004A7D0 08 08 00 52 00 21 00 00 00 02 00 00 00 00 04 00 ...R.!..........
400000000004A7E0 09 00 00 00 01 00 E0 00 94 20 20 00 00 00 04 00 .........  .....
400000000004A7F0 11 30 00 1C 87 39 00 00 00 02 80 03 30 04 00 43 .0...9......0..C
400000000004A800 11 00 00 00 01 00 00 00 00 02 00 00 C8 B2 FF 58 ...............X
400000000004A810 0B 08 00 52 00 21 A0 22 F6 AB 4F 00 00 00 04 00 ...R.!."..O.....
400000000004A820 11 50 01 54 18 10 00 00 00 02 00 00 68 AC FF 58 .P.T........h..X
400000000004A830 0B 08 00 52 00 21 A0 22 F5 B5 4F 00 00 00 04 00 ...R.!."..O.....
400000000004A840 11 50 01 54 18 10 00 00 00 02 00 00 48 AC FF 58 .P.T........H..X
400000000004A850 03 70 00 42 10 10 10 00 A4 00 42 C0 F1 77 FC 8C .p.B......B..w..
400000000004A860 10 00 38 42 90 11 00 00 00 02 00 00 80 EE FF 48 ..8B...........H
400000000004A870 09 00 00 00 01 00 E0 C0 80 00 42 00 00 00 04 00 ..........B.....
400000000004A880 11 50 01 1C 18 10 00 00 00 02 00 00 08 E6 FF 58 .P.............X
400000000004A890 11 00 00 00 01 00 10 00 A4 00 42 00 50 EE FF 48 ..........B.P..H
400000000004A8A0 09 00 00 00 01 00 A0 62 F6 AB 4F 00 00 00 04 00 .......b..O.....
400000000004A8B0 11 50 01 54 18 10 00 00 00 02 00 00 D8 AB FF 58 .P.T...........X
400000000004A8C0 0B 08 00 52 00 21 E0 00 06 6C 48 00 02 0F B0 90 ...R.!...lH.....
400000000004A8D0 09 78 00 1C 10 10 00 01 40 20 20 00 00 00 04 00 .x......@  .....
400000000004A8E0 09 00 00 00 01 00 F0 78 40 00 40 00 00 00 04 00 .......x@.@.....
400000000004A8F0 10 00 3C 1C 90 11 00 00 00 02 00 00 80 FE FF 48 ..<............H
400000000004A900 09 78 40 18 00 21 00 01 01 00 48 C0 01 70 50 00 .x@..!....H..pP.
400000000004A910 08 50 01 1E 00 21 10 80 3C 00 2B 00 22 61 00 84 .P...!..<.+."a..
400000000004A920 0A 20 01 1C 00 21 00 00 40 00 23 00 00 00 04 00 . ...!..@.#.....
400000000004A930 19 00 38 1E 80 11 00 00 00 02 00 00 58 CB FF 58 ..8.........X..X
400000000004A940 10 08 00 52 00 21 70 30 91 0C 73 03 40 00 00 42 ...R.!p0..s.@..B
400000000004A950 0B 70 00 46 18 10 E0 80 38 00 42 00 00 00 04 00 .p.F....8.B.....
400000000004A960 09 00 00 00 01 00 E0 00 38 30 20 00 00 00 04 00 ........80 .....
400000000004A970 10 00 00 00 01 00 60 00 38 0E 72 03 30 02 00 43 ......`.8.r.0..C
400000000004A980 09 00 00 00 01 00 A0 22 F6 AB 4F 00 00 00 04 00 ......."..O.....
400000000004A990 11 50 01 54 18 10 00 00 00 02 00 00 F8 AA FF 58 .P.T...........X
400000000004A9A0 08 00 00 00 01 00 E0 00 88 20 20 20 00 48 01 84 .........   .H..
400000000004A9B0 0A 78 00 46 18 10 E0 08 38 00 42 E0 01 79 00 84 .x.F....8.B..y..
400000000004A9C0 02 20 D1 02 36 24 00 00 00 02 00 00 00 00 04 00 . ..6$..........
400000000004A9D0 18 00 38 44 90 11 A0 02 3C 30 20 00 D0 FB FF 48 ..8D....<0 ....H
400000000004A9E0 09 70 60 10 00 21 00 00 00 02 00 C0 04 41 00 84 .p`..!.......A..
400000000004A9F0 08 70 00 1C 18 10 50 02 98 30 20 00 00 00 04 00 .p....P..0 .....
400000000004AA00 0B 00 00 4C 98 11 E0 40 38 00 42 00 00 00 04 00 ...L...@8.B.....
400000000004AA10 11 50 01 1C 18 10 00 00 00 02 00 00 F8 EB FF 58 .P.............X
400000000004AA20 11 08 00 52 00 21 00 00 00 02 00 00 E8 76 06 50 ...R.!.......v.P
400000000004AA30 08 08 00 52 00 21 00 01 90 20 20 C0 00 28 1D E4 ...R.!...  ..(..
400000000004AA40 09 00 00 00 01 00 E0 00 84 20 20 00 00 00 04 00 .........  .....
400000000004AA50 09 78 00 44 10 10 A0 E2 F4 B5 4F C0 E1 80 14 80 .x.D......O.....
400000000004AA60 09 78 FC 1F 3F 23 00 70 84 20 23 00 00 00 04 00 .x..?#.p. #.....
400000000004AA70 11 00 3C 44 90 11 00 00 00 02 00 03 C0 F9 FF 49 ..<D...........I
400000000004AA80 11 50 01 54 18 10 00 00 00 02 00 00 08 B7 FF 58 .P.T...........X
400000000004AA90 11 08 00 52 00 21 A0 02 94 00 42 00 38 C6 FF 58 ...R.!....B.8..X
400000000004AAA0 08 08 00 52 00 21 00 28 99 30 23 40 05 18 01 84 ...R.!.(.0#@....
400000000004AAB0 19 00 00 00 01 00 00 00 00 02 00 00 18 15 00 50 ...............P
400000000004AAC0 11 00 00 00 01 00 10 00 A4 00 42 00 20 EC FF 48 ..........B. ..H
400000000004AAD0 0B 20 D1 02 36 24 E0 00 90 30 20 00 00 00 04 00 . ..6$...0 .....
400000000004AAE0 11 38 00 1C 06 39 00 00 00 02 80 03 60 03 00 43 .8...9......`..C
400000000004AAF0 0B 28 21 03 36 24 A0 02 94 20 20 00 00 00 04 00 .(!.6$...  .....
400000000004AB00 0B 30 00 54 87 F9 A1 E2 F7 A9 4F 00 00 00 04 00 .0.T......O.....
400000000004AB10 CB 50 31 FA D5 E7 A1 02 A8 30 20 00 00 00 04 00 .P1......0 .....
400000000004AB20 D3 50 01 54 18 10 00 B4 E4 7F 2C 00 00 00 00 20 .P.T......,.... 
400000000004AB30 08 08 00 52 00 21 00 00 00 02 00 00 00 00 04 00 ...R.!..........
400000000004AB40 09 00 00 00 01 00 E0 00 94 20 20 00 00 00 04 00 .........  .....
400000000004AB50 10 00 00 00 01 00 60 00 38 0E 73 03 80 02 00 42 ......`.8.s....B
400000000004AB60 09 00 00 00 01 00 A0 62 F6 AB 4F 00 00 00 04 00 .......b..O.....
400000000004AB70 11 50 01 54 18 10 00 00 00 02 00 00 18 A9 FF 58 .P.T...........X
400000000004AB80 03 70 00 46 18 10 10 00 A4 00 42 C0 01 71 00 84 .p.F......B..q..
400000000004AB90 11 50 01 1C 18 10 00 00 00 02 00 00 10 FA FF 48 .P.............H
400000000004ABA0 11 50 01 00 00 21 40 A2 05 6C 48 00 00 FA FF 48 .P...!@..lH....H
400000000004ABB0 09 00 00 00 01 00 A0 A2 F5 B3 4F 00 00 00 04 00 ..........O.....
400000000004ABC0 11 50 01 54 18 10 00 00 00 02 00 00 C8 B5 FF 58 .P.T...........X
400000000004ABD0 11 00 00 00 01 00 10 00 A4 00 42 00 B0 F4 FF 48 ..........B....H

l400000000004ABE0:
	{ nop.m	0x0; addl	r42,-5508,r1; nop.i	0x0; }
	{ ld8	r42,[r42]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000045480; }
	{ adds	r1,0x0,r41; mov.i	ar.pfs,r40; mov.spnt	b0,r39,400000000004AC00 }
	{ nop.m	0x0; adds	r12,0x10,r12; br.ret	b0 }
400000000004AC20 09 00 00 00 01 00 A0 62 F6 AB 4F 00 00 00 04 00 .......b..O.....
400000000004AC30 11 50 01 54 18 10 00 00 00 02 00 00 58 A8 FF 58 .P.T........X..X
400000000004AC40 0B 08 00 52 00 21 E0 00 06 6C 48 00 02 0F B0 90 ...R.!...lH.....
400000000004AC50 09 78 00 1C 10 10 A0 02 40 20 20 00 00 00 04 00 .x......@  .....
400000000004AC60 09 00 00 00 01 00 A0 7A A8 0A 40 00 00 00 04 00 .......z..@.....
400000000004AC70 11 00 A8 1C 90 11 00 00 00 02 00 00 58 B3 FF 58 ............X..X
400000000004AC80 0B 08 00 52 00 21 A0 22 F5 B5 4F 00 00 00 04 00 ...R.!."..O.....
400000000004AC90 11 50 01 54 18 10 00 00 00 02 00 00 F8 A7 FF 58 .P.T...........X
400000000004ACA0 03 70 00 42 10 10 10 00 A4 00 42 C0 F1 77 FC 8C .p.B......B..w..
400000000004ACB0 10 00 38 42 90 11 00 00 00 02 00 00 30 EA FF 48 ..8B........0..H
400000000004ACC0 09 00 00 00 01 00 F0 00 01 04 48 00 00 00 04 00 ..........H.....
400000000004ACD0 11 30 3C 1C 87 38 F0 08 01 04 48 03 90 00 00 43 .0<..8....H....C
400000000004ACE0 10 00 00 00 01 00 60 78 38 0E F1 03 50 F8 FF 4A ......`x8...P..J
400000000004ACF0 09 00 00 00 01 00 A0 A2 F5 AB 4F 00 00 00 04 00 ..........O.....
400000000004AD00 11 50 01 54 18 10 00 00 00 02 00 00 88 C7 FF 58 .P.T...........X
400000000004AD10 03 70 00 46 18 10 10 00 A4 00 42 C0 01 71 00 84 .p.F......B..q..
400000000004AD20 0B 50 01 1C 18 10 60 00 A8 0E 72 00 00 00 04 00 .P....`...r.....
400000000004AD30 E3 70 00 4A 10 D0 41 A2 05 6C C8 C3 11 70 00 84 .p.J..A..l...p..
400000000004AD40 F0 00 38 4A 90 11 00 00 00 02 80 03 60 F8 FF 4A ..8J........`..J
400000000004AD50 10 00 00 00 01 00 40 A2 05 6C 48 00 50 F8 FF 48 ......@..lH.P..H
400000000004AD60 09 00 00 00 01 00 A0 62 F5 AB 4F 00 00 00 04 00 .......b..O.....
400000000004AD70 11 50 01 54 18 10 00 00 00 02 00 00 18 C7 FF 58 .P.T...........X
400000000004AD80 03 70 00 46 18 10 10 00 A4 00 42 C0 01 71 00 84 .p.F......B..q..
400000000004AD90 0B 50 01 1C 18 10 60 00 A8 0E 72 00 00 00 04 00 .P....`...r.....
400000000004ADA0 E3 70 00 4A 10 D0 41 A2 05 6C C8 C3 11 70 00 84 .p.J..A..l...p..
400000000004ADB0 F0 00 38 4A 90 11 00 00 00 02 80 03 F0 F7 FF 4A ..8J...........J
400000000004ADC0 10 00 00 00 01 00 00 00 00 02 00 00 90 FF FF 48 ...............H
400000000004ADD0 09 00 00 00 01 00 A0 22 F6 AB 4F 00 00 00 04 00 ......."..O.....
400000000004ADE0 11 50 01 54 18 10 00 00 00 02 00 00 A8 A6 FF 58 .P.T...........X
400000000004ADF0 03 70 00 46 18 10 10 00 A4 00 42 C0 01 71 00 84 .p.F......B..q..
400000000004AE00 09 00 00 00 01 00 A0 02 38 30 20 00 00 00 04 00 ........80 .....
400000000004AE10 11 30 00 54 07 39 00 00 00 02 00 03 90 F7 FF 4B .0.T.9.........K
400000000004AE20 0B 70 00 44 10 10 E0 08 38 00 42 00 00 00 04 00 .p.D....8.B.....
400000000004AE30 10 00 38 44 90 11 00 00 00 02 00 00 70 F7 FF 48 ..8D........p..H
400000000004AE40 0B 70 B0 02 36 24 F0 00 38 20 20 00 00 00 04 00 .p..6$..8  .....
400000000004AE50 09 00 00 00 01 00 70 00 3C 0C 73 00 00 00 04 00 ......p.<.s.....
400000000004AE60 D1 00 00 1C 90 91 51 42 06 6C 48 03 E0 FC FF 4A ......QB.lH....J
400000000004AE70 09 50 31 FA D5 27 00 00 00 02 00 A0 84 0C D8 90 .P1..'..........
400000000004AE80 11 50 01 54 18 10 00 00 00 02 00 00 08 A6 FF 58 .P.T...........X
400000000004AE90 11 00 00 00 01 00 10 00 A4 00 42 00 B0 FC FF 48 ..........B....H
400000000004AEA0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000004AEB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000004AEC0 08 38 2D 12 80 05 90 62 F6 B1 4F C0 04 00 C4 00 .8-....b..O.....
400000000004AED0 09 40 01 02 00 21 A0 02 84 00 42 80 04 00 01 84 .@...!....B.....
400000000004AEE0 11 48 01 52 18 10 00 00 00 02 00 00 A8 A5 FF 58 .H.R...........X
400000000004AEF0 09 08 00 50 00 21 00 00 00 02 00 00 82 00 01 84 ...P.!..........
400000000004AF00 08 70 F0 02 36 24 00 62 F4 B3 4F A0 44 0B D8 90 .p..6$.b..O.D...
400000000004AF10 09 10 01 03 36 24 90 02 40 30 20 60 04 0F B0 90 ....6$..@0 `....
400000000004AF20 09 78 00 1C 10 10 00 02 80 30 20 00 00 00 04 00 .x.......0 .....
400000000004AF30 09 00 00 00 01 00 F0 08 3C 00 42 00 00 00 04 00 ........<.B.....
400000000004AF40 11 00 3C 1C 90 11 00 00 00 02 00 00 C8 E6 FF 58 ..<............X
400000000004AF50 09 08 00 50 00 21 E0 00 94 30 20 00 00 00 04 00 ...P.!...0 .....
400000000004AF60 11 48 F1 FB D4 27 60 00 38 0E 72 03 30 00 00 43 .H...'`.8.r.0..C
400000000004AF70 13 48 01 52 18 10 00 8C E2 7F 2C 00 00 00 00 20 .H.R......,.... 
400000000004AF80 08 08 00 50 00 21 00 00 00 02 00 00 00 00 04 00 ...P.!..........
400000000004AF90 11 20 41 48 00 21 00 00 00 02 00 00 38 AB FF 58 . AH.!......8..X
400000000004AFA0 0B 08 00 50 00 21 90 22 F6 B5 4F 00 00 00 04 00 ...P.!."..O.....
400000000004AFB0 11 48 01 52 18 10 00 00 00 02 00 00 D8 A4 FF 58 .H.R...........X
400000000004AFC0 08 00 00 00 01 00 F0 00 88 20 20 20 00 40 01 84 .........   .@..
400000000004AFD0 09 00 00 00 01 00 E0 00 8C 20 20 00 00 00 04 00 .........  .....
400000000004AFE0 09 70 3C 1C 00 20 90 02 90 30 20 00 00 00 04 00 .p<.. ...0 .....
400000000004AFF0 11 00 38 44 90 11 00 00 00 02 00 00 18 E6 FF 58 ..8D...........X
400000000004B000 09 08 00 50 00 21 E0 00 94 30 20 00 00 00 04 00 ...P.!...0 .....
400000000004B010 11 48 F1 FB D4 27 60 00 38 0E 72 03 30 00 00 43 .H...'`.8.r.0..C
400000000004B020 13 48 01 52 18 10 00 34 E2 7F 2C 00 00 00 00 20 .H.R...4..,.... 
400000000004B030 08 08 00 50 00 21 00 00 00 02 00 00 00 00 04 00 ...P.!..........
400000000004B040 09 70 00 44 10 10 F0 00 8C 20 20 00 00 00 04 00 .p.D.....  .....
400000000004B050 09 00 00 00 01 00 E0 70 3C 0A 40 00 00 00 04 00 .......p<.@.....
400000000004B060 11 00 38 44 90 11 00 00 00 02 00 00 68 AA FF 58 ..8D........h..X
400000000004B070 03 08 00 50 00 21 00 30 05 80 03 00 70 02 AA 00 ...P.!.0....p...
400000000004B080 11 10 08 00 80 05 00 00 00 02 00 00 08 B1 FF 48 ...............H
400000000004B090 0D 00 00 00 01 00 00 00 00 00 00 00 00 00 04 00 ................
400000000004B0A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000004B0B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; make_command_string: 400000000004B0C0
;;   Called from:
;;     400000000004B16C (in print_command)
make_command_string proc
	{ alloc	r34,ar.pfs,0x5,0x0,0x4; addl	r14,6956,r1; mov	r33,b1 }
	{ adds	r35,0x0,r1; nop.m	0x0; adds	r36,0x0,r32; }
	{ st4	[r0],r14; nop.m	0x0; addl	r14,6940,r1; }
	{ st4	[r0],r14; nop.m	0x0; addl	r14,6964,r1; }
	{ st8	[r0],r14; nop.i	0x0; br.call.sptk.many	b0,fn4000000000049600; }
	{ adds	r1,0x0,r35; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ addl	r14,6948,r1; nop.m	0x0; mov.spnt	b0,r33,400000000004B120; }
	{ ld8	r8,[r14]; nop.i	0x0; br.ret	b0; }

;; print_command: 400000000004B140
print_command proc
	{ alloc	r34,ar.pfs,0x7,0x0,0x4; addl	r14,6940,r1; mov	r33,b1 }
	{ adds	r35,0x0,r1; nop.m	0x0; adds	r36,0x0,r32; }
	{ st4	[r0],r14; nop.i	0x0; br.call.sptk.many	b0,make_command_string; }
	{ adds	r1,0x0,r35; addl	r36,1,r0; adds	r38,0x0,r8; }
	{ nop.m	0x0; addl	r37,-5444,r1; nop.i	0x0; }
	{ ld8	r37,[r37]; nop.i	0x0; br.call.sptk.many	b0,fn400000000001BB80; }
	{ adds	r1,0x0,r35; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,400000000004B1B0; br.ret	b0; }

;; named_function_string: 400000000004B1C0
;;   Called from:
;;     400000000006166C (in fn4000000000061240)
;;     4000000000061A2C (in print_var_function)
;;     40000000000F170C (in fn40000000000F0900)
;;     400000000010AF9C (in show_var_attributes)
;;     400000000010B0EC (in show_var_attributes)
;;     400000000010B27C (in show_var_attributes)
;;     400000000010F36C (in describe_command)
named_function_string proc
	{ alloc	r44,ar.pfs,0x11,0x0,0xF; addl	r14,6956,r1; mov	r46,pr }
	{ addl	r36,6976,r1; addl	r38,5744,r1; adds	r45,0x0,r1; }
	{ st4	[r0],r14; addl	r14,6940,r1; mov	r43,b3 }
	{ ld4	r41,[r36]; ld4	r40,[r38]; cmp.eq	p06,p07,0x0,r32; }
	{ st4	[r0],r14; nop.m	0x0; addl	r14,6964,r1; }
	{ st8	[r0],r14; nop.i	0x0; (p06) br.cond.dpnt.few	400000000004B240; }

l400000000004B220:
	{ ld1	r14,[r32]; nop.m	0x0; sxt1	r14,r14; }
	{ nop.m	0x0; cmp4.eq	p06,p07,0x0,r14; (p07) br.cond.dpnt.few	400000000004B450 }

l400000000004B240:
	{ addl	r47,-4788,r1; nop.m	0x0; tnat.z	p17,p16,r34; }
	{ ld8	r47,[r47]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000045480; }
	{ nop.m	0x0; adds	r1,0x0,r45; (p17) addl	r15,1,r0 }

l400000000004B270:
	{ (p17) st4	[r0],r38; addl	r35,6984,r1; (p16) addl	r47,-5428,r1 }

l400000000004B276:
	{ (p17) nop; (p23) dep	r76,r125,r85,35,15; (p04) br.call.spnt.many	b0,400000000094FAA6 }

l400000000004B280:
	{ (p17) st4	[r15],r36; (p17) ld4	r14,[r35]; (p17) addl	r47,-4820,r1; }

l400000000004B286:
	{ (p07) nop; (p36) nop }

l400000000004B28C:
	{ (p22) cmp.le.and	p61,p41,r0,r79; (p05) nop; }

l400000000004B290:
	{ (p17) adds	r14,0x1,r14; (p16) ld8	r47,[r47]; nop.i	0x0; }

l400000000004B296:
	{ Invalid; Invalid; Invalid }

l400000000004B29C:
	{ nop; Invalid; Invalid }

l400000000004B2AC:
	{ cmp.gt.or.andcm	p00,p57,r0,r0; Invalid; break.i	0x101000 }

l400000000004B2B6:
	{ nop; (p32) nop; break.i	0x80000 }

l400000000004B2C0:
	{ nop.m	0x0; (p16) ld4	r14,[r38]; (p16) adds	r1,0x0,r45 }

l400000000004B2CC:
	{ cmp.gt.or.andcm	p45,p10,r0,r66; Invalid; (p02) cmp.le.or.andcm	p32,p08,r0,r4 }

l400000000004B2D0:
	{ (p16) ld4	r15,[r36]; (p16) ld4	r16,[r35]; (p16) addl	r47,-4844,r1 }

l400000000004B2D6:
	{ (p08) nop; (p36) nop }

l400000000004B2DC:
	{ (p10) cmp.le.and	p61,p10,r0,r79; (p18) nop; }

l400000000004B2E0:
	{ (p16) add	r14,r15,r14; (p16) adds	r16,0x1,r16; nop.i	0x0 }

l400000000004B2E6:
	{ Invalid; (p04) nop }

l400000000004B2EC:
	{ nop; (p32) cmp.gt.or.andcm	p03,p08,r0,r100; Invalid }

l400000000004B2F6:
	{ Invalid; Invalid; Invalid }

l400000000004B2FC:
	{ Invalid; Invalid; break.i	0x1000 }

l400000000004B306:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ Invalid; (p32) nop; (p32) br.call.sptk.few	b3,b0 }
	{ Invalid; (p18) nop; break.b	0x80000 }
	{ (p03) chk.a.clr	f9,3FFFFFFFFFD0E416; nop; (p48) nop.b	0x800B }

l400000000004B340:
	{ adds	r47,0x0,r8; nop.i	0x0; br.call.sptk.many	b0,fn4000000000049600; }
	{ ld4	r14,[r35]; nop.m	0x0; adds	r1,0x0,r45 }
	{ st4	[r41],r36; st4	[r40],r38; nop.i	0x0; }
	{ nop.m	0x0; adds	r14,0xFFFFFFFFFFFFFFFF,r14; nop.i	0x0; }
	{ st4	[r14],r35; nop.m	0x0; nop.i	0x0 }

l400000000004B390:
	{ addl	r47,-4828,r1; nop.i	0x0; nop.i	0x0 }
	{ ld8	r47,[r47]; nop.m	0x0; br.call.sptk.many	b0,fn4000000000046180; }
	{ adds	r1,0x0,r45; nop.m	0x0; nop.i	0x0; }

l400000000004B3C0:
	{ nop.m	0x0; addl	r14,6948,r1; nop.i	0x0; }
	{ ld8	r35,[r14]; nop.i	0x0; (p16) br.cond.dptk.few	400000000004B410; }

l400000000004B3E0:
	{ adds	r47,0x2,r35; ld1	r14,[r47]; nop.i	0x0; }
	{ nop.m	0x0; sxt1	r14,r14; nop.i	0x0; }
	{ nop.m	0x0; cmp4.eq	p07,p06,0xA,r14; (p07) br.cond.dpnt.few	400000000004B670 }

l400000000004B410:
	{ adds	r47,0x0,r37; nop.i	0x0; br.call.sptk.many	b0,dispose_command; }
	{ adds	r1,0x0,r45; tbit.z	p06,p07,r34,0x1; (p07) br.cond.dpnt.few	400000000004B630; }

l400000000004B430:
	{ adds	r8,0x0,r35; mov	pr,r46,0xFFFFFFFFFFFFFFFE; mov.i	ar.pfs,r44; }
	{ nop.m	0x0; mov.spnt	b0,r43,400000000004B440; br.ret	b0 }

l400000000004B450:
	{ addl	r47,-5044,r1; adds	r48,0x0,r32; tnat.z	p17,p16,r34; }
	{ ld8	r47,[r47]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000045480; }
	{ adds	r1,0x0,r45; addl	r47,-4788,r1; nop.i	0x0; }
	{ ld8	r47,[r47]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000045480; }
	{ nop.m	0x0; adds	r1,0x0,r45; (p17) addl	r15,1,r0 }

l400000000004B4A0:
	{ (p17) st4	[r0],r38; addl	r35,6984,r1; (p16) addl	r47,-5428,r1 }

l400000000004B4A6:
	{ (p17) nop; (p23) dep	r76,r125,r85,35,15; (p04) br.call.spnt.many	b0,400000000094FCD6 }

l400000000004B4B0:
	{ (p17) st4	[r15],r36; (p17) ld4	r14,[r35]; (p17) addl	r47,-4820,r1; }

l400000000004B4B6:
	{ (p07) nop; (p36) nop }

l400000000004B4BC:
	{ (p22) cmp.le.and	p61,p41,r0,r79; (p05) nop; }

l400000000004B4C0:
	{ (p17) adds	r14,0x1,r14; (p16) ld8	r47,[r47]; nop.i	0x0; }

l400000000004B4C6:
	{ Invalid; Invalid; Invalid }

l400000000004B4CC:
	{ nop; Invalid; Invalid }

l400000000004B4DC:
	{ cmp.gt.or.andcm	p00,p57,r0,r0; Invalid; break.i	0x101000 }

l400000000004B4E6:
	{ nop; (p32) nop; break.i	0x80000 }

l400000000004B4F0:
	{ nop.m	0x0; (p16) ld4	r14,[r38]; (p16) adds	r1,0x0,r45 }

l400000000004B4FC:
	{ cmp.gt.or.andcm	p45,p10,r0,r66; Invalid; (p02) cmp.le.or.andcm	p32,p08,r0,r4 }

l400000000004B500:
	{ (p16) ld4	r15,[r36]; (p16) ld4	r16,[r35]; (p16) addl	r47,-4844,r1 }

l400000000004B506:
	{ (p08) nop; (p36) nop }

l400000000004B50C:
	{ (p10) cmp.le.and	p61,p10,r0,r79; (p18) nop; }

l400000000004B510:
	{ (p16) add	r14,r15,r14; (p16) adds	r16,0x1,r16; nop.i	0x0 }

l400000000004B516:
	{ Invalid; (p04) nop }

l400000000004B51C:
	{ nop; (p32) cmp.gt.or.andcm	p03,p08,r0,r100; Invalid }

l400000000004B526:
	{ Invalid; Invalid; Invalid }

l400000000004B52C:
	{ Invalid; Invalid; break.i	0x1000 }

l400000000004B536:
	{ break.m	0x4000; (p32) nop; (p16) nop }
	{ Invalid; (p32) nop; (p32) br.call.sptk.few	b3,b0 }
	{ Invalid; (p18) nop; break.b	0x80000 }
	{ (p03) chk.a.clr	r9,3FFFFFFFFFD0E646; nop; (p32) nop.b	0x8303 }

l400000000004B570:
	{ adds	r14,0x18,r8; nop.m	0x0; adds	r42,0x10,r8; }
	{ ld8	r14,[r14]; ld8	r39,[r42]; nop.i	0x0 }
	{ st8	[r0],r42; adds	r14,0x8,r14; nop.i	0x0; }
	{ ld8	r47,[r14]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000049600; }
	{ adds	r1,0x0,r45; ld4	r14,[r35]; cmp.eq	p06,p07,0x0,r39 }
	{ st4	[r41],r36; st4	[r40],r38; nop.i	0x0; }
	{ addl	r47,-4836,r1; nop.m	0x0; adds	r14,0xFFFFFFFFFFFFFFFF,r14; }
	{ st4	[r14],r35; nop.i	0x0; (p06) br.cond.spnt.few	400000000004B390; }

l400000000004B5F0:
	{ ld8	r47,[r47]; nop.i	0x0; br.call.sptk.many	b0,fn4000000000046180; }
	{ adds	r1,0x0,r45; adds	r47,0x0,r39; br.call.sptk.many	b0,fn40000000000470C0; }
	{ nop.m	0x0; adds	r1,0x0,r45; nop.i	0x0 }
	{ st8	[r39],r42; nop.m	0x0; br.cond.sptk.few	400000000004B3C0 }

l400000000004B630:
	{ adds	r47,0x0,r35; nop.i	0x0; br.call.sptk.many	b0,remove_quoted_escapes; }
	{ adds	r35,0x0,r8; adds	r1,0x0,r45; mov	pr,r46,0xFFFFFFFFFFFFFFFE; }
	{ adds	r8,0x0,r35; nop.m	0x0; mov.i	ar.pfs,r44; }
	{ nop.m	0x0; mov.spnt	b0,r43,400000000004B660; br.ret	b0; }

l400000000004B670:
	{ adds	r48,0x3,r35; nop.i	0x0; br.call.sptk.many	b0,fn400000000001B180; }
	{ adds	r1,0x0,r45; adds	r47,0x0,r37; br.call.sptk.many	b0,dispose_command; }
	{ adds	r1,0x0,r45; tbit.z	p06,p07,r34,0x1; (p06) br.cond.dptk.few	400000000004B430 }

l400000000004B6A0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000004B630; }
400000000004B6B0 00 30 00 00 01 00 70 00 00 02 00 00 01 00 04 00 .0....p.........

;; dispose_word: 400000000004B6C0
;;   Called from:
;;     4000000000036BAC (in fn4000000000036A40)
;;     40000000000374FC (in fn4000000000036A40)
;;     400000000003777C (in fn4000000000036A40)
;;     400000000003782C (in fn4000000000036A40)
;;     400000000004B98C (in dispose_cond_node)
;;     400000000004BC1C (in dispose_words)
;;     400000000004BF1C (in dispose_redirects)
;;     400000000004BF8C (in dispose_redirects)
;;     400000000004C72C (in dispose_function_def_contents)
;;     40000000000A42CC (in fn40000000000A1400)
;;     40000000000A51AC (in fn40000000000A1400)
;;     400000000010C2CC (in set_or_show_attributes)
dispose_word proc
	{ alloc	r34,ar.pfs,0x6,0x0,0x4; ld8	r36,[r32]; nop.b	0x0 }
	{ adds	r35,0x0,r1; nop.m	0x0; mov	r33,b1; }
	{ cmp.eq	p06,p07,0x0,r36; nop.i	0x0; (p06) br.cond.dpnt.few	400000000004B710; }

l400000000004B6F0:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r35; nop.m	0x0; nop.i	0x0; }

l400000000004B710:
	{ addl	r15,14044,r1; addl	r14,-33,r0; adds	r17,0x0,r32 }
	{ adds	r37,0x2,r32; adds	r36,0x3,r32; adds	r31,0x4,r32; }
	{ nop.m	0x0; adds	r30,0x5,r32; adds	r29,0x6,r32 }
	{ adds	r28,0x7,r32; adds	r27,0x8,r32; adds	r26,0x9,r32; }
	{ adds	r16,0xC,r15; adds	r19,0x8,r15; adds	r25,0xA,r32 }
	{ adds	r24,0xB,r32; adds	r23,0xC,r32; adds	r22,0xD,r32; }
	{ ld4	r18,[r16]; adds	r21,0xE,r32; nop.b	0x0 }
	{ adds	r20,0xF,r32; ld4	r19,[r19]; mov.i	ar.pfs,r34; }
	{ cmp4.lt	p07,p06,r18,r19; mov.spnt	b0,r33,400000000004B790; (p06) br.cond.dpnt.few	400000000004B860; }

l400000000004B7A0:
	{ st1	[r17],r1,1; st1	[r14],r37; nop.i	0x0; }
	{ st1	[r14],r17; st1	[r14],r36; nop.i	0x0; }
	{ st1	[r14],r31; st1	[r14],r30; nop.i	0x0; }
	{ st1	[r14],r29; st1	[r14],r28; nop.i	0x0; }
	{ st1	[r14],r27; st1	[r14],r26; nop.i	0x0 }
	{ ld8	r15,[r15]; st1	[r14],r25; nop.i	0x0 }
	{ st1	[r14],r24; st1	[r14],r23; nop.i	0x0 }
	{ st1	[r14],r22; st1	[r14],r21; nop.i	0x0 }
	{ st1	[r14],r20; ld4	r14,[r16]; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r17,r14; adds	r14,0x1,r14; }
	{ shladd	r15,r17,0x3,r15; nop.i	0x0; nop.i	0x0 }
	{ st8	[r32],r15; st4	[r14],r16; br.ret	b0; }

l400000000004B860:
	{ adds	r36,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,xfree; }
	{ adds	r1,0x0,r35; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,400000000004B880; br.ret	b0; }
400000000004B890 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000004B8A0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000004B8B0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; dispose_cond_node: 400000000004B8C0
;;   Called from:
;;     4000000000036E2C (in fn4000000000036A40)
;;     40000000000372CC (in fn4000000000036A40)
;;     40000000000374EC (in fn4000000000036A40)
;;     400000000003776C (in fn4000000000036A40)
;;     40000000000377FC (in fn4000000000036A40)
;;     400000000004B90C (in dispose_cond_node)
;;     400000000004B94C (in dispose_cond_node)
dispose_cond_node proc
	{ alloc	r34,ar.pfs,0x5,0x0,0x4; adds	r14,0x18,r32; mov	r33,b1 }
	{ cmp.eq	p06,p07,0x0,r32; adds	r35,0x0,r1; (p06) br.cond.dpnt.few	400000000004B9C0; }

l400000000004B8E0:
	{ nop.m	0x0; ld8	r36,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r36; nop.i	0x0; (p06) br.cond.dpnt.few	400000000004B920; }

l400000000004B900:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,dispose_cond_node; }
	{ adds	r1,0x0,r35; nop.m	0x0; nop.i	0x0 }

l400000000004B920:
	{ adds	r14,0x20,r32; ld8	r36,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r36; nop.i	0x0; (p06) br.cond.dpnt.few	400000000004B960; }

l400000000004B940:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,dispose_cond_node; }
	{ adds	r1,0x0,r35; nop.m	0x0; nop.i	0x0 }

l400000000004B960:
	{ adds	r14,0x10,r32; ld8	r36,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r36; nop.i	0x0; (p06) br.cond.dpnt.few	400000000004B9A0; }

l400000000004B980:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,dispose_word; }
	{ adds	r1,0x0,r35; nop.m	0x0; nop.i	0x0 }

l400000000004B9A0:
	{ nop.m	0x0; adds	r36,0x0,r32; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r35; nop.m	0x0; nop.i	0x0 }

l400000000004B9C0:
	{ nop.m	0x0; mov.i	ar.pfs,r34; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r33,400000000004B9D0; br.ret	b0; }
400000000004B9E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000004B9F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; dispose_word_desc: 400000000004BA00
;;   Called from:
;;     40000000000A35FC (in fn40000000000A1400)
;;     40000000000E682C (in gen_compspec_completions)
;;     40000000000E73EC (in gen_compspec_completions)
dispose_word_desc proc
	{ alloc	r34,ar.pfs,0x6,0x0,0x4; addl	r15,14044,r1; nop.b	0x0 }
	{ adds	r17,0x0,r32; st8	[r0],r32; mov	r33,b1; }
	{ nop.m	0x0; addl	r14,-33,r0; adds	r35,0x0,r1 }
	{ adds	r37,0x2,r32; adds	r36,0x3,r32; adds	r31,0x4,r32; }
	{ adds	r16,0xC,r15; adds	r19,0x8,r15; adds	r30,0x5,r32 }
	{ adds	r29,0x6,r32; adds	r28,0x7,r32; adds	r27,0x8,r32; }
	{ ld4	r18,[r16]; adds	r26,0x9,r32; adds	r25,0xA,r32 }
	{ adds	r24,0xB,r32; adds	r23,0xC,r32; adds	r22,0xD,r32; }
	{ ld4	r19,[r19]; adds	r21,0xE,r32; nop.b	0x0 }
	{ adds	r20,0xF,r32; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ cmp4.lt	p07,p06,r18,r19; mov.spnt	b0,r33,400000000004BAA0; (p06) br.cond.dpnt.few	400000000004BB70; }

l400000000004BAB0:
	{ st1	[r17],r1,1; st1	[r14],r37; nop.i	0x0; }
	{ st1	[r14],r17; st1	[r14],r36; nop.i	0x0; }
	{ st1	[r14],r31; st1	[r14],r30; nop.i	0x0; }
	{ st1	[r14],r29; st1	[r14],r28; nop.i	0x0; }
	{ st1	[r14],r27; st1	[r14],r26; nop.i	0x0 }
	{ ld8	r15,[r15]; st1	[r14],r25; nop.i	0x0 }
	{ st1	[r14],r24; st1	[r14],r23; nop.i	0x0 }
	{ st1	[r14],r22; st1	[r14],r21; nop.i	0x0 }
	{ st1	[r14],r20; ld4	r14,[r16]; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r17,r14; adds	r14,0x1,r14; }
	{ shladd	r15,r17,0x3,r15; nop.i	0x0; nop.i	0x0 }
	{ st8	[r32],r15; st4	[r14],r16; br.ret	b0; }

l400000000004BB70:
	{ adds	r36,0x0,r32; nop.i	0x0; br.call.sptk.many	b0,xfree; }
	{ adds	r1,0x0,r35; nop.m	0x0; mov.i	ar.pfs,r34; }
	{ nop.m	0x0; mov.spnt	b0,r33,400000000004BB90; br.ret	b0; }
400000000004BBA0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000004BBB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; dispose_words: 400000000004BBC0
;;   Called from:
;;     400000000002213C (in fn4000000000021EC0)
;;     400000000002219C (in fn4000000000021EC0)
;;     400000000002768C (in decode_prompt_string)
;;     400000000002768C (in decode_prompt_string)
;;     4000000000033B4C (in fn4000000000030880)
;;     4000000000035D1C (in fn4000000000030880)
;;     400000000003DB2C (in parse_string_to_word_list)
;;     400000000004332C (in make_arith_for_command)
;;     400000000004357C (in make_arith_for_command)
;;     400000000006A76C (in pop_dollar_vars)
;;     400000000006A95C (in dispose_saved_dollar_vars)
;;     400000000008FFAC (in string_rest_of_args)
;;     400000000008FFFC (in string_rest_of_args)
;;     40000000000978EC (in fn4000000000097540)
;;     400000000009A11C (in expand_string)
;;     40000000000A5F2C (in fn40000000000A5B80)
;;     40000000000A619C (in fn40000000000A5B80)
;;     40000000000A665C (in cond_expand_word)
;;     40000000000A66EC (in cond_expand_word)
;;     40000000000A69EC (in expand_assignment_string_to_string)
;;     40000000000A6DAC (in expand_string_unsplit_to_string)
;;     40000000000A78EC (in expand_string_to_string)
;;     40000000000A7BDC (in fn40000000000A7940)
;;     40000000000A7F1C (in fn40000000000A7940)
;;     40000000000A810C (in fn40000000000A7940)
;;     40000000000A83DC (in fn40000000000A7940)
;;     40000000000A844C (in fn40000000000A7940)
;;     40000000000A857C (in fn40000000000A7940)
;;     40000000000A87CC (in fn40000000000A7940)
;;     40000000000A87EC (in fn40000000000A7940)
;;     40000000000A884C (in fn40000000000A7940)
;;     40000000000A885C (in fn40000000000A7940)
;;     40000000000A8B4C (in fn40000000000A7940)
;;     40000000000A902C (in expand_word)
;;     40000000000BF46C (in expand_compound_array_assignment)
;;     40000000000C0D3C (in assign_array_var_from_string)
;;     40000000000C184C (in fn40000000000C14C0)
;;     40000000000C1C3C (in fn40000000000C14C0)
;;     40000000000C201C (in array_keys)
;;     40000000000C214C (in array_keys)
;;     40000000000C39AC (in assoc_subrange)
;;     40000000000DE49C (in redirection_expand)
;;     40000000000DE4EC (in redirection_expand)
;;     40000000000DE54C (in redirection_expand)
;;     40000000000E5D0C (in gen_compspec_completions)
;;     40000000000E5F8C (in gen_compspec_completions)
;;     40000000000E62BC (in gen_compspec_completions)
;;     40000000000E683C (in gen_compspec_completions)
;;     40000000000E68FC (in gen_compspec_completions)
;;     40000000000E73FC (in gen_compspec_completions)
;;     40000000000EEC9C (in remember_args)
;;     4000000000101A8C (in fn40000000001019C0)
;;     400000000010559C (in read_builtin)
;;     4000000000107F1C (in read_builtin)
;;     400000000010CB0C (in shift_builtin)
;;     400000000011434C (in shopt_setopt)
;;     400000000011D0EC (in complete_builtin)
;;     400000000011D1CC (in complete_builtin)
;;     400000000011D7DC (in complete_builtin)
dispose_words proc
	{ alloc	r40,ar.pfs,0xB,0x0,0xA; addl	r38,14028,r1; nop.b	0x0 }
	{ adds	r41,0x0,r1; mov	r39,b7; cmp.eq	p07,p06,0x0,r32; }
	{ nop.m	0x0; addl	r33,-33,r0; (p07) br.cond.dpnt.few	400000000004BD70; }

l400000000004BBF0:
	{ nop.m	0x0; adds	r35,0xC,r38; adds	r37,0x8,r38; }

l400000000004BC00:
	{ adds	r34,0x0,r32; ld8	r36,[r34],8; nop.i	0x0; }
	{ ld8	r42,[r34]; nop.i	0x0; br.call.sptk.many	b0,dispose_word; }
	{ ld4	r16,[r35]; adds	r14,0x0,r32; adds	r1,0x0,r41 }
	{ adds	r29,0x2,r32; adds	r28,0x3,r32; adds	r27,0x4,r32; }
	{ ld4	r15,[r37]; adds	r26,0x5,r32; adds	r25,0x6,r32 }
	{ adds	r24,0x7,r32; adds	r23,0x9,r32; adds	r22,0xA,r32; }
	{ cmp4.lt	p07,p06,r16,r15; adds	r21,0xB,r32; adds	r20,0xC,r32 }
	{ adds	r19,0xD,r32; adds	r18,0xE,r32; (p06) br.cond.dpnt.few	400000000004BD90; }

l400000000004BC80:
	{ st1	[r14],r1,1; nop.m	0x0; adds	r17,0xF,r32 }
	{ st1	[r33],r29; nop.m	0x0; cmp.eq	p07,p06,0x0,r36; }
	{ st1	[r33],r14; st1	[r33],r28; nop.i	0x0; }
	{ st1	[r33],r27; st1	[r33],r26; nop.i	0x0; }
	{ ld8.a	r15,[r38]; st1	[r33],r25; nop.i	0x0 }
	{ st1	[r33],r24; ld8.c.clr	r15,[r38]; nop.i	0x0 }
	{ st1	[r33],r34; st1	[r33],r23; nop.i	0x0; }
	{ st1	[r33],r22; st1	[r33],r21; nop.i	0x0; }
	{ st1	[r33],r20; st1	[r33],r19; nop.i	0x0; }
	{ ld4.a	r14,[r35]; st1	[r33],r18; nop.i	0x0 }
	{ st1	[r33],r17; nop.m	0x0; sxt4	r16,r14 }
	{ chk.a.clr	r14,400000000004BDC0; nop.i	0x0; nop.i	0x0 }

l400000000004BD36:
	{ break.m	0x4000; nop; (p32) nop }

l400000000004BD40:
	{ adds	r14,0x1,r14; shladd	r15,r16,0x3,r15; nop.i	0x0; }
	{ nop.m	0x0; st8	[r32],r15; nop.i	0x0 }
	{ st4	[r14],r35; adds	r32,0x0,r36; (p06) br.cond.dptk.few	400000000004BC00 }

l400000000004BD70:
	{ nop.m	0x0; mov.i	ar.pfs,r40; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r39,400000000004BD80; br.ret	b0; }

l400000000004BD90:
	{ adds	r42,0x0,r32; adds	r32,0x0,r36; br.call.sptk.many	b0,xfree; }
	{ adds	r1,0x0,r41; cmp.eq	p07,p06,0x0,r36; (p06) br.cond.dptk.few	400000000004BC00 }

l400000000004BDB0:
	{ nop.m	0x0; nop.i	0x0; br.cond.sptk.few	400000000004BD70 }

l400000000004BDC0:
	{ nop.m	0x0; ld4	r14,[r35]; nop.i	0x0; }
	{ nop.m	0x0; sxt4	r16,r14; br.cond.sptk.few	400000000004BD40; }
400000000004BDE0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000004BDF0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; dispose_redirects: 400000000004BE00
;;   Called from:
;;     400000000004732C (in fn40000000000470C0)
;;     400000000004C00C (in dispose_command)
;;     400000000004F0FC (in dispose_exec_redirects)
;;     40000000000DE876 (in fn40000000000DE580)
;;     40000000000DF39C (in fn40000000000DE580)
;;     40000000000E169C (in do_redirections)
;;     40000000000F7DAC (in exec_builtin)
;;     40000000000F7DAC (in exec_builtin)
dispose_redirects proc
	{ alloc	r38,ar.pfs,0x9,0x0,0x8; adds	r39,0x0,r1; mov	r37,b5 }
	{ cmp.eq	p07,p06,0x0,r32; nop.m	0x0; (p07) br.cond.dpnt.few	400000000004BF50; }

l400000000004BE20:
	{ addl	r34,1,r0; addl	r35,949295,r0; addl	r36,272,r0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000004BE40:
	{ adds	r14,0x0,r32; ld8	r33,[r14],16; nop.i	0x0; }
	{ nop.m	0x0; ld4	r14,[r14]; nop.i	0x0; }
	{ nop.m	0x0; tbit.z	p06,p07,r14,0x0; (p07) br.cond.dpnt.few	400000000004BF70 }

l400000000004BE70:
	{ nop.m	0x0; adds	r14,0x18,r32; nop.i	0x0; }
	{ ld4	r14,[r14]; nop.i	0x0; sxt4	r15,r14 }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0x13,r14; (p06) br.cond.dptk.few	400000000004BF30; }

l400000000004BEA0:
	{ nop.m	0x0; shl	r14,r34,r15; nop.i	0x0; }
	{ and	r15,r35,r14; nop.m	0x0; and	r14,r36,r14; }
	{ nop.m	0x0; cmp.eq	p07,p06,0x0,r15; (p06) br.cond.dptk.few	400000000004BF00; }

l400000000004BED0:
	{ adds	r15,0x28,r32; cmp.eq	p07,p06,0x0,r14; (p07) br.cond.dptk.few	400000000004BF30; }

l400000000004BEE0:
	{ ld8	r40,[r15]; br.call.sptk.many	b0,fn400000000001A7E0; nop.b	0x0; }
	{ adds	r1,0x0,r39; nop.m	0x0; nop.i	0x0 }

l400000000004BF00:
	{ adds	r14,0x20,r32; nop.i	0x0; nop.i	0x0 }
	{ ld8	r40,[r14]; nop.m	0x0; br.call.sptk.many	b0,dispose_word; }
	{ adds	r1,0x0,r39; nop.m	0x0; nop.i	0x0 }

l400000000004BF30:
	{ adds	r40,0x0,r32; adds	r32,0x0,r33; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r39; cmp.eq	p07,p06,0x0,r33; (p06) br.cond.dptk.few	400000000004BE40 }

l400000000004BF50:
	{ nop.m	0x0; mov.i	ar.pfs,r38; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r37,400000000004BF60; br.ret	b0 }

l400000000004BF70:
	{ nop.m	0x0; adds	r14,0x8,r32; nop.i	0x0; }
	{ ld8	r40,[r14]; nop.i	0x0; br.call.sptk.many	b0,dispose_word; }
	{ nop.m	0x0; adds	r1,0x0,r39; br.cond.sptk.few	400000000004BE70; }
400000000004BFA0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000004BFB0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................

;; dispose_command: 400000000004BFC0
;;   Called from:
;;     4000000000023FAC (in reader_loop)
;;     4000000000023FAC (in reader_loop)
;;     40000000000241DC (in reader_loop)
;;     400000000002447C (in reader_loop)
;;     400000000004B41C (in named_function_string)
;;     400000000004B68C (in named_function_string)
;;     400000000004C74C (in dispose_function_def_contents)
;;     400000000005097C (in shell_execve)
;;     400000000006104C (in fn4000000000060F80)
;;     40000000000648BC (in bind_function)
;;     400000000007B5EC (in delete_job)
;;     40000000000F666C (in parse_and_execute)
;;     40000000000F775C (in parse_string)
;;     40000000000F794C (in parse_string)
;;     40000000000FF48C (in jobs_builtin)
dispose_command proc
	{ alloc	r37,ar.pfs,0xB,0x0,0x7; adds	r14,0x10,r32; mov	r36,b4 }
	{ cmp.eq	p06,p07,0x0,r32; adds	r38,0x0,r1; (p06) br.cond.dpnt.few	400000000004C0A0; }

l400000000004BFE0:
	{ nop.m	0x0; ld8	r39,[r14]; nop.i	0x0; }
	{ cmp.eq	p06,p07,0x0,r39; nop.i	0x0; (p06) br.cond.dpnt.few	400000000004C020; }

l400000000004C000:
	{ nop.m	0x0; nop.i	0x0; br.call.sptk.many	b0,dispose_redirects; }
	{ adds	r1,0x0,r38; nop.m	0x0; nop.i	0x0 }

l400000000004C020:
	{ nop.m	0x0; ld4	r41,[r32]; nop.i	0x0; }
	{ nop.m	0x0; cmp4.ltu	p06,p07,0xE,r41; (p07) br.cond.dptk.few	400000000004C0C0 }

l400000000004C040:
	{ addl	r39,-8668,r1; addl	r40,1,r0; adds	r42,0x0,r0; }
	{ ld8	r39,[r39]; nop.i	0x0; br.call.sptk.many	b0,command_error; }
	{ nop.m	0x0; adds	r1,0x0,r38; adds	r39,0x0,r32 }
	{ nop.m	0x0; nop.m	0x0; br.call.sptk.many	b0,fn400000000001A7E0; }
	{ adds	r1,0x0,r38; nop.m	0x0; nop.i	0x0; }
	{ nop.m	0x0; nop.m	0x0; nop.i	0x0 }

l400000000004C0A0:
	{ nop.m	0x0; mov.i	ar.pfs,r37; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b0,r36,400000000004C0B0; br.ret	b0 }

l400000000004C0C0:
	{ addl	r14,-8660,r1; nop.m	0x0; addp4	r41,r41,r0; }
	{ ld8	r14,[r14]; shladd	r41,r41,0x3,r14; nop.i	0x0; }
	{ ld8	r14,[r41]; add	r41,r41,r14; nop.i	0x0; }
	{ nop.m	0x0; mov.spnt	b6,r41,400000000004C0F0; br.cond	b6; }
400000000004C100 0B 08 61 40 00 21 E0 00 84 30 20 00 00 00 04 00 ..a@.!...0 .....
400000000004C110 09 00 00 00 01 00 E0 40 38 00 42 00 00 00 04 00 .......@8.B.....
400000000004C120 11 38 01 1C 18 10 00 00 00 02 00 00 A8 FE FF 58 .8.............X
400000000004C130 08 00 00 00 01 00 10 00 98 00 42 00 00 00 04 00 ..........B.....
400000000004C140 19 38 01 42 18 10 00 00 00 02 00 00 A8 E6 FC 58 .8.B...........X
400000000004C150 08 08 00 4C 00 21 00 00 00 02 00 00 00 00 04 00 ...L.!..........
400000000004C160 11 38 01 40 00 21 00 00 00 02 00 00 88 E6 FC 58 .8.@.!.........X
400000000004C170 10 00 00 00 01 00 10 00 98 00 42 00 30 FF FF 48 ..........B.0..H
400000000004C180 0B 70 60 40 00 21 10 02 38 30 20 00 00 00 04 00 .p`@.!..80 .....
400000000004C190 09 00 00 00 01 00 E0 40 84 00 42 00 00 00 04 00 .......@..B.....
400000000004C1A0 11 38 01 1C 18 10 00 00 00 02 00 00 28 FE FF 58 .8..........(..X
400000000004C1B0 09 70 40 42 00 21 00 00 00 02 00 20 00 30 01 84 .p@B.!..... .0..
400000000004C1C0 11 38 01 1C 18 10 00 00 00 02 00 00 08 FE FF 58 .8.............X
400000000004C1D0 08 00 00 00 01 00 10 00 98 00 42 E0 04 08 01 84 ..........B.....
400000000004C1E0 19 00 00 00 01 00 00 00 00 02 00 00 08 E6 FC 58 ...............X
400000000004C1F0 08 08 00 4C 00 21 00 00 00 02 00 00 00 00 04 00 ...L.!..........
400000000004C200 11 38 01 40 00 21 00 00 00 02 00 00 E8 E5 FC 58 .8.@.!.........X
400000000004C210 10 00 00 00 01 00 10 00 98 00 42 00 90 FE FF 48 ..........B....H
400000000004C220 09 00 00 00 01 00 E0 C0 80 00 42 00 00 00 04 00 ..........B.....
400000000004C230 11 38 01 1C 18 10 00 00 00 02 00 00 98 05 00 50 .8.............P
400000000004C240 11 08 00 4C 00 21 70 02 80 00 42 00 A8 E5 FC 58 ...L.!p...B....X
400000000004C250 10 00 00 00 01 00 10 00 98 00 42 00 50 FE FF 48 ..........B.P..H
400000000004C260 09 00 00 00 01 00 E0 C0 80 00 42 00 00 00 04 00 ..........B.....
400000000004C270 11 38 01 1C 18 10 00 00 00 02 00 00 58 F6 FF 58 .8..........X..X
400000000004C280 11 08 00 4C 00 21 70 02 80 00 42 00 68 E5 FC 58 ...L.!p...B.h..X
400000000004C290 10 00 00 00 01 00 10 00 98 00 42 00 10 FE FF 48 ..........B....H
400000000004C2A0 0B 70 60 40 00 21 10 02 38 30 20 00 00 00 04 00 .p`@.!..80 .....
400000000004C2B0 09 00 00 00 01 00 E0 40 84 00 42 00 00 00 04 00 .......@..B.....
400000000004C2C0 11 38 01 1C 18 10 00 00 00 02 00 00 08 F9 FF 58 .8.............X
400000000004C2D0 11 08 00 4C 00 21 70 02 84 00 42 00 18 E5 FC 58 ...L.!p...B....X
400000000004C2E0 11 08 00 4C 00 21 70 02 80 00 42 00 08 E5 FC 58 ...L.!p...B....X
400000000004C2F0 10 00 00 00 01 00 10 00 98 00 42 00 B0 FD FF 48 ..........B....H
400000000004C300 0B 70 60 40 00 21 10 02 38 30 20 00 00 00 04 00 .p`@.!..80 .....
400000000004C310 09 00 00 00 01 00 E0 40 84 00 42 00 00 00 04 00 .......@..B.....
400000000004C320 11 38 01 1C 18 10 00 00 00 02 00 00 A8 F8 FF 58 .8.............X
400000000004C330 09 70 40 42 00 21 00 00 00 02 00 20 00 30 01 84 .p@B.!..... .0..
400000000004C340 11 38 01 1C 18 10 00 00 00 02 00 00 C8 FA FF 58 .8.............X
400000000004C350 11 08 00 4C 00 21 70 02 84 00 42 00 98 E4 FC 58 ...L.!p...B....X
400000000004C360 11 08 00 4C 00 21 70 02 80 00 42 00 88 E4 FC 58 ...L.!p...B....X
400000000004C370 10 00 00 00 01 00 10 00 98 00 42 00 30 FD FF 48 ..........B.0..H
400000000004C380 0B 70 60 40 00 21 10 02 38 30 20 00 00 00 04 00 .p`@.!..80 .....
400000000004C390 09 00 00 00 01 00 E0 40 84 00 42 00 00 00 04 00 .......@..B.....
400000000004C3A0 11 38 01 1C 18 10 00 00 00 02 00 00 28 FC FF 58 .8..........(..X
400000000004C3B0 09 70 40 42 00 21 00 00 00 02 00 20 00 30 01 84 .p@B.!..... .0..
400000000004C3C0 11 38 01 1C 18 10 00 00 00 02 00 00 08 FC FF 58 .8.............X
400000000004C3D0 09 70 60 42 00 21 00 00 00 02 00 20 00 30 01 84 .p`B.!..... .0..
400000000004C3E0 11 38 01 1C 18 10 00 00 00 02 00 00 E8 FB FF 58 .8.............X
400000000004C3F0 11 08 00 4C 00 21 70 02 84 00 42 00 F8 E3 FC 58 ...L.!p...B....X
400000000004C400 10 00 00 00 01 00 10 00 98 00 42 00 00 FE FF 48 ..........B....H
400000000004C410 0B 70 60 40 00 21 10 02 38 30 20 00 00 00 04 00 .p`@.!..80 .....
400000000004C420 09 00 00 00 01 00 E0 40 84 00 42 00 00 00 04 00 .......@..B.....
400000000004C430 11 38 01 1C 18 10 00 00 00 02 00 00 98 F7 FF 58 .8.............X
400000000004C440 09 70 40 42 00 21 00 00 00 02 00 20 00 30 01 84 .p@B.!..... .0..
400000000004C450 11 38 01 1C 18 10 00 00 00 02 00 00 78 F7 FF 58 .8..........x..X
400000000004C460 09 70 60 42 00 21 00 00 00 02 00 20 00 30 01 84 .p`B.!..... .0..
400000000004C470 11 38 01 1C 18 10 00 00 00 02 00 00 58 F7 FF 58 .8..........X..X
400000000004C480 09 70 80 42 00 21 00 00 00 02 00 20 00 30 01 84 .p.B.!..... .0..
400000000004C490 11 38 01 1C 18 10 00 00 00 02 00 00 38 FB FF 58 .8..........8..X
400000000004C4A0 11 08 00 4C 00 21 70 02 84 00 42 00 48 E3 FC 58 ...L.!p...B.H..X
400000000004C4B0 10 00 00 00 01 00 10 00 98 00 42 00 50 FD FF 48 ..........B.P..H
400000000004C4C0 0B 70 60 40 00 21 30 02 38 30 20 00 00 00 04 00 .p`@.!0.80 .....
400000000004C4D0 09 00 00 00 01 00 E0 40 8C 00 42 00 00 00 04 00 .......@..B.....
400000000004C4E0 11 38 01 1C 18 10 00 00 00 02 00 00 E8 F1 FF 58 .8.............X
400000000004C4F0 09 70 40 46 00 21 00 00 00 02 00 20 00 30 01 84 .p@F.!..... .0..
400000000004C500 09 00 00 00 01 00 10 02 38 30 20 00 00 00 04 00 ........80 .....
400000000004C510 11 00 00 00 01 00 70 00 84 0C F2 03 90 00 00 43 ......p........C
400000000004C520 09 00 00 00 01 00 E0 40 84 00 42 00 00 00 04 00 .......@..B.....
400000000004C530 11 38 01 1C 18 10 00 00 00 02 00 00 98 F6 FF 58 .8.............X
400000000004C540 09 70 40 42 00 21 00 00 00 02 00 20 00 30 01 84 .p@B.!..... .0..
400000000004C550 11 38 01 1C 18 10 00 00 00 02 00 00 78 FA FF 58 .8..........x..X
400000000004C560 08 08 00 4C 00 21 20 02 84 30 20 E0 04 08 01 84 ...L.! ..0 .....
400000000004C570 19 00 00 00 01 00 00 00 00 02 00 00 78 E2 FC 58 ............x..X
400000000004C580 08 00 00 00 01 00 10 00 98 00 42 20 04 10 01 84 ..........B ....
400000000004C590 18 00 00 00 01 00 70 00 88 0C 72 03 90 FF FF 4A ......p...r....J
400000000004C5A0 11 38 01 46 00 21 00 00 00 02 00 00 48 E2 FC 58 .8.F.!......H..X
400000000004C5B0 11 08 00 4C 00 21 70 02 80 00 42 00 38 E2 FC 58 ...L.!p...B.8..X
400000000004C5C0 10 00 00 00 01 00 10 00 98 00 42 00 E0 FA FF 48 ..........B....H
400000000004C5D0 0B 70 60 40 00 21 10 02 38 30 20 00 00 00 04 00 .p`@.!..80 .....
400000000004C5E0 09 00 00 00 01 00 E0 40 84 00 42 00 00 00 04 00 .......@..B.....
400000000004C5F0 11 38 01 1C 18 10 00 00 00 02 00 00 D8 F0 FF 58 .8.............X
400000000004C600 09 70 40 42 00 21 00 00 00 02 00 20 00 30 01 84 .p@B.!..... .0..
400000000004C610 11 38 01 1C 18 10 00 00 00 02 00 00 B8 F5 FF 58 .8.............X
400000000004C620 09 70 60 42 00 21 00 00 00 02 00 20 00 30 01 84 .p`B.!..... .0..
400000000004C630 11 38 01 1C 18 10 00 00 00 02 00 00 98 F9 FF 58 .8.............X
400000000004C640 11 08 00 4C 00 21 70 02 84 00 42 00 A8 E1 FC 58 ...L.!p...B....X
400000000004C650 10 00 00 00 01 00 10 00 98 00 42 00 B0 FB FF 48 ..........B....H
400000000004C660 0B 08 61 40 00 21 E0 00 84 30 20 00 00 00 04 00 ..a@.!...0 .....
400000000004C670 09 00 00 00 01 00 E0 40 38 00 42 00 00 00 04 00 .......@8.B.....
400000000004C680 11 38 01 1C 18 10 00 00 00 02 00 00 68 E1 FC 58 .8..........h..X
400000000004C690 03 70 00 42 18 10 10 00 98 00 42 C0 01 71 00 84 .p.B......B..q..
400000000004C6A0 11 38 01 1C 18 10 00 00 00 02 00 00 28 F9 FF 58 .8..........(..X
400000000004C6B0 08 00 00 00 01 00 10 00 98 00 42 00 00 00 04 00 ..........B.....
400000000004C6C0 19 38 01 42 18 10 00 00 00 02 00 00 28 E1 FC 58 .8.B........(..X
400000000004C6D0 11 00 00 00 01 00 10 00 98 00 42 00 90 FA FF 48 ..........B....H
400000000004C6E0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
400000000004C6F0 08 00 00 00 01 00 00 00 00 02 00 00 00 00 04 00 ................
