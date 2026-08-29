
void __cdecl16far FUN_1000_2756(byte *param_1)

{
  byte *pbVar1;
  char cVar2;
  code *pcVar3;
  byte *pbVar4;
  char extraout_DL;
  char extraout_DH;
  byte *pbVar5;
  byte *pbVar6;
  undefined2 uVar7;
  undefined2 unaff_SS;

  FUN_1000_2e1a();
  FUN_1000_2efb();
  uVar7 = (undefined2)((ulong)param_1 >> 0x10);
  pbVar5 = (byte *)param_1;
  pbVar4 = pbVar5;
  while( true ) {
    do {
      do {
        pbVar6 = pbVar4;
        pbVar4 = pbVar6 + 1;
      } while (0xd < *pbVar6);
    } while (((*pbVar6 != 0xd) && (*pbVar6 != 10)) && (*pbVar6 != 0));
    FUN_1000_27d8();
    pbVar1 = pbVar5;
    pbVar5 = pbVar5 + 1;
    if (*pbVar1 == 0) break;
    if (*pbVar1 == 0xd) {
      FUN_1000_2836();
      pbVar4 = pbVar5;
    }
    else {
      FUN_1000_2825();
      pbVar4 = pbVar5;
    }
  }
  pcVar3 = (code *)swi(0x10);
  (*pcVar3)(pbVar5,&stack0xfffe);
  cVar2 = *(char *)&DAT_4000_d79f;
  *(char *)&DAT_4000_d79d = extraout_DL - *(char *)&DAT_4000_d7a1;
  *(char *)&DAT_4000_d79b = extraout_DH - cVar2;
  FUN_1000_2e3b();
  return;
}
