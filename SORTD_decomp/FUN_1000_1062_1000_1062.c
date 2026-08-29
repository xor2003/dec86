
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_1000_1062(void)

{
  char *pcVar1;
  byte *pbVar2;
  byte *pbVar3;
  byte *pbVar4;
  code *pcVar5;
  int iVar6;
  uint extraout_DX;
  int in_BX;
  int iVar7;
  int unaff_SI;
  byte *pbVar8;
  byte *pbVar9;
  undefined2 unaff_ES;
  undefined2 unaff_SS;
  bool bVar10;

  FUN_1000_14d4();
  FUN_1000_1753();
  if (*(int *)&DAT_4000_d628 == -0x292a) {
    (*(code *)*(undefined2 *)0x63c)();
  }
  (*_DAT_4000_d242)(0xff);
  pcVar1 = (char *)(in_BX + unaff_SI + 0x3500);
  *pcVar1 = *pcVar1 + (char)((uint)in_BX >> 8);
  pcVar5 = (code *)swi(0x21);
  (*pcVar5)();
  pcVar5 = (code *)swi(0x21);
  _DAT_4000_d26c = in_BX;
  _DAT_4000_d26e = unaff_ES;
  (*pcVar5)();
  if (*(int *)&DAT_4000_d63a != 0) {
    *(undefined2 *)&DAT_4000_d63c = 0x1000;
    *(undefined2 *)0x654 = 0x1000;
    bVar10 = false;
    (*(code *)*(undefined2 *)&DAT_4000_d63a)();
    if (bVar10) {
      FUN_1000_14f4();
      return;
    }
    (*(code *)*(undefined2 *)&DAT_4000_d63a)();
  }
  iVar7 = *(int *)0x2c;
  if (iVar7 != 0) {
    pbVar9 = (byte *)0x0;
    do {
      if (*pbVar9 == 0) break;
      iVar6 = 0xd;
      pbVar8 = (byte *)&DAT_4000_d25e;
      bVar10 = false;
      do {
        if (iVar6 == 0) break;
        iVar6 = iVar6 + -1;
        pbVar4 = pbVar9;
        pbVar9 = pbVar9 + 1;
        pbVar2 = pbVar8;
        pbVar8 = pbVar8 + 1;
        bVar10 = *pbVar2 == *pbVar4;
      } while (bVar10);
      if (bVar10) {
        pbVar8 = (byte *)0x299;
        goto LAB_1000_110f;
      }
      iVar6 = 0x7fff;
      bVar10 = true;
      do {
        if (iVar6 == 0) break;
        iVar6 = iVar6 + -1;
        pbVar2 = pbVar9;
        pbVar9 = pbVar9 + 1;
        bVar10 = *pbVar2 == 0;
      } while (!bVar10);
    } while (bVar10);
  }
LAB_1000_1123:
  iVar7 = 4;
  do {
    bVar10 = false;
    *(byte *)(iVar7 + 0x299) = *(byte *)(iVar7 + 0x299) & 0xbf;
    pcVar5 = (code *)swi(0x21);
    (*pcVar5)();
    if ((!bVar10) && ((extraout_DX & 0x80) != 0)) {
      *(byte *)(iVar7 + 0x299) = *(byte *)(iVar7 + 0x299) | 0x40;
    }
    iVar7 = iVar7 + -1;
  } while (-1 < iVar7);
  FUN_1000_120f();
  FUN_1000_1200();
  return;
LAB_1000_110f:
  pbVar2 = pbVar9;
  pbVar3 = pbVar9 + 1;
  if (*pbVar2 < 0x41) goto LAB_1000_1123;
  pbVar9 = pbVar9 + 2;
  if (*pbVar3 < 0x41) goto LAB_1000_1123;
  pbVar4 = pbVar8;
  pbVar8 = pbVar8 + 1;
  *pbVar4 = *pbVar3 + 0xbf | (*pbVar2 + 0xbf) * '\x10';
  goto LAB_1000_110f;
}
