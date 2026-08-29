/* FUN_1000_0010_1000_0010.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_0010(void)

{
  FUN_1000_1222();
  _DAT_4000_db92 = FUN_1000_2a29(0x2b);
  FUN_1000_2b5e(0);
  FUN_1000_2bc0(0);
  FUN_1000_0554();
  FUN_1000_005d();
  FUN_1000_02cc();
  FUN_1000_294f(0xffff);
  return;
}



/* FUN_1000_005d_1000_005d.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_005d(void)

{
  undefined1 local_14 [6];
  undefined2 uStack_e;
  undefined2 uStack_c;
  undefined1 *puStack_a;
  int iStack_8;
  undefined1 *puStack_6;
  int iVar1;

  FUN_1000_1222();
  puStack_6 = (undefined1 *)0xf;
  iStack_8 = 0x1000;
  puStack_a = (undefined1 *)0x74;
  FUN_1000_2b24();
  puStack_6 = (undefined1 *)0x0;
  iStack_8 = 0;
  puStack_a = (undefined1 *)0x1000;
  uStack_c = 0x80;
  FUN_1000_2b3e();
  puStack_6 = (undefined1 *)(_DAT_4000_d150 + 2);
  iStack_8 = 0x23;
  puStack_a = (undefined1 *)0x2d;
  uStack_c = 1;
  uStack_e = 0x99;
  FUN_1000_01db();
  iVar1 = 0;
  while (iVar1 < _DAT_4000_d150) {
    puStack_6 = (undefined1 *)0x32;
    iStack_8 = 0x1000;
    puStack_a = (undefined1 *)0xc2;
    FUN_1000_28e4();
    puStack_6 = (undefined1 *)uRam0004d186;
    iStack_8 = 0x1000;
    puStack_a = (undefined1 *)0xd4;
    FUN_1000_2756();
    iVar1 = 0x4d00;
  }
  if (_DAT_4000_db36 == 0) {
    puStack_6 = local_14;
    iStack_8 = 0x100;
    FUN_1000_123a();
  }
  else {
    puStack_6 = local_14;
    iStack_8 = 0xef;
    FUN_1000_123a();
  }
  puStack_6 = (undefined1 *)(_DAT_4000_d150 + -7);
  iStack_8 = 0x1000;
  puStack_a = (undefined1 *)0x113;
  FUN_1000_28e4();
  puStack_6 = local_14;
  iStack_8 = 0x1000;
  puStack_a = (undefined1 *)0x120;
  FUN_1000_2756();
  puStack_6 = (undefined1 *)0x1e;
  iStack_8 = _DAT_4000_d124;
  puStack_a = (undefined1 *)_DAT_4000_d122;
  uStack_c = 0x136;
  puStack_6 = (undefined1 *)FUN_1000_143a();
  iStack_8 = 0x16a;
  puStack_a = local_14;
  uStack_c = 0x143;
  FUN_1000_12ba();
  puStack_6 = (undefined1 *)(_DAT_4000_d150 + -5);
  iStack_8 = 0x1000;
  puStack_a = (undefined1 *)0x156;
  FUN_1000_28e4();
  puStack_6 = local_14;
  iStack_8 = 0x1000;
  puStack_a = (undefined1 *)0x163;
  FUN_1000_2756();
  puStack_6 = local_14;
  iStack_8 = 0x171;
  FUN_1000_123a();
  if ((_DAT_4000_d122 == 900) && (_DAT_4000_d124 == 0)) {
    puStack_6 = (undefined1 *)(_DAT_4000_d150 + -4);
    iStack_8 = 0x1000;
    puStack_a = (undefined1 *)0x199;
    FUN_1000_28e4();
    puStack_6 = local_14;
    iStack_8 = 0x1000;
    puStack_a = (undefined1 *)0x1a6;
    FUN_1000_2756();
  }
  if (_DAT_4000_d124 == 0 && _DAT_4000_d122 == 0) {
    puStack_6 = (undefined1 *)(_DAT_4000_d150 + -3);
    iStack_8 = 0x1000;
    puStack_a = (undefined1 *)0x1c5;
    FUN_1000_28e4();
    puStack_6 = local_14;
    iStack_8 = 0x1000;
    puStack_a = (undefined1 *)0x1d2;
    FUN_1000_2756();
  }
  return;
}



/* FUN_1000_01db_1000_01db.c */


void FUN_1000_01db(int param_1,undefined2 param_2,int param_3,int param_4)

{
  undefined2 unaff_SS;
  undefined1 auStack_55 [73];
  undefined2 uStack_c;
  undefined1 *puStack_a;
  undefined1 *puStack_8;
  int iVar1;

  FUN_1000_1222();
  puStack_8 = (undefined1 *)0xcd;
  puStack_a = auStack_55 + 1;
  uStack_c = 0x209;
  FUN_1000_13d4();
  auStack_55[1] = 0xc9;
  auStack_55[param_3] = 0xbb;
  auStack_55[param_3 + 1] = 0;
  puStack_8 = (undefined1 *)param_1;
  puStack_a = (undefined1 *)0x1000;
  uStack_c = 0x229;
  FUN_1000_28e4();
  puStack_8 = auStack_55 + 1;
  puStack_a = (undefined1 *)0x1000;
  uStack_c = 0x236;
  FUN_1000_2756();
  puStack_8 = (undefined1 *)0x20;
  puStack_a = auStack_55 + 1;
  uStack_c = 0x247;
  FUN_1000_13d4();
  auStack_55[1] = 0xba;
  auStack_55[param_3] = 0xba;
  iVar1 = param_1;
  while (iVar1 = iVar1 + 1, iVar1 <= param_4) {
    puStack_a = (undefined1 *)0x1000;
    uStack_c = 0x278;
    puStack_8 = (undefined1 *)iVar1;
    FUN_1000_28e4();
    puStack_8 = auStack_55 + 1;
    puStack_a = (undefined1 *)0x1000;
    uStack_c = 0x285;
    FUN_1000_2756();
  }
  puStack_8 = (undefined1 *)0xcd;
  puStack_a = auStack_55 + 1;
  uStack_c = 0x299;
  FUN_1000_13d4();
  auStack_55[1] = 200;
  auStack_55[param_3] = 0xbc;
  puStack_8 = (undefined1 *)(param_4 + param_1);
  puStack_a = (undefined1 *)0x1000;
  uStack_c = 0x2b6;
  FUN_1000_28e4();
  puStack_8 = auStack_55 + 1;
  puStack_a = (undefined1 *)0x1000;
  uStack_c = 0x2c3;
  FUN_1000_2756();
  return;
}



/* FUN_1000_02cc_1000_02cc.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_1000_02cc(void)

{
  undefined1 uVar1;
  int iVar2;
  undefined2 unaff_SI;
  bool bVar3;
  undefined1 uVar4;

  FUN_1000_1222();
  while( true ) {
    while( true ) {
      while( true ) {
        uVar4 = (undefined1)((uint)unaff_SI >> 8);
        _DAT_4000_db9a = 0;
        _DAT_4000_db94 = 0;
        FUN_1000_28e4(_DAT_4000_d150 + 1,0x4b);
        FUN_1000_2bc0(1);
        uVar1 = func_0x00011292();
        unaff_SI = CONCAT11(uVar4,uVar1);
        FUN_1000_2bc0(0,unaff_SI);
        iVar2 = FUN_1000_1278((int)(char)unaff_SI);
        if (iVar2 != 0x45) break;
        _DAT_4000_db9c = 3;
        FUN_1000_0672();
        func_0x00010b2c();
        FUN_1000_0491(0);
      }
      if (iVar2 < 0x46) break;
      if (iVar2 == 0x48) {
        _DAT_4000_db9c = 2;
        FUN_1000_0672();
        func_0x0001095b();
        FUN_1000_0491(0);
      }
      else if (iVar2 == 0x49) {
        _DAT_4000_db9c = 0;
        FUN_1000_0672();
        func_0x000107e7();
        FUN_1000_0491(0);
      }
      else if (iVar2 == 0x51) {
        _DAT_4000_db9c = 5;
        FUN_1000_0672();
        func_0x00010cd4(0,_DAT_4000_db92);
        FUN_1000_0491(0);
      }
      else if (iVar2 == 0x53) {
        _DAT_4000_db9c = 4;
        FUN_1000_0672();
        func_0x00010bf4();
        FUN_1000_0491(0);
      }
      else if (iVar2 == 0x54) {
        _DAT_4000_db36 = (uint)(_DAT_4000_db36 == 0);
        FUN_1000_005d();
      }
    }
    if (iVar2 == 0x1b) break;
    if (iVar2 == 0x3c) {
      if ((_DAT_4000_d124 < 1) && ((_DAT_4000_d124 < 0 || (_DAT_4000_d122 < 0x385)))) {
        bVar3 = 0xffe1 < _DAT_4000_d122;
        _DAT_4000_d122 = _DAT_4000_d122 + 0x1e;
        _DAT_4000_d124 = _DAT_4000_d124 + (uint)bVar3;
      }
      FUN_1000_005d();
    }
    else if (iVar2 == 0x3e) {
      if (_DAT_4000_d124 != 0 || _DAT_4000_d122 != 0) {
        bVar3 = _DAT_4000_d122 < 0x1e;
        _DAT_4000_d122 = _DAT_4000_d122 - 0x1e;
        _DAT_4000_d124 = _DAT_4000_d124 - (uint)bVar3;
      }
      FUN_1000_005d();
    }
    else if (iVar2 == 0x42) {
      _DAT_4000_db9c = 1;
      FUN_1000_0672();
      func_0x000108c0();
      FUN_1000_0491(0);
    }
  }
  return;
}



/* FUN_1000_0491_1000_0491.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_0491(int param_1)

{
  long lVar1;
  undefined1 local_52 [64];
  undefined2 uStack_12;
  undefined4 uStack_10;
  undefined4 uStack_c;
  undefined1 *puStack_8;

  FUN_1000_1222();
  puStack_8 = (undefined1 *)0x1000;
  uStack_c._2_2_ = 0x4ac;
  FUN_1000_2b24();
  _DAT_4000_db38 = FUN_1000_137e();
  puStack_8 = (undefined1 *)_DAT_4000_db94;
  uStack_c._2_2_ = 0;
  uStack_c._0_2_ = 1000;
  uStack_10 = _DAT_4000_db38 - CONCAT22(_DAT_4000_db98,_DAT_4000_db96);
  uStack_12 = 0x4dd;
  uStack_c = FUN_1000_143a();
  uStack_10._2_2_ = 0x17d;
  uStack_10._0_2_ = local_52;
  uStack_12 = 0x4ea;
  FUN_1000_12ba();
  puStack_8 = (undefined1 *)(_DAT_4000_db9c + 7);
  uStack_c._2_2_ = 0x1000;
  uStack_c._0_2_ = 0x4fd;
  FUN_1000_28e4();
  puStack_8 = local_52;
  uStack_c._2_2_ = 0x1000;
  uStack_c._0_2_ = 0x50a;
  FUN_1000_2756();
  if (_DAT_4000_db36 == 0) {
    puStack_8 = (undefined1 *)_DAT_4000_d122;
    uStack_c._2_2_ = 0x54b;
    FUN_1000_0f18();
    lVar1 = _DAT_4000_db38;
  }
  else {
    puStack_8 = (undefined1 *)(param_1 * 0x3c);
    uStack_c._2_2_ = 0x525;
    FUN_1000_0e5d();
    puStack_8 = (undefined1 *)0x53a;
    FUN_1000_0f18();
    lVar1 = _DAT_4000_db38;
  }
  _DAT_4000_db3a = (undefined2)((ulong)lVar1 >> 0x10);
  _DAT_4000_db38 = (undefined2)lVar1;
  return;
}



/* FUN_1000_0554_1000_0554.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_0554(void)

{
  int iVar1;
  int iVar2;
  undefined2 unaff_SS;
  int in_stack_00000bb8;
  int local_76;
  undefined1 local_74;
  undefined1 local_72 [14];
  int local_64;
  int local_60;
  int aiStack_5c [40];
  undefined2 uStack_c;
  undefined2 uStack_a;
  undefined1 *puStack_8;
  int iVar3;

  FUN_1000_1222();
  puStack_8 = (undefined1 *)0x572;
  FUN_1000_132c();
  puStack_8 = (undefined1 *)0x579;
  FUN_1000_1402();
  _DAT_4000_db36 = 1;
  _DAT_4000_d122 = 0x1e;
  _DAT_4000_d124 = 0;
  puStack_8 = local_72;
  uStack_a = 0x1000;
  uStack_c = 0x598;
  FUN_1000_2ac8();
  if (((local_60 == 1) || (local_64 == 2)) || (local_64 == 0)) {
    local_76 = 1;
  }
  else {
    local_76 = 0xf;
  }
  for (iVar3 = 0; iVar3 < _DAT_4000_db92; iVar3 = iVar3 + 1) {
    aiStack_5c[iVar3] = iVar3 + 1;
  }
  for (iVar3 = 0; iVar3 < _DAT_4000_db92; iVar3 = iVar3 + 1) {
    iVar2 = FUN_1000_1414();
    iVar1 = aiStack_5c[iVar2 % 0x60b];
    aiStack_5c[iVar2 % 0x60b] = in_stack_00000bb8;
    local_74 = (undefined1)iVar1;
    *(undefined1 *)(iVar3 * 2 + 0x8f0) = local_74;
    if (local_76 == 1) {
      *(undefined1 *)(iVar3 * 2 + 0x8f1) = 7;
    }
    else {
      *(char *)(iVar3 * 2 + 0x8f1) = (char)(iVar1 % local_76) + '\x01';
    }
  }
  FUN_1000_0672();
  return;
}



/* FUN_1000_0672_1000_0672.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_0672(void)

{
  undefined4 uVar1;
  int iVar2;

  FUN_1000_1222();
  uVar1 = FUN_1000_137e();
  for (iVar2 = 0; _DAT_4000_db98 = (undefined2)((ulong)uVar1 >> 0x10),
      _DAT_4000_db96 = (undefined2)uVar1, iVar2 < _DAT_4000_db92; iVar2 = iVar2 + 1) {
    _DAT_4000_db96 = uVar1;
    *(undefined2 *)(iVar2 * 2 + 0xb4c) = *(undefined2 *)(iVar2 * 2 + 0x8f0);
    FUN_1000_06c8(iVar2);
    uVar1 = _DAT_4000_db96;
  }
  return;
}



/* FUN_1000_06c8_1000_06c8.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_06c8(int param_1)

{
  undefined2 unaff_SS;
  undefined1 local_2e [34];
  undefined2 uStack_c;
  undefined1 *puStack_a;
  undefined1 *puStack_8;

  FUN_1000_1222();
  puStack_8 = (undefined1 *)0xdf;
  puStack_a = local_2e;
  uStack_c = 0x6e9;
  FUN_1000_13d4();
  puStack_8 = (undefined1 *)0x20;
  puStack_a = local_2e + *(char *)(param_1 * 2 + 0xb4c);
  uStack_c = 0x719;
  FUN_1000_13d4();
  local_2e[_DAT_4000_db92] = 0;
  puStack_8 = (undefined1 *)0x1000;
  puStack_a = (undefined1 *)0x734;
  FUN_1000_2b24();
  puStack_8 = (undefined1 *)(param_1 + 1);
  puStack_a = (undefined1 *)0x1000;
  uStack_c = 0x745;
  FUN_1000_28e4();
  puStack_8 = local_2e;
  puStack_a = (undefined1 *)0x1000;
  uStack_c = 0x752;
  FUN_1000_2756();
  return;
}



/* FUN_1000_075b_1000_075b.c */


void __cdecl16near FUN_1000_075b(undefined2 param_1,undefined2 param_2)

{
  FUN_1000_1222();
  FUN_1000_06c8(param_1);
  FUN_1000_06c8(param_2);
  FUN_1000_0491(param_1);
  return;
}



/* FUN_1000_0794_1000_0794.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_1000_0794(undefined2 *param_1,undefined2 *param_2)

{
  undefined2 uVar1;

  FUN_1000_1222();
  _DAT_4000_db94 = _DAT_4000_db94 + 1;
  uVar1 = *param_1;
  *param_1 = *param_2;
  *param_2 = uVar1;
  return;
}



/* FUN_1000_09e8_1000_09e8.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_09e8(int param_1)

{
  int iVar1;
  int iVar2;

  FUN_1000_1222();
  while( true ) {
    if (param_1 == 0) {
      return;
    }
    iVar1 = param_1 / 2;
    _DAT_4000_db9a = _DAT_4000_db9a + 1;
    if (*(char *)(param_1 * 2 + 0xb4c) <= *(char *)(iVar1 * 2 + 0xb4c)) break;
    iVar2 = param_1 * 2 + 0xb4c;
    FUN_1000_0794(iVar1 * 2 + 0xb4c,iVar2);
    FUN_1000_075b(iVar1,iVar2);
    param_1 = iVar1;
  }
  return;
}



/* FUN_1000_0e5d_1000_0e5d.c */


void FUN_1000_0e5d(int param_1,int param_2)

{
  int iVar1;
  undefined2 unaff_SI;

  FUN_1000_1222();
  if (param_1 != 0) {
    if (param_2 < 0x4b) {
      param_2 = 0x4b;
    }
    func_0x0001131e(0x43,0xb6);
    iVar1 = FUN_1000_143a(0x34dc,0x12,param_1,param_1 >> 0xf);
    param_1._0_1_ = (char)iVar1;
    func_0x0001131e(0x42,(int)(char)param_1);
    param_1._1_1_ = (char)((uint)iVar1 >> 8);
    func_0x0001131e(0x42,(int)param_1._1_1_);
    FUN_1000_1310();
    unaff_SI = 0xeed;
    func_0x0001131e(0x61);
    param_1 = iVar1;
  }
  FUN_1000_0f18(param_2,param_2 >> 0xf);
  if (param_1 != 0) {
    func_0x0001131e(0x61,unaff_SI);
  }
  return;
}



/* FUN_1000_0f18_1000_0f18.c */


void FUN_1000_0f18(uint param_1,int param_2)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;

  FUN_1000_1222();
  uVar3 = FUN_1000_137e();
  iVar1 = (int)((ulong)uVar3 >> 0x10) + param_2 + (uint)CARRY2((uint)uVar3,param_1);
  do {
    uVar3 = FUN_1000_137e();
    iVar2 = (int)((ulong)uVar3 >> 0x10);
    if (iVar1 < iVar2) {
      return;
    }
  } while ((iVar2 < iVar1) || ((uint)uVar3 < 0xf56));
  return;
}



/* FUN_1000_0f80_1000_0f80.c */


void __cdecl16near FUN_1000_0f80(void)

{
  return;
}



/* FUN_1000_0f81_1000_0f81.c */


void __cdecl16far FUN_1000_0f81(void)

{
  FUN_1000_0f80();
  return;
}



/* FUN_1000_0f90_1000_0f90.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16far FUN_1000_0f90(void)

{
  (*_DAT_4000_d62a)();
  return;
}



/* FUN_1000_1062_1000_1062.c */


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



/* FUN_1000_1084_1000_1084.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_1084(void)

{
  byte *pbVar1;
  byte *pbVar2;
  byte *pbVar3;
  code *pcVar4;
  int iVar5;
  uint extraout_DX;
  undefined2 in_BX;
  int iVar6;
  byte *pbVar7;
  byte *pbVar8;
  undefined2 unaff_ES;
  undefined2 unaff_SS;
  bool bVar9;

  pcVar4 = (code *)swi(0x21);
  (*pcVar4)();
  pcVar4 = (code *)swi(0x21);
  _DAT_4000_d26c = in_BX;
  _DAT_4000_d26e = unaff_ES;
  (*pcVar4)();
  if (*(int *)&DAT_4000_d63a != 0) {
    *(undefined2 *)&DAT_4000_d63c = 0x1000;
    *(undefined2 *)0x654 = 0x1000;
    bVar9 = false;
    (*(code *)*(undefined2 *)&DAT_4000_d63a)();
    if (bVar9) {
      FUN_1000_14f4();
      return;
    }
    (*(code *)*(undefined2 *)&DAT_4000_d63a)();
  }
  iVar6 = *(int *)0x2c;
  if (iVar6 != 0) {
    pbVar8 = (byte *)0x0;
    do {
      if (*pbVar8 == 0) break;
      iVar5 = 0xd;
      pbVar7 = (byte *)&DAT_4000_d25e;
      bVar9 = false;
      do {
        if (iVar5 == 0) break;
        iVar5 = iVar5 + -1;
        pbVar3 = pbVar8;
        pbVar8 = pbVar8 + 1;
        pbVar1 = pbVar7;
        pbVar7 = pbVar7 + 1;
        bVar9 = *pbVar1 == *pbVar3;
      } while (bVar9);
      if (bVar9) {
        pbVar7 = (byte *)0x299;
        goto LAB_1000_110f;
      }
      iVar5 = 0x7fff;
      bVar9 = true;
      do {
        if (iVar5 == 0) break;
        iVar5 = iVar5 + -1;
        pbVar1 = pbVar8;
        pbVar8 = pbVar8 + 1;
        bVar9 = *pbVar1 == 0;
      } while (!bVar9);
    } while (bVar9);
  }
LAB_1000_1123:
  iVar6 = 4;
  do {
    bVar9 = false;
    *(byte *)(iVar6 + 0x299) = *(byte *)(iVar6 + 0x299) & 0xbf;
    pcVar4 = (code *)swi(0x21);
    (*pcVar4)();
    if ((!bVar9) && ((extraout_DX & 0x80) != 0)) {
      *(byte *)(iVar6 + 0x299) = *(byte *)(iVar6 + 0x299) | 0x40;
    }
    iVar6 = iVar6 + -1;
  } while (-1 < iVar6);
  FUN_1000_120f();
  FUN_1000_1200();
  return;
LAB_1000_110f:
  pbVar1 = pbVar8;
  pbVar2 = pbVar8 + 1;
  if (*pbVar1 < 0x41) goto LAB_1000_1123;
  pbVar8 = pbVar8 + 2;
  if (*pbVar2 < 0x41) goto LAB_1000_1123;
  pbVar3 = pbVar7;
  pbVar7 = pbVar7 + 1;
  *pbVar3 = *pbVar2 + 0xbf | (*pbVar1 + 0xbf) * '\x10';
  goto LAB_1000_110f;
}



/* FUN_1000_1152_1000_1152.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_1152(void)

{
  code *pcVar1;

  FUN_1000_1200();
  FUN_1000_1200();
  if (_DAT_4000_d628 == -0x292a) {
    (*_DAT_4000_d62e)();
  }
  FUN_1000_1200();
  FUN_1000_120f();
  FUN_1000_14fa();
  FUN_1000_11d3();
  pcVar1 = (code *)swi(0x21);
  (*pcVar1)();
  return;
}



/* FUN_1000_11d3_1000_11d3.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_11d3(undefined2 param_1)

{
  code *pcVar1;

  if (_DAT_4000_d63c != 0) {
    (*_DAT_4000_d63a)(0x1000);
  }
  pcVar1 = (code *)swi(0x21);
  (*pcVar1)();
  if (*(char *)0x2ba != '\0') {
    pcVar1 = (code *)swi(0x21);
    (*pcVar1)();
  }
  return;
}



/* FUN_1000_1200_1000_1200.c */


void __cdecl16near FUN_1000_1200(void)

{
  int *unaff_SI;
  int *unaff_DI;

  while (unaff_SI < unaff_DI) {
    unaff_DI = unaff_DI + -1;
    if ((code *)*unaff_DI != (code *)0x0) {
      (*(code *)*unaff_DI)();
    }
  }
  return;
}



/* FUN_1000_120f_1000_120f.c */


void __cdecl16near FUN_1000_120f(void)

{
  int *piVar1;
  int *unaff_SI;
  int *unaff_DI;
  int *piVar2;

  while (unaff_SI < unaff_DI) {
    piVar2 = unaff_DI + -2;
    piVar1 = unaff_DI + -1;
    unaff_DI = piVar2;
    if (*piVar2 != 0 || *piVar1 != 0) {
      (*(code *)*piVar2)(0x1000);
    }
  }
  return;
}



/* FUN_1000_1222_1000_1222.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_1000_1222(void)

{
  undefined1 *in_AX;
  code *in_stack_00000000;

  if ((in_AX <= &stack0x0002) && (_DAT_4000_d2b2 <= &stack0x0002 + -(int)in_AX)) {
                    /* WARNING: Could not recover jumptable at 0x00011231. Too many branches */
                    /* WARNING: Treating indirect jump as call */
    (*in_stack_00000000)();
    return;
  }
  FUN_1000_1062();
  return;
}



/* FUN_1000_123a_1000_123a.c */


void __cdecl16near FUN_1000_123a(char *param_1,char *param_2)

{
  char *pcVar1;
  char *pcVar2;
  uint uVar3;
  uint uVar4;
  char *pcVar5;

  uVar3 = 0xffff;
  pcVar5 = param_2;
  do {
    if (uVar3 == 0) break;
    uVar3 = uVar3 - 1;
    pcVar1 = pcVar5;
    pcVar5 = pcVar5 + 1;
  } while (*pcVar1 != '\0');
  uVar3 = ~uVar3;
  if (((uint)param_1 & 1) != 0) {
    pcVar2 = param_1;
    param_1 = param_1 + 1;
    pcVar1 = param_2;
    param_2 = param_2 + 1;
    *pcVar2 = *pcVar1;
    uVar3 = uVar3 - 1;
  }
  for (uVar4 = uVar3 >> 1; uVar4 != 0; uVar4 = uVar4 - 1) {
    pcVar2 = param_1;
    param_1 = param_1 + 2;
    pcVar1 = param_2;
    param_2 = param_2 + 2;
    *(undefined2 *)pcVar2 = *(undefined2 *)pcVar1;
  }
  for (uVar3 = (uint)((uVar3 & 1) != 0); uVar3 != 0; uVar3 = uVar3 - 1) {
    pcVar2 = param_1;
    param_1 = param_1 + 1;
    pcVar1 = param_2;
    param_2 = param_2 + 1;
    *pcVar2 = *pcVar1;
  }
  return;
}



/* FUN_1000_126c_1000_126c.c */


int __cdecl16near FUN_1000_126c(int param_1)

{
  return param_1 + -0x20;
}



/* FUN_1000_1278_1000_1278.c */


int __cdecl16near FUN_1000_1278(int param_1)

{
  if ((*(byte *)(param_1 + 0x33b) & 2) != 0) {
    param_1 = param_1 + -0x20;
  }
  return param_1;
}



/* FUN_1000_12ba_1000_12ba.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined2 __cdecl16near FUN_1000_12ba(undefined1 *param_1,undefined2 param_2)

{
  undefined1 *puVar1;
  undefined2 uVar2;

  DAT_4000_d8d2 = 0x42;
  _DAT_4000_d8d0 = param_1;
  _DAT_4000_d8cc = param_1;
  _DAT_4000_d8ce = 0x7fff;
  uVar2 = FUN_1000_1878(0x8dc,param_2,&stack0x0006);
  _DAT_4000_d8ce = _DAT_4000_d8ce + -1;
  if (_DAT_4000_d8ce < 0) {
    FUN_1000_1788(0,0x8dc);
  }
  else {
    puVar1 = _DAT_4000_d8cc;
    _DAT_4000_d8cc = _DAT_4000_d8cc + 1;
    *puVar1 = 0;
  }
  return uVar2;
}



/* FUN_1000_1310_1000_1310.c */


undefined1 __cdecl16near FUN_1000_1310(undefined2 param_1)

{
  undefined1 uVar1;

  uVar1 = in(param_1);
  return uVar1;
}



/* FUN_1000_132c_1000_132c.c */


void __cdecl16near FUN_1000_132c(void)

{
  code *pcVar1;
  undefined2 *puVar2;
  uint in_CX;
  uint uVar3;
  uint uVar4;
  uint extraout_DX;
  byte extraout_DH;
  uint extraout_DX_00;
  uint uVar5;
  uint uVar6;
  undefined4 uVar7;

  pcVar1 = (code *)swi(0x21);
  (*pcVar1)();
  pcVar1 = (code *)swi(0x21);
  uVar3 = in_CX;
  uVar6 = extraout_DX;
  (*pcVar1)();
  puVar2 = (undefined2 *)(uint)extraout_DH;
  pcVar1 = (code *)swi(0x21);
  uVar4 = uVar3;
  (*pcVar1)(uVar3 >> 8);
  uVar5 = extraout_DX_00;
  if ((uVar6 != extraout_DX_00) && (uVar5 = extraout_DX_00, (char)uVar3 == '\x17')) {
    uVar4 = in_CX;
    uVar5 = uVar6;
  }
  uVar7 = FUN_1000_1e42(uVar4 - 0x7bc,uVar5 >> 8);
  if (puVar2 != (undefined2 *)0x0) {
    puVar2[1] = (int)((ulong)uVar7 >> 0x10);
    *puVar2 = (int)uVar7;
  }
  return;
}



/* FUN_1000_137e_1000_137e.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_137e(void)

{
  uint local_c;
  int local_a;

  _DAT_4000_d42c = 0;
  FUN_1000_1d4e(&local_c);
  FUN_1000_1f38(local_c - _DAT_4000_d2b6,
                (local_a - _DAT_4000_d2b8) - (uint)(local_c < _DAT_4000_d2b6),1000,0);
  return;
}



/* FUN_1000_13d4_1000_13d4.c */


undefined2 * __cdecl16near FUN_1000_13d4(undefined2 *param_1,undefined1 param_2,uint param_3)

{
  undefined2 *puVar1;
  uint uVar2;
  undefined2 *puVar3;

  if (param_3 != 0) {
    puVar3 = param_1;
    if (((uint)param_1 & 1) != 0) {
      puVar3 = (undefined2 *)((int)param_1 + 1);
      *(undefined1 *)param_1 = param_2;
      param_3 = param_3 - 1;
    }
    for (uVar2 = param_3 >> 1; uVar2 != 0; uVar2 = uVar2 - 1) {
      puVar1 = puVar3;
      puVar3 = puVar3 + 1;
      *puVar1 = CONCAT11(param_2,param_2);
    }
    for (uVar2 = (uint)((param_3 & 1) != 0); uVar2 != 0; uVar2 = uVar2 - 1) {
      puVar1 = puVar3;
      puVar3 = (undefined2 *)((int)puVar3 + 1);
      *(undefined1 *)puVar1 = param_2;
    }
  }
  return param_1;
}



/* FUN_1000_1402_1000_1402.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_1402(undefined2 param_1)

{
  _DAT_4000_d2c0 = param_1;
  _DAT_4000_d2c2 = 0;
  return;
}



/* FUN_1000_1414_1000_1414.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

uint __cdecl16near FUN_1000_1414(void)

{
  long lVar1;

  lVar1 = FUN_1000_1f38(_DAT_4000_d2c0,_DAT_4000_d2c2,0x43fd,3);
  _DAT_4000_d2c0 = lVar1 + 0x269ec3;
  return (uint)((ulong)(lVar1 + 0x269ec3) >> 0x10) & 0x7fff;
}



/* FUN_1000_143a_1000_143a.c */


undefined4 FUN_1000_143a(uint param_1,uint param_2,uint param_3,uint param_4)

{
  ulong uVar1;
  long lVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  bool bVar11;
  char cVar12;
  uint uVar10;

  cVar12 = (int)param_2 < 0;
  if ((bool)cVar12) {
    bVar11 = param_1 != 0;
    param_1 = -param_1;
    param_2 = -(uint)bVar11 - param_2;
  }
  if ((int)param_4 < 0) {
    cVar12 = cVar12 + '\x01';
    bVar11 = param_3 != 0;
    param_3 = -param_3;
    param_4 = -(uint)bVar11 - param_4;
  }
  uVar4 = param_1;
  uVar7 = param_3;
  uVar3 = param_2;
  uVar10 = param_4;
  if (param_4 == 0) {
    uVar4 = param_2 / param_3;
    iVar5 = (int)(((ulong)param_2 % (ulong)param_3 << 0x10 | (ulong)param_1) / (ulong)param_3);
  }
  else {
    do {
      uVar8 = uVar3;
      uVar6 = uVar4;
      uVar9 = uVar10 >> 1;
      uVar7 = uVar7 >> 1 | (uint)((uVar10 & 1) != 0) << 0xf;
      uVar4 = uVar6 >> 1 | (uint)((uVar8 & 1) != 0) << 0xf;
      uVar3 = uVar8 >> 1;
      uVar10 = uVar9;
    } while (uVar9 != 0);
    uVar1 = (CONCAT22(uVar8,uVar6) >> 1) / (ulong)uVar7;
    iVar5 = (int)uVar1;
    lVar2 = (ulong)param_3 * (uVar1 & 0xffff);
    uVar4 = (uint)((ulong)lVar2 >> 0x10);
    uVar7 = uVar4 + iVar5 * param_4;
    if (((CARRY2(uVar4,iVar5 * param_4)) || (param_2 < uVar7)) ||
       ((param_2 <= uVar7 && (param_1 < (uint)lVar2)))) {
      iVar5 = iVar5 + -1;
    }
    uVar4 = 0;
  }
  if (cVar12 == '\x01') {
    bVar11 = iVar5 != 0;
    iVar5 = -iVar5;
    uVar4 = -(uint)bVar11 - uVar4;
  }
  return CONCAT22(uVar4,iVar5);
}



/* FUN_1000_14d4_1000_14d4.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_14d4(void)

{
  FUN_1000_1753(0xfc);
  if (_DAT_4000_d2c4 != (code *)0x0) {
    (*_DAT_4000_d2c4)();
  }
  FUN_1000_1753(0xff);
  return;
}



/* FUN_1000_14f4_1000_14f4.c */


void FUN_1000_14f4(void)

{
  FUN_1000_1062();
  return;
}



/* FUN_1000_14fa_1000_14fa.c */


uint __cdecl16near FUN_1000_14fa(void)

{
  byte *pbVar1;
  byte bVar3;
  uint uVar2;
  int iVar4;
  byte *pbVar5;

  pbVar5 = (byte *)0x0;
  iVar4 = 0x42;
  bVar3 = 0;
  do {
    pbVar1 = pbVar5;
    pbVar5 = pbVar5 + 1;
    bVar3 = bVar3 ^ *pbVar1;
    iVar4 = iVar4 + -1;
  } while (iVar4 != 0);
  uVar2 = CONCAT11(bVar3,*pbVar1) ^ 0x5500;
  if (bVar3 != 0x55) {
    FUN_1000_14d4();
    FUN_1000_1753(1);
    uVar2 = 1;
  }
  return uVar2;
}



/* FUN_1000_151c_1000_151c.c */


/* WARNING (jumptable): Unable to track spacebase fully for stack */
/* WARNING: Unable to track spacebase fully for stack */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_1000_151c(undefined2 param_1,undefined2 param_2)

{
  char *pcVar1;
  char cVar2;
  char *pcVar3;
  undefined2 uVar4;
  code *pcVar5;
  int iVar6;
  uint uVar7;
  uint uVar8;
  undefined2 *puVar9;
  char *pcVar10;
  char *pcVar11;
  int iVar12;
  char *pcVar13;
  undefined2 uVar14;
  undefined2 unaff_SS;
  undefined2 in_stack_00000000;

  pcVar5 = (code *)swi(0x21);
  _DAT_4000_d2c6 = in_stack_00000000;
  _DAT_4000_d282 = (*pcVar5)();
  uVar8 = 1;
  if ((char)_DAT_4000_d282 != '\x02') {
    _DAT_4000_d2a5 = *(undefined2 *)0x2c;
    iVar6 = -0x8000;
    pcVar11 = (char *)0x0;
LAB_1000_1543:
    do {
      _DAT_4000_d2a3 = pcVar11;
      if (iVar6 != 0) {
        iVar6 = iVar6 + -1;
        pcVar3 = pcVar11;
        pcVar11 = pcVar11 + 1;
        _DAT_4000_d2a3 = pcVar11;
        if (*pcVar3 != '\0') goto LAB_1000_1543;
      }
      pcVar11 = _DAT_4000_d2a3 + 1;
    } while (*_DAT_4000_d2a3 != '\0');
    _DAT_4000_d2a3 = _DAT_4000_d2a3 + 3;
    uVar8 = 0xffff;
    pcVar11 = _DAT_4000_d2a3;
    do {
      if (uVar8 == 0) break;
      uVar8 = uVar8 - 1;
      pcVar3 = pcVar11;
      pcVar11 = pcVar11 + 1;
    } while (*pcVar3 != '\0');
    uVar8 = ~uVar8;
  }
  iVar6 = 1;
  pcVar11 = (char *)0x81;
LAB_1000_1561:
  do {
    do {
      pcVar3 = pcVar11;
      pcVar11 = pcVar11 + 1;
      cVar2 = *pcVar3;
    } while (cVar2 == ' ');
  } while (cVar2 == '\t');
  if ((cVar2 != '\r') && (cVar2 != '\0')) {
    iVar6 = iVar6 + 1;
    do {
      pcVar11 = pcVar11 + -1;
LAB_1000_1574:
      pcVar3 = pcVar11;
      pcVar11 = pcVar11 + 1;
      cVar2 = *pcVar3;
      if ((cVar2 == ' ') || (cVar2 == '\t')) goto LAB_1000_1561;
      if ((cVar2 == '\r') || (cVar2 == '\0')) break;
      if (cVar2 == '\"') {
LAB_1000_15ad:
        do {
          while( true ) {
            while( true ) {
              pcVar3 = pcVar11;
              pcVar11 = pcVar11 + 1;
              cVar2 = *pcVar3;
              if ((cVar2 == '\r') || (cVar2 == '\0')) goto LAB_1000_15dd;
              if (cVar2 == '\"') goto LAB_1000_1574;
              if (cVar2 == '\\') break;
              uVar8 = uVar8 + 1;
            }
            uVar7 = 0;
            do {
              pcVar13 = pcVar11;
              uVar7 = uVar7 + 1;
              pcVar11 = pcVar13 + 1;
            } while (*pcVar13 == '\\');
            if (*pcVar13 == '\"') break;
            uVar8 = uVar8 + uVar7;
            pcVar11 = pcVar13;
          }
          uVar8 = uVar8 + (uVar7 >> 1) + (uint)((uVar7 & 1) != 0);
        } while ((uVar7 & 1) != 0);
        goto LAB_1000_1574;
      }
      if (cVar2 != '\\') {
        uVar8 = uVar8 + 1;
        goto LAB_1000_1574;
      }
      uVar7 = 0;
      do {
        uVar7 = uVar7 + 1;
        pcVar3 = pcVar11;
        pcVar11 = pcVar11 + 1;
      } while (*pcVar3 == '\\');
      if (*pcVar3 == '\"') {
        uVar8 = uVar8 + (uVar7 >> 1) + (uint)((uVar7 & 1) != 0);
        if ((uVar7 & 1) == 0) goto LAB_1000_15ad;
        goto LAB_1000_1574;
      }
      uVar8 = uVar8 + uVar7;
    } while( true );
  }
LAB_1000_15dd:
  *(int *)0x2ad = iVar6;
  iVar12 = (iVar6 + 1) * 2;
  iVar6 = -(uVar8 + iVar6 + iVar12 + 1 & 0xfffe);
  *(undefined1 **)0x2af = &stack0x0006 + iVar6;
  pcVar13 = &stack0x0006 + iVar12 + iVar6;
  *(undefined2 *)((int)&stack0x0004 + iVar6) = unaff_SS;
  uVar14 = *(undefined2 *)((int)&stack0x0004 + iVar6);
  *(char **)(&stack0x0006 + iVar6) = pcVar13;
  puVar9 = (undefined2 *)(&stack0x0008 + iVar6);
  pcVar3 = (char *)*(undefined4 *)&DAT_4000_d2a3;
  pcVar11 = (char *)pcVar3;
  do {
    pcVar1 = pcVar11;
    pcVar11 = pcVar11 + 1;
    cVar2 = *pcVar1;
    pcVar1 = pcVar13;
    pcVar13 = pcVar13 + 1;
    *pcVar1 = cVar2;
  } while (cVar2 != '\0');
  uVar4 = *(undefined2 *)&DAT_4000_d280;
  pcVar11 = (char *)0x81;
LAB_1000_1617:
  do {
    do {
      pcVar3 = pcVar11;
      pcVar11 = pcVar11 + 1;
      cVar2 = *pcVar3;
    } while (cVar2 == ' ');
  } while (cVar2 == '\t');
  if ((cVar2 == '\r') || (cVar2 == '\0')) {
LAB_1000_16a0:
    *(undefined2 *)((int)&stack0x0004 + iVar6) = unaff_SS;
    uVar14 = *(undefined2 *)((int)&stack0x0004 + iVar6);
    *puVar9 = 0;
                    /* WARNING: Could not recover jumptable at 0x000116a6. Too many branches */
                    /* WARNING: Treating indirect jump as call */
    (*(code *)*(undefined2 *)&DAT_4000_d2c6)();
    return;
  }
  *puVar9 = pcVar13;
  puVar9 = puVar9 + 1;
  do {
    pcVar11 = pcVar11 + -1;
LAB_1000_162e:
    pcVar3 = pcVar11;
    pcVar11 = pcVar11 + 1;
    cVar2 = *pcVar3;
    if ((cVar2 == ' ') || (cVar2 == '\t')) {
      pcVar3 = pcVar13;
      pcVar13 = pcVar13 + 1;
      *pcVar3 = '\0';
      goto LAB_1000_1617;
    }
    if ((cVar2 == '\r') || (cVar2 == '\0')) {
LAB_1000_169d:
      *pcVar13 = '\0';
      goto LAB_1000_16a0;
    }
    pcVar10 = pcVar11;
    if (cVar2 == '\"') {
LAB_1000_166a:
      while( true ) {
        pcVar11 = pcVar10 + 1;
        cVar2 = *pcVar10;
        if ((cVar2 == '\r') || (cVar2 == '\0')) goto LAB_1000_169d;
        if (cVar2 == '\"') break;
        if (cVar2 == '\\') {
          uVar8 = 0;
          do {
            pcVar10 = pcVar11;
            uVar8 = uVar8 + 1;
            pcVar11 = pcVar10 + 1;
          } while (*pcVar10 == '\\');
          if (*pcVar10 == '\"') {
            for (uVar7 = uVar8 >> 1; uVar7 != 0; uVar7 = uVar7 - 1) {
              pcVar3 = pcVar13;
              pcVar13 = pcVar13 + 1;
              *pcVar3 = '\\';
            }
            if ((uVar8 & 1) == 0) break;
            pcVar3 = pcVar13;
            pcVar13 = pcVar13 + 1;
            *pcVar3 = '\"';
            pcVar10 = pcVar11;
          }
          else {
            for (; uVar8 != 0; uVar8 = uVar8 - 1) {
              pcVar3 = pcVar13;
              pcVar13 = pcVar13 + 1;
              *pcVar3 = '\\';
            }
          }
        }
        else {
          pcVar3 = pcVar13;
          pcVar13 = pcVar13 + 1;
          *pcVar3 = cVar2;
          pcVar10 = pcVar11;
        }
      }
      goto LAB_1000_162e;
    }
    if (cVar2 != '\\') {
      pcVar3 = pcVar13;
      pcVar13 = pcVar13 + 1;
      *pcVar3 = cVar2;
      goto LAB_1000_162e;
    }
    uVar8 = 0;
    do {
      uVar8 = uVar8 + 1;
      pcVar3 = pcVar11;
      pcVar11 = pcVar11 + 1;
    } while (*pcVar3 == '\\');
    if (*pcVar3 == '\"') {
      for (uVar7 = uVar8 >> 1; uVar7 != 0; uVar7 = uVar7 - 1) {
        pcVar3 = pcVar13;
        pcVar13 = pcVar13 + 1;
        *pcVar3 = '\\';
      }
      pcVar10 = pcVar11;
      if ((uVar8 & 1) == 0) goto LAB_1000_166a;
      pcVar3 = pcVar13;
      pcVar13 = pcVar13 + 1;
      *pcVar3 = '\"';
      goto LAB_1000_162e;
    }
    for (; uVar8 != 0; uVar8 = uVar8 - 1) {
      pcVar3 = pcVar13;
      pcVar13 = pcVar13 + 1;
      *pcVar3 = '\\';
    }
  } while( true );
}



/* FUN_1000_16aa_1000_16aa.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_16aa(void)

{
  int *piVar1;
  char *pcVar2;
  int *piVar3;
  char cVar4;
  int iVar5;
  undefined2 *puVar6;
  int iVar7;
  int iVar8;
  int *piVar9;
  int *piVar10;
  char *pcVar11;
  int *piVar12;
  undefined2 unaff_SS;
  bool bVar13;

  iVar5 = *(int *)0x2c;
  iVar8 = 0;
  pcVar11 = (char *)0x0;
  iVar7 = -1;
  if (iVar5 != 0) {
    cVar4 = *(char *)0x0;
    while (cVar4 != '\0') {
      do {
        if (iVar7 == 0) break;
        iVar7 = iVar7 + -1;
        pcVar2 = pcVar11;
        pcVar11 = pcVar11 + 1;
      } while (*pcVar2 != '\0');
      iVar8 = iVar8 + 1;
      pcVar2 = pcVar11;
      pcVar11 = pcVar11 + 1;
      cVar4 = *pcVar2;
    }
  }
  pcVar11 = (char *)FUN_1000_1f6a(0x4cff);
  puVar6 = (undefined2 *)FUN_1000_1f6a();
  piVar9 = (int *)0x0;
  _DAT_4000_d2a1 = puVar6;
  do {
    if (iVar8 == 0) {
      *puVar6 = 0;
      return;
    }
    bVar13 = *piVar9 == *(int *)&DAT_4000_d25e;
    if (bVar13) {
      piVar12 = (int *)&DAT_4000_d25e;
      iVar7 = 6;
      piVar10 = piVar9;
      do {
        if (iVar7 == 0) break;
        iVar7 = iVar7 + -1;
        piVar3 = piVar12;
        piVar12 = piVar12 + 1;
        piVar1 = piVar10;
        piVar10 = piVar10 + 1;
        bVar13 = *piVar1 == *piVar3;
      } while (bVar13);
      if (!bVar13) goto LAB_1000_1714;
    }
    else {
LAB_1000_1714:
      *puVar6 = pcVar11;
      puVar6 = puVar6 + 1;
    }
    do {
      piVar1 = piVar9;
      piVar9 = (int *)((int)piVar9 + 1);
      iVar7 = *piVar1;
      pcVar2 = pcVar11;
      pcVar11 = pcVar11 + 1;
      *pcVar2 = (char)iVar7;
    } while ((char)iVar7 != '\0');
    iVar8 = iVar8 + -1;
  } while( true );
}



/* FUN_1000_1728_1000_1728.c */


int * FUN_1000_1728(int param_1)

{
  int *piVar1;
  int iVar2;
  int *piVar3;
  int *piVar4;

  piVar3 = (int *)&DAT_4000_d65a;
  do {
    piVar1 = piVar3;
    piVar3 = piVar3 + 1;
    piVar4 = piVar3;
    if ((*piVar1 == param_1) || (piVar4 = (int *)0x0, *piVar1 == -1)) {
      return piVar4;
    }
    iVar2 = -1;
    do {
      if (iVar2 == 0) break;
      iVar2 = iVar2 + -1;
      piVar1 = piVar3;
      piVar3 = (int *)((int)piVar3 + 1);
    } while ((char)*piVar1 != '\0');
  } while( true );
}



/* FUN_1000_1753_1000_1753.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_1000_1753(undefined2 param_1)

{
  char *pcVar1;
  code *pcVar2;
  char *pcVar3;
  int iVar4;
  undefined2 unaff_ES;

  pcVar3 = (char *)FUN_1000_1728(param_1);
  if (pcVar3 != (char *)0x0) {
    iVar4 = -1;
    do {
      if (iVar4 == 0) break;
      iVar4 = iVar4 + -1;
      pcVar1 = pcVar3;
      pcVar3 = pcVar3 + 1;
    } while (*pcVar1 != '\0');
    if (_DAT_4000_d628 == -0x292a) {
      (*_DAT_4000_d62a)();
    }
    pcVar2 = (code *)swi(0x21);
    (*pcVar2)();
  }
  return;
}



/* FUN_1000_1788_1000_1788.c */


uint __cdecl16near FUN_1000_1788(uint param_1,int *param_2)

{
  int *piVar1;
  byte bVar2;
  int iVar3;
  uint uVar4;
  int unaff_DI;

  piVar1 = param_2;
  bVar2 = *(byte *)(param_2 + 3);
  if (((bVar2 & 0x82) != 0) && ((bVar2 & 0x40) == 0)) {
    param_2[1] = 0;
    if ((bVar2 & 1) != 0) {
      if ((bVar2 & 0x10) == 0) goto LAB_1000_17ff;
      *param_2 = param_2[2];
      bVar2 = bVar2 & 0xfe;
    }
    *(byte *)(param_2 + 3) = bVar2 & 0xef | 2;
    uVar4 = (uint)*(byte *)((int)param_2 + 7);
    if (((bVar2 & 8) == 0) &&
       (((bVar2 & 4) != 0 ||
        (((*(byte *)(param_2 + 0x50) & 1) == 0 &&
         (((((param_2 == (int *)0x446 || (param_2 == (int *)0x44e)) || (param_2 == (int *)0x45e)) &&
           ((*(byte *)(uVar4 + 0x299) & 0x40) != 0)) ||
          (FUN_1000_1f8e(param_2), (*(byte *)(piVar1 + 3) & 8) == 0)))))))) {
      iVar3 = FUN_1000_204a(uVar4,&param_1,1);
      unaff_DI = 1;
    }
    else {
      iVar3 = *piVar1 - piVar1[2];
      *piVar1 = piVar1[2] + 1;
      piVar1[1] = piVar1[0x51] + -1;
      if (iVar3 == 0) {
        iVar3 = 0;
        unaff_DI = 0;
        if ((*(byte *)(uVar4 + 0x299) & 0x20) != 0) {
          FUN_1000_1fd0(uVar4,0,0,2);
          iVar3 = 0;
          unaff_DI = 0;
        }
      }
      else {
        iVar3 = FUN_1000_204a(uVar4,piVar1[2],iVar3,iVar3);
      }
      *(undefined1 *)piVar1[2] = (char)param_1;
    }
    if (iVar3 == unaff_DI) {
      return param_1 & 0xff;
    }
  }
LAB_1000_17ff:
  *(byte *)(piVar1 + 3) = *(byte *)(piVar1 + 3) | 0x20;
  return 0xffff;
}



/* FUN_1000_1878_1000_1878.c */


undefined2 __cdecl16near FUN_1000_1878(undefined2 param_1,char *param_2)

{
  byte bVar1;
  undefined2 uVar2;

  FUN_1000_1222();
  if (*param_2 == '\0') {
    return 0;
  }
  bVar1 = *param_2 - 0x20;
  if (bVar1 < 0x59) {
    bVar1 = *(byte *)(ulong)(bVar1 + 0x2d8) & 0xf;
  }
  else {
    bVar1 = 0;
  }
                    /* WARNING: Could not emulate address calculation at 0x000118bc */
                    /* WARNING: Treating indirect jump as call */
  uVar2 = (*(code *)*(undefined2 *)
                     ((char)(*(byte *)(ulong)((byte)(bVar1 * '\b') + 0x2d8) >> 4) * 2 + 0x1868))();
  return uVar2;
}



/* FUN_1000_1d4e_1000_1d4e.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_1d4e(undefined2 *param_1)

{
  undefined2 uVar1;
  int iVar2;
  uint uVar3;
  undefined4 uVar4;
  undefined1 local_1e [4];
  uint local_1a;
  uint local_18;
  int local_16;
  int local_14;
  int local_10;
  byte local_c;
  char local_b;
  undefined1 local_a;
  byte local_9;
  byte local_8;
  byte local_7;
  int local_6;

  FUN_1000_2188();
  uVar1 = FUN_1000_143a(_DAT_4000_d5c2,_DAT_4000_d5c4,0x3c,0);
  param_1[3] = uVar1;
  FUN_1000_22fe(&local_8);
  FUN_1000_2318(&local_c);
  if ((local_c == 0) && (local_b == '\0')) {
    FUN_1000_22fe(&local_8);
  }
  local_14 = local_6 + -0x76c;
  local_18 = (uint)local_8;
  uVar3 = (uint)local_7;
  local_16 = uVar3 - 1;
  local_10 = local_18 + *(int *)(local_16 * 2 + 0x5ac);
  if (((local_6 - 0x7bcU & 3) == 0) && (2 < uVar3)) {
    local_10 = local_10 + 1;
  }
  local_1a = (uint)local_c;
  param_1[2] = (uint)local_9 * 10;
  uVar4 = FUN_1000_1e42(local_6 - 0x7bcU,uVar3,local_18,local_c,local_b,local_a);
  *param_1 = (int)uVar4;
  param_1[1] = (int)((ulong)uVar4 >> 0x10);
  if ((_DAT_4000_d5c6 != 0) && (iVar2 = FUN_1000_2234(local_1e), iVar2 != 0)) {
    param_1[4] = 1;
    return;
  }
  param_1[4] = 0;
  return;
}



/* FUN_1000_1e42_1000_1e42.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

long __cdecl16near
FUN_1000_1e42(int param_1,int param_2,int param_3,uint param_4,uint param_5,int param_6)

{
  int iVar1;
  uint uVar2;
  long lVar3;
  undefined4 uVar4;
  long lVar5;
  undefined2 uVar6;
  undefined2 uVar7;
  undefined2 uVar8;
  undefined2 uVar9;
  undefined1 local_14 [4];
  uint local_10;
  int local_c;
  int local_a;
  int local_6;

  iVar1 = (param_1 + 3) / 4;
  lVar3 = FUN_1000_1f38(iVar1,iVar1 >> 0xf,0x5180,1);
  iVar1 = *(int *)(param_2 * 2 + 0x5aa);
  if ((param_1 % 4 == 0) && (2 < param_2)) {
    iVar1 = iVar1 + 1;
  }
  local_6 = param_3 + iVar1;
  FUN_1000_2188();
  uVar9 = 0;
  uVar8 = 0x3c;
  uVar7 = 0;
  uVar6 = 0x3c;
  uVar2 = param_1 * 0x16d + param_3 + iVar1;
  uVar4 = FUN_1000_1f38(uVar2 + 0xe44,((int)uVar2 >> 0xf) + (uint)(0xf1bb < uVar2),0x18,0);
  uVar4 = FUN_1000_1f38(param_4 + (uint)uVar4,
                        ((int)param_4 >> 0xf) + (int)((ulong)uVar4 >> 0x10) +
                        (uint)CARRY2(param_4,(uint)uVar4),uVar6,uVar7);
  lVar5 = FUN_1000_1f38(param_5 + (uint)uVar4,
                        ((int)param_5 >> 0xf) + (int)((ulong)uVar4 >> 0x10) +
                        (uint)CARRY2(param_5,(uint)uVar4),uVar8,uVar9);
  lVar3 = lVar3 + param_6 + lVar5 + CONCAT22(_DAT_4000_d5c4,_DAT_4000_d5c2);
  local_a = param_1 + 0x50;
  local_c = param_2 + -1;
  local_10 = param_4;
  if (_DAT_4000_d5c6 != 0) {
    iVar1 = FUN_1000_2234(local_14);
    if (iVar1 != 0) {
      lVar3 = CONCAT22((int)((ulong)lVar3 >> 0x10) - (uint)((uint)lVar3 < 0xe10),(uint)lVar3 - 0xe10
                      );
    }
  }
  return lVar3;
}



/* FUN_1000_1f38_1000_1f38.c */


long FUN_1000_1f38(uint param_1,int param_2,uint param_3,int param_4)

{
  if (param_4 == 0 && param_2 == 0) {
    return (ulong)param_1 * (ulong)param_3;
  }
  return CONCAT22((int)((ulong)param_1 * (ulong)param_3 >> 0x10) +
                  param_2 * param_3 + param_1 * param_4,(int)((ulong)param_1 * (ulong)param_3));
}



/* FUN_1000_1f6a_1000_1f6a.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_1f6a(void)

{
  undefined2 uVar1;
  int iVar2;

  uVar1 = _DAT_4000_d61e;
  LOCK();
  _DAT_4000_d61e = 0x400;
  UNLOCK();
  iVar2 = thunk_FUN_1000_2607();
  _DAT_4000_d61e = uVar1;
  if (iVar2 != 0) {
    return;
  }
  FUN_1000_1062();
  return;
}



/* FUN_1000_1f8e_1000_1f8e.c */


void __cdecl16near FUN_1000_1f8e(int *param_1)

{
  int iVar1;

  iVar1 = thunk_FUN_1000_2607(0x200);
  if (iVar1 == 0) {
    *(byte *)(param_1 + 3) = *(byte *)(param_1 + 3) | 4;
    param_1[0x51] = 1;
    iVar1 = (int)param_1 + 0xa1;
  }
  else {
    *(byte *)(param_1 + 3) = *(byte *)(param_1 + 3) | 8;
    param_1[0x51] = 0x200;
  }
  *param_1 = iVar1;
  param_1[2] = iVar1;
  param_1[1] = 0;
  return;
}



/* FUN_1000_1fd0_1000_1fd0.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_1000_1fd0(uint param_1,uint param_2,uint param_3,uint param_4)

{
  uint uVar1;
  code *pcVar2;
  uint uVar3;
  uint uVar4;
  bool bVar5;
  undefined4 uVar6;

  if (_DAT_4000_d287 <= param_1) goto LAB_1000_2047;
  bVar5 = false;
  if ((param_3 & 0x8000) != 0) {
    if (param_4 == 0) goto LAB_1000_2047;
    bVar5 = false;
    pcVar2 = (code *)swi(0x21);
    uVar6 = (*pcVar2)();
    uVar3 = (uint)((ulong)uVar6 >> 0x10);
    if (bVar5) goto LAB_1000_2047;
    if ((param_4 & 2) == 0) {
      uVar1 = (uint)CARRY2((uint)uVar6,param_2);
      bVar5 = CARRY2(uVar3,param_3) || CARRY2(uVar3 + param_3,uVar1);
      if ((int)(uVar3 + param_3 + uVar1) < 0) goto LAB_1000_2047;
    }
    else {
      pcVar2 = (code *)swi(0x21);
      uVar6 = (*pcVar2)(uVar3);
      uVar4 = (uint)((ulong)uVar6 >> 0x10);
      uVar3 = (uint)CARRY2((uint)uVar6,param_2);
      uVar1 = uVar4 + param_3;
      bVar5 = CARRY2(uVar4,param_3) || CARRY2(uVar1,uVar3);
      if ((int)(uVar1 + uVar3) < 0) {
        pcVar2 = (code *)swi(0x21);
        (*pcVar2)();
        goto LAB_1000_2047;
      }
    }
  }
  pcVar2 = (code *)swi(0x21);
  (*pcVar2)();
  if (!bVar5) {
    *(byte *)(param_1 + 0x299) = *(byte *)(param_1 + 0x299) & 0xfd;
  }
LAB_1000_2047:
  FUN_1000_2347();
  return;
}



/* FUN_1000_204a_1000_204a.c */


/* WARNING: Unable to track spacebase fully for stack */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined2 FUN_1000_204a(uint param_1,char *param_2,int param_3)

{
  char *pcVar1;
  code *pcVar2;
  char cVar3;
  undefined2 uVar4;
  uint uVar5;
  int iVar6;
  char *pcVar7;
  char *pcVar8;
  undefined2 unaff_SS;
  bool bVar9;
  undefined4 uVar10;

  if (_DAT_4000_d287 <= param_1) {
LAB_1000_205d:
    uVar4 = FUN_1000_2347();
    return uVar4;
  }
  if (_DAT_4000_d628 == -0x292a) {
    (*_DAT_4000_d62a)();
  }
  if ((*(byte *)(param_1 + 0x299) & 0x20) != 0) {
    bVar9 = false;
    pcVar2 = (code *)swi(0x21);
    (*pcVar2)();
    if (bVar9) goto LAB_1000_205d;
  }
  if ((*(byte *)(param_1 + 0x299) & 0x80) != 0) {
    bVar9 = true;
    iVar6 = param_3;
    pcVar8 = param_2;
    if (param_3 != 0) {
      do {
        if (iVar6 == 0) break;
        iVar6 = iVar6 + -1;
        pcVar1 = pcVar8;
        pcVar8 = pcVar8 + 1;
        bVar9 = *pcVar1 == '\n';
      } while (!bVar9);
      if (!bVar9) goto LAB_1000_20f3;
      uVar5 = FUN_1000_2388();
      if (uVar5 < 0xa9) {
        uVar10 = FUN_1000_1222();
        pcVar7 = (char *)((ulong)uVar10 >> 0x10);
        bVar9 = pcVar8 < pcVar7;
        if (pcVar8 != pcVar7) {
          pcVar2 = (code *)swi(0x21);
          uVar5 = (*pcVar2)(iVar6);
          if ((bVar9) || (uVar5 < (uint)((int)pcVar8 - (int)pcVar7))) {
            uVar4 = FUN_1000_2347();
            return uVar4;
          }
        }
        return (int)uVar10;
      }
      pcVar7 = &stack0xfff2;
      pcVar8 = &stack0xfff2;
      do {
        pcVar1 = param_2;
        param_2 = param_2 + 1;
        cVar3 = *pcVar1;
        if (cVar3 == '\n') {
          cVar3 = '\r';
          if (pcVar8 == pcVar7) {
            cVar3 = FUN_1000_20fb();
          }
          pcVar1 = pcVar8;
          pcVar8 = pcVar8 + 1;
          *pcVar1 = cVar3;
          cVar3 = '\n';
        }
        if (pcVar8 == pcVar7) {
          cVar3 = FUN_1000_20fb();
        }
        pcVar1 = pcVar8;
        pcVar8 = pcVar8 + 1;
        *pcVar1 = cVar3;
        param_3 = param_3 + -1;
      } while (param_3 != 0);
      FUN_1000_20fb();
    }
    uVar4 = FUN_1000_2145();
    return uVar4;
  }
LAB_1000_20f3:
  uVar4 = FUN_1000_2153();
  return uVar4;
}



/* FUN_1000_20fb_1000_20fb.c */


/* WARNING: Unable to track spacebase fully for stack */

undefined2 __cdecl16near FUN_1000_20fb(void)

{
  code *pcVar1;
  undefined2 in_AX;
  uint uVar2;
  undefined2 uVar3;
  uint in_DX;
  int unaff_BP;
  uint unaff_DI;
  undefined2 unaff_SS;
  bool bVar4;

  bVar4 = unaff_DI < in_DX;
  if (unaff_DI != in_DX) {
    pcVar1 = (code *)swi(0x21);
    uVar2 = (*pcVar1)();
    if ((bVar4) ||
       (*(int *)(unaff_BP + -2) = *(int *)(unaff_BP + -2) + uVar2, uVar2 < unaff_DI - in_DX)) {
      uVar3 = FUN_1000_2347();
      return uVar3;
    }
  }
  return in_AX;
}



/* FUN_1000_2145_1000_2145.c */


/* WARNING: Stack frame is not setup normally: Input value of stackpointer is not used */

void FUN_1000_2145(void)

{
  FUN_1000_2347();
  return;
}



/* FUN_1000_2153_1000_2153.c */


void FUN_1000_2153(void)

{
  code *pcVar1;
  int unaff_BP;
  undefined2 unaff_SS;

  if (*(int *)(unaff_BP + 8) != 0) {
    pcVar1 = (code *)swi(0x21);
    (*pcVar1)();
    FUN_1000_2347();
    return;
  }
  FUN_1000_2347();
  return;
}



/* FUN_1000_2188_1000_2188.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_2188(void)

{
  if (_DAT_4000_d8d4 == 0) {
    FUN_1000_2198();
    _DAT_4000_d8d4 = _DAT_4000_d8d4 + 1;
  }
  return;
}



/* FUN_1000_2198_1000_2198.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_2198(void)

{
  char cVar1;
  char *pcVar2;
  int iVar3;
  undefined4 uVar4;
  undefined2 uVar5;
  undefined2 uVar6;

  pcVar2 = (char *)FUN_1000_24c8(0x5c6);
  uVar4 = CONCAT22(_DAT_4000_d5c4,_DAT_4000_d5c2);
  if ((pcVar2 != (char *)0x0) && (uVar4 = CONCAT22(_DAT_4000_d5c4,_DAT_4000_d5c2), *pcVar2 != '\0'))
  {
    FUN_1000_249c(_DAT_4000_d5c8,pcVar2,3);
    uVar6 = 0;
    uVar5 = 0xe10;
    pcVar2 = pcVar2 + 3;
    uVar4 = thunk_FUN_1000_2686(pcVar2,0xe10,0);
    _DAT_4000_d5c2 = FUN_1000_1f38(uVar4,uVar5,uVar6);
    iVar3 = 0;
    while (pcVar2[iVar3] != '\0') {
      cVar1 = pcVar2[iVar3];
      if ((((*(byte *)(cVar1 + 0x33b) & 4) == 0) && (cVar1 != '-')) ||
         (iVar3 = iVar3 + 1, 2 < iVar3)) break;
    }
    if (pcVar2[iVar3] == '\0') {
      *_DAT_4000_d5ca = '\0';
    }
    else {
      FUN_1000_249c(_DAT_4000_d5ca,pcVar2 + iVar3,3);
    }
    _DAT_4000_d5c6 = (uint)(*_DAT_4000_d5ca != '\0');
    uVar4 = _DAT_4000_d5c2;
  }
  _DAT_4000_d5c4 = (undefined2)((ulong)uVar4 >> 0x10);
  _DAT_4000_d5c2 = (undefined2)uVar4;
  return;
}



/* FUN_1000_2234_1000_2234.c */


undefined2 __cdecl16near FUN_1000_2234(int param_1)

{
  undefined2 uVar1;
  int iVar2;
  uint uVar3;
  int local_6;

  if ((*(int *)(param_1 + 8) < 3) || (9 < *(int *)(param_1 + 8))) goto LAB_1000_22f5;
  if ((*(int *)(param_1 + 8) < 4) || (8 < *(int *)(param_1 + 8))) {
    uVar3 = *(int *)(param_1 + 10) + 0x76c;
    if (((int)uVar3 < 0x7c3) || (*(int *)(param_1 + 8) != 3)) {
      local_6 = *(int *)(*(int *)(param_1 + 8) * 2 + 0x5ae);
    }
    else {
      local_6 = *(int *)(*(int *)(param_1 + 8) * 2 + 0x5ac) + 7;
    }
    if ((uVar3 & 3) == 0) {
      local_6 = local_6 + 1;
    }
    local_6 = ((*(int *)(param_1 + 10) + -0x45) / 4 + (*(int *)(param_1 + 10) + -0x46) * 0x16d +
               local_6 + 4) % 7 - local_6;
    iVar2 = -local_6;
    if (*(int *)(param_1 + 8) == 3) {
      if ((iVar2 < *(int *)(param_1 + 0xe)) ||
         ((-*(int *)(param_1 + 0xe) == local_6 && (1 < *(int *)(param_1 + 4))))) goto LAB_1000_22e1;
    }
    else if ((*(int *)(param_1 + 0xe) < iVar2) ||
            ((*(int *)(param_1 + 0xe) == iVar2 && (*(int *)(param_1 + 4) < 1)))) goto LAB_1000_22e1;
LAB_1000_22f5:
    uVar1 = 0;
  }
  else {
LAB_1000_22e1:
    uVar1 = 1;
  }
  return uVar1;
}



/* FUN_1000_22fe_1000_22fe.c */


undefined2 __cdecl16near FUN_1000_22fe(undefined1 *param_1)

{
  code *pcVar1;
  undefined1 uVar2;
  undefined2 in_CX;
  undefined1 extraout_DL;
  undefined1 extraout_DH;

  pcVar1 = (code *)swi(0x21);
  uVar2 = (*pcVar1)();
  *(undefined2 *)(param_1 + 2) = in_CX;
  param_1[1] = extraout_DH;
  *param_1 = extraout_DL;
  param_1[4] = uVar2;
  return 0;
}



/* FUN_1000_2318_1000_2318.c */


undefined2 __cdecl16near FUN_1000_2318(undefined1 *param_1)

{
  code *pcVar1;
  undefined1 in_CL;
  undefined1 in_CH;
  undefined1 extraout_DL;
  undefined1 extraout_DH;

  pcVar1 = (code *)swi(0x21);
  (*pcVar1)();
  *param_1 = in_CH;
  param_1[1] = in_CL;
  param_1[2] = extraout_DH;
  param_1[3] = extraout_DL;
  return 0;
}



/* FUN_1000_2347_1000_2347.c */


void __cdecl16near FUN_1000_2347(void)

{
  bool in_CF;

  if (in_CF) {
    FUN_1000_235a();
  }
  return;
}



/* FUN_1000_235a_1000_235a.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_235a(void)

{
  char cVar1;
  uint in_AX;

  DAT_4000_d285 = (byte)in_AX;
  cVar1 = (char)(in_AX >> 8);
  if (cVar1 != '\0') goto LAB_1000_237e;
  if (DAT_4000_d282 < 3) {
LAB_1000_2374:
    if (0x13 < DAT_4000_d285) {
LAB_1000_2378:
      in_AX = 0x13;
    }
  }
  else {
    if (0x21 < DAT_4000_d285) goto LAB_1000_2378;
    if (DAT_4000_d285 < 0x20) goto LAB_1000_2374;
    in_AX = 5;
  }
  cVar1 = *(char *)(ulong)((in_AX & 0xff) + 0x618);
LAB_1000_237e:
  _DAT_4000_d27a = (int)cVar1;
  return;
}



/* FUN_1000_2388_1000_2388.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_1000_2388(void)

{
  code *in_stack_00000000;

                    /* WARNING: Could not recover jumptable at 0x00012394. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (*in_stack_00000000)();
  return;
}



/* FUN_1000_239e_1000_239e.c */


void __cdecl16near FUN_1000_239e(void)

{
  int *piVar1;
  int iVar2;
  uint uVar3;
  int in_CX;
  uint uVar4;
  int iVar5;
  int in_BX;
  uint *unaff_SI;
  undefined2 *puVar6;
  undefined2 unaff_SS;
  bool bVar7;

  if ((*(byte *)(in_BX + 2) & 1) != 0) {
    FUN_1000_247b();
    if ((*unaff_SI & 1) != 0) {
      in_CX = (in_CX - *unaff_SI) + -1;
    }
    uVar3 = *(uint *)(in_BX + 4);
    if (uVar3 != 0) {
      if (!CARRY2(in_CX + 2U,uVar3)) {
        uVar3 = *(uint *)&DAT_4000_d61e;
        if (uVar3 == 0x2000) goto LAB_1000_23eb;
        uVar4 = 0x8000;
        while (uVar3 <= uVar4) {
          uVar4 = uVar4 >> 1;
          if (uVar4 == 0) goto LAB_1000_2404;
        }
        if (uVar4 < 8) goto LAB_1000_2404;
        uVar3 = uVar4 << 1;
        goto LAB_1000_23eb;
      }
      uVar4 = 0xfff0;
      if (in_CX + 2U + uVar3 == 0) {
        while( true ) {
          bVar7 = false;
          iVar2 = FUN_1000_242a();
          if (!bVar7) break;
          if (uVar4 == 0xfff0) {
            return;
          }
LAB_1000_2404:
          uVar3 = 0x10;
LAB_1000_23eb:
          uVar4 = ~(uVar3 - 1);
        }
        iVar5 = iVar2 - *(int *)(in_BX + 4);
        *(int *)(in_BX + 4) = iVar2;
        *(undefined2 *)(in_BX + 8) = unaff_SI;
        piVar1 = (int *)*(int *)(in_BX + 10);
        *piVar1 = iVar5 + -1;
        puVar6 = (undefined2 *)((int)piVar1 + iVar5);
        *puVar6 = 0xfffe;
        *(undefined2 *)(in_BX + 10) = puVar6;
      }
    }
  }
  return;
}



/* FUN_1000_242a_1000_242a.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_242a(int param_1)

{
  code *pcVar1;
  uint in_AX;
  uint uVar2;
  int extraout_DX;
  int in_BX;
  bool bVar3;

  if ((((*(byte *)(in_BX + 2) & 4) == 0) || (in_AX - 1 < *(int *)(in_BX + 4) - 1U)) ||
     (*(uint *)(in_BX + -2) < in_AX - 1)) {
    uVar2 = in_AX >> 4;
    if (uVar2 == 0) {
      uVar2 = 0x1000;
    }
    bVar3 = (*(byte *)(in_BX + 2) & 4) != 0 && uVar2 + 0x4cff < _DAT_4000_d280;
    pcVar1 = (code *)swi(0x21);
    (*pcVar1)();
    if ((!bVar3) && ((*(byte *)(param_1 + 2) & 4) != 0)) {
      *(int *)(param_1 + -2) = extraout_DX + -1;
    }
  }
  return;
}



/* FUN_1000_247b_1000_247b.c */


void __cdecl16near FUN_1000_247b(void)

{
  int in_BX;
  uint *puVar1;

  puVar1 = (uint *)*(undefined2 *)(in_BX + 8);
  if (puVar1 == (uint *)*(undefined2 *)(in_BX + 10)) {
    puVar1 = (uint *)*(undefined2 *)(in_BX + 6);
  }
  while( true ) {
    if (*puVar1 == 0xfffe) break;
    puVar1 = (uint *)((int)puVar1 + (*puVar1 & 0xfffe) + 2);
  }
  return;
}



/* FUN_1000_249c_1000_249c.c */


char * __cdecl16near FUN_1000_249c(char *param_1,char *param_2,int param_3)

{
  char *pcVar1;
  char *pcVar2;
  char *pcVar3;

  pcVar3 = param_1;
  if (param_3 != 0) {
    do {
      pcVar1 = param_2;
      param_2 = param_2 + 1;
      if (*pcVar1 == '\0') break;
      pcVar2 = pcVar3;
      pcVar3 = pcVar3 + 1;
      *pcVar2 = *pcVar1;
      param_3 = param_3 + -1;
    } while (param_3 != 0);
    for (; param_3 != 0; param_3 = param_3 + -1) {
      pcVar1 = pcVar3;
      pcVar3 = pcVar3 + 1;
      *pcVar1 = '\0';
    }
  }
  return param_1;
}



/* FUN_1000_24c8_1000_24c8.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int __cdecl16near FUN_1000_24c8(int param_1)

{
  int iVar1;
  int iVar2;
  int *piVar3;

  piVar3 = _DAT_4000_d2a1;
  if ((_DAT_4000_d2a1 != (int *)0x0) && (param_1 != 0)) {
    iVar1 = FUN_1000_2630(param_1);
    for (; *piVar3 != 0; piVar3 = piVar3 + 1) {
      iVar2 = FUN_1000_2630(*piVar3);
      if (((iVar1 < iVar2) && (*(char *)(*piVar3 + iVar1) == '=')) &&
         (iVar2 = FUN_1000_264c(*piVar3,param_1,iVar1), iVar2 == 0)) {
        return *piVar3 + iVar1 + 1;
      }
    }
  }
  return 0;
}



/* FUN_1000_2522_1000_2522.c */


undefined2 __cdecl16near FUN_1000_2522(int *param_1)

{
  int iVar1;
  int iVar2;
  undefined2 uVar3;

  uVar3 = 0;
  if (param_1 == (int *)0x0) {
    uVar3 = FUN_1000_259c(0);
  }
  else {
    if (((*(byte *)(param_1 + 3) & 3) == 2) &&
       (((*(byte *)(param_1 + 3) & 8) != 0 || ((*(byte *)(param_1 + 0x50) & 1) != 0)))) {
      iVar1 = *param_1 - param_1[2];
      if (0 < iVar1) {
        iVar2 = FUN_1000_204a(*(undefined1 *)((int)param_1 + 7),param_1[2],iVar1);
        if (iVar1 != iVar2) {
          *(byte *)(param_1 + 3) = *(byte *)(param_1 + 3) | 0x20;
          uVar3 = 0xffff;
        }
      }
    }
    *param_1 = param_1[2];
    param_1[1] = 0;
  }
  return uVar3;
}



/* FUN_1000_259c_1000_259c.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int FUN_1000_259c(int param_1)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  int local_4;

  iVar3 = 0;
  local_4 = 0;
  for (uVar2 = 0x43e; uVar2 <= _DAT_4000_d56e; uVar2 = uVar2 + 8) {
    if ((*(byte *)(uVar2 + 6) & 0x83) != 0) {
      iVar1 = FUN_1000_2522(uVar2);
      if (iVar1 == -1) {
        local_4 = -1;
      }
      else {
        iVar3 = iVar3 + 1;
      }
    }
  }
  if (param_1 == 1) {
    local_4 = iVar3;
  }
  return local_4;
}



/* FUN_1000_25e6_1000_25e6.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_25e6(uint param_1)

{
  byte *pbVar1;

  if (_DAT_4000_d24c < param_1) {
    pbVar1 = (byte *)(param_1 - 2);
    *pbVar1 = *pbVar1 | 1;
    if (pbVar1 < _DAT_4000_d24e) {
      _DAT_4000_d24e = pbVar1;
    }
  }
  return;
}



/* FUN_1000_2607_1000_2607.c */


void __cdecl16near FUN_1000_2607(uint param_1)

{
  bool bVar1;

  bVar1 = param_1 < 0xffe8;
  if (((param_1 < 0xffe9) && (FUN_1000_26da(), bVar1)) && (FUN_1000_239e(), !bVar1)) {
    FUN_1000_26da();
  }
  return;
}



/* FUN_1000_2630_1000_2630.c */


int __cdecl16near FUN_1000_2630(char *param_1)

{
  char *pcVar1;
  uint uVar2;

  uVar2 = 0xffff;
  do {
    if (uVar2 == 0) break;
    uVar2 = uVar2 - 1;
    pcVar1 = param_1;
    param_1 = param_1 + 1;
  } while (*pcVar1 != '\0');
  return ~uVar2 - 1;
}



/* FUN_1000_264c_1000_264c.c */


uint __cdecl16near FUN_1000_264c(char *param_1,char *param_2,int param_3)

{
  char *pcVar1;
  char *pcVar2;
  int iVar3;
  uint uVar4;
  char *pcVar5;

  uVar4 = 0;
  iVar3 = param_3;
  pcVar5 = param_1;
  if (param_3 != 0) {
    do {
      if (iVar3 == 0) break;
      iVar3 = iVar3 + -1;
      pcVar1 = pcVar5;
      pcVar5 = pcVar5 + 1;
    } while (*pcVar1 != '\0');
    param_3 = param_3 - iVar3;
    do {
      if (param_3 == 0) break;
      param_3 = param_3 + -1;
      pcVar2 = param_1;
      param_1 = param_1 + 1;
      pcVar1 = param_2;
      param_2 = param_2 + 1;
    } while (*pcVar1 == *pcVar2);
    uVar4 = 0;
    if ((byte)param_2[-1] <= (byte)param_1[-1]) {
      if (param_2[-1] == param_1[-1]) {
        return 0;
      }
      uVar4 = 0xfffe;
    }
    uVar4 = ~uVar4;
  }
  return uVar4;
}



/* FUN_1000_2686_1000_2686.c */


undefined4 __cdecl16near FUN_1000_2686(byte *param_1)

{
  byte *pbVar1;
  byte bVar2;
  uint uVar3;
  byte bVar4;
  uint uVar5;
  int iVar6;
  uint uVar7;
  int iVar8;
  uint uVar9;
  uint uVar10;
  bool bVar11;

  iVar6 = 0;
  iVar8 = 0;
  do {
    do {
      pbVar1 = param_1;
      param_1 = param_1 + 1;
      bVar2 = *pbVar1;
      uVar5 = (uint)bVar2;
    } while (bVar2 == 0x20);
  } while (bVar2 == 9);
  if ((bVar2 != 0x2d) && (bVar2 != 0x2b)) goto LAB_1000_26a6;
  while( true ) {
    pbVar1 = param_1;
    param_1 = param_1 + 1;
    uVar5 = CONCAT11((char)(uVar5 >> 8),*pbVar1);
LAB_1000_26a6:
    bVar4 = (byte)uVar5;
    if ((0x39 < bVar4) || (uVar5 = uVar5 + 0xd0, bVar4 < 0x30)) break;
    uVar9 = iVar8 * 2;
    uVar7 = iVar6 << 1 | (uint)(iVar8 < 0);
    iVar6 = iVar8 << 2;
    uVar10 = iVar8 * 8;
    uVar3 = iVar8 * 10;
    iVar8 = uVar3 + uVar5;
    iVar6 = ((uVar7 << 1 | (uint)((int)uVar9 < 0)) << 1 | (uint)(iVar6 < 0)) + uVar7 +
            (uint)CARRY2(uVar10,uVar9) + (uint)CARRY2(uVar3,uVar5);
  }
  if (bVar2 == 0x2d) {
    bVar11 = iVar8 != 0;
    iVar8 = -iVar8;
    iVar6 = -(iVar6 + (uint)bVar11);
  }
  return CONCAT22(iVar6,iVar8);
}



/* FUN_1000_26da_1000_26da.c */


uint * __cdecl16near FUN_1000_26da(void)

{
  uint *puVar1;
  uint uVar2;
  uint uVar3;
  int in_CX;
  uint uVar4;
  int in_BX;
  uint *puVar5;
  uint *puVar6;
  uint *puVar7;

  uVar4 = in_CX + 1U & 0xfffe;
  puVar7 = (uint *)*(undefined2 *)(in_BX + 8);
  puVar5 = (uint *)*(undefined2 *)(in_BX + 10);
  do {
    while( true ) {
      puVar1 = puVar7 + 1;
      uVar3 = *puVar7;
      puVar6 = puVar1;
      if ((uVar3 & 1) != 0) {
        while( true ) {
          uVar2 = uVar3 - 1;
          if (uVar4 <= uVar2) {
            *puVar7 = uVar4;
            puVar7 = puVar1;
            if (uVar2 != uVar4) {
              *(int *)((int)puVar1 + uVar4) = (uVar2 - uVar4) + -1;
              puVar7 = (uint *)((int)((int)puVar1 + uVar4) - uVar4);
            }
            *(int *)(in_BX + 8) = (int)puVar7 + uVar4;
            return puVar1;
          }
          if (CARRY2((uint)puVar1,uVar2)) goto LAB_1000_2733;
          puVar6 = (uint *)((int)puVar1 + uVar2) + 1;
          uVar3 = *(uint *)((int)puVar1 + uVar2);
          if ((uVar3 & 1) == 0) break;
          uVar3 = uVar3 + uVar2 + 2;
          *puVar7 = uVar3;
        }
      }
      if (puVar6 + -1 < puVar5) break;
      if (((uint)puVar5 & 1) != 0) goto LAB_1000_2733;
      puVar7 = (uint *)*(undefined2 *)(in_BX + 6);
      if ((uint *)*(undefined2 *)(in_BX + 8) == puVar7) goto LAB_1000_2733;
      puVar5 = (uint *)((int)*(undefined2 *)(in_BX + 8) + -1);
    }
    puVar7 = (uint *)((int)puVar6 + uVar3);
  } while (!CARRY2((uint)puVar6,uVar3));
LAB_1000_2733:
  puVar7 = (uint *)*(undefined2 *)(in_BX + 6);
  *(undefined2 *)(in_BX + 8) = puVar7;
  return puVar7;
}



/* FUN_1000_2756_1000_2756.c */


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



/* FUN_1000_27d8_1000_27d8.c */


void __cdecl16near FUN_1000_27d8(void)

{
  code *pcVar1;
  uint uVar2;
  int iVar3;
  uint in_CX;
  undefined2 in_DX;
  undefined2 extraout_DX;
  undefined2 in_BX;
  undefined2 unaff_SS;

  if ((in_CX != 0) && (*(char *)&DAT_4000_d7a7 == '\0')) {
    do {
      uVar2 = (int)(char)in_DX + in_CX;
      iVar3 = uVar2 - *(uint *)&DAT_4000_d7a5;
      if (uVar2 < *(uint *)&DAT_4000_d7a5 || iVar3 == 0) {
        FUN_1000_36da();
        return;
      }
      uVar2 = iVar3 - 1;
      if (uVar2 < in_CX) {
        FUN_1000_36da(uVar2,in_BX);
      }
      if (*(char *)&DAT_4000_d7a8 == '\0') {
        *(undefined1 *)&DAT_4000_d7a7 = 1;
        pcVar1 = (code *)swi(0x10);
        (*pcVar1)();
        return;
      }
      in_CX = uVar2;
      FUN_1000_2825();
      in_DX = extraout_DX;
    } while (in_CX != 0);
  }
  return;
}



/* FUN_1000_2825_1000_2825.c */


void FUN_1000_2825(void)

{
  code *pcVar1;
  char in_DH;
  undefined2 unaff_SS;

  if (*(byte *)&DAT_4000_d7a3 < (byte)(in_DH + 1U)) {
    FUN_1000_284c();
  }
  pcVar1 = (code *)swi(0x10);
  (*pcVar1)();
  *(undefined1 *)&DAT_4000_d7a7 = 0;
  return;
}



/* FUN_1000_2836_1000_2836.c */


void __cdecl16near FUN_1000_2836(void)

{
  code *pcVar1;
  undefined2 unaff_SS;

  pcVar1 = (code *)swi(0x10);
  (*pcVar1)();
  *(undefined1 *)&DAT_4000_d7a7 = 0;
  return;
}



/* FUN_1000_284c_1000_284c.c */


void __cdecl16near FUN_1000_284c(void)

{
  FUN_1000_3199();
  return;
}



/* FUN_1000_2880_1000_2880.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_2880(void)

{
  if (_DAT_4000_d79d < 0) {
    _DAT_4000_d79d = 0;
  }
  else if (_DAT_4000_d7a5 - _DAT_4000_d7a1 < _DAT_4000_d79d) {
    if (DAT_4000_d7a8 == '\0') {
      DAT_4000_d7a7 = 1;
      _DAT_4000_d79d = _DAT_4000_d7a5 - _DAT_4000_d7a1;
    }
    else {
      _DAT_4000_d79d = 0;
      _DAT_4000_d79b = _DAT_4000_d79b + 1;
    }
  }
  if (_DAT_4000_d79b < 0) {
    _DAT_4000_d79b = 0;
  }
  else if (_DAT_4000_d7a3 - _DAT_4000_d79f < _DAT_4000_d79b) {
    _DAT_4000_d79b = _DAT_4000_d7a3 - _DAT_4000_d79f;
    FUN_1000_284c();
  }
  FUN_1000_2efb();
  return;
}



/* FUN_1000_28e4_1000_28e4.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16far FUN_1000_28e4(void)

{
  FUN_1000_2e1a();
  FUN_1000_291a(_DAT_4000_d79d + 1,_DAT_4000_d79b + 1);
  FUN_1000_2e3b();
  return;
}



/* FUN_1000_291a_1000_291a.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_291a(void)

{
  _DAT_4000_d79b = FUN_1000_30df();
  _DAT_4000_d79d = FUN_1000_30df();
  DAT_4000_d7a7 = 0;
  FUN_1000_2880();
  return;
}



/* FUN_1000_2944_1000_2944.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16far FUN_1000_2944(uint param_1,char param_2)

{
  byte bVar1;
  uint uVar2;
  undefined1 uVar3;
  undefined1 in_ZF;
  undefined1 uVar4;
  undefined2 uVar5;

  DAT_4000_d1bc = param_2;
  FUN_1000_2e1a();
  DAT_4000_d17e = -1;
  if ((bool)in_ZF) {
    _DAT_4000_d7aa = CONCAT11((char)((uint)_DAT_4000_d1db >> 8),DAT_4000_d1d9);
  }
  if (param_1 == 0xffff) {
    if (DAT_4000_d1bc == '\0') {
      DAT_4000_d1bc = DAT_4000_d1d2;
    }
    uVar2 = (uint)DAT_4000_d1d0;
    DAT_4000_d23e = 1;
  }
  else {
    uVar2 = param_1;
    if (0x7fff < param_1) {
      if ((int)param_1 < -3) {
LAB_1000_298d:
        DAT_4000_d736 = 0xfc;
        goto LAB_1000_2a0f;
      }
      bVar1 = DAT_4000_d735;
      if (param_1 != 0xfffd) {
        bVar1 = DAT_4000_d734;
      }
      uVar2 = (uint)bVar1;
      if (bVar1 == 0) {
LAB_1000_2986:
        DAT_4000_d736 = 0xfe;
        goto LAB_1000_2a0f;
      }
    }
  }
  while( true ) {
    if (uVar2 < 0x14) {
      uVar3 = (int)uVar2 < 0;
      uVar4 = uVar2 * 2 == 0;
      (*(code *)*(undefined2 *)(uVar2 * 2 + 400))();
    }
    else {
      uVar3 = uVar2 < 0x40;
      uVar4 = uVar2 == 0x40;
      if (!(bool)uVar4) goto LAB_1000_298d;
      FUN_1000_362a();
    }
    if ((bool)uVar3) goto LAB_1000_2986;
    FUN_1000_2c31();
    FUN_1000_2c64();
    FUN_1000_33aa();
    (*_DAT_4000_d1f3)();
    FUN_1000_339a();
    if (!(bool)uVar3) break;
    DAT_4000_d736 = 0xff;
    DAT_4000_d17e = DAT_4000_d17e + '\x01';
    if (DAT_4000_d17e != '\0') goto LAB_1000_2a0f;
    LOCK();
    uVar2 = CONCAT11(DAT_4000_d1bc,(char)_DAT_4000_d7aa);
    UNLOCK();
    DAT_4000_d1bc = (char)((uint)_DAT_4000_d7aa >> 8);
  }
  FUN_1000_2c31();
  FUN_1000_2cc2();
  (*_DAT_4000_d1f7)();
  _DAT_4000_d79f = FUN_1000_2ef2();
  uVar5 = 0x29f1;
  _DAT_4000_d7a1 = _DAT_4000_d79f;
  (*_DAT_4000_d1f5)();
  FUN_1000_33fa(uVar5);
  if ((bool)uVar4) {
    if (param_1 == 0xffff) {
      _DAT_4000_d1cc = _DAT_4000_d1ce;
      FUN_1000_3117();
    }
    FUN_1000_30f7();
  }
  FUN_1000_2cf2();
LAB_1000_2a0f:
  FUN_1000_2e3b();
  return;
}



/* FUN_1000_294f_1000_294f.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16far FUN_1000_294f(uint param_1)

{
  byte bVar1;
  uint uVar2;
  undefined1 uVar3;
  undefined1 in_ZF;
  undefined1 uVar4;
  undefined2 uVar5;

  FUN_1000_2e1a();
  DAT_4000_d17e = -1;
  if ((bool)in_ZF) {
    _DAT_4000_d7aa = CONCAT11((char)((uint)_DAT_4000_d1db >> 8),DAT_4000_d1d9);
  }
  if (param_1 == 0xffff) {
    if (DAT_4000_d1bc == '\0') {
      DAT_4000_d1bc = DAT_4000_d1d2;
    }
    uVar2 = (uint)DAT_4000_d1d0;
    DAT_4000_d23e = 1;
  }
  else {
    uVar2 = param_1;
    if (0x7fff < param_1) {
      if ((int)param_1 < -3) {
LAB_1000_298d:
        DAT_4000_d736 = 0xfc;
        goto LAB_1000_2a0f;
      }
      bVar1 = DAT_4000_d735;
      if (param_1 != 0xfffd) {
        bVar1 = DAT_4000_d734;
      }
      uVar2 = (uint)bVar1;
      if (bVar1 == 0) {
LAB_1000_2986:
        DAT_4000_d736 = 0xfe;
        goto LAB_1000_2a0f;
      }
    }
  }
  while( true ) {
    if (uVar2 < 0x14) {
      uVar3 = (int)uVar2 < 0;
      uVar4 = uVar2 * 2 == 0;
      (*(code *)*(undefined2 *)(uVar2 * 2 + 400))();
    }
    else {
      uVar3 = uVar2 < 0x40;
      uVar4 = uVar2 == 0x40;
      if (!(bool)uVar4) goto LAB_1000_298d;
      FUN_1000_362a();
    }
    if ((bool)uVar3) goto LAB_1000_2986;
    FUN_1000_2c31();
    FUN_1000_2c64();
    FUN_1000_33aa();
    (*_DAT_4000_d1f3)();
    FUN_1000_339a();
    if (!(bool)uVar3) break;
    DAT_4000_d736 = 0xff;
    DAT_4000_d17e = DAT_4000_d17e + '\x01';
    if (DAT_4000_d17e != '\0') goto LAB_1000_2a0f;
    LOCK();
    uVar2 = CONCAT11(DAT_4000_d1bc,(char)_DAT_4000_d7aa);
    UNLOCK();
    DAT_4000_d1bc = (char)((uint)_DAT_4000_d7aa >> 8);
  }
  FUN_1000_2c31();
  FUN_1000_2cc2();
  (*_DAT_4000_d1f7)();
  _DAT_4000_d79f = FUN_1000_2ef2();
  uVar5 = 0x29f1;
  _DAT_4000_d7a1 = _DAT_4000_d79f;
  (*_DAT_4000_d1f5)();
  FUN_1000_33fa(uVar5);
  if ((bool)uVar4) {
    if (param_1 == 0xffff) {
      _DAT_4000_d1cc = _DAT_4000_d1ce;
      FUN_1000_3117();
    }
    FUN_1000_30f7();
  }
  FUN_1000_2cf2();
LAB_1000_2a0f:
  FUN_1000_2e3b();
  return;
}



/* FUN_1000_2a29_1000_2a29.c */


int __cdecl16far FUN_1000_2a29(int param_1)

{
  int iVar1;
  char cVar2;
  undefined4 uVar3;

  if (param_1 != -1) {
    DAT_4000_d736 = 0xfc;
    if ((char)((uint)param_1 >> 8) != '\0') goto LAB_1000_2a74;
    param_1 = CONCAT11((char)param_1,(char)param_1);
  }
  LOCK();
  cVar2 = (char)((uint)param_1 >> 8);
  UNLOCK();
  if ((char)param_1 == DAT_4000_d1dc) {
    DAT_4000_d736 = 0;
    DAT_4000_d1dc = cVar2;
  }
  else {
    DAT_4000_d1dc = cVar2;
    uVar3 = FUN_1000_2c64();
    DAT_4000_d1dc = (char)((ulong)uVar3 >> 0x18);
    cVar2 = (char)((ulong)uVar3 >> 0x10);
    if ((cVar2 == -1) || (DAT_4000_d736 = 3, cVar2 == (char)uVar3)) {
      iVar1 = FUN_1000_2944(DAT_4000_d1d9,(uint)uVar3 & 0xff);
      return iVar1;
    }
  }
LAB_1000_2a74:
  return (int)DAT_4000_d1dc;
}



/* FUN_1000_2ac8_1000_2ac8.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined2 * __cdecl16far FUN_1000_2ac8(undefined2 *param_1)

{
  undefined1 uVar1;
  int iVar2;
  undefined2 uVar3;
  undefined2 *puVar4;
  undefined2 uVar5;
  bool bVar6;
  undefined4 uVar7;

  uVar5 = (undefined2)((ulong)param_1 >> 0x10);
  puVar4 = (undefined2 *)param_1;
  bVar6 = true;
  uVar3 = 0;
  iVar2 = 0x20;
  DAT_4000_d736 = 0;
  uVar7 = FUN_1000_33fa();
  if (!bVar6) {
    uVar7 = CONCAT22((uint)DAT_4000_d1ff * (uint)DAT_4000_d200,_DAT_4000_d1dd);
    iVar2 = CONCAT11((char)((uint)iVar2 >> 8),DAT_4000_d1e3) + 1;
    uVar3 = _DAT_4000_d1df;
  }
  *param_1 = (int)uVar7;
  puVar4[1] = uVar3;
  puVar4[2] = (uint)DAT_4000_d1db;
  puVar4[3] = (uint)DAT_4000_d1dc;
  puVar4[4] = iVar2;
  puVar4[5] = (int)((ulong)uVar7 >> 0x10);
  iVar2 = CONCAT11((char)((ulong)uVar7 >> 0x18),DAT_4000_d1e8) + 1;
  puVar4[6] = iVar2;
  uVar1 = (undefined1)((uint)iVar2 >> 8);
  puVar4[7] = CONCAT11(uVar1,DAT_4000_d1d9);
  puVar4[8] = CONCAT11(uVar1,DAT_4000_d745);
  puVar4[9] = CONCAT11(uVar1,DAT_4000_d746);
  puVar4[10] = _DAT_4000_d747;
  return puVar4;
}



/* FUN_1000_2b24_1000_2b24.c */


void __cdecl16far FUN_1000_2b24(void)

{
  FUN_1000_2e1a();
  FUN_1000_2fd1();
  FUN_1000_2e3b();
  return;
}



/* FUN_1000_2b3e_1000_2b3e.c */


void __cdecl16far FUN_1000_2b3e(void)

{
  DAT_4000_d736 = 0;
  FUN_1000_2f3e();
  return;
}



/* FUN_1000_2b5e_1000_2b5e.c */


void __cdecl16far FUN_1000_2b5e(uint param_1)

{
  FUN_1000_2e1a();
  if (param_1 < 3) {
    if ((char)param_1 == '\x01') {
      if (DAT_4000_d1d8 == '\0') {
        DAT_4000_d736 = 0xfd;
      }
      else {
        DAT_4000_d737 = 0;
        FUN_1000_3760();
      }
    }
    else {
      if ((char)param_1 == '\0') {
        FUN_1000_3199();
      }
      else {
        FUN_1000_284c();
      }
      FUN_1000_2ef2();
      FUN_1000_2efb();
    }
  }
  else {
    DAT_4000_d736 = 0xfc;
  }
  FUN_1000_2e3b();
  return;
}



/* FUN_1000_2bc0_1000_2bc0.c */


/* WARNING: Instruction at (ram,0x00012be2) overlaps instruction at (ram,0x00012be1)
    */

void __cdecl16far FUN_1000_2bc0(undefined2 param_1)

{
  byte bVar1;
  undefined1 uVar2;
  byte in_ZF;

  FUN_1000_2e1a();
  uVar2 = 0;
  if ((char)param_1 != '\0' || (char)((uint)param_1 >> 8) != '\0') {
    uVar2 = 0xff;
  }
  if ((in_ZF & 1) == 0) {
    DAT_4000_d23e = DAT_4000_d23e >> 1;
  }
  bVar1 = DAT_4000_d23e;
  DAT_4000_d23e = uVar2;
  FUN_1000_30f7(bVar1);
  FUN_1000_2e3b();
  return;
}



/* FUN_1000_2c31_1000_2c31.c */


int __cdecl16near FUN_1000_2c31(void)

{
  int iVar1;
  uint uVar2;
  char extraout_DL;
  char cVar3;
  int extraout_DX;

  cVar3 = DAT_4000_d1bc;
  LOCK();
  DAT_4000_d1bc = 0;
  UNLOCK();
  if (cVar3 != '\0') {
    DAT_4000_d1dc = cVar3;
    iVar1 = FUN_1000_2c64();
    cVar3 = extraout_DL;
    if (extraout_DL == -1) {
      cVar3 = (char)iVar1;
    }
    if (cVar3 == (char)iVar1) {
      DAT_4000_d1dc = cVar3;
      return iVar1;
    }
  }
  uVar2 = 0;
  FUN_1000_33e6();
  DAT_4000_d1dc = (char)(extraout_DX + 1U);
  return (uVar2 & 0xff) * (extraout_DX + 1U & 0xff);
}



/* FUN_1000_2c64_1000_2c64.c */


/* WARNING: Instruction at (ram,0x00012c85) overlaps instruction at (ram,0x00012c84)
    */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_2c64(void)

{
  byte bVar1;

  if (((_DAT_4000_d745 & 0x1c) != 0) && (DAT_4000_d1d9 != 0x40)) {
    bVar1 = *(byte *)(ulong)(DAT_4000_d1d9 + 0x1b8);
    if ((_DAT_4000_d745 & 8) == 0) {
      if ((_DAT_4000_d745 & 0x10) == 0) {
        bVar1 = bVar1 & 5;
      }
      else {
        bVar1 = bVar1 & 0x13;
      }
    }
    if (DAT_4000_d1dc == -1) {
      DAT_4000_d1dc = '<';
    }
    if (DAT_4000_d1dc == '<') {
      if ((bVar1 & 0x10) != 0) {
        DAT_4000_d1dc = 0x3c;
        return;
      }
      DAT_4000_d1dc = '2';
    }
    if (DAT_4000_d1dc == '2') {
      if ((bVar1 & 8) != 0) {
        DAT_4000_d1dc = 0x32;
        return;
      }
      DAT_4000_d1dc = '+';
    }
    if (((DAT_4000_d1dc == '+') && ((bVar1 & 4) != 0)) && ((_DAT_4000_d745 & 0x200) == 0)) {
      DAT_4000_d1dc = 0x2b;
      return;
    }
    if ((bVar1 & 2) != 0) {
      DAT_4000_d1dc = 0x1e;
      return;
    }
  }
  DAT_4000_d1dc = 0x19;
  return;
}



/* FUN_1000_2cc2_1000_2cc2.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_2cc2(void)

{
  undefined1 in_ZF;

  FUN_1000_33fa();
  if ((bool)in_ZF) {
    if (DAT_4000_d1dc != 0x19) {
      DAT_4000_d1e8 = DAT_4000_d1dc & 1 | 6;
      if (DAT_4000_d1db != '(') {
        DAT_4000_d1e8 = 3;
      }
      if (((DAT_4000_d745 & 4) != 0) && (_DAT_4000_d747 < 0x41)) {
        DAT_4000_d1e8 = DAT_4000_d1e8 >> 1;
      }
    }
    FUN_1000_3993();
  }
  return;
}



/* FUN_1000_2cf2_1000_2cf2.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int __cdecl16near FUN_1000_2cf2(void)

{
  int iVar1;
  undefined1 in_ZF;

  FUN_1000_33fa();
  if (!(bool)in_ZF) {
    FUN_1000_530b();
    _DAT_4000_d774 = _DAT_4000_d862;
    _DAT_4000_d776 = _DAT_4000_d864;
    _DAT_4000_d77e = 0xffff;
    DAT_4000_d73f = 3;
    if (DAT_4000_d1d8 == '\x01') {
      FUN_1000_3034();
    }
  }
  _DAT_4000_d778 = 0;
  _DAT_4000_d77a = 0;
  FUN_1000_2fd1();
  _DAT_4000_d7a1 = 0;
  _DAT_4000_d79f = 0;
  DAT_4000_d7a7 = 0;
  DAT_4000_d7a9 = 0;
  DAT_4000_d788 = 0;
  DAT_4000_d737 = 0;
  DAT_4000_d7a8 = 1;
  _DAT_4000_d7a5 = DAT_4000_d1db - 1;
  iVar1 = CONCAT11((char)(DAT_4000_d1db - 1 >> 8),DAT_4000_d1dc);
  _DAT_4000_d7a3 = iVar1 + -1;
  return iVar1;
}



/* FUN_1000_2e1a_1000_2e1a.c */


void __cdecl16near FUN_1000_2e1a(void)

{
  FUN_1000_5390();
  if ((DAT_4000_d1d8 != '\0') && (DAT_4000_d7a9 != '\0')) {
    FUN_1000_2e5c();
    DAT_4000_d7a9 = '\0';
  }
  DAT_4000_d736 = 0;
  return;
}



/* FUN_1000_2e3b_1000_2e3b.c */


void __cdecl16near FUN_1000_2e3b(void)

{
  if (((DAT_4000_d1d8 != '\0') && (DAT_4000_d23e < '\0')) && (DAT_4000_d7a9 == '\0')) {
    FUN_1000_2e5c();
    DAT_4000_d7a9 = DAT_4000_d7a9 + '\x01';
  }
  return;
}



/* FUN_1000_2e5c_1000_2e5c.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near
FUN_1000_2e5c(undefined2 param_1,undefined2 *param_2,undefined2 param_3,undefined2 param_4,
             undefined2 param_5)

{
  code *pcVar1;
  ulong uVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  uint *puVar6;
  uint *puVar7;

  FUN_1000_2efb();
  if (DAT_4000_d1d8 < 3) {
    uRam0000007c = 0x1ce;
    uRam0000007e = 0x4cff;
  }
  else if (_DAT_4000_d1d9 == 0x13) {
    (*_DAT_4000_d20e)();
    uVar3 = CONCAT11(DAT_4000_d77d,DAT_4000_d77d);
    uVar2 = (ulong)_DAT_4000_d74c >> 0x10;
    puVar6 = (uint *)_DAT_4000_d74c;
    iVar4 = 8;
    do {
      iVar5 = 4;
      do {
        puVar7 = puVar6;
        *puVar7 = *puVar7 ^ uVar3;
        iVar5 = iVar5 + -1;
        puVar6 = puVar7 + 1;
      } while (iVar5 != 0);
      puVar6 = puVar7 + 0x9d;
      iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
    return;
  }
  pcVar1 = (code *)swi(0x10);
  (*pcVar1)();
  if (DAT_4000_d1d8 < 3) {
    *param_2 = param_4;
    param_2[1] = param_5;
  }
  return;
}



/* FUN_1000_2ef2_1000_2ef2.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_2ef2(void)

{
  _DAT_4000_d79d = 0;
  _DAT_4000_d79b = 0;
  return;
}



/* FUN_1000_2efb_1000_2efb.c */


void __cdecl16near FUN_1000_2efb(void)

{
  code *pcVar1;

  pcVar1 = (code *)swi(0x10);
  (*pcVar1)();
  return;
}



/* FUN_1000_2f3e_1000_2f3e.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_2f3e(void)

{
  code *pcVar1;
  uint uVar2;
  uint in_AX;
  int in_DX;
  undefined2 unaff_DI;
  undefined1 uVar3;
  undefined4 uVar4;

  uVar2 = _DAT_4000_d778;
  if ((in_DX != _DAT_4000_d77a) || (in_AX != _DAT_4000_d778)) {
    if (DAT_4000_d1d8 == '\0') {
      if ((in_DX != 0) || (7 < in_AX)) {
        in_AX = in_AX & 7;
        DAT_4000_d736 = 3;
      }
      _DAT_4000_d77a = 0;
      _DAT_4000_d778 = in_AX;
      FUN_1000_2ffa();
    }
    else {
      if ((_DAT_4000_d1d9 != 6) && (_DAT_4000_d1d9 != 0x40)) {
        uVar4 = FUN_1000_5390();
        if ((DAT_4000_d1d8 == '\x01') && ((DAT_4000_d745 & 0x1c) == 0)) {
          uVar3 = false;
          (*_DAT_4000_d1fb)();
          if (!(bool)uVar3) {
            pcVar1 = (code *)swi(0x10);
            (*pcVar1)(uVar2);
            uVar3 = false;
          }
        }
        else {
          uVar3 = 0;
          (*_DAT_4000_d1f9)((int)((ulong)uVar4 >> 0x10));
        }
        if (!(bool)uVar3) {
          _DAT_4000_d778 = unaff_DI;
          _DAT_4000_d77a = (int)uVar4;
          return;
        }
      }
      DAT_4000_d736 = 0xfc;
    }
  }
  return;
}



/* FUN_1000_2fd1_1000_2fd1.c */


undefined1 __cdecl16near FUN_1000_2fd1(void)

{
  undefined1 uVar1;
  uint in_AX;
  byte bVar2;

  uVar1 = DAT_4000_d77c;
  if ((char)(in_AX >> 8) == '\0') {
    bVar2 = DAT_4000_d1e3;
    if (DAT_4000_d1d8 == '\0') {
      bVar2 = 0x1f;
    }
    if ((byte)in_AX <= bVar2) goto LAB_1000_2ff0;
  }
  in_AX = (uint)DAT_4000_d1e3;
  DAT_4000_d736 = 3;
LAB_1000_2ff0:
  LOCK();
  DAT_4000_d77c = (undefined1)in_AX;
  UNLOCK();
  FUN_1000_2ffa();
  return uVar1;
}



/* FUN_1000_2ffa_1000_2ffa.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_2ffa(void)

{
  byte bVar1;

  if (DAT_4000_d1d8 == '\0') {
    bVar1 = DAT_4000_d77c & 0xf | (DAT_4000_d77c & 0x10) << 3 | (DAT_4000_d778 & 7) << 4;
  }
  else {
    bVar1 = DAT_4000_d77c;
    if (DAT_4000_d200 == '\x02') {
      (*_DAT_4000_d21a)();
      bVar1 = DAT_4000_d74b;
    }
  }
  DAT_4000_d77d = bVar1;
  return;
}



/* FUN_1000_3034_1000_3034.c */


/* WARNING: Instruction at (ram,0x0001306b) overlaps instruction at (ram,0x0001306a)
    */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

byte __cdecl16near FUN_1000_3034(undefined2 param_1,undefined2 param_2)

{
  code *pcVar1;
  byte bVar2;
  uint in_AX;
  undefined2 uVar3;
  char cVar5;
  uint uVar4;
  undefined2 unaff_SI;
  byte in_stack_00000000;

  if (DAT_4000_d1d8 == '\x04') {
    if (in_AX < 0x10) {
      pcVar1 = (code *)swi(0x10);
      (*pcVar1)();
      return in_stack_00000000;
    }
  }
  else if ((DAT_4000_d1d8 == '\x01') && (in_AX < 4)) {
    if ((DAT_4000_d745 & 0x1c) != 0) {
      (*_DAT_4000_d1fd)();
      LOCK();
      UNLOCK();
      bVar2 = DAT_4000_d73a;
      DAT_4000_d73a = (char)unaff_SI;
      return bVar2;
    }
    uVar3 = CONCAT11(uRam00000466,(char)in_AX);
    pcVar1 = (code *)swi(0x10);
    (*pcVar1)();
    pcVar1 = (code *)swi(0x10);
    (*pcVar1)(uVar3,unaff_SI);
    cVar5 = (char)((int)param_2 >> 0xc);
    uVar4 = CONCAT11(cVar5,cVar5) & 0xff01;
    uVar4 = CONCAT11((char)(uVar4 >> 8),(char)uVar4 << 1) & 0x2ff;
    return (byte)uVar4 | (byte)(uVar4 >> 9);
  }
  DAT_4000_d736 = 0xfc;
  return 0xff;
}



/* FUN_1000_30df_1000_30df.c */


int __cdecl16near FUN_1000_30df(void)

{
  int in_AX;
  int in_BX;

  if (in_AX < 0) {
    in_AX = 0;
    DAT_4000_d736 = 3;
  }
  if (in_BX <= in_AX) {
    in_AX = in_BX + -1;
    DAT_4000_d736 = 3;
  }
  return in_AX;
}



/* FUN_1000_30f7_1000_30f7.c */


void FUN_1000_30f7(void)

{
  if (DAT_4000_d23e != '\0') {
    FUN_1000_346f();
    return;
  }
  FUN_1000_3474();
  return;
}



/* FUN_1000_3117_1000_3117.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_3117(void)

{
  byte extraout_AL;
  byte bVar1;
  byte extraout_AH;
  byte bVar2;

  FUN_1000_314b();
  bVar1 = extraout_AL;
  if (6 < extraout_AL) {
    bVar1 = 7;
  }
  bVar2 = extraout_AH & 0x1f;
  if (6 < (extraout_AH & 0x1f)) {
    bVar2 = 7;
  }
  _DAT_4000_d1d4 = CONCAT11(bVar2 | extraout_AH & 0x20,bVar1);
  return;
}



/* FUN_1000_314b_1000_314b.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

uint __cdecl16near FUN_1000_314b(void)

{
  uint in_AX;
  byte bVar1;
  byte in_BL;
  byte in_BH;

  if (((DAT_4000_d1dc == '\x19') && (_DAT_4000_d1df != 200)) &&
     ((_DAT_4000_d1d9 == 7 || (((DAT_4000_d745 & 0xc) == 0 || ((bRam00000487 & 1) != 0)))))) {
    bVar1 = (byte)(in_AX >> 8);
    in_AX = CONCAT11(bVar1 & 0x20 |
                     (byte)(((bVar1 & 0x1f) * (uint)in_BH + (uint)(in_BL >> 1)) / (uint)in_BL),
                     (char)(((in_AX & 0x1f) * (uint)in_BH + (uint)(in_BL >> 1)) / (uint)in_BL));
  }
  return in_AX & 0x3f1f;
}



/* FUN_1000_3199_1000_3199.c */


void __cdecl16near FUN_1000_3199(void)

{
  FUN_1000_3406();
  FUN_1000_33e6();
  FUN_1000_3400();
  DAT_4000_d737 = 0;
  return;
}



/* FUN_1000_339a_1000_339a.c */


undefined2 __cdecl16near FUN_1000_339a(void)

{
  FUN_1000_33e6();
  return 0;
}



/* FUN_1000_33aa_1000_33aa.c */


void __cdecl16near FUN_1000_33aa(void)

{
  uint uVar1;

  if (DAT_4000_d745 == '\b') {
    uVar1 = CONCAT11(bRam00000410,DAT_4000_d1d9) & 0xff07;
    bRam00000410 = (byte)(uVar1 >> 8) | 0x30;
    if ((char)uVar1 != '\a') {
      bRam00000410 = bRam00000410 & 0xef;
    }
    DAT_4000_d742 = bRam00000410;
    if ((DAT_4000_d743 & 4) == 0) {
      FUN_1000_33e6();
    }
  }
  return;
}



/* FUN_1000_33e6_1000_33e6.c */


void __cdecl16near FUN_1000_33e6(void)

{
  code *pcVar1;

  pcVar1 = (code *)swi(0x10);
  (*pcVar1)();
  return;
}



/* FUN_1000_33ef_1000_33ef.c */


void __cdecl16near FUN_1000_33ef(void)

{
  return;
}



/* FUN_1000_33fa_1000_33fa.c */


void __cdecl16near FUN_1000_33fa(void)

{
  return;
}



/* FUN_1000_3400_1000_3400.c */


void __cdecl16near FUN_1000_3400(void)

{
  byte bVar1;
  long lVar2;
  undefined2 uVar3;
  undefined2 unaff_SS;

  bVar1 = *(byte *)0x1e7;
  lVar2 = (ulong)bVar1 * (ulong)(uint)(*(int *)&DAT_4000_d1e6 << 4);
  uVar3 = (undefined2)((ulong)lVar2 >> 0x10);
  *(undefined2 *)0x44e = (int)lVar2;
  *(byte *)0x462 = bVar1;
  return;
}



/* FUN_1000_3406_1000_3406.c */


void __cdecl16near FUN_1000_3406(void)

{
  byte bVar1;
  long lVar2;
  undefined2 uVar3;
  undefined2 unaff_SS;

  bVar1 = *(byte *)&DAT_4000_d1d6;
  lVar2 = (ulong)bVar1 * (ulong)(uint)(*(int *)&DAT_4000_d1e6 << 4);
  uVar3 = (undefined2)((ulong)lVar2 >> 0x10);
  *(undefined2 *)0x44e = (int)lVar2;
  *(byte *)0x462 = bVar1;
  return;
}



/* FUN_1000_346f_1000_346f.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined4 __cdecl16near FUN_1000_346f(void)

{
  uint uVar1;
  uint uVar2;
  undefined2 in_DX;

  uVar1 = _DAT_4000_d1cc;
  FUN_1000_33e6();
  uVar2 = uVar1;
  FUN_1000_33e6();
  if ((((uVar2 & 0x2000) == 0) && ((DAT_4000_d745 & 4) != 0)) && (DAT_4000_d1dc != '\x19')) {
    FUN_1000_357a();
  }
  return CONCAT22(in_DX,uVar1);
}



/* FUN_1000_3474_1000_3474.c */


undefined4 __cdecl16near FUN_1000_3474(void)

{
  uint uVar1;
  undefined2 in_DX;

  FUN_1000_33e6();
  uVar1 = 0x2707;
  FUN_1000_33e6();
  if ((((uVar1 & 0x2000) == 0) && ((DAT_4000_d745 & 4) != 0)) && (DAT_4000_d1dc != '\x19')) {
    FUN_1000_357a();
  }
  return CONCAT22(in_DX,0x2707);
}



/* FUN_1000_34b8_1000_34b8.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_34b8(void)

{
  undefined1 *puVar1;
  undefined1 *puVar2;
  undefined2 *puVar3;
  int in_CX;
  int iVar4;
  undefined1 *in_BX;
  undefined2 *puVar5;
  undefined1 *puVar6;

  if (in_CX == 0x27) {
    puVar5 = (undefined2 *)&DAT_4000_d20e;
    for (iVar4 = 0x17; iVar4 != 0; iVar4 = iVar4 + -1) {
      puVar3 = puVar5;
      puVar5 = puVar5 + 1;
      *puVar3 = 0x34b6;
    }
  }
  puVar6 = (undefined1 *)&DAT_4000_d1d8;
  for (; in_CX != 0; in_CX = in_CX + -1) {
    puVar2 = puVar6;
    puVar6 = puVar6 + 1;
    puVar1 = in_BX;
    in_BX = in_BX + 1;
    *puVar2 = *puVar1;
  }
  (*_DAT_4000_d21a)(0x4cff);
  DAT_4000_d76a = 0;
  return;
}



/* FUN_1000_34ed_1000_34ed.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_34ed(undefined2 param_1,undefined2 param_2)

{
  undefined1 uVar1;

  uVar1 = DAT_4000_d74a;
  (*_DAT_4000_d20e)();
  _DAT_4000_d75c = _DAT_4000_d74c + _DAT_4000_d201;
  (*_DAT_4000_d20e)();
  _DAT_4000_d75e = _DAT_4000_d74c;
  (*_DAT_4000_d20e)();
  _DAT_4000_d760 = _DAT_4000_d74c;
  DAT_4000_d764 = DAT_4000_d74a;
  (*_DAT_4000_d20e)();
  _DAT_4000_d762 = _DAT_4000_d74c;
  DAT_4000_d765 = DAT_4000_d74a;
  DAT_4000_d74a = uVar1;
  _DAT_4000_d74c = param_2;
  return;
}



/* FUN_1000_357a_1000_357a.c */


void __cdecl16near FUN_1000_357a(void)

{
  undefined1 in_AL;
  undefined1 in_AH;
  int in_DX;

  out(in_DX,in_AL);
  out(in_DX + 1,in_AH);
  return;
}



/* FUN_1000_362a_1000_362a.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_362a(void)

{
  if ((DAT_4000_d745 & 0x40) != 0) {
    FUN_1000_34b8();
    _DAT_4000_d842 = 0x2000;
    _DAT_4000_d844 = 0x5fb0;
    _DAT_4000_d846 = 0x7fb0;
  }
  return;
}



/* FUN_1000_36da_1000_36da.c */


void __cdecl16near FUN_1000_36da(void)

{
  undefined1 *puVar1;
  int *piVar2;
  code *pcVar3;
  byte bVar4;
  undefined1 uVar6;
  int in_CX;
  byte in_BL;
  undefined1 *unaff_SI;
  int *unaff_DI;
  undefined2 unaff_ES;
  undefined2 unaff_SS;
  int iVar5;

  if (*(char *)&DAT_4000_d1d8 != '\0') {
    do {
      pcVar3 = (code *)swi(0x10);
      (*pcVar3)();
      pcVar3 = (code *)swi(0x10);
      (*pcVar3)();
      in_CX = in_CX + -1;
    } while (in_CX != 0);
    return;
  }
  FUN_1000_3732();
  iVar5 = (uint)in_BL << 8;
  if ((*(char *)&DAT_4000_d745 == '\x02') && ((*(byte *)0x754 & 1) != 0)) {
    while( true ) {
      uVar6 = (undefined1)((uint)iVar5 >> 8);
      bVar4 = in(0x3da);
      iVar5 = CONCAT11(uVar6,bVar4);
      if ((bVar4 & 8) != 0) break;
      if ((bVar4 & 1) == 0) {
        puVar1 = unaff_SI;
        unaff_SI = unaff_SI + 1;
        iVar5 = CONCAT11(uVar6,*puVar1);
        do {
          bVar4 = in(0x3da);
        } while ((bVar4 & 1) == 0);
        piVar2 = unaff_DI;
        unaff_DI = unaff_DI + 1;
        *piVar2 = iVar5;
        in_CX = in_CX + -1;
        if (in_CX == 0) {
          return;
        }
      }
    }
  }
  do {
    puVar1 = unaff_SI;
    unaff_SI = unaff_SI + 1;
    iVar5 = CONCAT11((char)((uint)iVar5 >> 8),*puVar1);
    piVar2 = unaff_DI;
    unaff_DI = unaff_DI + 1;
    *piVar2 = iVar5;
    in_CX = in_CX + -1;
  } while (in_CX != 0);
  return;
}



/* FUN_1000_3732_1000_3732.c */


undefined4 __cdecl16near FUN_1000_3732(void)

{
  undefined1 uVar1;
  char in_CL;
  undefined2 in_DX;
  byte in_BH;

  uVar1 = (undefined1)((uint)in_DX >> 8);
  *(undefined2 *)((uint)in_BH * 2 + 0x450) = CONCAT11(uVar1,(char)in_DX + in_CL);
  return CONCAT22(CONCAT11(uVar1,(char)in_DX + in_CL),(uint)in_BH * 2);
}



/* FUN_1000_3760_1000_3760.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_3760(void)

{
  (*_DAT_4000_d21a)();
  _DAT_4000_d86a = _DAT_4000_d854;
  _DAT_4000_d86c = _DAT_4000_d858;
  FUN_1000_377e();
  FUN_1000_34ed();
  FUN_1000_52c4();
  (*_DAT_4000_d20e)();
  FUN_1000_0f81();
  return;
}



/* FUN_1000_377e_1000_377e.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_377e(void)

{
  undefined2 in_CX;
  undefined2 uVar1;
  byte extraout_DL;
  undefined2 extraout_DX;
  undefined2 extraout_DX_00;
  int in_BX;
  int unaff_BP;
  undefined1 in_CF;
  int iVar2;

  FUN_1000_37d4();
  if (!(bool)in_CF) {
    FUN_1000_3846();
    LOCK();
    UNLOCK();
    LOCK();
    UNLOCK();
    uVar1 = _DAT_4000_d86a;
    _DAT_4000_d86a = in_CX;
    _DAT_4000_d86c = extraout_DX;
    FUN_1000_3846();
    FUN_1000_3889();
    if ((bool)in_CF) {
      LOCK();
      UNLOCK();
      _DAT_4000_d86c = extraout_DX_00;
    }
    in_BX = in_BX + 1;
    iVar2 = in_BX;
    FUN_1000_387e(in_BX);
    if ((bool)in_CF) {
      LOCK();
      UNLOCK();
      _DAT_4000_d86a = uVar1;
    }
    DAT_4000_d886 = extraout_DL & 7;
    (*_DAT_4000_d20e)(in_BX + 1);
    do {
      (*_DAT_4000_d232)(iVar2);
      iVar2 = 0x37bf;
      (*_DAT_4000_d218)();
      DAT_4000_d886 = DAT_4000_d886 + 1 & 7;
      unaff_BP = unaff_BP + -1;
    } while (unaff_BP != 0);
  }
  _DAT_4000_d876 = 0xffff;
  return;
}



/* FUN_1000_37d4_1000_37d4.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_37d4(void)

{
  int in_CX;
  int in_DX;

  _DAT_4000_d76c = _DAT_4000_d86a;
  if (_DAT_4000_d86a < in_CX) {
    _DAT_4000_d76c = in_CX;
    in_CX = _DAT_4000_d86a;
  }
  _DAT_4000_d770 = _DAT_4000_d86c;
  if (_DAT_4000_d86c < in_DX) {
    _DAT_4000_d770 = in_DX;
    in_DX = _DAT_4000_d86c;
  }
  _DAT_4000_d76e = in_CX;
  _DAT_4000_d772 = in_DX;
  FUN_1000_37fc();
  return;
}



/* FUN_1000_37fc_1000_37fc.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_37fc(void)

{
  if ((((_DAT_4000_d852 <= _DAT_4000_d76c) && (_DAT_4000_d76e <= _DAT_4000_d854)) &&
      (_DAT_4000_d856 <= _DAT_4000_d770)) && (_DAT_4000_d772 <= _DAT_4000_d858)) {
    return;
  }
  return;
}



/* FUN_1000_3824_1000_3824.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

uint __cdecl16near FUN_1000_3824(void)

{
  uint in_AX;
  uint uVar1;
  int in_CX;
  int in_DX;

  uVar1 = in_AX & 0xff00;
  if (in_CX < _DAT_4000_d852) {
    uVar1 = uVar1 + 1;
  }
  if (_DAT_4000_d854 < in_CX) {
    uVar1 = uVar1 | 2;
  }
  if (in_DX < _DAT_4000_d856) {
    uVar1 = uVar1 | 4;
  }
  if (_DAT_4000_d858 < in_DX) {
    uVar1 = uVar1 | 8;
  }
  return uVar1;
}



/* FUN_1000_3846_1000_3846.c */


void __cdecl16near FUN_1000_3846(void)

{
  char cVar1;

  cVar1 = FUN_1000_3824();
  if (cVar1 != '\0') {
    DAT_4000_d736 = 2;
  }
  return;
}



/* FUN_1000_387e_1000_387e.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_387e(void)

{
  return;
}



/* FUN_1000_3889_1000_3889.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_3889(void)

{
  return;
}



/* FUN_1000_3993_1000_3993.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_3993(void)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int *piVar5;

  if (DAT_4000_d1dc != '\x19') {
    _DAT_4000_d1e6 = uRam0000044c >> 4;
  }
  piVar5 = (int *)&DAT_4000_d82c;
  iVar4 = _DAT_4000_d1e6 * 0x10;
  iVar2 = 0;
  iVar3 = 8;
  do {
    piVar1 = piVar5;
    piVar5 = piVar5 + 1;
    *piVar1 = iVar2;
    iVar2 = iVar2 + iVar4;
    iVar3 = iVar3 + -1;
  } while (iVar3 != 0);
  return;
}



/* FUN_1000_52c4_1000_52c4.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined2 __cdecl16near FUN_1000_52c4(void)

{
  undefined2 in_AX;
  int iVar1;
  int iVar2;

  iVar1 = _DAT_4000_d84e;
  iVar2 = 0;
  if (DAT_4000_d899 == '\0') {
    iVar1 = _DAT_4000_d854;
    iVar2 = _DAT_4000_d852;
  }
  _DAT_4000_d85e = iVar1 - iVar2;
  _DAT_4000_d862 = iVar2 + ((iVar1 - iVar2) + 1U >> 1);
  iVar1 = _DAT_4000_d850;
  iVar2 = 0;
  if (DAT_4000_d899 == '\0') {
    iVar1 = _DAT_4000_d858;
    iVar2 = _DAT_4000_d856;
  }
  _DAT_4000_d860 = iVar1 - iVar2;
  _DAT_4000_d864 = iVar2 + ((iVar1 - iVar2) + 1U >> 1);
  return in_AX;
}



/* FUN_1000_530b_1000_530b.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined4 __cdecl16near FUN_1000_530b(void)

{
  undefined2 in_AX;
  undefined2 in_DX;

  _DAT_4000_d876 = 0xffff;
  FUN_1000_5327();
  _DAT_4000_d896 = 0;
  return CONCAT22(in_DX,in_AX);
}



/* FUN_1000_5327_1000_5327.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_5327(void)

{
  undefined2 in_CX;
  undefined2 extraout_DX;
  undefined1 in_ZF;

  _DAT_4000_d898 = 0;
  FUN_1000_33fa();
  if ((bool)in_ZF) {
    return;
  }
  FUN_1000_33ef();
  _DAT_4000_d852 = 0;
  _DAT_4000_d856 = 0;
  _DAT_4000_d85a = 0;
  _DAT_4000_d85c = 0;
  _DAT_4000_d84e = in_CX;
  _DAT_4000_d850 = extraout_DX;
  _DAT_4000_d854 = in_CX;
  _DAT_4000_d858 = extraout_DX;
  FUN_1000_34ed();
  FUN_1000_52c4();
  (*_DAT_4000_d20e)();
  FUN_1000_0f81();
  return;
}



/* FUN_1000_5390_1000_5390.c */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_5390(void)

{
  if (_DAT_4000_d628 == -0x292a) {
    FUN_1000_0f90();
  }
  return;
}



/* entry_1000_0f9a.c */


/* WARNING: Stack frame is not setup normally: Input value of stackpointer is not used */
/* WARNING: This function may have set the stack pointer */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16far entry(void)

{
  undefined1 *puVar1;
  code *pcVar2;
  code *pcVar3;
  byte bVar4;
  int iVar5;
  undefined1 *puVar6;
  undefined1 *puVar7;
  undefined1 *puVar8;
  undefined1 *puVar9;
  undefined2 *puVar10;
  undefined1 *puVar11;
  uint uVar12;
  undefined1 *puVar13;
  undefined2 unaff_ES;
  undefined2 uVar14;

  uVar14 = 0x4cff;
  puVar6 = (undefined1 *)0x800;
  pcVar3 = (code *)swi(0x21);
  bVar4 = (*pcVar3)();
  if (bVar4 < 2) {
    *(undefined2 *)(puVar6 + -2) = unaff_ES;
    *(undefined2 *)(puVar6 + -4) = 0;
    return;
  }
  uVar12 = _DAT_4000_cff2 + 0xea26;
  if (0xfff < uVar12) {
    uVar12 = 0x1000;
  }
  puVar7 = puVar6 + 0xbae;
  puVar13 = puVar6 + 0xbae;
  if ((undefined1 *)0xf451 < puVar6) {
    *(undefined2 *)(puVar6 + 0xbac) = 0x15da;
    uVar14 = *(undefined2 *)(puVar6 + 0xbac);
    *(undefined2 *)(puVar6 + 0xbac) = 0xfc8;
    FUN_1000_14d4();
    *(undefined2 *)(puVar6 + 0xbac) = 0;
    *(undefined2 *)(puVar6 + 0xbaa) = 0xfce;
    FUN_1000_1753();
    pcVar3 = (code *)swi(0x21);
    (*pcVar3)();
    puVar13 = puVar7;
  }
  DAT_15da_0254 = uVar12 * 0x10 + -1;
  DAT_15da_0256 = 0x15da;
  puVar8 = (undefined1 *)((uint)puVar13 & 0xfffe);
  DAT_15da_0260 = puVar8 + -2;
  DAT_15da_025a = puVar8;
  *(undefined2 *)(puVar8 + -2) = 0xfffe;
  puVar9 = puVar8 + -4;
  DAT_15da_025c = puVar8 + -4;
  DAT_15da_025e = puVar8 + -4;
  DAT_15da_0250 = puVar8 + -4;
  *(undefined2 *)(puVar8 + -4) = 1;
  *(int *)&DAT_4000_cff2 = uVar12 + 0x15da;
  pcVar3 = (code *)swi(0x21);
  (*pcVar3)();
  DAT_15da_0290 = uVar14;
  *(undefined2 *)(puVar9 + -2) = 0x15da;
  uVar14 = *(undefined2 *)(puVar9 + -2);
  puVar13 = (undefined1 *)&DAT_4000_d734;
  for (iVar5 = 0x46c; iVar5 != 0; iVar5 = iVar5 + -1) {
    puVar1 = puVar13;
    puVar13 = puVar13 + 1;
    *puVar1 = 0;
  }
  *(undefined2 *)(puVar9 + -2) = 0x15da;
  pcVar2 = (code *)*(int *)0x646;
  if (pcVar2 != (code *)0x0) {
    puVar10 = (undefined2 *)(puVar9 + -2);
    puVar9 = puVar9 + -2;
    *puVar10 = 0x1031;
    (*pcVar2)();
  }
  *(undefined2 *)(puVar9 + -2) = 0x1034;
  FUN_1000_16aa();
  puVar11 = puVar9 + -2;
  *(undefined2 *)(puVar9 + -2) = 0x1037;
  FUN_1000_151c();
  *(undefined2 *)(puVar11 + -2) = 0x103c;
  FUN_1000_1084();
  *(undefined2 *)(puVar11 + -2) = 0x15da;
  uVar14 = *(undefined2 *)(puVar11 + -2);
  *(undefined2 *)(puVar11 + -2) = *(undefined2 *)&DAT_4000_d2a1;
  *(undefined2 *)(puVar11 + -4) = *(undefined2 *)0x2af;
  *(undefined2 *)(puVar11 + -6) = *(undefined2 *)0x2ad;
  *(undefined2 *)(puVar11 + -8) = 0x104d;
  uVar14 = FUN_1000_0010();
  *(undefined2 *)(puVar11 + -8) = uVar14;
  *(undefined2 *)(puVar11 + -10) = 0x1051;
  FUN_1000_1152();
  return;
}



/* thunk_FUN_1000_2607_1000_239a.c */


void __cdecl16near thunk_FUN_1000_2607(uint param_1)

{
  bool bVar1;

  bVar1 = param_1 < 0xffe8;
  if (((param_1 < 0xffe9) && (FUN_1000_26da(), bVar1)) && (FUN_1000_239e(), !bVar1)) {
    FUN_1000_26da();
  }
  return;
}



/* thunk_FUN_1000_2686_1000_24c4.c */


undefined4 __cdecl16near thunk_FUN_1000_2686(byte *param_1)

{
  byte *pbVar1;
  byte bVar2;
  uint uVar3;
  byte bVar4;
  uint uVar5;
  int iVar6;
  uint uVar7;
  int iVar8;
  uint uVar9;
  uint uVar10;
  bool bVar11;

  iVar6 = 0;
  iVar8 = 0;
  do {
    do {
      pbVar1 = param_1;
      param_1 = param_1 + 1;
      bVar2 = *pbVar1;
      uVar5 = (uint)bVar2;
    } while (bVar2 == 0x20);
  } while (bVar2 == 9);
  if ((bVar2 != 0x2d) && (bVar2 != 0x2b)) goto LAB_1000_26a6;
  while( true ) {
    pbVar1 = param_1;
    param_1 = param_1 + 1;
    uVar5 = CONCAT11((char)(uVar5 >> 8),*pbVar1);
LAB_1000_26a6:
    bVar4 = (byte)uVar5;
    if ((0x39 < bVar4) || (uVar5 = uVar5 + 0xd0, bVar4 < 0x30)) break;
    uVar9 = iVar8 * 2;
    uVar7 = iVar6 << 1 | (uint)(iVar8 < 0);
    iVar6 = iVar8 << 2;
    uVar10 = iVar8 * 8;
    uVar3 = iVar8 * 10;
    iVar8 = uVar3 + uVar5;
    iVar6 = ((uVar7 << 1 | (uint)((int)uVar9 < 0)) << 1 | (uint)(iVar6 < 0)) + uVar7 +
            (uint)CARRY2(uVar10,uVar9) + (uint)CARRY2(uVar3,uVar5);
  }
  if (bVar2 == 0x2d) {
    bVar11 = iVar8 != 0;
    iVar8 = -iVar8;
    iVar6 = -(iVar6 + (uint)bVar11);
  }
  return CONCAT22(iVar6,iVar8);
}
