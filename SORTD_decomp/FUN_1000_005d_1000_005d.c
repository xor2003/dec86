
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
