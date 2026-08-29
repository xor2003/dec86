
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
