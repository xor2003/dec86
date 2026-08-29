
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
