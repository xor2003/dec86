
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
