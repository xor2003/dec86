
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
