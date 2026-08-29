
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
