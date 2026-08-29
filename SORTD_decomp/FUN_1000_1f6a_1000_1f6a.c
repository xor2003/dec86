
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
