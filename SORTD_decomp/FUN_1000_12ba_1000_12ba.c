
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
