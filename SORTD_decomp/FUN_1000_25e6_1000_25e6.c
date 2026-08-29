
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
