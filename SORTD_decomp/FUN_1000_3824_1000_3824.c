
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
