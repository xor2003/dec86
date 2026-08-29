
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_37d4(void)

{
  int in_CX;
  int in_DX;

  _DAT_4000_d76c = _DAT_4000_d86a;
  if (_DAT_4000_d86a < in_CX) {
    _DAT_4000_d76c = in_CX;
    in_CX = _DAT_4000_d86a;
  }
  _DAT_4000_d770 = _DAT_4000_d86c;
  if (_DAT_4000_d86c < in_DX) {
    _DAT_4000_d770 = in_DX;
    in_DX = _DAT_4000_d86c;
  }
  _DAT_4000_d76e = in_CX;
  _DAT_4000_d772 = in_DX;
  FUN_1000_37fc();
  return;
}
