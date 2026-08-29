
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_2880(void)

{
  if (_DAT_4000_d79d < 0) {
    _DAT_4000_d79d = 0;
  }
  else if (_DAT_4000_d7a5 - _DAT_4000_d7a1 < _DAT_4000_d79d) {
    if (DAT_4000_d7a8 == '\0') {
      DAT_4000_d7a7 = 1;
      _DAT_4000_d79d = _DAT_4000_d7a5 - _DAT_4000_d7a1;
    }
    else {
      _DAT_4000_d79d = 0;
      _DAT_4000_d79b = _DAT_4000_d79b + 1;
    }
  }
  if (_DAT_4000_d79b < 0) {
    _DAT_4000_d79b = 0;
  }
  else if (_DAT_4000_d7a3 - _DAT_4000_d79f < _DAT_4000_d79b) {
    _DAT_4000_d79b = _DAT_4000_d7a3 - _DAT_4000_d79f;
    FUN_1000_284c();
  }
  FUN_1000_2efb();
  return;
}
