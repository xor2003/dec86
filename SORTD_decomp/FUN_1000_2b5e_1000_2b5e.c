
void __cdecl16far FUN_1000_2b5e(uint param_1)

{
  FUN_1000_2e1a();
  if (param_1 < 3) {
    if ((char)param_1 == '\x01') {
      if (DAT_4000_d1d8 == '\0') {
        DAT_4000_d736 = 0xfd;
      }
      else {
        DAT_4000_d737 = 0;
        FUN_1000_3760();
      }
    }
    else {
      if ((char)param_1 == '\0') {
        FUN_1000_3199();
      }
      else {
        FUN_1000_284c();
      }
      FUN_1000_2ef2();
      FUN_1000_2efb();
    }
  }
  else {
    DAT_4000_d736 = 0xfc;
  }
  FUN_1000_2e3b();
  return;
}
