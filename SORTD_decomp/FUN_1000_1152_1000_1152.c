
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_1152(void)

{
  code *pcVar1;

  FUN_1000_1200();
  FUN_1000_1200();
  if (_DAT_4000_d628 == -0x292a) {
    (*_DAT_4000_d62e)();
  }
  FUN_1000_1200();
  FUN_1000_120f();
  FUN_1000_14fa();
  FUN_1000_11d3();
  pcVar1 = (code *)swi(0x21);
  (*pcVar1)();
  return;
}
