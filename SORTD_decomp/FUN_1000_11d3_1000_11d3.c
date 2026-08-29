
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_11d3(undefined2 param_1)

{
  code *pcVar1;

  if (_DAT_4000_d63c != 0) {
    (*_DAT_4000_d63a)(0x1000);
  }
  pcVar1 = (code *)swi(0x21);
  (*pcVar1)();
  if (*(char *)0x2ba != '\0') {
    pcVar1 = (code *)swi(0x21);
    (*pcVar1)();
  }
  return;
}
