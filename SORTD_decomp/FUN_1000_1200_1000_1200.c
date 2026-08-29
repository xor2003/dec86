
void __cdecl16near FUN_1000_1200(void)

{
  int *unaff_SI;
  int *unaff_DI;

  while (unaff_SI < unaff_DI) {
    unaff_DI = unaff_DI + -1;
    if ((code *)*unaff_DI != (code *)0x0) {
      (*(code *)*unaff_DI)();
    }
  }
  return;
}
