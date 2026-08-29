
void __cdecl16near FUN_1000_2efb(void)

{
  code *pcVar1;

  pcVar1 = (code *)swi(0x10);
  (*pcVar1)();
  return;
}
