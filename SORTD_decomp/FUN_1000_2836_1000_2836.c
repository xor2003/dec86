
void __cdecl16near FUN_1000_2836(void)

{
  code *pcVar1;
  undefined2 unaff_SS;

  pcVar1 = (code *)swi(0x10);
  (*pcVar1)();
  *(undefined1 *)&DAT_4000_d7a7 = 0;
  return;
}
