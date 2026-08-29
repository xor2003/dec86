
void FUN_1000_2825(void)

{
  code *pcVar1;
  char in_DH;
  undefined2 unaff_SS;

  if (*(byte *)&DAT_4000_d7a3 < (byte)(in_DH + 1U)) {
    FUN_1000_284c();
  }
  pcVar1 = (code *)swi(0x10);
  (*pcVar1)();
  *(undefined1 *)&DAT_4000_d7a7 = 0;
  return;
}
