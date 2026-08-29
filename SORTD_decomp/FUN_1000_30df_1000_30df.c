
int __cdecl16near FUN_1000_30df(void)

{
  int in_AX;
  int in_BX;

  if (in_AX < 0) {
    in_AX = 0;
    DAT_4000_d736 = 3;
  }
  if (in_BX <= in_AX) {
    in_AX = in_BX + -1;
    DAT_4000_d736 = 3;
  }
  return in_AX;
}
