
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_2ffa(void)

{
  byte bVar1;

  if (DAT_4000_d1d8 == '\0') {
    bVar1 = DAT_4000_d77c & 0xf | (DAT_4000_d77c & 0x10) << 3 | (DAT_4000_d778 & 7) << 4;
  }
  else {
    bVar1 = DAT_4000_d77c;
    if (DAT_4000_d200 == '\x02') {
      (*_DAT_4000_d21a)();
      bVar1 = DAT_4000_d74b;
    }
  }
  DAT_4000_d77d = bVar1;
  return;
}
