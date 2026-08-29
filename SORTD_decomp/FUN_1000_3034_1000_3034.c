
/* WARNING: Instruction at (ram,0x0001306b) overlaps instruction at (ram,0x0001306a)
    */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

byte __cdecl16near FUN_1000_3034(undefined2 param_1,undefined2 param_2)

{
  code *pcVar1;
  byte bVar2;
  uint in_AX;
  undefined2 uVar3;
  char cVar5;
  uint uVar4;
  undefined2 unaff_SI;
  byte in_stack_00000000;

  if (DAT_4000_d1d8 == '\x04') {
    if (in_AX < 0x10) {
      pcVar1 = (code *)swi(0x10);
      (*pcVar1)();
      return in_stack_00000000;
    }
  }
  else if ((DAT_4000_d1d8 == '\x01') && (in_AX < 4)) {
    if ((DAT_4000_d745 & 0x1c) != 0) {
      (*_DAT_4000_d1fd)();
      LOCK();
      UNLOCK();
      bVar2 = DAT_4000_d73a;
      DAT_4000_d73a = (char)unaff_SI;
      return bVar2;
    }
    uVar3 = CONCAT11(uRam00000466,(char)in_AX);
    pcVar1 = (code *)swi(0x10);
    (*pcVar1)();
    pcVar1 = (code *)swi(0x10);
    (*pcVar1)(uVar3,unaff_SI);
    cVar5 = (char)((int)param_2 >> 0xc);
    uVar4 = CONCAT11(cVar5,cVar5) & 0xff01;
    uVar4 = CONCAT11((char)(uVar4 >> 8),(char)uVar4 << 1) & 0x2ff;
    return (byte)uVar4 | (byte)(uVar4 >> 9);
  }
  DAT_4000_d736 = 0xfc;
  return 0xff;
}
