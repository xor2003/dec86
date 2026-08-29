
void FUN_1000_01db(int param_1,undefined2 param_2,int param_3,int param_4)

{
  undefined2 unaff_SS;
  undefined1 auStack_55 [73];
  undefined2 uStack_c;
  undefined1 *puStack_a;
  undefined1 *puStack_8;
  int iVar1;

  FUN_1000_1222();
  puStack_8 = (undefined1 *)0xcd;
  puStack_a = auStack_55 + 1;
  uStack_c = 0x209;
  FUN_1000_13d4();
  auStack_55[1] = 0xc9;
  auStack_55[param_3] = 0xbb;
  auStack_55[param_3 + 1] = 0;
  puStack_8 = (undefined1 *)param_1;
  puStack_a = (undefined1 *)0x1000;
  uStack_c = 0x229;
  FUN_1000_28e4();
  puStack_8 = auStack_55 + 1;
  puStack_a = (undefined1 *)0x1000;
  uStack_c = 0x236;
  FUN_1000_2756();
  puStack_8 = (undefined1 *)0x20;
  puStack_a = auStack_55 + 1;
  uStack_c = 0x247;
  FUN_1000_13d4();
  auStack_55[1] = 0xba;
  auStack_55[param_3] = 0xba;
  iVar1 = param_1;
  while (iVar1 = iVar1 + 1, iVar1 <= param_4) {
    puStack_a = (undefined1 *)0x1000;
    uStack_c = 0x278;
    puStack_8 = (undefined1 *)iVar1;
    FUN_1000_28e4();
    puStack_8 = auStack_55 + 1;
    puStack_a = (undefined1 *)0x1000;
    uStack_c = 0x285;
    FUN_1000_2756();
  }
  puStack_8 = (undefined1 *)0xcd;
  puStack_a = auStack_55 + 1;
  uStack_c = 0x299;
  FUN_1000_13d4();
  auStack_55[1] = 200;
  auStack_55[param_3] = 0xbc;
  puStack_8 = (undefined1 *)(param_4 + param_1);
  puStack_a = (undefined1 *)0x1000;
  uStack_c = 0x2b6;
  FUN_1000_28e4();
  puStack_8 = auStack_55 + 1;
  puStack_a = (undefined1 *)0x1000;
  uStack_c = 0x2c3;
  FUN_1000_2756();
  return;
}
