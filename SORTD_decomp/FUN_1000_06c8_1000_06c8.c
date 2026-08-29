
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void __cdecl16near FUN_1000_06c8(int param_1)

{
  undefined2 unaff_SS;
  undefined1 local_2e [34];
  undefined2 uStack_c;
  undefined1 *puStack_a;
  undefined1 *puStack_8;

  FUN_1000_1222();
  puStack_8 = (undefined1 *)0xdf;
  puStack_a = local_2e;
  uStack_c = 0x6e9;
  FUN_1000_13d4();
  puStack_8 = (undefined1 *)0x20;
  puStack_a = local_2e + *(char *)(param_1 * 2 + 0xb4c);
  uStack_c = 0x719;
  FUN_1000_13d4();
  local_2e[_DAT_4000_db92] = 0;
  puStack_8 = (undefined1 *)0x1000;
  puStack_a = (undefined1 *)0x734;
  FUN_1000_2b24();
  puStack_8 = (undefined1 *)(param_1 + 1);
  puStack_a = (undefined1 *)0x1000;
  uStack_c = 0x745;
  FUN_1000_28e4();
  puStack_8 = local_2e;
  puStack_a = (undefined1 *)0x1000;
  uStack_c = 0x752;
  FUN_1000_2756();
  return;
}
