
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_1000_1222(void)

{
  undefined1 *in_AX;
  code *in_stack_00000000;

  if ((in_AX <= &stack0x0002) && (_DAT_4000_d2b2 <= &stack0x0002 + -(int)in_AX)) {
                    /* WARNING: Could not recover jumptable at 0x00011231. Too many branches */
                    /* WARNING: Treating indirect jump as call */
    (*in_stack_00000000)();
    return;
  }
  FUN_1000_1062();
  return;
}
