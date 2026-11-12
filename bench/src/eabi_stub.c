/* GCC emits a call to __eabi() at the top of main(); SDA bases are set by the entry stub. */
void __eabi(void);
void __eabi(void) {}
