#ifndef __MAIN_H
#define __MAIN_H
#define REG_UART (*(volatile unsigned int*)0x07000004)
extern void _trigger_timer(unsigned int cycles);
extern void print(const char *p);
extern void print_hex(unsigned int v, int digits);
#endif