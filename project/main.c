#include "main.h"
#include "irq.h"

void putchar(char c){
	if (c == '\n')
		putchar('\r');
	REG_UART = c;
}

void print(const char *p){
	while (*p)
		putchar(*(p++));
}

void print_hex(unsigned int v, int digits)
{
	for (int i = 7; i >= 0; i--) {
		char c = "0123456789abcdef"[(v >> (4*i)) & 15];
		if (c == '0' && i >= digits) continue;
		putchar(c);
		digits = i;
	}
} 

void print_dec(unsigned int val)
{
	char buffer[10];
	char *p = buffer;
	while (val || p == buffer) {
		*(p++) = val % 10;
		val = val / 10;
	}
	while (p != buffer) {
		REG_UART = '0' + *(--p);
	}
}

void irq_handle_picotimer(void){
	static t=0;
	print("time:");
	print_dec(t++);
	print("\n");
	_trigger_timer(125000000);
}

void irq_init(void){
	irq_attach(0, irq_handle_picotimer);// 设置BIT0（0号）中断服务函数
	irq_setie(1); // 打开中断使能
	irq_setmask(0x01);//设置BIT0(internal timer)中断使能
}

void main(void){
	print("PICORV32: HELLO!\n");
	irq_init();
	_trigger_timer(125000000);
	print("\nEND\n");
	return;
}