#include "irq.h"
#include "main.h"

struct irq_table
{
    isr_t isr;
} irq_table[CONFIG_CPU_INTERRUPTS];

int irq_attach(unsigned int irq, isr_t isr)
{
    if (irq >= CONFIG_CPU_INTERRUPTS) {
        print("Inv irq \n");
        return -1;
    }

    unsigned int ie = irq_getie();
    irq_setie(0);
    irq_table[irq].isr = isr;
    irq_setie(ie);
    return irq;
}

int irq_detach(unsigned int irq)
{
    return irq_attach(irq, 0);
}

void irq_handle(void)
{
    unsigned int irqs = irq_pending() & irq_getmask();
    while (irqs) {
        const unsigned int irq = __builtin_ctz(irqs);
        if ((irq < CONFIG_CPU_INTERRUPTS) && irq_table[irq].isr)
            irq_table[irq].isr();
        else {
            //irq_setmask(irq_getmask() & ~(1 << irq));
            //print("\n*** disabled spurious irq number ");
			print("\n*** spurious irq (no function to handle), irq number:");
			print_dec(irq);
			print(" ***\n");
        }
        irqs &= irqs - 1; /* Clear this IRQ (the first bit set). */
    }
}