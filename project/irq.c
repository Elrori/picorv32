void irq_handle(void)
{
    // unsigned int irqs = irq_pending() & irq_getmask();

    // while (irqs) {
        // const unsigned int irq = __builtin_ctz(irqs);
        // if ((irq < CONFIG_CPU_INTERRUPTS) && irq_table[irq].isr)
            // irq_table[irq].isr();
        // else {
            // irq_setmask(irq_getmask() & ~(1 << irq));
            // printf("\n*** disabled spurious irq %d ***\n", irq);
        // }
        // irqs &= irqs - 1; /* Clear this IRQ (the first bit set). */
    // }
}