static __attribute__((always_inline)) inline unsigned long long step(unsigned long long a) {
    return (a * 3) ^ 9;
}

unsigned long long entry(unsigned long long a, unsigned long long b) { return step(a) + b; }
