#include "streams.h"

class Operation {
  public:
    virtual unsigned apply(unsigned value) const = 0;

  protected:
    explicit Operation(unsigned& trace) : events(trace) { record(1); }
    ~Operation() { record(4); }
    // Each digit records an event on the same object, including destruction after dispatch.
    __attribute__((noinline)) void record(unsigned digit) { events = events * 10 + digit; }

  private:
    unsigned& events;
};

class Add : public Operation {
  public:
    explicit Add(unsigned& trace) : Operation(trace) { record(2); }
    ~Add() { record(5); }
    unsigned apply(unsigned value) const override { return value + 7; }
};

class Double : public Operation {
  public:
    explicit Double(unsigned& trace) : Operation(trace) { record(3); }
    ~Double() { record(6); }
    unsigned apply(unsigned value) const override { return 2 * value; }
};

__attribute__((noinline)) unsigned dispatch(const Operation& op, unsigned value) {
    return op.apply(value);
}

int main(int argc, char** argv) {
    if (!open_binary_streams() || argc != 2)
        return 2;
    for (const char* c = argv[1]; *c; ++c) {
        unsigned trace = 0;
        unsigned result;
        const auto value = static_cast<unsigned char>(*c);
        if (value % 2 != 0) {
            Add op(trace);
            result = dispatch(op, value);
        } else {
            Double op(trace);
            result = dispatch(op, value);
        }
        printf("value=%u lifetime=%u\n", result, trace);
    }
    return 0;
}
