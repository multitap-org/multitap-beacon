#pragma once

#include <cstddef>
#include <cstdint>

// Fills `out` with `size` bytes from the kernel's random generator
// (getrandom). Logs and returns false if that fails.
bool beacon_random_fill(uint8_t* out, size_t size);
