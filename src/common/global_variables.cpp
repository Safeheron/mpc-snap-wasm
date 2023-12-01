#include "global_variables.h"
namespace safeheron {
namespace mpc_snap_wasm {
namespace common {
static bool randomness_flag = false;

bool get_randomness_flag() {
    return randomness_flag;
}

void set_randomness_flag() {
    randomness_flag = true;
}
}
}
}