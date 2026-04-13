/* SPDX-FileCopyrightText: 2025-2026 Vacuumlabs */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdlib.h>

#include "os.h"

void os_longjmp(unsigned int exception) {
    (void) exception;
    abort();
}
