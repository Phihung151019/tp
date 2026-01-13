# SPDX-License-Identifier: GPL-2.0

#
# KFENCE stub
#
# This directory normally builds the KFENCE runtime (core/report) and optional
# KUnit tests. This patch replaces the runtime with a tiny stub implementation
# that keeps required symbols available but disables KFENCE functionality.

obj-$(CONFIG_KFENCE) := stub.o

# Tests are disabled by this stub patch.
# CFLAGS_kfence_test.o := -fno-omit-frame-pointer -fno-optimize-sibling-calls
# obj-$(CONFIG_KFENCE_KUNIT_TEST) += kfence_test.o
