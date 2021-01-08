#pragma once

#define DEBUG_MODE
#define INVALID_HANDLE_VALUE HANDLE(-1)

#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include <ifdef.h>
#include <ndis.h>
#include <intrin.h>

#include "ia32.hpp"
#include "imports.hpp"
#include "utils.hpp"
#include "comms.hpp"