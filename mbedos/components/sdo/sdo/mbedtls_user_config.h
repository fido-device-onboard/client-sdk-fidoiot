/*
 *  Copyright (C) 2006-2019, Arm Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of Mbed TLS (https://tls.mbed.org)
 */

/* Enable PSA APIs, which this example depends on. */
#if !defined(MBEDTLS_PSA_CRYPTO_C)
#define MBEDTLS_PSA_CRYPTO_C
#endif

/* Enable the default implementation of the PSA entropy injection API if we are
 * building for an SPE. */
#if defined(COMPONENT_PSA_SRV_IMPL) || defined(COMPONENT_PSA_SRV_EMUL)
#define MBEDTLS_PLATFORM_NV_SEED_READ_MACRO mbed_default_seed_read
#define MBEDTLS_PLATFORM_NV_SEED_WRITE_MACRO mbed_default_seed_write
#endif
