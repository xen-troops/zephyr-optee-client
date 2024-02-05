/*
 * Copyright (c) 2024, EPAM Systems
 */
#ifndef TEE_SUPPLICANT_H
#define TEE_SUPPLICANT_H

#ifndef CONFIG_OPTEE_TEE_SUPPLICANT_AUTOINIT
#ifdef __cplusplus
extern "C" {
#endif
int TEE_SupplicantInit(void);
#ifdef __cplusplus
}
#endif
#endif

#endif
