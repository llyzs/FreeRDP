/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * GDI Brush Functions
 *
 * Copyright 2010-2011 Marc-Andre Moreau <marcandre.moreau@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef FREERDP_GDI_BRUSH_H
#define FREERDP_GDI_BRUSH_H

#include <freerdp/api.h>
#include <freerdp/gdi/gdi.h>

#ifdef __cplusplus
 extern "C" {
#endif

FREERDP_API HGDI_BRUSH gdi_CreateSolidBrush(GDI_COLOR crColor);
FREERDP_API HGDI_BRUSH gdi_CreatePatternBrush(HGDI_BITMAP hbmp);
FREERDP_API HGDI_BRUSH gdi_CreateHatchBrush(HGDI_BITMAP hbmp);
FREERDP_API BOOL gdi_PatBlt(HGDI_DC hdc, int nXLeft, int nYLeft, int nWidth, int nHeight, DWORD rop);

#ifdef __cplusplus
 }
#endif

typedef BOOL (*p_PatBlt)(HGDI_DC hdc, int nXLeft, int nYLeft, int nWidth, int nHeight, DWORD rop);

#endif /* FREERDP_GDI_BRUSH_H */
