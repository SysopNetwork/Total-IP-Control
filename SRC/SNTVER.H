/***************************************************************************
 *                                                                         *
 *   SNTVER.H                                                              *
 *                                                                         *
 *   Total IP Control (SNTIPCTL) for The Major BBS v10                     *
 *   Copyright (c) 2026 Sysop Network.  All Rights Reserved.               *
 *                                                                         *
 *   The single source of the version number.  Used by the C code (Audit  *
 *   Trail at startup, the debug trace's first line, the N!SNTVER text    *
 *   variable on the /TIP screens) and by SNTIPCTL.RC (the DLL's         *
 *   Windows version resource), so the two can never disagree.            *
 *                                                                         *
 *   Every build that leaves this machine gets its own number: a version  *
 *   names exactly one binary, so bump it rather than rebuild under a     *
 *   number that has already been shared.                                 *
 *                                                                         *
 ***************************************************************************/

#ifndef SNTVER_H
#define SNTVER_H

#define SNTVER_STR      "2.0.0"             /* shown to sysops             */
#define SNTVER_DOTTED   "2.0.0.0"           /* Windows FileVersion string  */
#define SNTVER_NUMS     2,0,0,0             /* Windows FILEVERSION numbers */

#define SNTPRODUCT      "Total IP Control"
#define SNTMODNAME      "SNTIPCTL"
#define SNTCOPYRIGHT    "Copyright \251 2026 Sysop Network"

#endif /* SNTVER_H */
