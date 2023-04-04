/*
    DISKHASHER v0.2 - 2023 by Hyohko

    ##################################
    GPLv3 NOTICE AND DISCLAIMER
    ##################################

    This file is part of DISKHASHER.

    DISKHASHER is free software: you can redistribute it
    and/or modify it under the terms of the GNU General
    Public License as published by the Free Software
    Foundation, either version 3 of the License, or (at
    your option) any later version.

    DISKHASHER is distributed in the hope that it will
    be useful, but WITHOUT ANY WARRANTY; without even
    the implied warranty of MERCHANTABILITY or FITNESS
    FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General
    Public License along with DISKHASHER. If not, see
    <https://www.gnu.org/licenses/>.
*/

/// (2) MiB
pub const SIZE_2MB: usize = 1024 * 1024 * 2;
/// (128) MiB
pub const SIZE_128MB: usize = 1024 * 1024 * 128;

/// Buffer alignment for Direct I/O - one page (4096 bytes)
#[cfg(target_os = "linux")]
pub const ALIGNMENT: usize = 0x1000;

/// The Linux flag for Direct I/O
#[cfg(target_os = "linux")]
const O_DIRECT: u32 = 0x4000;
#[cfg(target_os = "linux")]
const O_SEQUENTIAL: u32 = 0;
#[cfg(target_os = "linux")]
const O_BINARY: u32 = 0;

#[cfg(target_os = "windows")]
const O_DIRECT: u32 = 0;
#[cfg(target_os = "windows")]
const O_SEQUENTIAL: u32 = 0x0020;
#[cfg(target_os = "windows")]
const O_BINARY: u32 = 0x8000;

pub const O_FLAGS: u32 = O_DIRECT | O_SEQUENTIAL | O_BINARY;
