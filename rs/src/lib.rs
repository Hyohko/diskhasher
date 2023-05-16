/*
    DISKHASHER v0.3 - 2023 by Hyohko

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
mod cli;
mod constants;
mod enums;
mod error;
mod filedata;
mod filesigner;
mod hasher;
mod macros;
mod threadfunc;
mod util;

extern crate pretty_env_logger;
#[macro_use]
extern crate log;

// The only exportable functionality we expose to any main function
pub use crate::{
    cli::{parse_cli, Arguments, HashMode},
    filesigner::{sign_hash_file, verify_hash_file},
    hasher::Hasher,
    threadfunc::hash_single_file,
};

///////////////////////////////////////////////////////////////////////////////
/// TESTS
///////////////////////////////////////////////////////////////////////////////
#[cfg(test)]
mod test;
