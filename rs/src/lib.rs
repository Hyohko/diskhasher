/*
    DKHASH - 2025 by Hyohko

    ##################################
    GPLv3 NOTICE AND DISCLAIMER
    ##################################

    This file is part of DKHASH.

    DKHASH is free software: you can redistribute it
    and/or modify it under the terms of the GNU General
    Public License as published by the Free Software
    Foundation, either version 3 of the License, or (at
    your option) any later version.

    DKHASH is distributed in the hope that it will
    be useful, but WITHOUT ANY WARRANTY; without even
    the implied warranty of MERCHANTABILITY or FITNESS
    FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General
    Public License along with DKHASH. If not, see
    <https://www.gnu.org/licenses/>.
*/
/*
#![deny(missing_docs)]
#![deny(rustdoc::missing_doc_code_examples)]
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
    cli::{Arguments, HashMode, parse_cli},
    filesigner::{gen_keypair, sign_file, verify_file},
    hasher::DirHasher,
    threadfunc::hash_single_file,
};

///////////////////////////////////////////////////////////////////////////////
// TESTS
///////////////////////////////////////////////////////////////////////////////
#[cfg(test)]
mod test;
