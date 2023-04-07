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

// in macros, we can't use the "use" block, but I'm putting it here for reference
// as to which crates we are importing.
/*use {
    digest::consts::{B0, B1},
    digest::core_api::{CoreWrapper, CtVariableCoreWrapper},
    md5::Md5Core,
    sha1::Sha1Core,
    sha2::{OidSha224, OidSha256, OidSha384, OidSha512, Sha256VarCore, Sha512VarCore},
    typenum::uint::{UInt, UTerm},
};*/

#[macro_export]
macro_rules! hashobj {
    ($alg:expr) => {
        match $alg {
            HashAlg::MD5 => Box::<digest::core_api::CoreWrapper<md5::Md5Core>>::default(),
            HashAlg::SHA1 => Box::<digest::core_api::CoreWrapper<sha1::Sha1Core>>::default(),
            HashAlg::SHA224 => Box::<
                digest::core_api::CoreWrapper<
                    digest::core_api::CtVariableCoreWrapper<
                        sha2::Sha256VarCore,
                        typenum::uint::UInt<
                            typenum::uint::UInt<
                                typenum::uint::UInt<
                                    typenum::uint::UInt<
                                        typenum::uint::UInt<
                                            typenum::uint::UTerm,
                                            digest::consts::B1,
                                        >,
                                        digest::consts::B1,
                                    >,
                                    digest::consts::B1,
                                >,
                                digest::consts::B0,
                            >,
                            digest::consts::B0,
                        >,
                        sha2::OidSha224,
                    >,
                >,
            >::default(),
            HashAlg::SHA256 => Box::<
                digest::core_api::CoreWrapper<
                    digest::core_api::CtVariableCoreWrapper<
                        sha2::Sha256VarCore,
                        typenum::uint::UInt<
                            typenum::uint::UInt<
                                typenum::uint::UInt<
                                    typenum::uint::UInt<
                                        typenum::uint::UInt<
                                            typenum::uint::UInt<
                                                typenum::uint::UTerm,
                                                digest::consts::B1,
                                            >,
                                            digest::consts::B0,
                                        >,
                                        digest::consts::B0,
                                    >,
                                    digest::consts::B0,
                                >,
                                digest::consts::B0,
                            >,
                            digest::consts::B0,
                        >,
                        sha2::OidSha256,
                    >,
                >,
            >::default(),
            HashAlg::SHA384 => Box::<
                digest::core_api::CoreWrapper<
                    digest::core_api::CtVariableCoreWrapper<
                        sha2::Sha512VarCore,
                        typenum::uint::UInt<
                            typenum::uint::UInt<
                                typenum::uint::UInt<
                                    typenum::uint::UInt<
                                        typenum::uint::UInt<
                                            typenum::uint::UInt<
                                                typenum::uint::UTerm,
                                                digest::consts::B1,
                                            >,
                                            digest::consts::B1,
                                        >,
                                        digest::consts::B0,
                                    >,
                                    digest::consts::B0,
                                >,
                                digest::consts::B0,
                            >,
                            digest::consts::B0,
                        >,
                        sha2::OidSha384,
                    >,
                >,
            >::default(),
            HashAlg::SHA512 => Box::<
                digest::core_api::CoreWrapper<
                    digest::core_api::CtVariableCoreWrapper<
                        sha2::Sha512VarCore,
                        typenum::uint::UInt<
                            typenum::uint::UInt<
                                typenum::uint::UInt<
                                    typenum::uint::UInt<
                                        typenum::uint::UInt<
                                            typenum::uint::UInt<
                                                typenum::uint::UInt<
                                                    typenum::uint::UTerm,
                                                    digest::consts::B1,
                                                >,
                                                digest::consts::B0,
                                            >,
                                            digest::consts::B0,
                                        >,
                                        digest::consts::B0,
                                    >,
                                    digest::consts::B0,
                                >,
                                digest::consts::B0,
                            >,
                            digest::consts::B0,
                        >,
                        sha2::OidSha512,
                    >,
                >,
            >::default(),
        }
    };
}

// Clippy complains about this being less performant. Retain, but know that
// the above macro is the expanded variant of this one - in case anyone wants
// to dig into it
#[macro_export]
macro_rules! hashobj_slow {
    ($alg:expr) => {
        match $alg {
            HashAlg::MD5 => Box::new(md5::Md5::default()),
            HashAlg::SHA1 => Box::new(sha1::Sha1::default()),
            HashAlg::SHA224 => Box::new(sha2::Sha224::default()),
            HashAlg::SHA256 => Box::new(sha2::Sha256::default()),
            HashAlg::SHA384 => Box::new(sha2::Sha384::default()),
            HashAlg::SHA512 => Box::new(sha2::Sha512::default()),
        }
    };
}

// The hashes of zero-length data are well known and never change - this avoids performance overhead
// when reading zero-length files: no allocation of either the hash object or the buffer is required
#[macro_export]
macro_rules! known_zero_hash {
    ($alg:expr) => {
        match $alg {
            HashAlg::MD5 => String::from("d41d8cd98f00b204e9800998ecf8427e"),
            HashAlg::SHA1 => String::from("da39a3ee5e6b4b0d3255bfef95601890afd80709"),
            HashAlg::SHA224 => String::from("d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"),
            HashAlg::SHA256 => String::from("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            HashAlg::SHA384 => String::from("38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"),
            HashAlg::SHA512 => String::from("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"),
        }
    };
}

// Given an Arc<Mutex<File>> and a String msg, write that string to the opened file
#[macro_export]
macro_rules! filelog {
    ($msg:expr, $filehandleopt:expr) => {
        if let Some(handle) = $filehandleopt {
            let mut guarded_filehandle = handle.lock().expect("Mutex unlock failure - Panic!");
            (*guarded_filehandle).write($msg.as_bytes()).ok();
        }
    };
}
