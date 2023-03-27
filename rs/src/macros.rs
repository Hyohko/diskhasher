/*
    DISKHASHER v0.1 - 2022 by Hyohko

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

// Clippy would prefer a better default() invocation, but
// that is waaaayyy too verbose. Suppress for this function
// The macros above have been generated from this function, retain for now
// so we don't forget what they're here for
/*#[allow(clippy::box_default)]
fn select_hasher(alg: HashAlg) -> Box<dyn DynDigest> {
    match alg {
        HashAlg::MD5 => Box::new(md5::Md5::default()),
        HashAlg::SHA1 => Box::new(sha1::Sha1::default()),
        HashAlg::SHA224 => Box::new(sha2::Sha224::default()),
        HashAlg::SHA256 => Box::new(sha2::Sha256::default()),
        HashAlg::SHA384 => Box::new(sha2::Sha384::default()),
        HashAlg::SHA512 => Box::new(sha2::Sha512::default()),
    }
}*/
