/**
 * Module      : hmac.mo
 * Description : HMAC-SHA-256
 * Copyright   : 2022 Mitsunari Shigeo
 * License     : Apache 2.0 with LLVM Exception
 * Maintainer  : herumi <herumi@nifty.com>
 * Stability   : Stable
 */

import Iter "mo:core/Iter";
import Array "mo:core/Array";
import Blob "mo:core/Blob";
import VarArray "mo:core/VarArray";
import Sha256 "mo:sha2/Sha256";

module {
  public type HashAlgorithm = {
    #sha256;
    #custom : (Iter.Iter<Nat8>) -> Blob;
  };

  public func generate(
    key : [Nat8],
    msg : Iter.Iter<Nat8>,
    algorithm : HashAlgorithm,
  ) : Blob {
    let ipad : Nat8 = 0x36;
    let opad : Nat8 = 0x5c;
    var k : [var Nat8] = VarArray.repeat<Nat8>(0, 64);
    var keySize = key.size();
    if (keySize > 64) {
      let messageDigest = Blob.toArray(Sha256.fromIter(#sha256, key.vals()));
      var i = 0;
      keySize := 32;
      while (i < keySize) {
        k[i] := messageDigest[i];
        i += 1;
      };
    } else {
      var i = 0;
      while (i < keySize) {
        k[i] := key[i];
        i += 1;
      };
    };
    var i = 0;
    while (i < 64) {
      k[i] ^= ipad;
      i += 1;
    };
    class k_and_msg(k : [var Nat8], msg : Iter.Iter<Nat8>) {
      var i = 0;
      public func next() : ?Nat8 {
        if (i < 64) {
          let ret = ?k[i];
          i += 1;
          ret;
        } else {
          msg.next();
        };
      };
    };
    let hmac = Blob.toArray(Sha256.fromIter(#sha256, k_and_msg(k, msg)));
    i := 0;
    while (i < 64) {
      k[i] ^= ipad ^ opad;
      i += 1;
    };
    let ith = func(i : Nat) : Nat8 {
      if (i < 64) k[i] else hmac[i - 64];
    };
    let cat = Array.tabulate<Nat8>(96, ith);
    switch (algorithm) {
      case (#sha256) Sha256.fromIter(#sha256, cat.vals());
      case (#custom(hasher)) hasher(cat.vals());
    };
  };
};
