import Hmac "../src/";
import Blob "mo:base/Blob";
import { test } "mo:test";
import List "mo:core/List";
import Iter "mo:core/Iter";
import Text "mo:core/Text";
import Runtime "mo:core/Runtime";
import Int "mo:core/Int";

test(
  "generate",
  func() {

    type TestCase = {
      key : Blob;
      msg : Blob;
      expected : Blob;
    };

    let testCases : [TestCase] = [
      {
        key = "\0b\0b\0b\0b\0b\0b\0b\0b\0b\0b\0b\0b\0b\0b\0b\0b\0b\0b\0b\0b";
        msg = "Hi There";
        expected = "\b0\34\4c\61\d8\db\38\53\5c\a8\af\ce\af\0b\f1\2b\88\1d\c2\00\c9\83\3d\a7\26\e9\37\6c\2e\32\cf\f7";
      },
      {
        key = "Jefe";
        msg = "what do ya want for nothing?";
        expected = "\5b\dc\c1\46\bf\60\75\4e\6a\04\24\26\08\95\75\c7\5a\00\3f\08\9d\27\39\83\9d\ec\58\b9\64\ec\38\43";
      },
      {
        key = "\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa";
        msg = "\dd\dd\dd\dd\dd\dd\dd\dd\dd\dd\dd\dd\dd\dd\dd\dd\dd\dd\dd\dd\dd\dd\dd\dd\dd\dd\dd\dd\dd\dd\dd\dd\dd\dd\dd\dd\dd\dd\dd\dd\dd\dd\dd\dd\dd\dd\dd\dd\dd\dd";
        expected = "\77\3e\a9\1e\36\80\0e\46\85\4d\b8\eb\d0\91\81\a7\29\59\09\8b\3e\f8\c1\22\d9\63\55\14\ce\d5\65\fe";
      },
      {
        key = "\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa";
        msg = "Test Using Larger Than Block-Size Key - Hash Key First";
        expected = "\60\e4\31\59\1e\e0\b6\7f\0d\8a\26\aa\cb\f5\b7\7f\8e\0b\c6\21\37\28\c5\14\05\46\04\0f\0e\e3\7f\54";
      },
      {
        key = "\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa";
        msg = "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";
        expected = "\9b\09\ff\a7\1b\94\2f\cb\27\63\5f\bc\d5\b0\e9\44\bf\dc\63\64\4f\07\13\93\8a\7f\51\53\5c\3a\35\e2";
      },
      {
        key = "\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01";
        msg = "\12";
        expected = "\9f\c5\fd\7a\cf\75\bf\21\25\22\02\40\29\3b\d8\22\1d\72\a2\5f\fb\5b\fb\39\7e\e1\a2\a0\0d\f7\a1\ad";
      },
      {
        key = "\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01";
        msg = "\12";
        expected = "\4a\8a\c5\b5\f1\40\61\a2\ed\19\ea\9a\c7\16\b3\c2\c2\73\43\ac\4d\c5\2e\42\fa\bb\9b\1a\b0\19\d3\35";
      },
      {
        key = "\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01\01";
        msg = "\12";
        expected = "\e4\ab\29\2c\53\a5\35\61\7d\5d\5a\80\a7\4d\e6\e5\e2\51\6f\ab\a8\70\8a\c5\36\a5\bb\79\c7\c8\e9\89";
      },
      {
        key = "";
        msg = "";
        expected = "\b6\13\67\9a\08\14\d9\ec\77\2f\95\d7\78\c3\5f\c5\ff\16\97\c4\93\71\56\53\c6\c7\12\14\42\92\c5\ad";
      },
    ];

    let failures = List.empty<(TestCase, Blob)>();
    for (testCase in testCases.vals()) {
      let key = Blob.toArray(testCase.key);
      let messageDigest = Hmac.generate(key, testCase.msg.vals(), #sha256);
      if (messageDigest.size() != testCase.expected.size()) {
        List.add(failures, (testCase, messageDigest));
      };
    };
    if (List.size(failures) > 0) {
      let failureTests = List.values(failures)
      |> Iter.map(
        _,
        func((tc : TestCase, messageDigest : Blob)) : Text {
          "Key: " # debug_show (tc.key) # "\n" # "Message: " # debug_show (tc.msg) # "\nExpected: " # debug_show (tc.expected) # "\nActual: " # debug_show (messageDigest);
        },
      );
      Runtime.trap("Failed test cases: " # Int.toText(List.size(failures)) # "\n" # Text.join("\n---\n", failureTests));
    };
  },
);
