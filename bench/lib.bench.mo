import Bench "mo:bench";
import Nat "mo:base/Nat";
import Nat8 "mo:base/Nat8";
import Iter "mo:base/Iter";
import Result "mo:base/Result";
import Debug "mo:base/Debug";
import Blob "mo:base/Blob";
import Array "mo:base/Array";
import Text "mo:base/Text";
import HMAC "../src";

module {

  public func init() : Bench.Bench {
    // Test data for benchmarking
    let shortMessage : Blob = "Hi There";
    let mediumMessage : Blob = "what do ya want for nothing?";
    let longMessage : Blob = "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";
    let veryLongMessage : Blob = Text.encodeUtf8("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum. Sed ut perspiciatis unde omnis iste natus error sit voluptatem accusantium doloremque laudantium, totam rem aperiam.");

    // Different key sizes for testing
    let shortKey : [Nat8] = Blob.toArray("\0b\0b\0b\0b\0b\0b\0b\0b\0b\0b\0b\0b\0b\0b\0b\0b\0b\0b\0b\0b"); // 20 bytes
    let largeKey : [Nat8] = Blob.toArray("\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa\aa"); // 131 bytes (needs hashing)

    // Pre-generated arrays for different message sizes
    let messages = [shortMessage, mediumMessage, longMessage, veryLongMessage];

    // Repeated patterns for stress testing
    let repeatedBytes : [Nat8] = Array.tabulate<Nat8>(1024, func(i : Nat) : Nat8 { Nat8.fromNat(i % 256) });

    let bench = Bench.Bench();

    bench.name("HMAC Cryptographic Operations Benchmarks");
    bench.description("Benchmark HMAC-SHA256 operations with various key and message sizes");

    bench.rows([
      "hmac_short_key_short_message",
      "hmac_short_key_very_long_message",
      "hmac_large_key_short_message",
      "hmac_repeated_pattern_1024",
      "hmac_stress_test_various_messages",
    ]);

    bench.cols(["1", "10", "100"]);

    bench.runner(
      func(row, col) {
        let ?n = Nat.fromText(col) else Debug.trap("Cols must only contain numbers: " # col);

        // Define the operation to perform based on the row
        let operation = switch (row) {
          case ("hmac_short_key_short_message") func(_ : Nat) : Result.Result<Any, Text> {
            let result = HMAC.generate(shortKey, shortMessage.vals(), #sha256);
            #ok(result);
          };
          case ("hmac_short_key_very_long_message") func(_ : Nat) : Result.Result<Any, Text> {
            let result = HMAC.generate(shortKey, veryLongMessage.vals(), #sha256);
            #ok(result);
          };
          case ("hmac_large_key_short_message") func(_ : Nat) : Result.Result<Any, Text> {
            let result = HMAC.generate(largeKey, shortMessage.vals(), #sha256);
            #ok(result);
          };
          case ("hmac_repeated_pattern_1024") func(_ : Nat) : Result.Result<Any, Text> {
            let result = HMAC.generate(repeatedBytes, longMessage.vals(), #sha256);
            #ok(result);
          };
          case ("hmac_stress_test_various_messages") func(i : Nat) : Result.Result<Any, Text> {
            let message = messages[i % messages.size()];
            let result = HMAC.generate(shortKey, message.vals(), #sha256);
            #ok(result);
          };
          case (_) Debug.trap("Unknown row: " # row);
        };

        // Single shared loop with result checking
        for (i in Iter.range(1, n)) {
          switch (operation(i)) {
            case (#ok(_)) ();
            case (#err(e)) Debug.trap(e);
          };
        };
      }
    );

    bench;
  };

};
