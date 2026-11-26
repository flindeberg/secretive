import Foundation
import CryptoKit

/// The values that accompany a signature made by an OpenSSH security key ("sk") secret, as described in https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.u2f
public struct SecurityKeyAssertion: Sendable, Hashable {

    public let application: String
    public let flags: Flags
    public let counter: UInt32

    public init(application: String, flags: Flags, counter: UInt32) {
        self.application = application
        self.flags = flags
        self.counter = counter
    }

    /// Generates the payload that a security key signs in place of the message itself.
    /// - Returns: The payload to sign.
    public func signedData(for message: Data) -> Data {
        Data(SHA256.hash(data: Data(application.utf8))) +
        flagsAndCounter +
        Data(SHA256.hash(data: message))
    }

    var flagsAndCounter: Data {
        var counterBigEndian = counter.bigEndian
        return unsafe Data([flags.rawValue]) + Data(bytes: &counterBigEndian, count: MemoryLayout<UInt32>.size)
    }

    public struct Flags: OptionSet, Sendable, Hashable {

        public let rawValue: UInt8

        public init(rawValue: UInt8) {
            self.rawValue = rawValue
        }

        public static let userPresent = Flags(rawValue: 0x01)
        public static let userVerified = Flags(rawValue: 0x04)

    }

}
