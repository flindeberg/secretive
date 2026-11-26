import Foundation
import Testing
import CryptoKit
@testable import SSHProtocolKit
@testable import SecretKit

// Reference values are from OpenSSH 10.5p1 with /usr/lib/ssh-keychain.dylib as provider: `ssh-keygen -Y sign -n sktest`.
@Suite struct SecurityKeyTests {

    private let publicKeyWriter = OpenSSHPublicKeyWriter()
    private let signatureWriter = OpenSSHSignatureWriter()

    @Test func ecdsaSK256Hash() {
        #expect(publicKeyWriter.data(secret: Constants.secret) == Constants.publicKeyBlob)
    }

    @Test func ecdsaSK256PublicKey() {
        #expect(publicKeyWriter.openSSHString(secret: Constants.secret) ==
                "sk-ecdsa-sha2-nistp256@openssh.com \(Constants.publicKeyBlob.base64EncodedString()) test@example.com")
    }

    @Test func ecdsaSK256SHA256Fingerprint() {
        #expect(publicKeyWriter.openSSHSHA256Fingerprint(secret: Constants.secret) == "SHA256:WfSDcrrDHjzJsLoPS8fo4FL51TImy67Ov6gwxWQ2tfw")
    }

    @Test func ecdsaSK256CustomApplication() {
        var secret = Constants.secret
        secret.attributes.securityKeyApplication = "ssh:example"
        let blob = publicKeyWriter.data(secret: secret)
        #expect(blob.suffix(15) == "ssh:example".lengthAndData)
    }

    @Test func ecdsaSK256Signature() {
        let written = signatureWriter.data(secret: Constants.secret, signature: Constants.rawSignature, securityKeyAssertion: Constants.assertion)
        #expect(written == Constants.signatureBlob.lengthAndData)
    }

    @Test func signedDataLayout() {
        let assertion = SecurityKeyAssertion(application: "ssh:", flags: [.userPresent, .userVerified], counter: 0x01020304)
        let message = Data("message".utf8)
        let signed = assertion.signedData(for: message)
        #expect(signed.count == 32 + 1 + 4 + 32)
        #expect(signed.prefix(32) == Data(SHA256.hash(data: Data("ssh:".utf8))))
        #expect(Array(signed[32..<37]) == [0x05, 0x01, 0x02, 0x03, 0x04])
        #expect(signed.suffix(32) == Data(SHA256.hash(data: message)))
    }

    @Test func signedDataVerifiesAgainstReferenceSignature() throws {
        let publicKey = try P256.Signing.PublicKey(x963Representation: Constants.publicKey)
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: Constants.rawSignature)
        let signedData = Constants.assertion.signedData(for: Constants.sshSigMessage)
        #expect(publicKey.isValidSignature(signature, for: signedData))

        let wrongCounter = SecurityKeyAssertion(application: "ssh:", flags: Constants.assertion.flags, counter: 2)
        #expect(!publicKey.isValidSignature(signature, for: wrongCounter.signedData(for: Constants.sshSigMessage)))
    }

}

private extension SecurityKeyTests {

    enum Constants {

        static let publicKey = Data(base64Encoded: "BKWEeOOtTNe85v/axTvr7xuOLzBcNXJWYTVpdiqUrApB2foYZyC7CrJ8C7oPyBbgvzCehH3+aYJbwwSi8DNiV5s=")!

        static let secret = TestSecret(
            id: Data(),
            name: "Test Key (ECDSA SK 256)",
            publicKey: publicKey,
            attributes: Attributes(
                keyType: .ecdsaSK256,
                authentication: .presenceRequired,
                publicKeyAttribution: "test@example.com"
            )
        )

        static let publicKeyBlob = Data(base64Encoded: "AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBKWEeOOtTNe85v/axTvr7xuOLzBcNXJWYTVpdiqUrApB2foYZyC7CrJ8C7oPyBbgvzCehH3+aYJbwwSi8DNiV5sAAAAEc3NoOg==")!

        static let rawSignature = Data(base64Encoded: "VAkU48yMZ83MbTK8NfmPGc8rWHHLV+GyWDYat82djmp8Nq9EJ9rexsEjeV4fBkOgaF68LBD4Ilu7LbEXWNAD6w==")!

        static let assertion = SecurityKeyAssertion(application: "ssh:", flags: .init(rawValue: 0x21), counter: 1)

        static let signatureBlob = Data(base64Encoded: "AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAABIAAAAIFQJFOPMjGfNzG0yvDX5jxnPK1hxy1fhslg2GrfNnY5qAAAAIHw2r0Qn2t7GwSN5Xh8GQ6BoXrwsEPgiW7stsRdY0APrIQAAAAE=")!

        // https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig
        static var sshSigMessage: Data {
            Data("SSHSIG".utf8) +
            "sktest".lengthAndData +
            "".lengthAndData +
            "sha512".lengthAndData +
            Data(SHA512.hash(data: Data("hello secure enclave\n".utf8))).lengthAndData
        }

    }

}
