import Foundation
import NFCPassportReader

@objc(PassportNFCScanner) class PassportNFCScanner: NSObject {
  @objc static func requiresMainQueueSetup() -> Bool { return true }
  
  @objc public func scan(
    _ mrzKey: String,
    dataGroups: [String],
    skipSecureElements: Bool,
    skipCA: Bool,
    skipPACE: Bool,
    resolver resolve: @escaping RCTPromiseResolveBlock,
    rejecter reject: @escaping RCTPromiseRejectBlock
  ) {
    Task {
      do {
        let validGroups = try dataGroups.map { name -> DataGroupId in
          let dg = DataGroupId.getIDFromName(name: name)
          if dg == .Unknown {
            throw NSError(domain: "PassportNFCScanner.scan", code: -1, userInfo: [
              NSLocalizedDescriptionKey: "Invalid data group: \(name)"
            ])
          }
          return dg
        }

        let passportReader = PassportReader()

        let passport = try await passportReader.readPassport(
          mrzKey: mrzKey,
          tags: validGroups,
          skipSecureElements: skipSecureElements,
          skipCA: skipCA,
          skipPACE: skipPACE
        )

        let dict = passport.dumpPassportData(
          selectedDataGroups: DataGroupId.allCases,
          includeActiveAuthenticationData: true
        )

        resolve(dict)
      } catch {
        reject("0", error.localizedDescription, error)
      }
    }
  }

  @objc public func verifySod(
    _ sodDataBase64: String,
    cscaCertBase64: String,
    dataGroupBase64: String,
    dataGroupNumber: NSNumber,
    resolver resolve: @escaping RCTPromiseResolveBlock,
    rejecter reject: @escaping RCTPromiseRejectBlock
  ) {
    do {
      try verifySodBase64(
         sodDataBase64: sodDataBase64,
         cscaCertBase64: cscaCertBase64,
         dataGroupBase64: dataGroupBase64,
         dataGroupNumber: dataGroupNumber.int32Value
      )
      resolve("SOD verified successfully!")
    } catch {
      reject("VERIFY_SOD_FAILED", error.localizedDescription, error)
    }
  }
}

