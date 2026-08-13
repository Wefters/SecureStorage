import Foundation
import Security

final class SecureStoragePlugin: WefterPlugin {

    private let service = "dev.wefter.plugins.secure-storage"
    private let maxKeyLength = 255
    private let maxValueLength = 8192

    // @WefterMethod
    func set(payload: [String: Any], callback: @escaping (Result<Any, Error>) -> Void) throws {
        guard let key = validatedKey(payload, callback) else { return }

        guard let value = payload["value"] as? String else {
            reject(callback, code: "VALUE_REQUIRED", message: "A string value is required.")
            return
        }

        if value.utf8.count > maxValueLength {
            reject(callback, code: "VALUE_TOO_LARGE", message: "Value must not exceed \(maxValueLength) bytes.")
            return
        }

        var query = baseQuery(forKey: key)
        let data = Data(value.utf8)
        let updateStatus = SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)

        if updateStatus == errSecItemNotFound {
            query[kSecValueData as String] = data
            query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            let addStatus = SecItemAdd(query as CFDictionary, nil)

            guard addStatus == errSecSuccess else {
                reject(callback, code: "WRITE_FAILED", message: "Could not write to Keychain (status \(addStatus)).")
                return
            }
        } else if updateStatus != errSecSuccess {
            reject(callback, code: "WRITE_FAILED", message: "Could not update Keychain item (status \(updateStatus)).")
            return
        }

        resolve(callback, data: ["success": true])
    }

    // @WefterMethod
    func get(payload: [String: Any], callback: @escaping (Result<Any, Error>) -> Void) throws {
        guard let key = validatedKey(payload, callback) else { return }

        var query = baseQuery(forKey: key)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        guard status == errSecSuccess, let data = item as? Data, let value = String(data: data, encoding: .utf8) else {
            resolve(callback, data: ["value": NSNull()])
            return
        }

        resolve(callback, data: ["value": value])
    }

    // @WefterMethod
    func remove(payload: [String: Any], callback: @escaping (Result<Any, Error>) -> Void) throws {
        guard let key = validatedKey(payload, callback) else { return }

        let status = SecItemDelete(baseQuery(forKey: key) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            reject(callback, code: "REMOVE_FAILED", message: "Could not remove Keychain item (status \(status)).")
            return
        }

        resolve(callback, data: ["success": true])
    }

    private func baseQuery(forKey key: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
        ]
    }

    private func validatedKey(_ payload: [String: Any], _ callback: @escaping (Result<Any, Error>) -> Void) -> String? {
        guard let rawKey = payload["key"] as? String else {
            reject(callback, code: "KEY_REQUIRED", message: "A non-empty key is required.")
            return nil
        }

        let key = rawKey.trimmingCharacters(in: .whitespacesAndNewlines)
        if key.isEmpty {
            reject(callback, code: "KEY_REQUIRED", message: "A non-empty key is required.")
            return nil
        }
        if key.count > maxKeyLength {
            reject(callback, code: "KEY_TOO_LONG", message: "Key must not exceed \(maxKeyLength) characters.")
            return nil
        }
        return key
    }
}
